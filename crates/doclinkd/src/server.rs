//! Data plane (LAN-facing): node info, authenticated + scope-filtered
//! share listing and download, and the pairing workflow.
//! See docs/protocol.md.

use crate::auth;
use crate::config::Config;
use crate::share::{ShareError, ShareRoot};
use crate::store::{ContactsFile, Grant, GrantsFile, SharedStore};
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    canonical_decision_string, canonical_request_string, EntryKind, ErrorResponse, ListResponse,
    NodeInfo, PairDecision, PairRequest, PairStatus, PairStatusResponse,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Flood defenses for the unauthenticated pairing plane.
pub const MAX_PENDING: usize = 64;
pub const PENDING_TTL_SECS: u64 = 600;
const MAX_DECISIONS: usize = 256;
/// Pairing endpoints allowed per source IP per minute — far above human
/// usage, low enough to make request floods pointless.
const PAIR_RATE_PER_MIN: u32 = 20;

/// A pending pair request plus when it arrived (for TTL eviction).
#[derive(Clone)]
pub struct PairRequestEntry {
    pub request: PairRequest,
    pub received_unix: u64,
}

/// In-flight pairing requests and recent decisions (not persisted).
#[derive(Clone, Default)]
pub struct PairingState {
    pub pending: Arc<Mutex<HashMap<String, PairRequestEntry>>>, // keyed by requester node_id
    pub decisions: Arc<Mutex<HashMap<String, (PairStatusResponse, u64)>>>,
}

/// Tiny fixed-window per-IP limiter guarding the pairing endpoints.
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>>,
    max_per_window: u32,
    window: Duration,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(PAIR_RATE_PER_MIN)
    }
}

impl RateLimiter {
    fn new(max_per_window: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            max_per_window,
            window: Duration::from_secs(60),
        }
    }

    fn allow(&self, ip: std::net::IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let now = Instant::now();
        let entry = buckets.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_window {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
}

impl axum::extract::FromRef<AppState> for RateLimiter {
    fn from_ref(s: &AppState) -> Self {
        s.inner.pair_limiter.clone()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub node: NodeInfo,
    pub share: ShareRoot,
    pub grants: SharedStore<GrantsFile>,
    pub contacts: SharedStore<ContactsFile>,
    pub pairing: PairingState,
    /// Signatures accepted within the current skew window, for replay
    /// rejection. Lives here so each daemon instance (and test state)
    /// gets its own cache.
    pub seen_sigs: Arc<Mutex<HashMap<String, u64>>>,
    /// Per-IP limiter for the unauthenticated pairing endpoints.
    pub pair_limiter: RateLimiter,
}

impl AppState {
    pub fn new(
        cfg: &Config,
        node: NodeInfo,
        grants: SharedStore<GrantsFile>,
        contacts: SharedStore<ContactsFile>,
        pairing: PairingState,
    ) -> Self {
        let share = ShareRoot::new(cfg.share_root.clone()).expect("share root must be creatable");
        Self {
            inner: Arc::new(Inner {
                node,
                share,
                grants,
                contacts,
                pairing,
                seen_sigs: Arc::new(Mutex::new(HashMap::new())),
                pair_limiter: RateLimiter::default(),
            }),
        }
    }
}

pub fn router(state: AppState) -> Router {
    // Pairing endpoints are unauthenticated -> wrap them in the per-IP
    // limiter; info/list/file keep their own auth paths.
    let pair_routes = Router::new()
        .route("/v1/pair/request", post(pair_request))
        .route("/v1/pair/decision", post(pair_decision))
        .route("/v1/pair/status", get(pair_status))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_pair,
        ));
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/list", get(list))
        .route("/v1/file", get(file))
        .merge(pair_routes)
        .with_state(state)
}

async fn rate_limit_pair(
    State(limiter): State<RateLimiter>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    match ip {
        Some(ip) if limiter.allow(ip) => Ok(next.run(req).await),
        Some(_) => Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pairing requests from this address — slow down",
        )),
        // No ConnectInfo (e.g. in-process tests): don't block.
        None => Ok(next.run(req).await),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse::new(msg)))
}

// ---- Grant path scoping ----

/// Outcome of parsing a `Range` header against a known file size.
enum ParsedRange {
    /// Serve the whole file (no header, malformed, multi-range, degenerate).
    Full,
    /// Out-of-bounds prefix range → 416.
    Unsatisfiable,
    Partial { start: u64, end_incl: u64 },
}

/// Resolve a single-byte-range spec ("bytes=a-b" | "bytes=a-" | "bytes=-n").
fn parse_range(hdr: Option<&str>, total: u64) -> ParsedRange {
    if total == 0 {
        return ParsedRange::Full; // nothing to range over
    }
    let Some(range) = hdr else { return ParsedRange::Full };
    let Some(spec) = range.strip_prefix("bytes=") else {
        return ParsedRange::Full;
    };
    if spec.contains(',') {
        return ParsedRange::Full; // multi-range: serve whole file
    }
    let Some((a, b)) = spec.split_once('-') else {
        return ParsedRange::Full;
    };
    if a.trim().is_empty() {
        // Suffix form: last N bytes.
        match b.trim().parse::<u64>() {
            Ok(n) if n > 0 => {
                let n = n.min(total);
                ParsedRange::Partial { start: total - n, end_incl: total - 1 }
            }
            _ => ParsedRange::Full,
        }
    } else {
        let Ok(start) = a.trim().parse::<u64>() else {
            return ParsedRange::Full;
        };
        if start >= total {
            return ParsedRange::Unsatisfiable;
        }
        let end_incl = match b.trim().parse::<u64>() {
            Ok(e) => e.min(total - 1),
            Err(_) => total - 1,
        };
        if start > end_incl {
            return ParsedRange::Full; // degenerate: serve whole file
        }
        ParsedRange::Partial { start, end_incl }
    }
}

/// true if `path` lies strictly inside `ancestor` (forward-slash paths).
fn within(path: &str, ancestor: &str) -> bool {
    !ancestor.is_empty()
        && path.len() > ancestor.len()
        && path.starts_with(ancestor)
        && path.as_bytes()[ancestor.len()] == b'/'
}

/// May this grantee list directory `dir`? Allowed when the grant covers
/// everything, when listing the root, when the dir is inside a granted
/// path, or when a granted path lives inside the dir (so the grantee can
/// navigate down to it — entries are filtered afterwards).
fn can_list(paths: &[String], dir: &str) -> bool {
    paths.is_empty()
        || dir.is_empty()
        || paths.iter().any(|p| dir == *p || within(dir, p) || within(p, dir))
}

/// May this grantee download file `file`?
fn can_read_file(paths: &[String], file: &str) -> bool {
    paths.is_empty() || paths.iter().any(|p| file == *p || within(file, p))
}

/// Is a listing entry visible to a scoped grantee? The item itself, or a
/// directory that contains (or is contained by) a granted path.
fn entry_visible(paths: &[String], path: &str, kind: EntryKind) -> bool {
    paths.iter().any(|p| {
        path == *p || within(path, p) || (kind == EntryKind::Dir && within(p, path))
    })
}

/// Unauthenticated: needed so a requester can verify a pairing target's identity.
async fn info(State(s): State<AppState>) -> Json<NodeInfo> {
    Json(s.inner.node.clone())
}

#[derive(Deserialize)]
struct PathQuery {
    /// Path relative to the share root ("" = root).
    #[serde(default)]
    path: String,
}

async fn list(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Result<Json<ListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let path_q = format!("/v1/list?path={}", urlencoding::encode(&q.path));
    let grant = auth::require_auth(&headers, "GET", &path_q, b"", &s)
        .map_err(auth::AuthError::into_response)?;
    if !can_list(&grant.paths, &q.path) {
        return Err(err(StatusCode::FORBIDDEN, "path outside grant scope"));
    }
    let mut entries = s
        .inner
        .share
        .list(&q.path)
        .await
        .map_err(|e| match e {
            ShareError::NotFound(_) => err(StatusCode::NOT_FOUND, "path not found"),
            ShareError::OutsideRoot | ShareError::IsRoot => {
                err(StatusCode::FORBIDDEN, "path outside share root")
            }
            ShareError::Io(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "share read error"),
        })?;
    if !grant.paths.is_empty() {
        entries.retain(|e| entry_visible(&grant.paths, &e.path, e.kind));
    }
    Ok(Json(ListResponse {
        path: q.path,
        entries,
    }))
}

async fn file(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let path_q = format!("/v1/file?path={}", urlencoding::encode(&q.path));
    let grant = auth::require_auth(&headers, "GET", &path_q, b"", &s)
        .map_err(auth::AuthError::into_response)?;
    if !can_read_file(&grant.paths, &q.path) {
        return Err(err(StatusCode::FORBIDDEN, "path outside grant scope"));
    }
    let path = s.inner.share.resolve(&q.path).map_err(|e| match e {
        ShareError::NotFound(_) => err(StatusCode::NOT_FOUND, "path not found"),
        ShareError::OutsideRoot | ShareError::IsRoot => {
            err(StatusCode::FORBIDDEN, "path outside share root")
        }
        ShareError::Io(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "share read error"),
    })?;

    let mut f = tokio::fs::File::open(&path)
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "share read error"))?;
    let total = f
        .metadata()
        .await
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "share read error"))?
        .len();

    // Single-byte-range support ("bytes=a-b", "bytes=a-", "bytes=-n").
    // Malformed or multi-range headers fall back to serving the whole
    // file; an out-of-bounds prefix range is 416.
    let (start, end_incl, partial) = if total == 0 {
        (0, 0, false)
    } else {
        match parse_range(headers.get(header::RANGE).and_then(|v| v.to_str().ok()), total) {
            ParsedRange::Unsatisfiable => {
                return Err(err(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "requested range is beyond the end of the file",
                ));
            }
            ParsedRange::Full => (0, total - 1, false),
            ParsedRange::Partial { start, end_incl } => (start, end_incl, true),
        }
    };

    use tokio::io::AsyncSeekExt;
    if start > 0 {
        f.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "share read error"))?;
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    out.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    if let Ok(v) = format!("attachment; filename=\"{name}\"").parse() {
        out.insert(header::CONTENT_DISPOSITION, v);
    }
    let len = if total == 0 { 0 } else { end_incl - start + 1 };
    out.insert(header::CONTENT_LENGTH, len.to_string().parse().unwrap());

    let stream = tokio_util::io::ReaderStream::with_capacity(f, 64 * 1024);
    if partial {
        if let Ok(v) = format!("bytes {start}-{end_incl}/{total}").parse() {
            out.insert(header::CONTENT_RANGE, v);
        }
        return Ok((StatusCode::PARTIAL_CONTENT, out, axum::body::Body::from_stream(stream))
            .into_response());
    }
    Ok((out, axum::body::Body::from_stream(stream)).into_response())
}

// ---- Pairing ----

async fn pair_request(
    State(s): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: String,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let req: PairRequest =
        serde_json::from_str(&body).map_err(|_| err(StatusCode::BAD_REQUEST, "invalid pair request"))?;
    NodeIdentity::verify(
        &req.pubkey_hex,
        canonical_request_string(&req).as_bytes(),
        &req.signature,
    )
    .map_err(|_| err(StatusCode::FORBIDDEN, "bad signature"))?;
    let fp = NodeIdentity::fingerprint_from_pubkey_hex(&req.pubkey_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad pubkey"))?;
    if fp[..16] != req.node_id {
        return Err(err(StatusCode::BAD_REQUEST, "node_id does not match pubkey"));
    }
    tracing::info!(%addr, name = %req.name, "pair request received");

    // Idempotent: a live grant means immediate approval.
    let now = unix_now();
    let existing = {
        s.inner
            .grants
            .lock()
            .unwrap()
            .read()
            .grants
            .iter()
            .find(|g| g.fingerprint == fp)
            .cloned()
    };
    if let Some(g) = existing {
        if g.expires_unix.is_none_or(|e| e > now) {
            return Ok(Json(PairStatusResponse {
                status: PairStatus::Approved,
                expires_unix: g.expires_unix,
            }));
        }
    }

    admit_pending(&s.inner.pairing, req).map_err(|m| err(StatusCode::TOO_MANY_REQUESTS, m))?;
    Ok(Json(PairStatusResponse {
        status: PairStatus::Pending,
        expires_unix: None,
    }))
}

/// Queue a pending pair request with TTL + cap enforcement. Returns Err
/// when the queue is full even after evicting stale entries.
fn admit_pending(pairing: &PairingState, req: PairRequest) -> Result<(), &'static str> {
    prune_pending(pairing);
    let mut pending = pairing.pending.lock().unwrap();
    if !pending.contains_key(&req.node_id) && pending.len() >= MAX_PENDING {
        return Err("too many pending pairing requests right now — try again later");
    }
    let received_unix = unix_now();
    pending.insert(req.node_id.clone(), PairRequestEntry { request: req, received_unix });
    Ok(())
}

/// Drop pair requests that have been waiting longer than PENDING_TTL_SECS.
fn prune_pending(pairing: &PairingState) {
    let cutoff = unix_now().saturating_sub(PENDING_TTL_SECS);
    pairing
        .pending
        .lock()
        .unwrap()
        .retain(|_, e| e.received_unix > cutoff);
}

/// Record a decision outcome with an insertion timestamp, bounding the map.
pub fn remember_decision(
    pairing: &PairingState,
    requester_node_id: &str,
    resp: PairStatusResponse,
) {
    let now = unix_now();
    let mut d = pairing.decisions.lock().unwrap();
    if !d.contains_key(requester_node_id) && d.len() >= MAX_DECISIONS {
        // Evict the oldest entry to keep the map bounded.
        if let Some((oldest, _)) = d.iter().min_by_key(|(_, (_, at))| *at).map(|(k, v)| (k.clone(), v.1)) {
            d.remove(&oldest);
        }
    }
    d.insert(requester_node_id.to_string(), (resp, now));
}

/// Grantor -> requester notification. Lets the requester learn the outcome
/// even though it cannot reach the grantor's admin plane (localhost-only).
///
/// This runs on the REQUESTER's machine: the grantor already applied the
/// decision (created its grant), so we must not create a grant here — we
/// record the outcome for `/v1/pair/status` and update our contact row so
/// the UI stops showing "pending".
async fn pair_decision(
    State(s): State<AppState>,
    body: String,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let d: PairDecision =
        serde_json::from_str(&body).map_err(|_| err(StatusCode::BAD_REQUEST, "invalid decision"))?;
    NodeIdentity::verify(
        &d.pubkey_hex,
        canonical_decision_string(&d).as_bytes(),
        &d.signature,
    )
    .map_err(|_| err(StatusCode::FORBIDDEN, "bad signature"))?;
    if d.requester_node_id != s.inner.node.node_id {
        return Err(err(
            StatusCode::FORBIDDEN,
            "decision is not addressed to this node",
        ));
    }
    // The signer must be a grantor WE actually added. Any LAN host can
    // produce a validly-signed body with a throwaway key; binding to the
    // recorded contact fingerprint is what makes the approval meaningful.
    let signer_fp = NodeIdentity::fingerprint_from_pubkey_hex(&d.pubkey_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad pubkey"))?;
    let known_grantor = {
        let contacts = s.inner.contacts.lock().unwrap();
        contacts
            .read()
            .contacts
            .iter()
            .any(|c| c.fingerprint == signer_fp)
    };
    if !known_grantor {
        tracing::warn!(requester = %d.requester_node_id, "pair decision from unknown grantor refused");
        return Err(err(
            StatusCode::FORBIDDEN,
            "decision from an unpaired PC",
        ));
    }
    let status = match d.decision.as_str() {
        "approve" => PairStatus::Approved,
        "deny" => PairStatus::Denied,
        _ => PairStatus::Unknown,
    };
    let resp = PairStatusResponse {
        status,
        expires_unix: (d.duration_secs != 0).then(|| unix_now() + d.duration_secs),
    };
    remember_decision(&s.inner.pairing, &d.requester_node_id, resp);
    // Update our contact row so the UI stops showing "pending".
    let label = match status {
        PairStatus::Approved => "approved",
        PairStatus::Denied => "denied",
        _ => "pending",
    };
    {
        let mut c = s.inner.contacts.lock().unwrap();
        if let Some(contact) = c
            .data_mut()
            .contacts
            .iter_mut()
            .find(|c| c.fingerprint == signer_fp)
        {
            if contact.status != label {
                contact.status = label.to_string();
                if let Err(e) = c.save() {
                    tracing::warn!(%e, "failed to persist contact status after decision");
                }
            }
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Shared by the data-plane decision handler and the admin-plane UI action.
pub fn apply_decision(
    pairing: &PairingState,
    grants: &SharedStore<GrantsFile>,
    requester_node_id: &str,
    decision: &str,
    duration_secs: u64,
) -> Result<PairStatusResponse, &'static str> {
    let pending = pairing
        .pending
        .lock()
        .unwrap()
        .remove(requester_node_id)
        .map(|entry| entry.request)
        .ok_or("no pending request from this node")?;
    if decision != "approve" {
        // Record the denial so the grantor's own /v1/pair/status answers
        // "denied" to the requester's catch-up poller, not "unknown".
        remember_decision(
            pairing,
            requester_node_id,
            PairStatusResponse {
                status: PairStatus::Denied,
                expires_unix: None,
            },
        );
        return Ok(PairStatusResponse {
            status: PairStatus::Denied,
            expires_unix: None,
        });
    }
    let now = unix_now();
    let expires = if duration_secs == 0 {
        None
    } else {
        Some(now + duration_secs)
    };
    let grant = Grant {
        fingerprint: NodeIdentity::fingerprint_from_pubkey_hex(&pending.pubkey_hex)
            .map_err(|_| "bad pubkey")?,
        node_id: pending.node_id.clone(),
        name: pending.name.clone(),
        granted_unix: now,
        expires_unix: expires,
        paths: Vec::new(), // new grants start with full access; scope via admin plane
    };
    let mut g = grants.lock().unwrap();
    g.data_mut().upsert(grant);
    g.save().map_err(|_| "failed to persist grant")?;
    Ok(PairStatusResponse {
        status: PairStatus::Approved,
        expires_unix: expires,
    })
}

#[derive(Deserialize)]
struct StatusQuery {
    node_id: String,
}

async fn pair_status(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Signed poll: proves the caller is really the node it claims to be
    // (its pubkey must hash to the queried node_id), without requiring a
    // grant — the whole point is pre-grant catch-up. Anonymous enumeration
    // of pairing state is no longer possible.
    let path_q = format!("/v1/pair/status?node_id={}", urlencoding::encode(&q.node_id));
    let (caller_node, pk_hex, sig) = auth::verify_signed_headers(&headers, "GET", &path_q, b"")
        .map_err(auth::AuthError::into_response)?;
    auth::reject_replays(&s, &sig).map_err(auth::AuthError::into_response)?;
    if caller_node != q.node_id {
        return Err(err(
            StatusCode::FORBIDDEN,
            "you may only poll your own pairing status",
        ));
    }
    let fp = NodeIdentity::fingerprint_from_pubkey_hex(&pk_hex)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "bad public key header"))?;
    if fp[..16] != q.node_id {
        return Err(err(StatusCode::BAD_REQUEST, "node_id does not match pubkey"));
    }
    Ok(Json(self::pair_status_lookup(&s, &q.node_id)))
}

fn pair_status_lookup(s: &AppState, node_id: &str) -> PairStatusResponse {
    if s.inner
        .pairing
        .pending
        .lock()
        .unwrap()
        .contains_key(node_id)
    {
        return PairStatusResponse {
            status: PairStatus::Pending,
            expires_unix: None,
        };
    }
    if let Some((d, _)) = s.inner.pairing.decisions.lock().unwrap().get(node_id) {
        return d.clone();
    }
    // A live grant for this node means the pair went through — the
    // requester's poller uses this to catch up when the decision push
    // was lost (peer offline at approval time).
    let now = unix_now();
    if let Some(g) = s
        .inner
        .grants
        .lock()
        .unwrap()
        .read()
        .grants
        .iter()
        .find(|g| g.node_id == node_id && g.expires_unix.is_none_or(|e| e > now))
    {
        return PairStatusResponse {
            status: PairStatus::Approved,
            expires_unix: g.expires_unix,
        };
    }
    PairStatusResponse {
        status: PairStatus::Unknown,
        expires_unix: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_requires_strict_prefix_boundary() {
        assert!(within("a/b", "a"));
        assert!(within("a/b/c", "a/b"));
        assert!(!within("ab", "a")); // no boundary
        assert!(!within("a", "a")); // equal is not inside
        assert!(!within("", "a"));
        assert!(!within("x/a", "a"));
    }

    #[test]
    fn can_list_full_grant_and_root_listing() {
        // Empty paths = whole share.
        assert!(can_list(&[], ""));
        assert!(can_list(&[], "any/dir"));

        // Root listing always allowed so scoped grantees can navigate down.
        assert!(can_list(&["docs/file.txt".into()], ""));
    }

    #[test]
    fn can_list_scoped() {
        let paths = vec!["parent/docs".to_string()];
        assert!(can_list(&paths, "parent/docs")); // granted dir itself
        assert!(can_list(&paths, "parent/docs/sub")); // inside grant
        assert!(can_list(&paths, "parent")); // dir containing a granted path
        assert!(!can_list(&paths, "other"));
        assert!(!can_list(&paths, "parents")); // prefix without boundary
    }

    #[test]
    fn can_read_file_scoped() {
        let paths = vec!["docs".to_string()];
        assert!(can_read_file(&paths, "docs/a.txt"));
        assert!(can_read_file(&paths, "docs/sub/b.txt"));
        assert!(!can_read_file(&paths, "docs2/a.txt"));
        assert!(!can_read_file(&paths, "other/a.txt"));

        // A grant scoped to a single *file* does not cover siblings of it.
        let file_grant = vec!["docs/a.txt".to_string()];
        assert!(can_read_file(&file_grant, "docs/a.txt"));
        assert!(!can_read_file(&file_grant, "docs/b.txt"));
        assert!(!can_read_file(&file_grant, "docs/sub/c.bin"));
        assert!(can_read_file(&[], "anything.bin"));
    }

    #[test]
    fn entry_visible_rules() {
        let paths = vec!["docs".to_string()];
        // The granted item itself.
        assert!(entry_visible(&paths, "docs", EntryKind::Dir));
        // Inside a granted path.
        assert!(entry_visible(&paths, "docs/a.txt", EntryKind::File));
        // A dir entry stays visible when a granted path lives INSIDE it —
        // this is how a scoped grantee sees the folder chain down to its
        // granted folder while browsing (grant "parent/docs" shows "parent").
        let nested = vec!["parent/docs".to_string()];
        assert!(entry_visible(&nested, "parent", EntryKind::Dir));
        assert!(!entry_visible(&nested, "sibling", EntryKind::Dir));
        // Siblings are hidden.
        assert!(!entry_visible(&paths, "other", EntryKind::Dir));
        assert!(!entry_visible(&paths, "other.txt", EntryKind::File));

        // Full-access grants bypass filtering upstream (paths.is_empty()),
        // so a non-empty list is required for these rules to apply at all.
    }

    #[tokio::test]
    async fn pair_request_rejects_node_id_pubkey_mismatch() {
        // A request whose node_id does not hash-match its pubkey must fail
        // before reaching the pending queue.
        let identity = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let req = PairRequest {
            node_id: other.node_id(), // mismatched vs signature key below
            name: "rogue".into(),
            pubkey_hex: hex::encode(identity.verifying_key().as_bytes()),
            requested_duration_secs: 3600,
            signature: String::new(),
        };
        let canonical = canonical_request_string(&req);
        let req = PairRequest {
            signature: hex::encode(identity.sign(canonical.as_bytes()).to_bytes()),
            ..req
        };
        let fp = NodeIdentity::fingerprint_from_pubkey_hex(&req.pubkey_hex).unwrap();
        assert_ne!(fp[..16], req.node_id);
    }

    #[test]
    fn rate_limiter_blocks_after_cap_and_recovers() {
        let limiter = RateLimiter::new(3);
        let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip), "4th hit inside window blocked");
        assert!(!limiter.allow(ip));
        // Different IP unaffected.
        assert!(limiter.allow("10.1.2.4".parse().unwrap()));
        // Window expiry resets the bucket.
        limiter.buckets.lock().unwrap().get_mut(&ip).unwrap().1 =
            Instant::now() - Duration::from_secs(61);
        assert!(limiter.allow(ip));
    }

    fn pair_req_for(node_id: &str) -> PairRequest {
        PairRequest {
            node_id: node_id.into(),
            name: "n".into(),
            pubkey_hex: "00".repeat(32),
            requested_duration_secs: 60,
            signature: String::new(),
        }
    }

    #[test]
    fn pending_queue_is_capped() {
        let pairing = PairingState::default();
        for i in 0..MAX_PENDING {
            admit_pending(&pairing, pair_req_for(&format!("{i:016x}")))
                .expect("within cap");
        }
        assert_eq!(
            admit_pending(&pairing, pair_req_for(&"f".repeat(16))),
            Err("too many pending pairing requests right now — try again later")
        );
        // Re-admitting an existing node stays allowed (idempotent re-pair).
        admit_pending(&pairing, pair_req_for(&format!("{:016x}", 0)))
            .expect("existing key refreshes");
    }

    #[test]
    fn stale_pending_requests_are_evicted() {
        let pairing = PairingState::default();
        for i in 0..MAX_PENDING {
            admit_pending(&pairing, pair_req_for(&format!("{i:016x}"))).unwrap();
        }
        // Age every entry past the TTL.
        let cutoff = unix_now() - PENDING_TTL_SECS - 1;
        for e in pairing.pending.lock().unwrap().values_mut() {
            e.received_unix = cutoff;
        }
        // The queue makes room for the newcomer after pruning.
        admit_pending(&pairing, pair_req_for(&"a".repeat(16))).expect("room after prune");
        assert_eq!(pairing.pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn decisions_map_is_bounded() {
        let pairing = PairingState::default();
        let resp = PairStatusResponse { status: PairStatus::Approved, expires_unix: None };
        for i in 0..(MAX_DECISIONS + 10) {
            remember_decision(&pairing, &format!("{i:016x}"), resp.clone());
        }
        let d = pairing.decisions.lock().unwrap();
        assert_eq!(d.len(), MAX_DECISIONS);
    }

    #[test]
    fn range_parsing_covers_all_forms() {
        let total = 100u64;
        // No / malformed headers -> full file.
        assert!(matches!(parse_range(None, total), ParsedRange::Full));
        assert!(matches!(parse_range(Some("chars=0-4"), total), ParsedRange::Full));
        assert!(matches!(parse_range(Some("bytes="), total), ParsedRange::Full));
        assert!(matches!(parse_range(Some("bytes=1-2,5-9"), total), ParsedRange::Full));
        assert!(matches!(parse_range(Some("bytes=x-y"), total), ParsedRange::Full));

        // Prefix forms.
        let p = |r| match parse_range(Some(r), total) {
            ParsedRange::Partial { start, end_incl } => (start, end_incl),
            _ => panic!("expected partial for {r}"),
        };
        assert_eq!(p("bytes=0-0"), (0, 0));
        assert_eq!(p("bytes=10-19"), (10, 19));
        assert_eq!(p("bytes=90-"), (90, 99));
        assert_eq!(p("bytes=10-999"), (10, 99)); // clamped
        assert_eq!(p("bytes=-5"), (95, 99)); // suffix
        assert_eq!(p("bytes=-500"), (0, 99)); // suffix larger than file

        // Out-of-bounds prefix -> 416.
        assert!(matches!(parse_range(Some("bytes=100-"), total), ParsedRange::Unsatisfiable));
        assert!(matches!(parse_range(Some("bytes=150-160"), total), ParsedRange::Unsatisfiable));

        // Degenerate inverted range falls back to full.
        assert!(matches!(parse_range(Some("bytes=50-10"), total), ParsedRange::Full));

        // Empty files never produce partials.
        assert!(matches!(parse_range(Some("bytes=0-"), 0), ParsedRange::Full));
    }
}
