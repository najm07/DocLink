//! Admin plane (127.0.0.1 only): window UI, contacts, approvals,
//! revocation, per-item share scoping, own-share management, and the
//! signed browse proxy. Never bound to a LAN interface — management
//! operations are unreachable from the network.

use crate::proxy::{self, ProxyError};
use crate::server::{self, PairingState};
use crate::share::{ShareError, ShareRoot};
use crate::store::{Contact, ContactsFile, Grant, GrantsFile, SharedStore};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use doclink_core::discovery::PeerRegistry;
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    canonical_decision_string, canonical_request_string, ContactInfo, ErrorResponse, GrantInfo,
    ListResponse, NodeInfo, PairDecision, PairRequest, PairStatus, PairStatusResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<AdminInner>,
}

pub(crate) struct AdminInner {
    pub node: NodeInfo,
    pub identity: NodeIdentity,
    pub peers: PeerRegistry,
    pub grants: SharedStore<GrantsFile>,
    pub contacts: SharedStore<ContactsFile>,
    pub pairing: PairingState,
    pub share: ShareRoot,
    /// Port the admin plane is actually bound to (http_port + 1); used by
    /// the Host/Origin guard below.
    pub admin_port: u16,
    /// Whether the active /24 scan fallback may run (config subnet_scan).
    pub scan_enabled: bool,
    /// Shared outbound client for all peer calls.
    pub http: reqwest::Client,
    /// Triggers the daemon-wide graceful shutdown.
    pub shutdown: tokio::sync::watch::Sender<bool>,
    /// Toast/notification event log shared with the data plane.
    pub events: crate::events::SharedEvents,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node: NodeInfo,
        identity: NodeIdentity,
        peers: PeerRegistry,
        grants: SharedStore<GrantsFile>,
        contacts: SharedStore<ContactsFile>,
        pairing: PairingState,
        share: ShareRoot,
        admin_port: u16,
        scan_enabled: bool,
        http: reqwest::Client,
        shutdown: tokio::sync::watch::Sender<bool>,
        events: crate::events::SharedEvents,
    ) -> Self {
        Self {
            inner: Arc::new(AdminInner {
                node,
                identity,
                peers,
                grants,
                contacts,
                pairing,
                share,
                admin_port,
                scan_enabled,
                http,
                shutdown,
                events,
            }),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/info", get(info))
        .route("/v1/admin/peers", get(list_peers))
        .route("/v1/admin/contacts", get(list_contacts).post(add_contact))
        .route("/v1/admin/contact-fingerprint", get(contact_fingerprint))
        .route("/v1/admin/contacts/{node_id}", delete(remove_contact))
        .route("/v1/admin/contacts/{node_id}/status", get(contact_status))
        .route("/v1/admin/requests", get(list_requests))
        .route("/v1/admin/requests/{node_id}/decision", post(decide_request))
        .route("/v1/admin/grants", get(list_grants))
        .route(
            "/v1/admin/grants/{fingerprint}",
            delete(revoke_grant).put(update_grant),
        )
        .route("/v1/admin/share-item", post(share_item))
        .route("/v1/admin/myshare/list", get(myshare_list))
        .route("/v1/admin/myshare", delete(myshare_delete))
        .route("/v1/admin/myshare/reveal", post(myshare_reveal))
        .route("/v1/admin/shutdown", post(shutdown_node))
        .route("/v1/admin/events", get(events_since))
        .route("/v1/admin/browse/{node_id}/list", get(browse_list))
        .route("/v1/admin/browse/{node_id}/file", get(browse_file))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(state.clone(), local_only_guard))
        .with_state(state)
}

// ---- Local-origin guard (CSRF / DNS-rebinding defense) ----

/// Is `authority` ("host" or "host:port") a legitimate address of this
/// admin plane? The UI and the window shell always use 127.0.0.1 or
/// localhost; anything else in a Host header is the classic DNS-rebinding
/// shape (attacker domain resolving to 127.0.0.1) and must be refused.
fn authority_allowed(authority: &str, admin_port: u16) -> bool {
    let lowered = authority.trim().to_ascii_lowercase();
    // Accept scheme-prefixed forms (Origin/Referer) as well as bare hosts.
    let rest = lowered.strip_prefix("http://").unwrap_or(&lowered);
    let rest = rest.strip_prefix("https://").unwrap_or(rest);
    // Cut off any path/query that Referer may carry.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Split host from :port; an explicit port is required — this plane is
    // never on a default port, and "bare host" requests are not ours.
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    // Trailing dot = FQDN spelling of localhost.
    let host = host.strip_suffix('.').unwrap_or(host);
    port == admin_port.to_string() && (host == "127.0.0.1" || host == "localhost")
}

async fn local_only_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let port = s.inner.admin_port;
    if let Some(host) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !authority_allowed(host, port) {
            tracing::warn!(%host, "admin request with foreign Host header refused");
            return not_found();
        }
    }
    for h in [header::ORIGIN, header::REFERER] {
        if let Some(v) = req.headers().get(&h).and_then(|v| v.to_str().ok()) {
            if v.eq_ignore_ascii_case("null") || !authority_allowed(v, port) {
                tracing::warn!(header = %h, %v, "admin request with foreign origin refused");
                return not_found();
            }
        }
    }
    next.run(req).await
}

/// 404 rather than 403 — do not confirm to a probing page that a service
/// lives on this port.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

// ---- Embedded web UI ----

/// webui/ is compiled into the binary in release builds and read from
/// disk in debug builds (rust-embed's debug-embed feature), so UI edits
/// during development don't need a rebuild.
#[derive(rust_embed::RustEmbed)]
#[folder = "../../webui"]
struct WebUi;

async fn static_file(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match WebUi::get(path) {
        Some(content) => {
            let mime = match path.rsplit('.').next() {
                Some("html") => "text/html; charset=utf-8",
                Some("css") => "text/css; charset=utf-8",
                Some("js") => "text/javascript; charset=utf-8",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                _ => "application/octet-stream",
            };
            let mut response = (
                [(header::CONTENT_TYPE, mime)],
                content.data.into_owned(),
            )
                .into_response();
            // Defense-in-depth for the localhost UI (complements the
            // Host/Origin guard): no third-party origins, no inline scripts.
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                header::HeaderValue::from_static(
                    "default-src 'self'; img-src 'self' data:; style-src 'self'",
                ),
            );
            response.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                header::HeaderValue::from_static("nosniff"),
            );
            response
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse::new(msg)))
}

fn share_err(e: ShareError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match e {
        ShareError::NotFound(_) => StatusCode::NOT_FOUND,
        ShareError::OutsideRoot | ShareError::IsRoot => StatusCode::FORBIDDEN,
        ShareError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    err(status, e.to_string())
}

/// true if `path` lies strictly inside `ancestor` (forward-slash paths).
fn within(path: &str, ancestor: &str) -> bool {
    !ancestor.is_empty()
        && path.len() > ancestor.len()
        && path.starts_with(ancestor)
        && path.as_bytes()[ancestor.len()] == b'/'
}

fn to_grant_info(g: &Grant) -> GrantInfo {
    GrantInfo {
        fingerprint: g.fingerprint.clone(),
        node_id: g.node_id.clone(),
        name: g.name.clone(),
        granted_unix: g.granted_unix,
        expires_unix: g.expires_unix,
        paths: g.paths.clone(),
    }
}

async fn info(State(s): State<AppState>) -> Json<NodeInfo> {
    Json(s.inner.node.clone())
}

// ---- Contacts ----

/// Everything the mDNS browser currently sees on the LAN. Lets the UI
/// show live discovery results and doubles as a diagnostic for firewall
/// / multicast issues ("no peers" usually means UDP 5353 is blocked).
async fn list_peers(State(s): State<AppState>) -> Json<Vec<doclink_core::protocol::Peer>> {
    Json(s.inner.peers.snapshot())
}

async fn list_contacts(State(s): State<AppState>) -> Json<Vec<ContactInfo>> {
    let peers = s.inner.peers.snapshot();
    let contacts = s.inner.contacts.lock().unwrap().read().clone();
    let mut out = Vec::new();
    for c in &contacts.contacts {
        out.push(ContactInfo {
            node_id: c.node_id.clone(),
            alias: c.alias.clone(),
            host: c.host.clone(),
            online: peers.iter().any(|p| p.node_id == c.node_id),
            status: c.status.clone(),
        });
    }
    Json(out)
}

#[derive(Deserialize)]
struct AddContactBody {
    node_id: String,
    alias: String,
    host: Option<String>,
    duration_secs: u64,
}

/// How long to wait for mDNS resolution before falling back to active
/// subnet probing. Generous: multicast + probing + the browser's own
/// resolve round-trip can take a few seconds on real networks.
const DISCOVERY_WAIT: Duration = Duration::from_secs(6);

/// Resolve a DocLink ID to `(base_url, mdns_fingerprint)`: wait for mDNS,
/// then fall back to active /24 probing. A manual `host:port` bypasses
/// discovery entirely (last resort for peers on another subnet).
async fn resolve_peer_base(
    s: &AppState,
    node_id: &str,
    manual_host: Option<&str>,
) -> Option<(String, String)> {
    if let Some(h) = manual_host.map(str::trim).filter(|h| !h.is_empty()) {
        return Some((format!("https://{h}"), String::new()));
    }
    let deadline = Instant::now() + DISCOVERY_WAIT;
    loop {
        if let Some(p) = s
            .inner
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.node_id == node_id)
        {
            return Some((doclink_core::protocol::peer_base_url(&p.addr, p.http_port), p.fingerprint));
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if s.inner.scan_enabled {
        crate::scan::find_node(node_id)
            .await
            .map(|base| (base, String::new()))
    } else {
        None
    }
}

fn valid_node_id(id: &str) -> bool {
    id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Fetch a candidate pairing target's full identity WITHOUT sending a pair
/// request. The Add PC dialog shows this 64-hex fingerprint for explicit
/// out-of-band verification (the DocLink ID alone is only a 64-bit hash).
async fn contact_fingerprint(
    State(s): State<AppState>,
    Query(q): Query<FingerprintQuery>,
) -> Result<Json<NodeInfo>, (StatusCode, Json<ErrorResponse>)> {
    let id = q.node_id.trim().to_lowercase();
    if !valid_node_id(&id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "DocLink ID must be 16 hex characters",
        ));
    }
    if id == s.inner.node.node_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "that's this PC's own DocLink ID",
        ));
    }
    let Some((base, discovered_fp)) = resolve_peer_base(&s, &id, q.host.as_deref()).await else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "peer not found on the LAN — check it is running DocLink, or set Host to its IP:port",
        ));
    };
    let resp = s
        .inner
        .http
        .get(format!("{base}/v1/info"))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("peer unreachable: {e}")))?;
    // Self-certifying check: the TLS certificate must hash to whatever
    // identity the body advertises, or the peer is lying about itself.
    let cert_fp = crate::peer::check(&resp, None)
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let info: NodeInfo = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("bad peer response: {e}")))?;
    if info.node_id != id {
        return Err(err(StatusCode::CONFLICT, "remote node_id mismatch"));
    }
    if !cert_fp.eq_ignore_ascii_case(&info.fingerprint) {
        return Err(err(
            StatusCode::CONFLICT,
            "peer certificate does not match its advertised fingerprint — possible MITM",
        ));
    }
    if !discovered_fp.is_empty() && discovered_fp != info.fingerprint {
        return Err(err(
            StatusCode::CONFLICT,
            "fingerprint mismatch between mDNS and /v1/info — possible spoofing",
        ));
    }
    Ok(Json(info))
}

#[derive(Deserialize)]
struct FingerprintQuery {
    node_id: String,
    #[serde(default)]
    host: Option<String>,
}

/// Normalize a user-supplied DocLink ID (strip separators/spaces, lowercase).
fn normalize_id(raw: &str) -> String {
    raw.trim().to_lowercase().chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect()
}

/// Add a PC by DocLink ID: verify identity, send a signed pair request,
/// persist the contact. The UI must have verified the remote fingerprint
/// via /v1/admin/contact-fingerprint BEFORE calling this.
async fn add_contact(
    State(s): State<AppState>,
    Json(body): Json<AddContactBody>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let id = normalize_id(&body.node_id);
    if !valid_node_id(&id) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "DocLink ID must be 16 hex characters",
        ));
    }
    if id == s.inner.node.node_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "that's this PC's own DocLink ID",
        ));
    }

    let Some((base, _)) = resolve_peer_base(&s, &id, body.host.as_deref()).await else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "peer not found on the LAN — check it is running DocLink and that both PCs are on the same subnet, or set Host (optional) to its IP:port (e.g. 192.168.1.20:37655)",
        ));
    };

    // Verify the target's identity before trusting it with our pubkey.
    let info_resp = s
        .inner
        .http
        .get(format!("{base}/v1/info"))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("peer unreachable: {e}")))?;
    let cert_fp = crate::peer::check(&info_resp, None)
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let remote_info: NodeInfo = info_resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("bad peer response: {e}")))?;
    if remote_info.node_id != id {
        return Err(err(StatusCode::CONFLICT, "remote node_id mismatch"));
    }
    if !cert_fp.eq_ignore_ascii_case(&remote_info.fingerprint) {
        return Err(err(
            StatusCode::CONFLICT,
            "peer certificate does not match its advertised fingerprint — possible MITM",
        ));
    }

    // Build and sign the pair request.
    let req = PairRequest {
        node_id: s.inner.node.node_id.clone(),
        name: s.inner.node.name.clone(),
        pubkey_hex: hex::encode(s.inner.identity.verifying_key().as_bytes()),
        requested_duration_secs: body.duration_secs,
        signature: String::new(),
    };
    let signature = hex::encode(
        s.inner
            .identity
            .sign(canonical_request_string(&req).as_bytes())
            .to_bytes(),
    );
    let req = PairRequest {
        signature,
        ..req
    };

    let resp = s
        .inner
        .http
        .post(format!("{base}/v1/pair/request"))
        .json(&req)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("pair request failed: {e}")))?;
    crate::peer::check(&resp, Some(&remote_info.fingerprint))
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let status: PairStatusResponse = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("bad pair response: {e}")))?;

    let status_str = match status.status {
        PairStatus::Approved => "approved",
        PairStatus::Pending => "pending",
        PairStatus::Denied => "denied",
        PairStatus::Unknown => "unknown",
    };
    let contact = Contact {
        node_id: id,
        alias: body.alias.clone(),
        fingerprint: remote_info.fingerprint.clone(),
        host: body.host.clone(),
        status: status_str.to_string(),
    };
    {
        let mut c = s.inner.contacts.lock().unwrap();
        c.data_mut().upsert(contact);
        c.save()
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(Json(status))
}

async fn remove_contact(
    State(s): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let mut c = s.inner.contacts.lock().unwrap();
    if !c.data_mut().remove(&node_id) {
        return Err(err(StatusCode::NOT_FOUND, "unknown contact"));
    }
    c.save()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Proxy to the data-plane `/v1/pair/status` for a contact. Lets the UI
/// poll the requester's view without CORS or port-crossing.
async fn contact_status(
    State(s): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Find the contact to get its host (manual or from mDNS).
    let contacts = s.inner.contacts.lock().unwrap().read().clone();
    let Some(contact) = contacts
        .contacts
        .iter()
        .find(|c| c.node_id == node_id)
    else {
        return Err(err(StatusCode::NOT_FOUND, "unknown contact"));
    };
    let base = if let Some(h) = &contact.host {
        format!("https://{h}")
    } else {
        // Try to find the peer via mDNS registry.
        let peers = s.inner.peers.snapshot();
        if let Some(p) = peers.iter().find(|p| p.node_id == node_id) {
            doclink_core::protocol::peer_base_url(&p.addr, p.http_port)
        } else {
            return Err(err(StatusCode::NOT_FOUND, "peer not currently reachable"));
        }
    };
    // Signed poll — the peer's /v1/pair/status requires proof of identity.
    let path_q = format!(
        "/v1/pair/status?node_id={}",
        urlencoding::encode(&s.inner.node.node_id)
    );
    let url = format!("{base}{path_q}");
    let mut req = s.inner.http.get(&url);
    for (k, v) in s.inner.identity.auth_headers("GET", &path_q) {
        req = req.header(k, v);
    }
    let resp = req
        .timeout(Duration::from_secs(4))
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("peer unreachable: {e}")))?;
    crate::peer::check(&resp, Some(&contact.fingerprint))
        .map_err(|e| err(StatusCode::BAD_GATEWAY, e))?;
    let status: PairStatusResponse = resp
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("bad peer response: {e}")))?;
    Ok(Json(status))
}

// ---- Incoming requests & grants ----

async fn list_requests(State(s): State<AppState>) -> Json<Vec<PairRequest>> {
    Json(
        s.inner
            .pairing
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|e| e.request.clone())
            .collect(),
    )
}

#[derive(Deserialize)]
struct DecisionBody {
    decision: String, // "approve" | "deny"
    duration_secs: u64, // 0 = until revoked
}

/// Approve or deny an incoming pair request. On approve, the grant is
/// created and the signed decision is pushed to the requester (via mDNS
/// registry or active probe), so its contact status updates immediately.
async fn decide_request(
    State(s): State<AppState>,
    Path(node_id): Path<String>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let resp = server::apply_decision(
        &s.inner.pairing,
        &s.inner.grants,
        &node_id,
        &body.decision,
        body.duration_secs,
    )
    .map_err(|e| err(StatusCode::NOT_FOUND, e))?;

    // Push the decision to the requester so its contact row updates and
    // its browse attempts say "denied" instead of "unknown". Denials are
    // pushed too — otherwise the requester never learns the outcome.
    let _ = push_decision_to_requester(&s, &node_id, &body).await;

    Ok(Json(resp))
}

/// Find the requester (mDNS registry or active probe) and POST the signed
/// decision so its `/v1/pair/status` returns `approved` immediately.
async fn push_decision_to_requester(
    s: &AppState,
    requester_node_id: &str,
    body: &DecisionBody,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Find the requester via mDNS registry first. The contacts lock guard
    // must be dropped before the await below (the future must stay Send).
    let base = {
        let peers = s.inner.peers.snapshot();
        if let Some(p) = peers.iter().find(|p| p.node_id == requester_node_id) {
            doclink_core::protocol::peer_base_url(&p.addr, p.http_port)
        } else {
            let host = s
                .inner
                .contacts
                .lock()
                .unwrap()
                .read()
                .contacts
                .iter()
                .find(|c| c.node_id == requester_node_id)
                .and_then(|c| c.host.clone());
            if let Some(h) = host {
                format!("https://{h}")
            } else {
                // Fallback: active probe (same as Add PC), when allowed.
                let found = if s.inner.scan_enabled {
                    crate::scan::find_node(requester_node_id).await
                } else {
                    None
                };
                if let Some(b) = found {
                    b
                } else {
                    return Err(err(
                        StatusCode::NOT_FOUND,
                        "requester not found on the LAN — decision will apply locally",
                    ));
                }
            }
        }
    };

    // The grantee's pinned fingerprint comes from the grant we just wrote.
    let expected_fp = s
        .inner
        .grants
        .lock()
        .unwrap()
        .read()
        .grants
        .iter()
        .find(|g| g.node_id == requester_node_id)
        .map(|g| g.fingerprint.clone())
        .unwrap_or_default();

    // Build and sign the decision.
    let decision = PairDecision {
        requester_node_id: requester_node_id.to_string(),
        decision: body.decision.clone(),
        duration_secs: body.duration_secs,
        pubkey_hex: hex::encode(s.inner.identity.verifying_key().as_bytes()),
        signature: String::new(),
    };
    let signature = hex::encode(
        s.inner
            .identity
            .sign(canonical_decision_string(&decision).as_bytes())
            .to_bytes(),
    );
    let decision = PairDecision { signature, ..decision };

    // POST to the requester's data plane (fire-and-forget: the catch-up
    // poller covers the case where this never lands).
    let url = format!("{base}/v1/pair/decision");
    if let Ok(resp) = s.inner.http.post(&url).json(&decision).send().await {
        if !expected_fp.is_empty() {
            let _ = crate::peer::check(&resp, Some(&expected_fp));
        }
    }
    Ok(())
}

async fn list_grants(State(s): State<AppState>) -> Json<Vec<GrantInfo>> {
    let grants = s.inner.grants.lock().unwrap().read().clone();
    Json(grants.grants.iter().map(to_grant_info).collect())
}

async fn revoke_grant(
    State(s): State<AppState>,
    Path(fingerprint): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let mut g = s.inner.grants.lock().unwrap();
    let before = g.read().grants.len();
    g.data_mut().grants.retain(|x| x.fingerprint != fingerprint);
    if g.read().grants.len() == before {
        return Err(err(StatusCode::NOT_FOUND, "unknown grant"));
    }
    g.save()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct GrantUpdate {
    /// Empty = full access; otherwise only these paths are visible.
    paths: Vec<String>,
}

/// Change a grant's access scope (which files/folders the grantee sees).
async fn update_grant(
    State(s): State<AppState>,
    Path(fingerprint): Path<String>,
    Json(body): Json<GrantUpdate>,
) -> Result<Json<GrantInfo>, (StatusCode, Json<ErrorResponse>)> {
    let mut g = s.inner.grants.lock().unwrap();
    let info = {
        let Some(grant) = g
            .data_mut()
            .grants
            .iter_mut()
            .find(|x| x.fingerprint == fingerprint)
        else {
            return Err(err(StatusCode::NOT_FOUND, "unknown grant"));
        };
        grant.paths = body.paths;
        to_grant_info(grant)
    };
    g.save()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(info))
}

#[derive(Deserialize)]
struct ShareItemBody {
    path: String,
    fingerprints: Vec<String>,
}

/// Scope value meaning "nothing may be listed or read". The empty list
/// already means full access, so true zero-access needs a sentinel that
/// no real path can ever equal.
const NO_ACCESS: &str = "\u{0}none";

/// Rewrite a grant's scope so that `removed` is no longer visible.
///
/// Subtraction on an allowlist requires recursive expansion: every
/// directory along `removed`'s ancestry that the grant covered is
/// replaced by its surviving descendants, fetched through
/// `children(dir)` (the caller pre-enumerated the ancestor chain,
/// already excluding the removed branch itself). An empty scope (full
/// access) expands starting at the share root. Returns None when the
/// scope did not cover `removed`, or a needed listing was unavailable
/// (fail closed — the scope is left untouched).
fn subtract_from_scope(
    paths: &[String],
    removed: &str,
    mut children: impl FnMut(&str) -> Option<Vec<String>>,
) -> Option<Vec<String>> {
    fn walk(
        dir: &str,
        removed: &str,
        children: &mut impl FnMut(&str) -> Option<Vec<String>>,
    ) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for k in children(dir)? {
            if k == removed {
                continue; // the branch being removed
            }
            if within(removed, &k) {
                // k is an ancestor of removed: descend into survivors.
                out.extend(walk(&k, removed, children)?);
            } else {
                out.push(k);
            }
        }
        Some(out)
    }

    let out: Vec<String> = if paths.is_empty() {
        walk("", removed, &mut children)?
    } else {
        let mut out = Vec::new();
        let mut changed = false;
        for p in paths {
            if p == removed {
                changed = true; // exact match simply disappears
            } else if !p.is_empty() && within(removed, p) {
                // removed lives INSIDE granted dir p.
                changed = true;
                out.extend(walk(p, removed, &mut children)?);
            } else {
                out.push(p.clone());
            }
        }
        if !changed {
            return None;
        }
        out
    };
    Some(if out.is_empty() {
        vec![NO_ACCESS.to_string()]
    } else {
        out
    })
}

/// Item-centric sharing: check/uncheck which granted PCs may see one
/// file or folder. Unchecking works for every grantee: full-access PCs
/// are narrowed to "everything except this item", scoped PCs lose the
/// item even when it was covered via a granted parent folder.
async fn share_item(
    State(s): State<AppState>,
    Json(body): Json<ShareItemBody>,
) -> Result<Json<Vec<GrantInfo>>, (StatusCode, Json<ErrorResponse>)> {
    if body.path.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "path must not be the share root"));
    }
    // The item must actually exist in my share.
    s.inner
        .share
        .resolve(&body.path)
        .map_err(share_err)?;

    // Phase 1 (read lock): does any deselected grant actually cover the
    // item (full access, or a granted ancestor)? If so, the whole
    // ancestor chain of the removed path must be enumerated so the
    // subtraction can expand recursively. (share.list is async, so it
    // cannot run under the store mutex.)
    let mut covers_any = false;
    {
        let g = s.inner.grants.lock().unwrap();
        for gr in &g.read().grants {
            if body.fingerprints.contains(&gr.fingerprint) || covers_any {
                continue;
            }
            covers_any = gr.paths.is_empty()
                || gr
                    .paths
                    .iter()
                    .any(|p| body.path == *p || within(&body.path, p));
        }
    }

    // Phase 2: enumerate the ancestor chain ("" first), minus the
    // removed branch in every listing.
    let mut fetched: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    if covers_any {
        let mut dirs: Vec<String> = vec![String::new()];
        for (i, b) in body.path.bytes().enumerate() {
            if b == b'/' && i + 1 < body.path.len() {
                dirs.push(body.path[..i].to_string());
            }
        }
        for dir in &dirs {
            let kids = match s.inner.share.list(dir).await {
                Ok(entries) => entries
                    .into_iter()
                    .filter(|e| !(e.path == body.path || within(&e.path, &body.path)))
                    .map(|e| e.path)
                    .collect(),
                Err(e) => {
                    tracing::warn!(%e, dir = %dir, "cannot enumerate scope parent for unshare");
                    Vec::new()
                }
            };
            fetched.insert(dir.clone(), kids);
        }
    }

    // Phase 3 (write lock): apply additions and subtractions.
    let mut g = s.inner.grants.lock().unwrap();
    for grant in &mut g.data_mut().grants {
        let wanted = body.fingerprints.contains(&grant.fingerprint);
        if wanted {
            let covered = grant
                .paths
                .iter()
                .any(|p| body.path == *p || within(&body.path, p));
            if !grant.paths.is_empty() && !covered {
                grant.paths.push(body.path.clone());
            }
        } else if let Some(next) = subtract_from_scope(
            &grant.paths.clone(),
            &body.path,
            |d| fetched.get(d).cloned(),
        ) {
            grant.paths = next;
        }
    }
    g.save()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let infos = g.read().grants.iter().map(to_grant_info).collect();
    Ok(Json(infos))
}

// ---- My share (owner-side management) ----

#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
}

async fn myshare_list(
    State(s): State<AppState>,
    Query(q): Query<BrowseQuery>,
) -> Result<Json<ListResponse>, (StatusCode, Json<ErrorResponse>)> {
    let entries = s.inner.share.list(&q.path).await.map_err(share_err)?;
    Ok(Json(ListResponse {
        path: q.path,
        entries,
    }))
}

async fn myshare_delete(
    State(s): State<AppState>,
    Query(q): Query<BrowseQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    s.inner.share.delete(&q.path).await.map_err(share_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Open the share folder in Windows Explorer (convenient for dropping
/// files in). No-op on other platforms.
async fn myshare_reveal(State(s): State<AppState>) -> StatusCode {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("explorer")
            .arg(s.inner.share.root())
            .spawn();
    }
    StatusCode::NO_CONTENT
}

/// Graceful stop, invoked by the window shell's Quit action. Protected by
/// the same local-origin guard as every other admin route.
async fn shutdown_node(State(s): State<AppState>) -> StatusCode {
    tracing::info!("shutdown requested from the admin plane");
    let _ = s.inner.shutdown.send(true);
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    since: u64,
}

/// Toast feed for the window shell: everything newer than `since`.
/// The shell tracks the last id it showed (persisted next to the exe)
/// so toasts survive neither restarts nor duplicates.
async fn events_since(State(s): State<AppState>, Query(q): Query<EventsQuery>) -> Json<Vec<crate::events::Event>> {
    Json(s.inner.events.lock().unwrap().since(q.since))
}

// ---- Browse proxy ----

async fn browse_list(
    State(s): State<AppState>,
    Path(node_id): Path<String>,
    Query(q): Query<BrowseQuery>,
) -> Result<Json<serde_json::Value>, ProxyError> {
    Ok(Json(proxy::list(&s, &node_id, &q.path).await?))
}

async fn browse_file(
    State(s): State<AppState>,
    Path(node_id): Path<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<BrowseQuery>,
) -> Result<Response, ProxyError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    proxy::file(&s, &node_id, &q.path, range.as_deref()).await
}

#[cfg(test)]
mod tests {
    use super::authority_allowed;

    #[test]
    fn accepts_local_hosts_on_admin_port() {
        assert!(authority_allowed("127.0.0.1:37656", 37656));
        assert!(authority_allowed("localhost:37656", 37656));
        assert!(authority_allowed("LOCALHOST:37656", 37656));
        assert!(authority_allowed("127.0.0.1:37656", 37656));
        // Scheme-prefixed Origin/Referer forms.
        assert!(authority_allowed("http://127.0.0.1:37656", 37656));
        assert!(authority_allowed("http://localhost:37656/some/path?x=1", 37656));
        // Trailing-dot FQDN spelling.
        assert!(authority_allowed("localhost.:37656", 37656));
        // Whitespace padding from header parsing quirks.
        assert!(authority_allowed(" localhost:37656 ", 37656));
    }

    #[test]
    fn rejects_everything_else() {
        // DNS rebinding: attacker domain resolving to 127.0.0.1.
        assert!(!authority_allowed("evil.example.com:37656", 37656));
        assert!(!authority_allowed("http://evil.example.com", 37656));
        // Right host, wrong port (e.g. data plane or another service).
        assert!(!authority_allowed("127.0.0.1:37655", 37656));
        assert!(!authority_allowed("localhost:9999", 37656));
        // No port / garbage.
        assert!(!authority_allowed("127.0.0.1", 37656));
        assert!(!authority_allowed("", 37656));
        // Opaque origin ("null") is checked separately by the guard but
        // must never pass through here either.
        assert!(!authority_allowed("null", 37656));
        // Lookalike suffix tricks.
        assert!(!authority_allowed("127.0.0.1.evil.com:37656", 37656));
        assert!(!authority_allowed("evillhost:37656", 37656));
    }

    mod share_scope {
        use super::super::{subtract_from_scope, NO_ACCESS};
        use std::collections::HashMap;

        fn fetcher(
            map: Vec<(&'static str, Vec<&'static str>)>,
        ) -> impl FnMut(&str) -> Option<Vec<String>> {
            let m: HashMap<String, Vec<String>> = map
                .into_iter()
                .map(|(d, kids)| (d.to_string(), kids.into_iter().map(String::from).collect()))
                .collect();
            move |dir| m.get(dir).cloned()
        }

        #[test]
        fn exact_drop_from_scoped_grant() {
            let paths = vec!["docs".into(), "a.txt".into()];
            let next = subtract_from_scope(&paths, "a.txt", |_| None).unwrap();
            assert_eq!(next, vec!["docs"]);
        }

        #[test]
        fn full_access_narrows_to_root_minus_branch() {
            let f = fetcher(vec![
                (
                    "",
                    vec!["docs", "private", "z.txt"],
                ),
                ("private", vec!["private/secret.txt"]),
            ]);
            let next = subtract_from_scope(&[], "private/secret.txt", f).unwrap();
            assert_eq!(next, vec!["docs", "z.txt"]);
        }

        #[test]
        fn covering_parent_expands_to_siblings() {
            // Grant covers everything via ["docs"]; removing docs/a.txt
            // must keep b/ and c.txt visible but drop the a-branch.
            let f = fetcher(vec![(
                "docs",
                vec!["docs/a.txt", "docs/b", "docs/c.txt"],
            )]);
            let next = subtract_from_scope(&["docs".into()], "docs/a.txt", f).unwrap();
            assert_eq!(next, vec!["docs/b", "docs/c.txt"]);
        }

        #[test]
        fn no_coverage_is_a_noop() {
            assert!(subtract_from_scope(&["other".into()], "docs/a.txt", |_| None).is_none());
        }

        #[test]
        fn emptied_scope_becomes_no_access_not_full() {
            // Removing the ONLY child of a granted dir must NOT flip to
            // full access (empty list semantics).
            let f = fetcher(vec![("docs", vec!["docs/gone.txt"])]); // nothing survives
            let next = subtract_from_scope(&["docs".into()], "docs/gone.txt", f).unwrap();
            assert_eq!(next, vec![NO_ACCESS.to_string()]);
        }

        #[test]
        fn deep_target_expands_every_level() {
            // Full access minus drop/nested/file.bin keeps "keep" and the
            // surviving sibling, while empty intermediate dirs collapse.
            let f = fetcher(vec![
                ("", vec!["keep", "drop"]),
                ("drop", vec!["drop/nested"]),
                (
                    "drop/nested",
                    vec!["drop/nested/file.bin", "drop/nested/sibling.txt"],
                ),
            ]);
            let next = subtract_from_scope(&[], "drop/nested/file.bin", f).unwrap();
            assert_eq!(next, vec!["keep", "drop/nested/sibling.txt"]);
        }

        #[test]
        fn missing_listing_fails_closed() {
            // No listing for the covering parent -> scope untouched.
            assert!(subtract_from_scope(&["docs".into()], "docs/a.txt", |_| None).is_none());
        }
    }
}
