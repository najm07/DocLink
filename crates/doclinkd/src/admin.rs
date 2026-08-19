//! Admin plane (127.0.0.1 only): window UI, contacts, approvals,
//! revocation, per-item share scoping, own-share management, and the
//! signed browse proxy. Never bound to a LAN interface — management
//! operations are unreachable from the network.

use crate::proxy::{self, ProxyError};
use crate::server::{self, PairingState};
use crate::share::{ShareError, ShareRoot};
use crate::store::{Contact, ContactsFile, Grant, GrantsFile, SharedStore};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use doclink_core::discovery::PeerRegistry;
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    canonical_request_string, ContactInfo, ErrorResponse, GrantInfo, ListResponse, NodeInfo,
    PairRequest, PairStatus, PairStatusResponse,
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
}

impl AppState {
    pub fn new(
        node: NodeInfo,
        identity: NodeIdentity,
        peers: PeerRegistry,
        grants: SharedStore<GrantsFile>,
        contacts: SharedStore<ContactsFile>,
        pairing: PairingState,
        share: ShareRoot,
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
            }),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/info", get(info))
        .route("/v1/admin/contacts", get(list_contacts).post(add_contact))
        .route("/v1/admin/contacts/{node_id}", delete(remove_contact))
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
        .route("/v1/admin/browse/{node_id}/list", get(browse_list))
        .route("/v1/admin/browse/{node_id}/file", get(browse_file))
        .fallback(static_file)
        .with_state(state)
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
            (
                [(header::CONTENT_TYPE, mime)],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.into(),
        }),
    )
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
/// subnet probing.
const DISCOVERY_WAIT: Duration = Duration::from_secs(3);

/// Add a PC by DocLink ID: resolve via mDNS (instant on most networks),
/// then fall back to active /24 probing if needed, verify identity,
/// send a signed pair request, persist the contact. A manual host:port
/// remains as the last-resort fallback for peers on a different subnet.
async fn add_contact(
    State(s): State<AppState>,
    Json(body): Json<AddContactBody>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    if body.node_id == s.inner.node.node_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "that's this PC's own DocLink ID",
        ));
    }

    let target = if let Some(h) = body.host.clone() {
        Some((format!("http://{h}"), String::new()))
    } else {
        let deadline = Instant::now() + DISCOVERY_WAIT;
        let mut found = None;
        loop {
            if let Some(p) = s
                .inner
                .peers
                .snapshot()
                .into_iter()
                .find(|p| p.node_id == body.node_id)
            {
                found = Some((format!("http://{}:{}", p.addr, p.http_port), p.fingerprint));
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if found.is_none() {
            // mDNS didn't surface the peer: actively probe the local subnet.
            if let Some(base) = crate::scan::find_node(&body.node_id).await {
                found = Some((base, String::new()));
            }
        }
        found
    };
    let Some((base, discovered_fp)) = target else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "peer not found on the LAN — check it is running DocLink and that both PCs are on the same subnet, or set Host (optional) to its IP:port (e.g. 192.168.1.20:37655)",
        ));
    };

    // Verify the target's identity before trusting it with our pubkey.
    let remote_info: NodeInfo = reqwest::get(format!("{base}/v1/info"))
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("peer unreachable: {e}")))?
        .json()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("bad peer response: {e}")))?;
    if remote_info.node_id != body.node_id {
        return Err(err(StatusCode::CONFLICT, "remote node_id mismatch"));
    }
    if !discovered_fp.is_empty() && discovered_fp != remote_info.fingerprint {
        return Err(err(
            StatusCode::CONFLICT,
            "fingerprint mismatch between mDNS and /v1/info — possible spoofing",
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

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/pair/request"))
        .json(&req)
        .send()
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("pair request failed: {e}")))?;
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
        node_id: body.node_id.clone(),
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

// ---- Incoming requests & grants ----

async fn list_requests(State(s): State<AppState>) -> Json<Vec<PairRequest>> {
    Json(
        s.inner
            .pairing
            .pending
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect(),
    )
}

#[derive(Deserialize)]
struct DecisionBody {
    decision: String, // "approve" | "deny"
    duration_secs: u64, // 0 = until revoked
}

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
    Ok(Json(resp))
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

/// Item-centric sharing: check/uncheck which granted PCs may see one
/// file or folder. Full-access grants (empty paths) already cover the
/// item and are left untouched; scoped grants gain or lose the path.
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
        } else {
            grant
                .paths
                .retain(|p| *p != body.path && !within(p, &body.path));
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
    let entries = s.inner.share.list(&q.path).map_err(share_err)?;
    Ok(Json(ListResponse {
        path: q.path,
        entries,
    }))
}

async fn myshare_delete(
    State(s): State<AppState>,
    Query(q): Query<BrowseQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    s.inner.share.delete(&q.path).map_err(share_err)?;
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
    Query(q): Query<BrowseQuery>,
) -> Result<Response, ProxyError> {
    proxy::file(&s, &node_id, &q.path).await
}
