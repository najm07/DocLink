//! Data plane (LAN-facing): node info, authenticated share listing and
//! download, and the pairing workflow. See docs/protocol.md.

use crate::auth;
use crate::config::Config;
use crate::share::{ShareError, ShareRoot};
use crate::store::{Grant, GrantsFile, SharedStore};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    canonical_decision_string, canonical_request_string, ErrorResponse, ListResponse, NodeInfo,
    PairDecision, PairRequest, PairStatus, PairStatusResponse,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// In-flight pairing requests and recent decisions (not persisted).
#[derive(Clone, Default)]
pub struct PairingState {
    pub pending: Arc<Mutex<HashMap<String, PairRequest>>>, // keyed by requester node_id
    pub decisions: Arc<Mutex<HashMap<String, PairStatusResponse>>>,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub node: NodeInfo,
    pub share: ShareRoot,
    pub grants: SharedStore<GrantsFile>,
    pub pairing: PairingState,
}

impl AppState {
    pub fn new(
        cfg: &Config,
        node: NodeInfo,
        grants: SharedStore<GrantsFile>,
        pairing: PairingState,
    ) -> Self {
        let share = ShareRoot::new(cfg.share_root.clone()).expect("share root must be creatable");
        Self {
            inner: Arc::new(Inner {
                node,
                share,
                grants,
                pairing,
            }),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/list", get(list))
        .route("/v1/file", get(file))
        .route("/v1/pair/request", post(pair_request))
        .route("/v1/pair/decision", post(pair_decision))
        .route("/v1/pair/status", get(pair_status))
        .with_state(state)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.into(),
        }),
    )
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
) -> Result<Json<ListResponse>, StatusCode> {
    let path_q = format!("/v1/list?path={}", urlencoding::encode(&q.path));
    auth::require_auth(&headers, "GET", &path_q, b"", &s)?;
    let entries = s
        .inner
        .share
        .list(&q.path)
        .map_err(|e| match e {
            ShareError::NotFound(_) => StatusCode::NOT_FOUND,
            ShareError::OutsideRoot => StatusCode::FORBIDDEN,
            ShareError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        })?;
    Ok(Json(ListResponse {
        path: q.path,
        entries,
    }))
}

async fn file(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PathQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let path_q = format!("/v1/file?path={}", urlencoding::encode(&q.path));
    auth::require_auth(&headers, "GET", &path_q, b"", &s)?;
    let path = s.inner.share.resolve(&q.path).map_err(|e| match e {
        ShareError::NotFound(_) => StatusCode::NOT_FOUND,
        ShareError::OutsideRoot => StatusCode::FORBIDDEN,
        ShareError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    })?;
    // TODO(M3): stream with tokio::fs::File + Range header support
    // instead of buffering the whole file in memory.
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let mut out = HeaderMap::new();
    out.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    out.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{name}\"").parse().unwrap(),
    );
    Ok((out, bytes))
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
        if g.expires_unix.map_or(true, |e| e > now) {
            return Ok(Json(PairStatusResponse {
                status: PairStatus::Approved,
                expires_unix: g.expires_unix,
            }));
        }
    }

    s.inner
        .pairing
        .pending
        .lock()
        .unwrap()
        .insert(req.node_id.clone(), req);
    Ok(Json(PairStatusResponse {
        status: PairStatus::Pending,
        expires_unix: None,
    }))
}

/// Grantor -> requester notification. Lets the requester learn the outcome
/// even though it cannot reach the grantor's admin plane (localhost-only).
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
    let resp = apply_decision(
        &s.inner.pairing,
        &s.inner.grants,
        &d.requester_node_id,
        &d.decision,
        d.duration_secs,
    )
    .map_err(|e| err(StatusCode::NOT_FOUND, e))?;
    s.inner
        .pairing
        .decisions
        .lock()
        .unwrap()
        .insert(d.requester_node_id.clone(), resp);
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
        .ok_or("no pending request from this node")?;
    if decision != "approve" {
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
    Query(q): Query<StatusQuery>,
) -> Json<PairStatusResponse> {
    if s.inner.pairing.pending.lock().unwrap().contains_key(&q.node_id) {
        return Json(PairStatusResponse {
            status: PairStatus::Pending,
            expires_unix: None,
        });
    }
    if let Some(d) = s.inner.pairing.decisions.lock().unwrap().get(&q.node_id) {
        return Json(d.clone());
    }
    Json(PairStatusResponse {
        status: PairStatus::Unknown,
        expires_unix: None,
    })
}
