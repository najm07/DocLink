//! Admin plane (127.0.0.1 only): window UI, contacts, approvals,
//! revocation, and the signed browse proxy. Never bound to a LAN
//! interface — management operations are unreachable from the network.

use crate::proxy::{self, ProxyError};
use crate::server::{self, PairingState};
use crate::store::{Contact, ContactsFile, GrantsFile, SharedStore};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use doclink_core::discovery::PeerRegistry;
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    canonical_request_string, ContactInfo, ErrorResponse, GrantInfo, NodeInfo, PairRequest,
    PairStatus, PairStatusResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::services::ServeDir;

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
}

impl AppState {
    pub fn new(
        node: NodeInfo,
        identity: NodeIdentity,
        peers: PeerRegistry,
        grants: SharedStore<GrantsFile>,
        contacts: SharedStore<ContactsFile>,
        pairing: PairingState,
    ) -> Self {
        Self {
            inner: Arc::new(AdminInner {
                node,
                identity,
                peers,
                grants,
                contacts,
                pairing,
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
        .route("/v1/admin/grants/{fingerprint}", delete(revoke_grant))
        .route("/v1/admin/browse/{node_id}/list", get(browse_list))
        .route("/v1/admin/browse/{node_id}/file", get(browse_file))
        .fallback_service(ServeDir::new("webui"))
        .with_state(state)
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.into(),
        }),
    )
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

/// Add a PC by DocLink ID: locate it (discovery, or manual host:port),
/// verify its identity, send a signed pair request, persist the contact.
async fn add_contact(
    State(s): State<AppState>,
    Json(body): Json<AddContactBody>,
) -> Result<Json<PairStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let target = {
        let peers = s.inner.peers.snapshot();
        peers
            .into_iter()
            .find(|p| p.node_id == body.node_id)
            .map(|p| (format!("http://{}:{}", p.addr, p.http_port), p.fingerprint))
            .or_else(|| {
                body.host
                    .clone()
                    .map(|h| (format!("http://{h}"), String::new()))
            })
    };
    let Some((base, discovered_fp)) = target else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "peer not seen on the LAN — provide host:port",
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
            "fingerprint mismatch between beacon and /v1/info — possible spoofing",
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
    Ok(Json(PairStatusResponse {
        status: resp.status,
        expires_unix: resp.expires_unix,
    }))
}

async fn list_grants(State(s): State<AppState>) -> Json<Vec<GrantInfo>> {
    let grants = s.inner.grants.lock().unwrap().read().clone();
    Json(
        grants
            .grants
            .iter()
            .map(|g| GrantInfo {
                fingerprint: g.fingerprint.clone(),
                node_id: g.node_id.clone(),
                name: g.name.clone(),
                granted_unix: g.granted_unix,
                expires_unix: g.expires_unix,
            })
            .collect(),
    )
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

// ---- Browse proxy ----

#[derive(Deserialize)]
struct BrowseQuery {
    #[serde(default)]
    path: String,
}

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
