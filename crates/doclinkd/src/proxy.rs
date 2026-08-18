//! Daemon-side proxy: the browser talks only to the local admin plane;
//! the daemon signs each request and forwards it to the selected peer.
//! Peers are located via discovery first, then the contact's manual host.

use crate::admin::AppState;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::ErrorResponse;
use std::time::{SystemTime, UNIX_EPOCH};

struct PeerTarget {
    base: String,
}

#[derive(Debug)]
pub enum ProxyError {
    UnknownPeer,
    Upstream(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ProxyError::UnknownPeer => (
                StatusCode::NOT_FOUND,
                "unknown or offline peer".to_string(),
            ),
            ProxyError::Upstream(m) => (StatusCode::BAD_GATEWAY, m),
        };
        (status, axum::Json(ErrorResponse { error: msg })).into_response()
    }
}

fn peer_lookup(s: &AppState, node_id: &str) -> Result<PeerTarget, ProxyError> {
    let contacts = s.inner.contacts.lock().unwrap().read().clone();
    if !contacts.contacts.iter().any(|c| c.node_id == node_id) {
        return Err(ProxyError::UnknownPeer);
    }
    if let Some(peer) = s
        .inner
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.node_id == node_id)
    {
        return Ok(PeerTarget {
            base: format!("http://{}:{}", peer.addr, peer.http_port),
        });
    }
    if let Some(host) = contacts
        .contacts
        .iter()
        .find(|c| c.node_id == node_id)
        .and_then(|c| c.host.clone())
    {
        return Ok(PeerTarget {
            base: format!("http://{host}"),
        });
    }
    Err(ProxyError::UnknownPeer)
}

/// The four authentication headers defined in docs/protocol.md §4.
fn sign_request(identity: &NodeIdentity, method: &str, path_q: &str) -> Vec<(String, String)> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string();
    let canonical = format!("{method}\n{path_q}\n{ts}\n");
    let sig = identity.sign(canonical.as_bytes());
    vec![
        ("x-doclink-node".into(), identity.node_id()),
        (
            "x-doclink-pub".into(),
            hex::encode(identity.verifying_key().as_bytes()),
        ),
        ("x-doclink-ts".into(), ts),
        ("x-doclink-sig".into(), hex::encode(sig.to_bytes())),
    ]
}

fn signed_get(s: &AppState, base: &str, path_q: &str) -> reqwest::RequestBuilder {
    let req = reqwest::Client::new().get(format!("{base}{path_q}"));
    sign_request(&s.inner.identity, "GET", path_q)
        .into_iter()
        .fold(req, |r, (k, v)| r.header(k, v))
}

pub async fn list(
    s: &AppState,
    node_id: &str,
    path: &str,
) -> Result<serde_json::Value, ProxyError> {
    let target = peer_lookup(s, node_id)?;
    let path_q = format!("/v1/list?path={}", urlencoding::encode(path));
    let resp = signed_get(s, &target.base, &path_q)
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if !status.is_success() {
        return Err(ProxyError::Upstream(format!("peer returned {status}: {body}")));
    }
    serde_json::from_str(&body)
        .map_err(|e| ProxyError::Upstream(format!("invalid peer response: {e}")))
}

pub async fn file(s: &AppState, node_id: &str, path: &str) -> Result<Response, ProxyError> {
    let target = peer_lookup(s, node_id)?;
    let path_q = format!("/v1/file?path={}", urlencoding::encode(path));
    let resp = signed_get(s, &target.base, &path_q)
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let cdisp = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if !status.is_success() {
        let msg = String::from_utf8_lossy(&bytes).to_string();
        return Err(ProxyError::Upstream(format!("peer returned {status}: {msg}")));
    }
    let name = path.rsplit('/').next().unwrap_or("download");
    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, ctype.parse().unwrap());
    out.insert(
        header::CONTENT_DISPOSITION,
        cdisp
            .unwrap_or_else(|| format!("attachment; filename=\"{name}\""))
            .parse()
            .unwrap(),
    );
    Ok((out, bytes.to_vec()).into_response())
}
