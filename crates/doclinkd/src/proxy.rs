//! Daemon-side proxy: the browser talks only to the local admin plane;
//! the daemon signs each request and forwards it to the selected peer.
//! Peers are located via discovery first, then the contact's manual host.

use crate::admin::AppState;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::ErrorResponse;

struct PeerTarget {
    base: String,
    /// Fingerprint to pin the TLS connection against ("" = unknown).
    fingerprint: String,
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
        (status, axum::Json(ErrorResponse::new(msg))).into_response()
    }
}

/// Surface the upstream error's human message verbatim — the data plane
/// already phrases pending/denied/expired for end users. Only fall back
/// to the noisy "peer returned …" wrapper when the body is not one of
/// ours.
fn upstream_message(status: StatusCode, body: &str) -> String {
    match serde_json::from_str::<ErrorResponse>(body) {
        Ok(e) if !e.error.is_empty() => e.error,
        _ => format!("peer returned {status}: {body}"),
    }
}

fn peer_lookup(s: &AppState, node_id: &str) -> Result<PeerTarget, ProxyError> {
    let contacts = s.inner.contacts.lock().unwrap().read().clone();
    let known = contacts
        .contacts
        .iter()
        .find(|c| c.node_id == node_id)
        .ok_or(ProxyError::UnknownPeer)?
        .clone();
    if let Some(peer) = s
        .inner
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.node_id == node_id)
    {
        return Ok(PeerTarget {
            base: doclink_core::protocol::peer_base_url(&peer.addr, peer.http_port),
            fingerprint: known.fingerprint,
        });
    }
    if let Some(host) = known.host.clone() {
        return Ok(PeerTarget {
            base: format!("https://{host}"),
            fingerprint: known.fingerprint,
        });
    }
    Err(ProxyError::UnknownPeer)
}

/// The four authentication headers defined in docs/protocol.md §4.
fn sign_request(identity: &NodeIdentity, method: &str, path_q: &str) -> Vec<(String, String)> {
    identity.auth_headers(method, path_q)
}

fn signed_get(s: &AppState, base: &str, path_q: &str) -> reqwest::RequestBuilder {
    let req = s.inner.http.get(format!("{base}{path_q}"));
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
    crate::peer::check(&resp, Some(&target.fingerprint))
        .map_err(ProxyError::Upstream)?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    if !status.is_success() {
        return Err(ProxyError::Upstream(upstream_message(status, &body)));
    }
    serde_json::from_str(&body)
        .map_err(|e| ProxyError::Upstream(format!("invalid peer response: {e}")))
}

pub async fn file(
    s: &AppState,
    node_id: &str,
    path: &str,
    range: Option<&str>,
) -> Result<Response, ProxyError> {
    let target = peer_lookup(s, node_id)?;
    let path_q = format!("/v1/file?path={}", urlencoding::encode(path));
    let mut req = signed_get(s, &target.base, &path_q);
    if let Some(r) = range {
        req = req.header(header::RANGE, r);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
    crate::peer::check(&resp, Some(&target.fingerprint))
        .map_err(ProxyError::Upstream)?;
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
    let content_range = resp
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_length = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if !status.is_success() {
        let msg = resp.text().await.unwrap_or_default();
        return Err(ProxyError::Upstream(upstream_message(status, &msg)));
    }
    // Stream the body straight through — never buffer a whole file here.
    let name = path.rsplit('/').next().unwrap_or("download");
    let mut out = HeaderMap::new();
    if let Ok(v) = ctype.parse() {
        out.insert(header::CONTENT_TYPE, v);
    }
    let cd = cdisp.unwrap_or_else(|| format!("attachment; filename=\"{name}\""));
    if let Ok(v) = cd.parse() {
        out.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Some(len) = content_length {
        if let Ok(v) = len.to_string().parse() {
            out.insert(header::CONTENT_LENGTH, v);
        }
    }
    let status_out = if content_range.is_some() || status == StatusCode::PARTIAL_CONTENT {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    if let Some(cr) = content_range {
        if let Ok(v) = cr.parse() {
            out.insert(header::CONTENT_RANGE, v);
        }
    }
    let body = axum::body::Body::from_stream(resp.bytes_stream());
    let mut response = (out, body).into_response();
    *response.status_mut() = status_out;
    Ok(response)
}
