//! HTTP API: node info, share listing, file download, peer list,
//! plus the static web UI. See docs/protocol.md.

use crate::config::Config;
use crate::share::{ShareError, ShareRoot};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use doclink_core::discovery::PeerRegistry;
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{
    ErrorResponse, ListResponse, NodeInfo, Peer, PROTOCOL_VERSION,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    node: NodeInfo,
    share: ShareRoot,
    peers: PeerRegistry,
}

impl AppState {
    pub fn new(cfg: Config, identity: NodeIdentity, peers: PeerRegistry) -> Self {
        let share = ShareRoot::new(cfg.share_root.clone()).expect("share root must be creatable");
        Self {
            inner: Arc::new(Inner {
                node: NodeInfo {
                    node_id: identity.node_id(),
                    name: cfg.node_name(),
                    version: PROTOCOL_VERSION.to_string(),
                    fingerprint: identity.fingerprint(),
                },
                share,
                peers,
            }),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/list", get(list))
        .route("/v1/file", get(file))
        .route("/v1/peers", get(peers))
        // TODO(M2): /v1/peers/{id}/list and /v1/peers/{id}/file —
        // daemon-side proxy so the browser only ever talks to localhost.
        .fallback_service(ServeDir::new("webui"))
        .with_state(state)
}

async fn info(State(s): State<AppState>) -> Json<NodeInfo> {
    Json(s.inner.node.clone())
}

async fn peers(State(s): State<AppState>) -> Json<Vec<Peer>> {
    Json(s.inner.peers.snapshot())
}

#[derive(Deserialize)]
struct PathQuery {
    /// Path relative to the share root ("" = root).
    #[serde(default)]
    path: String,
}

async fn list(
    State(s): State<AppState>,
    Query(q): Query<PathQuery>,
) -> Result<Json<ListResponse>, ApiError> {
    let entries = s.inner.share.list(&q.path)?;
    Ok(Json(ListResponse {
        path: q.path,
        entries,
    }))
}

async fn file(
    State(s): State<AppState>,
    Query(q): Query<PathQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let path = s.inner.share.resolve(&q.path)?;
    // TODO(M3): stream with tokio::fs::File + Range header support
    // instead of buffering the whole file in memory.
    let bytes = tokio::fs::read(&path).await.map_err(ShareError::Io)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".into());
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/octet-stream".parse().unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{name}\"").parse().unwrap(),
    );
    Ok((headers, bytes))
}

struct ApiError(ShareError);

impl From<ShareError> for ApiError {
    fn from(e: ShareError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self.0 {
            ShareError::NotFound(_) => StatusCode::NOT_FOUND,
            ShareError::OutsideRoot => StatusCode::FORBIDDEN,
            ShareError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: self.0.to_string(),
            }),
        )
            .into_response()
    }
}
