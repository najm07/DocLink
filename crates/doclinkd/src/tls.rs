//! v0.3 data-plane TLS: rustls server config from the node's derived
//! certificate, plus an accept loop serving the axum router over it.
//! The admin plane stays plain HTTP on localhost — only LAN traffic
//! is encrypted.

use anyhow::Result;
use axum::Router;
use doclink_core::cert::NodeTls;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

pub fn server_config(tls: &NodeTls) -> Result<Arc<rustls::ServerConfig>> {
    // Explicit provider: several crates in the tree enable rustls
    // features, so automatic detection is ambiguous (and panics).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(tls.cert_der.clone())],
            PrivatePkcs8KeyDer::from(tls.key_der.clone()).into(),
        )?;
    Ok(Arc::new(cfg))
}

/// Accept loop for the TLS data plane. Each handshake + connection runs
/// on its own task; shutdown closes the listener (in-flight downloads
/// finish or drop with the process — acceptable for a desktop app).
pub async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    tls_cfg: Arc<rustls::ServerConfig>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
    loop {
        let (tcp, addr) = tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => { tracing::warn!(%e, "data-plane accept error"); continue; }
            },
        };
        let acceptor = acceptor.clone();
        // Re-attach the socket address as ConnectInfo so handlers and the
        // pairing rate-limiter see it exactly like axum::serve does for TCP.
        let app = app
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(addr)));
        let service = TowerToHyperService::new(app);
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(stream) => {
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await;
                }
                Err(e) => tracing::debug!(%e, "TLS handshake failed"),
            }
        });
    }
}
