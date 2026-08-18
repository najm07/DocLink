mod config;
mod server;
mod share;

use anyhow::{Context, Result};
use clap::Parser;
use doclink_core::discovery::{self, PeerRegistry};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::Beacon;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "doclinkd", about = "DocLink node daemon")]
struct Cli {
    /// Path to the config file (default: ./doclink.toml)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cfg = config::Config::load(cli.config.as_deref()).context("loading config")?;
    let identity = NodeIdentity::load_or_generate(&cfg.identity_key_path())?;

    info!(node_id = %identity.node_id(), name = %cfg.node_name(), "doclinkd starting");

    let registry = PeerRegistry::new();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let http_port = cfg.http_port();
    let beacon = Beacon::new(
        identity.node_id(),
        cfg.node_name(),
        http_port,
        identity.fingerprint(),
    );
    let broadcast = tokio::spawn(discovery::run_broadcast(beacon, shutdown_rx.clone()));
    let listener = tokio::spawn(discovery::run_listener(
        registry.clone(),
        identity.node_id(),
        shutdown_rx,
    ));

    let state = server::AppState::new(cfg, identity, registry);
    let app = server::router(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    info!(%addr, "share API + web UI listening");
    let tcp = tokio::net::TcpListener::bind(addr).await?;

    // TODO(M3): graceful shutdown on Ctrl-C / service stop.
    axum::serve(tcp, app).await?;

    shutdown_tx.send(true).ok();
    let _ = tokio::join!(broadcast, listener);
    Ok(())
}
