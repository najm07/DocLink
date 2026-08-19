mod admin;
mod auth;
mod config;
mod proxy;
mod scan;
mod server;
mod share;
mod store;

use anyhow::{Context, Result};
use clap::Parser;
use doclink_core::discovery::{self, PeerRegistry};
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{Beacon, NodeInfo, PROTOCOL_VERSION};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "doclinkd", about = "DocLink node daemon")]
struct Cli {
    /// Path to the config file (default: ./doclink.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override the data-plane port (admin plane = port + 1).
    /// Useful for a second instance on the same machine.
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut cfg = config::Config::load(cli.config.as_deref()).context("loading config")?;
    if let Some(p) = cli.port {
        cfg.http_port = p;
    }
    let identity = NodeIdentity::load_or_generate(&cfg.identity_key_path())?;

    let node = NodeInfo {
        node_id: identity.node_id(),
        name: cfg.node_name(),
        version: PROTOCOL_VERSION.to_string(),
        fingerprint: identity.fingerprint(),
    };
    info!(name = %node.name, "doclinkd starting");
    info!(id = %node.node_id, "your DocLink ID — share it with PCs that want to add you");

    let registry = PeerRegistry::new();
    let grants = store::open(&cfg.grants_path())?;
    let contacts = store::open(&cfg.contacts_path())?;
    let pairing = server::PairingState::default();
    let admin_share = share::ShareRoot::new(&cfg.share_root).context("opening share root")?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let http_port = cfg.http_port();

    // mDNS advertiser: register our service so other PCs can resolve our ID.
    if cfg.advertise() {
        let _advertiser = doclink_core::discovery::start_advertiser(
            &node.node_id,
            &node.name,
            http_port,
        );
        info!("advertising on mDNS as _doclink._tcp.local");
    } else {
        info!("mDNS advertising disabled — this PC is hidden from discovery");
    }

    // mDNS browser: watch for other PCs and populate the registry.
    tokio::spawn(doclink_core::discovery::run_browser(
        registry.clone(),
        node.node_id.clone(),
        shutdown_rx.clone(),
    ));

    tokio::spawn(store::run_expiry_sweeper(grants.clone(), shutdown_rx));

    // Data plane: LAN-facing, signature-authenticated, read-only, scope-filtered.
    let data_state = server::AppState::new(&cfg, node.clone(), grants.clone(), pairing.clone());
    let data_app = server::router(data_state);
    let data_addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    let data_tcp = tokio::net::TcpListener::bind(data_addr).await?;
    info!(%data_addr, "share API (peer-facing) listening");

    // Admin plane: localhost only — window UI, contacts, approvals, proxy.
    let admin_state = admin::AppState::new(
        node,
        identity,
        registry,
        grants,
        contacts,
        pairing,
        admin_share,
    );
    let admin_app = admin::router(admin_state);
    let admin_addr = std::net::SocketAddr::from(([127, 0, 0, 1], http_port + 1));
    let admin_tcp = tokio::net::TcpListener::bind(admin_addr).await?;
    info!(%admin_addr, "web UI listening — open http://{}", admin_addr);

    // TODO(M3): graceful shutdown on Ctrl-C / service stop.
    let data = axum::serve(
        data_tcp,
        data_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );
    let admin = axum::serve(admin_tcp, admin_app);
    tokio::try_join!(data, admin)?;

    shutdown_tx.send(true).ok();
    Ok(())
}
