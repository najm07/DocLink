mod admin;
mod auth;
mod config;
mod events;
mod peer;
mod proxy;
mod scan;
mod server;
mod share;
mod store;
mod tls;

use anyhow::{Context, Result};
use clap::Parser;
use doclink_core::discovery::PeerRegistry;
use doclink_core::identity::NodeIdentity;
use doclink_core::protocol::{NodeInfo, PROTOCOL_VERSION};
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

/// Every 15 s, probe every registry peer's data plane (`/v1/info`, 2 s
/// timeout) and refresh its liveness on success. Peers that stop answering
/// are left alone; the registry's snapshot pruning removes them after
/// PEER_TTL_SECS.
async fn run_peer_keepalive(
    http: reqwest::Client,
    registry: PeerRegistry,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                for peer in registry.snapshot() {
                    let url = format!(
                        "{}{}",
                        doclink_core::protocol::peer_base_url(&peer.addr, peer.http_port),
                        "/v1/info"
                    );
                    let ok = http
                        .get(&url)
                        .timeout(std::time::Duration::from_secs(2))
                        .send()
                        .await
                        .map(|r| {
                            // Liveness only: require a well-formed ed25519
                            // cert; the pin (when known) is enforced on
                            // the authenticated paths.
                            crate::peer::check(&r, None).is_ok()
                                && r.status().is_success()
                        })
                        .unwrap_or(false);
                    if ok {
                        registry.touch(&peer.node_id);
                    }
                }
            }
        }
    }
}

/// Resolves when a graceful stop has been requested (admin endpoint or Ctrl-C).
async fn wait_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.changed().await;
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
    // Ctrl-C takes the same graceful path as the admin stop endpoint.
    tokio::spawn({
        let tx = shutdown_tx.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("Ctrl-C — shutting down");
                let _ = tx.send(true);
            }
        }
    });

    let http_port = cfg.http_port();

    // One shared client for all outbound peer calls: pinned-cert HTTPS
    // (danger mode + TlsInfo; verification happens in peer::check). No
    // global timeout — file downloads are long — call sites set their own.
    let http = peer::client();

    // mDNS advertiser: register our service so other PCs can resolve our ID.
    if cfg.advertise() {
        let _advertiser = match doclink_core::discovery::start_advertiser(
            &node.node_id,
            &node.name,
            http_port,
        ) {
            Some(d) => Some(d),
            None => {
                tracing::warn!("mDNS advertising failed — peers cannot discover this PC by ID");
                None
            }
        };
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

    let events = events::shared();
    tokio::spawn(store::run_expiry_sweeper(
        grants.clone(),
        events.clone(),
        shutdown_rx.clone(),
    ));

    // Catch-up poller for pair decisions that never reached us.
    tokio::spawn(store::run_pair_verifier(
        http.clone(),
        contacts.clone(),
        registry.clone(),
        identity.clone(),
        shutdown_rx.clone(),
    ));

    // Liveness keepalive: mdns-sd only re-fires ServiceResolved when a
    // record's content *changes* (identical re-announcements just refresh
    // TTLs), so without this every peer would age out of the registry and
    // show "offline" after PEER_TTL_SECS even while running. We probe the
    // data plane directly instead — that is what "online" actually means.
    tokio::spawn(run_peer_keepalive(
        http.clone(),
        registry.clone(),
        shutdown_rx.clone(),
    ));

    // Data plane: LAN-facing, TLS-only (v0.3), signature-authenticated,
    // read-only, scope-filtered. The certificate is derived from the node
    // identity, so peers pin sha256(SPKI) == fingerprint.
    let data_state = server::AppState::new(&cfg, node.clone(), grants.clone(), contacts.clone(), pairing.clone(), events.clone());
    let data_app = server::router(data_state);
    let data_addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    let data_tcp = tokio::net::TcpListener::bind(data_addr).await?;
    let node_tls = doclink_core::cert::NodeTls::from_identity(&identity)
        .context("deriving node TLS certificate")?;
    let data_tls_cfg = tls::server_config(&node_tls)?;
    info!(%data_addr, "share API (peer-facing) listening on TLS");

    // Admin plane: localhost only — window UI, contacts, approvals, proxy.
    let admin_port = http_port + 1;
    let admin_state = admin::AppState::new(
        node,
        identity,
        registry,
        grants,
        contacts,
        pairing,
        admin_share,
        admin_port,
        cfg.subnet_scan,
        http,
        shutdown_tx,
        events,
    );
    let admin_app = admin::router(admin_state);
    let admin_addr = std::net::SocketAddr::from(([127, 0, 0, 1], admin_port));
    let admin_tcp = tokio::net::TcpListener::bind(admin_addr).await?;
    info!(%admin_addr, "web UI listening — open http://{}", admin_addr);

    // Publish the actual bound port so doclink-win (and other local
    // tools) can find this instance even with a --port override.
    let _ = std::fs::write("doclink-admin.port", admin_port.to_string());

    let data = tls::serve(data_tcp, data_app, data_tls_cfg, shutdown_rx.clone());
    let admin = axum::serve(admin_tcp, admin_app).with_graceful_shutdown(wait_shutdown(shutdown_rx));
    tokio::try_join!(
        async { data.await.map_err(anyhow::Error::from) },
        async { admin.await.map_err(anyhow::Error::from) }
    )?;
    Ok(())
}
