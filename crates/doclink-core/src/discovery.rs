//! mDNS discovery: advertise our presence and resolve other PCs' DocLink IDs
//! to (ip, port) without any central server or static IPs. This is the same
//! model that made PrintLink's discovery reliable on mixed networks.
//!
//! Service type: _doclink._tcp.local
//! Instance name: doclink-<node_id>._doclink._tcp.local
//! Properties: node_id (hex), http_port (decimal)
//!
//! The browser runs continuously and updates the registry; the advertiser
//! can be disabled (via config) so a PC can stay hidden while still adding
//! others.

use crate::protocol::{Peer, PEER_TTL_SECS};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MDNS_SERVICE_TYPE: &str = "_doclink._tcp.local.";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Tracks recently-seen peers. Cloning shares the same underlying map.
#[derive(Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<Mutex<HashMap<String, Peer>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Currently-reachable peers (stale entries pruned on read).
    pub fn snapshot(&self) -> Vec<Peer> {
        let mut peers = self.peers.lock().unwrap();
        let now = unix_now();
        peers.retain(|_, p| now.saturating_sub(p.last_seen_unix) <= PEER_TTL_SECS);
        peers.values().cloned().collect()
    }

    fn upsert(&self, peer: Peer) {
        self.peers
            .lock()
            .unwrap()
            .insert(peer.node_id.clone(), peer);
    }
}

/// Primary interface IPv4, derived from the routing table.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// mDNS advertiser: registers our service so other PCs can resolve our ID.
/// Returns a handle that can be dropped to stop advertising.
pub fn start_advertiser(
    node_id: &str,
    name: &str,
    http_port: u16,
) -> Option<ServiceDaemon> {
    let daemon = ServiceDaemon::new().ok()?;
    let ip = primary_ipv4()?;
    let instance_name = format!("doclink-{}.{}", node_id, MDNS_SERVICE_TYPE);
    let mut props = HashMap::new();
    props.insert("node_id".to_string(), node_id.to_string());
    props.insert("http_port".to_string(), http_port.to_string());
    let service = ServiceInfo::new(
        MDNS_SERVICE_TYPE,
        &instance_name,
        name,
        ip.to_string(),
        http_port,
        props,
    )
    .ok()?;
    if daemon.register(service).is_err() {
        return None;
    }
    Some(daemon)
}

/// mDNS browser: watches for _doclink._tcp.local services and updates the
/// registry with any peers we see. Runs until shutdown.
pub async fn run_browser(
    registry: PeerRegistry,
    self_node_id: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let Ok(daemon) = ServiceDaemon::new() else {
        return;
    };
    let Ok(rx) = daemon.browse(MDNS_SERVICE_TYPE) else {
        return;
    };

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                while let Ok(event) = rx.try_recv() {
                    use mdns_sd::ServiceEvent::*;
                    match event {
                        ServiceFound(_, _) | ServiceRemoved(_, _) => {}
                        ServiceResolved(info) => {
                            let props = info.get_properties();
                            let Some(node_id) = props.get("node_id").map(|s| s.to_string()) else { continue };
                            if node_id == self_node_id {
                                continue;
                            }
                            let http_port = props
                                .get("http_port")
                                .and_then(|p| p.val_str().map(|s| s.parse::<u16>().ok()).flatten())
                                .unwrap_or(37656);
                            let addr = info.get_addresses().iter().next().map(|a| a.to_string());
                            if let Some(addr) = addr {
                                registry.upsert(Peer {
                                    node_id,
                                    name: info.get_fullname().to_string(),
                                    addr,
                                    http_port,
                                    fingerprint: String::new(),
                                    last_seen_unix: unix_now(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
