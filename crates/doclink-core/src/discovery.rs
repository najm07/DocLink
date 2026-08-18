//! LAN peer discovery via UDP broadcast beacons.
//!
//! Every node broadcasts a [`Beacon`] every BEACON_INTERVAL_SECS and
//! listens for beacons from others. A peer is online until it has
//! been silent for PEER_TTL_SECS.
//!
//! Discovery is only an address book (node_id -> current IP + port).
//! Trust comes from pairing, never from presence on the network.
//!
//! Notes:
//! - The listener binds with SO_REUSEADDR (+ SO_REUSEPORT on unix) so
//!   multiple nodes can run on one machine for testing.
//! - Beacons go to the limited broadcast address AND to loopback, so
//!   same-machine instances discover each other even when the network
//!   stack doesn't loop broadcasts back.
//!
//! TODO(interop): align beacon fields with PrintLink's discovery
//! format (Printlink repo, agent/discovery.py) so both ecosystems
//! can share a network segment and compose (e.g. print-on-host).

use crate::protocol::{Beacon, Peer, BEACON_INTERVAL_SECS, DISCOVERY_PORT, PEER_TTL_SECS};
use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

#[derive(Clone, Default)]
pub struct PeerRegistry {
    peers: Arc<Mutex<HashMap<String, Peer>>>,
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, beacon: Beacon, addr: std::net::SocketAddr) {
        let peer = Peer {
            node_id: beacon.node_id.clone(),
            name: beacon.name,
            addr: addr.ip().to_string(),
            http_port: beacon.http_port,
            fingerprint: beacon.fingerprint,
            last_seen_unix: unix_now(),
        };
        self.peers.lock().unwrap().insert(beacon.node_id, peer);
    }

    /// All peers seen within the TTL; stale entries are pruned.
    pub fn snapshot(&self) -> Vec<Peer> {
        let now = unix_now();
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|_, p| now.saturating_sub(p.last_seen_unix) <= PEER_TTL_SECS);
        let mut out: Vec<Peer> = peers.values().cloned().collect();
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        out
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Broadcast our presence until shutdown is signalled. Each beacon goes
/// to the limited broadcast address (other machines) and to loopback
/// (other instances on this machine).
pub async fn run_broadcast(
    beacon: Beacon,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    let payload = serde_json::to_vec(&beacon)?;
    let targets = [
        format!("255.255.255.255:{DISCOVERY_PORT}"),
        format!("127.0.0.1:{DISCOVERY_PORT}"),
    ];
    let mut interval = tokio::time::interval(Duration::from_secs(BEACON_INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                for target in &targets {
                    if let Err(e) = socket.send_to(&payload, target).await {
                        warn!(%e, %target, "discovery broadcast failed");
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
    Ok(())
}

/// Listen for other nodes' beacons and keep the registry fresh.
/// SO_REUSEADDR lets several nodes share the port on one machine;
/// broadcast beacons are then delivered to every bound listener.
pub async fn run_listener(
    registry: PeerRegistry,
    own_node_id: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    let bind_addr: std::net::SocketAddr = ([0, 0, 0, 0], DISCOVERY_PORT).into();
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket)?;

    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, addr) = recv?;
                if let Ok(b) = serde_json::from_slice::<Beacon>(&buf[..n]) {
                    if b.is_valid() && b.node_id != own_node_id {
                        debug!(peer = %b.name, %addr, "beacon received");
                        registry.upsert(b, addr);
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
    Ok(())
}
