//! UDP discovery: beacons announce presence; the registry tracks who is
//! currently reachable. Discovery is only an address book — trust comes
//! from pairing, not presence.
//!
//! Beacons are announced to every plausible destination:
//!   * 255.255.255.255 — limited broadcast; on machines with virtual NICs
//!     (Hyper-V/WSL/VPN) Windows often routes this out the wrong adapter
//!   * the /24 subnet-directed broadcast of the primary interface
//!     (e.g. 192.168.1.255) — routed via the correct adapter, which is
//!     how PrintLink's discovery reliably reached the LAN
//!   * 127.0.0.1 — so same-machine instances (second node via --port)
//!     can find each other
//! The listener binds 0.0.0.0 with SO_REUSEADDR (and SO_REUSEPORT on
//! unix) so several nodes can share one machine.

use crate::protocol::{Beacon, Peer, BEACON_INTERVAL_SECS, DISCOVERY_PORT, PEER_TTL_SECS};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// Primary interface IPv4, derived from the routing table. The UDP
/// "connect" sends no packets — it just makes the OS pick the interface
/// it would use for real traffic, which is almost always the LAN adapter.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// All addresses we announce ourselves to.
fn broadcast_targets() -> Vec<Ipv4Addr> {
    let mut targets = vec![
        Ipv4Addr::BROADCAST, // 255.255.255.255
        Ipv4Addr::LOCALHOST, // same-machine instances
    ];
    if let Some(ip) = primary_ipv4() {
        // Assume a /24 — the overwhelmingly common office LAN. The
        // directed broadcast is routed via the interface that owns the
        // subnet, sidestepping the wrong-adapter problem entirely.
        let directed = Ipv4Addr::from(u32::from(ip) | 0x0000_00FF);
        if !targets.contains(&directed) {
            targets.push(directed);
        }
    }
    targets
}

/// Broadcast our beacon until shutdown. Best-effort: send failures are
/// ignored (adapters come and go).
pub async fn run_broadcast(beacon: Beacon, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let Ok(bytes) = serde_json::to_vec(&beacon) else {
        return;
    };
    let sock = match std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return,
    };
    if sock.set_broadcast(true).is_err() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(BEACON_INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                for target in broadcast_targets() {
                    let _ = sock.send_to(&bytes, SocketAddr::from((target, DISCOVERY_PORT)));
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Listen for beacons until shutdown, updating the registry.
pub async fn run_listener(
    registry: PeerRegistry,
    self_node_id: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    // socket2 lets us set SO_REUSEADDR/SO_REUSEPORT before bind so
    // multiple nodes on one machine can share the discovery port.
    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    if sock
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).into())
        .is_err()
    {
        return;
    }
    let std_sock: std::net::UdpSocket = sock.into();
    if std_sock.set_nonblocking(true).is_err() {
        return;
    }
    let udp = match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(u) => u,
        Err(_) => return,
    };

    let mut buf = vec![0u8; 2048];
    loop {
        tokio::select! {
            recv = udp.recv_from(&mut buf) => {
                let Ok((n, src)) = recv else { continue };
                let Ok(beacon) = serde_json::from_slice::<Beacon>(&buf[..n]) else { continue };
                if !beacon.is_valid() || beacon.node_id == self_node_id {
                    continue;
                }
                registry.upsert(Peer {
                    node_id: beacon.node_id,
                    name: beacon.name,
                    addr: src.ip().to_string(),
                    http_port: beacon.http_port,
                    fingerprint: beacon.fingerprint,
                    last_seen_unix: unix_now(),
                });
            }
            _ = shutdown.changed() => break,
        }
    }
}
