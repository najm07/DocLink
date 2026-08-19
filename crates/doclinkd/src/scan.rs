//! Active subnet probing — fallback when mDNS can't resolve a peer (rare
//! on Windows, but useful on networks that block multicast). Probes
//! http://<ip>:37655/v1/info across the local /24 until the target
//! node_id answers.

use doclink_core::protocol::{NodeInfo, DEFAULT_HTTP_PORT};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Primary interface IPv4 via the routing table (sends no packets).
fn primary_ipv4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Probe the local /24 for a node with the given DocLink ID.
/// Returns its base URL ("http://<ip>:<port>") when found.
pub async fn find_node(node_id: &str) -> Option<String> {
    let ip = primary_ipv4()?;
    let o = ip.octets();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .ok()?;

    let mut set = tokio::task::JoinSet::new();
    for host in 1..=254u8 {
        if host == o[3] {
            continue; // that's us
        }
        let target = Ipv4Addr::new(o[0], o[1], o[2], host);
        let client = client.clone();
        let wanted = node_id.to_string();
        set.spawn(async move {
            let url = format!("http://{target}:{DEFAULT_HTTP_PORT}/v1/info");
            let info: NodeInfo = client.get(&url).send().await.ok()?.json().await.ok()?;
            (info.node_id == wanted).then(|| format!("http://{target}:{DEFAULT_HTTP_PORT}"))
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(base)) = res {
            return Some(base);
        }
    }
    None
}
