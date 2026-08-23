//! Active subnet probing — fallback when mDNS can't resolve a peer (rare
//! on Windows, but useful on networks that block multicast). Probes
//! https://<ip>:37655/v1/info across the local /24 until the target
//! node_id answers with a certificate that self-certifies (SPKI hash ==
//! advertised fingerprint).

use doclink_core::discovery::primary_ipv4;
use doclink_core::protocol::{NodeInfo, DEFAULT_HTTP_PORT};
use std::net::Ipv4Addr;
use std::time::Duration;

/// Probe the local /24 for a node with the given DocLink ID.
/// Returns its base URL ("https://<ip>:<port>") when found.
pub async fn find_node(node_id: &str) -> Option<String> {
    let ip = primary_ipv4()?;
    let o = ip.octets();
    let client = crate::peer::client();

    let mut set = tokio::task::JoinSet::new();
    for host in 1..=254u8 {
        if host == o[3] {
            continue; // that's us
        }
        let target = Ipv4Addr::new(o[0], o[1], o[2], host);
        let client = client.clone();
        let wanted = node_id.to_string();
        set.spawn(async move {
            let url =
                format!("https://{target}:{DEFAULT_HTTP_PORT}/v1/info");
            let resp = client.get(&url).timeout(Duration::from_millis(400)).send().await.ok()?;
            // Self-certifying: cert hash must equal the advertised fingerprint.
            let cert_fp = crate::peer::check(&resp, None).ok()?;
            let info: NodeInfo = resp.json().await.ok()?;
            if info.node_id == wanted
                && info.fingerprint[..16] == *wanted
                && cert_fp.eq_ignore_ascii_case(&info.fingerprint)
            {
                Some(format!("https://{target}:{DEFAULT_HTTP_PORT}"))
            } else {
                None
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Ok(Some(base)) = res {
            return Some(base);
        }
    }
    None
}
