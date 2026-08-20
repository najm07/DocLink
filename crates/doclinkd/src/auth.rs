//! Request authentication for the data plane (protocol v0.2).
//!
//! Every authenticated peer request carries four headers:
//!   x-doclink-node:  caller's node_id
//!   x-doclink-pub:   caller's ed25519 public key, hex
//!   x-doclink-ts:    unix timestamp (士5 min replay window)
//!   x-doclink-sig:   signature over "<METHOD>\n<PATH>?<QUERY>\n<TS>\n<BODY>"
//!
//! The caller must hold a live grant: sha256(pubkey) must equal the
//! fingerprint stored when the share owner approved the pairing.
//! On success the matching grant is returned so handlers can enforce
//! its path scope.

use crate::server::AppState;
use crate::store::Grant;
use axum::http::{HeaderMap, StatusCode};
use doclink_core::identity::NodeIdentity;
use std::time::{SystemTime, UNIX_EPOCH};

/// Clock tolerance for the timestamp header. 15 min instead of the usual
/// 5 because LAN PCs often have drifted clocks (bad RTC, no NTP); the
/// failure mode is confusing ("peer returned 401") and the window is
/// still fine for a signed, single-LAN protocol.
const MAX_SKEW_SECS: u64 = 900;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Auth failure: HTTP status plus a human-readable reason. The reason is
/// echoed back to the caller's UI, so "peer returned 401" stops being a
/// mystery (clock skew, expired grant, re-pair needed, ...).
pub type AuthError = (axum::http::StatusCode, &'static str);

pub fn require_auth(
    headers: &HeaderMap,
    method: &str,
    path_q: &str,
    body: &[u8],
    state: &AppState,
) -> Result<Grant, AuthError> {
    let get = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let (node, pk, ts, sig) = match (
        get("x-doclink-node"),
        get("x-doclink-pub"),
        get("x-doclink-ts"),
        get("x-doclink-sig"),
    ) {
        (Some(n), Some(p), Some(t), Some(s)) => (n, p, t, s),
        _ => return Err((StatusCode::UNAUTHORIZED, "missing auth headers")),
    };

    let ts: u64 = ts
        .parse()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad timestamp header"))?;
    let now = unix_now();
    if now.abs_diff(ts) > MAX_SKEW_SECS {
        return Err((
            StatusCode::UNAUTHORIZED,
            "request timestamp is too far from this PC's clock — check that both PCs' clocks are in sync",
        ));
    }

    let grants = state.inner.grants.lock().unwrap().read().clone();
    let grant = grants
        .grants
        .iter()
        .find(|g| g.node_id == node)
        .ok_or((
            StatusCode::FORBIDDEN,
            "no grant for this node — ask the PC owner to approve the pairing again",
        ))?;
    if grant.expires_unix.map_or(false, |e| e <= now) {
        return Err((StatusCode::FORBIDDEN, "grant expired — re-pair"));
    }

    // The presented key must be the one that was paired.
    let fp = NodeIdentity::fingerprint_from_pubkey_hex(&pk)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad public key header"))?;
    if fp != grant.fingerprint {
        return Err((
            StatusCode::FORBIDDEN,
            "identity mismatch — this PC's identity changed, ask the owner to re-approve",
        ));
    }

    let canonical = format!("{method}\n{path_q}\n{ts}\n{}", String::from_utf8_lossy(body));
    NodeIdentity::verify(&pk, canonical.as_bytes(), &sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad signature"))?;
    Ok(grant.clone())
}
