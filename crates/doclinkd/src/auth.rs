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

/// Auth failure: HTTP status, a stable machine-readable `code` (see
/// docs/protocol.md §6) and a human message that is good enough to show
/// in the requester's UI as-is.
#[derive(Debug, Clone, Copy)]
pub struct AuthError {
    pub status: axum::http::StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

impl AuthError {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self { status, code, message }
    }

    pub fn into_response(
        self,
    ) -> (StatusCode, axum::Json<doclink_core::protocol::ErrorResponse>) {
        (
            self.status,
            axum::Json(doclink_core::protocol::ErrorResponse::coded(
                self.message, self.code,
            )),
        )
    }
}

/// Parse and verify the four x-doclink headers over
/// "<METHOD>\n<PATH>?<QUERY>\n<TS>\n<BODY>". Returns the caller's node_id,
/// hex pubkey and signature hex. No grant is required, so pre-grant
/// endpoints (`/v1/pair/status` catch-up polling) reuse this too.
pub fn verify_signed_headers(
    headers: &HeaderMap,
    method: &str,
    path_q: &str,
    body: &[u8],
) -> Result<(String, String, String), AuthError> {
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
        _ => return Err(AuthError::new(StatusCode::UNAUTHORIZED, "unauthenticated", "missing auth headers")),
    };
    // Per-request nonce: absent on legacy callers → empty line in the
    // canonical string; present → makes the signature unique per request
    // so the replay cache below never collides with fast successive calls.
    let nonce = get("x-doclink-nonce").unwrap_or_default();

    let ts: u64 = ts
        .parse()
        .map_err(|_| AuthError::new(StatusCode::UNAUTHORIZED, "bad-timestamp", "bad timestamp header"))?;
    let now = unix_now();
    if now.abs_diff(ts) > MAX_SKEW_SECS {
        return Err(AuthError::new(
            StatusCode::UNAUTHORIZED,
            "clock-skew",
            "request timestamp is too far from this PC's clock — check that both PCs' clocks are in sync",
        ));
    }

    let canonical = format!(
        "{method}\n{path_q}\n{ts}\n{nonce}\n{}",
        String::from_utf8_lossy(body)
    );
    NodeIdentity::verify(&pk, canonical.as_bytes(), &sig)
        .map_err(|_| AuthError::new(StatusCode::UNAUTHORIZED, "bad-signature", "bad signature"))?;
    Ok((node, pk, sig))
}

/// Replay defense: a signature accepted within the current skew window is
/// remembered, so capturing and re-sending an identical request fails. The
/// cache lives on AppState — per daemon instance, isolated between tests.
pub fn reject_replays(state: &AppState, sig_hex: &str) -> Result<(), AuthError> {
    fn reject() -> AuthError {
        AuthError::new(StatusCode::UNAUTHORIZED, "replayed", "replayed request")
    }
    let mut seen = state.inner.seen_sigs.lock().map_err(|_| reject())?;
    let now = unix_now();
    seen.retain(|_, at| now.saturating_sub(*at) <= MAX_SKEW_SECS);
    if seen.insert(sig_hex.to_string(), now).is_some() {
        return Err(reject());
    }
    Ok(())
}

pub fn require_auth(
    headers: &HeaderMap,
    method: &str,
    path_q: &str,
    body: &[u8],
    state: &AppState,
) -> Result<Grant, AuthError> {
    let (node, pk, sig) = verify_signed_headers(headers, method, path_q, body)?;
    reject_replays(state, &sig)?;

    let grants = state.inner.grants.lock().unwrap().read().clone();
    let Some(grant) = grants.grants.iter().find(|g| g.node_id == node) else {
        // No live grant. Tell the requester WHICH human step they are
        // waiting on instead of a generic 403.
        let pairing = &state.inner.pairing;
        if pairing.pending.lock().unwrap().contains_key(&node) {
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                "pending",
                "This PC has not approved your access request yet — it is still waiting in the owner's Incoming list.",
            ));
        }
        if let Some((resp, _)) = pairing.decisions.lock().unwrap().get(&node) {
            if resp.status == doclink_core::protocol::PairStatus::Denied {
                return Err(AuthError::new(
                    StatusCode::FORBIDDEN,
                    "denied",
                    "The owner of this PC denied your access request.",
                ));
            }
        }
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "unknown-node",
            "You don't have approved access to this PC yet — send a pair request first (Add PC by DocLink ID).",
        ));
    };
    if grant.expires_unix.is_some_and(|e| e <= unix_now()) {
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "expired",
            "Access expired — send a new pair request to extend it.",
        ));
    }

    // The presented key must be the one that was paired.
    let fp = NodeIdentity::fingerprint_from_pubkey_hex(&pk)
        .map_err(|_| AuthError::new(StatusCode::UNAUTHORIZED, "bad-key", "bad public key header"))?;
    if fp != grant.fingerprint {
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "identity-changed",
            "identity mismatch — this PC's identity changed, ask the owner to re-approve",
        ));
    }

    Ok(grant.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::server::{AppState, PairingState};
    use crate::store::{self, Grant, GrantsFile};
    use doclink_core::protocol::NodeInfo;

    fn test_state(tag: &str) -> (tempdir::Guard, AppState, NodeIdentity) {
        let dir = tempdir::Guard::new(tag);
        let cfg = Config {
            node_name: "test-node".into(),
            http_port: 37655,
            share_root: dir.path.join("shared").to_string_lossy().into_owned(),
            advertise: false,
            subnet_scan: false,
            check_updates: false,
        };
        let grants: store::SharedStore<GrantsFile> = store::open(&dir.path.join("g.json")).unwrap();
        let contacts: store::SharedStore<crate::store::ContactsFile> =
            store::open(&dir.path.join("c.json")).unwrap();
        let identity = NodeIdentity::generate();
        let node = NodeInfo {
            node_id: identity.node_id(),
            name: "test-node".into(),
            version: "0.2".into(),
            fingerprint: identity.fingerprint(),
            app_version: "0.0.0-test".into(),
        };
        let state = AppState::new(
            &cfg,
            node,
            grants,
            contacts,
            PairingState::default(),
            crate::events::shared(),
        );
        (dir, state, identity)
    }

    /// Minimal scoped temp dir with best-effort cleanup on drop.
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU32, Ordering};

        static NEXT_ID: AtomicU32 = AtomicU32::new(0);

        pub struct Guard {
            pub path: PathBuf,
        }

        impl Guard {
            pub fn new(tag: &str) -> Self {
                let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
                let path = std::env::temp_dir()
                    .join(format!("doclink-auth-test-{}-{}-{}", tag, std::process::id(), id));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    fn headers_for(
        id: &NodeIdentity,
        method: &str,
        path_q: &str,
        ts: u64,
        tamper_sig: bool,
    ) -> HeaderMap {
        let nonce = "0123456789abcdef";
        let canonical = format!("{method}\n{path_q}\n{ts}\n{nonce}\n");
        let mut sig = id.sign(canonical.as_bytes()).to_bytes();
        if tamper_sig {
            sig[0] ^= 0xff;
        }
        let mut h = HeaderMap::new();
        h.insert("x-doclink-node", id.node_id().parse().unwrap());
        h.insert(
            "x-doclink-pub",
            hex::encode(id.verifying_key().as_bytes()).parse().unwrap(),
        );
        h.insert("x-doclink-ts", ts.to_string().parse().unwrap());
        h.insert("x-doclink-nonce", nonce.parse().unwrap());
        h.insert("x-doclink-sig", hex::encode(sig).parse().unwrap());
        h
    }

    fn insert_grant(state: &AppState, id: &NodeIdentity, expires_unix: Option<u64>) {
        let grant = Grant {
            fingerprint: id.fingerprint(),
            node_id: id.node_id(),
            name: "grantee".into(),
            granted_unix: unix_now() - 60,
            expires_unix,
            paths: vec![],
        };
        state.inner.grants.lock().unwrap().data_mut().upsert(grant);
    }

    const PATH_Q: &str = "/v1/list?path=";

    #[test]
    fn accepts_valid_signed_request() {
        let (_guard, state, id) = test_state("ok");
        insert_grant(&state, &id, None);
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        let grant = require_auth(&h, "GET", PATH_Q, b"", &state).expect("valid");
        assert_eq!(grant.fingerprint, id.fingerprint());
    }

    #[test]
    fn rejects_missing_headers() {
        let (_guard, state, id) = test_state("missing");
        insert_grant(&state, &id, None);
        let e = require_auth(&HeaderMap::new(), "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.status, StatusCode::UNAUTHORIZED);
        assert_eq!(e.code, "unauthenticated");
    }

    #[test]
    fn rejects_stale_timestamp() {
        let (_guard, state, id) = test_state("skew");
        insert_grant(&state, &id, None);
        let h = headers_for(&id, "GET", PATH_Q, unix_now() - MAX_SKEW_SECS - 5, false);
        assert_eq!(
            require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rejects_unknown_node() {
        let (_guard, state, id) = test_state("unknown");
        // No grant inserted.
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        assert_eq!(
            require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err().status,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn rejects_expired_grant() {
        let (_guard, state, id) = test_state("expired");
        insert_grant(&state, &id, Some(unix_now() - 10));
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        let e = require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert_eq!(e.code, "expired");
    }

    #[test]
    fn rejects_identity_swap() {
        // The grant is paired with the impostor's node_id + fingerprint, but
        // the request presents that node_id alongside a DIFFERENT public key
        // (and a matching signature for it) -> fingerprint mismatch.
        let (_guard, state, id) = test_state("swap");
        let impostor = NodeIdentity::generate();
        insert_grant(&state, &impostor, None);

        let ts = unix_now();
        let nonce = "fedcba9876543210";
        let canonical = format!("GET\n{PATH_Q}\n{ts}\n{nonce}\n");
        let sig = id.sign(canonical.as_bytes());
        let mut h = HeaderMap::new();
        h.insert("x-doclink-node", impostor.node_id().parse().unwrap());
        h.insert(
            "x-doclink-pub",
            hex::encode(id.verifying_key().as_bytes()).parse().unwrap(),
        );
        h.insert("x-doclink-ts", ts.to_string().parse().unwrap());
        h.insert("x-doclink-nonce", nonce.parse().unwrap());
        h.insert("x-doclink-sig", hex::encode(sig.to_bytes()).parse().unwrap());

        let e = require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert_eq!(e.code, "identity-changed");
    }

    #[test]
    fn rejects_tampered_signature() {
        let (_guard, state, id) = test_state("tamper");
        insert_grant(&state, &id, None);
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), true);
        assert_eq!(
            require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rejects_signature_covering_different_path() {
        let (_guard, state, id) = test_state("pathswap");
        insert_grant(&state, &id, None);
        let h = headers_for(&id, "GET", "/v1/list?path=docs", unix_now(), false);
        assert_eq!(
            require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn rejects_replayed_request() {
        // The exact same request (same signature) must not be accepted
        // twice within the skew window.
        let (_guard, state, id) = test_state("replay");
        insert_grant(&state, &id, None);
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        require_auth(&h, "GET", PATH_Q, b"", &state).expect("first use ok");
        let e = require_auth(&h, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.status, StatusCode::UNAUTHORIZED);
        assert_eq!(e.code, "replayed");
    }

    #[test]
    fn replay_cache_is_per_state() {
        // Two independent daemon instances accept the same signature —
        // the cache must not leak between states.
        let (_g1, s1, id) = test_state("iso1");
        let (_g2, s2, _) = test_state("iso2");
        insert_grant(&s1, &id, None);
        insert_grant(&s2, &id, None);
        let h = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        require_auth(&h, "GET", PATH_Q, b"", &s1).expect("s1 first");
        require_auth(&h, "GET", PATH_Q, b"", &s1)
            .expect_err("s1 second must be a replay");
        require_auth(&h, "GET", PATH_Q, b"", &s2).expect("s2 is isolated");
    }

    #[test]
    fn reports_pending_then_denied_before_unknown() {
        use crate::server::{remember_decision, PairRequestEntry};
        use doclink_core::protocol::{PairRequest, PairStatusResponse};

        let (_guard, state, id) = test_state("pairing");

        // Nothing queued at all -> generic unknown-node guidance.
        // Fresh headers per stage: identical signatures would trip the
        // replay cache before the pairing-state checks are reached.
        let h0 = headers_for(&id, "GET", PATH_Q, unix_now(), false);
        let e = require_auth(&h0, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.code, "unknown-node");

        // Pair request queued but not yet approved -> pending.
        state.inner.pairing.pending.lock().unwrap().insert(
            id.node_id(),
            PairRequestEntry {
                request: PairRequest {
                    node_id: id.node_id(),
                    name: "n".into(),
                    pubkey_hex: String::new(),
                    requested_duration_secs: 0,
                    signature: String::new(),
                },
                received_unix: unix_now(),
            },
        );
        let h1 = headers_for(&id, "GET", PATH_Q, unix_now() + 1, false);
        let e = require_auth(&h1, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert_eq!(e.code, "pending");
        assert!(e.message.contains("waiting"), "{}", e.message);

        // Owner denied -> denied beats unknown.
        state.inner.pairing.pending.lock().unwrap().clear();
        remember_decision(
            &state.inner.pairing,
            &id.node_id(),
            PairStatusResponse {
                status: doclink_core::protocol::PairStatus::Denied,
                expires_unix: None,
            },
        );
        let h2 = headers_for(&id, "GET", PATH_Q, unix_now() + 2, false);
        let e = require_auth(&h2, "GET", PATH_Q, b"", &state).unwrap_err();
        assert_eq!(e.code, "denied");

        // The wire body carries the code so peers can localize.
        let (_, axum::Json(body)) = e.into_response();
        assert_eq!(body.code.as_deref(), Some("denied"));
    }
}

