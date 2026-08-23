//! Peer-facing HTTPS client plumbing (protocol v0.3).
//!
//! Trust model: pinned self-signed certs, SSH-style. The peer's
//! certificate MUST carry its ed25519 identity key as SPKI, so
//! sha256(SPKI) == the fingerprint the human verified during pairing.
//! Chain/CA validation is therefore intentionally skipped — the pin IS
//! the anchor — but every connection is checked before its body is
//! trusted. A response whose certificate does not parse as an ed25519
//! cert, or hashes to something other than the expected fingerprint,
//! fails the call.

use anyhow::Result;
use reqwest::tls::TlsInfo;

/// Client for peer calls. Skips CA validation (meaningless for
/// self-signed pinned peers) and enables the TlsInfo extension so
/// [`check`] can inspect the leaf certificate.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("peer http client")
}

fn spki_hex_of(resp: &reqwest::Response) -> Result<String> {
    let info = resp
        .extensions()
        .get::<TlsInfo>()
        .ok_or_else(|| anyhow::anyhow!("no TLS session info on peer response"))?;
    let der = info
        .peer_certificate()
        .ok_or_else(|| anyhow::anyhow!("peer presented no certificate"))?;
    Ok(hex::encode(doclink_core::cert::spki_sha256(der)?))
}

/// Verify the connection's certificate. When `expected_fp` is given the
/// hashes must match; when None (pre-trust discovery of an unknown ID)
/// any well-formed ed25519 cert is accepted and its hash returned for
/// the caller to cross-check against advertised identity fields.
pub fn check(
    resp: &reqwest::Response,
    expected_fp: Option<&str>,
) -> Result<String, String> {
    let got = spki_hex_of(resp).map_err(|e| e.to_string())?;
    if let Some(want) = expected_fp {
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!(
                "TLS pin mismatch: certificate hashes to {got}, expected {want}"
            ));
        }
    }
    Ok(got)
}
