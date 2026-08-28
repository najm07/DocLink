//! Local PrintLink client: DocLink on this PC talks to PrintLink on
//! 127.0.0.1:9100 to print jobs that peers asked us to print.
//!
//! Wire is PrintLink v1.0: TLS with pinned cert, HMAC challenge, AES-GCM.
//! This module is localhost-only — no mDNS, no remote host registry.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::store::{SharedStore, Storable};

pub const PRINTLINK_LOCAL_ADDR: &str = "127.0.0.1";
pub const PRINTLINK_LOCAL_PORT: u16 = 9100;
pub const MAX_JOB_BYTES: usize = 100 * 1024 * 1024;

fn local_port() -> u16 {
    std::env::var("DOCLINK_PRINTLINK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(PRINTLINK_LOCAL_PORT)
}

fn ports_to_try() -> Vec<u16> {
    let primary = local_port();
    let mut v = vec![primary];
    if primary != 19100 {
        v.push(19100);
    }
    if primary != PRINTLINK_LOCAL_PORT && !v.contains(&PRINTLINK_LOCAL_PORT) {
        v.push(PRINTLINK_LOCAL_PORT);
    }
    v
}

fn base_url_for(port: u16) -> String {
    format!("https://{}:{}", PRINTLINK_LOCAL_ADDR, port)
}

// ---------- persona ----------

pub fn persona_id(identity: &doclink_core::identity::NodeIdentity) -> String {
    let fp = identity.fingerprint();
    let hash = Sha256::digest(fp.as_bytes());
    let last8: [u8; 8] = hash[24..32].try_into().unwrap();
    let n = u64::from_be_bytes(last8) % 1_000_000_000;
    format!("{n:09}")
}

#[allow(dead_code)]
pub fn is_valid_id(s: &str) -> bool {
    s.len() == 9 && s.chars().all(|c| c.is_ascii_digit())
}

// ---------- crypto (mirrors PrintLink agent/crypto.py + auth.py) ----------

fn key_from_token(token: &str) -> Vec<u8> {
    let raw = hex::decode(token).unwrap_or_else(|_| token.as_bytes().to_vec());
    Sha256::digest(&raw).to_vec()
}

pub fn token_hint(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))[..16].to_string()
}

pub fn sign_nonce(token: &str, nonce: &str) -> String {
    let key = key_from_token(token);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC key");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn encrypt_payload(plain: &[u8], token: &str) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;
    let key = key_from_token(token);
    let cipher = Aes256Gcm::new_from_slice(&key).context("bad AES key")?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
fn decrypt_payload(blob: &[u8], token: &str) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    if blob.len() < 12 + 16 {
        anyhow::bail!("blob too short");
    }
    let key = key_from_token(token);
    let cipher = Aes256Gcm::new_from_slice(&key).context("bad AES key")?;
    let (nonce, ct) = blob.split_at(12);
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
    Ok(pt)
}

// ---------- local token store ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalPrintToken {
    pub token: String,
    pub expires_at: String, // "%Y-%m-%d %H:%M:%S" UTC from host
    pub pinned_fp: String,  // sha256(DER cert)
    pub added_unix: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LocalPrintFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<LocalPrintToken>,
}

impl LocalPrintFile {
    pub fn get(&self) -> Option<&LocalPrintToken> {
        self.token.as_ref()
    }
    pub fn set(&mut self, t: LocalPrintToken) {
        self.token = Some(t);
    }
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.token = None;
    }
}

impl Storable for LocalPrintFile {
    fn label() -> &'static str {
        "local-print"
    }
}

pub fn token_path() -> PathBuf {
    PathBuf::from("doclink-local-print.json")
}

// ---------- PrintLink wire helpers (localhost only) ----------

#[allow(dead_code)]
fn base_url() -> String {
    format!("https://{}:{}", PRINTLINK_LOCAL_ADDR, local_port())
}

fn der_fingerprint(resp: &reqwest::Response) -> Result<String> {
    let info = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .ok_or_else(|| anyhow::anyhow!("no TLS session info"))?;
    let cert = info
        .peer_certificate()
        .ok_or_else(|| anyhow::anyhow!("no peer cert"))?;
    Ok(hex::encode(Sha256::digest(cert)))
}

fn check_pin(resp: &reqwest::Response, expected: &str) -> Result<String> {
    let got = der_fingerprint(resp)?;
    if !got.eq_ignore_ascii_case(expected) {
        anyhow::bail!("TLS pin mismatch: expected {expected}, got {got}");
    }
    Ok(got)
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HostPrinter {
    pub alias: String,
    pub status: HostPrinterStatus,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)]
pub struct HostPrinterStatus {
    #[serde(default)]
    pub offline: bool,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub error: bool,
    #[serde(default)]
    pub jobs_queued: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ShareAccept {
    status: String,
    token: String,
    expires_at: String,
    tls_fp: String,
}

#[allow(dead_code)]
pub async fn list_printers(http: &reqwest::Client, expected_fp: Option<&str>) -> Result<(Vec<HostPrinter>, String)> {
    let mut last_err: Option<anyhow::Error> = None;
    for port in ports_to_try() {
        let url = format!("{}/printers", base_url_for(port));
        let resp = match http.get(&url).timeout(std::time::Duration::from_secs(4)).send().await {
            Ok(r) => r,
            Err(e) => { last_err = Some(e.into()); continue; }
        };
        let fp = match der_fingerprint(&resp) {
            Ok(v) => v,
            Err(e) => { last_err = Some(e); continue; }
        };
        if let Some(want) = expected_fp {
            if let Err(e) = check_pin(&resp, want) {
                anyhow::bail!(e);
            }
        }
        if !resp.status().is_success() {
            anyhow::bail!("local /printers returned {}", resp.status());
        }
        let printers: Vec<HostPrinter> = resp.json().await.context("parsing /printers")?;
        return Ok((printers, fp));
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local PrintLink not reachable — is it running on 9100?")))
}

#[allow(dead_code)]
async fn auth_challenge(http: &reqwest::Client, sender_id: &str) -> Result<String> {
    let mut last_err: Option<anyhow::Error> = None;
    for port in ports_to_try() {
        let url = format!("{}/auth-challenge?sender_id={}", base_url_for(port), urlencoding::encode(sender_id));
        let resp = match http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await {
            Ok(r) => r,
            Err(e) => { last_err = Some(e.into()); continue; }
        };
        if !resp.status().is_success() {
            anyhow::bail!("local /auth-challenge returned {}", resp.status());
        }
        let v: serde_json::Value = resp.json().await.context("parsing challenge")?;
        if let Some(n) = v.get("nonce").and_then(|x| x.as_str()).map(|s| s.to_string()) {
            return Ok(n);
        }
        last_err = Some(anyhow::anyhow!("no nonce in challenge"));
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local /auth-challenge failed")))
}

#[allow(dead_code)]
async fn request_share(
    http: &reqwest::Client,
    expected_fp: &str,
    sender_id: &str,
    sender_name: &str,
    printer_alias: &str,
    days: u64,
) -> Result<(ShareAccept, String)> {
    let body = serde_json::json!({
        "sender_id": sender_id,
        "sender_name": sender_name,
        "printer_alias": printer_alias,
        "days": days,
    });
    let mut last_err: Option<anyhow::Error> = None;
    for port in ports_to_try() {
        let url = format!("{}/request-share", base_url_for(port));
        let resp = match http.post(&url).json(&body).timeout(std::time::Duration::from_secs(8)).send().await {
            Ok(r) => r,
            Err(e) => { last_err = Some(e.into()); continue; }
        };
        let fp = match der_fingerprint(&resp) {
            Ok(v) => v,
            Err(e) => { last_err = Some(e); continue; }
        };
        if let Err(e) = check_pin(&resp, expected_fp) {
            anyhow::bail!(e);
        }
        let status = resp.status();
        let accept: ShareAccept = match resp.json().await {
            Ok(v) => v,
            Err(e) => { last_err = Some(e.into()); continue; }
        };
        if accept.status != "accepted" {
            anyhow::bail!("local /request-share refused: {}", accept.status);
        }
        if status != reqwest::StatusCode::OK {
            anyhow::bail!("local /request-share returned {status}");
        }
        return Ok((accept, fp));
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local /request-share failed")))
}

async fn list_printers_on_port(
    http: &reqwest::Client,
    port: u16,
    expected_fp: Option<&str>,
) -> Result<(Vec<HostPrinter>, String)> {
    let url = format!("{}/printers", base_url_for(port));
    let resp = http.get(&url).timeout(std::time::Duration::from_secs(4)).send().await.context("connecting to local PrintLink")?;
    let fp = der_fingerprint(&resp)?;
    if let Some(want) = expected_fp {
        check_pin(&resp, want)?;
    }
    if !resp.status().is_success() {
        anyhow::bail!("local /printers returned {}", resp.status());
    }
    let printers: Vec<HostPrinter> = resp.json().await.context("parsing /printers")?;
    Ok((printers, fp))
}

async fn auth_challenge_on_port(http: &reqwest::Client, port: u16, sender_id: &str) -> Result<String> {
    let url = format!("{}/auth-challenge?sender_id={}", base_url_for(port), urlencoding::encode(sender_id));
    let resp = http.get(&url).timeout(std::time::Duration::from_secs(5)).send().await.context("local /auth-challenge")?;
    if !resp.status().is_success() {
        anyhow::bail!("local /auth-challenge returned {}", resp.status());
    }
    let v: serde_json::Value = resp.json().await.context("parsing challenge")?;
    v.get("nonce").and_then(|x| x.as_str()).map(|s| s.to_string()).context("no nonce in challenge")
}

async fn request_share_on_port(
    http: &reqwest::Client,
    port: u16,
    expected_fp: &str,
    sender_id: &str,
    sender_name: &str,
    printer_alias: &str,
    days: u64,
) -> Result<(ShareAccept, String)> {
    let url = format!("{}/request-share", base_url_for(port));
    let body = serde_json::json!({
        "sender_id": sender_id,
        "sender_name": sender_name,
        "printer_alias": printer_alias,
        "days": days,
    });
    let resp = http.post(&url).json(&body).timeout(std::time::Duration::from_secs(8)).send().await.context("local /request-share")?;
    let fp = der_fingerprint(&resp)?;
    check_pin(&resp, expected_fp)?;
    let status = resp.status();
    let accept: ShareAccept = resp.json().await.context("parsing /request-share")?;
    if accept.status != "accepted" {
        anyhow::bail!("local /request-share refused: {}", accept.status);
    }
    if status != reqwest::StatusCode::OK {
        anyhow::bail!("local /request-share returned {status}");
    }
    Ok((accept, fp))
}

/// Ensure we have a valid token for the local PrintLink's default printer.
/// On first use (or expired), probes /printers, picks the first alias,
/// and requests a share. Stores the token + pin on success.
/// Tries each candidate port (9100, 19100) with the whole flow on one port.
pub async fn ensure_paired(
    http: &reqwest::Client,
    store: &SharedStore<LocalPrintFile>,
    identity: &doclink_core::identity::NodeIdentity,
    sender_name: &str,
) -> Result<LocalPrintToken> {
    // Fast path: cached token still valid.
    {
        let g = store.lock().unwrap();
        if let Some(t) = g.read().get() {
            if !is_expired(&t.expires_at) && !t.token.is_empty() && !t.pinned_fp.is_empty() {
                return Ok(t.clone());
            }
        }
    }

    let persona = persona_id(identity);
    let mut last_err: Option<anyhow::Error> = None;
    for port in ports_to_try() {
        tracing::info!(port, "trying local PrintLink pairing");
        let (printers, fp) = match list_printers_on_port(http, port, None).await {
            Ok(v) => v,
            Err(e) => { tracing::warn!(port, %e, "local PrintLink list failed"); last_err = Some(e); continue; }
        };
        if printers.is_empty() {
            tracing::warn!(port, "local PrintLink has no shared printers");
            last_err = Some(anyhow::anyhow!("local PrintLink on {port} has no shared printers"));
            continue;
        }
        let alias = &printers[0].alias;
        let pin = {
            let g = store.lock().unwrap();
            g.read().get().map(|t| t.pinned_fp.clone()).unwrap_or_else(|| fp.clone())
        };
        match request_share_on_port(http, port, &pin, &persona, sender_name, alias, 30).await {
            Ok((accept, _)) => {
                if !accept.tls_fp.eq_ignore_ascii_case(&pin) && !accept.tls_fp.eq_ignore_ascii_case(&fp) {
                    last_err = Some(anyhow::anyhow!("local PrintLink tls_fp mismatch on {port}"));
                    continue;
                }
                let tok = LocalPrintToken {
                    token: accept.token,
                    expires_at: accept.expires_at,
                    pinned_fp: pin.clone(),
                    added_unix: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                };
                {
                    let mut g = store.lock().unwrap();
                    g.data_mut().set(tok.clone());
                    let _ = g.save();
                }
                return Ok(tok);
            }
            Err(e) => { last_err = Some(e); continue; }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local PrintLink not reachable — is it running on 9100?")))
}

fn is_expired(expires_at: &str) -> bool {
    // "%Y-%m-%d %H:%M:%S" UTC. Lenient: unparsable → expired.
    if let Some(unix) = expires_unix(expires_at) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        unix <= now
    } else {
        true
    }
}

pub fn expires_unix(s: &str) -> Option<u64> {
    // Manual parse to avoid chrono dep.
    let mut parts = s.split([' ', '-', ':']);
    let y: u64 = parts.next()?.parse().ok()?;
    let mo: u64 = parts.next()?.parse().ok()?;
    let d: u64 = parts.next()?.parse().ok()?;
    let h: u64 = parts.next()?.parse().ok()?;
    let mi: u64 = parts.next()?.parse().ok()?;
    let sec: u64 = parts.next()?.parse().ok()?;
    let days = days_since_epoch(y, mo, d)?;
    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

fn days_since_epoch(y: u64, m: u64, d: u64) -> Option<u64> {
    if !(1970..=2100).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    // Hinnant
    let (y, m) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) as u64)
}

/// Submit an already-encrypted-ready `payload` to the local PrintLink's
/// default printer. Handles the full HMAC challenge internally.
/// Tries each candidate port with challenge+POST on the same port.
pub async fn submit_job(
    http: &reqwest::Client,
    token: &LocalPrintToken,
    sender_id: &str,
    filename: &str,
    payload: &[u8],
) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    for port in ports_to_try() {
        let nonce = match auth_challenge_on_port(http, port, sender_id).await {
            Ok(n) => n,
            Err(e) => { last_err = Some(e); continue; }
        };
        let encrypted = encrypt_payload(payload, &token.token)?;
        let sig = sign_nonce(&token.token, &nonce);
        let hint = token_hint(&token.token);
        let file_name = filename.rsplit('/').next().unwrap_or("document");
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(encrypted)
                .file_name(file_name.to_string())
                .mime_str("application/octet-stream")?,
        );
        let url = format!("{}/print", base_url_for(port));
        let resp = match http
            .post(&url)
            .header("X-Sender-ID", sender_id)
            .header("X-Token-Hint", hint.clone())
            .header("X-Nonce", nonce.clone())
            .header("X-Signature", sig.clone())
            .multipart(form)
            .timeout(std::time::Duration::from_secs(180))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => { last_err = Some(e.into()); continue; }
        };
        if let Err(e) = check_pin(&resp, &token.pinned_fp) {
            last_err = Some(e);
            continue;
        }
        let status = resp.status();
        let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let msg = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
        match status.as_u16() {
            200 => return Ok(()),
            503 => anyhow::bail!("printer is offline on this PC"),
            401 => anyhow::bail!("local PrintLink rejected the token — re-pair by printing again"),
            403 => anyhow::bail!("local PrintLink refused: {msg}"),
            413 => anyhow::bail!("file exceeds PrintLink size limit"),
            _ => {
                // Non-connection error on this port — don't try next port, surface it.
                anyhow::bail!("local PrintLink returned {status}: {msg}")
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local PrintLink not reachable")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persona_id_is_nine_digits_and_stable() {
        let id = doclink_core::identity::NodeIdentity::generate();
        let a = persona_id(&id);
        let b = persona_id(&id);
        assert_eq!(a, b);
        assert_eq!(a.len(), 9);
        assert!(a.chars().all(|c| c.is_ascii_digit()));
        let id2 = doclink_core::identity::NodeIdentity::generate();
        assert_ne!(a, persona_id(&id2));
    }

    #[test]
    fn token_hint_is_first_16_hex() {
        assert_eq!(token_hint("abc"), hex::encode(Sha256::digest(b"abc"))[..16].to_string());
    }

    #[test]
    fn encrypt_roundtrips_with_python_shape() {
        let token = "a".repeat(64);
        let plain = b"hello local printlink";
        let blob = encrypt_payload(plain, &token).unwrap();
        assert_eq!(blob.len(), plain.len() + 12 + 16);
        assert_eq!(decrypt_payload(&blob, &token).unwrap(), plain);
    }

    #[test]
    fn interop_matches_printlink_python_vectors() {
        let token = "0123456789abcdef".repeat(4);
        assert_eq!(
            hex::encode(key_from_token(token.as_str())),
            "4884fdaafea47c29fea7159d0daddd9c085d6200e1359e85bb81736af6b7c837"
        );
        assert_eq!(token_hint(&token), "a8ae6e6ee929abea");
        assert_eq!(
            sign_nonce(&token, "TestNonceValue_2026_0001"),
            "bf7c04bb01dfd022ffe30fa8257afa6c893e1be5749ae5d6fb509c9bc14c932c"
        );
        assert_eq!(
            decrypt_payload(
                &hex::decode("000102030405060708090a0bc22bc2254bc8f676d5c01e9ccf3fc9f73f7e85853c69b33b929e84ba1c428e").unwrap(),
                &token
            )
            .unwrap(),
            b"hello printlink"
        );
    }

    #[test]
    fn expires_unix_parses_known_utc_timestamps() {
        // 2026-09-26 14:34:45 UTC
        assert_eq!(expires_unix("2026-09-26 14:34:45"), Some(1790433285));
        assert_eq!(expires_unix("1970-01-01 00:00:00"), Some(0));
        assert_eq!(expires_unix("bad"), None);
    }
}
