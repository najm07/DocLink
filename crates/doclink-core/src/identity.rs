//! Machine identity: an ed25519 keypair persisted per node.
//!
//! The fingerprint is the SHA-256 of the public key, hex-encoded —
//! the same idea as SSH host key fingerprints. The node_id (shown in
//! the UI as the "DocLink ID") is a short prefix of it.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone)]
pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load the keypair from `path`, or generate and persist a new one.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading identity key {}", path.display()))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!("identity key {} has invalid length", path.display())
            })?;
            // Re-apply on every load: keys written by older versions may
            // carry permissive inherited ACEs.
            harden_key_permissions(path);
            return Ok(Self {
                signing_key: SigningKey::from_bytes(&bytes),
            });
        }
        let id = Self::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, id.signing_key.to_bytes())
            .with_context(|| format!("writing identity key {}", path.display()))?;
        harden_key_permissions(path);
        Ok(id)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Full SHA-256 fingerprint of the public key, hex-encoded.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.verifying_key().as_bytes()))
    }

    /// Short node id: first 16 hex chars of the fingerprint.
    pub fn node_id(&self) -> String {
        self.fingerprint()[..16].to_string()
    }

    /// Sign a message (pairing requests, authenticated peer calls).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// The four+one signature headers for an outgoing authenticated peer
    /// request. The signature covers
    /// "<METHOD>\n<PATH>?<QUERY>\n<TS>\n<NONCE>\n" (empty-body convention,
    /// matching docs/protocol.md §4). The random nonce makes every
    /// signature unique even when two requests land in the same second —
    /// without it the publisher's anti-replay cache would reject
    /// legitimate fast successive calls to the same path.
    pub fn auth_headers(&self, method: &str, path_q: &str) -> Vec<(String, String)> {
        use rand::RngCore;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string();
        let mut nb = [0u8; 8];
        OsRng.fill_bytes(&mut nb);
        let nonce = hex::encode(nb);
        let canonical = format!("{method}\n{path_q}\n{ts}\n{nonce}\n");
        let sig = self.sign(canonical.as_bytes());
        vec![
            ("x-doclink-node".into(), self.node_id()),
            (
                "x-doclink-pub".into(),
                hex::encode(self.verifying_key().as_bytes()),
            ),
            ("x-doclink-ts".into(), ts),
            ("x-doclink-nonce".into(), nonce),
            ("x-doclink-sig".into(), hex::encode(sig.to_bytes())),
        ]
    }

    /// Verify an ed25519 signature against a hex-encoded public key.
    pub fn verify(pubkey_hex: &str, msg: &[u8], signature_hex: &str) -> Result<()> {
        let pk_bytes: [u8; 32] = hex::decode(pubkey_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad pubkey length"))?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)?;
        let sig_bytes: [u8; 64] = hex::decode(signature_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        vk.verify_strict(msg, &Signature::from_bytes(&sig_bytes))?;
        Ok(())
    }

    /// Fingerprint (hex sha256) of a hex-encoded public key.
    pub fn fingerprint_from_pubkey_hex(pubkey_hex: &str) -> Result<String> {
        let bytes = hex::decode(pubkey_hex)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// Restrict the identity key file to the current user. Best-effort:
/// Windows removes inheritance and grants just `<user>:(R,W)` via icacls
/// (same DACL outcome as raw FFI, far less unsafe code); unix chmods to
/// 0600.
#[cfg(windows)]
fn harden_key_permissions(path: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let user = match std::env::var("USERNAME") {
        Ok(u) if !u.is_empty() => u,
        _ => return,
    };
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{user}:(R,W)"))
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    if !matches!(&status, Ok(o) if o.status.success()) {
        tracing::warn!(
            "could not tighten permissions on {} — other local users may be able to read it",
            path.display()
        );
    }
}

#[cfg(not(windows))]
fn harden_key_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("could not chmod 600 {}: {e}", path.display());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
