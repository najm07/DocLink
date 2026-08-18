//! Machine identity: an ed25519 keypair persisted per node.
//!
//! The fingerprint is the SHA-256 of the public key, hex-encoded —
//! the same idea as SSH host key fingerprints. The node_id is a
//! short prefix of it, convenient for logs and URLs.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::Path;

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
        // TODO(M4): restrict permissions (0600 on unix, ACL on Windows).
        Ok(id)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Full SHA-256 fingerprint of the public key, hex-encoded.
    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.verifying_key().as_bytes()))
    }

    /// Short node id: first 16 hex chars of the fingerprint.
    pub fn node_id(&self) -> String {
        self.fingerprint()[..16].to_string()
    }

    /// Sign a message — used by the pairing handshake (M4).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }
}
