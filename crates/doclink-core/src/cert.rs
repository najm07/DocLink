//! v0.3 transport identity: a self-signed TLS certificate whose public
//! key IS the node's ed25519 identity key.
//!
//! Because an ed25519 SubjectPublicKeyInfo carries the raw 32-byte key,
//! sha256(SPKI key bits) == NodeIdentity::fingerprint(). One human-checked
//! number therefore pins both the wire signatures and the TLS handshake —
//! there is no CA and no second trust anchor.
//!
//! The certificate is rebuilt deterministically at every boot from the
//! existing seed (fixed PKCS#8 template), so nothing new is persisted.

use crate::identity::NodeIdentity;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// PKCS#8 (RFC 5958) wrapper around a raw ed25519 seed:
/// SEQUENCE { INTEGER 0, SEQ{OID 1.3.101.112}, OCTET STRING(32) }.
const ED25519_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
    0x20,
];

fn pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = Vec::with_capacity(16 + 32);
    der.extend_from_slice(ED25519_PKCS8_PREFIX);
    der.extend_from_slice(seed);
    der
}

/// A node's TLS material: DER cert + matching key, derived from the
/// long-lived identity. Regenerate freely; bytes differ per boot but the
/// SPKI (and thus the fingerprint peers pin) never changes.
pub struct NodeTls {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>, // PKCS#8
}

impl NodeTls {
    pub fn from_identity(identity: &NodeIdentity) -> Result<Self, anyhow::Error> {
        let kp = KeyPair::try_from(&pkcs8_from_seed(&identity.signing_key().to_bytes())[..])?;
        let fp_hex = identity.fingerprint();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("doclink-{fp_hex}"));

        let mut params =
            CertificateParams::new(vec![format!("doclink-{fp_hex}")])?;
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::IpAddress(
            "127.0.0.1".parse::<IpAddr>().expect("static ip"),
        ));

        let cert = params.self_signed(&kp)?;
        Ok(Self {
            cert_der: cert.der().as_ref().to_vec(),
            // The same fixed-template PKCS#8 the KeyPair was built from;
            // rustls consumes it directly as PrivatePkcs8KeyDer.
            key_der: pkcs8_from_seed(&identity.signing_key().to_bytes()),
        })
    }
}

/// sha256 over the raw ed25519 public key carried in a DER certificate.
/// For our certs this equals NodeIdentity::fingerprint().
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("bad peer certificate: {e}"))?;
    // public_key().raw is the full SPKI DER. Ed25519 SPKIs are a fixed
    // 12-byte header (SEQ{ SEQ{OID 1.3.101.112}, BIT STRING(0x21,00) })
    // followed by the bare 32-byte key. Anything else is not a key we
    // know how to pin.
    const ED25519_SPKI_HEADER: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let spki = cert.public_key().raw;
    if spki.len() != 44 || spki[..12] != ED25519_SPKI_HEADER {
        anyhow::bail!("peer certificate does not carry an ed25519 subjectPublicKey");
    }
    Ok(Sha256::digest(&spki[12..]).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_hash_equals_identity_fingerprint() {
        let id = NodeIdentity::generate();
        let tls = NodeTls::from_identity(&id).expect("tls material");
        assert_eq!(
            hex::encode(spki_sha256(&tls.cert_der).unwrap()),
            id.fingerprint()
        );
    }

    #[test]
    fn rejects_non_ed25519_spki() {
        // RSA-ish garbage with valid DER framing around it.
        let mut der = vec![0x30, 0x10, 0x02, 0x01, 0x00];
        der.extend_from_slice(&[0u8; 11]);
        assert!(spki_sha256(&der).is_err());
    }

    #[test]
    fn regenerated_cert_keeps_same_spki_fingerprint() {
        // Bytes may differ per boot; the pin must not.
        let id = NodeIdentity::generate();
        let a = NodeTls::from_identity(&id).unwrap();
        let b = NodeTls::from_identity(&id).unwrap();
        assert_eq!(
            spki_sha256(&a.cert_der).unwrap(),
            spki_sha256(&b.cert_der).unwrap()
        );
    }

    #[test]
    fn rejects_garbage_cert() {
        assert!(spki_sha256(b"not a certificate").is_err());
    }
}
