//! Tiny JSON-file stores with atomic writes. Grants (who may read my
//! share, and which parts of it) and contacts (PCs I have added) are
//! small enough that a full-file rewrite on change is simpler and
//! safer than a database.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// sha256 of the grantee's public key — the credential checked on every request.
    pub fingerprint: String,
    pub node_id: String,
    pub name: String,
    pub granted_unix: u64,
    /// None = until revoked.
    pub expires_unix: Option<u64>,
    /// Access scope: empty = the whole share; otherwise only these
    /// relative paths (files or folders) are visible to the grantee.
    /// Defaults to empty so pre-scope grant files keep full access.
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct GrantsFile {
    pub grants: Vec<Grant>,
}

impl GrantsFile {
    pub fn upsert(&mut self, g: Grant) {
        self.grants.retain(|x| x.fingerprint != g.fingerprint);
        self.grants.push(g);
    }

    /// Drop expired grants; returns true if anything changed.
    pub fn prune_expired(&mut self, now: u64) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.expires_unix.is_none_or(|e| e > now));
        self.grants.len() != before
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub node_id: String,
    pub alias: String,
    pub fingerprint: String,
    /// Manual "ip:port" fallback when discovery can't see the peer.
    pub host: Option<String>,
    /// "approved" | "pending" | "denied" | "unknown"
    pub status: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ContactsFile {
    pub contacts: Vec<Contact>,
}

impl ContactsFile {
    pub fn upsert(&mut self, c: Contact) {
        self.contacts.retain(|x| x.node_id != c.node_id);
        self.contacts.push(c);
    }

    pub fn remove(&mut self, node_id: &str) -> bool {
        let before = self.contacts.len();
        self.contacts.retain(|c| c.node_id != node_id);
        self.contacts.len() != before
    }
}

pub trait Storable: Serialize + DeserializeOwned + Default + Send + 'static {
    fn label() -> &'static str;
}

impl Storable for GrantsFile {
    fn label() -> &'static str {
        "grants"
    }
}

impl Storable for ContactsFile {
    fn label() -> &'static str {
        "contacts"
    }
}

pub struct Store<T: Storable> {
    path: PathBuf,
    data: T,
}

impl<T: Storable> Store<T> {
    pub fn open(path: &Path) -> Result<Self> {
        let data = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {} store {}", T::label(), path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        } else {
            T::default()
        };
        Ok(Self {
            path: path.to_path_buf(),
            data,
        })
    }

    pub fn read(&self) -> &T {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Atomic-ish persist: write a temp file, fsync it, then rename over
    /// the original. The fsync matters — without it a crash right after
    /// the rename can leave the target with zero-length content.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        let tmp = self.path.with_extension("tmp");
        let payload = serde_json::to_string_pretty(&self.data)?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(payload.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub type SharedStore<T> = Arc<Mutex<Store<T>>>;

pub fn open<T: Storable>(path: &Path) -> Result<SharedStore<T>> {
    Ok(Arc::new(Mutex::new(Store::open(path)?)))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Periodically prune expired grants and persist the change.
pub async fn run_expiry_sweeper(
    store: SharedStore<GrantsFile>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut g = store.lock().unwrap();
                if g.data_mut().prune_expired(unix_now()) {
                    if let Err(e) = g.save() {
                        tracing::warn!(%e, "failed to persist grants after expiry sweep");
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Re-check pending contacts against the grantor's `/v1/pair/status`.
/// The grantor pushes the decision, but if that push is lost (requester
/// offline at approval time, or mDNS miss), this polling catches up and
/// flips the contact to "approved"/"denied". Polls are signed — the
/// grantor's `/v1/pair/status` requires proof of the requester's identity.
pub async fn run_pair_verifier(
    http: reqwest::Client,
    contacts: SharedStore<ContactsFile>,
    peers: doclink_core::discovery::PeerRegistry,
    identity: doclink_core::identity::NodeIdentity,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use doclink_core::protocol::{PairStatus, PairStatusResponse};

    let my_id = identity.node_id();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let pending: Vec<String> = contacts.lock().unwrap().read().contacts
                    .iter()
                    .filter(|c| c.status == "pending")
                    .map(|c| c.node_id.clone())
                    .collect();
                for node_id in pending {
                    let Some(p) = peers.snapshot().into_iter().find(|p| p.node_id == node_id) else {
                        continue;
                    };
                    let path_q = format!("/v1/pair/status?node_id={}", urlencoding::encode(&my_id));
                    let url = format!(
                        "{}{}",
                        doclink_core::protocol::peer_base_url(&p.addr, p.http_port),
                        path_q
                    );
                    let mut req = http.get(&url);
                    for (k, v) in identity.auth_headers("GET", &path_q) {
                        req = req.header(k, v);
                    }
                    let Ok(resp) = req.timeout(Duration::from_secs(2)).send().await else {
                        continue;
                    };
                    let Ok(status) = resp.json::<PairStatusResponse>().await else {
                        continue;
                    };
                    let label = match status.status {
                        PairStatus::Approved => Some("approved"),
                        PairStatus::Denied => Some("denied"),
                        _ => None,
                    };
                    let Some(label) = label else { continue };
                    let mut c = contacts.lock().unwrap();
                    let Some(contact) = c.data_mut().contacts.iter_mut().find(|c| c.node_id == node_id) else {
                        continue;
                    };
                    if contact.status != label {
                        contact.status = label.to_string();
                        if let Err(e) = c.save() {
                            tracing::warn!(%e, "failed to persist contact status from verifier");
                        }
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "doclink-store-test-{}-{}-{}.json",
            tag,
            std::process::id(),
            id
        ))
    }

    fn grant(fp: &str, expires_unix: Option<u64>) -> Grant {
        Grant {
            fingerprint: fp.into(),
            node_id: format!("node-{fp}"),
            name: "n".into(),
            granted_unix: 1000,
            expires_unix,
            paths: vec![],
        }
    }

    #[test]
    fn upsert_replaces_by_fingerprint() {
        let mut f = GrantsFile::default();
        f.upsert(grant("aa", None));
        f.upsert(grant("bb", None));
        assert_eq!(f.grants.len(), 2);
        f.upsert(grant("aa", Some(5000)));
        assert_eq!(f.grants.len(), 2);
        let aa = f.grants.iter().find(|g| g.fingerprint == "aa").unwrap();
        assert_eq!(aa.expires_unix, Some(5000));
    }

    #[test]
    fn prune_expired_keeps_open_and_future_grants() {
        let mut f = GrantsFile::default();
        f.upsert(grant("open", None));
        f.upsert(grant("future", Some(2000)));
        f.upsert(grant("past", Some(999)));
        assert!(f.prune_expired(1500));
        let fps: Vec<&str> = f.grants.iter().map(|g| g.fingerprint.as_str()).collect();
        assert_eq!(fps, vec!["open", "future"]);
        assert!(!f.prune_expired(1500)); // idempotent
    }

    #[test]
    fn contacts_upsert_and_remove_by_node_id() {
        let mut c = ContactsFile::default();
        c.upsert(Contact {
            node_id: "n1".into(),
            alias: "A".into(),
            fingerprint: "f1".into(),
            host: None,
            status: "pending".into(),
        });
        c.upsert(Contact {
            node_id: "n1".into(),
            alias: "A2".into(),
            fingerprint: "f1".into(),
            host: None,
            status: "approved".into(),
        });
        assert_eq!(c.contacts.len(), 1);
        assert_eq!(c.contacts[0].alias, "A2");
        assert!(c.remove("n1"));
        assert!(!c.remove("n1"));
    }

    #[test]
    fn save_then_reload_roundtrips() {
        let path = tmp_path("roundtrip");
        {
            let mut store = Store::<GrantsFile>::open(&path).unwrap();
            store.data_mut().upsert(grant("cc", Some(42)));
            store.save().unwrap();
        }
        let reloaded = Store::<GrantsFile>::open(&path).unwrap();
        assert_eq!(reloaded.read().grants.len(), 1);
        assert_eq!(reloaded.read().grants[0].expires_unix, Some(42));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_writes_tmp_then_renames() {
        let path = tmp_path("rename");
        let store = Store::<GrantsFile>::open(&path).unwrap();
        store.save().unwrap();
        // After a successful save no .tmp residue remains next to the target.
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists());
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }
}
