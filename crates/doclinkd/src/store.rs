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
        self.grants.retain(|g| g.expires_unix.map_or(true, |e| e > now));
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

    /// Atomic-ish persist: write a temp file, then rename over the original.
    pub fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.data)?)?;
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
