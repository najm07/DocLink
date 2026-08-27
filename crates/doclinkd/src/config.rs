//! Config: optional doclink.toml on the same directory as the executable.
//! If the file is missing, sensible defaults apply so the portable package
//! works out of the box (node name from the OS hostname).
//!
//! ```toml
//! node_name = "PC-Direction"
//! http_port = 37655
//! share_root = "shared"
//! inbox_root = "inbox"
//! inbox_max_size = 268435456   # 256 MiB per uploaded file
//! advertise = true  # mDNS advertising; set false to hide this PC from discovery
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_share_root")]
    pub share_root: String,
    /// Drop folder peers upload into. Stays out of `shared/` until the
    /// owner accepts a file (moves it across) or discards it.
    #[serde(default = "default_inbox_root")]
    pub inbox_root: String,
    /// Largest single file a peer may upload into the inbox (bytes).
    #[serde(default = "default_inbox_max_size")]
    pub inbox_max_size: u64,
    #[serde(default = "default_true")]
    pub advertise: bool,
    /// Active /24 probing fallback when mDNS misses. Off avoids the
    /// network noise of probing 254 hosts (some corporate IDS setups
    /// flag it); discovery and manual host:port still work.
    #[serde(default = "default_true")]
    pub subnet_scan: bool,
    /// Auto-update checks against GitHub releases. Off means the daemon
    /// never contacts the internet; the UI can still check manually.
    #[serde(default = "default_true")]
    pub check_updates: bool,
}

fn default_node_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "DocLink PC".into())
}

fn default_http_port() -> u16 {
    37655
}

fn default_share_root() -> String {
    "shared".into()
}

fn default_inbox_root() -> String {
    "inbox".into()
}

const MIB: u64 = 1024 * 1024;

fn default_inbox_max_size() -> u64 {
    256 * MIB
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_name: default_node_name(),
            http_port: default_http_port(),
            share_root: default_share_root(),
            inbox_root: default_inbox_root(),
            inbox_max_size: default_inbox_max_size(),
            advertise: default_true(),
            subnet_scan: default_true(),
            check_updates: default_true(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.unwrap_or_else(|| Path::new("doclink.toml"));
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading config {}", path.display())),
        }
    }

    pub fn node_name(&self) -> String {
        self.node_name.clone()
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    pub fn advertise(&self) -> bool {
        self.advertise
    }

    /*pub fn share_root(&self) -> PathBuf {
        PathBuf::from(&self.share_root)
    }*/

    pub fn grants_path(&self) -> PathBuf {
        PathBuf::from("doclink-grants.json")
    }

    pub fn contacts_path(&self) -> PathBuf {
        PathBuf::from("doclink-contacts.json")
    }

    pub fn identity_key_path(&self) -> PathBuf {
        PathBuf::from("doclink-identity.key")
    }
}
