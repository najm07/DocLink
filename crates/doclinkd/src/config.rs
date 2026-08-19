//! Config: doclink.toml on the same directory as the executable.
//!
//! ```toml
//! node_name = "PC-Direction"
//! http_port = 37655
//! share_root = "shared"
//! advertise = true  # mDNS advertising; set false to hide this PC from discovery
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub node_name: String,
    pub http_port: u16,
    pub share_root: String,
    #[serde(default = "default_true")]
    pub advertise: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path.unwrap_or_else(|| Path::new("doclink.toml"));
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
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

    pub fn share_root(&self) -> PathBuf {
        PathBuf::from(&self.share_root)
    }

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
