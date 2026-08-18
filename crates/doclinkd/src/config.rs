//! Node configuration: an optional TOML file next to the binary.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Display name shown to other nodes (default: machine hostname).
    pub node_name: Option<String>,
    /// Folder this PC publishes to the network (read-only).
    pub share_root: PathBuf,
    /// HTTP port for the share API + web UI.
    pub http_port: u16,
    /// Path of the ed25519 identity key file.
    pub identity_key: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_name: None,
            share_root: PathBuf::from("./shared"),
            http_port: doclink_core::protocol::DEFAULT_HTTP_PORT,
            identity_key: PathBuf::from("./doclink-identity.key"),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("doclink.toml"));
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn node_name(&self) -> String {
        self.node_name.clone().unwrap_or_else(|| {
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "doclink-node".into())
        })
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    pub fn identity_key_path(&self) -> PathBuf {
        self.identity_key.clone()
    }
}
