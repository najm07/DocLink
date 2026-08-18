//! Wire types shared by all DocLink nodes.
//! See docs/protocol.md for the full specification.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "0.1";
pub const DISCOVERY_PORT: u16 = 37654;
pub const DEFAULT_HTTP_PORT: u16 = 37655;
pub const BEACON_MAGIC: &str = "DOCLINK_BEACON";
pub const BEACON_INTERVAL_SECS: u64 = 5;
pub const PEER_TTL_SECS: u64 = 20;

/// UDP broadcast announcement sent every BEACON_INTERVAL_SECS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beacon {
    pub magic: String,
    pub version: String,
    pub node_id: String,
    pub name: String,
    pub http_port: u16,
    pub fingerprint: String,
}

impl Beacon {
    pub fn new(
        node_id: impl Into<String>,
        name: impl Into<String>,
        http_port: u16,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            magic: BEACON_MAGIC.to_string(),
            version: PROTOCOL_VERSION.to_string(),
            node_id: node_id.into(),
            name: name.into(),
            http_port,
            fingerprint: fingerprint.into(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == BEACON_MAGIC
    }
}

/// GET /v1/info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub name: String,
    pub version: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    /// Path relative to the share root, forward-slash separated.
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub modified_unix: Option<u64>,
}

/// GET /v1/list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub path: String,
    pub entries: Vec<DirEntry>,
}

/// A peer as tracked by the discovery registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub name: String,
    pub addr: String,
    pub http_port: u16,
    pub fingerprint: String,
    pub last_seen_unix: u64,
}

/// Uniform error body for all HTTP endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
