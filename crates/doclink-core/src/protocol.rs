//! Wire types shared by all DocLink nodes.
//! See docs/protocol.md for the full specification (v0.5).

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: &str = "0.5";
pub const DISCOVERY_PORT: u16 = 37654;
pub const DEFAULT_HTTP_PORT: u16 = 37655;
pub const BEACON_MAGIC: &str = "DOCLINK_BEACON";
pub const BEACON_INTERVAL_SECS: u64 = 5;
/// How long a peer stays in the registry without a fresh mDNS event.
/// Generous on purpose: mdns-sd re-announcements land every ~60 s (the
/// A-record refresh cadence), so a short TTL makes live peers disappear
/// between announcements. "Online" is cosmetic — real access is enforced
/// by signed grants, and stale entries fail cleanly at connect time.
pub const PEER_TTL_SECS: u64 = 300;

/// UDP broadcast announcement sent every BEACON_INTERVAL_SECS.
/// Discovery is only an address book (node_id -> current IP);
/// trust comes from pairing, not presence.
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

/// GET /v1/info response (unauthenticated — needed to verify pairing targets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub name: String,
    /// Wire protocol version (PROTOCOL_VERSION).
    pub version: String,
    pub fingerprint: String,
    /// App build version (Cargo workspace version). Empty on peers that
    /// predate this field — the old-protocol fallback path covers them.
    #[serde(default)]
    pub app_version: String,
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

/// GET /v1/search response: flat, scope-filtered filename matches.
/// `truncated` is set when the visit budget ran out before the whole
/// granted scope was walked — the client should tell the user the list
/// may be incomplete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub query: String,
    pub truncated: bool,
    pub results: Vec<DirEntry>,
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
///
/// `code` carries a stable machine-readable reason so peers can render
/// their own wording: `"pending" | "denied" | "expired" |
/// "unknown-node"` on the data plane. Absent for generic errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>) -> Self {
        Self { error: error.into(), code: None }
    }

    pub fn coded(error: impl Into<String>, code: &str) -> Self {
        Self { error: error.into(), code: Some(code.to_string()) }
    }
}

/// Base URL for a discovered peer address (v0.3: TLS-only data plane).
/// IPv6 literals must be bracketed or reqwest rejects the URL.
pub fn peer_base_url(addr: &str, port: u16) -> String {
    if addr.contains(':') {
        format!("https://[{addr}]:{port}")
    } else {
        format!("https://{addr}:{port}")
    }
}

// ---- Pairing (protocol v0.2) ----

/// POST /v1/pair/request body. `signature` covers canonical_request_string().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub node_id: String,
    pub name: String,
    pub pubkey_hex: String,
    pub requested_duration_secs: u64,
    pub signature: String,
}

/// POST /v1/pair/decision body (grantor -> requester notification).
/// `signature` covers canonical_decision_string().
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairDecision {
    pub requester_node_id: String,
    pub decision: String, // "approve" | "deny"
    pub duration_secs: u64, // 0 = until revoked
    pub pubkey_hex: String, // grantor's public key
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairStatus {
    Pending,
    Approved,
    Denied,
    Unknown,
}

/// Outcome of a pair request — returned by /v1/pair/request,
/// /v1/pair/status, and the admin decision endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairStatusResponse {
    pub status: PairStatus,
    pub expires_unix: Option<u64>,
}

/// A grant as stored by the sharing node (admin view).
/// `paths` empty = full access to the share; otherwise only the listed
/// files/folders (and the parent folders needed to reach them).
/// `allow_files` / `allow_print` are the two orthogonal permissions:
/// files+printing, only files, or only printing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInfo {
    pub fingerprint: String,
    pub node_id: String,
    pub name: String,
    pub granted_unix: u64,
    pub expires_unix: Option<u64>,
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_files: bool,
    #[serde(default)]
    pub allow_print: bool,
}

fn default_true() -> bool {
    true
}

/// A contact as stored by the browsing node (admin view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub node_id: String,
    pub alias: String,
    pub host: Option<String>,
    pub online: bool,
    pub status: String,
}

// ---- Inbox / drop-folder (protocol v0.4) ----

/// One file sitting in the owner's inbox drop folder (admin view).
/// `from*` is absent for files dropped directly on disk (no sidecar).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxEntry {
    pub name: String,
    pub size: u64,
    pub modified_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_unix: Option<u64>,
}

/// POST /v1/upload response: the (possibly deduped) name stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub name: String,
    pub size: u64,
}

/// Canonical string the requester signs in a PairRequest.
pub fn canonical_request_string(r: &PairRequest) -> String {
    format!(
        "doclink-pair-v1\n{}\n{}\n{}\n{}",
        r.node_id, r.name, r.pubkey_hex, r.requested_duration_secs
    )
}

/// Canonical string the grantor signs in a PairDecision.
pub fn canonical_decision_string(d: &PairDecision) -> String {
    format!(
        "doclink-decision-v1\n{}\n{}\n{}\n{}",
        d.requester_node_id, d.decision, d.duration_secs, d.pubkey_hex
    )
}
