//! Read-only access to the published folder.
//!
//! Security invariant: `resolve` never returns a path outside the
//! share root. Client-supplied paths are rejected if absolute or if
//! they contain `..`, and the canonicalized result must still live
//! under the canonicalized root (symlink-safe).

use doclink_core::protocol::{DirEntry, EntryKind};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("path escapes the share root")]
    OutsideRoot,
    #[error("path not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct ShareRoot {
    root: PathBuf, // canonicalized at construction
}

impl ShareRoot {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ShareError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.canonicalize()?,
        })
    }

    /// Resolve a client-supplied relative path to a real path that is
    /// guaranteed to live under the share root.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, ShareError> {
        let rel_path = Path::new(rel);
        let suspicious = rel_path.is_absolute()
            || rel_path.components().any(|c| {
                matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))
            });
        if suspicious {
            return Err(ShareError::OutsideRoot);
        }
        let candidate = self
            .root
            .join(rel_path)
            .canonicalize()
            .map_err(|_| ShareError::NotFound(rel.to_string()))?;
        if !candidate.starts_with(&self.root) {
            return Err(ShareError::OutsideRoot);
        }
        Ok(candidate)
    }

    /// List one directory inside the share ("" = root).
    pub fn list(&self, rel: &str) -> Result<Vec<DirEntry>, ShareError> {
        let dir = self.resolve(rel)?;
        let mut entries = Vec::new();
        for item in std::fs::read_dir(dir)? {
            let item = item?;
            let meta = item.metadata()?;
            let name = item.file_name().to_string_lossy().into_owned();
            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            entries.push(DirEntry {
                name,
                path,
                kind: if meta.is_dir() {
                    EntryKind::Dir
                } else {
                    EntryKind::File
                },
                size: meta.len(),
                modified_unix: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            });
        }
        // Directories first, then alphabetical.
        entries.sort_by_key(|e| (e.kind == EntryKind::File, e.name.to_lowercase()));
        Ok(entries)
    }
}
