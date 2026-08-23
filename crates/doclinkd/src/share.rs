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
    #[error("path is the share root")]
    IsRoot,
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

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a client-supplied relative path to a real path that is
    /// guaranteed to live under the share root.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, ShareError> {
        let rel_path = Path::new(rel);
        // `:` never appears in a legitimate relative component on Windows:
        // it is either a drive/prefix or an NTFS alternate data stream
        // selector (`file.txt:hidden`), so reject it outright.
        let suspicious = rel.contains(':')
            || rel_path.is_absolute()
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
    pub async fn list(&self, rel: &str) -> Result<Vec<DirEntry>, ShareError> {
        let dir = self.resolve(rel)?;
        let mut rd = tokio::fs::read_dir(dir).await?;
        let mut entries = Vec::new();
        while let Some(item) = rd.next_entry().await? {
            let meta = item.metadata().await?;
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

    /// Owner-side management: delete a file or folder from the share.
    /// The share root itself cannot be deleted.
    pub async fn delete(&self, rel: &str) -> Result<(), ShareError> {
        if rel.is_empty() {
            return Err(ShareError::IsRoot);
        }
        let path = self.resolve(rel)?;
        if path == self.root {
            return Err(ShareError::IsRoot);
        }
        let meta = tokio::fs::metadata(&path).await?;
        if meta.is_dir() {
            tokio::fs::remove_dir_all(&path).await?;
        } else {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT_ID: AtomicU32 = AtomicU32::new(0);

    /// Fresh temp share root with `a/b.txt` and an empty dir `c/`.
    fn test_root() -> (ShareRoot, PathBuf) {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("doclink-share-test-{}-{}", std::process::id(), id));
        let root = ShareRoot::new(&dir).expect("share root");
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::write(dir.join("a").join("b.txt"), b"hello").unwrap();
        std::fs::create_dir_all(dir.join("c")).unwrap();
        (root, dir)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_accepts_normal_paths() {
        let (root, dir) = test_root();
        assert!(root.resolve("a/b.txt").is_ok());
        assert!(root.resolve("a").is_ok());
        assert!(root.resolve("").is_ok());
        cleanup(&dir);
    }

    #[test]
    fn resolve_rejects_traversal() {
        let (root, dir) = test_root();
        for bad in ["../x", "a/../../x", "..", "a/../.."] {
            assert!(matches!(root.resolve(bad), Err(ShareError::OutsideRoot)), "{bad}");
        }
        cleanup(&dir);
    }

    #[test]
    fn resolve_rejects_absolute_and_prefixes() {
        let (root, dir) = test_root();
        for bad in ["C:/Windows", r"C:\Windows", r"\\?\C:\Windows", r"\\server\share", "/etc/passwd"] {
            assert!(
                matches!(root.resolve(bad), Err(ShareError::OutsideRoot) | Err(ShareError::NotFound(_))),
                "{bad}"
            );
        }
        cleanup(&dir);
    }

    #[test]
    fn resolve_rejects_alternate_data_stream_selectors() {
        let (root, dir) = test_root();
        for bad in ["a/b.txt:hidden", ":ads", "a:stream", "a/b.txt:Zone.Identifier:$DATA"] {
            assert!(matches!(root.resolve(bad), Err(ShareError::OutsideRoot)), "{bad}");
        }
        cleanup(&dir);
    }

    #[test]
    fn resolve_rejects_symlink_escaping_root() {
        let (root, dir) = test_root();
        let outside = dir.parent().unwrap().join(format!("doclink-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let link = dir.join("leak");
        let created = std::os::windows::fs::symlink_dir(&outside, &link).is_ok();
        if created {
            // The canonicalized target lives outside the root -> must be rejected.
            assert!(matches!(root.resolve("leak"), Err(ShareError::OutsideRoot)));
        } // symlink creation needs developer mode/admin; skip silently otherwise
        let _ = std::fs::remove_dir_all(&outside);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn delete_refuses_share_root() {
        let (root, dir) = test_root();
        assert!(matches!(root.delete("").await, Err(ShareError::IsRoot)));
        assert!(matches!(root.delete(".").await, Err(ShareError::IsRoot)));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn list_sorts_dirs_first_and_reports_metadata() {
        let (root, dir) = test_root();
        let entries = root.list("").await.unwrap();
        assert_eq!(entries.len(), 2); // a/ and c/
        assert_eq!(entries[0].kind, EntryKind::Dir);
        assert_eq!(entries[0].path, "a");
        let inner = root.list("a").await.unwrap();
        assert_eq!(inner.len(), 1);
        assert_eq!(inner[0].name, "b.txt");
        assert_eq!(inner[0].size, 5);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn list_rejects_traversal() {
        let (root, dir) = test_root();
        assert!(matches!(root.list("../").await, Err(ShareError::OutsideRoot)));
        cleanup(&dir);
    }
}
