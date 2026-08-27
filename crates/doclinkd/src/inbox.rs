//! Write-enabled "drop folder" that peers upload into.
//!
//! Peers never write into `shared/` directly — the share stays read-only
//! to them. They drop files here instead; the owner reviews them and
//! either **accepts** (moves into the share root, an explicit approval
//! action, so nobody can plant unvetted content in your shared folder)
//! or **discards**. Files placed directly on disk (drag-in) work too,
//! they just lack a sidecar.
//!
//! Security invariants (mirroring `ShareRoot`):
//! - uploads are single-component filenames only: `/`, `\`, `:`, control
//!   and path-hostile characters are rejected, so list/accept/discard can
//!   never touch anything outside the inbox root;
//! - `resolve` refuses symlinks — a dropped link is never followed;
//! - writes go through a temp file + atomic rename inside the root;
//! - a per-file sidecar `«name».doclink.json` records who sent what; the
//!   suffix is reserved and cannot be used as a payload name.

use doclink_core::protocol::InboxEntry;
use std::path::{Path, PathBuf};
use thiserror::Error;

const SIDECAR_SUFFIX: &str = ".doclink.json";

#[derive(Debug, Error)]
pub enum InboxError {
    #[error("invalid inbox file name")]
    InvalidName,
    #[error("inbox file not found: {0}")]
    NotFound(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Metadata recorded next to an uploaded file. All fields are optional:
/// manually dropped files have no sidecar at all.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct InboxMeta {
    pub from: Option<String>,
    pub from_node_id: Option<String>,
    pub received_unix: Option<u64>,
}

/// True if `name` is an acceptable single-component file name.
pub fn valid_name(name: &str) -> bool {
    use std::path::Component;
    let reserved = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
    !name.is_empty()
        // keeps "..", dot-prefixed hidden files, and Windows's trailing
        // dot/space aliasing out of the inbox
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name == name.trim()
        // the metadata suffix is reserved for sidecar files
        && !name.ends_with(SIDECAR_SUFFIX)
        && name.chars().all(|c| !reserved.contains(&c))
        && Path::new(name).components().all(|c| matches!(c, Component::Normal(_)))
}

/// First free name in `dir`: `name`, else `name (1).ext`, `name (2).ext`, …
fn dedupe_in_dir(dir: &Path, name: &str) -> String {
    if !dir.join(name).exists() {
        return name.to_string();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            for n in 1.. {
                let cand = format!("{stem} ({n}).{ext}");
                if !dir.join(&cand).exists() {
                    return cand;
                }
            }
        }
        _ => {
            for n in 1.. {
                let cand = format!("{name} ({n})");
                if !dir.join(&cand).exists() {
                    return cand;
                }
            }
        }
    }
    unreachable!()
}

#[derive(Clone)]
pub struct InboxRoot {
    root: PathBuf, // canonicalized at construction
}

impl InboxRoot {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, InboxError> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.canonicalize()?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve an existing inbox file to its real path. Refuses names
    /// that fail [`valid_name`] and symlinks.
    pub async fn resolve(&self, name: &str) -> Result<PathBuf, InboxError> {
        if !valid_name(name) {
            return Err(InboxError::InvalidName);
        }
        let candidate = self.root.join(name);
        if tokio::fs::symlink_metadata(&candidate)
            .await
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(InboxError::NotFound(name.to_string()));
        }
        match tokio::fs::metadata(&candidate).await {
            Ok(m) if m.is_file() => Ok(candidate),
            _ => Err(InboxError::NotFound(name.to_string())),
        }
    }

    /// Store an uploaded file, returning the (possibly deduped) name it
    /// landed under. Buffered caller-side and size-checked by the caller.
    pub async fn write_file(
        &self,
        name: &str,
        bytes: &[u8],
        meta: &InboxMeta,
    ) -> Result<String, InboxError> {
        let name = name.trim();
        if !valid_name(name) {
            return Err(InboxError::InvalidName);
        }
        let stored = dedupe_in_dir(&self.root, name);
        let target = self.root.join(&stored);
        let tmp = self.root.join(format!(".{stored}.part"));
        tokio::fs::write(&tmp, bytes).await?;
        tokio::fs::rename(&tmp, &target).await?;
        if let Ok(raw) = serde_json::to_vec(meta) {
            tokio::fs::write(self.sidecar_path(&stored), raw).await?;
        }
        Ok(stored)
    }

    /// Every payload file in the inbox, newest first, with sidecar metadata.
    pub async fn list(&self) -> Result<Vec<InboxEntry>, InboxError> {
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(&self.root).await?;
        while let Some(item) = rd.next_entry().await? {
            let fname = item.file_name().to_string_lossy().into_owned();
            if fname.ends_with(SIDECAR_SUFFIX) {
                continue; // metadata, not a payload
            }
            let meta = item.metadata().await?;
            if !meta.is_file() {
                continue;
            }
            let m = self.read_meta(&fname).await;
            out.push(InboxEntry {
                name: fname,
                size: meta.len(),
                modified_unix: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                from: m.from,
                from_node_id: m.from_node_id,
                received_unix: m.received_unix,
            });
        }
        out.sort_by(|a, b| {
            let ka = a.received_unix.unwrap_or(a.modified_unix);
            let kb = b.received_unix.unwrap_or(b.modified_unix);
            kb.cmp(&ka)
        });
        Ok(out)
    }

    /// Move an inbox file into `dest_dir` (the owner's share), returning
    /// the final name there. Fast-renames on the same volume, falls back
    /// to copy across volumes; the inbox copy and sidecar are removed
    /// only after the destination is in place.
    pub async fn accept(
        &self,
        name: &str,
        dest_dir: impl AsRef<Path>,
    ) -> Result<String, InboxError> {
        let src = self.resolve(name).await?;
        let dest_dir = dest_dir.as_ref();
        let final_name = dedupe_in_dir(dest_dir, name);
        let dest = dest_dir.join(&final_name);
        let dest_tmp = dest_dir.join(format!(".{final_name}.part"));
        match tokio::fs::rename(&src, &dest).await {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(18) => {
                // EXDEV: different volumes -> copy, then drop the source.
                tokio::fs::copy(&src, &dest_tmp).await?;
                tokio::fs::rename(&dest_tmp, &dest).await?;
                tokio::fs::remove_file(&src).await?;
            }
            Err(e) => return Err(e.into()),
        }
        let _ = tokio::fs::remove_file(self.sidecar_path(name)).await;
        Ok(final_name)
    }

    /// Delete an inbox file and its sidecar.
    pub async fn remove(&self, name: &str) -> Result<(), InboxError> {
        let path = self.resolve(name).await?;
        tokio::fs::remove_file(&path).await?;
        let _ = tokio::fs::remove_file(self.sidecar_path(name)).await;
        Ok(())
    }

    fn sidecar_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}{SIDECAR_SUFFIX}"))
    }

    async fn read_meta(&self, name: &str) -> InboxMeta {
        let raw = match tokio::fs::read(self.sidecar_path(name)).await {
            Ok(r) => r,
            Err(_) => return InboxMeta::default(),
        };
        serde_json::from_slice(&raw).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT_ID: AtomicU32 = AtomicU32::new(0);

    fn test_root() -> (InboxRoot, PathBuf) {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("doclink-inbox-test-{}-{}", std::process::id(), id));
        let root = InboxRoot::new(&dir).expect("inbox root");
        (root, dir)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_name_whitelist() {
        assert!(valid_name("hello.txt"));
        assert!(valid_name("report final.pdf"));
        assert!(valid_name("x-1_y.z"));
        assert!(valid_name("ñ çafé.odt"));
    }

    #[test]
    fn valid_name_rejects_hostile_input() {
        for bad in [
            "", ".", "..", ".hidden", "a.", " a", "a ", "a.b.txt ",
            "../x", "a/../../x", r"a\b", "a/b", "C:/x", r"C:\x",
            "a:b", "a*b", "a?b", "a<b", "a>b", "a|b", "a\"b", "a\0b",
            "x.doclink.json", ".x.doclink.json",
        ] {
            assert!(!valid_name(bad), "should reject {bad:?}");
        }
    }

    #[tokio::test]
    async fn write_list_roundtrip_carries_sender_meta() {
        let (root, dir) = test_root();
        let meta = InboxMeta {
            from: Some("Living Room".into()),
            from_node_id: Some("abc".into()),
            received_unix: Some(42),
        };
        let stored = root.write_file("hello.txt", b"hi there", &meta).await.unwrap();
        assert_eq!(stored, "hello.txt");
        assert_eq!(std::fs::read(root.root().join("hello.txt")).unwrap(), b"hi there");

        let list = root.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "hello.txt");
        assert_eq!(list[0].size, 8);
        assert_eq!(list[0].from.as_deref(), Some("Living Room"));
        assert_eq!(list[0].from_node_id.as_deref(), Some("abc"));
        assert_eq!(list[0].received_unix, Some(42));
        cleanup(&dir);
    }

    #[tokio::test]
    async fn write_sidecar_is_written_and_duplicated_names_dedupe() {
        let (root, dir) = test_root();
        let meta = InboxMeta::default();
        let a = root.write_file("a.txt", b"one", &meta).await.unwrap();
        let b = root.write_file("a.txt", b"two", &meta).await.unwrap();
        assert_eq!(a, "a.txt");
        assert_eq!(b, "a (1).txt");
        assert_eq!(tokio::fs::read(root.root().join("a.txt")).await.unwrap(), b"one");
        assert_eq!(tokio::fs::read(root.root().join("a (1).txt")).await.unwrap(), b"two");
        assert!(tokio::fs::read(root.root().join("a.txt.doclink.json")).await.is_ok());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn write_leaves_no_temp_residue() {
        let (root, dir) = test_root();
        root.write_file("a.txt", b"one", &InboxMeta::default()).await.unwrap();
        root.write_file("a.txt", b"two", &InboxMeta::default()).await.unwrap();
        let names = root.list().await.unwrap();
        assert_eq!(names.len(), 2);
        for e in &names {
            assert!(!e.name.starts_with('.'));
        }
        cleanup(&dir);
    }

    #[tokio::test]
    async fn accept_moves_into_share_and_cleans_sidecar() {
        let (root, dir) = test_root();
        let meta = InboxMeta { from: Some("bob".into()), from_node_id: Some("n1".into()), received_unix: Some(1) };
        root.write_file("notes.txt", b"notes", &meta).await.unwrap();
        let share_dir = std::env::temp_dir().join(format!("doclink-inbox-dest-{}", NEXT_ID.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&share_dir).unwrap();
        let moved = root.accept("notes.txt", &share_dir).await.unwrap();
        assert_eq!(moved, "notes.txt");
        assert_eq!(std::fs::read(share_dir.join("notes.txt")).unwrap(), b"notes");
        assert!(root.list().await.unwrap().is_empty());
        assert!(!share_dir.join("notes.txt.doclink.json").exists());
        let _ = std::fs::remove_dir_all(&share_dir);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn accept_dedupes_when_share_has_same_name() {
        let (root, dir) = test_root();
        let share_dir = std::env::temp_dir().join(format!("doclink-inbox-dest2-{}", NEXT_ID.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&share_dir).unwrap();
        std::fs::write(share_dir.join("a.txt"), b"existing").unwrap();
        root.write_file("a.txt", b"new", &InboxMeta::default()).await.unwrap();
        let moved = root.accept("a.txt", &share_dir).await.unwrap();
        assert_eq!(moved, "a (1).txt");
        assert_eq!(std::fs::read(share_dir.join("a (1).txt")).unwrap(), b"new");
        assert_eq!(std::fs::read(share_dir.join("a.txt")).unwrap(), b"existing");
        let _ = std::fs::remove_dir_all(&share_dir);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn remove_deletes_file_and_sidecar_only() {
        let (root, dir) = test_root();
        root.write_file("keep.txt", b"k", &InboxMeta::default()).await.unwrap();
        root.write_file("drop.txt", b"d", &InboxMeta::default()).await.unwrap();
        root.remove("drop.txt").await.unwrap();
        let names: Vec<String> = root.list().await.unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["keep.txt"]);
        assert!(!root.root().join("drop.txt.doclink.json").exists());
        cleanup(&dir);
    }

    #[tokio::test]
    async fn resolve_rejects_bad_names_missing_and_symlinks() {
        let (root, dir) = test_root();
        assert!(matches!(root.resolve("../x").await, Err(InboxError::InvalidName)));
        assert!(matches!(root.resolve("nope.txt").await, Err(InboxError::NotFound(_))));
        root.write_file("real.txt", b"x", &InboxMeta::default()).await.unwrap();
        assert!(root.resolve("real.txt").await.is_ok());

        // A symlinked file inside the inbox must not resolve.
        let outside = dir.parent().unwrap().join(format!("doclink-out-{}", std::process::id()));
        std::fs::write(&outside, b"out").unwrap();
        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(&outside, dir.join("link.txt")).is_ok();
        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(&outside, dir.join("link.txt")).is_ok();
        if created {
            assert!(matches!(root.resolve("link.txt").await, Err(InboxError::NotFound(_))));
            // and it must not appear as a deliverable payload either
            assert!(root.list().await.unwrap().iter().all(|e| e.name != "link.txt"));
        }
        let _ = std::fs::remove_file(&outside);
        cleanup(&dir);
    }

    #[tokio::test]
    async fn manual_files_without_sidecar_list_with_unknown_sender() {
        let (root, dir) = test_root();
        std::fs::write(dir.join("manual.bin"), b"raw").unwrap();
        let list = root.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "manual.bin");
        assert_eq!(list[0].from, None);
        assert_eq!(list[0].received_unix, None);
        // manual files are acceptable too (move into a real destination dir)
        let dest = dir.join("out");
        std::fs::create_dir_all(&dest).unwrap();
        let moved = root.accept("manual.bin", &dest).await.unwrap();
        assert_eq!(moved, "manual.bin");
        assert_eq!(std::fs::read(dest.join("manual.bin")).unwrap(), b"raw");
        assert!(root.list().await.unwrap().is_empty());
        cleanup(&dir);
    }
}