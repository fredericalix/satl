// SPDX-License-Identifier: BSD-2-Clause
//! The rootfs inventory: what a mutating build step changed (M8b).
//!
//! Every mutating step (the PKG group, each COPY, each RUN) is bracketed by
//! two walks of the rootfs, and the difference becomes the step's layer. An
//! inventory maps each relative path to its metadata — file type, mode,
//! owner, size, mtime in nanoseconds, link target.
//!
//! **There is deliberately no content hash.** The 2 GB image is the case
//! this must not hash on every step, and it does not have to: a build step
//! rewrites a file through `cp -Rp`, `pkg` or a compiler, and all of them
//! move the mtime when the content moves. The trust model is rsync's —
//! metadata says what changed — and a step that forges an mtime to hide a
//! rewrite is outside it (and outside what a cache keyed on inputs would
//! catch anyway: such a step's *inputs* did not change either).
//!
//! The full-content hashing the cache needs happens on the other side of the
//! comparison — the COPY *sources* in the build context, which are small and
//! are what the cache key must be exact about ([`source_hash`]).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One path's metadata, as the diff compares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// What the path is.
    pub kind: EntryKind,
    /// Permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Byte length (0 for non-files).
    pub size: u64,
    /// Modification time, nanoseconds since the epoch.
    pub mtime_ns: i64,
    /// Symlink target, for symlinks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<PathBuf>,
    /// Device number, for device nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdev: Option<u64>,
}

/// What a path in the rootfs is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
    /// A named pipe.
    Fifo,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A unix socket. Recorded (its appearance is a real change) but never
    /// packed into a layer — a socket has no archived form.
    Socket,
}

/// A rootfs snapshot: relative path → metadata.
pub type Inventory = BTreeMap<PathBuf, Entry>;

/// What one step did to the rootfs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Diff {
    /// Added or changed paths, sorted (parents before their children, which
    /// byte order gives for free).
    pub changed: Vec<PathBuf>,
    /// Removed paths, sorted, with the children of a removed directory
    /// folded into it — one whiteout covers the subtree.
    pub removed: Vec<PathBuf>,
}

impl Diff {
    /// Nothing changed: the step emits no layer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.removed.is_empty()
    }
}

/// Walks `root` into an inventory. Synchronous: callers on the async
/// runtime wrap this in `spawn_blocking`.
pub fn walk(root: &Path) -> std::io::Result<Inventory> {
    let mut inventory = Inventory::new();
    walk_into(root, Path::new(""), &mut inventory)?;
    Ok(inventory)
}

/// The recursive half of [`walk`].
fn walk_into(root: &Path, relative: &Path, inventory: &mut Inventory) -> std::io::Result<()> {
    let dir = if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = relative.join(entry.file_name());
        let metadata = entry.metadata()?;
        let kind = entry_kind(&metadata);
        inventory.insert(
            path.clone(),
            Entry {
                kind,
                mode: metadata.mode() & 0o7777,
                uid: metadata.uid(),
                gid: metadata.gid(),
                size: if kind == EntryKind::File {
                    metadata.size()
                } else {
                    0
                },
                mtime_ns: metadata.mtime_nsec(),
                link: if kind == EntryKind::Symlink {
                    std::fs::read_link(entry.path()).ok()
                } else {
                    None
                },
                rdev: match kind {
                    EntryKind::CharDevice | EntryKind::BlockDevice => Some(metadata.rdev()),
                    _ => None,
                },
            },
        );
        if kind == EntryKind::Dir {
            walk_into(root, &path, inventory)?;
        }
    }
    Ok(())
}

/// The [`EntryKind`] of a metadata record.
fn entry_kind(metadata: &std::fs::Metadata) -> EntryKind {
    let file_type = metadata.file_type();
    if file_type.is_file() {
        EntryKind::File
    } else if file_type.is_dir() {
        EntryKind::Dir
    } else if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_fifo() {
        EntryKind::Fifo
    } else if file_type.is_char_device() {
        EntryKind::CharDevice
    } else if file_type.is_block_device() {
        EntryKind::BlockDevice
    } else if file_type.is_socket() {
        EntryKind::Socket
    } else {
        //_unreachable in practice; treated as a file by the layer writer.
        EntryKind::File
    }
}

/// The difference between the inventory before a step and the one after.
///
/// A changed entry carries everything the layer needs except the content
/// (read from the rootfs at pack time). A removal becomes a whiteout; a
/// removal whose ancestor is also removed is folded into it.
#[must_use]
pub fn diff(before: &Inventory, after: &Inventory) -> Diff {
    let changed = after
        .iter()
        .filter(|(path, entry)| before.get(*path) != Some(entry))
        .map(|(path, _)| path.clone())
        .collect();
    let doomed: BTreeSet<&Path> = before
        .keys()
        .filter(|path| !after.contains_key(*path))
        .map(PathBuf::as_path)
        .collect();
    let removed = doomed
        .iter()
        .filter(|path| {
            !path
                .ancestors()
                .skip(1)
                .any(|ancestor| doomed.contains(ancestor))
        })
        .map(|path| path.to_path_buf())
        .collect();
    Diff { changed, removed }
}

/// The whiteout marker's relative path for a removed path: the sibling
/// `.wh.<name>` (OCI image spec).
#[must_use]
pub fn whiteout_name(path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".wh.");
    name.push(path.file_name().unwrap_or_default());
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// A content hash of one COPY source (file or directory tree), for the
/// step's cache key. Unlike the rootfs inventory, this hashes every byte:
/// the context is small, and the key must notice *any* source change.
/// Modes are included (a `cp -Rp` preserves them), mtimes are not (a
/// re-checkout is the same source).
pub fn source_hash(absolute: &Path) -> std::io::Result<String> {
    let mut entries: Vec<serde_json::Value> = Vec::new();
    hash_into(absolute, Path::new(""), &mut entries)?;
    let canonical = serde_json::to_string(&entries).expect("strings and numbers serialize");
    Ok(crate::repack::sha256_hex(canonical.as_bytes()))
}

/// The recursive half of [`source_hash`].
fn hash_into(
    absolute: &Path,
    relative: &Path,
    entries: &mut Vec<serde_json::Value>,
) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(absolute)?;
    let kind = entry_kind(&metadata);
    let mode = metadata.mode() & 0o7777;
    let detail = match kind {
        EntryKind::File => sha256_hex_file(absolute)?,
        EntryKind::Symlink => std::fs::read_link(absolute)
            .map(|target| target.to_string_lossy().into_owned())
            .unwrap_or_default(),
        _ => String::new(),
    };
    entries.push(serde_json::json!([
        relative.to_string_lossy(),
        kind_name(kind),
        format!("{mode:04o}"),
        detail,
    ]));
    if kind == EntryKind::Dir {
        let mut children = Vec::new();
        for entry in std::fs::read_dir(absolute)? {
            children.push(entry?.file_name());
        }
        children.sort();
        for child in children {
            hash_into(&absolute.join(&child), &relative.join(child), entries)?;
        }
    }
    Ok(())
}

/// The stable name of an [`EntryKind`], for hashing.
fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
        EntryKind::Symlink => "symlink",
        EntryKind::Fifo => "fifo",
        EntryKind::CharDevice => "char",
        EntryKind::BlockDevice => "block",
        EntryKind::Socket => "socket",
    }
}

/// sha256 of a file's content, lowercase hex.
fn sha256_hex_file(path: &Path) -> std::io::Result<String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let mut hasher = sha2::Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// Lowercase hex of a digest.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small rootfs fixture; paths are created relative to it.
    struct Rootfs(tempfile::TempDir);

    impl Rootfs {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }

        fn path(&self) -> &Path {
            self.0.path()
        }

        fn file(&self, relative: &str, content: &str) {
            let path = self.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
    }

    #[test]
    fn an_unchanged_tree_diffs_empty() {
        let rootfs = Rootfs::new();
        rootfs.file("usr/bin/nginx", "binary");
        let first = walk(rootfs.path()).unwrap();
        let second = walk(rootfs.path()).unwrap();
        assert!(diff(&first, &second).is_empty());
    }

    #[test]
    fn additions_changes_and_deletions_are_seen() {
        let rootfs = Rootfs::new();
        rootfs.file("etc/rc.conf", "a=1");
        rootfs.file("usr/bin/nginx", "binary");
        let before = walk(rootfs.path()).unwrap();

        rootfs.file("etc/rc.conf", "a=2"); // changed content
        rootfs.file("usr/local/bin/node", "node"); // added
        std::fs::remove_file(rootfs.path().join("usr/bin/nginx")).unwrap(); // removed
        let after = walk(rootfs.path()).unwrap();

        let diff = diff(&before, &after);
        assert!(diff.changed.contains(&PathBuf::from("etc/rc.conf")));
        assert!(diff.changed.contains(&PathBuf::from("usr/local/bin/node")));
        // The parent directories of the additions rode along (mtime bumps).
        assert!(diff.changed.contains(&PathBuf::from("usr/local")));
        assert_eq!(diff.removed, [PathBuf::from("usr/bin/nginx")]);
    }

    #[test]
    fn a_mode_only_change_is_a_change() {
        let rootfs = Rootfs::new();
        rootfs.file("run.sh", "#!/bin/sh\n");
        let before = walk(rootfs.path()).unwrap();
        std::fs::set_permissions(
            rootfs.path().join("run.sh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let after = walk(rootfs.path()).unwrap();
        let diff = diff(&before, &after);
        assert_eq!(diff.changed, [PathBuf::from("run.sh")]);
    }

    #[test]
    fn a_removed_directory_folds_its_children() {
        let rootfs = Rootfs::new();
        rootfs.file("var/db/pkg/local.sqlite", "db");
        rootfs.file("var/db/pkg/repos/repo.conf", "conf");
        rootfs.file("etc/keep", "x");
        let before = walk(rootfs.path()).unwrap();
        std::fs::remove_dir_all(rootfs.path().join("var/db/pkg")).unwrap();
        let after = walk(rootfs.path()).unwrap();
        let diff = diff(&before, &after);
        assert_eq!(diff.removed, [PathBuf::from("var/db/pkg")]);
    }

    #[test]
    fn whiteout_names_are_sibling_markers() {
        assert_eq!(
            whiteout_name(Path::new("usr/bin/nginx")),
            PathBuf::from("usr/bin/.wh.nginx")
        );
        assert_eq!(whiteout_name(Path::new("etc")), PathBuf::from(".wh.etc"));
    }

    #[test]
    fn source_hash_tracks_content_not_names_or_mtimes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("app");
        std::fs::create_dir_all(source.join("lib")).unwrap();
        std::fs::write(source.join("index.js"), "// v1").unwrap();
        std::fs::write(source.join("lib/util.js"), "// util").unwrap();
        let first = source_hash(&source).unwrap();
        assert_eq!(source_hash(&source).unwrap(), first, "stable");

        std::fs::write(source.join("index.js"), "// v2").unwrap();
        assert_ne!(source_hash(&source).unwrap(), first, "content change");

        let _ = std::fs::remove_file(source.join("index.js"));
        assert_ne!(source_hash(&source).unwrap(), first, "a removal too");
    }
}
