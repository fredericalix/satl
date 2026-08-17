// SPDX-License-Identifier: BSD-2-Clause
//! One step's layer: the diff, as an OCI `tar+gzip` blob (M8b).
//!
//! The writer is the `tar` crate, not `/usr/bin/tar`, on purpose — and the
//! reason is the cache. bsdtar's pax output carries `atime`/`ctime` keywords,
//! which change on every read and every hardlink, so the same step on the
//! same rootfs never packs to the same bytes twice. A content-addressed
//! cache wants the opposite property: same step ⇒ same `diff_id`, verifiably.
//! Here the entry order is fixed (whiteouts first, then paths in byte
//! order), every header field comes from the inventory the diff was computed
//! against, and nothing time- or host-dependent leaks in — so two runs of
//! one step over identical content produce byte-identical layers, and the
//! golden test can pin those bytes.
//!
//! The cost, weighed and accepted: file flags (schg) are not representable
//! in this tar and are not preserved for step-layer files. The build clears
//! schg recursively before the first step (the base carries it), so only a
//! step that *re-adds* the flag loses it on unpack. `cpio`'s format would
//! keep them; the FreeBSD base files that have them live in base layers,
//! which this module never rewrites.
//!
//! Whiteouts (`.wh.<name>`) are emitted for every removed path; the unpacker
//! in `satl-storage` applies them.

use std::path::Path;

use crate::inventory::{Diff, EntryKind, Inventory, whiteout_name};

/// A packed step layer: the gzipped blob and the digests of both its forms.
#[derive(Debug)]
pub struct LayerBlob {
    /// sha256 of the uncompressed tar (the config's `diff_ids` entry).
    pub diff_id: String,
    /// sha256 of the gzip blob (the manifest's layer digest).
    pub blob_digest: String,
    /// The gzip blob's byte length (the manifest's layer size).
    pub size: u64,
    /// The gzip blob itself (staged into the store / written to the cache by
    /// the caller).
    pub gz: Vec<u8>,
}

/// Packs `diff` — read against `rootfs`, described by `inventory` — into a
/// layer, or returns `None` when the step changed nothing.
///
/// Synchronous (tar writing and file reads): callers on the async runtime
/// wrap this in `spawn_blocking`.
pub fn build_layer(
    rootfs: &Path,
    diff: &Diff,
    inventory: &Inventory,
) -> Result<Option<LayerBlob>, LayerError> {
    if diff.is_empty() {
        return Ok(None);
    }
    let tar = write_tar(rootfs, diff, inventory)?;
    let diff_id = format!("sha256:{}", crate::repack::sha256_hex(&tar));
    let gz = crate::repack::gzip(&tar);
    let blob_digest = format!("sha256:{}", crate::repack::sha256_hex(&gz));
    Ok(Some(LayerBlob {
        diff_id,
        blob_digest,
        size: gz.len() as u64,
        gz,
    }))
}

/// The uncompressed tar of one diff: whiteouts first, then the changed
/// entries in path order.
fn write_tar(rootfs: &Path, diff: &Diff, inventory: &Inventory) -> Result<Vec<u8>, LayerError> {
    let mut builder = tar::Builder::new(Vec::new());
    // Byte order, always: whiteouts first (a type change's new entry lands
    // after its whiteout), then the changed entries in path order.
    let mut doomed = diff.removed.clone();
    doomed.sort();
    for removed in &doomed {
        let mut header = plain_header(tar::EntryType::Regular, 0o644, 0);
        header.set_cksum();
        builder
            .append_data(&mut header, whiteout_name(removed), std::io::empty())
            .map_err(|source| LayerError::Tar {
                path: removed.clone(),
                source,
            })?;
    }
    let mut changed = diff.changed.clone();
    changed.sort();
    for path in &changed {
        let entry = inventory
            .get(path)
            .ok_or_else(|| LayerError::Vanished { path: path.clone() })?;
        append(&mut builder, rootfs, path, entry, inventory)?;
    }
    let tar = builder.into_inner().map_err(LayerError::Io)?;
    Ok(tar)
}

/// Appends one changed entry (directories before their contents: the diff's
/// byte order already guarantees it).
fn append(
    builder: &mut tar::Builder<Vec<u8>>,
    rootfs: &Path,
    path: &Path,
    entry: &crate::inventory::Entry,
    _inventory: &Inventory,
) -> Result<(), LayerError> {
    let tar_error = |source: std::io::Error| LayerError::Tar {
        path: path.to_path_buf(),
        source,
    };
    let mut header = plain_header(entry_type(entry.kind), entry.mode, entry.size);
    header.set_uid(u64::from(entry.uid));
    header.set_gid(u64::from(entry.gid));
    #[allow(clippy::cast_sign_loss)] // the clock is past the epoch for every file
    header.set_mtime((entry.mtime_ns / 1_000_000_000) as u64);
    match entry.kind {
        EntryKind::File => {
            let mut content = std::fs::File::open(rootfs.join(path)).map_err(tar_error)?;
            header.set_cksum();
            builder
                .append_data(&mut header, path, &mut content)
                .map_err(tar_error)?;
        }
        EntryKind::Dir | EntryKind::Fifo => {
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, path, std::io::empty())
                .map_err(tar_error)?;
        }
        EntryKind::Symlink => {
            header.set_size(0);
            let target = entry.link.clone().unwrap_or_default();
            header.set_link_name(&target).map_err(tar_error)?;
            header.set_cksum();
            builder
                .append_data(&mut header, path, std::io::empty())
                .map_err(tar_error)?;
        }
        EntryKind::CharDevice | EntryKind::BlockDevice | EntryKind::Socket => {
            // Not packed: a socket has no archived form, and a device node in
            // a jail image is dead weight (jails get a curated /dev). The
            // diff still records the change, so the step is not cached as
            // empty — the layer simply does not carry it.
            tracing::debug!(path = %path.display(), kind = ?entry.kind, "unpackable entry in a build diff: not packed");
        }
    }
    Ok(())
}

/// The tar entry type for an [`EntryKind`].
fn entry_type(kind: EntryKind) -> tar::EntryType {
    match kind {
        EntryKind::File => tar::EntryType::Regular,
        EntryKind::Dir => tar::EntryType::Directory,
        EntryKind::Symlink => tar::EntryType::Symlink,
        EntryKind::Fifo => tar::EntryType::Fifo,
        // Never written (see `append`); the value is unused.
        EntryKind::CharDevice | EntryKind::BlockDevice | EntryKind::Socket => {
            tar::EntryType::Regular
        }
    }
}

/// A header with the fields every entry shares; the caller fills the rest.
fn plain_header(entry_type: tar::EntryType, mode: u32, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(mode);
    header.set_size(size);
    header
}

/// Packing one step's layer failed.
#[derive(Debug, thiserror::Error)]
pub enum LayerError {
    /// A diff entry could not be read or packed. Carries the path.
    #[error("packing {path:?}: {source}")]
    Tar {
        /// The rootfs-relative path being packed.
        path: std::path::PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A diff entry is gone from the inventory (a build step raced itself —
    /// should not happen).
    #[error("diff entry {path:?} is missing from the inventory")]
    Vanished {
        /// The rootfs-relative path.
        path: std::path::PathBuf,
    },
    /// An I/O failure finishing the tar.
    #[error("layer tar: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Read as _;
    use std::path::PathBuf;

    use super::*;
    use crate::inventory::Entry;

    /// An inventory entry with fixed, environment-independent metadata — the
    /// golden bytes below depend on these values and nothing else.
    fn entry(kind: EntryKind, mode: u32, size: u64) -> Entry {
        Entry {
            kind,
            mode,
            uid: 0,
            gid: 0,
            size,
            mtime_ns: 1_577_836_800_000_000_000, // 2020-01-01T00:00:00Z
            link: None,
            rdev: None,
        }
    }

    /// A rootfs fixture whose content the writer reads; the metadata the
    /// golden pins comes from the fabricated inventory, not the filesystem.
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("etc")).unwrap();
        std::fs::write(rootfs.join("etc/motd"), "hello satl\n").unwrap();
        (dir, rootfs)
    }

    /// Read a built tar back into (path, type, mode, content) rows.
    fn listing(tar: &[u8]) -> Vec<(String, tar::EntryType, u32, Vec<u8>)> {
        let mut archive = tar::Archive::new(tar);
        let mut rows = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let kind = entry.header().entry_type();
            let mode = entry.header().mode().unwrap();
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            rows.push((path, kind, mode, content));
        }
        rows
    }

    #[test]
    fn an_empty_diff_packs_no_layer() {
        let (_dir, rootfs) = fixture();
        assert!(
            build_layer(&rootfs, &Diff::default(), &Inventory::new())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn whiteouts_pack_first_and_name_the_victim() {
        let (_dir, rootfs) = fixture();
        let mut inventory = Inventory::new();
        inventory.insert(
            PathBuf::from("etc/motd"),
            entry(EntryKind::File, 0o644, "hello satl\n".len() as u64),
        );
        let diff = Diff {
            changed: vec![PathBuf::from("etc/motd")],
            removed: vec![PathBuf::from("usr/bin/old"), PathBuf::from("etc/stale")],
        };
        let layer = build_layer(&rootfs, &diff, &inventory)
            .unwrap()
            .expect("a layer");
        let rows = listing(&{
            let mut plain = Vec::new();
            flate2::read::GzDecoder::new(&layer.gz[..])
                .read_to_end(&mut plain)
                .unwrap();
            plain
        });
        assert_eq!(
            rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            ["etc/.wh.stale", "usr/bin/.wh.old", "etc/motd"]
        );
        assert_eq!(rows[2].2, 0o644);
        assert_eq!(rows[2].3, b"hello satl\n");
    }

    #[test]
    fn the_diff_id_is_pinned_bytes_for_fixed_inputs() {
        let (_dir, rootfs) = fixture();
        let mut inventory = Inventory::new();
        inventory.insert(PathBuf::from("etc"), entry(EntryKind::Dir, 0o755, 0));
        inventory.insert(
            PathBuf::from("etc/motd"),
            entry(EntryKind::File, 0o644, "hello satl\n".len() as u64),
        );
        let diff = Diff {
            changed: vec![PathBuf::from("etc"), PathBuf::from("etc/motd")],
            removed: vec![PathBuf::from("var/cache/pkg")],
        };
        let layer = build_layer(&rootfs, &diff, &inventory)
            .unwrap()
            .expect("a layer");
        // The golden: this diff_id must never drift. If it does, the cache's
        // promise (same step ⇒ same layer) changed meaning — investigate,
        // don't re-pin blindly.
        assert_eq!(
            layer.diff_id,
            "sha256:b26cd90e96cc899a86c690e199a07cc9243252d8d176255c4946755c8367401a"
        );
        // And a rebuild of the same inputs is byte-identical.
        let again = build_layer(&rootfs, &diff, &inventory)
            .unwrap()
            .expect("a layer");
        assert_eq!(again.blob_digest, layer.blob_digest);
    }

    #[test]
    fn a_type_change_whiteouts_then_replaces() {
        let (_dir, rootfs) = fixture();
        // "thing" was a file, is now a directory containing a file.
        std::fs::create_dir_all(rootfs.join("thing")).unwrap();
        std::fs::write(rootfs.join("thing/inside"), "x").unwrap();
        let mut inventory = BTreeMap::new();
        inventory.insert(PathBuf::from("thing"), entry(EntryKind::Dir, 0o755, 0));
        inventory.insert(
            PathBuf::from("thing/inside"),
            entry(EntryKind::File, 0o644, 1),
        );
        let diff = Diff {
            changed: vec![PathBuf::from("thing"), PathBuf::from("thing/inside")],
            removed: vec![PathBuf::from("thing")],
        };
        let layer = build_layer(&rootfs, &diff, &inventory)
            .unwrap()
            .expect("a layer");
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(&layer.gz[..])
            .read_to_end(&mut plain)
            .unwrap();
        let rows = listing(&plain);
        assert_eq!(
            rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            [".wh.thing", "thing", "thing/inside"]
        );
    }

    #[test]
    fn long_paths_survive_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");
        let deep = "usr/local/share/".to_owned() + &"a".repeat(120) + "/file.txt";
        std::fs::create_dir_all(rootfs.join(&deep).parent().unwrap()).unwrap();
        std::fs::write(rootfs.join(&deep), "deep").unwrap();
        let mut inventory = BTreeMap::new();
        inventory.insert(PathBuf::from(&deep), entry(EntryKind::File, 0o644, 4));
        let diff = Diff {
            changed: vec![PathBuf::from(&deep)],
            removed: vec![],
        };
        let layer = build_layer(&rootfs, &diff, &inventory)
            .unwrap()
            .expect("a layer");
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(&layer.gz[..])
            .read_to_end(&mut plain)
            .unwrap();
        let rows = listing(&plain);
        assert_eq!(rows[0].0, deep);
        assert_eq!(rows[0].3, b"deep");
    }
}
