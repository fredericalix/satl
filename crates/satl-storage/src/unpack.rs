// SPDX-License-Identifier: BSD-2-Clause
//! OCI layer tar application into a directory (`docs/architecture.md` §10).
//!
//! Pure-ish: this module knows nothing about ZFS — it takes a blob file, a
//! declared compression, an expected diff ID, and a target directory (the
//! mountpoint of a freshly cloned dataset), and applies the layer:
//!
//! - stream: file → decompressor → sha256 tee → tar unpack, so the diff ID
//!   (digest of the *uncompressed* tar stream) is verified in one pass;
//! - OCI whiteouts: `.wh.<name>` deletes `<name>`, `.wh..wh..opq` makes the
//!   containing directory opaque (pre-existing children are removed);
//! - permissions, numeric ownership, symlinks/hardlinks, and mtimes are
//!   preserved; device nodes are skipped with a warning when creation fails
//!   unprivileged;
//! - path safety: absolute entry paths and `..` traversal are rejected with
//!   a typed error, and deletions never walk through symlinked directories.
//!
//! The sync core ([`unpack_layer_sync`]) does blocking I/O; async callers use
//! [`unpack_layer`], which runs it under [`tokio::task::spawn_blocking`]
//! (CLAUDE.md: no blocking work on the async runtime).

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::chain::{ChainIdError, SHA256_PREFIX, parse_sha256_digest};

/// AUFS-style whiteout prefix (adopted by the OCI image spec).
const WHITEOUT_PREFIX: &str = ".wh.";
/// Opaque-directory marker: hides all lower-layer content of its directory.
const OPAQUE_MARKER: &str = ".wh..wh..opq";
/// Prefix of AUFS bookkeeping entries that are not plain whiteouts.
const WHITEOUT_META_PREFIX: &str = ".wh..wh.";

/// Compression of a layer blob, as declared by its manifest media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerCompression {
    /// `+gzip` media types.
    Gzip,
    /// `+zstd` media types.
    Zstd,
    /// Plain uncompressed tar.
    None,
}

impl LayerCompression {
    /// Map an OCI / Docker layer media type to its compression.
    ///
    /// # Errors
    ///
    /// [`UnpackError::UnsupportedMediaType`] for media types SatL does not
    /// know how to unpack.
    pub fn from_media_type(media_type: &str) -> Result<Self, UnpackError> {
        match media_type {
            "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar" => Ok(Self::None),
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Ok(Self::Gzip),
            "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
            | "application/vnd.docker.image.rootfs.diff.tar.zstd" => Ok(Self::Zstd),
            other => Err(UnpackError::UnsupportedMediaType {
                media_type: other.to_owned(),
            }),
        }
    }
}

/// Counters describing what a layer application did (for structured logs).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnpackSummary {
    /// Tar entries materialized in the target directory.
    pub entries_unpacked: u64,
    /// `.wh.<name>` whiteouts applied.
    pub whiteouts: u64,
    /// `.wh..wh..opq` opaque markers applied.
    pub opaque_dirs: u64,
    /// Device nodes skipped because creation failed (unprivileged run).
    pub devices_skipped: u64,
    /// Ownership changes skipped because `lchown` was denied (unprivileged).
    pub chowns_skipped: u64,
}

/// Error applying a layer blob.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// The manifest media type is not a tar layer SatL can unpack.
    #[error("unsupported layer media type {media_type:?}")]
    UnsupportedMediaType {
        /// The offending media type.
        media_type: String,
    },

    /// The expected diff ID is not a well-formed sha256 digest.
    #[error("invalid expected diff id: {0}")]
    InvalidDiffId(#[from] ChainIdError),

    /// The blob file could not be opened (or the decompressor initialized).
    #[error("failed to open layer blob {path}: {source}")]
    OpenBlob {
        /// Blob file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The unpacked stream hashed to a different digest than the manifest
    /// declared — the blob is corrupt or mislabeled; nothing may be trusted.
    #[error("layer diff id mismatch: manifest says {expected}, blob content is {actual}")]
    DigestMismatch {
        /// Digest from the image config (`rootfs.diff_ids`).
        expected: String,
        /// Digest actually computed over the uncompressed tar stream.
        actual: String,
    },

    /// A tar entry path was absolute, contained `..`, or would otherwise
    /// escape the target directory.
    #[error("unsafe path in layer tar entry {entry:?}: {reason}")]
    UnsafePath {
        /// The raw entry name from the archive.
        entry: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Reading the tar stream itself failed (truncated/corrupt archive).
    #[error("failed to read layer tar stream from {blob}: {source}")]
    Archive {
        /// Blob file path.
        blob: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Materializing one entry in the target directory failed.
    #[error("failed to unpack tar entry {entry:?} to {target}: {source}")]
    Entry {
        /// The entry name from the archive.
        entry: String,
        /// Destination path that failed.
        target: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// Applying a whiteout/opaque marker failed.
    #[error("failed to apply whiteout {entry:?} (removing {victim}): {source}")]
    Whiteout {
        /// The whiteout entry name from the archive.
        entry: String,
        /// The path being removed when the error occurred.
        victim: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The `spawn_blocking` worker was cancelled before finishing.
    #[error("layer unpack task was cancelled")]
    Cancelled,
}

// ---------------------------------------------------------------------------
// sha256 tee
// ---------------------------------------------------------------------------

/// Reader adapter that feeds every byte it yields into a sha256 hasher.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finalize_hex(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Path safety (pure)
// ---------------------------------------------------------------------------

/// Normalize a tar entry path to a safe relative path: strips `.` components,
/// rejects absolute paths and any `..` component. Returns an empty path for
/// the archive root entry (`./`).
fn sanitize_entry_path(raw: &Path) -> Result<PathBuf, String> {
    let mut clean = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                return Err("absolute paths are not allowed in layer tars".to_owned());
            }
            Component::ParentDir => {
                return Err("`..` path traversal is not allowed in layer tars".to_owned());
            }
            Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
        }
    }
    Ok(clean)
}

/// Join `rel` onto `root`, refusing to walk through any component that is a
/// symlink (a deletion following a symlink could escape the target).
/// Returns `None` when a symlink is encountered.
fn resolve_no_symlink(root: &Path, rel: &Path) -> Option<PathBuf> {
    let mut path = root.to_path_buf();
    for component in rel.components() {
        path.push(component);
        if let Ok(meta) = fs::symlink_metadata(&path)
            && meta.file_type().is_symlink()
        {
            return None;
        }
    }
    Some(path)
}

// ---------------------------------------------------------------------------
// Whiteout handling
// ---------------------------------------------------------------------------

/// Remove a path of any kind; missing is fine (whiteout with no lower-layer
/// counterpart is a no-op per the OCI image spec).
fn remove_any(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Apply `.wh.<victim_name>`: delete the named sibling in the target tree.
fn apply_whiteout(
    target_dir: &Path,
    parent_rel: &Path,
    victim_name: &str,
    entry_name: &str,
) -> Result<(), UnpackError> {
    let Some(parent) = resolve_no_symlink(target_dir, parent_rel) else {
        return Err(UnpackError::UnsafePath {
            entry: entry_name.to_owned(),
            reason: "whiteout path traverses a symlinked directory".to_owned(),
        });
    };
    let victim = parent.join(victim_name);
    tracing::debug!(victim = %victim.display(), "applying whiteout");
    remove_any(&victim).map_err(|source| UnpackError::Whiteout {
        entry: entry_name.to_owned(),
        victim,
        source,
    })
}

/// Apply `.wh..wh..opq`: remove every pre-existing child of the marker's
/// directory, so only same-layer siblings (extracted after the marker) remain.
fn apply_opaque(target_dir: &Path, parent_rel: &Path, entry_name: &str) -> Result<(), UnpackError> {
    let Some(dir) = resolve_no_symlink(target_dir, parent_rel) else {
        return Err(UnpackError::UnsafePath {
            entry: entry_name.to_owned(),
            reason: "opaque marker path traverses a symlinked directory".to_owned(),
        });
    };
    tracing::debug!(dir = %dir.display(), "applying opaque directory marker");
    let children = match fs::read_dir(&dir) {
        Ok(children) => children,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(UnpackError::Whiteout {
                entry: entry_name.to_owned(),
                victim: dir,
                source,
            });
        }
    };
    for child in children {
        let child_path = match child {
            Ok(child) => child.path(),
            Err(source) => {
                return Err(UnpackError::Whiteout {
                    entry: entry_name.to_owned(),
                    victim: dir,
                    source,
                });
            }
        };
        remove_any(&child_path).map_err(|source| UnpackError::Whiteout {
            entry: entry_name.to_owned(),
            victim: child_path,
            source,
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry materialization
// ---------------------------------------------------------------------------

/// Resolve dir↔non-dir conflicts with content inherited from the lower layer
/// (the dataset clone), and remove any pre-existing symlink at the
/// destination so nothing is ever written *through* a symlink.
fn prepare_destination(target_dir: &Path, rel: &Path, entry_is_dir: bool) -> io::Result<()> {
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    // A symlinked ancestor is handled (rejected) by `unpack_in` itself.
    let Some(parent) = resolve_no_symlink(target_dir, parent_rel) else {
        return Ok(());
    };
    let Some(name) = rel.file_name() else {
        return Ok(());
    };
    let dst = parent.join(name);
    match fs::symlink_metadata(&dst) {
        Ok(meta) if meta.file_type().is_symlink() => fs::remove_file(&dst),
        Ok(meta) if entry_is_dir && !meta.is_dir() => fs::remove_file(&dst),
        Ok(meta) if !entry_is_dir && meta.is_dir() => fs::remove_dir_all(&dst),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Apply the header's numeric uid/gid to the unpacked path. Requires root;
/// unprivileged runs count the skip instead of failing (unit tests, dev).
fn apply_ownership(
    header: &tar::Header,
    dst: &Path,
    entry_name: &str,
    summary: &mut UnpackSummary,
) -> Result<(), UnpackError> {
    let (Ok(uid), Ok(gid)) = (header.uid(), header.gid()) else {
        tracing::warn!(entry = %entry_name, "unreadable numeric uid/gid in tar header, skipping chown");
        summary.chowns_skipped += 1;
        return Ok(());
    };
    let (Ok(uid), Ok(gid)) = (u32::try_from(uid), u32::try_from(gid)) else {
        tracing::warn!(entry = %entry_name, uid, gid, "uid/gid out of range, skipping chown");
        summary.chowns_skipped += 1;
        return Ok(());
    };
    match std::os::unix::fs::lchown(dst, Some(uid), Some(gid)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            summary.chowns_skipped += 1;
            Ok(())
        }
        Err(source) => Err(UnpackError::Entry {
            entry: entry_name.to_owned(),
            target: dst.to_owned(),
            source,
        }),
    }
}

/// Process a single tar entry: whiteout handling or materialization.
fn process_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    target_dir: &Path,
    summary: &mut UnpackSummary,
) -> Result<(), UnpackError> {
    let entry_name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
    let unsafe_path = |reason: String| UnpackError::UnsafePath {
        entry: entry_name.clone(),
        reason,
    };

    let raw_path = entry
        .path()
        .map_err(|err| unsafe_path(format!("unreadable entry path: {err}")))?
        .into_owned();
    let rel = sanitize_entry_path(&raw_path).map_err(unsafe_path)?;
    if rel.as_os_str().is_empty() {
        // The `./` root entry: the target directory already exists.
        return Ok(());
    }
    let parent_rel = rel.parent().map(Path::to_path_buf).unwrap_or_default();

    if let Some(name) = rel.file_name().and_then(OsStr::to_str) {
        if name == OPAQUE_MARKER {
            apply_opaque(target_dir, &parent_rel, &entry_name)?;
            summary.opaque_dirs += 1;
            return Ok(());
        }
        if name.starts_with(WHITEOUT_META_PREFIX) {
            tracing::warn!(entry = %entry_name, "ignoring unknown AUFS metadata entry");
            return Ok(());
        }
        if let Some(victim_name) = name.strip_prefix(WHITEOUT_PREFIX) {
            if victim_name.is_empty() {
                return Err(unsafe_path(
                    "whiteout entry with empty target name".to_owned(),
                ));
            }
            apply_whiteout(target_dir, &parent_rel, victim_name, &entry_name)?;
            summary.whiteouts += 1;
            return Ok(());
        }
    }

    let entry_type = entry.header().entry_type();
    let is_device = entry_type.is_block_special() || entry_type.is_character_special();
    let dst = target_dir.join(&rel);

    prepare_destination(target_dir, &rel, entry_type.is_dir()).map_err(|source| {
        UnpackError::Entry {
            entry: entry_name.clone(),
            target: dst.clone(),
            source,
        }
    })?;

    match entry.unpack_in(target_dir) {
        Ok(true) => {}
        Ok(false) => {
            return Err(unsafe_path(
                "rejected by tar unpack (would escape the target directory)".to_owned(),
            ));
        }
        Err(source) if is_device => {
            tracing::warn!(
                entry = %entry_name,
                error = %source,
                "cannot create device node (unprivileged run?), skipping"
            );
            summary.devices_skipped += 1;
            return Ok(());
        }
        Err(source) => {
            return Err(UnpackError::Entry {
                entry: entry_name,
                target: dst,
                source,
            });
        }
    }
    summary.entries_unpacked += 1;

    apply_ownership(entry.header(), &dst, &entry_name, summary)
}

// ---------------------------------------------------------------------------
// The unpack itself
// ---------------------------------------------------------------------------

/// Apply one layer blob into `target_dir` (blocking; see [`unpack_layer`]
/// for the async wrapper).
///
/// Streams file → decompressor → sha256 tee → tar unpack, verifying that the
/// uncompressed stream hashes to `expected_diff_id`.
///
/// # Errors
///
/// See [`UnpackError`]. On [`UnpackError::DigestMismatch`] (reported only
/// after the stream ends) the target directory content must be discarded by
/// the caller — [`crate::LayerStore`] destroys the half-made dataset.
pub fn unpack_layer_sync(
    blob_path: &Path,
    compression: LayerCompression,
    expected_diff_id: &str,
    target_dir: &Path,
) -> Result<UnpackSummary, UnpackError> {
    let span = tracing::info_span!(
        "layer_unpack",
        blob = %blob_path.display(),
        target = %target_dir.display(),
        diff_id = %expected_diff_id,
    );
    let _guard = span.enter();

    let expected_hex = parse_sha256_digest(expected_diff_id)?;

    let file = fs::File::open(blob_path).map_err(|source| UnpackError::OpenBlob {
        path: blob_path.to_owned(),
        source,
    })?;
    let decoder: Box<dyn Read> = match compression {
        LayerCompression::None => Box::new(file),
        LayerCompression::Gzip => Box::new(flate2::read::GzDecoder::new(file)),
        LayerCompression::Zstd => {
            Box::new(zstd::stream::read::Decoder::new(file).map_err(|source| {
                UnpackError::OpenBlob {
                    path: blob_path.to_owned(),
                    source,
                }
            })?)
        }
    };

    let archive_err = |source: io::Error| UnpackError::Archive {
        blob: blob_path.to_owned(),
        source,
    };

    let mut archive = tar::Archive::new(HashingReader::new(decoder));
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);

    let mut summary = UnpackSummary::default();
    {
        let entries = archive.entries().map_err(archive_err)?;
        for entry in entries {
            let mut entry = entry.map_err(archive_err)?;
            process_entry(&mut entry, target_dir, &mut summary)?;
        }
    }

    // Drain trailing padding so the digest covers the *entire* uncompressed
    // tar stream — diff IDs are computed over the whole stream, terminator
    // blocks included.
    let mut hashing = archive.into_inner();
    io::copy(&mut hashing, &mut io::sink()).map_err(archive_err)?;
    let actual_hex = hashing.finalize_hex();
    if actual_hex != expected_hex {
        return Err(UnpackError::DigestMismatch {
            expected: format!("{SHA256_PREFIX}{expected_hex}"),
            actual: format!("{SHA256_PREFIX}{actual_hex}"),
        });
    }

    if summary.chowns_skipped > 0 {
        tracing::warn!(
            skipped = summary.chowns_skipped,
            "could not apply numeric ownership (unprivileged run?)"
        );
    }
    tracing::info!(
        entries = summary.entries_unpacked,
        whiteouts = summary.whiteouts,
        opaque_dirs = summary.opaque_dirs,
        devices_skipped = summary.devices_skipped,
        "layer unpacked"
    );
    Ok(summary)
}

/// Async wrapper for [`unpack_layer_sync`]: runs the blocking tar extraction
/// on the tokio blocking pool. Panics in the worker are propagated.
///
/// # Errors
///
/// See [`unpack_layer_sync`]; additionally [`UnpackError::Cancelled`] if the
/// blocking task was cancelled.
pub async fn unpack_layer(
    blob_path: PathBuf,
    compression: LayerCompression,
    expected_diff_id: String,
    target_dir: PathBuf,
) -> Result<UnpackSummary, UnpackError> {
    let handle = tokio::task::spawn_blocking(move || {
        unpack_layer_sync(&blob_path, compression, &expected_diff_id, &target_dir)
    });
    match handle.await {
        Ok(result) => result,
        Err(join_err) if join_err.is_panic() => std::panic::resume_unwind(join_err.into_panic()),
        Err(_) => Err(UnpackError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::time::{Duration, SystemTime};

    use super::*;

    const MTIME: u64 = 1_700_000_000;

    // ---- in-memory tar building helpers ------------------------------------

    fn build_tar(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        build(&mut builder);
        builder.into_inner().unwrap()
    }

    fn base_header(entry_type: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(mode);
        header.set_size(size);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(MTIME);
        header
    }

    fn add_file(b: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, content: &[u8]) {
        let mut header = base_header(tar::EntryType::Regular, mode, content.len() as u64);
        b.append_data(&mut header, path, content).unwrap();
    }

    fn add_file_owned(b: &mut tar::Builder<Vec<u8>>, path: &str, uid: u64, gid: u64) {
        let mut header = base_header(tar::EntryType::Regular, 0o644, 0);
        header.set_uid(uid);
        header.set_gid(gid);
        b.append_data(&mut header, path, &[][..]).unwrap();
    }

    fn add_dir(b: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32) {
        let mut header = base_header(tar::EntryType::Directory, mode, 0);
        b.append_data(&mut header, path, &[][..]).unwrap();
    }

    fn add_symlink(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
        let mut header = base_header(tar::EntryType::Symlink, 0o777, 0);
        b.append_link(&mut header, path, target).unwrap();
    }

    fn add_hardlink(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
        let mut header = base_header(tar::EntryType::Link, 0o644, 0);
        b.append_link(&mut header, path, target).unwrap();
    }

    fn add_char_device(b: &mut tar::Builder<Vec<u8>>, path: &str, major: u32, minor: u32) {
        let mut header = base_header(tar::EntryType::Char, 0o666, 0);
        header.set_device_major(major).unwrap();
        header.set_device_minor(minor).unwrap();
        b.append_data(&mut header, path, &[][..]).unwrap();
    }

    /// Append a file entry with a raw (unvalidated) name — the only way to
    /// craft `../` or absolute paths, which `append_data` would reject.
    fn add_raw_name_file(b: &mut tar::Builder<Vec<u8>>, raw_name: &str, content: &[u8]) {
        let mut header = base_header(tar::EntryType::Regular, 0o644, content.len() as u64);
        let name_bytes = raw_name.as_bytes();
        header.as_gnu_mut().unwrap().name[..name_bytes.len()].copy_from_slice(name_bytes);
        header.set_cksum();
        b.append(&header, content).unwrap();
    }

    fn diff_id_of(tar_bytes: &[u8]) -> String {
        format!("{SHA256_PREFIX}{}", hex::encode(Sha256::digest(tar_bytes)))
    }

    fn write_blob(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// Unpack `tar_bytes` (uncompressed) into a fresh target dir; returns
    /// (tempdir-guard, target path, result).
    fn unpack_plain(
        tar_bytes: &[u8],
        prepopulate: impl FnOnce(&Path),
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Result<UnpackSummary, UnpackError>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", tar_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        prepopulate(&target);
        let result = unpack_layer_sync(
            &blob,
            LayerCompression::None,
            &diff_id_of(tar_bytes),
            &target,
        );
        (tmp, target, result)
    }

    // ---- media types --------------------------------------------------------

    #[test]
    fn media_type_mapping() {
        assert_eq!(
            LayerCompression::from_media_type("application/vnd.oci.image.layer.v1.tar").unwrap(),
            LayerCompression::None
        );
        assert_eq!(
            LayerCompression::from_media_type("application/vnd.oci.image.layer.v1.tar+gzip")
                .unwrap(),
            LayerCompression::Gzip
        );
        assert_eq!(
            LayerCompression::from_media_type("application/vnd.oci.image.layer.v1.tar+zstd")
                .unwrap(),
            LayerCompression::Zstd
        );
        assert_eq!(
            LayerCompression::from_media_type("application/vnd.docker.image.rootfs.diff.tar.gzip")
                .unwrap(),
            LayerCompression::Gzip
        );
        let err = LayerCompression::from_media_type("application/x-not-a-layer").unwrap_err();
        assert!(
            matches!(err, UnpackError::UnsupportedMediaType { .. }),
            "{err}"
        );
    }

    // ---- path sanitizing (pure) ---------------------------------------------

    #[test]
    fn sanitize_accepts_relative_paths() {
        assert_eq!(
            sanitize_entry_path(Path::new("a/b/c")).unwrap(),
            PathBuf::from("a/b/c")
        );
        assert_eq!(
            sanitize_entry_path(Path::new("./a")).unwrap(),
            PathBuf::from("a")
        );
        assert_eq!(
            sanitize_entry_path(Path::new("./")).unwrap(),
            PathBuf::new()
        );
        assert_eq!(sanitize_entry_path(Path::new(".")).unwrap(), PathBuf::new());
    }

    #[test]
    fn sanitize_rejects_absolute_and_traversal() {
        assert!(
            sanitize_entry_path(Path::new("/etc/passwd"))
                .unwrap_err()
                .contains("absolute")
        );
        assert!(
            sanitize_entry_path(Path::new("a/../../b"))
                .unwrap_err()
                .contains("traversal")
        );
        assert!(
            sanitize_entry_path(Path::new("../evil"))
                .unwrap_err()
                .contains("traversal")
        );
    }

    // ---- happy path: files, dirs, symlinks, modes, mtimes -------------------

    #[test]
    fn unpacks_files_dirs_symlinks_with_modes_and_mtimes() {
        let tar_bytes = build_tar(|b| {
            add_dir(b, "./", 0o755); // root entry, skipped
            add_dir(b, "etc", 0o755);
            add_file(b, "etc/hello.txt", 0o640, b"hi there\n");
            add_symlink(b, "etc/link", "hello.txt");
            add_file(b, "top.txt", 0o600, b"top\n");
        });
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |_| {});
        let summary = result.unwrap();
        assert_eq!(summary.entries_unpacked, 4);
        assert_eq!(summary.whiteouts, 0);

        assert_eq!(
            fs::read_to_string(target.join("etc/hello.txt")).unwrap(),
            "hi there\n"
        );
        assert_eq!(fs::read_to_string(target.join("top.txt")).unwrap(), "top\n");
        let mode = fs::metadata(target.join("etc/hello.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o640);
        assert_eq!(
            fs::read_link(target.join("etc/link")).unwrap(),
            PathBuf::from("hello.txt")
        );
        let mtime = fs::metadata(target.join("etc/hello.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime, SystemTime::UNIX_EPOCH + Duration::from_secs(MTIME));
    }

    #[test]
    fn hardlinks_share_an_inode() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "a.txt", 0o644, b"linked\n");
            add_hardlink(b, "b.txt", "a.txt");
        });
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |_| {});
        result.unwrap();
        let ino_a = fs::metadata(target.join("a.txt")).unwrap().ino();
        let ino_b = fs::metadata(target.join("b.txt")).unwrap().ino();
        assert_eq!(ino_a, ino_b);
        assert_eq!(
            fs::read_to_string(target.join("b.txt")).unwrap(),
            "linked\n"
        );
    }

    // ---- compression --------------------------------------------------------

    #[test]
    fn gzip_blob_verifies_diff_id_of_uncompressed_stream() {
        let tar_bytes = build_tar(|b| add_file(b, "f.txt", 0o644, b"gz\n"));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let gz_bytes = encoder.finish().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar.gz", &gz_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        let summary = unpack_layer_sync(
            &blob,
            LayerCompression::Gzip,
            &diff_id_of(&tar_bytes),
            &target,
        )
        .unwrap();
        assert_eq!(summary.entries_unpacked, 1);
        assert_eq!(fs::read_to_string(target.join("f.txt")).unwrap(), "gz\n");
    }

    #[test]
    fn zstd_blob_verifies_diff_id_of_uncompressed_stream() {
        let tar_bytes = build_tar(|b| add_file(b, "f.txt", 0o644, b"zst\n"));
        let zst_bytes = zstd::encode_all(&tar_bytes[..], 0).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar.zst", &zst_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        let summary = unpack_layer_sync(
            &blob,
            LayerCompression::Zstd,
            &diff_id_of(&tar_bytes),
            &target,
        )
        .unwrap();
        assert_eq!(summary.entries_unpacked, 1);
        assert_eq!(fs::read_to_string(target.join("f.txt")).unwrap(), "zst\n");
    }

    // ---- digest verification -------------------------------------------------

    #[test]
    fn digest_mismatch_is_a_typed_error() {
        let tar_bytes = build_tar(|b| add_file(b, "f.txt", 0o644, b"real\n"));
        let wrong = format!(
            "{SHA256_PREFIX}{}",
            hex::encode(Sha256::digest(b"something else entirely"))
        );

        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", &tar_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        let err = unpack_layer_sync(&blob, LayerCompression::None, &wrong, &target).unwrap_err();
        match err {
            UnpackError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, diff_id_of(&tar_bytes));
            }
            other => panic!("expected DigestMismatch, got {other}"),
        }
    }

    #[test]
    fn malformed_expected_diff_id_is_a_typed_error() {
        let tar_bytes = build_tar(|b| add_file(b, "f.txt", 0o644, b"x"));
        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", &tar_bytes);
        let err =
            unpack_layer_sync(&blob, LayerCompression::None, "md5:nope", tmp.path()).unwrap_err();
        assert!(matches!(err, UnpackError::InvalidDiffId(_)), "{err}");
    }

    // ---- whiteouts -----------------------------------------------------------

    #[test]
    fn whiteout_removes_lower_layer_file_and_dir() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "data/.wh.removeme.txt", 0o644, b"");
            add_file(b, ".wh.olddir", 0o644, b"");
            add_file(b, ".wh.never-existed", 0o644, b"");
        });
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |target| {
            fs::create_dir_all(target.join("data")).unwrap();
            fs::write(target.join("data/removeme.txt"), "lower").unwrap();
            fs::write(target.join("data/keep.txt"), "keep").unwrap();
            fs::create_dir_all(target.join("olddir/sub")).unwrap();
            fs::write(target.join("olddir/sub/f.txt"), "lower").unwrap();
        });
        let summary = result.unwrap();
        assert_eq!(summary.whiteouts, 3);
        assert_eq!(summary.entries_unpacked, 0);
        assert!(!target.join("data/removeme.txt").exists());
        assert!(target.join("data/keep.txt").exists());
        assert!(!target.join("olddir").exists());
    }

    #[test]
    fn opaque_marker_clears_preexisting_children_but_keeps_same_layer_siblings() {
        let tar_bytes = build_tar(|b| {
            add_dir(b, "opq", 0o755);
            add_file(b, "opq/.wh..wh..opq", 0o644, b"");
            add_file(b, "opq/new.txt", 0o644, b"fresh\n");
        });
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |target| {
            fs::create_dir_all(target.join("opq/sub")).unwrap();
            fs::write(target.join("opq/old1.txt"), "lower").unwrap();
            fs::write(target.join("opq/sub/old2.txt"), "lower").unwrap();
        });
        let summary = result.unwrap();
        assert_eq!(summary.opaque_dirs, 1);
        let children: Vec<String> = fs::read_dir(target.join("opq"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(children, ["new.txt"]);
        assert_eq!(
            fs::read_to_string(target.join("opq/new.txt")).unwrap(),
            "fresh\n"
        );
    }

    #[test]
    fn empty_whiteout_name_is_rejected() {
        let tar_bytes = build_tar(|b| add_file(b, "data/.wh.", 0o644, b""));
        let (_tmp, _target, result) = unpack_plain(&tar_bytes, |target| {
            fs::create_dir_all(target.join("data")).unwrap();
        });
        let err = result.unwrap_err();
        assert!(matches!(err, UnpackError::UnsafePath { .. }), "{err}");
    }

    // ---- path traversal attacks ----------------------------------------------

    #[test]
    fn parent_traversal_entry_is_rejected() {
        let tar_bytes = build_tar(|b| add_raw_name_file(b, "../evil.txt", b"pwn"));
        let (tmp, _target, result) = unpack_plain(&tar_bytes, |_| {});
        let err = result.unwrap_err();
        assert!(matches!(err, UnpackError::UnsafePath { .. }), "{err}");
        assert!(!tmp.path().join("evil.txt").exists());
    }

    #[test]
    fn absolute_path_entry_is_rejected() {
        let tar_bytes = build_tar(|b| add_raw_name_file(b, "/abs-evil.txt", b"pwn"));
        let (_tmp, _target, result) = unpack_plain(&tar_bytes, |_| {});
        let err = result.unwrap_err();
        assert!(matches!(err, UnpackError::UnsafePath { .. }), "{err}");
        assert!(!Path::new("/abs-evil.txt").exists());
    }

    #[test]
    fn writing_through_a_preexisting_symlinked_dir_is_rejected() {
        let tar_bytes = build_tar(|b| add_file(b, "sneaky/pwn.txt", 0o644, b"pwn"));
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", &tar_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&outside, target.join("sneaky")).unwrap();

        let result = unpack_layer_sync(
            &blob,
            LayerCompression::None,
            &diff_id_of(&tar_bytes),
            &target,
        );
        assert!(result.is_err(), "unpack through symlinked dir must fail");
        assert!(!outside.join("pwn.txt").exists());
    }

    #[test]
    fn file_entry_replaces_preexisting_symlink_instead_of_writing_through_it() {
        let tar_bytes = build_tar(|b| add_file(b, "twist", 0o644, b"replaced\n"));
        let tmp = tempfile::tempdir().unwrap();
        let outside_file = tmp.path().join("outside-file");
        fs::write(&outside_file, "untouched").unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", &tar_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&outside_file, target.join("twist")).unwrap();

        unpack_layer_sync(
            &blob,
            LayerCompression::None,
            &diff_id_of(&tar_bytes),
            &target,
        )
        .unwrap();
        assert!(
            !fs::symlink_metadata(target.join("twist"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(target.join("twist")).unwrap(),
            "replaced\n"
        );
        assert_eq!(fs::read_to_string(&outside_file).unwrap(), "untouched");
    }

    // ---- dir <-> non-dir conflicts with lower-layer content -------------------

    #[test]
    fn file_replaces_lower_layer_dir_and_dir_replaces_lower_layer_file() {
        let tar_bytes = build_tar(|b| {
            add_file(b, "x", 0o644, b"now a file\n");
            add_dir(b, "y", 0o755);
            add_file(b, "y/in.txt", 0o644, b"inside\n");
        });
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |target| {
            fs::create_dir_all(target.join("x")).unwrap();
            fs::write(target.join("x/child.txt"), "lower").unwrap();
            fs::write(target.join("y"), "lower file").unwrap();
        });
        result.unwrap();
        assert!(fs::metadata(target.join("x")).unwrap().is_file());
        assert_eq!(
            fs::read_to_string(target.join("y/in.txt")).unwrap(),
            "inside\n"
        );
    }

    // ---- ownership & device nodes (unprivileged-tolerant) ---------------------

    #[test]
    fn numeric_ownership_applied_or_counted_as_skipped() {
        let tar_bytes = build_tar(|b| add_file_owned(b, "owned.txt", 12345, 54321));
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |_| {});
        let summary = result.unwrap();
        let meta = fs::metadata(target.join("owned.txt")).unwrap();
        let chowned = meta.uid() == 12345 && meta.gid() == 54321;
        assert!(
            chowned || summary.chowns_skipped == 1,
            "expected chown applied (root) or skipped (unprivileged); \
             uid={} gid={} skipped={}",
            meta.uid(),
            meta.gid(),
            summary.chowns_skipped
        );
    }

    #[test]
    fn device_node_creation_failure_is_skipped_with_count() {
        let tar_bytes = build_tar(|b| add_char_device(b, "dev-null", 1, 3));
        let (_tmp, target, result) = unpack_plain(&tar_bytes, |_| {});
        let summary = result.unwrap();
        assert!(
            summary.devices_skipped == 1 || target.join("dev-null").exists(),
            "device must be created (root) or skipped with a count (unprivileged)"
        );
    }

    // ---- async wrapper ---------------------------------------------------------

    #[tokio::test]
    async fn async_wrapper_runs_the_sync_core_off_the_runtime() {
        let tar_bytes = build_tar(|b| add_file(b, "async.txt", 0o644, b"via spawn_blocking\n"));
        let tmp = tempfile::tempdir().unwrap();
        let blob = write_blob(tmp.path(), "layer.tar", &tar_bytes);
        let target = tmp.path().join("rootfs");
        fs::create_dir(&target).unwrap();

        let summary = unpack_layer(
            blob,
            LayerCompression::None,
            diff_id_of(&tar_bytes),
            target.clone(),
        )
        .await
        .unwrap();
        assert_eq!(summary.entries_unpacked, 1);
        assert_eq!(
            fs::read_to_string(target.join("async.txt")).unwrap(),
            "via spawn_blocking\n"
        );
    }
}
