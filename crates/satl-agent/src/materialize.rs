// SPDX-License-Identifier: BSD-2-Clause
//! Writing secret/config payload files with the requested ownership and
//! mode (architecture §12.4).
//!
//! Secrets are written into the per-task tmpfs **after** `ocijail create`
//! mounted it (invariant #7: the bytes exist on the worker only in memory
//! and on that tmpfs); configs are written under the bundle directory before
//! create, as nullfs file-mount sources. Both go through [`write_payload`],
//! which is deliberately blocking `std::fs` code — the controller calls it
//! via `spawn_blocking` (CLAUDE.md: no blocking syscalls on the async
//! runtime).
//!
//! Nothing in this module ever logs, formats or errors with payload bytes:
//! errors carry the object name and the path, and the path never contains
//! payload material.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, fchown};
use std::path::Path;

use crate::bundle::PayloadFile;

/// Write one payload file per `plan`, pairing each [`PayloadFile`] with its
/// payload bytes (same order — the planner preserves spec order).
///
/// # Errors
///
/// The first failing file's error, naming the object and the path.
pub(crate) fn write_payloads(
    files: &[PayloadFile],
    payloads: &[impl AsRef<[u8]>],
) -> Result<(), PayloadWriteError> {
    debug_assert_eq!(files.len(), payloads.len());
    for (file, payload) in files.iter().zip(payloads) {
        write_payload(file, payload.as_ref())?;
        tracing::debug!(
            id = %file.id,
            name = %file.name,
            path = %file.path.display(),
            mode = format_args!("{:04o}", file.mode),
            uid = file.uid,
            gid = file.gid,
            "materialized dependency payload"
        );
    }
    Ok(())
}

/// A payload file could not be written. Never carries payload bytes.
#[derive(Debug, thiserror::Error)]
#[error("cannot materialize the payload of {name} at {path}: {step}: {source}",
        path = path.display())]
pub struct PayloadWriteError {
    /// Name of the secret/config.
    pub name: String,
    /// The host path being written.
    pub path: std::path::PathBuf,
    /// Which step failed.
    pub step: &'static str,
    /// The underlying I/O error.
    #[source]
    pub source: std::io::Error,
}

fn write_payload(file: &PayloadFile, payload: &[u8]) -> Result<(), PayloadWriteError> {
    let fail = |step: &'static str, source: std::io::Error| PayloadWriteError {
        name: file.name.clone(),
        path: file.path.clone(),
        step,
        source,
    };
    if let Some(parent) = file.path.parent() {
        ensure_dirs(parent).map_err(|source| fail("creating parent directories", source))?;
    }
    let mut handle = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // tightest first; widened below after the write
        .open(&file.path)
        .map_err(|source| fail("opening the file", source))?;
    handle
        .write_all(payload)
        .map_err(|source| fail("writing the payload", source))?;
    // Rewrites (re-entrant prepare) keep the file, so ownership and mode are
    // set explicitly every time; O_CREAT's mode is also umask-masked, so the
    // requested bits must be applied after the fact either way.
    fchown(&handle, Some(file.uid), Some(file.gid))
        .map_err(|source| fail("setting the owner", source))?;
    handle
        .set_permissions(fs::Permissions::from_mode(file.mode))
        .map_err(|source| fail("setting the mode", source))?;
    handle
        .sync_all()
        .map_err(|source| fail("syncing the file", source))?;
    Ok(())
}

/// `create_dir_all`; directories are left at the umask-derived default
/// (0755 under the daemon's 022), which is what Docker uses for
/// `/run/secrets` itself.
fn ensure_dirs(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use satl_core::Id;
    use std::os::unix::fs::MetadataExt as _;

    fn file(path: std::path::PathBuf, mode: u32) -> PayloadFile {
        // Chown to the test's own uid/gid (read off a directory the test
        // owns) so the tests run unprivileged.
        let own = std::fs::metadata(path.parent().map_or(Path::new("."), |p| {
            // The deepest existing ancestor is owned by the test.
            p.ancestors().find(|a| a.exists()).unwrap_or(Path::new("."))
        }))
        .unwrap();
        PayloadFile {
            id: Id::generate(),
            name: "db.password".to_owned(),
            path,
            uid: own.uid(),
            gid: own.gid(),
            mode,
        }
    }

    #[test]
    fn writes_content_mode_and_owner() {
        let dir = tempfile::tempdir().unwrap();
        let target = file(dir.path().join("sub/dir/db.password"), 0o440);
        write_payloads(std::slice::from_ref(&target), &[b"hunter2"]).unwrap();
        let meta = std::fs::metadata(&target.path).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o440, "mode must beat the umask");
        assert_eq!(meta.uid(), target.uid);
        assert_eq!(meta.gid(), target.gid);
        assert_eq!(std::fs::read(&target.path).unwrap(), b"hunter2");
    }

    #[test]
    fn rewrites_replace_content_and_restore_mode() {
        let dir = tempfile::tempdir().unwrap();
        let target = file(dir.path().join("token"), 0o400);
        write_payloads(std::slice::from_ref(&target), &[b"first"]).unwrap();
        // Simulate drift (an interrupted earlier write, a chmod).
        std::fs::set_permissions(&target.path, fs::Permissions::from_mode(0o777)).unwrap();
        write_payloads(std::slice::from_ref(&target), &[b"second"]).unwrap();
        let meta = std::fs::metadata(&target.path).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o400);
        assert_eq!(std::fs::read(&target.path).unwrap(), b"second");
    }

    #[test]
    fn error_names_the_object_and_path_never_the_payload() {
        let dir = tempfile::tempdir().unwrap();
        // Writing below a regular file must fail.
        std::fs::write(dir.path().join("blocker"), b"x").unwrap();
        let target = file(dir.path().join("blocker/impossible"), 0o444);
        let err = write_payloads(&[target], &[b"SUPERSECRETVALUE"]).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("db.password"), "{message}");
        assert!(message.contains("blocker"), "{message}");
        assert!(!message.contains("SUPERSECRETVALUE"), "{message}");
    }
}
