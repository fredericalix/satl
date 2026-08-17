// SPDX-License-Identifier: BSD-2-Clause
//! Small synchronous filesystem helpers (atomic write-rename).
//!
//! Everything here blocks: callers on the async runtime wrap these in
//! `tokio::task::spawn_blocking` (CLAUDE.md invariant #4).

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Atomically replaces `path` with `bytes`: write to `<path>.tmp`, fsync,
/// rename over `path`, fsync the directory. A crash leaves either the old
/// file or the new one, never a torn write.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(tmp, path)?;
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn atomic_write_replaces_content_and_sets_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        atomic_write(&path, b"one", 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o644, "mode was {mode:04o}");

        atomic_write(&path, b"two", 0o644).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert!(!path.with_extension("tmp").exists());
    }
}
