// SPDX-License-Identifier: BSD-2-Clause
//! On-disk TLS material (architecture §12.2, SWK §16.6).
//!
//! Layout, under the daemon's state directory:
//!
//! ```text
//! <state_dir>/certs/node.key   0600   PKCS#8 private key
//! <state_dir>/certs/node.crt   0644   this node's certificate
//! <state_dir>/certs/ca.crt     0644   the cluster root CA bundle
//! ```
//!
//! Writes go to a temporary file in the same directory, are `fsync`ed, then
//! renamed — a crash mid-write leaves the previous identity intact rather than
//! a truncated key. The key is written **last**: it is the synchronization
//! point, exactly as SwarmKit's `KeyReadWriter` treats it (SWK §16.6), so a
//! half-applied update never presents a new key with an old certificate.
//!
//! Loading refuses a key file that is group- or world-readable. That is not
//! paranoia about a hypothetical: the node key is the node's whole identity in
//! the cluster, and a `0644` key file is an operator mistake worth stopping
//! the daemon over.
//!
//! Out of scope (architecture §14): the KEK/autolock PEM headers SwarmKit
//! carries in this file, and the manager DEK stored alongside it (§12.4) —
//! both land with their own milestones.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tracing::{debug, info};

/// Mode of the private key file: owner read/write only.
pub const KEY_MODE: u32 = 0o600;

/// Mode of the certificate files: world readable.
pub const CERT_MODE: u32 = 0o644;

/// Mode of the `certs` directory itself.
pub const DIR_MODE: u32 = 0o700;

/// Bits that must not be set on the key file.
const FORBIDDEN_KEY_BITS: u32 = 0o077;

const KEY_FILE: &str = "node.key";
const CERT_FILE: &str = "node.crt";
const CA_FILE: &str = "ca.crt";

/// Failures reading or writing the node's TLS material.
///
/// Every variant names the path involved: this is the error an operator reads
/// at 3 a.m. when a node refuses to start.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The certificate directory could not be created or inspected.
    #[error("failed to prepare the certificate directory {dir}: {source}")]
    Directory {
        /// The directory involved.
        dir: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A file could not be read.
    #[error("failed to read {path}: {source}")]
    Read {
        /// The file involved.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A file could not be written.
    #[error("failed to write {path} (via the temporary file {temp}): {source}")]
    Write {
        /// The destination file.
        path: PathBuf,
        /// The temporary file it was staged through.
        temp: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Some but not all of the three files are present.
    #[error(
        "the certificate directory {dir} is incomplete: {present} is present but {missing} is \
         missing. Remove the directory to re-join the cluster, or restore the missing file"
    )]
    Incomplete {
        /// The directory involved.
        dir: PathBuf,
        /// A file that is there.
        present: &'static str,
        /// The file that is not.
        missing: &'static str,
    },

    /// The key file is readable by more than its owner.
    #[error(
        "refusing to load the node private key {path}: mode is {mode:04o}, which lets the group \
         or other users read this node's identity. Run `chmod 0600 {path}` (satl writes it \
         {expected:04o})"
    )]
    KeyPermissions {
        /// The key file.
        path: PathBuf,
        /// The mode found.
        mode: u32,
        /// The mode SatL writes.
        expected: u32,
    },
}

/// The three PEM blobs that make up a node's TLS identity.
///
/// `Debug` redacts the private key.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// This node's certificate chain, PEM (leaf first).
    pub cert_pem: String,
    /// This node's private key, PKCS#8 PEM. **Never log this.**
    pub key_pem: String,
    /// The cluster root CA bundle, PEM.
    pub ca_pem: String,
}

impl NodeIdentity {
    /// Assembles an identity from its three PEM blobs.
    #[must_use]
    pub fn new(cert_pem: String, key_pem: String, ca_pem: String) -> Self {
        Self {
            cert_pem,
            key_pem,
            ca_pem,
        }
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .field("ca_pem_len", &self.ca_pem.len())
            .finish()
    }
}

/// Where the three files live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPaths {
    /// `<dir>/node.key`.
    pub key: PathBuf,
    /// `<dir>/node.crt`.
    pub cert: PathBuf,
    /// `<dir>/ca.crt`.
    pub ca: PathBuf,
}

/// The node's certificate directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertStore {
    dir: PathBuf,
}

impl CertStore {
    /// Opens (creating if needed) the certificate directory `dir`.
    ///
    /// The directory is created `0700`; an existing directory's mode is left
    /// alone, since operators sometimes widen it deliberately for a monitoring
    /// user — only the key file's mode is enforced, on load.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let dir = dir.as_ref().to_path_buf();
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|source| StoreError::Directory {
                dir: dir.clone(),
                source,
            })?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE)).map_err(|source| {
                StoreError::Directory {
                    dir: dir.clone(),
                    source,
                }
            })?;
            debug!(dir = %dir.display(), mode = format!("{DIR_MODE:04o}"), "created certificate directory");
        }
        Ok(Self { dir })
    }

    /// The directory itself.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The three file paths.
    #[must_use]
    pub fn paths(&self) -> CertPaths {
        CertPaths {
            key: self.dir.join(KEY_FILE),
            cert: self.dir.join(CERT_FILE),
            ca: self.dir.join(CA_FILE),
        }
    }

    /// Loads the stored identity, if this node has one.
    ///
    /// `Ok(None)` means "never joined a cluster" — all three files absent. A
    /// partially populated directory is an error, not a silent re-join: it
    /// usually means someone deleted one file by hand.
    pub fn load(&self) -> Result<Option<NodeIdentity>, StoreError> {
        let paths = self.paths();
        let present = [
            (KEY_FILE, paths.key.exists()),
            (CERT_FILE, paths.cert.exists()),
            (CA_FILE, paths.ca.exists()),
        ];
        if present.iter().all(|(_, exists)| !exists) {
            debug!(dir = %self.dir.display(), "no stored node identity");
            return Ok(None);
        }
        if let Some((missing, _)) = present.iter().find(|(_, exists)| !exists) {
            let (found, _) = present
                .iter()
                .find(|(_, exists)| *exists)
                .unwrap_or(&(KEY_FILE, true));
            return Err(StoreError::Incomplete {
                dir: self.dir.clone(),
                present: found,
                missing,
            });
        }

        check_key_mode(&paths.key)?;

        let identity = NodeIdentity {
            cert_pem: read(&paths.cert)?,
            key_pem: read(&paths.key)?,
            ca_pem: read(&paths.ca)?,
        };
        debug!(
            dir = %self.dir.display(),
            cert_bytes = identity.cert_pem.len(),
            "loaded node identity"
        );
        Ok(Some(identity))
    }

    /// Writes the identity atomically, with the documented modes.
    ///
    /// Order is CA bundle, certificate, key: the key lands last so a crash
    /// never leaves a key that does not match the certificate beside it.
    pub fn save(&self, identity: &NodeIdentity) -> Result<(), StoreError> {
        let paths = self.paths();
        write_atomic(&paths.ca, identity.ca_pem.as_bytes(), CERT_MODE)?;
        write_atomic(&paths.cert, identity.cert_pem.as_bytes(), CERT_MODE)?;
        write_atomic(&paths.key, identity.key_pem.as_bytes(), KEY_MODE)?;
        sync_dir(&self.dir)?;
        info!(
            dir = %self.dir.display(),
            key_mode = format!("{KEY_MODE:04o}"),
            "stored node identity"
        );
        Ok(())
    }
}

fn check_key_mode(path: &Path) -> Result<(), StoreError> {
    let metadata = fs::metadata(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & FORBIDDEN_KEY_BITS != 0 {
        return Err(StoreError::KeyPermissions {
            path: path.to_path_buf(),
            mode,
            expected: KEY_MODE,
        });
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, StoreError> {
    fs::read_to_string(path).map_err(|source| StoreError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), StoreError> {
    let temp = path.with_extension("tmp");
    let fail = |source: std::io::Error| StoreError::Write {
        path: path.to_path_buf(),
        temp: temp.clone(),
        source,
    };

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temp)
        .map_err(fail)?;
    file.write_all(contents).map_err(fail)?;
    file.sync_all().map_err(fail)?;
    // `mode` only applies to a file this call created; force it either way so
    // a leftover temp file cannot widen the key's permissions.
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode)).map_err(fail)?;
    drop(file);
    fs::rename(&temp, path).map_err(fail)?;
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    // Durability of the renames themselves; harmless if the platform refuses.
    match File::open(dir) {
        Ok(handle) => handle.sync_all().map_err(|source| StoreError::Directory {
            dir: dir.to_path_buf(),
            source,
        }),
        Err(source) => Err(StoreError::Directory {
            dir: dir.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NodeIdentity {
        NodeIdentity::new(
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n".to_owned(),
            "-----BEGIN PRIVATE KEY-----\nsupersecretkeymaterial\n-----END PRIVATE KEY-----\n"
                .to_owned(),
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n".to_owned(),
        )
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path)
            .expect("file exists")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn open_creates_the_directory_with_a_private_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("state").join("certs");
        let store = CertStore::open(&dir).expect("open");
        assert!(dir.is_dir());
        assert_eq!(mode_of(&dir), DIR_MODE);
        assert_eq!(store.dir(), dir);

        // Re-opening an existing directory is fine and does not change it.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).expect("chmod");
        CertStore::open(&dir).expect("reopen");
        assert_eq!(mode_of(&dir), 0o750);
    }

    #[test]
    fn paths_are_the_pinned_names() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        let paths = store.paths();
        assert_eq!(
            paths.key.file_name().and_then(|n| n.to_str()),
            Some("node.key")
        );
        assert_eq!(
            paths.cert.file_name().and_then(|n| n.to_str()),
            Some("node.crt")
        );
        assert_eq!(
            paths.ca.file_name().and_then(|n| n.to_str()),
            Some("ca.crt")
        );
    }

    #[test]
    fn empty_directory_loads_as_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        assert!(store.load().expect("load").is_none());
    }

    #[test]
    fn save_then_load_roundtrips_with_the_documented_modes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        let original = identity();
        store.save(&original).expect("save");

        let paths = store.paths();
        assert_eq!(mode_of(&paths.key), KEY_MODE, "key must be 0600");
        assert_eq!(mode_of(&paths.cert), CERT_MODE);
        assert_eq!(mode_of(&paths.ca), CERT_MODE);

        let loaded = store.load().expect("load").expect("identity present");
        assert_eq!(loaded, original);

        // No temporary files left behind.
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left temporary files: {leftovers:?}");
    }

    #[test]
    fn save_overwrites_an_existing_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        store.save(&identity()).expect("save");

        let mut renewed = identity();
        renewed.cert_pem =
            "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----\n".to_owned();
        store.save(&renewed).expect("save again");

        let loaded = store.load().expect("load").expect("present");
        assert_eq!(loaded.cert_pem, renewed.cert_pem);
        assert_eq!(mode_of(&store.paths().key), KEY_MODE);
    }

    #[test]
    fn a_group_readable_key_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        store.save(&identity()).expect("save");

        for bad in [0o644, 0o640, 0o604, 0o666, 0o660] {
            fs::set_permissions(&store.paths().key, fs::Permissions::from_mode(bad))
                .expect("chmod");
            let err = store
                .load()
                .expect_err("a world/group readable key must be refused");
            match err {
                StoreError::KeyPermissions { mode, expected, .. } => {
                    assert_eq!(mode, bad);
                    assert_eq!(expected, KEY_MODE);
                }
                other => panic!("unexpected error for mode {bad:04o}: {other}"),
            }
            // The message tells the operator exactly what to do.
            let rendered = store.load().expect_err("still refused").to_string();
            assert!(rendered.contains("chmod 0600"), "{rendered}");
        }

        // 0600 and 0400 are both fine.
        for good in [0o600, 0o400] {
            fs::set_permissions(&store.paths().key, fs::Permissions::from_mode(good))
                .expect("chmod");
            assert!(store.load().expect("load").is_some(), "mode {good:04o}");
        }
    }

    #[test]
    fn an_incomplete_directory_is_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        store.save(&identity()).expect("save");
        fs::remove_file(&store.paths().ca).expect("remove ca");

        let err = store.load().expect_err("incomplete directory must fail");
        match err {
            StoreError::Incomplete { missing, .. } => assert_eq!(missing, CA_FILE),
            other => panic!("unexpected error: {other}"),
        }

        fs::remove_file(&store.paths().cert).expect("remove cert");
        fs::remove_file(&store.paths().key).expect("remove key");
        assert!(store.load().expect("load").is_none(), "empty again");
    }

    #[test]
    fn a_missing_key_alone_is_reported() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        store.save(&identity()).expect("save");
        fs::remove_file(&store.paths().key).expect("remove key");
        let err = store.load().expect_err("must fail");
        assert!(err.to_string().contains("node.key"), "{err}");
    }

    #[test]
    fn a_stale_temporary_file_cannot_widen_the_key_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        let stale = store.paths().key.with_extension("tmp");
        fs::write(&stale, b"stale").expect("write stale temp");
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o666)).expect("chmod");

        store.save(&identity()).expect("save over the stale temp");
        assert_eq!(mode_of(&store.paths().key), KEY_MODE);
        store.load().expect("load").expect("present");
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let identity = identity();
        let rendered = format!("{identity:?}");
        assert!(!rendered.contains("supersecretkeymaterial"), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(rendered.contains("redacted"));

        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        assert!(!format!("{store:?}").contains("supersecret"));
    }

    #[test]
    fn errors_name_the_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = CertStore::open(tmp.path()).expect("open");
        store.save(&identity()).expect("save");
        fs::set_permissions(&store.paths().key, fs::Permissions::from_mode(0o644)).expect("chmod");
        let rendered = store.load().expect_err("refused").to_string();
        assert!(
            rendered.contains(&store.paths().key.display().to_string()),
            "{rendered}"
        );
    }
}
