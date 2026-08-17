// SPDX-License-Identifier: BSD-2-Clause
//! At-rest encryption for Raft log entries and snapshots (architecture
//! §12.4), and the autolock half of it (SWK §12.4's KEK, Docker's
//! `swarm --autolock`).
//!
//! The per-manager data encryption key (DEK) lives in `<raft_dir>/dek`, mode
//! `0600`, created from OS randomness on first boot. Every record written to
//! disk by `satl-cluster` — log entries, log metadata, snapshots — is sealed
//! with XChaCha20-Poly1305 under this key.
//!
//! Sealed record format (version 1):
//!
//! ```text
//! [ 0x01 ][ 24-byte XChaCha20-Poly1305 nonce ][ ciphertext + 16-byte tag ]
//! ```
//!
//! The random 24-byte nonce makes nonce reuse a non-concern at any realistic
//! write volume (that is why `XChaCha20` and not `ChaCha20`). The leading version
//! byte leaves room for key rotation via a `MultiDecrypter` shape later
//! (§12.4).
//!
//! # Autolock: the KEK
//!
//! With autolock on, the plain `dek` file is replaced by `dek.sealed` — the
//! DEK itself sealed, in the same record format, under a **key encryption
//! key** that exists only in the operator's hands and inside the
//! DEK-encrypted store (`ClusterSpec::unlock_key`). The circularity is
//! Docker's own: the key is readable from the store only after unlocking,
//! and the store is readable only after it. The KEK is 32 random bytes shown
//! base64-encoded once, at enable and at rotate — no passphrase KDF, because
//! the key is already high-entropy (Docker does the same). A locked manager
//! therefore boots into a listener that answers only `POST /swarm/unlock`;
//! [`Dek::open_sealed`] is the check that turns a presented key into the DEK
//! or into a refusal.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;

/// Sealed record format version this build writes and understands.
const FORMAT_VERSION: u8 = 0x01;

/// XChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// DEK length in bytes (XChaCha20-Poly1305 key size).
pub const DEK_LEN: usize = 32;

/// Name of the plain DEK file inside the raft directory.
pub const DEK_FILE: &str = "dek";

/// Name of the KEK-sealed DEK file inside the raft directory — its presence
/// (with no plain `dek` alongside) is what "this manager is locked" means.
pub const SEALED_DEK_FILE: &str = "dek.sealed";

/// Whether the raft directory is in the locked state: a sealed DEK and no
/// plain one. The boot flow reads no further than this.
#[must_use]
pub fn is_locked(raft_dir: &Path) -> bool {
    raft_dir.join(SEALED_DEK_FILE).exists() && !raft_dir.join(DEK_FILE).exists()
}

/// A fresh unlock key: 32 random bytes, base64-encoded for showing to the
/// operator exactly once (Docker's `SWMKEY`-less shape — plain base64).
#[must_use]
pub fn generate_unlock_key() -> String {
    let mut key = [0_u8; DEK_LEN];
    rand::rng().fill_bytes(&mut key);
    BASE64.encode(key)
}

/// The KEK a base64 unlock key encodes.
///
/// # Errors
///
/// [`UnlockKeyError`] when the string is not base64 for exactly [`DEK_LEN`]
/// bytes — reported to the operator as "invalid unlock key".
pub fn kek_from_unlock_key(encoded: &str) -> Result<Dek, UnlockKeyError> {
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|_| UnlockKeyError::Malformed)?;
    let key: [u8; DEK_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| UnlockKeyError::WrongLength { len: bytes.len() })?;
    Ok(Dek::from_bytes(&key))
}

/// Why an unlock key string was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UnlockKeyError {
    /// Not base64 at all.
    #[error("invalid unlock key: not base64")]
    Malformed,
    /// Base64, but not of a 32-byte key.
    #[error("invalid unlock key: decodes to {len} bytes, expected exactly {DEK_LEN}")]
    WrongLength {
        /// How many bytes the string decoded to.
        len: usize,
    },
}

/// Errors loading or creating the DEK file. Every variant names the file and
/// what the operator should do about it.
#[derive(Debug, thiserror::Error)]
pub enum DekError {
    /// Filesystem error touching the key file.
    #[error("DEK file {path}: {op}: {source}")]
    Io {
        /// The key file.
        path: PathBuf,
        /// What was being attempted.
        op: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The key file is group- or world-accessible.
    #[error(
        "DEK file {path} has mode {mode:04o}; it must not be group- or world-accessible. Run: chmod 600 {path}"
    )]
    Permissions {
        /// The key file.
        path: PathBuf,
        /// The offending permission bits.
        mode: u32,
    },
    /// The key file does not contain exactly [`DEK_LEN`] bytes.
    #[error(
        "DEK file {path} is {len} bytes, expected exactly {DEK_LEN}; the file is corrupt or not a SatL DEK. Restore it from backup (data sealed under the old key is unreadable without it)"
    )]
    WrongLength {
        /// The key file.
        path: PathBuf,
        /// Actual file length.
        len: usize,
    },
}

/// Errors opening a KEK-sealed DEK file ([`Dek::open_sealed`]).
#[derive(Debug, thiserror::Error)]
pub enum OpenSealedError {
    /// Filesystem error reading the sealed file.
    #[error("sealed DEK file {path}: {source}")]
    Io {
        /// The sealed key file.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Authenticated decryption failed: the unlock key is wrong, or the
    /// sealed file was tampered with.
    #[error("the unlock key does not open this manager's sealed DEK ({0})")]
    Unseal(#[from] UnsealError),
    /// The file decrypted to something that is not a 32-byte DEK.
    #[error("sealed DEK file {path} did not contain a {DEK_LEN}-byte key; the file is corrupt")]
    NotADek {
        /// The sealed key file.
        path: PathBuf,
    },
}

/// Writes `bytes` to `path` with mode `0600`, atomically (temp file +
/// rename + fsync): a key file is never half-written.
fn write_key_file(path: &Path, bytes: &[u8]) -> Result<(), DekError> {
    let io = |op: &'static str| {
        let path = path.to_path_buf();
        move |source: std::io::Error| DekError::Io { path, op, source }
    };
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io("create"))?;
        file.write_all(bytes).map_err(io("write"))?;
        file.sync_all().map_err(io("fsync"))?;
    }
    // A `0600` create honours the mode only on a fresh file; a leftover temp
    // file with laxer bits must not keep them through the rename.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(io("set permissions"))?;
    fs::rename(&tmp, path).map_err(io("rename"))
}

/// Errors opening a sealed record.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UnsealError {
    /// The leading version byte is not one this build understands.
    #[error(
        "sealed record has unsupported format version {found:#04x} (this build writes {FORMAT_VERSION:#04x})"
    )]
    UnsupportedVersion {
        /// The version byte found.
        found: u8,
    },
    /// The record is shorter than header + nonce + tag.
    #[error(
        "sealed record is truncated: {len} bytes, need at least {min}",
        min = 1 + NONCE_LEN + TAG_LEN
    )]
    Truncated {
        /// Actual record length.
        len: usize,
    },
    /// Authenticated decryption failed: wrong key, or the record was
    /// tampered with.
    #[error("sealed record failed authenticated decryption: wrong DEK or corrupted/tampered data")]
    Aead,
}

/// The node's data encryption key. Cheap to clone; used from blocking I/O
/// workers and the snapshot builder concurrently.
#[derive(Clone)]
pub struct Dek {
    /// The raw key, kept so the autolock watcher can re-seal it under a KEK
    /// ([`Dek::seal_to`]) or write it back out on unlock-at-boot. Never
    /// printed ([`Debug`] omits it).
    key: [u8; DEK_LEN],
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for Dek {
    /// Never prints key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dek").finish_non_exhaustive()
    }
}

impl Dek {
    /// Builds a DEK from raw key bytes (used by tests and key loading).
    #[must_use]
    pub fn from_bytes(key: &[u8; DEK_LEN]) -> Self {
        // Infallible: the slice length is exactly the key size by type.
        let Ok(cipher) = XChaCha20Poly1305::new_from_slice(key) else {
            unreachable!("DEK_LEN is the XChaCha20-Poly1305 key size")
        };
        Self { key: *key, cipher }
    }

    /// Loads the DEK from `path`, creating it with mode `0600` from OS
    /// randomness on first boot.
    ///
    /// Refuses to use an existing file with lax permissions or the wrong
    /// length — both indicate operator error or corruption, and silently
    /// proceeding would either leak the key or destroy data.
    ///
    /// Synchronous (small file I/O): callers on the async runtime wrap this
    /// in `spawn_blocking`.
    pub fn load_or_create(path: &Path) -> Result<Self, DekError> {
        let io = |op: &'static str| {
            let path = path.to_path_buf();
            move |source: std::io::Error| DekError::Io { path, op, source }
        };

        match fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(DekError::Permissions {
                        path: path.to_path_buf(),
                        mode: mode & 0o7777,
                    });
                }
                let bytes = fs::read(path).map_err(io("read"))?;
                let key: [u8; DEK_LEN] =
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| DekError::WrongLength {
                            path: path.to_path_buf(),
                            len: bytes.len(),
                        })?;
                Ok(Self::from_bytes(&key))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0_u8; DEK_LEN];
                rand::rng().fill_bytes(&mut key);
                // create_new: if another process races us here, fail loudly
                // instead of overwriting a key that may already seal data.
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(io("create"))?;
                file.write_all(&key).map_err(io("write"))?;
                file.sync_all().map_err(io("fsync"))?;
                tracing::info!(path = %path.display(), "created new DEK");
                Ok(Self::from_bytes(&key))
            }
            Err(source) => Err(DekError::Io {
                path: path.to_path_buf(),
                op: "stat",
                source,
            }),
        }
    }

    /// Seals this DEK under `kek` and writes the record to `path` — the
    /// `dek.sealed` of a locked manager. Mode `0600`, temp file + rename +
    /// fsync: the plain key file is removed only after this has landed, so
    /// the window with neither must not exist.
    ///
    /// Synchronous (small file I/O): callers on the async runtime wrap this
    /// in `spawn_blocking`.
    pub fn seal_to(&self, kek: &Dek, path: &Path) -> Result<(), DekError> {
        write_key_file(path, &kek.seal(&self.key))
    }

    /// Writes this DEK as a plain key file — the reverse of [`Dek::seal_to`],
    /// run when autolock is disabled. Mode `0600`, temp file + rename.
    ///
    /// Synchronous, like [`Dek::seal_to`].
    pub fn store_to(&self, path: &Path) -> Result<(), DekError> {
        write_key_file(path, &self.key)
    }

    /// Opens a KEK-sealed DEK file with `kek` — the unlock check. A wrong
    /// key surfaces as [`UnsealError::Aead`], indistinguishable from
    /// tampering, which is exactly what an AEAD is for.
    ///
    /// Synchronous (small file I/O), like [`Dek::load_or_create`].
    pub fn open_sealed(kek: &Dek, path: &Path) -> Result<Self, OpenSealedError> {
        let bytes = fs::read(path).map_err(|source| OpenSealedError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let key: [u8; DEK_LEN] =
            kek.open(&bytes)?
                .as_slice()
                .try_into()
                .map_err(|_| OpenSealedError::NotADek {
                    path: path.to_path_buf(),
                })?;
        Ok(Self::from_bytes(&key))
    }

    /// Seals `plaintext` into a self-contained record:
    /// `[version][nonce][ciphertext+tag]`.
    #[must_use]
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let nonce = XNonce::from(nonce);
        // XChaCha20-Poly1305 encryption of an in-memory buffer is infallible
        // for any input that fits in memory (the aead API returns Result for
        // generality only).
        let Ok(ciphertext) = self.cipher.encrypt(&nonce, plaintext) else {
            unreachable!("XChaCha20-Poly1305 sealing of in-memory buffers cannot fail")
        };
        let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        sealed.push(FORMAT_VERSION);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        sealed
    }

    /// Opens a record produced by [`Dek::seal`], authenticating it.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, UnsealError> {
        let min = 1 + NONCE_LEN + TAG_LEN;
        if sealed.len() < min {
            // Check the version byte first when we have one, so a truncated
            // record of a future version reports the more useful error.
            if let Some(&version) = sealed.first()
                && version != FORMAT_VERSION
            {
                return Err(UnsealError::UnsupportedVersion { found: version });
            }
            return Err(UnsealError::Truncated { len: sealed.len() });
        }
        if sealed[0] != FORMAT_VERSION {
            return Err(UnsealError::UnsupportedVersion { found: sealed[0] });
        }
        // Infallible: the length was checked above.
        let Ok(nonce) = <[u8; NONCE_LEN]>::try_from(&sealed[1..=NONCE_LEN]) else {
            unreachable!("slice is exactly NONCE_LEN bytes");
        };
        let nonce = XNonce::from(nonce);
        self.cipher
            .decrypt(&nonce, &sealed[1 + NONCE_LEN..])
            .map_err(|_| UnsealError::Aead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> Dek {
        Dek::from_bytes(&[7_u8; DEK_LEN])
    }

    #[test]
    fn seal_open_roundtrip() {
        let dek = test_dek();
        for plaintext in [&b""[..], b"x", b"hello raft", &[0_u8; 4096]] {
            let sealed = dek.seal(plaintext);
            assert_eq!(sealed[0], FORMAT_VERSION);
            assert_eq!(dek.open(&sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn seals_are_randomized() {
        let dek = test_dek();
        assert_ne!(dek.seal(b"same"), dek.seal(b"same"));
    }

    #[test]
    fn tamper_detection_any_byte() {
        let dek = test_dek();
        let sealed = dek.seal(b"integrity matters");
        for i in 1..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert_eq!(
                dek.open(&tampered).unwrap_err(),
                UnsealError::Aead,
                "flipping byte {i} went undetected"
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = test_dek().seal(b"secret");
        let other = Dek::from_bytes(&[8_u8; DEK_LEN]);
        assert_eq!(other.open(&sealed).unwrap_err(), UnsealError::Aead);
    }

    #[test]
    fn truncation_detected() {
        let dek = test_dek();
        let sealed = dek.seal(b"will be cut");
        for len in 0..(1 + NONCE_LEN + TAG_LEN) {
            let err = dek.open(&sealed[..len]).unwrap_err();
            assert_eq!(err, UnsealError::Truncated { len }, "at length {len}");
        }
        // One byte short of the full record: long enough for the header
        // check, but the ciphertext no longer authenticates.
        let almost = &sealed[..sealed.len() - 1];
        assert_eq!(dek.open(almost).unwrap_err(), UnsealError::Aead);
    }

    #[test]
    fn version_mismatch_detected() {
        let dek = test_dek();
        let mut sealed = dek.seal(b"future");
        sealed[0] = 0x02;
        assert_eq!(
            dek.open(&sealed).unwrap_err(),
            UnsealError::UnsupportedVersion { found: 0x02 }
        );
        // Version is also reported for records too short to hold a nonce.
        assert_eq!(
            dek.open(&[0x09, 0x00]).unwrap_err(),
            UnsealError::UnsupportedVersion { found: 0x09 }
        );
    }

    #[test]
    fn key_file_created_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dek");
        let dek = Dek::load_or_create(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600, "mode was {mode:04o}");
        assert_eq!(fs::read(&path).unwrap().len(), DEK_LEN);

        // Reload gets the same key: records seal/open across loads.
        let sealed = dek.seal(b"persistent");
        let reloaded = Dek::load_or_create(&path).unwrap();
        assert_eq!(reloaded.open(&sealed).unwrap(), b"persistent");
    }

    #[test]
    fn lax_permissions_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dek");
        Dek::load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = Dek::load_or_create(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, DekError::Permissions { mode: 0o644, .. }),
            "{msg}"
        );
        assert!(msg.contains("chmod 600"), "{msg}");
    }

    #[test]
    fn wrong_length_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dek");
        fs::write(&path, b"short").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = Dek::load_or_create(&path).unwrap_err();
        assert!(matches!(err, DekError::WrongLength { len: 5, .. }), "{err}");
    }

    #[test]
    fn seal_to_and_open_sealed_roundtrip_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SEALED_DEK_FILE);
        let dek = test_dek();
        let kek = Dek::from_bytes(&[9_u8; DEK_LEN]);

        dek.seal_to(&kek, &path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600, "mode was {mode:04o}");
        assert!(!dir.path().join("dek.tmp").exists(), "temp renamed");

        let opened = Dek::open_sealed(&kek, &path).unwrap();
        // The unsealed DEK is the same key: records cross-open.
        let sealed = dek.seal(b"log entry");
        assert_eq!(opened.open(&sealed).unwrap(), b"log entry");
    }

    #[test]
    fn open_sealed_with_the_wrong_key_is_an_authentication_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(SEALED_DEK_FILE);
        test_dek()
            .seal_to(&Dek::from_bytes(&[9_u8; DEK_LEN]), &path)
            .unwrap();

        let wrong = Dek::from_bytes(&[8_u8; DEK_LEN]);
        let err = Dek::open_sealed(&wrong, &path).unwrap_err();
        assert!(
            matches!(err, OpenSealedError::Unseal(UnsealError::Aead)),
            "{err}"
        );
    }

    #[test]
    fn store_to_writes_the_plain_key_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEK_FILE);
        test_dek().store_to(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600, "mode was {mode:04o}");
        // And `load_or_create` reads it as its own.
        let reloaded = Dek::load_or_create(&path).unwrap();
        let sealed = test_dek().seal(b"across the lock boundary");
        assert_eq!(reloaded.open(&sealed).unwrap(), b"across the lock boundary");
    }

    #[test]
    fn is_locked_reads_the_two_files() {
        let dir = tempfile::tempdir().unwrap();
        let raft = dir.path();
        assert!(!is_locked(raft), "empty: a first boot is not locked");
        fs::write(raft.join(DEK_FILE), [7_u8; DEK_LEN]).unwrap();
        assert!(!is_locked(raft), "a plain DEK: unlocked");
        fs::write(raft.join(SEALED_DEK_FILE), b"sealed").unwrap();
        assert!(
            !is_locked(raft),
            "both files: mid-transition, still unlocked"
        );
        fs::remove_file(raft.join(DEK_FILE)).unwrap();
        assert!(is_locked(raft));
    }

    #[test]
    fn unlock_keys_generate_and_parse() {
        let key = generate_unlock_key();
        assert!(kek_from_unlock_key(&key).is_ok());
        // Whitespace from an operator's paste is tolerated.
        assert!(kek_from_unlock_key(&format!("  {key}\n")).is_ok());
        // Two generations never collide (a 32-byte random space).
        assert_ne!(generate_unlock_key(), generate_unlock_key());

        assert_eq!(
            kek_from_unlock_key("!!! not base64 !!!").unwrap_err(),
            UnlockKeyError::Malformed
        );
        let short = BASE64.encode([1_u8; 16]);
        assert_eq!(
            kek_from_unlock_key(&short).unwrap_err(),
            UnlockKeyError::WrongLength { len: 16 }
        );
    }
}
