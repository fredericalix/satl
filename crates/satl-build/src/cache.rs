// SPDX-License-Identifier: BSD-2-Clause
//! The incremental build cache (M8b): one entry per mutating step, content-
//! addressed, so a rebuild reuses a step whose inputs did not move instead
//! of re-executing it.
//!
//! # The key
//!
//! `sha256` of the canonical JSON (object keys sorted, no whitespace) of:
//!
//! ```json
//! {"parent": "<OCI chain ID digest of the layer stack so far>",
//!  "step": { …kind + payload… }}
//! ```
//!
//! Payloads: PKG = sorted package list + pkg ABI; COPY = resolved dest +
//! sorted (source path, content hash of the source tree) pairs — plus, for a
//! `COPY --from` (M8c), the source stage's index, with the hash read from
//! that stage's finished rootfs so a rebuilt builder invalidates the final
//! stage; RUN = command + env + workdir. The parent chain is the OCI chain
//! ID of the `diff_ids` up to this step, so the first step keys off the
//! stage's base image — or off the canonical empty chain for `FROM scratch`
//! — and a different base, a different earlier step, or a different stage
//! invalidates everything after it. (A step whose diff came out empty adds
//! no layer and therefore no chain link; its own key still changes when its
//! payload does, which is the half that matters.)
//!
//! # Layout
//!
//! ```text
//! <cache-dir>/entries/<key>.json    diff_id, blob digest, post-step inventory
//! <cache-dir>/blobs/<key>           the gzipped layer
//! ```
//!
//! An entry whose blob is missing, or whose JSON does not parse, is simply a
//! miss: the cache is a cache, never a correctness dependency. A store
//! failure is logged and the build proceeds uncached.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::inventory::{Entry, Inventory};

/// The default cache location (`--cache-dir` overrides).
pub const DEFAULT_CACHE_DIR: &str = "/var/db/satl/build-cache";

/// One step's cached outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The instruction text ("RUN npm install"), for logs and debugging.
    pub instruction: String,
    /// The step's `diff_id`; `None` for a step whose diff was empty (no layer,
    /// but the *decision* is still cached — it does not re-execute).
    pub diff_id: Option<String>,
    /// The step's blob digest, when it has a layer.
    pub blob_digest: Option<String>,
    /// The blob's byte length.
    pub size: u64,
    /// The post-step inventory, adopted wholesale on a hit (the layer is
    /// applied to the rootfs first — a later miss needs the real tree).
    pub inventory: BTreeMap<String, Entry>,
}

/// A build cache in a directory. Cheap to construct; directories are made on
/// the first store.
#[derive(Debug, Clone)]
pub struct BuildCache {
    dir: PathBuf,
}

impl BuildCache {
    /// A cache rooted at `dir` (the default is [`DEFAULT_CACHE_DIR`]).
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The entry file for `key`.
    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join("entries").join(format!("{key}.json"))
    }

    /// The blob file for `key`.
    #[must_use]
    pub fn blob_path(&self, key: &str) -> PathBuf {
        self.dir.join("blobs").join(key)
    }

    /// The cached outcome for `key`, or `None` — a miss — which is also the
    /// answer for a corrupt entry, a missing blob or an unreadable file.
    #[must_use]
    pub fn load(&self, key: &str) -> Option<CacheEntry> {
        let bytes = std::fs::read(self.entry_path(key)).ok()?;
        let entry: CacheEntry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(key, %error, "ignoring an unparseable build-cache entry");
                return None;
            }
        };
        if entry.diff_id.is_some() && !self.blob_path(key).exists() {
            tracing::warn!(
                key,
                "build-cache entry without its blob; treating as a miss"
            );
            return None;
        }
        Some(entry)
    }

    /// Records a step's outcome: the blob (when the step has a layer) and the
    /// entry JSON, both written temp-then-rename. Failures are the caller's
    /// to log — the build must not fail over a cache.
    pub fn store(&self, key: &str, entry: &CacheEntry, blob: Option<&[u8]>) -> std::io::Result<()> {
        let entries = self.dir.join("entries");
        let blobs = self.dir.join("blobs");
        std::fs::create_dir_all(&entries)?;
        std::fs::create_dir_all(&blobs)?;
        if let Some(blob) = blob {
            write_atomic(&blobs.join(key), blob)?;
        }
        let json = serde_json::to_vec_pretty(entry).map_err(std::io::Error::other)?;
        write_atomic(&entries.join(format!("{key}.json")), &json)
    }
}

/// The cache key of one step: sha256 of the canonical JSON of the parent
/// chain ID and the step payload (see the module docs). Canonical because
/// `serde_json`'s map is a `BTreeMap` — keys serialize sorted.
#[must_use]
pub fn key(parent_chain: &str, payload: &serde_json::Value) -> String {
    let canonical = serde_json::to_string(&serde_json::json!({
        "parent": parent_chain,
        "step": payload,
    }))
    .expect("strings and values serialize");
    crate::repack::sha256_hex(canonical.as_bytes())
}

/// Writes `bytes` to `path` atomically (temp file + rename), like every
/// other state file in the tree.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// The serialized form of an inventory (cache entries key paths as strings).
pub fn inventory_to_wire(inventory: &Inventory) -> BTreeMap<String, Entry> {
    inventory
        .iter()
        .map(|(path, entry)| (path.to_string_lossy().into_owned(), entry.clone()))
        .collect()
}

/// Back from the wire.
pub fn inventory_from_wire(wire: BTreeMap<String, Entry>) -> Inventory {
    wire.into_iter()
        .map(|(path, entry)| (PathBuf::from(path), entry))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_is_pinned_canonical_json() {
        // The whole cache contract in one golden: parent chain first, step
        // second, keys sorted, no whitespace. A change here invalidates every
        // cache on every node — that is what this pin exists to notice.
        let payload = serde_json::json!({
            "command": "npm install",
            "env": [["PATH", "/usr/bin"]],
            "kind": "run",
            "workdir": "/srv",
        });
        let key = key(
            "sha256:0139c1c77468f75e6763a4612262743bd47a36b26cb2863d662756b3377bb029",
            &payload,
        );
        assert_eq!(
            key,
            "aefb2afe7c98a069a7b5d27c3834124e65ace16f1f058da271c8ebc88a9560eb"
        );
    }

    #[test]
    fn store_load_roundtrip_and_missing_blob_is_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BuildCache::new(dir.path().to_path_buf());
        let mut inventory = BTreeMap::new();
        inventory.insert(
            "etc/motd".to_owned(),
            Entry {
                kind: crate::inventory::EntryKind::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: 3,
                mtime_ns: 42,
                link: None,
                rdev: None,
            },
        );
        let entry = CacheEntry {
            instruction: "COPY app /srv".to_owned(),
            diff_id: Some("sha256:abc".to_owned()),
            blob_digest: Some("sha256:def".to_owned()),
            size: 5,
            inventory,
        };
        cache.store("k1", &entry, Some(b"blob")).expect("store");
        let loaded = cache.load("k1").expect("a hit");
        assert_eq!(loaded.diff_id.as_deref(), Some("sha256:abc"));
        assert!(loaded.inventory.contains_key("etc/motd"));

        // The blob goes: the entry alone is not a hit.
        std::fs::remove_file(cache.blob_path("k1")).unwrap();
        assert!(cache.load("k1").is_none());

        // Garbage parses as nothing, quietly.
        std::fs::write(dir.path().join("entries/k2.json"), b"not json").unwrap();
        assert!(cache.load("k2").is_none());
        assert!(cache.load("k3").is_none(), "absent entry is a miss");
    }

    #[test]
    fn an_empty_diff_is_a_cacheable_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BuildCache::new(dir.path().to_path_buf());
        let entry = CacheEntry {
            instruction: "RUN true".to_owned(),
            diff_id: None,
            blob_digest: None,
            size: 0,
            inventory: BTreeMap::new(),
        };
        cache.store("k", &entry, None).expect("store");
        let loaded = cache.load("k").expect("a hit");
        assert!(loaded.diff_id.is_none());
    }

    #[test]
    fn the_inventory_wire_form_round_trips() {
        let mut inventory = Inventory::new();
        inventory.insert(
            PathBuf::from("etc/motd"),
            Entry {
                kind: crate::inventory::EntryKind::File,
                mode: 0o644,
                uid: 1,
                gid: 2,
                size: 3,
                mtime_ns: 42,
                link: None,
                rdev: None,
            },
        );
        let back = inventory_from_wire(inventory_to_wire(&inventory));
        assert_eq!(back, inventory);
    }
}
