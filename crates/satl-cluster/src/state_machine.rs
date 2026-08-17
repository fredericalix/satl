// SPDX-License-Identifier: BSD-2-Clause
//! The Raft state machine: the in-memory object store (architecture §6.1)
//! plus snapshot build/install/persistence (§6.3).
//!
//! # Locking model (architecture §6.2, normative)
//!
//! One `parking_lot::RwLock` protects [`StoreInner`]. The only writer is the
//! Raft apply path; apply is **pure in-memory** (CLAUDE.md invariant #4): it
//! decodes, validates and mutates maps — no I/O, no syscalls, no awaits —
//! so the write lock is held for microseconds.
//!
//! `parking_lot` over `std::sync::RwLock`, for two load-bearing reasons:
//!
//! - its guards are `!Send`, so holding one across an `.await` in any
//!   spawned (`Send`) future is a **compile error** — the "no await while
//!   holding the lock" rule is machine-checked, not convention;
//! - it does not poison: lock acquisition is infallible, which keeps the
//!   no-`unwrap` rule intact on every read path.
//!
//! # Watch feed
//!
//! After the write lock is released, the transaction's events
//! (`Created`/`Updated{old,new}`/`Removed` per action, then a
//! `Commit(version)` marker) are published on a bounded
//! [`tokio::sync::broadcast`] channel. **Lagged-receiver contract**: a
//! watcher that observes [`broadcast::error::RecvError::Lagged`] has lost
//! events irrecoverably and must re-sync by taking a fresh
//! [`crate::ClusterStore::view`] snapshot read, then resume watching —
//! object versions make the cutover unambiguous. No unbounded buffering, no
//! blocking publishers.
//!
//! # Snapshots
//!
//! A snapshot is the full store (all seven maps) + `last_applied` +
//! membership, CBOR-serialized into one blob (`SnapshotData =
//! Cursor<Vec<u8>>`). The latest snapshot is persisted to
//! `<raft_dir>/snapshot` with atomic write-rename and reloaded on restart.
//!
//! **Encryption boundary**: the *persisted file* is sealed with this node's
//! DEK (§12.4); the in-memory/on-wire `SnapshotData` blob is plaintext CBOR.
//! DEKs are per-manager and never shared, so a snapshot sealed by the leader
//! would be garbage to a follower — exactly like SwarmKit, at-rest
//! encryption is local to each manager, and snapshot *transfer* is protected
//! by the mTLS transport (M2, architecture §7).
//!
//! Snapshot **install** replaces the store contents wholesale, without
//! re-stamping versions and without per-object events: an install means this
//! node is a follower catching up (M2+), and any watcher is by definition
//! arbitrarily far behind — it must re-sync from a snapshot read exactly as
//! a lagged watcher does, rather than replay a synthetic diff.

// Triaged pedantic allow: `StorageError<u64>` (~200 bytes) is the error type
// imposed by openraft's storage trait signatures — it cannot be boxed here,
// and these are cold error paths.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeSet, HashMap};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openraft::storage::RaftStateMachine;
use openraft::{
    AnyError, BasicNode, EntryPayload, ErrorSubject, ErrorVerb, LogId, OptionalSend,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use satl_core::defaults::{MAX_TX_ACTIONS, MAX_TX_BYTES};
use satl_core::{
    Cluster, Config, Id, Network, Node, ObjectKind, Secret, Service, StoreAction, StoreEvent,
    StoreObject, Task, Version,
};

use crate::crypto::{Dek, UnsealError};
use crate::fs_util::atomic_write;
use crate::types::{Proposal, ProposalRejection, ProposalResponse, TypeConfig};

type Entry = openraft::Entry<TypeConfig>;

/// Capacity of the store watch feed. Sized so that control loops that poll
/// every few milliseconds never lag in practice; a consumer that still lags
/// must re-sync from a snapshot read (see the module docs).
pub const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Filename of the persisted snapshot inside the raft directory.
pub const SNAPSHOT_FILE_NAME: &str = "snapshot";

/// Error loading the persisted snapshot at startup.
#[derive(Debug, thiserror::Error)]
pub enum StateMachineError {
    /// Filesystem error touching the snapshot file.
    #[error("snapshot file {path}: {op}: {source}")]
    Io {
        /// The snapshot file.
        path: PathBuf,
        /// What was being attempted.
        op: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The snapshot file failed authenticated decryption.
    #[error("snapshot file {path}: {source}")]
    Unseal {
        /// The snapshot file.
        path: PathBuf,
        /// Underlying unseal error.
        #[source]
        source: UnsealError,
    },
    /// The snapshot decrypted but did not decode as a snapshot payload.
    #[error("snapshot file {path}: decode: {message}")]
    Decode {
        /// The snapshot file.
        path: PathBuf,
        /// Decoder error text.
        message: String,
    },
}

/// The in-memory object store: seven typed maps plus a name index and the
/// Raft apply cursors. Objects are immutable once inserted — updates swap
/// the `Arc` — so readers clone cheap handles and never see torn state.
#[derive(Debug, Default)]
pub(crate) struct StoreInner {
    pub(crate) clusters: HashMap<Id, Arc<Cluster>>,
    pub(crate) nodes: HashMap<Id, Arc<Node>>,
    pub(crate) services: HashMap<Id, Arc<Service>>,
    pub(crate) tasks: HashMap<Id, Arc<Task>>,
    pub(crate) networks: HashMap<Id, Arc<Network>>,
    pub(crate) secrets: HashMap<Id, Arc<Secret>>,
    pub(crate) configs: HashMap<Id, Arc<Config>>,
    /// Name index for named kinds (see [`object_name`]). Tasks are not
    /// indexed: task names are derived (`<service>.<slot>`) and resolved
    /// through their service.
    pub(crate) names: HashMap<(ObjectKind, String), Id>,
    pub(crate) last_applied: Option<LogId<u64>>,
    pub(crate) last_membership: StoredMembership<u64, BasicNode>,
    /// Raft member IDs that have been removed from the group and must never
    /// be re-admitted or reused (SWK §11.1, architecture §6.6).
    ///
    /// Derived deterministically from the applied membership entries — every
    /// replica sees the same `Membership` payloads in the same order, so every
    /// replica computes the same set — and carried in snapshots so it survives
    /// log compaction and follower catch-up.
    pub(crate) removed_raft_ids: BTreeSet<u64>,
}

/// The user-facing name of an object, for the name index. `None` for kinds
/// that are not name-addressable (tasks) or unnamed objects (nodes without
/// an operator-assigned name).
fn object_name(object: &StoreObject) -> Option<&str> {
    match object {
        StoreObject::Cluster(o) => Some(&o.spec.annotations.name),
        StoreObject::Node(o) => o.spec.name.as_deref(),
        StoreObject::Service(o) => Some(&o.spec.annotations.name),
        StoreObject::Task(_) => None,
        StoreObject::Network(o) => Some(&o.spec.annotations.name),
        StoreObject::Secret(o) => Some(&o.spec.annotations.name),
        StoreObject::Config(o) => Some(&o.spec.annotations.name),
    }
}

/// The stored version of an object carried in a proposal.
fn object_version(object: &StoreObject) -> u64 {
    match object {
        StoreObject::Cluster(o) => o.meta.version.0,
        StoreObject::Node(o) => o.meta.version.0,
        StoreObject::Service(o) => o.meta.version.0,
        StoreObject::Task(o) => o.meta.version.0,
        StoreObject::Network(o) => o.meta.version.0,
        StoreObject::Secret(o) => o.meta.version.0,
        StoreObject::Config(o) => o.meta.version.0,
    }
}

/// Stamps the store-assigned version (the Raft log index of the applying
/// entry) onto an object. Timestamps are proposer-supplied and untouched.
fn stamp_version(object: &mut StoreObject, version: Version) {
    match object {
        StoreObject::Cluster(o) => o.meta.version = version,
        StoreObject::Node(o) => o.meta.version = version,
        StoreObject::Service(o) => o.meta.version = version,
        StoreObject::Task(o) => o.meta.version = version,
        StoreObject::Network(o) => o.meta.version = version,
        StoreObject::Secret(o) => o.meta.version = version,
        StoreObject::Config(o) => o.meta.version = version,
    }
}

/// Stamps `Service::spec_version`, which moves only when the spec itself
/// changes (SWK §4.1).
///
/// It lives here, beside [`stamp_version`], for two reasons. Every replica
/// applies the same `old` and `new` at the same log index, so the outcome is
/// identical everywhere — a proposer computing it would not be. And the
/// rolling updater writes `update_status` on the object it is rolling, so a
/// version that moved on those writes would mark every task dirty on every
/// tick; carrying the old value forward when the spec is untouched is what
/// makes the dirtiness fast path usable at all.
///
/// A `Create` passes `old = None` and so takes its creation index, which
/// discards whatever the proposer put there — the same discipline
/// [`stamp_version`] applies to `meta.version`.
fn stamp_spec_version(new: &mut StoreObject, old: Option<&StoreObject>, version: Version) {
    let StoreObject::Service(new) = new else {
        return;
    };
    match old {
        // The spec is untouched, so the version it was published under stands.
        Some(StoreObject::Service(old)) if old.spec == new.spec => {
            new.spec_version = old.spec_version;
        }
        // Changed spec, or an update against a service that is not there (the
        // validator rejects that, so this arm is unreachable in practice):
        // this index is the spec's new version.
        _ => new.spec_version = version,
    }
}

/// Existence/version overlay used while validating a transaction against
/// the pre-transaction store state plus the transaction's own earlier
/// actions.
enum Overlay {
    Exists(u64),
    Removed,
}

impl StoreInner {
    /// Whether `(kind, id)` exists in the store.
    fn contains(&self, kind: ObjectKind, id: &Id) -> bool {
        match kind {
            ObjectKind::Cluster => self.clusters.contains_key(id),
            ObjectKind::Node => self.nodes.contains_key(id),
            ObjectKind::Service => self.services.contains_key(id),
            ObjectKind::Task => self.tasks.contains_key(id),
            ObjectKind::Network => self.networks.contains_key(id),
            ObjectKind::Secret => self.secrets.contains_key(id),
            ObjectKind::Config => self.configs.contains_key(id),
        }
    }

    /// The stored version of `(kind, id)`, if present.
    fn version_of(&self, kind: ObjectKind, id: &Id) -> Option<u64> {
        match kind {
            ObjectKind::Cluster => self.clusters.get(id).map(|o| o.meta.version.0),
            ObjectKind::Node => self.nodes.get(id).map(|o| o.meta.version.0),
            ObjectKind::Service => self.services.get(id).map(|o| o.meta.version.0),
            ObjectKind::Task => self.tasks.get(id).map(|o| o.meta.version.0),
            ObjectKind::Network => self.networks.get(id).map(|o| o.meta.version.0),
            ObjectKind::Secret => self.secrets.get(id).map(|o| o.meta.version.0),
            ObjectKind::Config => self.configs.get(id).map(|o| o.meta.version.0),
        }
    }

    /// Deep-clones the stored object `(kind, id)` for event payloads.
    pub(crate) fn get_object(&self, kind: ObjectKind, id: &Id) -> Option<StoreObject> {
        match kind {
            ObjectKind::Cluster => self
                .clusters
                .get(id)
                .map(|o| StoreObject::Cluster((**o).clone())),
            ObjectKind::Node => self.nodes.get(id).map(|o| StoreObject::Node((**o).clone())),
            ObjectKind::Service => self
                .services
                .get(id)
                .map(|o| StoreObject::Service((**o).clone())),
            ObjectKind::Task => self.tasks.get(id).map(|o| StoreObject::Task((**o).clone())),
            ObjectKind::Network => self
                .networks
                .get(id)
                .map(|o| StoreObject::Network((**o).clone())),
            ObjectKind::Secret => self
                .secrets
                .get(id)
                .map(|o| StoreObject::Secret((**o).clone())),
            ObjectKind::Config => self
                .configs
                .get(id)
                .map(|o| StoreObject::Config((**o).clone())),
        }
    }

    /// Inserts (or replaces) an object, keeping the name index consistent.
    fn insert_object(&mut self, object: StoreObject) {
        let kind = object.kind();
        let id = object.id().clone();
        // Drop the old name mapping if the replaced object had one that
        // pointed at this id.
        if let Some(old) = self.get_object(kind, &id)
            && let Some(old_name) = object_name(&old)
        {
            let key = (kind, old_name.to_owned());
            if self.names.get(&key) == Some(&id) {
                self.names.remove(&key);
            }
        }
        if let Some(name) = object_name(&object) {
            self.names.insert((kind, name.to_owned()), id.clone());
        }
        match object {
            StoreObject::Cluster(o) => {
                self.clusters.insert(id, Arc::new(o));
            }
            StoreObject::Node(o) => {
                self.nodes.insert(id, Arc::new(o));
            }
            StoreObject::Service(o) => {
                self.services.insert(id, Arc::new(o));
            }
            StoreObject::Task(o) => {
                self.tasks.insert(id, Arc::new(o));
            }
            StoreObject::Network(o) => {
                self.networks.insert(id, Arc::new(o));
            }
            StoreObject::Secret(o) => {
                self.secrets.insert(id, Arc::new(o));
            }
            StoreObject::Config(o) => {
                self.configs.insert(id, Arc::new(o));
            }
        }
    }

    /// Removes an object, keeping the name index consistent.
    fn remove_object(&mut self, kind: ObjectKind, id: &Id) {
        if let Some(old) = self.get_object(kind, id)
            && let Some(name) = object_name(&old)
        {
            let key = (kind, name.to_owned());
            if self.names.get(&key) == Some(id) {
                self.names.remove(&key);
            }
        }
        match kind {
            ObjectKind::Cluster => {
                self.clusters.remove(id);
            }
            ObjectKind::Node => {
                self.nodes.remove(id);
            }
            ObjectKind::Service => {
                self.services.remove(id);
            }
            ObjectKind::Task => {
                self.tasks.remove(id);
            }
            ObjectKind::Network => {
                self.networks.remove(id);
            }
            ObjectKind::Secret => {
                self.secrets.remove(id);
            }
            ObjectKind::Config => {
                self.configs.remove(id);
            }
        }
    }

    /// Applies one transaction: validate everything first, then apply all
    /// actions or none (architecture §6.1). Deterministic: every replica
    /// computes the same outcome from the same entry.
    ///
    /// Validation runs against the pre-transaction state plus an overlay of
    /// the transaction's own earlier actions, so `Remove` + `Create` of the
    /// same ID in one transaction is valid. An `Update` of an object
    /// created/updated earlier in the same transaction must carry
    /// `meta.version == log index` — proposers cannot know the index in
    /// advance, so the useful pattern is one write per object per
    /// transaction.
    ///
    /// `serialized_len` is the CBOR length of the proposal, measured by the
    /// caller (outside the store lock) to enforce
    /// [`MAX_TX_BYTES`] deterministically.
    fn apply_transaction(
        &mut self,
        proposal: &Proposal,
        index: u64,
        serialized_len: usize,
    ) -> (ProposalResponse, Vec<StoreEvent>) {
        // Phase 1: validate the whole transaction; first rejection wins.
        if let Err(rejection) = self.validate_transaction(proposal, index, serialized_len) {
            return (ProposalResponse::Rejected(rejection), Vec::new());
        }

        // Phase 2: apply all actions; stamp every write with the log index.
        let version = Version(index);
        let mut events = Vec::with_capacity(proposal.actions.len() + 1);
        for action in &proposal.actions {
            match action {
                StoreAction::Create(object) => {
                    let mut object = object.clone();
                    stamp_version(&mut object, version);
                    stamp_spec_version(&mut object, None, version);
                    self.insert_object(object.clone());
                    events.push(StoreEvent::Created(object));
                }
                StoreAction::Update(object) => {
                    let old = self.get_object(object.kind(), object.id());
                    let mut new = object.clone();
                    stamp_version(&mut new, version);
                    stamp_spec_version(&mut new, old.as_ref(), version);
                    self.insert_object(new.clone());
                    events.push(StoreEvent::Updated { old, new });
                }
                StoreAction::Remove { kind, id } => {
                    self.remove_object(*kind, id);
                    events.push(StoreEvent::Removed {
                        kind: *kind,
                        id: id.clone(),
                    });
                }
            }
        }
        events.push(StoreEvent::Commit(version));
        (ProposalResponse::Applied { version }, events)
    }

    /// Validates a transaction against the pre-transaction store state plus
    /// an overlay of the transaction's own earlier actions. First failing
    /// action wins; a clean pass means every action will apply.
    fn validate_transaction(
        &self,
        proposal: &Proposal,
        index: u64,
        serialized_len: usize,
    ) -> Result<(), ProposalRejection> {
        if proposal.actions.len() > MAX_TX_ACTIONS {
            return Err(ProposalRejection::TooManyActions {
                count: proposal.actions.len(),
            });
        }
        if serialized_len > MAX_TX_BYTES {
            return Err(ProposalRejection::TooLarge {
                bytes: serialized_len,
            });
        }

        let mut overlay: HashMap<(ObjectKind, Id), Overlay> = HashMap::new();
        for action in &proposal.actions {
            match action {
                StoreAction::Create(object) => {
                    let kind = object.kind();
                    let id = object.id();
                    let exists = match overlay.get(&(kind, id.clone())) {
                        Some(Overlay::Exists(_)) => true,
                        Some(Overlay::Removed) => false,
                        None => self.contains(kind, id),
                    };
                    if exists {
                        return Err(ProposalRejection::AlreadyExists {
                            kind,
                            id: id.clone(),
                        });
                    }
                    overlay.insert((kind, id.clone()), Overlay::Exists(index));
                }
                StoreAction::Update(object) => {
                    let kind = object.kind();
                    let id = object.id();
                    let current = match overlay.get(&(kind, id.clone())) {
                        Some(Overlay::Exists(version)) => Some(*version),
                        Some(Overlay::Removed) => None,
                        None => self.version_of(kind, id),
                    };
                    let Some(expected) = current else {
                        return Err(ProposalRejection::NotFound {
                            kind,
                            id: id.clone(),
                        });
                    };
                    let found = object_version(object);
                    if found != expected {
                        return Err(ProposalRejection::SequenceConflict {
                            kind,
                            id: id.clone(),
                            expected,
                            found,
                        });
                    }
                    overlay.insert((kind, id.clone()), Overlay::Exists(index));
                }
                StoreAction::Remove { kind, id } => {
                    let exists = match overlay.get(&(*kind, id.clone())) {
                        Some(Overlay::Exists(_)) => true,
                        Some(Overlay::Removed) => false,
                        None => self.contains(*kind, id),
                    };
                    if !exists {
                        return Err(ProposalRejection::NotFound {
                            kind: *kind,
                            id: id.clone(),
                        });
                    }
                    overlay.insert((*kind, id.clone()), Overlay::Removed);
                }
            }
        }
        Ok(())
    }
}

/// On-disk / on-wire snapshot payload: the full store plus the apply
/// cursors, self-describing so the persisted file needs no side metadata.
#[derive(Serialize, Deserialize)]
struct SnapshotPayload {
    snapshot_id: String,
    last_applied: Option<LogId<u64>>,
    last_membership: StoredMembership<u64, BasicNode>,
    /// Removed raft IDs (SWK §11.1). `default` so a snapshot written before
    /// this field existed still loads.
    #[serde(default)]
    removed_raft_ids: BTreeSet<u64>,
    clusters: Vec<Cluster>,
    nodes: Vec<Node>,
    services: Vec<Service>,
    tasks: Vec<Task>,
    networks: Vec<Network>,
    secrets: Vec<Secret>,
    configs: Vec<Config>,
}

impl SnapshotPayload {
    /// Deep-copies the store into a payload.
    fn from_store(inner: &StoreInner, snapshot_id: String) -> Self {
        Self {
            snapshot_id,
            last_applied: inner.last_applied,
            last_membership: inner.last_membership.clone(),
            removed_raft_ids: inner.removed_raft_ids.clone(),
            clusters: inner.clusters.values().map(|o| (**o).clone()).collect(),
            nodes: inner.nodes.values().map(|o| (**o).clone()).collect(),
            services: inner.services.values().map(|o| (**o).clone()).collect(),
            tasks: inner.tasks.values().map(|o| (**o).clone()).collect(),
            networks: inner.networks.values().map(|o| (**o).clone()).collect(),
            secrets: inner.secrets.values().map(|o| (**o).clone()).collect(),
            configs: inner.configs.values().map(|o| (**o).clone()).collect(),
        }
    }

    /// Replaces `inner` wholesale with this payload's contents. Versions are
    /// **not** re-stamped (architecture §6.3) and no events are emitted (see
    /// the module docs).
    fn install_into(self, inner: &mut StoreInner) {
        let mut fresh = StoreInner {
            last_applied: self.last_applied,
            last_membership: self.last_membership,
            removed_raft_ids: self.removed_raft_ids,
            ..StoreInner::default()
        };
        for o in self.clusters {
            fresh.insert_object(StoreObject::Cluster(o));
        }
        for o in self.nodes {
            fresh.insert_object(StoreObject::Node(o));
        }
        for o in self.services {
            fresh.insert_object(StoreObject::Service(o));
        }
        for o in self.tasks {
            fresh.insert_object(StoreObject::Task(o));
        }
        for o in self.networks {
            fresh.insert_object(StoreObject::Network(o));
        }
        for o in self.secrets {
            fresh.insert_object(StoreObject::Secret(o));
        }
        for o in self.configs {
            fresh.insert_object(StoreObject::Config(o));
        }
        *inner = fresh;
    }

    /// The snapshot metadata described by this payload.
    fn meta(&self) -> SnapshotMeta<u64, BasicNode> {
        SnapshotMeta {
            last_log_id: self.last_applied,
            last_membership: self.last_membership.clone(),
            snapshot_id: self.snapshot_id.clone(),
        }
    }
}

/// A unique snapshot id: last-applied log id plus wall-clock nanos.
fn new_snapshot_id(last_applied: Option<LogId<u64>>) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    match last_applied {
        Some(log_id) => format!("{}-{}-{nanos}", log_id.leader_id, log_id.index),
        None => format!("none-{nanos}"),
    }
}

/// The openraft state machine. Owns the shared store handle; [`crate::ClusterStore`]
/// holds clones of the same handle for reads and the watch feed.
pub struct StateMachine {
    store: Arc<RwLock<StoreInner>>,
    events: broadcast::Sender<StoreEvent>,
    dek: Dek,
    snapshot_path: PathBuf,
}

impl StateMachine {
    /// Opens the state machine, loading the persisted snapshot from
    /// `<raft_dir>/snapshot` if present.
    ///
    /// Synchronous (reads the snapshot file): callers on the async runtime
    /// wrap this in `spawn_blocking`.
    pub fn open(raft_dir: &Path, dek: Dek) -> Result<Self, StateMachineError> {
        let snapshot_path = raft_dir.join(SNAPSHOT_FILE_NAME);
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let mut inner = StoreInner::default();

        match std::fs::read(&snapshot_path) {
            Ok(bytes) => {
                let payload = decode_snapshot_file(&dek, &snapshot_path, &bytes)?;
                tracing::info!(
                    path = %snapshot_path.display(),
                    snapshot_id = %payload.snapshot_id,
                    last_applied = ?payload.last_applied,
                    "loaded persisted store snapshot"
                );
                payload.install_into(&mut inner);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(StateMachineError::Io {
                    path: snapshot_path,
                    op: "read",
                    source,
                });
            }
        }

        Ok(Self {
            store: Arc::new(RwLock::new(inner)),
            events,
            dek,
            snapshot_path,
        })
    }

    /// The shared store handle (for [`crate::ClusterStore`]).
    pub(crate) fn store_handle(&self) -> Arc<RwLock<StoreInner>> {
        Arc::clone(&self.store)
    }

    /// The watch feed sender (for [`crate::ClusterStore`]).
    pub(crate) fn event_sender(&self) -> broadcast::Sender<StoreEvent> {
        self.events.clone()
    }

    /// Storage error naming the snapshot file and operation.
    fn snapshot_err(&self, verb: ErrorVerb, msg: &str) -> StorageError<u64> {
        StorageIOError::new(
            ErrorSubject::Snapshot(None),
            verb,
            AnyError::error(format!(
                "{msg} (snapshot file {})",
                self.snapshot_path.display()
            )),
        )
        .into()
    }
}

/// Applies one committed entry to the store (write lock held by the
/// caller). Pure in-memory (invariant #4). Events from applied transactions
/// are appended to `pending_events` for publication after the lock drops.
fn apply_entry(
    inner: &mut StoreInner,
    entry: Entry,
    serialized_len: usize,
    pending_events: &mut Vec<StoreEvent>,
) -> ProposalResponse {
    let index = entry.log_id.index;
    let reply = match entry.payload {
        EntryPayload::Blank => ProposalResponse::Applied {
            version: Version(index),
        },
        EntryPayload::Membership(membership) => {
            // Nodes that disappear from the config are gone for good: their
            // raft IDs join the removal blacklist so they can never be
            // re-admitted or handed out again (SWK §11.1). A joint config
            // still lists the departing node, so the blacklist entry is
            // recorded when the *uniform* config commits.
            let before: BTreeSet<u64> = inner.last_membership.nodes().map(|(id, _)| *id).collect();
            let after: BTreeSet<u64> = membership.nodes().map(|(id, _)| *id).collect();
            for gone in before.difference(&after) {
                if inner.removed_raft_ids.insert(*gone) {
                    tracing::info!(
                        log_index = index,
                        raft_id = gone,
                        "raft member removed; its raft ID is blacklisted from reuse"
                    );
                }
            }
            inner.last_membership = StoredMembership::new(Some(entry.log_id), membership);
            ProposalResponse::Applied {
                version: Version(index),
            }
        }
        EntryPayload::Normal(proposal) => {
            let (response, events) = inner.apply_transaction(&proposal, index, serialized_len);
            match &response {
                ProposalResponse::Applied { version } => {
                    tracing::debug!(
                        log_index = index,
                        actions = proposal.actions.len(),
                        version = version.0,
                        "store transaction applied"
                    );
                }
                ProposalResponse::Rejected(rejection) => {
                    tracing::info!(
                        log_index = index,
                        actions = proposal.actions.len(),
                        rejection = %rejection,
                        "store transaction rejected"
                    );
                }
            }
            pending_events.extend(events);
            response
        }
    };
    inner.last_applied = Some(entry.log_id);
    reply
}

/// Unseals and decodes a snapshot file read from disk.
fn decode_snapshot_file(
    dek: &Dek,
    path: &Path,
    sealed: &[u8],
) -> Result<SnapshotPayload, StateMachineError> {
    let plain = dek
        .open(sealed)
        .map_err(|source| StateMachineError::Unseal {
            path: path.to_path_buf(),
            source,
        })?;
    decode_snapshot_blob(path, &plain)
}

/// Decodes a plaintext snapshot blob (the `SnapshotData` wire format).
fn decode_snapshot_blob(path: &Path, plain: &[u8]) -> Result<SnapshotPayload, StateMachineError> {
    ciborium::de::from_reader(plain).map_err(|e| StateMachineError::Decode {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

/// Serializes a snapshot payload into the plaintext `SnapshotData` blob.
fn encode_snapshot_blob(payload: &SnapshotPayload) -> Result<Vec<u8>, String> {
    let mut plain = Vec::new();
    ciborium::ser::into_writer(payload, &mut plain).map_err(|e| e.to_string())?;
    Ok(plain)
}

/// Builds snapshots from a point-in-time copy of the store and persists
/// them to `<raft_dir>/snapshot`.
pub struct SnapshotBuilder {
    store: Arc<RwLock<StoreInner>>,
    dek: Dek,
    snapshot_path: PathBuf,
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<u64>> {
        // Point-in-time copy under the read lock (pure in-memory), then
        // serialize/seal/write on the blocking pool.
        let payload = {
            let inner = self.store.read();
            SnapshotPayload::from_store(&inner, new_snapshot_id(inner.last_applied))
        };
        let meta = payload.meta();
        tracing::info!(
            snapshot_id = %meta.snapshot_id,
            last_log_id = ?meta.last_log_id,
            "building store snapshot"
        );

        let dek = self.dek.clone();
        let path = self.snapshot_path.clone();
        let plain = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let plain = encode_snapshot_blob(&payload)?;
            // Only the persisted copy is sealed; the returned blob is the
            // plaintext wire format (see the module docs).
            let sealed = dek.seal(&plain);
            atomic_write(&path, &sealed, 0o600)
                .map_err(|e| format!("persist snapshot to {}: {e}", path.display()))?;
            Ok(plain)
        })
        .await
        .map_err(|e| self.storage_err(&format!("snapshot build task failed: {e}")))?
        .map_err(|e| self.storage_err(&e))?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(plain)),
        })
    }
}

impl SnapshotBuilder {
    /// Storage error naming the snapshot file.
    fn storage_err(&self, msg: &str) -> StorageError<u64> {
        StorageIOError::new(
            ErrorSubject::Snapshot(None),
            ErrorVerb::Write,
            AnyError::error(format!(
                "{msg} (snapshot file {})",
                self.snapshot_path.display()
            )),
        )
        .into()
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<u64>>, StoredMembership<u64, BasicNode>), StorageError<u64>> {
        let inner = self.store.read();
        Ok((inner.last_applied, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ProposalResponse>, StorageError<u64>>
    where
        I: IntoIterator<Item = Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        // Pre-compute proposal sizes outside the lock: the size limit check
        // must be deterministic, and serialization is CPU work that has no
        // business inside the store lock.
        let mut prepared = Vec::new();
        for entry in entries {
            let size = if let EntryPayload::Normal(proposal) = &entry.payload {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(proposal, &mut buf).map_err(|e| {
                    StorageIOError::apply(
                        entry.log_id,
                        AnyError::error(format!("re-serialize proposal for size check: {e}")),
                    )
                })?;
                buf.len()
            } else {
                0
            };
            prepared.push((entry, size));
        }

        let mut replies = Vec::with_capacity(prepared.len());
        let mut pending_events = Vec::new();
        {
            let mut inner = self.store.write();
            for (entry, size) in prepared {
                replies.push(apply_entry(&mut inner, entry, size, &mut pending_events));
            }
        }
        // Lock released: publish. Send errors just mean nobody is watching.
        for event in pending_events {
            let _ = self.events.send(event);
        }
        Ok(replies)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SnapshotBuilder {
            store: Arc::clone(&self.store),
            dek: self.dek.clone(),
            snapshot_path: self.snapshot_path.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<u64>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<u64, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<u64>> {
        tracing::info!(
            snapshot_id = %meta.snapshot_id,
            last_log_id = ?meta.last_log_id,
            "installing store snapshot"
        );
        let bytes = snapshot.into_inner();

        // Decode + persist (sealed with the local DEK) on the blocking
        // pool, then swap the store.
        let dek = self.dek.clone();
        let path = self.snapshot_path.clone();
        let payload = tokio::task::spawn_blocking(move || -> Result<SnapshotPayload, String> {
            let payload = decode_snapshot_blob(&path, &bytes).map_err(|e| e.to_string())?;
            let sealed = dek.seal(&bytes);
            atomic_write(&path, &sealed, 0o600)
                .map_err(|e| format!("persist snapshot to {}: {e}", path.display()))?;
            Ok(payload)
        })
        .await
        .map_err(|e| self.snapshot_err(ErrorVerb::Write, &format!("install task failed: {e}")))?
        .map_err(|e| self.snapshot_err(ErrorVerb::Write, &e))?;

        {
            let mut inner = self.store.write();
            payload.install_into(&mut inner);
            // The meta from the leader is authoritative for the cursors.
            inner.last_applied = meta.last_log_id;
            inner.last_membership = meta.last_membership.clone();
        }
        // Wholesale replacement: no per-object events (see module docs).
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<u64>> {
        /// The persisted snapshot's metadata and sealed bytes, if present.
        type Loaded = Option<(SnapshotMeta<u64, BasicNode>, Vec<u8>)>;

        let dek = self.dek.clone();
        let path = self.snapshot_path.clone();
        let loaded = tokio::task::spawn_blocking(move || -> Result<Loaded, String> {
            let sealed = match std::fs::read(&path) {
                Ok(sealed) => sealed,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => return Err(format!("read snapshot {}: {err}", path.display())),
            };
            let plain = dek
                .open(&sealed)
                .map_err(|e| format!("unseal snapshot {}: {e}", path.display()))?;
            let payload = decode_snapshot_blob(&path, &plain).map_err(|e| e.to_string())?;
            Ok(Some((payload.meta(), plain)))
        })
        .await
        .map_err(|e| self.snapshot_err(ErrorVerb::Read, &format!("read task failed: {e}")))?
        .map_err(|e| self.snapshot_err(ErrorVerb::Read, &e))?;

        Ok(loaded.map(|(meta, bytes)| Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(bytes)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use openraft::storage::RaftStateMachine;
    use openraft::testing::log_id;
    use openraft::{CommittedLeaderId, Membership};

    use satl_core::{Annotations, IpamConfig, Meta, NetworkDriver, NetworkSpec, SecretSpec};

    use crate::crypto::DEK_LEN;

    use super::*;

    fn test_dek() -> Dek {
        Dek::from_bytes(&[5_u8; DEK_LEN])
    }

    fn open_sm(dir: &Path) -> StateMachine {
        StateMachine::open(dir, test_dek()).unwrap()
    }

    fn normal_entry(index: u64, actions: Vec<StoreAction>) -> Entry {
        Entry {
            log_id: openraft::LogId::new(CommittedLeaderId::new(1, 1), index),
            payload: EntryPayload::Normal(Proposal { actions }),
        }
    }

    fn sample_network(name: &str) -> Network {
        Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                driver: NetworkDriver::Bridge,
                ipam: Some(IpamConfig::default()),
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: false,
            },
            vni: None,
            vxlan_port: None,
            subnet: None,
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        }
    }

    fn sample_secret(name: &str, payload: Vec<u8>) -> Secret {
        Secret {
            id: Id::generate(),
            meta: Meta::new(),
            spec: SecretSpec::new(
                Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                payload,
            )
            .unwrap(),
        }
    }

    fn sample_config(name: &str, payload: Vec<u8>) -> Config {
        Config {
            id: Id::generate(),
            meta: Meta::new(),
            spec: satl_core::ConfigSpec::new(
                Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                payload,
            )
            .unwrap(),
        }
    }

    async fn apply_one(
        sm: &mut StateMachine,
        index: u64,
        actions: Vec<StoreAction>,
    ) -> ProposalResponse {
        let mut replies = sm.apply(vec![normal_entry(index, actions)]).await.unwrap();
        replies.pop().unwrap()
    }

    #[tokio::test]
    async fn create_update_remove_happy_path_stamps_log_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let store = sm.store_handle();

        let network = sample_network("backend");
        let id = network.id.clone();

        // Create at index 5 → version 5.
        let reply = apply_one(
            &mut sm,
            5,
            vec![StoreAction::Create(StoreObject::Network(network.clone()))],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Applied {
                version: Version(5)
            }
        );
        {
            let inner = store.read();
            let stored = inner.networks.get(&id).unwrap();
            assert_eq!(stored.meta.version, Version(5));
            assert_eq!(
                inner
                    .names
                    .get(&(ObjectKind::Network, "backend".to_owned())),
                Some(&id)
            );
            assert_eq!(inner.last_applied, Some(log_id(1, 1, 5)));
        }

        // Update at index 8 with the current version → version 8.
        let mut updated = network.clone();
        updated.meta.version = Version(5);
        updated.vni = Some(4097);
        let reply = apply_one(
            &mut sm,
            8,
            vec![StoreAction::Update(StoreObject::Network(updated))],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Applied {
                version: Version(8)
            }
        );
        {
            let inner = store.read();
            let stored = inner.networks.get(&id).unwrap();
            assert_eq!(stored.meta.version, Version(8));
            assert_eq!(stored.vni, Some(4097));
        }

        // Remove at index 9.
        let reply = apply_one(
            &mut sm,
            9,
            vec![StoreAction::Remove {
                kind: ObjectKind::Network,
                id: id.clone(),
            }],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Applied {
                version: Version(9)
            }
        );
        {
            let inner = store.read();
            assert!(inner.networks.is_empty());
            assert!(inner.names.is_empty());
        }
    }

    #[tokio::test]
    async fn sequence_conflict_rejects_whole_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let store = sm.store_handle();

        let existing = sample_network("existing");
        let existing_id = existing.id.clone();
        apply_one(
            &mut sm,
            1,
            vec![StoreAction::Create(StoreObject::Network(existing.clone()))],
        )
        .await;

        // Transaction: one valid create + one stale update. All-or-nothing:
        // the valid create must not apply.
        let fresh = sample_network("fresh");
        let fresh_id = fresh.id.clone();
        let mut stale = existing.clone();
        stale.meta.version = Version(0); // store has 1
        let reply = apply_one(
            &mut sm,
            2,
            vec![
                StoreAction::Create(StoreObject::Network(fresh)),
                StoreAction::Update(StoreObject::Network(stale)),
            ],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Rejected(ProposalRejection::SequenceConflict {
                kind: ObjectKind::Network,
                id: existing_id.clone(),
                expected: 1,
                found: 0,
            })
        );
        {
            let inner = store.read();
            assert!(
                !inner.networks.contains_key(&fresh_id),
                "atomicity violated"
            );
            assert_eq!(
                inner.networks.get(&existing_id).unwrap().meta.version,
                Version(1)
            );
            // The rejected entry still advances the apply cursor.
            assert_eq!(inner.last_applied, Some(log_id(1, 1, 2)));
        }
    }

    #[tokio::test]
    async fn already_exists_and_not_found_rejections() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());

        let network = sample_network("net");
        let id = network.id.clone();
        apply_one(
            &mut sm,
            1,
            vec![StoreAction::Create(StoreObject::Network(network.clone()))],
        )
        .await;

        // Duplicate create.
        let reply = apply_one(
            &mut sm,
            2,
            vec![StoreAction::Create(StoreObject::Network(network.clone()))],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Rejected(ProposalRejection::AlreadyExists {
                kind: ObjectKind::Network,
                id: id.clone(),
            })
        );

        // Update of a missing object.
        let ghost = sample_network("ghost");
        let ghost_id = ghost.id.clone();
        let reply = apply_one(
            &mut sm,
            3,
            vec![StoreAction::Update(StoreObject::Network(ghost))],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Rejected(ProposalRejection::NotFound {
                kind: ObjectKind::Network,
                id: ghost_id.clone(),
            })
        );

        // Remove of a missing object.
        let reply = apply_one(
            &mut sm,
            4,
            vec![StoreAction::Remove {
                kind: ObjectKind::Network,
                id: ghost_id.clone(),
            }],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Rejected(ProposalRejection::NotFound {
                kind: ObjectKind::Network,
                id: ghost_id,
            })
        );
    }

    #[tokio::test]
    async fn remove_then_create_same_id_in_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let store = sm.store_handle();

        let network = sample_network("net");
        let id = network.id.clone();
        apply_one(
            &mut sm,
            1,
            vec![StoreAction::Create(StoreObject::Network(network.clone()))],
        )
        .await;

        let mut replacement = network;
        replacement.spec.annotations.name = "renamed".to_owned();
        let reply = apply_one(
            &mut sm,
            2,
            vec![
                StoreAction::Remove {
                    kind: ObjectKind::Network,
                    id: id.clone(),
                },
                StoreAction::Create(StoreObject::Network(replacement)),
            ],
        )
        .await;
        assert_eq!(
            reply,
            ProposalResponse::Applied {
                version: Version(2)
            }
        );
        let inner = store.read();
        assert_eq!(inner.networks.get(&id).unwrap().meta.version, Version(2));
        assert_eq!(
            inner
                .names
                .get(&(ObjectKind::Network, "renamed".to_owned())),
            Some(&id)
        );
        assert!(
            !inner
                .names
                .contains_key(&(ObjectKind::Network, "net".to_owned()))
        );
    }

    #[tokio::test]
    async fn event_emission_order_and_commit_marker() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let mut watch = sm.event_sender().subscribe();

        let network = sample_network("net");
        let secret = sample_secret("db.password", vec![42]);
        let secret_id = secret.id.clone();
        apply_one(
            &mut sm,
            1,
            vec![
                StoreAction::Create(StoreObject::Network(network.clone())),
                StoreAction::Create(StoreObject::Secret(secret.clone())),
            ],
        )
        .await;

        let mut updated = network.clone();
        updated.meta.version = Version(1);
        updated.vni = Some(9);
        apply_one(
            &mut sm,
            2,
            vec![
                StoreAction::Update(StoreObject::Network(updated.clone())),
                StoreAction::Remove {
                    kind: ObjectKind::Secret,
                    id: secret_id.clone(),
                },
            ],
        )
        .await;

        // Expected stamped shapes.
        let mut created_network = network.clone();
        created_network.meta.version = Version(1);
        let mut created_secret = secret.clone();
        created_secret.meta.version = Version(1);
        let mut new_network = updated;
        new_network.meta.version = Version(2);

        let events: Vec<StoreEvent> = std::iter::from_fn(|| watch.try_recv().ok()).collect();
        assert_eq!(
            events,
            vec![
                StoreEvent::Created(StoreObject::Network(created_network.clone())),
                StoreEvent::Created(StoreObject::Secret(created_secret)),
                StoreEvent::Commit(Version(1)),
                StoreEvent::Updated {
                    old: Some(StoreObject::Network(created_network)),
                    new: StoreObject::Network(new_network),
                },
                StoreEvent::Removed {
                    kind: ObjectKind::Secret,
                    id: secret_id,
                },
                StoreEvent::Commit(Version(2)),
            ]
        );
    }

    #[tokio::test]
    async fn rejected_transaction_emits_no_events() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let mut watch = sm.event_sender().subscribe();

        let ghost = sample_network("ghost");
        let reply = apply_one(
            &mut sm,
            1,
            vec![StoreAction::Update(StoreObject::Network(ghost))],
        )
        .await;
        assert!(matches!(reply, ProposalResponse::Rejected(_)));
        assert!(watch.try_recv().is_err(), "rejected tx must emit nothing");
    }

    #[tokio::test]
    async fn max_tx_actions_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());

        let actions: Vec<StoreAction> = (0..=MAX_TX_ACTIONS)
            .map(|_| StoreAction::Create(StoreObject::Network(sample_network("n"))))
            .collect();
        let count = actions.len();
        assert_eq!(count, MAX_TX_ACTIONS + 1);
        let reply = apply_one(&mut sm, 1, actions).await;
        assert_eq!(
            reply,
            ProposalResponse::Rejected(ProposalRejection::TooManyActions { count })
        );
    }

    #[tokio::test]
    async fn max_tx_bytes_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());

        // Two configs just under the per-object limit exceed the 1.5 MiB
        // transaction budget together.
        let actions = vec![
            StoreAction::Create(StoreObject::Config(sample_config("a", vec![7; 900 * 1024]))),
            StoreAction::Create(StoreObject::Config(sample_config("b", vec![7; 900 * 1024]))),
        ];
        let reply = apply_one(&mut sm, 1, actions).await;
        match reply {
            ProposalResponse::Rejected(ProposalRejection::TooLarge { bytes }) => {
                assert!(bytes > MAX_TX_BYTES, "{bytes}");
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blank_and_membership_entries_advance_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());

        let blank = Entry {
            log_id: openraft::LogId::new(CommittedLeaderId::new(1, 1), 1),
            payload: EntryPayload::Blank,
        };
        let membership = Entry {
            log_id: openraft::LogId::new(CommittedLeaderId::new(1, 1), 2),
            payload: EntryPayload::Membership(Membership::new(
                vec![std::collections::BTreeSet::from([1_u64])],
                None,
            )),
        };
        let replies = sm.apply(vec![blank, membership]).await.unwrap();
        assert_eq!(
            replies,
            vec![
                ProposalResponse::Applied {
                    version: Version(1)
                },
                ProposalResponse::Applied {
                    version: Version(2)
                },
            ]
        );
        let (last_applied, membership) = sm.applied_state().await.unwrap();
        assert_eq!(last_applied, Some(log_id(1, 1, 2)));
        assert_eq!(membership.log_id(), &Some(log_id(1, 1, 2)));
        assert_eq!(membership.voter_ids().collect::<Vec<_>>(), vec![1]);
    }

    /// The raft-ID removal blacklist (SWK §11.1) is derived from the applied
    /// membership entries: a node that disappears from the config is recorded
    /// once, a joint config does not record anything prematurely, and the set
    /// survives a snapshot round trip and a restart.
    #[tokio::test]
    async fn removed_raft_ids_are_blacklisted_and_survive_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        let store = sm.store_handle();

        let membership = |index: u64, configs: Vec<BTreeSet<u64>>| Entry {
            log_id: openraft::LogId::new(CommittedLeaderId::new(1, 1), index),
            payload: EntryPayload::Membership(Membership::new(configs, None)),
        };

        // {1,2,3} -> joint {1,2,3}/{1,2} -> uniform {1,2}: only the uniform
        // step drops node 3 from the node set.
        sm.apply(vec![membership(1, vec![BTreeSet::from([1_u64, 2, 3])])])
            .await
            .unwrap();
        assert!(store.read().removed_raft_ids.is_empty());

        sm.apply(vec![membership(
            2,
            vec![BTreeSet::from([1_u64, 2, 3]), BTreeSet::from([1_u64, 2])],
        )])
        .await
        .unwrap();
        assert!(
            store.read().removed_raft_ids.is_empty(),
            "a joint config still lists the departing member"
        );

        sm.apply(vec![membership(3, vec![BTreeSet::from([1_u64, 2])])])
            .await
            .unwrap();
        assert_eq!(store.read().removed_raft_ids, BTreeSet::from([3_u64]));

        // Re-applying the same config does not double-record, and a later
        // removal accumulates.
        sm.apply(vec![membership(4, vec![BTreeSet::from([1_u64, 2])])])
            .await
            .unwrap();
        sm.apply(vec![membership(5, vec![BTreeSet::from([1_u64])])])
            .await
            .unwrap();
        assert_eq!(store.read().removed_raft_ids, BTreeSet::from([2_u64, 3]));

        // Snapshot -> install into a fresh machine: the blacklist travels.
        let mut builder = sm.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let mut other = open_sm(other_dir.path());
        other
            .install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await
            .unwrap();
        assert_eq!(
            other.store_handle().read().removed_raft_ids,
            BTreeSet::from([2_u64, 3]),
            "a follower catching up must inherit the blacklist"
        );

        // ...and a restart from the persisted snapshot recovers it.
        drop(sm);
        let restarted = open_sm(dir.path());
        assert_eq!(
            restarted.store_handle().read().removed_raft_ids,
            BTreeSet::from([2_u64, 3])
        );
    }

    #[tokio::test]
    async fn snapshot_build_install_roundtrip_and_restart() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let mut sm_a = open_sm(dir_a.path());

        let network = sample_network("net");
        let network_id = network.id.clone();
        let secret = sample_secret("s", b"hunter2".to_vec());
        let secret_id = secret.id.clone();
        apply_one(
            &mut sm_a,
            7,
            vec![
                StoreAction::Create(StoreObject::Network(network)),
                StoreAction::Create(StoreObject::Secret(secret)),
            ],
        )
        .await;

        // Build on A; persisted to <dir_a>/snapshot and returned as a blob.
        let mut builder = sm_a.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.unwrap();
        assert_eq!(snapshot.meta.last_log_id, Some(log_id(1, 1, 7)));

        // The persisted snapshot must be sealed, not plaintext.
        let raw = std::fs::read(dir_a.path().join(SNAPSHOT_FILE_NAME)).unwrap();
        let mut haystack = raw.windows(7);
        assert!(
            !haystack.any(|w| w == b"hunter2"),
            "secret payload leaked to disk in the clear"
        );

        // Install into a fresh machine (as a follower would).
        let mut sm_b = open_sm(dir_b.path());
        sm_b.install_snapshot(&snapshot.meta, snapshot.snapshot)
            .await
            .unwrap();
        {
            let store_b = sm_b.store_handle();
            let inner = store_b.read();
            // Contents identical, versions NOT re-stamped.
            assert_eq!(
                inner.networks.get(&network_id).unwrap().meta.version,
                Version(7)
            );
            assert_eq!(
                inner.secrets.get(&secret_id).unwrap().spec.data(),
                b"hunter2"
            );
            assert_eq!(
                inner.names.get(&(ObjectKind::Network, "net".to_owned())),
                Some(&network_id)
            );
            assert_eq!(inner.last_applied, Some(log_id(1, 1, 7)));
        }
        let current = sm_b.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta.snapshot_id, snapshot.meta.snapshot_id);

        // Restart both machines from their directories: contents recovered.
        drop(sm_a);
        drop(sm_b);
        for dir in [dir_a.path(), dir_b.path()] {
            let mut sm = open_sm(dir);
            {
                let store = sm.store_handle();
                let inner = store.read();
                assert_eq!(
                    inner.networks.get(&network_id).unwrap().meta.version,
                    Version(7)
                );
                assert_eq!(inner.last_applied, Some(log_id(1, 1, 7)));
            }
            let reloaded = sm.get_current_snapshot().await.unwrap().unwrap();
            assert_eq!(reloaded.meta.last_log_id, Some(log_id(1, 1, 7)));
        }
    }

    #[tokio::test]
    async fn get_current_snapshot_is_none_before_first_build() {
        let dir = tempfile::tempdir().unwrap();
        let mut sm = open_sm(dir.path());
        assert!(sm.get_current_snapshot().await.unwrap().is_none());
    }
}
