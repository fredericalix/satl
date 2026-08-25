// SPDX-License-Identifier: BSD-2-Clause
//! The ZFS layer store (`docs/architecture.md` §10): one dataset per applied
//! layer chain under `<root>/layers/<chain-id-hex>`, with an `@final`
//! snapshot taken after the layer tar has been unpacked into it.
//!
//! Layer N's dataset is a clone of layer N−1's `@final` (base layers are
//! plain `zfs create`), so images sharing a layer prefix share datasets.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use tracing::Instrument as _;

use crate::chain::{ChainId, ChainIdError, chain_id};
use crate::unpack::{LayerCompression, UnpackError, unpack_layer};
use crate::zfs::{CommandRunner, SystemRunner, Zfs, ZfsError};

/// Name of the snapshot taken once a layer is fully applied. A layer dataset
/// without this snapshot is a half-made leftover and gets destroyed.
pub const FINAL_SNAPSHOT: &str = "final";

/// How many times [`LayerStore::reclaim_incomplete`] retries a destroy that
/// answered "dataset is busy", and how long it waits between tries.
///
/// The budget covers an abandoned `spawn_blocking` unpack finishing its tar,
/// which is bounded by the layer's size and by nothing this process can
/// interrogate. 60 s, because the arithmetic that matters is the slow end: a
/// 1 GiB layer on a virtio disk unpacks in well under a minute, and
/// overrunning the budget means the rejected task this whole path exists to
/// prevent. Bounded all the same, so a mount held by something else is
/// reported instead of waited on for ever.
const RECLAIM_ATTEMPTS: u32 = 30;
/// Pause between the reclaim attempts (see [`RECLAIM_ATTEMPTS`]).
const RECLAIM_STEP: std::time::Duration = std::time::Duration::from_secs(2);

/// One layer of an image, in application order.
#[derive(Debug, Clone)]
pub struct LayerSource {
    /// Diff ID from the image config (`rootfs.diff_ids`): sha256 of the
    /// uncompressed tar stream.
    pub diff_id: String,
    /// Local path of the (possibly compressed) blob, owned by `satl-image`.
    pub blob_path: std::path::PathBuf,
    /// Compression, from the manifest layer media type.
    pub compression: LayerCompression,
}

/// Error applying layers to the ZFS layer store.
#[derive(Debug, thiserror::Error)]
pub enum LayerStoreError {
    /// A diff ID was malformed.
    #[error(transparent)]
    Chain(#[from] ChainIdError),

    /// A `zfs` invocation failed (full argv/status/stderr inside).
    #[error(transparent)]
    Zfs(#[from] ZfsError),

    /// Unpacking the blob into the fresh dataset failed; the dataset has
    /// been destroyed (best-effort).
    #[error("failed to unpack layer (diff id {diff_id}) into dataset '{dataset}': {source}")]
    Unpack {
        /// Diff ID of the failing layer.
        diff_id: String,
        /// The dataset the blob was being unpacked into.
        dataset: String,
        /// The unpack error.
        #[source]
        source: UnpackError,
    },

    /// The parent layer's dataset is missing its `@final` snapshot (or the
    /// dataset itself is missing) — the parent was never fully applied, so
    /// nothing can be stacked on it.
    #[error(
        "parent layer dataset '{dataset}' is missing its @{FINAL_SNAPSHOT} snapshot; \
         the parent layer was never fully applied"
    )]
    ParentLayerIncomplete {
        /// The parent layer dataset.
        dataset: String,
    },

    /// `apply_image` was called with zero layers.
    #[error("cannot apply an image with zero layers")]
    EmptyImage,

    /// A chain ID handed to [`LayerStore::destroy`] is not a bare 64-character
    /// lowercase hex string, so it cannot name a layer dataset. Nothing in the
    /// GC should ever produce one — this refuses rather than passing an
    /// arbitrary string to `zfs destroy`.
    #[error("invalid layer chain id {chain:?}: {reason}")]
    InvalidChainId {
        /// The offending input.
        chain: String,
        /// Why it was rejected.
        reason: String,
    },
}

/// The chain a clone `origin` of the form `<layers_root>/<chain>@final` was
/// built on, or `None` when the origin points somewhere else entirely (a
/// snapshot outside the layers root is not a layer edge).
fn parent_chain_of<'o>(prefix: &str, origin: &'o str) -> Option<&'o str> {
    origin
        .strip_prefix(prefix)?
        .strip_suffix(&format!("@{FINAL_SNAPSHOT}"))
}

/// A layer dataset name component is a bare chain-ID hex and nothing else.
fn validate_chain_hex(chain: &str) -> Result<(), LayerStoreError> {
    let invalid = |reason: &str| LayerStoreError::InvalidChainId {
        chain: chain.to_owned(),
        reason: reason.to_owned(),
    };
    if chain.len() != 64 {
        return Err(invalid("expected 64 hex characters"));
    }
    if !chain
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(invalid("expected lowercase hexadecimal characters"));
    }
    Ok(())
}

/// Applies OCI layers as ZFS datasets under a layers root dataset
/// (e.g. `zroot/satl/layers`).
#[derive(Debug, Clone)]
pub struct LayerStore<R = SystemRunner> {
    zfs: Zfs<R>,
    root: String,
    /// One mutex per chain id, so two tasks applying the same layer at the
    /// same time take turns instead of racing.
    ///
    /// Without this, two replicas of a service starting together on a node
    /// that has not cached the image both find the dataset absent and both
    /// `zfs create` it — one fails with "dataset already exists" and its task
    /// is rejected. Worse, if the loser instead arrives while the winner is
    /// mid-unpack, it sees a dataset with no `@final` snapshot, concludes an
    /// apply was interrupted, and **destroys the work in progress**. Observed
    /// on a real 3-node cluster with `--replicas 6`.
    ///
    /// The map only ever grows by the number of distinct layers on the node,
    /// which is bounded by the image cache itself. Shared through `Arc` so
    /// clones of the store serialize against each other — a per-clone map
    /// would defeat the whole point.
    applying: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl<R: CommandRunner> LayerStore<R> {
    /// Store over `zfs`, holding layer datasets under `layers_root_dataset`.
    pub fn new(zfs: Zfs<R>, layers_root_dataset: impl Into<String>) -> Self {
        Self {
            zfs,
            root: layers_root_dataset.into(),
            applying: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// The dataset holding the layer chain identified by `chain`.
    #[must_use]
    pub fn dataset_for(&self, chain: &ChainId) -> String {
        format!("{}/{}", self.root, chain.hex())
    }

    /// The root dataset the layer datasets are children of.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Every layer dataset on this node, as the GC needs to see it: whether it
    /// carries its `@final` snapshot, which chain it was cloned from, and the
    /// bytes it and its snapshots are charged.
    ///
    /// One `zfs list` for the whole picture (see [`Zfs::list_space`]): reading
    /// the datasets and their snapshots separately is how a layer being applied
    /// right now gets classified as a half-applied leftover.
    ///
    /// `used` on a layer with clones is only the space *unique* to it, because
    /// that is what ZFS charges it — which is also the honest answer to "what
    /// would destroying this free", and it grows to the full size as the clones
    /// go away.
    ///
    /// # Errors
    ///
    /// [`LayerStoreError::Zfs`] when listing fails (full command context
    /// inside). A missing layers root is *not* an error: a node that has never
    /// pulled an image has no layers, and the GC must treat that as "nothing to
    /// do" rather than as trouble.
    pub async fn list(&self) -> Result<Vec<crate::gc::LayerOnDisk>, LayerStoreError> {
        let rows = match self.zfs.list_space(&self.root).await {
            Ok(rows) => rows,
            Err(error) if error.is_missing_dataset() => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let prefix = format!("{}/", self.root);
        let mut layers: HashMap<String, crate::gc::LayerOnDisk> = HashMap::new();
        let mut snapshot_bytes: HashMap<String, u64> = HashMap::new();
        for row in rows {
            let Some(tail) = row.name.strip_prefix(&prefix) else {
                // The root itself, or a sibling with a shared name prefix.
                continue;
            };
            match tail.split_once('@') {
                None => {
                    layers.insert(
                        tail.to_owned(),
                        crate::gc::LayerOnDisk {
                            chain: tail.to_owned(),
                            complete: false,
                            parent: row.origin.as_deref().and_then(|origin| {
                                parent_chain_of(&prefix, origin).map(str::to_owned)
                            }),
                            used: row.used,
                        },
                    );
                }
                Some((chain, snapshot)) => {
                    *snapshot_bytes.entry(chain.to_owned()).or_default() += row.used;
                    if snapshot == FINAL_SNAPSHOT {
                        // `zfs list -r` prints a dataset before its snapshots,
                        // so the entry is already there.
                        if let Some(layer) = layers.get_mut(chain) {
                            layer.complete = true;
                        }
                    }
                }
            }
        }
        let mut out: Vec<crate::gc::LayerOnDisk> = layers
            .into_iter()
            .map(|(chain, mut layer)| {
                layer.used += snapshot_bytes.get(&chain).copied().unwrap_or_default();
                layer
            })
            .collect();
        out.sort_by(|a, b| a.chain.cmp(&b.chain));
        Ok(out)
    }

    /// Destroy one layer dataset and its snapshots.
    ///
    /// `-r` but never `-R`: recursion takes the dataset's own snapshots, and
    /// **ZFS's refusal to destroy a snapshot that still has clones is a safety
    /// net this must not disable**. `-R` would flatten a container's writable
    /// layer along with the image layer under it; `-r` fails with `filesystem
    /// has dependent clones` instead, which is the correct outcome and is
    /// reported with the full `zfs` command line.
    ///
    /// # Errors
    ///
    /// [`LayerStoreError::InvalidChainId`] when `chain` could not name a layer
    /// dataset; [`LayerStoreError::Zfs`] when `zfs destroy` fails.
    pub async fn destroy(&self, chain: &str) -> Result<(), LayerStoreError> {
        validate_chain_hex(chain)?;
        let dataset = format!("{}/{chain}", self.root);
        let span = tracing::info_span!("layer_destroy", chain_id = %chain, dataset = %dataset);
        async {
            self.zfs.destroy(&dataset, true).await?;
            tracing::info!("layer dataset destroyed");
            Ok(())
        }
        .instrument(span)
        .await
    }

    /// The chains an apply is holding the gate for right now.
    ///
    /// A chain in here has a task in `ensure_layer` between `zfs create` and
    /// `zfs snapshot`, so its dataset may exist with no `@final` and no image
    /// record naming it yet. The GC skips incomplete datasets anyway; this is
    /// the claim that makes that decision explicit rather than incidental.
    #[must_use]
    pub fn applying_now(&self) -> std::collections::BTreeSet<String> {
        let gates = match self.applying.lock() {
            Ok(gates) => gates,
            Err(poisoned) => poisoned.into_inner(),
        };
        gates
            .iter()
            .filter(|(_, gate)| gate.try_lock().is_err())
            .map(|(chain, _)| chain.clone())
            .collect()
    }

    /// Ensure the layer chain `parent + diff_id` exists as a fully applied
    /// dataset; returns its chain ID.
    ///
    /// Idempotent: an existing dataset with an `@final` snapshot is adopted
    /// as-is. An existing dataset *without* the snapshot (interrupted apply)
    /// is destroyed and rebuilt. On unpack failure the half-made dataset is
    /// destroyed (best-effort) and the error returned.
    ///
    /// # Errors
    ///
    /// See [`LayerStoreError`].
    pub async fn ensure_layer(
        &self,
        parent: Option<&ChainId>,
        diff_id: &str,
        blob_path: &Path,
        compression: LayerCompression,
    ) -> Result<ChainId, LayerStoreError> {
        let chain = chain_id(parent, diff_id)?;
        let dataset = self.dataset_for(&chain);
        let span = tracing::info_span!(
            "layer_apply",
            chain_id = %chain,
            diff_id = %diff_id,
            dataset = %dataset,
        );
        // Take this chain's turn before touching the dataset (see `applying`).
        let gate = self.gate_for(&chain);
        let _turn = gate.lock().await;
        self.ensure_layer_inner(parent, diff_id, blob_path, compression, &chain, &dataset)
            .instrument(span)
            .await?;
        Ok(chain)
    }

    /// The mutex guarding applies of one chain id, created on first use.
    fn gate_for(&self, chain: &ChainId) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = match self.applying.lock() {
            Ok(gates) => gates,
            // The guarded value is a map of `Arc`s; a panic while inserting
            // cannot leave it inconsistent in a way that matters, and refusing
            // to apply layers for the rest of the process's life would be far
            // worse than carrying on.
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(
            gates
                .entry(chain.hex().to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    /// Deal with a layer dataset that exists **without** its `@final`
    /// snapshot: either finish reclaiming it, or discover that it was not
    /// incomplete after all.
    ///
    /// `Ok(true)` means the dataset became complete while we were looking at
    /// it and the caller should adopt it; `Ok(false)` means it was destroyed
    /// and has to be rebuilt.
    ///
    /// # Why this is a loop and not a `zfs destroy`
    ///
    /// "Dataset without `@final`" reads as an interrupted apply, and usually
    /// is: a daemon that died mid-unpack leaves exactly that. But it is also
    /// what an apply that is *still running* looks like, and this process
    /// cannot always see one of those, which is the part that cost a rolling
    /// update (decision log, 2026-08-25).
    ///
    /// [`Self::ensure_layer`] holds a per-chain mutex across the whole apply,
    /// so two live applies cannot interleave. What escapes it is
    /// **cancellation**: `unpack_layer` awaits a `spawn_blocking` handle, and
    /// dropping a `JoinHandle` does not stop a blocking task. So when the
    /// agent replaces a task manager mid-prepare, the future is dropped, the
    /// mutex guard goes with it, and the tar extraction carries on writing
    /// into the dataset with nothing holding the gate. The next apply then
    /// finds a dataset with no `@final`, calls it interrupted, and destroys a
    /// mountpoint that is in use: `cannot unmount ...: pool or dataset is
    /// busy`, a fatal task rejection, and a paused rollout.
    ///
    /// `zfs destroy` is the only thing that knows whether anything still has
    /// the dataset, so it makes the decision rather than a check before it,
    /// the same conclusion [`crate::ContainerFsStore::create`] reached for
    /// container clones. Busy means "not yet", not "give up": the abandoned
    /// unpack is bounded by the layer it is writing, and when it stops the
    /// destroy succeeds. Every other refusal (`filesystem has dependent
    /// clones`, a permission problem, a missing pool) stays fatal on the
    /// first try, because waiting cannot change any of them.
    async fn reclaim_incomplete(
        &self,
        chain: &ChainId,
        dataset: &str,
    ) -> Result<bool, LayerStoreError> {
        tracing::warn!(
            chain_id = %chain,
            "layer dataset exists without @{FINAL_SNAPSHOT} snapshot (interrupted apply), destroying and re-applying"
        );
        for attempt in 1..=RECLAIM_ATTEMPTS {
            let error = match self.zfs.destroy(dataset, true).await {
                Ok(()) => return Ok(false),
                Err(error) if error.is_busy() => error,
                Err(error) => return Err(error.into()),
            };

            // Busy. Before waiting, ask the one question that would make the
            // wait pointless: an apply this process could not await may have
            // reached its snapshot, in which case the dataset is complete and
            // adopting it is both correct and free.
            if self
                .zfs
                .snapshot_exists(dataset, FINAL_SNAPSHOT)
                .await
                .unwrap_or(false)
            {
                tracing::info!(
                    chain_id = %chain,
                    attempt,
                    "the layer was being finished by an apply this process no longer tracks; \
                     adopting the completed dataset instead of rebuilding it"
                );
                return Ok(true);
            }

            if attempt == RECLAIM_ATTEMPTS {
                tracing::error!(
                    chain_id = %chain,
                    waited_secs = u64::from(RECLAIM_ATTEMPTS) * RECLAIM_STEP.as_secs(),
                    "layer dataset stayed busy for the whole reclaim budget; something outside \
                     this daemon is holding it. Look for a leftover mount with `mount -p` and \
                     for a dying prison with `jls -d -h name dying`"
                );
                return Err(error.into());
            }
            tracing::info!(
                chain_id = %chain,
                attempt,
                of = RECLAIM_ATTEMPTS,
                "layer dataset is busy, so an unpack is still writing into it; waiting rather \
                 than failing the task"
            );
            tokio::time::sleep(RECLAIM_STEP).await;
        }
        // The loop returns on every path; `1..=N` with N >= 1 always runs.
        unreachable!("the reclaim loop returns from inside its last iteration")
    }

    async fn ensure_layer_inner(
        &self,
        parent: Option<&ChainId>,
        diff_id: &str,
        blob_path: &Path,
        compression: LayerCompression,
        chain: &ChainId,
        dataset: &str,
    ) -> Result<(), LayerStoreError> {
        if self.zfs.dataset_exists(dataset).await? {
            if self.zfs.snapshot_exists(dataset, FINAL_SNAPSHOT).await? {
                tracing::info!(chain_id = %chain, "layer already applied, adopting existing dataset");
                return Ok(());
            }
            if self.reclaim_incomplete(chain, dataset).await? {
                return Ok(());
            }
        }

        match parent {
            None => self.zfs.create(dataset, &[]).await?,
            Some(parent) => {
                let parent_dataset = self.dataset_for(parent);
                if !self
                    .zfs
                    .snapshot_exists(&parent_dataset, FINAL_SNAPSHOT)
                    .await?
                {
                    return Err(LayerStoreError::ParentLayerIncomplete {
                        dataset: parent_dataset,
                    });
                }
                self.zfs
                    .clone_snapshot(&format!("{parent_dataset}@{FINAL_SNAPSHOT}"), dataset, &[])
                    .await?;
            }
        }

        let mountpoint = self.zfs.mountpoint_of(dataset).await?;

        match unpack_layer(
            blob_path.to_owned(),
            compression,
            diff_id.to_owned(),
            mountpoint,
        )
        .await
        {
            Ok(summary) => {
                tracing::info!(
                    entries = summary.entries_unpacked,
                    whiteouts = summary.whiteouts,
                    opaque_dirs = summary.opaque_dirs,
                    "layer blob unpacked into dataset"
                );
            }
            Err(source) => {
                tracing::warn!(
                    error = %source,
                    "unpack failed, destroying half-applied layer dataset"
                );
                if let Err(destroy_err) = self.zfs.destroy(dataset, true).await {
                    tracing::warn!(
                        error = %destroy_err,
                        "best-effort cleanup of half-applied layer dataset failed"
                    );
                }
                return Err(LayerStoreError::Unpack {
                    diff_id: diff_id.to_owned(),
                    dataset: dataset.to_owned(),
                    source,
                });
            }
        }

        self.zfs.snapshot(dataset, FINAL_SNAPSHOT).await?;
        Ok(())
    }

    /// Apply an image's layer stack in order; returns the top chain ID
    /// (the snapshot `<root>/<top>@final` is what container rootfs clones
    /// come from).
    ///
    /// # Errors
    ///
    /// [`LayerStoreError::EmptyImage`] for an empty stack; otherwise
    /// whatever [`LayerStore::ensure_layer`] returns for the failing layer.
    pub async fn apply_image(&self, layers: &[LayerSource]) -> Result<ChainId, LayerStoreError> {
        let mut top: Option<ChainId> = None;
        for layer in layers {
            let chain = self
                .ensure_layer(
                    top.as_ref(),
                    &layer.diff_id,
                    &layer.blob_path,
                    layer.compression,
                )
                .await?;
            top = Some(chain);
        }
        top.ok_or(LayerStoreError::EmptyImage)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::zfs::MockRunner;

    const ROOT: &str = "zroot/satl/layers";

    fn tar_with_file(name: &str, content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(content.len() as u64);
        header.set_mtime(1_700_000_000);
        builder.append_data(&mut header, name, content).unwrap();
        builder.into_inner().unwrap()
    }

    fn diff_id_of(tar_bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(tar_bytes)))
    }

    fn missing_stderr(name: &str) -> String {
        format!("cannot open '{name}': dataset does not exist\n")
    }

    /// What `zfs destroy` prints, verbatim from FreeBSD 15.1, while something
    /// still has the dataset's mountpoint open.
    fn busy_stderr(mountpoint: &std::path::Path) -> String {
        format!(
            "cannot unmount '{}': pool or dataset is busy\n",
            mountpoint.display()
        )
    }

    struct TestLayer {
        diff_id: String,
        blob_path: std::path::PathBuf,
    }

    fn make_layer(dir: &std::path::Path, file_name: &str, content: &[u8]) -> TestLayer {
        let tar_bytes = tar_with_file(file_name, content);
        let diff_id = diff_id_of(&tar_bytes);
        let blob_path = dir.join(format!("{file_name}.tar"));
        fs::write(&blob_path, &tar_bytes).unwrap();
        TestLayer { diff_id, blob_path }
    }

    /// Two tasks applying the same layer at once must take turns: the second
    /// finds the dataset finished and adopts it, instead of racing `zfs
    /// create` (spurious rejection) or destroying a mid-unpack dataset it
    /// mistakes for an interrupted apply. Regression test for the failure
    /// seen on a real 3-node cluster with `--replicas 6`.
    #[tokio::test]
    async fn concurrent_applies_of_one_layer_take_turns() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "shared.txt", b"shared\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt-shared");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        // First turn: absent -> create -> mountpoint -> snapshot.
        mock.push_output(1, "", &missing_stderr(&dataset));
        mock.push_output(0, "", "");
        mock.push_output(0, &format!("{}\n", mount.display()), "");
        mock.push_output(0, "", "");
        // Second turn: present, with @final -> adopt, nothing else.
        mock.push_output(0, &format!("{dataset}\n"), "");
        mock.push_output(0, &format!("{dataset}@final\n"), "");

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let (a, b) = tokio::join!(
            store.ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None
            ),
            store.ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None
            ),
        );
        assert_eq!(a.unwrap(), c1);
        assert_eq!(b.unwrap(), c1);

        // Exactly one create and one snapshot, and no destroy at all.
        let calls = mock.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.contains(&format!("create {dataset}")))
                .count(),
            1,
            "{calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.contains("snapshot"))
                .filter(|c| !c.contains("list"))
                .count(),
            1,
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.contains("destroy")),
            "a concurrent apply must never destroy the winner's dataset: {calls:?}"
        );
    }

    #[tokio::test]
    async fn base_layer_flow_runs_create_mountpoint_unpack_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt-base");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&dataset)); // dataset_exists -> no
        mock.push_output(0, "", ""); // create
        mock.push_output(0, &format!("{}\n", mount.display()), ""); // mountpoint
        mock.push_output(0, "", ""); // snapshot

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let got = store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap();
        assert_eq!(got, c1);
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {dataset}"),
                format!("/sbin/zfs create {dataset}"),
                format!("/sbin/zfs get -H -p -o value mountpoint {dataset}"),
                format!("/sbin/zfs snapshot {dataset}@final"),
            ]
        );
        // The blob really was unpacked into the mock-provided mountpoint.
        assert_eq!(
            fs::read_to_string(mount.join("base.txt")).unwrap(),
            "base\n"
        );
    }

    #[tokio::test]
    async fn stacked_layer_flow_checks_parent_and_clones_its_final_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let base = make_layer(tmp.path(), "base.txt", b"base\n");
        let upper = make_layer(tmp.path(), "upper.txt", b"upper\n");
        let c1 = chain_id(None, &base.diff_id).unwrap();
        let c2 = chain_id(Some(&c1), &upper.diff_id).unwrap();
        let parent_ds = format!("{ROOT}/{}", c1.hex());
        let child_ds = format!("{ROOT}/{}", c2.hex());
        let mount = tmp.path().join("mnt-upper");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&child_ds)); // child exists? no
        mock.push_output(0, &format!("{parent_ds}@final\n"), ""); // parent @final? yes
        mock.push_output(0, "", ""); // clone
        mock.push_output(0, &format!("{}\n", mount.display()), ""); // mountpoint
        mock.push_output(0, "", ""); // snapshot

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let got = store
            .ensure_layer(
                Some(&c1),
                &upper.diff_id,
                &upper.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap();
        assert_eq!(got, c2);
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {child_ds}"),
                format!("/sbin/zfs list -H -o name {parent_ds}@final"),
                format!("/sbin/zfs clone {parent_ds}@final {child_ds}"),
                format!("/sbin/zfs get -H -p -o value mountpoint {child_ds}"),
                format!("/sbin/zfs snapshot {child_ds}@final"),
            ]
        );
        assert_eq!(
            fs::read_to_string(mount.join("upper.txt")).unwrap(),
            "upper\n"
        );
    }

    #[tokio::test]
    async fn already_applied_layer_is_adopted_without_any_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(0, &format!("{dataset}@final\n"), ""); // @final exists

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let got = store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap();
        assert_eq!(got, c1);
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {dataset}"),
                format!("/sbin/zfs list -H -o name {dataset}@final"),
            ]
        );
    }

    #[tokio::test]
    async fn interrupted_apply_leftover_is_destroyed_and_rebuilt() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // no @final
        mock.push_output(0, "", ""); // destroy -r
        mock.push_output(0, "", ""); // create
        mock.push_output(0, &format!("{}\n", mount.display()), ""); // mountpoint
        mock.push_output(0, "", ""); // snapshot

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {dataset}"),
                format!("/sbin/zfs list -H -o name {dataset}@final"),
                format!("/sbin/zfs destroy -r {dataset}"),
                format!("/sbin/zfs create {dataset}"),
                format!("/sbin/zfs get -H -p -o value mountpoint {dataset}"),
                format!("/sbin/zfs snapshot {dataset}@final"),
            ]
        );
    }

    /// `cannot unmount ...: pool or dataset is busy` on the reclaim destroy
    /// means an unpack is still writing into the dataset -- an apply whose
    /// future was dropped mid-`spawn_blocking`, which releases the per-chain
    /// mutex while the tar extraction carries on. That is "not yet", not a
    /// fatal task failure: the destroy is retried until the mountpoint frees
    /// up, and the layer is then rebuilt.
    ///
    /// Regression test for the paused rolling update of 2026-08-25.
    #[tokio::test(start_paused = true)]
    async fn a_busy_dataset_is_waited_out_rather_than_failing_the_task() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt-busy");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // no @final
        // Two destroys refused by a live unpack, and after each one the
        // @final re-check that would have let us adopt instead.
        mock.push_output(1, "", &busy_stderr(&mount));
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final")));
        mock.push_output(1, "", &busy_stderr(&mount));
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final")));
        // The unpack has finished; the third destroy goes through.
        mock.push_output(0, "", "");
        mock.push_output(0, "", ""); // create
        mock.push_output(0, &format!("{}\n", mount.display()), ""); // mountpoint
        mock.push_output(0, "", ""); // snapshot

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .expect("a busy dataset must not fail the layer apply");

        let destroys = mock
            .calls()
            .iter()
            .filter(|c| c.contains("destroy"))
            .count();
        assert_eq!(destroys, 3, "two refusals, then the one that worked");
        assert!(
            mock.calls()
                .contains(&format!("/sbin/zfs snapshot {dataset}@final")),
            "the layer must be rebuilt and snapshotted after the reclaim: {:?}",
            mock.calls()
        );
    }

    /// The other half of the same decision: if the apply this process could
    /// not await *finished*, the dataset is complete and adopting it is both
    /// correct and free. No destroy, no rebuild, no wasted unpack.
    #[tokio::test(start_paused = true)]
    async fn a_busy_dataset_that_became_complete_is_adopted() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt-raced");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // no @final yet
        mock.push_output(1, "", &busy_stderr(&mount)); // destroy refused
        mock.push_output(0, &format!("{dataset}@final\n"), ""); // ... it just appeared

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        assert_eq!(
            store
                .ensure_layer(
                    None,
                    &layer.diff_id,
                    &layer.blob_path,
                    LayerCompression::None,
                )
                .await
                .unwrap(),
            c1
        );
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {dataset}"),
                format!("/sbin/zfs list -H -o name {dataset}@final"),
                format!("/sbin/zfs destroy -r {dataset}"),
                format!("/sbin/zfs list -H -o name {dataset}@final"),
            ],
            "nothing is created, unpacked or snapshotted when the dataset was already finished"
        );
    }

    /// A dataset that stays busy for the whole budget is reported, with the
    /// real `zfs` failure rather than a synthesised one, so the operator sees
    /// the argv and the stderr. Waiting for ever would hang the prepare.
    #[tokio::test(start_paused = true)]
    async fn a_dataset_busy_for_the_whole_budget_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt-stuck");

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // no @final
        for _ in 0..RECLAIM_ATTEMPTS {
            mock.push_output(1, "", &busy_stderr(&mount)); // destroy: busy
            mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // still no @final
        }

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let error = store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .expect_err("a permanently busy dataset has to be reported");
        let rendered = error.to_string();
        assert!(
            rendered.contains("zfs destroy -r") && rendered.contains("dataset is busy"),
            "the operator needs the argv and the stderr: {rendered}"
        );
        assert_eq!(
            mock.calls()
                .iter()
                .filter(|c| c.contains("destroy"))
                .count(),
            RECLAIM_ATTEMPTS as usize,
            "exactly the budget, no more"
        );
    }

    /// Only "busy" is transient. `filesystem has dependent clones` means a
    /// container rootfs was cloned from this layer: waiting cannot change it,
    /// so it stays fatal on the first try and the task fails fast.
    #[tokio::test(start_paused = true)]
    async fn a_destroy_refused_for_any_other_reason_stays_fatal_at_once() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        let c1 = chain_id(None, &layer.diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());

        let mock = MockRunner::new();
        mock.push_output(0, &format!("{dataset}\n"), ""); // dataset exists
        mock.push_output(1, "", &missing_stderr(&format!("{dataset}@final"))); // no @final
        mock.push_output(
            1,
            "",
            &format!("cannot destroy '{dataset}': filesystem has dependent clones\n"),
        );

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let error = store
            .ensure_layer(
                None,
                &layer.diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .expect_err("dependent clones is not something to wait out");
        assert!(
            error.to_string().contains("dependent clones"),
            "{}",
            error.to_string()
        );
        assert_eq!(
            mock.calls().len(),
            3,
            "one probe, one snapshot check, one destroy, and no retry: {:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn failed_unpack_destroys_the_half_made_dataset() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = make_layer(tmp.path(), "base.txt", b"base\n");
        // Lie about the diff id so digest verification fails after unpack.
        let wrong_diff_id = diff_id_of(b"not the tar bytes at all");
        let c1 = chain_id(None, &wrong_diff_id).unwrap();
        let dataset = format!("{ROOT}/{}", c1.hex());
        let mount = tmp.path().join("mnt");
        fs::create_dir(&mount).unwrap();

        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&dataset)); // exists? no
        mock.push_output(0, "", ""); // create
        mock.push_output(0, &format!("{}\n", mount.display()), ""); // mountpoint
        mock.push_output(0, "", ""); // destroy -r (cleanup)

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store
            .ensure_layer(
                None,
                &wrong_diff_id,
                &layer.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                LayerStoreError::Unpack {
                    source: UnpackError::DigestMismatch { .. },
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(
            mock.calls(),
            [
                format!("/sbin/zfs list -H -o name {dataset}"),
                format!("/sbin/zfs create {dataset}"),
                format!("/sbin/zfs get -H -p -o value mountpoint {dataset}"),
                format!("/sbin/zfs destroy -r {dataset}"),
            ]
        );
        // No @final snapshot was ever taken.
        assert!(!mock.calls().iter().any(|c| c.contains("snapshot")));
    }

    #[tokio::test]
    async fn missing_parent_final_snapshot_is_a_typed_error_and_stops_before_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let base = make_layer(tmp.path(), "base.txt", b"base\n");
        let upper = make_layer(tmp.path(), "upper.txt", b"upper\n");
        let c1 = chain_id(None, &base.diff_id).unwrap();
        let c2 = chain_id(Some(&c1), &upper.diff_id).unwrap();
        let parent_ds = format!("{ROOT}/{}", c1.hex());
        let child_ds = format!("{ROOT}/{}", c2.hex());

        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(&child_ds)); // child exists? no
        mock.push_output(1, "", &missing_stderr(&format!("{parent_ds}@final"))); // parent @final? no

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store
            .ensure_layer(
                Some(&c1),
                &upper.diff_id,
                &upper.blob_path,
                LayerCompression::None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&err, LayerStoreError::ParentLayerIncomplete { dataset } if *dataset == parent_ds),
            "{err}"
        );
        assert_eq!(mock.calls().len(), 2, "must stop before cloning anything");
    }

    #[tokio::test]
    async fn apply_image_walks_the_chain_and_returns_the_top_chain_id() {
        let tmp = tempfile::tempdir().unwrap();
        let base = make_layer(tmp.path(), "base.txt", b"base\n");
        let upper = make_layer(tmp.path(), "upper.txt", b"upper\n");
        let c1 = chain_id(None, &base.diff_id).unwrap();
        let c2 = chain_id(Some(&c1), &upper.diff_id).unwrap();
        let ds1 = format!("{ROOT}/{}", c1.hex());
        let ds2 = format!("{ROOT}/{}", c2.hex());
        let mount1 = tmp.path().join("m1");
        let mount2 = tmp.path().join("m2");
        fs::create_dir(&mount1).unwrap();
        fs::create_dir(&mount2).unwrap();

        let mock = MockRunner::new();
        // layer 1 (base)
        mock.push_output(1, "", &missing_stderr(&ds1));
        mock.push_output(0, "", "");
        mock.push_output(0, &format!("{}\n", mount1.display()), "");
        mock.push_output(0, "", "");
        // layer 2 (stacked)
        mock.push_output(1, "", &missing_stderr(&ds2));
        mock.push_output(0, &format!("{ds1}@final\n"), "");
        mock.push_output(0, "", "");
        mock.push_output(0, &format!("{}\n", mount2.display()), "");
        mock.push_output(0, "", "");

        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let layers = vec![
            LayerSource {
                diff_id: base.diff_id.clone(),
                blob_path: base.blob_path.clone(),
                compression: LayerCompression::None,
            },
            LayerSource {
                diff_id: upper.diff_id.clone(),
                blob_path: upper.blob_path.clone(),
                compression: LayerCompression::None,
            },
        ];
        let top = store.apply_image(&layers).await.unwrap();
        assert_eq!(top, c2);
        assert_eq!(mock.calls().len(), 9);
        assert!(mount1.join("base.txt").exists());
        assert!(mount2.join("upper.txt").exists());
    }

    // ---- what the GC sees --------------------------------------------------

    const FIXTURE_SPACE_STACKED: &str =
        include_str!("../tests/fixtures/zfs_list_space_stacked.txt");

    /// The whole GC input, read off one real `zfs list`: two applied layers
    /// with the clone edge between them, and a third that has no `@final` and
    /// therefore belongs to `ensure_layer`, not to the collector.
    #[tokio::test]
    async fn list_reads_completeness_parentage_and_size_from_one_listing() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SPACE_STACKED, "");
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let layers = store.list().await.unwrap();

        assert_eq!(
            mock.calls(),
            [format!(
                "/sbin/zfs list -H -p -r -d 2 -t filesystem,snapshot -o name,origin,used {ROOT}"
            )],
            "one listing, not one per layer"
        );
        assert_eq!(layers.len(), 3, "{layers:?}");

        let base = &layers[0];
        assert!(base.chain.starts_with("aaaa1111"), "{layers:?}");
        assert!(base.complete);
        assert_eq!(base.parent, None);
        // dataset 102400 + its @final snapshot 0.
        assert_eq!(base.used, 102_400);

        let stacked = &layers[1];
        assert!(stacked.chain.starts_with("bbbb2222"), "{layers:?}");
        assert!(stacked.complete);
        assert_eq!(stacked.parent.as_deref(), Some(base.chain.as_str()));
        assert_eq!(stacked.used, 69_632);

        let half = &layers[2];
        assert!(half.chain.starts_with("cccc3333"), "{layers:?}");
        assert!(
            !half.complete,
            "a dataset with no @final is not a collectable layer"
        );
        assert_eq!(half.parent.as_deref(), Some(base.chain.as_str()));
    }

    /// A node that has never pulled an image has no layers root, and that is
    /// not trouble — a GC that errored here would report a problem on every
    /// fresh node.
    #[tokio::test]
    async fn list_treats_a_missing_layers_root_as_empty() {
        let mock = MockRunner::new();
        mock.push_output(1, "", &missing_stderr(ROOT));
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        assert!(store.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_propagates_a_real_zfs_failure() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "internal error: I/O error\n");
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.list().await.unwrap_err();
        assert!(matches!(err, LayerStoreError::Zfs(_)), "{err}");
    }

    /// `-r` and never `-R`: recursion is for the layer's own snapshots, and
    /// ZFS refusing to destroy a snapshot that still has clones is a safety net
    /// the GC must not disable.
    #[tokio::test]
    async fn destroy_is_recursive_but_never_forced() {
        let chain = "a".repeat(64);
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        store.destroy(&chain).await.unwrap();
        assert_eq!(
            mock.calls(),
            [format!("/sbin/zfs destroy -r {ROOT}/{chain}")]
        );
        assert!(!mock.calls().iter().any(|call| call.contains("-R")));
    }

    #[tokio::test]
    async fn destroy_refuses_anything_that_is_not_a_chain_hex() {
        let mock = MockRunner::new();
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        for bad in [
            "",
            "..",
            "zroot/satl",
            "a".repeat(63).as_str(),
            "A".repeat(64).as_str(),
            &format!("{}@final", "a".repeat(58)),
        ] {
            let err = store.destroy(bad).await.unwrap_err();
            assert!(
                matches!(err, LayerStoreError::InvalidChainId { .. }),
                "{bad:?}: {err}"
            );
        }
        assert!(mock.calls().is_empty(), "no zfs command may have run");
    }

    /// A layer whose clones are still there cannot be destroyed, and the error
    /// has to say so with the command line that failed — this is the message an
    /// operator sees when the GC is right to be refused.
    #[tokio::test]
    async fn destroy_reports_zfs_refusing_because_of_dependent_clones() {
        let chain = "b".repeat(64);
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            &format!(
                "cannot destroy '{ROOT}/{chain}': filesystem has dependent clones\n\
                 use '-R' to destroy the following datasets:\n"
            ),
        );
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.destroy(&chain).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dependent clones"), "{msg}");
        assert!(msg.contains(&format!("destroy -r {ROOT}/{chain}")), "{msg}");
    }

    #[test]
    fn a_clone_origin_outside_the_layers_root_is_not_a_parent_edge() {
        let prefix = format!("{ROOT}/");
        assert_eq!(
            parent_chain_of(&prefix, &format!("{ROOT}/abc@final")),
            Some("abc")
        );
        // A container clone's origin, seen from the wrong side.
        assert_eq!(
            parent_chain_of(&prefix, "zroot/satl/containers/task1@snap"),
            None
        );
        // Right root, wrong snapshot: not the applied-layer edge.
        assert_eq!(parent_chain_of(&prefix, &format!("{ROOT}/abc@other")), None);
    }

    /// The gate is the claim that covers a chain mid-apply, before any snapshot
    /// or image record proves it.
    #[tokio::test]
    async fn applying_now_names_the_chain_an_apply_is_holding() {
        let mock = MockRunner::new();
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let chain = chain_id(None, &format!("sha256:{}", "1".repeat(64))).unwrap();
        assert!(store.applying_now().is_empty());
        let gate = store.gate_for(&chain);
        let held = gate.lock().await;
        assert_eq!(
            store.applying_now(),
            std::collections::BTreeSet::from([chain.hex().to_owned()])
        );
        drop(held);
        assert!(store.applying_now().is_empty());
    }

    #[tokio::test]
    async fn apply_image_with_zero_layers_is_a_typed_error() {
        let mock = MockRunner::new();
        let store = LayerStore::new(Zfs::with_runner(&mock), ROOT);
        let err = store.apply_image(&[]).await.unwrap_err();
        assert!(matches!(err, LayerStoreError::EmptyImage), "{err}");
        assert!(mock.calls().is_empty());
    }
}
