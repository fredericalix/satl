// SPDX-License-Identifier: BSD-2-Clause
//! `satl system prune` on the daemon side: reclaiming what nothing references.
//!
//! Four operations, and they do not have the same scope. That asymmetry is not
//! an accident of implementation, it is what SatL *is*:
//!
//! - **containers and networks are cluster objects.** A container is a task of a
//!   service (invariant #2) and a network lives in the Raft store, so pruning
//!   either is a store mutation on the leader and takes effect cluster-wide,
//!   exactly like `satl rm` and `satl network rm` already do.
//! - **images, layers, blobs and volumes are node-local.** They exist on
//!   whichever node pulled or created them. This daemon can reclaim its own and
//!   nothing else, and an operator who runs prune on one manager has reclaimed
//!   one node — which is why the CLI says so in as many words.
//!
//! ## Pruning a stopped container removes its service
//!
//! There is no other coherent answer. A stopped container in SatL is a task in a
//! terminal state whose service still exists; leaving the service would have the
//! orchestrator refill the slot the moment the reaper freed it, so "prune the
//! container" would create a new one. `satl rm` already resolves this the same
//! way (api-compat 33) and prune must not disagree with it. So pruning a stopped
//! container removes the backing service, and with it the jail, the epair and
//! the rootfs dataset that container still holds — the three things the M4 open
//! question observed exited containers keeping.
//!
//! The safety rail is at the service, not at the container: a service is pruned
//! only when **every** container of it is stopped. A `--replicas 3` service with
//! one dead task keeps all three, because destroying a live service to reclaim
//! one task record is not what anybody asked for.
//!
//! ## Two passes, always
//!
//! Layer reclamation destroys data that can only be recovered from a registry
//! that may not answer, so it follows the discipline `27ccb64` set for the
//! dataset sweep: compute what is unreferenced, wait, compute it again, and
//! destroy only what both passes agree on. A single `satl system prune` therefore
//! does two passes itself, [`SETTLE`] apart, and reports what it deferred.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use satl_api::model::{
    BackendError, ImageDeleted, PrunedContainers, PrunedImages, PrunedNetworks, PrunedVolumes,
    Result,
};
use satl_core::{DesiredState, Id, ObjectKind, StoreAction, StoreObject};

use super::{DaemonBackend, names};

/// How long the two passes of the layer GC are apart.
///
/// Long enough to matter and short enough that an operator does not think the
/// command has hung. What it buys is a *second reading* of the claim set: the
/// store just after a leadership change, a worker just after a restart and an
/// image store mid-pull are each momentarily incomplete, and a pass taken while
/// one of them is settling must not be the only pass.
const SETTLE: Duration = Duration::from_millis(1500);

impl DaemonBackend {
    /// `POST /containers/prune`: remove every stopped container, with the
    /// service backing it.
    pub(super) async fn prune_containers_impl(&self) -> Result<PrunedContainers> {
        // Measure first: once the tasks are marked for removal the datasets
        // start going away, and a size read afterwards would report zero.
        let candidates = self.stopped_container_ids()?;
        let space_reclaimed = self.bytes_of_container_datasets(&candidates).await;
        if candidates.is_empty() {
            return Ok(PrunedContainers::default());
        }

        // One proposal for all of them: `remove_container` waits for each task
        // to disappear, and N of those in a row would take N removal timeouts.
        let deleted: Vec<String> = self
            .propose_from_view("prune stopped containers", |view| {
                let mut actions = Vec::new();
                let mut removed = Vec::new();
                let mut services: BTreeSet<Id> = BTreeSet::new();
                for (service, task) in names::visible_containers(view) {
                    if !candidates.contains(task.id.as_str()) {
                        continue;
                    }
                    if task.desired_state < DesiredState::Remove {
                        let mut updated = (*task).clone();
                        updated.desired_state = DesiredState::Remove;
                        updated.meta.updated_at = SystemTime::now();
                        actions.push(StoreAction::Update(StoreObject::Task(updated)));
                    }
                    if services.insert(service.id.clone()) {
                        actions.push(StoreAction::Remove {
                            kind: ObjectKind::Service,
                            id: service.id.clone(),
                        });
                    }
                    removed.push(task.id.as_str().to_owned());
                }
                Ok((actions, removed))
            })
            .await?;

        for id in &deleted {
            if let Ok(task_id) = id.parse::<Id>() {
                self.execs.forget_container(&task_id);
            }
        }
        Ok(PrunedContainers {
            deleted,
            space_reclaimed,
        })
    }

    /// The containers `docker system prune` would call stopped: visible, and not
    /// running — with the whole-service rule applied, so a service with a live
    /// replica contributes none of its tasks.
    fn stopped_container_ids(&self) -> Result<BTreeSet<String>> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let rows = names::visible_containers(&view);
        let live_services: BTreeSet<Id> = rows
            .iter()
            .filter(|(_, task)| super::is_stoppable(task))
            .map(|(service, _)| service.id.clone())
            .collect();
        Ok(rows
            .iter()
            .filter(|(service, task)| {
                !super::is_stoppable(task) && !live_services.contains(&service.id)
            })
            .map(|(_, task)| task.id.as_str().to_owned())
            .collect())
    }

    /// The bytes those containers' writable layers hold on **this** node.
    ///
    /// Only this node's: a container of another node has no dataset here, and
    /// there is no cluster-wide byte count to give. Short of the truth by
    /// design when a jail is still dying — the periodic sweep is what actually
    /// frees that one.
    async fn bytes_of_container_datasets(&self, ids: &BTreeSet<String>) -> u64 {
        if ids.is_empty() {
            return 0;
        }
        let root = &self.datasets.containers_root;
        let Ok(rows) = self.executor.zfs().list_space(root).await else {
            return 0;
        };
        let prefix = format!("{root}/");
        rows.iter()
            .filter_map(|row| {
                let tail = row.name.strip_prefix(&prefix)?;
                let id = tail.split('@').next()?;
                ids.contains(id).then_some(row.used)
            })
            .sum()
    }

    /// `POST /networks/prune`: remove every user-defined network nothing is
    /// attached to.
    ///
    /// The ingress network is never pruned. It is created by `swarm init`, not
    /// by an operator, and it holds no task of its own even when every published
    /// service depends on it — Docker exempts its predefined networks for the
    /// same reason.
    pub(super) async fn prune_networks_impl(&self) -> Result<PrunedNetworks> {
        let candidates: Vec<(Id, String)> = {
            let manager = self.manager()?;
            let view = manager.store.view();
            view.networks()
                .into_iter()
                .filter(|network| !network.spec.ingress)
                .map(|network| (network.id.clone(), network.spec.annotations.name.clone()))
                .collect()
        };
        let mut deleted = Vec::new();
        for (id, name) in candidates {
            // Reuse the single-network path so "has active endpoints" is decided
            // in exactly one place; a Conflict here means the network is in use,
            // which for a prune is a skip and not a failure.
            match self.remove_network_impl(id.as_str()).await {
                Ok(()) => deleted.push(name),
                Err(BackendError::Conflict(reason)) => {
                    tracing::debug!(network = %name, %reason, "network still in use; not pruned");
                }
                Err(BackendError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(PrunedNetworks { deleted })
    }

    /// `POST /images/prune`: reclaim image content and layer datasets on this
    /// node.
    ///
    /// Three stages, in the only order that is safe:
    ///
    /// 1. with `all`, **records first**: an image record no container uses is
    ///    forgotten. `ImageStore::remove` writes `repositories.json` before
    ///    anything is deleted, so a store read is never left pointing at a file
    ///    that has gone;
    /// 2. **layer datasets**, two agreeing passes apart, deepest first;
    /// 3. **content** — blobs, manifests, configs nothing reaches. This is
    ///    SatL's "dangling image": there are no untagged records to delete
    ///    because a record *is* a reference, so what a re-pulled tag leaves
    ///    behind is content, not a record.
    pub(super) async fn prune_images_impl(&self, all: bool) -> Result<PrunedImages> {
        let mut report = PrunedImages::default();
        if all {
            self.untag_unused_images(&mut report).await?;
        }
        self.collect_layers(&mut report).await;
        self.collect_content(&mut report).await;
        Ok(report)
    }

    /// Forget every image record no task's spec asks for.
    ///
    /// Comparison is on the **canonical** reference both ways: a record is keyed
    /// `docker.io/library/alpine:latest` while a spec may say `alpine`, and
    /// comparing the two literally would untag an image a service is about to
    /// pull. A spec image that will not parse is treated as claiming everything
    /// it could possibly mean — nothing is untagged on this pass — because a
    /// reference we cannot read is not evidence that nothing uses it.
    async fn untag_unused_images(&self, report: &mut PrunedImages) -> Result<()> {
        let mut wanted: BTreeSet<String> = BTreeSet::new();
        let mut unparsable = 0;
        let mut add = |image: &str| match satl_image::ImageReference::parse(image) {
            Ok(parsed) => {
                wanted.insert(parsed.canonical());
                wanted.insert(image.to_owned());
            }
            Err(_) => unparsable += 1,
        };
        match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                for task in view.tasks() {
                    add(&task.spec.container.image);
                }
                for service in view.services() {
                    add(&service.spec.task.container.image);
                }
            }
            Err(_) => {
                for task in self.local_tasks().await? {
                    add(&task.spec.container.image);
                }
            }
        }
        if unparsable > 0 {
            tracing::warn!(
                specs = unparsable,
                "some task specs name an image reference that will not parse; no image \
                 record will be untagged on this pass"
            );
            return Ok(());
        }

        let images = self
            .executor
            .images()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list images: {err}")))?;
        for image in images {
            if wanted.contains(&image.reference) {
                continue;
            }
            match self.executor.images().remove(&image.reference).await {
                Ok(true) => report
                    .deleted
                    .push(ImageDeleted::Untagged(image.reference.clone())),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    reference = %image.reference,
                    %error,
                    "cannot forget this image record; leaving it and its layers alone"
                ),
            }
        }
        Ok(())
    }

    /// Destroy the layer datasets nothing references, on two agreeing passes.
    async fn collect_layers(&self, report: &mut PrunedImages) {
        let mut sweeper = satl_storage::LayerSweeper::default();
        let first = self.layer_claims().await;
        let Some((layers, claims)) = first else {
            return;
        };
        sweeper.plan(&layers, &claims);
        tokio::time::sleep(SETTLE).await;
        let Some((layers, claims)) = self.layer_claims().await else {
            return;
        };
        let due = sweeper.plan(&layers, &claims);
        report.deferred = sweeper
            .awaiting_agreement()
            .iter()
            .filter(|chain| !due.contains(chain))
            .cloned()
            .collect();
        if !report.deferred.is_empty() {
            tracing::info!(
                chains = ?report.deferred,
                "these layer chains looked unreferenced on only one of the two passes; \
                 nothing was destroyed for them. Run prune again to reclaim them"
            );
        }
        let sizes: std::collections::BTreeMap<&str, u64> = layers
            .iter()
            .map(|layer| (layer.chain.as_str(), layer.used))
            .collect();
        for chain in due {
            let bytes = sizes.get(chain.as_str()).copied().unwrap_or_default();
            match self.executor.layers().destroy(&chain).await {
                Ok(()) => {
                    report.space_reclaimed += bytes;
                    report
                        .deleted
                        .push(ImageDeleted::Deleted(format!("sha256:{chain}")));
                }
                // The expected refusal, and the one ZFS makes for us: something
                // still holds a clone of this layer. Not an error — a claim the
                // planner did not have.
                Err(error) => tracing::warn!(
                    chain_id = %chain,
                    %error,
                    "cannot destroy this layer dataset; something still holds a clone \
                     of it and it is being left alone"
                ),
            }
        }
    }

    /// One reading of the disk and of everything that may claim a layer chain.
    ///
    /// The claim set is the union of three readings, and the report says where
    /// each comes from because that is what makes it complete:
    ///
    /// - **image records** on this node, expanded to every chain in each
    ///   image's stack (`satl_storage::chains_of` over the config's diff IDs) —
    ///   not just the top chain, or every layer under an image would look
    ///   unreferenced;
    /// - **clone origins** on disk, which is how a container's writable layer
    ///   claims the image layer it was cloned from. This is the reading that
    ///   protects a **stopped** container, whose image record may well be gone;
    /// - **applies in flight**, from the layer store's own per-chain gate.
    async fn layer_claims(
        &self,
    ) -> Option<(Vec<satl_storage::LayerOnDisk>, satl_storage::LayerClaims)> {
        let layers = match self.executor.layers().list().await {
            Ok(layers) => layers,
            Err(error) => {
                tracing::warn!(%error, "cannot list layer datasets; nothing will be reclaimed");
                return None;
            }
        };
        let mut claims = satl_storage::LayerClaims {
            applying: self.executor.layers().applying_now(),
            ..satl_storage::LayerClaims::default()
        };

        match self.executor.images().list().await {
            Ok(images) => {
                for image in images {
                    let diff_ids: Vec<String> = image
                        .layers
                        .iter()
                        .map(|layer| layer.diff_id.as_str().to_owned())
                        .collect();
                    match satl_storage::chains_of(&diff_ids) {
                        Ok(chains) => claims
                            .image_chains
                            .extend(chains.into_iter().map(|chain| chain.hex().to_owned())),
                        Err(error) => {
                            tracing::warn!(
                                reference = %image.reference,
                                %error,
                                "cannot compute this image's layer chain; nothing will be \
                                 reclaimed on this pass"
                            );
                            return None;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "cannot read the image store; nothing will be reclaimed on this pass"
                );
                return None;
            }
        }

        // Clone origins, from the whole SatL root rather than from the container
        // dataset list: any clone of a layer's @final is a claim, wherever it
        // lives, and reading it off ZFS means the GC cannot be wrong about it.
        let layers_prefix = format!("{}/", self.executor.layers().root());
        match self
            .executor
            .zfs()
            .list_with_origin(&self.datasets.root)
            .await
        {
            Ok(rows) => {
                for row in rows {
                    // A layer's own origin is the parent edge, handled by the
                    // planner's ancestry closure; what matters here is a clone
                    // from *outside* the layers root.
                    if row.name.starts_with(&layers_prefix) {
                        continue;
                    }
                    if let Some(origin) = row.origin.as_deref()
                        && let Some(chain) = origin
                            .strip_prefix(&layers_prefix)
                            .and_then(|tail| tail.strip_suffix("@final"))
                    {
                        claims.clone_chains.insert(chain.to_owned());
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "cannot read clone origins; nothing will be reclaimed on this pass"
                );
                return None;
            }
        }
        tracing::debug!(
            layers = layers.len(),
            claimed = claims.len(),
            images = claims.image_chains.len(),
            clones = claims.clone_chains.len(),
            applying = claims.applying.len(),
            "layer GC pass"
        );
        Some((layers, claims))
    }

    /// Delete the content-store files no image record reaches.
    async fn collect_content(&self, report: &mut PrunedImages) {
        let audit = match self.executor.images().audit_content().await {
            Ok(audit) => audit,
            Err(error) => {
                tracing::warn!(%error, "cannot audit the image content store");
                return;
            }
        };
        if audit.pulls_in_flight > 0 {
            tracing::info!(
                pulls = audit.pulls_in_flight,
                "an image pull is in flight; the reachable set is incomplete by \
                 construction, so no content was reclaimed"
            );
            return;
        }
        for file in &audit.unreferenced {
            match self.executor.images().remove_content(file).await {
                Ok(()) => {
                    report.space_reclaimed += file.size;
                    report.deleted.push(ImageDeleted::Deleted(format!(
                        "{}:sha256:{}",
                        file.kind.as_str(),
                        file.digest
                    )));
                }
                Err(error) => tracing::warn!(
                    kind = file.kind.as_str(),
                    digest = %file.digest,
                    %error,
                    "cannot delete this unreferenced content file"
                ),
            }
        }
    }

    /// `POST /volumes/prune`: remove every node-local volume no task mounts.
    ///
    /// "No task mounts" is read from every task the cluster holds, not only the
    /// ones on this node: a volume name is cluster-visible in a service spec,
    /// and a task scheduled elsewhere today may be scheduled here tomorrow. A
    /// worker with no store falls back to its own task records, which is the
    /// only claim set it has.
    pub(super) async fn prune_volumes_impl(&self) -> Result<PrunedVolumes> {
        let mounted = self.mounted_volume_names().await?;
        let volumes = self
            .executor
            .volumes()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list volumes: {err}")))?;
        let mut deleted = Vec::new();
        let mut space_reclaimed = 0;
        for volume in volumes {
            if mounted.contains(&volume.name) {
                continue;
            }
            let bytes = self.bytes_of_volume(&volume.name).await;
            match self.executor.volumes().remove(&volume.name).await {
                Ok(()) => {
                    space_reclaimed += bytes;
                    deleted.push(volume.name);
                }
                Err(error) => tracing::warn!(
                    volume = %volume.name,
                    %error,
                    "cannot prune this volume; leaving it alone"
                ),
            }
        }
        Ok(PrunedVolumes {
            deleted,
            space_reclaimed,
        })
    }

    /// Every volume name any task mounts.
    async fn mounted_volume_names(&self) -> Result<BTreeSet<String>> {
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut collect = |task: &satl_core::Task| {
            for mount in &task.spec.container.mounts {
                if mount.kind == satl_core::MountType::Volume {
                    names.extend(mount.source.clone());
                }
            }
        };
        match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                for task in view.tasks() {
                    collect(&task);
                }
                for service in view.services() {
                    for mount in &service.spec.task.container.mounts {
                        if mount.kind == satl_core::MountType::Volume {
                            names.extend(mount.source.clone());
                        }
                    }
                }
            }
            Err(_) => {
                for task in self.local_tasks().await? {
                    collect(&task);
                }
            }
        }
        Ok(names)
    }

    /// Bytes one volume's dataset holds.
    async fn bytes_of_volume(&self, name: &str) -> u64 {
        let dataset = format!("{}/{name}", self.datasets.volumes_root);
        self.executor
            .zfs()
            .list_space(&dataset)
            .await
            .map(|rows| rows.iter().map(|row| row.used).sum())
            .unwrap_or_default()
    }
}
