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

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use satl_api::model::{
    BackendError, ImageDeleted, PrunedContainers, PrunedImages, PrunedNetworks, PrunedVolumes,
    Result,
};
use satl_core::{DesiredState, Id, ObjectKind, StoreAction, StoreObject};

use super::{DaemonBackend, events, names};

/// How long the two passes of the layer GC are apart.
///
/// Long enough to matter and short enough that an operator does not think the
/// command has hung. What it buys is a *second reading* of the claim set: the
/// store just after a leadership change, a worker just after a restart and an
/// image store mid-pull are each momentarily incomplete, and a pass taken while
/// one of them is settling must not be the only pass.
const SETTLE: Duration = Duration::from_millis(1500);

/// The shortest image-ID prefix `DELETE /images/{name}` will resolve.
///
/// Docker's own floor. Shorter than this and a prefix stops identifying
/// anything in a store of any size, and "remove the image whose digest starts
/// with `a`" is not a request anybody means.
const MIN_ID_PREFIX: usize = 6;

/// Every image reference the cluster -- or, on a worker, this node -- asks
/// for, split by how strong the claim is.
///
/// Both spellings of every reference are inserted, the raw one from the spec
/// and its canonical form, because a record is keyed
/// `docker.io/library/alpine:latest` while a spec may say `alpine`, and
/// comparing the two literally would miss.
#[derive(Debug, Default)]
pub(super) struct ImageClaims {
    /// References a **non-terminal** task, or a service that still wants
    /// tasks, asks for — mapped to the operator-facing name of what holds
    /// them. `--force` cannot override these: a service that will mint another
    /// task is a standing order, and untagging under it turns the next start
    /// into a pull against a registry that may be gone.
    live: BTreeMap<String, String>,
    /// References only **terminal** tasks hold. `--force` untags anyway.
    stopped: BTreeMap<String, String>,
    /// Specs whose image reference will not parse. One of these makes the
    /// whole claim set incomplete by construction.
    unparsable: usize,
}

impl ImageClaims {
    /// Record a claim under both spellings of `image`.
    // Deliberately not `satl_image::canonical_key`: this site keeps both
    // spellings because conflict messages must echo what the user typed.
    fn add(&mut self, image: &str, holder: String, live: bool) {
        let Ok(parsed) = satl_image::ImageReference::parse(image) else {
            self.unparsable += 1;
            return;
        };
        let map = if live {
            &mut self.live
        } else {
            &mut self.stopped
        };
        map.entry(parsed.canonical())
            .or_insert_with(|| holder.clone());
        map.entry(image.to_owned()).or_insert(holder);
    }

    /// A task claims its image; whether the claim is live is the task's own
    /// state. Deliberately **not** `is_stoppable`: a task created but never
    /// started sits at a non-terminal state with `desired = Ready`, and it
    /// still needs its image to start.
    fn add_task(&mut self, task: &satl_core::Task) {
        let live = !task.status.state.is_terminal();
        let holder = if live {
            format!("running container {}", task.id)
        } else {
            format!("container {}", task.id)
        };
        self.add(&task.spec.container.image, holder, live);
    }

    /// A service claims its image, live **unless it has stopped wanting
    /// tasks**.
    ///
    /// The nuance is forced by invariant #2. Every container is a task of a
    /// service, so a `satl stop`ped container still has its service, and a
    /// service that claimed unconditionally would make Docker's
    /// `(must force)` arm unreachable: there would be no way to reach "only a
    /// stopped container references this image", because the service behind it
    /// always would too.
    ///
    /// So the question is not "does a service exist" but "will it produce a
    /// task that needs this image". It will unless **every** task it owns is
    /// terminal *and* desired-shutdown — which is exactly the state `satl
    /// stop` leaves, and exactly the rail `prune_containers_impl` already uses
    /// to decide a service is prunable. A service with no tasks yet is live:
    /// it is about to have some.
    fn add_service(&mut self, service: &satl_core::Service, tasks: &[&satl_core::Task]) {
        let owned: Vec<&&satl_core::Task> = tasks
            .iter()
            .filter(|task| task.service_id.as_ref() == Some(&service.id))
            .collect();
        let live = owned.is_empty()
            || owned.iter().any(|task| {
                !task.status.state.is_terminal() || task.desired_state < DesiredState::Shutdown
            });
        let holder = format!("service {}", service.spec.annotations.name);
        self.add(&service.spec.task.container.image, holder, live);
    }

    /// Whether any reference here is claimed at all -- used by the prune to
    /// skip a record without building an error for it.
    fn holds(&self, reference: &str) -> bool {
        self.live.contains_key(reference) || self.stopped.contains_key(reference)
    }
}

/// What the operator named, as the set of store records it selects.
#[derive(Debug)]
pub(super) struct ImageTarget {
    /// The image ID -- SatL's is the manifest digest (api-compat #41).
    pub(super) id: String,
    /// Every canonical reference in this node's store that resolves to it.
    pub(super) references: Vec<String>,
}

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
        self.reclaim(&mut report).await;
        Ok(report)
    }

    /// `DELETE /images/{name}?force=&noprune=`: forget one image record and
    /// reclaim what stopped being referenced.
    ///
    /// The same three stages as [`prune_images_impl`], scoped to one target.
    /// In particular the layer sweep is the *same* sweep, two agreeing
    /// readings [`SETTLE`] apart, which is why a single removal takes about a
    /// second and a half (api-compat 155): a layer's loss is not recoverable
    /// by re-running anything, so one reading is not evidence here either.
    /// `noprune` skips both sweeps, and is the way to pay that cost once for a
    /// batch instead of once per image.
    pub(super) async fn remove_image_impl(
        &self,
        reference: &str,
        force: bool,
        noprune: bool,
    ) -> Result<PrunedImages> {
        let claims = self.image_claims().await?;
        let target = self.resolve_image_target(reference).await?;
        let mut report = PrunedImages::default();
        self.untag_image(&claims, &target, force, &mut report)
            .await?;
        if !noprune {
            self.reclaim(&mut report).await;
        }
        Ok(report)
    }

    /// The two sweeps, without the record pass: layers on two agreeing
    /// readings, then unreachable content.
    async fn reclaim(&self, report: &mut PrunedImages) {
        self.collect_layers(report).await;
        self.collect_content(report).await;
    }

    /// One reading of every image reference this node's cluster asks for.
    ///
    /// On a manager the claim set is the whole store's tasks and services; on
    /// a worker it is this node's local task DB. That fallback is why image
    /// removal **never answers 503** — an image is node-local (api-compat
    /// #130) and has no cluster read to be refused for, unlike `satl node ps`.
    async fn image_claims(&self) -> Result<ImageClaims> {
        let mut claims = ImageClaims::default();
        match Self::manager_of(self.cluster()?.as_ref()) {
            Ok(manager) => {
                let view = manager.store.view();
                let owned = view.tasks();
                let tasks: Vec<&satl_core::Task> =
                    owned.iter().map(std::convert::AsRef::as_ref).collect();
                for task in &tasks {
                    claims.add_task(task);
                }
                for service in view.services() {
                    claims.add_service(service.as_ref(), &tasks);
                }
            }
            Err(_) => {
                for task in self.local_tasks().await? {
                    claims.add_task(&task);
                }
            }
        }
        if claims.unparsable > 0 {
            tracing::warn!(
                specs = claims.unparsable,
                "some task specs name an image reference that will not parse; no image \
                 record will be untagged on this pass"
            );
        }
        Ok(claims)
    }

    /// The one place "is this image in use" is decided.
    ///
    /// Both `DELETE /images/{name}` and the `-a` half of `POST /images/prune`
    /// ask this function the same question, so the two verbs cannot disagree
    /// about what is in use — the same discipline `remove_network_impl` and
    /// `prune_networks_impl` already share (api-compat 161).
    fn image_conflict(
        claims: &ImageClaims,
        target: &ImageTarget,
        force: bool,
    ) -> Option<BackendError> {
        let named = target
            .references
            .first()
            .map_or(target.id.as_str(), String::as_str);

        // A claim set assembled from a spec that will not parse is incomplete
        // by construction, so nothing may go on this reading. This is the
        // fail-safe `untag_unused_images` has always had, now expressed once
        // for both callers.
        if claims.unparsable > 0 {
            return Some(BackendError::conflict(format!(
                "unable to delete {named} (cannot be forced) - a task spec names an image \
                 reference that cannot be read, so what still uses this image is unknown"
            )));
        }

        for reference in &target.references {
            if let Some(holder) = claims.live.get(reference) {
                return Some(BackendError::conflict(format!(
                    "unable to delete {reference} (cannot be forced) - image is being used \
                     by {holder}"
                )));
            }
        }

        // More than one reference resolving to the same image is Docker's
        // "referenced in multiple repositories": removing by ID would forget
        // all of them, which is not what an unqualified request means.
        if !force && target.references.len() > 1 {
            return Some(BackendError::conflict(format!(
                "unable to delete {} (must be forced) - image is referenced in multiple \
                 repositories",
                short_id(&target.id)
            )));
        }

        if force {
            return None;
        }
        for reference in &target.references {
            if let Some(holder) = claims.stopped.get(reference) {
                return Some(BackendError::conflict(format!(
                    "unable to remove repository reference \"{reference}\" (must force) - \
                     {holder} is using its referenced image {}",
                    short_id(&target.id)
                )));
            }
        }
        None
    }

    /// Resolve what the operator named to the store records it selects.
    ///
    /// The **image-ID form is tried first, before the reference parser**, and
    /// that order is load-bearing: `sha256:abcdef` is a syntactically valid
    /// Docker reference (`docker.io/library/sha256:abcdef`), so parsing first
    /// would turn every removal by ID into a lookup that can only miss
    /// (api-compat 158).
    pub(super) async fn resolve_image_target(&self, name: &str) -> Result<ImageTarget> {
        let images = self
            .executor
            .images()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list images: {err}")))?;

        if let Some(prefix) = id_prefix(name) {
            let mut references = Vec::new();
            let mut id = None;
            for image in &images {
                if image.manifest_digest.hex().starts_with(prefix) {
                    id = Some(image.manifest_digest.as_str().to_owned());
                    references.push(image.reference.clone());
                }
            }
            if let Some(id) = id {
                return Ok(ImageTarget { id, references });
            }
            return Err(BackendError::not_found(format!("No such image: {name}")));
        }

        let parsed = satl_image::ImageReference::parse(name)
            .map_err(|err| BackendError::invalid(format!("invalid reference {name}: {err}")))?;
        let canonical = parsed.canonical();
        let found = images
            .iter()
            .find(|image| image.reference == canonical)
            .ok_or_else(|| BackendError::not_found(format!("No such image: {name}")))?;
        Ok(ImageTarget {
            id: found.manifest_digest.as_str().to_owned(),
            references: vec![found.reference.clone()],
        })
    }

    /// Forget one target's records, refusing if anything still claims them.
    ///
    /// `ImageStore::remove` writes `repositories.json` before anything is
    /// deleted, so a store read is never left pointing at a file that has
    /// gone; the sweeps that follow are what actually reclaim disk.
    async fn untag_image(
        &self,
        claims: &ImageClaims,
        target: &ImageTarget,
        force: bool,
        report: &mut PrunedImages,
    ) -> Result<()> {
        if let Some(conflict) = Self::image_conflict(claims, target, force) {
            return Err(conflict);
        }
        for reference in &target.references {
            match self.executor.images().remove(reference).await {
                Ok(true) => {
                    report
                        .deleted
                        .push(ImageDeleted::Untagged(reference.clone()));
                    let _ = self.local_events.send(events::image_untag(reference));
                }
                // Raced with another remover; nothing to report.
                Ok(false) => {}
                Err(error) => {
                    return Err(BackendError::internal(format!(
                        "cannot forget the image record {reference}: {error}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Forget every image record no task's spec asks for.
    ///
    /// Drives the same single-object path `DELETE /images/{name}` does and
    /// swallows its `Conflict` as a skip — the shape `prune_networks_impl`
    /// already uses for networks, and the reason the two image verbs cannot
    /// disagree about what is in use.
    ///
    /// The claim set is read **once** for the whole pass. A spec image that
    /// will not parse still means nothing is untagged at all, because
    /// `image_conflict` turns `unparsable > 0` into a conflict for every
    /// record: a reference we cannot read is not evidence that nothing uses
    /// it.
    async fn untag_unused_images(&self, report: &mut PrunedImages) -> Result<()> {
        let claims = self.image_claims().await?;
        let images = self
            .executor
            .images()
            .list()
            .await
            .map_err(|err| BackendError::internal(format!("cannot list images: {err}")))?;
        for image in images {
            if claims.holds(&image.reference) {
                continue;
            }
            let target = ImageTarget {
                id: image.manifest_digest.as_str().to_owned(),
                references: vec![image.reference.clone()],
            };
            // `force` is true so a record held only by a terminal task is
            // still reclaimed: a prune is the verb whose whole job is
            // reclaiming those. A *live* claim is refused regardless, which is
            // the point of the distinction.
            match self.untag_image(&claims, &target, true, report).await {
                Ok(()) => {}
                Err(BackendError::Conflict(reason)) => tracing::debug!(
                    reference = %image.reference,
                    %reason,
                    "image still in use; not untagged"
                ),
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

/// The hex part of `name`, if it names an image by ID rather than by
/// reference: `sha256:<hex>` or a bare hex prefix of at least
/// [`MIN_ID_PREFIX`] characters.
///
/// Returns `None` for anything that could be a repository name, so an image
/// called `deadbeef` is still addressable — it is simply spelled with its tag
/// (`deadbeef:latest`), which the reference parser then accepts.
fn id_prefix(name: &str) -> Option<&str> {
    let hex = match name.strip_prefix("sha256:") {
        // With the algorithm spelled out there is no ambiguity, so any
        // non-empty hex run is an ID.
        Some(rest) => rest,
        // Bare hex is only an ID when it cannot be a reference: no separator
        // of any kind, and long enough to mean something.
        None if !name.contains([':', '/', '@', '.']) && name.len() >= MIN_ID_PREFIX => name,
        None => return None,
    };
    (!hex.is_empty() && hex.len() <= 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(hex)
}

/// An image ID as Docker prints it in a conflict: the first 12 hex
/// characters, without the algorithm prefix.
fn short_id(id: &str) -> &str {
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    &hex[..hex.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sha256:<hex>` and a long enough bare hex run are IDs; anything that
    /// could be a repository name is not.
    #[test]
    fn an_image_id_is_recognised_before_it_can_parse_as_a_reference() {
        assert_eq!(id_prefix("sha256:deadbeef"), Some("deadbeef"));
        assert_eq!(id_prefix("deadbeef"), Some("deadbeef"));
        // Too short to mean anything.
        assert_eq!(id_prefix("dead"), None);
        // Not hex.
        assert_eq!(id_prefix("nginxserver"), None);
        // Carries a separator, so it is a reference: `alpine:latest`,
        // `ghcr.io/x/y`, `x@sha256:...`, and a bare `deadbeef:latest` are all
        // addressable by name.
        assert_eq!(id_prefix("deadbeef:latest"), None);
        assert_eq!(id_prefix("ghcr.io/x/y"), None);
        assert_eq!(id_prefix("x@sha256:aa"), None);
        // `sha256:` with a non-hex tail is not an ID either.
        assert_eq!(id_prefix("sha256:zzzz"), None);
    }

    #[test]
    fn short_id_is_dockers_twelve_characters_without_the_algorithm() {
        assert_eq!(short_id("sha256:0123456789abcdef0123"), "0123456789ab");
        assert_eq!(short_id("sha256:abc"), "abc");
    }

    /// A service naming `image`, as the control plane would write it.
    fn a_service(name: &str, image: &str) -> satl_core::Service {
        let mut spec = crate::backend::service_spec(
            name.to_owned(),
            &satl_api::model::CreateContainerOptions {
                image: image.to_owned(),
                ..satl_api::model::CreateContainerOptions::default()
            },
        );
        spec.task.container.image = image.to_owned();
        satl_core::Service {
            id: Id::generate(),
            meta: satl_core::Meta::new(),
            spec,
            endpoint: None,
            spec_version: satl_core::Version::default(),
            previous_spec: None,
            update_status: None,
        }
    }

    /// One task of `service`, in the given observed and desired states.
    fn a_task(service: &Id, state: satl_core::TaskState, desired: DesiredState) -> satl_core::Task {
        satl_core::Task {
            id: Id::generate(),
            annotations: satl_core::Annotations::default(),
            meta: satl_core::Meta::new(),
            spec: crate::backend::tests::empty_task_spec(),
            spec_version: None,
            service_id: Some(service.clone()),
            slot: 1,
            node_id: None,
            service_annotations: satl_core::Annotations::default(),
            status: satl_core::TaskStatus::new(state, "test"),
            desired_state: desired,
            networks: Vec::new(),
            endpoint: None,
            job_iteration: None,
        }
    }

    fn target(references: &[&str]) -> ImageTarget {
        ImageTarget {
            id: "sha256:0123456789abcdef".to_owned(),
            references: references.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    fn claims(live: &[(&str, &str)], stopped: &[(&str, &str)]) -> ImageClaims {
        let owned = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        };
        ImageClaims {
            live: owned(live),
            stopped: owned(stopped),
            unparsable: 0,
        }
    }

    /// A live claim is the one thing `--force` cannot buy past.
    #[test]
    fn a_live_claim_cannot_be_forced() {
        let claims = claims(
            &[("docker.io/library/alpine:latest", "running container 1kql")],
            &[],
        );
        let target = target(&["docker.io/library/alpine:latest"]);
        for force in [false, true] {
            let error = DaemonBackend::image_conflict(&claims, &target, force)
                .expect("a running container still holds it");
            let text = error.to_string();
            assert!(text.contains("cannot be forced"), "{text}");
            assert!(text.contains("running container 1kql"), "{text}");
        }
    }

    /// A service spec is a standing order to create tasks, so it is live even
    /// with no task running yet.
    #[test]
    fn a_service_spec_is_a_live_claim() {
        let claims = claims(&[("docker.io/library/nginx:1.27", "service web")], &[]);
        let target = target(&["docker.io/library/nginx:1.27"]);
        let error = DaemonBackend::image_conflict(&claims, &target, true)
            .expect("the service spec still names it");
        assert!(error.to_string().contains("service web"), "{error}");
    }

    /// The classification a stopped container has to produce.
    ///
    /// Invariant #2 makes every container a task of a service, so if a service
    /// claimed unconditionally there would be no reachable state in which only
    /// a *stopped* container references an image -- and Docker's `(must
    /// force)` arm would be dead code. A service is live while it still wants
    /// tasks, and stops being live exactly when `satl stop` has left every one
    /// of its tasks terminal and desired-shutdown.
    #[test]
    fn a_service_stops_claiming_live_once_it_has_stopped_wanting_tasks() {
        let service = a_service("web", "alpine");
        let stopped_task = a_task(
            &service.id,
            satl_core::TaskState::Shutdown,
            DesiredState::Shutdown,
        );
        let running_task = a_task(
            &service.id,
            satl_core::TaskState::Running,
            DesiredState::Running,
        );

        // Every task terminal and desired-shutdown: a stopped container.
        let mut claims = ImageClaims::default();
        claims.add_service(&service, &[&stopped_task]);
        assert!(
            !claims.live.contains_key("docker.io/library/alpine:latest"),
            "a service whose every task is stopped is not a live claim"
        );
        assert!(
            claims
                .stopped
                .contains_key("docker.io/library/alpine:latest")
        );

        // One task still running: live.
        let mut claims = ImageClaims::default();
        claims.add_service(&service, &[&stopped_task, &running_task]);
        assert!(claims.live.contains_key("docker.io/library/alpine:latest"));

        // No tasks yet: live, because it is about to have some.
        let mut claims = ImageClaims::default();
        claims.add_service(&service, &[]);
        assert!(claims.live.contains_key("docker.io/library/alpine:latest"));
    }

    /// Only terminal tasks: refused by default, reclaimed with `--force`.
    #[test]
    fn a_stopped_claim_is_refused_by_default_and_forced_through() {
        let claims = claims(
            &[],
            &[("docker.io/library/alpine:latest", "container 2ju5")],
        );
        let target = target(&["docker.io/library/alpine:latest"]);
        let error = DaemonBackend::image_conflict(&claims, &target, false)
            .expect("a stopped container still references it");
        assert!(error.to_string().contains("must force"), "{error}");
        assert!(DaemonBackend::image_conflict(&claims, &target, true).is_none());
    }

    /// Nothing claims it: it goes, forced or not.
    #[test]
    fn an_unclaimed_image_is_removable() {
        let claims = claims(&[], &[]);
        let target = target(&["docker.io/library/alpine:latest"]);
        assert!(DaemonBackend::image_conflict(&claims, &target, false).is_none());
    }

    /// Removing by ID when several references share the digest is Docker's
    /// multi-repository refusal.
    #[test]
    fn an_image_reachable_from_several_references_must_be_forced() {
        let claims = claims(&[], &[]);
        let target = target(&[
            "docker.io/library/alpine:3.20",
            "docker.io/library/alpine:latest",
        ]);
        let error = DaemonBackend::image_conflict(&claims, &target, false)
            .expect("two references resolve to it");
        let text = error.to_string();
        assert!(text.contains("must be forced"), "{text}");
        assert!(
            text.contains("referenced in multiple repositories"),
            "{text}"
        );
        assert!(DaemonBackend::image_conflict(&claims, &target, true).is_none());
    }

    /// The fail-safe: one spec we cannot read makes the claim set incomplete
    /// by construction, so nothing may go — which is what keeps
    /// `untag_unused_images` untagging nothing at all on such a pass.
    #[test]
    fn one_unparsable_spec_refuses_every_removal() {
        let mut claims = claims(&[], &[]);
        claims.unparsable = 1;
        let target = target(&["docker.io/library/alpine:latest"]);
        for force in [false, true] {
            let error = DaemonBackend::image_conflict(&claims, &target, force)
                .expect("the claim set is incomplete");
            let text = error.to_string();
            assert!(text.contains("cannot be forced"), "{text}");
            assert!(text.contains("cannot be read"), "{text}");
        }
    }

    /// Both spellings of a spec image are claimed, so a spec saying `alpine`
    /// protects the record keyed `docker.io/library/alpine:latest`. This is
    /// the comparison `list_images`' Containers count used to get wrong.
    #[test]
    fn a_short_spec_reference_claims_the_canonical_record() {
        let mut claims = ImageClaims::default();
        claims.add("alpine", "running container 1kql".to_owned(), true);
        assert!(claims.holds("docker.io/library/alpine:latest"));
        assert!(claims.holds("alpine"));
    }
}
