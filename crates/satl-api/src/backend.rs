// SPDX-License-Identifier: BSD-2-Clause
//! The seam between the Docker REST API and the daemon.
//!
//! [`Backend`] is everything `satld` must provide for the M1 endpoint set
//! (containers, images, exec, volumes, events, counts). The API crate owns
//! Docker semantics — status codes, JSON shapes, framing, timestamps — and
//! nothing else: every request is validated, converted into the plain types
//! of [`model`], handed to a `Backend`, and its answer rendered back.
//!
//! Until the daemon wires a real implementation, [`ApiState`](crate::ApiState)
//! carries [`UnwiredBackend`], which fails every call with `501 Not
//! Implemented`.

pub mod model;

use async_trait::async_trait;
use futures_util::stream::BoxStream;

use model::{
    BackendError, ChangeOutcome, ConfigCreated, ContainerInspect, ContainerSummary, Counts,
    CreateContainerOptions, CreateNetworkOptions, CreateVolumeOptions, CreatedContainer,
    EventMessage, ExecConfig, ExecId, ExecInspect, ExecStream, ImageSummary, LogFrame, LogOptions,
    NetworkConnectOptions, NetworkCreated, NetworkDetail, NetworkDisconnectOptions, NetworkSummary,
    NodeDetail, NodeSpecUpdate, NodeSummary, PrunedContainers, PrunedImages, PrunedNetworks,
    PrunedVolumes, PullProgressLine, RegistryAuth, Result, SecretCreated, ServiceCreateOptions,
    ServiceCreated, ServiceDetail, ServiceSummary, ServiceUpdateOptions, SwarmDetail,
    SwarmInitOptions, SwarmInitResult, SwarmJoinOptions, SwarmStatus, TaskDetail, TaskFilters,
    TaskSummary, TokenRole, VolumeInfo, WaitCondition, WaitResult,
};
use satl_core::{Platform, Version};
use std::time::{Duration, SystemTime};

/// Daemon operations behind the Docker REST API.
///
/// Implementations live in `satld`; the API crate is built and tested against
/// this trait alone. Every method returns [`BackendError`], which the API maps
/// to Docker's status codes (`crate::error`).
///
/// Identifiers are accepted the way Docker accepts them: a full container ID
/// (= Task ID, 25-char base36), an unambiguous ID prefix, or the container
/// name (= service name). Resolution is the backend's job.
#[async_trait]
pub trait Backend: Send + Sync + 'static {
    // -- containers ---------------------------------------------------------

    /// Creates the anonymous single-replica service backing one container and
    /// returns its Task ID. Does not start it.
    async fn create_container(&self, options: CreateContainerOptions) -> Result<CreatedContainer>;

    /// Starts a created container. `Unchanged` when it was already running.
    async fn start_container(&self, id: &str) -> Result<ChangeOutcome>;

    /// Stops a running container, `SIGKILL`-ing it after `timeout`
    /// ([`DEFAULT_STOP_TIMEOUT`](model::DEFAULT_STOP_TIMEOUT) when `None`).
    /// `Unchanged` when it was already stopped.
    async fn stop_container(&self, id: &str, timeout: Option<Duration>) -> Result<ChangeOutcome>;

    /// Sends `signal` (e.g. `SIGKILL`, `TERM`, `9`) to the container's main
    /// process. Conflict when the container is not running.
    async fn kill_container(&self, id: &str, signal: &str) -> Result<()>;

    /// Removes a container. `force` kills it first; `remove_volumes` also
    /// destroys its anonymous volumes.
    async fn remove_container(&self, id: &str, force: bool, remove_volumes: bool) -> Result<()>;

    /// Lists containers; `all` includes non-running ones.
    async fn list_containers(&self, all: bool) -> Result<Vec<ContainerSummary>>;

    /// Full inspect document for one container.
    async fn inspect_container(&self, id: &str) -> Result<ContainerInspect>;

    /// Blocks until the container reaches `condition`, then reports its exit
    /// code.
    async fn wait_container(&self, id: &str, condition: WaitCondition) -> Result<WaitResult>;

    /// Streams container output as unframed [`LogFrame`]s (the API applies
    /// Docker's multiplexed framing).
    async fn container_logs(
        &self,
        id: &str,
        options: LogOptions,
    ) -> Result<BoxStream<'static, LogFrame>>;

    // -- images -------------------------------------------------------------

    /// Pulls `reference` (`name[:tag|@digest]`), streaming progress lines.
    async fn pull_image(
        &self,
        reference: &str,
        auth: Option<RegistryAuth>,
        platform: Option<Platform>,
    ) -> Result<BoxStream<'static, PullProgressLine>>;

    /// Lists images held in the content store.
    async fn list_images(&self) -> Result<Vec<ImageSummary>>;

    /// Makes `target` an additional local reference to the image `source`
    /// names (`POST /images/{name}/tag`). Both are `name[:tag|@digest]`
    /// strings the backend validates: `NotFound` when the source is unknown
    /// locally, `InvalidParameter` when either fails to parse. Tagging an
    /// image with the name it already has is a no-op success (Docker's
    /// behavior).
    async fn tag_image(&self, source: &str, target: &str) -> Result<()>;

    // -- prune --------------------------------------------------------------
    //
    // Four calls because Docker has four endpoints and `docker system prune`
    // drives them in this order. Only the first two are cluster-wide: a
    // container is a task of a service and a network is a store object, while
    // images, layers, blobs and volumes are **node-local** — they exist on
    // whichever node pulled or created them, and this daemon can only reclaim
    // its own. Deviations 129-136 in `docs/api-compat.md`.

    /// Removes every stopped container, with the backing service of each — the
    /// same thing `remove_container` does, for the same reason (the
    /// orchestrator would otherwise refill the slot).
    ///
    /// A service is only pruned when **all** of its containers are stopped, so
    /// pruning never destroys a service that still has a replica serving.
    async fn prune_containers(&self) -> Result<PrunedContainers>;

    /// Reclaims image content and layer datasets **on this node**.
    ///
    /// `all` is Docker's `-a`: without it only content nothing references is
    /// reclaimed (SatL's equivalent of a dangling image — see
    /// [`model::PrunedImages`]); with it, image records no container uses are
    /// removed first and their content follows.
    async fn prune_images(&self, all: bool) -> Result<PrunedImages>;

    /// Removes every user-defined network with no task attached.
    async fn prune_networks(&self) -> Result<PrunedNetworks>;

    /// Removes every node-local volume no task mounts.
    async fn prune_volumes(&self) -> Result<PrunedVolumes>;

    // -- exec ---------------------------------------------------------------

    /// Prepares an exec instance against a running container.
    async fn create_exec(&self, container: &str, config: ExecConfig) -> Result<ExecId>;

    /// Runs a prepared exec instance, returning its output stream and a
    /// receiver for its exit code.
    async fn start_exec(&self, exec_id: &str) -> Result<ExecStream>;

    /// State of an exec instance.
    async fn inspect_exec(&self, exec_id: &str) -> Result<ExecInspect>;

    // -- volumes ------------------------------------------------------------

    /// Creates (or adopts, Docker-style) a named volume.
    async fn create_volume(&self, options: CreateVolumeOptions) -> Result<VolumeInfo>;

    /// Lists node-local volumes.
    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>>;

    /// Removes a volume; `force` ignores "no such volume".
    async fn remove_volume(&self, name: &str, force: bool) -> Result<()>;

    // -- networks -----------------------------------------------------------

    /// Lists networks, each with the gateway address **this node** holds on it
    /// (`None` when it holds none) — an overlay has one gateway per
    /// participating node, so there is no cluster-wide answer to give.
    async fn list_networks(&self) -> Result<Vec<NetworkSummary>>;

    /// One network, by ID, ID prefix or name, with its attached tasks.
    async fn inspect_network(&self, id_or_name: &str) -> Result<NetworkDetail>;

    /// Creates a network from a validated spec. Name collisions are a
    /// `Conflict`; a second `ingress` network is an `InvalidParameter`.
    async fn create_network(&self, options: CreateNetworkOptions) -> Result<NetworkCreated>;

    /// Removes a network. A network with tasks still attached is a `Conflict`
    /// (Docker's "has active endpoints").
    async fn remove_network(&self, id_or_name: &str) -> Result<()>;

    /// Attaches a container to a network.
    async fn connect_network(&self, id_or_name: &str, options: NetworkConnectOptions)
    -> Result<()>;

    /// Detaches a container from a network.
    async fn disconnect_network(
        &self,
        id_or_name: &str,
        options: NetworkDisconnectOptions,
    ) -> Result<()>;

    // -- events / system ----------------------------------------------------

    /// Streams daemon events, replaying those at or after `since`.
    async fn events(&self, since: Option<SystemTime>) -> Result<BoxStream<'static, EventMessage>>;

    /// Container/image counts for `GET /info`.
    async fn system_counts(&self) -> Result<Counts>;

    // -- swarm --------------------------------------------------------------

    /// Bootstraps (or re-bootstraps) the local cluster and returns the ID of
    /// the node that now manages it.
    async fn swarm_init(&self, options: SwarmInitOptions) -> Result<SwarmInitResult>;

    /// Joins an existing cluster through one of `remote_addrs`; the token
    /// decides whether the node joins as a worker or a manager.
    async fn swarm_join(&self, options: SwarmJoinOptions) -> Result<()>;

    /// Leaves the cluster. `force` lets the last manager leave, destroying the
    /// cluster state with it.
    async fn swarm_leave(&self, force: bool) -> Result<()>;

    /// The cluster object: identity, spec, join tokens, root CA.
    async fn swarm_inspect(&self) -> Result<SwarmDetail>;

    /// Regenerates one join token and returns the updated cluster object.
    async fn swarm_rotate_token(&self, role: TokenRole) -> Result<SwarmDetail>;

    /// Turns manager autolock on or off (Docker's
    /// `EncryptionConfig.AutoLockManagers`). Enabling generates a fresh
    /// unlock key; each manager's watcher then seals its DEK. Returns the
    /// updated cluster object.
    async fn swarm_set_autolock(&self, enabled: bool) -> Result<SwarmDetail>;

    /// The current unlock key (base64), for `GET /swarm/unlockkey` —
    /// readable only from an unlocked manager's store.
    async fn swarm_unlock_key(&self) -> Result<String>;

    /// Rotates the unlock key (Docker's
    /// `POST /swarm/update?rotateManagerUnlockKey=true`): a fresh key into
    /// the store, and each manager's watcher reseals. Returns the updated
    /// cluster object.
    async fn swarm_rotate_unlock_key(&self) -> Result<SwarmDetail>;

    /// Starts a root CA rotation (docker's `CAConfig.ForceRotate` bump on
    /// `POST /swarm/update`): mints a new root, cross-signs the transition,
    /// installs the transitional trust bundle and regenerates the join
    /// tokens. The rotation itself then converges asynchronously; progress
    /// is visible as `RootRotationInProgress` on `GET /swarm`.
    /// `force_rotate` is the counter value the caller's spec carried.
    async fn swarm_rotate_ca(&self, force_rotate: u64) -> Result<SwarmDetail>;

    /// Live cluster membership for `GET /info`'s `Swarm` section.
    ///
    /// Answering `NotImplemented` is meaningful: `GET /info` then falls back
    /// to the static section [`ApiState::new`](crate::ApiState::new) was built
    /// with, so `/info` keeps working before the daemon wires its backend.
    async fn swarm_status(&self) -> Result<SwarmStatus>;

    // -- nodes --------------------------------------------------------------

    /// Lists cluster members.
    async fn list_nodes(&self) -> Result<Vec<NodeSummary>>;

    /// One member, by ID, ID prefix or hostname.
    async fn inspect_node(&self, id_or_name: &str) -> Result<NodeDetail>;

    /// Replaces a node's spec. `version` is the caller's copy of the object
    /// version: a mismatch is an optimistic-concurrency conflict (409).
    async fn update_node(&self, id: &str, version: Version, spec: NodeSpecUpdate) -> Result<()>;

    /// Removes a member from the cluster. `force` removes a node that is
    /// still reachable (Docker's `--force`).
    async fn remove_node(&self, id: &str, force: bool) -> Result<()>;

    // -- services -----------------------------------------------------------

    /// Creates a service from a validated spec.
    async fn create_service(&self, options: ServiceCreateOptions) -> Result<ServiceCreated>;

    /// Lists services with their replica counts.
    async fn list_services(&self) -> Result<Vec<ServiceSummary>>;

    /// One service, by ID, ID prefix or name.
    async fn inspect_service(&self, id_or_name: &str) -> Result<ServiceDetail>;

    /// Replaces a service's spec, returning the daemon's warnings. `version`
    /// is the caller's copy of the object version (409 on mismatch).
    async fn update_service(
        &self,
        id: &str,
        version: Version,
        options: ServiceUpdateOptions,
    ) -> Result<Vec<String>>;

    /// Removes a service and, with it, every task it owns.
    async fn remove_service(&self, id_or_name: &str) -> Result<()>;

    // -- tasks --------------------------------------------------------------

    /// Lists tasks matching `filters` (an empty filter set matches all).
    async fn list_tasks(&self, filters: TaskFilters) -> Result<Vec<TaskSummary>>;

    /// One task, by ID or ID prefix.
    async fn inspect_task(&self, id: &str) -> Result<TaskDetail>;

    // -- secrets ------------------------------------------------------------

    /// Creates a secret from a validated spec. A name collision is a
    /// `Conflict`.
    ///
    /// The spec is taken by value and never logged: the payload lives inside
    /// it, and `SecretSpec`'s `Debug` redacts it (invariant #7).
    async fn create_secret(&self, spec: satl_core::SecretSpec) -> Result<SecretCreated>;

    /// Lists secrets. The objects carry their payloads — the API is what drops
    /// them, so a backend never has to.
    async fn list_secrets(&self) -> Result<Vec<satl_core::Secret>>;

    /// One secret, by ID, ID prefix or name.
    async fn inspect_secret(&self, id_or_name: &str) -> Result<satl_core::Secret>;

    /// Removes a secret. One a service or a live task still references is a
    /// `Conflict` naming them.
    async fn remove_secret(&self, id_or_name: &str) -> Result<()>;

    // -- configs ------------------------------------------------------------

    /// Creates a config from a validated spec. A name collision is a
    /// `Conflict`.
    async fn create_config(&self, spec: satl_core::ConfigSpec) -> Result<ConfigCreated>;

    /// Lists configs, payloads included (a config is not a secret).
    async fn list_configs(&self) -> Result<Vec<satl_core::Config>>;

    /// One config, by ID, ID prefix or name.
    async fn inspect_config(&self, id_or_name: &str) -> Result<satl_core::Config>;

    /// Removes a config. One a service or a live task still references is a
    /// `Conflict` naming them.
    async fn remove_config(&self, id_or_name: &str) -> Result<()>;
}

/// Placeholder backend used until `satld` injects the real one: every call
/// fails with `501 Not Implemented`, except
/// [`system_counts`](Backend::system_counts), which reports zeros so `GET
/// /info` keeps answering.
///
/// It exists so [`ApiState::new`](crate::ApiState::new) keeps its M0
/// signature (and `satld` keeps building) while the daemon side is written.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredBackend;

impl UnwiredBackend {
    /// The error every method of this backend returns.
    fn unwired<T>() -> Result<T> {
        Err(BackendError::not_implemented("daemon wiring pending"))
    }
}

#[async_trait]
impl Backend for UnwiredBackend {
    async fn create_container(&self, _options: CreateContainerOptions) -> Result<CreatedContainer> {
        Self::unwired()
    }

    async fn start_container(&self, _id: &str) -> Result<ChangeOutcome> {
        Self::unwired()
    }

    async fn stop_container(&self, _id: &str, _timeout: Option<Duration>) -> Result<ChangeOutcome> {
        Self::unwired()
    }

    async fn kill_container(&self, _id: &str, _signal: &str) -> Result<()> {
        Self::unwired()
    }

    async fn remove_container(&self, _id: &str, _force: bool, _remove_volumes: bool) -> Result<()> {
        Self::unwired()
    }

    async fn list_containers(&self, _all: bool) -> Result<Vec<ContainerSummary>> {
        Self::unwired()
    }

    async fn inspect_container(&self, _id: &str) -> Result<ContainerInspect> {
        Self::unwired()
    }

    async fn wait_container(&self, _id: &str, _condition: WaitCondition) -> Result<WaitResult> {
        Self::unwired()
    }

    async fn container_logs(
        &self,
        _id: &str,
        _options: LogOptions,
    ) -> Result<BoxStream<'static, LogFrame>> {
        Self::unwired()
    }

    async fn pull_image(
        &self,
        _reference: &str,
        _auth: Option<RegistryAuth>,
        _platform: Option<Platform>,
    ) -> Result<BoxStream<'static, PullProgressLine>> {
        Self::unwired()
    }

    async fn list_images(&self) -> Result<Vec<ImageSummary>> {
        Self::unwired()
    }

    async fn tag_image(&self, _source: &str, _target: &str) -> Result<()> {
        Self::unwired()
    }

    async fn prune_containers(&self) -> Result<PrunedContainers> {
        Self::unwired()
    }

    async fn prune_images(&self, _all: bool) -> Result<PrunedImages> {
        Self::unwired()
    }

    async fn prune_networks(&self) -> Result<PrunedNetworks> {
        Self::unwired()
    }

    async fn prune_volumes(&self) -> Result<PrunedVolumes> {
        Self::unwired()
    }

    async fn create_exec(&self, _container: &str, _config: ExecConfig) -> Result<ExecId> {
        Self::unwired()
    }

    async fn start_exec(&self, _exec_id: &str) -> Result<ExecStream> {
        Self::unwired()
    }

    async fn inspect_exec(&self, _exec_id: &str) -> Result<ExecInspect> {
        Self::unwired()
    }

    async fn create_volume(&self, _options: CreateVolumeOptions) -> Result<VolumeInfo> {
        Self::unwired()
    }

    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>> {
        Self::unwired()
    }

    async fn remove_volume(&self, _name: &str, _force: bool) -> Result<()> {
        Self::unwired()
    }

    async fn list_networks(&self) -> Result<Vec<NetworkSummary>> {
        Self::unwired()
    }

    async fn inspect_network(&self, _id_or_name: &str) -> Result<NetworkDetail> {
        Self::unwired()
    }

    async fn create_network(&self, _options: CreateNetworkOptions) -> Result<NetworkCreated> {
        Self::unwired()
    }

    async fn remove_network(&self, _id_or_name: &str) -> Result<()> {
        Self::unwired()
    }

    async fn connect_network(
        &self,
        _id_or_name: &str,
        _options: NetworkConnectOptions,
    ) -> Result<()> {
        Self::unwired()
    }

    async fn disconnect_network(
        &self,
        _id_or_name: &str,
        _options: NetworkDisconnectOptions,
    ) -> Result<()> {
        Self::unwired()
    }

    async fn events(&self, _since: Option<SystemTime>) -> Result<BoxStream<'static, EventMessage>> {
        Self::unwired()
    }

    /// The one method that answers: `GET /info` must stay usable on a daemon
    /// whose backend is not wired yet, and "no containers, no images" is the
    /// truthful answer in that state (it is also exactly what M0 served).
    async fn system_counts(&self) -> Result<Counts> {
        Ok(Counts::default())
    }

    async fn swarm_init(&self, _options: SwarmInitOptions) -> Result<SwarmInitResult> {
        Self::unwired()
    }

    async fn swarm_join(&self, _options: SwarmJoinOptions) -> Result<()> {
        Self::unwired()
    }

    async fn swarm_leave(&self, _force: bool) -> Result<()> {
        Self::unwired()
    }

    async fn swarm_inspect(&self) -> Result<SwarmDetail> {
        Self::unwired()
    }

    async fn swarm_rotate_token(&self, _role: TokenRole) -> Result<SwarmDetail> {
        Self::unwired()
    }

    async fn swarm_set_autolock(&self, _enabled: bool) -> Result<SwarmDetail> {
        Self::unwired()
    }

    async fn swarm_unlock_key(&self) -> Result<String> {
        Self::unwired()
    }

    async fn swarm_rotate_unlock_key(&self) -> Result<SwarmDetail> {
        Self::unwired()
    }

    async fn swarm_rotate_ca(&self, _force_rotate: u64) -> Result<SwarmDetail> {
        Self::unwired()
    }

    /// Deliberately `NotImplemented`: `GET /info` reads that as "no live
    /// cluster state yet" and serves the static `Swarm` section instead of
    /// failing (see [`Backend::swarm_status`]).
    async fn swarm_status(&self) -> Result<SwarmStatus> {
        Self::unwired()
    }

    async fn list_nodes(&self) -> Result<Vec<NodeSummary>> {
        Self::unwired()
    }

    async fn inspect_node(&self, _id_or_name: &str) -> Result<NodeDetail> {
        Self::unwired()
    }

    async fn update_node(&self, _id: &str, _version: Version, _spec: NodeSpecUpdate) -> Result<()> {
        Self::unwired()
    }

    async fn remove_node(&self, _id: &str, _force: bool) -> Result<()> {
        Self::unwired()
    }

    async fn create_service(&self, _options: ServiceCreateOptions) -> Result<ServiceCreated> {
        Self::unwired()
    }

    async fn list_services(&self) -> Result<Vec<ServiceSummary>> {
        Self::unwired()
    }

    async fn inspect_service(&self, _id_or_name: &str) -> Result<ServiceDetail> {
        Self::unwired()
    }

    async fn update_service(
        &self,
        _id: &str,
        _version: Version,
        _options: ServiceUpdateOptions,
    ) -> Result<Vec<String>> {
        Self::unwired()
    }

    async fn remove_service(&self, _id_or_name: &str) -> Result<()> {
        Self::unwired()
    }

    async fn list_tasks(&self, _filters: TaskFilters) -> Result<Vec<TaskSummary>> {
        Self::unwired()
    }

    async fn inspect_task(&self, _id: &str) -> Result<TaskDetail> {
        Self::unwired()
    }

    async fn create_secret(&self, _spec: satl_core::SecretSpec) -> Result<SecretCreated> {
        Self::unwired()
    }

    async fn list_secrets(&self) -> Result<Vec<satl_core::Secret>> {
        Self::unwired()
    }

    async fn inspect_secret(&self, _id_or_name: &str) -> Result<satl_core::Secret> {
        Self::unwired()
    }

    async fn remove_secret(&self, _id_or_name: &str) -> Result<()> {
        Self::unwired()
    }

    async fn create_config(&self, _spec: satl_core::ConfigSpec) -> Result<ConfigCreated> {
        Self::unwired()
    }

    async fn list_configs(&self) -> Result<Vec<satl_core::Config>> {
        Self::unwired()
    }

    async fn inspect_config(&self, _id_or_name: &str) -> Result<satl_core::Config> {
        Self::unwired()
    }

    async fn remove_config(&self, _id_or_name: &str) -> Result<()> {
        Self::unwired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unwired_backend_reports_not_implemented() {
        let backend = UnwiredBackend;
        let err = backend.list_images().await.unwrap_err();
        assert_eq!(
            err,
            BackendError::NotImplemented("daemon wiring pending".to_owned())
        );
        assert_eq!(err.to_string(), "daemon wiring pending");
    }
}
