// SPDX-License-Identifier: BSD-2-Clause
//! [`Executor`] — the node-local subsystems a task controller drives
//! (SWK §15.1's `Executor`, architecture §8.2).
//!
//! It owns nothing policy-shaped: it is the bag of already-constructed
//! subsystems (`satld` wires them at startup, after the ZFS preflight and the
//! host-fact probes), the directory layout, and the host facts that decide
//! platform selection and rctl enforcement. Every decision lives in
//! [`crate::controller`] and [`crate::do_step`].
//!
//! Directory layout under the state dir (architecture §15, pinned M1
//! contracts):
//!
//! ```text
//! <state_dir>/bundles/<task_id>/config.json   OCI bundle written per task
//! <state_dir>/bundles/<task_id>/pid           ocijail --pid-file
//! <state_dir>/logs/<task_id>/stdout.log       raw container stdout
//! <state_dir>/logs/<task_id>/stderr.log       raw container stderr
//! <state_dir>/health/<task_id>/probe.pid      healthcheck probe pid file
//! <state_dir>/health/<task_id>/probe.out      last healthcheck probe output
//! <state_dir>/worker/tasks/<task_id>          local task DB (crate::db)
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use satl_image::{ImageStore, PlatformPolicy};
use satl_net::NetworkManager;
use satl_runtime::{Jails, OcijailRuntime};
use satl_storage::{ContainerFsStore, LayerStore, VolumeStore, Zfs};

use crate::controller::Controller;
use crate::health::HealthRegistry;
use crate::rctl::Rctl;

/// Self-reported facts that change how tasks are prepared (architecture
/// §8.3). `satld` probes these once at startup and feeds the same values into
/// the node description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFacts {
    /// `linux.ko` and friends are loaded, so `linux/*` images may be selected
    /// and run under the linuxulator (docs/linuxulator.md).
    pub linux_emulation: bool,
    /// `kern.racct.enable=1`, so rctl(8) rules are actually installed
    /// (architecture §8.3).
    pub racct_enabled: bool,
}

/// The ZFS dataset names the executor works with (architecture §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datasets {
    /// The root SatL dataset all the others are children of, e.g. `zroot/satl`.
    /// The layer GC reads clone origins across the whole tree from here.
    pub root: String,
    /// Layer chains, e.g. `zroot/satl/layers`.
    pub layers_root: String,
    /// Container writable layers, e.g. `zroot/satl/containers`.
    pub containers_root: String,
    /// Named node-local volumes, e.g. `zroot/satl/volumes`. Here because
    /// `satl system prune` has to measure a volume's dataset before destroying
    /// it, and deriving the name a second time is how the two drift apart.
    pub volumes_root: String,
}

/// Pre-built subsystems handed to [`Executor::new`]. `satld` constructs each
/// one (they all need configuration this crate has no opinion about) and
/// transfers ownership here.
pub struct ExecutorParts {
    /// Image content + metadata store.
    pub images: ImageStore,
    /// ZFS layer store.
    pub layers: LayerStore,
    /// Per-task writable rootfs clones.
    pub container_fs: ContainerFsStore,
    /// Named local volumes.
    pub volumes: VolumeStore,
    /// Raw zfs(8) wrapper, used to adopt an existing container dataset on a
    /// re-entrant `prepare` (the stores themselves are write paths).
    pub zfs: Zfs,
    /// Node-local networking (bridge, epairs, pf anchors).
    ///
    /// Shared rather than owned: the daemon's overlay programmer drives the
    /// *same* manager — it hosts every overlay segment's bridge and epairs —
    /// and two instances would keep two copies of the IPAM and published-port
    /// bookkeeping this type carries in process.
    pub network: Arc<NetworkManager>,
    /// The ocijail-backed runtime.
    pub runtime: OcijailRuntime,
    /// `jls`(8) wrapper: the only observer of a prison that `ocijail delete`
    /// has already forgotten but the kernel has not finished destroying
    /// (`docs/jail-teardown.md`).
    pub jails: Jails,
    /// rctl(8) wrapper, already told whether racct is enabled.
    pub rctl: Rctl,
    /// Node state directory (`/var/db/satl` in production).
    pub state_dir: PathBuf,
    /// Dataset names.
    pub datasets: Datasets,
    /// Host facts.
    pub host: HostFacts,
    /// The node's overlay plumbing ([`crate::overlay::TaskOverlay`]), or
    /// `None` on a daemon that programs no overlay — the M1 path, and every
    /// unit and integration test in this crate.
    pub overlay: Option<Arc<dyn crate::overlay::TaskOverlay>>,
    /// The in-memory secret/config set the dispatcher session feeds
    /// ([`crate::deps`]). Shared with the daemon's session sink: the same
    /// store the assignment stream writes is the one task controllers read
    /// when they materialize payloads (invariant #7).
    pub dependencies: Arc<crate::deps::DependencyStore>,
}

/// The node-local execution environment shared by every task controller.
pub struct Executor {
    images: ImageStore,
    layers: LayerStore,
    container_fs: ContainerFsStore,
    volumes: VolumeStore,
    zfs: Zfs,
    network: Arc<NetworkManager>,
    runtime: OcijailRuntime,
    jails: Jails,
    rctl: Rctl,
    state_dir: PathBuf,
    datasets: Datasets,
    host: HostFacts,
    overlay: Option<Arc<dyn crate::overlay::TaskOverlay>>,
    dependencies: Arc<crate::deps::DependencyStore>,
    /// Per-task health, node-local and ephemeral (invariant #1). Created here
    /// rather than passed in: nothing outside this crate produces health, and
    /// the daemon only ever reads it back through [`Executor::health`].
    health: Arc<HealthRegistry>,
}

impl std::fmt::Debug for Executor {
    /// Only the configuration is printable — the subsystems are handles to
    /// external state, not values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executor")
            .field("state_dir", &self.state_dir)
            .field("datasets", &self.datasets)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

impl Executor {
    /// Take ownership of the pre-built subsystems.
    #[must_use]
    pub fn new(parts: ExecutorParts) -> Self {
        Self {
            images: parts.images,
            layers: parts.layers,
            container_fs: parts.container_fs,
            volumes: parts.volumes,
            zfs: parts.zfs,
            network: parts.network,
            runtime: parts.runtime,
            jails: parts.jails,
            rctl: parts.rctl,
            state_dir: parts.state_dir,
            datasets: parts.datasets,
            host: parts.host,
            overlay: parts.overlay,
            dependencies: parts.dependencies,
            health: Arc::new(HealthRegistry::new()),
        }
    }

    /// The node's secret/config set (fed by the dispatcher session, read by
    /// task controllers when they materialize payloads).
    #[must_use]
    pub fn dependencies(&self) -> &Arc<crate::deps::DependencyStore> {
        &self.dependencies
    }

    /// A controller driving `task` (SWK §15.1 `Executor.Controller`).
    #[must_use]
    pub fn controller(self: &Arc<Self>, task: satl_core::Task) -> Controller {
        Controller::new(Arc::clone(self), task)
    }

    /// Host facts (also reported in the node description).
    #[must_use]
    pub fn host(&self) -> HostFacts {
        self.host
    }

    /// Platform selection policy for this node, with `explicit` taken from
    /// the container spec's resolved platform when the caller pinned one
    /// (architecture §9).
    #[must_use]
    pub fn platform_policy(&self, explicit: Option<&satl_core::Platform>) -> PlatformPolicy {
        let mut policy = PlatformPolicy::for_host(self.host.linux_emulation);
        // The node is FreeBSD by construction; be explicit rather than
        // trusting the build target of whatever binary linked this crate.
        "freebsd".clone_into(&mut policy.host_os);
        policy.explicit = explicit
            .map(|platform| satl_image::Platform::new(&platform.os, arch_alias(&platform.arch)));
        policy
    }

    /// The per-task OCI bundle directory.
    #[must_use]
    pub fn bundle_dir(&self, task_id: &str) -> PathBuf {
        self.state_dir.join("bundles").join(task_id)
    }

    /// The per-task log directory (`stdout.log`, `stderr.log`).
    #[must_use]
    pub fn log_dir(&self, task_id: &str) -> PathBuf {
        self.state_dir.join("logs").join(task_id)
    }

    /// The per-task healthcheck scratch directory (`probe.pid`, `probe.out`).
    #[must_use]
    pub fn health_dir(&self, task_id: &str) -> PathBuf {
        self.state_dir.join("health").join(task_id)
    }

    /// Per-task health as this node's probers observe it.
    ///
    /// The daemon's REST backend reads `State.Health` from here: health is
    /// node-local and never enters the store (invariant #1), exactly as
    /// `docker service ps` shows no health either.
    #[must_use]
    pub fn health(&self) -> &Arc<HealthRegistry> {
        &self.health
    }

    /// The node state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// The image content + metadata store.
    ///
    /// The subsystem accessors below are public because the daemon that
    /// *built* these subsystems needs them back for work that is not
    /// per-task: the REST backend pulls and lists images, manages volumes and
    /// runs `exec`; startup reconciliation sweeps orphaned jails, container
    /// datasets and epairs. Handing the executor a second instance instead
    /// would be wrong for the two subsystems that carry in-process state —
    /// [`ImageStore`]'s per-reference pull locks and [`NetworkManager`]'s
    /// IPAM plus published-port bookkeeping — so the executor lends out the
    /// ones it owns. They are read-only handles; the executor keeps
    /// ownership.
    #[must_use]
    pub fn images(&self) -> &ImageStore {
        &self.images
    }

    /// The ZFS layer store.
    #[must_use]
    pub fn layers(&self) -> &LayerStore {
        &self.layers
    }

    /// Per-task writable rootfs clones.
    #[must_use]
    pub fn container_fs(&self) -> &ContainerFsStore {
        &self.container_fs
    }

    /// Named local volumes.
    #[must_use]
    pub fn volumes(&self) -> &VolumeStore {
        &self.volumes
    }

    /// The raw zfs(8) wrapper.
    #[must_use]
    pub fn zfs(&self) -> &Zfs {
        &self.zfs
    }

    /// Node-local networking (bridge, epairs, pf anchors).
    #[must_use]
    pub fn network(&self) -> &NetworkManager {
        &self.network
    }

    /// The node's overlay plumbing, when the daemon wired one.
    ///
    /// `None` means this node programs no overlay, and every overlay step in
    /// [`crate::controller`] is then skipped.
    #[must_use]
    pub fn overlay(&self) -> Option<&Arc<dyn crate::overlay::TaskOverlay>> {
        self.overlay.as_ref()
    }

    /// The ocijail-backed runtime.
    #[must_use]
    pub fn runtime(&self) -> &OcijailRuntime {
        &self.runtime
    }

    /// The `jls`(8) wrapper. A container's rootfs cannot be destroyed while
    /// its prison is still dying, and this is what sees that
    /// (`docs/jail-teardown.md`).
    #[must_use]
    pub fn jails(&self) -> &Jails {
        &self.jails
    }

    /// The `rctl`(8) wrapper. The metrics collector reads per-jail usage
    /// through it; already told whether racct is enabled, so a racct-off node
    /// never spawns `rctl`.
    #[must_use]
    pub fn rctl(&self) -> &Rctl {
        &self.rctl
    }

    pub(crate) fn datasets(&self) -> &Datasets {
        &self.datasets
    }

    /// The ZFS dataset holding `task_id`'s writable layer.
    pub(crate) fn container_dataset(&self, task_id: &str) -> String {
        format!("{}/{task_id}", self.datasets.containers_root)
    }
}

/// Normalize an architecture name to the GOARCH spelling image indexes use.
fn arch_alias(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_aliases_map_to_goarch() {
        assert_eq!(arch_alias("x86_64"), "amd64");
        assert_eq!(arch_alias("aarch64"), "arm64");
        assert_eq!(arch_alias("amd64"), "amd64");
        assert_eq!(arch_alias("riscv64"), "riscv64");
    }
}
