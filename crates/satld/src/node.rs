// SPDX-License-Identifier: BSD-2-Clause
//! The node-local runtime: every subsystem a task controller drives, wired
//! from the daemon configuration (architecture §1.2 "every node, always",
//! §8.2).
//!
//! `satld` builds this once at startup, after the ZFS preflight and before
//! any reconciliation:
//!
//! ```text
//! Zfs ─┬─ LayerStore      <zfs_root>/layers
//!      ├─ ContainerFsStore <zfs_root>/containers
//!      └─ VolumeStore      <zfs_root>/volumes
//! ImageStore              <state_dir>/images
//! NetworkManager          network `satl` on bridge `satl0`, pf mode from config
//! OcijailRuntime          state db <state_dir>/ocijail, scratch <state_dir>/scratch
//! Rctl                    enforcing iff kern.racct.enable=1
//!            ▼
//!         Executor ──▶ Worker (TaskDb at <state_dir>/worker/tasks)
//! ```
//!
//! Two facts are probed here at startup, because both change how tasks are
//! prepared (architecture §8.3):
//!
//! - `linux_emulation`: whether `compat.linux.osrelease` answers, i.e.
//!   `linux.ko` is loaded — gates selecting `linux/*` images. Probed here at
//!   startup and re-probed every 10 s by `crate::reconcile::spawn_linux_probe`
//!   through the shared [`satl_agent::LinuxEmulation`] handle, so a
//!   `kldload linux` after startup takes effect without a daemon restart;
//! - `racct_enabled`: whether `kern.racct.enable=1` — a boot tunable, so it
//!   is probed once and never again; when it is off, rctl(8) rules cannot be
//!   installed, so `--memory`/`--cpus` are accepted and *degraded* with a
//!   prominent warning instead of failing.
//!
//! The SatL devfs ruleset is installed here too: it must exist before any
//! jail mounts `/dev` (docs/ocijail.md §2.3).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use satl_agent::{
    Datasets, DependencyStore, Executor, ExecutorParts, LinuxEmulation, Rctl, TaskDb, Worker,
};
use satl_dispatcher::agent::SessionReporter;
use satl_image::ImageStore;
use satl_net::{NetworkManager, NetworkManagerConfig, SubnetV4};
use satl_runtime::{Devfs, Jails, OcijailRuntime};
use satl_storage::{ContainerFsStore, LayerStore, VolumeStore, Zfs};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::sysctl::Sysctl;

/// The node's task executor and the facts the daemon gathered building it.
///
/// The [`Executor`] owns every node-local subsystem (it lends them back
/// through its accessors); this struct adds what only the daemon needs: the
/// worker, the probed host facts, and where the network manager keeps its
/// IPAM state, which the REST backend reads to answer `docker inspect`.
pub struct NodeRuntime {
    /// The task execution environment shared by every controller.
    pub executor: Arc<Executor>,
    /// The node's task set.
    pub worker: Arc<Worker<SessionReporter>>,
    /// The node's overlay programmer: VTEPs, overlay bridges, FDB and ARP
    /// entries, and the embedded DNS responder.
    ///
    /// Node-local like everything else here, and deliberately outside the
    /// cluster runtime: the interfaces belong to the host and survive a
    /// `swarm join`, which only tells the programmer that its identity changed
    /// (`crate::overlay::OverlayManager::adopt_identity`).
    pub overlay: Arc<crate::overlay::OverlayManager>,
    /// The local task database, which the agent re-reports from on every
    /// registration (architecture §7.2).
    pub task_db: TaskDb,
    /// Wakes the published-port sweep out of band.
    ///
    /// The sweep is level-triggered on a 5 s tick and only *forces* a
    /// re-assert every twelfth pass, so a change of role -- which swaps the
    /// whole derivation, store to local task db -- would otherwise take up to
    /// a minute to be reflected in `satl/rdr`. `satld` notifies this whenever
    /// it republishes the cluster core.
    pub port_sweep_kick: Arc<tokio::sync::Notify>,
    /// The L4 PROXY-protocol listeners (M6e), fed by the port sweep.
    pub proxy: std::sync::Arc<crate::proxy::ProxyManager>,
    /// Secrets and configs the assignment stream ships, read by task
    /// controllers when they build a bundle.
    pub dependencies: Arc<DependencyStore>,
    /// Dataset names (`<zfs_root>/layers`, `<zfs_root>/containers`).
    pub datasets: Datasets,
    /// Live linuxulator availability, shared with the executor and the node
    /// describer and flipped by `crate::reconcile::spawn_linux_probe`.
    pub linux: LinuxEmulation,
    /// `kern.racct.enable=1` (a boot tunable, probed once at startup).
    pub racct_enabled: bool,
    /// Node state directory.
    pub state_dir: PathBuf,
    /// Where `satl-net` keeps its IPAM state (read for container inspect).
    pub net_state_dir: PathBuf,
    /// The pool node-local networks are carved from.
    pub net_pool: SubnetV4,
    /// Name of the node-local bridge network containers attach to.
    pub network_name: String,
}

impl std::fmt::Debug for NodeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRuntime")
            .field("state_dir", &self.state_dir)
            .field("datasets", &self.datasets)
            .field("linux_emulation", &self.linux.get())
            .field("racct_enabled", &self.racct_enabled)
            .finish_non_exhaustive()
    }
}

impl NodeRuntime {
    /// The ocijail state database directory (`--root`).
    #[must_use]
    pub fn ocijail_root(state_dir: &std::path::Path) -> PathBuf {
        state_dir.join("ocijail")
    }
}

/// Probe `compat.linux.osrelease` silently: the oid only exists when
/// `linux.ko` is loaded (`satl_runtime::precheck::LINUX_PROBE_OID`).
///
/// Silent on purpose: `crate::reconcile::spawn_linux_probe` runs this every
/// 10 s and logs only transitions; [`build`] logs the startup result once at
/// its call site.
pub(crate) async fn probe_linux_emulation(sysctl: &Sysctl) -> bool {
    linux_osrelease(sysctl).await.is_ok()
}

/// The linuxulator's advertised osrelease, or the probe error.
async fn linux_osrelease(sysctl: &Sysctl) -> anyhow::Result<String> {
    sysctl.get(satl_runtime::precheck::LINUX_PROBE_OID).await
}

/// The interface container traffic is NAT-ed out of.
///
/// Configured `egress_if` wins; otherwise the interface of the host's default
/// route is used, which is right on every ordinary host and matches what an
/// operator would write by hand. Without one there is no `nat` rule at all and
/// containers cannot reach anything off-node, so failing to determine it is
/// worth a loud warning — but never a refusal to start: a node whose
/// containers only talk to each other is legitimate.
async fn egress_interface(cfg: &Config) -> Option<String> {
    if let Some(configured) = cfg.egress_if.clone() {
        tracing::info!(egress_if = %configured, "using the configured egress interface");
        return Some(configured);
    }
    match satl_net::Route::system().default_egress_interface().await {
        Ok(Some(iface)) => {
            tracing::info!(
                egress_if = %iface,
                "egress interface taken from the default route (set egress_if to override)"
            );
            Some(iface)
        }
        Ok(None) => {
            tracing::warn!(
                "no default route on this host: containers will have NO OUTBOUND \
                 connectivity because no NAT rule can be generated. Set egress_if in \
                 satld.toml if this node reaches other networks through a specific interface."
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "cannot determine the egress interface; containers will have no outbound \
                 connectivity. Set egress_if in satld.toml."
            );
            None
        }
    }
}

/// Probe `net.inet.ip.forwarding` and warn when container egress cannot work.
///
/// Without forwarding the bridge subnet is never routed to the egress
/// interface: pf's NAT rule matches nothing and containers have no outbound
/// connectivity — while inbound `rdr` to a task address still answers, which
/// makes the symptom look like a container problem rather than a host one
/// (`docs/networking.md`). Like the racct probe this only warns: a node that
/// runs containers with no outbound traffic is perfectly valid.
async fn probe_ip_forwarding(sysctl: &crate::sysctl::Sysctl) {
    match sysctl.get_u64("net.inet.ip.forwarding").await {
        Ok(1) => tracing::debug!("net.inet.ip.forwarding=1; container egress can be routed"),
        Ok(_) => tracing::warn!(
            "net.inet.ip.forwarding=0: containers will have NO OUTBOUND connectivity \
             (published ports still answer, which makes this easy to misdiagnose). \
             Run `sysrc gateway_enable=YES` and `sysctl net.inet.ip.forwarding=1`."
        ),
        Err(error) => tracing::warn!(
            %error,
            "cannot determine whether IP forwarding is enabled; container egress may not work"
        ),
    }
}

/// Probe pf's interface skip list and warn when `lo0` is skipped.
///
/// The lo0 half of published-port access (api-compat #35, measured in
/// `hack/experiments/lo0rdr`) is a `nat on lo0` plus an `rdr ... on lo0` per
/// pool: with `set skip on lo0` in `/etc/pf.conf` pf never consults either,
/// so localhost access to published ports cannot work while external access
/// still does — the same shape of easy misdiagnosis as the forwarding
/// sysctl above. Like the other probes this only warns; and when pf is
/// unavailable it stays quiet (the caller only runs it in enforce mode,
/// where an unusable pf already fails the anchor loads loudly).
async fn probe_lo0_skip() {
    match satl_net::PfCtl::system().interface_is_skipped("lo0").await {
        Ok(true) => tracing::warn!(
            "pf is set to 'skip on lo0': localhost access to published ports CANNOT \
             work (the lo0 nat and rdr rules are never consulted). Remove lo0 from \
             the 'set skip' line in /etc/pf.conf and reload the ruleset."
        ),
        Ok(false) => {
            tracing::debug!("pf does not skip lo0; published ports are reachable via localhost");
        }
        Err(error) => tracing::debug!(
            %error,
            "cannot read pf's interface skip list; skipping the lo0 probe"
        ),
    }
}

/// Probe `kern.racct.enable` and warn loudly when limits cannot be enforced
/// (architecture §8.3: degrade with an explicit log, never crash).
async fn probe_racct() -> bool {
    match satl_agent::racct_enabled(&satl_agent::SystemRunner).await {
        Ok(true) => {
            tracing::info!("kern.racct.enable=1; rctl(8) resource limits are enforced");
            true
        }
        Ok(false) => {
            tracing::warn!(
                "kern.racct.enable=0: rctl(8) rules cannot be installed, so --memory and \
                 --cpus are ACCEPTED BUT NOT ENFORCED. Add kern.racct.enable=1 to \
                 /boot/loader.conf and reboot to enable resource limits."
            );
            false
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "cannot determine whether racct is enabled; assuming it is off, so \
                 --memory and --cpus will be accepted but not enforced"
            );
            false
        }
    }
}

/// Install SatL's devfs ruleset, logging what had to change. A failure is not
/// fatal — it is reported here and again, per task, as a jail-create failure.
async fn install_devfs_ruleset() {
    match Devfs::system().ensure_ruleset().await {
        Ok(outcome) => tracing::info!(
            ruleset = satl_runtime::SATL_DEVFS_RULESET,
            ?outcome,
            "SatL devfs ruleset ready"
        ),
        Err(error) => tracing::error!(
            ruleset = satl_runtime::SATL_DEVFS_RULESET,
            %error,
            "could not install the SatL devfs ruleset; jails will fail to mount /dev \
             (satld must run as root)"
        ),
    }
}

/// Build the node-local runtime from `cfg`, reporting task status through
/// `reporter`.
///
/// The host network (bridge, gateway address, NAT anchor) is ensured here so
/// that a node with no tasks still owns a coherent network, and so the
/// failure is reported once at startup rather than on the first container.
pub async fn build(
    cfg: &Config,
    sysctl: &Sysctl,
    reporter: Arc<SessionReporter>,
    shutdown: CancellationToken,
) -> anyhow::Result<NodeRuntime> {
    let state_dir = cfg.state_dir.clone();
    let datasets = Datasets {
        root: cfg.zfs_root.clone(),
        layers_root: format!("{}/layers", cfg.zfs_root),
        containers_root: format!("{}/containers", cfg.zfs_root),
        volumes_root: format!("{}/volumes", cfg.zfs_root),
    };
    let net_state_dir = state_dir.join("net");

    install_devfs_ruleset().await;
    probe_ip_forwarding(sysctl).await;
    // Only where the anchors are actually loaded: in check/disabled mode no
    // published port redirects at all, so a warning about its lo0 half would
    // point at the wrong knob.
    if cfg.pf_mode.as_pf_mode() == satl_net::PfMode::Enforce {
        probe_lo0_skip().await;
    }
    // Startup probe, logged once here; the periodic re-probe
    // (`crate::reconcile::spawn_linux_probe`) then logs transitions only.
    let linux = LinuxEmulation::new(match linux_osrelease(sysctl).await {
        Ok(release) => {
            tracing::info!(
                osrelease = %release,
                "linuxulator available; linux/* images may be selected"
            );
            true
        }
        Err(error) => {
            tracing::info!(
                reason = %error,
                "linuxulator not available; only freebsd/* images can run (service linux start)"
            );
            false
        }
    });
    let racct_enabled = probe_racct().await;

    let images = ImageStore::open(state_dir.join("images")).with_context(|| {
        format!(
            "failed to open the image store at {}",
            state_dir.join("images").display()
        )
    })?;

    let network = NetworkManager::open(NetworkManagerConfig {
        network: cfg.network_name.clone(),
        bridge: cfg.bridge(),
        // The interface group is what `destroy_orphans` sweeps, so two
        // daemons on one host must never share it — hence it follows the
        // network name rather than being a constant.
        group: cfg.network_name.clone(),
        state_dir: net_state_dir.clone(),
        pool: cfg.network_pool,
        egress_if: egress_interface(cfg).await,
        pf_mode: cfg.pf_mode.as_pf_mode(),
    })
    .context("failed to open the node-local network manager")?;
    let host_network = network
        .ensure_host_network()
        .await
        .context("failed to bring up the node-local bridge network")?;
    tracing::info!(
        network = %cfg.network_name,
        bridge = %host_network.bridge,
        subnet = %host_network.subnet,
        gateway = %host_network.gateway,
        pf_mode = cfg.pf_mode.as_str(),
        "node-local network ready"
    );

    // The overlay programmer drives the *same* network manager: an overlay
    // network's bridge and its tasks' epairs are node-local plumbing, so
    // `satl-net` owns them, and two managers would keep two copies of the IPAM
    // and published-port bookkeeping it holds in process.
    let network = Arc::new(network);
    let overlay = crate::overlay::OverlayManager::new(
        cfg.network_name.clone(),
        cfg.overlay_blackhole,
        Arc::clone(&network),
        shutdown.clone(),
    )?;

    let ocijail_root = NodeRuntime::ocijail_root(&state_dir);
    let scratch_dir = state_dir.join("scratch");
    // One dependency store, shared between the session sink (which writes
    // it from the assignment stream) and the executor's task controllers
    // (which read it to materialize payloads — invariant #7).
    let dependencies = Arc::new(DependencyStore::new());
    let executor = Arc::new(Executor::new(ExecutorParts {
        images,
        layers: LayerStore::new(Zfs::system(), datasets.layers_root.clone()),
        container_fs: ContainerFsStore::new(Zfs::system(), datasets.containers_root.clone()),
        volumes: VolumeStore::new(Zfs::system(), datasets.volumes_root.clone()),
        zfs: Zfs::system(),
        network,
        runtime: OcijailRuntime::system(&ocijail_root, &scratch_dir),
        jails: Jails::system(),
        rctl: Rctl::system(racct_enabled),
        state_dir: state_dir.clone(),
        datasets: datasets.clone(),
        linux: linux.clone(),
        racct_enabled,
        overlay: Some(Arc::clone(&overlay) as Arc<dyn satl_agent::TaskOverlay>),
        dependencies: Arc::clone(&dependencies),
    }));

    let db = TaskDb::open(&state_dir).with_context(|| {
        format!(
            "failed to open the local task database under {}",
            state_dir.join("worker").join("tasks").display()
        )
    })?;
    let worker = Arc::new(Worker::new(Arc::clone(&executor), db.clone(), reporter));

    Ok(NodeRuntime {
        executor,
        worker,
        overlay,
        task_db: db,
        port_sweep_kick: Arc::new(tokio::sync::Notify::new()),
        dependencies,
        datasets,
        linux,
        racct_enabled,
        proxy: std::sync::Arc::new(crate::proxy::ProxyManager::new(shutdown)),
        net_state_dir,
        net_pool: cfg.network_pool,
        network_name: cfg.network_name.clone(),
        state_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ocijail_root_lives_under_the_state_dir() {
        assert_eq!(
            NodeRuntime::ocijail_root(std::path::Path::new("/var/db/satl")),
            PathBuf::from("/var/db/satl/ocijail")
        );
    }
}
