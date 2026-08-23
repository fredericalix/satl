// SPDX-License-Identifier: BSD-2-Clause
//! `satld` — the SatL daemon. Wiring, config loading, rc.d entrypoint.
//!
//! M2 startup sequence (architecture §1.2, §7, §12, §15):
//!
//! ```text
//! parse CLI → load config → init tracing        (logging.rs)
//!   → storage preflight         ZFS is mandatory (invariant #5)
//!   → host facts                hostname, ncpu, physmem, os release
//!   → advertise address         configured, else the default route's address
//!   → node runtime              images, ZFS stores, network, ocijail, rctl,
//!                               executor, worker            (node.rs)
//!   → identity + cluster        certificate (load / init / join), Raft with
//!                               Dispatcher + NodeCA + Health registered,
//!                               NodeCA bootstrap listener, co-located
//!                               dispatcher socket, leader-only components,
//!                               the agent session, cert renewal
//!                                                (identity.rs, cluster.rs)
//!   → startup reconciliation    adopt survivors, sweep orphans (reconcile.rs)
//!   → REST API                  Docker Engine API on the unix socket
//!                                                          (backend.rs)
//!   → SIGTERM/SIGINT
//!   → stop serving → cluster runtime shutdown → Worker::shutdown()
//! ```
//!
//! Two ordering facts are load-bearing:
//!
//! - the **node runtime is built before the cluster**, because the cluster
//!   runtime starts the agent, and the agent needs the worker it drives;
//! - **reconciliation runs after the cluster is up but before the API
//!   answers**, so a client cannot ask about containers while the daemon is
//!   still deciding which of them survived.
//!
//! `Worker::shutdown` deliberately **leaves running jails alone**: a
//! container survives a daemon restart and is re-attached by the next
//! startup's reconciliation pass (architecture §7.2).

mod autolock;
mod backend;
mod channels;
mod cluster;
mod config;
mod guard;
mod hostinfo;
mod identity;
mod leadership;
mod logging;
mod metrics;
mod node;
mod overlay;
mod proxy;
mod reconcile;
mod rotation;
mod sysctl;
mod underlay;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use satl_core::{Id, StoreAction, StoreObject};
use satl_dispatcher::agent::SessionReporter;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

use crate::cluster::{Bringup, ClusterRuntime, ClusterSlot, ControlRequest};
use crate::config::{Config, ConfigSource};
use crate::logging::{LogFormat, LogTarget};

/// SatL daemon: Docker-compatible container engine and cluster orchestrator
/// for FreeBSD.
#[derive(Debug, Parser)]
#[command(name = "satld", version)]
struct Cli {
    /// Path to the daemon configuration file (a missing file means defaults).
    #[arg(long, value_name = "PATH", default_value = config::DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Log output format.
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    /// Where log lines go. `syslog` sends one datagram per event to the local
    /// syslogd and is what the rc.d service uses; `stdout` is for running the
    /// daemon in the foreground.
    #[arg(long, value_enum, value_name = "TARGET", default_value_t = LogTarget::Stdout)]
    log_target: LogTarget,

    /// Log level filter (the `RUST_LOG` environment variable wins when set).
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    /// Address the Prometheus `/metrics` endpoint binds (overrides
    /// `metrics_addr` in the config file; the endpoint is off when neither is
    /// set). Unauthenticated, like dockerd's — bind a private address.
    #[arg(long, value_name = "ADDR")]
    metrics_addr: Option<String>,

    /// Skip the ZFS storage preflight. Testing/development only.
    #[arg(long, hide = true)]
    skip_zfs_check: bool,
}

/// Run the hidden in-jail ARP helper and exit, if that is what this process was
/// started as.
///
/// **Nothing may happen before this**: no config load, no tracing init, no tokio
/// runtime. The child speaks a line protocol on stdin and stdout, so a single
/// line of log output on stdout would corrupt the response, and it calls
/// `jail_attach`(2), which it can never leave — so it must not have inherited a
/// runtime, a worker or an open state directory.
///
/// The contract is exactly two arguments (`<path to satld> __jail-arp`) and no
/// environment: everything, the jail included, travels in the request
/// (`satl_overlay::arphelper`). Matching on the exact argv rather than accepting
/// a prefix keeps a mistyped operator command from silently entering a jail.
///
/// It cannot be a `clap` subcommand: `Cli::parse` would have to run first, and
/// its own `--help`/error paths write to stdout.
fn is_jail_arp_helper() -> bool {
    let mut args = std::env::args_os().skip(1);
    let Some(subcommand) = args.next() else {
        return false;
    };
    subcommand == satl_overlay::HELPER_SUBCOMMAND && args.next().is_none()
}

fn main() -> anyhow::Result<()> {
    if is_jail_arp_helper() {
        // The helper must not fall through to the daemon's start-up under any
        // circumstances, and `main` returns `anyhow::Result<()>`, which cannot
        // carry an exit status — so it leaves here.
        std::process::exit(i32::from(satl_overlay::child_main()));
    }
    let cli = Cli::parse();

    // Config first (it decides nothing about logging today, but the startup
    // banner must show the effective config), tracing second; config errors
    // before tracing init go to stderr via anyhow.
    let default_node_name = hostinfo::hostname();
    let (cfg, source) = config::load(&cli.config, &default_node_name)?;

    logging::init(cli.log_format, cli.log_target, &cli.log_level);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?;
    let result = runtime.block_on(run(&cli, &cfg, source));

    // Every running container has a kqueue `NOTE_EXIT` watch parked on a
    // blocking thread, and those threads only return when the container dies
    // — which is exactly what must *not* happen at shutdown (architecture
    // §7.2: containers outlive the daemon and are re-attached at startup).
    // Dropping the runtime would wait for them forever, so give in-flight
    // blocking work a moment to finish and then abandon the rest; the process
    // is about to exit anyway, and everything with state of its own (Raft,
    // the task DB, the socket) has already been shut down inside `run`.
    runtime.shutdown_timeout(SHUTDOWN_GRACE);
    result
}

/// How long a stopping daemon waits for in-flight blocking work (zfs,
/// ifconfig, ocijail invocations) before abandoning the blocking pool.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Map Rust's arch names to Docker's (`x86_64` → `amd64`).
fn docker_arch(rust_arch: &str) -> &str {
    match rust_arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Compile-time build identity (filled from `SATL_GIT_COMMIT` /
/// `SATL_BUILD_TIME` when set at build time).
struct BuildIdentity {
    version: &'static str,
    git_commit: &'static str,
    build_time: &'static str,
}

/// Assemble the facts the REST API serves on `/version` and `/info`.
fn build_api_state(
    cfg: &Config,
    host: &hostinfo::HostInfo,
    build: &BuildIdentity,
    node_id: &satl_core::Id,
    advertise_addr: &str,
) -> satl_api::ApiState {
    let version_info = satl_api::VersionInfo {
        version: build.version.to_owned(),
        api_version: satl_api::API_VERSION.to_owned(),
        min_api_version: satl_api::MIN_API_VERSION.to_owned(),
        git_commit: build.git_commit.to_owned(),
        os: std::env::consts::OS.to_owned(),
        arch: docker_arch(std::env::consts::ARCH).to_owned(),
        kernel_version: host.os_release.clone(),
        build_time: build.build_time.to_owned(),
    };
    let system_info = satl_api::SystemInfo {
        id: node_id.to_string(),
        name: cfg.node_name.clone(),
        ncpu: i64::try_from(host.ncpu).unwrap_or(i64::MAX),
        mem_total: i64::try_from(host.physmem_bytes).unwrap_or(i64::MAX),
        operating_system: "FreeBSD".to_owned(),
        os_version: host.os_release.clone(),
        server_version: build.version.to_owned(),
    };
    // SatL auto-initializes a single-node cluster on first boot
    // (architecture §1.2), so the Swarm section is active from day one —
    // a deliberate deviation from Docker, recorded in docs/api-compat.md.
    // remote_managers stays null until the manager list is served.
    let swarm_info = satl_api::SwarmInfo {
        node_id: node_id.to_string(),
        node_addr: advertise_addr.to_owned(),
        local_node_state: "active".to_owned(),
        control_available: true,
        error: String::new(),
        remote_managers: None,
    };
    satl_api::ApiState::new(version_info, system_info, swarm_info)
}

/// The address peers are told to dial (architecture §7, config
/// `advertise_addr`).
///
/// Configured value wins; otherwise the IPv4 address of the interface
/// carrying the default route — the same interface `node.rs` NATs container
/// traffic out of, so the two agree on what "this host's network" means. A
/// node that cannot determine one still starts: the leader substitutes the
/// address it sees the node connect from (SWK §11.3).
async fn advertise_address(cfg: &Config) -> Option<String> {
    let detected = match cfg.advertise_addr {
        Some(_) => None,
        None => default_route_address().await,
    };
    let resolved = config::resolve_advertise_addr(
        cfg.advertise_addr.as_deref(),
        detected,
        cfg.listen_addr.port(),
    );
    if let Some(addr) = &resolved {
        tracing::info!(
            advertise_addr = %addr,
            configured = cfg.advertise_addr.is_some(),
            "advertise address resolved"
        );
    } else {
        tracing::warn!(
            "no advertise address: none configured and the default route has no usable address. \
             Peers will be told to dial whatever address the leader sees this node connect from; \
             set advertise_addr in satld.toml if that is wrong."
        );
    }
    resolved
}

/// The IPv4 address of the interface the default route uses.
async fn default_route_address() -> Option<std::net::IpAddr> {
    let iface = match satl_net::Route::system().default_egress_interface().await {
        Ok(Some(iface)) => iface,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "cannot read the default route while resolving the advertise address");
            return None;
        }
    };
    match satl_net::Ifconfig::system().get_inet(&iface).await {
        Ok(addrs) => addrs.into_iter().next().map(std::net::IpAddr::V4),
        Err(error) => {
            tracing::warn!(
                %iface,
                %error,
                "cannot read the address of the default-route interface"
            );
            None
        }
    }
}

/// The future the API server stops on: SIGTERM or SIGINT.
fn shutdown_signal() -> anyhow::Result<impl std::future::Future<Output = ()>> {
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;
    let mut sigint =
        signal(SignalKind::interrupt()).context("failed to register SIGINT handler")?;
    Ok(async move {
        tokio::select! {
            _ = sigterm.recv() => tracing::info!(signal = "SIGTERM", "shutdown signal received"),
            _ = sigint.recv() => tracing::info!(signal = "SIGINT", "shutdown signal received"),
        }
    })
}

/// How [`unlock_if_locked`] ended.
enum LockGate {
    /// No sealed DEK on disk: the normal boot path.
    NotLocked,
    /// The operator's key unsealed the DEK — carried in memory only.
    Unlocked(satl_cluster::Dek),
    /// The daemon is stopping while still locked.
    Shutdown,
}

/// The cluster half of startup: the autolock gate first (a sealed DEK means
/// the unlock-only API until the operator's key arrives), then the normal
/// bring-up with the DEK it produced, if any. `Ok(None)` is a daemon that
/// stopped while still locked.
async fn boot_cluster(
    cfg: &Config,
    shutdown: &CancellationToken,
    node_runtime: &Arc<node::NodeRuntime>,
    reporter: &Arc<SessionReporter>,
    describer: &Arc<HostDescriber>,
    slot: &Arc<ClusterSlot>,
) -> anyhow::Result<Option<ClusterRuntime>> {
    let dek = match unlock_if_locked(cfg, shutdown).await? {
        LockGate::NotLocked => None,
        LockGate::Unlocked(dek) => Some(dek),
        LockGate::Shutdown => return Ok(None),
    };
    let advertise = advertise_address(cfg).await;
    describer.set_data_addr(advertise.as_deref());
    let runtime = cluster::start(Bringup {
        cfg,
        node: node_runtime,
        reporter: Arc::clone(reporter),
        describer: Arc::clone(describer) as Arc<dyn satl_dispatcher::NodeDescriber>,
        advertise_addr: advertise,
        slot: Arc::clone(slot),
        shutdown: shutdown.clone(),
        dek,
    })
    .await
    .context("cluster bring-up failed")?;
    Ok(Some(runtime))
}

/// The autolock boot gate (SWK §12.4, Docker's "swarm is locked" state).
///
/// When the raft directory holds `dek.sealed` and no plain `dek`, the store
/// cannot be opened — so instead of the cluster, satld serves the
/// unlock-only API surface ([`satl_api::locked_router`]: `POST
/// /swarm/unlock`, `GET /_ping`, a 503 for everything else) on the API
/// socket and waits. A correct key unseals the DEK **in memory** — no plain
/// key file is ever written back — and the boot proceeds with it.
async fn unlock_if_locked(cfg: &Config, shutdown: &CancellationToken) -> anyhow::Result<LockGate> {
    let raft_dir = cfg.state_dir.join("raft");
    if !satl_cluster::is_locked(&raft_dir) {
        return Ok(LockGate::NotLocked);
    }
    tracing::warn!(
        socket = %cfg.socket_path.display(),
        "this manager's raft store is locked (autolock); serving only POST /swarm/unlock \
         until the unlock key is presented (`satl swarm unlock`)"
    );

    let accepted: Arc<std::sync::Mutex<Option<satl_cluster::Dek>>> =
        Arc::new(std::sync::Mutex::new(None));
    let ready = Arc::new(tokio::sync::Notify::new());
    let gate: satl_api::UnlockGate = {
        let sealed = raft_dir.join(satl_cluster::SEALED_DEK_FILE);
        let accepted = Arc::clone(&accepted);
        let ready = Arc::clone(&ready);
        Arc::new(move |key: &str| {
            let accepted_here = satl_cluster::kek_from_unlock_key(key)
                .ok()
                .and_then(|kek| satl_cluster::Dek::open_sealed(&kek, &sealed).ok());
            let Some(dek) = accepted_here else {
                tracing::warn!("an unlock attempt presented a key that does not open the store");
                return false;
            };
            // The first correct key wins; a second one is fine too and simply
            // has nothing left to deliver (the listener is already stopping).
            let mut slot = match accepted.lock() {
                Ok(slot) => slot,
                Err(poisoned) => poisoned.into_inner(),
            };
            let first = slot.replace(dek).is_none();
            drop(slot);
            if first {
                // Let the 200 response flush before the socket is torn down.
                let ready = Arc::clone(&ready);
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    ready.notify_one();
                });
            }
            true
        })
    };

    let listen = {
        let shutdown = shutdown.clone();
        let ready = Arc::clone(&ready);
        async move {
            tokio::select! {
                () = shutdown.cancelled() => {},
                () = ready.notified() => {},
            }
        }
    };
    satl_api::serve_unix(&cfg.socket_path, satl_api::locked_router(gate), listen)
        .await
        .with_context(|| {
            format!(
                "locked-mode API server failed on unix socket {}",
                cfg.socket_path.display()
            )
        })?;
    let dek = match accepted.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    match dek {
        Some(dek) => {
            tracing::info!("unlock key accepted; continuing the boot");
            Ok(LockGate::Unlocked(dek))
        }
        None => Ok(LockGate::Shutdown),
    }
}

/// This node's description, recomputed on every agent registration and every
/// 20 s refresh (architecture §8.3).
#[derive(Debug)]
struct HostDescriber {
    hostname: String,
    ncpu: i64,
    memory_bytes: i64,
    version: String,
    /// Live linuxulator availability: the same shared handle the executor
    /// reads, flipped by `reconcile::spawn_linux_probe`, so the next 20 s
    /// description refresh re-registers the session with the new value.
    linux: satl_agent::LinuxEmulation,
    /// `kern.racct.enable=1` (a boot tunable, probed once at startup).
    racct_enabled: bool,
    /// This node's underlay address (`NodeDescription::data_addr`), from the
    /// advertise address the current bring-up resolved.
    ///
    /// Interior-mutable because the describer outlives any one cluster: `swarm
    /// join` may bring the node up with a different advertise address
    /// ([`Daemon::join_config`]) and the description must then carry the new one,
    /// or peers keep programming a VXLAN tunnel to where this node used to be.
    data_addr: std::sync::RwLock<Option<String>>,
}

impl HostDescriber {
    /// Records the underlay address peers should tunnel to, from the resolved
    /// advertise address (`None` when this node has none).
    ///
    /// Called on every bring-up, before the agent can open a session.
    fn set_data_addr(&self, advertise_addr: Option<&str>) {
        let resolved = advertise_addr.and_then(underlay_addr);
        match (&resolved, advertise_addr) {
            (Some(addr), _) => tracing::info!(
                data_addr = %addr,
                "underlay address published to peers as this node's VXLAN endpoint"
            ),
            (None, Some(advertise)) => tracing::warn!(
                advertise_addr = advertise,
                "this node's advertise address is not an IP literal, so it reports no underlay \
                 address: peers will fall back to the address they see it connect from, which is \
                 the control-plane path. Set advertise_addr in satld.toml to this node's underlay \
                 address if overlay traffic goes nowhere."
            ),
            // `advertise_address` has already warned, actionably, that there is
            // none; a second warning saying the same thing is noise.
            (None, None) => tracing::debug!(
                "no advertise address, so this node reports no underlay address: peers will fall \
                 back to the address they see it connect from"
            ),
        }
        match self.data_addr.write() {
            Ok(mut slot) => *slot = resolved,
            // A poisoned lock means a panic while swapping addresses; the value
            // is a plain Option<String>, so recovering it beats describing this
            // node with a stale endpoint forever.
            Err(poisoned) => *poisoned.into_inner() = resolved,
        }
    }

    /// The recorded underlay address.
    fn data_addr(&self) -> Option<String> {
        match self.data_addr.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// The bare address inside an advertise address (`10.2.0.5:2377` →
/// `10.2.0.5`), or `None` when it names no IP literal.
///
/// A VXLAN tunnel endpoint is an address, never a name and never a port: the
/// UDP port belongs to the overlay (4789), not to the control plane. A
/// configured `advertise_addr` that is a hostname therefore yields nothing
/// rather than a `data_addr` peers cannot parse.
fn underlay_addr(advertise_addr: &str) -> Option<String> {
    let trimmed = advertise_addr.trim();
    if let Ok(addr) = trimmed.parse::<std::net::SocketAddr>() {
        return Some(addr.ip().to_string());
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    trimmed
        .rsplit_once(':')
        .and_then(|(host, _port)| host.parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
}

impl satl_dispatcher::NodeDescriber for HostDescriber {
    fn describe(&self) -> satl_core::NodeDescription {
        satl_core::NodeDescription {
            hostname: self.hostname.clone(),
            platform: satl_core::Platform {
                os: std::env::consts::OS.to_owned(),
                arch: docker_arch(std::env::consts::ARCH).to_owned(),
            },
            resources: satl_core::Resources {
                nano_cpus: self.ncpu.saturating_mul(1_000_000_000),
                memory_bytes: self.memory_bytes,
            },
            engine: satl_core::EngineDescription {
                version: self.version.clone(),
                labels: BTreeMap::new(),
            },
            linux_emulation: self.linux.get(),
            racct_enabled: self.racct_enabled,
            data_addr: self.data_addr(),
        }
    }
}

/// Everything a cluster bring-up needs that outlives any one cluster: the
/// node-local runtime, the agent's status queue, the node describer and the
/// daemon's own configuration and shutdown token.
struct Daemon {
    slot: Arc<ClusterSlot>,
    cfg: Config,
    node_runtime: Arc<node::NodeRuntime>,
    reporter: Arc<SessionReporter>,
    describer: Arc<HostDescriber>,
    shutdown: CancellationToken,
}

impl Daemon {
    /// A bring-up request against `cfg`, which may differ from the daemon's
    /// own when `swarm join` overrode the listen/advertise addresses.
    fn bringup<'a>(&'a self, cfg: &'a Config, advertise_addr: Option<String>) -> Bringup<'a> {
        // The description this node reports must carry the address of the
        // cluster it is about to belong to, not the previous one.
        self.describer.set_data_addr(advertise_addr.as_deref());
        Bringup {
            cfg,
            node: &self.node_runtime,
            reporter: Arc::clone(&self.reporter),
            describer: Arc::clone(&self.describer) as Arc<dyn satl_dispatcher::NodeDescriber>,
            advertise_addr,
            slot: Arc::clone(&self.slot),
            shutdown: self.shutdown.clone(),
            // A rebuild (join/leave/role change) never boots locked: those
            // paths wipe the raft directory first.
            dek: None,
        }
    }

    /// The configuration a join runs under: the daemon's, with the addresses
    /// the caller overrode.
    ///
    /// An unparseable `ListenAddr` is ignored rather than fatal — the request
    /// already passed the API's validation, and refusing a join over a
    /// cosmetic field would be worse than using the configured listener.
    fn join_config(&self, listen_addr: Option<&str>, advertise_addr: Option<String>) -> Config {
        let mut cfg = self.cfg.clone();
        match listen_addr.map(str::parse) {
            None => {}
            Some(Ok(addr)) => cfg.listen_addr = addr,
            Some(Err(error)) => tracing::warn!(
                listen_addr = listen_addr.unwrap_or_default(),
                %error,
                "ignoring an unusable ListenAddr; keeping the configured one"
            ),
        }
        if advertise_addr.is_some() {
            cfg.advertise_addr = advertise_addr;
        }
        cfg
    }

    /// Brings a fresh cluster runtime up on this node — after a leave, and
    /// after a failed join.
    async fn restart(&self) -> Option<ClusterRuntime> {
        let advertise = advertise_address(&self.cfg).await;
        match cluster::start(self.bringup(&self.cfg, advertise)).await {
            Ok(runtime) => Some(runtime),
            Err(error) => {
                tracing::error!(%error, "cannot re-initialize this node's cluster");
                None
            }
        }
    }
}

/// The cluster supervisor: owns the [`ClusterRuntime`] and rebuilds it when
/// `swarm join` or `swarm leave` asks for a different cluster.
///
/// It is a task rather than inline code in the REST handler because
/// replacing the runtime means stopping the very components a handler runs
/// on top of; doing it from a serialized owner keeps "one runtime at a time"
/// a structural property instead of a lock discipline.
async fn cluster_supervisor(
    mut runtime: ClusterRuntime,
    mut requests: tokio::sync::mpsc::Receiver<ControlRequest>,
    daemon: Daemon,
) -> Option<ClusterRuntime> {
    loop {
        let request = tokio::select! {
            biased;
            () = daemon.shutdown.cancelled() => return Some(runtime),
            request = requests.recv() => match request {
                Some(request) => request,
                None => return Some(runtime),
            },
        };
        let replacement = match request {
            ControlRequest::Join {
                remote_addrs,
                token,
                advertise_addr,
                listen_addr,
                availability,
                reply,
            } => {
                // Never log `token`.
                tracing::info!(
                    managers = ?remote_addrs,
                    ?availability,
                    "swarm join requested; stopping the current cluster runtime"
                );
                let cfg = daemon.join_config(listen_addr.as_deref(), advertise_addr);
                runtime.shutdown().await;
                let advertise = advertise_address(&cfg).await;
                let bringup = daemon.bringup(&cfg, advertise);
                match cluster::join(bringup, &remote_addrs, &token, availability).await {
                    Ok(joined) => {
                        let node_id = joined.core().node_id.clone();
                        tracing::info!(node_id = %node_id, "joined the cluster");
                        let _ = reply.send(Ok(node_id));
                        Some(joined)
                    }
                    Err(error) => {
                        // The node has no cluster left: its state was wiped or
                        // its old runtime stopped. Re-initialize so the daemon
                        // keeps answering rather than becoming an inert
                        // process the operator has to restart.
                        tracing::error!(%error, "swarm join failed; re-initializing this node");
                        let _ = reply.send(Err(format!("{error:#}")));
                        daemon.restart().await
                    }
                }
            }
            ControlRequest::Leave { force, reply } => {
                tracing::info!(force, "swarm leave requested");
                runtime.shutdown().await;
                if let Err(error) = cluster::reset(&daemon.cfg.state_dir) {
                    tracing::error!(%error, "cannot discard this node's cluster state");
                    let _ = reply.send(Err(format!("{error:#}")));
                    return None;
                }
                let fresh = daemon.restart().await;
                let _ = reply.send(if fresh.is_some() {
                    tracing::info!("left the cluster; a fresh single-node cluster was created");
                    Ok(())
                } else {
                    Err("this node could not re-initialize after leaving".to_owned())
                });
                fresh
            }
            ControlRequest::ApplyRole { role, managers } => {
                let node_id = runtime.core().node_id.clone();
                tracing::info!(
                    node_id = %node_id,
                    role = satl_ca::role_ou(role),
                    "applying a role change: rebuilding the cluster runtime, no daemon restart"
                );
                runtime.shutdown().await;
                apply_role_request(&daemon, &node_id, role, managers).await
            }
        };
        let Some(fresh) = replacement else {
            tracing::error!("this node has no cluster runtime left; satld must be restarted");
            return None;
        };
        daemon.slot.publish(fresh.core());
        runtime = fresh;
    }
}

/// The supervisor's `ApplyRole` arm, after the old runtime is down: rebuild
/// in the new role, or recover to *some* runtime rather than none.
async fn apply_role_request(
    daemon: &Daemon,
    node_id: &satl_core::Id,
    role: satl_core::NodeRole,
    managers: Vec<String>,
) -> Option<ClusterRuntime> {
    let advertise = advertise_address(&daemon.cfg).await;
    let bringup = daemon.bringup(&daemon.cfg, advertise);
    match cluster::apply_role(bringup, role, managers).await {
        Ok(rebuilt) => {
            tracing::info!(
                node_id = %node_id,
                role = satl_ca::role_ou(role),
                "role change applied; the runtime now serves the new role"
            );
            if role == satl_core::NodeRole::Manager
                && let Some(manager) = rebuilt.core().manager.as_ref()
            {
                // The rebuilt manager can now correct its own spec against
                // the store it just joined.
                publish_node_name(&manager.store, node_id, &daemon.cfg.node_name).await;
            }
            Some(rebuilt)
        }
        Err(error) => {
            // `apply_role` itself falls back to a worker runtime when a
            // promotion cannot join raft; reaching here means even that
            // failed. `cluster::start` resumes an interrupted promotion
            // rather than self-initializing, so it is safe as the last
            // resort.
            tracing::error!(
                %error,
                role = satl_ca::role_ou(role),
                "applying the role change failed; restarting the cluster runtime"
            );
            daemon.restart().await
        }
    }
}

/// Storage preflight: ZFS is mandatory (architecture invariant #5), so a
/// missing root dataset is a fatal, operator-actionable error.
async fn storage_preflight(cli: &Cli, cfg: &Config) -> anyhow::Result<()> {
    if cli.skip_zfs_check {
        tracing::warn!("--skip-zfs-check set: skipping ZFS storage preflight (tests/dev only)");
        return Ok(());
    }
    let zfs = satl_storage::Zfs::system();
    let state_dir = cfg.state_dir.display().to_string();
    match satl_storage::preflight(&zfs, &cfg.zfs_root, &state_dir).await {
        Ok(storage) => {
            if storage.root_mountpoint != cfg.state_dir {
                tracing::warn!(
                    root_mountpoint = %storage.root_mountpoint.display(),
                    state_dir = %cfg.state_dir.display(),
                    "zfs root dataset mountpoint differs from configured state_dir"
                );
            }
            Ok(())
        }
        Err(err) => {
            // Operator-actionable message to both tracing and stderr (anyhow
            // prints the chain to stderr on exit), exit code 1.
            tracing::error!(error = %err, "storage preflight failed");
            Err(anyhow::Error::new(err).context("storage preflight failed"))
        }
    }
}

/// The one line an operator reads first: what this build is and what
/// configuration it came up with.
fn startup_banner(cli: &Cli, cfg: &Config, source: ConfigSource, version: &str, git_commit: &str) {
    tracing::info!(
        version,
        git_commit,
        config_file = %cli.config.display(),
        config_source = match source {
            ConfigSource::File => "file",
            ConfigSource::Defaults => "defaults (config file absent)",
        },
        socket_path = %cfg.socket_path.display(),
        state_dir = %cfg.state_dir.display(),
        zfs_root = %cfg.zfs_root,
        node_name = %cfg.node_name,
        socket_group = %cfg.socket_group,
        pf_mode = cfg.pf_mode.as_str(),
        listen_addr = %cfg.listen_addr,
        ca_listen_addr = %cfg.ca_listen_addr(),
        advertise_addr = cfg
            .advertise_addr
            .as_deref()
            .unwrap_or("(from the default route)"),
        cert_validity_secs = cfg.effective_cert_validity().as_secs(),
        keyring_rotate_after_secs = cfg.keyring_rotate_after.as_secs(),
        keyring_phase_settle_secs = cfg.keyring_phase_settle.as_secs(),
        "starting satld"
    );
    if let Some(validity) = cfg.cert_validity
        && validity < satl_ca::MIN_CERT_VALIDITY
    {
        tracing::warn!(
            cert_validity_secs = validity.as_secs(),
            production_floor_secs = satl_ca::MIN_CERT_VALIDITY.as_secs(),
            "cert_validity is below one hour: node certificates will expire within minutes. \
             This is a TESTING knob for exercising certificate renewal; remove it from \
             satld.toml on any real cluster"
        );
    }
    if cfg.keyring_cadence() != satl_orchestrator::Cadence::default() {
        tracing::warn!(
            keyring_rotate_after_secs = cfg.keyring_rotate_after.as_secs(),
            keyring_phase_settle_secs = cfg.keyring_phase_settle.as_secs(),
            "the keyring cadence is not the production 12h/60s: encrypted networks will \
             rotate their data-plane keys within minutes. These are TESTING knobs for \
             exercising key rotation; remove them from satld.toml on any real cluster"
        );
    }
}

/// Seeds this node's `Node` object with the labels an operator configured and
/// the description the daemon probed, so `satl node ls` is useful before the
/// first agent session lands (the session refreshes it afterwards — SWK
/// §13.1 makes the dispatcher the writer of `Node.description`).
async fn publish_node_name(store: &satl_cluster::ClusterStore, node_id: &Id, node_name: &str) {
    let action = {
        let view = store.view();
        let Some(node) = view.node(node_id) else {
            // A joiner's node object is created by the CA on the leader and
            // arrives by replication; there is nothing to name yet.
            tracing::debug!(node_id = %node_id, "no Node object to name yet");
            return;
        };
        if node.spec.name.as_deref() == Some(node_name) {
            return;
        }
        let mut updated = (*node).clone();
        updated.spec.name = Some(node_name.to_owned());
        updated.meta.updated_at = std::time::SystemTime::now();
        StoreAction::Update(StoreObject::Node(updated))
    };
    match store.propose(vec![action]).await {
        Ok(_) => tracing::info!(node_id = %node_id, node_name, "node name published"),
        Err(error) => {
            tracing::warn!(node_id = %node_id, %error, "cannot publish the node name");
        }
    }
}

/// The effective metrics endpoint address: `--metrics-addr` wins over
/// `metrics_addr` in the config file, mirroring dockerd; `None` means off.
fn metrics_addr(cli: &Cli, cfg: &Config) -> anyhow::Result<Option<std::net::SocketAddr>> {
    match cli.metrics_addr.as_deref() {
        Some(addr) => addr
            .parse::<std::net::SocketAddr>()
            .map(Some)
            .with_context(|| format!("invalid --metrics-addr {addr:?} (expected host:port)")),
        None => Ok(cfg.metrics_addr),
    }
}

/// The facts behind `engine_daemon_engine_info` and the cpu/memory gauges,
/// assembled where the build identity, the host facts and the node id meet.
fn engine_facts(
    version: &str,
    git_commit: &str,
    host: &hostinfo::HostInfo,
    node_id: &satl_core::Id,
) -> crate::metrics::EngineFacts {
    crate::metrics::EngineFacts {
        labels: satl_metrics::EngineInfoLabels {
            version: version.to_owned(),
            commit: git_commit.to_owned(),
            architecture: docker_arch(std::env::consts::ARCH).to_owned(),
            // Docker's label name, SatL's one and only driver (invariant #5).
            graphdriver: "zfs".to_owned(),
            kernel: host.os_release.clone(),
            os: "FreeBSD".to_owned(),
            os_type: "freebsd".to_owned(),
            os_version: host.os_release.clone(),
            daemon_id: node_id.to_string(),
        },
        cpus: i64::try_from(host.ncpu).unwrap_or(i64::MAX),
        memory_bytes: i64::try_from(host.physmem_bytes).unwrap_or(i64::MAX),
    }
}

/// The periodic loops hung off the daemon's shutdown: the node-local safety
/// nets (a rootfs whose `remove` had to be deferred is reclaimed; the
/// `satl/rdr` anchor is re-derived from the live task set —
/// crates/satld/src/reconcile.rs) and, alongside them, the metrics collector
/// and endpoint. Node-local, so they hang off the daemon's shutdown rather
/// than any one cluster's.
fn spawn_sweeps(
    slot: &Arc<ClusterSlot>,
    node_runtime: &Arc<node::NodeRuntime>,
    sysctl: &sysctl::Sysctl,
    shutdown: &CancellationToken,
    metrics: satl_metrics::Metrics,
    metrics_addr: Option<std::net::SocketAddr>,
    facts: &crate::metrics::EngineFacts,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut sweeps: Vec<tokio::task::JoinHandle<()>> =
        reconcile::spawn_node_sweeps(slot, node_runtime, sysctl.clone(), shutdown).into();
    sweeps.extend(crate::metrics::spawn(
        metrics,
        metrics_addr,
        facts,
        Arc::clone(slot),
        Arc::clone(node_runtime),
        shutdown.clone(),
    ));
    sweeps
}

async fn run(cli: &Cli, cfg: &Config, source: ConfigSource) -> anyhow::Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let git_commit = option_env!("SATL_GIT_COMMIT").unwrap_or("unknown");
    let build_time = option_env!("SATL_BUILD_TIME").unwrap_or("unknown");

    startup_banner(cli, cfg, source, version, git_commit);

    // Metrics before anything that can fail a command: the runners count
    // into the global instance from the first zfs probe on. The endpoint
    // itself is off unless the operator picked an address (CLI wins over the
    // config file, mirroring dockerd's `--metrics-addr`).
    let metrics = satl_metrics::Metrics::new();
    // The daemon's own handle stays `metrics`; the returned one is the same
    // instance (satld is by construction the first installer).
    let _installed = metrics.install_global();
    let metrics_addr = metrics_addr(cli, cfg)?;

    storage_preflight(cli, cfg).await?;

    // Host facts for /version and /info.
    let sysctl = sysctl::Sysctl::system();
    let host = hostinfo::gather(&sysctl)
        .await
        .context("failed to gather host information")?;
    tracing::info!(
        hostname = %host.hostname,
        ncpu = host.ncpu,
        physmem_bytes = host.physmem_bytes,
        os_release = %host.os_release,
        "host information gathered"
    );

    // The node-local runtime, before the cluster: the cluster runtime starts
    // this node's agent, and the agent drives the worker built here. The
    // reporter is the agent's status queue — statuses now travel over the
    // dispatcher session, not straight into the store.
    //
    // The shutdown token is created here rather than after the runtime because
    // the overlay programmer owns the DNS responder's sockets, and those are
    // children of the daemon's shutdown, not of any one cluster's.
    let shutdown = CancellationToken::new();
    let reporter = SessionReporter::new();
    let node_runtime = Arc::new(
        node::build(cfg, &sysctl, Arc::clone(&reporter), shutdown.clone())
            .await
            .context("failed to build the node runtime")?,
    );
    let describer = Arc::new(HostDescriber {
        hostname: host.hostname.clone(),
        ncpu: i64::try_from(host.ncpu).unwrap_or(i64::MAX),
        memory_bytes: i64::try_from(host.physmem_bytes).unwrap_or(i64::MAX),
        version: version.to_owned(),
        linux: node_runtime.linux.clone(),
        racct_enabled: node_runtime.racct_enabled,
        data_addr: std::sync::RwLock::new(None),
    });

    // The slot exists before the first bring-up: the runtime's role watcher
    // holds it to ask for a rebuild, and the REST backend reads through it.
    let (slot, control) = ClusterSlot::new();

    // Identity, Raft (managers only), the internal gRPC surface, the
    // leader-only components and this node's agent session — behind the
    // autolock gate. `None` means the daemon stopped while still locked.
    let Some(runtime) =
        boot_cluster(cfg, &shutdown, &node_runtime, &reporter, &describer, &slot).await?
    else {
        return Ok(());
    };
    let core = runtime.core();
    let node_id = core.node_id.clone();
    let node_addr = core.advertise_addr.clone();

    reconcile_after_bringup(&core, &node_runtime, cfg).await;

    slot.publish(runtime.core());

    // Periodic sweeps + metrics collector/endpoint (spawn_sweeps). The engine
    // info needs the node id, which only exists once the cluster is up.
    let sweeps = spawn_sweeps(
        &slot,
        &node_runtime,
        &sysctl,
        &shutdown,
        metrics,
        metrics_addr,
        &engine_facts(version, git_commit, &host, &node_id),
    );
    let supervisor = tokio::spawn(cluster_supervisor(
        runtime,
        control,
        Daemon {
            slot: Arc::clone(&slot),
            cfg: cfg.clone(),
            node_runtime: Arc::clone(&node_runtime),
            reporter: Arc::clone(&reporter),
            describer: Arc::clone(&describer),
            shutdown: shutdown.clone(),
        },
    ));

    let build = BuildIdentity {
        version,
        git_commit,
        build_time,
    };
    let backend = Arc::new(backend::DaemonBackend::new(
        Arc::clone(&slot),
        &node_runtime,
    ));
    let router = satl_api::router(
        build_api_state(cfg, &host, &build, &node_id, &node_addr).with_backend(backend),
    );

    let serve_result = satl_api::serve_unix(&cfg.socket_path, router, shutdown_signal()?)
        .await
        .with_context(|| {
            format!(
                "REST API server failed on unix socket {}",
                cfg.socket_path.display()
            )
        });

    stop(&shutdown, supervisor, sweeps, &node_runtime, cfg).await;
    serve_result
}

/// Shutdown, in the only order that is safe: the API has already stopped
/// answering, so stop the cluster (loops, listeners, Raft) and only then the
/// task managers.
///
/// Running jails are deliberately left alone — they survive the restart and
/// Startup reconciliation before the API answers and before the agent's
/// first assignment lands: adopt what survived, destroy what leaked. On a
/// manager the claim set comes from the store; a worker has none — its
/// claims are the local task DB, and its overlay sweep waits for the first
/// assignment snapshot (the earliest complete claim set it can know).
async fn reconcile_after_bringup(
    core: &crate::cluster::ClusterCore,
    node_runtime: &node::NodeRuntime,
    cfg: &Config,
) {
    let node_id = &core.node_id;
    match core.manager.as_ref() {
        Some(manager) => {
            publish_node_name(&manager.store, node_id, &cfg.node_name).await;
            reconcile_startup(&manager.store, node_id, node_runtime).await;
        }
        None => reconcile_startup_worker(node_id, node_runtime).await,
    }
}

/// The startup pass, with its one-line verdict.
///
/// Anything it had to destroy is a leak some earlier run left behind, so it is
/// a warn and not an info: on a node that shut down cleanly this prints
/// nothing at all.
async fn reconcile_startup(
    store: &satl_cluster::ClusterStore,
    node_id: &satl_core::Id,
    node_runtime: &node::NodeRuntime,
) {
    let report = reconcile::run(store, node_id, node_runtime).await;
    report_reconcile(&report);
}

/// The worker variant: the same node-local sweeps, with the claim set read
/// from the local task DB instead of a store this node does not hold.
async fn reconcile_startup_worker(node_id: &satl_core::Id, node_runtime: &node::NodeRuntime) {
    let report = reconcile::run_worker(node_id, node_runtime).await;
    report_reconcile(&report);
}

fn report_reconcile(report: &reconcile::ReconcileReport) {
    if report.destroyed_anything() {
        tracing::warn!(
            jails = ?report.jails_destroyed,
            rctl_rules = ?report.rctl_rules_purged,
            datasets = ?report.datasets_destroyed,
            epairs = ?report.epairs_destroyed,
            overlay_epairs = ?report.overlay_epairs_destroyed,
            overlay_bridges = ?report.overlay_bridges_destroyed,
            vteps = ?report.vteps_destroyed,
            "startup reconciliation destroyed leaked resources"
        );
    }
}

/// Shutdown, in the only order that is safe: the API has already stopped
/// answering, so stop the cluster (loops, listeners, Raft) and only then the
/// task managers.
///
/// Running jails are deliberately left alone — they survive the restart and
/// are re-attached by the next reconciliation pass (architecture §7.2).
async fn stop(
    shutdown: &CancellationToken,
    supervisor: tokio::task::JoinHandle<Option<ClusterRuntime>>,
    sweeps: Vec<tokio::task::JoinHandle<()>>,
    node_runtime: &node::NodeRuntime,
    cfg: &Config,
) {
    shutdown.cancel();
    for sweep in sweeps {
        if let Err(error) = sweep.await {
            tracing::warn!(%error, "a periodic node sweep did not stop cleanly");
        }
    }
    match supervisor.await {
        Ok(Some(runtime)) => runtime.shutdown().await,
        Ok(None) => tracing::warn!("the cluster supervisor had already given up its runtime"),
        Err(error) => tracing::warn!(%error, "the cluster supervisor did not stop cleanly"),
    }
    node_runtime.worker.shutdown().await;
    tracing::info!("task managers stopped; running containers were left in place");

    // serve_unix removes the socket on clean shutdown (best-effort); make
    // sure it is really gone before we report a clean stop.
    match std::fs::remove_file(&cfg.socket_path) {
        Ok(()) => tracing::debug!(socket = %cfg.socket_path.display(), "removed socket file"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(
            socket = %cfg.socket_path.display(),
            error = %err,
            "failed to remove socket file on shutdown"
        ),
    }
    tracing::info!("satld stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_defaults() {
        let cli = Cli::parse_from(["satld"]);
        assert_eq!(cli.config, PathBuf::from("/usr/local/etc/satl/satld.toml"));
        assert_eq!(cli.log_format, LogFormat::Text);
        // A foreground `satld` logs to its own stdout; only the rc.d service
        // asks for syslog, and it does so explicitly.
        assert_eq!(cli.log_target, LogTarget::Stdout);
        assert_eq!(cli.log_level, "info");
        assert!(!cli.skip_zfs_check);
    }

    #[test]
    fn cli_accepts_json_log_format_and_hidden_skip_flag() {
        let cli = Cli::parse_from([
            "satld",
            "--log-format",
            "json",
            "--log-target",
            "syslog",
            "--log-level",
            "debug",
            "--skip-zfs-check",
            "--config",
            "/tmp/x.toml",
        ]);
        assert_eq!(cli.log_format, LogFormat::Json);
        assert_eq!(cli.log_target, LogTarget::Syslog);
        assert_eq!(cli.log_level, "debug");
        assert!(cli.skip_zfs_check);
        assert_eq!(cli.config, PathBuf::from("/tmp/x.toml"));
    }

    /// The VTEP is an address; the advertise address carries a port. A node that
    /// reported `10.2.0.5:2377` as its underlay address would have every peer
    /// program a tunnel to a socket, which is not a thing a VXLAN endpoint is.
    #[test]
    fn an_underlay_address_is_the_advertise_address_without_its_port() {
        assert_eq!(underlay_addr("10.2.0.5:2377").as_deref(), Some("10.2.0.5"));
        assert_eq!(underlay_addr("10.2.0.5").as_deref(), Some("10.2.0.5"));
        assert_eq!(
            underlay_addr("  10.2.0.5:2377 ").as_deref(),
            Some("10.2.0.5")
        );
        assert_eq!(underlay_addr("[fd00::1]:2377").as_deref(), Some("fd00::1"));
        // A name is not an endpoint: better none than one no peer can parse.
        assert_eq!(underlay_addr("node1.example:2377"), None);
        assert_eq!(underlay_addr(""), None);
    }

    #[test]
    fn docker_arch_mapping() {
        assert_eq!(docker_arch("x86_64"), "amd64");
        assert_eq!(docker_arch("aarch64"), "arm64");
        assert_eq!(docker_arch("riscv64"), "riscv64");
    }

    /// The description must read linuxulator availability live through the
    /// shared handle: the re-probe sweep flips it and the next 20 s refresh
    /// re-registers the session with the new value, no daemon restart.
    #[test]
    fn the_description_reads_linux_emulation_live() {
        use satl_dispatcher::NodeDescriber as _;
        let linux = satl_agent::LinuxEmulation::new(false);
        let describer = HostDescriber {
            hostname: "test".to_owned(),
            ncpu: 4,
            memory_bytes: 1024,
            version: "0.0.0".to_owned(),
            linux: linux.clone(),
            racct_enabled: false,
            data_addr: std::sync::RwLock::new(None),
        };
        assert!(!describer.describe().linux_emulation);
        linux.set(true);
        assert!(describer.describe().linux_emulation);
        linux.set(false);
        assert!(!describer.describe().linux_emulation);
    }
}

/// man/satld.8 is pinned to the clap surface. `Cli` is private to this
/// binary, so the check lives here rather than in an integration test.
/// Hand-written on purpose, no rewrite gate: see the rationale in
/// crates/satl-cli/tests/man_sync.rs.
#[cfg(test)]
mod man {
    use clap::CommandFactory as _;

    use super::Cli;

    fn page() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../man/satld.8");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
    }

    /// Every visible long flag must appear in the page in its mdoc
    /// spelling, `Fl \-log\-format` (the `Fl` macro contributes the first
    /// dash, the escaped `\-` the second).
    #[test]
    fn every_visible_flag_is_documented() {
        let page = page();
        let command = Cli::command();
        for arg in command.get_arguments() {
            if arg.is_hide_set() {
                continue; // --skip-zfs-check stays undocumented on purpose.
            }
            let Some(long) = arg.get_long() else { continue };
            if long == "help" || long == "version" {
                continue; // clap's own, not satld's surface.
            }
            let needle = format!("Fl \\-{}", long.replace('-', "\\-"));
            assert!(
                page.contains(&needle),
                "man/satld.8 does not document --{long}: expected the mdoc \
                 spelling {needle:?} somewhere in the page. Add the flag to \
                 the SYNOPSIS and the options list."
            );
        }
    }

    /// Every `Fl \-...` in the page names a real clap long. Hidden flags
    /// are allowed here: documenting --skip-zfs-check later would not fail.
    #[test]
    fn every_documented_flag_exists() {
        let command = Cli::command();
        let longs: Vec<String> = command
            .get_arguments()
            .filter_map(|arg| arg.get_long())
            .map(str::to_owned)
            .collect();
        for line in page().lines().filter(|line| line.starts_with('.')) {
            let mut words = line.split_whitespace().peekable();
            while let Some(word) = words.next() {
                if word != "Fl" {
                    continue;
                }
                let Some(flag) = words.peek().and_then(|next| next.strip_prefix("\\-")) else {
                    continue;
                };
                let name = flag.replace("\\-", "-");
                assert!(
                    longs.contains(&name),
                    "man/satld.8 documents --{name} (line {line:?}), which is \
                     not a flag satld has; fix the page or add the flag."
                );
            }
        }
    }
}
