// SPDX-License-Identifier: BSD-2-Clause
//! `NetworkManager`: the node-local networking composition (architecture
//! §11.1).
//!
//! One instance per `satld` manages the default local bridge network:
//!
//! - [`NetworkManager::ensure_host_network`] — bridge exists, is grouped and
//!   described, carries the gateway address, is up; NAT rules are in
//!   `satl/nat` (idempotent, probe before create).
//! - [`NetworkManager::attach_task`] / [`NetworkManager::detach_task`] —
//!   epair plumbing into a task's VNET jail with full rollback on failure.
//! - [`NetworkManager::list_owned`] / [`NetworkManager::destroy_orphans`] —
//!   reconciliation building blocks for the startup pass (CLAUDE.md gotcha:
//!   epairs leak when teardown is interrupted).
//! - [`NetworkManager::publish_ports`] / [`NetworkManager::unpublish_ports`]
//!   / [`NetworkManager::reconcile_published_ports`] — full-ruleset
//!   regeneration of the `satl/rdr` anchor (see below).
//!
//! ## The `satl/rdr` anchor has two writers
//!
//! Port publishing is written from two sides, and the split is deliberate:
//!
//! - the **task controller** publishes a task's host-mode redirects the
//!   moment it starts the container. It is edge-triggered and it is the fast
//!   path: a container answers on its published port as soon as it is up.
//! - the **node's convergence pass** ([`NetworkManager::reconcile_published_ports`],
//!   driven by `satld`'s reconciler) recomputes what *every* live task on the
//!   node should publish, in both modes, from the replicated store. It is
//!   level-triggered and it is the truth: a missed edge, a leadership change
//!   or a restart is repaired by the next pass.
//!
//! Each task therefore has two slots ([`TaskRedirects`]) and each writer owns
//! one, so neither can erase the other's work and no ordering between them has
//! to hold. The anchor is `rdr_rules` over both slots of every task, and
//! duplicate redirects — the common case, since the pass recomputes exactly
//! what the controller published — collapse into one rule.
//!
//! ## Ownership markers
//!
//! Every interface SatL creates is tagged so reconciliation can find it:
//!
//! - interface group = the configured group (`satl` in production) on the
//!   bridge and the host-side epair end;
//! - description `<group>:<task-id>` on **both** epair ends and
//!   `<group>:network:<network>` on the bridge.
//!
//! The description is the load-bearing marker: it survives the `vnet` move
//! into the jail *and* the automatic return to the host when the jail dies,
//! while group membership does not (verified live on FreeBSD 15.1 —
//! see `crate::ifconfig` docs). Orphan scans therefore look at the group
//! *and* at every `epair`-group interface's description.
//!
//! The full marker grammar, with the overlay additions of M3
//! ([`crate::overlay`]), is one namespace so a single sweep understands
//! everything SatL puts on a host:
//!
//! | Description | Interface | Owner |
//! |---|---|---|
//! | `<group>:network:<net>` | node-local bridge | `satl-net` |
//! | `<group>:<task-id>` | epair ends of a local attachment | `satl-net` |
//! | `<group>:overlay:<net>` | an overlay network's bridge | `satl-net` |
//! | `<group>:overlay:<net>:<task-id>` | epair ends of an overlay attachment | `satl-net` |
//! | `<group>:vxlan:<net>` | the network's VTEP | **`satl-overlay`** |
//!
//! The last row is the one that matters for teardown: a VTEP carries a SatL
//! marker but belongs to another crate's lifecycle, so it is classified
//! ([`OwnedKind::Vtep`]) precisely so that nothing here ever destroys it.
//! Network names and task IDs contain no `:` (enforced for names by
//! [`crate::ipam`]'s validation, and IDs are base32), so the grammar parses
//! unambiguously.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::ifconfig::{EpairPair, Ifconfig, IfconfigError};
use crate::ipam::{DEFAULT_LOCAL_BRIDGE_POOL, IpamError, LocalIpam, SubnetV4};
use crate::pf::{
    ANCHOR_NAT, ANCHOR_RDR, MeshEgress, PfCtl, PfError, PoolKey, PortPublish, mesh_rules,
    nat_rules, pool_publishes, rdr_rules, table_name,
};
use crate::route::{Route, RouteError};
use crate::runner::{CommandRunner, SystemRunner};

/// How the manager applies pf rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PfMode {
    /// Syntax-check and load into the live `satl/*` anchors (production).
    #[default]
    Enforce,
    /// Syntax-check only (`pfctl -nf -`), never load — the only mode
    /// allowed on the shared dev host.
    CheckOnly,
    /// Generate rules and log them, never invoke pfctl (hosts without pf).
    Disabled,
}

/// Configuration of a [`NetworkManager`].
#[derive(Debug, Clone)]
pub struct NetworkManagerConfig {
    /// Network name (IPAM key), default `satl`.
    pub network: String,
    /// Bridge interface name, default `satl0`.
    pub bridge: String,
    /// Interface group and description prefix, default `satl`.
    pub group: String,
    /// Directory for IPAM state files.
    pub state_dir: PathBuf,
    /// Pool to carve network subnets from.
    pub pool: SubnetV4,
    /// Egress interface for outbound NAT; `None` disables NAT rules.
    pub egress_if: Option<String>,
    /// How pf rules are applied.
    pub pf_mode: PfMode,
}

impl Default for NetworkManagerConfig {
    fn default() -> Self {
        Self {
            network: "satl".to_owned(),
            bridge: "satl0".to_owned(),
            group: "satl".to_owned(),
            state_dir: PathBuf::from("/var/db/satl/net"),
            pool: DEFAULT_LOCAL_BRIDGE_POOL,
            egress_if: None,
            pf_mode: PfMode::default(),
        }
    }
}

/// The host side of an ensured local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetwork {
    /// Bridge interface name.
    pub bridge: String,
    /// The network's subnet.
    pub subnet: SubnetV4,
    /// Gateway address (assigned to the bridge).
    pub gateway: Ipv4Addr,
}

/// Result of attaching a task to the local network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAttachment {
    /// Host-side epair end (bridge member).
    pub epair_a: String,
    /// Jail-side epair end.
    pub epair_b: String,
    /// The task's address.
    pub ip: Ipv4Addr,
    /// The network gateway (bridge address).
    pub gateway: Ipv4Addr,
}

/// What an owned interface is, parsed from its description (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedKind {
    /// An epair end belonging to a task on the node-local bridge network
    /// (`<group>:<task-id>`).
    Task {
        /// The owning task.
        task_id: String,
    },
    /// A node-local bridge network (`<group>:network:<name>`).
    Network {
        /// The network name.
        network: String,
    },
    /// An overlay network's bridge on this node (`<group>:overlay:<name>`).
    OverlayNetwork {
        /// The network name.
        network: String,
    },
    /// An epair end of a task attached to an overlay network
    /// (`<group>:overlay:<name>:<task-id>`).
    OverlayTask {
        /// The overlay network.
        network: String,
        /// The owning task.
        task_id: String,
    },
    /// An overlay network's VTEP (`<group>:vxlan:<name>`).
    ///
    /// **Not this crate's to destroy**: `satl-overlay` creates and owns the
    /// vxlan interface, and `satl-net` only consumes its name as a bridge
    /// member. Classified so that every teardown path can recognise and skip
    /// it instead of seeing an unattributable SatL-marked interface.
    Vtep {
        /// The network the VTEP serves.
        network: String,
    },
}

/// Classify an interface description against the marker grammar (module docs).
/// `None` for anything that is not SatL's, including a `<group>:`-prefixed
/// marker this version does not understand — unknown markers are left alone,
/// never destroyed.
pub(crate) fn classify_marker(group: &str, descr: &str) -> Option<OwnedKind> {
    let rest = descr.strip_prefix(group)?.strip_prefix(':')?;
    if let Some(network) = rest.strip_prefix("network:") {
        return valid_segment(network).then(|| OwnedKind::Network {
            network: network.to_owned(),
        });
    }
    if let Some(network) = rest.strip_prefix("vxlan:") {
        return valid_segment(network).then(|| OwnedKind::Vtep {
            network: network.to_owned(),
        });
    }
    if let Some(tail) = rest.strip_prefix("overlay:") {
        return match tail.split_once(':') {
            None => valid_segment(tail).then(|| OwnedKind::OverlayNetwork {
                network: tail.to_owned(),
            }),
            Some((network, task_id)) => {
                (valid_segment(network) && valid_segment(task_id)).then(|| OwnedKind::OverlayTask {
                    network: network.to_owned(),
                    task_id: task_id.to_owned(),
                })
            }
        };
    }
    valid_segment(rest).then(|| OwnedKind::Task {
        task_id: rest.to_owned(),
    })
}

/// A marker segment: non-empty and free of the `:` the grammar separates on.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains(':')
}

/// An interface carrying SatL's ownership marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedIface {
    /// Interface name.
    pub name: String,
    /// Raw description text.
    pub descr: String,
    /// Parsed ownership.
    pub kind: OwnedKind,
}

/// The attach step that failed (for typed rollback errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachStep {
    /// IPAM allocation of the task address.
    AllocateAddress,
    /// `ifconfig epair create`.
    CreateEpair,
    /// Setting descriptions/group markers on the epair ends.
    TagInterfaces,
    /// Setting the derived MAC on the jail-side end (overlay only).
    SetMac,
    /// Setting the overlay MTU on both epair ends (overlay only).
    SetMtu,
    /// Adding the host end to the bridge.
    JoinBridge,
    /// Bringing the host end up.
    HostSideUp,
    /// Moving the jail end into the jail's vnet.
    MoveToJail,
    /// Assigning the task address inside the jail.
    AssignAddress,
    /// Bringing the jail-side interfaces up.
    BringUp,
    /// Installing the in-jail default route.
    DefaultRoute,
    /// Reading the plumbing back and finding it wrong (overlay only): the MTU,
    /// the derived MAC or the flags did not survive. `ifconfig` exit codes are
    /// not evidence (`crate::ifconfig` docs).
    Verify,
}

impl std::fmt::Display for AttachStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::AllocateAddress => "allocate-address",
            Self::CreateEpair => "create-epair",
            Self::TagInterfaces => "tag-interfaces",
            Self::SetMac => "set-mac",
            Self::SetMtu => "set-mtu",
            Self::JoinBridge => "join-bridge",
            Self::HostSideUp => "host-side-up",
            Self::MoveToJail => "move-to-jail",
            Self::AssignAddress => "assign-address",
            Self::BringUp => "bring-up",
            Self::DefaultRoute => "default-route",
            Self::Verify => "verify",
        };
        f.write_str(name)
    }
}

/// Error from the network manager.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Attaching a task failed; the partial plumbing was rolled back
    /// (epair destroyed, address released) unless `rolled_back` is false.
    #[error(
        "attaching task {task_id} to jail '{jail}' failed at step {step} \
         (rolled back: {rolled_back}): {source}"
    )]
    Attach {
        /// The task being attached.
        task_id: String,
        /// The target jail (name or jid).
        jail: String,
        /// The step that failed.
        step: AttachStep,
        /// Whether rollback fully succeeded.
        rolled_back: bool,
        /// The underlying failure.
        #[source]
        source: Box<NetError>,
    },

    /// An `ifconfig` operation failed.
    #[error(transparent)]
    Ifconfig(#[from] IfconfigError),

    /// A `route` operation failed.
    #[error(transparent)]
    Route(#[from] RouteError),

    /// A `pfctl` operation failed.
    #[error(transparent)]
    Pf(#[from] PfError),

    /// A local IPAM operation failed.
    #[error(transparent)]
    Ipam(#[from] IpamError),

    /// An overlay segment was misconfigured, unhealthy, or read back wrong.
    #[error(transparent)]
    Overlay(#[from] crate::overlay::OverlayError),
}

/// Node-local network manager. See the module docs.
///
/// Fields are `pub(crate)` so [`crate::overlay`] can compose the same
/// `ifconfig`/`route` wrappers and the same ownership-marker configuration:
/// the overlay segment of a network is more node-local plumbing, not a second
/// networking stack.
#[derive(Debug)]
pub struct NetworkManager<R = SystemRunner> {
    pub(crate) config: NetworkManagerConfig,
    pub(crate) ifconfig: Ifconfig<R>,
    pub(crate) route: Route<R>,
    pfctl: PfCtl<R>,
    ipam: Mutex<LocalIpam>,
    published: Mutex<BTreeMap<String, TaskRedirects>>,
    /// The last `satl/rdr` state handed to pf, under an async lock held
    /// across *both* the computation and the pfctl runs.
    ///
    /// Two jobs. It serialises anchor writes, so the ruleset loaded last is
    /// always the one computed last — without it two concurrent publishers can
    /// compute in one order and load in the other, leaving the anchor holding
    /// the older set. And it is what makes a periodic pass free: the anchor is
    /// only reloaded when the text changes, so a node whose tasks are steady
    /// runs no pfctl at all.
    rdr_applied: tokio::sync::Mutex<Option<RdrApplied>>,
    /// The mesh half of the anchor (M6d): set by the manager-side port sweep
    /// when this node has a gateway on the ingress network, `None` everywhere
    /// else. Stored rather than passed through every writer so the
    /// edge-triggered paths re-render the same ruleset the sweep computed.
    mesh: std::sync::Mutex<Option<MeshEgress>>,
}

/// What this manager believes the `satl/rdr` anchor holds, split the way pf
/// holds it (see [`NetworkManager::write_rdr`]): the static ruleset, and the
/// per-table membership behind each pool.
#[derive(Debug)]
struct RdrApplied {
    /// The anchor's ruleset text: table declarations plus the static rdr
    /// rules, a pure function of the pool *keys*.
    rules: String,
    /// Table name → membership last pushed with `-T replace` (sorted).
    membership: BTreeMap<String, Vec<std::net::Ipv4Addr>>,
}

/// The redirects one task contributes to `satl/rdr`, by writer.
///
/// Two slots because two writers reach this map from different directions and
/// with different completeness (see the module docs). Merging them into one
/// vector would mean the last writer wins, and the last writer is whichever
/// lost a race — the controller would drop the ingress redirects the pass had
/// computed, or the pass would drop a redirect for a task the store has not
/// caught up with.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaskRedirects {
    /// What the task's own controller published when it started the container:
    /// host-mode ports only, edge-triggered.
    pub started: Vec<PortPublish>,
    /// What the node's last convergence pass derived from the cluster store
    /// for this task: every publish mode, level-triggered.
    pub converged: Vec<PortPublish>,
}

impl TaskRedirects {
    /// Whether this task contributes no redirect at all (its entry can go).
    fn is_empty(&self) -> bool {
        self.started.is_empty() && self.converged.is_empty()
    }
}

/// What one [`NetworkManager::reconcile_published_ports`] pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortReconcile {
    /// Tasks publishing at least one port after the pass.
    pub tasks: usize,
    /// Redirects in the anchor after the pass (before pooling).
    pub redirects: usize,
    /// Whether the anchor's ruleset text changed (i.e. pf was reloaded).
    pub changed: bool,
}

impl NetworkManager<SystemRunner> {
    /// Manager running the real FreeBSD binaries.
    pub fn open(config: NetworkManagerConfig) -> Result<Self, NetError> {
        Self::with_runner(config, SystemRunner)
    }
}

impl<R: CommandRunner + Clone> NetworkManager<R> {
    /// Manager with an injected [`CommandRunner`] (test seam).
    pub fn with_runner(config: NetworkManagerConfig, runner: R) -> Result<Self, NetError> {
        let ipam = LocalIpam::open_with_pool(&config.state_dir, config.pool)?;
        Ok(Self {
            ifconfig: Ifconfig::with_runner(runner.clone()),
            route: Route::with_runner(runner.clone()),
            pfctl: PfCtl::with_runner(runner),
            ipam: Mutex::new(ipam),
            published: Mutex::new(BTreeMap::new()),
            rdr_applied: tokio::sync::Mutex::new(None),
            mesh: Mutex::new(None),
            config,
        })
    }
}

impl<R: CommandRunner> NetworkManager<R> {
    fn task_descr(&self, task_id: &str) -> String {
        format!("{}:{}", self.config.group, task_id)
    }

    fn network_descr(&self) -> String {
        format!("{}:network:{}", self.config.group, self.config.network)
    }

    /// Lock the IPAM state. A poisoned lock is recovered rather than
    /// propagated: [`LocalIpam`] keeps its file writes atomic, so the in-memory
    /// state a panicking thread left behind is still internally consistent.
    fn ipam(&self) -> std::sync::MutexGuard<'_, LocalIpam> {
        self.ipam
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn published(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, TaskRedirects>> {
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Apply a full anchor ruleset according to the configured [`PfMode`].
    async fn apply_pf(&self, anchor: &str, rules: &str) -> Result<(), NetError> {
        match self.config.pf_mode {
            PfMode::Disabled => {
                tracing::debug!(anchor = %anchor, rules = %rules.trim_end(), "pf disabled; rules not applied");
                Ok(())
            }
            PfMode::CheckOnly => {
                if !rules.is_empty() {
                    self.pfctl.check_syntax(rules).await?;
                }
                tracing::info!(anchor = %anchor, rules = %rules.trim_end(), "pf check-only; rules validated, not loaded");
                Ok(())
            }
            PfMode::Enforce => {
                if rules.is_empty() {
                    self.pfctl.flush_anchor(anchor).await?;
                } else {
                    self.pfctl.check_syntax(rules).await?;
                    self.pfctl.load_anchor(anchor, rules).await?;
                }
                Ok(())
            }
        }
    }

    /// Push one pool table's membership according to the configured
    /// [`PfMode`]. `pfctl -T` has no parse-only mode, so `CheckOnly` — which
    /// exists for hosts whose pf ruleset is managed elsewhere — has nothing
    /// to validate and, like `apply_pf`, loads nothing.
    async fn apply_table(
        &self,
        anchor: &str,
        table: &str,
        addrs: &[std::net::Ipv4Addr],
    ) -> Result<(), NetError> {
        match self.config.pf_mode {
            PfMode::Disabled => {}
            PfMode::CheckOnly => {
                tracing::debug!(anchor = %anchor, table = %table, members = addrs.len(), "pf check-only; table membership not pushed");
            }
            PfMode::Enforce => {
                self.pfctl.replace_table(anchor, table, addrs).await?;
            }
        }
        Ok(())
    }

    /// Destroy one pool table whose triple has gone, same mode gating as
    /// [`Self::apply_table`]. `persist` tables survive an anchor flush with
    /// their members, so a disappearing triple must kill its table
    /// explicitly or `-T show` keeps reporting a live pool.
    async fn apply_kill_table(&self, anchor: &str, table: &str) -> Result<(), NetError> {
        match self.config.pf_mode {
            PfMode::Disabled => {}
            PfMode::CheckOnly => {
                tracing::debug!(anchor = %anchor, table = %table, "pf check-only; table not killed");
            }
            PfMode::Enforce => {
                self.pfctl.kill_table(anchor, table).await?;
            }
        }
        Ok(())
    }

    /// Ensure the local network's host side exists and is configured:
    /// bridge (created if missing), group + description markers, gateway
    /// address, up, NAT rules in `satl/nat`. Idempotent.
    #[tracing::instrument(skip_all, fields(network = %self.config.network, bridge = %self.config.bridge))]
    pub async fn ensure_host_network(&self) -> Result<HostNetwork, NetError> {
        let bridge = self.config.bridge.clone();
        let subnet = self.ipam().ensure_network(&self.config.network)?;
        let gateway = subnet.gateway();

        if self.ifconfig.exists(&bridge).await? {
            // Repair markers if a previous run was interrupted. Description
            // writes are idempotent; group adds are not, so probe first.
            let descr = self.ifconfig.get_descr(&bridge).await?;
            if descr.as_deref() != Some(self.network_descr().as_str()) {
                self.ifconfig
                    .set_descr(&bridge, &self.network_descr())
                    .await?;
            }
            let members = self.ifconfig.list_group(&self.config.group).await?;
            if !members.iter().any(|m| m == &bridge) {
                self.ifconfig.set_group(&bridge, &self.config.group).await?;
            }
        } else {
            self.ifconfig.create_bridge(&bridge).await?;
            self.ifconfig.set_group(&bridge, &self.config.group).await?;
            self.ifconfig
                .set_descr(&bridge, &self.network_descr())
                .await?;
        }

        let addresses = self.ifconfig.get_inet(&bridge).await?;
        if !addresses.contains(&gateway) {
            let cidr = format!("{gateway}/{}", subnet.prefix_len());
            self.ifconfig.add_inet(&bridge, &cidr).await?;
        }
        self.ifconfig.up(&bridge).await?;

        if let Some(egress) = self.config.egress_if.clone() {
            let rules = nat_rules(subnet, &egress);
            self.apply_pf(ANCHOR_NAT, &rules).await?;
        }

        tracing::info!(subnet = %subnet, gateway = %gateway, "host network ensured");
        Ok(HostNetwork {
            bridge,
            subnet,
            gateway,
        })
    }

    /// The failable plumbing after the epair exists; returns the failed
    /// step so `attach_task` can roll back.
    async fn plumb(
        &self,
        task_id: &str,
        jail: &str,
        pair: &EpairPair,
        ip: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> Result<(), (AttachStep, NetError)> {
        let (epair_a, epair_b) = (pair.a.as_str(), pair.b.as_str());
        let descr = self.task_descr(task_id);
        // Tag both ends: the description is what survives the vnet move and
        // the auto-return after jail death; the group marker only exists on
        // the host side.
        self.ifconfig
            .set_descr(epair_a, &descr)
            .await
            .map_err(|e| (AttachStep::TagInterfaces, e.into()))?;
        self.ifconfig
            .set_group(epair_a, &self.config.group)
            .await
            .map_err(|e| (AttachStep::TagInterfaces, e.into()))?;
        self.ifconfig
            .set_descr(epair_b, &descr)
            .await
            .map_err(|e| (AttachStep::TagInterfaces, e.into()))?;

        self.ifconfig
            .bridge_addm(&self.config.bridge, epair_a)
            .await
            .map_err(|e| (AttachStep::JoinBridge, e.into()))?;
        self.ifconfig
            .up(epair_a)
            .await
            .map_err(|e| (AttachStep::HostSideUp, e.into()))?;

        self.ifconfig
            .move_to_jail(epair_b, jail)
            .await
            .map_err(|e| (AttachStep::MoveToJail, e.into()))?;

        let cidr = format!("{ip}/{prefix_len}");
        self.ifconfig
            .jail_add_inet(jail, epair_b, &cidr)
            .await
            .map_err(|e| (AttachStep::AssignAddress, e.into()))?;

        self.ifconfig
            .jail_up(jail, epair_b)
            .await
            .map_err(|e| (AttachStep::BringUp, e.into()))?;
        self.ifconfig
            .jail_up(jail, "lo0")
            .await
            .map_err(|e| (AttachStep::BringUp, e.into()))?;

        self.route
            .add_default_in_jail(jail, gateway)
            .await
            .map_err(|e| (AttachStep::DefaultRoute, e.into()))?;
        Ok(())
    }

    /// Best-effort rollback of a failed attach: destroy the epair (either
    /// end may already be gone or in the jail — destroying one end destroys
    /// the pair) and release the task's address.
    async fn rollback_attach(&self, task_id: &str, epair_a: &str, epair_b: &str) -> bool {
        let mut ok = true;
        match self.ifconfig.destroy_if_exists(epair_a).await {
            Ok(true) => {}
            Ok(false) => {
                // Host end already gone; the jail end may have returned.
                if let Err(err) = self.ifconfig.destroy_if_exists(epair_b).await {
                    tracing::error!(iface = %epair_b, error = %err, "rollback: failed to destroy epair b end");
                    ok = false;
                }
            }
            Err(err) => {
                tracing::error!(iface = %epair_a, error = %err, "rollback: failed to destroy epair a end");
                ok = false;
            }
        }
        if let Err(err) = self.ipam().release(task_id) {
            tracing::error!(task_id = %task_id, error = %err, "rollback: failed to release address");
            ok = false;
        }
        ok
    }

    /// Attach `task_id`'s VNET jail (`jail` — name or jid) to the local
    /// network: allocate an address, create an epair, bridge the host end,
    /// move the other end into the jail, address it, bring it up, and
    /// install the default route.
    ///
    /// On failure at any step the partial plumbing is rolled back (epair
    /// destroyed, address released) and the returned [`NetError::Attach`]
    /// names the failed step.
    #[tracing::instrument(skip_all, fields(task_id = %task_id, jail = %jail))]
    pub async fn attach_task(&self, task_id: &str, jail: &str) -> Result<TaskAttachment, NetError> {
        let attach_err = |step: AttachStep, rolled_back: bool, source: NetError| NetError::Attach {
            task_id: task_id.to_owned(),
            jail: jail.to_owned(),
            step,
            rolled_back,
            source: Box::new(source),
        };

        // Step 1: address. Nothing to roll back on failure (allocation is
        // the transaction itself).
        let (ip, prefix_len, gateway) = {
            let mut ipam = self.ipam();
            let ip = ipam
                .allocate(&self.config.network, task_id)
                .map_err(|e| attach_err(AttachStep::AllocateAddress, true, e.into()))?;
            // Infallible: allocate() just ensured the network.
            let subnet = ipam
                .subnet(&self.config.network)
                .unwrap_or(self.config.pool);
            (ip, subnet.prefix_len(), subnet.gateway())
        };

        // Step 2: epair. Roll back the allocation on failure.
        let pair = match self.ifconfig.create_epair().await {
            Ok(pair) => pair,
            Err(err) => {
                let released = self.ipam().release(task_id).is_ok();
                return Err(attach_err(AttachStep::CreateEpair, released, err.into()));
            }
        };

        // Steps 3..: plumbing, with rollback.
        if let Err((step, source)) = self
            .plumb(task_id, jail, &pair, ip, prefix_len, gateway)
            .await
        {
            let rolled_back = self.rollback_attach(task_id, &pair.a, &pair.b).await;
            return Err(attach_err(step, rolled_back, source));
        }

        tracing::info!(
            epair_a = %pair.a,
            epair_b = %pair.b,
            ip = %ip,
            gateway = %gateway,
            "task attached to local network"
        );
        Ok(TaskAttachment {
            epair_a: pair.a,
            epair_b: pair.b,
            ip,
            gateway,
        })
    }

    /// Detach a task: destroy its epair and release its address. Handles
    /// both post-jail states (the `b` end still in the jail, or auto-
    /// returned to the host after jail death) — destroying either end
    /// destroys the pair. Idempotent: missing interfaces are fine.
    ///
    /// Also drops the task's published ports from the rdr set.
    #[tracing::instrument(skip_all, fields(task_id = %task_id, epair_a = %attachment.epair_a))]
    pub async fn detach_task(
        &self,
        task_id: &str,
        attachment: &TaskAttachment,
    ) -> Result<(), NetError> {
        let destroyed_a = self.ifconfig.destroy_if_exists(&attachment.epair_a).await?;
        if destroyed_a {
            tracing::info!(iface = %attachment.epair_a, "destroyed task epair");
        } else {
            // The a end is gone (interrupted teardown); the b end may have
            // auto-returned to the host when the jail died.
            let destroyed_b = self.ifconfig.destroy_if_exists(&attachment.epair_b).await?;
            tracing::info!(
                iface_a = %attachment.epair_a,
                iface_b = %attachment.epair_b,
                destroyed_b,
                "task epair a end already gone"
            );
        }
        self.ipam().release(task_id)?;
        self.unpublish_ports(task_id).await?;
        Ok(())
    }

    /// List every interface carrying SatL's ownership marker: members of the
    /// configured group plus every interface in the `epair`, `bridge` and
    /// `vxlan` **driver** groups, classified by description (module docs).
    ///
    /// The driver groups are what make this robust: a `b` end that
    /// auto-returned from a dead jail has lost the `satl` group but kept its
    /// description, a bridge whose group tagging was interrupted is still in
    /// `bridge`, and `satl-overlay`'s VTEPs are in `vxlan` — the sweep has to
    /// see them to know not to touch them.
    pub async fn list_owned(&self) -> Result<Vec<OwnedIface>, NetError> {
        let mut names: BTreeSet<String> = BTreeSet::new();
        names.extend(self.ifconfig.list_group(&self.config.group).await?);
        // The drivers put every interface they clone into an eponymous group;
        // an unknown group (module not loaded) prints nothing and exits 0.
        for driver in ["epair", "bridge", "vxlan"] {
            names.extend(self.ifconfig.list_group(driver).await?);
        }

        let mut owned = Vec::new();
        for name in names {
            let descr = match self.ifconfig.get_descr(&name).await {
                Ok(descr) => descr,
                // The interface can vanish between listing and probing
                // (task teardown racing reconciliation) — skip it.
                Err(IfconfigError::Failed { failure, .. })
                    if failure.stderr.contains("does not exist") =>
                {
                    continue;
                }
                Err(err) => return Err(err.into()),
            };
            let Some(descr) = descr else { continue };
            let Some(kind) = classify_marker(&self.config.group, &descr) else {
                continue;
            };
            owned.push(OwnedIface { name, descr, kind });
        }
        Ok(owned)
    }

    /// Destroy every owned **node-local** task interface whose task is not in
    /// `known_task_ids`, releasing the orphans' addresses too. Bridges
    /// (network markers) are never touched. Returns the destroyed interface
    /// names.
    ///
    /// This is the startup reconciliation building block for the epair-leak
    /// gotcha: interrupted teardowns leave `a` ends on the bridge and `b`
    /// ends that returned from dead jails.
    ///
    /// Overlay interfaces are **not** in scope: an overlay attachment's epairs
    /// are [`OwnedKind::OverlayTask`], their addresses come from cluster IPAM
    /// rather than this node's, and whether a task should still be attached is
    /// a per-network question. [`NetworkManager::sweep_overlay`] is their
    /// reconciler.
    #[tracing::instrument(skip_all)]
    pub async fn destroy_orphans(
        &self,
        known_task_ids: &BTreeSet<String>,
    ) -> Result<Vec<String>, NetError> {
        let mut destroyed = Vec::new();
        let mut released: BTreeSet<String> = BTreeSet::new();
        for iface in self.list_owned().await? {
            let OwnedKind::Task { task_id } = iface.kind else {
                continue;
            };
            if known_task_ids.contains(&task_id) {
                continue;
            }
            // Destroying the first end of a pair removes the second; the
            // second then shows up as already-gone (Ok(false)).
            if self.ifconfig.destroy_if_exists(&iface.name).await? {
                tracing::warn!(
                    iface = %iface.name,
                    task_id = %task_id,
                    "destroyed orphaned interface"
                );
                destroyed.push(iface.name);
            }
            if released.insert(task_id.clone()) {
                self.ipam().release(&task_id)?;
            }
        }
        Ok(destroyed)
    }

    /// Rewrite the published set and apply what changed, split the way pf
    /// holds it: the **static ruleset** is reloaded only when the *set* of
    /// published triples changes; **membership** moves through `-T replace`
    /// on the pool's table and never touches the ruleset.
    ///
    /// The one path through which the anchor is ever written. The async lock is
    /// held across the mutation *and* the pfctl runs, which is what makes
    /// concurrent writers safe: the state loaded last is always the one
    /// computed last. On a failed load the record of what is in the anchor is
    /// deliberately left untouched, so the next caller retries rather than
    /// believing the failed state is live.
    ///
    /// `force` re-asserts an unchanged ruleset *and* every table. What is
    /// remembered here is a belief about the kernel's anchor, not a reading of
    /// it — nothing stops an operator from flushing it or killing a table —
    /// so the periodic pass re-asserts from time to time and a hand-flushed
    /// anchor repairs itself.
    ///
    /// One ordering fact is load-bearing: **every anchor reload is followed
    /// by a full membership re-push.** The declared tables are `persist` but
    /// empty of inline addresses by construction, so a reload re-creates them
    /// empty; skipping the re-push would leave every published port dead
    /// until the next membership change happened by.
    async fn write_rdr<T>(
        &self,
        force: bool,
        mutate: impl FnOnce(&mut BTreeMap<String, TaskRedirects>) -> T,
    ) -> Result<(T, bool), NetError> {
        let mut applied = self.rdr_applied.lock().await;
        let (out, rules, membership) = {
            let mut published = self.published();
            let out = mutate(&mut published);
            published.retain(|_, redirects| !redirects.is_empty());
            let all: Vec<PortPublish> = published
                .values()
                .flat_map(|redirects| redirects.started.iter().chain(&redirects.converged))
                .cloned()
                .collect();
            let pools = pool_publishes(&all);
            let membership: BTreeMap<String, Vec<std::net::Ipv4Addr>> = pools
                .iter()
                .map(|(key, addrs)| (table_name(key), addrs.iter().copied().collect()))
                .collect();
            (out, self.render_rules(&pools), membership)
        };
        let rules_changed = applied
            .as_ref()
            .is_none_or(|applied| applied.rules != rules);
        if rules_changed || force {
            // Tables whose triple disappeared: killed explicitly, after the
            // reload — `persist` tables survive a reload *with their members*,
            // so without this a dead pool stays readable in `-T show`.
            let stale: Vec<String> = applied
                .as_ref()
                .map(|applied| {
                    applied
                        .membership
                        .keys()
                        .filter(|table| !membership.contains_key(*table))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            self.apply_pf(ANCHOR_RDR, &rules).await?;
            for (table, addrs) in &membership {
                self.apply_table(ANCHOR_RDR, table, addrs).await?;
            }
            for table in &stale {
                self.apply_kill_table(ANCHOR_RDR, table).await?;
            }
            *applied = Some(RdrApplied { rules, membership });
            // `changed` reports a *ruleset* change, not "pf was touched": a
            // forced re-assertion is not a change (PortReconcile's contract).
            return Ok((out, rules_changed));
        }
        // Ruleset unchanged: only membership can move, through table replaces
        // alone — a health-driven pool change must not rewrite the anchor.
        let mut membership_changed = false;
        if let Some(applied) = applied.as_mut() {
            for (table, addrs) in &membership {
                if applied.membership.get(table) != Some(addrs) {
                    self.apply_table(ANCHOR_RDR, table, addrs).await?;
                    membership_changed = true;
                }
            }
            applied.membership = membership;
        }
        Ok((out, membership_changed))
    }

    /// Set the host-mode published ports of `task_id` and reload the full
    /// `satl/rdr` ruleset (idempotent full regeneration — no incremental
    /// edits).
    ///
    /// The edge-triggered fast path, called by a task's controller when it
    /// starts the container. It writes the task's `started` slot only, so it
    /// can never drop what the node's convergence pass computed for the same
    /// task (module docs).
    #[tracing::instrument(skip_all, fields(task_id = %task_id, ports = ports.len()))]
    pub async fn publish_ports(
        &self,
        task_id: &str,
        ports: Vec<PortPublish>,
    ) -> Result<(), NetError> {
        let ((), changed) = self
            .write_rdr(false, |published| {
                published.entry(task_id.to_owned()).or_default().started = ports;
            })
            .await?;
        if changed {
            tracing::info!("published ports reloaded");
        }
        Ok(())
    }

    /// Remove all published ports of `task_id` and reload `satl/rdr`.
    /// Idempotent: unknown tasks are a no-op reload.
    #[tracing::instrument(skip_all, fields(task_id = %task_id))]
    pub async fn unpublish_ports(&self, task_id: &str) -> Result<(), NetError> {
        let ((), changed) = self
            .write_rdr(false, |published| {
                published.remove(task_id);
            })
            .await?;
        if changed {
            tracing::info!("published ports removed");
        }
        Ok(())
    }

    /// Converge `satl/rdr` on `wanted`: the redirects every live task on this
    /// node should have, whatever this manager believed a moment ago.
    ///
    /// This is the level-triggered writer. `wanted` is derived from the
    /// replicated store, which is authoritative about which tasks run here and
    /// which ports the allocator published for them, but which necessarily
    /// lags this node's own agent by a round trip. `keep` names the tasks the
    /// node itself still claims: an entry for one of those is left alone even
    /// when `wanted` does not mention it, so a task whose container has just
    /// started does not lose its redirect for the length of one pass. An entry
    /// in neither is a leftover and goes.
    ///
    /// `force` re-asserts the ruleset even when nothing changed (see
    /// [`Self::write_rdr`]).
    ///
    /// `mesh` is this node's ingress-mesh egress view (M6d): `Some` on a
    /// manager whose ingress gateway is allocated, and it lands in the
    /// ruleset (SNAT + MSS clamp), so a gateway (re)allocation is itself a
    /// ruleset change. `None` — workers, clusters without ingress publishing —
    /// renders the pre-mesh ruleset. It is stored, so the edge-triggered
    /// writers re-render with the same mesh half.
    pub async fn reconcile_published_ports(
        &self,
        wanted: BTreeMap<String, Vec<PortPublish>>,
        keep: &BTreeSet<String>,
        force: bool,
        mesh: Option<MeshEgress>,
    ) -> Result<PortReconcile, NetError> {
        {
            let mut cell = self
                .mesh
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *cell = mesh;
        }
        let ((tasks, redirects), changed) = self
            .write_rdr(force, |published| {
                published.retain(|task_id, redirects| {
                    if wanted.contains_key(task_id) {
                        // Superseded below; the controller's slot survives.
                        redirects.converged.clear();
                        true
                    } else {
                        keep.contains(task_id)
                    }
                });
                for (task_id, ports) in wanted {
                    published.entry(task_id).or_default().converged = ports;
                }
                let redirects: usize = published
                    .values()
                    .map(|redirects| redirects.started.len() + redirects.converged.len())
                    .sum();
                (published.len(), redirects)
            })
            .await?;
        Ok(PortReconcile {
            tasks,
            redirects,
            changed,
        })
    }

    /// The full anchor text for a pool set: the table declarations and static
    /// rdr rules first, then the mesh half (SNAT + MSS clamp, M6d) when the
    /// sweep gave this node an ingress gateway — pf.conf(5) statement order,
    /// `match` is a filter-section statement and must come last. One function,
    /// so the writer (`write_rdr`) and the read-back surface (`rdr_ruleset`)
    /// can never disagree about what the anchor holds.
    fn render_rules(&self, pools: &BTreeMap<PoolKey, BTreeSet<std::net::Ipv4Addr>>) -> String {
        let mesh = self
            .mesh
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match mesh.as_ref() {
            Some(mesh) => format!("{}{}", rdr_rules(pools), mesh_rules(mesh, pools)),
            None => rdr_rules(pools),
        }
    }

    /// The address this manager has on record for a task, if any.
    ///
    /// Lets the daemon rebuild per-task networking state (published ports in
    /// particular) after a restart, when its in-process maps are empty but the
    /// persisted IPAM still knows every live task's address.
    #[must_use]
    pub fn address_of(&self, network: &str, task_id: &str) -> Option<std::net::Ipv4Addr> {
        self.ipam().address_of(network, task_id)
    }

    /// The current full `satl/rdr` ruleset (for status surfaces and tests).
    #[must_use]
    pub fn rdr_ruleset(&self) -> String {
        let published = self.published();
        let all: Vec<PortPublish> = published
            .values()
            .flat_map(|redirects| redirects.started.iter().chain(&redirects.converged))
            .cloned()
            .collect();
        let pools = pool_publishes(&all);
        drop(published);
        self.render_rules(&pools)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;
    use satl_core::PortProtocol;

    const MISSING: &str = "ifconfig: interface satlnt-nope does not exist\n";

    fn test_config(dir: &std::path::Path) -> NetworkManagerConfig {
        NetworkManagerConfig {
            network: "satl".to_owned(),
            bridge: "satl0".to_owned(),
            group: "satl".to_owned(),
            state_dir: dir.to_path_buf(),
            pool: DEFAULT_LOCAL_BRIDGE_POOL,
            egress_if: Some("ice0".to_owned()),
            pf_mode: PfMode::CheckOnly,
        }
    }

    /// Synthesize `ifconfig <iface>` show output in the real fixture format.
    fn show_output(name: &str, descr: Option<&str>, inet: Option<&str>) -> String {
        use std::fmt::Write as _;
        let mut out = format!(
            "{name}: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n"
        );
        if let Some(d) = descr {
            let _ = writeln!(out, "\tdescription: {d}");
        }
        out.push_str("\tether 58:9c:fc:10:c5:b8\n");
        if let Some(i) = inet {
            let _ = writeln!(out, "\tinet {i} netmask 0xffffff00 broadcast 10.88.0.255");
        }
        out.push_str("\tgroups: epair satl\n");
        out
    }

    #[test]
    fn marker_grammar_classifies_every_kind_and_rejects_the_rest() {
        let task = "0123456789abcdefghijklmno";
        assert_eq!(
            classify_marker("satl", &format!("satl:{task}")),
            Some(OwnedKind::Task {
                task_id: task.to_owned()
            })
        );
        assert_eq!(
            classify_marker("satl", "satl:network:satl"),
            Some(OwnedKind::Network {
                network: "satl".to_owned()
            })
        );
        assert_eq!(
            classify_marker("satl", "satl:overlay:web"),
            Some(OwnedKind::OverlayNetwork {
                network: "web".to_owned()
            })
        );
        assert_eq!(
            classify_marker("satl", &format!("satl:overlay:web:{task}")),
            Some(OwnedKind::OverlayTask {
                network: "web".to_owned(),
                task_id: task.to_owned()
            })
        );
        // The VTEP is recognised precisely so nothing here destroys it.
        assert_eq!(
            classify_marker("satl", "satl:vxlan:web"),
            Some(OwnedKind::Vtep {
                network: "web".to_owned()
            })
        );
        // Not ours, or not understood: left alone rather than swept.
        for other in [
            "podman:whatever",
            "satl",
            "satl:",
            "satl:overlay:",
            "satl:overlay:web:",
            "satl:overlay:web:task:extra",
            "satl:network:",
            "satl:vxlan:",
            "satlx:network:web",
        ] {
            assert_eq!(classify_marker("satl", other), None, "{other:?}");
        }
        // A different group prefix is a different daemon's namespace.
        assert_eq!(
            classify_marker("satlnt", "satlnt:overlay:web"),
            Some(OwnedKind::OverlayNetwork {
                network: "web".to_owned()
            })
        );
        assert_eq!(classify_marker("satlnt", "satl:overlay:web"), None);
    }

    #[tokio::test]
    async fn ensure_host_network_creates_and_configures_everything() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        // exists(satl0) -> missing
        mock.push_output(1, "", MISSING);
        // create bridge -> prints name
        mock.push_output(0, "satl0\n", "");
        mock.push_ok(); // group
        mock.push_ok(); // descr
        // get_inet -> no address yet
        mock.push_output(
            0,
            &show_output("satl0", Some("satl:network:satl"), None),
            "",
        );
        mock.push_ok(); // add_inet
        mock.push_ok(); // up
        mock.push_ok(); // pfctl -nf (CheckOnly)
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        let net = mgr.ensure_host_network().await.unwrap();
        assert_eq!(net.bridge, "satl0");
        assert_eq!(net.subnet.to_string(), "10.88.0.0/24");
        assert_eq!(net.gateway, "10.88.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig satl0",
                "/sbin/ifconfig bridge create name satl0",
                "/sbin/ifconfig satl0 group satl",
                "/sbin/ifconfig satl0 description satl:network:satl",
                "/sbin/ifconfig satl0",
                "/sbin/ifconfig satl0 inet 10.88.0.1/24",
                "/sbin/ifconfig satl0 up",
                "/sbin/pfctl -nf -",
            ]
        );
        // The NAT ruleset went through the syntax check.
        assert_eq!(
            mock.stdins().last().unwrap().as_deref(),
            Some("nat on ice0 inet from 10.88.0.0/24 to any -> (ice0)\n")
        );
    }

    #[tokio::test]
    async fn ensure_host_network_is_idempotent_on_existing_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        let bridge_show = show_output("satl0", Some("satl:network:satl"), Some("10.88.0.1"));
        // exists -> yes
        mock.push_output(0, &bridge_show, "");
        // get_descr -> already correct
        mock.push_output(0, &bridge_show, "");
        // list_group -> bridge already a member
        mock.push_output(0, "satl0\n", "");
        // get_inet -> gateway already assigned
        mock.push_output(0, &bridge_show, "");
        mock.push_ok(); // up (idempotent)
        mock.push_ok(); // pfctl -nf
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        let net = mgr.ensure_host_network().await.unwrap();
        assert_eq!(net.gateway, "10.88.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig satl0",
                "/sbin/ifconfig satl0",
                "/sbin/ifconfig -g satl",
                "/sbin/ifconfig satl0",
                "/sbin/ifconfig satl0 up",
                "/sbin/pfctl -nf -",
            ]
        );
    }

    #[tokio::test]
    async fn attach_task_happy_path_builds_expected_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "epair0a\n", ""); // epair create
        mock.push_ok(); // descr a
        mock.push_ok(); // group a
        mock.push_ok(); // descr b
        mock.push_ok(); // addm
        mock.push_ok(); // up a
        mock.push_ok(); // vnet
        mock.push_ok(); // -j inet
        mock.push_ok(); // -j up epair0b
        mock.push_ok(); // -j up lo0
        mock.push_output(0, "add net default: gateway 10.88.0.1\n", ""); // route
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        let att = mgr.attach_task("task1", "satlnt-it").await.unwrap();
        assert_eq!(att.epair_a, "epair0a");
        assert_eq!(att.epair_b, "epair0b");
        assert_eq!(att.ip, "10.88.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(att.gateway, "10.88.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair create",
                "/sbin/ifconfig epair0a description satl:task1",
                "/sbin/ifconfig epair0a group satl",
                "/sbin/ifconfig epair0b description satl:task1",
                "/sbin/ifconfig satl0 addm epair0a",
                "/sbin/ifconfig epair0a up",
                "/sbin/ifconfig epair0b vnet satlnt-it",
                "/sbin/ifconfig -j satlnt-it epair0b inet 10.88.0.2/24",
                "/sbin/ifconfig -j satlnt-it epair0b up",
                "/sbin/ifconfig -j satlnt-it lo0 up",
                "/sbin/route -j satlnt-it add default 10.88.0.1",
            ]
        );
    }

    #[tokio::test]
    async fn attach_task_rolls_back_on_move_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "epair0a\n", ""); // epair create
        mock.push_ok(); // descr a
        mock.push_ok(); // group a
        mock.push_ok(); // descr b
        mock.push_ok(); // addm
        mock.push_ok(); // up a
        // vnet move fails: jail is gone
        mock.push_output(1, "", "ifconfig: jail \"satlnt-it\" not found\n");
        // rollback: destroy a
        mock.push_ok();
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        let err = mgr.attach_task("task1", "satlnt-it").await.unwrap_err();
        match &err {
            NetError::Attach {
                task_id,
                jail,
                step,
                rolled_back,
                ..
            } => {
                assert_eq!(task_id, "task1");
                assert_eq!(jail, "satlnt-it");
                assert_eq!(*step, AttachStep::MoveToJail);
                assert!(rolled_back);
            }
            other => panic!("expected Attach error, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("move-to-jail"), "{text}");
        assert!(text.contains("not found"), "{text}");
        // Rollback destroyed the pair via the a end.
        assert_eq!(
            mock.calls().last().unwrap(),
            "/sbin/ifconfig epair0a destroy"
        );
        // Rollback released the address: the persisted state has no
        // allocations left.
        let state = std::fs::read_to_string(dir.path().join("satl.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&state).unwrap();
        assert_eq!(json["allocations"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn detach_task_is_idempotent_and_handles_returned_b_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.pf_mode = PfMode::Disabled;
        let mock = MockRunner::new();
        // First detach: a end still exists.
        mock.push_ok();
        // Second detach: a gone, b returned to host after jail death.
        mock.push_output(1, "", MISSING);
        mock.push_ok();
        // Third detach: both gone.
        mock.push_output(1, "", MISSING);
        mock.push_output(1, "", MISSING);
        let mgr = NetworkManager::with_runner(config, &mock).unwrap();
        let att = TaskAttachment {
            epair_a: "epair0a".to_owned(),
            epair_b: "epair0b".to_owned(),
            ip: "10.88.0.2".parse().unwrap(),
            gateway: "10.88.0.1".parse().unwrap(),
        };
        mgr.detach_task("task1", &att).await.unwrap();
        mgr.detach_task("task1", &att).await.unwrap();
        mgr.detach_task("task1", &att).await.unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair0a destroy",
                "/sbin/ifconfig epair0a destroy",
                "/sbin/ifconfig epair0b destroy",
                "/sbin/ifconfig epair0a destroy",
                "/sbin/ifconfig epair0b destroy",
            ]
        );
    }

    #[tokio::test]
    async fn list_owned_and_destroy_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.pf_mode = PfMode::Disabled;
        let mock = MockRunner::new();
        // list_owned inside destroy_orphans:
        // group satl members
        mock.push_output(0, "satl0\nepair0a\n", "");
        // group epair members (epair0b vanished from a live jail; epair5a is
        // an orphan; epair9a is someone else's epair)
        mock.push_output(0, "epair0a\nepair5a\nepair5b\nepair9a\n", "");
        // group bridge, then group vxlan: the driver groups catch a bridge
        // whose group tagging was interrupted and satl-overlay's VTEPs.
        mock.push_output(0, "satl0\n", "");
        mock.push_output(0, "satl-vx4096\n", "");
        // get_descr probes, BTreeSet order:
        // epair0a epair5a epair5b epair9a satl-vx4096 satl0
        mock.push_output(0, &show_output("epair0a", Some("satl:task1"), None), "");
        mock.push_output(0, &show_output("epair5a", Some("satl:orphan1"), None), "");
        mock.push_output(1, "", MISSING); // epair5b raced away — skipped
        mock.push_output(0, &show_output("epair9a", None, None), ""); // no descr — not ours
        mock.push_output(
            0,
            &show_output("satl-vx4096", Some("satl:vxlan:web"), None),
            "",
        );
        mock.push_output(
            0,
            &show_output("satl0", Some("satl:network:satl"), Some("10.88.0.1")),
            "",
        );
        // destroy_orphans: only epair5a (orphan1 not in known set)
        mock.push_ok();
        let mgr = NetworkManager::with_runner(config, &mock).unwrap();
        let known: BTreeSet<String> = ["task1".to_owned()].into();
        let destroyed = mgr.destroy_orphans(&known).await.unwrap();
        // Only the node-local orphan: a VTEP is never a local-orphan candidate
        // even though it carries a SatL marker.
        assert_eq!(destroyed, ["epair5a"]);
        assert_eq!(
            mock.calls().last().unwrap(),
            "/sbin/ifconfig epair5a destroy"
        );
    }

    #[tokio::test]
    async fn list_owned_classifies_local_overlay_and_vtep_interfaces() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.pf_mode = PfMode::Disabled;
        let mock = MockRunner::new();
        mock.push_output(0, "satl0\n", ""); // group satl
        mock.push_output(0, "epair0a\nepair1a\n", ""); // group epair
        mock.push_output(0, "satl0\nsatl-br4096\n", ""); // group bridge
        mock.push_output(0, "satl-vx4096\n", ""); // group vxlan
        // BTreeSet order: epair0a epair1a satl-br4096 satl-vx4096 satl0
        mock.push_output(0, &show_output("epair0a", Some("satl:task1"), None), "");
        mock.push_output(
            0,
            &show_output("epair1a", Some("satl:overlay:web:task2"), None),
            "",
        );
        mock.push_output(
            0,
            &show_output("satl-br4096", Some("satl:overlay:web"), Some("10.100.0.2")),
            "",
        );
        mock.push_output(
            0,
            &show_output("satl-vx4096", Some("satl:vxlan:web"), None),
            "",
        );
        mock.push_output(
            0,
            &show_output("satl0", Some("satl:network:satl"), Some("10.88.0.1")),
            "",
        );
        let mgr = NetworkManager::with_runner(config, &mock).unwrap();
        let owned = mgr.list_owned().await.unwrap();
        let kinds: Vec<(String, OwnedKind)> = owned
            .into_iter()
            .map(|iface| (iface.name, iface.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                (
                    "epair0a".to_owned(),
                    OwnedKind::Task {
                        task_id: "task1".to_owned()
                    }
                ),
                (
                    "epair1a".to_owned(),
                    OwnedKind::OverlayTask {
                        network: "web".to_owned(),
                        task_id: "task2".to_owned()
                    }
                ),
                (
                    "satl-br4096".to_owned(),
                    OwnedKind::OverlayNetwork {
                        network: "web".to_owned()
                    }
                ),
                (
                    "satl-vx4096".to_owned(),
                    OwnedKind::Vtep {
                        network: "web".to_owned()
                    }
                ),
                (
                    "satl0".to_owned(),
                    OwnedKind::Network {
                        network: "satl".to_owned()
                    }
                ),
            ]
        );
    }

    #[tokio::test]
    async fn publish_and_unpublish_regenerate_the_full_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_ok(); // pfctl -nf for task1
        mock.push_ok(); // pfctl -nf for task2
        mock.push_ok(); // pfctl -nf after unpublish task1
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        mgr.publish_ports(
            "task1",
            vec![PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 80,
            }],
        )
        .await
        .unwrap();
        mgr.publish_ports(
            "task2",
            vec![PortPublish {
                proto: PortProtocol::Udp,
                host_port: 8053,
                task_ip: "10.88.0.3".parse().unwrap(),
                task_port: 53,
            }],
        )
        .await
        .unwrap();
        assert_eq!(
            mgr.rdr_ruleset(),
            "table <satl_p8053_udp_53> persist\n\
             rdr pass inet proto udp from any to any port 8053 -> <satl_p8053_udp_53> port 53 round-robin\n\
             table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n"
        );
        mgr.unpublish_ports("task1").await.unwrap();
        assert_eq!(
            mgr.rdr_ruleset(),
            "table <satl_p8053_udp_53> persist\n\
             rdr pass inet proto udp from any to any port 8053 -> <satl_p8053_udp_53> port 53 round-robin\n"
        );
        // Unknown task: no pfctl call.
        mgr.unpublish_ports("never-published").await.unwrap();
        assert_eq!(mock.calls(), ["/sbin/pfctl -nf -"; 3]);
        // Every check saw the then-current full ruleset.
        let stdins = mock.stdins();
        assert!(stdins[1].as_deref().unwrap().contains("8053"));
        assert!(stdins[1].as_deref().unwrap().contains("8080"));
        assert!(!stdins[2].as_deref().unwrap().contains("8080"));
    }

    // ---- the convergence pass ----------------------------------------------

    fn publish(host_port: u16, ip: &str, task_port: u16) -> PortPublish {
        PortPublish {
            proto: PortProtocol::Tcp,
            host_port,
            task_ip: ip.parse().expect("test address"),
            task_port,
        }
    }

    fn wanted(entries: &[(&str, PortPublish)]) -> BTreeMap<String, Vec<PortPublish>> {
        let mut map: BTreeMap<String, Vec<PortPublish>> = BTreeMap::new();
        for (task, publish) in entries {
            map.entry((*task).to_owned())
                .or_default()
                .push(publish.clone());
        }
        map
    }

    fn keep(tasks: &[&str]) -> BTreeSet<String> {
        tasks.iter().map(|task| (*task).to_owned()).collect()
    }

    /// The pass is the level: what the store wants is in the anchor, and what
    /// nothing claims any more is gone, whatever this process believed.
    #[tokio::test]
    async fn the_convergence_pass_writes_the_whole_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        for _ in 0..3 {
            mock.push_ok();
        }
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();

        let report = mgr
            .reconcile_published_ports(
                wanted(&[
                    ("task1", publish(8080, "10.88.0.2", 80)),
                    ("task2", publish(9090, "10.88.0.3", 80)),
                ]),
                &keep(&[]),
                false,
                None,
            )
            .await
            .unwrap();
        assert!(report.changed);
        assert_eq!(report.tasks, 2);
        assert_eq!(report.redirects, 2);
        assert_eq!(
            mgr.rdr_ruleset(),
            "table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n\
             table <satl_p9090_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 9090 -> <satl_p9090_tcp_80> port 80 round-robin\n"
        );

        // task2 is gone from the store and nothing on the node claims it.
        let report = mgr
            .reconcile_published_ports(
                wanted(&[("task1", publish(8080, "10.88.0.2", 80))]),
                &keep(&[]),
                false,
                None,
            )
            .await
            .unwrap();
        assert!(report.changed);
        assert_eq!(
            mgr.rdr_ruleset(),
            "table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n"
        );

        // Nothing left at all: the anchor is emptied.
        let report = mgr
            .reconcile_published_ports(BTreeMap::new(), &keep(&[]), false, None)
            .await
            .unwrap();
        assert!(report.changed);
        assert_eq!(mgr.rdr_ruleset(), "");
    }

    /// The store lags this node's own agent by a round trip. A task the node
    /// still claims must not lose the redirect its controller just installed
    /// because the pass has not seen it yet.
    #[tokio::test]
    async fn a_task_the_node_still_claims_keeps_its_redirect() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        for _ in 0..2 {
            mock.push_ok();
        }
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();

        mgr.publish_ports("fresh", vec![publish(8080, "10.88.0.2", 80)])
            .await
            .unwrap();
        let report = mgr
            .reconcile_published_ports(BTreeMap::new(), &keep(&["fresh"]), false, None)
            .await
            .unwrap();
        assert!(!report.changed, "the anchor must not have been rewritten");
        assert_eq!(
            mgr.rdr_ruleset(),
            "table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n"
        );

        // Once the node stops claiming it, the same pass removes it.
        mgr.reconcile_published_ports(BTreeMap::new(), &keep(&[]), false, None)
            .await
            .unwrap();
        assert_eq!(mgr.rdr_ruleset(), "");
    }

    /// Neither writer can erase the other's slot, in either order: the
    /// controller publishes the host-mode port, the pass publishes host *and*
    /// ingress, and the anchor holds both whichever ran last.
    #[tokio::test]
    async fn the_two_writers_do_not_erase_each_other() {
        for controller_last in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mock = MockRunner::new();
            for _ in 0..2 {
                mock.push_ok();
            }
            let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
            let host = publish(7070, "10.88.0.2", 70);
            let ingress = publish(8080, "10.88.0.2", 80);
            let claimed = keep(&["task1"]);
            let pass = || {
                mgr.reconcile_published_ports(
                    wanted(&[("task1", host.clone()), ("task1", ingress.clone())]),
                    &claimed,
                    false,
                    None,
                )
            };
            if controller_last {
                pass().await.unwrap();
                mgr.publish_ports("task1", vec![host.clone()])
                    .await
                    .unwrap();
            } else {
                mgr.publish_ports("task1", vec![host.clone()])
                    .await
                    .unwrap();
                pass().await.unwrap();
            }
            assert_eq!(
                mgr.rdr_ruleset(),
                "table <satl_p7070_tcp_70> persist\n\
                 rdr pass inet proto tcp from any to any port 7070 -> <satl_p7070_tcp_70> port 70 round-robin\n\
                 table <satl_p8080_tcp_80> persist\n\
                 rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n",
                "controller_last = {controller_last}"
            );
        }
    }

    /// **The M6c invariant, pinned**: a membership change goes through
    /// `-T replace` alone — the anchor's ruleset is reloaded only when the
    /// *set* of published triples changes. Enforce mode, so every pfctl run
    /// is visible in the mock's calls.
    #[tokio::test]
    async fn membership_moves_through_table_replaces_not_anchor_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        for _ in 0..8 {
            mock.push_ok();
        }
        let mut config = test_config(dir.path());
        config.pf_mode = PfMode::Enforce;
        let mgr = NetworkManager::with_runner(config, &mock).unwrap();

        // First publish: the triple appears, so the anchor loads and the
        // table is pushed.
        mgr.publish_ports("task1", vec![publish(8080, "10.88.0.2", 80)])
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/sbin/pfctl -nf -",
                "/sbin/pfctl -a satl/rdr -f -",
                "/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T replace 10.88.0.2",
            ]
        );

        // A second task of the same service on this node: same triple, new
        // member — the ruleset MUST NOT be rewritten.
        mgr.publish_ports("task2", vec![publish(8080, "10.88.0.5", 80)])
            .await
            .unwrap();
        assert_eq!(
            &mock.calls()[3..],
            ["/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T replace 10.88.0.2 10.88.0.5"]
        );

        // task2 dies: same, membership shrinks through the table alone.
        mgr.unpublish_ports("task2").await.unwrap();
        assert_eq!(
            &mock.calls()[4..],
            ["/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T replace 10.88.0.2"]
        );

        // The last task goes: the triple disappears — that IS a ruleset
        // change, and an empty ruleset flushes the anchor. The now-stale
        // table is killed explicitly: `persist` tables survive a flush with
        // their members, and a dead pool must not stay readable.
        mgr.unpublish_ports("task1").await.unwrap();
        assert_eq!(
            &mock.calls()[5..],
            [
                "/sbin/pfctl -a satl/rdr -F nat",
                "/sbin/pfctl -a satl/rdr -F rules",
                "/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T kill",
            ]
        );
    }

    /// A steady node runs no pfctl at all, and `force` is how the periodic
    /// pass re-asserts an anchor it cannot read back.
    #[tokio::test]
    async fn an_unchanged_ruleset_is_reloaded_only_when_forced() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        for _ in 0..2 {
            mock.push_ok();
        }
        let mgr = NetworkManager::with_runner(test_config(dir.path()), &mock).unwrap();
        let nothing_claimed = keep(&[]);
        let same = || {
            mgr.reconcile_published_ports(
                wanted(&[("task1", publish(8080, "10.88.0.2", 80))]),
                &nothing_claimed,
                false,
                None,
            )
        };
        assert!(same().await.unwrap().changed);
        assert!(!same().await.unwrap().changed);
        assert!(!same().await.unwrap().changed);
        assert_eq!(mock.calls().len(), 1, "one load, then nothing to do");

        let forced = mgr
            .reconcile_published_ports(
                wanted(&[("task1", publish(8080, "10.88.0.2", 80))]),
                &keep(&[]),
                true,
                None,
            )
            .await
            .unwrap();
        assert!(
            !forced.changed,
            "a re-assertion is not a change, and must not be reported as one"
        );
        assert_eq!(mock.calls().len(), 2, "but pf was told again");
    }
}
