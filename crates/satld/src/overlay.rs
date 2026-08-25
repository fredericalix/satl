// SPDX-License-Identifier: BSD-2-Clause
//! The node's overlay programmer: where the dispatcher's network assignments
//! meet `satl-overlay` and `satl-net` (architecture §11.2, §11.5).
//!
//! ```text
//!  dispatcher assignments ─▶ OverlaySink ─┐
//!  task prepare/start/remove ────────────▶ OverlayManager ─┬─▶ satl_overlay::Vxlan      VTEP
//!  startup reconciliation ───────────────┘                 ├─▶ satl_net  segment + epairs
//!  store watch feed ─┬─▶ EndpointTable ─┐                  ├─▶ satl_overlay::Programmer  FDB + ARP
//!                    └─▶ ScopeTable ────┴─▶ DnsServer      ├─▶ satl_overlay::Ipsec      SAD + SPD (encrypted)
//!                                                        ├─▶ crate::guard               satl/guard + enc0
//!                                                        └─▶ DnsSupervisor              :53
//! ```
//!
//! The two DNS projections answer two different questions and are fed from one
//! store walk: [`satl_overlay::EndpointTable`] is *what a name means on a
//! network*, [`satl_overlay::ScopeTable`] is *which networks a given client may
//! be answered from* — the querying task's, in attachment order. See
//! [`spawn_dns_feed`].
//!
//! # What is programmed, and in which order
//!
//! Per overlay network on this node, and the order is the whole design
//! (`docs/vxlan.md` §5, §7, §8):
//!
//! 1. **the VTEP** (`satl-vx<vni>`), because the *first* interface added to a
//!    bridge overwrites the bridge's MTU with its own, so the 1450-byte vxlan
//!    interface has to be the first member;
//! 2. **the bridge with this node's gateway address on it**, before any epair:
//!    a jail that ARPs for its gateway and gets no answer caches nothing, but a
//!    jail whose gateway address appears *later* on another node's bridge
//!    resolves it there and hands that node its traffic — the measured
//!    duplicate-gateway hazard (`docs/vxlan.md` §8);
//! 3. **the task's epair**, derived MAC and overlay MTU set on both ends before
//!    `addm` (a bridge member's MTU cannot be set at all afterwards);
//! 4. **the FDB and the per-jail ARP entries**, which need the jail to exist and
//!    are the only thing that makes a remote endpoint reachable at all;
//! 5. **`resolv.conf`**, which is content in the writable layer and therefore
//!    written earliest in *time* (at `prepare`) while depending on the least —
//!    only on this node's gateway for the network, not on any interface.
//!
//! No **default route** is installed for an overlay attachment: the subnet is
//! on-link through the epair, and the default route belongs to the node-local
//! bridge attachment that carries NAT and published ports. Two would race.
//!
//! # Idempotent and reconciling, never incremental
//!
//! [`OverlayManager::apply_network`] is called again on every endpoint change
//! anywhere in the cluster — that is how FDB updates reach a node — and again
//! for every network in every `COMPLETE` snapshot. There is deliberately no
//! `reset_networks`, so re-registration must not flap a live overlay. Every step
//! below therefore adopts what exists and changes only what differs:
//! `Vxlan::ensure_vtep`, `NetworkManager::ensure_overlay_segment` and
//! `Programmer::reconcile` are each written that way, and `ftable add` on an
//! existing MAC is `EEXIST` rather than an overwrite, which is why the delta has
//! a third `replace` list.
//!
//! # The lock
//!
//! One mutex guards the whole per-network map and is held across the `ifconfig`
//! and ioctl work of a pass. That serialises overlay programming on the node,
//! which is wanted: two passes racing on one bridge or one forwarding table
//! would interleave adds and removes computed against different read-backs. It
//! is never held across a Raft or dispatcher call, so it cannot couple the
//! control plane to the data plane.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use satl_agent::overlay::TaskOverlay;
use satl_core::{Id, Ipv4Cidr, Network, NetworkDriver, Task};
use satl_dispatcher::assignment::{NetworkAssignment, NetworkEndpoint};
use satl_net::{NetworkManager, OverlayAttach, OverlayAttachment, OverlaySegment, OwnedKind};
use satl_overlay::{
    ArpHelper, DesiredOverlay, EndpointTable, Ftable, LocalEndpoint, Programmer, RemoteEndpoint,
    ScopeTable, VtepSpec, Vxlan,
};
use satl_runtime::Jails;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::underlay::{Underlay, UnderlayError, UnderlayFacts};

/// How often every network is re-reconciled even with no assignment change.
///
/// The assignment stream is the fast path; this is the safety net for the two
/// cases it cannot cover: a pass that failed halfway (the delta is idempotent,
/// so the next one retries exactly what is missing) and a forwarding table that
/// had to be flushed and re-pushed because the dump sysctl truncated
/// (`satl_overlay::Applied::ftable_flushed`). One sysctl dump plus one ioctl per
/// network, plus one helper child per local jail, so it is deliberately slow.
const RESYNC_INTERVAL: Duration = Duration::from_mins(1);

/// How long a starting task waits for its network to become programmable.
///
/// A node's gateway address is allocated when its **first task is scheduled**
/// there, so the first shipment of a network can legitimately arrive before the
/// allocator's next pass has filled `Network::node_gateways`. Failing the task
/// then would turn a one-pass control-plane lag into a `REJECTED` container, so
/// the attach waits — and still fails loudly rather than starting a container
/// with no overlay.
const PROGRAMMABLE_WAIT: Duration = Duration::from_secs(30);

/// Poll interval inside [`PROGRAMMABLE_WAIT`].
const PROGRAMMABLE_POLL: Duration = Duration::from_millis(250);

/// Shortest interval between two rebuilds of the DNS endpoint table.
///
/// A store commit marks the table dirty and this tick does the work, so a burst
/// of commits costs one full walk rather than one per commit — and a rebuild
/// still happens within this window of any change, which matters because the
/// table *is* the load balancer: a task that left `RUNNING` must stop being
/// answered quickly (`satl_overlay::endpoints`, rule 3).
const ENDPOINT_REBUILD_FLOOR: Duration = Duration::from_millis(500);

/// Where the host's upstream resolvers are read from.
const HOST_RESOLV_CONF: &str = "/etc/resolv.conf";

/// The `Programmer` this daemon runs: the real ioctl FDB, the re-exec ARP
/// helper, the real `sysctl` reader.
type SystemProgrammer = Programmer<Ftable, ArpHelper, satl_overlay::SystemRunner>;

/// Why an overlay could not be programmed.
///
/// Every variant either wraps a wrapper error — which already carries the full
/// argv, exit status and stderr of what was attempted (CLAUDE.md, "External
/// command wrappers") — or says in plain ASCII which piece of cluster state was
/// missing and what an operator should look at.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// The underlay could not be measured, so neither the MTU nor the blackhole
    /// could be derived.
    #[error(transparent)]
    Underlay(#[from] UnderlayError),

    /// VTEP lifecycle failure (`ifconfig`, or a driver that refused).
    #[error(transparent)]
    Vxlan(#[from] satl_overlay::VxlanError),

    /// Bridge, gateway address or epair failure.
    #[error(transparent)]
    Net(#[from] satl_net::NetError),

    /// The forwarding table or a jail's ARP table could not be read or written.
    #[error(transparent)]
    Program(#[from] satl_overlay::ProgramError),

    /// The VTEP's clone unit could not be resolved by probe.
    #[error(transparent)]
    Ftable(#[from] satl_overlay::FtableError),

    /// This node cannot program an overlay, and the message says which of the
    /// two very different reasons it is.
    ///
    /// Collapsing them was a real cost: a node with a public **/32** address
    /// can derive no VXLAN blackhole (docs/vxlan.md §2), so `satld` degrades
    /// deliberately and says so at boot -- and then every task that attached
    /// to an overlay failed in a loop with "this is a start-up ordering bug in
    /// satld", sending the reader after a race that does not exist. A /32 VPS
    /// is the ordinary shape for a single public server, so this is the first
    /// thing a new user meets.
    #[error("overlay: {reason}")]
    NoIdentity {
        /// What actually stopped this node from having an overlay identity.
        reason: NoIdentityReason,
    },

    /// The network is not (yet) programmable on this node.
    #[error("overlay network '{network}' is not programmable on this node: {reason}")]
    NotReady {
        /// Network name, as an operator names it.
        network: String,
        /// Which piece of allocator state is missing.
        reason: String,
    },

    /// A task referenced a network this node was never given.
    #[error(
        "overlay: task {task_id} attaches to network {network_id}, which was \
         never delivered to this node. The dispatcher ships networks before the \
         tasks that use them, so this means the assignment stream was \
         interrupted; the next snapshot repairs it"
    )]
    UnknownNetwork {
        /// The task being attached.
        task_id: Id,
        /// The network it asked for.
        network_id: Id,
    },

    /// The blackhole default remote is, or could be, a real peer.
    #[error(
        "overlay: the blackhole default remote {blackhole} is also node {node_id}'s \
         VXLAN endpoint. if_vxlan sends every broadcast and unknown-unicast frame \
         to the default remote without consulting the forwarding table, so a real \
         peer there makes a missing entry work anyway and hides the bug \
         (docs/vxlan.md section 2). Set overlay_blackhole in satld.toml to an \
         address on this underlay that no node holds"
    )]
    BlackholeIsAPeer {
        /// The offending address.
        blackhole: Ipv4Addr,
        /// The node that holds it.
        node_id: Id,
    },

    /// The pass ran but some entries did not take.
    #[error(
        "overlay network '{network}': the data plane is only partially \
         programmed, so some peers are unreachable: {failures}"
    )]
    Partial {
        /// Network name.
        network: String,
        /// Rendered per-entry failures.
        failures: String,
    },
}

/// This node's identity as the overlay needs it, refreshed on every cluster
/// bring-up (`swarm join` gives the node a different id *and* possibly a
/// different advertise address).
#[derive(Debug, Clone)]
struct Identity {
    /// This node's id in the cluster it currently belongs to.
    node_id: Id,
    /// Measured facts of the interface carrying [`Self::vtep`].
    underlay: UnderlayFacts,
    /// This node's underlay address, i.e. every VTEP's `vxlanlocal`.
    vtep: Ipv4Addr,
    /// The blackhole default remote, derived from the underlay prefix.
    blackhole: Ipv4Addr,
}

/// One task of this network attached on this node.
#[derive(Debug, Clone)]
struct Attached {
    /// The jail to enter for ARP: the task id, which is the jail name (a pinned
    /// M1 contract, `satl_agent`'s crate docs).
    jail: String,
    /// The task's address on this network.
    ip: Ipv4Addr,
    /// Both epair ends, as the ownership markers name them. Recorded so a
    /// detach after a daemon restart does not have to guess.
    epairs: Vec<String>,
}

/// Everything this node knows about one overlay network.
#[derive(Debug)]
struct NetworkState {
    /// The network object, from the last assignment (or, at startup, from the
    /// store — see [`OverlayManager::seed`]).
    network: Network,
    /// Every endpoint of the network cluster-wide, keyed by task. Empty until
    /// the first assignment arrives.
    endpoints: BTreeMap<Id, NetworkEndpoint>,
    /// The per-node load-balancer attachments, keyed by node (M6d): every
    /// gateway the network records, so the kernel tables can cover the
    /// relaying nodes too (FDB entry + ARP entry in every local jail).
    gateways: BTreeMap<Id, satl_dispatcher::GatewayAttachment>,
    /// The host-table static ARP entries this manager installed for the
    /// ingress network's remote task addresses (M6d), so a relaying node's own
    /// stack can resolve a task it forwards to — broadcast ARP goes to the
    /// blackhole remote and is never answered (hack/experiments/mesh). Tracked
    /// so a dead endpoint's entry is deleted, not left to rot.
    host_arp: BTreeMap<Ipv4Addr, satl_core::MacAddr>,
    /// This node's attachments, keyed by task.
    local: BTreeMap<Id, Attached>,
    /// The VTEP's clone unit. `None` until it is known: the per-interface sysctl
    /// tree is keyed by the unit and nothing maps a unit back to a name
    /// (`docs/vxlan.md` §2 point 3), so an *adopted* interface needs
    /// `FtableReader::resolve_unit` before its table can be read back.
    unit: Option<u32>,
    /// Whether the VTEP and the bridge have been ensured in this process.
    ensured: bool,
}

/// Why this node has no overlay identity.
///
/// Kept as data rather than collapsed into `Option::None`, because the three
/// cases want three different sentences and only one of them is a bug.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Default)]
pub enum NoIdentityReason {
    /// No `advertise_addr`: a configuration choice, fixable by the operator.
    #[error(
        "this node publishes no underlay address, so it can host no overlay network. \
         Set advertise_addr in satld.toml and restart satld; bridge networks work \
         without it"
    )]
    NoUnderlayAddress,

    /// The underlay could not be measured -- typically a public /32, where no
    /// VXLAN blackhole can be derived. A deliberate degradation.
    #[error(
        "this node's underlay could not be measured, so it can host no overlay network: \
         {detail}. This is a deliberate degradation, not a start-up race -- satld said \
         so at boot ('cannot measure this node's underlay'). A single public address \
         with a /32 netmask is the usual cause; bridge networks, and therefore \
         satl compose, work unaffected. satl stack and any multi-node setup need a \
         real underlay"
    )]
    UnmeasurableUnderlay {
        /// What the measurement complained about.
        detail: String,
    },

    /// Adoption has genuinely not happened yet. This one *is* an ordering bug.
    #[default]
    #[error(
        "this node has no cluster identity yet, so it does not know its own node id \
         or its underlay address. This is a start-up ordering bug in satld, not a \
         configuration problem"
    )]
    NotAdoptedYet,
}
/// The mutable half, behind one lock.
#[derive(Debug, Default)]
struct Inner {
    identity: Option<Identity>,
    /// Why `identity` is `None`, so the attach path can say which of the
    /// three cases it is instead of guessing the worst one.
    no_identity: NoIdentityReason,
    networks: BTreeMap<Id, NetworkState>,
    /// Networks this node was shipped that are **not** overlays.
    ///
    /// Recorded so that "this task's network is not in my overlay map" can be
    /// answered from the network's *driver* rather than guessed. Without it a
    /// bridge attachment and a lost overlay assignment look identical, and one of
    /// them must fail the task while the other must be ignored.
    node_local: BTreeSet<Id>,
}

/// One overlay network startup reconciliation says this node should host, with
/// the local tasks on it. Built from the store by [`crate::reconcile`].
#[derive(Debug, Clone)]
pub struct WantedNetwork {
    /// The network object as the store holds it.
    pub network: Network,
    /// Its live tasks on this node.
    pub tasks: Vec<WantedTask>,
}

/// One live local task on an overlay network.
#[derive(Debug, Clone)]
pub struct WantedTask {
    /// The task, whose id is also its jail name.
    pub task_id: Id,
    /// The jail to enter for ARP.
    pub jail: String,
    /// Its address on the network.
    pub ip: Ipv4Addr,
}

/// One of a task's attachments, as the attach path sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Planned {
    /// An overlay network this node holds, and the task's address on it.
    Overlay {
        /// Which network.
        network_id: Id,
        /// The task's address there.
        ip: Ipv4Addr,
    },
    /// A network id this node has no object for at all.
    Unknown {
        /// Which network.
        network_id: Id,
    },
}

/// The node's overlay programmer. One per daemon, shared by the assignment
/// sink, the task controllers and startup reconciliation.
pub struct OverlayManager {
    /// Ownership marker and interface group — the daemon's `network_name`, so
    /// two daemons on one host never claim each other's interfaces.
    marker: String,
    /// Operator override for the blackhole default remote (`overlay_blackhole`).
    configured_blackhole: Option<Ipv4Addr>,
    /// VTEP lifecycle.
    vxlan: Vxlan<satl_overlay::SystemRunner>,
    /// FDB and in-jail ARP.
    programmer: SystemProgrammer,
    /// ESP SAD/SPD programming (`setkey`), for encrypted networks.
    ipsec: satl_overlay::Ipsec,
    /// The pf cleartext guard and the enc0/IPsec substrate behind it.
    guard: crate::guard::Guard,
    /// The same node-local manager the executor drives: it owns the overlay
    /// bridge and the task epairs.
    net: Arc<NetworkManager>,
    /// The underlay probe (MTU and prefix).
    underlay: Underlay<satl_net::SystemRunner>,
    /// `jls`(8) wrapper: the periodic resync validates `state.local` against
    /// the prisons that actually exist (`docs/jail-teardown.md`).
    jails: Jails,
    /// What the DNS responder answers from, fed by [`spawn_dns_feed`].
    table: EndpointTable,
    /// Which networks each local task's queries are answered from, fed by the
    /// same walk.
    scopes: ScopeTable,
    /// The responder itself, rebound as this node's gateway set changes.
    dns: DnsSupervisor,
    /// Woken whenever an assignment changed something the DNS tables are
    /// built from; [`spawn_dns_feed`] rebuilds on it.
    dns_dirty: Arc<tokio::sync::Notify>,
    /// Whether the once-per-process post-snapshot sweep has run
    /// ([`OverlayManager::sweep_after_snapshot`]).
    swept: std::sync::atomic::AtomicBool,
    /// `kldload if_vxlan`, once per process.
    module: tokio::sync::OnceCell<()>,
    inner: tokio::sync::Mutex<Inner>,
}

impl std::fmt::Debug for OverlayManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayManager")
            .field("marker", &self.marker)
            .field("configured_blackhole", &self.configured_blackhole)
            .finish_non_exhaustive()
    }
}

impl OverlayManager {
    /// Build the programmer over the node-local network manager the executor
    /// also uses.
    ///
    /// The ARP mechanism is `satld` re-executing **itself**
    /// ([`ArpHelper::from_current_exe`]): an OCI image ships no usable `arp`(8)
    /// and `route -j` cannot install a link-layer entry, so the entry has to be
    /// written from a process that has entered the jail's VNET
    /// (`docs/vxlan.md` §4). Resolving the path here rather than per batch turns
    /// "the binary was replaced under a running daemon" into one start-up error.
    pub fn new(
        marker: String,
        configured_blackhole: Option<Ipv4Addr>,
        net: Arc<NetworkManager>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Arc<Self>> {
        let arp = ArpHelper::from_current_exe().map_err(|source| {
            anyhow::Error::new(source).context(
                "cannot resolve this executable's path, which is what the daemon \
                 re-executes to program a jail's ARP table",
            )
        })?;
        tracing::info!(
            arp_helper = %arp.command_line(),
            "overlay ARP helper resolved"
        );
        let table = EndpointTable::new();
        let scopes = ScopeTable::new();
        Ok(Arc::new(Self {
            marker: marker.clone(),
            configured_blackhole,
            vxlan: Vxlan::system().with_marker(marker),
            programmer: Programmer::system(arp),
            ipsec: satl_overlay::Ipsec::system(),
            guard: crate::guard::Guard::system(),
            net,
            underlay: Underlay::system(),
            jails: Jails::system(),
            table: table.clone(),
            scopes: scopes.clone(),
            dns: DnsSupervisor::new(table, scopes, shutdown),
            dns_dirty: Arc::new(tokio::sync::Notify::new()),
            swept: std::sync::atomic::AtomicBool::new(false),
            module: tokio::sync::OnceCell::new(),
            inner: tokio::sync::Mutex::new(Inner::default()),
        }))
    }

    /// Wakes the DNS feed: something an answer is built from changed.
    pub fn mark_dns_dirty(&self) {
        self.dns_dirty.notify_one();
    }

    /// The wake handle [`spawn_dns_feed`] sleeps on.
    #[must_use]
    pub fn dns_dirty(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.dns_dirty)
    }

    /// One endpoint record per (task, network) this node holds an assignment
    /// for — the DNS half of the dispatcher's endpoint tables (§11.5).
    ///
    /// Cluster-wide by construction: the table a manager ships covers every
    /// endpoint of the network, not just this node's, so a name resolves to
    /// replicas wherever they run. Networks this node holds no assignment for
    /// contribute nothing, which is exactly the set no local task could be
    /// answered from anyway (the scope table only admits a task's own
    /// networks).
    pub async fn dns_records(&self) -> Vec<satl_overlay::EndpointRecord> {
        let inner = self.inner.lock().await;
        inner
            .networks
            .values()
            .flat_map(|state| {
                state
                    .endpoints
                    .values()
                    .map(|endpoint| record_of(&state.network.id, endpoint))
            })
            .collect()
    }

    /// DNS for this node's bridge networks: endpoint records, and the source
    /// addresses their tasks' queries will carry.
    ///
    /// Neither the dispatcher's endpoint tables nor the store can supply these.
    /// A bridge network's addressing never reaches Raft (architecture §11.1),
    /// so the task objects carry no address and the assignment stream ships no
    /// endpoints; the node's own IPAM is the only source. That costs nothing in
    /// completeness, because every task on a node-local bridge *is* local by
    /// construction -- there is no remote peer whose endpoints could be missed.
    ///
    /// The record is derived exactly as the dispatcher derives an overlay one
    /// (`satl_dispatcher::manager`), field for field, so a service name means
    /// the same thing whichever driver answers it. The persisted status is
    /// canonical over the task's own copy (architecture §7.2), so it is what
    /// decides whether the endpoint is answered at all.
    ///
    /// Returns the records, and per task the addresses to add to its scope --
    /// without which the task's queries match no local task, are forwarded
    /// upstream, and come back `NXDOMAIN` (`satl_overlay::scopes`).
    pub async fn node_local_dns(
        &self,
        tasks: &[satl_agent::TaskRecord],
    ) -> (Vec<satl_overlay::EndpointRecord>, BTreeMap<Id, Vec<IpAddr>>) {
        let inner = self.inner.lock().await;
        if inner.node_local.is_empty() {
            return (Vec::new(), BTreeMap::new());
        }
        let network = self.net.local_network();
        let mut records = Vec::new();
        let mut scoped: BTreeMap<Id, Vec<IpAddr>> = BTreeMap::new();
        for record in tasks {
            let task = &record.task;
            let Some(addr) = self.net.address_of(network, task.id.as_str()) else {
                continue;
            };
            let mut on_bridge = false;
            for attachment in &task.networks {
                if !inner.node_local.contains(&attachment.network_id) {
                    continue;
                }
                on_bridge = true;
                records.push(satl_overlay::EndpointRecord {
                    network_id: attachment.network_id.clone(),
                    service_name: task.service_annotations.name.clone(),
                    task_name: task.annotations.name.clone(),
                    addresses: vec![IpAddr::V4(addr)],
                    aliases: attachment.aliases.clone(),
                    state: record.status.state,
                });
            }
            if on_bridge {
                scoped.insert(task.id.clone(), vec![IpAddr::V4(addr)]);
            }
        }
        (records, scoped)
    }

    /// Reconciles host overlay state against a `COMPLETE` snapshot's network
    /// set, **once per process** — the restarted-worker hole: interfaces a
    /// previous daemon programmed for networks this snapshot no longer
    /// mentions are invisible to the applier's own diff (it starts empty) and
    /// a worker has no store to sweep them from at startup, so the first
    /// snapshot is the earliest complete claim set. Once, because later
    /// snapshots race task attach: a task assigned right after the snapshot
    /// was cut would look like a leftover.
    pub async fn sweep_after_snapshot(
        &self,
        current: &[satl_dispatcher::assignment::NetworkAssignment],
    ) {
        if self.swept.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let node_id = {
            let inner = self.inner.lock().await;
            inner.identity.as_ref().map(|id| id.node_id.clone())
        };
        let Some(node_id) = node_id else {
            // No overlay identity means nothing was ever programmed by us and
            // nothing can be attributed; the resync loop retries nothing here.
            return;
        };
        let wanted: Vec<WantedNetwork> = current
            .iter()
            .filter(|assignment| assignment.network.spec.driver == NetworkDriver::Overlay)
            .map(|assignment| WantedNetwork {
                network: assignment.network.clone(),
                tasks: assignment
                    .endpoints
                    .values()
                    .filter(|endpoint| endpoint.is_local_to(&node_id))
                    .map(|endpoint| WantedTask {
                        task_id: endpoint.task_id.clone(),
                        jail: endpoint.task_id.as_str().to_owned(),
                        ip: endpoint.addr,
                    })
                    .collect(),
            })
            .collect();
        let report = self.reconcile_startup(wanted).await;
        if !report.destroyed_epairs.is_empty()
            || !report.destroyed_bridges.is_empty()
            || !report.destroyed_vteps.is_empty()
        {
            tracing::warn!(
                epairs = ?report.destroyed_epairs,
                bridges = ?report.destroyed_bridges,
                vteps = ?report.destroyed_vteps,
                "the first assignment snapshot exposed overlay leftovers from a previous run; \
                 destroyed"
            );
        }
    }

    /// The endpoint table the DNS responder answers from.
    pub fn table(&self) -> EndpointTable {
        self.table.clone()
    }

    /// The scope table that decides which networks a client may be answered
    /// from.
    pub fn scopes(&self) -> ScopeTable {
        self.scopes.clone()
    }

    /// Record the cluster identity this node is now programming overlays for,
    /// and measure the underlay behind `advertise_addr`.
    ///
    /// Called on **every** bring-up, before the agent can open a session, for
    /// the same reason `HostDescriber::set_data_addr` is: `swarm join` gives this
    /// node a different node id in a different cluster, and both the gateway
    /// lookup (`Network::node_gateways` is keyed by node id) and every VTEP's
    /// `vxlanlocal` depend on which cluster this is. A node id that *changed*
    /// means the previous cluster's overlays belong to nobody, so they are torn
    /// down here rather than left to leak until the next restart.
    ///
    /// Never fatal: a node that cannot measure its underlay still serves
    /// containers on the node-local bridge. The failure is recorded and every
    /// `apply_network` then fails with it, which is where an operator will look.
    pub async fn adopt_identity(&self, node_id: &Id, advertise_addr: Option<&str>) {
        let vtep = advertise_addr.and_then(underlay_address);
        let mut reason = NoIdentityReason::NotAdoptedYet;
        let identity = match vtep {
            None => {
                tracing::warn!(
                    node_id = %node_id,
                    "this node publishes no underlay address, so it can host no \
                     overlay network: set advertise_addr in satld.toml"
                );
                reason = NoIdentityReason::NoUnderlayAddress;
                None
            }
            Some(vtep) => match self.measure(node_id, vtep).await {
                Ok(identity) => Some(identity),
                Err(error) => {
                    // A degradation, not a failure, so it is warn and not error:
                    // this node keeps serving bridge networks and only refuses
                    // overlay ones (a task that wants no overlay is unaffected --
                    // see `attach`, which takes the identity per attachment for
                    // exactly this reason). Logging it at error would put a line
                    // in /var/log/messages that `grep ERROR` reports on a node
                    // working as designed, which is how an operator learns to
                    // ignore the errors that matter.
                    tracing::warn!(
                        node_id = %node_id,
                        vtep = %vtep,
                        %error,
                        "cannot measure this node's underlay, so it can host no \
                         overlay network; bridge networks are unaffected"
                    );
                    reason = NoIdentityReason::UnmeasurableUnderlay {
                        detail: error.to_string(),
                    };
                    None
                }
            },
        };

        let stale: Vec<Id> = {
            let mut inner = self.inner.lock().await;
            let changed = inner
                .identity
                .as_ref()
                .is_some_and(|current| current.node_id != *node_id);
            // Written as a pair, and this is the only place either is
            // assigned, so the reason can never describe a different identity
            // than the one beside it. `reason` is meaningless when `identity`
            // is `Some` and is never read then -- the attach path consults it
            // only on the `None` branch.
            inner.identity = identity;
            inner.no_identity = reason;
            if changed {
                tracing::warn!(
                    node_id = %node_id,
                    "this node joined a different cluster; tearing down the \
                     overlays of the previous one"
                );
                inner.networks.keys().cloned().collect()
            } else {
                Vec::new()
            }
        };
        for network_id in stale {
            if let Err(error) = self.remove_network(&network_id).await {
                tracing::error!(network_id = %network_id, %error, "cannot tear down a stale overlay");
            }
        }
    }

    /// Measure the underlay behind `vtep` and derive the blackhole from it.
    async fn measure(&self, node_id: &Id, vtep: Ipv4Addr) -> Result<Identity, OverlayError> {
        let underlay = self.underlay.facts(vtep).await?;
        let blackhole = match self.configured_blackhole {
            Some(configured) => {
                crate::underlay::check_blackhole(&underlay, configured)?;
                tracing::info!(
                    blackhole = %configured,
                    "using the configured overlay blackhole default remote"
                );
                configured
            }
            None => crate::underlay::blackhole_in(&underlay)?,
        };
        tracing::info!(
            iface = %underlay.iface,
            vtep = %vtep,
            prefix = %underlay.prefix,
            underlay_mtu = underlay.mtu,
            overlay_mtu = underlay.overlay_mtu(),
            blackhole = %blackhole,
            "underlay measured: overlay MTU is the underlay's minus 50, and the \
             blackhole default remote is the top host of the underlay prefix"
        );
        Ok(Identity {
            node_id: node_id.clone(),
            underlay,
            vtep,
            blackhole,
        })
    }

    /// `kldload -n if_vxlan`, once per process.
    ///
    /// Not load-bearing for correctness — `ifconfig` derives the module name
    /// from the clone name and loads it itself — but it turns "this kernel has
    /// no `if_vxlan` at all" into one start-up failure with a real message
    /// instead of a per-network one.
    async fn ensure_module(&self) -> Result<(), OverlayError> {
        // OnceCell::get_or_try_init would keep retrying a transient failure,
        // which is right here: a kldload that failed must not be remembered as
        // done.
        self.module
            .get_or_try_init(|| async {
                self.vxlan.ensure_module().await?;
                Ok::<(), OverlayError>(())
            })
            .await?;
        Ok(())
    }

    /// Bring this node's segment of one network to the desired state: the VTEP,
    /// then the bridge with this node's gateway on it.
    ///
    /// The order is the MTU rule: `man 4 bridge` gives the bridge the MTU of its
    /// **first** member, so the 1450-byte VTEP has to be added before any epair,
    /// and `ensure_overlay_segment` refuses to run at all until the VTEP exists
    /// and reports `RUNNING` — which is the only health signal vxlan(4) gives,
    /// since `ifconfig` exits 0 for an interface the driver refused
    /// (`docs/vxlan.md` §2 point 5).
    ///
    /// Idempotent, and it has to be: this runs on every assignment, on every
    /// task start and on every resync. See [`Self::ensure_vtep`] for the one
    /// thing that makes "just call `ensure_vtep` again" wrong.
    async fn ensure_segment(
        &self,
        state: &mut NetworkState,
        identity: &Identity,
    ) -> Result<OverlaySegment, OverlayError> {
        let mtu = segment_mtu(&state.network, &identity.underlay);
        let (segment, vni) = segment_of(&state.network, &identity.node_id, mtu)?;
        let name = segment.network.clone();

        // A blackhole that is a real peer makes a *missing* forwarding entry work
        // anyway, on that one peer, which is exactly how an FDB bug survives a
        // two-node test (docs/vxlan.md §2 point 4). The endpoint table is the
        // only list of peer VTEPs a node has, so it is checked here, on every
        // pass, rather than once at start-up: a node that joins later brings a
        // new VTEP address with it.
        check_blackhole_against_peers(state, identity)?;
        self.ensure_vtep(state, identity, &segment, vni, mtu)
            .await?;

        let bridge = self.net.ensure_overlay_segment(&segment).await?;
        tracing::debug!(
            network = %name,
            bridge = %bridge.bridge,
            gateway = %bridge.gateway,
            mtu = bridge.mtu,
            "overlay segment ready on this node"
        );
        state.ensured = true;
        Ok(segment)
    }

    /// Create the network's VTEP, or adopt and verify the one that is there.
    ///
    /// ## Why this is not `Vxlan::ensure_vtep`
    ///
    /// `Vxlan::ensure_vtep` does create-or-adopt and then sets the MTU
    /// **unconditionally**. That is safe exactly once: from the moment
    /// `ensure_overlay_segment` has made the VTEP a member of the overlay bridge,
    /// setting its MTU fails — `sys/net/if.c` returns `EOPNOTSUPP` for any bridge
    /// member before it even looks at the value, so *even setting the MTU it
    /// already has* fails (`docs/vxlan.md` §5, "a member's MTU is not
    /// 'automatic', it is unsettable"). Measured here, in the first cluster run
    /// of this wiring: the second pass over a live network failed with
    ///
    /// ```text
    /// ifconfig: ioctl SIOCSIFMTU (set mtu): Operation not supported
    /// ```
    ///
    /// and took every task on the network down with it, because an attach that
    /// cannot program the overlay must not start the container.
    ///
    /// So the MTU is set here **only on the interface this call created**, while
    /// it is still memberless. Afterwards it belongs to the bridge:
    /// `ensure_overlay_segment` sets the *bridge's* MTU on every pass, which
    /// `man 4 bridge` propagates to every member, and then reads it back off the
    /// VTEP. Which is exactly the division `docs/vxlan.md` §5's table prescribes —
    /// "a member at 1450: nothing. Set the bridge; never the member".
    ///
    /// Nothing is lost by not calling `ensure_vtep`: identity is verified here
    /// against `VXLAN_CMD_GET_CONFIG` (through `ifconfig`), health is verified
    /// with `RUNNING` — the only signal vxlan(4) gives, since `ifconfig` exits 0
    /// for an interface the driver refused — and the MTU is verified by
    /// `satl-net`, on both the bridge and the VTEP.
    async fn ensure_vtep(
        &self,
        state: &mut NetworkState,
        identity: &Identity,
        segment: &OverlaySegment,
        vni: u32,
        mtu: u32,
    ) -> Result<(), OverlayError> {
        let iface = segment.vtep.as_str();
        // Encrypted networks get their allocator-assigned VXLAN port
        // (`segment_of` has already refused an encrypted network without
        // one); everything else stays on the IANA default 4789, which is
        // also what `None` means on a pre-feature VTEP being adopted.
        let spec = VtepSpec::new(vni, identity.vtep, identity.blackhole).with_mtu(mtu);
        let spec = match state.network.vxlan_port {
            Some(port) if state.network.spec.encrypted => spec.with_vxlan_port(port),
            _ => spec,
        };
        let want_port = spec.vxlan_port.unwrap_or(satl_overlay::VXLAN_PORT);

        if self.vxlan.exists(iface).await? {
            self.check_adoptable(identity, segment, vni, want_port)
                .await?;
            // The kernel offers no unit-to-name mapping, so an adopted interface
            // needs its clone unit probed for before its table can be read back.
            if state.unit.is_none() {
                state.unit = self.resolve_unit(iface).await;
            }
        } else {
            self.ensure_module().await?;
            // create + rename as one step: a crash in between leaves a `vxlanN`
            // clone with no ownership marker that no sweep can attribute.
            let created = self.vxlan.create_vtep(&spec, iface).await?;
            // Memberless, and this is the only moment it is: set the MTU now.
            self.vxlan.set_mtu(iface, mtu).await?;
            tracing::info!(
                network = %segment.network,
                vni,
                iface = %created.name,
                unit = created.unit,
                local = %identity.vtep,
                blackhole = %identity.blackhole,
                vxlan_port = want_port,
                mtu,
                "created the network's VTEP"
            );
            state.unit = Some(created.unit);
        }

        // Both are idempotent and both are permitted on a bridge member.
        self.vxlan
            .set_descr(
                iface,
                &satl_overlay::vtep_descr(self.vxlan.marker(), &segment.network),
            )
            .await?;
        self.vxlan.up(iface).await?;
        let flags = self.vxlan.verify_running(iface).await?;
        if flags.mtu != mtu {
            // Not an error: the bridge owns a member's MTU and
            // `ensure_overlay_segment` is about to set and verify it.
            tracing::info!(
                iface = %iface,
                found = flags.mtu,
                want = mtu,
                "adopted VTEP has the wrong MTU; the bridge will propagate the \
                 right one (a member's MTU cannot be set directly)"
            );
        }
        Ok(())
    }

    /// Refuse an existing VTEP whose VNI, local address, default remote or
    /// VXLAN port is not the one this network needs.
    ///
    /// Deliberately a refusal rather than a reconfiguration: changing a live
    /// VTEP's VNI or local address blackholes every task attached to it, and
    /// silently repointing a tunnel is worse than saying so.
    async fn check_adoptable(
        &self,
        identity: &Identity,
        segment: &OverlaySegment,
        vni: u32,
        want_port: u16,
    ) -> Result<(), OverlayError> {
        let iface = segment.vtep.as_str();
        let Some(config) = self.vxlan.vtep_config(iface).await? else {
            return Err(OverlayError::NotReady {
                network: segment.network.clone(),
                reason: format!("interface '{iface}' exists but is not a vxlan interface"),
            });
        };
        let mismatches =
            adoption_mismatches(&config, vni, identity.vtep, identity.blackhole, want_port);
        if mismatches.is_empty() {
            tracing::debug!(iface = %iface, network = %segment.network, "adopted existing VTEP");
            return Ok(());
        }
        Err(OverlayError::NotReady {
            network: segment.network.clone(),
            reason: format!(
                "its VTEP '{iface}' cannot be adopted: {}. Destroy it by hand if \
                 it is a leftover; SatL will not repoint a live tunnel",
                mismatches.join("; ")
            ),
        })
    }

    /// Probe for an adopted VTEP's clone unit, logging rather than failing: a
    /// missing unit costs the read-back (and therefore the removal of stale
    /// entries), not the ability to install the entries this node needs.
    async fn resolve_unit(&self, iface: &str) -> Option<u32> {
        match self
            .programmer
            .reader()
            .resolve_unit(&Ftable::new(), iface)
            .await
        {
            Ok(unit) => {
                tracing::info!(iface = %iface, unit, "resolved the adopted VTEP's clone unit");
                Some(unit)
            }
            Err(error) => {
                tracing::error!(
                    iface = %iface,
                    %error,
                    "cannot resolve the adopted VTEP's clone unit, so its \
                     forwarding table cannot be read back: entries will be \
                     pushed blind and stale ones will survive until the \
                     interface is re-created"
                );
                None
            }
        }
    }

    /// Push the forwarding and ARP tables of one network to what the endpoint
    /// table says they should be.
    ///
    /// The desired state is a pure function of the assignment plus this node's
    /// attachments; the reconciler diffs it against the kernel and applies only
    /// the difference. Note what goes where, because the asymmetry is the whole
    /// design (`docs/vxlan.md` §7): an FDB entry per **remote** endpoint, once
    /// per node, and an ARP entry per endpoint in **every local jail**, because
    /// each jail has its own stack.
    async fn reconcile_tables(
        &self,
        state: &mut NetworkState,
        identity: &Identity,
        segment: &OverlaySegment,
    ) -> Result<(), OverlayError> {
        let desired = DesiredOverlay::new(segment.vtep.clone(), identity.vtep)
            // Which ARP entries in a shared jail are this network's: a task on
            // two overlays has one VNET and therefore one ARP table, and
            // without the subnet each network's pass deletes the other's
            // entries (`satl_overlay::DesiredOverlay::subnet`).
            .with_subnet(segment.subnet)
            .with_local(
                state
                    .local
                    .values()
                    .map(|attached| LocalEndpoint::new(attached.jail.clone(), attached.ip)),
            )
            .with_remote(
                state
                    .endpoints
                    .values()
                    .filter(|endpoint| !endpoint.is_local_to(&identity.node_id))
                    .map(|endpoint| RemoteEndpoint::new(endpoint.addr, endpoint.vtep))
                    // The load-balancer attachments (M6d): every OTHER node's
                    // gateway on this network is a remote endpoint as far as the
                    // kernel tables are concerned — an FDB entry so its frames
                    // reach its VTEP, an ARP entry in every local jail so a task
                    // can answer traffic relayed through it (a non-flooding
                    // VXLAN has no cross-node broadcast ARP — measured in
                    // hack/experiments/mesh). The node's own gateway is filtered
                    // out: its VTEP is this node's, and a self-pointing FDB
                    // entry would loop.
                    .chain(
                        state
                            .gateways
                            .values()
                            .filter(|gateway| gateway.node_id != identity.node_id)
                            .map(|gateway| RemoteEndpoint::new(gateway.addr, gateway.vtep)),
                    ),
            );

        let applied = if let Some(unit) = state.unit {
            self.programmer.reconcile(&desired, unit).await?
        } else {
            // No unit means no read-back. Diffing against an empty state pushes
            // everything: `add` on an entry that is already there comes back
            // `EEXIST` and the applier repoints it instead, and `arp -s`
            // overwrites, so this converges — it just cannot *remove* anything.
            tracing::warn!(
                network = %segment.network,
                iface = %segment.vtep,
                "pushing the overlay tables without a read-back: the VTEP's \
                 clone unit is unknown, so stale entries cannot be removed"
            );
            self.programmer
                .apply(&satl_overlay::OverlayDelta::between(
                    &desired,
                    &satl_overlay::ProgrammedState::empty(),
                ))
                .await
        };
        tracing::debug!(
            network = %segment.network,
            iface = %segment.vtep,
            local = state.local.len(),
            endpoints = state.endpoints.len(),
            applied = %applied.summary(),
            "overlay data plane reconciled"
        );
        if applied.ftable_flushed {
            tracing::warn!(
                network = %segment.network,
                "the whole forwarding table had to be flushed and re-pushed: \
                 this network has more endpoints on this node than the dump \
                 sysctl can report (about 81), so every pass will do the same"
            );
        }
        if !applied.is_complete() {
            return Err(OverlayError::Partial {
                network: segment.network.clone(),
                failures: applied.failures.join("; "),
            });
        }
        if state.network.spec.ingress {
            self.reconcile_host_arp(state, identity).await;
        }
        Ok(())
    }

    /// The third table the mesh needs (M6d): static ARP entries in the
    /// **host's** table for the ingress network's remote task addresses.
    ///
    /// A node relaying mesh traffic forwards to a task address through its
    /// own stack, and for a task on another node the ARP reply never arrives
    /// — the VXLAN never floods, so the request goes to the blackhole remote.
    /// The relaying node must therefore carry a static entry per remote task
    /// (measured in `hack/experiments/mesh`). Local tasks need none: their
    /// ARP is answered on the local bridge segment directly. Level-triggered,
    /// like the FDB: the desired set is recomputed from the endpoint table
    /// every pass, vanished endpoints' entries are deleted, and a failure is
    /// a warning rather than a failed pass — a missing entry breaks relaying
    /// to that one task, and the next pass retries.
    async fn reconcile_host_arp(&self, state: &mut NetworkState, identity: &Identity) {
        let desired: BTreeMap<Ipv4Addr, satl_core::MacAddr> = state
            .endpoints
            .values()
            .filter(|endpoint| !endpoint.is_local_to(&identity.node_id))
            .map(|endpoint| (endpoint.addr, endpoint.mac()))
            .collect();
        let arp = satl_net::Arp::system();
        let vanished: Vec<Ipv4Addr> = state
            .host_arp
            .keys()
            .filter(|addr| !desired.contains_key(*addr))
            .copied()
            .collect();
        for addr in vanished {
            match arp.delete(addr).await {
                Ok(()) => {
                    state.host_arp.remove(&addr);
                }
                Err(error) => {
                    tracing::warn!(%addr, %error, "deleting a stale host ARP entry failed");
                }
            }
        }
        for (addr, mac) in desired {
            if state.host_arp.get(&addr) == Some(&mac) {
                continue;
            }
            match arp.set(addr, mac).await {
                Ok(()) => {
                    state.host_arp.insert(addr, mac);
                }
                Err(error) => {
                    tracing::warn!(%addr, %mac, %error, "installing a host ARP entry failed");
                }
            }
        }
    }

    /// Reconcile the node-wide data-plane security state: the SAD/SPD against
    /// the **full** desired view of every encrypted network this node holds,
    /// and the pf cleartext guard against "at least one encrypted network".
    ///
    /// Runs in the same pass as the dataplane reconcile, from three places:
    /// [`Self::apply_network`] (the assignment stream — a key rotation lands
    /// here too, because the keyring travels on the network object, so a
    /// keys-only change reconciles with no endpoint change),
    /// [`Self::remove_network`] (teardown is an absence in the next full
    /// view), and the periodic [`Self::resync`] safety net. It never fails
    /// its caller: a missed pass is retried from all three.
    ///
    /// Key material flows through here (the desired view carries the
    /// keyrings): it goes to `setkey -c` and nowhere else — every log line
    /// below logs counts, and `satl_overlay`'s own logging of a batch is the
    /// redacted form.
    async fn reconcile_security(&self) {
        let inner = self.inner.lock().await;
        let Some(identity) = inner.identity.clone() else {
            return;
        };
        let view = desired_security(&inner.networks, &identity.node_id);
        for pending in &view.pending {
            // Info, like the "recorded but not programmed yet" dataplane
            // case: an operator watching a network come up should see why
            // its encryption has not yet.
            tracing::info!(
                network = %pending.network,
                reason = %pending.reason,
                "encrypted overlay recorded but not securable yet"
            );
        }
        if let Err(error) = self.reconcile_ipsec(identity.vtep, &view.ready).await {
            tracing::error!(
                %error,
                "cannot reconcile the overlay IPsec state; the next pass will retry"
            );
        }
        let guard_wanted = inner
            .networks
            .values()
            .any(|state| state.network.spec.encrypted);
        self.guard
            .reconcile(guard_wanted, &identity.underlay.iface)
            .await;
    }

    /// Diff the full desired view against the kernel's SAD/SPD and apply the
    /// plan as one `setkey -c` batch. The kernel read-back is first reduced
    /// to the entries SatL manages ([`satl_managed_present`]) so a
    /// third-party `IPsec` user on the same node is never planned against.
    async fn reconcile_ipsec(
        &self,
        me: Ipv4Addr,
        desired: &[satl_overlay::PeerSecurity],
    ) -> Result<(), satl_overlay::IpsecError> {
        let present = satl_overlay::PresentSecurity {
            sas: self.ipsec.sas().await?,
            sps: self.ipsec.sps().await?,
        };
        let present = satl_managed_present(me, desired, &present);
        let plan = satl_overlay::plan_security(me, desired, &present);
        if plan.is_empty() {
            tracing::debug!(
                peers = desired.len(),
                "overlay IPsec state already matches the desired view"
            );
            return Ok(());
        }
        // Counts only, and only ever counts: the plan's adds carry key
        // material, which must not reach a log line in any form.
        let mut counts = [0_usize; 4];
        for op in &plan.ops {
            match op {
                satl_overlay::SecurityOp::AddSa { .. } => counts[0] += 1,
                satl_overlay::SecurityOp::AddSp(_) => counts[1] += 1,
                satl_overlay::SecurityOp::RemoveSp(_) => counts[2] += 1,
                satl_overlay::SecurityOp::RemoveSa(_) => counts[3] += 1,
            }
        }
        self.ipsec.apply(&plan).await?;
        tracing::info!(
            peers = desired.len(),
            sas_added = counts[0],
            sps_added = counts[1],
            sps_removed = counts[2],
            sas_removed = counts[3],
            "overlay IPsec state reconciled"
        );
        Ok(())
    }

    /// A network one of this node's tasks attaches to was assigned, or its
    /// endpoint table changed: program (or re-program) it.
    ///
    /// **Idempotent and reconciling, not incremental.** This is called again on
    /// every endpoint change anywhere in the cluster — that is how an FDB update
    /// reaches a node — and again for every network of every `COMPLETE`
    /// snapshot, so it must never flap a live overlay. It adopts the VTEP and the
    /// bridge, repairs their markers, MTU and gateway address, and applies only
    /// the forwarding and ARP entries that differ.
    ///
    /// A network the allocator has not finished (no VNI, no subnet, or no
    /// gateway for *this* node) is **recorded and not programmed**: the endpoint
    /// table is kept so that nothing is lost, and the next shipment — which the
    /// gateway's arrival itself triggers, since it changes the network object —
    /// completes the job.
    #[tracing::instrument(
        skip_all,
        fields(
            network_id = %assignment.network.id,
            network = %network_name(&assignment.network),
            endpoints = assignment.endpoints.len(),
        )
    )]
    pub async fn apply_network(&self, assignment: NetworkAssignment) -> Result<(), OverlayError> {
        if !is_overlay(&assignment.network) {
            tracing::debug!("not an overlay network; nothing to program on this node");
            {
                let mut inner = self.inner.lock().await;
                inner.node_local.insert(assignment.network.id);
            }
            // Nothing to program, but the responder still has to learn that
            // this node now carries a bridge network: its gateway is where
            // those tasks' `resolv.conf` points (M11b). Before this the
            // refresh only ran on the overlay path, so a node hosting bridge
            // networks alone -- every node whose underlay cannot be measured,
            // and any single-node install -- never bound a DNS socket at all.
            self.refresh_dns().await;
            return Ok(());
        }
        let (network_id, identity) = {
            let mut inner = self.inner.lock().await;
            let identity = inner
                .identity
                .clone()
                .ok_or_else(|| OverlayError::NoIdentity {
                    reason: inner.no_identity.clone(),
                })?;
            let network_id = assignment.network.id.clone();
            let state = inner
                .networks
                .entry(network_id.clone())
                .or_insert_with(|| NetworkState {
                    network: assignment.network.clone(),
                    endpoints: BTreeMap::new(),
                    gateways: BTreeMap::new(),
                    host_arp: BTreeMap::new(),
                    local: BTreeMap::new(),
                    unit: None,
                    ensured: false,
                });
            state.network = assignment.network;
            state.endpoints = assignment.endpoints;
            state.gateways = assignment.gateways;
            (network_id, identity)
        };
        // The security state goes in BEFORE the dataplane: on the very first
        // shipment of an encrypted network, programming the VTEP first would
        // leave a window with a live tunnel but no pf cleartext guard (the
        // guard is inbound-only, but an encrypted segment must never have a
        // moment without it). The reconcile works from the full recorded
        // view, so the network had to be entered above first — and a keyring
        // that arrived with this shipment is reconciled here too.
        self.reconcile_security().await;
        let outcome = {
            let mut inner = self.inner.lock().await;
            // Recorded just above; a removal in between simply means there is
            // nothing left to program.
            let Some(state) = inner.networks.get_mut(&network_id) else {
                return Ok(());
            };
            self.program(state, &identity).await
        };
        // Outside the per-network critical section: binding a socket is not
        // part of it either — the bind list is recomputed from the map under
        // its own lock.
        self.refresh_dns().await;
        outcome
    }

    /// Ensure the segment and reconcile the tables of one network, tolerating
    /// "the allocator has not got there yet".
    async fn program(
        &self,
        state: &mut NetworkState,
        identity: &Identity,
    ) -> Result<(), OverlayError> {
        match self.ensure_segment(state, identity).await {
            Ok(segment) => self.reconcile_tables(state, identity, &segment).await,
            Err(error @ OverlayError::NotReady { .. }) => {
                // Not a failure: the endpoint table is recorded and the next
                // shipment programs it. Logged at info because an operator
                // watching a network come up should see why it has not yet.
                tracing::info!(%error, "overlay network recorded but not programmed yet");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The last task attached to this network left, or the network is gone: tear
    /// this node's segment down.
    ///
    /// Called **after** the tasks that were attached have been released
    /// (`ObjectRef::teardown_rank`), so the bridge should have no epair of ours
    /// left on it. The bridge goes first and the VTEP second: `destroy_overlay_segment`
    /// detaches the VTEP from the bridge and deliberately never destroys it,
    /// because `satl-overlay` owns its lifecycle — this is the only place that does.
    #[tracing::instrument(skip_all, fields(network_id = %id))]
    pub async fn remove_network(&self, id: &Id) -> Result<(), OverlayError> {
        let state = {
            let mut inner = self.inner.lock().await;
            inner.node_local.remove(id);
            let Some(state) = inner.networks.remove(id) else {
                tracing::debug!("no overlay state for this network on this node");
                return Ok(());
            };
            state
        };
        let name = network_name(&state.network).to_owned();
        if !state.local.is_empty() {
            tracing::warn!(
                network = %name,
                tasks = state.local.len(),
                "tearing down an overlay segment that still records local \
                 attachments: their epairs go with the bridge"
            );
        }

        // The teardown is the sweep, run against the networks that are left.
        // Sharing one path with startup reconciliation is deliberate: a bridge
        // and a VTEP are destroyed for exactly one reason — no network of that
        // name is wanted here any more — and two code paths deciding that
        // independently is how one of them ends up wrong.
        let result = self.sweep().await;
        self.table.remove_network(id);
        // The network is gone from the full view, so its SAs/SPs are planned
        // for deletion here; when it was the last encrypted network, the
        // cleartext guard goes with it.
        self.reconcile_security().await;
        self.refresh_dns().await;
        result.map(|report| {
            if report.destroyed_anything() {
                tracing::info!(network = %name, report = %report.summary(), "overlay torn down");
            }
        })
    }

    /// Recompute the responder's bind list from every network this node has a
    /// gateway on, and rebind if it changed.
    async fn refresh_dns(&self) {
        let binds = {
            let inner = self.inner.lock().await;
            let mut binds = match inner.identity.as_ref() {
                // No overlay identity is not "no DNS": a node whose underlay
                // cannot be measured hosts no overlay but still runs bridge
                // networks, and their tasks need service names just as much
                // (M11b). Only the overlay half is skipped.
                None => BTreeMap::new(),
                Some(identity) => gateway_binds(&inner, &identity.node_id),
            };
            if let Some(gateway) = self.node_bridge_bind(&inner) {
                binds.insert(gateway, BindOwner::NodeBridge);
            }
            binds
        };
        self.dns.set_binds(binds).await;
    }

    /// The node-local bridge's gateway, when it should be answering.
    ///
    /// Two conditions, and both matter. **A bridge network must have been
    /// shipped here**, or the responder would bind an address nothing queries
    /// and a node that only ever runs overlays would grow a socket it does not
    /// need. And **the gateway must already exist**, because `DnsServer::bind`
    /// reports a failure to its caller instead of retrying, so offering it an
    /// address that is not on an interface yet takes the whole responder down —
    /// including the overlay sockets that were working. `local_gateway` answers
    /// `Some` only after `ensure_host_network` put the address on the bridge,
    /// which is exactly the permission to try.
    fn node_bridge_bind(&self, inner: &Inner) -> Option<Ipv4Addr> {
        if inner.node_local.is_empty() {
            return None;
        }
        self.net.local_gateway()
    }

    /// Destroy every overlay interface on this node that no wanted network
    /// claims, and adopt the rest.
    ///
    /// Three kinds of interface, three rules
    /// (`docs/networking.md`, "Ownership markers"):
    ///
    /// - an **epair** whose `(network, task)` is not wanted here is destroyed —
    ///   the epair-leak gotcha, which for an overlay also leaves members on a
    ///   bridge;
    /// - a **bridge** whose network is not wanted here is destroyed, after the
    ///   VTEP has been detached from it;
    /// - a **VTEP** whose network is not wanted here is destroyed, and this is the
    ///   only place that destroys one: `satl-net` classifies them precisely so
    ///   that none of its own teardown paths can.
    ///
    /// **Never destroy an interface SatL does not own.** Ownership is the
    /// interface description; a description that carries the marker in a shape
    /// this version does not understand classifies as unowned, and unowned means
    /// untouched. That is what lets an older daemon coexist with a marker form
    /// added later, and it is asserted in `satl-net`'s `classify_marker` tests
    /// and in `Vxlan::list_owned`.
    async fn sweep(&self) -> Result<SweepReport, OverlayError> {
        let desired: BTreeMap<String, BTreeSet<String>> = {
            let inner = self.inner.lock().await;
            inner
                .networks
                .values()
                .map(|state| {
                    (
                        network_name(&state.network).to_owned(),
                        state
                            .local
                            .keys()
                            .map(|task_id| task_id.as_str().to_owned())
                            .collect(),
                    )
                })
                .collect()
        };

        let swept = self.net.sweep_overlay(&desired).await?;
        let mut report = SweepReport {
            destroyed_epairs: swept.destroyed_epairs,
            destroyed_bridges: swept.destroyed_bridges,
            destroyed_vteps: Vec::new(),
            adopted_epairs: swept.adopted_epairs.len(),
            adopted_bridges: swept.adopted_bridges.len(),
        };

        // VTEPs after the bridges, so a VTEP is never destroyed while it is
        // still a member of one.
        for owned in self.vxlan.list_owned().await? {
            let Some(network) = owned.network.as_deref() else {
                // Marked by SatL but not in the `<group>:vxlan:<network>` shape:
                // another component's marker, or a convention from a future
                // version. Unattributable means untouched.
                tracing::warn!(
                    iface = %owned.name,
                    descr = %owned.descr,
                    "vxlan interface carries a SatL marker this version cannot \
                     attribute to a network; leaving it alone"
                );
                continue;
            };
            if desired.contains_key(network) {
                continue;
            }
            if self.vxlan.destroy_if_exists(&owned.name).await? {
                tracing::warn!(
                    iface = %owned.name,
                    network = %network,
                    "destroyed the VTEP of an overlay network with no local task"
                );
                report.destroyed_vteps.push(owned.name);
            }
        }
        Ok(report)
    }

    /// The overlay attachments of `task`, in spec order, paired with the
    /// address the allocator gave the task on each.
    ///
    /// A bridge attachment is skipped here: it is node-local and belongs to
    /// `satl_net::NetworkManager`. A network this node was never given is an
    /// error, because the dispatcher ships networks before the tasks that use
    /// them, so its absence means the stream was interrupted.
    async fn overlay_attachments(&self, task: &Task) -> Result<Vec<Planned>, OverlayError> {
        let inner = self.inner.lock().await;
        let mut out = Vec::new();
        for attachment in &task.networks {
            let network_id = attachment.network_id.clone();
            if inner.node_local.contains(&network_id) {
                // A node-local bridge network: `satl_net::NetworkManager` owns it,
                // and it is recorded here only so that this decision is made from
                // the network's *driver* rather than guessed from the absence of
                // an address.
                continue;
            }
            let Some(state) = inner.networks.get(&network_id) else {
                out.push(Planned::Unknown { network_id });
                continue;
            };
            let Some(ip) = attachment
                .addresses
                .iter()
                .filter_map(|text| text.parse::<Ipv4Cidr>().ok())
                .map(Ipv4Cidr::addr)
                .next()
            else {
                return Err(OverlayError::NotReady {
                    network: network_name(&state.network).to_owned(),
                    reason: format!(
                        "task {} has no usable IPv4 address on it, so it has no \
                         endpoint to program",
                        task.id
                    ),
                });
            };
            out.push(Planned::Overlay { network_id, ip });
        }
        Ok(out)
    }

    /// Attach one jail to one overlay network, then reconcile that network's
    /// tables so the new jail learns every peer.
    async fn attach_one(
        &self,
        network_id: &Id,
        task_id: &Id,
        jail: &str,
        ip: Ipv4Addr,
    ) -> Result<(), OverlayError> {
        let mut inner = self.inner.lock().await;
        let identity = inner
            .identity
            .clone()
            .ok_or_else(|| OverlayError::NoIdentity {
                reason: inner.no_identity.clone(),
            })?;
        let state =
            inner
                .networks
                .get_mut(network_id)
                .ok_or_else(|| OverlayError::UnknownNetwork {
                    task_id: task_id.clone(),
                    network_id: network_id.clone(),
                })?;

        // 1 + 2. The VTEP, then the bridge with this node's gateway on it.
        let segment = self.ensure_segment(state, &identity).await?;

        // 3. The epair. `attach_task_overlay` sets the derived MAC and the
        //    overlay MTU on both ends *before* `addm` — a bridge member's MTU
        //    cannot be set at all afterwards — and reads both ends back,
        //    including inside the jail, where nothing propagates.
        //    No default route: see this module's docs.
        let attach = OverlayAttach::new(task_id.as_str(), jail, ip);
        let attachment = match state.local.get(task_id) {
            // Adopted from a previous process by the startup sweep: the epair is
            // already in the jail with the right MAC and MTU, and re-creating it
            // would flap a live container's connectivity for nothing.
            Some(existing) if !existing.epairs.is_empty() => {
                tracing::info!(
                    network = %segment.network,
                    task_id = %task_id,
                    epairs = ?existing.epairs,
                    "adopted an overlay epair that survived the daemon"
                );
                None
            }
            _ => Some(self.net.attach_task_overlay(&segment, &attach).await?),
        };
        if let Some(attachment) = attachment {
            state.local.insert(
                task_id.clone(),
                Attached {
                    jail: jail.to_owned(),
                    ip,
                    epairs: vec![attachment.epair_a.clone(), attachment.epair_b.clone()],
                },
            );
        } else if let Some(existing) = state.local.get_mut(task_id) {
            // The jail name and address are the authoritative ones now.
            jail.clone_into(&mut existing.jail);
            existing.ip = ip;
        }

        // 4. The forwarding table and this jail's ARP entries.
        self.reconcile_tables(state, &identity, &segment).await
    }

    /// Wait, briefly, for a network to become programmable on this node.
    ///
    /// See [`PROGRAMMABLE_WAIT`]: the gateway address is allocated when the
    /// node's first task is *scheduled* there, so the first shipment of a network
    /// can arrive before the allocator has filled it in. Polling here converts a
    /// one-pass control-plane lag into a slightly slower container start instead
    /// of a rejected task, and still fails loudly if the state never arrives.
    async fn wait_programmable(&self, network_id: &Id, node_id: &Id) {
        let deadline = tokio::time::Instant::now() + PROGRAMMABLE_WAIT;
        loop {
            {
                let inner = self.inner.lock().await;
                let ready = inner
                    .networks
                    .get(network_id)
                    .is_some_and(|state| segment_of(&state.network, node_id, 1500).is_ok());
                if ready {
                    return;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    network_id = %network_id,
                    waited_secs = PROGRAMMABLE_WAIT.as_secs(),
                    "the overlay network is still not programmable on this node; \
                     attaching anyway so the real reason is reported"
                );
                return;
            }
            tokio::time::sleep(PROGRAMMABLE_POLL).await;
        }
    }

    /// Re-reconcile one network after a task left it, logging rather than
    /// failing: the caller is a cleanup path.
    async fn reconcile_after_detach(&self, network_id: &Id) {
        let mut inner = self.inner.lock().await;
        let Some(identity) = inner.identity.clone() else {
            return;
        };
        let Some(state) = inner.networks.get_mut(network_id) else {
            return;
        };
        if !state.ensured {
            return;
        }
        let mtu = segment_mtu(&state.network, &identity.underlay);
        let Ok((segment, _vni)) = segment_of(&state.network, &identity.node_id, mtu) else {
            return;
        };
        if let Err(error) = self.reconcile_tables(state, &identity, &segment).await {
            tracing::warn!(
                network_id = %network_id,
                %error,
                "could not reconcile the overlay after a task detached; the \
                 periodic resync will retry"
            );
        }
    }

    /// Detach every local attachment whose jail is gone.
    ///
    /// `state.local` is written at attach time and removed on the controller's
    /// detach paths, but those paths are exactly what a container that dies
    /// before its first healthcheck can miss — and the leftover entry is not
    /// inert: it makes this node claim the address as **local**, so once the
    /// allocator has handed it to a replacement on another node the endpoint
    /// reads "both local and remote" and the FDB pass refuses to program it
    /// (the measured ~1/3 traffic loss, B1). `jls -d` is the source of truth
    /// for "the prison exists" (`docs/jail-teardown.md`); a jail with no row
    /// at all is gone.
    async fn detach_dead_attachments(&self) {
        let live: BTreeSet<String> = match self.jails.list().await {
            // Dying prisons stay in the set: their teardown is already running
            // and detaches them; this sweep is for the deaths no path saw.
            Ok(jails) => jails.into_iter().map(|(name, _)| name).collect(),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "cannot list this node's jails; skipping the dead-attachment sweep"
                );
                return;
            }
        };
        let orphaned = {
            let inner = self.inner.lock().await;
            orphaned_attachments(&inner.networks, &live)
        };
        for task_id in orphaned {
            tracing::warn!(
                task_id = %task_id,
                "detaching an overlay attachment whose jail is gone"
            );
            self.detach(&task_id).await;
        }
    }

    /// Re-reconcile every network. The safety net behind the assignment stream
    /// ([`RESYNC_INTERVAL`]).
    async fn resync(&self) {
        self.detach_dead_attachments().await;
        let ids: Vec<Id> = {
            let inner = self.inner.lock().await;
            inner.networks.keys().cloned().collect()
        };
        for network_id in ids {
            let mut inner = self.inner.lock().await;
            let Some(identity) = inner.identity.clone() else {
                return;
            };
            let Some(state) = inner.networks.get_mut(&network_id) else {
                continue;
            };
            if let Err(error) = self.program(state, &identity).await {
                tracing::warn!(
                    network_id = %network_id,
                    %error,
                    "periodic overlay resync failed; retrying next interval"
                );
            }
        }
        // The safety net behind a security pass that failed halfway too: a
        // rotation lands on the assignment stream, but a node that missed it
        // converges here within one interval.
        self.reconcile_security().await;
        self.refresh_dns().await;
    }

    /// Startup reconciliation: adopt what survived the daemon, destroy what
    /// leaked.
    ///
    /// `wanted` is what the **store** says this node should be running — one
    /// entry per overlay network with a live local task, carrying the network
    /// object and each task's address. It is seeded into the per-network map so
    /// that:
    ///
    /// - the sweep knows which bridges, epairs and VTEPs to keep;
    /// - a container that survived the restart keeps its epair (adopted, never
    ///   re-created — re-creating it would flap a live connection), and its jail
    ///   is back in the desired state, so the next pass programs its ARP table
    ///   again. Nothing else would do that: a re-attached task never runs
    ///   `start`, so `attach` is never called for it;
    /// - the first assignment for the network then only has to fill in the
    ///   endpoint table.
    ///
    /// Networks already in the map are **kept**: the agent session can beat this
    /// pass to the first assignment, and a bridge that `apply_network` just
    /// created must not be swept because a follower's store view lagged behind
    /// the manager that shipped it.
    pub async fn reconcile_startup(&self, wanted: Vec<WantedNetwork>) -> SweepReport {
        // Discover the epairs that survived, so an adopted task's ends are known
        // and a later detach does not have to guess them.
        let mut survivors: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        match self.net.list_owned().await {
            Ok(owned) => {
                for iface in owned {
                    if let OwnedKind::OverlayTask { network, task_id } = iface.kind {
                        survivors
                            .entry((network, task_id))
                            .or_default()
                            .push(iface.name);
                    }
                }
            }
            Err(error) => tracing::error!(
                %error,
                "cannot list this node's interfaces; overlay epairs that survived \
                 the daemon cannot be adopted and will be re-created"
            ),
        }

        {
            let mut inner = self.inner.lock().await;
            for network in wanted {
                let name = network_name(&network.network).to_owned();
                let state = inner
                    .networks
                    .entry(network.network.id.clone())
                    .or_insert_with(|| NetworkState {
                        network: network.network.clone(),
                        endpoints: BTreeMap::new(),
                        // The startup seed has no assignment yet; the first
                        // shipment fills this in (its endpoints likewise).
                        gateways: BTreeMap::new(),
                        host_arp: BTreeMap::new(),
                        local: BTreeMap::new(),
                        unit: None,
                        ensured: false,
                    });
                for task in network.tasks {
                    let epairs = survivors
                        .get(&(name.clone(), task.task_id.as_str().to_owned()))
                        .cloned()
                        .unwrap_or_default();
                    state.local.entry(task.task_id).or_insert(Attached {
                        jail: task.jail,
                        ip: task.ip,
                        epairs,
                    });
                }
            }
        }

        match self.sweep().await {
            Ok(report) => {
                tracing::info!(report = %report.summary(), "overlay startup sweep complete");
                report
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "the overlay startup sweep failed; leaked interfaces may \
                     survive until the next restart"
                );
                SweepReport::default()
            }
        }
    }
}

/// Refuse a blackhole default remote that is also a peer's VTEP.
///
/// The endpoint table is the only list of peer VTEP addresses a node has, so
/// this runs on every pass rather than once at start-up: a node that joins later
/// brings a new underlay address with it, and if that address happens to be the
/// one this node blackholes, every unprogrammed frame would quietly reach a real
/// peer and a missing forwarding entry would stop being visible at all
/// (`docs/vxlan.md` §2 point 4).
fn check_blackhole_against_peers(
    state: &NetworkState,
    identity: &Identity,
) -> Result<(), OverlayError> {
    for endpoint in state.endpoints.values() {
        if endpoint.vtep == identity.blackhole {
            return Err(OverlayError::BlackholeIsAPeer {
                blackhole: identity.blackhole,
                node_id: endpoint.node_id.clone(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The security view: assignments into node-wide IPsec desired state
// ---------------------------------------------------------------------------

/// An encrypted network whose security requirements cannot be computed from
/// this shipment yet. Same class as [`OverlayError::NotReady`] — "the
/// allocator (or the leader's keyring) has not got there yet" — but for the
/// security view, which must never fail a pass over it: the next shipment
/// completes the picture.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingSecurity {
    /// Network name, as an operator names it.
    network: String,
    /// Which piece of state is missing.
    reason: String,
}

/// The **complete** per-node desired security state: one entry per
/// (encrypted network, remote peer) pair this node knows.
///
/// Completeness is a correctness requirement, not a style one:
/// [`satl_overlay::plan_security`] deletes anything present that is not
/// desired, so handing it a per-network partial view would tear down the
/// other networks' SAs. Teardown of one network is that network being
/// absent here.
#[derive(Debug, Default, PartialEq, Eq)]
struct SecurityView {
    /// Computable requirements, sorted for a deterministic view.
    ready: Vec<satl_overlay::PeerSecurity>,
    /// Encrypted networks waiting on allocator/keyring state.
    pending: Vec<PendingSecurity>,
}

/// Build the security view of every encrypted network this node holds.
///
/// The peer set comes from the same data [`OverlayManager::reconcile_tables`]
/// programs the forwarding tables from — the network's remote endpoints
/// **and** its other-node gateway attachments, excluding this node — so the
/// FDB and the SAs can never disagree about who a peer is.
fn desired_security(networks: &BTreeMap<Id, NetworkState>, node_id: &Id) -> SecurityView {
    let mut view = SecurityView::default();
    for state in networks.values() {
        if !state.network.spec.encrypted {
            continue;
        }
        let name = network_name(&state.network).to_owned();
        let pending = |reason: &str| PendingSecurity {
            network: name.clone(),
            reason: reason.to_owned(),
        };
        let Some(port) = state.network.vxlan_port else {
            view.pending.push(pending(
                "the allocator has not assigned it a VXLAN port yet",
            ));
            continue;
        };
        if state.network.keys.is_empty() {
            view.pending
                .push(pending("the leader has not shipped its keyring yet"));
            continue;
        }
        let peers: BTreeSet<Ipv4Addr> = state
            .endpoints
            .values()
            .filter(|endpoint| !endpoint.is_local_to(node_id))
            .map(|endpoint| endpoint.vtep)
            .chain(
                state
                    .gateways
                    .values()
                    .filter(|gateway| gateway.node_id != *node_id)
                    .map(|gateway| gateway.vtep),
            )
            .collect();
        view.ready
            .extend(peers.into_iter().map(|peer| satl_overlay::PeerSecurity {
                peer,
                port,
                keys: state.network.keys.clone(),
            }));
    }
    view.ready.sort_by_key(|ps| (ps.peer, ps.port));
    view
}

/// Restrict a parsed kernel SAD/SPD to the entries SatL manages, before the
/// reconciler sees them.
///
/// `plan_security` plans to delete anything present-but-not-desired, and the
/// kernel's tables may also hold a **third-party** `IPsec` user's entries on
/// the same node — deleting those would be the `pf`-anchor ownership rule's
/// violation in another shape. SatL's entries are recognizable: its SPs are
/// the only outbound udp policies this node sources that select on the
/// encrypted port range
/// ([`satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE`]), and its SAs are
/// exactly the ones towards the peers those SPs (or the desired view) name.
/// A peer whose network was torn down stays managed while its SP lingers,
/// which is what lets the teardown pass delete its SAs too.
fn satl_managed_present(
    me: Ipv4Addr,
    desired: &[satl_overlay::PeerSecurity],
    present: &satl_overlay::PresentSecurity,
) -> satl_overlay::PresentSecurity {
    use satl_overlay::{Direction, PortSelector};

    let range = &satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE;
    let sps: Vec<satl_overlay::SecurityPolicy> = present
        .sps
        .iter()
        .filter(|sp| {
            sp.direction == Direction::Out
                && sp.src == me
                && sp.src_port == PortSelector::Any
                && sp.protocol == "udp"
                && matches!(sp.dst_port, PortSelector::Port(port) if range.contains(&port))
        })
        .cloned()
        .collect();
    let managed_peers: BTreeSet<Ipv4Addr> = desired
        .iter()
        .map(|ps| ps.peer)
        .chain(sps.iter().map(|sp| sp.dst))
        .collect();
    let sas = present
        .sas
        .iter()
        .filter(|sa| {
            (sa.src == me && managed_peers.contains(&sa.dst))
                || (sa.dst == me && managed_peers.contains(&sa.src))
        })
        .copied()
        .collect();
    satl_overlay::PresentSecurity { sas, sps }
}

// ---------------------------------------------------------------------------
// Reports and pure helpers
// ---------------------------------------------------------------------------

/// The task ids of `networks`' local attachments whose jail is not in `live`.
///
/// Pure so the selection is unit-testable; the `jls` call and the detach stay
/// in [`OverlayManager::detach_dead_attachments`].
fn orphaned_attachments(networks: &BTreeMap<Id, NetworkState>, live: &BTreeSet<String>) -> Vec<Id> {
    networks
        .values()
        .flat_map(|state| state.local.iter())
        .filter(|(_, attached)| !live.contains(&attached.jail))
        .map(|(task_id, _)| task_id.clone())
        .collect()
}

/// What one [`OverlayManager::sweep`] pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    /// Task epair ends destroyed.
    pub destroyed_epairs: Vec<String>,
    /// Overlay bridges destroyed.
    pub destroyed_bridges: Vec<String>,
    /// VTEPs destroyed.
    pub destroyed_vteps: Vec<String>,
    /// Epair ends kept for tasks that should still be attached.
    pub adopted_epairs: usize,
    /// Overlay bridges kept.
    pub adopted_bridges: usize,
}

impl SweepReport {
    /// Whether the pass destroyed anything at all.
    #[must_use]
    pub fn destroyed_anything(&self) -> bool {
        !self.destroyed_epairs.is_empty()
            || !self.destroyed_bridges.is_empty()
            || !self.destroyed_vteps.is_empty()
    }

    /// One-line description for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "destroyed {} epair(s), {} bridge(s), {} vtep(s); adopted {} epair(s), {} bridge(s)",
            self.destroyed_epairs.len(),
            self.destroyed_bridges.len(),
            self.destroyed_vteps.len(),
            self.adopted_epairs,
            self.adopted_bridges,
        )
    }
}

/// This node's gateway address on every network it has a programmed segment
/// for, which is exactly the responder's bind list.
///
/// A network whose segment is not up yet is deliberately absent: the socket
/// cannot bind an address that is not on an interface, and `DnsServer::bind`
/// reports a bind failure to its caller rather than retrying, so offering it an
/// address that does not exist yet would take the whole responder down with it.
fn gateway_binds(inner: &Inner, node_id: &Id) -> BTreeMap<Ipv4Addr, BindOwner> {
    inner
        .networks
        .values()
        .filter(|state| state.ensured)
        .filter_map(|state| {
            let gateway: Ipv4Addr = state.network.node_gateways.get(node_id)?.parse().ok()?;
            Some((gateway, BindOwner::Overlay(state.network.id.clone())))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Pure derivation: a store object into a segment and a VTEP spec
// ---------------------------------------------------------------------------

/// The name an operator knows a network by, which is also what its interfaces
/// are described with (`<group>:overlay:<name>`, `<group>:vxlan:<name>` —
/// `docs/networking.md`, "Ownership markers").
fn network_name(network: &Network) -> &str {
    &network.spec.annotations.name
}

/// Whether this is a network this module programs at all. Bridge networks are
/// node-local and belong to `satl_net::NetworkManager`; they arrive on the same
/// assignment stream and must be ignored here, not mis-programmed as overlays.
fn is_overlay(network: &Network) -> bool {
    network.spec.driver == NetworkDriver::Overlay
}

/// The ways an existing VTEP's configuration can disagree with what a
/// network needs: VNI, local address and port, default remote and port.
///
/// Pure so the comparison is unit-testable; the read-back
/// ([`Vxlan::vtep_config`]) and the refusal stay in `check_adoptable`. The
/// port is pinned (`want_port` is the network's `vxlan_port`, or 4789 when
/// unset — what a pre-feature VTEP necessarily listens on): adopting a
/// tunnel on the wrong port would put an encrypted network's traffic on a
/// port its SPs and the cleartext guard do not cover.
fn adoption_mismatches(
    config: &satl_overlay::VtepConfig,
    vni: u32,
    vtep: Ipv4Addr,
    blackhole: Ipv4Addr,
    want_port: u16,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    if config.vni != vni {
        mismatches.push(format!("vni {} is not the requested {vni}", config.vni));
    }
    match config.local {
        Some((addr, port)) if addr == vtep && port == want_port => {}
        Some((addr, port)) if addr == vtep => mismatches.push(format!(
            "vxlanlocal port {port} is not the requested {want_port}"
        )),
        Some((addr, _)) => mismatches.push(format!(
            "vxlanlocal {addr} is not this node's underlay address {vtep}"
        )),
        None => mismatches.push("vxlanlocal is unset".to_owned()),
    }
    match config.remote {
        Some((addr, port)) if addr == blackhole && port == want_port => {}
        Some((addr, port)) if addr == blackhole => mismatches.push(format!(
            "vxlanremote port {port} is not the requested {want_port}"
        )),
        Some((addr, _)) => mismatches.push(format!(
            "vxlanremote {addr} is not the blackhole {blackhole}"
        )),
        None => mismatches.push(
            "vxlanremote is unset, so the driver never initialized this \
             interface (docs/vxlan.md section 2)"
                .to_owned(),
        ),
    }
    mismatches
}

/// The MTU a network's segment is programmed with: the measured underlay MTU
/// minus the VXLAN overhead (50), and minus the ESP transport overhead too
/// (34 more, so 84) when the network is encrypted — the measured expansion of
/// `hack/experiments/esp/README.md` §4. This one value is what flows to the
/// exactly two places the overlay MTU may live: the bridge and each in-jail
/// epair `b` end (CLAUDE.md, "VXLAN MTU").
fn segment_mtu(network: &Network, underlay: &UnderlayFacts) -> u32 {
    if network.spec.encrypted {
        underlay.overlay_mtu_encrypted()
    } else {
        underlay.overlay_mtu()
    }
}

/// This node's local segment of `network`, or why it cannot have one yet.
///
/// Everything comes from the assignment: the allocator's VNI and subnet, and
/// **this node's own** gateway out of `Network::node_gateways`. The
/// `NotReady` cases are all "the allocator (or the leader's keyring) has not
/// got there yet" rather than errors — the subnet and VNI are filled in when
/// the network is created, the per-node gateway when that node's first task
/// is scheduled, and the encrypted network's port and keyring one
/// allocator/rotation pass later. The keyring case is load-bearing beyond
/// politeness: an encrypted network programmed without keys has no outbound
/// SP and no outbound block, so a task that attached would send cleartext
/// VXLAN onto the wire until the keyring landed.
fn segment_of(
    network: &Network,
    node_id: &Id,
    mtu: u32,
) -> Result<(OverlaySegment, u32), OverlayError> {
    let name = network_name(network).to_owned();
    let not_ready = |reason: String| OverlayError::NotReady {
        network: name.clone(),
        reason,
    };
    let vni = network
        .vni
        .ok_or_else(|| not_ready("the allocator has assigned it no VNI yet".to_owned()))?;
    if network.spec.encrypted && network.vxlan_port.is_none() {
        return Err(not_ready(
            "it is encrypted but the allocator has not assigned it a VXLAN port yet. \
             Encrypted networks get one per network from the 4790-4999 space, so this \
             resolves itself within an allocator pass"
                .to_owned(),
        ));
    }
    if network.spec.encrypted && network.keys.is_empty() {
        return Err(not_ready(
            "it is encrypted but the leader has not shipped its keyring yet. Without \
             keys there is no outbound security policy to program, and attaching now \
             would send cleartext VXLAN onto the wire, so this waits for the next \
             keyring write"
                .to_owned(),
        ));
    }
    let subnet_text = network
        .subnet
        .as_deref()
        .ok_or_else(|| not_ready("the allocator has assigned it no subnet yet".to_owned()))?;
    let subnet: Ipv4Cidr = subnet_text.parse().map_err(|error| {
        not_ready(format!(
            "its subnet {subnet_text:?} is not a usable IPv4 CIDR: {error}"
        ))
    })?;
    let gateway_text = network.node_gateways.get(node_id).ok_or_else(|| {
        not_ready(
            "this node holds no gateway address on it yet. One is allocated when \
             the node's first task on the network is scheduled, so this resolves \
             itself within an allocator pass"
                .to_owned(),
        )
    })?;
    let gateway: Ipv4Addr = gateway_text.parse().map_err(|error| {
        not_ready(format!(
            "this node's gateway {gateway_text:?} is not a usable IPv4 address: {error}"
        ))
    })?;
    let segment = OverlaySegment::new(
        name,
        vni,
        satl_overlay::vtep_iface_name(vni),
        subnet,
        gateway,
        mtu,
    );
    Ok((segment, vni))
}

/// The bare address inside an advertise address (`10.2.0.5:2377` →
/// `10.2.0.5`).
///
/// A VXLAN endpoint is an address, never a name and never a port: 4789 belongs
/// to the overlay, not to the control plane. Mirrors `main::underlay_addr`,
/// which does the same for the node description this node publishes — the two
/// must agree, or a node programs a tunnel from an address its peers do not
/// expect.
fn underlay_address(advertise_addr: &str) -> Option<Ipv4Addr> {
    let trimmed = advertise_addr.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return as_v4(addr.ip());
    }
    if let Ok(addr) = trimmed.parse::<IpAddr>() {
        return as_v4(addr);
    }
    trimmed
        .rsplit_once(':')
        .and_then(|(host, _port)| host.parse::<IpAddr>().ok())
        .and_then(as_v4)
}

/// SatL assigns no IPv6 VTEP yet; an IPv6 advertise address is not one.
fn as_v4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(addr) => Some(addr),
        IpAddr::V6(_) => None,
    }
}

// ---------------------------------------------------------------------------
// The assignment sink
// ---------------------------------------------------------------------------

/// The worker's [`satl_dispatcher::AssignmentSink`], with the overlay half
/// filled in.
///
/// `satl_dispatcher::WorkerSink` leaves `apply_network`/`remove_network` at the
/// trait's logging defaults on purpose: `satl-dispatcher` may not depend on
/// `satl-overlay` (`docs/architecture.md` §2 lists its edges exhaustively), so
/// the crate that owns the *protocol* cannot own the programming. This wrapper
/// is where the two meet — the daemon depends on everything — and it delegates
/// every other method to the real sink unchanged.
pub struct OverlaySink<R: satl_agent::StatusReporter> {
    inner: satl_dispatcher::WorkerSink<R>,
    overlay: Arc<OverlayManager>,
}

impl<R: satl_agent::StatusReporter> std::fmt::Debug for OverlaySink<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlaySink").finish_non_exhaustive()
    }
}

impl<R: satl_agent::StatusReporter> OverlaySink<R> {
    /// A sink over the worker's own sink and this node's overlay programmer.
    pub fn new(inner: satl_dispatcher::WorkerSink<R>, overlay: Arc<OverlayManager>) -> Self {
        Self { inner, overlay }
    }
}

impl<R: satl_agent::StatusReporter> satl_dispatcher::AssignmentSink for OverlaySink<R> {
    async fn init(
        &self,
        live: &BTreeSet<Id>,
    ) -> Result<
        BTreeMap<Id, (satl_core::DesiredState, satl_core::ResourceRequirements)>,
        satl_dispatcher::SinkError,
    > {
        self.inner.init(live).await
    }

    async fn task_ids(&self) -> BTreeSet<Id> {
        self.inner.task_ids().await
    }

    async fn apply_task(&self, task: Task) -> Result<(), satl_dispatcher::SinkError> {
        let applied = self.inner.apply_task(task).await;
        // The scope table is built from the local task set, so it moves with
        // the tasks, not only with the networks.
        self.overlay.mark_dns_dirty();
        applied
    }

    async fn remove_task(&self, task_id: &Id) -> Result<(), satl_dispatcher::SinkError> {
        let removed = self.inner.remove_task(task_id).await;
        self.overlay.mark_dns_dirty();
        removed
    }

    fn reset_secrets(&self, secrets: Vec<satl_core::Secret>) {
        self.inner.reset_secrets(secrets);
    }

    fn put_secret(&self, secret: satl_core::Secret) {
        self.inner.put_secret(secret);
    }

    fn remove_secret(&self, id: &Id) {
        self.inner.remove_secret(id);
    }

    fn reset_configs(&self, configs: Vec<satl_core::Config>) {
        self.inner.reset_configs(configs);
    }

    fn put_config(&self, config: satl_core::Config) {
        self.inner.put_config(config);
    }

    fn remove_config(&self, id: &Id) {
        self.inner.remove_config(id);
    }

    /// Program the network, and **never fail the stream over it**.
    ///
    /// `SinkError` carries only a worker failure, and rightly so: dropping the
    /// assignment stream would not fix an `ifconfig` that refused. The failure is
    /// logged with everything it carries and then re-attempted from two other
    /// places — the periodic resync ([`RESYNC_INTERVAL`]) and the attach of the
    /// very next task on that network, which ensures the segment itself. A task
    /// whose overlay genuinely cannot be programmed fails *as that task*, with
    /// this error in its status, which is where an operator looks.
    async fn apply_network(
        &self,
        assignment: NetworkAssignment,
    ) -> Result<(), satl_dispatcher::SinkError> {
        let network_id = assignment.network.id.clone();
        if let Err(error) = self.overlay.apply_network(assignment).await {
            tracing::error!(
                network_id = %network_id,
                %error,
                "cannot program this node's segment of an overlay network; the \
                 periodic resync and the next task attach will retry"
            );
        }
        // Programming may have failed; the endpoint table was recorded either
        // way, and the DNS answer is built from the table, not the wires.
        self.overlay.mark_dns_dirty();
        Ok(())
    }

    async fn remove_network(&self, id: &Id) -> Result<(), satl_dispatcher::SinkError> {
        if let Err(error) = self.overlay.remove_network(id).await {
            tracing::error!(
                network_id = %id,
                %error,
                "cannot tear down this node's segment of an overlay network; the \
                 next startup sweep will"
            );
        }
        self.overlay.mark_dns_dirty();
        Ok(())
    }

    async fn networks_synced(&self, current: Vec<NetworkAssignment>) {
        self.overlay.sweep_after_snapshot(&current).await;
    }
}

// ---------------------------------------------------------------------------
// The controller's view (satl_agent::TaskOverlay)
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl TaskOverlay for OverlayManager {
    /// One `nameserver` line per overlay network the task is on, each holding
    /// **this node's** gateway on it.
    ///
    /// Per node, not per cluster: every participating node's bridge is on one L2
    /// segment, so a shared gateway address is a duplicate address there and the
    /// ARP race decides whose responder answers (`docs/vxlan.md` §8, measured).
    /// Pointing the container at its own host's address is what makes the answer
    /// come back from the socket it asked.
    async fn resolv_conf(&self, task: &Task) -> Option<String> {
        let nameservers: Vec<IpAddr> = {
            let inner = self.inner.lock().await;
            // Attachment order is resolution order (`satl_overlay::scopes`),
            // so the walk is over the task's attachments, not over the
            // network maps. An overlay contributes its per-node gateway; a
            // bridge network contributes the node bridge's gateway, which
            // every bridge network on this node shares -- hence the dedup.
            //
            // The overlay node id is looked up lazily rather than demanded up
            // front: a node with no overlay identity (an unmeasurable
            // underlay -- a /32 address is the ordinary case) hosts no overlay
            // but does host bridge networks, and its tasks used to fall all
            // the way through to a copy of the host's resolv.conf and resolve
            // no service name at all (M11b).
            let node_id = inner.identity.as_ref().map(|identity| &identity.node_id);
            let bridge_gateway = self.net.local_gateway();
            let mut nameservers = Vec::with_capacity(task.networks.len());
            for attachment in &task.networks {
                let address = if let Some(state) = inner.networks.get(&attachment.network_id) {
                    node_id
                        .and_then(|node_id| state.network.node_gateways.get(node_id))
                        .and_then(|text| text.parse::<Ipv4Addr>().ok())
                } else if inner.node_local.contains(&attachment.network_id) {
                    bridge_gateway
                } else {
                    None
                };
                if let Some(address) = address.map(IpAddr::V4)
                    && !nameservers.contains(&address)
                {
                    nameservers.push(address);
                }
            }
            nameservers
        };
        if nameservers.is_empty() {
            return None;
        }
        // The host's `search`/`options` pass through; its *nameservers* do not —
        // they are the responder's upstreams, not the container's, and a
        // container that fell back to them would resolve no service name at all.
        let host = satl_overlay::HostResolvConf::read(HOST_RESOLV_CONF)
            .await
            .unwrap_or_default();
        let conf = satl_overlay::OverlayResolvConf::from_host(nameservers, &host);
        let conf = match task.spec.container.dns_config.as_ref() {
            Some(dns) => conf.with_task_dns(dns),
            None => conf,
        };
        Some(conf.render())
    }

    #[tracing::instrument(skip_all, fields(task_id = %task.id, jail = %jail))]
    async fn attach(&self, task: &Task, jail: &str) -> Result<(), satl_agent::OverlayError> {
        let planned = self
            .overlay_attachments(task)
            .await
            .map_err(satl_agent::OverlayError::new)?;
        for plan in planned {
            match plan {
                Planned::Unknown { network_id } => {
                    return Err(satl_agent::OverlayError::new(
                        OverlayError::UnknownNetwork {
                            task_id: task.id.clone(),
                            network_id,
                        },
                    ));
                }
                Planned::Overlay { network_id, ip } => {
                    // The identity is demanded here, per overlay attachment,
                    // and not once up front: a task with nothing on an overlay
                    // needs nothing from this file. Asking first made a node
                    // that cannot host overlays *at all* fail every task at
                    // `start` -- including bridge-only ones -- which is exactly
                    // what `adopt_identity` above refuses to do when it cannot
                    // measure the underlay: it logs and degrades. A host whose
                    // underlay address is a /32 (no blackhole remote can be
                    // derived from it, docs/vxlan.md section 2) is the case
                    // that proves it; that is a legitimate configuration and it
                    // must still run node-local containers.
                    let (node_id, reason) = {
                        let inner = self.inner.lock().await;
                        (
                            inner
                                .identity
                                .as_ref()
                                .map(|identity| identity.node_id.clone()),
                            inner.no_identity.clone(),
                        )
                    };
                    let Some(node_id) = node_id else {
                        return Err(satl_agent::OverlayError::new(OverlayError::NoIdentity {
                            reason,
                        }));
                    };
                    self.wait_programmable(&network_id, &node_id).await;
                    self.attach_one(&network_id, &task.id, jail, ip)
                        .await
                        .map_err(satl_agent::OverlayError::new)?;
                    tracing::info!(
                        network_id = %network_id,
                        ip = %ip,
                        "task attached to its overlay network"
                    );
                }
            }
        }
        self.refresh_dns().await;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(task_id = %task_id))]
    async fn detach(&self, task_id: &Id) {
        // Best-effort and never fatal: this runs from the controller's cleanup
        // path, where every step tolerates "already gone" and none may stop the
        // others. Anything that survives is caught by the next startup sweep.
        let removals = {
            let mut inner = self.inner.lock().await;
            let mut removals = Vec::new();
            for (network_id, state) in &mut inner.networks {
                if let Some(attached) = state.local.remove(task_id) {
                    removals.push((network_id.clone(), attached));
                }
            }
            removals
        };
        if removals.is_empty() {
            return;
        }
        for (network_id, attached) in removals {
            if attached.epairs.is_empty() {
                tracing::debug!(
                    network_id = %network_id,
                    "no overlay epair recorded for this task; nothing to destroy"
                );
            } else {
                // One call for the pair, not one per end: destroying either end
                // destroys the other, and `detach_task_overlay` already falls back
                // to the `b` end when the `a` end is gone. Passing the two ends it
                // discovered keeps its log line truthful about which is which.
                let attachment = OverlayAttachment {
                    network: network_id.as_str().to_owned(),
                    epair_a: attached.epairs[0].clone(),
                    epair_b: attached
                        .epairs
                        .get(1)
                        .unwrap_or(&attached.epairs[0])
                        .clone(),
                    ip: attached.ip,
                    mac: satl_core::MacAddr::from_ipv4(attached.ip),
                    // Never read by a teardown; the pair is identified by name.
                    mtu: 0,
                };
                if let Err(error) = self
                    .net
                    .detach_task_overlay(task_id.as_str(), &attachment)
                    .await
                {
                    tracing::error!(
                        network_id = %network_id,
                        epairs = ?attached.epairs,
                        %error,
                        "cannot destroy an overlay epair; the startup sweep will"
                    );
                }
            }
            tracing::info!(network_id = %network_id, "task detached from its overlay network");
            // The peers' entries are unchanged, but this jail is gone, so its ARP
            // table is no longer part of the desired state and a later pass must
            // not try to read it.
            self.reconcile_after_detach(&network_id).await;
        }
        self.refresh_dns().await;
    }
}

// ---------------------------------------------------------------------------
// The DNS responder
// ---------------------------------------------------------------------------

/// One responder per node, bound to **each overlay gateway address the node
/// holds** and nothing else.
///
/// The bind list is a parameter of `satl_overlay::DnsServer` precisely because
/// this is a data-plane decision (`docs/vxlan.md` §8 resolved it): a socket bound
/// to the network's gateway address answers with *that* address as its source,
/// which is what a stub resolver's connected UDP socket requires, and several
/// such sockets coexist on port 53 with no coordination. A wildcard bind would
/// answer on the node's public address, i.e. be an open resolver and a reflection
/// amplifier.
///
/// **The socket decides the source address, not the scope.** Every one of these
/// sockets answers from the querying task's own networks
/// (`satl_overlay::scopes`), so a task attached to two of them gets the same
/// answers whichever of its `nameserver` lines the stub resolver picked. The
/// bind list changing is therefore a data-plane event only; nothing about *what*
/// resolves depends on it.
///
/// The set changes as networks arrive and leave, and `DnsServer` binds its
/// sockets once at construction, so a change means stopping the old server and
/// binding a new one. The comparison first makes that rare: a re-registration
/// that re-applies the same networks does not touch the responder, which is the
/// same "never flap a live overlay" rule the rest of this module follows.
struct DnsSupervisor {
    table: EndpointTable,
    scopes: ScopeTable,
    /// Parent of every generation's token, so a daemon shutdown stops the
    /// responder whatever else is happening.
    shutdown: CancellationToken,
    state: tokio::sync::Mutex<DnsState>,
}

/// What a bound gateway address belongs to, for logs and change detection.
///
/// Never a scope: every socket answers from the *querying task's* networks
/// (`satl_overlay::scopes`), which is why one address can serve many networks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BindOwner {
    /// One overlay network's per-node gateway.
    Overlay(Id),
    /// The node-local bridge's gateway, which carries **every** bridge network
    /// on this node: SatL programs one bridge per node, so they share it
    /// (M11b, api-compat 170).
    NodeBridge,
}

#[derive(Default)]
struct DnsState {
    /// Gateway address → what it belongs to.
    binds: BTreeMap<Ipv4Addr, BindOwner>,
    running: Option<RunningDns>,
}

struct RunningDns {
    server: satl_overlay::DnsServer,
    cancel: CancellationToken,
}

impl DnsSupervisor {
    fn new(table: EndpointTable, scopes: ScopeTable, shutdown: CancellationToken) -> Self {
        Self {
            table,
            scopes,
            shutdown,
            state: tokio::sync::Mutex::new(DnsState::default()),
        }
    }

    /// Bind exactly `binds`, if that is not already what is bound.
    async fn set_binds(&self, binds: BTreeMap<Ipv4Addr, BindOwner>) {
        let mut state = self.state.lock().await;
        if state.binds == binds && (state.running.is_some() || binds.is_empty()) {
            return;
        }
        if let Some(previous) = state.running.take() {
            previous.cancel.cancel();
            previous.server.join().await;
            tracing::info!("stopped the DNS responder to rebind it");
        }
        state.binds = binds;
        if state.binds.is_empty() {
            tracing::info!("no network with a gateway on this node; DNS responder stopped");
            return;
        }

        // Read the host's resolvers at every rebind rather than once: a node
        // whose /etc/resolv.conf changed under a running daemon would otherwise
        // forward to a resolver that is gone. Forwarding nowhere is a
        // degradation (unknown names get NXDOMAIN), never a refusal to serve
        // service names, which is what the responder exists for.
        let upstream = match satl_overlay::Upstream::from_resolv_conf(HOST_RESOLV_CONF).await {
            Ok(upstream) => upstream,
            Err(error) => {
                tracing::warn!(
                    path = HOST_RESOLV_CONF,
                    %error,
                    "cannot read the host resolvers; container queries for names \
                     outside the cluster will get NXDOMAIN"
                );
                satl_overlay::Upstream::none()
            }
        };
        let binds: Vec<SocketAddr> = state
            .binds
            .keys()
            .map(|addr| SocketAddr::new(IpAddr::V4(*addr), satl_overlay::DNS_PORT))
            .collect();
        let cancel = self.shutdown.child_token();
        match satl_overlay::DnsServer::bind(
            binds,
            self.table.clone(),
            self.scopes.clone(),
            upstream,
            cancel.clone(),
        )
        .await
        {
            Ok(server) => {
                tracing::info!(
                    addrs = ?server.local_addrs(),
                    networks = state.binds.len(),
                    // The gateway of each network, so an operator can map a
                    // socket back to the network whose bridge carries it. It is
                    // not the scope: every socket answers from the querying
                    // task's networks.
                    gateways = ?state.binds,
                    "DNS responder listening"
                );
                state.running = Some(RunningDns { server, cancel });
            }
            Err(error) => {
                tracing::error!(
                    %error,
                    "cannot bind the DNS responder; containers on this node will not \
                     resolve service names. The gateway address must be on its \
                     bridge before the socket can bind"
                );
                // Leave `binds` recorded but `running` empty so the next pass
                // retries instead of comparing equal and doing nothing.
                state.running = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

/// Re-reconcile every overlay network every [`RESYNC_INTERVAL`].
///
/// The assignment stream is the fast path and this is the safety net. It exists
/// because two things the stream cannot see leave the data plane behind: a pass
/// that failed halfway (the delta is idempotent, so the next one retries exactly
/// what is missing) and a forwarding table that had to be flushed because the
/// dump sysctl truncated.
pub fn spawn_resync(overlay: Arc<OverlayManager>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RESYNC_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it, since bring-up has just
        // programmed everything there is to program.
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => overlay.resync().await,
            }
        }
    })
}

/// How often the DNS tables are rebuilt with no wake at all — the safety net
/// for a notification lost to timing, nothing else.
const DNS_SAFETY_TICK: Duration = Duration::from_secs(10);

/// Feed the DNS responder's two projections from what the dispatcher shipped
/// and what this node runs — **no store involved**, so the same feed serves a
/// manager and a worker (§11.5; the store-fed variant died with the
/// all-managers assumption).
///
/// The **endpoint table** answers `<service>` and `<task-name>` with the
/// addresses of the **running** tasks behind them, cluster-wide. It is built
/// from the per-network endpoint tables the assignment stream delivered
/// ([`OverlayManager::dns_records`]): the names and the observed state travel
/// on [`satl_dispatcher::assignment::NetworkEndpoint`] precisely so this
/// projection needs no store read.
///
/// The **scope table** answers the question that comes first: which networks
/// a given client may be answered from at all. It is built from the **local
/// task DB** — every record there is a task this node hosts, and its
/// attachment list, in spec order, is the scope. A source address we cannot
/// attribute to one of our own tasks is forwarded upstream rather than
/// resolved (`satl_overlay::scopes`).
///
/// Rebuilds are woken by the assignment sink ([`OverlaySink`] marks dirty on
/// every task or network change), coalesced over [`ENDPOINT_REBUILD_FLOOR`],
/// with a slow safety tick behind them.
pub fn spawn_dns_feed(
    overlay: Arc<OverlayManager>,
    task_db: satl_agent::TaskDb,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let dirty = overlay.dns_dirty();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                () = dirty.notified() => {
                    // Coalesce a burst: further wakes during this floor (and
                    // during the rebuild itself) leave a permit behind, so
                    // nothing is lost and a storm costs one walk per floor.
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        () = tokio::time::sleep(ENDPOINT_REBUILD_FLOOR) => {}
                    }
                }
                () = tokio::time::sleep(DNS_SAFETY_TICK) => {}
            }
            let mut records = overlay.dns_records().await;
            // An unreadable task DB must not wipe the scope table — a
            // momentary read failure would cut every container's name
            // resolution. Keep answering from the last good projection.
            let Some(local) = local_records(&task_db).await else {
                continue;
            };
            // The bridge half (M11b): its records and scope addresses come
            // from the node's own IPAM, because Raft never sees them.
            let (bridge_records, bridge_addresses) = overlay.node_local_dns(&local).await;
            let bridge_count = bridge_records.len();
            records.extend(bridge_records);
            let task_scopes: Vec<satl_overlay::TaskScope> = local
                .into_iter()
                .filter_map(|record| scope_of_record(record, &bridge_addresses))
                .collect();
            let (record_count, scope_count) = (records.len(), task_scopes.len());
            overlay.table().update(records);
            overlay.scopes().update(task_scopes);
            tracing::debug!(
                records = record_count,
                bridge_records = bridge_count,
                local_tasks = scope_count,
                "DNS endpoint and scope tables rebuilt"
            );
        }
    })
}

/// One endpoint's DNS record: the names and state the dispatcher shipped,
/// the address the FDB entry uses.
fn record_of(
    network_id: &Id,
    endpoint: &satl_dispatcher::assignment::NetworkEndpoint,
) -> satl_overlay::EndpointRecord {
    satl_overlay::EndpointRecord {
        network_id: network_id.clone(),
        service_name: endpoint.service_name.clone(),
        task_name: endpoint.task_name.clone(),
        addresses: vec![IpAddr::V4(endpoint.addr)],
        aliases: endpoint.aliases.clone(),
        state: endpoint.state,
    }
}

/// One local task's scope from its persisted record. The persisted status is
/// canonical over the assignment's copy (architecture §7.2), so it is what
/// decides "terminal, scope withdrawn".
fn scope_of_record(
    record: satl_agent::TaskRecord,
    bridge_addresses: &BTreeMap<Id, Vec<IpAddr>>,
) -> Option<satl_overlay::TaskScope> {
    let local = bridge_addresses
        .get(&record.task.id)
        .map_or(&[][..], Vec::as_slice);
    let mut task = record.task;
    task.status = record.status;
    satl_overlay::scope_for_task_with(&task, local)
}

/// Every local task's record, from the task DB.
async fn local_records(task_db: &satl_agent::TaskDb) -> Option<Vec<satl_agent::TaskRecord>> {
    match task_db.list().await {
        Ok(records) => Some(records),
        Err(error) => {
            tracing::warn!(%error, "cannot read the local task db for the DNS scope table");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satl_core::{Annotations, Meta, NetworkSpec};

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    /// A network as the allocator leaves it: subnet and VNI assigned, and a
    /// gateway for each node that runs a task on it.
    fn network(name: &str, driver: NetworkDriver) -> Network {
        Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                driver,
                ipam: None,
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: false,
            },
            vni: Some(4096),
            vxlan_port: None,
            subnet: Some("10.100.0.0/24".to_owned()),
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        }
    }

    fn state(network: Network) -> NetworkState {
        NetworkState {
            network,
            endpoints: BTreeMap::new(),
            gateways: BTreeMap::new(),
            host_arp: BTreeMap::new(),
            local: BTreeMap::new(),
            unit: None,
            ensured: false,
        }
    }

    // ---- the dead-jail sweep -----------------------------------------------

    /// The safety net behind B1: an entry of `state.local` whose jail no
    /// prison of that name backs is orphaned, and only that one — a live
    /// jail keeps its attachment, and a *dying* one too, because `jls -d`
    /// still lists it and its teardown path is what detaches it.
    #[test]
    fn an_attachment_whose_jail_is_gone_is_orphaned() {
        let gone = Id::generate();
        let alive = Id::generate();
        let dying = Id::generate();
        let mut st = state(network("ovl", NetworkDriver::Overlay));
        for (task_id, jail) in [(&gone, "gone"), (&alive, "alive"), (&dying, "dying")] {
            st.local.insert(
                task_id.clone(),
                Attached {
                    jail: jail.to_owned(),
                    ip: ip("10.100.0.7"),
                    epairs: Vec::new(),
                },
            );
        }
        let networks = BTreeMap::from([(st.network.id.clone(), st)]);
        let live = BTreeSet::from(["alive".to_owned(), "dying".to_owned()]);
        assert_eq!(orphaned_attachments(&networks, &live), vec![gone]);

        // No jails listed at all orphans everything; every jail listed
        // orphans nothing.
        assert_eq!(orphaned_attachments(&networks, &BTreeSet::new()).len(), 3);
        let all = BTreeSet::from(["gone".to_owned(), "alive".to_owned(), "dying".to_owned()]);
        assert!(orphaned_attachments(&networks, &all).is_empty());
    }

    // ---- the segment ------------------------------------------------------

    #[test]
    fn a_segment_takes_this_nodes_own_gateway() {
        let node = Id::generate();
        let other = Id::generate();
        let mut net = network("ovl", NetworkDriver::Overlay);
        net.node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());
        net.node_gateways.insert(other, "10.100.0.6".to_owned());

        let (segment, vni) = segment_of(&net, &node, 1450).expect("programmable");
        assert_eq!(vni, 4096);
        assert_eq!(segment.network, "ovl");
        // Both names are derived from the VNI so they fit IFNAMSIZ.
        assert_eq!(segment.vtep, "satl-vx4096");
        assert_eq!(segment.bridge, "satl-br4096");
        assert_eq!(
            segment.gateway,
            ip("10.100.0.5"),
            "the other node's is not ours"
        );
        assert_eq!(segment.mtu, 1450);
        // And the segment satisfies satl-net's own rules, including that the
        // reserved .1 is nobody's.
        segment.validate().expect("valid segment");
    }

    #[test]
    fn allocator_state_that_has_not_arrived_is_not_ready_rather_than_an_error() {
        let node = Id::generate();
        let mut net = network("ovl", NetworkDriver::Overlay);
        net.node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());

        // No gateway for this node: the common case on the very first shipment,
        // since a node's gateway is allocated when its first task is scheduled.
        let mut pending = net.clone();
        pending.node_gateways.clear();
        let error = segment_of(&pending, &node, 1450).expect_err("not ready");
        assert!(matches!(error, OverlayError::NotReady { .. }), "{error}");
        assert!(error.to_string().contains("allocator pass"), "{error}");

        // No VNI, and no subnet.
        let mut no_vni = net.clone();
        no_vni.vni = None;
        assert!(segment_of(&no_vni, &node, 1450).is_err());
        let mut no_subnet = net.clone();
        no_subnet.subnet = None;
        assert!(segment_of(&no_subnet, &node, 1450).is_err());

        // Unparseable values are reported, never guessed at.
        let mut bad = net;
        bad.subnet = Some("not-a-cidr".to_owned());
        let error = segment_of(&bad, &node, 1450).expect_err("not ready");
        assert!(error.to_string().contains("not-a-cidr"), "{error}");
    }

    #[test]
    fn only_overlay_networks_are_this_modules_business() {
        assert!(is_overlay(&network("ovl", NetworkDriver::Overlay)));
        assert!(
            !is_overlay(&network("satl", NetworkDriver::Bridge)),
            "a node-local bridge belongs to satl-net, not here"
        );
    }

    // ---- encryption: port and MTU --------------------------------------------

    /// An encrypted network whose per-network VXLAN port the allocator has
    /// not assigned yet is the same kind of "not there yet" as a missing
    /// gateway: recorded, waited on, never an error.
    #[test]
    fn an_encrypted_network_without_a_vxlan_port_is_not_ready() {
        let node = Id::generate();
        let mut net = network("ovl", NetworkDriver::Overlay);
        net.node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());
        net.spec.encrypted = true;

        let error = segment_of(&net, &node, 1416).expect_err("not ready");
        assert!(matches!(error, OverlayError::NotReady { .. }), "{error}");
        assert!(error.to_string().contains("VXLAN port"), "{error}");

        net.vxlan_port = Some(4793);
        net.keys.push(satl_core::NetworkKey {
            tag: 1,
            key: [0; 16],
            primary: true,
        });
        segment_of(&net, &node, 1416).expect("programmable once the port arrived");
    }

    /// An encrypted network with a port but an empty keyring is the same
    /// "not there yet" again — and the one where being ready would hurt:
    /// attaching would give a task a live VTEP with no outbound SP and no
    /// outbound block, so its first packets would egress as cleartext VXLAN
    /// until the leader's keyring landed. The pf guard is inbound-only, so
    /// the wait is the whole fix.
    #[test]
    fn an_encrypted_network_without_keys_is_not_ready() {
        let node = Id::generate();
        let mut net = network("ovl", NetworkDriver::Overlay);
        net.node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());
        net.spec.encrypted = true;
        net.vxlan_port = Some(4793);

        let error = segment_of(&net, &node, 1416).expect_err("not ready");
        assert!(matches!(error, OverlayError::NotReady { .. }), "{error}");
        assert!(error.to_string().contains("keyring"), "{error}");

        net.keys.push(satl_core::NetworkKey {
            tag: 1,
            key: [0; 16],
            primary: true,
        });
        segment_of(&net, &node, 1416).expect("programmable once a key landed");

        // An unencrypted network carries no keyring at all and is unaffected.
        let mut plain = network("ovl", NetworkDriver::Overlay);
        plain
            .node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());
        segment_of(&plain, &node, 1450).expect("unencrypted networks need no keys");
    }

    /// The encrypted MTU is the underlay's minus 84 (50 VXLAN + 34 ESP,
    /// measured in hack/experiments/esp section 4); cleartext stays at
    /// minus 50. Both flow through the one segment MTU to the bridge and the
    /// epairs.
    #[test]
    fn the_segment_mtu_subtracts_esp_overhead_for_encrypted_networks() {
        let facts = crate::underlay::UnderlayFacts {
            iface: "vtnet1".to_owned(),
            addr: ip("10.2.2.47"),
            prefix: "10.2.2.47/16".parse().expect("valid cidr"),
            mtu: 1500,
        };
        let mut net = network("ovl", NetworkDriver::Overlay);
        assert_eq!(segment_mtu(&net, &facts), 1450);
        net.spec.encrypted = true;
        assert_eq!(segment_mtu(&net, &facts), 1416);
    }

    /// Adoption pins the tunnel's port: a pre-feature VTEP lives on 4789 and
    /// must still adopt for an unencrypted network (requested port `None`),
    /// while an encrypted network must refuse to adopt a tunnel on the wrong
    /// port rather than silently talk cleartext expectations into it.
    #[test]
    fn adoption_mismatches_pin_the_vxlan_port() {
        let config = satl_overlay::VtepConfig {
            vni: 4096,
            local: Some((ip("10.2.2.47"), 4789)),
            remote: Some((ip("10.2.255.254"), 4789)),
        };
        // Unencrypted network: wants the IANA default, finds it.
        assert!(
            adoption_mismatches(&config, 4096, ip("10.2.2.47"), ip("10.2.255.254"), 4789)
                .is_empty()
        );
        // Encrypted network on 4793: both ends are flagged.
        let mismatches =
            adoption_mismatches(&config, 4096, ip("10.2.2.47"), ip("10.2.255.254"), 4793);
        assert_eq!(mismatches.len(), 2, "{mismatches:?}");
        assert!(
            mismatches
                .iter()
                .all(|m| m.contains("4789") && m.contains("4793"))
        );
    }

    /// A node that can host no overlay at all must still resolve service names
    /// on its bridge networks.
    ///
    /// Same host as the test below, and the same degradation: an unmeasurable
    /// underlay leaves `adopt_identity` with no identity. `resolv_conf`
    /// demanded that identity before it looked at what the task attached to,
    /// so on such a node *every* task fell through to a copy of the host's
    /// `/etc/resolv.conf` and resolved no service name at all — measured on a
    /// host whose only address is a /32, which is an ordinary way for a single
    /// public server to be configured, not a misconfiguration (M11b).
    ///
    /// The IPAM is seeded rather than programmed: `ensure_host_network` and an
    /// attach both need root, and what this asserts is the projection, not the
    /// plumbing. Seeding is faithful because the manager reloads that file
    /// verbatim.
    #[tokio::test]
    async fn a_bridge_task_resolves_through_the_node_bridge_with_no_overlay_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        // One task, built once: `tests::task()` generates a fresh id per call,
        // and the seeded allocation has to be for the id under test.
        let mut task = crate::overlay::tests::task();
        let task_id = task.id.clone();
        {
            let mut ipam = satl_net::LocalIpam::open_with_pool(
                dir.path(),
                satl_net::DEFAULT_LOCAL_BRIDGE_POOL,
            )
            .expect("ipam");
            ipam.ensure_network("satl").expect("the node's subnet");
            ipam.allocate("satl", task_id.as_str())
                .expect("the task's address");
        }
        let net = satl_net::NetworkManager::open(satl_net::NetworkManagerConfig {
            state_dir: dir.path().to_owned(),
            pf_mode: satl_net::PfMode::Disabled,
            ..satl_net::NetworkManagerConfig::default()
        })
        .expect("network manager");
        let gateway = net
            .local_gateway()
            .expect("the seeded network has a gateway");
        let address = net
            .address_of("satl", task_id.as_str())
            .expect("the seeded allocation");

        let overlay = OverlayManager::new(
            "satl".to_owned(),
            None,
            Arc::new(net),
            CancellationToken::new(),
        )
        .expect("overlay manager");
        assert!(overlay.inner.lock().await.identity.is_none());

        let bridge = network("shop-front", NetworkDriver::Bridge);
        overlay
            .inner
            .lock()
            .await
            .node_local
            .insert(bridge.id.clone());

        task.status.state = satl_core::TaskState::Running;
        task.networks.push(satl_core::NetworkAttachment {
            network_id: bridge.id.clone(),
            // A bridge attachment carries no address in the store: that is
            // exactly what the node's IPAM is here to supply.
            addresses: Vec::new(),
            aliases: vec!["cache".to_owned()],
        });

        let rendered = satl_agent::TaskOverlay::resolv_conf(overlay.as_ref(), &task)
            .await
            .expect("a bridge task points at the node bridge's responder");
        assert!(
            rendered.contains(&format!("nameserver {gateway}")),
            "{rendered}"
        );

        // And the projection that lets that responder answer: one record for
        // the attachment, and the source address its queries will carry.
        let records = vec![satl_agent::TaskRecord {
            task: task.clone(),
            status: task.status.clone(),
        }];
        let (endpoints, scoped) = overlay.node_local_dns(&records).await;
        assert_eq!(endpoints.len(), 1, "{endpoints:?}");
        assert_eq!(endpoints[0].network_id, bridge.id);
        assert_eq!(endpoints[0].addresses, vec![IpAddr::V4(address)]);
        assert_eq!(endpoints[0].aliases, ["cache"]);
        assert_eq!(endpoints[0].state, satl_core::TaskState::Running);
        assert_eq!(scoped.get(&task.id), Some(&vec![IpAddr::V4(address)]));
    }

    /// A node that can host no overlay at all must still run node-local
    /// containers.
    ///
    /// `adopt_identity` treats an unmeasurable underlay as a degradation: it
    /// logs and carries on with no identity. But `attach` demanded that
    /// identity before looking at what the task attaches to, so on such a host
    /// **every** task failed at `start` with "no cluster identity yet",
    /// including tasks whose only network is the node-local bridge. The real
    /// case is a host whose underlay address is a /32 — no blackhole remote can
    /// be derived from it (`docs/vxlan.md` §2) — which is an ordinary way for a
    /// public address to be configured, not a misconfiguration to fail on.
    #[tokio::test]
    async fn a_task_on_no_overlay_starts_on_a_node_that_has_no_overlay_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let net = satl_net::NetworkManager::open(satl_net::NetworkManagerConfig {
            state_dir: dir.path().to_owned(),
            pf_mode: satl_net::PfMode::Disabled,
            ..satl_net::NetworkManagerConfig::default()
        })
        .expect("network manager");
        let overlay = OverlayManager::new(
            "satl".to_owned(),
            None,
            Arc::new(net),
            CancellationToken::new(),
        )
        .expect("overlay manager");

        // No `adopt_identity`: this node measured no underlay, so it holds no
        // identity — exactly the state that ERROR leaves behind.
        assert!(overlay.inner.lock().await.identity.is_none());

        let bridge = network("satl", NetworkDriver::Bridge);
        let overlay_net = network("ovl", NetworkDriver::Overlay);
        {
            let mut inner = overlay.inner.lock().await;
            inner.node_local.insert(bridge.id.clone());
            inner
                .networks
                .insert(overlay_net.id.clone(), state(overlay_net.clone()));
        }

        let mut task = crate::overlay::tests::task();
        task.networks.push(satl_core::NetworkAttachment {
            network_id: bridge.id.clone(),
            addresses: vec!["10.84.0.7/24".to_owned()],
            aliases: Vec::new(),
        });
        overlay
            .attach(&task, "jail1")
            .await
            .expect("a node-local attachment asks nothing of the overlay");

        // A task that *is* on an overlay still refuses, and says why.
        let mut wants_overlay = crate::overlay::tests::task();
        wants_overlay.networks.push(satl_core::NetworkAttachment {
            network_id: overlay_net.id,
            addresses: vec!["10.100.0.7/24".to_owned()],
            aliases: Vec::new(),
        });
        let error = overlay
            .attach(&wants_overlay, "jail2")
            .await
            .expect_err("an overlay attachment needs the identity this node lacks");
        assert!(error.to_string().contains("no cluster identity"), "{error}");
    }

    /// A task with nothing but the fields this module reads.
    fn task() -> Task {
        let id = Id::generate();
        Task {
            annotations: Annotations {
                name: format!("web.1.{id}"),
                labels: BTreeMap::new(),
            },
            id,
            meta: Meta::new(),
            spec: satl_core::TaskSpec {
                container: satl_core::ContainerSpec {
                    image: "127.0.0.1:5000/satl-test/freebsd-nginx:latest".to_owned(),
                    labels: BTreeMap::new(),
                    command: Vec::new(),
                    args: Vec::new(),
                    hostname: None,
                    env: Vec::new(),
                    dir: None,
                    user: None,
                    groups: Vec::new(),
                    tty: false,
                    open_stdin: false,
                    read_only: false,
                    stop_signal: None,
                    stop_grace_period: None,
                    healthcheck: None,
                    hosts: Vec::new(),
                    dns_config: None,
                    mounts: Vec::new(),
                    secrets: Vec::new(),
                    configs: Vec::new(),
                    pull_options: None,
                    platform: None,
                },
                resources: satl_core::ResourceRequirements::default(),
                restart: satl_core::RestartPolicy::default(),
                placement: satl_core::Placement::default(),
                networks: Vec::new(),
                force_update: 0,
            },
            spec_version: None,
            service_id: None,
            slot: 1,
            node_id: None,
            service_annotations: Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::new(),
            },
            status: satl_core::TaskStatus::new(satl_core::TaskState::Starting, "test"),
            desired_state: satl_core::DesiredState::Running,
            networks: Vec::new(),
            endpoint: None,
            job_iteration: None,
        }
    }

    // ---- the DNS bind list -------------------------------------------------

    #[test]
    fn the_responder_binds_this_nodes_gateway_on_every_ensured_network() {
        let node = Id::generate();
        let mut first = network("ovl-a", NetworkDriver::Overlay);
        first
            .node_gateways
            .insert(node.clone(), "10.100.0.5".to_owned());
        let mut second = network("ovl-b", NetworkDriver::Overlay);
        second.vni = Some(4097);
        second.subnet = Some("10.100.1.0/24".to_owned());
        second
            .node_gateways
            .insert(node.clone(), "10.100.1.7".to_owned());

        let (first_id, second_id) = (first.id.clone(), second.id.clone());
        let mut inner = Inner::default();
        for net in [first, second] {
            let mut st = state(net);
            st.ensured = true;
            inner.networks.insert(st.network.id.clone(), st);
        }

        let binds = gateway_binds(&inner, &node);
        assert_eq!(
            binds,
            BTreeMap::from([
                (ip("10.100.0.5"), BindOwner::Overlay(first_id.clone())),
                (ip("10.100.1.7"), BindOwner::Overlay(second_id)),
            ]),
            "one socket per (node, network), on that network's own gateway"
        );

        // A network whose segment is not up yet is absent: the socket cannot bind
        // an address that is not on an interface, and DnsServer::bind reports a
        // bind failure rather than retrying, so offering it one would take the
        // whole responder down.
        if let Some(st) = inner.networks.get_mut(&first_id) {
            st.ensured = false;
        }
        assert_eq!(gateway_binds(&inner, &node).len(), 1);

        // And a node that holds no gateway on a network binds nothing for it.
        assert!(gateway_binds(&inner, &Id::generate()).is_empty());
    }

    // ---- the DNS projections -----------------------------------------------

    /// The endpoint record is the endpoint's DNS half verbatim: the names and
    /// state the dispatcher shipped, and the address peers program. The table
    /// answers `RUNNING` records only, so the state travelling through here is
    /// what keeps a stopped task out of the answers with no store read.
    #[test]
    fn a_shipped_endpoint_becomes_a_dns_record() {
        let network_id = Id::generate();
        let task_id = Id::generate();
        let endpoint = NetworkEndpoint {
            task_id: task_id.clone(),
            node_id: Id::generate(),
            addr: ip("10.100.0.9"),
            vtep: ip("10.2.1.50"),
            service_name: "web".to_owned(),
            task_name: format!("web.1.{task_id}"),
            aliases: vec!["www".to_owned()],
            state: satl_core::TaskState::Running,
        };
        let record = record_of(&network_id, &endpoint);
        assert_eq!(record.network_id, network_id);
        assert_eq!(record.service_name, "web");
        assert_eq!(record.task_name, format!("web.1.{task_id}"));
        assert_eq!(record.aliases, vec!["www".to_owned()]);
        assert_eq!(record.addresses, vec![IpAddr::V4(ip("10.100.0.9"))]);
        assert!(record.is_live());

        // A pre-DNS encoding decodes to state NEW: recorded, never answered.
        let stale = NetworkEndpoint {
            state: satl_core::TaskState::New,
            ..endpoint
        };
        assert!(!record_of(&network_id, &stale).is_live());
    }

    /// A scope is built from the local record with the **persisted** status
    /// (architecture §7.2: local is canonical for observed state), in the
    /// spec's attachment order — which is what makes a name present on two
    /// networks resolve the same way on every node.
    #[test]
    fn a_local_record_scopes_its_networks_in_attachment_order() {
        let (front, back) = (Id::generate(), Id::generate());
        let mut mine = task();
        mine.status.state = satl_core::TaskState::Running;
        mine.networks = vec![
            attachment(&front, "10.100.0.5/24"),
            attachment(&back, "10.100.1.5/24"),
        ];
        let record = satl_agent::TaskRecord {
            status: mine.status.clone(),
            task: mine.clone(),
        };
        let scope = scope_of_record(record, &BTreeMap::new()).expect("a running local task scopes");
        assert_eq!(scope.task_id, mine.id);
        assert_eq!(
            scope.networks,
            vec![front.clone(), back],
            "attachment order, not id order"
        );
        assert_eq!(
            scope.addresses,
            vec![IpAddr::V4(ip("10.100.0.5")), IpAddr::V4(ip("10.100.1.5"))]
        );

        // The persisted status wins over the assignment's copy: a task the
        // agent reported terminal scopes nothing, whatever the manager's
        // (necessarily lagging) copy says.
        let mut stale_assignment = mine.clone();
        stale_assignment.status.state = satl_core::TaskState::Running;
        let record = satl_agent::TaskRecord {
            status: satl_core::TaskStatus::new(satl_core::TaskState::Shutdown, "stopped"),
            task: stale_assignment,
        };
        assert!(scope_of_record(record, &BTreeMap::new()).is_none());
    }

    fn attachment(network: &Id, address: &str) -> satl_core::NetworkAttachment {
        satl_core::NetworkAttachment {
            network_id: network.clone(),
            addresses: vec![address.to_owned()],
            aliases: Vec::new(),
        }
    }

    // ---- the VTEP address --------------------------------------------------

    /// A VXLAN endpoint is an address, never a name and never a port. This must
    /// agree with `main::underlay_addr`, which derives the same value for the
    /// node description peers read.
    #[test]
    fn a_vtep_is_the_advertise_address_without_its_port() {
        assert_eq!(underlay_address("10.2.0.5:2377"), Some(ip("10.2.0.5")));
        assert_eq!(underlay_address("10.2.0.5"), Some(ip("10.2.0.5")));
        assert_eq!(underlay_address("  10.2.0.5:2377 "), Some(ip("10.2.0.5")));
        // A name is not an endpoint, and SatL assigns no IPv6 VTEP yet.
        assert_eq!(underlay_address("node1.example:2377"), None);
        assert_eq!(underlay_address("[fd00::1]:2377"), None);
        assert_eq!(underlay_address(""), None);
    }

    // ---- the blackhole, against live peers ---------------------------------

    #[test]
    fn a_blackhole_that_is_a_live_peers_vtep_is_refused() {
        let node = Id::generate();
        let peer = Id::generate();
        let identity = Identity {
            node_id: node.clone(),
            underlay: crate::underlay::UnderlayFacts {
                iface: "vtnet1".to_owned(),
                addr: ip("10.2.2.47"),
                prefix: "10.2.2.47/16".parse().expect("valid cidr"),
                mtu: 1500,
            },
            vtep: ip("10.2.2.47"),
            blackhole: ip("10.2.255.254"),
        };
        let mut st = state(network("ovl", NetworkDriver::Overlay));
        let task = Id::generate();
        st.endpoints.insert(
            task.clone(),
            NetworkEndpoint {
                task_id: task,
                node_id: peer.clone(),
                addr: ip("10.100.0.9"),
                // A peer that happens to sit on the top address of the underlay.
                vtep: ip("10.2.255.254"),
                service_name: String::new(),
                task_name: String::new(),
                aliases: Vec::new(),
                state: satl_core::TaskState::Running,
            },
        );
        let error = check_blackhole_against_peers(&st, &identity).expect_err("refused");
        assert!(
            matches!(error, OverlayError::BlackholeIsAPeer { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("overlay_blackhole"), "{error}");

        // An ordinary peer is fine.
        if let Some(endpoint) = st.endpoints.values_mut().next() {
            endpoint.vtep = ip("10.2.1.50");
        }
        check_blackhole_against_peers(&st, &identity).expect("accepted");
    }

    // ---- the security view ---------------------------------------------------

    fn key(tag: u32, primary: bool) -> satl_core::NetworkKey {
        let mut material = [0_u8; 16];
        material[..4].copy_from_slice(&tag.to_be_bytes());
        satl_core::NetworkKey {
            tag,
            key: material,
            primary,
        }
    }

    fn encrypted_network(name: &str, port: Option<u16>, tags: &[(u32, bool)]) -> Network {
        let mut net = network(name, NetworkDriver::Overlay);
        net.spec.encrypted = true;
        net.vxlan_port = port;
        net.keys = tags
            .iter()
            .map(|&(tag, primary)| key(tag, primary))
            .collect();
        net
    }

    fn endpoint(node: &Id, addr: &str, vtep: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            task_id: Id::generate(),
            node_id: node.clone(),
            addr: ip(addr),
            vtep: ip(vtep),
            service_name: String::new(),
            task_name: String::new(),
            aliases: Vec::new(),
            state: satl_core::TaskState::Running,
        }
    }

    fn gateway(node: &Id, addr: &str, vtep: &str) -> satl_dispatcher::GatewayAttachment {
        satl_dispatcher::GatewayAttachment {
            node_id: node.clone(),
            addr: ip(addr),
            vtep: ip(vtep),
        }
    }

    fn insert(networks: &mut BTreeMap<Id, NetworkState>, st: NetworkState) {
        networks.insert(st.network.id.clone(), st);
    }

    /// The peer set is built from the same data as the forwarding tables, so
    /// the two can never disagree: remote endpoints AND other nodes' gateway
    /// attachments, excluding this node, deduplicated to VTEP addresses.
    #[test]
    fn the_security_view_pairs_each_remote_vtep_with_the_networks_port_and_keys() {
        let me = Id::generate();
        let node_a = Id::generate();
        let node_b = Id::generate();
        let mut st = state(encrypted_network(
            "enc",
            Some(4790),
            &[(1, true), (2, false)],
        ));
        // Two tasks on node A (one peer, not two), one on B, one local.
        st.endpoints
            .insert(Id::generate(), endpoint(&node_a, "10.100.0.9", "10.2.1.50"));
        st.endpoints.insert(
            Id::generate(),
            endpoint(&node_a, "10.100.0.10", "10.2.1.50"),
        );
        st.endpoints.insert(
            Id::generate(),
            endpoint(&node_b, "10.100.0.11", "10.2.3.124"),
        );
        st.endpoints
            .insert(Id::generate(), endpoint(&me, "10.100.0.12", "10.2.2.47"));
        // The mesh gateways: node A's is already a peer, this node's is not.
        st.gateways
            .insert(node_a.clone(), gateway(&node_a, "10.100.0.1", "10.2.1.50"));
        st.gateways
            .insert(me.clone(), gateway(&me, "10.100.0.2", "10.2.2.47"));

        let mut networks = BTreeMap::new();
        insert(&mut networks, st);
        let view = desired_security(&networks, &me);
        assert!(view.pending.is_empty(), "{:?}", view.pending);
        assert_eq!(
            view.ready,
            vec![
                satl_overlay::PeerSecurity {
                    peer: ip("10.2.1.50"),
                    port: 4790,
                    keys: vec![key(1, true), key(2, false)],
                },
                satl_overlay::PeerSecurity {
                    peer: ip("10.2.3.124"),
                    port: 4790,
                    keys: vec![key(1, true), key(2, false)],
                },
            ]
        );
    }

    /// No port yet, or no keyring yet: the network is *pending*, exactly the
    /// "the allocator has not got there yet" class — it must neither fail the
    /// pass nor contribute a half-built entry to the full view.
    #[test]
    fn an_encrypted_network_without_port_or_keyring_is_pending() {
        let me = Id::generate();
        let peer = Id::generate();

        let mut no_port = state(encrypted_network("no-port", None, &[(1, true)]));
        no_port
            .endpoints
            .insert(Id::generate(), endpoint(&peer, "10.100.0.9", "10.2.1.50"));
        let mut networks = BTreeMap::new();
        insert(&mut networks, no_port);
        let view = desired_security(&networks, &me);
        assert!(view.ready.is_empty());
        assert_eq!(view.pending.len(), 1);
        assert!(
            view.pending[0].reason.contains("VXLAN port"),
            "{:?}",
            view.pending
        );

        let mut no_keys = state(encrypted_network("no-keys", Some(4790), &[]));
        no_keys
            .endpoints
            .insert(Id::generate(), endpoint(&peer, "10.100.0.9", "10.2.1.50"));
        let mut networks = BTreeMap::new();
        insert(&mut networks, no_keys);
        let view = desired_security(&networks, &me);
        assert!(view.ready.is_empty());
        assert_eq!(view.pending.len(), 1);
        assert!(
            view.pending[0].reason.contains("keyring"),
            "{:?}",
            view.pending
        );
    }

    #[test]
    fn unencrypted_networks_contribute_nothing_to_the_security_view() {
        let me = Id::generate();
        let peer = Id::generate();
        let mut st = state(network("plain", NetworkDriver::Overlay));
        st.endpoints
            .insert(Id::generate(), endpoint(&peer, "10.100.0.9", "10.2.1.50"));
        let mut networks = BTreeMap::new();
        insert(&mut networks, st);
        let view = desired_security(&networks, &me);
        assert!(view.ready.is_empty() && view.pending.is_empty());
    }

    /// Two encrypted networks on one peer are two (peer, port) entries with
    /// independent keyrings — the reconciler keys SAs by per-network tags.
    #[test]
    fn two_encrypted_networks_sharing_a_peer_get_independent_entries() {
        let me = Id::generate();
        let peer = Id::generate();
        let mut networks = BTreeMap::new();
        for (name, port, tag) in [("enc-a", 4790, 1), ("enc-b", 4791, 7)] {
            let mut st = state(encrypted_network(name, Some(port), &[(tag, true)]));
            st.endpoints
                .insert(Id::generate(), endpoint(&peer, "10.100.0.9", "10.2.1.50"));
            insert(&mut networks, st);
        }
        let view = desired_security(&networks, &me);
        assert_eq!(view.ready.len(), 2);
        assert!(
            view.ready
                .iter()
                .any(|ps| ps.port == 4790 && ps.keys == vec![key(1, true)])
        );
        assert!(
            view.ready
                .iter()
                .any(|ps| ps.port == 4791 && ps.keys == vec![key(7, true)])
        );

        // Teardown of one network is that network absent from the next full
        // view — the reconciler's deletes then cover exactly its entries.
        let remaining = networks.keys().next().unwrap().clone();
        networks.remove(&remaining);
        assert_eq!(desired_security(&networks, &me).ready.len(), 1);
        networks.clear();
        let empty = desired_security(&networks, &me);
        assert!(empty.ready.is_empty() && empty.pending.is_empty());
    }

    /// The kernel's SAD/SPD may hold entries SatL does not manage (a
    /// third-party `IPsec` user on the same node). Only SatL-shaped entries —
    /// the outbound udp SPs selecting on the encrypted port range, and the
    /// SAs towards peers those SPs or the desired view name — may reach the
    /// reconciler, whose deletes are "anything present but not desired".
    #[test]
    fn the_present_view_filter_keeps_only_satl_managed_entries() {
        use satl_overlay::{Direction, PortSelector, SecurityPolicy, desired_sp};

        let me = ip("10.2.2.47");
        let managed = ip("10.2.1.50");
        let foreign = ip("10.2.9.9");
        let desired = [satl_overlay::PeerSecurity {
            peer: managed,
            port: 4790,
            keys: vec![key(1, true)],
        }];
        let satl_sp = desired_sp(me, managed, 4790);
        let foreign_sps = vec![
            // Inbound policy.
            SecurityPolicy {
                direction: Direction::In,
                ..satl_sp.clone()
            },
            // Not udp.
            SecurityPolicy {
                protocol: "tcp".to_owned(),
                ..satl_sp.clone()
            },
            // A port outside the encrypted range.
            desired_sp(me, managed, 4789),
            // Not sourced here.
            SecurityPolicy {
                src: foreign,
                ..satl_sp.clone()
            },
            // A pinned source port is not the SatL shape ([any] is mandatory).
            SecurityPolicy {
                src_port: PortSelector::Port(4790),
                ..satl_sp.clone()
            },
        ];
        let present = satl_overlay::PresentSecurity {
            sas: vec![
                satl_overlay::SecurityAssociation {
                    src: me,
                    dst: managed,
                    spi: 1,
                },
                satl_overlay::SecurityAssociation {
                    src: managed,
                    dst: me,
                    spi: 2,
                },
                // A third-party SA involving this node but no managed peer.
                satl_overlay::SecurityAssociation {
                    src: me,
                    dst: foreign,
                    spi: 3,
                },
                // A third-party SA not involving this node at all.
                satl_overlay::SecurityAssociation {
                    src: foreign,
                    dst: managed,
                    spi: 4,
                },
            ],
            sps: [vec![satl_sp.clone()], foreign_sps].concat(),
        };

        let filtered = satl_managed_present(me, &desired, &present);
        assert_eq!(filtered.sps, vec![satl_sp]);
        assert_eq!(
            filtered.sas,
            vec![
                satl_overlay::SecurityAssociation {
                    src: me,
                    dst: managed,
                    spi: 1
                },
                satl_overlay::SecurityAssociation {
                    src: managed,
                    dst: me,
                    spi: 2
                },
            ]
        );
    }

    /// A peer no network desires any more stays managed while its SatL SP is
    /// still present — that is how the teardown pass gets to delete its SAs.
    #[test]
    fn a_peer_with_a_lingering_satl_sp_stays_managed_for_teardown() {
        use satl_overlay::desired_sp;

        let me = ip("10.2.2.47");
        let gone_peer = ip("10.2.1.50");
        let present = satl_overlay::PresentSecurity {
            sas: vec![satl_overlay::SecurityAssociation {
                src: me,
                dst: gone_peer,
                spi: 1,
            }],
            sps: vec![desired_sp(me, gone_peer, 4793)],
        };
        let filtered = satl_managed_present(me, &[], &present);
        assert_eq!(filtered.sps.len(), 1);
        assert_eq!(filtered.sas.len(), 1, "the stale SA must stay deletable");
    }
}
