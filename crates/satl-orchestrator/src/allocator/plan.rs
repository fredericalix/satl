// SPDX-License-Identifier: BSD-2-Clause
//! The allocator's decision function: **restore, then allocate** (SWK §9.2).
//!
//! [`plan`] is pure — store objects in, store actions out — and it is the whole
//! allocator. The loop in [`super`] only feeds it a fresh view and proposes
//! what it returns.
//!
//! # The two-phase walk
//!
//! Every pass walks networks → services → tasks **twice**:
//!
//! 1. [`Pass::restore`] claims what the store already records: each network's
//!    subnet, VNI, VXLAN port and per-node gateway addresses, each service's
//!    published ports, each task's addresses. Nothing is invented and nothing
//!    is written.
//! 2. `Pass::allocate_*` hands out what is still missing, from spaces that now
//!    know about every existing allocation.
//!
//! SwarmKit does this once, on becoming leader, because its allocator state is
//! long-lived. SatL rebuilds the state from the store on *every* pass, so the
//! restore phase is not a special leader-start path that could rot: it is the
//! only way the spaces are ever populated. A new leader therefore cannot
//! re-hand-out an in-use subnet, VNI or address, and neither can a leader that
//! missed a watch event.
//!
//! # Ordering
//!
//! Networks are ordered ingress-first, then by creation time (SWK §9.2: the
//! ingress network's preferred subnet is claimed before anything else), and
//! services and tasks by creation time. Actions are emitted in that same order,
//! so truncating an oversized transaction can only ever drop *dependent*
//! actions (a task's address) and never the one it depends on (its network's
//! subnet).
//!
//! # Concurrent spec edits
//!
//! Each action is built by cloning the object **as the view has it** and
//! setting only the allocated fields. The loop re-runs `plan` against a fresh
//! view on a sequence conflict, so a spec edit that raced the allocation is
//! preserved rather than clobbered — SWK §9.3's "targeted merge", obtained by
//! construction instead of by copying fields back onto a stale object.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use satl_core::defaults::{
    DEFAULT_OVERLAY_POOL, DEFAULT_SUBNET_SIZE, INGRESS_PORT_RANGE, MAX_TX_ACTIONS,
    OVERLAY_VNI_RANGE, OVERLAY_VXLAN_PORT_RANGE,
};
use satl_core::{
    Cluster, DesiredState, Endpoint, EndpointSpec, Id, Ipv4Cidr, MacAddr, Network,
    NetworkAttachment, NetworkDriver, Node, ObjectKind, PortConfig, PortProtocol, PublishMode,
    Service, StoreAction, StoreObject, Task, TaskState, TaskStatus, Version,
};

use crate::task::update_task;

use super::error::AllocError;
use super::ports::{PortError, PortSpace};
use super::space::{AddressSpace, SpaceError, SubnetSpace, VniSpace, VtepPortSpace};

/// Status message SwarmKit's allocator writes when a task becomes schedulable
/// (`manager/allocator/network.go`).
pub(crate) const ALLOCATED_MESSAGE: &str = "pending task scheduling";

/// The allocators registered on the task ballot (SWK §9).
///
/// SwarmKit registers "allocator actors" that each vote per task; a task moves
/// `NEW → PENDING` only once **every** registered actor has voted. Exactly one
/// is registered there, and exactly one here: the network allocator. The
/// mechanism is kept rather than collapsed because it is the seam a second
/// allocator (volumes, SWK §18) plugs into — it would register a voter here and
/// vote in [`Pass::allocate_tasks`], and tasks would stop being promoted until
/// both agreed.
pub(crate) const VOTERS: &[&str] = &[NETWORK_VOTER];

/// The network allocator's name on the ballot.
pub(crate) const NETWORK_VOTER: &str = "network";

/// One task's ballot (SWK §9).
#[derive(Debug, Default)]
pub(crate) struct Ballot {
    votes: BTreeSet<&'static str>,
}

impl Ballot {
    /// An empty ballot: no allocator has voted yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Records `voter`'s vote for this task.
    pub(crate) fn vote(&mut self, voter: &'static str) {
        self.votes.insert(voter);
    }

    /// Whether every registered allocator has voted — the condition for
    /// promoting the task to `PENDING`.
    pub(crate) fn is_complete(&self) -> bool {
        VOTERS.iter().all(|voter| self.votes.contains(voter))
    }
}

/// The store objects one pass reasons about.
#[derive(Debug)]
pub(crate) struct PlanInput<'a> {
    /// The cluster object, for the address pools (architecture §11.3).
    pub cluster: Option<&'a Cluster>,
    /// Every network.
    pub networks: &'a [Arc<Network>],
    /// Every service.
    pub services: &'a [Arc<Service>],
    /// Every task.
    pub tasks: &'a [Arc<Task>],
    /// Every node — the ingress network's participant set is *all of them*
    /// (SWK §9.1: one load-balancer attachment per node).
    pub nodes: &'a [Arc<Node>],
}

/// An allocation that could not be made, deferred until the retry window or
/// the next deallocation (SWK §9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    /// Kind of the object that could not be allocated.
    pub kind: ObjectKind,
    /// Its ID.
    pub id: Id,
    /// Its name, for the log line.
    pub name: String,
    /// The version it failed at: any edit to the object retries immediately.
    pub version: Version,
    /// Why it failed.
    pub error: AllocError,
}

/// What one pass decided.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    /// The transaction to propose, in dependency order.
    pub actions: Vec<StoreAction>,
    /// Objects whose allocation failed.
    pub failures: Vec<Failure>,
    /// Whether anything was released — freed space may unblock a deferred
    /// allocation, so the caller retries immediately instead of waiting for the
    /// retry window (SWK §9.3).
    pub freed: bool,
}

/// Objects deferred by an earlier pass: ID → the version they failed at.
///
/// A pass skips an object only while its version is unchanged, so fixing a
/// spec retries immediately and a doomed object is not retried on every tick.
pub(crate) type Deferred = BTreeMap<Id, Version>;

/// Runs one restore-then-allocate pass.
pub(crate) fn plan(input: &PlanInput<'_>, deferred: &Deferred) -> Plan {
    let mut pass = Pass::new(input.cluster, deferred);
    pass.restore(input);
    pass.allocate_networks(input);
    pass.allocate_services(input);
    pass.allocate_tasks(input);
    let mut plan = pass.plan;
    plan.actions.truncate(MAX_TX_ACTIONS);
    plan
}

/// One pass's working state: the four spaces plus what the walk has learned.
struct Pass<'a> {
    deferred: &'a Deferred,
    subnets: SubnetSpace,
    vnis: VniSpace,
    vtep_ports: VtepPortSpace,
    ports: PortSpace,
    /// Address space of every network that has a subnet.
    spaces: BTreeMap<Id, AddressSpace>,
    /// Every network, by ID and by name, for attachment resolution.
    networks: BTreeMap<Id, Arc<Network>>,
    network_ids: BTreeMap<String, Id>,
    /// Which nodes participate in each cluster-scoped network: the nodes
    /// running a non-terminal task attached to it, and therefore the nodes that
    /// need a gateway address on it (SWK §9.3's node-attachment convergence).
    participants: BTreeMap<Id, BTreeSet<Id>>,
    /// The endpoint each service will have once this pass commits.
    endpoints: BTreeMap<Id, Option<Endpoint>>,
    /// Services whose endpoint is not fully allocated: their tasks wait
    /// (SWK §9.4).
    blocked: BTreeSet<Id>,
    /// Objects that failed in this pass, so a later phase does not build on
    /// them.
    failed: BTreeSet<Id>,
    plan: Plan,
}

impl<'a> Pass<'a> {
    fn new(cluster: Option<&Cluster>, deferred: &'a Deferred) -> Self {
        let mut plan = Plan::default();
        let (pools, subnet_size) = match pool_config(cluster) {
            Ok(config) => config,
            Err(error) => {
                // The pool configuration is unusable: nothing can be carved,
                // but everything that needs no address still gets allocated.
                if let Some(cluster) = cluster {
                    plan.failures.push(Failure {
                        kind: ObjectKind::Cluster,
                        id: cluster.id.clone(),
                        name: cluster.spec.annotations.name.clone(),
                        version: cluster.meta.version,
                        error,
                    });
                }
                (Vec::new(), DEFAULT_SUBNET_SIZE)
            }
        };
        Self {
            deferred,
            subnets: SubnetSpace::new(pools, subnet_size),
            vnis: VniSpace::new(OVERLAY_VNI_RANGE),
            vtep_ports: VtepPortSpace::new(OVERLAY_VXLAN_PORT_RANGE),
            ports: PortSpace::new(),
            spaces: BTreeMap::new(),
            networks: BTreeMap::new(),
            network_ids: BTreeMap::new(),
            participants: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            blocked: BTreeSet::new(),
            failed: BTreeSet::new(),
            plan,
        }
    }

    // -- phase 1: restore ---------------------------------------------------

    /// Claims everything the store already records, in the same order the
    /// allocation phase will walk (SWK §9.2).
    fn restore(&mut self, input: &PlanInput<'_>) {
        for network in ordered_networks(input.networks) {
            self.network_ids
                .insert(network.spec.annotations.name.clone(), network.id.clone());
            self.networks
                .insert(network.id.clone(), Arc::clone(&network));
            if !cluster_scoped(&network) {
                continue;
            }
            self.restore_network(&network);
        }
        for service in ordered_services(input.services) {
            let Some(endpoint) = service.endpoint.as_ref() else {
                continue;
            };
            for (port, err) in self.ports.claim_endpoint(&service.id, endpoint) {
                let SpaceError::Occupied(holder) = err else {
                    continue;
                };
                self.fail(
                    ObjectKind::Service,
                    &service.id,
                    &service.spec.annotations.name,
                    service.meta.version,
                    AllocError::PortOccupied {
                        service: service.spec.annotations.name.clone(),
                        service_id: service.id.clone(),
                        port: port.published_port,
                        protocol: port.protocol,
                        holder,
                    },
                );
            }
        }
        for task in ordered_tasks(input.tasks) {
            self.restore_task(&task);
        }
    }

    /// Claims one network's recorded subnet, VNI, VXLAN port and per-node
    /// gateways.
    ///
    /// A conflict or a malformed value fails the network rather than healing
    /// it: re-allocating over an in-use subnet would change the addressing of
    /// jails that are already running on it. The operator gets a named error
    /// and the network keeps what it has.
    fn restore_network(&mut self, network: &Network) {
        let name = network.spec.annotations.name.clone();
        // A VNI two networks both record: the one restored first keeps it.
        if let Some(vni) = network.vni
            && let Err(SpaceError::Occupied(holder)) = self.vnis.claim(vni, &network.id)
        {
            self.fail(
                ObjectKind::Network,
                &network.id,
                &name,
                network.meta.version,
                AllocError::VniOverlap {
                    network: name.clone(),
                    network_id: network.id.clone(),
                    vni,
                    holder,
                },
            );
        }
        // Same for a VXLAN port, claimed for encrypted networks only. A port
        // recorded on an unencrypted one is a restored-store edge — the spec
        // is immutable post-create, so the flag cannot have been turned off:
        // logged and left on the object, the way a stale value on a network
        // the allocator does not manage is ignored, but never claimed, so it
        // blocks nothing.
        if let Some(port) = network.vxlan_port {
            if network.spec.encrypted {
                if let Err(SpaceError::Occupied(holder)) = self.vtep_ports.claim(port, &network.id)
                {
                    self.fail(
                        ObjectKind::Network,
                        &network.id,
                        &name,
                        network.meta.version,
                        AllocError::VxlanPortOverlap {
                            network: name.clone(),
                            network_id: network.id.clone(),
                            port,
                            holder,
                        },
                    );
                }
            } else {
                tracing::warn!(
                    network_id = %network.id,
                    network = %name,
                    vxlan_port = port,
                    "network records a VXLAN port but is not encrypted; leaving the value alone"
                );
            }
        }
        let Some(text) = network.subnet.as_deref() else {
            return;
        };
        let subnet = match text.parse::<Ipv4Cidr>() {
            Ok(subnet) => subnet.network_cidr(),
            Err(err) => {
                self.fail(
                    ObjectKind::Network,
                    &network.id,
                    &name,
                    network.meta.version,
                    AllocError::bad_cidr(&name, &network.id, "recorded subnet", &err),
                );
                return;
            }
        };
        if let Err(SpaceError::Occupied(holder)) = self.subnets.claim(subnet, &network.id) {
            self.fail(
                ObjectKind::Network,
                &network.id,
                &name,
                network.meta.version,
                AllocError::SubnetOverlap {
                    network: name.clone(),
                    network_id: network.id.clone(),
                    subnet: subnet.to_string(),
                    holder,
                },
            );
            return;
        }
        let space = self.space_for(network, subnet);
        self.spaces.insert(network.id.clone(), space);
        self.restore_node_gateways(network);
    }

    /// Claims the gateway address each node already has on this network, before
    /// any task address is claimed and long before anything is handed out.
    ///
    /// A node's gateway is the address on its overlay bridge: the default route
    /// and the DNS listener of every task of its on the network
    /// (`docs/vxlan.md` §8). Moving it under a running jail is a silent black
    /// hole, so a value that cannot be reclaimed fails the network — the
    /// operator gets a named error and nothing is renumbered.
    fn restore_node_gateways(&mut self, network: &Network) {
        let name = network.spec.annotations.name.clone();
        for (node, address) in &network.node_gateways {
            let Some(space) = self.spaces.get_mut(&network.id) else {
                return;
            };
            let reason = match address.parse::<Ipv4Addr>() {
                Err(_) => Some("not an IPv4 address".to_owned()),
                Ok(ip) => match space.claim(ip, node) {
                    Ok(()) => None,
                    Err(SpaceError::Occupied(holder)) => {
                        Some(format!("already claimed by {holder}"))
                    }
                    Err(SpaceError::Outside) => {
                        Some(format!("outside the network's subnet {}", space.subnet()))
                    }
                    Err(SpaceError::Reserved) => Some("reserved address".to_owned()),
                    Err(SpaceError::Exhausted) => Some("subnet is full".to_owned()),
                },
            };
            if let Some(reason) = reason {
                self.fail(
                    ObjectKind::Network,
                    &network.id,
                    &name,
                    network.meta.version,
                    AllocError::InvalidNodeGateway {
                        network: name.clone(),
                        node: node.clone(),
                        address: address.clone(),
                        reason,
                    },
                );
            }
        }
    }

    /// Claims the addresses a task already holds.
    ///
    /// Terminal tasks are claimed too, and only then released by
    /// [`Pass::allocate_tasks`] in the same pass. SwarmKit skips them on
    /// restore; claiming first means an address is never simultaneously
    /// recorded on a task in the store and handed to another one, even though
    /// the stopped task's epair may still be around on the node.
    fn restore_task(&mut self, task: &Task) {
        for attachment in &task.networks {
            let network = self.networks.get(&attachment.network_id).map_or_else(
                || attachment.network_id.to_string(),
                |network| network.spec.annotations.name.clone(),
            );
            // A live task on a node makes that node a participant in the
            // network: its bridge carries the network's gateway address for as
            // long as it runs one (SWK §9.3, `docs/vxlan.md` §8). A terminal
            // task is on its way out and holds nothing.
            if !task.status.state.is_terminal()
                && let Some(node) = task.node_id.as_ref()
                && self
                    .networks
                    .get(&attachment.network_id)
                    .is_some_and(|network| cluster_scoped(network))
            {
                self.participants
                    .entry(attachment.network_id.clone())
                    .or_default()
                    .insert(node.clone());
            }
            for address in &attachment.addresses {
                let Some(space) = self.spaces.get_mut(&attachment.network_id) else {
                    // The network is gone or has no subnet: nothing to claim.
                    continue;
                };
                let reason = match address.parse::<Ipv4Cidr>() {
                    Err(err) => Some(err.to_string()),
                    Ok(cidr) => match space.claim(cidr.addr(), &task.id) {
                        Ok(()) => None,
                        Err(SpaceError::Occupied(holder)) => {
                            Some(format!("already claimed by {holder}"))
                        }
                        Err(SpaceError::Outside) => {
                            Some(format!("outside the network's subnet {}", space.subnet()))
                        }
                        Err(SpaceError::Reserved) => Some("reserved address".to_owned()),
                        Err(SpaceError::Exhausted) => Some("subnet is full".to_owned()),
                    },
                };
                if let Some(reason) = reason {
                    self.fail(
                        ObjectKind::Task,
                        &task.id,
                        &task.annotations.name,
                        task.meta.version,
                        AllocError::InvalidTaskAddress {
                            task: task.id.clone(),
                            network,
                            address: address.clone(),
                            reason,
                        },
                    );
                    break;
                }
            }
        }
    }

    // -- phase 2: allocate --------------------------------------------------

    /// Gives every cluster-scoped network a subnet, a VNI, a VXLAN port (when
    /// encrypted) and one gateway address per participating node.
    ///
    /// The ingress network's participant set is **every node** (SWK §9.1's
    /// load-balancer attachment): that is what lets a node with no replica
    /// route into the mesh, and it is filled here, before any per-network
    /// work, so `node_gateways_for` hands every node a gateway address on it
    /// — the address the mesh's SNAT rule sources from.
    fn allocate_networks(&mut self, input: &PlanInput<'_>) {
        // A service publishing ingress ports needs the ingress network
        // (SWK §9.3). Create it lazily — only then, so a cluster without
        // ingress publishing never grows a network it does not use (and the
        // visible surface stays Docker's: `network ls` hides `ingress`).
        // Bare Create this pass; the next pass allocates subnet, VNI and
        // per-node gateways like any fresh network (a same-transaction Update
        // cannot know the Create's store version). The network is registered
        // with this pass anyway, so a task's attachment resolves to it and
        // waits on its subnet like on any un-allocated network.
        let wants_ingress = input.services.iter().any(|service| {
            service.spec.endpoint.as_ref().is_some_and(|spec| {
                spec.ports
                    .iter()
                    .any(|port| port.publish_mode == PublishMode::Ingress)
            })
        });
        if wants_ingress && !input.networks.iter().any(|network| network.spec.ingress) {
            tracing::info!(
                "a service publishes an ingress port; creating the default ingress network"
            );
            let network = Arc::new(Network::default_ingress());
            let id = network.id.clone();
            self.network_ids
                .insert(network.spec.annotations.name.clone(), id.clone());
            self.plan
                .actions
                .push(StoreAction::Create(StoreObject::Network(
                    (*network).clone(),
                )));
            self.networks.insert(id, network);
        }
        for network in ordered_networks(input.networks) {
            if network.spec.ingress {
                self.participants.insert(
                    network.id.clone(),
                    input.nodes.iter().map(|node| node.id.clone()).collect(),
                );
            }
        }
        let mut ingress: Option<Id> = None;
        for network in ordered_networks(input.networks) {
            if !cluster_scoped(&network) {
                // Bridge networks are node-local (architecture §11.1): their
                // subnet comes from the node's own IPAM, not from Raft.
                continue;
            }
            let name = network.spec.annotations.name.clone();
            if network.spec.ingress {
                match &ingress {
                    Some(holder) => {
                        self.fail(
                            ObjectKind::Network,
                            &network.id,
                            &name,
                            network.meta.version,
                            AllocError::SecondIngressNetwork {
                                network: name.clone(),
                                network_id: network.id.clone(),
                                holder: holder.clone(),
                            },
                        );
                        continue;
                    }
                    None => ingress = Some(network.id.clone()),
                }
            }
            if self.failed.contains(&network.id)
                || self.is_deferred(&network.id, network.meta.version)
            {
                continue;
            }
            self.allocate_network(&network, &name);
        }
    }

    /// One network: VNI first (cheap to give back), then the VXLAN port for
    /// an encrypted one (equally cheap), then the subnet.
    fn allocate_network(&mut self, network: &Network, name: &str) {
        let (vni, vni_is_new) = match self.vni_for(network, name) {
            Ok(vni) => vni,
            Err(error) => return self.fail_network(network, name, error),
        };
        // The VTEP port is like the VNI — one per network, cluster-wide — but
        // only encrypted networks need one: it is the UDP port both ends'
        // VTEPs bind, and an unencrypted network has no SPD entry to
        // disambiguate by it. A port already recorded on an unencrypted
        // network is left alone (see `restore_network`).
        let (vxlan_port, port_is_new) = match self.vxlan_port_for(network, name) {
            Ok(port) => port,
            Err(error) => {
                if vni_is_new {
                    self.vnis.release(&network.id);
                }
                return self.fail_network(network, name, error);
            }
        };
        // An already-allocated network keeps the subnet its address space was
        // restored with: changing the addressing of a network that has running
        // tasks on it is not something to do behind their back.
        let subnet = if let Some(space) = self.spaces.get(&network.id) {
            space.subnet()
        } else {
            let subnet = match self.subnet_for(network, name) {
                Ok(subnet) => subnet,
                Err(error) => {
                    if vni_is_new {
                        self.vnis.release(&network.id);
                    }
                    if port_is_new {
                        self.vtep_ports.release(&network.id);
                    }
                    return self.fail_network(network, name, error);
                }
            };
            let space = self.space_for(network, subnet);
            if self.failed.contains(&network.id) {
                // The requested gateway or IP range is unusable. Allocate
                // nothing: a network whose object records no subnet must not
                // have tasks addressed out of one, so its tasks wait until the
                // operator fixes the spec.
                if vni_is_new {
                    self.vnis.release(&network.id);
                }
                if port_is_new {
                    self.vtep_ports.release(&network.id);
                }
                return;
            }
            self.spaces.insert(network.id.clone(), space);
            subnet
        };
        let node_gateways = match self.node_gateways_for(network, name) {
            Ok(node_gateways) => node_gateways,
            Err(error) => return self.fail_network(network, name, error),
        };

        let subnet_text = subnet.to_string();
        if network.subnet.as_deref() == Some(subnet_text.as_str())
            && network.vni == Some(vni)
            && network.vxlan_port == vxlan_port
            && network.node_gateways == node_gateways
        {
            return;
        }
        if network
            .node_gateways
            .keys()
            .any(|node| !node_gateways.contains_key(node))
        {
            // A node stopped participating: its address is free again — from
            // the next pass on, never this one (see `node_gateways_for`).
            self.plan.freed = true;
        }
        tracing::info!(
            network_id = %network.id,
            network = name,
            subnet = %subnet_text,
            vni,
            vxlan_port = ?vxlan_port,
            node_gateways = node_gateways.len(),
            driver = ?network.spec.driver,
            "network allocated"
        );
        self.plan.actions.push(update_network(network, |allocated| {
            allocated.subnet = Some(subnet_text);
            allocated.vni = Some(vni);
            allocated.vxlan_port = vxlan_port;
            allocated.node_gateways = node_gateways;
        }));
    }

    /// The VNI this network should have: the one it records, or the lowest
    /// free one in the range. The bool says the VNI was newly claimed in this
    /// pass (and must be given back if a later step of the allocation fails).
    fn vni_for(&mut self, network: &Network, name: &str) -> Result<(u32, bool), AllocError> {
        if let Some(vni) = network.vni {
            return Ok((vni, false));
        }
        let vni = self
            .vnis
            .allocate(&network.id)
            .map_err(|_| AllocError::VniExhausted {
                network: name.to_owned(),
                network_id: network.id.clone(),
                start: *self.vnis.range().start(),
                end: *self.vnis.range().end(),
            })?;
        Ok((vni, true))
    }

    /// The VTEP port this network should have: the one it records, the lowest
    /// free one in the pool for an encrypted network, or `None` for an
    /// unencrypted one. The bool says the port was newly claimed in this pass
    /// (and must be given back if a later step of the allocation fails).
    fn vxlan_port_for(
        &mut self,
        network: &Network,
        name: &str,
    ) -> Result<(Option<u16>, bool), AllocError> {
        match network.vxlan_port {
            Some(port) => Ok((Some(port), false)),
            None if !network.spec.encrypted => Ok((None, false)),
            None => {
                let port = self.vtep_ports.allocate(&network.id).map_err(|_| {
                    AllocError::VxlanPortExhausted {
                        network: name.to_owned(),
                        network_id: network.id.clone(),
                        start: *self.vtep_ports.range().start(),
                        end: *self.vtep_ports.range().end(),
                    }
                })?;
                Ok((Some(port), true))
            }
        }
    }

    /// The gateway address of every node participating in this network: one per
    /// node, from the network's own subnet (SWK §9.1, `docs/vxlan.md` §8).
    ///
    /// The map is rebuilt from the participants rather than edited, which is
    /// what makes both halves work at once:
    ///
    /// - a node that already has one gets it back — [`AddressSpace::allocate`]
    ///   returns what the restore phase claimed for it — so a gateway is stable
    ///   per `(network, node)` across allocator restarts and leadership changes,
    ///   exactly as a task address is;
    /// - a node that no longer runs any non-terminal task on the network is
    ///   simply absent, which releases its address. The claim the restore phase
    ///   made still stands for the rest of the pass, so the address cannot be
    ///   handed to another node in the pass that gave it up — the node's bridge
    ///   may well still be carrying it, and two bridges on one L2 segment with
    ///   one address is the bug this whole shape exists to avoid. The pass sets
    ///   [`Plan::freed`], so the next one hands it out (SWK §9.3).
    fn node_gateways_for(
        &mut self,
        network: &Network,
        name: &str,
    ) -> Result<BTreeMap<Id, String>, AllocError> {
        let Some(nodes) = self.participants.get(&network.id) else {
            return Ok(BTreeMap::new());
        };
        let Some(space) = self.spaces.get_mut(&network.id) else {
            return Ok(BTreeMap::new());
        };
        let subnet = space.subnet();
        let capacity = space.capacity();
        let mut gateways = BTreeMap::new();
        let mut fresh = Vec::new();
        for node in nodes {
            let address = space
                .allocate(node)
                .map_err(|_| AllocError::NodeGatewayExhausted {
                    network: name.to_owned(),
                    subnet: subnet.to_string(),
                    capacity,
                    node: node.clone(),
                })?;
            let text = address.to_string();
            if network.node_gateways.get(node) != Some(&text) {
                fresh.push((node.clone(), address));
            }
            gateways.insert(node.clone(), text);
        }
        for (node, address) in fresh {
            tracing::info!(
                network_id = %network.id,
                network = name,
                node_id = %node,
                gateway = %address,
                subnet = %subnet,
                // Derived, never discovered, like a task's (§11.2): the node
                // sets this MAC on its overlay bridge.
                mac = %MacAddr::from_ipv4(address),
                "node gateway allocated"
            );
        }
        for (node, address) in &network.node_gateways {
            if !gateways.contains_key(node) {
                tracing::info!(
                    network_id = %network.id,
                    network = name,
                    node_id = %node,
                    gateway = %address,
                    "node gateway released: the node runs no more tasks on this network"
                );
            }
        }
        Ok(gateways)
    }

    /// The subnet to give a network that has none: the one the operator asked
    /// for, or the next free one from the pools.
    fn subnet_for(&mut self, network: &Network, name: &str) -> Result<Ipv4Cidr, AllocError> {
        let requested = network
            .spec
            .ipam
            .as_ref()
            .and_then(|ipam| ipam.subnet.as_deref());
        let Some(text) = requested else {
            return self.subnets.allocate(&network.id).map_err(|_| {
                let pools = self
                    .subnets
                    .pools()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                AllocError::PoolExhausted {
                    network: name.to_owned(),
                    network_id: network.id.clone(),
                    pools,
                    subnet_size: self.subnets.subnet_size(),
                }
            });
        };
        let subnet = text
            .parse::<Ipv4Cidr>()
            .map_err(|err| AllocError::bad_cidr(name, &network.id, "requested subnet", &err))?
            .network_cidr();
        if subnet.prefix_len() > 30 {
            return Err(AllocError::InvalidNetworkAddressing {
                network: name.to_owned(),
                network_id: network.id.clone(),
                reason: format!(
                    "requested subnet {subnet} is too small: a /31 or /32 has no room for a \
                     gateway and a task"
                ),
            });
        }
        match self.subnets.claim(subnet, &network.id) {
            Ok(()) => Ok(subnet),
            Err(SpaceError::Occupied(holder)) => Err(AllocError::SubnetOverlap {
                network: name.to_owned(),
                network_id: network.id.clone(),
                subnet: subnet.to_string(),
                holder,
            }),
            Err(_) => Err(AllocError::InvalidNetworkAddressing {
                network: name.to_owned(),
                network_id: network.id.clone(),
                reason: format!("requested subnet {subnet} cannot be claimed"),
            }),
        }
    }

    /// The address space of a network: its subnet, the sub-range addresses come
    /// from, and the reservations on top of the `.1` convention.
    fn space_for(&mut self, network: &Network, subnet: Ipv4Cidr) -> AddressSpace {
        let range = self.range_of(network, subnet);
        let mut space = AddressSpace::new(subnet, range);
        if let Some(gateway) = self.requested_gateway(network, subnet) {
            space.reserve(gateway);
        }
        space
    }

    /// The gateway address the operator asked for (`--gateway`), which on a
    /// cluster network is honoured as a **reservation**: an overlay's gateways
    /// are per node ([`Network::node_gateways`]), so one requested address can
    /// only mean "hand this one to nobody" (architecture §11.3).
    ///
    /// A value outside the subnet is reported and ignored; `.1` is reserved
    /// either way.
    fn requested_gateway(&mut self, network: &Network, subnet: Ipv4Cidr) -> Option<Ipv4Addr> {
        let text = network
            .spec
            .ipam
            .as_ref()
            .and_then(|ipam| ipam.gateway.as_deref())?;
        let name = network.spec.annotations.name.clone();
        let reason = match text.parse::<Ipv4Addr>() {
            Ok(gateway) if subnet.contains(gateway) && gateway != subnet.broadcast() => {
                return Some(gateway);
            }
            Ok(gateway) => format!("gateway {gateway} is not a usable address in {subnet}"),
            Err(_) => format!("gateway {text:?} is not an IPv4 address"),
        };
        self.fail(
            ObjectKind::Network,
            &network.id,
            &name,
            network.meta.version,
            AllocError::InvalidNetworkAddressing {
                network: name.clone(),
                network_id: network.id.clone(),
                reason,
            },
        );
        None
    }

    /// The sub-range tasks are allocated from: `ipam.ip_range` when it is
    /// inside the subnet, else the whole subnet.
    fn range_of(&mut self, network: &Network, subnet: Ipv4Cidr) -> Ipv4Cidr {
        let requested = network
            .spec
            .ipam
            .as_ref()
            .and_then(|ipam| ipam.ip_range.as_deref());
        let Some(text) = requested else {
            return subnet;
        };
        let name = network.spec.annotations.name.clone();
        let reason = match text.parse::<Ipv4Cidr>() {
            Ok(range) if subnet.contains_subnet(range.network_cidr()) => {
                return range.network_cidr();
            }
            Ok(range) => format!("IP range {range} is not inside the subnet {subnet}"),
            Err(err) => format!("IP range: {err}"),
        };
        self.fail(
            ObjectKind::Network,
            &network.id,
            &name,
            network.meta.version,
            AllocError::InvalidNetworkAddressing {
                network: name.clone(),
                network_id: network.id.clone(),
                reason,
            },
        );
        subnet
    }

    /// Allocates each service's published ports (SWK §9.5). No VIPs: SatL
    /// resolves services by DNS round-robin (architecture §11.5).
    fn allocate_services(&mut self, input: &PlanInput<'_>) {
        for service in ordered_services(input.services) {
            let name = service.spec.annotations.name.clone();
            let deferred = self.failed.contains(&service.id)
                || self.is_deferred(&service.id, service.meta.version);
            let planned = if deferred {
                service.endpoint.clone()
            } else {
                match self.plan_endpoint(&service, &name) {
                    Ok(planned) => planned,
                    Err(error) => {
                        self.fail(
                            ObjectKind::Service,
                            &service.id,
                            &name,
                            service.meta.version,
                            error,
                        );
                        service.endpoint.clone()
                    }
                }
            };
            if !fully_allocated(service.spec.endpoint.as_ref(), planned.as_ref()) {
                self.blocked.insert(service.id.clone());
            }
            if planned.as_ref() != service.endpoint.as_ref() {
                if released_ports(service.endpoint.as_ref(), planned.as_ref()) {
                    self.plan.freed = true;
                }
                tracing::info!(
                    service_id = %service.id,
                    service = %name,
                    ports = ?planned.as_ref().map(|endpoint| endpoint
                        .ports
                        .iter()
                        .map(|port| format!("{}:{}/{}", port.published_port, port.target_port, port.protocol))
                        .collect::<Vec<_>>()),
                    "service endpoint allocated"
                );
                self.plan
                    .actions
                    .push(update_service(&service, |allocated| {
                        allocated.endpoint.clone_from(&planned);
                    }));
            }
            self.endpoints.insert(service.id.clone(), planned);
        }
    }

    /// The endpoint a service should have: `None` when its spec has no
    /// endpoint (which deallocates the ports it used to hold).
    fn plan_endpoint(
        &mut self,
        service: &Service,
        name: &str,
    ) -> Result<Option<Endpoint>, AllocError> {
        let Some(spec) = service.spec.endpoint.as_ref() else {
            return Ok(None);
        };
        let ports = self
            .ports
            .allocate_service(&service.id, spec, service.endpoint.as_ref())
            .map_err(|err| port_error(name, &service.id, err))?;
        Ok(Some(Endpoint {
            spec: spec.clone(),
            ports,
        }))
    }

    /// Gives every `NEW` task its attachments and addresses, copies its
    /// service's endpoint, and votes it into `PENDING` (SWK §9.4). Terminal
    /// tasks are deallocated.
    fn allocate_tasks(&mut self, input: &PlanInput<'_>) {
        let services: BTreeMap<Id, Arc<Service>> = input
            .services
            .iter()
            .map(|service| (service.id.clone(), Arc::clone(service)))
            .collect();
        for task in ordered_tasks(input.tasks) {
            if task.status.state.is_terminal() {
                self.deallocate_task(&task);
                continue;
            }
            // Attachments are built once and never revised: a task object is
            // effectively immutable after allocation (architecture §4), so a
            // task past NEW keeps what it was given, and one heading for
            // shutdown is never allocated at all.
            if task.status.state != TaskState::New
                || task.desired_state > DesiredState::Running
                || self.failed.contains(&task.id)
                || self.is_deferred(&task.id, task.meta.version)
            {
                continue;
            }
            let service = task.service_id.as_ref().and_then(|id| services.get(id));
            let service_name =
                service.map_or_else(String::new, |service| service.spec.annotations.name.clone());
            // A task waits for its service's ports before anything else
            // (SWK §9.4).
            if task
                .service_id
                .as_ref()
                .is_some_and(|id| self.blocked.contains(id))
            {
                tracing::debug!(
                    task_id = %task.id,
                    service = %service_name,
                    "task allocation waiting for its service's endpoint"
                );
                continue;
            }
            let attachments = match self.attachments_for(&task, service.map(AsRef::as_ref)) {
                Ok(Some(attachments)) => attachments,
                Ok(None) => continue,
                Err(error) => {
                    self.fail(
                        ObjectKind::Task,
                        &task.id,
                        &task.annotations.name,
                        task.meta.version,
                        error,
                    );
                    continue;
                }
            };
            let endpoint = match task.service_id.as_ref() {
                Some(service_id) => self.endpoints.get(service_id).cloned().flatten(),
                None => task.endpoint.clone(),
            };

            let mut ballot = Ballot::new();
            ballot.vote(NETWORK_VOTER);
            if !ballot.is_complete() {
                tracing::debug!(
                    task_id = %task.id,
                    "task allocated by the network allocator; waiting for the other voters"
                );
                continue;
            }
            tracing::info!(
                task_id = %task.id,
                service_id = ?task.service_id,
                slot = task.slot,
                attachments = attachments.len(),
                from = %TaskState::New,
                to = %TaskState::Pending,
                "task allocated"
            );
            self.plan.actions.push(update_task(&task, |allocated| {
                allocated.networks = attachments;
                allocated.endpoint = endpoint;
                allocated.status = TaskStatus::new(TaskState::Pending, ALLOCATED_MESSAGE);
            }));
        }
    }

    /// The attachments a task should carry, addresses included.
    ///
    /// `Ok(None)` means "wait": a network it attaches to has no subnet yet.
    fn attachments_for(
        &mut self,
        task: &Task,
        service: Option<&Service>,
    ) -> Result<Option<Vec<NetworkAttachment>>, AllocError> {
        let service_name =
            service.map_or_else(String::new, |service| service.spec.annotations.name.clone());
        let mut attachments = if task.networks.is_empty() {
            let mut built = Vec::with_capacity(task.spec.networks.len());
            for config in &task.spec.networks {
                let id = self.resolve_network(&config.target).ok_or_else(|| {
                    AllocError::UnknownNetwork {
                        task: task.id.clone(),
                        service: service_name.clone(),
                        target: config.target.clone(),
                    }
                })?;
                built.push(NetworkAttachment {
                    network_id: id,
                    addresses: Vec::new(),
                    aliases: config.aliases.clone(),
                });
            }
            built
        } else {
            task.networks.clone()
        };
        // SWK §9.3: a service publishing ingress ports gets an attachment to
        // the ingress network — that address is what the mesh routes to.
        // User-specified attachments win; a second ingress attachment is
        // never added. The network is created lazily (allocate_networks), so
        // its absence means "wait a pass", not "fail".
        let publishes_ingress = service.is_some_and(|service| {
            service.spec.endpoint.as_ref().is_some_and(|spec| {
                spec.ports
                    .iter()
                    .any(|port| port.publish_mode == PublishMode::Ingress)
            })
        });
        if publishes_ingress
            && !attachments.iter().any(|attachment| {
                self.networks
                    .get(&attachment.network_id)
                    .is_some_and(|network| network.spec.ingress)
            })
        {
            let Some(ingress) = self
                .networks
                .values()
                .find(|network| network.spec.ingress)
                .map(|network| network.id.clone())
            else {
                tracing::debug!(
                    task_id = %task.id,
                    service = %service_name,
                    "task allocation waiting for the ingress network to exist"
                );
                return Ok(None);
            };
            attachments.push(NetworkAttachment {
                network_id: ingress,
                addresses: Vec::new(),
                aliases: Vec::new(),
            });
        }
        for attachment in &mut attachments {
            let network = self.networks.get(&attachment.network_id).ok_or_else(|| {
                AllocError::UnknownNetwork {
                    task: task.id.clone(),
                    service: service_name.clone(),
                    target: attachment.network_id.to_string(),
                }
            })?;
            let name = network.spec.annotations.name.clone();
            // Node-local networks get their address from the node's own IPAM
            // (architecture §11.1); the attachment is recorded without one.
            if !cluster_scoped(network) || !attachment.addresses.is_empty() {
                continue;
            }
            let Some(space) = self.spaces.get_mut(&attachment.network_id) else {
                // Nothing is written for this task, so an address taken for an
                // earlier attachment of it stays claimed for the rest of the
                // pass and is handed to the same task again on the next one.
                tracing::debug!(
                    task_id = %task.id,
                    network = %name,
                    "task allocation waiting for its network's subnet"
                );
                return Ok(None);
            };
            let subnet = space.subnet();
            let capacity = space.capacity();
            let address = space
                .allocate(&task.id)
                .map_err(|_| AllocError::SubnetExhausted {
                    network: name.clone(),
                    subnet: subnet.to_string(),
                    capacity,
                    task: task.id.clone(),
                })?;
            tracing::info!(
                task_id = %task.id,
                network = %name,
                address = %address,
                subnet = %subnet,
                // Derived, never discovered: the node sets this MAC on the
                // jail's interface so the FDB needs no learning (§11.2).
                mac = %MacAddr::from_ipv4(address),
                "task address allocated"
            );
            attachment
                .addresses
                .push(format!("{address}/{}", subnet.prefix_len()));
        }
        Ok(Some(attachments))
    }

    /// Releases the addresses of a terminal task (SWK §9.4).
    ///
    /// The attachment shells (network ID and aliases) are kept: they are a
    /// record of what the task was on, and the addresses are what was
    /// allocated.
    fn deallocate_task(&mut self, task: &Task) {
        if task
            .networks
            .iter()
            .all(|attachment| attachment.addresses.is_empty())
        {
            return;
        }
        for attachment in &task.networks {
            if let Some(space) = self.spaces.get_mut(&attachment.network_id) {
                space.release(&task.id);
            }
        }
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            state = %task.status.state,
            addresses = ?task
                .networks
                .iter()
                .flat_map(|attachment| attachment.addresses.clone())
                .collect::<Vec<_>>(),
            "task addresses released"
        );
        self.plan.freed = true;
        self.plan.actions.push(update_task(task, |released| {
            for attachment in &mut released.networks {
                attachment.addresses.clear();
            }
        }));
    }

    // -- helpers ------------------------------------------------------------

    /// Resolves a `TaskSpec` network target: ID first, then name.
    fn resolve_network(&self, target: &str) -> Option<Id> {
        let by_id = target
            .parse::<Id>()
            .ok()
            .filter(|id| self.networks.contains_key(id));
        by_id.or_else(|| self.network_ids.get(target).cloned())
    }

    /// Whether an earlier pass deferred this object at this very version.
    fn is_deferred(&self, id: &Id, version: Version) -> bool {
        self.deferred.get(id) == Some(&version)
    }

    fn fail(&mut self, kind: ObjectKind, id: &Id, name: &str, version: Version, error: AllocError) {
        self.failed.insert(id.clone());
        self.plan.failures.push(Failure {
            kind,
            id: id.clone(),
            name: name.to_owned(),
            version,
            error,
        });
    }

    /// [`Pass::fail`] for the network being allocated.
    fn fail_network(&mut self, network: &Network, name: &str, error: AllocError) {
        self.fail(
            ObjectKind::Network,
            &network.id,
            name,
            network.meta.version,
            error,
        );
    }
}

/// The pools and subnet size to carve from, from the cluster object
/// (architecture §11.3; the defaults are §15).
fn pool_config(cluster: Option<&Cluster>) -> Result<(Vec<Ipv4Cidr>, u8), AllocError> {
    let default_pool = || {
        DEFAULT_OVERLAY_POOL
            .parse::<Ipv4Cidr>()
            .map_or_else(|_| Vec::new(), |pool| vec![pool])
    };
    let Some(cluster) = cluster else {
        return Ok((default_pool(), DEFAULT_SUBNET_SIZE));
    };
    let subnet_size = cluster.spec.subnet_size;
    if !(1..=30).contains(&subnet_size) {
        return Err(AllocError::InvalidSubnetSize { subnet_size });
    }
    let mut pools = Vec::with_capacity(cluster.spec.default_address_pool.len());
    for text in &cluster.spec.default_address_pool {
        let pool = text
            .parse::<Ipv4Cidr>()
            .map_err(|err| AllocError::InvalidPool {
                pool: text.clone(),
                reason: err.to_string(),
            })?;
        if pool.prefix_len() > subnet_size {
            return Err(AllocError::InvalidPool {
                pool: text.clone(),
                reason: format!(
                    "a /{} pool cannot be carved into /{subnet_size} subnets",
                    pool.prefix_len()
                ),
            });
        }
        pools.push(pool.network_cidr());
    }
    if pools.is_empty() {
        // A cluster object with no pool configured: the architecture §15
        // default is what `satl swarm init` documents, so use it rather than
        // refusing to allocate.
        pools = default_pool();
    }
    Ok((pools, subnet_size))
}

/// Whether a network's addressing is the cluster's business.
///
/// Overlay networks only: a bridge network is node-local (architecture §11.1)
/// and its subnet comes from each node's own IPAM, never from Raft.
fn cluster_scoped(network: &Network) -> bool {
    matches!(network.spec.driver, NetworkDriver::Overlay)
}

/// Whether `endpoint` is what `spec` asks for, with every ingress port the spec
/// declares actually published — the condition a task waits on (SWK §9.4).
///
/// Checked per spec port rather than over the endpoint's own list: an endpoint
/// can carry *fewer* ports than the spec asks for (the REST backend writes the
/// host-mode ones at create time and leaves the ingress ones to the allocator),
/// and that is precisely the not-yet-allocated case.
fn fully_allocated(spec: Option<&EndpointSpec>, endpoint: Option<&Endpoint>) -> bool {
    match (spec, endpoint) {
        (None, endpoint) => endpoint.is_none(),
        (Some(spec), None) => spec.ports.is_empty(),
        (Some(spec), Some(endpoint)) => {
            endpoint.spec == *spec
                && ingress_of(&spec.ports).all(|wanted| {
                    ingress_of(&endpoint.ports).any(|allocated| {
                        allocated.name == wanted.name
                            && allocated.protocol == wanted.protocol
                            && allocated.target_port == wanted.target_port
                            && allocated.published_port != 0
                    })
                })
        }
    }
}

/// The ingress entries of a port list.
fn ingress_of(ports: &[PortConfig]) -> impl Iterator<Item = &PortConfig> {
    ports
        .iter()
        .filter(|port| port.publish_mode == PublishMode::Ingress)
}

/// Whether moving from `before` to `after` gives up any published port.
fn released_ports(before: Option<&Endpoint>, after: Option<&Endpoint>) -> bool {
    let published = |endpoint: Option<&Endpoint>| -> BTreeSet<(u16, PortProtocol)> {
        endpoint
            .map(|endpoint| {
                ingress_of(&endpoint.ports)
                    .filter(|port| port.published_port != 0)
                    .map(|port| (port.published_port, port.protocol))
                    .collect()
            })
            .unwrap_or_default()
    };
    !published(before).is_subset(&published(after))
}

/// Names a [`PortError`] after the service it belongs to.
fn port_error(service: &str, service_id: &Id, err: PortError) -> AllocError {
    match err {
        PortError::Occupied {
            port,
            protocol,
            holder,
        } => AllocError::PortOccupied {
            service: service.to_owned(),
            service_id: service_id.clone(),
            port,
            protocol,
            holder,
        },
        PortError::Duplicate { port, protocol } => AllocError::PortDuplicate {
            service: service.to_owned(),
            service_id: service_id.clone(),
            port,
            protocol,
        },
        PortError::DynamicExhausted { protocol } => AllocError::PortRangeExhausted {
            service: service.to_owned(),
            service_id: service_id.clone(),
            protocol,
            start: *INGRESS_PORT_RANGE.start(),
            end: *INGRESS_PORT_RANGE.end(),
        },
    }
}

/// Networks, ingress first (SWK §9.2), then oldest first.
fn ordered_networks(networks: &[Arc<Network>]) -> Vec<Arc<Network>> {
    let mut sorted = networks.to_vec();
    sorted.sort_by(|a, b| {
        b.spec.ingress.cmp(&a.spec.ingress).then_with(|| {
            created_key(a.meta.created_at, &a.id).cmp(&created_key(b.meta.created_at, &b.id))
        })
    });
    sorted
}

/// Services, oldest first.
fn ordered_services(services: &[Arc<Service>]) -> Vec<Arc<Service>> {
    let mut sorted = services.to_vec();
    sorted.sort_by_key(|service| created_key(service.meta.created_at, &service.id));
    sorted
}

/// Tasks, oldest first.
fn ordered_tasks(tasks: &[Arc<Task>]) -> Vec<Arc<Task>> {
    let mut sorted = tasks.to_vec();
    sorted.sort_by_key(|task| created_key(task.meta.created_at, &task.id));
    sorted
}

/// A total order over objects: creation time, then ID, so a pass is
/// deterministic even for objects created in the same transaction.
fn created_key(created_at: SystemTime, id: &Id) -> (SystemTime, Id) {
    (created_at, id.clone())
}

/// Builds an `Update` for `network` with only the allocated fields changed.
fn update_network(network: &Network, mutate: impl FnOnce(&mut Network)) -> StoreAction {
    let mut next = network.clone();
    mutate(&mut next);
    next.meta.updated_at = SystemTime::now();
    StoreAction::Update(StoreObject::Network(next))
}

/// Builds an `Update` for `service` with only the allocated fields changed.
fn update_service(service: &Service, mutate: impl FnOnce(&mut Service)) -> StoreAction {
    let mut next = service.clone();
    mutate(&mut next);
    next.meta.updated_at = SystemTime::now();
    StoreAction::Update(StoreObject::Service(next))
}
