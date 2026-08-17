// SPDX-License-Identifier: BSD-2-Clause
//! The assignment set: what one node should be running, and the secrets,
//! configs and networks those tasks reference (SWK §13.4,
//! `proto/dispatcher.proto`).
//!
//! This module is **pure**: no store, no clock, no network. It is the part of
//! the dispatcher that is easy to get subtly wrong, so it is the part that is
//! exhaustively unit-tested.
//!
//! # The set
//!
//! A task belongs to node *N*'s set when it is bound to *N* and its observed
//! state has reached `ASSIGNED`. The scheduler writes `ASSIGNED`; everything
//! above it is written by the agent, so a task below `ASSIGNED` is not the
//! agent's business yet.
//!
//! # Dependency reference counting (the rule implementers get wrong)
//!
//! A secret, config or network is shipped with the **first** task that
//! references it and withdrawn when the **last** referencing task goes away.
//! "Goes away" includes a case that has nothing to do with removal: a task
//! that moves **past `RUNNING`** — to `COMPLETE`, `SHUTDOWN`, `FAILED`,
//! `REJECTED`, `ORPHANED` — releases its dependencies even though the task
//! object itself is otherwise unchanged and stays in the set. An agent must
//! therefore never assume a secret stays valid because "the task is still
//! there", and this tracker must emit the `REMOVE` for it.
//!
//! # Networks are a dependency with a moving payload
//!
//! A network assignment is not just the [`Network`] object: it carries the
//! **endpoint table** ([`NetworkEndpoint`]) the node needs to program its FDB
//! and static ARP entries — per endpoint, the overlay address (from which both
//! ends *derive* the MAC) and the underlay VTEP address of the node running it
//! (architecture §11.2, `docs/vxlan.md` §7). Workers hold no store
//! (invariant #3), so this table is the only channel through which a node
//! learns about a peer's endpoints.
//!
//! That makes networks the one dependency whose payload changes while the
//! object does not: a task scheduled on *another* node re-ships the network to
//! *this* one. [`NetworkAssignment::endpoint_changes`] is what turns that into
//! a diff worth logging, and [`AssignmentTracker::observe_network`] suppresses
//! the no-op case.
//!
//! # Change suppression
//!
//! A task update that changes nothing the agent can act on is not shipped.
//! "Stable" fields are everything except the observed status: the spec is
//! immutable (architecture §4 rule 4) and the observed status is the agent's
//! own, echoed back through the store — re-sending it would make every status
//! report bounce back as an assignment and cancel the controller operation in
//! flight. What the agent *does* act on is `desired_state`, so a desired-state
//! move is always shipped.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use satl_core::{Config, Id, MacAddr, Network, Secret, Task, TaskState};
use serde::{Deserialize, Serialize};

/// Which kind of object a change concerns.
///
/// The declaration order **is** the application order for `UPDATE`s:
/// dependencies before dependents (`proto/dispatcher.proto`: "apply secrets
/// first, then configs, then networks, then tasks"). `REMOVE`s use
/// [`ObjectRef::teardown_rank`], which is the reverse — see there for why the
/// two directions are not interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectRef {
    /// A secret one of the node's tasks references.
    Secret,
    /// A config one of the node's tasks references.
    Config,
    /// A network one of the node's tasks attaches to.
    Network,
    /// A task to run.
    Task,
}

impl ObjectRef {
    /// Rank in **teardown** order: dependents before dependencies, i.e. the
    /// reverse of the [`Ord`] order.
    ///
    /// Removals cannot reuse the application order. Releasing a task before
    /// the network it is attached to is not a matter of taste: a node that
    /// destroys the vxlan interface and the bridge while a jail still has an
    /// epair in it black-holes that jail's traffic and can leak the epair
    /// (`docs/vxlan.md` §8, "do not remove a network's gateway address while
    /// tasks are attached", and the VNET-cleanup gotcha in CLAUDE.md). The
    /// same order is the right one for secrets and configs — a container that
    /// is still running should not have its tmpfs pulled first — it just did
    /// not matter until a dependency became a kernel object.
    #[must_use]
    pub fn teardown_rank(self) -> u8 {
        match self {
            Self::Task => 0,
            Self::Network => 1,
            Self::Config => 2,
            Self::Secret => 3,
        }
    }

    /// The four kinds in application order (dependencies first).
    #[must_use]
    pub fn apply_order() -> [Self; 4] {
        [Self::Secret, Self::Config, Self::Network, Self::Task]
    }

    /// The four kinds in teardown order (dependents first).
    #[must_use]
    pub fn teardown_order() -> [Self; 4] {
        [Self::Task, Self::Network, Self::Config, Self::Secret]
    }
}

/// One endpoint on a network: a task, where it runs, how to reach it, and
/// what it is called.
///
/// This is the unit of FDB distribution (architecture §11.2) **and** of
/// service discovery on nodes that hold no replicated store (§11.5): a worker
/// answers DNS from this table, so the names and the observed state travel
/// here. Everything a node needs in order to program an entry for a
/// **remote** endpoint is:
///
/// ```text
/// vxlan-ftable add satl-vx-<net> <mac(addr)> <vtep>   # ioctl, vxlan.md §3
/// arp -s <addr> <mac(addr)>                           # per local jail, §4
/// ```
///
/// The MAC is deliberately **absent**: it is [derived](MacAddr::from_ipv4)
/// from `addr` on both ends, because unicast VXLAN never floods and so never
/// learns one. Shipping it would create a second source of truth for a value
/// that is a pure function of the address.
///
/// The DNS fields (`service_name`, `task_name`, `aliases`, `state`) are
/// `#[serde(default)]`: an endpoint encoded by a build that predates them
/// decodes with empty names and state `NEW` — which the DNS table refuses to
/// answer (only `RUNNING` is answered), so a mixed-version cluster degrades to
/// "no answer from this manager" rather than to a wrong answer. `state` is
/// also what keeps the table honest without a store: a task leaving `RUNNING`
/// changes the endpoint value, so the manager's comparison pushes the update
/// and the name stops resolving to it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    /// The task this endpoint belongs to.
    pub task_id: Id,
    /// The node running that task. A receiver tells its own endpoints from
    /// remote ones by comparing this to its own node ID — only remote ones get
    /// FDB entries.
    pub node_id: Id,
    /// The task's address on the overlay, host bits included.
    pub addr: Ipv4Addr,
    /// The underlay address of `node_id`'s VTEP (architecture §11.2: the
    /// node's advertise address on the private underlay).
    pub vtep: Ipv4Addr,
    /// Owning service's name; empty for a task without a service.
    #[serde(default)]
    pub service_name: String,
    /// Task name (`<service>.<slot>.<taskID>`, architecture §3).
    #[serde(default)]
    pub task_name: String,
    /// Extra network-scoped names, resolved like the service name.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Observed task state; the DNS table answers `RUNNING` endpoints only.
    #[serde(default = "default_endpoint_state")]
    pub state: TaskState,
}

/// The state a pre-DNS encoding decodes to: `NEW`, which no DNS answer is
/// built from — old payloads degrade to silence, never to a stale answer.
fn default_endpoint_state() -> TaskState {
    TaskState::New
}

impl NetworkEndpoint {
    /// The endpoint's MAC, derived from its overlay address.
    #[must_use]
    pub fn mac(&self) -> MacAddr {
        MacAddr::from_ipv4(self.addr)
    }

    /// Whether this endpoint is on `node_id` (and therefore needs no FDB
    /// entry there).
    #[must_use]
    pub fn is_local_to(&self, node_id: &Id) -> bool {
        self.node_id == *node_id
    }
}

/// One node's load-balancer attachment to a network (SWK §9.1, M6d): its
/// gateway address on the overlay, and its VTEP's underlay address.
///
/// Tasks know their peers from [`NetworkEndpoint`], but a node running **no**
/// task on the network appears in no endpoint — and the ingress mesh has
/// every node relaying, task or not. This map is what tells a task's node the
/// relaying nodes' MACs (derived from the gateway address, as endpoints') and
/// VTEPs, so a task can answer traffic relayed through them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GatewayAttachment {
    /// The node holding the gateway.
    pub node_id: Id,
    /// The gateway address on the overlay (the mesh SNAT's source on that
    /// node).
    pub addr: Ipv4Addr,
    /// The underlay address of that node's VTEP.
    pub vtep: Ipv4Addr,
}

impl GatewayAttachment {
    /// The gateway's MAC, derived from its overlay address — the same
    /// derivation as endpoints', so one rule covers both.
    #[must_use]
    pub fn mac(&self) -> MacAddr {
        MacAddr::from_ipv4(self.addr)
    }
}

/// A network the node must program, with its endpoint table.
///
/// This is the CBOR payload of `satl.internal.v1.NetworkAssignment`. Endpoints
/// are kept keyed by task ID so the encoding is canonical: two reads of the
/// same store state produce equal values, which is what lets
/// [`AssignmentTracker::observe_network`] suppress no-op updates by comparison.
///
/// The payload also carries the data-plane keyring ([`Network::keys`]) of an
/// encrypted network, and the tracker's reference counting is the only thing
/// keeping that keyring on participant nodes — so the no-op suppression must
/// never compare less than the full assignment: a keyring-only change is a
/// change, and it must ship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAssignment {
    /// The network object as the store holds it.
    pub network: Network,
    /// Every endpoint on that network, cluster-wide, keyed by task ID.
    pub endpoints: BTreeMap<Id, NetworkEndpoint>,
    /// The per-node gateway attachments (M6d), keyed by node ID.
    ///
    /// Filled for networks that record `node_gateways`; empty in payloads
    /// written by a pre-M6d build (serde default), which degrades to the
    /// pre-mesh behavior: gateways of other nodes are simply unknown.
    #[serde(default)]
    pub gateways: BTreeMap<Id, GatewayAttachment>,
}

impl NetworkAssignment {
    /// A network with no endpoints yet.
    #[must_use]
    pub fn new(network: Network) -> Self {
        Self {
            network,
            endpoints: BTreeMap::new(),
            gateways: BTreeMap::new(),
        }
    }

    /// The network's ID.
    #[must_use]
    pub fn id(&self) -> &Id {
        &self.network.id
    }

    /// Adds (or replaces) one endpoint. Builder form, for the manager's
    /// store read and for tests.
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: NetworkEndpoint) -> Self {
        self.endpoints.insert(endpoint.task_id.clone(), endpoint);
        self
    }

    /// Endpoints that are not on `node_id` — the ones that need FDB and ARP
    /// entries.
    pub fn remote_endpoints(&self, node_id: &Id) -> impl Iterator<Item = &NetworkEndpoint> {
        self.endpoints
            .values()
            .filter(move |endpoint| !endpoint.is_local_to(node_id))
    }

    /// How this table differs from `previous`.
    ///
    /// Used for structured logging on the manager (an endpoint appearing or
    /// disappearing is the event an operator debugging the overlay is looking
    /// for) and, on the worker side, to explain a re-application.
    #[must_use]
    pub fn endpoint_changes(&self, previous: &Self) -> EndpointChanges {
        let mut changes = EndpointChanges::default();
        for (task_id, endpoint) in &self.endpoints {
            match previous.endpoints.get(task_id) {
                None => changes.added.push(endpoint.clone()),
                Some(old) if old != endpoint => changes.moved.push(endpoint.clone()),
                Some(_) => {}
            }
        }
        for (task_id, endpoint) in &previous.endpoints {
            if !self.endpoints.contains_key(task_id) {
                changes.removed.push(endpoint.clone());
            }
        }
        changes
    }
}

/// What changed between two endpoint tables of the same network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointChanges {
    /// Endpoints that appeared (a task was scheduled on the network).
    pub added: Vec<NetworkEndpoint>,
    /// Endpoints that disappeared (a task stopped or was removed).
    pub removed: Vec<NetworkEndpoint>,
    /// Endpoints whose address or VTEP changed — in practice a task
    /// rescheduled onto another node, which invalidates the peer's FDB entry.
    pub moved: Vec<NetworkEndpoint>,
}

impl EndpointChanges {
    /// Whether the two tables were identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.moved.is_empty()
    }
}

/// What to do with an assignment locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeAction {
    /// Drop it. Ordered before [`ChangeAction::Update`] so that, within one
    /// kind, a batch never removes what it just added.
    Remove,
    /// Create it, or replace the existing one.
    Update,
}

/// Identity of one assignment: kind plus object ID. Changes are coalesced on
/// this key, so a batch carries at most one change per object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeKey {
    /// Which kind.
    pub kind: ObjectRef,
    /// Which object.
    pub id: Id,
}

/// The object a change carries. Absent for a removal: only the ID is needed
/// (`proto/dispatcher.proto`, `ACTION_REMOVE`).
#[derive(Debug, Clone, PartialEq)]
pub enum AssignmentItem {
    /// A task to run.
    Task(Box<Task>),
    /// A secret. **Never log this value** (invariant #7).
    Secret(Box<Secret>),
    /// A config.
    Config(Box<Config>),
    /// A network, with the endpoint table needed to program it.
    Network(Box<NetworkAssignment>),
}

impl AssignmentItem {
    /// Which kind of object this is.
    #[must_use]
    pub fn kind(&self) -> ObjectRef {
        match self {
            Self::Task(_) => ObjectRef::Task,
            Self::Secret(_) => ObjectRef::Secret,
            Self::Config(_) => ObjectRef::Config,
            Self::Network(_) => ObjectRef::Network,
        }
    }

    /// The object's ID.
    #[must_use]
    pub fn id(&self) -> &Id {
        match self {
            Self::Task(task) => &task.id,
            Self::Secret(secret) => &secret.id,
            Self::Config(config) => &config.id,
            Self::Network(network) => network.id(),
        }
    }
}

/// One thing the node should — or should no longer — have.
#[derive(Debug, Clone, PartialEq)]
pub struct AssignmentChange {
    /// The object this concerns.
    pub key: ChangeKey,
    /// What to do with it.
    pub action: ChangeAction,
    /// The object itself; `None` for a removal.
    pub item: Option<AssignmentItem>,
}

impl AssignmentChange {
    /// An `UPDATE` carrying `item`.
    #[must_use]
    pub fn update(item: AssignmentItem) -> Self {
        Self {
            key: ChangeKey {
                kind: item.kind(),
                id: item.id().clone(),
            },
            action: ChangeAction::Update,
            item: Some(item),
        }
    }

    /// A `REMOVE` of `id`.
    #[must_use]
    pub fn remove(kind: ObjectRef, id: Id) -> Self {
        Self {
            key: ChangeKey { kind, id },
            action: ChangeAction::Remove,
            item: None,
        }
    }
}

/// Where the tracker finds a secret, config or network it has to ship.
///
/// The manager implements this over a store view; tests implement it over a
/// map. Returning `None` means the object is gone — the tracker records the
/// reference anyway, so that a later arrival still ships.
pub trait DependencyLookup {
    /// The secret with this ID, if the store still holds it.
    fn secret(&self, id: &Id) -> Option<Secret>;
    /// The config with this ID, if the store still holds it.
    fn config(&self, id: &Id) -> Option<Config>;
    /// The network with this ID **and its current endpoint table**.
    ///
    /// Composing the two here rather than in the tracker is deliberate: which
    /// tasks are endpoints, and what a node's VTEP address is, are store
    /// questions (`manager::StoreDeps`). What the tracker owns is the
    /// reference counting and the diff of the value this returns.
    fn network(&self, id: &Id) -> Option<NetworkAssignment>;
}

impl DependencyLookup for () {
    fn secret(&self, _id: &Id) -> Option<Secret> {
        None
    }
    fn config(&self, _id: &Id) -> Option<Config> {
        None
    }
    fn network(&self, _id: &Id) -> Option<NetworkAssignment> {
        None
    }
}

/// Whether two versions of a task differ in anything the agent acts on.
///
/// SwarmKit calls this `TasksEqualStable`: everything but the observed
/// status. `meta` is excluded too — a version bump alone means the manager
/// wrote the object, not that the agent has work to do.
#[must_use]
pub fn stable_equal(a: &Task, b: &Task) -> bool {
    a.id == b.id
        && a.desired_state == b.desired_state
        && a.node_id == b.node_id
        && a.service_id == b.service_id
        && a.slot == b.slot
        && a.spec == b.spec
        && a.networks == b.networks
        && a.endpoint == b.endpoint
        && a.annotations == b.annotations
        && a.service_annotations == b.service_annotations
}

/// Whether a task belongs in a node's assignment set at all.
///
/// Membership is about the *observed* state only: `desired_state` never
/// removes a task from the set, because the agent is the one that has to act
/// on `SHUTDOWN`/`REMOVE`, and it cannot act on what it was never sent.
#[must_use]
pub fn belongs_to(task: &Task, node_id: &Id) -> bool {
    task.node_id.as_ref() == Some(node_id) && task.status.state >= TaskState::Assigned
}

/// Whether a task still needs its secrets, configs and networks.
///
/// Past `RUNNING` the container is gone or going: nothing can read the tmpfs
/// any more and nothing sends packets, so the dependencies are released
/// (SWK §13.4).
#[must_use]
pub fn needs_dependencies(task: &Task) -> bool {
    task.status.state <= TaskState::Running
}

/// Whether a task is a live endpoint on the networks it is attached to.
///
/// The window is `[ASSIGNED, RUNNING]`: the allocator has written the task's
/// addresses and the scheduler has bound it to a node, so peers can program
/// FDB entries for it; past `RUNNING` its address is dead and the entries must
/// go. This is the same window [`needs_dependencies`] closes, seen from the
/// other side — a task is an endpoint on a network exactly while it holds a
/// reference to it.
#[must_use]
pub fn is_endpoint(task: &Task) -> bool {
    task.node_id.is_some() && task.status.state >= TaskState::Assigned && needs_dependencies(task)
}

/// The assignment set of one node, plus the changes not yet shipped.
///
/// The tracker is fed one object at a time ([`AssignmentTracker::observe_task`],
/// [`AssignmentTracker::forget_task`], …) and produces either a `COMPLETE`
/// snapshot ([`AssignmentTracker::snapshot`]) or the accumulated
/// `INCREMENTAL` diff ([`AssignmentTracker::take_changes`]).
#[derive(Debug)]
pub struct AssignmentTracker {
    node_id: Id,
    tasks: BTreeMap<Id, Task>,
    secrets: BTreeMap<Id, Secret>,
    configs: BTreeMap<Id, Config>,
    networks: BTreeMap<Id, NetworkAssignment>,
    /// Reference counts: dependency ID → the tasks that hold it.
    secret_users: BTreeMap<Id, BTreeSet<Id>>,
    config_users: BTreeMap<Id, BTreeSet<Id>>,
    network_users: BTreeMap<Id, BTreeSet<Id>>,
    /// The ingress network's ID, learned from its assignment (M6d). It is
    /// shipped to every node whether or not a task references it (SWK §9.1:
    /// every node is a load balancer), and never withdrawn by refcount.
    ingress: Option<Id>,
    /// Changes since the last flush, coalesced per object (last wins).
    changes: BTreeMap<ChangeKey, AssignmentChange>,
}

impl AssignmentTracker {
    /// An empty set for `node_id`.
    #[must_use]
    pub fn new(node_id: Id) -> Self {
        Self {
            node_id,
            tasks: BTreeMap::new(),
            secrets: BTreeMap::new(),
            configs: BTreeMap::new(),
            networks: BTreeMap::new(),
            secret_users: BTreeMap::new(),
            config_users: BTreeMap::new(),
            network_users: BTreeMap::new(),
            ingress: None,
            changes: BTreeMap::new(),
        }
    }

    /// The node this set belongs to.
    #[must_use]
    pub fn node_id(&self) -> &Id {
        &self.node_id
    }

    /// Task IDs currently in the set.
    #[must_use]
    pub fn task_ids(&self) -> BTreeSet<Id> {
        self.tasks.keys().cloned().collect()
    }

    /// Secret IDs currently in the set.
    #[must_use]
    pub fn secret_ids(&self) -> BTreeSet<Id> {
        self.secrets.keys().cloned().collect()
    }

    /// Config IDs currently in the set.
    #[must_use]
    pub fn config_ids(&self) -> BTreeSet<Id> {
        self.configs.keys().cloned().collect()
    }

    /// Network IDs currently in the set.
    #[must_use]
    pub fn network_ids(&self) -> BTreeSet<Id> {
        self.networks.keys().cloned().collect()
    }

    /// The network assignment the node currently holds, endpoint table
    /// included.
    #[must_use]
    pub fn network(&self, id: &Id) -> Option<&NetworkAssignment> {
        self.networks.get(id)
    }

    /// Whether this task is in the set (cheaper than building
    /// [`Self::task_ids`] on a hot event path).
    #[must_use]
    pub fn tracks_task(&self, id: &Id) -> bool {
        self.tasks.contains_key(id)
    }

    /// Whether any task in this set references `id`.
    ///
    /// Reference *counting*, not possession: a secret the store does not hold
    /// yet is still tracked, so that its arrival ships it.
    #[must_use]
    pub fn tracks_secret(&self, id: &Id) -> bool {
        self.secret_users.contains_key(id)
    }

    /// Whether any task in this set references `id`.
    #[must_use]
    pub fn tracks_config(&self, id: &Id) -> bool {
        self.config_users.contains_key(id)
    }

    /// Whether any task in this set attaches to `id` — or `id` is the ingress
    /// network, held unconditionally (SWK §9.1): without that, a task gaining
    /// its ingress attachment would not re-ship the network to a node running
    /// no task of it, and that node's pool would never learn the member
    /// (measured on the cluster: the replica-less node had the gateways but
    /// no endpoints in its FDB).
    #[must_use]
    pub fn tracks_network(&self, id: &Id) -> bool {
        self.network_users.contains_key(id) || self.ingress.as_ref() == Some(id)
    }

    /// Networks any task on this node **references**, plus the ingress
    /// network — held unconditionally (SWK §9.1), so it is in this set whether
    /// or not a task references it.
    ///
    /// Wider than [`Self::network_ids`] on purpose: this is the set the
    /// manager's event filter re-reads when something that feeds an endpoint
    /// table changes, and a network whose object has not arrived yet still has
    /// to be re-read — that arrival is what ships it.
    #[must_use]
    pub fn referenced_network_ids(&self) -> BTreeSet<Id> {
        let mut ids: BTreeSet<Id> = self.network_users.keys().cloned().collect();
        if let Some(ingress) = &self.ingress {
            ids.insert(ingress.clone());
        }
        ids
    }

    /// Whether anything is waiting to be shipped.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// How many changes are waiting.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.changes.len()
    }

    /// Feeds one task in.
    ///
    /// Handles all four cases in one place: joining the set, being updated in
    /// place, releasing dependencies on the way past `RUNNING`, and leaving
    /// the set. Returns whether anything was queued for the agent.
    pub fn observe_task(&mut self, task: &Task, deps: &impl DependencyLookup) -> bool {
        if !belongs_to(task, &self.node_id) {
            // Either it was never ours, or it was reassigned (which cannot
            // happen — tasks are one-shot, architecture §4 rule 4 — but a
            // task deleted and replaced by ID reuse would look like this).
            return self.forget_task(&task.id);
        }

        let previous = self.tasks.insert(task.id.clone(), task.clone());
        if needs_dependencies(task) {
            self.acquire_dependencies(task, deps);
        } else {
            self.release_dependencies(&task.id);
        }

        let ship = match previous.as_ref() {
            None => true,
            Some(old) => !stable_equal(old, task),
        };
        if ship {
            self.queue(AssignmentChange::update(AssignmentItem::Task(Box::new(
                task.clone(),
            ))));
        } else {
            tracing::trace!(
                task_id = %task.id,
                state = %task.status.state,
                "task update carries nothing the agent acts on; suppressed"
            );
        }
        ship
    }

    /// Drops a task from the set (deleted, or no longer ours), releasing its
    /// dependencies. Returns whether it was in the set.
    pub fn forget_task(&mut self, task_id: &Id) -> bool {
        if self.tasks.remove(task_id).is_none() {
            return false;
        }
        self.release_dependencies(task_id);
        self.queue(AssignmentChange::remove(ObjectRef::Task, task_id.clone()));
        true
    }

    /// A secret changed in the store. Only shipped if the node holds it —
    /// the reference count decides membership, not the store.
    pub fn observe_secret(&mut self, secret: &Secret) -> bool {
        if !self.secret_users.contains_key(&secret.id) {
            return false;
        }
        let unchanged = self
            .secrets
            .get(&secret.id)
            .is_some_and(|held| held == secret);
        self.secrets.insert(secret.id.clone(), secret.clone());
        if unchanged {
            return false;
        }
        self.queue(AssignmentChange::update(AssignmentItem::Secret(Box::new(
            secret.clone(),
        ))));
        true
    }

    /// A config changed in the store; same rule as [`Self::observe_secret`].
    pub fn observe_config(&mut self, config: &Config) -> bool {
        if !self.config_users.contains_key(&config.id) {
            return false;
        }
        let unchanged = self
            .configs
            .get(&config.id)
            .is_some_and(|held| held == config);
        self.configs.insert(config.id.clone(), config.clone());
        if unchanged {
            return false;
        }
        self.queue(AssignmentChange::update(AssignmentItem::Config(Box::new(
            config.clone(),
        ))));
        true
    }

    /// A secret was deleted from the store while tasks still referenced it.
    ///
    /// The control plane refuses to delete a secret in use, so this is a
    /// "cannot happen" that is nevertheless handled: the node must not keep
    /// serving a payload the cluster has retracted.
    pub fn forget_secret(&mut self, id: &Id) -> bool {
        if self.secrets.remove(id).is_none() {
            return false;
        }
        tracing::warn!(
            secret_id = %id,
            node_id = %self.node_id,
            users = self.secret_users.get(id).map_or(0, BTreeSet::len),
            "a secret still referenced by assigned tasks was deleted from the store; withdrawing it"
        );
        self.queue(AssignmentChange::remove(ObjectRef::Secret, id.clone()));
        true
    }

    /// A network, or one of its endpoints, changed. Only shipped if the node
    /// holds it — the reference count decides membership, not the store.
    ///
    /// Unlike a secret, the value here changes without the network object
    /// changing: `assignment` is re-read whenever any task on that network
    /// moves anywhere in the cluster. The comparison is therefore over the
    /// whole assignment, endpoint table included, and what it suppresses is
    /// the genuinely identical re-read.
    pub fn observe_network(&mut self, assignment: &NetworkAssignment) -> bool {
        let id = assignment.id().clone();
        if !self.network_users.contains_key(&id) && !assignment.network.spec.ingress {
            return false;
        }
        if assignment.network.spec.ingress {
            // Learned once, kept: the ingress network ships to every node and
            // is never refcounted away (SWK §9.1). Broadcast is exactly why
            // ingress must stay unencrypted: a keyring here would reach every
            // node in the cluster, participant or not — see
            // `Network::default_ingress`, which never sets `encrypted`.
            self.ingress = Some(id.clone());
        }
        let previous = self.networks.insert(id.clone(), assignment.clone());
        let Some(previous) = previous else {
            self.queue(AssignmentChange::update(AssignmentItem::Network(Box::new(
                assignment.clone(),
            ))));
            return true;
        };
        if previous == *assignment {
            return false;
        }
        let changes = assignment.endpoint_changes(&previous);
        tracing::debug!(
            network_id = %id,
            node_id = %self.node_id,
            endpoints = assignment.endpoints.len(),
            added = changes.added.len(),
            removed = changes.removed.len(),
            moved = changes.moved.len(),
            "shipping an updated endpoint table"
        );
        self.queue(AssignmentChange::update(AssignmentItem::Network(Box::new(
            assignment.clone(),
        ))));
        true
    }

    /// A network was deleted from the store while tasks were still attached.
    ///
    /// Same "cannot happen" as [`Self::forget_secret`] — the control plane
    /// refuses to delete a network in use — and handled for the same reason:
    /// the node must not keep programming a segment the cluster has retracted.
    pub fn forget_network(&mut self, id: &Id) -> bool {
        if self.networks.remove(id).is_none() {
            return false;
        }
        tracing::warn!(
            network_id = %id,
            node_id = %self.node_id,
            users = self.network_users.get(id).map_or(0, BTreeSet::len),
            "a network still used by assigned tasks was deleted from the store; withdrawing it"
        );
        self.queue(AssignmentChange::remove(ObjectRef::Network, id.clone()));
        true
    }

    /// A config was deleted from the store; same rule as
    /// [`Self::forget_secret`].
    pub fn forget_config(&mut self, id: &Id) -> bool {
        if self.configs.remove(id).is_none() {
            return false;
        }
        tracing::warn!(
            config_id = %id,
            node_id = %self.node_id,
            "a config still referenced by assigned tasks was deleted from the store; withdrawing it"
        );
        self.queue(AssignmentChange::remove(ObjectRef::Config, id.clone()));
        true
    }

    /// The whole set as `UPDATE` changes, in application order — the body of
    /// a `COMPLETE` message.
    ///
    /// Taking a snapshot also clears the pending diff: everything it could
    /// have said is already in the snapshot.
    pub fn snapshot(&mut self) -> Vec<AssignmentChange> {
        self.changes.clear();
        let mut changes = Vec::with_capacity(
            self.secrets.len() + self.configs.len() + self.networks.len() + self.tasks.len(),
        );
        for secret in self.secrets.values() {
            changes.push(AssignmentChange::update(AssignmentItem::Secret(Box::new(
                secret.clone(),
            ))));
        }
        for config in self.configs.values() {
            changes.push(AssignmentChange::update(AssignmentItem::Config(Box::new(
                config.clone(),
            ))));
        }
        for network in self.networks.values() {
            changes.push(AssignmentChange::update(AssignmentItem::Network(Box::new(
                network.clone(),
            ))));
        }
        for task in self.tasks.values() {
            changes.push(AssignmentChange::update(AssignmentItem::Task(Box::new(
                task.clone(),
            ))));
        }
        changes
    }

    /// The accumulated diff, in wire order, leaving the tracker clean.
    ///
    /// Removals come first, dependents before dependencies
    /// ([`ObjectRef::teardown_rank`]); then updates, dependencies before
    /// dependents ([`ObjectRef`]'s own order). Both halves are what
    /// `proto/dispatcher.proto` pins, and the removals-first split also keeps
    /// the older guarantee that a batch never removes what it just added.
    pub fn take_changes(&mut self) -> Vec<AssignmentChange> {
        let mut changes: Vec<AssignmentChange> =
            std::mem::take(&mut self.changes).into_values().collect();
        changes.sort_by(|a, b| {
            a.action
                .cmp(&b.action)
                .then_with(|| match a.action {
                    ChangeAction::Remove => {
                        a.key.kind.teardown_rank().cmp(&b.key.kind.teardown_rank())
                    }
                    ChangeAction::Update => a.key.kind.cmp(&b.key.kind),
                })
                .then_with(|| a.key.id.cmp(&b.key.id))
        });
        changes
    }

    fn queue(&mut self, change: AssignmentChange) {
        self.changes.insert(change.key.clone(), change);
    }

    /// Records `task` as a user of each of its dependencies, shipping any
    /// that the node does not hold yet.
    fn acquire_dependencies(&mut self, task: &Task, deps: &impl DependencyLookup) {
        for reference in &task.spec.container.secrets {
            let id = reference.secret_id.clone();
            let first = self
                .secret_users
                .entry(id.clone())
                .or_default()
                .insert(task.id.clone());
            if !first || self.secrets.contains_key(&id) {
                continue;
            }
            let Some(secret) = deps.secret(&id) else {
                tracing::warn!(
                    secret_id = %id,
                    task_id = %task.id,
                    "task references a secret that is not in the store; the task will not start \
                     until it appears"
                );
                continue;
            };
            tracing::debug!(
                secret_id = %id,
                task_id = %task.id,
                node_id = %self.node_id,
                "shipping a secret with its first dependent task"
            );
            self.secrets.insert(id, secret.clone());
            self.queue(AssignmentChange::update(AssignmentItem::Secret(Box::new(
                secret,
            ))));
        }
        for reference in &task.spec.container.configs {
            let id = reference.config_id.clone();
            let first = self
                .config_users
                .entry(id.clone())
                .or_default()
                .insert(task.id.clone());
            if !first || self.configs.contains_key(&id) {
                continue;
            }
            let Some(config) = deps.config(&id) else {
                tracing::warn!(
                    config_id = %id,
                    task_id = %task.id,
                    "task references a config that is not in the store; the task will not start \
                     until it appears"
                );
                continue;
            };
            tracing::debug!(
                config_id = %id,
                task_id = %task.id,
                node_id = %self.node_id,
                "shipping a config with its first dependent task"
            );
            self.configs.insert(id, config.clone());
            self.queue(AssignmentChange::update(AssignmentItem::Config(Box::new(
                config,
            ))));
        }
        // Networks come from the task's *allocated* attachments, not from the
        // spec's `target` list: the spec names a network by name or ID, and
        // only the allocator's `NetworkAttachment` says which network object
        // that resolved to and which address it handed out.
        for attachment in &task.networks {
            let id = attachment.network_id.clone();
            let first = self
                .network_users
                .entry(id.clone())
                .or_default()
                .insert(task.id.clone());
            if !first || self.networks.contains_key(&id) {
                continue;
            }
            let Some(assignment) = deps.network(&id) else {
                tracing::warn!(
                    network_id = %id,
                    task_id = %task.id,
                    "task attaches to a network that is not in the store; the task will not have \
                     connectivity on it until it appears"
                );
                continue;
            };
            tracing::debug!(
                network_id = %id,
                task_id = %task.id,
                node_id = %self.node_id,
                endpoints = assignment.endpoints.len(),
                "shipping a network with its first attached task"
            );
            self.networks.insert(id, assignment.clone());
            self.queue(AssignmentChange::update(AssignmentItem::Network(Box::new(
                assignment,
            ))));
        }
    }

    /// Drops `task_id` from every reference count, withdrawing whatever it
    /// was the last user of.
    fn release_dependencies(&mut self, task_id: &Id) {
        let mut orphaned_secrets = Vec::new();
        self.secret_users.retain(|id, users| {
            if !users.remove(task_id) {
                return true;
            }
            if users.is_empty() {
                orphaned_secrets.push(id.clone());
                return false;
            }
            true
        });
        for id in orphaned_secrets {
            if self.secrets.remove(&id).is_some() {
                tracing::debug!(
                    secret_id = %id,
                    task_id = %task_id,
                    node_id = %self.node_id,
                    "withdrawing a secret from the node: its last dependent task released it"
                );
                self.queue(AssignmentChange::remove(ObjectRef::Secret, id));
            }
        }

        let mut orphaned_configs = Vec::new();
        self.config_users.retain(|id, users| {
            if !users.remove(task_id) {
                return true;
            }
            if users.is_empty() {
                orphaned_configs.push(id.clone());
                return false;
            }
            true
        });
        for id in orphaned_configs {
            if self.configs.remove(&id).is_some() {
                tracing::debug!(
                    config_id = %id,
                    task_id = %task_id,
                    node_id = %self.node_id,
                    "withdrawing a config from the node: its last dependent task released it"
                );
                self.queue(AssignmentChange::remove(ObjectRef::Config, id));
            }
        }

        let mut orphaned_networks = Vec::new();
        self.network_users.retain(|id, users| {
            if !users.remove(task_id) {
                return true;
            }
            if users.is_empty() {
                orphaned_networks.push(id.clone());
                return false;
            }
            true
        });
        for id in orphaned_networks {
            // The ingress network is never withdrawn: it is not refcounted —
            // every node holds it, task or not (SWK §9.1, M6d).
            if self.ingress.as_ref() == Some(&id) {
                continue;
            }
            if self.networks.remove(&id).is_some() {
                tracing::info!(
                    network_id = %id,
                    task_id = %task_id,
                    node_id = %self.node_id,
                    "withdrawing a network from the node: its last attached task released it"
                );
                self.queue(AssignmentChange::remove(ObjectRef::Network, id));
            }
        }
    }
}

/// Splits a diff into wire messages of at most `max` changes
/// (architecture §15: 100 changes per message).
///
/// The order within the diff is preserved, so a batch boundary never puts a
/// task ahead of the secret it depends on.
#[must_use]
pub fn split_batches(changes: &[AssignmentChange], max: usize) -> Vec<Vec<AssignmentChange>> {
    assert!(max > 0, "batch size must be positive");
    if changes.is_empty() {
        return Vec::new();
    }
    changes
        .chunks(max)
        .map(<[AssignmentChange]>::to_vec)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use satl_core::DesiredState;

    /// A lookup over fixed objects.
    #[derive(Default)]
    struct Deps {
        secrets: BTreeMap<Id, Secret>,
        configs: BTreeMap<Id, Config>,
        networks: BTreeMap<Id, NetworkAssignment>,
    }

    impl Deps {
        fn with_secret(mut self, secret: &Secret) -> Self {
            self.secrets.insert(secret.id.clone(), secret.clone());
            self
        }
        fn with_config(mut self, config: &Config) -> Self {
            self.configs.insert(config.id.clone(), config.clone());
            self
        }
        fn with_network(mut self, assignment: &NetworkAssignment) -> Self {
            self.networks
                .insert(assignment.id().clone(), assignment.clone());
            self
        }
    }

    impl DependencyLookup for Deps {
        fn secret(&self, id: &Id) -> Option<Secret> {
            self.secrets.get(id).cloned()
        }
        fn config(&self, id: &Id) -> Option<Config> {
            self.configs.get(id).cloned()
        }
        fn network(&self, id: &Id) -> Option<NetworkAssignment> {
            self.networks.get(id).cloned()
        }
    }

    fn endpoint(task_id: &Id, node_id: &Id, addr: &str, vtep: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            task_id: task_id.clone(),
            node_id: node_id.clone(),
            addr: addr.parse().expect("valid address"),
            vtep: vtep.parse().expect("valid address"),
            service_name: "web".to_owned(),
            task_name: format!("web.1.{task_id}"),
            aliases: Vec::new(),
            state: TaskState::Running,
        }
    }

    fn keys(changes: &[AssignmentChange]) -> Vec<(ObjectRef, ChangeAction)> {
        changes.iter().map(|c| (c.key.kind, c.action)).collect()
    }

    #[test]
    fn membership_starts_at_assigned_and_only_for_this_node() {
        let me = Id::generate();
        let other = Id::generate();
        for state in testing::OBSERVABLE_STATES {
            let mine = testing::task_on(Some(&me), state, DesiredState::Running);
            assert_eq!(
                belongs_to(&mine, &me),
                state >= TaskState::Assigned,
                "{state} on this node"
            );
            let theirs = testing::task_on(Some(&other), state, DesiredState::Running);
            assert!(!belongs_to(&theirs, &me), "{state} on another node");
            let unscheduled = testing::task_on(None, state, DesiredState::Running);
            assert!(!belongs_to(&unscheduled, &me), "{state} unscheduled");
        }
    }

    #[test]
    fn a_task_leaves_the_set_only_when_it_is_forgotten_not_when_it_terminates() {
        let me = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        assert!(tracker.observe_task(&task, &()));
        task.status.state = TaskState::Failed;
        tracker.observe_task(&task, &());
        assert_eq!(tracker.task_ids(), BTreeSet::from([task.id.clone()]));
        assert!(tracker.forget_task(&task.id));
        assert!(tracker.task_ids().is_empty());
        assert!(
            !tracker.forget_task(&task.id),
            "forgetting twice is a no-op"
        );
    }

    #[test]
    fn a_status_echo_is_suppressed_but_a_desired_state_move_is_shipped() {
        let me = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        assert!(tracker.observe_task(&task, &()));
        tracker.take_changes();

        // The agent reports progress; the manager writes it back into the
        // store, and the same task comes round on the watch feed.
        for state in [
            TaskState::Accepted,
            TaskState::Preparing,
            TaskState::Ready,
            TaskState::Starting,
            TaskState::Running,
        ] {
            task.status.state = state;
            task.meta.version = satl_core::Version(task.meta.version.0 + 1);
            assert!(
                !tracker.observe_task(&task, &()),
                "{state} echo must not be shipped back"
            );
        }
        assert!(!tracker.has_changes());

        task.desired_state = DesiredState::Shutdown;
        assert!(tracker.observe_task(&task, &()));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Update)]
        );
    }

    #[test]
    fn a_secret_ships_with_the_first_task_and_is_withdrawn_with_the_last() {
        let me = Id::generate();
        let secret = testing::secret("db.password", b"hunter2");
        let deps = Deps::default().with_secret(&secret);
        let mut tracker = AssignmentTracker::new(me.clone());

        let first = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        let second = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &secret,
        );

        tracker.observe_task(&first, &deps);
        let changes = tracker.take_changes();
        assert_eq!(
            keys(&changes),
            vec![
                (ObjectRef::Secret, ChangeAction::Update),
                (ObjectRef::Task, ChangeAction::Update)
            ],
            "the secret must precede the task that needs it"
        );

        // The second task does not re-ship the secret.
        tracker.observe_task(&second, &deps);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Update)]
        );

        // One user leaves: the secret stays.
        tracker.forget_task(&first.id);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Remove)]
        );
        assert_eq!(tracker.secret_ids(), BTreeSet::from([secret.id.clone()]));

        // The last user leaves: the secret goes with it, *after* it — teardown
        // is dependents-first (`ObjectRef::teardown_rank`).
        tracker.forget_task(&second.id);
        let changes = tracker.take_changes();
        assert_eq!(
            keys(&changes),
            vec![
                (ObjectRef::Task, ChangeAction::Remove),
                (ObjectRef::Secret, ChangeAction::Remove)
            ]
        );
        assert!(tracker.secret_ids().is_empty());
    }

    /// The rule the proto singles out: past RUNNING, the dependencies go even
    /// though the task object itself is unchanged and stays assigned.
    #[test]
    fn moving_past_running_releases_dependencies_without_touching_the_task() {
        let me = Id::generate();
        let secret = testing::secret("db.password", b"hunter2");
        let config = testing::config("nginx.conf", b"server {}");
        let deps = Deps::default().with_secret(&secret).with_config(&config);
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::with_config(
            testing::with_secret(
                testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
                &secret,
            ),
            &config,
        );
        tracker.observe_task(&task, &deps);
        tracker.take_changes();

        task.status.state = TaskState::Running;
        tracker.observe_task(&task, &deps);
        assert!(
            !tracker.has_changes(),
            "RUNNING still needs its dependencies"
        );

        task.status.state = TaskState::Complete;
        tracker.observe_task(&task, &deps);
        let changes = tracker.take_changes();
        assert_eq!(
            keys(&changes),
            vec![
                (ObjectRef::Config, ChangeAction::Remove),
                (ObjectRef::Secret, ChangeAction::Remove)
            ],
            "the task object did not change, but its dependencies are released"
        );
        assert!(tracker.secret_ids().is_empty());
        assert!(tracker.config_ids().is_empty());
        assert_eq!(
            tracker.task_ids(),
            BTreeSet::from([task.id.clone()]),
            "the task stays in the set until it is deleted"
        );
    }

    #[test]
    fn every_terminal_state_releases_dependencies() {
        let me = Id::generate();
        for state in [
            TaskState::Complete,
            TaskState::Shutdown,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
        ] {
            let secret = testing::secret("s", b"x");
            let deps = Deps::default().with_secret(&secret);
            let mut tracker = AssignmentTracker::new(me.clone());
            let mut task = testing::with_secret(
                testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
                &secret,
            );
            tracker.observe_task(&task, &deps);
            tracker.take_changes();
            task.status.state = state;
            tracker.observe_task(&task, &deps);
            assert!(
                tracker.secret_ids().is_empty(),
                "{state} must release the secret"
            );
        }
    }

    /// A task that arrives already terminal (a manager replaying history)
    /// must never pull its dependencies onto the node.
    #[test]
    fn a_task_that_is_already_terminal_never_acquires_dependencies() {
        let me = Id::generate();
        let secret = testing::secret("s", b"x");
        let deps = Deps::default().with_secret(&secret);
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Failed, DesiredState::Shutdown),
            &secret,
        );
        tracker.observe_task(&task, &deps);
        assert!(tracker.secret_ids().is_empty());
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Update)]
        );
    }

    #[test]
    fn a_snapshot_lists_dependencies_before_dependents_and_clears_the_diff() {
        let me = Id::generate();
        let secret = testing::secret("s", b"x");
        let config = testing::config("c", b"y");
        let network = testing::overlay_network("blue");
        let assignment = NetworkAssignment::new(network.clone());
        let deps = Deps::default()
            .with_secret(&secret)
            .with_config(&config)
            .with_network(&assignment);
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::with_config(
                testing::with_secret(
                    testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
                    &secret,
                ),
                &config,
            ),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &deps);
        assert!(tracker.has_changes());

        let snapshot = tracker.snapshot();
        assert_eq!(
            keys(&snapshot),
            vec![
                (ObjectRef::Secret, ChangeAction::Update),
                (ObjectRef::Config, ChangeAction::Update),
                (ObjectRef::Network, ChangeAction::Update),
                (ObjectRef::Task, ChangeAction::Update)
            ],
            "a task must never precede the network it is attached to"
        );
        assert!(
            !tracker.has_changes(),
            "a snapshot supersedes the pending diff"
        );
        assert!(snapshot.iter().all(|change| change.item.is_some()));
    }

    #[test]
    fn an_empty_node_snapshots_to_nothing() {
        let mut tracker = AssignmentTracker::new(Id::generate());
        assert!(tracker.snapshot().is_empty());
    }

    #[test]
    fn changes_coalesce_per_object_last_wins() {
        let me = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        tracker.observe_task(&task, &());
        task.desired_state = DesiredState::Shutdown;
        tracker.observe_task(&task, &());
        tracker.forget_task(&task.id);
        let changes = tracker.take_changes();
        assert_eq!(changes.len(), 1, "one object, one change");
        assert_eq!(changes[0].action, ChangeAction::Remove);
        assert!(changes[0].item.is_none(), "a removal carries only the id");
    }

    #[test]
    fn a_secret_update_only_reaches_nodes_that_hold_it() {
        let me = Id::generate();
        let secret = testing::secret("s", b"x");
        let deps = Deps::default().with_secret(&secret);
        let mut tracker = AssignmentTracker::new(me.clone());
        assert!(
            !tracker.observe_secret(&secret),
            "a secret nobody references is not this node's business"
        );

        let task = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        tracker.observe_task(&task, &deps);
        tracker.take_changes();

        assert!(!tracker.observe_secret(&secret), "an identical copy");
        let mut rotated = secret.clone();
        rotated.meta.version = satl_core::Version(7);
        rotated.spec =
            satl_core::SecretSpec::new(rotated.spec.annotations.clone(), b"rotated".to_vec())
                .expect("valid");
        assert!(tracker.observe_secret(&rotated));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Secret, ChangeAction::Update)]
        );
    }

    #[test]
    fn a_deleted_dependency_is_withdrawn_from_the_node() {
        let me = Id::generate();
        let secret = testing::secret("s", b"x");
        let deps = Deps::default().with_secret(&secret);
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        tracker.observe_task(&task, &deps);
        tracker.take_changes();
        assert!(tracker.forget_secret(&secret.id));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Secret, ChangeAction::Remove)]
        );
        assert!(!tracker.forget_secret(&secret.id));
    }

    /// A dependency that is missing at acquisition time is still counted, so
    /// it ships as soon as it appears.
    #[test]
    fn a_dependency_missing_from_the_store_ships_when_it_arrives() {
        let me = Id::generate();
        let secret = testing::secret("s", b"x");
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_secret(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &secret,
        );
        tracker.observe_task(&task, &());
        assert!(tracker.secret_ids().is_empty());
        tracker.take_changes();

        assert!(tracker.observe_secret(&secret));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Secret, ChangeAction::Update)]
        );
    }

    #[test]
    fn removals_precede_updates_within_a_kind() {
        let me = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        let gone = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        let fresh = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        tracker.observe_task(&gone, &());
        tracker.take_changes();
        tracker.forget_task(&gone.id);
        tracker.observe_task(&fresh, &());
        let changes = tracker.take_changes();
        assert_eq!(
            keys(&changes),
            vec![
                (ObjectRef::Task, ChangeAction::Remove),
                (ObjectRef::Task, ChangeAction::Update)
            ]
        );
    }

    #[test]
    fn batches_never_exceed_the_wire_limit_and_keep_their_order() {
        let me = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        for _ in 0..250 {
            let task = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
            tracker.observe_task(&task, &());
        }
        let changes = tracker.take_changes();
        assert_eq!(changes.len(), 250);
        let batches = split_batches(&changes, crate::ASSIGNMENT_BATCH_MAX);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 100);
        assert_eq!(batches[2].len(), 50);
        let flattened: Vec<AssignmentChange> = batches.into_iter().flatten().collect();
        assert_eq!(flattened, changes);
        assert!(split_batches(&[], 100).is_empty());
    }

    // ---- networks ----------------------------------------------------------

    #[test]
    fn a_network_ships_with_the_first_attached_task_and_is_withdrawn_with_the_last() {
        let me = Id::generate();
        let network = testing::overlay_network("blue");
        let assignment = NetworkAssignment::new(network.clone());
        let deps = Deps::default().with_network(&assignment);
        let mut tracker = AssignmentTracker::new(me.clone());

        let first = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        let second = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.6/24",
        );

        tracker.observe_task(&first, &deps);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![
                (ObjectRef::Network, ChangeAction::Update),
                (ObjectRef::Task, ChangeAction::Update)
            ],
            "the network must precede the task attached to it"
        );
        assert_eq!(tracker.network_ids(), BTreeSet::from([network.id.clone()]));

        // The second task does not re-ship the network.
        tracker.observe_task(&second, &deps);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Update)]
        );

        // One attached task leaves: the network stays.
        tracker.forget_task(&first.id);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Remove)]
        );
        assert_eq!(tracker.network_ids(), BTreeSet::from([network.id.clone()]));

        // The last one leaves: the network goes with it — and after it.
        tracker.forget_task(&second.id);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![
                (ObjectRef::Task, ChangeAction::Remove),
                (ObjectRef::Network, ChangeAction::Remove)
            ],
            "a network must never be torn down before the task attached to it"
        );
        assert!(tracker.network_ids().is_empty());
    }

    #[test]
    fn a_terminal_task_releases_its_network_like_any_other_dependency() {
        let me = Id::generate();
        let network = testing::overlay_network("blue");
        let deps = Deps::default().with_network(&NetworkAssignment::new(network.clone()));
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &deps);
        tracker.take_changes();

        task.status.state = TaskState::Running;
        tracker.observe_task(&task, &deps);
        assert!(
            !tracker.has_changes(),
            "a running task still needs its network"
        );

        task.status.state = TaskState::Shutdown;
        tracker.observe_task(&task, &deps);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Network, ChangeAction::Remove)]
        );
        assert!(tracker.network_ids().is_empty());
    }

    /// The endpoint table is the reason a network is re-shipped when nothing
    /// about the network object changed: a peer's task appearing on it is an
    /// FDB entry this node has to program.
    #[test]
    fn an_endpoint_appearing_or_disappearing_re_ships_the_network() {
        let me = Id::generate();
        let peer = Id::generate();
        let network = testing::overlay_network("blue");
        let mine = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        let local = endpoint(&mine.id, &me, "10.100.4.5", "10.2.0.1");
        let remote_task = Id::generate();
        let remote = endpoint(&remote_task, &peer, "10.100.4.9", "10.2.0.2");

        let one = NetworkAssignment::new(network.clone()).with_endpoint(local.clone());
        let mut tracker = AssignmentTracker::new(me.clone());
        tracker.observe_task(&mine, &Deps::default().with_network(&one));
        tracker.take_changes();

        // An identical re-read ships nothing.
        assert!(
            !tracker.observe_network(&one),
            "re-reading the same endpoint table must not re-ship it"
        );

        // A remote endpoint appears.
        let two = one.clone().with_endpoint(remote.clone());
        assert!(tracker.observe_network(&two));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Network, ChangeAction::Update)]
        );
        let held = tracker.network(&network.id).expect("held");
        assert_eq!(held.endpoints.len(), 2);
        assert_eq!(
            held.remote_endpoints(&me).collect::<Vec<_>>(),
            vec![&remote],
            "only the peer's endpoint needs an fdb entry here"
        );

        // ...and disappears again.
        assert!(tracker.observe_network(&one));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Network, ChangeAction::Update)]
        );
        assert_eq!(
            tracker.network(&network.id).expect("held").endpoints.len(),
            1
        );
    }

    #[test]
    fn an_endpoint_table_diff_names_what_moved() {
        let network = testing::overlay_network("blue");
        let node_a = Id::generate();
        let node_b = Id::generate();
        let stable = Id::generate();
        let leaving = Id::generate();
        let arriving = Id::generate();
        let rescheduled = Id::generate();

        let before = NetworkAssignment::new(network.clone())
            .with_endpoint(endpoint(&stable, &node_a, "10.100.4.2", "10.2.0.1"))
            .with_endpoint(endpoint(&leaving, &node_a, "10.100.4.3", "10.2.0.1"))
            .with_endpoint(endpoint(&rescheduled, &node_a, "10.100.4.4", "10.2.0.1"));
        let after = NetworkAssignment::new(network)
            .with_endpoint(endpoint(&stable, &node_a, "10.100.4.2", "10.2.0.1"))
            .with_endpoint(endpoint(&arriving, &node_b, "10.100.4.7", "10.2.0.2"))
            // Same task, now on the other node: the peer's fdb entry for it is
            // stale, which is exactly what `moved` is for.
            .with_endpoint(endpoint(&rescheduled, &node_b, "10.100.4.4", "10.2.0.2"));

        let changes = after.endpoint_changes(&before);
        assert_eq!(
            changes
                .added
                .iter()
                .map(|e| e.task_id.clone())
                .collect::<Vec<_>>(),
            vec![arriving]
        );
        assert_eq!(
            changes
                .removed
                .iter()
                .map(|e| e.task_id.clone())
                .collect::<Vec<_>>(),
            vec![leaving]
        );
        assert_eq!(
            changes
                .moved
                .iter()
                .map(|e| e.task_id.clone())
                .collect::<Vec<_>>(),
            vec![rescheduled]
        );
        assert!(!changes.is_empty());
        assert!(after.endpoint_changes(&after).is_empty());
    }

    #[test]
    fn a_network_update_only_reaches_nodes_that_hold_it() {
        let me = Id::generate();
        let network = testing::overlay_network("blue");
        let assignment = NetworkAssignment::new(network.clone());
        let mut tracker = AssignmentTracker::new(me);
        assert!(
            !tracker.observe_network(&assignment),
            "a network nobody on this node attaches to is not this node's business"
        );
        assert!(tracker.network_ids().is_empty());
        assert!(tracker.referenced_network_ids().is_empty());
    }

    /// The security property the keyring rests on: `Network.keys` travels
    /// inside the assignment payload, and an assignment only exists on a node
    /// that runs a task on the network. A node with nothing attached must
    /// never receive the keyring — no matter how often the (rotating)
    /// assignment is re-read — while the participant holds it in full.
    #[test]
    fn a_keyring_reaches_only_nodes_running_a_task_on_the_network() {
        let me = Id::generate();
        let network = testing::encrypted_overlay("blue");
        let assignment = NetworkAssignment::new(network.clone());

        // The bystander: same re-reads the participant gets, no task.
        let mut bystander = AssignmentTracker::new(me.clone());
        assert!(
            !bystander.observe_network(&assignment),
            "a node with no task on the network must not receive its keyring"
        );
        assert!(bystander.network_ids().is_empty());
        assert!(!bystander.has_changes());

        // The participant: the keyring rides the assignment of the first
        // attached task, verbatim.
        let mut participant = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        participant.observe_task(&task, &Deps::default().with_network(&assignment));
        let shipped = participant
            .take_changes()
            .into_iter()
            .find_map(|change| match change.item {
                Some(AssignmentItem::Network(assignment)) => Some(assignment),
                _ => None,
            })
            .expect("the network ships with its first attached task");
        assert_eq!(
            shipped.network.keys, network.keys,
            "the keyring travels inside the assignment payload"
        );
    }

    /// Rotation changes `network.keys` and nothing the endpoint table sees.
    /// The no-op suppression must still ship it, because it compares the
    /// *whole* assignment; an "optimization" comparing fewer fields would
    /// silently stop key rotation from reaching the nodes.
    #[test]
    fn a_keyring_only_change_re_ships_the_assignment() {
        let me = Id::generate();
        let network = testing::encrypted_overlay("blue");
        let one = NetworkAssignment::new(network.clone());
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &Deps::default().with_network(&one));
        tracker.take_changes();

        assert!(
            !tracker.observe_network(&one),
            "an identical re-read stays suppressed"
        );

        // A rotation: same object, same endpoints, new ring.
        let mut rotated = one.clone();
        rotated.network.keys = vec![
            testing::network_key(0x5a71_0002, false),
            testing::network_key(0x5a71_0003, true),
        ];
        rotated.network.keys_updated_at = Some(std::time::SystemTime::now());
        assert!(
            tracker.observe_network(&rotated),
            "a keyring-only change on a used network must push an update"
        );
        let changes = tracker.take_changes();
        assert_eq!(
            keys(&changes),
            vec![(ObjectRef::Network, ChangeAction::Update)]
        );
        let Some(AssignmentItem::Network(shipped)) = &changes[0].item else {
            panic!("a network update carries the assignment");
        };
        assert_eq!(
            shipped.network.keys, rotated.network.keys,
            "what ships carries the new ring, not the old one"
        );
        assert_eq!(
            tracker.network(&network.id).expect("held").network.keys,
            rotated.network.keys
        );
    }

    /// When the last task leaves an encrypted network, the assignment —
    /// keyring included — is withdrawn, and the withdrawal keeps the
    /// dependents-first order (`ObjectRef::teardown_order`): the keyring, and
    /// the SAs the node derives from it, outlive the task that needed them,
    /// never the other way round.
    #[test]
    fn the_last_task_leaving_an_encrypted_network_withdraws_it_after_the_task() {
        let me = Id::generate();
        let network = testing::encrypted_overlay("blue");
        let assignment = NetworkAssignment::new(network.clone());
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &Deps::default().with_network(&assignment));
        tracker.take_changes();

        tracker.forget_task(&task.id);
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![
                (ObjectRef::Task, ChangeAction::Remove),
                (ObjectRef::Network, ChangeAction::Remove)
            ],
            "the keyring is withdrawn only after the task that used it"
        );
        assert!(tracker.network_ids().is_empty());

        // And the node has left the participant set for good: a later
        // rotation re-read no longer reaches it.
        let mut rotated = assignment.clone();
        rotated.network.keys = vec![testing::network_key(0x5a71_0009, true)];
        assert!(
            !tracker.observe_network(&rotated),
            "a node off the network stops receiving rotations"
        );
    }

    /// SWK §9.1: the ingress network is every node's business, task or not —
    /// including the event filter, so a task gaining its ingress attachment
    /// re-ships the network (and with it the endpoint table) to a node running
    /// no task of it. Measured missing on the cluster: the replica-less node
    /// had the gateways but no endpoints in its FDB.
    #[test]
    fn the_ingress_network_is_tracked_without_a_single_task() {
        let me = Id::generate();
        let mut network = testing::overlay_network("ingress");
        network.spec.ingress = true;
        let mut tracker = AssignmentTracker::new(me);
        assert!(tracker.observe_network(&NetworkAssignment::new(network.clone())));
        assert!(tracker.tracks_network(&network.id));
        assert!(tracker.referenced_network_ids().contains(&network.id));
    }

    #[test]
    fn a_network_missing_from_the_store_ships_when_it_arrives() {
        let me = Id::generate();
        let network = testing::overlay_network("blue");
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &());
        assert!(tracker.network_ids().is_empty());
        assert!(
            tracker.tracks_network(&network.id),
            "the reference is counted even though the object is missing"
        );
        tracker.take_changes();

        assert!(tracker.observe_network(&NetworkAssignment::new(network.clone())));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Network, ChangeAction::Update)]
        );
    }

    #[test]
    fn a_deleted_network_is_withdrawn_from_the_node() {
        let me = Id::generate();
        let network = testing::overlay_network("blue");
        let deps = Deps::default().with_network(&NetworkAssignment::new(network.clone()));
        let mut tracker = AssignmentTracker::new(me.clone());
        let task = testing::with_network(
            testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running),
            &network,
            "10.100.4.5/24",
        );
        tracker.observe_task(&task, &deps);
        tracker.take_changes();
        assert!(tracker.forget_network(&network.id));
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Network, ChangeAction::Remove)]
        );
        assert!(!tracker.forget_network(&network.id));
    }

    #[test]
    fn a_mac_is_derived_from_the_endpoint_address_and_never_shipped() {
        let endpoint = endpoint(&Id::generate(), &Id::generate(), "10.100.4.5", "10.2.0.2");
        assert_eq!(endpoint.mac().to_string(), "02:42:0a:64:04:05");
        assert_eq!(
            endpoint.mac(),
            MacAddr::from_ipv4("10.100.4.5".parse().expect("addr"))
        );
    }

    #[test]
    fn endpoints_are_local_or_remote_relative_to_the_reader() {
        let me = Id::generate();
        let peer = Id::generate();
        let network = testing::overlay_network("blue");
        let local = endpoint(&Id::generate(), &me, "10.100.4.5", "10.2.0.1");
        let remote = endpoint(&Id::generate(), &peer, "10.100.4.9", "10.2.0.2");
        let assignment = NetworkAssignment::new(network)
            .with_endpoint(local.clone())
            .with_endpoint(remote.clone());
        assert!(local.is_local_to(&me));
        assert!(!remote.is_local_to(&me));
        assert_eq!(
            assignment.remote_endpoints(&me).collect::<Vec<_>>(),
            vec![&remote]
        );
        assert_eq!(
            assignment.remote_endpoints(&peer).collect::<Vec<_>>(),
            vec![&local]
        );
    }

    #[test]
    fn task_endpoint_membership_is_the_assigned_to_running_window() {
        let me = Id::generate();
        for state in testing::OBSERVABLE_STATES {
            let task = testing::task_on(Some(&me), state, DesiredState::Running);
            assert_eq!(
                is_endpoint(&task),
                state >= TaskState::Assigned && state <= TaskState::Running,
                "{state} bound to a node"
            );
            let unscheduled = testing::task_on(None, state, DesiredState::Running);
            assert!(!is_endpoint(&unscheduled), "{state} unscheduled");
        }
    }

    #[test]
    fn the_two_kind_orders_are_exact_reverses() {
        let apply = ObjectRef::apply_order();
        let mut teardown = ObjectRef::teardown_order();
        teardown.reverse();
        assert_eq!(apply, teardown);
        // The Ord order is the application order, and teardown_rank ranks the
        // other way — both are what `take_changes` sorts by.
        let mut sorted = apply;
        sorted.sort_unstable();
        assert_eq!(sorted, apply);
        let mut by_rank = apply;
        by_rank.sort_by_key(|kind| kind.teardown_rank());
        assert_eq!(by_rank, ObjectRef::teardown_order());
    }

    #[test]
    fn a_task_reassigned_away_leaves_the_set() {
        let me = Id::generate();
        let elsewhere = Id::generate();
        let mut tracker = AssignmentTracker::new(me.clone());
        let mut task = testing::task_on(Some(&me), TaskState::Assigned, DesiredState::Running);
        tracker.observe_task(&task, &());
        tracker.take_changes();
        task.node_id = Some(elsewhere);
        assert!(tracker.observe_task(&task, &()));
        assert!(tracker.task_ids().is_empty());
        assert_eq!(
            keys(&tracker.take_changes()),
            vec![(ObjectRef::Task, ChangeAction::Remove)]
        );
    }
}
