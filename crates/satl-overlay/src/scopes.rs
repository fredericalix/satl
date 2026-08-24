// SPDX-License-Identifier: BSD-2-Clause
//! Who is asking: the querying task's resolution scope (architecture §11.5).
//!
//! [`crate::endpoints::EndpointTable`] answers "what does this name mean *on
//! this network*". This module answers the question that comes first: **which
//! networks may this client's query be answered from at all**.
//!
//! # Why the scope is the task and not the socket
//!
//! A node's responder binds one socket per overlay network, on that network's
//! own gateway address, and a task's `resolv.conf` carries one `nameserver`
//! line per network it is attached to ([`crate::resolv::OverlayResolvConf`]).
//! Scoping a query to the network whose socket received it therefore scopes it
//! to whichever `nameserver` line the stub resolver happened to pick — and a
//! task on two networks then gets `NXDOMAIN` for every service on the other
//! one.
//!
//! `NXDOMAIN` is not a missing answer, it is a **wrong** one: it asserts that
//! the name does not exist, and a stub resolver does not try the next
//! `nameserver` line after an answer — it caches the denial and stops. That
//! makes the failure permanent for the client and invisible on the node, which
//! is worse than a timeout.
//!
//! So the scope is the **querying task**: the chain is source address → task →
//! that task's networks, walked in attachment order. Two properties follow, and
//! both are load-bearing:
//!
//! 1. **A source that matches no local task is scoped to nothing.** Its query
//!    is forwarded upstream, never answered from the table. Answering an
//!    unknown source from *every* network would hand one tenant the service
//!    names of another — and the socket is not private: an overlay network's
//!    gateway addresses all sit on one L2 segment, so every task of that
//!    network, on every node, can reach every node's responder. A task's
//!    `resolv.conf` points at its own node's gateway, so in normal operation
//!    nothing else ever asks.
//! 2. **The order is the task's attachment order**, i.e. the order of
//!    `Task::networks`, which comes from the service spec and is therefore the
//!    same on every node and for every query. A name present on two of a task's
//!    networks resolves the same way everywhere, instead of depending on a map
//!    iteration order or on which socket the stub picked.
//!
//! Nothing here talks to the store, the dispatcher or a socket: the projection
//! is built by the node (`satld`), which is what knows the local tasks and
//! their attachments, and handed here as plain data.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use satl_core::{Id, Task};

use crate::endpoints::parse_cidr_address;

/// One local task's resolution scope: the addresses it can query from, and the
/// networks its queries may be answered from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskScope {
    /// The task, for logs and for the collision warning. This is the identifier
    /// an operator greps by.
    pub task_id: Id,
    /// Every address the task holds, i.e. every source address a query from it
    /// can carry.
    pub addresses: Vec<IpAddr>,
    /// The networks this task's queries are answered from, **in attachment
    /// order**. The first one that knows a name answers it.
    pub networks: Vec<Id>,
}

impl TaskScope {
    /// A scope for `task_id` over `addresses`, resolving against `networks` in
    /// the order given.
    #[must_use]
    pub fn new(task_id: Id, addresses: Vec<IpAddr>, networks: Vec<Id>) -> Self {
        Self {
            task_id,
            addresses,
            networks,
        }
    }

    /// Whether this scope can ever match or answer anything.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.addresses.is_empty() && !self.networks.is_empty()
    }
}

/// The scope of one query: the networks it may be answered from, in the order
/// they are searched.
///
/// [`QueryScope::Unscoped`] is not "answer from nothing found": it is "this is
/// not a client of ours", which the responder turns into a forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryScope {
    /// The source address belongs to no local task: forward the query.
    Unscoped,
    /// The querying task, whose networks are searched in attachment order.
    Task(Arc<TaskScope>),
}

impl QueryScope {
    /// The networks to search, in order. Empty when the query is not ours.
    #[must_use]
    pub fn networks(&self) -> &[Id] {
        match self {
            Self::Unscoped => &[],
            Self::Task(scope) => &scope.networks,
        }
    }

    /// The task the query came from, when it is one of ours.
    #[must_use]
    pub fn task_id(&self) -> Option<&Id> {
        match self {
            Self::Unscoped => None,
            Self::Task(scope) => Some(&scope.task_id),
        }
    }

    /// Whether the query can be answered from the table at all.
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        !self.networks().is_empty()
    }
}

/// Source address → the scope of the task that holds it.
///
/// Shared, cheap to clone, and rebuilt wholesale by the node from a full view
/// of the local tasks — the same discipline as
/// [`crate::endpoints::EndpointTable`], and for the same reason: one place
/// decides who may resolve what, so the rule cannot drift.
#[derive(Debug, Clone, Default)]
pub struct ScopeTable {
    inner: Arc<RwLock<BTreeMap<IpAddr, Arc<TaskScope>>>>,
}

impl ScopeTable {
    /// An empty table: every source is unscoped, so every query is forwarded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole table with the scopes of the node's local tasks.
    ///
    /// Scopes are indexed by task id before they are inserted, so two tasks
    /// claiming one address resolve the same way whatever order the caller
    /// produced them in: the lower task id wins and the collision is logged.
    /// That is an allocator bug rather than a legal state, and a *stable* wrong
    /// answer is the one an operator can diagnose.
    pub fn update<I>(&self, scopes: I)
    where
        I: IntoIterator<Item = TaskScope>,
    {
        let by_task: BTreeMap<Id, TaskScope> = scopes
            .into_iter()
            .filter(TaskScope::is_usable)
            .map(|scope| (scope.task_id.clone(), scope))
            .collect();

        let mut index: BTreeMap<IpAddr, Arc<TaskScope>> = BTreeMap::new();
        for scope in by_task.into_values() {
            let shared = Arc::new(scope);
            for address in &shared.addresses {
                if let Some(held) = index.get(address) {
                    tracing::warn!(
                        address = %address,
                        holder = %held.task_id,
                        other = %shared.task_id,
                        "two local tasks claim one address; DNS scoping keeps the \
                         first and ignores the second"
                    );
                    continue;
                }
                index.insert(*address, Arc::clone(&shared));
            }
        }

        let tasks = index
            .values()
            .map(|scope| scope.task_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let mut inner = self.write();
        *inner = index;
        tracing::debug!(tasks, addresses = inner.len(), "DNS scope table rebuilt");
    }

    /// The scope of the task holding `client`, or [`QueryScope::Unscoped`].
    #[must_use]
    pub fn scope_for(&self, client: IpAddr) -> QueryScope {
        match self.read().get(&client) {
            Some(scope) => QueryScope::Task(Arc::clone(scope)),
            None => QueryScope::Unscoped,
        }
    }

    /// Number of source addresses the table can scope.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether the table scopes nothing, i.e. every query is forwarded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// See [`crate::endpoints::EndpointTable`]'s note on poisoning: a resolver
    /// that stops answering because an unrelated thread panicked is worse than
    /// one serving the last good state, and nothing here can panic under the
    /// lock anyway.
    fn read(&self) -> RwLockReadGuard<'_, BTreeMap<IpAddr, Arc<TaskScope>>> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, BTreeMap<IpAddr, Arc<TaskScope>>> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The scope of one task, or `None` when it can never be a client.
///
/// Two tasks are excluded, and each for its own reason:
///
/// - a **terminal** task will send no more queries, and its addresses go back
///   to the allocator's pool — keeping it could scope a *new* task's query to
///   the dead one's networks;
/// - a task with **no parsed address** has no source address to be recognised
///   by. A bridge attachment carries none in the store — the node's own IPAM
///   owns it (architecture §11.1) — so a task on bridge networks alone is only
///   scopable through [`scope_for_task_with`], which is how the node hands its
///   IPAM's answer in.
///
/// Whether the task runs on *this* node is not decided here: this module is
/// given data and the caller is what knows the node id.
#[must_use]
pub fn scope_for_task(task: &Task) -> Option<TaskScope> {
    scope_for_task_with(task, &[])
}

/// The same, plus addresses the **node** knows and the store does not.
///
/// A bridge network's addressing never reaches Raft (architecture §11.1), so a
/// task attached only to bridge networks parses to no source address and would
/// be unscopable — it would send queries no responder recognises, and get them
/// forwarded upstream, which is exactly the `NXDOMAIN`-for-a-service-name this
/// module exists to prevent. The node reads the address out of
/// `satl_net::NetworkManager::address_of` and passes it here; everything after
/// that is identical for both drivers, which is the point: one scoping rule,
/// not one per network kind.
///
/// `local` is additive and deduplicated against what the store already carries,
/// so passing an address the store also holds changes nothing.
#[must_use]
pub fn scope_for_task_with(task: &Task, local: &[IpAddr]) -> Option<TaskScope> {
    if task.status.state.is_terminal() {
        return None;
    }
    let mut addresses = Vec::new();
    let mut networks = Vec::with_capacity(task.networks.len());
    for attachment in &task.networks {
        networks.push(attachment.network_id.clone());
        addresses.extend(
            attachment
                .addresses
                .iter()
                .filter_map(|address| parse_cidr_address(address)),
        );
    }
    for address in local {
        if !addresses.contains(address) {
            addresses.push(*address);
        }
    }
    let scope = TaskScope::new(task.id.clone(), addresses, networks);
    scope.is_usable().then_some(scope)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use satl_core::TaskState;

    use super::*;

    fn id(prefix: char, seed: u8) -> Id {
        format!(
            "{}{}{}",
            prefix,
            "w".repeat(23),
            char::from(b'a' + seed % 26)
        )
        .parse()
        .expect("valid id")
    }

    fn v4(third: u8, last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 100, third, last))
    }

    #[test]
    fn a_scope_indexes_every_address_of_the_task() {
        let (task, front, back) = (id('t', 0), id('n', 1), id('n', 2));
        let table = ScopeTable::new();
        table.update([TaskScope::new(
            task.clone(),
            vec![v4(0, 5), v4(1, 5)],
            vec![front.clone(), back.clone()],
        )]);
        assert_eq!(table.len(), 2);
        for address in [v4(0, 5), v4(1, 5)] {
            let scope = table.scope_for(address);
            assert_eq!(scope.task_id(), Some(&task), "{address}");
            assert_eq!(
                scope.networks(),
                [front.clone(), back.clone()],
                "attachment order is preserved, {address}"
            );
            assert!(scope.is_scoped());
        }
    }

    #[test]
    fn an_unknown_source_is_scoped_to_nothing_rather_than_to_everything() {
        let table = ScopeTable::new();
        table.update([TaskScope::new(id('t', 1), vec![v4(0, 5)], vec![id('n', 3)])]);
        let scope = table.scope_for(v4(9, 9));
        assert_eq!(scope, QueryScope::Unscoped);
        assert!(scope.networks().is_empty(), "no network, so no answer");
        assert_eq!(scope.task_id(), None);
        assert!(!scope.is_scoped());

        // And an empty table scopes nothing at all.
        assert!(ScopeTable::new().is_empty());
        assert_eq!(ScopeTable::new().scope_for(v4(0, 5)), QueryScope::Unscoped);
    }

    #[test]
    fn update_replaces_and_drops_unusable_scopes() {
        let table = ScopeTable::new();
        table.update([TaskScope::new(id('t', 2), vec![v4(0, 5)], vec![id('n', 4)])]);
        table.update([TaskScope::new(id('t', 3), vec![v4(0, 6)], vec![id('n', 4)])]);
        assert_eq!(
            table.scope_for(v4(0, 5)),
            QueryScope::Unscoped,
            "not a merge"
        );
        assert_eq!(table.scope_for(v4(0, 6)).task_id(), Some(&id('t', 3)));

        // A task with no address can never be a source, and one with no network
        // could only ever be answered from nothing.
        table.update([
            TaskScope::new(id('t', 4), Vec::new(), vec![id('n', 4)]),
            TaskScope::new(id('t', 5), vec![v4(0, 7)], Vec::new()),
        ]);
        assert!(table.is_empty());
    }

    #[test]
    fn one_address_claimed_twice_resolves_to_the_lower_task_id_either_way() {
        let (first, second) = (id('t', 6), id('t', 7));
        assert!(first < second);
        let clash = v4(0, 8);
        for order in [[first.clone(), second.clone()], [second, first.clone()]] {
            let table = ScopeTable::new();
            table.update(
                order
                    .iter()
                    .map(|task| TaskScope::new(task.clone(), vec![clash], vec![id('n', 5)])),
            );
            assert_eq!(
                table.scope_for(clash).task_id(),
                Some(&first),
                "the winner must not depend on the caller's order"
            );
        }
    }

    #[test]
    fn a_tasks_scope_is_its_attachments_in_spec_order() {
        let (front, back) = (id('n', 6), id('n', 7));
        let mut task = task(TaskState::Running);
        task.networks = vec![
            attachment(&front, &["10.100.0.5/24"]),
            attachment(&back, &["10.100.1.5/24", "fd00::5/64"]),
        ];
        let scope = scope_for_task(&task).expect("a usable scope");
        assert_eq!(scope.networks, [front, back]);
        assert_eq!(
            scope.addresses,
            [
                v4(0, 5),
                v4(1, 5),
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),
            ]
        );
    }

    #[test]
    fn a_terminal_task_and_an_addressless_one_are_not_clients() {
        let net = id('n', 8);
        for state in [
            TaskState::Complete,
            TaskState::Shutdown,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
        ] {
            let mut task = task(state);
            task.networks = vec![attachment(&net, &["10.100.0.5/24"])];
            assert!(scope_for_task(&task).is_none(), "{state}");
        }

        // A bridge attachment carries no cluster address, so a task on nothing
        // else has no source address to be recognised by.
        let mut bridge_only = task(TaskState::Running);
        bridge_only.networks = vec![attachment(&net, &[])];
        assert!(scope_for_task(&bridge_only).is_none());

        // A task on no network at all is not a client either.
        assert!(scope_for_task(&task(TaskState::Running)).is_none());
    }

    #[test]
    fn an_unparseable_address_costs_that_address_and_not_the_scope() {
        let (front, back) = (id('n', 9), id('n', 10));
        let mut task = task(TaskState::Running);
        task.networks = vec![
            attachment(&front, &["not-an-address"]),
            attachment(&back, &["10.100.1.5/24"]),
        ];
        let scope = scope_for_task(&task).expect("still a client");
        assert_eq!(scope.addresses, [v4(1, 5)]);
        assert_eq!(
            scope.networks,
            [front, back],
            "the network stays in scope: the task is on it, address or not"
        );
    }

    /// A bridge-only task is unscopable from the store alone, and scopable the
    /// moment the node supplies the address the store never saw.
    ///
    /// This is the whole reason [`scope_for_task_with`] exists. A bridge
    /// network's addressing stays node-local (architecture §11.1), so the task
    /// object carries no address on it; an unscoped source is forwarded
    /// upstream, and a service name forwarded upstream comes back NXDOMAIN.
    #[test]
    fn a_bridge_only_task_scopes_on_the_address_the_node_supplies() {
        let network = id('n', 4);
        let mut task = task(TaskState::Running);
        // A bridge attachment: the store holds the network, never the address.
        task.networks = vec![attachment(&network, &[])];

        assert!(
            scope_for_task(&task).is_none(),
            "no source address means no way to recognise the querying task"
        );

        let local = IpAddr::V4(Ipv4Addr::new(10, 88, 0, 6));
        let scope = scope_for_task_with(&task, &[local]).expect("the node knows the address");
        assert_eq!(scope.addresses, [local]);
        assert_eq!(scope.networks, [network]);
    }

    /// Addresses the store already carries are not duplicated, so a task on
    /// both drivers is scoped once per address however the two halves overlap.
    #[test]
    fn local_addresses_are_additive_and_deduplicated() {
        let overlay = id('n', 5);
        let bridge = id('n', 6);
        let mut task = task(TaskState::Running);
        task.networks = vec![
            attachment(&overlay, &["10.100.0.9/24"]),
            attachment(&bridge, &[]),
        ];

        let already = v4(0, 9);
        let bridge_address = IpAddr::V4(Ipv4Addr::new(10, 88, 0, 6));
        let scope =
            scope_for_task_with(&task, &[already, bridge_address]).expect("scopable on both");
        assert_eq!(scope.addresses, [already, bridge_address]);
        assert_eq!(scope.networks, [overlay, bridge]);
    }

    fn attachment(network: &Id, addresses: &[&str]) -> satl_core::NetworkAttachment {
        satl_core::NetworkAttachment {
            network_id: network.clone(),
            addresses: addresses.iter().map(|text| (*text).to_owned()).collect(),
            aliases: Vec::new(),
        }
    }

    fn task(state: TaskState) -> Task {
        let id = Id::generate();
        Task {
            annotations: satl_core::Annotations {
                name: format!("web.1.{id}"),
                labels: BTreeMap::new(),
            },
            id,
            meta: satl_core::Meta::new(),
            spec: satl_core::TaskSpec {
                container: satl_core::ContainerSpec {
                    image: "example:latest".to_owned(),
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
            service_annotations: satl_core::Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::new(),
            },
            status: satl_core::TaskStatus::new(state, "test"),
            desired_state: satl_core::DesiredState::Running,
            networks: Vec::new(),
            endpoint: None,
            job_iteration: None,
        }
    }
}
