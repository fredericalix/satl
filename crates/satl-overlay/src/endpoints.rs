// SPDX-License-Identifier: BSD-2-Clause
//! The node's endpoint table: what the embedded resolver knows, and the whole
//! of SatL's load balancing (architecture §11.5).
//!
//! There is no VIP and no data-path load balancer (FreeBSD has no IPVS, and
//! pf-based per-connection balancing would add state and failure modes —
//! architecture §11.5). A service name resolves to the addresses of its
//! running tasks, **shuffled on every query**: the client's own choice of
//! answer is the round robin. That makes this table the load balancer, and
//! makes four rules load-bearing:
//!
//! 1. **Only `RUNNING` tasks are answered.** A `PREPARING` task has no
//!    working address yet; handing it out is a connection refused.
//! 2. **Answers are shuffled per query**, so successive queries spread across
//!    replicas. The *set* is deterministic, the *order* is not.
//! 3. **A task that leaves `RUNNING` disappears from the next answer**, with
//!    no grace period — the endpoint's absence is the failure signal.
//! 4. **Scope is per network.** The same service on two networks has two
//!    address sets, and a lookup names the network it is for. *Which* networks
//!    a given query may be looked up in is the querying task's business, not
//!    this table's: see [`crate::scopes`].
//!
//! Both a service name and an individual task name are resolvable
//! (architecture §11.5); network-scoped aliases
//! ([`satl_core::NetworkAttachment::aliases`]) resolve like service names,
//! round-robin over every task that carries them.
//!
//! The table is fed by the node — in the wiring wave, from the dispatcher's
//! assignment stream (architecture §11.2, §7.2). [`EndpointTable::update`]
//! takes a full snapshot (what `TYPE_COMPLETE` delivers) while
//! [`EndpointTable::upsert`] and [`EndpointTable::remove_task`] apply the
//! incremental changes. Nothing here talks to the store or the network: the
//! table is pure state plus a lock, so every rule above is unit-testable.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use rand::seq::SliceRandom as _;
use satl_core::{Task, TaskState};

use satl_core::Id;

/// Address family a query asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// `A` records.
    V4,
    /// `AAAA` records.
    V6,
}

impl Family {
    /// Whether an address belongs to this family.
    #[must_use]
    pub fn matches(self, address: IpAddr) -> bool {
        match self {
            Self::V4 => address.is_ipv4(),
            Self::V6 => address.is_ipv6(),
        }
    }
}

/// One task's presence on one network, as the node knows it.
///
/// This is the shape the dispatcher will deliver: which network, which
/// service, which task, at which addresses, in which observed state. The
/// state is kept rather than filtered by the caller so the table — not every
/// caller — owns rule 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRecord {
    /// The network this presence is scoped to.
    pub network_id: Id,
    /// Owning service's name; empty for a task without a service.
    pub service_name: String,
    /// Task name (`<service>.<slot>.<taskID>`, architecture §3).
    pub task_name: String,
    /// Addresses allocated to the task on this network.
    pub addresses: Vec<IpAddr>,
    /// Extra network-scoped names, resolved like the service name.
    pub aliases: Vec<String>,
    /// Observed task state; only [`TaskState::Running`] is answered.
    pub state: TaskState,
}

impl EndpointRecord {
    /// A record with no aliases.
    #[must_use]
    pub fn new(
        network_id: Id,
        service_name: impl Into<String>,
        task_name: impl Into<String>,
        addresses: Vec<IpAddr>,
        state: TaskState,
    ) -> Self {
        Self {
            network_id,
            service_name: service_name.into(),
            task_name: task_name.into(),
            addresses,
            aliases: Vec::new(),
            state,
        }
    }

    /// Adds network-scoped aliases.
    #[must_use]
    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases;
        self
    }

    /// Whether this record is answerable (rule 1).
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.state == TaskState::Running && !self.addresses.is_empty()
    }
}

/// Turns a task into one record per attached network.
///
/// The addresses on a [`satl_core::NetworkAttachment`] are CIDR strings
/// written by the allocator; the host part is what the resolver answers, so
/// the prefix length is stripped here. An address that does not parse is
/// skipped with a warning rather than failing the whole task: a bad string in
/// the store must cost one endpoint, not the node's name resolution.
#[must_use]
pub fn records_for_task(task: &Task) -> Vec<EndpointRecord> {
    task.networks
        .iter()
        .map(|attachment| {
            let addresses = attachment
                .addresses
                .iter()
                .filter_map(|address| {
                    let parsed = parse_cidr_address(address);
                    if parsed.is_none() {
                        tracing::warn!(
                            task_id = %task.id,
                            network_id = %attachment.network_id,
                            address = %address,
                            "unparseable task address; skipping this endpoint"
                        );
                    }
                    parsed
                })
                .collect();
            EndpointRecord {
                network_id: attachment.network_id.clone(),
                service_name: task.service_annotations.name.clone(),
                task_name: task.annotations.name.clone(),
                addresses,
                aliases: attachment.aliases.clone(),
                state: task.status.state,
            }
        })
        .collect()
}

/// Parses `10.100.1.5/24` (or a bare address) into its host address.
pub(crate) fn parse_cidr_address(text: &str) -> Option<IpAddr> {
    let host = text.split('/').next()?;
    host.parse().ok()
}

/// What a lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// The name is not in this network's table: the responder is not
    /// authoritative for it and the query should be forwarded.
    Unknown,
    /// The name exists. `addresses` are the ones matching the queried family,
    /// shuffled — and **empty** when the name has none of that family, which
    /// the responder must answer as `NOERROR` with no records, never
    /// `NXDOMAIN` (RFC 2308 §2.2: the name exists, the type does not).
    Found(Vec<IpAddr>),
}

impl Lookup {
    /// Whether the name exists on this network, whatever the family.
    #[must_use]
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Found(_))
    }
}

/// Per-network map of resolvable name → addresses of the live tasks behind it.
#[derive(Debug, Clone, Default)]
pub struct EndpointTable {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Authoritative input, keyed by (network, task name).
    records: BTreeMap<(Id, String), EndpointRecord>,
    /// Derived answer index: network → lowercased name → addresses.
    /// Rebuilt from `records` after every mutation, so the "only RUNNING"
    /// and "gone means gone" rules cannot drift out of one place.
    index: BTreeMap<Id, BTreeMap<String, Vec<IpAddr>>>,
}

impl EndpointTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole table with `records` — the shape of a `TYPE_COMPLETE`
    /// assignment snapshot (architecture §7.2).
    pub fn update<I>(&self, records: I)
    where
        I: IntoIterator<Item = EndpointRecord>,
    {
        let mut inner = self.write();
        inner.records = records
            .into_iter()
            .map(|record| {
                (
                    (record.network_id.clone(), record.task_name.clone()),
                    record,
                )
            })
            .collect();
        inner.reindex();
        log_state(&inner, "endpoint table replaced");
    }

    /// Adds or replaces one task's presence on one network.
    pub fn upsert(&self, record: EndpointRecord) {
        let mut inner = self.write();
        inner.records.insert(
            (record.network_id.clone(), record.task_name.clone()),
            record,
        );
        inner.reindex();
        log_state(&inner, "endpoint table updated");
    }

    /// Drops one task's presence on one network. Returns whether it was there.
    pub fn remove_task(&self, network_id: &Id, task_name: &str) -> bool {
        let mut inner = self.write();
        let removed = inner
            .records
            .remove(&(network_id.clone(), task_name.to_owned()))
            .is_some();
        if removed {
            inner.reindex();
            log_state(&inner, "endpoint removed");
        }
        removed
    }

    /// Drops a whole network, e.g. when its last local task goes away.
    /// Returns how many records were dropped.
    pub fn remove_network(&self, network_id: &Id) -> usize {
        let mut inner = self.write();
        let before = inner.records.len();
        inner
            .records
            .retain(|(network, _), _| network != network_id);
        let removed = before - inner.records.len();
        if removed > 0 {
            inner.reindex();
            log_state(&inner, "network removed from the endpoint table");
        }
        removed
    }

    /// Resolves `name` on `network_id` for one address family.
    ///
    /// `name` is matched case-insensitively without a trailing dot (that is
    /// what [`crate::dns::Name::to_key`] produces). Answers are shuffled per
    /// call: this is the round robin.
    #[must_use]
    pub fn lookup(&self, network_id: &Id, name: &str, family: Family) -> Lookup {
        let key = name.to_ascii_lowercase();
        let inner = self.read();
        let Some(addresses) = inner
            .index
            .get(network_id)
            .and_then(|names| names.get(&key))
        else {
            return Lookup::Unknown;
        };
        let mut matching: Vec<IpAddr> = addresses
            .iter()
            .copied()
            .filter(|address| family.matches(*address))
            .collect();
        drop(inner);
        matching.shuffle(&mut rand::rng());
        Lookup::Found(matching)
    }

    /// Whether the name exists on this network, whatever the record type. Used
    /// for question types we do not implement: a name we own must not be
    /// forwarded upstream just because the type is unsupported.
    #[must_use]
    pub fn contains(&self, network_id: &Id, name: &str) -> bool {
        let key = name.to_ascii_lowercase();
        self.read()
            .index
            .get(network_id)
            .is_some_and(|names| names.contains_key(&key))
    }

    /// Number of task presences held (live or not).
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().records.len()
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of resolvable names on a network (live tasks only).
    #[must_use]
    pub fn name_count(&self, network_id: &Id) -> usize {
        self.read().index.get(network_id).map_or(0, BTreeMap::len)
    }

    /// A poisoned lock means a previous holder panicked *inside* a critical
    /// section. None of them can (they only move `BTreeMap`s around), and a
    /// resolver that stops answering because of an unrelated panic is worse
    /// than one that keeps serving the last good state — so the guard is
    /// taken either way, and `unwrap` never appears.
    fn read(&self) -> RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Inner {
    /// Rebuilds the answer index from the records.
    ///
    /// O(records) on every mutation, which is the point: there is one place
    /// where "answerable" is decided, and a node holds tens of tasks, not
    /// millions.
    fn reindex(&mut self) {
        self.index.clear();
        for record in self.records.values() {
            if !record.is_live() {
                continue;
            }
            let names = self.index.entry(record.network_id.clone()).or_default();
            let candidates = std::iter::once(&record.service_name)
                .chain(std::iter::once(&record.task_name))
                .chain(record.aliases.iter());
            for name in candidates {
                if name.is_empty() {
                    continue;
                }
                let entry = names.entry(name.to_ascii_lowercase()).or_default();
                for address in &record.addresses {
                    if !entry.contains(address) {
                        entry.push(*address);
                    }
                }
            }
        }
    }
}

fn log_state(inner: &Inner, message: &'static str) {
    tracing::debug!(
        endpoints = inner.records.len(),
        networks = inner.index.len(),
        live = inner
            .records
            .values()
            .filter(|record| record.is_live())
            .count(),
        "{message}"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn network(seed: u8) -> Id {
        // Deterministic, valid 25-character base36 IDs.
        format!("{}{}", "z".repeat(24), char::from(b'a' + seed % 26))
            .parse()
            .expect("valid id")
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 100, 0, last))
    }

    fn record(net: &Id, slot: u8, state: TaskState) -> EndpointRecord {
        EndpointRecord::new(
            net.clone(),
            "web",
            format!("web.{slot}.task{slot}"),
            vec![v4(slot)],
            state,
        )
    }

    fn addresses(lookup: &Lookup) -> BTreeSet<IpAddr> {
        match lookup {
            Lookup::Found(found) => found.iter().copied().collect(),
            Lookup::Unknown => BTreeSet::new(),
        }
    }

    #[test]
    fn only_running_tasks_are_answered() {
        let net = network(0);
        let table = EndpointTable::new();
        table.update([
            record(&net, 1, TaskState::Running),
            record(&net, 2, TaskState::Preparing),
            record(&net, 3, TaskState::Starting),
            record(&net, 4, TaskState::Complete),
            record(&net, 5, TaskState::Failed),
            record(&net, 6, TaskState::Running),
        ]);
        assert_eq!(
            addresses(&table.lookup(&net, "web", Family::V4)),
            BTreeSet::from([v4(1), v4(6)])
        );
        // The non-running tasks are not resolvable under their own names.
        for slot in [2, 3, 4, 5] {
            assert_eq!(
                table.lookup(&net, &format!("web.{slot}.task{slot}"), Family::V4),
                Lookup::Unknown,
                "slot {slot}"
            );
        }
        assert_eq!(table.len(), 6, "records are kept, answers are filtered");
    }

    #[test]
    fn task_names_resolve_to_their_own_address() {
        let net = network(1);
        let table = EndpointTable::new();
        table.update([
            record(&net, 1, TaskState::Running),
            record(&net, 2, TaskState::Running),
        ]);
        assert_eq!(
            addresses(&table.lookup(&net, "web.1.task1", Family::V4)),
            BTreeSet::from([v4(1)])
        );
        assert_eq!(
            addresses(&table.lookup(&net, "web.2.task2", Family::V4)),
            BTreeSet::from([v4(2)])
        );
    }

    #[test]
    fn names_match_case_insensitively() {
        let net = network(2);
        let table = EndpointTable::new();
        table.update([EndpointRecord::new(
            net.clone(),
            "Web-Frontend",
            "Web-Frontend.1.abc",
            vec![v4(7)],
            TaskState::Running,
        )]);
        for name in ["web-frontend", "WEB-FRONTEND", "Web-Frontend"] {
            assert!(table.lookup(&net, name, Family::V4).is_known(), "{name}");
        }
    }

    #[test]
    fn leaving_running_removes_the_endpoint_immediately() {
        let net = network(3);
        let table = EndpointTable::new();
        table.update([
            record(&net, 1, TaskState::Running),
            record(&net, 2, TaskState::Running),
        ]);
        assert_eq!(
            addresses(&table.lookup(&net, "web", Family::V4)),
            BTreeSet::from([v4(1), v4(2)])
        );

        // A status change to SHUTDOWN, delivered as an incremental update.
        table.upsert(record(&net, 2, TaskState::Shutdown));
        assert_eq!(
            addresses(&table.lookup(&net, "web", Family::V4)),
            BTreeSet::from([v4(1)])
        );

        // And a removal takes the last one out; the name disappears.
        assert!(table.remove_task(&net, "web.1.task1"));
        assert_eq!(table.lookup(&net, "web", Family::V4), Lookup::Unknown);
        assert!(!table.remove_task(&net, "web.1.task1"), "idempotent");
    }

    #[test]
    fn the_same_service_on_two_networks_has_two_address_sets() {
        let (front, back) = (network(4), network(5));
        let table = EndpointTable::new();
        table.update([
            EndpointRecord::new(
                front.clone(),
                "web",
                "web.1.aaa",
                vec![v4(11)],
                TaskState::Running,
            ),
            EndpointRecord::new(
                back.clone(),
                "web",
                "web.1.aaa",
                vec![v4(21)],
                TaskState::Running,
            ),
            EndpointRecord::new(
                back.clone(),
                "web",
                "web.2.bbb",
                vec![v4(22)],
                TaskState::Running,
            ),
        ]);
        assert_eq!(
            addresses(&table.lookup(&front, "web", Family::V4)),
            BTreeSet::from([v4(11)])
        );
        assert_eq!(
            addresses(&table.lookup(&back, "web", Family::V4)),
            BTreeSet::from([v4(21), v4(22)])
        );
        // A network nobody attached to knows nothing.
        assert_eq!(
            table.lookup(&network(6), "web", Family::V4),
            Lookup::Unknown
        );
    }

    #[test]
    fn the_answer_set_is_deterministic_and_its_order_is_not() {
        let net = network(7);
        let table = EndpointTable::new();
        table.update((1..=4).map(|slot| record(&net, slot, TaskState::Running)));
        let expected = BTreeSet::from([v4(1), v4(2), v4(3), v4(4)]);

        let mut orders = BTreeSet::new();
        for _ in 0..64 {
            let Lookup::Found(found) = table.lookup(&net, "web", Family::V4) else {
                panic!("web must resolve");
            };
            assert_eq!(found.iter().copied().collect::<BTreeSet<_>>(), expected);
            orders.insert(found);
        }
        // 4! = 24 orders; seeing exactly one across 64 draws has probability
        // 24 * (1/24)^64 — this cannot flake in practice.
        assert!(orders.len() > 1, "answers are not shuffled");
    }

    #[test]
    fn aaaa_on_a_v4_only_name_is_known_but_empty() {
        let net = network(8);
        let table = EndpointTable::new();
        table.update([record(&net, 1, TaskState::Running)]);
        assert_eq!(
            table.lookup(&net, "web", Family::V6),
            Lookup::Found(Vec::new()),
            "the name exists, the family does not"
        );
        assert_eq!(table.lookup(&net, "nope", Family::V6), Lookup::Unknown);
    }

    #[test]
    fn dual_stack_records_are_split_by_family() {
        let net = network(9);
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let table = EndpointTable::new();
        table.update([EndpointRecord::new(
            net.clone(),
            "web",
            "web.1.aaa",
            vec![v4(1), v6],
            TaskState::Running,
        )]);
        assert_eq!(
            table.lookup(&net, "web", Family::V4),
            Lookup::Found(vec![v4(1)])
        );
        assert_eq!(
            table.lookup(&net, "web", Family::V6),
            Lookup::Found(vec![v6])
        );
    }

    #[test]
    fn aliases_round_robin_like_a_service_name() {
        let net = network(10);
        let table = EndpointTable::new();
        table.update([
            record(&net, 1, TaskState::Running).with_aliases(vec!["frontend".to_owned()]),
            record(&net, 2, TaskState::Running).with_aliases(vec!["frontend".to_owned()]),
        ]);
        assert_eq!(
            addresses(&table.lookup(&net, "frontend", Family::V4)),
            BTreeSet::from([v4(1), v4(2)])
        );
    }

    #[test]
    fn records_without_names_or_addresses_are_ignored() {
        let net = network(11);
        let table = EndpointTable::new();
        table.update([
            // A task with no service (standalone) still answers its own name.
            EndpointRecord::new(
                net.clone(),
                "",
                "lonely.1.aaa",
                vec![v4(30)],
                TaskState::Running,
            ),
            // Running but unallocated: nothing to answer with.
            EndpointRecord::new(
                net.clone(),
                "web",
                "web.9.zzz",
                Vec::new(),
                TaskState::Running,
            ),
        ]);
        assert!(table.lookup(&net, "lonely.1.aaa", Family::V4).is_known());
        assert_eq!(table.lookup(&net, "", Family::V4), Lookup::Unknown);
        assert_eq!(table.lookup(&net, "web", Family::V4), Lookup::Unknown);
        assert_eq!(table.name_count(&net), 1);
    }

    #[test]
    fn update_replaces_the_whole_table() {
        let net = network(12);
        let table = EndpointTable::new();
        table.update([record(&net, 1, TaskState::Running)]);
        table.update([record(&net, 2, TaskState::Running)]);
        assert_eq!(
            addresses(&table.lookup(&net, "web", Family::V4)),
            BTreeSet::from([v4(2)]),
            "a snapshot is not a merge"
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn removing_a_network_leaves_the_others_alone() {
        let (a, b) = (network(13), network(14));
        let table = EndpointTable::new();
        table.update([
            record(&a, 1, TaskState::Running),
            record(&a, 2, TaskState::Running),
            record(&b, 3, TaskState::Running),
        ]);
        assert_eq!(table.remove_network(&a), 2);
        assert_eq!(table.lookup(&a, "web", Family::V4), Lookup::Unknown);
        assert!(table.lookup(&b, "web", Family::V4).is_known());
        assert_eq!(table.remove_network(&a), 0);
    }

    #[test]
    fn contains_covers_names_whatever_the_family() {
        let net = network(15);
        let table = EndpointTable::new();
        table.update([record(&net, 1, TaskState::Running)]);
        assert!(table.contains(&net, "WEB"));
        assert!(table.contains(&net, "web.1.task1"));
        assert!(!table.contains(&net, "elsewhere"));
        assert!(!table.contains(&network(16), "web"));
    }

    #[test]
    fn records_for_task_reads_attachments_and_skips_bad_addresses() {
        use satl_core::{Annotations, NetworkAttachment};

        let net = network(17);
        let mut task = satl_core::Task {
            id: Id::generate(),
            meta: satl_core::Meta::new(),
            spec: task_spec(),
            spec_version: None,
            service_id: None,
            slot: 1,
            node_id: None,
            annotations: Annotations {
                name: "web.1.abc".to_owned(),
                labels: BTreeMap::new(),
            },
            service_annotations: Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::new(),
            },
            status: satl_core::TaskStatus::new(TaskState::Running, "started"),
            desired_state: satl_core::DesiredState::Running,
            networks: vec![NetworkAttachment {
                network_id: net.clone(),
                addresses: vec![
                    "10.100.0.5/24".to_owned(),
                    "not-an-address".to_owned(),
                    "fd00::5/64".to_owned(),
                ],
                aliases: vec!["frontend".to_owned()],
            }],
            endpoint: None,
            job_iteration: None,
        };

        let records = records_for_task(&task);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 100, 0, 5)),
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),
            ]
        );
        assert_eq!(records[0].service_name, "web");
        assert_eq!(records[0].task_name, "web.1.abc");
        assert_eq!(records[0].aliases, vec!["frontend".to_owned()]);
        assert!(records[0].is_live());

        task.status.state = TaskState::Preparing;
        assert!(!records_for_task(&task)[0].is_live());
    }

    fn task_spec() -> satl_core::TaskSpec {
        satl_core::TaskSpec {
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
        }
    }
}
