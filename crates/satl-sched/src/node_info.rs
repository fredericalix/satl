// SPDX-License-Identifier: BSD-2-Clause
//! The scheduler's per-node bookkeeping (SWK §8, `NodeInfo`).
//!
//! The scheduler never queries the store on the hot path: every filter and
//! the ranking comparator read this structure, which the loop maintains from
//! the watch feed. It holds, per node:
//!
//! - the [`Node`] object itself (liveness, availability, labels, platform);
//! - the tasks the scheduler counts against that node, and from them the
//!   **available resources** (capacity − reservations), the **active task
//!   counts** (total and per service) and the **host ports** already bound;
//! - a log of recent task **failures** per `(service, spec version)`, which
//!   the comparator turns into the 5-failures/5-minute fault penalty
//!   (SWK §8.4).
//!
//! Everything here is pure: no store handle, no I/O, no clock of its own —
//! `now` is always passed in, which is what makes the fault penalty testable.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_core::{DesiredState, Id, Node, PortProtocol, PublishMode, Resources, Task, Version};

/// Lookback window for the fault penalty (SWK §8.4, architecture §15).
pub const MONITOR_FAILURES: Duration = Duration::from_mins(5);

/// Failures within [`MONITOR_FAILURES`] that make a node sort last for a
/// service (SWK §8.4, architecture §15).
pub const MAX_FAILURES: usize = 5;

/// A host-mode published port bound on a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPort {
    /// Transport protocol.
    pub protocol: PortProtocol,
    /// The port bound on the host.
    pub published_port: u16,
}

impl HostPort {
    /// Total-order key. [`PortProtocol`] is a domain enum with no ordering of
    /// its own; ordering here is an implementation detail of the set that
    /// tracks bound ports, not a property of the protocol.
    fn key(self) -> (u8, u16) {
        let protocol = match self.protocol {
            PortProtocol::Tcp => 0,
            PortProtocol::Udp => 1,
        };
        (protocol, self.published_port)
    }
}

impl Ord for HostPort {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for HostPort {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Identifies a set of interchangeable tasks: same service, same spec version
/// (SWK §8.2). Used both to group a scheduling batch and to key the failure
/// log (SWK §8.4 penalises a node per service *and* spec version, so a fixed
/// service update clears the penalty).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskGroup {
    /// Owning service; `None` for tasks with no service.
    pub service_id: Option<Id>,
    /// The service spec version the task was stamped from.
    pub spec_version: Option<Version>,
}

impl TaskGroup {
    /// The group `task` belongs to.
    pub fn of(task: &Task) -> Self {
        Self {
            service_id: task.service_id.clone(),
            spec_version: task.spec_version,
        }
    }
}

/// Whether a task counts as "active" on its node (SWK §8: `NodeInfo.addTask`
/// counts tasks whose *desired* state has not passed `COMPLETE`).
fn is_active(task: &Task) -> bool {
    task.desired_state <= DesiredState::Complete
}

/// The reservations a task subtracts from its node's capacity.
fn reservations(task: &Task) -> Resources {
    task.spec.resources.reservations.unwrap_or_default()
}

/// Host-mode ports with an explicit published port; those are the only ones
/// that can conflict on a node (architecture §11.4, SWK §8.3 filter 6).
fn host_ports(task: &Task) -> impl Iterator<Item = HostPort> + '_ {
    task.endpoint
        .iter()
        .flat_map(|endpoint| endpoint.ports.iter())
        .filter(|port| port.publish_mode == PublishMode::Host && port.published_port != 0)
        .map(|port| HostPort {
            protocol: port.protocol,
            published_port: port.published_port,
        })
}

/// A node plus the scheduler's bookkeeping for it (SWK §8).
#[derive(Debug, Clone)]
pub struct NodeInfo {
    node: Arc<Node>,
    /// Tasks counted against this node, by task ID.
    tasks: BTreeMap<Id, Arc<Task>>,
    /// Capacity minus the reservations of the tasks above. May go negative
    /// when a node's reported capacity shrinks under running tasks.
    available: Resources,
    /// Active tasks on the node, all services together.
    active_total: usize,
    /// Active tasks per service.
    active_by_service: BTreeMap<Option<Id>, usize>,
    /// Host-mode ports already bound.
    used_host_ports: BTreeSet<HostPort>,
    /// Timestamps of recent failures, per task group, oldest first.
    failures: BTreeMap<TaskGroup, Vec<SystemTime>>,
    /// Last time [`NodeInfo::cleanup_failures`] ran, so the log cannot grow
    /// without bound on a long-lived leader.
    last_cleanup: SystemTime,
}

impl NodeInfo {
    /// A node with no tasks counted against it yet.
    pub fn new(node: Arc<Node>, now: SystemTime) -> Self {
        let available = capacity(&node);
        Self {
            node,
            tasks: BTreeMap::new(),
            available,
            active_total: 0,
            active_by_service: BTreeMap::new(),
            used_host_ports: BTreeSet::new(),
            failures: BTreeMap::new(),
            last_cleanup: now,
        }
    }

    /// The node object.
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// The node's ID.
    pub fn id(&self) -> &Id {
        &self.node.id
    }

    /// The store version of the node object this bookkeeping was built from.
    /// A decision taken against a stale version is abandoned (SWK §8.9).
    pub fn version(&self) -> Version {
        self.node.meta.version
    }

    /// Capacity left after the reservations of the tasks on this node.
    pub fn available(&self) -> Resources {
        self.available
    }

    /// Active tasks on this node, all services together.
    pub fn active_tasks(&self) -> usize {
        self.active_total
    }

    /// Active tasks of one service on this node.
    pub fn active_tasks_for(&self, service_id: Option<&Id>) -> usize {
        self.active_by_service
            .get(&service_id.cloned())
            .copied()
            .unwrap_or(0)
    }

    /// Whether a host-mode port is already bound on this node.
    pub fn host_port_in_use(&self, port: HostPort) -> bool {
        self.used_host_ports.contains(&port)
    }

    /// Replaces the node object, recomputing available resources from the
    /// (possibly changed) reported capacity and the tasks still counted here.
    /// Failure history survives — it belongs to the node, not to the object
    /// version (SWK §8: `createOrUpdateNode`).
    pub fn set_node(&mut self, node: Arc<Node>) {
        self.node = node;
        self.available = capacity(&self.node);
        for task in self.tasks.values() {
            self.available = subtract(self.available, reservations(task));
        }
    }

    /// Counts `task` against this node: reservations, host ports and active
    /// counts. Returns whether anything changed.
    ///
    /// Re-adding a known task only reconciles the active counts (its desired
    /// state may have crossed `COMPLETE`); resources are never double-counted.
    pub fn add_task(&mut self, task: &Arc<Task>) -> bool {
        if let Some(old) = self.tasks.get(&task.id) {
            let (was, now) = (is_active(old), is_active(task));
            if was == now {
                return false;
            }
            if now {
                self.active_total += 1;
                *self
                    .active_by_service
                    .entry(task.service_id.clone())
                    .or_default() += 1;
            } else {
                self.decrement_active(task.service_id.as_ref());
            }
            self.tasks.insert(task.id.clone(), Arc::clone(task));
            return true;
        }

        self.available = subtract(self.available, reservations(task));
        for port in host_ports(task) {
            self.used_host_ports.insert(port);
        }
        if is_active(task) {
            self.active_total += 1;
            *self
                .active_by_service
                .entry(task.service_id.clone())
                .or_default() += 1;
        }
        self.tasks.insert(task.id.clone(), Arc::clone(task));
        true
    }

    /// Stops counting a task against this node, releasing its reservations
    /// and host ports. Returns whether the task was tracked here.
    pub fn remove_task(&mut self, task_id: &Id) -> bool {
        let Some(task) = self.tasks.remove(task_id) else {
            return false;
        };
        if is_active(&task) {
            self.decrement_active(task.service_id.as_ref());
        }
        for port in host_ports(&task) {
            self.used_host_ports.remove(&port);
        }
        self.available = add(self.available, reservations(&task));
        true
    }

    /// Records one `FAILED`/`REJECTED` observation for a task group
    /// (SWK §8.1). Expired entries are dropped as they are noticed.
    pub fn record_failure(&mut self, group: TaskGroup, now: SystemTime) {
        if elapsed(self.last_cleanup, now) >= MONITOR_FAILURES {
            self.cleanup_failures(now);
        }
        let log = self.failures.entry(group).or_default();
        log.retain(|at| elapsed(*at, now) < MONITOR_FAILURES);
        log.push(now);
    }

    /// How many failures of `group` this node saw within the lookback window
    /// (SWK §8.4). Older entries age out silently — this is where the
    /// penalty expires.
    pub fn recent_failures(&self, group: &TaskGroup, now: SystemTime) -> usize {
        self.failures.get(group).map_or(0, |log| {
            log.iter()
                .filter(|at| elapsed(**at, now) < MONITOR_FAILURES)
                .count()
        })
    }

    /// Moves the failure log out, to carry it across a mirror rebuild.
    pub fn take_failures(&mut self) -> BTreeMap<TaskGroup, Vec<SystemTime>> {
        std::mem::take(&mut self.failures)
    }

    /// Restores a failure log taken by [`NodeInfo::take_failures`].
    pub fn restore_failures(&mut self, failures: BTreeMap<TaskGroup, Vec<SystemTime>>) {
        self.failures = failures;
    }

    /// Drops groups whose failures have all aged out.
    fn cleanup_failures(&mut self, now: SystemTime) {
        self.failures
            .retain(|_, log| log.iter().any(|at| elapsed(*at, now) < MONITOR_FAILURES));
        self.last_cleanup = now;
    }

    /// Decrements the active counters for one service, keeping the map clean.
    fn decrement_active(&mut self, service_id: Option<&Id>) {
        self.active_total = self.active_total.saturating_sub(1);
        let key = service_id.cloned();
        if let Some(count) = self.active_by_service.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.active_by_service.remove(&key);
            }
        }
    }
}

/// The node's reported schedulable capacity; zero when it has never described
/// itself (SWK §8: an undescribed node has no room for reservations).
fn capacity(node: &Node) -> Resources {
    node.description
        .as_ref()
        .map_or_else(Resources::default, |description| description.resources)
}

/// `left - right`, saturating instead of overflowing.
fn subtract(left: Resources, right: Resources) -> Resources {
    Resources {
        nano_cpus: left.nano_cpus.saturating_sub(right.nano_cpus),
        memory_bytes: left.memory_bytes.saturating_sub(right.memory_bytes),
    }
}

/// `left + right`, saturating instead of overflowing.
fn add(left: Resources, right: Resources) -> Resources {
    Resources {
        nano_cpus: left.nano_cpus.saturating_add(right.nano_cpus),
        memory_bytes: left.memory_bytes.saturating_add(right.memory_bytes),
    }
}

/// Time from `earlier` to `now`; zero if the clock went backwards (a failure
/// stamped in the future simply counts as recent).
fn elapsed(earlier: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(earlier).unwrap_or_default()
}

/// Whether the scheduler tracks this task at all (SWK §8.1 intake): below
/// `PENDING` nothing is allocated yet, past `RUNNING` it consumes nothing.
pub fn is_tracked(task: &Task) -> bool {
    task.status.state >= satl_core::TaskState::Pending
        && task.status.state <= satl_core::TaskState::Running
}

/// Whether a tracked task is waiting for the scheduler to pick a node.
pub fn is_queued(task: &Task) -> bool {
    is_tracked(task) && task.node_id.is_none()
}

/// Whether a tracked task arrived with its node already chosen and still
/// needs validating against it (SWK §8.6).
pub fn is_pending_preassigned(task: &Task) -> bool {
    is_tracked(task) && task.node_id.is_some() && task.status.state == satl_core::TaskState::Pending
}

/// Whether a task should be dropped at mirror-rebuild time: unassigned tasks
/// that are already meant to stop are the orchestrator's to delete, not the
/// scheduler's to place (SWK §8.1, `setupTasksList`).
pub fn is_abandoned(task: &Task) -> bool {
    task.status.state == satl_core::TaskState::Pending
        && task.desired_state > DesiredState::Complete
}

#[cfg(test)]
mod tests {
    use satl_core::{PortProtocol, TaskState};

    use crate::testing::{NodeBuilder, gib, host_port, planted_task, reserve, sample_service};

    use super::*;

    fn info(node: Node) -> NodeInfo {
        NodeInfo::new(Arc::new(node), SystemTime::now())
    }

    fn task(service: &satl_core::Service, slot: u64, desired: DesiredState) -> Arc<Task> {
        Arc::new(planted_task(
            service,
            slot,
            satl_core::TaskState::Running,
            desired,
            SystemTime::now(),
        ))
    }

    #[test]
    fn capacity_comes_from_the_node_description() {
        let described = info(
            NodeBuilder::new("alpha")
                .resources(2_000_000_000, gib(4))
                .build(),
        );
        assert_eq!(described.available().nano_cpus, 2_000_000_000);
        assert_eq!(described.available().memory_bytes, gib(4));

        // A node that never registered offers nothing.
        let bare = info(NodeBuilder::new("beta").no_description().build());
        assert_eq!(bare.available(), Resources::default());
    }

    #[test]
    fn adding_a_task_consumes_resources_ports_and_a_replica_slot() {
        let service = sample_service("web", 2);
        let mut node = info(
            NodeBuilder::new("alpha")
                .resources(4_000_000_000, gib(8))
                .build(),
        );
        let mut running = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        );
        reserve(&mut running, 1_500_000_000, gib(2));
        host_port(&mut running, PortProtocol::Tcp, 8080);
        let running = Arc::new(running);

        assert!(node.add_task(&running));
        assert_eq!(node.available().nano_cpus, 2_500_000_000);
        assert_eq!(node.available().memory_bytes, gib(6));
        assert_eq!(node.active_tasks(), 1);
        assert_eq!(node.active_tasks_for(Some(&service.id)), 1);
        assert!(node.host_port_in_use(HostPort {
            protocol: PortProtocol::Tcp,
            published_port: 8080,
        }));
        assert!(!node.host_port_in_use(HostPort {
            protocol: PortProtocol::Udp,
            published_port: 8080,
        }));

        // Removing it gives everything back.
        assert!(node.remove_task(&running.id));
        assert_eq!(node.available().nano_cpus, 4_000_000_000);
        assert_eq!(node.available().memory_bytes, gib(8));
        assert_eq!(node.active_tasks(), 0);
        assert_eq!(node.active_tasks_for(Some(&service.id)), 0);
        assert!(!node.host_port_in_use(HostPort {
            protocol: PortProtocol::Tcp,
            published_port: 8080,
        }));
        assert!(!node.remove_task(&running.id), "already gone");
    }

    #[test]
    fn re_adding_a_task_never_double_counts_resources() {
        let service = sample_service("web", 1);
        let mut node = info(
            NodeBuilder::new("alpha")
                .resources(4_000_000_000, gib(8))
                .build(),
        );
        let mut first = planted_task(
            &service,
            1,
            TaskState::Assigned,
            DesiredState::Running,
            SystemTime::now(),
        );
        reserve(&mut first, 1_000_000_000, gib(1));
        let first = Arc::new(first);
        node.add_task(&first);

        // The same task again, one state later.
        let mut later = (*first).clone();
        later.status = satl_core::TaskStatus::new(TaskState::Running, "started");
        assert!(!node.add_task(&Arc::new(later)), "nothing changed");
        assert_eq!(node.available().nano_cpus, 3_000_000_000);
        assert_eq!(node.active_tasks(), 1);

        // Now it is asked to stop: it stops counting as active, but still
        // holds its reservation until it actually goes away.
        let mut stopping = (*first).clone();
        stopping.desired_state = DesiredState::Shutdown;
        assert!(node.add_task(&Arc::new(stopping)));
        assert_eq!(node.active_tasks(), 0);
        assert_eq!(node.active_tasks_for(Some(&service.id)), 0);
        assert_eq!(node.available().nano_cpus, 3_000_000_000);
    }

    #[test]
    fn active_counts_ignore_tasks_desired_past_complete() {
        let service = sample_service("web", 4);
        let mut node = info(NodeBuilder::new("alpha").build());
        node.add_task(&task(&service, 1, DesiredState::Running));
        node.add_task(&task(&service, 2, DesiredState::Ready));
        node.add_task(&task(&service, 3, DesiredState::Complete));
        node.add_task(&task(&service, 4, DesiredState::Shutdown));
        node.add_task(&task(&service, 5, DesiredState::Remove));
        assert_eq!(node.active_tasks(), 3);
        assert_eq!(node.active_tasks_for(Some(&service.id)), 3);
    }

    #[test]
    fn updating_the_node_object_recomputes_what_is_left() {
        let service = sample_service("web", 1);
        let mut node = info(
            NodeBuilder::new("alpha")
                .resources(4_000_000_000, gib(8))
                .build(),
        );
        let mut running = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        );
        reserve(&mut running, 1_000_000_000, gib(2));
        node.add_task(&Arc::new(running));

        // The agent re-describes the node with half the memory.
        node.set_node(Arc::new(
            NodeBuilder::new("alpha")
                .resources(4_000_000_000, gib(4))
                .build(),
        ));
        assert_eq!(
            node.available().memory_bytes,
            gib(2),
            "capacity − reservations"
        );
        assert_eq!(node.active_tasks(), 1, "tasks survive a node update");
    }

    #[test]
    fn failures_are_counted_per_group_and_age_out() {
        let service = sample_service("web", 1);
        let mut node = info(NodeBuilder::new("alpha").build());
        let group = TaskGroup {
            service_id: Some(service.id.clone()),
            spec_version: Some(service.meta.version),
        };
        let other = TaskGroup {
            service_id: Some(service.id.clone()),
            spec_version: Some(satl_core::Version(42)),
        };
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        for index in 0..3 {
            node.record_failure(group.clone(), start + Duration::from_secs(index));
        }
        assert_eq!(node.recent_failures(&group, start), 3);
        assert_eq!(node.recent_failures(&other, start), 0, "keyed per revision");

        // Half the window later the old ones still count.
        let mid = start + MONITOR_FAILURES / 2;
        assert_eq!(node.recent_failures(&group, mid), 3);
        node.record_failure(group.clone(), mid);
        assert_eq!(node.recent_failures(&group, mid), 4);

        // Past the window the first three have aged out; only the fourth
        // remains, and later still nothing does.
        let late = start + MONITOR_FAILURES + Duration::from_secs(10);
        assert_eq!(node.recent_failures(&group, late), 1);
        let much_later = mid + MONITOR_FAILURES + Duration::from_secs(1);
        assert_eq!(node.recent_failures(&group, much_later), 0);
    }

    #[test]
    fn failure_history_survives_a_mirror_rebuild() {
        let service = sample_service("web", 1);
        let mut node = info(NodeBuilder::new("alpha").build());
        let group = TaskGroup {
            service_id: Some(service.id),
            spec_version: Some(service.meta.version),
        };
        let now = SystemTime::now();
        node.record_failure(group.clone(), now);
        node.record_failure(group.clone(), now);

        let carried = node.take_failures();
        assert_eq!(node.recent_failures(&group, now), 0, "moved out");
        let mut rebuilt = info(NodeBuilder::new("alpha").build());
        rebuilt.restore_failures(carried);
        assert_eq!(rebuilt.recent_failures(&group, now), 2);
    }

    #[test]
    fn host_ports_only_count_host_mode_with_an_explicit_port() {
        let service = sample_service("web", 1);
        let mut node = info(NodeBuilder::new("alpha").build());
        let mut task = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        );
        task.endpoint = Some(satl_core::Endpoint {
            spec: satl_core::EndpointSpec::default(),
            ports: vec![
                // Ingress: allocated cluster-wide, never a node conflict.
                satl_core::PortConfig {
                    name: String::new(),
                    protocol: PortProtocol::Tcp,
                    target_port: 80,
                    published_port: 30000,
                    publish_mode: satl_core::PublishMode::Ingress,
                },
                // Host mode, auto-assigned: nothing is bound yet.
                satl_core::PortConfig {
                    name: String::new(),
                    protocol: PortProtocol::Tcp,
                    target_port: 81,
                    published_port: 0,
                    publish_mode: satl_core::PublishMode::Host,
                },
            ],
        });
        node.add_task(&Arc::new(task));
        assert!(!node.host_port_in_use(HostPort {
            protocol: PortProtocol::Tcp,
            published_port: 30000,
        }));
        assert!(!node.host_port_in_use(HostPort {
            protocol: PortProtocol::Tcp,
            published_port: 0,
        }));
    }
}
