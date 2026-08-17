// SPDX-License-Identifier: BSD-2-Clause
//! Ranking and placement (SWK §8.4) — pure, no store, no clock of its own.
//!
//! Ranking is a spread: tasks of a service go to the node running the fewest
//! of them, ties broken by the node's total task count. Ahead of both sits
//! the **fault penalty**: a node that failed or rejected this exact service
//! revision [`MAX_FAILURES`] times within [`MONITOR_FAILURES`](
//! crate::node_info::MONITOR_FAILURES) sorts last, so a service crash-looping
//! on one node moves elsewhere instead of hammering it.
//!
//! Placement then walks the ranked list round-robin, re-running the filter
//! pipeline as its own decisions consume resources — within one batch the
//! scheduler is the only writer, so it must account for what it just decided
//! before deciding the next task (SWK §8.4).

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use satl_core::{Id, Task};

use crate::filters::Pipeline;
use crate::node_info::{MAX_FAILURES, NodeInfo, TaskGroup};

/// One placement decision: this task goes on this node.
#[derive(Debug, Clone)]
pub struct Assignment {
    /// The task as the scheduler read it (its version guards the commit).
    pub task: Arc<Task>,
    /// The node it was placed on.
    pub node_id: Id,
}

/// Orders two nodes for a task group, best (lowest) first (SWK §8.4):
///
/// 1. the fault penalty — when either node is at or past [`MAX_FAILURES`]
///    recent failures of this `(service, spec version)`, the one with fewer
///    failures wins outright;
/// 2. each spread preference, in spec order: the node whose descriptor-value
///    group holds fewer of this service's tasks wins (M7d);
/// 3. fewer active tasks **of this service** (the spread criterion);
/// 4. fewer active tasks in total (tie-break);
/// 5. node ID, so a batch is deterministic rather than map-order dependent.
pub fn compare_nodes(
    a: &NodeInfo,
    b: &NodeInfo,
    group: &TaskGroup,
    now: SystemTime,
    spread: &[SpreadCount],
) -> Ordering {
    let failures_a = a.recent_failures(group, now);
    let failures_b = b.recent_failures(group, now);
    if failures_a >= MAX_FAILURES || failures_b >= MAX_FAILURES {
        match failures_a.cmp(&failures_b) {
            Ordering::Equal => {}
            decided => return decided,
        }
    }
    for group_count in spread {
        let ordering = group_count.of(a.node()).cmp(&group_count.of(b.node()));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    let service = group.service_id.as_ref();
    a.active_tasks_for(service)
        .cmp(&b.active_tasks_for(service))
        .then_with(|| a.active_tasks().cmp(&b.active_tasks()))
        .then_with(|| a.id().cmp(b.id()))
}

/// One spread preference's precomputed state (M7d): for each value of the
/// descriptor, how many of the service's active tasks it currently holds.
/// Nodes missing the key fall in the empty-value group, as Docker's spread.
pub struct SpreadCount {
    descriptor: String,
    counts: BTreeMap<String, usize>,
}

impl SpreadCount {
    /// Build the counts for one descriptor over the live node set.
    fn build(nodes: &BTreeMap<Id, NodeInfo>, service: Option<&Id>, descriptor: &str) -> Self {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for info in nodes.values() {
            *counts
                .entry(descriptor_value(info.node(), descriptor))
                .or_default() += info.active_tasks_for(service);
        }
        Self {
            descriptor: descriptor.to_owned(),
            counts,
        }
    }

    /// The task count of the descriptor-value group `node` belongs to.
    fn of(&self, node: &satl_core::Node) -> usize {
        self.counts
            .get(&descriptor_value(node, &self.descriptor))
            .copied()
            .unwrap_or(0)
    }

    /// Account for a task just placed on `node` within this batch: without
    /// it the whole batch reads the pre-placement counts and a second task
    /// would not see the first (measured: two replicas, two zones, both
    /// landed in the same one).
    fn account(&mut self, node: &satl_core::Node) {
        *self
            .counts
            .entry(descriptor_value(node, &self.descriptor))
            .or_default() += 1;
    }
}

/// A node's value for a spread descriptor: `node.id`, `node.hostname`,
/// `node.labels.<key>` or `engine.labels.<key>` (validated at the API; an
/// unknown form groups every node under the empty value, spreading nothing).
fn descriptor_value(node: &satl_core::Node, descriptor: &str) -> String {
    if descriptor == "node.id" {
        return node.id.to_string();
    }
    if descriptor == "node.hostname" {
        return node
            .description
            .as_ref()
            .map_or_else(String::new, |description| description.hostname.clone());
    }
    if let Some(key) = descriptor.strip_prefix("node.labels.") {
        return node.spec.labels.get(key).cloned().unwrap_or_default();
    }
    if let Some(key) = descriptor.strip_prefix("engine.labels.") {
        return node
            .description
            .as_ref()
            .and_then(|description| description.engine.labels.get(key).cloned())
            .unwrap_or_default();
    }
    String::new()
}

/// Whether one node — already chosen for the task — still accepts it
/// (SWK §8.6). `pipeline` must have been configured with the task first; its
/// rejection counts explain a refusal.
pub fn fits_on_node(
    nodes: &BTreeMap<Id, NodeInfo>,
    node_id: &Id,
    pipeline: &mut Pipeline,
) -> Option<bool> {
    let info = nodes.get(node_id)?;
    Some(pipeline.check(info))
}

/// Places a group of interchangeable tasks (SWK §8.4).
///
/// Returns the decisions taken and the tasks left over. `nodes` is updated as
/// decisions are made — each placed task immediately consumes its
/// reservations, host ports and replica slot on the chosen node — so the
/// caller must undo a placement ([`NodeInfo::remove_task`]) if committing it
/// later fails.
pub fn place_group(
    nodes: &mut BTreeMap<Id, NodeInfo>,
    group: &[Arc<Task>],
    pipeline: &mut Pipeline,
    now: SystemTime,
) -> (Vec<Assignment>, Vec<Arc<Task>>) {
    let Some(sample) = group.first() else {
        return (Vec::new(), Vec::new());
    };
    pipeline.set_task(sample);
    let key = TaskGroup::of(sample);
    let spread: Vec<SpreadCount> = sample
        .spec
        .placement
        .preferences
        .iter()
        .filter_map(|preference| preference.spread.as_ref())
        .map(|spread| SpreadCount::build(nodes, key.service_id.as_ref(), &spread.spread_descriptor))
        .collect();
    let mut spread = spread;

    // Candidates: every node that passes the pipeline, best first. SwarmKit
    // keeps only the best `len(group)` of them in a size-capped heap and
    // evaluates the pipeline lazily; sorting and truncating gives the same
    // set, and the same explanation, at a cluster size where the difference
    // is noise.
    let mut candidates: Vec<Id> = nodes
        .values()
        .filter(|info| pipeline.check(info))
        .map(|info| info.id().clone())
        .collect();
    candidates.sort_by(|a, b| compare_nodes(&nodes[a], &nodes[b], &key, now, &spread));
    // No truncation to the group size: the per-step re-ranking below can
    // bring a node from beyond it to the front (a spread preference's better
    // group may sit there — measured: the zone-b node was truncated away and
    // both replicas landed in zone a).
    if candidates.is_empty() {
        return (Vec::new(), group.to_vec());
    }

    let mut exhausted: std::collections::BTreeSet<Id> = std::collections::BTreeSet::new();
    let mut assignments = Vec::with_capacity(group.len());

    for (index, task) in group.iter().enumerate() {
        // Re-rank at every step: a placement worsens its node's whole spread
        // group, and an order computed before the batch cannot see that
        // (M7d — measured: two replicas, two zones, both landed in one).
        candidates.sort_by(|a, b| compare_nodes(&nodes[a], &nodes[b], &key, now, &spread));
        let mut chosen = None;
        for node_id in &candidates {
            if exhausted.contains(node_id) {
                continue;
            }
            if pipeline.check(&nodes[node_id]) {
                chosen = Some(node_id.clone());
                break;
            }
            // The decisions above consumed real capacity on this node.
            exhausted.insert(node_id.clone());
        }
        let Some(node_id) = chosen else {
            return (assignments, group[index..].to_vec());
        };
        if let Some(info) = nodes.get_mut(&node_id) {
            info.add_task(task);
            // The spread counts must see this placement too: they were
            // computed before the batch, and the next ranking reads them.
            for count in &mut spread {
                count.account(info.node());
            }
        }
        assignments.push(Assignment {
            task: Arc::clone(task),
            node_id,
        });
    }

    (assignments, Vec::new())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use satl_core::{Availability, DesiredState, TaskState};

    use crate::node_info::MONITOR_FAILURES;
    use crate::testing::{NodeBuilder, gib, planted_task, reserve, sample_service};

    use super::*;

    /// Bookkeeping for a node with nothing on it yet.
    fn node_info(node: satl_core::Node) -> NodeInfo {
        NodeInfo::new(Arc::new(node), SystemTime::now())
    }

    /// The group every task of `service` at its current revision belongs to.
    fn task_group(service: &satl_core::Service) -> TaskGroup {
        TaskGroup {
            service_id: Some(service.id.clone()),
            spec_version: Some(service.meta.version),
        }
    }

    /// Three nodes named so that their IDs sort in creation order.
    fn node_set(names: [&str; 3]) -> BTreeMap<Id, NodeInfo> {
        let mut set = BTreeMap::new();
        for name in names {
            let info = node_info(
                NodeBuilder::new(name)
                    .id_from_name()
                    .resources(4_000_000_000, gib(8))
                    .build(),
            );
            set.insert(info.id().clone(), info);
        }
        set
    }

    fn pending(service: &satl_core::Service, slot: u64) -> Arc<Task> {
        Arc::new(planted_task(
            service,
            slot,
            TaskState::Pending,
            DesiredState::Running,
            SystemTime::now(),
        ))
    }

    #[test]
    fn comparator_prefers_fewer_tasks_of_the_service_then_fewer_overall() {
        let service = sample_service("web", 3);
        let other = sample_service("api", 3);
        let now = SystemTime::now();
        let group = task_group(&service);

        let mut a = node_info(NodeBuilder::new("alpha").id_from_name().build());
        let mut b = node_info(NodeBuilder::new("beta").id_from_name().build());

        assert_eq!(
            compare_nodes(&a, &b, &group, now, &[]),
            Ordering::Less,
            "IDs break the tie"
        );

        // One task of this service on `a` makes `b` the better choice.
        a.add_task(&pending(&service, 1));
        assert_eq!(compare_nodes(&a, &b, &group, now, &[]), Ordering::Greater);

        // Equal on this service, but `a` runs another service's task: `b` wins.
        b.add_task(&pending(&service, 2));
        b.add_task(&pending(&other, 1));
        assert_eq!(compare_nodes(&a, &b, &group, now, &[]), Ordering::Less);
    }

    #[test]
    fn comparator_ignores_terminating_tasks() {
        let service = sample_service("web", 2);
        let now = SystemTime::now();
        let group = task_group(&service);
        let mut a = node_info(NodeBuilder::new("alpha").id_from_name().build());
        let b = node_info(NodeBuilder::new("beta").id_from_name().build());

        let mut leaving =
            planted_task(&service, 1, TaskState::Running, DesiredState::Shutdown, now);
        leaving.desired_state = DesiredState::Shutdown;
        a.add_task(&Arc::new(leaving));
        assert_eq!(
            compare_nodes(&a, &b, &group, now, &[]),
            Ordering::Less,
            "a task on its way out does not count against the node"
        );
    }

    #[test]
    fn spread_preference_balances_across_descriptor_values() {
        // alpha and beta are in zone a, gamma in zone b; one task of the
        // service already runs in zone a. The plain spread would take any
        // empty node; the preference must take gamma — the empty *group*.
        let service = sample_service("web", 4);
        let now = SystemTime::now();
        let group = task_group(&service);
        let mut nodes = BTreeMap::new();
        for (name, zone) in [("alpha", "a"), ("beta", "a"), ("gamma", "b")] {
            let info = node_info(
                NodeBuilder::new(name)
                    .id_from_name()
                    .label("zone", zone)
                    .build(),
            );
            nodes.insert(info.id().clone(), info);
        }
        let alpha = nodes.keys().next().unwrap().clone();
        nodes
            .get_mut(&alpha)
            .unwrap()
            .add_task(&pending(&service, 1));

        let spread = [SpreadCount::build(
            &nodes,
            group.service_id.as_ref(),
            "node.labels.zone",
        )];
        let beta = node_info(
            NodeBuilder::new("beta")
                .id_from_name()
                .label("zone", "a")
                .build(),
        );
        let gamma = node_info(
            NodeBuilder::new("gamma")
                .id_from_name()
                .label("zone", "b")
                .build(),
        );
        assert_eq!(
            compare_nodes(&beta, &gamma, &group, now, &spread),
            Ordering::Greater,
            "a node in the fuller group loses, even with no task of its own"
        );
        // Without the preference they tie on service tasks and the total.
        assert_eq!(
            compare_nodes(&beta, &gamma, &group, now, &[]),
            Ordering::Less,
            "without the preference the node IDs decide (beta < gamma)"
        );
    }

    #[test]
    fn fault_penalty_sorts_a_failing_node_last_and_ages_out() {
        let service = sample_service("web", 2);
        let group = task_group(&service);
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        let mut faulty = node_info(NodeBuilder::new("alpha").id_from_name().build());
        let healthy = node_info(NodeBuilder::new("beta").id_from_name().build());

        // Four failures are not enough — SwarmKit only reacts at five.
        for _ in 0..4 {
            faulty.record_failure(group.clone(), start);
        }
        assert_eq!(
            compare_nodes(&faulty, &healthy, &group, start, &[]),
            Ordering::Less,
            "under the threshold the ID tie-break still applies"
        );

        faulty.record_failure(group.clone(), start);
        assert_eq!(faulty.recent_failures(&group, start), 5);
        assert_eq!(
            compare_nodes(&faulty, &healthy, &group, start, &[]),
            Ordering::Greater,
            "five failures in the window push the node last"
        );

        // The penalty is per (service, spec version): another revision of the
        // same service is unaffected.
        let mut other_revision = group.clone();
        other_revision.spec_version = Some(satl_core::Version(999));
        assert_eq!(
            compare_nodes(&faulty, &healthy, &other_revision, start, &[]),
            Ordering::Less
        );

        // Just inside the window it still counts...
        let almost = start + MONITOR_FAILURES - Duration::from_secs(1);
        assert_eq!(faulty.recent_failures(&group, almost), 5);
        assert_eq!(
            compare_nodes(&faulty, &healthy, &group, almost, &[]),
            Ordering::Greater
        );

        // ...and past it the node is ordinary again.
        let later = start + MONITOR_FAILURES + Duration::from_secs(1);
        assert_eq!(faulty.recent_failures(&group, later), 0);
        assert_eq!(
            compare_nodes(&faulty, &healthy, &group, later, &[]),
            Ordering::Less
        );
    }

    #[test]
    fn a_spread_preference_places_one_per_group_within_a_batch() {
        // alpha and beta in zone a, gamma in zone b: two replicas with a zone
        // spread must land one per zone — the batch's own placements have to
        // update the group counts, or the second task reads a stale 0.
        let mut service = sample_service("web", 2);
        service.spec.task.placement.preferences = vec![satl_core::PlacementPreference {
            spread: Some(satl_core::SpreadPreference {
                spread_descriptor: "node.labels.zone".to_owned(),
            }),
        }];
        let mut nodes = BTreeMap::new();
        for (name, zone) in [("alpha", "a"), ("beta", "a"), ("gamma", "b")] {
            let info = node_info(
                NodeBuilder::new(name)
                    .id_from_name()
                    .label("zone", zone)
                    .build(),
            );
            nodes.insert(info.id().clone(), info);
        }
        let group: Vec<Arc<Task>> = (1..=2).map(|slot| pending(&service, slot)).collect();
        let mut pipeline = Pipeline::new();

        let (assignments, leftovers) =
            place_group(&mut nodes, &group, &mut pipeline, SystemTime::now());
        assert!(leftovers.is_empty());
        let mut zones: Vec<&str> = assignments
            .iter()
            .map(|assignment| nodes[&assignment.node_id].node().spec.labels["zone"].as_str())
            .collect();
        zones.sort_unstable();
        assert_eq!(zones, ["a", "b"], "one task per zone group: {zones:?}");
    }

    #[test]
    fn six_replicas_spread_two_per_node() {
        let service = sample_service("web", 6);
        let mut nodes = node_set(["alpha", "beta", "gamma"]);
        let group: Vec<Arc<Task>> = (1..=6).map(|slot| pending(&service, slot)).collect();
        let mut pipeline = Pipeline::new();

        let (assignments, leftovers) =
            place_group(&mut nodes, &group, &mut pipeline, SystemTime::now());
        assert!(leftovers.is_empty());
        assert_eq!(assignments.len(), 6);

        let mut per_node: BTreeMap<&Id, usize> = BTreeMap::new();
        for assignment in &assignments {
            *per_node.entry(&assignment.node_id).or_default() += 1;
        }
        assert_eq!(per_node.len(), 3, "every node was used");
        assert!(
            per_node.values().all(|count| *count == 2),
            "expected 2/2/2, got {per_node:?}"
        );
        // The mirror reflects the decisions immediately (batch-local
        // accounting), which is what makes the next batch spread correctly.
        for info in nodes.values() {
            assert_eq!(info.active_tasks_for(Some(&service.id)), 2);
        }
    }

    #[test]
    fn placement_stops_when_the_batch_exhausts_the_last_node() {
        // One node with room for exactly two reserving tasks.
        let service = sample_service("web", 3);
        let mut nodes = BTreeMap::new();
        let info = node_info(
            NodeBuilder::new("alpha")
                .id_from_name()
                .resources(2_000_000_000, gib(4))
                .build(),
        );
        nodes.insert(info.id().clone(), info);

        let group: Vec<Arc<Task>> = (1..=3)
            .map(|slot| {
                let mut task = planted_task(
                    &service,
                    slot,
                    TaskState::Pending,
                    DesiredState::Running,
                    SystemTime::now(),
                );
                reserve(&mut task, 1_000_000_000, gib(2));
                Arc::new(task)
            })
            .collect();

        let mut pipeline = Pipeline::new();
        let (assignments, leftovers) =
            place_group(&mut nodes, &group, &mut pipeline, SystemTime::now());
        assert_eq!(assignments.len(), 2, "the node only fits two");
        assert_eq!(leftovers.len(), 1);
        assert_eq!(leftovers[0].id, group[2].id);
        assert_eq!(pipeline.explain(), "insufficient resources on 1 node");
    }

    #[test]
    fn placement_skips_nodes_the_batch_filled_and_uses_the_rest() {
        // alpha fits one reserving task, beta fits three.
        let service = sample_service("web", 3);
        let mut nodes = BTreeMap::new();
        for (name, cpus) in [("alpha", 1_000_000_000_i64), ("beta", 3_000_000_000)] {
            let info = node_info(
                NodeBuilder::new(name)
                    .id_from_name()
                    .resources(cpus, gib(64))
                    .build(),
            );
            nodes.insert(info.id().clone(), info);
        }
        let group: Vec<Arc<Task>> = (1..=3)
            .map(|slot| {
                let mut task = planted_task(
                    &service,
                    slot,
                    TaskState::Pending,
                    DesiredState::Running,
                    SystemTime::now(),
                );
                reserve(&mut task, 1_000_000_000, gib(1));
                Arc::new(task)
            })
            .collect();

        let mut pipeline = Pipeline::new();
        let (assignments, leftovers) =
            place_group(&mut nodes, &group, &mut pipeline, SystemTime::now());
        assert!(leftovers.is_empty(), "beta absorbs what alpha cannot take");
        let mut per_node: BTreeMap<&Id, usize> = BTreeMap::new();
        for assignment in &assignments {
            *per_node.entry(&assignment.node_id).or_default() += 1;
        }
        assert_eq!(per_node.values().copied().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn no_candidate_leaves_every_task_unplaced() {
        let service = sample_service("web", 2);
        let mut nodes = BTreeMap::new();
        let info = node_info(
            NodeBuilder::new("alpha")
                .id_from_name()
                .availability(Availability::Drain)
                .build(),
        );
        nodes.insert(info.id().clone(), info);

        let group: Vec<Arc<Task>> = (1..=2).map(|slot| pending(&service, slot)).collect();
        let mut pipeline = Pipeline::new();
        let (assignments, leftovers) =
            place_group(&mut nodes, &group, &mut pipeline, SystemTime::now());
        assert!(assignments.is_empty());
        assert_eq!(leftovers.len(), 2);
        assert_eq!(pipeline.explain(), "1 node not available for new tasks");
    }

    #[test]
    fn fits_on_node_validates_a_single_node() {
        let service = sample_service("web", 1);
        let mut task = planted_task(
            &service,
            1,
            TaskState::Pending,
            DesiredState::Running,
            SystemTime::now(),
        );
        reserve(&mut task, 2_000_000_000, gib(2));
        let task = Arc::new(task);

        let mut nodes = BTreeMap::new();
        let big = node_info(
            NodeBuilder::new("alpha")
                .id_from_name()
                .resources(4_000_000_000, gib(8))
                .build(),
        );
        let big_id = big.id().clone();
        nodes.insert(big_id.clone(), big);
        let small = node_info(
            NodeBuilder::new("beta")
                .id_from_name()
                .resources(1_000_000_000, gib(1))
                .build(),
        );
        let small_id = small.id().clone();
        nodes.insert(small_id.clone(), small);

        let mut pipeline = Pipeline::new();
        pipeline.set_task(&task);
        assert_eq!(fits_on_node(&nodes, &big_id, &mut pipeline), Some(true));
        assert_eq!(fits_on_node(&nodes, &small_id, &mut pipeline), Some(false));
        assert_eq!(pipeline.explain(), "insufficient resources on 1 node");
        assert_eq!(
            fits_on_node(&nodes, &Id::generate(), &mut pipeline),
            None,
            "an unknown node is not a refusal, there is simply nothing to decide"
        );
    }
}
