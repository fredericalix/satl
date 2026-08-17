// SPDX-License-Identifier: BSD-2-Clause
//! Common orchestration building blocks (SWK §7.1): task creation, desired
//! state transitions, slot grouping and classification.
//!
//! Everything here is pure — no store, no async — so the decision rules are
//! unit-testable in isolation, which is what the loops in this crate are
//! made of.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::SystemTime;

use satl_core::naming::task_name;
use satl_core::{
    Annotations, DesiredState, Endpoint, Id, Meta, Service, ServiceSpec, StoreAction, StoreObject,
    Task, TaskState, TaskStatus,
};

/// Service label carrying the `satl run` autostart contract (M1).
///
/// `satl run` creates an anonymous single-replica service; whether its task
/// is meant to start immediately (`docker run`) or only be created
/// (`docker create`) is expressed as a service label:
///
/// - `satl.autostart = "false"` ⇒ tasks are created with desired
///   [`DesiredState::Ready`] (Docker's `created` state). Promotion to
///   `Running` is done externally by the API backend on `container start`.
/// - `satl.autostart = "true"`, or no label at all ⇒ desired
///   [`DesiredState::Running`].
///
/// The loops in this crate never *lower* a desired state, so a task that has
/// been promoted to `Running` is never written back to `Ready`.
pub const AUTOSTART_LABEL: &str = "satl.autostart";

/// The desired state tasks of `spec` are born with — the [`AUTOSTART_LABEL`]
/// contract.
#[must_use]
pub fn initial_desired_state(spec: &ServiceSpec) -> DesiredState {
    match spec.annotations.labels.get(AUTOSTART_LABEL) {
        Some(value) if value.eq_ignore_ascii_case("false") => DesiredState::Ready,
        _ => DesiredState::Running,
    }
}

/// Creates a task for `service` in `slot` (SWK §7.1 `NewTask`).
///
/// Fresh ID, spec snapshot, `spec_version` = the service's current version,
/// status `NEW`/"created", desired state per [`initial_desired_state`], and
/// a copy of the service endpoint. The task is *not* bound to a node: the
/// scheduler does that. Global tasks, which are born bound, come from
/// [`new_global_task`] instead.
#[must_use]
pub fn new_task(service: &Service, slot: u64) -> Task {
    build_task(service, slot, None)
}

/// Creates the task a global service runs on `node_id` (SWK §7.8 global
/// orchestrator).
///
/// Two differences from [`new_task`], both from SWK §4.5: the slot is **0**
/// (there is one task per node, not per numbered replica) and the node ID
/// takes the slot's place in the task name. The task is created already bound
/// to its node — a "preassigned" task, which the scheduler validates rather
/// than places (SWK §8.6).
#[must_use]
pub fn new_global_task(service: &Service, node_id: &Id) -> Task {
    build_task(service, GLOBAL_SLOT, Some(node_id.clone()))
}

/// The slot every global task carries (SWK §4.5): global services have one
/// task per node, and the node ID rather than a slot number identifies the
/// replica.
pub(crate) const GLOBAL_SLOT: u64 = 0;

/// Whether `task` is a global service's task, i.e. one whose replica identity
/// is its node rather than a slot number (SWK §4.5).
///
/// Slot 0 is the marker, and it is a reliable one: a replicated service's
/// slots are `1..=replicas` and [`slots_to_remove`] gives up slot 0
/// unconditionally, so no replicated task ever settles there.
pub(crate) fn is_global_task(task: &Task) -> bool {
    task.slot == GLOBAL_SLOT
}

/// SwarmKit's `SlotTuple` (SWK §7.1): what identifies **one replica** of a
/// service, and therefore what its task history and its restart budget are
/// keyed by.
///
/// For a replicated service that is the slot number. For a global service the
/// slot is always 0 and the *node* is the replica identity, so it is carried
/// too — otherwise every node of a global service would share one slot's
/// history, and one node's crash loop would spend the whole service's restart
/// budget and prune another node's history.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SlotTuple {
    /// The service the replica belongs to.
    pub(crate) service_id: Id,
    /// Its slot: `1..=replicas`, or 0 for a global task.
    pub(crate) slot: u64,
    /// The node it is pinned to — global tasks only.
    pub(crate) node_id: Option<Id>,
}

impl SlotTuple {
    /// The replica `task` belongs to, or `None` for a task with no service
    /// (which has no slot history of its own).
    pub(crate) fn of(task: &Task) -> Option<Self> {
        Some(Self {
            service_id: task.service_id.clone()?,
            slot: task.slot,
            node_id: if is_global_task(task) {
                task.node_id.clone()
            } else {
                None
            },
        })
    }
}

/// Shared construction for [`new_task`] and [`new_global_task`].
fn build_task(service: &Service, slot: u64, node_id: Option<Id>) -> Task {
    let id = Id::generate();
    let key = node_id
        .as_ref()
        .map_or_else(|| slot.to_string(), Id::to_string);
    let name = task_name(&service.spec.annotations.name, &key, &id);
    Task {
        annotations: Annotations {
            name,
            labels: BTreeMap::new(),
        },
        id,
        meta: Meta::new(),
        spec: service.spec.task.clone(),
        // The *spec's* version, not the object's. `meta.version` moves on every
        // write to the service -- including the rolling updater's writes to its
        // own `update_status` -- so stamping it here would make every existing
        // task look stale the moment an update began, and the scheduler groups
        // its placement and fault history by this value.
        spec_version: Some(service.spec_version),
        service_id: Some(service.id.clone()),
        slot,
        node_id,
        service_annotations: service.spec.annotations.clone(),
        status: TaskStatus::new(TaskState::New, "created"),
        desired_state: initial_desired_state(&service.spec),
        networks: Vec::new(),
        // The allocated endpoint if the service already has one, else the
        // spec copy (SWK §7.1: `Endpoint{Spec: service.Spec.Endpoint}`).
        // M1's allocator is a no-op, so this is normally the spec copy.
        endpoint: service.endpoint.clone().or_else(|| {
            service.spec.endpoint.clone().map(|spec| Endpoint {
                spec,
                ports: Vec::new(),
            })
        }),
        job_iteration: None,
    }
}

/// Builds an `Update` action for `task` with `mutate` applied, refreshing
/// `meta.updated_at` (the store stamps `meta.version`, not timestamps).
pub(crate) fn update_task(task: &Task, mutate: impl FnOnce(&mut Task)) -> StoreAction {
    let mut next = task.clone();
    mutate(&mut next);
    next.meta.updated_at = SystemTime::now();
    StoreAction::Update(StoreObject::Task(next))
}

/// Builds an action raising `task`'s desired state to `desired`, or `None`
/// when that would lower it (architecture §4 rule 3: desired state never
/// decreases).
pub(crate) fn raise_desired_state(task: &Task, desired: DesiredState) -> Option<StoreAction> {
    if task.desired_state >= desired {
        return None;
    }
    Some(update_task(task, |t| t.desired_state = desired))
}

/// Whether the task is on its way out (the reaper will delete it), so it no
/// longer occupies its slot.
pub(crate) fn is_removing(task: &Task) -> bool {
    task.desired_state == DesiredState::Remove
}

/// Sort key for task history (SWK §7.1 `TasksByTimestamp`): the manager
/// clock (`applied_at`) when known, else the agent clock.
pub(crate) fn task_timestamp(task: &Task) -> SystemTime {
    task.status.applied_at.unwrap_or(task.status.timestamp)
}

/// Groups a service's tasks by slot, dropping tasks already marked for
/// removal.
pub(crate) fn group_by_slot(tasks: &[Arc<Task>]) -> BTreeMap<u64, Vec<Arc<Task>>> {
    let mut slots: BTreeMap<u64, Vec<Arc<Task>>> = BTreeMap::new();
    for task in tasks.iter().filter(|t| !is_removing(t)) {
        slots.entry(task.slot).or_default().push(Arc::clone(task));
    }
    slots
}

/// Groups a global service's tasks by the node they are pinned to, dropping
/// tasks already marked for removal and tasks no node ever accepted.
///
/// The node is a global service's slot (SWK §4.5), so this is
/// [`group_by_slot`]'s counterpart and feeds the same [`classify_slot`].
pub(crate) fn group_by_node(tasks: &[Arc<Task>]) -> BTreeMap<Id, Vec<Arc<Task>>> {
    let mut nodes: BTreeMap<Id, Vec<Arc<Task>>> = BTreeMap::new();
    for task in tasks.iter().filter(|t| !is_removing(t)) {
        if let Some(node_id) = task.node_id.clone() {
            nodes.entry(node_id).or_default().push(Arc::clone(task));
        }
    }
    nodes
}

/// What a slot currently holds, from the replicated orchestrator's point of
/// view (see [`classify_slot`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotState {
    /// Holds a live task: desired ≤ `Running` and observed not terminal.
    Runnable,
    /// Holds only stopped or stopping tasks. Whether a replacement appears
    /// is the restart supervisor's decision, not the orchestrator's.
    Held,
    /// Holds nothing (or only tasks marked for removal).
    Empty,
}

/// Classifies the tasks of one slot.
///
/// **The ownership rule** (a deliberate divergence from SWK §7.8): SwarmKit
/// classifies slots purely on desired state, deletes "dead" slots and lets
/// its scale-up path refill them, because its restart supervisor runs inside
/// the same reconcile transaction. Here the restart supervisor is a separate
/// loop, so a slot whose tasks have all stopped is [`SlotState::Held`]: the
/// orchestrator leaves it alone and the supervisor decides — otherwise a
/// service with `restart-condition = none` would be resurrected by the
/// reconcile pass, and a restartable one would race two replacements into
/// the same slot. A slot only becomes [`SlotState::Empty`] once its history
/// is gone (scale-down + reaper), which is exactly when the orchestrator
/// should own it again.
pub(crate) fn classify_slot(tasks: &[Arc<Task>]) -> SlotState {
    if tasks.iter().all(|t| is_removing(t)) {
        return SlotState::Empty;
    }
    let runnable = tasks.iter().any(|t| {
        !is_removing(t) && t.desired_state <= DesiredState::Running && !t.status.state.is_terminal()
    });
    if runnable {
        SlotState::Runnable
    } else {
        SlotState::Held
    }
}

/// The slots that hold a task and therefore count towards `replicas`.
pub(crate) fn occupied_slots(slots: &BTreeMap<u64, Vec<Arc<Task>>>) -> BTreeSet<u64> {
    slots
        .iter()
        .filter(|(_, tasks)| classify_slot(tasks) != SlotState::Empty)
        .map(|(slot, _)| *slot)
        .collect()
}

/// The lowest `count` free slot numbers — the slots the replicated
/// orchestrator must fill (SWK §7.8 fills the lowest free slot numbers).
///
/// "Free" means no task the cluster still wants: a slot whose tasks are all
/// marked for removal is free again, which is exactly when the orchestrator
/// owns it (see [`classify_slot`]). Numbers above `replicas` are eligible too,
/// because a scale-down keeps *slots*, not numbers, and asking for six
/// replicas of a service whose surviving slots are 7 and 8 must not create six
/// more.
///
/// `limit` caps the work of one pass: one store transaction is bounded anyway
/// ([`satl_core::defaults::MAX_TX_ACTIONS`]), and a service asking for a
/// billion replicas must not turn a reconcile into a billion-iteration loop.
/// The next pass continues where this one stopped.
pub(crate) fn free_slots(occupied: &BTreeSet<u64>, count: u64, limit: usize) -> Vec<u64> {
    let count = usize::try_from(count).unwrap_or(usize::MAX).min(limit);
    (1..)
        .filter(|slot| !occupied.contains(slot))
        .take(count)
        .collect()
}

/// Which slots a scale-down gives up, in SwarmKit's order (SWK §7.8).
///
/// SwarmKit sorts the slots and keeps the first `replicas`, so the *ordering*
/// is the specification:
///
/// 1. **running slots first** — a slot that is not serving is the cheapest to
///    lose, and losing it costs no request;
/// 2. then by **how many copies of the service its node already runs**, so the
///    most loaded node gives up a task first and the service rebalances as it
///    shrinks. Within one node the copies are counted in ascending slot order,
///    which is what makes the last rule fall out;
/// 3. ties prefer removing the **highest slot numbers**, keeping the low slots
///    stable for workloads that treat slot 1 as a master.
///
/// Slot 0 is never valid for a replicated service (it is global-task
/// territory, SWK §4.5) and is always given up.
///
/// The multi-node half of this needs the placement data M1 did not have: with
/// every task on one node, rules 2 and 3 collapse into "remove the highest
/// slot numbers", which is what the M1 code did directly.
pub(crate) fn slots_to_remove(
    slots: &BTreeMap<u64, Vec<Arc<Task>>>,
    occupied: &BTreeSet<u64>,
    replicas: u64,
) -> BTreeSet<u64> {
    let mut doomed: BTreeSet<u64> = occupied.iter().copied().filter(|slot| *slot == 0).collect();
    let mut candidates: Vec<SlotRank> = occupied
        .iter()
        .filter(|slot| **slot != 0)
        .map(|slot| SlotRank {
            slot: *slot,
            running: slots
                .get(slot)
                .is_some_and(|tasks| tasks.iter().any(|task| is_serving(task))),
            node: slots
                .get(slot)
                .and_then(|tasks| tasks.iter().find_map(|task| task.node_id.clone())),
            copy: 0,
        })
        .collect();

    // The n-th copy of the service on its node, counted in ascending slot
    // order so that a tie between two nodes' n-th copies is broken by rule 3.
    let mut copies: BTreeMap<Option<Id>, u64> = BTreeMap::new();
    for candidate in &mut candidates {
        let count = copies.entry(candidate.node.clone()).or_insert(0);
        candidate.copy = *count;
        *count += 1;
    }

    // Keepable first; whatever does not fit in `replicas` is given up.
    candidates.sort_by(|a, b| {
        a.running
            .cmp(&b.running)
            .reverse()
            .then(a.copy.cmp(&b.copy))
            .then(a.slot.cmp(&b.slot))
    });
    let keep = usize::try_from(replicas).unwrap_or(usize::MAX);
    doomed.extend(candidates.iter().skip(keep).map(|candidate| candidate.slot));
    doomed
}

/// One slot's position in the scale-down ordering.
struct SlotRank {
    slot: u64,
    /// Whether the slot is actually serving.
    running: bool,
    /// The node its live task sits on, if it has one.
    node: Option<Id>,
    /// Which copy of the service this slot is on that node, from 0.
    copy: u64,
}

/// Whether a task is serving: the cluster wants it running and its node says
/// it is.
fn is_serving(task: &Task) -> bool {
    !is_removing(task)
        && task.desired_state <= DesiredState::Running
        && task.status.state == TaskState::Running
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use satl_core::{EndpointMode, EndpointSpec, ServiceMode};

    use crate::testing::{assigned_to, planted_task, sample_service, with_label};

    use super::*;

    fn arc_tasks(tasks: Vec<Task>) -> Vec<Arc<Task>> {
        tasks.into_iter().map(Arc::new).collect()
    }

    #[test]
    fn new_task_follows_swarmkit_semantics() {
        let mut service = sample_service("web", 3);
        // Deliberately different, because the distinction is the point: the
        // object's version moves on every write to the service (the updater
        // writes its own `update_status`), the spec's version only when the spec
        // changes. A task stamped from the former would look stale the moment an
        // update began.
        service.meta.version = satl_core::Version(99);
        service.spec_version = satl_core::Version(42);
        let task = new_task(&service, 2);

        assert_eq!(task.slot, 2);
        assert_eq!(task.service_id.as_ref(), Some(&service.id));
        assert_eq!(
            task.spec_version,
            Some(satl_core::Version(42)),
            "the spec's version, never the object's"
        );
        assert_eq!(task.spec, service.spec.task);
        assert_eq!(task.status.state, TaskState::New);
        assert_eq!(task.status.message, "created");
        assert_eq!(task.desired_state, DesiredState::Running);
        assert!(task.node_id.is_none());
        assert_eq!(task.service_annotations, service.spec.annotations);
        assert_eq!(task.meta.version, satl_core::Version(0), "store stamps it");
        assert_eq!(
            task.annotations.name,
            format!("web.2.{}", task.id),
            "canonical task name (architecture §3)"
        );
    }

    #[test]
    fn new_task_copies_the_endpoint_spec() {
        let mut service = sample_service("web", 1);
        service.spec.endpoint = Some(EndpointSpec {
            mode: EndpointMode::DnsRR,
            ports: vec![],
        });
        let task = new_task(&service, 1);
        let endpoint = task.endpoint.expect("endpoint copied");
        assert_eq!(endpoint.spec, service.spec.endpoint.unwrap());
        assert!(endpoint.ports.is_empty(), "ports are allocator-written");
    }

    #[test]
    fn autostart_label_drives_the_initial_desired_state() {
        let service = sample_service("web", 1);
        assert_eq!(initial_desired_state(&service.spec), DesiredState::Running);

        let running = with_label(sample_service("web", 1), AUTOSTART_LABEL, "true");
        assert_eq!(initial_desired_state(&running.spec), DesiredState::Running);

        let created = with_label(sample_service("web", 1), AUTOSTART_LABEL, "false");
        assert_eq!(initial_desired_state(&created.spec), DesiredState::Ready);
        assert_eq!(new_task(&created, 1).desired_state, DesiredState::Ready);

        // Only an explicit "false" opts out; anything else means "start it".
        let odd = with_label(sample_service("web", 1), AUTOSTART_LABEL, "maybe");
        assert_eq!(initial_desired_state(&odd.spec), DesiredState::Running);
        let upper = with_label(sample_service("web", 1), AUTOSTART_LABEL, "FALSE");
        assert_eq!(initial_desired_state(&upper.spec), DesiredState::Ready);
    }

    #[test]
    fn desired_state_never_decreases() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let task = planted_task(&service, 1, TaskState::Running, DesiredState::Running, now);
        assert!(raise_desired_state(&task, DesiredState::Ready).is_none());
        assert!(raise_desired_state(&task, DesiredState::Running).is_none());
        assert!(raise_desired_state(&task, DesiredState::Shutdown).is_some());
        assert!(raise_desired_state(&task, DesiredState::Remove).is_some());

        let removing = planted_task(&service, 1, TaskState::New, DesiredState::Remove, now);
        assert!(raise_desired_state(&removing, DesiredState::Remove).is_none());
    }

    #[test]
    fn slot_classification() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();

        assert_eq!(classify_slot(&[]), SlotState::Empty);

        let live = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            now,
        )]);
        assert_eq!(classify_slot(&live), SlotState::Runnable);

        // A task that has not started yet is still runnable.
        let new = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::New,
            DesiredState::Running,
            now,
        )]);
        assert_eq!(classify_slot(&new), SlotState::Runnable);

        // Created-not-started (autostart=false) is runnable too.
        let created = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::Ready,
            DesiredState::Ready,
            now,
        )]);
        assert_eq!(classify_slot(&created), SlotState::Runnable);

        // Terminal: the restart supervisor's business.
        let failed = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::Failed,
            DesiredState::Running,
            now,
        )]);
        assert_eq!(classify_slot(&failed), SlotState::Held);

        // Stopping tasks do not make the slot runnable either.
        let shutting_down = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Shutdown,
            now,
        )]);
        assert_eq!(classify_slot(&shutting_down), SlotState::Held);

        // Everything on its way out: the slot is free again.
        let removing = arc_tasks(vec![planted_task(
            &service,
            1,
            TaskState::Shutdown,
            DesiredState::Remove,
            now,
        )]);
        assert_eq!(classify_slot(&removing), SlotState::Empty);

        // History plus one live task: runnable.
        let mixed = arc_tasks(vec![
            planted_task(&service, 1, TaskState::Failed, DesiredState::Shutdown, now),
            planted_task(&service, 1, TaskState::New, DesiredState::Running, now),
        ]);
        assert_eq!(classify_slot(&mixed), SlotState::Runnable);
    }

    #[test]
    fn free_slots_are_the_lowest_unoccupied_numbers() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let tasks = arc_tasks(vec![
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
            planted_task(&service, 3, TaskState::Failed, DesiredState::Running, now),
            planted_task(&service, 4, TaskState::Shutdown, DesiredState::Remove, now),
        ]);
        let slots = group_by_slot(&tasks);
        let occupied = occupied_slots(&slots);
        assert_eq!(
            occupied,
            BTreeSet::from([1, 3]),
            "3 is held by a stopped task, 4 is on its way out and free again"
        );
        assert_eq!(
            free_slots(&occupied, 2, 100),
            vec![2, 4],
            "1 and 3 are taken"
        );
        assert_eq!(free_slots(&occupied, 0, 100), Vec::<u64>::new());
        assert_eq!(
            free_slots(&occupied, u64::MAX, 3),
            vec![2, 4, 5],
            "one pass is bounded regardless of the replica count"
        );
    }

    /// The scale-down ordering (SWK §7.8) on the shape only a real cluster
    /// produces: several nodes with different numbers of copies.
    #[test]
    fn scale_down_gives_up_the_most_loaded_node_first() {
        let service = sample_service("web", 6);
        let now = SystemTime::now();
        let (a, b) = (Id::generate(), Id::generate());
        // node a: slots 1, 2. node b: slots 3, 4, 5, 6.
        let tasks = arc_tasks(vec![
            assigned_to(
                planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
                &a,
            ),
            assigned_to(
                planted_task(&service, 2, TaskState::Running, DesiredState::Running, now),
                &a,
            ),
            assigned_to(
                planted_task(&service, 3, TaskState::Running, DesiredState::Running, now),
                &b,
            ),
            assigned_to(
                planted_task(&service, 4, TaskState::Running, DesiredState::Running, now),
                &b,
            ),
            assigned_to(
                planted_task(&service, 5, TaskState::Running, DesiredState::Running, now),
                &b,
            ),
            assigned_to(
                planted_task(&service, 6, TaskState::Running, DesiredState::Running, now),
                &b,
            ),
        ]);
        let slots = group_by_slot(&tasks);
        let occupied = occupied_slots(&slots);

        assert_eq!(
            slots_to_remove(&slots, &occupied, 6),
            BTreeSet::new(),
            "nothing to give up at the desired count"
        );
        assert_eq!(
            slots_to_remove(&slots, &occupied, 4),
            BTreeSet::from([5, 6]),
            "the four-copy node loses its third and fourth copies, not the two-copy node"
        );
        assert_eq!(
            slots_to_remove(&slots, &occupied, 2),
            BTreeSet::from([2, 4, 5, 6]),
            "one copy left per node, and the higher slot number of each pair goes"
        );
        assert_eq!(
            slots_to_remove(&slots, &occupied, 0),
            BTreeSet::from([1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn scale_down_gives_up_slots_that_are_not_serving_first() {
        let service = sample_service("web", 3);
        let now = SystemTime::now();
        let node = Id::generate();
        let tasks = arc_tasks(vec![
            // Slot 1 is not serving: still being prepared.
            assigned_to(
                planted_task(
                    &service,
                    1,
                    TaskState::Preparing,
                    DesiredState::Running,
                    now,
                ),
                &node,
            ),
            assigned_to(
                planted_task(&service, 2, TaskState::Running, DesiredState::Running, now),
                &node,
            ),
            assigned_to(
                planted_task(&service, 3, TaskState::Running, DesiredState::Running, now),
                &node,
            ),
        ]);
        let slots = group_by_slot(&tasks);
        let occupied = occupied_slots(&slots);
        assert_eq!(
            slots_to_remove(&slots, &occupied, 2),
            BTreeSet::from([1]),
            "the slot that serves nothing costs no request to lose, even at slot 1"
        );
    }

    #[test]
    fn slot_zero_is_never_a_replicated_slot() {
        let service = sample_service("web", 3);
        let now = SystemTime::now();
        let tasks = arc_tasks(vec![
            planted_task(&service, 0, TaskState::Running, DesiredState::Running, now),
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
        ]);
        let slots = group_by_slot(&tasks);
        let occupied = occupied_slots(&slots);
        assert_eq!(
            slots_to_remove(&slots, &occupied, 3),
            BTreeSet::from([0]),
            "global-task territory (SWK §4.5), whatever the replica count"
        );
    }

    #[test]
    fn group_by_slot_ignores_tasks_marked_for_removal() {
        let service = sample_service("web", 2);
        let now = SystemTime::now();
        let tasks = arc_tasks(vec![
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
            planted_task(&service, 2, TaskState::Running, DesiredState::Remove, now),
        ]);
        let slots = group_by_slot(&tasks);
        assert_eq!(slots.len(), 1);
        assert!(slots.contains_key(&1));
    }

    #[test]
    fn task_timestamp_prefers_the_manager_clock() {
        let service = sample_service("web", 1);
        let agent_clock = SystemTime::now();
        let manager_clock = agent_clock + Duration::from_mins(1);
        let mut task = planted_task(
            &service,
            1,
            TaskState::Failed,
            DesiredState::Running,
            agent_clock,
        );
        assert_eq!(task_timestamp(&task), agent_clock);
        task.status.applied_at = Some(manager_clock);
        assert_eq!(task_timestamp(&task), manager_clock);
    }

    #[test]
    fn replicas_come_from_the_service_mode() {
        let service = sample_service("web", 7);
        assert_eq!(service.spec.mode, ServiceMode::Replicated { replicas: 7 });
    }
}
