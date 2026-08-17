// SPDX-License-Identifier: BSD-2-Clause
//! Node enforcement: which tasks a node that can no longer run them has to
//! give up (SWK §7.1 `InvalidNode`, SWK §7.8 "node down/drain/delete →
//! restart, i.e. replace, all its replicated tasks", and the §7.6 **constraint
//! enforcer** — [`constraints_unmet`]).
//!
//! Two questions, one eviction path: a node is unfit for *every* task
//! ([`node_invalidity`]: gone, `DOWN`, draining) or unfit for *this* task
//! ([`constraints_unmet`]: its labels no longer match the service's
//! placement). Both answers are handed to the same
//! [`crate::restart::RestartSupervisor`] trigger machinery, so there is one
//! replacement transaction and one `max_attempts` budget however a task lost
//! its place.
//!
//! # Why the decisions live here and the loop does not
//!
//! SwarmKit's replicated orchestrator reacts to node events by calling
//! `restart.Supervisor.Restart(...)` — the very object that handles a crashed
//! task, inside the same transaction. That sharing is load-bearing:
//! `max_attempts` is one budget per replica and spec version, so a slot that has
//! burned its retries on crashes cannot win extra ones by having its node go
//! down, and vice versa.
//!
//! The loops in this crate, by contract, never call each other and share no
//! mutable state (see the crate docs and CLAUDE.md invariant #1). A separate
//! node-enforcer *loop* would therefore need a second copy of the replacement
//! construction to keep in sync with the supervisor's, and — before the budget
//! became store-derived ([`crate::restart::RestartHistory`]) — could not have
//! read its counters at all. Either way it is one decision about one slot, and
//! two components taking it is how a slot ends up with two replacements.
//!
//! So the loop half of the enforcer is [`crate::restart::RestartSupervisor`],
//! which gains two more triggers
//! ([`crate::restart::Trigger::InvalidNode`] and
//! [`crate::restart::Trigger::ConstraintsUnmet`]).
//! It already watches the store feed, already runs the periodic
//! self-healing pass, already proposes through
//! [`crate::propose::propose_with_retry`], and is already spawned with — and
//! cancelled by — the same [`tokio_util::sync::CancellationToken`] as every
//! other loop in [`crate::Orchestrator::spawn`]. It now also watches `Node`
//! events (created/updated/removed).
//!
//! What stays here is the *decision*, pure and table-testable:
//! [`node_invalidity`] ("may this node run tasks at all?"), [`evict_reason`]
//! ("must this task give up its place?") and [`constraints_unmet`] ("does this
//! node still qualify for this task?").
//!
//! # The rules
//!
//! `InvalidNode(n)` (SWK §7.1) is `n == nil || n.Status.State == DOWN ||
//! n.Spec.Availability == DRAIN` — and nothing else:
//!
//! - `PAUSE` means "no new tasks, leave the running ones alone", so it never
//!   evicts (SWK §7.8, global orchestrator: "`PAUSE` node → leave as-is");
//! - `UNKNOWN` (no dispatcher session has ever registered) and `DISCONNECTED`
//!   (session invalidated, e.g. a manager leadership change) are *not*
//!   invalid: the node is expected back within its heartbeat TTL, and the
//!   scheduler already refuses to place new tasks on it (`satl-sched`'s
//!   `NodeReadyFilter` requires `Ready`/`Active`).
//!
//! Eviction is deliberately not deletion, and not even a status rewrite. The
//! node may be merely partitioned and still running the jail, so:
//!
//! - the old task keeps existing with desired state `SHUTDOWN` — if its agent
//!   ever reconnects, it stops the container;
//! - the replacement is a *new* task in the same slot (architecture §4 rule 4:
//!   a task is one-shot and is never re-executed).
//!
//! Both writes land in one transaction, so the slot never passes through a
//! state in which the replicated orchestrator could believe it is empty (see
//! [`crate::task::classify_slot`] and the note in
//! [`crate::restart::RestartSupervisor`]). While the predecessor lingers, the
//! slot legitimately holds two live tasks — SWK §4.5 exists for exactly this
//! case; the rolling updater is what converges it back to one.

use satl_core::{Availability, DesiredState, Node, NodeState, Service, Task};

/// Why a node may no longer run tasks (SWK §7.1 `InvalidNode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeInvalidity {
    /// The node object is gone from the store (SwarmKit's `n == nil`) — a
    /// demoted, removed or never-created member.
    Missing,
    /// The dispatcher's heartbeat TTL expired (`Status.State == DOWN`).
    Down,
    /// The operator asked for the node to be emptied
    /// (`Spec.Availability == DRAIN`).
    Drained,
}

impl NodeInvalidity {
    /// Short operator-facing reason, for logs.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Missing => "node object is gone",
            Self::Down => "node is down",
            Self::Drained => "node is draining",
        }
    }
}

/// Whether `node` is unfit to run tasks, and why (SWK §7.1 `InvalidNode`).
///
/// `None` means the node object is absent from the store, which is itself an
/// invalidity ([`NodeInvalidity::Missing`]).
///
/// `DRAIN` is reported in preference to `DOWN` when both hold: a drain is an
/// explicit operator instruction, and it is the case SWK §7.4 forces the
/// restart delay to zero for.
pub(crate) fn node_invalidity(node: Option<&Node>) -> Option<NodeInvalidity> {
    let Some(node) = node else {
        return Some(NodeInvalidity::Missing);
    };
    if node.spec.availability == Availability::Drain {
        return Some(NodeInvalidity::Drained);
    }
    if node.status.state == NodeState::Down {
        return Some(NodeInvalidity::Down);
    }
    // Active/Pause × Unknown/Ready/Disconnected: the node keeps its tasks.
    None
}

/// Whether `task` is a candidate for node-based eviction at all, before its
/// node is even looked at.
///
/// A task qualifies while it is bound to a node, still wanted
/// (`desired_state <= Running`) and not already finished:
///
/// - **unbound** tasks (`node_id == None`) have nothing to be evicted from —
///   the scheduler simply will not place them on an invalid node;
/// - tasks already at desired `Shutdown`/`Remove` are being stopped by
///   somebody else; raising their desired state again would be a no-op and
///   creating a replacement would double up on whoever owns them;
/// - tasks in a terminal observed state belong to the restart supervisor's
///   [`Terminated`](crate::restart::Trigger::Terminated) path — judging them
///   twice is how a slot ends up with two replacements.
pub(crate) fn evictable(task: &Task) -> bool {
    task.node_id.is_some()
        && task.desired_state <= DesiredState::Running
        && !task.status.state.is_terminal()
}

/// Whether `task` must give up its place on `node`, and why.
///
/// `node` is the store's current value for `task.node_id`; `None` means the
/// node object no longer exists. The full decision table is
/// [`evictable`] × [`node_invalidity`].
pub(crate) fn evict_reason(task: &Task, node: Option<&Node>) -> Option<NodeInvalidity> {
    if !evictable(task) {
        return None;
    }
    node_invalidity(node)
}

/// Whether `task`'s node has stopped satisfying the placement constraints its
/// service asks for (SWK §7.6, the constraint enforcer).
///
/// Constraints are checked at *scheduling* time against the node as it was
/// then. A node's labels and its availability are operator-writable at any
/// moment, so a task can keep running somewhere the service no longer allows —
/// which is the gap this closes.
///
/// Three parts, each load-bearing:
///
/// - the **service's current** placement is the reference, never the task's
///   snapshot: a placement-only service update deliberately keeps matching
///   tasks (SWK §7.2 rule 2, [`crate::dirty`]), so the task's copy goes stale
///   by design. The same predicate answers both questions
///   ([`crate::dirty::node_satisfies`]);
/// - only an **`ACTIVE`** node is judged. `DRAIN` already evicts through
///   [`node_invalidity`], and `PAUSE` means "do not touch what runs here" — a
///   paused node is one an operator is inspecting, and evicting from it would
///   be the opposite of what they asked for (SWK §7.6);
/// - **resources are not re-checked.** SWK §7.6 also evicts when the running
///   reservations no longer fit the node's capacity; that total lives in the
///   scheduler's in-memory mirror, and re-deriving it here would put a second
///   resource accountant in the tree. Recorded as a gap rather than
///   approximated.
pub(crate) fn constraints_unmet(service: &Service, task: &Task, node: &Node) -> bool {
    if !evictable(task) {
        return false;
    }
    if node.spec.availability != Availability::Active {
        return false;
    }
    !crate::dirty::node_satisfies(&service.spec.task, Some(node))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use satl_core::TaskState;

    use crate::testing::{assigned_to, planted_node, planted_task, sample_service};

    use super::*;

    /// Every `(state, availability)` pair, with the SWK §7.1 verdict.
    const NODE_TABLE: [(NodeState, Availability, Option<NodeInvalidity>); 12] = [
        // Active: only liveness matters.
        (NodeState::Ready, Availability::Active, None),
        (NodeState::Unknown, Availability::Active, None),
        (NodeState::Disconnected, Availability::Active, None),
        (
            NodeState::Down,
            Availability::Active,
            Some(NodeInvalidity::Down),
        ),
        // Pause: "no new tasks, leave the running ones alone" — never evicts,
        // whatever the liveness (SWK §7.8).
        (NodeState::Ready, Availability::Pause, None),
        (NodeState::Unknown, Availability::Pause, None),
        (NodeState::Disconnected, Availability::Pause, None),
        (
            NodeState::Down,
            Availability::Pause,
            Some(NodeInvalidity::Down),
        ),
        // Drain: always evicts, and is reported in preference to Down.
        (
            NodeState::Ready,
            Availability::Drain,
            Some(NodeInvalidity::Drained),
        ),
        (
            NodeState::Unknown,
            Availability::Drain,
            Some(NodeInvalidity::Drained),
        ),
        (
            NodeState::Disconnected,
            Availability::Drain,
            Some(NodeInvalidity::Drained),
        ),
        (
            NodeState::Down,
            Availability::Drain,
            Some(NodeInvalidity::Drained),
        ),
    ];

    #[test]
    fn invalid_node_is_missing_down_or_draining() {
        for (state, availability, expected) in NODE_TABLE {
            let mut node = planted_node("alpha");
            node.status.state = state;
            node.spec.availability = availability;
            assert_eq!(
                node_invalidity(Some(&node)),
                expected,
                "{state:?} / {availability:?}"
            );
        }
    }

    #[test]
    fn a_node_that_is_gone_is_invalid() {
        assert_eq!(node_invalidity(None), Some(NodeInvalidity::Missing));
    }

    #[test]
    fn pause_never_evicts_a_healthy_node() {
        for state in [
            NodeState::Ready,
            NodeState::Unknown,
            NodeState::Disconnected,
        ] {
            let mut node = planted_node("alpha");
            node.status.state = state;
            node.spec.availability = Availability::Pause;
            assert_eq!(node_invalidity(Some(&node)), None, "{state:?}");
        }
    }

    /// The task half of the table: which tasks a `DOWN` node has to give up.
    #[test]
    fn only_live_bound_tasks_are_evicted() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let mut node = planted_node("alpha");
        node.status.state = NodeState::Down;

        let cases = [
            // Running, still wanted: the case the bug is about.
            (TaskState::Running, DesiredState::Running, true),
            // Not started yet, but assigned to a node that just died.
            (TaskState::Assigned, DesiredState::Running, true),
            (TaskState::Accepted, DesiredState::Running, true),
            (TaskState::Preparing, DesiredState::Running, true),
            (TaskState::Starting, DesiredState::Running, true),
            // `docker create`d (autostart=false) tasks are wanted too.
            (TaskState::Ready, DesiredState::Ready, true),
            // Already being stopped or removed: somebody else owns them.
            (TaskState::Running, DesiredState::Shutdown, false),
            (TaskState::Running, DesiredState::Remove, false),
            // Terminal: the restart supervisor's `Terminated` path owns them.
            (TaskState::Complete, DesiredState::Running, false),
            (TaskState::Shutdown, DesiredState::Running, false),
            (TaskState::Failed, DesiredState::Running, false),
            (TaskState::Rejected, DesiredState::Running, false),
            (TaskState::Orphaned, DesiredState::Running, false),
        ];
        for (state, desired, expected) in cases {
            let task = assigned_to(planted_task(&service, 1, state, desired, now), &node.id);
            assert_eq!(evictable(&task), expected, "{state} / {desired}");
            assert_eq!(
                evict_reason(&task, Some(&node)).is_some(),
                expected,
                "{state} / {desired}"
            );
        }
    }

    #[test]
    fn an_unbound_task_is_never_evicted() {
        let service = sample_service("web", 1);
        let mut node = planted_node("alpha");
        node.status.state = NodeState::Down;
        // No `assigned_to`: the scheduler has not placed it yet.
        let task = planted_task(
            &service,
            1,
            TaskState::Pending,
            DesiredState::Running,
            SystemTime::now(),
        );
        assert!(!evictable(&task));
        assert_eq!(evict_reason(&task, Some(&node)), None);
        assert_eq!(evict_reason(&task, None), None);
    }

    /// The full cross product: a live bound task is evicted exactly when its
    /// node is invalid, with the node's own reason.
    #[test]
    fn eviction_is_evictable_times_node_invalidity() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        for (state, availability, expected) in NODE_TABLE {
            let mut node = planted_node("alpha");
            node.status.state = state;
            node.spec.availability = availability;
            let live = assigned_to(
                planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
                &node.id,
            );
            assert_eq!(
                evict_reason(&live, Some(&node)),
                expected,
                "live task on {state:?}/{availability:?}"
            );

            let stopping = assigned_to(
                planted_task(&service, 1, TaskState::Running, DesiredState::Shutdown, now),
                &node.id,
            );
            assert_eq!(
                evict_reason(&stopping, Some(&node)),
                None,
                "already-shutdown task on {state:?}/{availability:?}"
            );
        }
    }

    /// The constraint enforcer (SWK §7.6): the service's *current* placement
    /// against the node as it is now.
    #[test]
    fn a_node_that_stops_matching_the_constraints_gives_up_its_task() {
        let mut service = sample_service("web", 1);
        service.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];
        let now = SystemTime::now();

        let mut node = planted_node("n1");
        node.spec.labels.insert("zone".to_owned(), "a".to_owned());
        let task = assigned_to(
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
            &node.id,
        );
        assert!(
            !constraints_unmet(&service, &task, &node),
            "the label still matches"
        );

        // The operator relabels the node: the task no longer belongs there.
        node.spec.labels.insert("zone".to_owned(), "b".to_owned());
        assert!(constraints_unmet(&service, &task, &node));

        // The task's own snapshot is deliberately not the reference: a
        // placement-only service update keeps matching tasks (SWK §7.2 rule 2),
        // so the copy it carries is stale by design.
        let mut stale = task.clone();
        stale.spec.placement.constraints.clear();
        assert!(constraints_unmet(&service, &stale, &node));
    }

    /// Availability decides whether the question is even asked (SWK §7.6).
    #[test]
    fn only_an_active_node_is_judged_on_its_constraints() {
        let mut service = sample_service("web", 1);
        service.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];
        let now = SystemTime::now();
        let mut node = planted_node("n1");
        node.spec.labels.insert("zone".to_owned(), "b".to_owned());
        let task = assigned_to(
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
            &node.id,
        );

        node.spec.availability = Availability::Active;
        assert!(constraints_unmet(&service, &task, &node));

        node.spec.availability = Availability::Pause;
        assert!(
            !constraints_unmet(&service, &task, &node),
            "pause means do not touch what runs here"
        );

        node.spec.availability = Availability::Drain;
        assert!(
            !constraints_unmet(&service, &task, &node),
            "a drain already evicts through node_invalidity, with delay 0"
        );
    }

    /// A service with no constraints never evicts, and a task that is already
    /// on its way out is nobody's to evict again.
    #[test]
    fn the_constraint_enforcer_leaves_everything_else_alone() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let node = planted_node("n1");
        let task = assigned_to(
            planted_task(&service, 1, TaskState::Running, DesiredState::Running, now),
            &node.id,
        );
        assert!(
            !constraints_unmet(&service, &task, &node),
            "no constraints, nothing to fail"
        );

        let mut constrained = sample_service("web", 1);
        constrained.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];
        for (state, desired) in [
            (TaskState::Running, DesiredState::Shutdown),
            (TaskState::Running, DesiredState::Remove),
            (TaskState::Failed, DesiredState::Running),
        ] {
            let task = assigned_to(planted_task(&constrained, 1, state, desired, now), &node.id);
            assert!(
                !constraints_unmet(&constrained, &task, &node),
                "{state} / {desired}"
            );
        }
    }

    #[test]
    fn reasons_name_the_problem() {
        assert_eq!(NodeInvalidity::Down.reason(), "node is down");
        assert_eq!(NodeInvalidity::Drained.reason(), "node is draining");
        assert_eq!(NodeInvalidity::Missing.reason(), "node object is gone");
    }
}
