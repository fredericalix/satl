// SPDX-License-Identifier: BSD-2-Clause
//! The global-service reconciliation loop (SWK §7.8, global orchestrator).
//!
//! A global service runs **one task per eligible node**. There is no replica
//! count to satisfy and no slot numbering: the node *is* the replica identity
//! (SWK §4.5, so the task's slot is 0 and its name carries the node ID — see
//! [`crate::task::new_global_task`]), and the reconciliation is a join over
//! (service × node) rather than over slots. A **global job** looks similar
//! but is not this loop's business: it runs once per node and is done, so
//! [`crate::jobs`] owns it (reusing this module's eligibility verdicts).
//!
//! Per node, one of three verdicts ([`NodeVerdict`]):
//!
//! - **`Run`** — the node is `Ready`, `Active`, and satisfies the service's
//!   placement constraints and platform requirements. It must hold exactly one
//!   task; if it holds none the loop creates one, already bound to it. That is a
//!   "preassigned" task (SWK §8.6): the scheduler validates the node rather than
//!   choosing it.
//! - **`Hold`** — `PAUSE`, or a node that is simply not reachable yet
//!   (`UNKNOWN`/`DISCONNECTED`). No new task, and nothing taken away: SWK §7.8
//!   spells this out for `PAUSE`, and it is the same rule the constraint
//!   enforcer follows ([`crate::node_enforcer::constraints_unmet`]).
//! - **`Reject`** — draining, `DOWN`, gone, or no longer matching the
//!   constraints. Its tasks of this service are given up.
//!
//! # Why the tasks of a rejected node are not "restarted"
//!
//! For a replicated service, a node that can no longer run a task means the task
//! moves: the restart supervisor shuts it down and creates a replacement in the
//! same slot, which the scheduler then places elsewhere (SWK §7.8, node
//! down/drain/delete). A global task has no elsewhere — its node is its
//! identity — so it is shut down and *not* replaced, and the service simply runs
//! on one node fewer until the node comes back. The restart supervisor
//! deliberately ignores global tasks for its two node-driven triggers
//! ([`crate::restart::Trigger::applies_to_global`]) so that exactly one
//! component owns this decision.
//!
//! A **crash** is the other way round: it is the supervisor's, and its
//! replacement is pinned to the same node (SWK §7.4 step 4). That is why this
//! loop's occupancy test is SwarmKit's — *does the node hold a task the cluster
//! still wants there* (`desired_state <= RUNNING`), rather than *a task that is
//! still running*:
//!
//! - a task that crashed keeps desired `RUNNING`, so this loop leaves the node
//!   alone and the supervisor decides whether a replacement is due. Two
//!   components never create a task for one node;
//! - a task this loop shut down is at desired `SHUTDOWN`, so when its node
//!   becomes eligible again the node counts as empty and gets a fresh task —
//!   which is exactly what an operator who ran `node update --availability
//!   active` after a drain expects;
//! - a service whose restart policy refuses to replace a crashed task keeps that
//!   task at desired `RUNNING` and therefore gains no replacement, consistently
//!   with a replicated service's held slot ([`crate::task::classify_slot`]).
//!
//! # Rolling updates
//!
//! The updater ([`crate::update`]) drives global services too, with the node as
//! the unit a batch advances: `parallelism` is a number of *nodes* and the
//! rollout proceeds node by node (SWK §7.8, "one slot per node ⇒ updates proceed
//! node-by-node"). It considers only `Run` nodes — a paused node is not updated,
//! and a rejected one is losing its task anyway — and creating the task for a
//! node that has none is this loop's job, never the updater's, exactly as
//! filling an empty slot belongs to [`crate::replicated`].

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use satl_cluster::{ClusterStore, StoreView};
use satl_core::defaults::MAX_TX_ACTIONS;
use satl_core::{
    Availability, DesiredState, Id, Node, NodeState, ObjectKind, Service, ServiceMode, StoreAction,
    StoreEvent, StoreObject, Task,
};
use satl_sched::{PlacementRequirements, accepts_new_tasks};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::node_enforcer::evictable;
use crate::propose::propose_with_retry;
use crate::task::{group_by_node, new_global_task, raise_desired_state};

/// What a global service should do about one node (SWK §7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeVerdict {
    /// The node must hold exactly one task of the service.
    Run,
    /// No new task, and nothing taken away.
    Hold,
    /// The node must not run this service: its tasks are given up.
    Reject,
}

/// What to do about `node`, given what the service asks of a node.
///
/// The order of the rules is the specification:
///
/// 1. **`DRAIN` first.** An operator emptying a node has asked for exactly that,
///    whatever else is true of it.
/// 2. **`PAUSE` next**, before any other reason to reject: "no new tasks, leave
///    the running ones alone" (SWK §7.8) is an instruction not to touch this
///    node, and it outranks a constraint that stopped matching — the same
///    precedence the constraint enforcer uses (SWK §7.6).
/// 3. **`DOWN`** is a rejection: the node is past its heartbeat TTL and its
///    tasks are not running (and if the node comes back, its agent stops them).
/// 4. **Constraints and platform** decide next, through the scheduler's own
///    predicate so this loop can never create a task the scheduler would refuse.
/// 5. What is left is `Ready` (⇒ `Run`) or merely not-reachable-yet
///    (`UNKNOWN`/`DISCONNECTED` ⇒ `Hold`): the node is expected back inside its
///    TTL and its tasks are none of this loop's business until then.
pub(crate) fn node_verdict(node: &Node, requirements: &PlacementRequirements) -> NodeVerdict {
    if node.spec.availability == Availability::Drain {
        return NodeVerdict::Reject;
    }
    if node.spec.availability == Availability::Pause {
        return NodeVerdict::Hold;
    }
    if node.status.state == NodeState::Down {
        return NodeVerdict::Reject;
    }
    if !requirements.satisfied_by(node) {
        return NodeVerdict::Reject;
    }
    if accepts_new_tasks(node) {
        NodeVerdict::Run
    } else {
        NodeVerdict::Hold
    }
}

/// The nodes a global service should be running on right now (verdict `Run`) —
/// the unit set of its rolling updates too ([`crate::update`]).
pub(crate) fn eligible_nodes(view: &StoreView<'_>, service: &Service) -> BTreeSet<Id> {
    let requirements = PlacementRequirements::of(&service.spec.task);
    view.nodes()
        .into_iter()
        .filter(|node| node_verdict(node, &requirements) == NodeVerdict::Run)
        .map(|node| node.id.clone())
        .collect()
}

/// Reconciles global services against the nodes of the cluster.
pub(crate) struct GlobalOrchestrator {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Services touched since the last commit marker.
    dirty: BTreeSet<Id>,
    /// Task ID to owning service ID: a `Removed` event carries only the ID, and
    /// the object is already gone from the store.
    task_owner: HashMap<Id, Id>,
    /// Whether a node changed in this transaction, which can change the verdict
    /// for **every** global service.
    nodes_changed: bool,
}

impl GlobalOrchestrator {
    pub(crate) fn new(store: ClusterStore, interval: Duration) -> Self {
        Self {
            store,
            interval,
            dirty: BTreeSet::new(),
            task_owner: HashMap::new(),
            nodes_changed: false,
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.global");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    // The first tick fires immediately: that is the initial
                    // full pass, and the leader-change replay (SWK §7.9 needs
                    // none here — every decision is derived from the store).
                    _ = ticker.tick() => self.full_pass().await,
                    event = events.recv() => match event {
                        Ok(event) => self.observe(event).await,
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full pass");
                            self.dirty.clear();
                            self.full_pass().await;
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("global orchestrator stopped");
        }
        .instrument(span))
        .await;
    }

    /// Accumulates the services a transaction touched, reconciling them when its
    /// commit marker arrives.
    ///
    /// Unlike the replicated orchestrator, this loop watches nodes: a node
    /// joining, draining or being relabelled is the *only* thing that changes a
    /// global service's desired task set. Node objects are rewritten on every
    /// heartbeat, so a node event only reconciles the global services — there
    /// are usually none, and the pass is then a single store read.
    async fn observe(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => match object {
                StoreObject::Service(service) => {
                    self.dirty.insert(service.id.clone());
                }
                StoreObject::Task(task) => {
                    if let Some(service_id) = task.service_id.clone() {
                        self.task_owner.insert(task.id.clone(), service_id.clone());
                        self.dirty.insert(service_id);
                    }
                }
                StoreObject::Node(_) => self.nodes_changed = true,
                _ => {}
            },
            StoreEvent::Removed { kind, id } => match kind {
                // A removed service leaves its tasks behind; the replicated
                // loop's orphan handling marks them for removal.
                ObjectKind::Service => {
                    self.dirty.remove(&id);
                }
                ObjectKind::Task => {
                    if let Some(service_id) = self.task_owner.remove(&id) {
                        self.dirty.insert(service_id);
                    }
                }
                ObjectKind::Node => self.nodes_changed = true,
                _ => {}
            },
            StoreEvent::Commit(_) => {
                if std::mem::take(&mut self.nodes_changed) {
                    self.dirty.extend(self.global_services());
                }
                for service_id in std::mem::take(&mut self.dirty) {
                    self.reconcile(&service_id).await;
                }
            }
        }
    }

    /// Reconciles every global service from a full store read.
    async fn full_pass(&mut self) {
        let targets = self.global_services();
        tracing::debug!(services = targets.len(), "full global reconciliation pass");
        for service_id in targets {
            self.reconcile(&service_id).await;
        }
    }

    /// The IDs of the cluster's global services.
    fn global_services(&self) -> Vec<Id> {
        let view = self.store.view();
        view.services()
            .iter()
            .filter(|service| service.spec.mode == ServiceMode::Global)
            .map(|service| service.id.clone())
            .collect()
    }

    /// Reconciles one service, retrying its decision on sequence conflicts.
    async fn reconcile(&mut self, service_id: &Id) {
        let result = propose_with_retry(&self.store, "global reconcile", |view| {
            reconcile_actions(view, service_id)
        })
        .await;
        if let Err(error) = result {
            // Never fatal: the periodic pass re-derives the same decision.
            tracing::warn!(service_id = %service_id, %error, "global reconciliation deferred");
        }
    }
}

/// Derives the store transaction that brings one global service's tasks in line
/// with the nodes of the cluster. Pure and idempotent: a converged service
/// yields no actions, and a replicated one yields none at all.
fn reconcile_actions(view: &StoreView<'_>, service_id: &Id) -> Vec<StoreAction> {
    // A service that is gone is the replicated loop's business: it owns the
    // orphan-task sweep for every mode (`remove_all`).
    let Some(service) = view.service(service_id) else {
        return Vec::new();
    };
    if service.spec.mode != ServiceMode::Global {
        return Vec::new();
    }

    // TODO(M2): the store has no service→tasks index yet (architecture §6.1), so
    // this is a full scan per reconcile.
    let tasks: Vec<Arc<Task>> = view
        .tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .collect();
    let requirements = PlacementRequirements::of(&service.spec.task);
    let by_node = group_by_node(&tasks);
    let mut actions = Vec::new();

    // Nodes that must give up their task. Done first, for the same reason the
    // replicated loop scales down first: it is the half that cannot wait, and a
    // full transaction leaves the additions for the next pass.
    for (node_id, on_node) in &by_node {
        let verdict = view.node(node_id).map_or(NodeVerdict::Reject, |node| {
            node_verdict(&node, &requirements)
        });
        if verdict != NodeVerdict::Reject {
            continue;
        }
        for task in on_node.iter().filter(|task| evictable(task)) {
            if let Some(action) = raise_desired_state(task, DesiredState::Shutdown) {
                tracing::info!(
                    service_id = %service.id,
                    service = %service.spec.annotations.name,
                    task_id = %task.id,
                    slot = task.slot,
                    node_id = %node_id,
                    from = %task.desired_state,
                    to = %DesiredState::Shutdown,
                    reason = "node is no longer eligible for this global service",
                    "stopping a global task"
                );
                actions.push(action);
            }
        }
    }

    // Eligible nodes that hold no task the cluster still wants there.
    for node in view.nodes() {
        if node_verdict(&node, &requirements) != NodeVerdict::Run {
            continue;
        }
        if by_node
            .get(&node.id)
            .is_some_and(|on_node| occupied(on_node))
        {
            continue;
        }
        let task = new_global_task(&service, &node.id);
        tracing::info!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            task_id = %task.id,
            slot = task.slot,
            node_id = %node.id,
            desired = %task.desired_state,
            "creating a global task for a node that has none"
        );
        actions.push(StoreAction::Create(StoreObject::Task(task)));
    }

    actions.truncate(MAX_TX_ACTIONS);
    actions
}

/// Whether a node already holds a task of the service that the cluster still
/// wants there — SwarmKit's global occupancy test, and the reason this loop and
/// the restart supervisor never both create a task for one node (see the module
/// docs).
fn occupied(on_node: &[Arc<Task>]) -> bool {
    on_node
        .iter()
        .any(|task| task.desired_state <= DesiredState::Running)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use satl_core::TaskState;

    use crate::testing::{assigned_to, planted_node, planted_task, sample_service};

    use super::*;

    /// A global service with no placement requirements at all.
    fn global_service(name: &str) -> Service {
        let mut service = sample_service(name, 1);
        service.spec.mode = ServiceMode::Global;
        service
    }

    fn requirements(service: &Service) -> PlacementRequirements {
        PlacementRequirements::of(&service.spec.task)
    }

    /// Every `(state, availability)` pair, with the SWK §7.8 verdict.
    #[test]
    fn the_verdict_table_follows_availability_then_liveness() {
        let service = global_service("agent");
        let cases = [
            (NodeState::Ready, Availability::Active, NodeVerdict::Run),
            (NodeState::Ready, Availability::Pause, NodeVerdict::Hold),
            (NodeState::Ready, Availability::Drain, NodeVerdict::Reject),
            (NodeState::Down, Availability::Active, NodeVerdict::Reject),
            (NodeState::Down, Availability::Pause, NodeVerdict::Hold),
            (NodeState::Down, Availability::Drain, NodeVerdict::Reject),
            // Not reachable yet: no new task, and nothing taken away.
            (NodeState::Unknown, Availability::Active, NodeVerdict::Hold),
            (
                NodeState::Disconnected,
                Availability::Active,
                NodeVerdict::Hold,
            ),
        ];
        for (state, availability, expected) in cases {
            let mut node = planted_node("n1");
            node.status.state = state;
            node.spec.availability = availability;
            assert_eq!(
                node_verdict(&node, &requirements(&service)),
                expected,
                "{state:?} / {availability:?}"
            );
        }
    }

    /// Constraints and platform decide too — through the scheduler's predicate,
    /// so this loop never creates a task the scheduler would refuse.
    #[test]
    fn a_node_that_does_not_match_the_placement_is_rejected() {
        let mut service = global_service("agent");
        service.spec.task.placement.constraints = vec!["node.labels.zone == a".to_owned()];

        let mut matching = planted_node("n1");
        matching
            .spec
            .labels
            .insert("zone".to_owned(), "a".to_owned());
        assert_eq!(
            node_verdict(&matching, &requirements(&service)),
            NodeVerdict::Run
        );

        let other = planted_node("n2");
        assert_eq!(
            node_verdict(&other, &requirements(&service)),
            NodeVerdict::Reject
        );

        // ... except on a paused node, which is not to be touched at all.
        let mut paused = planted_node("n3");
        paused.spec.availability = Availability::Pause;
        assert_eq!(
            node_verdict(&paused, &requirements(&service)),
            NodeVerdict::Hold,
            "pause outranks a constraint that stopped matching (SWK §7.6)"
        );

        let mut wrong_platform = planted_node("n4");
        service.spec.task.placement.constraints.clear();
        service.spec.task.placement.platforms = vec![satl_core::Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        }];
        if let Some(description) = wrong_platform.description.as_mut() {
            description.platform.os = "linux".to_owned();
        }
        assert_eq!(
            node_verdict(&wrong_platform, &requirements(&service)),
            NodeVerdict::Reject
        );
    }

    /// The occupancy test that keeps this loop and the restart supervisor from
    /// both creating a task for one node.
    #[test]
    fn a_node_is_occupied_by_a_task_the_cluster_still_wants_there() {
        let service = global_service("agent");
        let node = Id::generate();
        let task = |state, desired| {
            let planted = planted_task(&service, 0, state, desired, SystemTime::now());
            Arc::new(assigned_to(planted, &node))
        };

        assert!(!occupied(&[]), "no task at all");
        assert!(occupied(&[task(TaskState::Running, DesiredState::Running)]));
        assert!(occupied(&[task(TaskState::New, DesiredState::Running)]));
        assert!(
            occupied(&[task(TaskState::Failed, DesiredState::Running)]),
            "a crashed task is the restart supervisor's, not ours to duplicate"
        );
        assert!(
            occupied(&[task(TaskState::Ready, DesiredState::Ready)]),
            "created-not-started is still a task the cluster wants there"
        );
        assert!(
            !occupied(&[task(TaskState::Running, DesiredState::Shutdown)]),
            "a task this loop shut down leaves the node free to be filled again"
        );
        assert!(!occupied(&[task(
            TaskState::Shutdown,
            DesiredState::Shutdown
        )]));
        // History plus a live task: occupied.
        assert!(occupied(&[
            task(TaskState::Shutdown, DesiredState::Shutdown),
            task(TaskState::Running, DesiredState::Running),
        ]));
    }
}
