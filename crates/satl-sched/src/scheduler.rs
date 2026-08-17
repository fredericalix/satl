// SPDX-License-Identifier: BSD-2-Clause
//! The scheduler loop: `PENDING` tasks in, `ASSIGNED` tasks out (SWK §8).
//!
//! Shape follows SwarmKit:
//!
//! - an **in-memory mirror** of the schedulable tasks and of every node
//!   ([`NodeInfo`]), fed by the store watch feed — the hot path never reads
//!   the store (SWK §8);
//! - **intake** (SWK §8.1): a task is tracked from `PENDING` up to `RUNNING`;
//!   with no node bound it joins the scheduling queue, with a node already
//!   bound (global services) it joins the preassigned queue (§8.6), and past
//!   `PENDING` it is bookkeeping only — its reservations, host ports and
//!   replica count against the node it runs on. Entering `FAILED`/`REJECTED`
//!   records a fault against `(node, service, spec version)` unless the task
//!   was preassigned, since the scheduler did not choose that node;
//! - **batching** (SWK §8.2): a commit starts or resets a
//!   [`SCHEDULER_DEBOUNCE`](satl_core::defaults::SCHEDULER_DEBOUNCE) (50 ms)
//!   timer, a batch never waits longer than
//!   [`SCHEDULER_DEBOUNCE_MAX`](satl_core::defaults::SCHEDULER_DEBOUNCE_MAX)
//!   (1 s), and tasks are grouped by `(service, spec version)` so the node
//!   ranking is computed once per group;
//! - a **filter pipeline** (SWK §8.3, [`crate::filters`]) whose failure counts
//!   produce the `"no suitable node (…)"` message written to
//!   `Task.Status.Err`, then **ranking and round-robin placement**
//!   (SWK §8.4, [`crate::placement`]);
//! - **preassigned tasks first** every pass (SWK §8.6);
//! - **unschedulable tasks** (SWK §8.8): a task whose service is gone is
//!   forgotten, one that belongs to an outdated revision and is already meant
//!   to stop is moved to `SHUTDOWN`, anything else keeps its explanation and
//!   is retried next tick. A queued task that is already meant to stop is
//!   never placed at all — see [`SchedulerLoop::abandon`];
//! - **committing** (SWK §8.9): one task per proposal; a decision taken
//!   against a task or node version that moved underneath is abandoned and
//!   the task is re-queued for the next tick.
//!
//! Not implemented, deliberately: placement preferences and their topology
//! decision tree (SWK §8.5) — deferred by architecture §14, so the ranked
//! node list here is SwarmKit's single-leaf case.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_cluster::{ClusterStore, ProposeError};
use satl_core::{
    DesiredState, Id, Node, ObjectKind, StoreAction, StoreEvent, StoreObject, Task, TaskState,
    TaskStatus,
};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::filters::Pipeline;
use crate::node_info::{
    NodeInfo, TaskGroup, is_abandoned, is_pending_preassigned, is_queued, is_tracked,
};
use crate::placement;

/// Status message SwarmKit writes when a task is assigned (SWK §8.4).
const ASSIGNED_MESSAGE: &str = "scheduler assigned task to node";

/// Status message for a validated preassigned task (SWK §8.6).
const PREASSIGNED_MESSAGE: &str = "scheduler confirmed task can run on preassigned node";

/// Status message when the scheduler stops a task of a superseded revision
/// instead of placing it (SWK §8.8).
const OUTDATED_MESSAGE: &str = "scheduler shut down a task of an outdated service revision";

/// What to do with a task no node accepted (SWK §8.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unschedulable {
    /// The service is gone: drop the task from the scheduler.
    Forget,
    /// Outdated revision, already meant to stop: shut it down here.
    Shutdown,
    /// Record the explanation and try again next tick.
    Retry,
}

/// Assigns pending tasks to nodes.
pub(crate) struct SchedulerLoop {
    store: ClusterStore,
    /// Quiet time before a batch is scheduled.
    debounce: Duration,
    /// Longest a batch may be delayed by repeated commits.
    max_debounce: Duration,
    /// Mirror: every node with its bookkeeping, by ID.
    nodes: BTreeMap<Id, NodeInfo>,
    /// Mirror: every task the scheduler tracks (SWK §8.1), by ID.
    all_tasks: BTreeMap<Id, Arc<Task>>,
    /// Mirror: the tasks waiting for a node, by ID.
    queue: BTreeMap<Id, Arc<Task>>,
    /// Mirror: tasks that arrived with a node already chosen and still need
    /// validating against it (SWK §8.6).
    pending_preassigned: BTreeMap<Id, Arc<Task>>,
    /// Tasks that were ever preassigned, including those past `PENDING`:
    /// their failures are not held against the node (SWK §8.1).
    preassigned: BTreeSet<Id>,
    /// When the current batch runs (debounce), and the deadline it may not
    /// slip past (SWK §8.2).
    due: Option<Instant>,
    limit: Option<Instant>,
}

impl SchedulerLoop {
    pub(crate) fn new(store: ClusterStore, debounce: Duration, max_debounce: Duration) -> Self {
        Self {
            store,
            debounce,
            max_debounce,
            nodes: BTreeMap::new(),
            all_tasks: BTreeMap::new(),
            queue: BTreeMap::new(),
            pending_preassigned: BTreeMap::new(),
            preassigned: BTreeSet::new(),
            due: None,
            limit: None,
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("scheduler");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(
            async move {
                let mut events = self.store.watch();
                self.resync();
                // Anything already queued at startup is scheduled straight away
                // (leader change, satld restart) rather than waiting for the next
                // commit to wake the loop.
                self.arm();
                loop {
                    let due = self.due;
                    let batch_due = async move {
                        match due {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => break,
                        () = batch_due => self.schedule_batch().await,
                        event = events.recv() => match event {
                            Ok(event) => self.observe(event),
                            Err(RecvError::Lagged(missed)) => {
                                tracing::warn!(missed, "watch feed lagged; re-syncing the mirror");
                                self.resync();
                                self.arm();
                            }
                            Err(RecvError::Closed) => break,
                        },
                    }
                }
                tracing::debug!("scheduler stopped");
            }
            .instrument(span),
        )
        .await;
    }

    /// Rebuilds the mirror from a store read (startup, lagged watcher).
    ///
    /// Failure history is not store state — it is the scheduler's own memory
    /// of what happened on each node — so it is carried across the rebuild.
    fn resync(&mut self) {
        let now = SystemTime::now();
        let mut failures: BTreeMap<Id, _> = self
            .nodes
            .iter_mut()
            .map(|(id, info)| (id.clone(), info.take_failures()))
            .collect();

        let (nodes, tasks) = {
            let view = self.store.view();
            (view.nodes(), view.tasks())
        };

        self.nodes = nodes
            .into_iter()
            .map(|node| {
                let id = node.id.clone();
                let mut info = NodeInfo::new(node, now);
                if let Some(log) = failures.remove(&id) {
                    info.restore_failures(log);
                }
                (id, info)
            })
            .collect();
        self.all_tasks.clear();
        self.queue.clear();
        self.pending_preassigned.clear();
        self.preassigned.clear();

        for task in tasks {
            // Unassigned tasks that are already meant to stop belong to the
            // orchestrator (they appear when a service is updated, scaled
            // down or deleted before its tasks were placed) — SWK §8.1.
            if !is_tracked(&task) || is_abandoned(&task) {
                continue;
            }
            self.all_tasks.insert(task.id.clone(), Arc::clone(&task));
            if task.node_id.is_none() {
                self.queue.insert(task.id.clone(), task);
            } else if task.status.state == TaskState::Pending {
                self.preassigned.insert(task.id.clone());
                self.pending_preassigned.insert(task.id.clone(), task);
            } else {
                self.count_on_node(&task);
            }
        }

        tracing::debug!(
            nodes = self.nodes.len(),
            queued = self.queue.len(),
            preassigned = self.pending_preassigned.len(),
            tracked = self.all_tasks.len(),
            "scheduler mirror synced"
        );
    }

    /// Applies one watch event to the mirror.
    fn observe(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => match object {
                StoreObject::Node(node) => self.create_or_update_node(node),
                StoreObject::Task(task) => self.update_task(Arc::new(task)),
                _ => {}
            },
            StoreEvent::Removed { kind, id } => match kind {
                ObjectKind::Node => {
                    self.nodes.remove(&id);
                }
                ObjectKind::Task => {
                    // Deleting a task frees its reservations for the queue.
                    self.forget_task(&id);
                }
                _ => {}
            },
            // Scheduling runs on commits, debounced (SWK §8.2).
            StoreEvent::Commit(_) => self.arm(),
        }
    }

    /// Node created or updated: refresh the object, keep the bookkeeping.
    fn create_or_update_node(&mut self, node: Node) {
        let node = Arc::new(node);
        if let Some(info) = self.nodes.get_mut(&node.id) {
            info.set_node(node);
            return;
        }
        let mut info = NodeInfo::new(Arc::clone(&node), SystemTime::now());
        // A node object can show up after the tasks bound to it (snapshot
        // install, a manager rejoining): count what we already know.
        for task in self.all_tasks.values() {
            if task.node_id.as_ref() == Some(&node.id) && task.status.state > TaskState::Pending {
                info.add_task(task);
            }
        }
        self.nodes.insert(node.id.clone(), info);
    }

    /// Task created or updated: intake (SWK §8.1).
    fn update_task(&mut self, task: Arc<Task>) {
        if task.status.state < TaskState::Pending {
            return;
        }
        let old = self.all_tasks.get(&task.id).cloned();

        if task.status.state > TaskState::Running {
            // The task stopped consuming resources. Note the fault first: it
            // steers this service away from a node it keeps dying on.
            if let Some(old) = old {
                if old.status.state != task.status.state {
                    self.record_failure(&task);
                }
                self.forget_task(&task.id);
            }
            return;
        }

        if task.node_id.is_none() {
            self.forget_task(&task.id);
            self.all_tasks.insert(task.id.clone(), Arc::clone(&task));
            self.queue.insert(task.id.clone(), task);
            return;
        }

        if task.status.state == TaskState::Pending {
            // Preassigned: validated against its node before the queue every
            // pass, and not counted against the node until it is (SWK §8.6).
            self.forget_task(&task.id);
            self.preassigned.insert(task.id.clone());
            self.all_tasks.insert(task.id.clone(), Arc::clone(&task));
            self.pending_preassigned.insert(task.id.clone(), task);
            return;
        }

        self.queue.remove(&task.id);
        self.pending_preassigned.remove(&task.id);
        self.all_tasks.insert(task.id.clone(), Arc::clone(&task));
        self.count_on_node(&task);
    }

    /// Records a `FAILED`/`REJECTED` observation against the node that ran
    /// the task (SWK §8.1). Preassigned tasks are exempt: the scheduler did
    /// not choose their node, so penalising it would be meaningless.
    fn record_failure(&mut self, task: &Task) {
        if !matches!(task.status.state, TaskState::Failed | TaskState::Rejected)
            || self.preassigned.contains(&task.id)
        {
            return;
        }
        let Some(node_id) = task.node_id.as_ref() else {
            return;
        };
        let Some(info) = self.nodes.get_mut(node_id) else {
            return;
        };
        let group = TaskGroup::of(task);
        info.record_failure(group.clone(), SystemTime::now());
        let failures = info.recent_failures(&group, SystemTime::now());
        tracing::debug!(
            task_id = %task.id,
            service_id = ?task.service_id,
            node_id = %node_id,
            state = %task.status.state,
            failures,
            "recorded a task failure against the node"
        );
        if failures == crate::node_info::MAX_FAILURES {
            tracing::warn!(
                node_id = %node_id,
                service_id = ?task.service_id,
                failures,
                "underweighting node: repeated failures of this service revision"
            );
        }
    }

    /// Drops a task from every mirror, releasing what it held on its node.
    fn forget_task(&mut self, task_id: &Id) {
        self.queue.remove(task_id);
        self.pending_preassigned.remove(task_id);
        self.preassigned.remove(task_id);
        let Some(task) = self.all_tasks.remove(task_id) else {
            return;
        };
        if let Some(info) = task
            .node_id
            .as_ref()
            .and_then(|node_id| self.nodes.get_mut(node_id))
        {
            info.remove_task(task_id);
        }
    }

    /// Counts a bound task against its node.
    fn count_on_node(&mut self, task: &Arc<Task>) {
        if let Some(info) = task
            .node_id
            .as_ref()
            .and_then(|node_id| self.nodes.get_mut(node_id))
        {
            info.add_task(task);
        }
    }

    /// Starts or extends the batching window.
    fn arm(&mut self) {
        if self.queue.is_empty() && self.pending_preassigned.is_empty() {
            return;
        }
        let now = Instant::now();
        let limit = *self.limit.get_or_insert(now + self.max_debounce);
        self.due = Some((now + self.debounce).min(limit));
    }

    /// Schedules everything currently queued.
    async fn schedule_batch(&mut self) {
        self.due = None;
        self.limit = None;
        // Preassigned tasks first: a global service must get its node before
        // replicated tasks eat the room on it (SWK §8.6).
        if !self.pending_preassigned.is_empty() {
            self.process_preassigned().await;
        }
        self.tick().await;
        // Whatever stayed queued (unschedulable, or a lost race) is retried
        // on the next tick (SWK §8.8) — a node coming back also wakes the
        // loop through its own commit.
        if !(self.queue.is_empty() && self.pending_preassigned.is_empty()) && self.due.is_none() {
            self.due = Some(Instant::now() + self.max_debounce);
        }
    }

    /// Validates every preassigned task against the node it already carries
    /// (SWK §8.6).
    async fn process_preassigned(&mut self) {
        let tasks: Vec<Arc<Task>> = self.pending_preassigned.values().cloned().collect();
        let mut pipeline = Pipeline::new();
        for task in tasks {
            let Some(node_id) = task.node_id.clone() else {
                continue;
            };
            if is_abandoned(&task) {
                // Already meant to stop: not a placement candidate, however
                // firmly the orchestrator pinned it to a node.
                self.abandon(&task).await;
                continue;
            }
            pipeline.set_task(&task);
            match placement::fits_on_node(&self.nodes, &node_id, &mut pipeline) {
                // The node is gone from the mirror: nothing to decide yet.
                None => {}
                Some(true) => self.confirm_preassigned(&task, &node_id).await,
                Some(false) => {
                    let explanation = pipeline.explain();
                    self.record_error(&task, explanation, "preassigned node refused the task")
                        .await;
                }
            }
        }
    }

    /// Moves a validated preassigned task to `ASSIGNED` (SWK §8.6).
    async fn confirm_preassigned(&mut self, task: &Arc<Task>, node_id: &Id) {
        if !self.node_is_current(node_id) {
            return;
        }
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.add_task(task);
        }
        let mut next = (**task).clone();
        next.status = TaskStatus::new(TaskState::Assigned, PREASSIGNED_MESSAGE);
        next.meta.updated_at = SystemTime::now();
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            node_id = %node_id,
            from = %task.status.state,
            to = %TaskState::Assigned,
            "scheduler confirmed task can run on preassigned node"
        );
        if self.commit(task, next, "confirm preassigned task").await {
            self.pending_preassigned.remove(&task.id);
        } else if let Some(info) = self.nodes.get_mut(node_id) {
            info.remove_task(&task.id);
        }
    }

    /// Schedules the queue: group by `(service, spec version)`, then place
    /// each group (SWK §8.2).
    async fn tick(&mut self) {
        let mut groups: BTreeMap<TaskGroup, Vec<Arc<Task>>> = BTreeMap::new();
        let mut one_offs: Vec<Arc<Task>> = Vec::new();
        let mut abandoned: Vec<Arc<Task>> = Vec::new();
        for task in std::mem::take(&mut self.queue).into_values() {
            if task.node_id.is_some() {
                continue;
            }
            if is_abandoned(&task) {
                abandoned.push(task);
            } else if task.spec_version.is_some() {
                groups.entry(TaskGroup::of(&task)).or_default().push(task);
            } else {
                // No spec version to group by: schedule it on its own.
                one_offs.push(task);
            }
        }
        for task in abandoned {
            self.abandon(&task).await;
        }
        for group in groups.into_values() {
            self.schedule_group(group).await;
        }
        for task in one_offs {
            self.schedule_group(vec![task]).await;
        }
    }

    /// A task that was never placed and is already meant to stop is not a
    /// placement candidate — starting it would mean starting a container the
    /// cluster has already given up on (a scale-down or a deleted service
    /// between task creation and scheduling). SwarmKit drops these when it
    /// rebuilds its mirror (SWK §8.1, `setupTasksList`); SatL applies the
    /// same rule to tasks that reach that state while queued, and runs them
    /// through the unschedulable verdict (SWK §8.8) so an outdated revision
    /// still gets its terminal `SHUTDOWN` record.
    async fn abandon(&mut self, task: &Arc<Task>) {
        match self.verdict(task) {
            Unschedulable::Shutdown => self.shutdown_outdated(task).await,
            Unschedulable::Forget | Unschedulable::Retry => {
                tracing::debug!(
                    task_id = %task.id,
                    service_id = ?task.service_id,
                    desired = %task.desired_state,
                    "task is desired stopped before it was ever placed; \
                     leaving it to the reaper"
                );
                self.forget_task(&task.id);
            }
        }
    }

    /// Ranks the nodes once for a group of interchangeable tasks and places
    /// them round-robin (SWK §8.4).
    async fn schedule_group(&mut self, group: Vec<Arc<Task>>) {
        let mut pipeline = Pipeline::new();
        let (assignments, leftovers) =
            placement::place_group(&mut self.nodes, &group, &mut pipeline, SystemTime::now());
        for assignment in assignments {
            self.assign(&assignment.task, &assignment.node_id).await;
        }
        if !leftovers.is_empty() {
            let explanation = pipeline.explain();
            self.no_suitable_node(leftovers, &explanation).await;
        }
    }

    /// Binds `task` to `node_id` (SWK §8.9: one task per proposal).
    async fn assign(&mut self, task: &Arc<Task>, node_id: &Id) {
        if !self.node_is_current(node_id) {
            // The node object moved under the decision: the ranking it was
            // based on is stale, so drop the decision and decide again.
            tracing::debug!(task_id = %task.id, node_id = %node_id, "node changed mid-batch; re-queueing");
            self.roll_back(task, node_id);
            return;
        }
        let mut next = (**task).clone();
        next.node_id = Some(node_id.clone());
        next.status = TaskStatus::new(TaskState::Assigned, ASSIGNED_MESSAGE);
        next.meta.updated_at = SystemTime::now();
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            slot = task.slot,
            node_id = %node_id,
            from = %task.status.state,
            to = %TaskState::Assigned,
            "scheduler assigned task to node"
        );
        if !self.commit(task, next, "assign task").await {
            self.roll_back(task, node_id);
        }
    }

    /// Undoes the batch-local bookkeeping of a decision that was not
    /// committed, and puts the task back in the queue.
    fn roll_back(&mut self, task: &Arc<Task>, node_id: &Id) {
        if let Some(info) = self.nodes.get_mut(node_id) {
            info.remove_task(&task.id);
        }
        self.requeue(&task.id);
    }

    /// Whether the mirror's copy of a node is still the store's copy
    /// (SWK §8.9: a decision made against a stale node is abandoned).
    fn node_is_current(&self, node_id: &Id) -> bool {
        let Some(mirrored) = self.nodes.get(node_id).map(NodeInfo::version) else {
            return false;
        };
        let stored = self
            .store
            .view()
            .node(node_id)
            .map(|node| node.meta.version);
        stored == Some(mirrored)
    }

    /// Decides what happens to the tasks no node accepted (SWK §8.8).
    async fn no_suitable_node(&mut self, tasks: Vec<Arc<Task>>, explanation: &str) {
        for task in tasks {
            match self.verdict(&task) {
                Unschedulable::Forget => {
                    tracing::debug!(
                        task_id = %task.id,
                        service_id = ?task.service_id,
                        "service no longer exists; dropping the task from the scheduler"
                    );
                    self.forget_task(&task.id);
                }
                Unschedulable::Shutdown => self.shutdown_outdated(&task).await,
                Unschedulable::Retry => {
                    let message = format!("no suitable node ({explanation})");
                    self.record_error(&task, message, "no suitable node available for task")
                        .await;
                }
            }
        }
    }

    /// Classifies an unschedulable task (SWK §8.8).
    ///
    /// "Outdated" compares the task's `spec_version` against the service's
    /// object version, since SatL has no separate `Service.spec_version`
    /// field (SwarmKit does). Any write to the service — an endpoint
    /// allocation, an update-status change — therefore makes older tasks look
    /// outdated. That is why the shutdown branch also requires the task to be
    /// desired-stopped and never placed: on its own, a version bump only
    /// ever means "keep explaining and retrying", never "stop this task".
    fn verdict(&self, task: &Task) -> Unschedulable {
        let Some(service_id) = task.service_id.as_ref() else {
            return Unschedulable::Retry;
        };
        let view = self.store.view();
        let Some(service) = view.service(service_id) else {
            return Unschedulable::Forget;
        };
        let outdated = task
            .spec_version
            .is_some_and(|version| version < service.meta.version);
        if outdated
            && task.status.state == TaskState::Pending
            && task.desired_state >= DesiredState::Shutdown
        {
            Unschedulable::Shutdown
        } else {
            Unschedulable::Retry
        }
    }

    /// A task of a superseded revision that is already meant to stop is never
    /// going to run: the scheduler completes its shutdown itself (SWK §8.8).
    async fn shutdown_outdated(&mut self, task: &Arc<Task>) {
        let mut next = (**task).clone();
        next.status = TaskStatus::new(TaskState::Shutdown, OUTDATED_MESSAGE);
        next.meta.updated_at = SystemTime::now();
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            slot = task.slot,
            from = %task.status.state,
            to = %TaskState::Shutdown,
            "task belongs to an outdated service revision and is desired shutdown"
        );
        if self.commit(task, next, "shut down outdated task").await {
            self.forget_task(&task.id);
        }
    }

    /// Records why a task could not be placed and keeps it queued for the
    /// next tick (SWK §8.8).
    async fn record_error(&mut self, task: &Arc<Task>, message: String, what: &'static str) {
        // Re-queue first: the task is retried whether or not the store write
        // below is needed or succeeds.
        self.requeue_object(task);
        if task.status.err.as_deref() == Some(message.as_str()) {
            // Already recorded — writing it again would only churn the store
            // and wake every watcher.
            return;
        }
        let mut next = (**task).clone();
        next.status.err = Some(message.clone());
        next.status.timestamp = SystemTime::now();
        next.meta.updated_at = SystemTime::now();
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            slot = task.slot,
            reason = %message,
            what,
            "task unschedulable"
        );
        self.commit(task, next, "record unschedulable task").await;
    }

    /// Proposes one task update. A rejection means the object moved under
    /// the decision: refresh the mirror entry and let the next tick decide
    /// again (SWK §8.9).
    async fn commit(&mut self, task: &Task, next: Task, what: &'static str) -> bool {
        match self
            .store
            .propose(vec![StoreAction::Update(StoreObject::Task(next))])
            .await
        {
            Ok(_) => true,
            Err(ProposeError::Rejected(rejection)) => {
                tracing::debug!(
                    task_id = %task.id,
                    what,
                    rejection = %rejection,
                    "decision raced another writer; re-queueing"
                );
                self.requeue(&task.id);
                false
            }
            Err(err) => {
                tracing::warn!(task_id = %task.id, what, error = %err, "scheduling deferred");
                self.requeue(&task.id);
                false
            }
        }
    }

    /// Refreshes one task in the mirror from the store and re-arms the batch.
    fn requeue(&mut self, task_id: &Id) {
        let refreshed = self.store.view().task(task_id);
        if let Some(task) = refreshed {
            self.requeue_object(&task);
        } else {
            self.forget_task(task_id);
            self.arm();
        }
    }

    /// Puts a task back on the queue it belongs to and re-arms the batch.
    fn requeue_object(&mut self, task: &Arc<Task>) {
        if is_queued(task) {
            self.all_tasks.insert(task.id.clone(), Arc::clone(task));
            self.queue.insert(task.id.clone(), Arc::clone(task));
        } else if is_pending_preassigned(task) {
            self.all_tasks.insert(task.id.clone(), Arc::clone(task));
            self.preassigned.insert(task.id.clone());
            self.pending_preassigned
                .insert(task.id.clone(), Arc::clone(task));
        } else {
            self.queue.remove(&task.id);
            self.pending_preassigned.remove(&task.id);
        }
        self.arm();
    }
}

#[cfg(test)]
mod tests {
    use satl_core::Version;

    use crate::testing::{planted_task, sample_service};

    use super::*;

    fn task(state: TaskState, desired: DesiredState, bound: bool) -> Task {
        let service = sample_service("web", 1);
        let mut task = planted_task(&service, 1, state, desired, SystemTime::now());
        if bound {
            task.node_id = Some(Id::generate());
        }
        task
    }

    #[test]
    fn intake_tracks_pending_through_running() {
        let cases = [
            (TaskState::New, false),
            (TaskState::Pending, true),
            (TaskState::Assigned, true),
            (TaskState::Running, true),
            (TaskState::Complete, false),
            (TaskState::Failed, false),
            (TaskState::Shutdown, false),
            (TaskState::Orphaned, false),
        ];
        for (state, expected) in cases {
            let task = task(state, DesiredState::Running, false);
            assert_eq!(is_tracked(&task), expected, "{state}");
        }
    }

    #[test]
    fn intake_splits_queued_from_preassigned() {
        // Unbound and pending: the general queue.
        let unbound = task(TaskState::Pending, DesiredState::Running, false);
        assert!(is_queued(&unbound));
        assert!(!is_pending_preassigned(&unbound));

        // "Prepare but don't start" still needs a node.
        let ready = task(TaskState::Pending, DesiredState::Ready, false);
        assert!(is_queued(&ready));

        // Bound and still pending: preassigned, validated against that node.
        let bound = task(TaskState::Pending, DesiredState::Running, true);
        assert!(!is_queued(&bound));
        assert!(is_pending_preassigned(&bound));

        // Bound and past pending: bookkeeping only.
        let assigned = task(TaskState::Assigned, DesiredState::Running, true);
        assert!(!is_queued(&assigned));
        assert!(!is_pending_preassigned(&assigned));
    }

    #[test]
    fn tasks_desired_stopped_before_placement_are_never_candidates() {
        // A task that was never placed and is already meant to stop belongs
        // to the orchestrator, not the scheduler (SWK §8.1).
        for desired in [DesiredState::Shutdown, DesiredState::Remove] {
            assert!(is_abandoned(&task(TaskState::Pending, desired, false)));
        }
        for desired in [
            DesiredState::Ready,
            DesiredState::Running,
            DesiredState::Complete,
        ] {
            assert!(!is_abandoned(&task(TaskState::Pending, desired, false)));
        }
        // Once it is running somewhere, a shutdown request is normal.
        assert!(!is_abandoned(&task(
            TaskState::Running,
            DesiredState::Shutdown,
            true
        )));
    }

    #[test]
    fn task_groups_key_on_service_and_spec_version() {
        let service = sample_service("web", 2);
        let now = SystemTime::now();
        let one = planted_task(&service, 1, TaskState::Pending, DesiredState::Running, now);
        let two = planted_task(&service, 2, TaskState::Pending, DesiredState::Running, now);
        assert_eq!(TaskGroup::of(&one), TaskGroup::of(&two));

        let mut updated = two.clone();
        updated.spec_version = Some(Version(999));
        assert_ne!(TaskGroup::of(&one), TaskGroup::of(&updated));

        let other = sample_service("api", 1);
        let elsewhere = planted_task(&other, 1, TaskState::Pending, DesiredState::Running, now);
        assert_ne!(TaskGroup::of(&one), TaskGroup::of(&elsewhere));
    }

    #[test]
    fn status_messages_match_swarmkit() {
        assert_eq!(ASSIGNED_MESSAGE, "scheduler assigned task to node");
        assert_eq!(
            PREASSIGNED_MESSAGE,
            "scheduler confirmed task can run on preassigned node"
        );
        // The states the loop writes never move backwards from `PENDING`,
        // so no decision can be rejected by the task state machine.
        assert!(TaskState::Assigned > TaskState::Pending);
        assert!(TaskState::Shutdown > TaskState::Pending);
    }
}
