// SPDX-License-Identifier: BSD-2-Clause
//! Task status reporting: coalescing on both ends, and the manager's store
//! write (architecture §7.1, §7.2; SWK §13.3, §14.5).
//!
//! One queue type serves both sides, because both sides need the same three
//! properties and getting them subtly different is how a status regression
//! reaches the store:
//!
//! - **one pending status per task** — newer overwrites older;
//! - **regressions are dropped**, never queued (observed state is a Lamport
//!   clock, architecture §4 rule 1);
//! - a failed send **re-inserts** what it took, but only if nothing newer
//!   arrived meanwhile.
//!
//! The store write ([`StatusWriter`]) is the manager's half: it refuses
//! backward transitions, stamps `applied_by`/`applied_at` from the
//! **manager's** clock — agent clocks are not trusted, and restart windows
//! and history ordering are computed from these stamps — and retries the
//! optimistic-concurrency race a bounded number of times.

use std::collections::BTreeMap;
use std::time::SystemTime;

use satl_cluster::{ClusterStore, ProposalRejection, ProposeError};
use satl_core::{Id, StoreAction, StoreObject, TaskState, TaskStatus};

/// How many times a status write is retried after a sequence conflict before
/// it is dropped (the next transition carries the same information, and the
/// agent re-reports everything at its next registration).
pub const MAX_WRITE_ATTEMPTS: u32 = 5;

/// Whether `proposed` may replace `current` as a task's observed state.
///
/// Equality is accepted: agents re-report the same state on retries and after
/// a restart, and those writes still carry fresh messages, errors and
/// container status.
#[must_use]
pub fn accepts(current: TaskState, proposed: TaskState) -> bool {
    proposed >= current
}

/// A coalescing set of pending status updates, keyed by task.
#[derive(Debug, Default)]
pub struct StatusQueue {
    pending: BTreeMap<Id, TaskStatus>,
}

impl StatusQueue {
    /// An empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a status, dropping it if it regresses what is already pending.
    ///
    /// Returns whether it was accepted.
    pub fn push(&mut self, task_id: &Id, status: TaskStatus) -> bool {
        match self.pending.get(task_id) {
            Some(pending) if !accepts(pending.state, status.state) => {
                tracing::debug!(
                    task_id = %task_id,
                    pending = %pending.state,
                    dropped = %status.state,
                    "dropping a status that regresses the one already queued"
                );
                false
            }
            _ => {
                self.pending.insert(task_id.clone(), status);
                true
            }
        }
    }

    /// Takes up to `max` updates out of the queue.
    pub fn take(&mut self, max: usize) -> Vec<(Id, TaskStatus)> {
        if max == 0 {
            return Vec::new();
        }
        let ids: Vec<Id> = self.pending.keys().take(max).cloned().collect();
        ids.into_iter()
            .filter_map(|id| self.pending.remove_entry(&id))
            .collect()
    }

    /// Takes everything.
    pub fn drain(&mut self) -> Vec<(Id, TaskStatus)> {
        std::mem::take(&mut self.pending).into_iter().collect()
    }

    /// Puts a failed batch back, keeping anything newer that arrived while it
    /// was in flight (SWK §14.5).
    pub fn requeue(&mut self, batch: Vec<(Id, TaskStatus)>) {
        for (id, status) in batch {
            match self.pending.get(&id) {
                // Something newer (or equally new) landed while we were
                // sending: it supersedes what we failed to deliver.
                Some(newer) if newer.state >= status.state => {}
                _ => {
                    self.pending.insert(id, status);
                }
            }
        }
    }

    /// How many tasks have a pending status.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// What a status write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOutcome {
    /// Written into the store.
    Applied,
    /// The task is gone; the manager no longer cares (SWK §14.5 treats a
    /// `NotFound` as success — the dispatcher will tell the agent to release
    /// it).
    Unknown,
    /// The status carried nothing new.
    Unchanged,
    /// The status would move the observed state backwards.
    Regression {
        /// The state in the store.
        from: TaskState,
        /// The state that was proposed.
        to: TaskState,
    },
    /// The write kept losing the optimistic-concurrency race, or Raft refused
    /// it. Not fatal: the agent's local DB holds the canonical copy and
    /// re-reports at the next registration.
    Failed,
}

/// Writes agent-reported task status into the cluster store.
///
/// This is the manager half of the status path and the piece `satld`'s M1
/// `StoreReporter` becomes: same rules, now reached over the dispatcher
/// instead of in-process.
#[derive(Clone)]
pub struct StatusWriter {
    store: ClusterStore,
    manager_id: Id,
}

impl std::fmt::Debug for StatusWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusWriter")
            .field("manager_id", &self.manager_id)
            .finish_non_exhaustive()
    }
}

impl StatusWriter {
    /// A writer stamping `manager_id` as the manager that applied each
    /// status.
    #[must_use]
    pub fn new(store: ClusterStore, manager_id: Id) -> Self {
        Self { store, manager_id }
    }

    /// The node this writer stamps as `applied_by`.
    #[must_use]
    pub fn manager_id(&self) -> &Id {
        &self.manager_id
    }

    /// Applies one status, retrying the sequence-conflict race.
    #[tracing::instrument(skip_all, fields(task_id = %task_id, state = %status.state))]
    pub async fn apply(&self, task_id: &Id, status: &TaskStatus) -> StatusOutcome {
        for attempt in 1..=MAX_WRITE_ATTEMPTS {
            match self.attempt(task_id, status).await {
                Ok(outcome) => return outcome,
                Err(ProposeError::Rejected(ProposalRejection::SequenceConflict { .. })) => {
                    tracing::debug!(
                        attempt,
                        "sequence conflict writing task status; re-reading and re-deciding"
                    );
                }
                Err(ProposeError::Rejected(ProposalRejection::NotFound { .. })) => {
                    return StatusOutcome::Unknown;
                }
                Err(error) => {
                    // NotLeader means we stopped being the dispatcher; a raft
                    // error means the node is going down. Either way the
                    // agent's local DB is canonical and will re-report.
                    tracing::warn!(%error, "cannot write task status to the cluster store");
                    return StatusOutcome::Failed;
                }
            }
        }
        tracing::warn!(
            attempts = MAX_WRITE_ATTEMPTS,
            "gave up writing task status after repeated sequence conflicts"
        );
        StatusOutcome::Failed
    }

    async fn attempt(
        &self,
        task_id: &Id,
        status: &TaskStatus,
    ) -> Result<StatusOutcome, ProposeError> {
        // Scope the view: its guard is !Send and must not cross an await.
        let current = {
            let view = self.store.view();
            view.task(task_id).map(|task| (*task).clone())
        };
        let Some(mut task) = current else {
            tracing::debug!("task is gone from the store; status dropped");
            return Ok(StatusOutcome::Unknown);
        };

        if !accepts(task.status.state, status.state) {
            tracing::error!(
                service_id = ?task.service_id,
                from = %task.status.state,
                to = %status.state,
                "refusing a backward task status transition; status dropped"
            );
            return Ok(StatusOutcome::Regression {
                from: task.status.state,
                to: status.state,
            });
        }

        let unchanged = task.status.state == status.state
            && task.status.message == status.message
            && task.status.err == status.err
            && task.status.container == status.container
            && task.status.port_status == status.port_status;
        if unchanged {
            tracing::trace!("status unchanged; not proposing");
            return Ok(StatusOutcome::Unchanged);
        }

        let from = task.status.state;
        let now = SystemTime::now();
        let mut next = status.clone();
        next.applied_by = Some(self.manager_id.clone());
        next.applied_at = Some(now);
        task.status = next;
        task.meta.updated_at = now;

        let version = self
            .store
            .propose(vec![StoreAction::Update(StoreObject::Task(task))])
            .await?;
        tracing::info!(
            from = %from,
            to = %status.state,
            version = version.0,
            message = %status.message,
            "task status applied to the cluster store"
        );
        Ok(StatusOutcome::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use satl_core::DesiredState;

    fn status(state: TaskState, message: &str) -> TaskStatus {
        TaskStatus::new(state, message)
    }

    #[test]
    fn progress_and_re_reports_are_accepted_every_regression_is_refused() {
        for (index, current) in testing::OBSERVABLE_STATES.iter().enumerate() {
            for proposed in &testing::OBSERVABLE_STATES[index..] {
                assert!(accepts(*current, *proposed), "{current} -> {proposed}");
            }
            for proposed in &testing::OBSERVABLE_STATES[..index] {
                assert!(!accepts(*current, *proposed), "{current} -> {proposed}");
            }
        }
    }

    #[test]
    fn the_queue_keeps_one_status_per_task_newest_wins() {
        let mut queue = StatusQueue::new();
        let task = Id::generate();
        assert!(queue.push(&task, status(TaskState::Preparing, "preparing")));
        assert!(queue.push(&task, status(TaskState::Running, "started")));
        assert_eq!(queue.len(), 1);
        let batch = queue.drain();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].1.state, TaskState::Running);
        assert!(queue.is_empty());
    }

    #[test]
    fn a_regression_never_displaces_a_newer_pending_status() {
        let mut queue = StatusQueue::new();
        let task = Id::generate();
        queue.push(&task, status(TaskState::Running, "started"));
        assert!(!queue.push(&task, status(TaskState::Preparing, "stale")));
        assert_eq!(queue.drain()[0].1.state, TaskState::Running);
    }

    #[test]
    fn take_bounds_the_batch_and_leaves_the_rest() {
        let mut queue = StatusQueue::new();
        for _ in 0..10 {
            queue.push(&Id::generate(), status(TaskState::Running, "started"));
        }
        assert_eq!(queue.take(4).len(), 4);
        assert_eq!(queue.len(), 6);
        assert!(queue.take(0).is_empty());
        assert_eq!(queue.take(100).len(), 6);
        assert!(queue.is_empty());
    }

    #[test]
    fn a_failed_batch_is_requeued_unless_something_newer_arrived() {
        let mut queue = StatusQueue::new();
        let stale = Id::generate();
        let overtaken = Id::generate();
        queue.push(&stale, status(TaskState::Preparing, "preparing"));
        queue.push(&overtaken, status(TaskState::Preparing, "preparing"));
        let batch = queue.drain();

        // While the batch was in flight, one task moved on.
        queue.push(&overtaken, status(TaskState::Running, "started"));
        queue.requeue(batch);

        let mut states: BTreeMap<Id, TaskState> = BTreeMap::new();
        for (id, status) in queue.drain() {
            states.insert(id, status.state);
        }
        assert_eq!(states[&stale], TaskState::Preparing, "re-inserted");
        assert_eq!(
            states[&overtaken],
            TaskState::Running,
            "the newer status wins over the redelivery"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_status_write_stamps_the_manager_clock_and_identity() {
        let cluster = testing::TestCluster::start().await;
        let node = cluster.node_id().clone();
        let task = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        let task_id = task.id.clone();
        cluster.create(StoreObject::Task(task)).await;

        let writer = StatusWriter::new(cluster.store().clone(), node.clone());
        let outcome = writer
            .apply(&task_id, &status(TaskState::Running, "started"))
            .await;
        assert_eq!(outcome, StatusOutcome::Applied);

        let stored = {
            let view = cluster.store().view();
            (*view.task(&task_id).expect("task")).clone()
        };
        assert_eq!(stored.status.state, TaskState::Running);
        assert_eq!(stored.status.applied_by, Some(node));
        assert!(
            stored.status.applied_at.is_some(),
            "history ordering must not depend on agent clocks"
        );
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_store_write_refuses_a_backward_transition() {
        let cluster = testing::TestCluster::start().await;
        let node = cluster.node_id().clone();
        let task = testing::task_on(Some(&node), TaskState::Running, DesiredState::Running);
        let task_id = task.id.clone();
        cluster.create(StoreObject::Task(task)).await;

        let writer = StatusWriter::new(cluster.store().clone(), node);
        let outcome = writer
            .apply(&task_id, &status(TaskState::Preparing, "rewind"))
            .await;
        assert_eq!(
            outcome,
            StatusOutcome::Regression {
                from: TaskState::Running,
                to: TaskState::Preparing
            }
        );
        let stored = {
            let view = cluster.store().view();
            (*view.task(&task_id).expect("task")).clone()
        };
        assert_eq!(stored.status.state, TaskState::Running);
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_status_for_a_deleted_task_is_not_an_error() {
        let cluster = testing::TestCluster::start().await;
        let writer = StatusWriter::new(cluster.store().clone(), cluster.node_id().clone());
        let outcome = writer
            .apply(&Id::generate(), &status(TaskState::Running, "started"))
            .await;
        assert_eq!(outcome, StatusOutcome::Unknown);
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_identical_re_report_does_not_touch_the_store() {
        let cluster = testing::TestCluster::start().await;
        let node = cluster.node_id().clone();
        let task = testing::task_on(Some(&node), TaskState::Assigned, DesiredState::Running);
        let task_id = task.id.clone();
        cluster.create(StoreObject::Task(task)).await;

        let writer = StatusWriter::new(cluster.store().clone(), node);
        let reported = status(TaskState::Running, "started");
        assert_eq!(
            writer.apply(&task_id, &reported).await,
            StatusOutcome::Applied
        );
        let version = {
            let view = cluster.store().view();
            view.task(&task_id).expect("task").meta.version
        };
        assert_eq!(
            writer.apply(&task_id, &reported).await,
            StatusOutcome::Unchanged
        );
        let after = {
            let view = cluster.store().view();
            view.task(&task_id).expect("task").meta.version
        };
        assert_eq!(version, after, "a redelivery must not churn the raft log");
        cluster.shutdown().await;
    }
}
