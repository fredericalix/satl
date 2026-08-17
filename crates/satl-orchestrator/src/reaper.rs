// SPDX-License-Identifier: BSD-2-Clause
//! Task reaper (SWK §7.5): executes `REMOVE` and prunes slot history.
//!
//! Two jobs, both batched behind a
//! [`REAPER_BATCH`](satl_core::defaults::REAPER_BATCH) (250 ms) timer that is
//! forced when more than [`OrchestratorConfig::reaper_force_at`] items are
//! queued:
//!
//! - **deletion**: a task with desired state `REMOVE` is deleted once it is
//!   shut down (observed ≥ `COMPLETE`) or never ran (observed < `ASSIGNED`).
//!   Never before: deleting a task frees its jail, clones and epairs, and
//!   those must not be released while the jail might still run
//!   (architecture §4 rule 5).
//! - **history pruning**: terminated tasks are retained per slot up to
//!   [`TASK_HISTORY_LIMIT`](satl_core::defaults::TASK_HISTORY_LIMIT) (5),
//!   raised to `max_attempts + 1` for services with bounded restarts so the
//!   restart supervisor's history stays reconstructible (SWK §4.6). The
//!   oldest terminal tasks go first.
//!
//! [`OrchestratorConfig::reaper_force_at`]: crate::OrchestratorConfig::reaper_force_at

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use satl_cluster::{ClusterStore, StoreView};
use satl_core::defaults::{MAX_TX_ACTIONS, TASK_HISTORY_LIMIT};
use satl_core::{
    DesiredState, Id, ObjectKind, Service, StoreAction, StoreEvent, StoreObject, Task, TaskState,
};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::propose::propose_with_retry;
use crate::task::{SlotTuple, task_timestamp};

/// Identifies one slot's history — SwarmKit's `SlotTuple`, so a global
/// service's per-node histories are pruned separately (see
/// [`crate::task::SlotTuple`]).
type SlotKey = SlotTuple;

/// Deletes removed tasks and prunes per-slot history.
pub(crate) struct TaskReaper {
    store: ClusterStore,
    /// Batching window.
    batch: Duration,
    /// Queue size that forces an immediate flush.
    force_at: usize,
    /// Period of the full self-healing scan.
    interval: Duration,
    /// Slots whose history may have grown past the limit.
    dirty_slots: BTreeSet<SlotKey>,
    /// Tasks marked for removal, kept until they are actually deletable.
    candidates: BTreeSet<Id>,
    /// When the current batch is due.
    deadline: Option<Instant>,
}

impl TaskReaper {
    pub(crate) fn new(
        store: ClusterStore,
        batch: Duration,
        force_at: usize,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            batch,
            force_at,
            interval,
            dirty_slots: BTreeSet::new(),
            candidates: BTreeSet::new(),
            deadline: None,
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.reaper");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let deadline = self.deadline;
                let batch_due = async move {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    () = batch_due => self.flush().await,
                    _ = ticker.tick() => {
                        self.full_scan();
                        self.flush().await;
                    }
                    event = events.recv() => match event {
                        Ok(event) => self.observe(&event),
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full scan");
                            self.full_scan();
                            self.flush().await;
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("task reaper stopped");
        }
        .instrument(span))
        .await;
    }

    /// Queues work from one watch event and arms the batch timer.
    fn observe(&mut self, event: &StoreEvent) {
        match event {
            // Every task creation makes its slot's history one longer, and
            // every status or desired-state change can make a task deletable
            // or prunable.
            StoreEvent::Created(StoreObject::Task(task))
            | StoreEvent::Updated {
                new: StoreObject::Task(task),
                ..
            } => self.mark(task),
            StoreEvent::Removed {
                kind: ObjectKind::Task,
                id,
            } => {
                self.candidates.remove(id);
            }
            _ => {}
        }
        let queued = self.dirty_slots.len() + self.candidates.len();
        if queued == 0 {
            return;
        }
        if queued >= self.force_at {
            // Forced flush: fire on the next loop turn instead of waiting out
            // the batching window (SWK §7.5).
            self.deadline = Some(Instant::now());
        } else if self.deadline.is_none() {
            self.deadline = Some(Instant::now() + self.batch);
        }
    }

    /// Records a task as a deletion candidate and/or a dirty slot.
    fn mark(&mut self, task: &Task) {
        if task.desired_state == DesiredState::Remove {
            self.candidates.insert(task.id.clone());
        }
        if let Some(key) = SlotTuple::of(task) {
            self.dirty_slots.insert(key);
        }
    }

    /// Rebuilds the queues from store state (startup, lag, self-healing).
    fn full_scan(&mut self) {
        let tasks = self.store.view().tasks();
        for task in tasks {
            self.mark(&task);
        }
        if !self.dirty_slots.is_empty() || !self.candidates.is_empty() {
            self.deadline = Some(Instant::now());
        }
    }

    /// Commits one batch: deletions first, then history pruning.
    async fn flush(&mut self) {
        self.deadline = None;
        if self.dirty_slots.is_empty() && self.candidates.is_empty() {
            return;
        }
        let candidates: Vec<Id> = self.candidates.iter().cloned().collect();
        let slots: Vec<SlotKey> = std::mem::take(&mut self.dirty_slots).into_iter().collect();

        let mut truncated = false;
        let result = propose_with_retry(&self.store, "reap tasks", |view| {
            let mut actions = reap_actions(view, &candidates, &slots);
            truncated = actions.len() > MAX_TX_ACTIONS;
            actions.truncate(MAX_TX_ACTIONS);
            actions
        })
        .await;

        match result {
            Ok(_) => {
                // Candidates that are still not deletable (a running task
                // being shut down) stay queued; the store view is the
                // authority on what is gone.
                let view = self.store.view();
                self.candidates.retain(|id| view.task(id).is_some());
            }
            Err(err) => {
                tracing::warn!(error = %err, "task reaping deferred");
                // Put the slots back: their history is still over the limit.
                self.dirty_slots.extend(slots.iter().cloned());
            }
        }
        if truncated {
            self.dirty_slots.extend(slots);
            self.deadline = Some(Instant::now());
        }
    }
}

/// The deletions for one batch: executed removals first, then history
/// pruning of the dirty slots. Pure and idempotent.
fn reap_actions(view: &StoreView<'_>, candidates: &[Id], slots: &[SlotKey]) -> Vec<StoreAction> {
    let mut doomed: BTreeSet<Id> = BTreeSet::new();
    let mut actions = Vec::new();

    for id in candidates {
        let Some(task) = view.task(id) else { continue };
        if !is_deletable(&task) {
            continue;
        }
        tracing::info!(
            task_id = %task.id,
            service_id = ?task.service_id,
            slot = task.slot,
            state = %task.status.state,
            "deleting removed task"
        );
        doomed.insert(task.id.clone());
        actions.push(StoreAction::Remove {
            kind: ObjectKind::Task,
            id: task.id.clone(),
        });
    }

    // TODO(M2): a service→tasks index (architecture §6.1) turns this full
    // scan into a lookup.
    let mut by_slot: BTreeMap<SlotKey, Vec<Arc<Task>>> = BTreeMap::new();
    let wanted: BTreeSet<&SlotKey> = slots.iter().collect();
    for task in view.tasks() {
        let Some(key) = SlotTuple::of(&task) else {
            continue;
        };
        if wanted.contains(&key) && !doomed.contains(&task.id) {
            by_slot.entry(key).or_default().push(task);
        }
    }

    for (key, tasks) in by_slot {
        let SlotTuple {
            service_id, slot, ..
        } = &key;
        // A negative retention limit means "keep forever" (SWK §4.6).
        let Some(limit) = history_limit(view.service(service_id).as_deref()) else {
            continue;
        };
        let mut history: Vec<Arc<Task>> = tasks.into_iter().filter(|t| is_prunable(t)).collect();
        if history.len() <= limit {
            continue;
        }
        history.sort_by(|a, b| {
            task_timestamp(a)
                .cmp(&task_timestamp(b))
                .then(a.id.cmp(&b.id))
        });
        let excess = history.len() - limit;
        for task in history.into_iter().take(excess) {
            tracing::info!(
                task_id = %task.id,
                service_id = %service_id,
                slot,
                state = %task.status.state,
                limit,
                "pruning task history"
            );
            actions.push(StoreAction::Remove {
                kind: ObjectKind::Task,
                id: task.id.clone(),
            });
        }
    }
    actions
}

/// A task marked `REMOVE` may be deleted once it is shut down or once it is
/// certain it never ran (SWK §7.5).
fn is_deletable(task: &Task) -> bool {
    task.desired_state == DesiredState::Remove
        && (task.status.state >= TaskState::Complete || task.status.state < TaskState::Assigned)
}

/// Whether a task counts as slot history: terminated, or never going to run.
fn is_prunable(task: &Task) -> bool {
    task.status.state > TaskState::Running
        || (task.status.state < TaskState::Assigned && task.desired_state > DesiredState::Running)
}

/// Retained history per slot: the cluster-wide limit, raised to
/// `max_attempts + 1` for services with bounded restarts (SWK §4.6).
/// `None` means "keep forever".
fn history_limit(service: Option<&Service>) -> Option<usize> {
    let max_attempts = service.map_or(0, |s| s.spec.task.restart.max_attempts);
    if max_attempts > 0 {
        return usize::try_from(max_attempts.saturating_add(1)).ok();
    }
    usize::try_from(TASK_HISTORY_LIMIT).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use satl_core::RestartCondition;

    use crate::testing::{planted_task, sample_service, with_restart};

    use super::*;

    #[test]
    fn deletable_tasks_are_shut_down_or_never_started() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let cases = [
            (TaskState::New, DesiredState::Remove, true),
            (TaskState::Pending, DesiredState::Remove, true),
            // Assigned or later: the agent may hold a jail — wait for it.
            (TaskState::Assigned, DesiredState::Remove, false),
            (TaskState::Running, DesiredState::Remove, false),
            (TaskState::Complete, DesiredState::Remove, true),
            (TaskState::Shutdown, DesiredState::Remove, true),
            (TaskState::Failed, DesiredState::Remove, true),
            (TaskState::Orphaned, DesiredState::Remove, true),
            // Not marked for removal: never deleted by the reaper.
            (TaskState::Shutdown, DesiredState::Shutdown, false),
            (TaskState::New, DesiredState::Running, false),
        ];
        for (state, desired, expected) in cases {
            let task = planted_task(&service, 1, state, desired, now);
            assert_eq!(is_deletable(&task), expected, "{state} / {desired}");
        }
    }

    #[test]
    fn prunable_tasks_are_history_or_will_never_run() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let cases = [
            (TaskState::Running, DesiredState::Running, false),
            (TaskState::Ready, DesiredState::Ready, false),
            (TaskState::Complete, DesiredState::Shutdown, true),
            (TaskState::Failed, DesiredState::Running, true),
            (TaskState::Rejected, DesiredState::Running, true),
            (TaskState::Orphaned, DesiredState::Shutdown, true),
            // Never scheduled and no longer wanted.
            (TaskState::New, DesiredState::Shutdown, true),
            (TaskState::Pending, DesiredState::Running, false),
        ];
        for (state, desired, expected) in cases {
            let task = planted_task(&service, 1, state, desired, now);
            assert_eq!(is_prunable(&task), expected, "{state} / {desired}");
        }
    }

    #[test]
    fn history_limit_follows_the_restart_policy() {
        let service = sample_service("web", 1);
        assert_eq!(history_limit(Some(&service)), Some(5));
        assert_eq!(history_limit(None), Some(5));

        let bounded = with_restart(
            sample_service("web", 1),
            RestartCondition::OnFailure,
            Duration::from_secs(5),
            2,
        );
        assert_eq!(
            history_limit(Some(&bounded)),
            Some(3),
            "max_attempts + 1 (SWK §4.6)"
        );
    }
}
