// SPDX-License-Identifier: BSD-2-Clause
//! [`Worker`] — the node's task set (SWK §14.2, architecture §7.2).
//!
//! `satld` feeds it the dispatcher's assignments; it owns one
//! [`TaskManager`] per assigned task and the local DB that survives restarts.
//!
//! - [`Worker::apply`] — a task was assigned or updated. The task snapshot is
//!   persisted *without* clobbering the locally-recorded status (the local
//!   status is canonical, architecture §7.2), then handed to an existing
//!   manager or given a fresh one.
//! - [`Worker::remove`] — the task is no longer assigned: stop the manager,
//!   release every resource, delete the record.
//! - [`Worker::init_from_disk`] — the startup pass. Records whose task is
//!   still assigned resume **from their persisted status** (a running jail is
//!   re-attached, not restarted); records for tasks that are gone get the
//!   full removal treatment.
//!
//! The resume decision itself is a pure function ([`resume_decision`]) so the
//! matrix that decides "re-attach vs. declare dead vs. replay the state
//! machine" is exhaustively testable without a runtime.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use satl_core::{DesiredState, Id, Task, TaskState, TaskStatus};
use satl_runtime::{Runtime as _, RuntimeState, RuntimeStatus};

use crate::controller::{Controller, TaskController as _};
use crate::db::{DbError, TaskDb};
use crate::executor::Executor;
use crate::reporter::StatusReporter;
use crate::task_manager::TaskManager;

/// Status message used when a container did not survive a daemon restart.
pub const DIED_WHILE_DOWN: &str =
    "container died while satld was down (no jail found for the task at startup)";

/// What [`Worker::init_from_disk`] did with one persisted record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeDecision {
    /// The task is no longer assigned to this node: release everything.
    Remove,
    /// The jail is still alive: re-arm the exit watch on `pid` and keep
    /// reporting `RUNNING` (architecture §7.2 — re-attach, don't restart).
    Reattach {
        /// The surviving container process.
        pid: i32,
    },
    /// The task was `RUNNING` but no live jail backs it any more.
    DiedWhileDown,
    /// Replay the state machine from the persisted status (every controller
    /// step is re-entrant, so an interrupted `prepare`/`start` just re-runs).
    Resume,
}

/// Decide what to do with one persisted task record at startup.
///
/// `assigned` is whether the manager still lists the task for this node;
/// `state` is the persisted (canonical) observed state; `runtime` is what
/// `ocijail state` says about a jail with this task's ID, if anything.
#[must_use]
pub fn resume_decision(
    assigned: bool,
    state: TaskState,
    runtime: Option<&RuntimeState>,
) -> ResumeDecision {
    if !assigned {
        return ResumeDecision::Remove;
    }
    if state.is_terminal() {
        // Nothing left to drive; the manager parks and re-reports the status.
        return ResumeDecision::Resume;
    }
    if state == TaskState::Running {
        return match runtime {
            Some(state) if state.status != RuntimeStatus::Stopped => match state.pid {
                Some(pid) => ResumeDecision::Reattach { pid },
                None => ResumeDecision::DiedWhileDown,
            },
            _ => ResumeDecision::DiedWhileDown,
        };
    }
    ResumeDecision::Resume
}

/// Summary of a startup pass, for `satld`'s log line and tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InitReport {
    /// Tasks whose managers were resumed.
    pub resumed: Vec<Id>,
    /// Tasks whose live container was re-attached.
    pub reattached: Vec<Id>,
    /// Tasks reported `FAILED` because their container did not survive.
    pub died_while_down: Vec<Id>,
    /// Tasks removed because they are no longer assigned.
    pub removed: Vec<Id>,
    /// The desired state each resumed task manager is now driving, taken from
    /// the **persisted** task definition, and the resources last handed to it.
    ///
    /// This is what a freshly assigned copy of the same task has to be
    /// compared against: the manager may have moved the desired state on while
    /// this node was down, and the caller cannot tell that from the snapshot
    /// alone (see the seeding comment in `satl_dispatcher`'s
    /// `AssignmentApplier::apply_snapshot`). The resources ride along for the
    /// M6g hot resize: a task whose limits moved while the agent was down must
    /// be handed over again so the live jail's rctl rules follow.
    pub driving: BTreeMap<Id, (DesiredState, satl_core::ResourceRequirements)>,
}

/// Failure applying assignments.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// The local task DB failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// The node's task set.
pub struct Worker<R: StatusReporter> {
    executor: Arc<Executor>,
    db: TaskDb,
    reporter: Arc<R>,
    managers: tokio::sync::Mutex<BTreeMap<Id, TaskManager>>,
}

impl<R: StatusReporter> std::fmt::Debug for Worker<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("db", &self.db)
            .finish_non_exhaustive()
    }
}

impl<R: StatusReporter> Worker<R> {
    /// A worker over `executor`, persisting to `db` and reporting via
    /// `reporter`.
    #[must_use]
    pub fn new(executor: Arc<Executor>, db: TaskDb, reporter: Arc<R>) -> Self {
        Self {
            executor,
            db,
            reporter,
            managers: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Task IDs currently being driven.
    pub async fn task_ids(&self) -> BTreeSet<Id> {
        self.managers.lock().await.keys().cloned().collect()
    }

    /// A task was assigned or updated (SWK §14.2).
    ///
    /// # Errors
    ///
    /// [`WorkerError::Db`] when the record cannot be persisted — the task is
    /// then not started, because a task the agent cannot remember is a task
    /// it cannot clean up after a restart.
    #[tracing::instrument(skip_all, fields(task_id = %task.id, desired = %task.desired_state))]
    pub async fn apply(&self, task: Task) -> Result<(), WorkerError> {
        let status = self.db.put_task(&task).await?;
        let mut managers = self.managers.lock().await;
        if let Some(manager) = managers.get_mut(&task.id) {
            let task_id = task.id.clone();
            let desired = task.desired_state;
            // A refused update is either a desired-state regression (dropped on
            // purpose, and `update` says why) or an undeliverable command —
            // which can only mean the manager's loop is gone while its handle
            // is not, i.e. it panicked. That case used to pass silently: the
            // task then looks perfectly healthy from the outside and nothing
            // ever drives it again, which is how a `desired Shutdown` ends up
            // never stopping anything.
            let regression = desired < manager.desired_state();
            if !manager.update(task) && !regression {
                tracing::error!(
                    task_id = %task_id,
                    desired = %desired,
                    "the task manager is not accepting updates; this task is no longer driven"
                );
            }
            return Ok(());
        }
        tracing::info!(state = %status.state, "starting task manager");
        let id = task.id.clone();
        let manager = self.spawn_manager(task, status, None);
        managers.insert(id, manager);
        Ok(())
    }

    /// The task is no longer assigned: stop it and release everything.
    ///
    /// # Errors
    ///
    /// [`WorkerError::Db`] when the record cannot be read.
    #[tracing::instrument(skip_all, fields(task_id = %task_id))]
    pub async fn remove(&self, task_id: &Id) -> Result<(), WorkerError> {
        let manager = self.managers.lock().await.remove(task_id);
        if let Some(manager) = manager {
            manager.remove().await;
            return Ok(());
        }
        // No manager: clean up from the persisted definition, if any. This is
        // the path startup reconciliation takes for orphans.
        let Some(record) = self.db.get(task_id).await? else {
            tracing::debug!("nothing known about this task; nothing to remove");
            return Ok(());
        };
        self.remove_record(record.task, record.status).await;
        Ok(())
    }

    /// Rebuild the task set from disk (SWK §14.2 `Init`).
    ///
    /// `live_task_ids` is the set the manager still assigns to this node —
    /// on a cold start with no dispatcher session yet, pass the tasks from
    /// the first assignment snapshot.
    ///
    /// # Errors
    ///
    /// [`WorkerError::Db`] when the DB cannot be enumerated.
    #[tracing::instrument(skip_all, fields(live = live_task_ids.len()))]
    pub async fn init_from_disk(
        &self,
        live_task_ids: &BTreeSet<Id>,
    ) -> Result<InitReport, WorkerError> {
        let records = self.db.list().await?;
        let mut report = InitReport::default();
        for record in records {
            let task_id = record.task.id.clone();
            let desired = record.task.desired_state;
            let assigned = live_task_ids.contains(&task_id);
            let runtime = if assigned && record.status.state == TaskState::Running {
                self.executor.runtime().state(task_id.as_str()).await.ok()
            } else {
                None
            };
            let decision = resume_decision(assigned, record.status.state, runtime.as_ref());
            tracing::info!(
                task_id = %task_id,
                state = %record.status.state,
                ?decision,
                "resuming task from the local db"
            );
            if decision != ResumeDecision::Remove {
                // The manager that resumes below drives the *persisted*
                // desired state, not whatever the cluster wants now.
                report
                    .driving
                    .insert(task_id.clone(), (desired, record.task.spec.resources));
            }
            match decision {
                ResumeDecision::Remove => {
                    self.remove_record(record.task, record.status).await;
                    report.removed.push(task_id);
                }
                ResumeDecision::Reattach { pid } => {
                    self.resume(record.task, record.status, Some(pid)).await;
                    report.reattached.push(task_id);
                }
                ResumeDecision::DiedWhileDown => {
                    let mut status = TaskStatus::new(TaskState::Failed, "failed");
                    status.err = Some(DIED_WHILE_DOWN.to_owned());
                    status.container = record.status.container.clone();
                    if let Err(error) = self.db.put_status(&task_id, &status).await {
                        tracing::error!(task_id = %task_id, %error, "cannot persist the failure");
                    }
                    self.reporter.report(&task_id, status.clone()).await;
                    self.resume(record.task, status, None).await;
                    report.died_while_down.push(task_id);
                }
                ResumeDecision::Resume => {
                    self.resume(record.task, record.status, None).await;
                    report.resumed.push(task_id);
                }
            }
        }
        Ok(report)
    }

    /// Stop every task manager without touching the tasks' resources — a
    /// running jail survives a daemon restart and is re-adopted at startup.
    pub async fn shutdown(&self) {
        let managers = std::mem::take(&mut *self.managers.lock().await);
        for (_, manager) in managers {
            manager.close().await;
        }
    }

    fn spawn_manager(
        &self,
        task: Task,
        status: TaskStatus,
        reattach_pid: Option<i32>,
    ) -> TaskManager {
        let mut controller = Controller::new(Arc::clone(&self.executor), task.clone());
        if let Some(pid) = reattach_pid {
            controller.reattach_running(pid);
        }
        TaskManager::spawn(
            task,
            status,
            controller,
            self.db.clone(),
            Arc::clone(&self.reporter),
        )
    }

    async fn resume(&self, task: Task, status: TaskStatus, reattach_pid: Option<i32>) {
        let id = task.id.clone();
        let manager = self.spawn_manager(task, status, reattach_pid);
        self.managers.lock().await.insert(id, manager);
    }

    /// Release a task's resources without a manager (startup orphans and
    /// tasks the worker never started).
    async fn remove_record(&self, task: Task, status: TaskStatus) {
        let task_id = task.id.clone();
        let mut controller = Controller::new(Arc::clone(&self.executor), task);
        if !status.state.is_terminal()
            && let Err(error) = controller.shutdown().await
        {
            tracing::warn!(task_id = %task_id, %error, "shutdown before removal failed");
        }
        if let Err(error) = controller.remove().await {
            tracing::error!(task_id = %task_id, %error, "task cleanup failed");
        }
        if let Err(error) = self.db.remove(&task_id).await {
            tracing::error!(task_id = %task_id, %error, "cannot delete the task record");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn runtime_state(status: RuntimeStatus, pid: Option<i32>) -> RuntimeState {
        RuntimeState {
            id: crate::testing::TASK_ID.to_owned(),
            status,
            pid,
            bundle: PathBuf::from("/var/db/satl/bundles/t"),
            annotations: BTreeMap::new(),
            oci_version: "1.0.2".to_owned(),
        }
    }

    /// Every observed state a record can hold.
    const STATES: [TaskState; 13] = [
        TaskState::New,
        TaskState::Pending,
        TaskState::Assigned,
        TaskState::Accepted,
        TaskState::Preparing,
        TaskState::Ready,
        TaskState::Starting,
        TaskState::Running,
        TaskState::Complete,
        TaskState::Shutdown,
        TaskState::Failed,
        TaskState::Rejected,
        TaskState::Orphaned,
    ];

    #[test]
    fn an_unassigned_record_is_always_removed() {
        for state in STATES {
            assert_eq!(
                resume_decision(false, state, None),
                ResumeDecision::Remove,
                "{state}"
            );
            assert_eq!(
                resume_decision(
                    false,
                    state,
                    Some(&runtime_state(RuntimeStatus::Running, Some(7)))
                ),
                ResumeDecision::Remove,
                "{state}"
            );
        }
    }

    #[test]
    fn every_non_running_assigned_state_replays_the_state_machine() {
        for state in STATES {
            if state == TaskState::Running {
                continue;
            }
            assert_eq!(
                resume_decision(true, state, None),
                ResumeDecision::Resume,
                "{state}"
            );
        }
    }

    #[test]
    fn a_running_task_is_reattached_only_when_a_live_jail_backs_it() {
        // Live jail with a pid: re-attach (never restart).
        assert_eq!(
            resume_decision(
                true,
                TaskState::Running,
                Some(&runtime_state(RuntimeStatus::Running, Some(4242)))
            ),
            ResumeDecision::Reattach { pid: 4242 }
        );
        // Created-but-not-started still counts as alive: the container
        // process exists and its exit is still observable.
        assert_eq!(
            resume_decision(
                true,
                TaskState::Running,
                Some(&runtime_state(RuntimeStatus::Created, Some(11)))
            ),
            ResumeDecision::Reattach { pid: 11 }
        );
        // Stopped, no pid, or unknown to ocijail: it died while we were down.
        assert_eq!(
            resume_decision(
                true,
                TaskState::Running,
                Some(&runtime_state(RuntimeStatus::Stopped, None))
            ),
            ResumeDecision::DiedWhileDown
        );
        assert_eq!(
            resume_decision(
                true,
                TaskState::Running,
                Some(&runtime_state(RuntimeStatus::Running, None))
            ),
            ResumeDecision::DiedWhileDown
        );
        assert_eq!(
            resume_decision(true, TaskState::Running, None),
            ResumeDecision::DiedWhileDown
        );
    }

    #[test]
    fn terminal_records_are_resumed_so_their_status_is_re_reported() {
        for state in [
            TaskState::Complete,
            TaskState::Shutdown,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
        ] {
            assert_eq!(
                resume_decision(true, state, None),
                ResumeDecision::Resume,
                "{state}"
            );
        }
    }
}
