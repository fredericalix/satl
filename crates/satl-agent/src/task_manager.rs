// SPDX-License-Identifier: BSD-2-Clause
//! One tokio task per assigned task, serializing controller operations
//! (SWK §14.4, architecture §7.2).
//!
//! The loop is deliberately dumb: call [`do_step`] once, persist the status
//! it produced, hand it to the [`StatusReporter`], repeat.
//!
//! - [`Step::Noop`] → park until the next task update (SwarmKit
//!   `ErrTaskNoop`).
//! - [`Step::Retry`] → wait [`RETRY_BACKOFF`] (a flat 1 s, exactly as
//!   SwarmKit — an acknowledged TODO there, kept for parity) or until an
//!   update arrives, whichever comes first.
//! - [`Step::Advanced`] → loop immediately.
//!
//! Task updates never move the desired state backwards (architecture §7.2)
//! and always cancel the in-flight operation: the step future is dropped, its
//! borrow of the controller ends, and the loop re-dispatches against the new
//! definition. That is safe because every controller step is re-entrant.

use std::sync::Arc;
use std::time::Duration;

use satl_core::{DesiredState, Id, Task, TaskStatus};

use crate::controller::TaskController;
use crate::db::TaskDb;
use crate::do_step::{Step, do_step};
use crate::reporter::StatusReporter;

/// Flat backoff between retries of a transient failure (SWK §14.4).
pub const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Commands the worker sends to a running task manager.
#[derive(Debug)]
enum Command {
    /// A new definition of the same task.
    Update(Box<Task>),
    /// Stop driving the task and release all of its resources.
    Remove,
    /// Stop driving the task, leaving its resources in place (daemon
    /// shutdown — a running jail survives and is re-adopted at startup).
    Close,
}

/// Why a task manager's loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The worker asked for removal and the controller released everything.
    Removed,
    /// The worker asked the loop to stop; resources were left alone.
    Closed,
}

/// Handle on a running task manager.
#[derive(Debug)]
pub struct TaskManager {
    task_id: Id,
    desired: DesiredState,
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
    join: tokio::task::JoinHandle<Exit>,
}

impl TaskManager {
    /// Spawn the loop driving `ctlr` for `task`, starting from `status` (the
    /// canonical local status, architecture §7.2).
    pub fn spawn<C, R>(
        task: Task,
        status: TaskStatus,
        ctlr: C,
        db: TaskDb,
        reporter: Arc<R>,
    ) -> Self
    where
        C: TaskController + Send + 'static,
        R: StatusReporter,
    {
        let (commands, rx) = tokio::sync::mpsc::unbounded_channel();
        let task_id = task.id.clone();
        let desired = task.desired_state;
        let join = tokio::spawn(run(task, status, ctlr, db, reporter, rx));
        Self {
            task_id,
            desired,
            commands,
            join,
        }
    }

    /// The task being driven.
    #[must_use]
    pub fn task_id(&self) -> &Id {
        &self.task_id
    }

    /// The highest desired state accepted so far.
    #[must_use]
    pub fn desired_state(&self) -> DesiredState {
        self.desired
    }

    /// Adopt a new definition of the task. Desired-state regressions are
    /// dropped (architecture §7.2); returns whether the update was forwarded.
    pub fn update(&mut self, task: Task) -> bool {
        if task.desired_state < self.desired {
            tracing::warn!(
                task_id = %self.task_id,
                current = %self.desired,
                proposed = %task.desired_state,
                "ignoring a task update that would move the desired state backwards"
            );
            return false;
        }
        self.desired = task.desired_state;
        self.commands.send(Command::Update(Box::new(task))).is_ok()
    }

    /// Stop the loop and release the task's resources.
    pub async fn remove(self) -> Exit {
        self.finish(Command::Remove).await
    }

    /// Stop the loop, leaving the task's resources in place.
    pub async fn close(self) -> Exit {
        self.finish(Command::Close).await
    }

    async fn finish(self, command: Command) -> Exit {
        let expected = match command {
            Command::Remove => Exit::Removed,
            _ => Exit::Closed,
        };
        if self.commands.send(command).is_err() {
            // The loop is already gone (it only ends on command).
            return expected;
        }
        self.join.await.unwrap_or_else(|error| {
            tracing::error!(task_id = %self.task_id, %error, "task manager panicked");
            expected
        })
    }
}

/// Persist then report — in that order, so a crash can never lose a status
/// the manager already believes was delivered.
async fn publish<R: StatusReporter>(db: &TaskDb, reporter: &R, task_id: &Id, status: &TaskStatus) {
    match db.put_status(task_id, status).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!(task_id = %task_id, "task record is gone; status not persisted");
        }
        Err(error) => {
            tracing::error!(task_id = %task_id, %error, "cannot persist task status");
        }
    }
    reporter.report(task_id, status.clone()).await;
}

async fn run<C, R>(
    mut task: Task,
    mut status: TaskStatus,
    mut ctlr: C,
    db: TaskDb,
    reporter: Arc<R>,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<Command>,
) -> Exit
where
    C: TaskController + Send + 'static,
    R: StatusReporter,
{
    let task_id = task.id.clone();
    let exit = loop {
        // The step borrows `task`/`ctlr`; scope it so a command that
        // interrupts it can mutate them afterwards. Dropping the future is
        // what cancels the in-flight controller operation — safe because
        // every step is re-entrant.
        let interrupt = {
            let running = do_step(&task, &status, &mut ctlr);
            tokio::pin!(running);
            tokio::select! {
                step = &mut running => Interrupt::Stepped(step),
                command = commands.recv() => Interrupt::Commanded(command),
            }
        };
        let step = match interrupt {
            Interrupt::Stepped(step) => step,
            Interrupt::Commanded(command) => match apply_command(command, &mut task, &mut ctlr) {
                Flow::Continue => continue,
                Flow::Stop(exit) => break exit,
            },
        };

        match step {
            Step::Advanced(next) => {
                status = next;
                publish(&db, reporter.as_ref(), &task_id, &status).await;
            }
            Step::Retry(next) => {
                status = next;
                publish(&db, reporter.as_ref(), &task_id, &status).await;
                tokio::select! {
                    () = tokio::time::sleep(RETRY_BACKOFF) => {}
                    command = commands.recv() => {
                        match apply_command(command, &mut task, &mut ctlr) {
                            Flow::Continue => {}
                            Flow::Stop(exit) => break exit,
                        }
                    }
                }
            }
            Step::Noop => {
                // Park until something changes (SwarmKit ErrTaskNoop).
                let command = commands.recv().await;
                match apply_command(command, &mut task, &mut ctlr) {
                    Flow::Continue => {}
                    Flow::Stop(exit) => break exit,
                }
            }
        }
    };

    if exit == Exit::Removed {
        // Politeness: a task that is still alive gets its stop signal and
        // grace period before `remove` force-deletes the jail.
        if !status.state.is_terminal()
            && let Err(error) = ctlr.shutdown().await
        {
            tracing::warn!(task_id = %task_id, %error, "shutdown before removal failed");
        }
        if let Err(error) = ctlr.remove().await {
            tracing::error!(task_id = %task_id, %error, "task cleanup failed");
        }
        if let Err(error) = db.remove(&task_id).await {
            tracing::error!(task_id = %task_id, %error, "cannot delete the task record");
        }
    }
    tracing::info!(task_id = %task_id, ?exit, "task manager stopped");
    exit
}

/// Which arm of the step/command race won.
enum Interrupt {
    Stepped(Step),
    Commanded(Option<Command>),
}

/// What the loop should do after a command.
enum Flow {
    Continue,
    Stop(Exit),
}

fn apply_command<C: TaskController>(
    command: Option<Command>,
    task: &mut Task,
    ctlr: &mut C,
) -> Flow {
    match command {
        Some(Command::Update(updated)) => {
            if updated.desired_state < task.desired_state {
                tracing::warn!(
                    task_id = %task.id,
                    current = %task.desired_state,
                    proposed = %updated.desired_state,
                    "dropping a desired-state regression"
                );
                return Flow::Continue;
            }
            tracing::debug!(
                task_id = %task.id,
                desired = %updated.desired_state,
                "task definition updated"
            );
            *task = *updated;
            // The controller keeps its own snapshot — the hot resize (M6g)
            // lives there: a resources move re-applies rctl to the live jail.
            ctlr.update(task.clone());
            Flow::Continue
        }
        Some(Command::Remove) => Flow::Stop(Exit::Removed),
        // `None` = every sender dropped, i.e. the worker is gone: same
        // handling as an explicit close.
        Some(Command::Close) | None => Flow::Stop(Exit::Closed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::ExitOutcome;
    use crate::error::ControllerError;
    use crate::testing;
    use satl_core::{ContainerStatus, TaskState};
    use std::sync::Mutex;

    /// Records every status handed to it.
    #[derive(Debug, Default)]
    struct RecordingReporter {
        seen: Mutex<Vec<TaskStatus>>,
    }

    impl RecordingReporter {
        fn states(&self) -> Vec<TaskState> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|status| status.state)
                .collect()
        }
    }

    impl StatusReporter for RecordingReporter {
        async fn report(&self, _task_id: &Id, status: TaskStatus) {
            self.seen.lock().unwrap().push(status);
        }
    }

    /// A controller that succeeds at everything, optionally blocking in
    /// `wait` forever (a "running" container) and counting `remove` calls.
    struct FakeController {
        block_in_wait: bool,
        removed: Arc<Mutex<u32>>,
        shutdowns: Arc<Mutex<u32>>,
        fail_prepare_times: Arc<Mutex<u32>>,
    }

    impl FakeController {
        fn new() -> Self {
            Self {
                block_in_wait: false,
                removed: Arc::new(Mutex::new(0)),
                shutdowns: Arc::new(Mutex::new(0)),
                fail_prepare_times: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl TaskController for FakeController {
        async fn prepare(&mut self) -> Result<(), ControllerError> {
            let mut left = self.fail_prepare_times.lock().unwrap();
            if *left > 0 {
                *left -= 1;
                return Err(ControllerError::Cancelled);
            }
            Ok(())
        }

        async fn start(&mut self) -> Result<(), ControllerError> {
            Ok(())
        }

        async fn wait(&mut self) -> Result<ExitOutcome, ControllerError> {
            if self.block_in_wait {
                std::future::pending::<()>().await;
            }
            Ok(ExitOutcome {
                code: Some(0),
                signal: None,
                unharvestable: None,
            })
        }

        fn update(&mut self, _task: Task) {}

        async fn shutdown(&mut self) -> Result<(), ControllerError> {
            *self.shutdowns.lock().unwrap() += 1;
            Ok(())
        }

        async fn remove(&mut self) -> Result<(), ControllerError> {
            *self.removed.lock().unwrap() += 1;
            Ok(())
        }

        fn container_status(&self) -> Option<ContainerStatus> {
            None
        }

        fn port_status(&self) -> Vec<satl_core::PortStatus> {
            Vec::new()
        }

        fn status_note(&self) -> Option<&str> {
            None
        }
    }

    fn db() -> (tempfile::TempDir, TaskDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = TaskDb::open(dir.path()).unwrap();
        (dir, db)
    }

    /// Wait until `check` holds, or fail the test.
    async fn eventually(mut check: impl FnMut() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition never became true");
    }

    #[tokio::test]
    async fn drives_a_task_to_running_and_persists_every_status() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = db.put_task(&task).await.unwrap();
        let reporter = Arc::new(RecordingReporter::default());
        let mut ctlr = FakeController::new();
        ctlr.block_in_wait = true;

        let manager = TaskManager::spawn(
            task.clone(),
            status,
            ctlr,
            db.clone(),
            Arc::clone(&reporter),
        );
        eventually(|| reporter.states().last() == Some(&TaskState::Running)).await;
        assert_eq!(
            reporter.states(),
            [
                TaskState::Accepted,
                TaskState::Preparing,
                TaskState::Ready,
                TaskState::Starting,
                TaskState::Running,
            ]
        );
        // The DB carries the canonical status.
        assert_eq!(
            db.get(&task.id).await.unwrap().unwrap().status.state,
            TaskState::Running
        );
        assert_eq!(manager.close().await, Exit::Closed);
    }

    #[tokio::test]
    async fn a_desired_ready_task_parks_until_it_is_promoted() {
        let (_dir, db) = db();
        let mut task = testing::task();
        task.desired_state = DesiredState::Ready;
        let status = db.put_task(&task).await.unwrap();
        let reporter = Arc::new(RecordingReporter::default());

        let mut manager = TaskManager::spawn(
            task.clone(),
            status,
            FakeController::new(),
            db.clone(),
            Arc::clone(&reporter),
        );
        eventually(|| reporter.states().last() == Some(&TaskState::Ready)).await;

        // Promotion releases it.
        let mut promoted = task.clone();
        promoted.desired_state = DesiredState::Running;
        assert!(manager.update(promoted));
        eventually(|| reporter.states().contains(&TaskState::Running)).await;
        assert_eq!(manager.close().await, Exit::Closed);
    }

    #[tokio::test]
    async fn desired_state_regressions_are_ignored() {
        let (_dir, db) = db();
        let mut task = testing::task();
        task.desired_state = DesiredState::Shutdown;
        let status = db.put_task(&task).await.unwrap();
        let reporter = Arc::new(RecordingReporter::default());
        let mut manager = TaskManager::spawn(
            task.clone(),
            status,
            FakeController::new(),
            db.clone(),
            Arc::clone(&reporter),
        );
        eventually(|| reporter.states().last() == Some(&TaskState::Shutdown)).await;

        let mut regressed = task.clone();
        regressed.desired_state = DesiredState::Running;
        assert!(!manager.update(regressed));
        assert_eq!(manager.desired_state(), DesiredState::Shutdown);
        assert_eq!(manager.close().await, Exit::Closed);
    }

    #[tokio::test]
    async fn retryable_failures_are_retried_and_reported() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = db.put_task(&task).await.unwrap();
        let reporter = Arc::new(RecordingReporter::default());
        let ctlr = FakeController::new();
        *ctlr.fail_prepare_times.lock().unwrap() = 1;

        let manager = TaskManager::spawn(
            task.clone(),
            status,
            ctlr,
            db.clone(),
            Arc::clone(&reporter),
        );
        // The retry reports PREPARING again (state unchanged, err set) and
        // the next attempt succeeds.
        eventually(|| reporter.states().contains(&TaskState::Ready)).await;
        let preparing: Vec<TaskStatus> = {
            let seen = reporter.seen.lock().unwrap();
            seen.iter()
                .filter(|status| status.state == TaskState::Preparing)
                .cloned()
                .collect()
        };
        assert_eq!(preparing.len(), 2, "{:?}", reporter.states());
        assert!(preparing[1].err.is_some());
        assert_eq!(manager.close().await, Exit::Closed);
    }

    #[tokio::test]
    async fn remove_shuts_down_a_live_task_cleans_up_and_drops_the_record() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = db.put_task(&task).await.unwrap();
        let reporter = Arc::new(RecordingReporter::default());
        let mut ctlr = FakeController::new();
        ctlr.block_in_wait = true;
        let removed = Arc::clone(&ctlr.removed);
        let shutdowns = Arc::clone(&ctlr.shutdowns);

        let manager = TaskManager::spawn(task.clone(), status, ctlr, db.clone(), reporter);
        eventually(|| {
            std::fs::read(db.dir().join(task.id.as_str())).is_ok_and(|bytes| !bytes.is_empty())
        })
        .await;

        assert_eq!(manager.remove().await, Exit::Removed);
        assert_eq!(*removed.lock().unwrap(), 1);
        assert_eq!(
            *shutdowns.lock().unwrap(),
            1,
            "a live task is stopped first"
        );
        assert!(db.get(&task.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn close_leaves_the_record_and_the_resources_alone() {
        let (_dir, db) = db();
        let task = testing::task();
        let status = db.put_task(&task).await.unwrap();
        let ctlr = FakeController::new();
        let removed = Arc::clone(&ctlr.removed);
        let manager = TaskManager::spawn(
            task.clone(),
            status,
            ctlr,
            db.clone(),
            Arc::new(RecordingReporter::default()),
        );
        assert_eq!(manager.close().await, Exit::Closed);
        assert_eq!(*removed.lock().unwrap(), 0);
        assert!(db.get(&task.id).await.unwrap().is_some());
    }
}
