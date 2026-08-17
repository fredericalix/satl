// SPDX-License-Identifier: BSD-2-Clause
//! The agent's one-step task state machine — a port of SwarmKit's
//! `exec.Do` (SWK §15.4, architecture §8.2).
//!
//! [`do_step`] performs **exactly one** operation on a task and returns the
//! resulting status; [`crate::task_manager`] loops it. Decision order (the
//! order is load-bearing):
//!
//! 1. **Shutdown wins.** `desired >= SHUTDOWN` and not yet terminal ⇒
//!    `shutdown()` → `SHUTDOWN`. (The agent never produces `REMOVE` or
//!    `ORPHANED`.)
//! 2. **Observed past desired** ⇒ no-op.
//! 3. **In-flight states finish what they started**, even past the desired
//!    state: `PREPARING`→`prepare`→`READY`, `STARTING`→`start`→`RUNNING`,
//!    `RUNNING`→`wait`→`COMPLETE`/`FAILED`.
//! 4. **Pause gate**: `observed >= desired` ⇒ no-op (a `READY` task whose
//!    desired state is `READY` waits for promotion — architecture §4 rule 3).
//! 5. **Bookkeeping advances**: `NEW`/`PENDING`/`ASSIGNED`→`ACCEPTED`,
//!    `ACCEPTED`→`PREPARING`, `READY`→`STARTING`.
//!
//! Failure handling: retryable errors ([`ControllerError::is_temporary`])
//! report the error and leave the state alone; anything else is terminal —
//! `REJECTED` below `STARTING`, `FAILED` from `STARTING` on. For states at or
//! past `STARTING` the container and port status are harvested onto the
//! reported status either way.
//!
//! Transitions are monotonic by construction and additionally checked with
//! [`satl_core::TaskState::advance`]: SwarmKit panics on a regression, SatL
//! returns the state unchanged and logs at error level (architecture §4
//! rule 1).

use satl_core::{DesiredState, Task, TaskState, TaskStatus};

use crate::controller::TaskController;
use crate::error::ControllerError;

/// What one [`do_step`] call produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// The task advanced; persist and report `status`, then step again.
    Advanced(TaskStatus),
    /// Nothing to do until the task definition changes (SwarmKit
    /// `ErrTaskNoop`).
    Noop,
    /// Transient failure (SwarmKit `ErrTaskRetry`): report `status` — which
    /// carries the error text but the *unchanged* state — and retry after the
    /// backoff.
    Retry(TaskStatus),
}

impl Step {
    /// The status to persist and report, if any.
    #[must_use]
    pub fn status(&self) -> Option<&TaskStatus> {
        match self {
            Self::Advanced(status) | Self::Retry(status) => Some(status),
            Self::Noop => None,
        }
    }
}

/// Perform one state-machine step for `task` using `ctlr`.
///
/// `status` is the **local** status (canonical — architecture §7.2), not
/// necessarily the manager's copy carried on `task`.
pub async fn do_step<C: TaskController>(task: &Task, status: &TaskStatus, ctlr: &mut C) -> Step {
    let mut next = status.clone();
    next.timestamp = std::time::SystemTime::now();
    next.applied_by = None;
    next.applied_at = None;

    let observed = status.state;
    let desired = task.desired_state;

    // 1. Shutdown wins.
    if desired >= DesiredState::Shutdown {
        if observed >= TaskState::Complete {
            return Step::Noop;
        }
        return match ctlr.shutdown().await {
            Ok(()) => transition(task, next, ctlr, TaskState::Shutdown, "shutdown"),
            Err(error) => fatal(task, next, ctlr, &error),
        };
    }

    // 2. Observed past desired: nothing to do (also covers terminal states).
    if observed > desired.as_task_state() {
        return Step::Noop;
    }

    // 3. In-flight states finish what they started, even past desired.
    match observed {
        TaskState::Preparing => {
            return match ctlr.prepare().await {
                Ok(()) => transition(task, next, ctlr, TaskState::Ready, "prepared"),
                Err(error) => fatal(task, next, ctlr, &error),
            };
        }
        TaskState::Starting => {
            return match ctlr.start().await {
                Ok(()) => transition(task, next, ctlr, TaskState::Running, "started"),
                Err(error) => fatal(task, next, ctlr, &error),
            };
        }
        TaskState::Running => {
            return match ctlr.wait().await {
                Ok(exit) if exit.is_success() => {
                    transition(task, next, ctlr, TaskState::Complete, "finished")
                }
                Ok(exit) => {
                    // A non-zero exit is a task failure, not a controller
                    // error: the message carries the code/signal and the
                    // container status carries the exit code.
                    next.err = Some(exit.describe());
                    let step = transition(task, next, ctlr, TaskState::Failed, "failed");
                    return step;
                }
                Err(error) => fatal(task, next, ctlr, &error),
            };
        }
        _ => {}
    }

    // 4. Pause gate: wait for the manager to raise the desired state.
    if observed >= desired.as_task_state() {
        return Step::Noop;
    }

    // 5. Bookkeeping advances.
    match observed {
        TaskState::New | TaskState::Pending | TaskState::Assigned => {
            transition(task, next, ctlr, TaskState::Accepted, "accepted")
        }
        TaskState::Accepted => transition(task, next, ctlr, TaskState::Preparing, "preparing"),
        TaskState::Ready => transition(task, next, ctlr, TaskState::Starting, "starting"),
        // Terminal states below desired cannot happen (they are all above
        // RUNNING numerically), but the agent never invents work.
        _ => Step::Noop,
    }
}

/// Move `status` to `state`, harvesting runtime status for active states.
fn transition<C: TaskController>(
    task: &Task,
    mut status: TaskStatus,
    ctlr: &C,
    state: TaskState,
    message: &str,
) -> Step {
    let from = status.state;
    match TaskState::advance(from, state) {
        Ok(state) => {
            status.state = state;
            message.clone_into(&mut status.message);
            if state != TaskState::Failed && state != TaskState::Rejected {
                status.err = None;
            }
            if let Some(note) = ctlr.status_note() {
                status.message = format!("{message} ({note})");
            }
            harvest(&mut status, ctlr);
            tracing::info!(
                task_id = %task.id,
                service_id = ?task.service_id.as_ref().map(satl_core::Id::as_str),
                node_id = ?task.node_id.as_ref().map(satl_core::Id::as_str),
                %from,
                to = %state,
                desired = %task.desired_state,
                message = %status.message,
                "task state transition"
            );
            Step::Advanced(status)
        }
        Err(error) => {
            // Architecture §4 rule 1: never regress. SwarmKit panics here.
            tracing::error!(
                task_id = %task.id,
                %error,
                "refusing a task state regression (agent bug)"
            );
            Step::Noop
        }
    }
}

/// Terminal-vs-retryable classification (SwarmKit's `fatal`).
fn fatal<C: TaskController>(
    task: &Task,
    mut status: TaskStatus,
    ctlr: &C,
    error: &ControllerError,
) -> Step {
    status.err = Some(error.to_string());
    if status.state >= TaskState::Starting {
        harvest(&mut status, ctlr);
    }
    if error.is_temporary() {
        tracing::warn!(
            task_id = %task.id,
            state = %status.state,
            %error,
            "retryable task failure"
        );
        return Step::Retry(status);
    }
    let terminal = if status.state < TaskState::Starting {
        TaskState::Rejected
    } else {
        TaskState::Failed
    };
    tracing::error!(
        task_id = %task.id,
        from = %status.state,
        to = %terminal,
        %error,
        "fatal task failure"
    );
    let message = format!("{terminal}");
    transition(task, status, ctlr, terminal, &message)
}

/// Attach container and port status once the task is at least `STARTING`
/// (SWK §15.4: only active states carry runtime status).
fn harvest<C: TaskController>(status: &mut TaskStatus, ctlr: &C) {
    if status.state < TaskState::Starting {
        return;
    }
    if let Some(container) = ctlr.container_status() {
        status.container = Some(container);
    }
    let ports = ctlr.port_status();
    if !ports.is_empty() {
        status.port_status = ports;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::ExitOutcome;
    use crate::testing;
    use satl_core::ContainerStatus;
    use std::sync::{Arc, Mutex};

    /// Every call a mock controller recorded, in order.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        Prepare,
        Start,
        Wait,
        Shutdown,
        Remove,
    }

    /// What the mock should do for each method.
    #[derive(Default)]
    struct MockPlan {
        prepare: Option<ControllerError>,
        start: Option<ControllerError>,
        shutdown: Option<ControllerError>,
        wait: Option<Result<ExitOutcome, ControllerError>>,
    }

    struct MockController {
        plan: MockPlan,
        calls: Arc<Mutex<Vec<Call>>>,
        note: Option<String>,
        container: Option<ContainerStatus>,
        ports: Vec<satl_core::PortStatus>,
    }

    impl MockController {
        fn new(plan: MockPlan) -> Self {
            Self {
                plan,
                calls: Arc::new(Mutex::new(Vec::new())),
                note: None,
                container: Some(ContainerStatus {
                    jail_id: Some(testing::TASK_ID.to_owned()),
                    pid: Some(4242),
                    exit_code: None,
                }),
                ports: Vec::new(),
            }
        }

        fn ok() -> Self {
            Self::new(MockPlan::default())
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn record(&self, call: Call) {
            self.calls.lock().unwrap().push(call);
        }
    }

    impl TaskController for MockController {
        async fn prepare(&mut self) -> Result<(), ControllerError> {
            self.record(Call::Prepare);
            match self.plan.prepare.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn start(&mut self) -> Result<(), ControllerError> {
            self.record(Call::Start);
            match self.plan.start.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn wait(&mut self) -> Result<ExitOutcome, ControllerError> {
            self.record(Call::Wait);
            self.plan.wait.take().unwrap_or(Ok(ExitOutcome {
                code: Some(0),
                signal: None,
                unharvestable: None,
            }))
        }

        fn update(&mut self, _task: Task) {}

        async fn shutdown(&mut self) -> Result<(), ControllerError> {
            self.record(Call::Shutdown);
            match self.plan.shutdown.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn remove(&mut self) -> Result<(), ControllerError> {
            self.record(Call::Remove);
            Ok(())
        }

        fn container_status(&self) -> Option<ContainerStatus> {
            self.container.clone()
        }

        fn port_status(&self) -> Vec<satl_core::PortStatus> {
            self.ports.clone()
        }

        fn status_note(&self) -> Option<&str> {
            self.note.as_deref()
        }
    }

    /// Every observed state the agent can hold, in ascending order.
    const OBSERVED: [TaskState; 13] = [
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

    const DESIRED: [DesiredState; 5] = [
        DesiredState::Ready,
        DesiredState::Running,
        DesiredState::Complete,
        DesiredState::Shutdown,
        DesiredState::Remove,
    ];

    fn task_at(desired: DesiredState) -> Task {
        let mut task = testing::task();
        task.desired_state = desired;
        task
    }

    async fn run_step(
        observed: TaskState,
        desired: DesiredState,
        ctlr: &mut MockController,
    ) -> Step {
        let task = task_at(desired);
        let status = TaskStatus::new(observed, "");
        do_step(&task, &status, ctlr).await
    }

    /// The expected outcome of one cell of the decision table.
    #[derive(Debug, PartialEq, Eq)]
    enum Expect {
        Noop,
        To(TaskState, Option<Call>),
    }

    /// The full (observed × desired) decision table, derived by hand from
    /// SWK §15.4's algorithm. Any divergence in the port shows up here.
    fn expected(observed: TaskState, desired: DesiredState) -> Expect {
        // 1. Shutdown wins.
        if desired >= DesiredState::Shutdown {
            return if observed >= TaskState::Complete {
                Expect::Noop
            } else {
                Expect::To(TaskState::Shutdown, Some(Call::Shutdown))
            };
        }
        // 2. Observed past desired.
        if observed > desired.as_task_state() {
            return Expect::Noop;
        }
        // 3. In-flight states proceed past desired.
        match observed {
            TaskState::Preparing => return Expect::To(TaskState::Ready, Some(Call::Prepare)),
            TaskState::Starting => return Expect::To(TaskState::Running, Some(Call::Start)),
            TaskState::Running => return Expect::To(TaskState::Complete, Some(Call::Wait)),
            _ => {}
        }
        // 4. Pause gate.
        if observed >= desired.as_task_state() {
            return Expect::Noop;
        }
        // 5. Bookkeeping.
        match observed {
            TaskState::New | TaskState::Pending | TaskState::Assigned => {
                Expect::To(TaskState::Accepted, None)
            }
            TaskState::Accepted => Expect::To(TaskState::Preparing, None),
            TaskState::Ready => Expect::To(TaskState::Starting, None),
            _ => Expect::Noop,
        }
    }

    #[tokio::test]
    async fn decision_table_covers_every_observed_desired_pair() {
        for observed in OBSERVED {
            for desired in DESIRED {
                let mut ctlr = MockController::ok();
                let step = run_step(observed, desired, &mut ctlr).await;
                let expect = expected(observed, desired);
                match (&step, &expect) {
                    (Step::Noop, Expect::Noop) => {
                        assert!(
                            ctlr.calls().is_empty(),
                            "{observed}/{desired}: noop must not touch the controller: {:?}",
                            ctlr.calls()
                        );
                    }
                    (Step::Advanced(status), Expect::To(state, call)) => {
                        assert_eq!(status.state, *state, "{observed}/{desired}");
                        assert_eq!(
                            ctlr.calls(),
                            call.iter().copied().collect::<Vec<_>>(),
                            "{observed}/{desired}"
                        );
                    }
                    other => panic!("{observed}/{desired}: got {other:?}, want {expect:?}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn a_task_reaches_running_in_six_steps_from_assigned() {
        // SWK §15.4: ACCEPTED, PREPARING, prepare→READY, STARTING,
        // start→RUNNING; the sixth blocks in wait.
        let mut ctlr = MockController::ok();
        let task = task_at(DesiredState::Running);
        let mut status = TaskStatus::new(TaskState::Assigned, "assigned");
        let mut walked = Vec::new();
        for _ in 0..6 {
            match do_step(&task, &status, &mut ctlr).await {
                Step::Advanced(next) => {
                    walked.push(next.state);
                    status = next;
                }
                other => panic!("unexpected {other:?} after {walked:?}"),
            }
        }
        assert_eq!(
            walked,
            [
                TaskState::Accepted,
                TaskState::Preparing,
                TaskState::Ready,
                TaskState::Starting,
                TaskState::Running,
                TaskState::Complete,
            ]
        );
        assert_eq!(ctlr.calls(), [Call::Prepare, Call::Start, Call::Wait]);
    }

    #[tokio::test]
    async fn desired_ready_parks_at_ready_until_promotion() {
        let mut ctlr = MockController::ok();
        let step = run_step(TaskState::Ready, DesiredState::Ready, &mut ctlr).await;
        assert_eq!(step, Step::Noop);
        // Promotion to RUNNING releases it.
        let step = run_step(TaskState::Ready, DesiredState::Running, &mut ctlr).await;
        assert!(
            matches!(&step, Step::Advanced(status) if status.state == TaskState::Starting),
            "{step:?}"
        );
    }

    #[tokio::test]
    async fn non_zero_exit_fails_the_task_with_the_code_in_the_status() {
        let mut ctlr = MockController::new(MockPlan {
            wait: Some(Ok(ExitOutcome {
                code: Some(3),
                signal: None,
                unharvestable: None,
            })),
            ..MockPlan::default()
        });
        ctlr.container = Some(ContainerStatus {
            jail_id: Some(testing::TASK_ID.to_owned()),
            pid: Some(4242),
            exit_code: Some(3),
        });
        let step = run_step(TaskState::Running, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Failed);
        assert!(status.err.unwrap().contains("code 3"));
        assert_eq!(status.container.unwrap().exit_code, Some(3));
    }

    #[tokio::test]
    async fn signal_death_fails_the_task() {
        let mut ctlr = MockController::new(MockPlan {
            wait: Some(Ok(ExitOutcome {
                code: None,
                signal: Some(9),
                unharvestable: None,
            })),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Running, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Failed);
        assert!(status.err.unwrap().contains("signal 9"));
    }

    #[tokio::test]
    async fn failures_before_starting_reject_and_after_starting_fail() {
        // prepare failure at PREPARING (< STARTING) ⇒ REJECTED.
        let mut ctlr = MockController::new(MockPlan {
            prepare: Some(ControllerError::NoExitWatch {
                task_id: "t".to_owned(),
            }),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Preparing, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Rejected);
        assert!(status.err.is_some());
        // SwarmKit harvests against the *final* state, so a REJECTED task
        // still carries whatever the controller managed to create before it
        // failed (useful when `prepare` dies after `ocijail create`).
        assert_eq!(status.container.unwrap().pid, Some(4242));

        // A retryable failure below STARTING harvests nothing: the state is
        // unchanged, so the "active state" gate still says PREPARING.
        let mut ctlr = MockController::new(MockPlan {
            prepare: Some(ControllerError::Cancelled),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Preparing, DesiredState::Running, &mut ctlr).await;
        let Step::Retry(status) = step else {
            panic!("expected a retry, got {step:?}")
        };
        assert!(status.container.is_none());

        // start failure at STARTING (>= STARTING) ⇒ FAILED, with harvest.
        let mut ctlr = MockController::new(MockPlan {
            start: Some(ControllerError::NoExitWatch {
                task_id: "t".to_owned(),
            }),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Starting, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Failed);
        assert_eq!(status.container.unwrap().pid, Some(4242));
    }

    #[tokio::test]
    async fn retryable_failures_keep_the_state_and_report_the_error() {
        for (observed, plan) in [
            (
                TaskState::Preparing,
                MockPlan {
                    prepare: Some(ControllerError::Cancelled),
                    ..MockPlan::default()
                },
            ),
            (
                TaskState::Starting,
                MockPlan {
                    start: Some(
                        ControllerError::NoExitWatch {
                            task_id: "t".to_owned(),
                        }
                        .temporary(),
                    ),
                    ..MockPlan::default()
                },
            ),
            (
                TaskState::Running,
                MockPlan {
                    wait: Some(Err(ControllerError::Cancelled)),
                    ..MockPlan::default()
                },
            ),
        ] {
            let mut ctlr = MockController::new(plan);
            let step = run_step(observed, DesiredState::Running, &mut ctlr).await;
            let Step::Retry(status) = step else {
                panic!("{observed}: expected Retry, got {step:?}")
            };
            assert_eq!(status.state, observed, "{observed}: state must not move");
            assert!(status.err.is_some(), "{observed}");
        }
    }

    #[tokio::test]
    async fn shutdown_failure_is_classified_like_any_other() {
        let mut ctlr = MockController::new(MockPlan {
            shutdown: Some(ControllerError::Cancelled),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Running, DesiredState::Shutdown, &mut ctlr).await;
        assert!(matches!(step, Step::Retry(_)), "{step:?}");

        let mut ctlr = MockController::new(MockPlan {
            shutdown: Some(ControllerError::NoExitWatch {
                task_id: "t".to_owned(),
            }),
            ..MockPlan::default()
        });
        let step = run_step(TaskState::Running, DesiredState::Shutdown, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Failed);
    }

    #[tokio::test]
    async fn the_rctl_degradation_note_rides_the_status_message() {
        let mut ctlr = MockController::ok();
        ctlr.note = Some("limits not enforced".to_owned());
        let step = run_step(TaskState::Preparing, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Ready);
        assert!(status.message.contains("limits not enforced"), "{status:?}");
    }

    #[tokio::test]
    async fn published_ports_are_harvested_from_starting_onwards() {
        let port = satl_core::PortConfig {
            name: "http".to_owned(),
            protocol: satl_core::PortProtocol::Tcp,
            target_port: 80,
            published_port: 8080,
            publish_mode: satl_core::PublishMode::Host,
        };
        let mut ctlr = MockController::ok();
        ctlr.ports = vec![port.clone()];
        let step = run_step(TaskState::Starting, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert_eq!(status.state, TaskState::Running);
        assert_eq!(status.port_status, [port]);

        // ...but not below STARTING.
        let mut ctlr = MockController::ok();
        ctlr.ports = vec![satl_core::PortConfig {
            name: "http".to_owned(),
            protocol: satl_core::PortProtocol::Tcp,
            target_port: 80,
            published_port: 8080,
            publish_mode: satl_core::PublishMode::Host,
        }];
        let step = run_step(TaskState::Accepted, DesiredState::Running, &mut ctlr).await;
        let Step::Advanced(status) = step else {
            panic!("expected a transition, got {step:?}")
        };
        assert!(status.port_status.is_empty());
    }

    #[tokio::test]
    async fn a_regression_is_refused_instead_of_panicking() {
        // Contrived: a controller whose status is already past the target.
        // SwarmKit panics here; SatL logs and no-ops (architecture §4 rule 1).
        let mut ctlr = MockController::ok();
        let task = task_at(DesiredState::Shutdown);
        let status = TaskStatus::new(TaskState::Running, "");
        // Shutdown from RUNNING is a legal advance...
        assert!(matches!(
            do_step(&task, &status, &mut ctlr).await,
            Step::Advanced(_)
        ));
        // ...and from a terminal state it is a no-op, never a regression.
        let status = TaskStatus::new(TaskState::Failed, "");
        assert_eq!(do_step(&task, &status, &mut ctlr).await, Step::Noop);
    }
}
