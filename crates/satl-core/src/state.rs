// SPDX-License-Identifier: BSD-2-Clause
//! Task state machine — adopted from SwarmKit verbatim (architecture §4,
//! SWK §4.2), including the sparse numeric values so the ordering is explicit
//! and new intermediate states remain possible.
//!
//! Task states form a monotonic total order (a Lamport clock): given two
//! observations of the same task, the greater is authoritative, and observed
//! state never decreases. Regressions are rejected with a typed error
//! ([`InvalidTransition`]) rather than a panic.

use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::InvalidTransition;
use crate::id::Id;

/// Host-level bound port observed by the agent — same shape as an endpoint
/// [`PortConfig`](crate::objects::PortConfig) (SWK §4.4).
pub type PortStatus = crate::objects::PortConfig;

/// Observed task state (architecture §4).
///
/// Discriminants are deliberately sparse (SwarmKit's exact values); the
/// derived ordering follows the numeric value because variants are declared
/// in ascending discriminant order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum TaskState {
    /// Task object created (written by the orchestrator).
    New = 0,
    /// Resources allocated, awaiting scheduling (written by the allocator).
    Pending = 64,
    /// Node chosen, or preassigned node validated (written by the scheduler).
    Assigned = 192,
    /// Agent accepted the task (controller resolved).
    Accepted = 256,
    /// Preparing: pulling image, cloning layers, creating the jail.
    Preparing = 320,
    /// Prepared; a start would execute immediately.
    Ready = 384,
    /// Start in progress.
    Starting = 448,
    /// Started — and healthy, if a healthcheck is configured.
    Running = 512,
    /// Exited with code 0.
    Complete = 576,
    /// Requested shutdown completed.
    Shutdown = 640,
    /// Execution failed: non-zero exit or execution error.
    Failed = 704,
    /// Never ran — environment problem (written by the agent or the
    /// manager-side constraint enforcer).
    Rejected = 768,
    /// Desired-state-only marker: shut down, then delete (architecture §4
    /// rule 5). Never a legal *observed* state.
    Remove = 800,
    /// Node down too long; frees resources without deleting the task
    /// (written by the manager).
    Orphaned = 832,
}

impl TaskState {
    /// The sparse numeric value of this state (SWK §4.2 table).
    #[must_use]
    pub fn value(self) -> u16 {
        self as u16
    }

    /// Monotonicity guard (architecture §4 rule 1): returns `proposed` if it
    /// does not regress from `current`, otherwise a typed error. Re-reporting
    /// the same state is allowed (idempotent status re-delivery).
    ///
    /// Desired-state-only handling (e.g. observed `Remove` being illegal) is
    /// enforced by the store write path, not here.
    pub fn advance(current: Self, proposed: Self) -> Result<Self, InvalidTransition> {
        if proposed < current {
            Err(InvalidTransition {
                from: current,
                to: proposed,
            })
        } else {
            Ok(proposed)
        }
    }

    /// Whether this state is terminal from the agent's perspective (SWK §4.2):
    /// `Complete`, `Shutdown`, `Failed`, `Rejected`, or `Orphaned`.
    ///
    /// `Remove` is excluded: it is a desired-state marker, never observed.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Shutdown | Self::Failed | Self::Rejected | Self::Orphaned
        )
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::New => "new",
            Self::Pending => "pending",
            Self::Assigned => "assigned",
            Self::Accepted => "accepted",
            Self::Preparing => "preparing",
            Self::Ready => "ready",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Shutdown => "shutdown",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Remove => "remove",
            Self::Orphaned => "orphaned",
        };
        f.write_str(name)
    }
}

/// Target state for a task, written only by manager components and never
/// decreased (architecture §4 rule 3, SWK §4.3).
///
/// Restricted to the five values SwarmKit allows as desired states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    /// Prepare but don't start (replacement tasks awaiting promotion).
    Ready,
    /// Normal target for service tasks.
    Running,
    /// Run to successful completion. Unused as a *desired* state: a job's
    /// task keeps desired `Running` and is observed `Complete` (SWK §4.3).
    Complete,
    /// Graceful stop requested.
    Shutdown,
    /// Shut down, then delete via the task reaper.
    Remove,
}

impl DesiredState {
    /// The equivalent point on the [`TaskState`] scale, for comparisons
    /// against observed state.
    #[must_use]
    pub fn as_task_state(self) -> TaskState {
        match self {
            Self::Ready => TaskState::Ready,
            Self::Running => TaskState::Running,
            Self::Complete => TaskState::Complete,
            Self::Shutdown => TaskState::Shutdown,
            Self::Remove => TaskState::Remove,
        }
    }
}

impl fmt::Display for DesiredState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_task_state().fmt(f)
    }
}

/// Observed status of a task, reported by the agent and stamped by the
/// manager on store write (architecture §4, SWK §4.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskStatus {
    /// When this status was produced (set on every status change).
    pub timestamp: SystemTime,
    /// The observed state.
    pub state: TaskState,
    /// Human-readable note on the transition (e.g. "started").
    pub message: String,
    /// Companion error — set for `Failed`/`Rejected`; user-facing messages
    /// belong here, routine transitions in `message`.
    pub err: Option<String>,
    /// Jail-level runtime status, once known.
    pub container: Option<ContainerStatus>,
    /// Host-level bound ports.
    pub port_status: Vec<PortStatus>,
    /// Which manager wrote this status into the store (skew-free clock
    /// source together with `applied_at`).
    pub applied_by: Option<Id>,
    /// When the manager wrote this status into the store (manager clock).
    pub applied_at: Option<SystemTime>,
}

impl TaskStatus {
    /// A fresh status observed now, with no runtime details yet.
    #[must_use]
    pub fn new(state: TaskState, message: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now(),
            state,
            message: message.into(),
            err: None,
            container: None,
            port_status: Vec::new(),
            applied_by: None,
            applied_at: None,
        }
    }
}

/// Jail-level runtime status (FreeBSD adaptation of SwarmKit's
/// `ContainerStatus`, SWK §4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerStatus {
    /// The jail name/id — the bare task ID (architecture §3: jail(8) treats
    /// `.` as a hierarchy separator, so dotted task names are not usable).
    pub jail_id: Option<String>,
    /// PID of the jail's main process.
    pub pid: Option<i64>,
    /// Exit code, once the task terminated.
    pub exit_code: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All states in ascending declaration order with their SWK §4.2 values.
    const ALL: [(TaskState, u16); 14] = [
        (TaskState::New, 0),
        (TaskState::Pending, 64),
        (TaskState::Assigned, 192),
        (TaskState::Accepted, 256),
        (TaskState::Preparing, 320),
        (TaskState::Ready, 384),
        (TaskState::Starting, 448),
        (TaskState::Running, 512),
        (TaskState::Complete, 576),
        (TaskState::Shutdown, 640),
        (TaskState::Failed, 704),
        (TaskState::Rejected, 768),
        (TaskState::Remove, 800),
        (TaskState::Orphaned, 832),
    ];

    #[test]
    fn values_match_the_swarmkit_table() {
        for (state, value) in ALL {
            assert_eq!(state.value(), value, "{state}");
        }
    }

    #[test]
    fn ordering_follows_numeric_values_for_all_pairs() {
        for (a, va) in ALL {
            for (b, vb) in ALL {
                assert_eq!(a.cmp(&b), va.cmp(&vb), "{a} vs {b}");
            }
        }
    }

    #[test]
    fn advance_accepts_progress_and_equality() {
        for (i, (current, _)) in ALL.iter().enumerate() {
            for (proposed, _) in &ALL[i..] {
                assert_eq!(
                    TaskState::advance(*current, *proposed),
                    Ok(*proposed),
                    "{current} -> {proposed}"
                );
            }
        }
    }

    #[test]
    fn advance_rejects_every_regression() {
        for (i, (current, _)) in ALL.iter().enumerate() {
            for (proposed, _) in &ALL[..i] {
                assert_eq!(
                    TaskState::advance(*current, *proposed),
                    Err(InvalidTransition {
                        from: *current,
                        to: *proposed,
                    }),
                    "{current} -> {proposed}"
                );
            }
        }
    }

    #[test]
    fn invalid_transition_message_names_both_states() {
        let err = TaskState::advance(TaskState::Running, TaskState::New).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("running"), "{message}");
        assert!(message.contains("new"), "{message}");
    }

    #[test]
    fn terminal_states_match_the_agent_perspective() {
        let terminal = [
            TaskState::Complete,
            TaskState::Shutdown,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
        ];
        for (state, _) in ALL {
            assert_eq!(state.is_terminal(), terminal.contains(&state), "{state}");
        }
        // Remove sits between Rejected and Orphaned numerically but is a
        // desired-state marker, never a terminal observed state.
        assert!(!TaskState::Remove.is_terminal());
    }

    #[test]
    fn desired_state_conversions() {
        let cases = [
            (DesiredState::Ready, TaskState::Ready),
            (DesiredState::Running, TaskState::Running),
            (DesiredState::Complete, TaskState::Complete),
            (DesiredState::Shutdown, TaskState::Shutdown),
            (DesiredState::Remove, TaskState::Remove),
        ];
        for (desired, expected) in cases {
            assert_eq!(desired.as_task_state(), expected);
        }
    }

    #[test]
    fn desired_state_orders_like_task_state() {
        let all = [
            DesiredState::Ready,
            DesiredState::Running,
            DesiredState::Complete,
            DesiredState::Shutdown,
            DesiredState::Remove,
        ];
        for a in all {
            for b in all {
                assert_eq!(
                    a.cmp(&b),
                    a.as_task_state().cmp(&b.as_task_state()),
                    "{a} vs {b}"
                );
            }
        }
    }

    #[test]
    fn serde_uses_snake_case_names() {
        assert_eq!(
            serde_json::to_string(&TaskState::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&DesiredState::Shutdown).unwrap(),
            "\"shutdown\""
        );
        let back: TaskState = serde_json::from_str("\"preparing\"").unwrap();
        assert_eq!(back, TaskState::Preparing);
    }

    #[test]
    fn task_status_roundtrips_through_serde() {
        let mut status = TaskStatus::new(TaskState::Running, "started");
        status.container = Some(ContainerStatus {
            jail_id: Some("1hvy0lj3x0b883f8e30fyp217".to_owned()),
            pid: Some(4242),
            exit_code: None,
        });
        let json = serde_json::to_string(&status).unwrap();
        let back: TaskStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}
