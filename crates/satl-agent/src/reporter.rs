// SPDX-License-Identifier: BSD-2-Clause
//! Where task statuses go once they are persisted.
//!
//! The agent's job ends at "persist, then hand off": whoever implements
//! [`StatusReporter`] owns the coalescing/retry pipeline to the dispatcher
//! (SWK §14.5 — one pending status per task, newer states overwrite,
//! regressions dropped, retry forever, `NotFound` treated as success). That
//! pipeline lives in `satld` because it is session-shaped; keeping it behind
//! this trait is also what makes the task manager unit-testable.
//!
//! Reporting is infallible on purpose: a transport failure must never fail a
//! task, and the local DB already holds the canonical copy to re-report at
//! the next registration (architecture §7.2).

use std::future::Future;

use satl_core::{Id, TaskStatus};

/// Sink for task status updates produced by the agent.
pub trait StatusReporter: Send + Sync + 'static {
    /// Hand `status` for `task_id` to the reporting pipeline.
    ///
    /// Implementations must not block: enqueue and return. Transport errors
    /// are the implementation's problem (retry forever, per SWK §14.5).
    fn report(&self, task_id: &Id, status: TaskStatus) -> impl Future<Output = ()> + Send;
}

/// A reporter that drops everything — for single-node smoke tests and for
/// `satld` before a dispatcher session exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardingReporter;

impl StatusReporter for DiscardingReporter {
    async fn report(&self, task_id: &Id, status: TaskStatus) {
        tracing::debug!(
            task_id = %task_id,
            state = %status.state,
            message = %status.message,
            "status discarded (no dispatcher session)"
        );
    }
}
