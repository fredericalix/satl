// SPDX-License-Identifier: BSD-2-Clause
//! Scheduler: filter pipeline and placement (SWK §8).
//! See `docs/architecture.md` §5.
//!
//! The scheduler is one of the manager's leader-only loops
//! (architecture §1.2). It consumes the store watch feed, keeps an in-memory
//! mirror of nodes and of the tasks waiting for one, and writes back exactly
//! one thing: the node a task was bound to, with observed state `ASSIGNED`.
//! Like every other control-plane loop it talks to the rest of the manager
//! only through the store (CLAUDE.md invariant #1).
//!
//! The parts, all of them SwarmKit's (SWK §8):
//!
//! - [`node_info`] — the per-node bookkeeping every decision reads: available
//!   resources, active task counts, bound host ports, recent failures;
//! - [`filters`] — the ordered filter pipeline and the explanations it
//!   produces;
//! - [`placement`] — the node comparator (spread + fault penalty) and
//!   round-robin placement;
//! - the loop itself, which feeds them from the watch feed and commits their
//!   decisions.
//!
//! Filters, ranking and placement are **pure**: they take nodes and tasks,
//! never a store handle, which is what keeps them unit-testable against
//! synthetic clusters. Placement preferences (SWK §8.5) are deferred by
//! architecture §14.

pub mod filters;
pub mod node_info;
pub mod placement;
mod scheduler;
#[cfg(test)]
mod testing;

use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::defaults::{SCHEDULER_DEBOUNCE, SCHEDULER_DEBOUNCE_MAX};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use filters::{
    ConstraintFilter, Filter, HostPortFilter, MaxReplicasFilter, NodeReadyFilter, Pipeline,
    PlacementRequirements, PlatformFilter, ResourceFilter, accepts_new_tasks,
};
pub use node_info::{HostPort, NodeInfo, TaskGroup};
pub use placement::{Assignment, compare_nodes, place_group};

/// Tunables for the scheduling batch (SWK §8.2). The defaults are the
/// constants in `docs/architecture.md` §15; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Quiet time after a commit before a batch runs.
    pub debounce: Duration,
    /// Longest a batch may be delayed by a stream of commits.
    pub max_debounce: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            debounce: SCHEDULER_DEBOUNCE,
            max_debounce: SCHEDULER_DEBOUNCE_MAX,
        }
    }
}

/// Handle to the running scheduler loop.
pub struct Scheduler {
    handle: JoinHandle<()>,
}

impl Scheduler {
    /// Starts the scheduler with the default configuration.
    pub fn spawn(store: ClusterStore, shutdown: CancellationToken) -> Self {
        Self::spawn_with_config(store, SchedulerConfig::default(), shutdown)
    }

    /// Starts the scheduler; it stops when `shutdown` is cancelled (or when
    /// the store closes its watch feed).
    pub fn spawn_with_config(
        store: ClusterStore,
        config: SchedulerConfig,
        shutdown: CancellationToken,
    ) -> Self {
        tracing::info!(
            debounce_ms = config.debounce.as_millis(),
            max_debounce_ms = config.max_debounce.as_millis(),
            "starting scheduler"
        );
        let handle = tokio::spawn(
            scheduler::SchedulerLoop::new(store, config.debounce, config.max_debounce)
                .run(shutdown),
        );
        Self { handle }
    }

    /// Waits for the loop to stop. Cancel the token first.
    pub async fn join(self) {
        if let Err(err) = self.handle.await {
            tracing::warn!(error = %err, "scheduler did not stop cleanly");
        }
        tracing::info!("scheduler stopped");
    }
}
