// SPDX-License-Identifier: BSD-2-Clause
//! Manager-side reconciliation loops: replicated and global orchestrators,
//! the jobs orchestrator, cluster allocator, restart supervisor, rolling
//! updater, task reaper and the encrypted-overlay keyring.
//! See `docs/architecture.md` §5, SWK §7 and — for the allocator — SWK §9.
//!
//! # Shape
//!
//! The loops are independent and communicate **only through the store and its
//! watch feed** (architecture §5, CLAUDE.md invariant #1): none of them calls
//! another, each watches object events and proposes its own writes back into
//! Raft. Every loop pairs an event-driven fast path with a periodic full pass
//! that re-derives its decisions from store state, so a missed event, a
//! lagged watcher or a lost optimistic-concurrency race is always
//! self-healing rather than fatal. A failed proposal never stops a loop.
//!
//! ```text
//!   service created ──▶ replicated ──▶ Task{NEW}            (slots 1..=replicas)
//!   node joins/leaves ─▶ global    ──▶ Task{NEW, node_id}   (one per eligible node)
//!   job service ───────▶ jobs      ──▶ Task{NEW}            (run to completion:
//!                                        │                   never restarted on success)
//!   network created ──┐                  │
//!   service endpoint ─┼─▶ allocator ─────┴──▶ Task{PENDING}   (satl-sched takes it from here)
//!   task NEW/terminal ┘   (subnet, VNI, addresses, ports — SWK §9)
//!
//!   spec changed    ────▶ update  ────────▶ a batch of slots (or nodes) onto the new spec
//!
//!   task terminated ──┐
//!   node down/drain/  ├─▶ restart ────────▶ old Task{desired SHUTDOWN} + replacement in the same slot
//!   delete            │
//!   node stops        │
//!   matching          ┘
//!   task removed    ────▶ reaper  ────────▶ object deleted, slot history pruned
//!
//!   encrypted network ──▶ keyring ────────▶ Network.keys generated, rotated 12h
//! ```
//!
//! Node-state enforcement (SWK §7.8) and the constraint enforcer (SWK §7.6) are
//! the restart supervisor's second and third *triggers* rather than loops of
//! their own, so that every way of losing a place shares one `max_attempts`
//! budget and one replacement transaction; the `node_enforcer` module holds the
//! (pure) decision rules and the full rationale.
//!
//! # State, and where it lives
//!
//! Every decision in this crate is derived from the store, which is what makes a
//! leadership change a non-event (SWK §7.9): the new leader's first pass reads
//! the same objects and reaches the same conclusions. The rolling updater's
//! progress is in `Service::update_status` and the tasks' `spec_version`; the
//! restart supervisor's `max_attempts` history is the slot's task history itself
//! ([`restart::RestartHistory`]). What the loops keep in memory is only ever a
//! *hint* — a dirty set, a wake-up timer, a "already judged this" guard — whose
//! loss costs one re-derivation and changes no outcome.

mod allocator;
mod dirty;
mod global;
mod jobs;
mod keyring;
mod node_enforcer;
mod propose;
mod reaper;
mod replicated;
mod restart;
mod task;
#[cfg(test)]
mod testing;
mod update;

use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::defaults::{ALLOCATOR_RETRY, REAPER_BATCH};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use task::{AUTOSTART_LABEL, initial_desired_state, new_global_task, new_task};

pub use keyring::{Cadence, PHASE_SETTLE, ROTATE_AFTER};

/// Period of every loop's full reconciliation pass (architecture §5:
/// event-driven with a periodic fallback).
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// Queued reaper items that force an immediate flush (architecture §15).
pub const REAPER_FORCE_AT: usize = 1000;

/// Tunables for the orchestration loops. The defaults are the constants in
/// `docs/architecture.md` §15; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrchestratorConfig {
    /// How often each loop re-derives its decisions from a full store read.
    pub reconcile_interval: Duration,
    /// Task reaper batching window.
    pub reaper_batch: Duration,
    /// Queued reaper items that force an immediate flush.
    pub reaper_force_at: usize,
    /// How often the allocator retries allocations that failed for want of
    /// address space (SWK §9.3). Deallocations retry them immediately.
    pub allocator_retry: Duration,
    /// The encrypted-network keyring's cadence: production defaults
    /// ([`ROTATE_AFTER`]/[`PHASE_SETTLE`]), overridable from satld's config
    /// so a cluster test can watch a full rotation.
    pub keyring_cadence: Cadence,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            reconcile_interval: RECONCILE_INTERVAL,
            reaper_batch: REAPER_BATCH,
            reaper_force_at: REAPER_FORCE_AT,
            allocator_retry: ALLOCATOR_RETRY,
            keyring_cadence: Cadence::default(),
        }
    }
}

/// Handle to the running orchestration loops.
///
/// The loops are leader-only components (architecture §1.2): the caller
/// starts them on leadership gain and cancels the token on leadership loss or
/// shutdown, then awaits [`Orchestrator::join`].
pub struct Orchestrator {
    handles: Vec<JoinHandle<()>>,
}

impl Orchestrator {
    /// Starts the loops with the default configuration.
    pub fn spawn(store: ClusterStore, shutdown: CancellationToken) -> Self {
        Self::spawn_with_config(store, OrchestratorConfig::default(), shutdown)
    }

    /// Starts the loops: replicated and global orchestrators, jobs
    /// orchestrator, allocator, restart supervisor (which also enforces node
    /// state and placement constraints, SWK §7.8 and §7.6), rolling updater,
    /// task reaper and the encrypted-network keyring.
    ///
    /// Each loop runs on its own tokio task and stops when `shutdown` is
    /// cancelled (or when the store closes its watch feed).
    pub fn spawn_with_config(
        store: ClusterStore,
        config: OrchestratorConfig,
        shutdown: CancellationToken,
    ) -> Self {
        tracing::info!(
            reconcile_interval_ms = config.reconcile_interval.as_millis(),
            reaper_batch_ms = config.reaper_batch.as_millis(),
            reaper_force_at = config.reaper_force_at,
            allocator_retry_ms = config.allocator_retry.as_millis(),
            keyring_rotate_after_secs = config.keyring_cadence.rotate_after.as_secs(),
            keyring_phase_settle_secs = config.keyring_cadence.phase_settle.as_secs(),
            "starting orchestration loops"
        );
        let handles = vec![
            tokio::spawn(
                replicated::ReplicatedOrchestrator::new(store.clone(), config.reconcile_interval)
                    .run(shutdown.clone()),
            ),
            tokio::spawn(
                global::GlobalOrchestrator::new(store.clone(), config.reconcile_interval)
                    .run(shutdown.clone()),
            ),
            tokio::spawn(
                jobs::JobsOrchestrator::new(store.clone(), config.reconcile_interval)
                    .run(shutdown.clone()),
            ),
            tokio::spawn(
                keyring::Keyring::new(
                    store.clone(),
                    config.reconcile_interval,
                    config.keyring_cadence,
                )
                .run(shutdown.clone()),
            ),
            tokio::spawn(
                allocator::Allocator::new(
                    store.clone(),
                    config.reconcile_interval,
                    config.allocator_retry,
                )
                .run(shutdown.clone()),
            ),
            tokio::spawn(
                restart::RestartSupervisor::new(store.clone(), config.reconcile_interval)
                    .run(shutdown.clone()),
            ),
            tokio::spawn(
                update::Updater::new(store.clone(), config.reconcile_interval)
                    .run(shutdown.clone()),
            ),
            tokio::spawn(
                reaper::TaskReaper::new(
                    store,
                    config.reaper_batch,
                    config.reaper_force_at,
                    config.reconcile_interval,
                )
                .run(shutdown),
            ),
        ];
        Self { handles }
    }

    /// Waits for every loop to stop. Cancel the token first.
    pub async fn join(self) {
        for handle in self.handles {
            if let Err(err) = handle.await {
                tracing::warn!(error = %err, "orchestration loop did not stop cleanly");
            }
        }
        tracing::info!("orchestration loops stopped");
    }
}
