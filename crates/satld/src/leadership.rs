// SPDX-License-Identifier: BSD-2-Clause
//! Leader-only components: start on leadership gain, stop on leadership loss
//! (architecture §1.2).
//!
//! The orchestrator loops and the scheduler must run on exactly one manager —
//! the leader — or two managers would create replacements for the same slot
//! and bind the same task twice. M1 has a single node, which is leader from
//! the moment `RaftNode::start` returns, so in practice this supervisor
//! starts the loops once and never stops them. It is written as a supervisor
//! anyway because M2's multi-manager cluster changes leadership at runtime,
//! and that must be a configuration change here, not a redesign:
//!
//! ```text
//!   metrics.is_leader  false ──▶ true   spawn Orchestrator + Scheduler
//!                      true  ──▶ false  cancel their token, await their join
//! ```
//!
//! Both components already take a [`CancellationToken`] and expose a `join`,
//! so stopping is orderly: cancel, await, drop. The token this supervisor
//! hands them is a child of the daemon's shutdown token, so a daemon shutdown
//! stops the loops too, whatever the Raft role is.
//!
//! Leadership is polled rather than watched because [`ClusterStore`] exposes
//! point-in-time [`metrics`](ClusterStore::metrics) only; the poll is a
//! `watch::Receiver::borrow` behind the façade — cheap, and M2 can swap it
//! for a real subscription without touching the transitions below.

use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_orchestrator::{Cadence, Orchestrator, OrchestratorConfig};
use satl_sched::Scheduler;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// How often the Raft role is sampled.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The leader-only components, while this node leads.
struct LeaderComponents {
    orchestrator: Orchestrator,
    scheduler: Scheduler,
    /// The root CA rotation reconciler (architecture §12.3): idle while
    /// `Cluster.root_rotation` is empty, so it costs one store read per tick
    /// outside a rotation.
    rotation: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl LeaderComponents {
    fn start(store: &ClusterStore, keyring: Cadence, parent: &CancellationToken) -> Self {
        let cancel = parent.child_token();
        // Every interval but the keyring's is the production default; the
        // keyring cadence is satld's config knob for rotation tests.
        let orchestrator = OrchestratorConfig {
            keyring_cadence: keyring,
            ..OrchestratorConfig::default()
        };
        Self {
            orchestrator: Orchestrator::spawn_with_config(
                store.clone(),
                orchestrator,
                cancel.clone(),
            ),
            scheduler: Scheduler::spawn(store.clone(), cancel.clone()),
            rotation: crate::rotation::spawn_reconciler(store.clone(), cancel.clone()),
            cancel,
        }
    }

    async fn stop(self) {
        self.cancel.cancel();
        self.orchestrator.join().await;
        self.scheduler.join().await;
        if let Err(error) = self.rotation.await {
            tracing::warn!(%error, "the rotation reconciler did not stop cleanly");
        }
    }
}

/// Run the leader-component supervisor until `shutdown` is cancelled.
///
/// Returns a handle the daemon awaits after cancelling, so the loops are
/// stopped before Raft is.
pub fn spawn(
    store: ClusterStore,
    cfg: &crate::config::Config,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    let keyring = cfg.keyring_cadence();
    tokio::spawn(async move {
        let mut running: Option<LeaderComponents> = None;
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let metrics = store.metrics();
                    match (metrics.is_leader, running.is_some()) {
                        (true, false) => {
                            tracing::info!(
                                raft_id = metrics.node_raft_id,
                                term = metrics.term,
                                "leadership gained: starting the leader-only components"
                            );
                            running = Some(LeaderComponents::start(&store, keyring, &shutdown));
                        }
                        (false, true) => {
                            tracing::info!(
                                raft_id = metrics.node_raft_id,
                                term = metrics.term,
                                leader = ?metrics.leader_id,
                                "leadership lost: stopping the leader-only components"
                            );
                            if let Some(components) = running.take() {
                                components.stop().await;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        if let Some(components) = running.take() {
            tracing::info!("shutting down the leader-only components");
            components.stop().await;
        }
    })
}
