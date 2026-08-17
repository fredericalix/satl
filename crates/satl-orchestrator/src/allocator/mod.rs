// SPDX-License-Identifier: BSD-2-Clause
//! The cluster allocator (architecture §5 step 3, §11.3, SWK §9): overlay
//! subnets and VXLAN VNIs on networks, published ports on services, per-task
//! addresses on attachments, and the ballot that promotes a task
//! `NEW → PENDING`.
//!
//! # Shape
//!
//! Like every loop in this crate: watch the store, re-derive everything from a
//! full view, propose. The decision itself is one pure function, [`plan::plan`]
//! — see its docs for the two-phase restore-then-allocate walk that keeps a new
//! leader from re-handing-out an in-use subnet, VNI or address (SWK §9.2).
//!
//! ```text
//!   network created ──▶ subnet + VNI on the Network
//!   service created ──▶ published ports on Service.endpoint
//!   task NEW        ──▶ attachments + addresses, endpoint copy, ballot ──▶ PENDING
//!   task scheduled  ──▶ its node's gateway address on Network.node_gateways
//!   task terminal   ──▶ addresses released
//!   node's last task on a network gone ──▶ its gateway address released
//!   endpoint spec removed / network deleted ──▶ ports and subnets freed
//! ```
//!
//! # Retry discipline (SWK §9.3)
//!
//! An allocation that fails — the pool is full, a requested subnet overlaps —
//! must not be retried on every watch event: that would fill the log with the
//! same error thousands of times. Failed objects are **deferred**, keyed by the
//! version they failed at, and retried:
//!
//! - immediately, if the object is edited (the version moves, so the deferral
//!   no longer matches): fixing the spec takes effect at once;
//! - immediately after any **deallocation**, in this pass or in an observed
//!   removal — freed space may be exactly what was missing;
//! - otherwise every [`ALLOCATOR_RETRY`](satl_core::defaults::ALLOCATOR_RETRY)
//!   (5 min).
//!
//! # Cost
//!
//! Every pass reads all networks, services and tasks and rebuilds the address
//! spaces from them — the same full-scan shape as the other loops in this
//! crate, and what makes the restore phase impossible to skip. TODO(M4): with a
//! service→tasks index in the store (architecture §6.1) and per-object work
//! queues (SWK §9.3's `pendingStates`), a commit that only reports one task's
//! status would stop costing a full walk.
//!
//! # What is deliberately not here
//!
//! - **VIPs.** SwarmKit allocates one virtual IP per service per network
//!   (SWK §9.1). SatL resolves services by DNS round-robin instead — FreeBSD
//!   has no IPVS (architecture §11.5) — so there is nothing to allocate.
//! - **Node load-balancer attachments** as SwarmKit shapes them (SWK §9.1,
//!   §9.3): a full `NetworkAttachment` per node, on the `Node` object, carrying
//!   the VIPs above, plus the ingress network auto-attachment that goes with
//!   them. v1 publishes ingress ports with a per-node pf redirect to local
//!   tasks (architecture §11.4), so a task needs no ingress attachment, and the
//!   routing mesh is M6.
//!
//!   What SatL does keep is the *reason* that allocation exists per node: one
//!   overlay network in use on a node needs one address of its own there. Ours
//!   is that reduced to a single address — the node's gateway on the network,
//!   held in `Network.node_gateways` — because the gateway has to live on every
//!   participating node's bridge, is the tasks' default route and is what their
//!   DNS responder binds to (`docs/vxlan.md` §8). One cluster-wide gateway
//!   address is a duplicate address on one L2 segment; it was measured taking
//!   over another node's DNS and egress.
//! - **Bridge networks.** Node-local by definition (architecture §11.1): their
//!   subnets come from each node's own IPAM, not from Raft. Attachments to them
//!   are recorded, without a cluster address.

mod error;
mod plan;
mod ports;
mod space;

use std::collections::BTreeMap;
use std::time::Duration;

use satl_cluster::ClusterStore;
use satl_core::{Id, ObjectKind, StoreEvent, StoreObject, Version};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::propose::propose_with_retry;

use plan::{Deferred, PlanInput};

/// How many times a pass re-runs within one wake-up after freeing space.
///
/// A pass that deallocates something retries the deferred objects at once
/// instead of waiting for the retry window. That converges after one extra
/// pass in practice (the second frees nothing), so the cap only exists to keep
/// a pathological store from monopolising the loop — the next tick or watch
/// event continues the work.
const MAX_PASSES_PER_WAKEUP: u32 = 4;

/// Allocates cluster network resources and votes tasks into `PENDING`.
pub(crate) struct Allocator {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Period at which deferred (failed) allocations are retried.
    retry: Duration,
    /// Whether an object the allocator cares about changed since the last
    /// commit marker.
    dirty: bool,
    /// Objects deferred by an earlier pass (SWK §9.3).
    deferred: Deferred,
}

impl Allocator {
    pub(crate) fn new(store: ClusterStore, interval: Duration, retry: Duration) -> Self {
        Self {
            store,
            interval,
            retry,
            dirty: false,
            deferred: BTreeMap::new(),
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.allocator");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut retry = tokio::time::interval(self.retry);
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The retry ticker's first tick is immediate and coincides with the
            // first full pass; there is nothing deferred yet, so it is a no-op.
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    // The first tick fires immediately: that is the initial
                    // full pass, which is also the leader-start restore
                    // (SWK §9.2).
                    _ = ticker.tick() => self.allocate().await,
                    _ = retry.tick() => {
                        if !self.deferred.is_empty() {
                            tracing::debug!(
                                deferred = self.deferred.len(),
                                "retrying deferred allocations"
                            );
                            self.deferred.clear();
                            self.allocate().await;
                        }
                    }
                    event = events.recv() => match event {
                        Ok(event) => self.observe(event).await,
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full pass");
                            self.dirty = false;
                            // Missed events may have removed objects, so
                            // whatever was deferred deserves another try.
                            self.deferred.clear();
                            self.allocate().await;
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("allocator stopped");
        }
        .instrument(span))
        .await;
    }

    /// Notes what a transaction touched and allocates once its commit marker
    /// arrives.
    ///
    /// Cluster, network and service writes also clear the deferred set: they
    /// are operator actions (a new network, a wider pool, a deleted service),
    /// and each one can be exactly what a deferred allocation was missing.
    /// Task writes do not — there are thousands of them, and a task deferred
    /// for its own sake is retried when *its* version moves.
    async fn observe(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => match object {
                StoreObject::Cluster(_) | StoreObject::Network(_) | StoreObject::Service(_) => {
                    self.deferred.clear();
                    self.dirty = true;
                }
                StoreObject::Task(_) => self.dirty = true,
                _ => {}
            },
            StoreEvent::Removed { kind, id: _ } => {
                if matches!(
                    kind,
                    ObjectKind::Network | ObjectKind::Service | ObjectKind::Task
                ) {
                    // A removal frees whatever the object held, which may be
                    // what a deferred allocation was waiting for (SWK §9.3).
                    self.deferred.clear();
                    self.dirty = true;
                }
            }
            StoreEvent::Commit(_) => {
                if std::mem::take(&mut self.dirty) {
                    self.allocate().await;
                }
            }
        }
    }

    /// One restore-then-allocate pass, plus an immediate re-run whenever the
    /// pass freed space (SWK §9.3).
    async fn allocate(&mut self) {
        for _ in 0..MAX_PASSES_PER_WAKEUP {
            if !self.pass().await {
                break;
            }
            // Something was released: retry everything that was deferred.
            self.deferred.clear();
        }
    }

    /// Runs the planner against a fresh view and proposes its actions. Returns
    /// whether the pass freed anything.
    async fn pass(&mut self) -> bool {
        let deferred = std::mem::take(&mut self.deferred);
        let mut outcome = Outcome::default();
        let result = propose_with_retry(&self.store, "allocate", |view| {
            let cluster = view.cluster();
            let networks = view.networks();
            let services = view.services();
            let tasks = view.tasks();
            let nodes = view.nodes();
            let plan = plan::plan(
                &PlanInput {
                    cluster: cluster.as_deref(),
                    networks: &networks,
                    services: &services,
                    tasks: &tasks,
                    nodes: &nodes,
                },
                &deferred,
            );
            outcome = Outcome {
                failures: plan.failures,
                freed: plan.freed,
            };
            plan.actions
        })
        .await;

        // A proposal that did not commit changed nothing, so nothing was freed
        // either; the failures the last attempt observed still stand, and the
        // next pass re-derives the rest.
        let committed = match result {
            Ok(_) => true,
            Err(err) => {
                // Never fatal (architecture §5): the periodic pass retries.
                tracing::warn!(error = %err, "allocation transaction not committed");
                false
            }
        };
        for failure in &outcome.failures {
            tracing::warn!(
                kind = %failure.kind,
                id = %failure.id,
                name = %failure.name,
                error = %failure.error,
                "allocation failed; deferred until the next deallocation or retry window"
            );
        }
        self.deferred = outcome
            .failures
            .iter()
            .map(|failure| (failure.id.clone(), failure.version))
            .collect::<BTreeMap<Id, Version>>();
        committed && outcome.freed
    }
}

/// What the last planning attempt of a pass decided, minus the actions.
#[derive(Debug, Default)]
struct Outcome {
    failures: Vec<plan::Failure>,
    freed: bool,
}

#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod tests;
