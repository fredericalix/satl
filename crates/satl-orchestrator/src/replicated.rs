// SPDX-License-Identifier: BSD-2-Clause
//! The replicated-service reconciliation loop (SWK §7.8, M1 subset).
//!
//! Desired state in, tasks out: for every replicated service, slots
//! `1..=replicas` must each hold a task. The loop is driven by the store
//! watch feed — reconciling every service touched by a committed transaction
//! — with a periodic full pass as the self-healing fallback (missed events,
//! lagged watcher, a proposal that lost too many races).
//!
//! What it does:
//!
//! - **scale up / fill**: create tasks for the lowest free slot numbers, with
//!   SWK §7.1 `NewTask` semantics (see [`crate::task::new_task`]);
//! - **scale down**: give up whole slots, in SwarmKit's order — running slots
//!   last, most-loaded node first, highest slot number on a tie (see
//!   [`crate::task::slots_to_remove`]);
//! - **service deleted**: every task of the service gets desired `Remove`.
//!
//! What it deliberately does *not* do:
//!
//! - it never resurrects a slot that still holds stopped tasks — that is the
//!   restart supervisor's decision (see [`crate::task::classify_slot`]);
//! - it never *replaces* a task: bringing a slot onto a new spec is the rolling
//!   updater's job ([`crate::update`], SWK §7.2/§7.3), which is a separate loop
//!   for the same reason as the restart supervisor. The two never collide,
//!   because this loop counts occupied *slots* and the updater works inside
//!   one;
//! - it does not reconcile **global** services: they have no replica count and
//!   their unit is the node, so [`crate::global`] owns them (SWK §7.8). Nor
//!   **job** services, which run to completion under [`crate::jobs`]. The one
//!   thing this loop still does for every mode is the orphan sweep — the tasks
//!   of a service that is gone are marked for removal here, whatever their mode.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use satl_cluster::{ClusterStore, StoreView};
use satl_core::defaults::MAX_TX_ACTIONS;
use satl_core::{
    DesiredState, Id, ObjectKind, ServiceMode, StoreAction, StoreEvent, StoreObject, Task,
};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::propose::propose_with_retry;
use crate::task::{
    free_slots, group_by_slot, is_removing, new_task, occupied_slots, raise_desired_state,
    slots_to_remove,
};

/// Reconciles replicated services against their tasks.
pub(crate) struct ReplicatedOrchestrator {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Services touched since the last commit marker.
    dirty: BTreeSet<Id>,
    /// Task ID to owning service ID. A `Removed` event carries only the ID,
    /// and the object is already gone from the store, so the owner has to be
    /// remembered from the event that introduced the task.
    task_owner: HashMap<Id, Id>,
}

impl ReplicatedOrchestrator {
    pub(crate) fn new(store: ClusterStore, interval: Duration) -> Self {
        Self {
            store,
            interval,
            dirty: BTreeSet::new(),
            task_owner: HashMap::new(),
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.replicated");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    // The first tick fires immediately: that is the initial
                    // full pass (also the leader-change replay, SWK §7.9).
                    _ = ticker.tick() => self.full_pass().await,
                    event = events.recv() => match event {
                        Ok(event) => self.observe(event).await,
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full pass");
                            self.dirty.clear();
                            self.full_pass().await;
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("replicated orchestrator stopped");
        }
        .instrument(span))
        .await;
    }

    /// Accumulates the services a transaction touched, reconciling them when
    /// its commit marker arrives (SWK §7.8 reconciles per commit).
    async fn observe(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => match object {
                StoreObject::Service(service) => {
                    self.dirty.insert(service.id.clone());
                }
                StoreObject::Task(task) => {
                    if let Some(service_id) = task.service_id.clone() {
                        self.task_owner.insert(task.id.clone(), service_id.clone());
                        self.dirty.insert(service_id);
                    }
                }
                _ => {}
            },
            StoreEvent::Removed { kind, id } => match kind {
                // A removed service leaves its tasks behind.
                ObjectKind::Service => {
                    self.dirty.insert(id);
                }
                // A removed task may have emptied its slot.
                ObjectKind::Task => {
                    if let Some(service_id) = self.task_owner.remove(&id) {
                        self.dirty.insert(service_id);
                    }
                }
                _ => {}
            },
            StoreEvent::Commit(_) => {
                for service_id in std::mem::take(&mut self.dirty) {
                    reconcile(&self.store, &service_id).await;
                }
            }
        }
    }

    /// Reconciles every service, plus the services referenced by orphan
    /// tasks (their service object is gone — their tasks must be removed).
    async fn full_pass(&mut self) {
        let targets: BTreeSet<Id> = {
            let view = self.store.view();
            let mut targets: BTreeSet<Id> = view.services().iter().map(|s| s.id.clone()).collect();
            targets.extend(
                view.tasks()
                    .iter()
                    .filter_map(|t| t.service_id.clone())
                    .filter(|id| view.service(id).is_none()),
            );
            targets
        };
        tracing::debug!(services = targets.len(), "full reconciliation pass");
        for service_id in targets {
            reconcile(&self.store, &service_id).await;
        }
    }
}

/// Reconciles one service, retrying its decision on sequence conflicts.
async fn reconcile(store: &ClusterStore, service_id: &Id) {
    let result = propose_with_retry(store, "replicated reconcile", |view| {
        reconcile_actions(view, service_id)
    })
    .await;
    if let Err(err) = result {
        // Never fatal: the periodic pass re-derives the same decision.
        tracing::warn!(service_id = %service_id, error = %err, "reconciliation deferred");
    }
}

/// Derives the store transaction that brings one service's tasks in line
/// with its spec. Pure and idempotent: an already-reconciled service yields
/// no actions.
fn reconcile_actions(view: &StoreView<'_>, service_id: &Id) -> Vec<StoreAction> {
    // TODO(M2): the store has no service→tasks index yet (architecture §6.1
    // lists one), so this is a full scan per reconcile. Fine at M1 scale.
    let tasks: Vec<Arc<Task>> = view
        .tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .collect();

    let Some(service) = view.service(service_id) else {
        return remove_all(&tasks, service_id);
    };
    let ServiceMode::Replicated { replicas } = service.spec.mode else {
        // One task per node, not per slot: [`crate::global`]'s business.
        return Vec::new();
    };

    let slots = group_by_slot(&tasks);
    let occupied = occupied_slots(&slots);
    let doomed = slots_to_remove(&slots, &occupied, replicas);
    let mut actions = Vec::new();

    // Scale down first, because it decides how many slots survive and
    // therefore how many the fill below must create. Removal is by *slot*, in
    // SwarmKit's order (see `slots_to_remove`) rather than by slot number.
    for slot in &doomed {
        for task in slots.get(slot).into_iter().flatten() {
            if let Some(action) = raise_desired_state(task, DesiredState::Remove) {
                tracing::info!(
                    service_id = %service.id,
                    task_id = %task.id,
                    slot,
                    node_id = ?task.node_id,
                    from = %task.desired_state,
                    to = %DesiredState::Remove,
                    "removing task from a scaled-down slot"
                );
                actions.push(action);
            }
        }
    }

    // Scale up / fill: one task per slot still missing, in the lowest free
    // slot numbers.
    let kept = u64::try_from(occupied.len().saturating_sub(doomed.len())).unwrap_or(u64::MAX);
    for slot in free_slots(&occupied, replicas.saturating_sub(kept), MAX_TX_ACTIONS) {
        let task = new_task(&service, slot);
        tracing::info!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            task_id = %task.id,
            slot,
            desired = %task.desired_state,
            "creating task"
        );
        actions.push(StoreAction::Create(StoreObject::Task(task)));
    }

    actions.truncate(MAX_TX_ACTIONS);
    actions
}

/// The service is gone: mark every task of it for removal (SWK §7.1
/// `SetServiceTasksRemove`). The reaper deletes them once they are stopped
/// — resources are never released while a jail might still run
/// (architecture §4 rule 5).
fn remove_all(tasks: &[Arc<Task>], service_id: &Id) -> Vec<StoreAction> {
    let mut actions = Vec::new();
    for task in tasks.iter().filter(|task| !is_removing(task)) {
        if let Some(action) = raise_desired_state(task, DesiredState::Remove) {
            tracing::info!(
                service_id = %service_id,
                task_id = %task.id,
                slot = task.slot,
                from = %task.desired_state,
                to = %DesiredState::Remove,
                "removing task of a deleted service"
            );
            actions.push(action);
        }
    }
    actions.truncate(MAX_TX_ACTIONS);
    actions
}
