// SPDX-License-Identifier: BSD-2-Clause
//! The jobs loop: run-to-completion services (Docker's `ReplicatedJob` and
//! `GlobalJob`, SWK §3.4; the orchestration half of SWK §7.8's job
//! reconcilers, deferred until now by architecture §14).
//!
//! A replicated or global service is kept alive forever; a **job** runs to
//! completion. That inverts two rules the other loops live by:
//!
//! - a task exiting 0 (`COMPLETE`) is a **success**, never restarted,
//!   anywhere — the restart supervisor deliberately skips job tasks
//!   ([`crate::restart`]), so this loop owns the job lifecycle (the one
//!   exception being the replicated loop's orphan sweep, which marks the
//!   tasks of a *deleted* service for removal whatever their mode);
//! - a task that *failed* is retried here, in the same slot, within the
//!   restart policy's `max_attempts` budget — the same budget derivation the
//!   supervisor uses (the slot's task history *is* the counter), minus the
//!   delay queue: a job has no caller to pace, so a retry is created as soon
//!   as the failure is observed.
//!
//! Level-triggered like its siblings: every pass re-derives the whole
//! decision from the store and an already-converged job costs one read and no
//! writes. The unit of work is a **slot** for a replicated job (`1..=
//! total_completions`, exactly like [`crate::replicated`]) or a **node** for
//! a global one (one run per eligible node, the eligibility rules of
//! [`crate::global`] reused unchanged).
//!
//! # The per-unit verdict
//!
//! From the tasks of one slot (or node), newest current-spec task first:
//!
//! - a `COMPLETE` current-spec task ⇒ the unit is **done**, forever (for this
//!   spec version);
//! - a live current-spec task, or a still-draining old-spec one ⇒ **busy**:
//!   nothing to do but wait (the old-spec task is ordered to stop, and a slot
//!   starts its new run only once nothing live remains in it);
//! - a newest current-spec task that ended any other way ⇒ **retry** if
//!   [`crate::restart::decide`] allows it under the policy's budget, else the
//!   unit is **exhausted** — the job has failed there, which is logged
//!   clearly and exactly once per spec version;
//! - no current-spec task at all ⇒ **fresh**: the unit has never run under
//!   this spec and gets a task, budget permitting.
//!
//! `max_concurrent` caps the tasks that are live *across the whole service*
//! (desired ≤ `RUNNING`, observed not terminal); when one completes or fails
//! into a retry, the freed place starts the lowest not-yet-complete slot.
//! Both `max_concurrent` and `total_completions` default to 1.
//!
//! # A spec update re-runs the job
//!
//! That is the whole point of updating a job, and it falls out of the store's
//! own bookkeeping: a spec change bumps [`Service::spec_version`], which
//! turns every existing task *stale* — live stale tasks are ordered to stop,
//! and once a unit holds nothing live it starts over from the current spec.
//! There is no rolling semantics and no `update_status`: the rolling updater
//! skips job services entirely ([`crate::update`]).
//!
//! # Deliberate gaps (v1)
//!
//! - `Restart.Window` is not honoured: the attempt count is the slot's
//!   lifetime, not a rate. The budget still comes from the store.
//! - A constraint change (SWK §7.6) does not evict a replicated job's task;
//!   a node that is `DOWN`, draining or gone does — the task is stopped and
//!   retried elsewhere without waiting for a report that will never come,
//!   the same reading the restart supervisor makes for keep-alive services.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use satl_cluster::{ClusterStore, StoreView};
use satl_core::defaults::MAX_TX_ACTIONS;
use satl_core::{
    DesiredState, Id, ObjectKind, Service, ServiceMode, StoreAction, StoreEvent, StoreObject, Task,
    TaskState, Version,
};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::global::{NodeVerdict, node_verdict};
use crate::node_enforcer::evict_reason;
use crate::propose::propose_with_retry;
use crate::restart::{self, RestartDecision};
use crate::task::{is_global_task, is_removing, new_global_task, new_task, raise_desired_state};

/// What one unit of a job is — a slot for a replicated job, a node for a
/// global one, encoded the way [`crate::update`] encodes it.
type Unit = (u64, Option<Id>);

/// The unit `task` belongs to, or `None` when it belongs to none (a global
/// task that was never bound to a node).
fn unit_of(task: &Task) -> Option<Unit> {
    if is_global_task(task) {
        return Some((task.slot, Some(task.node_id.clone()?)));
    }
    Some((task.slot, None))
}

/// The tasks of one unit, bucketed the way the verdicts read them.
#[derive(Default)]
struct UnitView {
    /// Live tasks stamped from the current spec (desired ≤ `RUNNING`,
    /// observed not terminal). More than one is only ever a race this loop
    /// refuses to make worse.
    live: Vec<Arc<Task>>,
    /// Live tasks on an older spec: an update re-runs the job, so these are
    /// ordered to stop and keep their place until they are gone.
    stale: Vec<Arc<Task>>,
    /// Ordered to stop (either spec) and not reported terminal yet.
    stopping: Vec<Arc<Task>>,
    /// Terminal current-spec tasks, oldest first — the unit's run history
    /// under this spec, and therefore its restart budget.
    terminal: Vec<Arc<Task>>,
}

/// The per-unit verdict (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitState {
    /// Newest current-spec run exited 0.
    Done,
    /// A live task or a draining old run: wait.
    Busy,
    /// Newest run failed; the budget allows a retry.
    Retry,
    /// Newest run failed and the budget is spent.
    Exhausted,
    /// Never started under the current spec.
    Fresh,
}

/// Buckets one unit's tasks and reads its verdict.
///
/// `policy` is the service's restart policy — jobs force `on-failure`
/// semantics at the API boundary, and this loop honours whatever is stored
/// (a `Complete` is a success under every condition but `any`, and `any`
/// never reaches the store for a job).
fn unit_state(policy: &satl_core::RestartPolicy, view: &UnitView) -> UnitState {
    if !view.live.is_empty() || !view.stale.is_empty() || !view.stopping.is_empty() {
        return UnitState::Busy;
    }
    let Some(newest) = view.terminal.last() else {
        return UnitState::Fresh;
    };
    if newest.status.state == TaskState::Complete {
        return UnitState::Done;
    }
    // The restarts this unit already had, derived the way the restart
    // supervisor derives them: the unit's first task is the original run,
    // every later one is a retry (see `restart::RestartHistory`). The
    // reaper's per-slot retention (`max_attempts + 1`) is exactly the count
    // at which the budget is spent, so pruning never hands budget back.
    let attempts = view.terminal.len().saturating_sub(1) as u64;
    match restart::decide(policy, newest.status.state, attempts) {
        RestartDecision::Restart => UnitState::Retry,
        RestartDecision::ConditionNotMet | RestartDecision::AttemptsExhausted => {
            UnitState::Exhausted
        }
    }
}

/// What one pass decided for one job.
#[derive(Default)]
struct Decision {
    /// The transaction to propose; empty means "nothing to do".
    actions: Vec<StoreAction>,
    /// The spec version the decision was derived against (a log key).
    spec_version: Version,
    /// Units whose newest run failed past the restart budget.
    exhausted: Vec<Unit>,
    /// The units of a job that just finished: every one of them `Done`.
    completed: Option<usize>,
}

/// The log-worthy half of a [`Decision`], lifted out of the proposal
/// closure so the loop can dedup it.
struct Notes {
    /// The spec version the decision was derived against.
    spec_version: Version,
    /// Units whose newest run failed past the restart budget.
    exhausted: Vec<Unit>,
    /// Set when every unit of the job is `Done`.
    completed: Option<usize>,
}

impl Decision {
    /// The notes, cloned out (a handful of units, and only on passes that
    /// ran at all).
    fn notes(&self) -> Notes {
        Notes {
            spec_version: self.spec_version,
            exhausted: self.exhausted.clone(),
            completed: self.completed,
        }
    }
}

/// The shape a job is reconciled against: which units must complete, and how
/// many tasks may be live at once.
struct Shape {
    /// The units that owe a completion, in start order.
    wanted: Vec<Unit>,
    /// Cap on simultaneously live tasks (`u64::MAX` for a global job: every
    /// eligible node runs at once by definition).
    max_live: u64,
}

/// The whole decision for one job, once its units are bucketed. Pure and
/// idempotent: a converged job yields no actions.
fn plan_units(service: &Service, shape: &Shape, units: &BTreeMap<Unit, UnitView>) -> Decision {
    let mut decision = Decision {
        spec_version: service.spec_version,
        ..Decision::default()
    };

    // Live tasks keep their concurrency place until they are terminal,
    // whatever spec they are on — and stale ones are ordered to stop: a spec
    // update re-runs the job.
    let mut live = 0usize;
    for view in units.values() {
        live += view.live.len() + view.stale.len();
        for task in &view.stale {
            let Some(action) = raise_desired_state(task, DesiredState::Shutdown) else {
                continue;
            };
            tracing::info!(
                service_id = %service.id,
                service = %service.spec.annotations.name,
                task_id = %task.id,
                slot = task.slot,
                node_id = ?task.node_id,
                from = %task.desired_state,
                to = %DesiredState::Shutdown,
                "job updated: stopping the old run"
            );
            decision.actions.push(action);
        }
    }

    let policy = service.spec.task.restart;
    let states: BTreeMap<&Unit, UnitState> = shape
        .wanted
        .iter()
        .map(|unit| {
            let state = units
                .get(unit)
                .map_or(UnitState::Fresh, |view| unit_state(&policy, view));
            (unit, state)
        })
        .collect();

    // Retries first — a slot already in progress finishes before a fresh one
    // starts — then the lowest fresh units, until the concurrency budget is
    // spent.
    let mut budget = shape
        .max_live
        .saturating_sub(live as u64)
        .min(MAX_TX_ACTIONS as u64);
    for wanted in [UnitState::Retry, UnitState::Fresh] {
        for (unit, state) in &states {
            if *state != wanted || budget == 0 {
                continue;
            }
            budget -= 1;
            decision.actions.push(start_unit(service, unit, *state));
        }
    }

    decision.exhausted = states
        .iter()
        .filter(|(_, state)| **state == UnitState::Exhausted)
        .map(|(unit, _)| (*unit).clone())
        .collect();
    if !states.is_empty() && states.values().all(|state| *state == UnitState::Done) {
        decision.completed = Some(states.len());
    }
    decision.actions.truncate(MAX_TX_ACTIONS);
    decision
}

/// The `Create` action that starts (or retries) one unit, with the line an
/// operator greps for.
fn start_unit(service: &Service, unit: &Unit, state: UnitState) -> StoreAction {
    let (slot, node) = unit;
    let task = match node {
        Some(node_id) => new_global_task(service, node_id),
        None => new_task(service, *slot),
    };
    tracing::info!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        task_id = %task.id,
        slot,
        node_id = ?task.node_id,
        desired = %task.desired_state,
        reason = if state == UnitState::Retry { "retrying a failed run" } else { "starting a run" },
        "creating a job task"
    );
    StoreAction::Create(StoreObject::Task(task))
}

/// Buckets a service's tasks by unit, dropping tasks already marked for
/// removal and the `skip` set (tasks on nodes that can no longer run them —
/// they neither block their unit nor count towards the concurrency budget,
/// because a replacement must not wait for a report that may never come).
fn bucketize(
    tasks: &[Arc<Task>],
    spec_version: Version,
    skip: &HashSet<Id>,
) -> BTreeMap<Unit, UnitView> {
    let mut units: BTreeMap<Unit, UnitView> = BTreeMap::new();
    for task in tasks
        .iter()
        .filter(|task| !is_removing(task) && !skip.contains(&task.id))
    {
        let Some(unit) = unit_of(task) else {
            continue;
        };
        let current = task.spec_version == Some(spec_version);
        let view = units.entry(unit).or_default();
        if !task.status.state.is_terminal() {
            if task.desired_state >= DesiredState::Shutdown {
                view.stopping.push(Arc::clone(task));
            } else if current {
                view.live.push(Arc::clone(task));
            } else {
                view.stale.push(Arc::clone(task));
            }
        } else if current {
            view.terminal.push(Arc::clone(task));
        }
        // A terminal old-spec task is history: the unit's verdict reads only
        // the current spec's runs.
    }
    for view in units.values_mut() {
        view.terminal.sort_by(|a, b| {
            a.meta
                .created_at
                .cmp(&b.meta.created_at)
                .then(a.id.cmp(&b.id))
        });
    }
    units
}

/// Plans one service. `None` (and no work) for anything that is not a job.
fn plan(view: &StoreView<'_>, service_id: &Id) -> Decision {
    let Some(service) = view.service(service_id) else {
        // The orphan sweep belongs to the replicated loop, for every mode.
        return Decision::default();
    };
    let tasks: Vec<Arc<Task>> = view
        .tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .collect();
    match service.spec.mode {
        ServiceMode::ReplicatedJob {
            max_concurrent,
            total_completions,
        } => plan_replicated(view, &service, &tasks, max_concurrent, total_completions),
        ServiceMode::GlobalJob => plan_global(view, &service, &tasks),
        _ => Decision::default(),
    }
}

/// A replicated job: slots `1..=total_completions`, at most `max_concurrent`
/// live at once.
fn plan_replicated(
    view: &StoreView<'_>,
    service: &Service,
    tasks: &[Arc<Task>],
    max_concurrent: Option<u64>,
    total_completions: Option<u64>,
) -> Decision {
    let total = total_completions.unwrap_or(1).max(1);
    let max_live = max_concurrent.unwrap_or(1).max(1);

    // A task whose node is down, draining or gone is as good as dead: order
    // it to stop, and let its unit move on without it (SWK §7.8's InvalidNode,
    // which the restart supervisor declines for jobs — see the module docs).
    let mut doomed: HashSet<Id> = HashSet::new();
    let mut actions = Vec::new();
    for task in tasks {
        let node = task.node_id.as_ref().and_then(|id| view.node(id));
        if evict_reason(task, node.as_deref()).is_none() {
            continue;
        }
        doomed.insert(task.id.clone());
        if let Some(action) = raise_desired_state(task, DesiredState::Shutdown) {
            tracing::info!(
                service_id = %service.id,
                service = %service.spec.annotations.name,
                task_id = %task.id,
                slot = task.slot,
                node_id = ?task.node_id,
                reason = "node can no longer run this task",
                "stopping a job task; its slot is retried elsewhere"
            );
            actions.push(action);
        }
    }

    let units = bucketize(tasks, service.spec_version, &doomed);
    let wanted = (1..=total).map(|slot| (slot, None)).collect();
    let mut decision = plan_units(service, &Shape { wanted, max_live }, &units);
    // Shutdowns first: they are the half that cannot wait, and a full
    // transaction leaves the starts for the next pass.
    actions.append(&mut decision.actions);
    decision.actions = actions;
    decision
}

/// A global job: one run per eligible node, the eligibility verdicts of
/// [`crate::global`] reused unchanged.
fn plan_global(view: &StoreView<'_>, service: &Service, tasks: &[Arc<Task>]) -> Decision {
    let requirements = satl_sched::PlacementRequirements::of(&service.spec.task);
    let verdict = |node_id: &Id| {
        view.node(node_id).map_or(NodeVerdict::Reject, |node| {
            node_verdict(&node, &requirements)
        })
    };

    // A `Reject` node's live tasks are stopped and do not block anything; a
    // `Hold` node's are left entirely alone — not started, not stopped, not
    // counted (SWK §7.8's pause rule).
    let mut skip: HashSet<Id> = HashSet::new();
    let mut actions = Vec::new();
    for task in tasks {
        let Some(node_id) = task.node_id.clone() else {
            continue;
        };
        match verdict(&node_id) {
            NodeVerdict::Reject => {
                skip.insert(task.id.clone());
                // Only a live run is stopped — a `COMPLETE` one is the node's
                // finished work, and its record is not to be touched.
                if task.status.state.is_terminal() {
                    continue;
                }
                if let Some(action) = raise_desired_state(task, DesiredState::Shutdown) {
                    tracing::info!(
                        service_id = %service.id,
                        service = %service.spec.annotations.name,
                        task_id = %task.id,
                        node_id = %node_id,
                        reason = "node is no longer eligible for this global job",
                        "stopping a global job task"
                    );
                    actions.push(action);
                }
            }
            NodeVerdict::Hold => {
                skip.insert(task.id.clone());
            }
            NodeVerdict::Run => {}
        }
    }

    let units = bucketize(tasks, service.spec_version, &skip);
    let wanted = view
        .nodes()
        .iter()
        .filter(|node| node_verdict(node, &requirements) == NodeVerdict::Run)
        .map(|node| (0, Some(node.id.clone())))
        .collect();
    let mut decision = plan_units(
        service,
        &Shape {
            wanted,
            max_live: u64::MAX,
        },
        &units,
    );
    actions.append(&mut decision.actions);
    decision.actions = actions;
    decision
}

/// Reconciles job services against their tasks.
pub(crate) struct JobsOrchestrator {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Services touched since the last commit marker.
    dirty: BTreeSet<Id>,
    /// Task ID to owning service ID: a `Removed` event carries only the ID,
    /// and the object is already gone from the store.
    task_owner: HashMap<Id, Id>,
    /// Whether a node changed in this transaction, which can change the
    /// verdict for every global job.
    nodes_changed: bool,
    /// Jobs whose completion was already logged, per spec version. A hint,
    /// never a decision: losing it costs one duplicate log line.
    completion_logged: HashSet<(Id, Version)>,
    /// Failed-past-budget units already logged, per spec version.
    exhausted_logged: HashSet<(Id, Version, Unit)>,
}

impl JobsOrchestrator {
    pub(crate) fn new(store: ClusterStore, interval: Duration) -> Self {
        Self {
            store,
            interval,
            dirty: BTreeSet::new(),
            task_owner: HashMap::new(),
            nodes_changed: false,
            completion_logged: HashSet::new(),
            exhausted_logged: HashSet::new(),
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.jobs");
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
            tracing::debug!("jobs orchestrator stopped");
        }
        .instrument(span))
        .await;
    }

    /// Accumulates the services a transaction touched, reconciling them when
    /// its commit marker arrives. Node events reconcile the global jobs:
    /// eligibility is the only thing a node changes.
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
                StoreObject::Node(_) => self.nodes_changed = true,
                _ => {}
            },
            StoreEvent::Removed { kind, id } => match kind {
                ObjectKind::Service => {
                    self.dirty.remove(&id);
                }
                ObjectKind::Task => {
                    if let Some(service_id) = self.task_owner.remove(&id) {
                        self.dirty.insert(service_id);
                    }
                }
                ObjectKind::Node => self.nodes_changed = true,
                _ => {}
            },
            StoreEvent::Commit(_) => {
                if std::mem::take(&mut self.nodes_changed) {
                    self.dirty.extend(self.job_services());
                }
                for service_id in std::mem::take(&mut self.dirty) {
                    self.reconcile(&service_id).await;
                }
            }
        }
    }

    /// Reconciles every job service from a full store read.
    async fn full_pass(&mut self) {
        let targets = self.job_services();
        tracing::debug!(services = targets.len(), "full jobs reconciliation pass");
        // Forget log hints for jobs that are gone (a spec change keys a fresh
        // entry, so re-runs log again).
        let alive: HashSet<Id> = targets.iter().cloned().collect();
        self.completion_logged.retain(|(id, _)| alive.contains(id));
        self.exhausted_logged
            .retain(|(id, _, _)| alive.contains(id));
        for service_id in targets {
            self.reconcile(&service_id).await;
        }
    }

    /// The IDs of the cluster's job services.
    fn job_services(&self) -> Vec<Id> {
        let view = self.store.view();
        view.services()
            .iter()
            .filter(|service| service.spec.mode.is_job())
            .map(|service| service.id.clone())
            .collect()
    }

    /// Reconciles one service, retrying its decision on sequence conflicts,
    /// and publishes the once-per-spec-version log notes the plan raised.
    async fn reconcile(&mut self, service_id: &Id) {
        let mut notes = None;
        let result = propose_with_retry(&self.store, "job reconcile", |view| {
            let decision = plan(view, service_id);
            notes = Some(decision.notes());
            decision.actions
        })
        .await;
        if let Some(notes) = notes {
            self.log_notes(service_id, &notes);
        }
        if let Err(err) = result {
            // Never fatal: the periodic pass re-derives the same decision.
            tracing::warn!(service_id = %service_id, error = %err, "job reconciliation deferred");
        }
    }

    /// The two lines a job owes an operator — a unit that failed for good,
    /// and a job that finished — logged once per spec version. Both are
    /// derived from store state, so the dedup set is a hint whose loss costs
    /// a duplicate line, never a wrong decision.
    fn log_notes(&mut self, service_id: &Id, notes: &Notes) {
        for unit in &notes.exhausted {
            let key = (service_id.clone(), notes.spec_version, unit.clone());
            if self.exhausted_logged.insert(key) {
                tracing::warn!(
                    service_id = %service_id,
                    slot = unit.0,
                    node_id = ?unit.1,
                    "job unit failed past its restart budget; the job has failed there"
                );
            }
        }
        if let Some(units) = notes.completed {
            let key = (service_id.clone(), notes.spec_version);
            if self.completion_logged.insert(key) {
                tracing::info!(
                    service_id = %service_id,
                    units,
                    "job completed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use satl_core::{RestartCondition, RestartPolicy};

    use crate::testing::{planted_task, sample_service, with_restart};

    use super::*;

    /// A replicated-job service with the given totals, at spec version 1.
    fn job(total: u64, max_concurrent: u64) -> Service {
        let mut service = sample_service("batch", 1);
        service.spec.mode = ServiceMode::ReplicatedJob {
            max_concurrent: Some(max_concurrent),
            total_completions: Some(total),
        };
        service.spec_version = Version(1);
        service
    }

    /// A current-spec task of `service` in `slot`, in the given states.
    fn run(service: &Service, slot: u64, state: TaskState, desired: DesiredState) -> Arc<Task> {
        let mut task = planted_task(service, slot, state, desired, SystemTime::now());
        task.spec_version = Some(service.spec_version);
        Arc::new(task)
    }

    /// The one-slot shape: the service's defaults give `total = max = 1`.
    fn shape(total: u64, max_live: u64) -> Shape {
        Shape {
            wanted: (1..=total).map(|slot| (slot, None)).collect(),
            max_live,
        }
    }

    fn units_of(service: &Service, tasks: &[Arc<Task>]) -> BTreeMap<Unit, UnitView> {
        bucketize(tasks, service.spec_version, &HashSet::new())
    }

    #[test]
    fn a_fresh_job_starts_up_to_max_concurrent_slots() {
        let service = job(3, 2);
        let units = units_of(&service, &[]);
        let decision = plan_units(&service, &shape(3, 2), &units);
        assert_eq!(decision.actions.len(), 2, "the cap binds from the start");
        assert_eq!(decision.completed, None);
    }

    #[test]
    fn a_complete_unit_is_never_touched_again() {
        let service = job(1, 1);
        let units = units_of(
            &service,
            &[run(&service, 1, TaskState::Complete, DesiredState::Running)],
        );
        let decision = plan_units(&service, &shape(1, 1), &units);
        assert!(decision.actions.is_empty(), "success is final");
        assert_eq!(decision.completed, Some(1));
    }

    #[test]
    fn a_failed_unit_is_retried_within_the_budget() {
        // Two retries allowed: the second failure is the last one answered.
        let service = with_restart(job(1, 1), RestartCondition::OnFailure, Duration::ZERO, 2);
        let one = units_of(
            &service,
            &[run(&service, 1, TaskState::Failed, DesiredState::Running)],
        );
        let decision = plan_units(&service, &shape(1, 1), &one);
        assert_eq!(decision.actions.len(), 1, "first failure: retry");
        assert!(decision.exhausted.is_empty());

        let three = units_of(
            &service,
            &[
                run(&service, 1, TaskState::Failed, DesiredState::Running),
                run(&service, 1, TaskState::Failed, DesiredState::Running),
                run(&service, 1, TaskState::Failed, DesiredState::Running),
            ],
        );
        let decision = plan_units(&service, &shape(1, 1), &three);
        assert!(decision.actions.is_empty(), "budget spent: no fourth task");
        assert_eq!(decision.exhausted, vec![(1, None)]);
        assert_eq!(decision.completed, None);
    }

    #[test]
    fn condition_none_leaves_a_failed_unit_exhausted() {
        let mut service = job(1, 1);
        service.spec.task.restart = RestartPolicy {
            condition: RestartCondition::None,
            ..RestartPolicy::default()
        };
        let units = units_of(
            &service,
            &[run(&service, 1, TaskState::Failed, DesiredState::Running)],
        );
        let decision = plan_units(&service, &shape(1, 1), &units);
        assert!(decision.actions.is_empty());
        assert_eq!(decision.exhausted, vec![(1, None)]);
    }

    #[test]
    fn a_completion_frees_the_place_for_the_next_slot() {
        let service = job(2, 1);
        let units = units_of(
            &service,
            &[run(&service, 1, TaskState::Complete, DesiredState::Running)],
        );
        let decision = plan_units(&service, &shape(2, 1), &units);
        assert_eq!(decision.actions.len(), 1, "slot 2 starts");
        let StoreAction::Create(StoreObject::Task(task)) = &decision.actions[0] else {
            panic!("a task creation, not a shutdown");
        };
        assert_eq!(task.slot, 2);
        assert_eq!(decision.completed, None, "one completion of two");
    }

    #[test]
    fn a_live_old_spec_run_blocks_its_slot_and_is_stopped() {
        let service = job(1, 1);
        // Planted on the previous spec version, still running: an update
        // re-runs the job, but only once the old run is gone.
        let old = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        );
        let units = units_of(&service, &[Arc::new(old)]);
        let decision = plan_units(&service, &shape(1, 1), &units);
        assert_eq!(decision.actions.len(), 1, "the old run is ordered to stop");
        assert!(
            matches!(&decision.actions[0], StoreAction::Update(StoreObject::Task(task))
                if task.desired_state == DesiredState::Shutdown),
            "no fresh task while the old one lives"
        );
    }

    #[test]
    fn a_stopping_old_run_still_blocks_its_slot() {
        let service = job(1, 1);
        let mut old = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Shutdown,
            SystemTime::now(),
        );
        old.spec_version = Some(Version(0));
        let units = units_of(&service, &[Arc::new(old)]);
        let decision = plan_units(&service, &shape(1, 1), &units);
        assert!(
            decision.actions.is_empty(),
            "shutdown already ordered; the new run waits for it"
        );
    }

    #[test]
    fn the_concurrency_cap_counts_live_tasks_across_slots() {
        let service = job(3, 2);
        let units = units_of(
            &service,
            &[run(&service, 1, TaskState::Running, DesiredState::Running)],
        );
        let decision = plan_units(&service, &shape(3, 2), &units);
        assert_eq!(
            decision.actions.len(),
            1,
            "one place left: slot 2 starts, slot 3 waits"
        );
    }

    #[test]
    fn bucketize_drops_history_and_orders_runs_oldest_first() {
        let service = job(1, 1);
        let now = SystemTime::now();
        let mut old_terminal = planted_task(
            &service,
            1,
            TaskState::Complete,
            DesiredState::Running,
            now - Duration::from_mins(1),
        );
        old_terminal.spec_version = Some(Version(0));
        let removing = run(&service, 1, TaskState::Failed, DesiredState::Remove);
        let first = {
            let mut task = planted_task(
                &service,
                1,
                TaskState::Failed,
                DesiredState::Running,
                now - Duration::from_secs(30),
            );
            task.spec_version = Some(service.spec_version);
            Arc::new(task)
        };
        let second = run(&service, 1, TaskState::Complete, DesiredState::Running);
        let units = bucketize(
            &[Arc::new(old_terminal), removing, second, Arc::clone(&first)],
            service.spec_version,
            &HashSet::new(),
        );
        let view = units.get(&(1, None)).expect("slot 1");
        assert_eq!(view.terminal.len(), 2, "old-spec history is not a run");
        assert!(
            Arc::ptr_eq(&view.terminal[0], &first),
            "oldest first: the newest run is the verdict's"
        );
        assert_eq!(
            unit_state(&service.spec.task.restart, view),
            UnitState::Done
        );
    }
}
