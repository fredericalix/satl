// SPDX-License-Identifier: BSD-2-Clause
//! The rolling updater (SWK §7.3, architecture §5): brings the tasks of a
//! service onto its current spec, a batch at a time, and reacts to failures by
//! pausing or rolling back.
//!
//! # Level-triggered, and why that is the whole design
//!
//! SwarmKit runs one `Updater` goroutine per service, holding the batch, the
//! failure count and the delay timers in its own memory, and cancels it when
//! the goal changes. That shape cannot survive a leadership change: the state
//! of a half-finished update would live only in the memory of a manager that
//! just lost the election.
//!
//! So this updater keeps **no state of its own**. Every pass re-derives the
//! whole decision from the store:
//!
//! | question | answered by |
//! |---|---|
//! | is an update in flight, paused, rolling back? | [`Service::update_status`] |
//! | which slots are still on the old spec? | [`crate::dirty::is_task_dirty`] per task |
//! | which slots has this update already done? | tasks stamped with the current `spec_version` |
//! | is a batch finished? | those tasks' observed state and its timestamp |
//! | how many tasks has it lost? | terminal current-spec tasks |
//!
//! A new leader therefore *resumes*: it reads the same store, computes the same
//! plan, and finds most of it already applied. Nothing is replayed and nothing
//! is rolled twice. The same property makes a missed watch event, a lagged
//! watcher and a lost optimistic-concurrency race non-events — the pattern the
//! node-status, teardown and port-publishing fixes (`9a85d2f`, `27ccb64`,
//! `01f6d41`) all converged on.
//!
//! # One pass, per service
//!
//! 1. `PAUSED` / `ROLLBACK_PAUSED` ⇒ do nothing at all (SWK §7.3 step 1).
//! 2. Count the failures of tasks this update created. Over
//!    `max_failure_ratio` ⇒ pause, continue or roll back, and stop there:
//!    rolling back rewrites the spec, which makes every other decision stale.
//! 3. Classify every unit of the service ([`Unit`], [`Phase`]).
//! 4. Nothing left to do ⇒ `COMPLETED` / `ROLLBACK_COMPLETED`.
//! 5. Otherwise: finish the units already in flight, and start as many new ones
//!    as `parallelism` and `delay` allow.
//!
//! # Slots, or nodes
//!
//! "Unit" rather than "slot", because a **global** service has no slots: it runs
//! one task per node (SWK §4.5), so the thing a batch advances is a *node* and
//! `parallelism` is a number of nodes — SWK §7.8's "one slot per node ⇒ updates
//! proceed node-by-node". Every rule below is written once and reads the same for
//! both shapes ([`Unit`], [`Shape`]); the two places the difference surfaces are
//! the unit set (slots `1..=replicas`, or the nodes the global orchestrator deems
//! eligible) and task creation (a global replacement is pinned to the node whose
//! turn it is). A **job** service has no shape here at all: updating a job
//! re-runs it, which is [`crate::jobs`]' business, and this loop returns
//! without a plan for one.
//!
//! # Health gating
//!
//! A slot leaves the batch only once its new task has been **observed
//! `RUNNING`** *and* has stayed there for the `monitor` window. Since a task
//! that declares a healthcheck does not reach `RUNNING` until it is healthy
//! (M4, `satl-runtime`/`satl-agent`), waiting for observed `RUNNING` is waiting
//! for "actually serving", and no updater-side probing is needed. This is
//! stricter than SwarmKit, which starts the next slot as soon as the previous
//! task reaches `RUNNING` and keeps monitoring in the background: here the
//! monitor window is part of the batch, so a broken image is caught before the
//! next batch is disturbed.
//!
//! The window applies only to tasks **this rollout created** (the ones stamped
//! with the current `spec_version`). A task that was already running and is
//! merely *judged* clean by the deep comparison — the shape a rollback produces,
//! where the tasks it returns to are the ones that never stopped serving — is
//! settled on sight: there is nothing to observe about a container that predates
//! the rollout, and watching it would spend the batch's budget on slots that
//! need no work at all.
//!
//! Its elapsed time is measured with [`task_timestamp`], i.e. from
//! `status.applied_at` — the *manager* clock, stamped when the manager applied
//! the status. The agent's own `status.timestamp` is stamped when a step
//! *begins*, so for a health-gated task it can predate the moment the task
//! became `RUNNING` by the whole health gate, and keying the window on it would
//! spend the window before there was anything to observe.
//!
//! # Deliberate divergences from SWK §7.3
//!
//! - **A slot with no live task is usually not the updater's.** The restart
//!   supervisor is a separate loop here and owns stopped slots (see
//!   [`crate::task::classify_slot`]); it creates its replacement from the
//!   *current* spec, so such a slot converges without the updater and two loops
//!   never race a replacement into one. SwarmKit's `UpdatableTasksInSlot`
//!   fallback is implemented only for the half that turns on the *policy* — a
//!   slot the restart condition will not refill ([`abandoned`]). The other half,
//!   "attempts exhausted", is deliberately still left to the supervisor even
//!   though the attempt count is now derivable from the store
//!   ([`crate::restart::RestartHistory`]): what is *not* derivable is whether the
//!   supervisor already has a replacement for that slot queued behind its restart
//!   delay, and filling a slot that is about to be refilled is exactly the
//!   two-live-tasks bug this loop is careful never to cause.
//! - **The failure denominator is derived, not remembered**: the slots this
//!   update is responsible for (dirty, or already carrying a current-spec
//!   task), which equals SwarmKit's initial dirty-slot count in every case
//!   where the replica count did not change mid-update.
//! - **A pause is not cleared here.** Entering `PAUSED`/`ROLLBACK_PAUSED` is this
//!   loop's decision; leaving it is not. SwarmKit clears the state in its control
//!   API, on the next `UpdateService`, and inventing a heuristic here ("resume if
//!   no task carries the current spec") would resume a paused update the moment
//!   the reaper pruned its history. What the control surface does with the field
//!   is recorded in `docs/api-compat.md`.
//! - **A global service's unit set can change under an update.** SwarmKit's
//!   global orchestrator bypasses the updater for per-node events entirely
//!   ("it must not disturb a running rolling update"); here a node that joins
//!   mid-rollout simply becomes another unit. It is born *up to date* — the
//!   global orchestrator stamps its task from the current spec, so the updater
//!   never replaces it — but it is watched like any other new task of this spec:
//!   its unit is `Watching` until it has been running for the monitor window,
//!   which holds one slot of the batch budget and keeps the rollout `updating`
//!   until it settles. That is the honest reading: a task at the new spec that
//!   nobody has yet seen serve is exactly what the monitor window is for. A node
//!   that leaves stops being a unit, and the budget it held is released.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_cluster::{ClusterStore, StoreView};
use satl_core::defaults::MAX_TX_ACTIONS;
use satl_core::{
    DesiredState, FailureAction, Id, ObjectKind, Service, ServiceMode, StoreAction, StoreEvent,
    StoreObject, Task, TaskState, UpdateConfig, UpdateOrder, UpdateStateKind, UpdateStatus,
};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::dirty::is_task_dirty;
use crate::propose::propose_with_retry;
use crate::task::{
    initial_desired_state, is_global_task, new_global_task, new_task, raise_desired_state,
    task_timestamp,
};

/// How long a `stop-first` promotion waits for the predecessor it shut down to
/// actually stop before promoting anyway (SwarmKit's `defaultOldTaskTimeout`).
///
/// The wait exists so that a slot does not run two containers at once; the
/// bound exists because the predecessor may be on a node that will never
/// answer again, and a slot must not stay down for it.
pub(crate) const OLD_TASK_TIMEOUT: Duration = Duration::from_mins(1);

/// Floor for the wake-up a pass asks for, so a rounding error cannot turn a
/// timer into a spin.
const MIN_WAKE: Duration = Duration::from_millis(50);

/// What one rolling update advances at a time — what `parallelism` counts and
/// `delay` paces (SWK §7.3).
///
/// For a replicated service that is a **slot**; for a global service it is a
/// **node**, because a global service has one task per node and no slot
/// numbering at all (SWK §7.8: "one slot per node ⇒ updates proceed
/// node-by-node"). Encoded as the `(slot, node)` pair a task carries, with the
/// node present only for global tasks (slot 0, SWK §4.5) — so the ordering is
/// the slot order for a replicated service and stable for a global one, and
/// every batching rule below reads the same way for both.
type Unit = (u64, Option<Id>);

/// The unit `task` belongs to, or `None` when it belongs to none: a global task
/// that is not bound to a node has nowhere to be updated.
fn unit_of(task: &Task) -> Option<Unit> {
    if is_global_task(task) {
        return Some((task.slot, Some(task.node_id.clone()?)));
    }
    Some((task.slot, None))
}

/// The units of one service: the slots a replicated service must fill, or the
/// nodes a global one must run on (SWK §7.8).
#[derive(Debug)]
enum Shape {
    Replicated { replicas: u64 },
    Global { nodes: BTreeSet<Id> },
}

impl Shape {
    /// How the service is shaped right now, reading the eligible node set from
    /// the store for a global one.
    fn of(view: &StoreView<'_>, service: &Service) -> Self {
        match service.spec.mode {
            ServiceMode::Replicated { replicas } => Self::Replicated { replicas },
            // Only the nodes the service *should* be running on: a paused node
            // is not updated and a rejected one is losing its task anyway
            // (SWK §7.8).
            ServiceMode::Global => Self::Global {
                nodes: crate::global::eligible_nodes(view, service),
            },
            // `plan()` returns before reaching here for a job: it re-runs
            // rather than rolls ([`crate::jobs`]).
            ServiceMode::ReplicatedJob { .. } | ServiceMode::GlobalJob => {
                unreachable!("job services never reach the rolling updater")
            }
        }
    }

    /// Whether `unit` is one this update is responsible for. Slots outside
    /// `1..=replicas` are the replicated orchestrator's scale-down business, and
    /// a node that is not eligible is the global orchestrator's.
    fn owns(&self, unit: &Unit) -> bool {
        match (self, unit) {
            (Self::Replicated { replicas }, (slot, None)) => *slot >= 1 && slot <= replicas,
            (Self::Global { nodes }, (_, Some(node_id))) => nodes.contains(node_id),
            _ => false,
        }
    }

    /// How many units the service has, for the operator-facing progress line.
    fn count(&self) -> u64 {
        match self {
            Self::Replicated { replicas } => *replicas,
            Self::Global { nodes } => nodes.len() as u64,
        }
    }

    /// What to call a unit in an operator-facing message, plain ASCII.
    fn noun(&self) -> &'static str {
        match self {
            Self::Replicated { .. } => "slots",
            Self::Global { .. } => "nodes",
        }
    }
}

/// What one pass decided for one service.
#[derive(Debug, Default)]
struct Plan {
    /// The transaction to propose; empty means "nothing to do".
    actions: Vec<StoreAction>,
    /// How long until this service could decide something new with no event
    /// at all (a monitor window closing, a batch delay expiring).
    wake: Option<Duration>,
}

impl Plan {
    /// Nothing to do, and nothing to wait for.
    fn idle() -> Self {
        Self::default()
    }

    /// One transaction and nothing to wait for.
    fn act(actions: Vec<StoreAction>) -> Self {
        Self {
            actions,
            wake: None,
        }
    }
}

/// Drives every service's tasks onto its current spec.
pub(crate) struct Updater {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Services touched since the last commit marker.
    dirty: BTreeSet<Id>,
    /// Task ID to owning service ID: a `Removed` event carries only the ID.
    task_owner: HashMap<Id, Id>,
    /// Per-service timers, as absolute instants. Rebuilt from the store on
    /// every pass — this is a wake-up hint, never a decision.
    wake: HashMap<Id, tokio::time::Instant>,
}

impl Updater {
    pub(crate) fn new(store: ClusterStore, interval: Duration) -> Self {
        Self {
            store,
            interval,
            dirty: BTreeSet::new(),
            task_owner: HashMap::new(),
            wake: HashMap::new(),
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.update");
        // Boxed for the same reason as the other loops: a `StoreEvent` is held
        // across await points and that enum spans every store object
        // (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let next = self.wake.values().copied().min();
                let timer = async move {
                    match next {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    () = timer => self.fire_due().await,
                    // The first tick fires immediately: that is the initial
                    // full pass, which is also the leader-change resume
                    // (SWK §7.9 — here it needs no replay, see the module docs).
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
            tracing::debug!("rolling updater stopped");
        }
        .instrument(span))
        .await;
    }

    /// Accumulates the services a transaction touched, reconciling them when
    /// its commit marker arrives.
    ///
    /// Node events are deliberately not watched. The only decision a node can
    /// change is the placement fast path (SWK §7.2 rule 2), node objects are
    /// rewritten on every heartbeat, and the periodic pass covers it — the
    /// alternative is a full store scan every few seconds for a label change
    /// that almost never happens.
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
                ObjectKind::Service => {
                    self.dirty.remove(&id);
                    self.wake.remove(&id);
                }
                ObjectKind::Task => {
                    if let Some(service_id) = self.task_owner.remove(&id) {
                        self.dirty.insert(service_id);
                    }
                }
                _ => {}
            },
            StoreEvent::Commit(_) => {
                for service_id in std::mem::take(&mut self.dirty) {
                    self.reconcile(&service_id).await;
                }
            }
        }
    }

    /// Every service, from a full store read.
    async fn full_pass(&mut self) {
        let services: Vec<Id> = {
            let view = self.store.view();
            view.services().iter().map(|s| s.id.clone()).collect()
        };
        tracing::debug!(services = services.len(), "full update pass");
        self.wake.retain(|id, _| services.contains(id));
        for service_id in services {
            self.reconcile(&service_id).await;
        }
    }

    /// The services whose timer has expired.
    async fn fire_due(&mut self) {
        let now = tokio::time::Instant::now();
        let due: Vec<Id> = self
            .wake
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for service_id in due {
            self.wake.remove(&service_id);
            self.reconcile(&service_id).await;
        }
    }

    /// Plans one service and proposes the result, retrying on conflicts.
    async fn reconcile(&mut self, service_id: &Id) {
        let mut wake = None;
        let result = propose_with_retry(&self.store, "rolling update", |view| {
            let plan = plan(view, service_id, SystemTime::now());
            wake = plan.wake;
            plan.actions
        })
        .await;
        match wake {
            Some(after) => {
                self.wake.insert(
                    service_id.clone(),
                    tokio::time::Instant::now() + after.max(MIN_WAKE),
                );
            }
            None => {
                self.wake.remove(service_id);
            }
        }
        if let Err(error) = result {
            // Never fatal: the periodic pass re-derives the same plan.
            tracing::warn!(service_id = %service_id, %error, "rolling update deferred");
        }
    }
}

// ---------------------------------------------------------------------------
// The plan: pure, and the whole of the decision
// ---------------------------------------------------------------------------

/// One slot of a service, as the updater sees it.
///
/// "Live" is SwarmKit's `UpdatableTasksInSlot` narrowed to the tasks this loop
/// may touch: desired state at most `RUNNING` and an observed state that is not
/// terminal. A task being stopped, or one that already stopped, is history.
#[derive(Default)]
struct SlotView {
    /// Live tasks already stamped from the current spec.
    clean: Vec<Arc<Task>>,
    /// Live tasks still on an older spec — what an update replaces.
    stale: Vec<Arc<Task>>,
    /// Tasks ordered to stop that have not reported a terminal state yet, with
    /// the moment the order was written (`meta.updated_at`).
    stopping: Vec<Arc<Task>>,
    /// Whether **any** task of this slot — live, stopping or finished — carries
    /// the current spec version. That is the record that this update has
    /// already created a task here, and it is what stops the updater from
    /// creating a second one after the first died: replacing a task that ran
    /// and failed is the restart supervisor's job, not the updater's.
    touched: bool,
    /// Whether the slot holds a task that is finished, that no restart
    /// policy will replace (see [`abandoned`]), **and** that is deep-dirty
    /// against the current spec ([`is_task_dirty`]). Such a slot is nobody
    /// else's, so the updater fills it rather than leaving the service short.
    /// A finished task whose spec already matches the service's is the
    /// converged state of a one-shot container, not a hole to fill.
    abandoned: bool,
}

/// Where one slot stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// No live task: the replicated orchestrator (empty slot) or the restart
    /// supervisor (stopped slot) owns it, and whatever they create is stamped
    /// from the current spec. Not the updater's business.
    Absent,
    /// One current-spec task, observed running for at least `monitor`.
    Settled,
    /// One current-spec task, not yet running long enough. In flight, but
    /// there is nothing to do but wait.
    Watching,
    /// Needs work. `started` distinguishes a slot this update has already
    /// touched (it holds a current-spec task) from one still entirely on the
    /// old spec — only the latter consumes batch budget.
    Pending { started: bool },
}

/// The failure-observation window (SWK §7.3 step 4): the configured `monitor`,
/// extended to `delay + 1s` when the delay is at least as long, so a paced
/// update still watches each task past the pause that follows it.
fn monitoring_period(config: &UpdateConfig) -> Duration {
    if config.delay >= config.monitor {
        config.delay + Duration::from_secs(1)
    } else {
        config.monitor
    }
}

/// Plans one service's update. Pure, idempotent and total: an up-to-date
/// service yields no actions, and every timer it needs is returned rather than
/// remembered.
fn plan(view: &StoreView<'_>, service_id: &Id, now: SystemTime) -> Plan {
    let Some(service) = view.service(service_id) else {
        return Plan::idle();
    };
    // A job is re-run by [`crate::jobs`] when its spec changes, not rolled:
    // there is nothing to batch, pace or monitor here.
    if service.spec.mode.is_job() {
        return Plan::idle();
    }
    // Slots for a replicated service, eligible nodes for a global one: the rest
    // of this function reads the same either way (see [`Unit`]).
    let shape = Shape::of(view, &service);
    let state = service.update_status.as_ref().map(|status| status.state);
    if matches!(
        state,
        Some(UpdateStateKind::Paused | UpdateStateKind::RollbackPaused)
    ) {
        return Plan::idle();
    }
    let rolling_back = state == Some(UpdateStateKind::RollbackStarted);
    let config = if rolling_back {
        service.spec.rollback
    } else {
        service.spec.update
    }
    .unwrap_or_default();
    let monitor = monitoring_period(&config);

    let tasks: Vec<Arc<Task>> = view
        .tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service_id))
        .collect();
    // M6g: a resources-only spec change is pushed into the live tasks, not
    // rolled — `dirty` exempts these tasks from replacement, so without this
    // pass the new rctl limits would never reach the node at all. The next
    // pass finds the service converged and takes the steady path.
    let resizes = resize_actions(view, &service, &tasks);
    if !resizes.is_empty() {
        return Plan::act(resizes);
    }
    let target = initial_desired_state(&service.spec);
    let slots = slot_views(view, &service, &tasks, &shape, target);
    let updating = matches!(
        state,
        Some(UpdateStateKind::Updating | UpdateStateKind::RollbackStarted)
    );
    let phases: Phases = slots
        .iter()
        .map(|(unit, slot_view)| {
            (
                unit.clone(),
                phase(slot_view, target, monitor, now, updating),
            )
        })
        .collect();

    // Failures are judged before anything else is done: a rollback rewrites
    // the spec, and every other decision on this pass would be about a spec
    // that is on its way out.
    if let Some(action) = failure_verdict(&service, &tasks, &phases, &config, now) {
        return Plan::act(vec![action]);
    }

    if !work_left(&phases) {
        return finished(&service, state, &phases, &shape, now);
    }

    let mut plan = slot_work(&service, &slots, &phases, &config, monitor, now);
    publish_progress(
        &mut plan, &service, state, &phases, &shape, &config, monitor, now,
    );
    plan
}

/// Where every unit of one service stands.
type Phases = BTreeMap<Unit, Phase>;

/// The in-place half of a resources-only update (M6g): copy the service's
/// resources into every live task that is otherwise converged, and stamp it
/// current.
///
/// [`is_task_dirty`] exempts a resources-only difference from the roll, so
/// this pass is the only thing that makes the new limits reach the node —
/// the agent re-applies them to the live jail (rctl attaches to the jail,
/// not the container, which is exactly why no replacement is needed). The
/// mutation is the one sanctioned breach of task-spec immutability
/// (architecture §4 rule 4): every other field compares equal by the
/// exemption's own construction.
fn resize_actions(
    view: &StoreView<'_>,
    service: &Service,
    tasks: &[Arc<Task>],
) -> Vec<StoreAction> {
    let mut actions = Vec::new();
    for task in tasks {
        if task.desired_state > DesiredState::Running
            || task.status.state.is_terminal()
            || task.spec.resources == service.spec.task.resources
        {
            continue;
        }
        let node = task.node_id.as_ref().and_then(|id| view.node(id));
        if is_task_dirty(service, task, node.as_deref()) {
            // More than the resources changed: the roll owns this task, and
            // its replacement lands on the new spec whole.
            continue;
        }
        tracing::info!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            task_id = %task.id,
            node_id = ?task.node_id,
            limits = ?service.spec.task.resources.limits,
            reservations = ?service.spec.task.resources.reservations,
            "hot resize: resources pushed to the live task, no roll"
        );
        actions.push(crate::task::update_task(task, |next| {
            next.spec.resources = service.spec.task.resources;
            next.spec_version = Some(service.spec_version);
        }));
    }
    actions
}

/// Whether this update still has anything to do: a slot to replace, or one
/// whose replacement is not yet settled.
fn work_left(phases: &Phases) -> bool {
    phases
        .values()
        .any(|phase| matches!(phase, Phase::Pending { .. } | Phase::Watching))
}

/// The final transition of an update that has nothing left to do (SWK §7.3
/// steps 3 and 8). A service that was not updating yields nothing at all — this
/// is the steady state of every service in the cluster and must cost one store
/// read and no writes.
fn finished(
    service: &Service,
    state: Option<UpdateStateKind>,
    phases: &Phases,
    shape: &Shape,
    now: SystemTime,
) -> Plan {
    let done = match state {
        Some(UpdateStateKind::Updating) => UpdateStateKind::Completed,
        Some(UpdateStateKind::RollbackStarted) => UpdateStateKind::RollbackCompleted,
        _ => return Plan::idle(),
    };
    tracing::info!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        slots = phases.len(),
        from = describe_state(state),
        to = describe_state(Some(done)),
        image = %service.spec.task.container.image,
        "rolling update finished"
    );
    Plan::act(vec![status_action(
        service,
        done,
        &progress_message(done, phases, shape),
        now,
    )])
}

/// Prepends the `update_status` write that makes the rollout visible to
/// `satl service inspect` and the API.
///
/// Two cases: the first action of a new update announces it, and a rollout
/// already in flight refreshes its progress line — the latter only when the
/// rendered message actually changed, so a service being watched does not take
/// a Raft entry per pass.
#[allow(clippy::too_many_arguments)] // one write, and every input decides part of it
fn publish_progress(
    plan: &mut Plan,
    service: &Service,
    state: Option<UpdateStateKind>,
    phases: &Phases,
    shape: &Shape,
    config: &UpdateConfig,
    monitor: Duration,
    now: SystemTime,
) {
    let engaged = matches!(
        state,
        Some(UpdateStateKind::Updating | UpdateStateKind::RollbackStarted)
    );
    if !engaged {
        if plan.actions.is_empty() {
            return;
        }
        tracing::info!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            slots = phases.len(),
            dirty = phases
                .values()
                .filter(|phase| matches!(phase, Phase::Pending { .. }))
                .count(),
            parallelism = config.parallelism,
            delay_ms = config.delay.as_millis(),
            monitor_ms = monitor.as_millis(),
            order = describe_order(config.order),
            failure_action = describe_action(config.failure_action),
            image = %service.spec.task.container.image,
            "rolling update started"
        );
        let started = UpdateStateKind::Updating;
        plan.actions.insert(
            0,
            status_action(
                service,
                started,
                &progress_message(started, phases, shape),
                now,
            ),
        );
        return;
    }
    let state = state.unwrap_or(UpdateStateKind::Updating);
    let message = progress_message(state, phases, shape);
    if service
        .update_status
        .as_ref()
        .is_none_or(|status| status.message != message)
    {
        plan.actions
            .insert(0, status_action(service, state, &message, now));
    }
}

/// Groups a service's tasks by unit ([`Unit`]: slot, or node for a global
/// service), in the three categories the updater distinguishes.
///
/// A unit the service does not own is skipped — a slot outside `1..=replicas` is
/// the replicated orchestrator's scale-down business, and a node that is not
/// eligible is the global orchestrator's — and so are tasks already marked for
/// removal.
fn slot_views(
    view: &StoreView<'_>,
    service: &Service,
    tasks: &[Arc<Task>],
    shape: &Shape,
    target: DesiredState,
) -> BTreeMap<Unit, SlotView> {
    let mut slots: BTreeMap<Unit, SlotView> = BTreeMap::new();
    for task in tasks {
        if task.desired_state == DesiredState::Remove {
            continue;
        }
        let Some(unit) = unit_of(task).filter(|unit| shape.owns(unit)) else {
            continue;
        };
        let current = task.spec_version == Some(service.spec_version);
        let entry = slots.entry(unit).or_default();
        entry.touched |= current;
        if task.desired_state <= DesiredState::Running && !task.status.state.is_terminal() {
            let node = task.node_id.as_ref().and_then(|id| view.node(id));
            if is_task_dirty(service, task, node.as_deref()) {
                entry.stale.push(Arc::clone(task));
            } else {
                entry.clean.push(Arc::clone(task));
            }
        } else if task.desired_state >= DesiredState::Shutdown && !task.status.state.is_terminal() {
            entry.stopping.push(Arc::clone(task));
        } else if task.status.state.is_terminal() && abandoned(task, target) {
            // Deep dirtiness ([`is_task_dirty`]) is part of the verdict: a
            // finished task whose spec already matches the current one is the
            // *converged* state of a one-shot service, and its slot is
            // nobody's to fill. Filling it anyway was the measured bug behind
            // every `satl run` executing its command twice: `start_container`
            // flips the autostart label, which bumps `spec_version` without
            // touching the task spec, so the completed restart-none task
            // looked abandoned at the old version and the updater re-ran it.
            // A deep-dirty finished task (a real update over a dead slot) is
            // still the updater's to fill.
            let node = task.node_id.as_ref().and_then(|id| view.node(id));
            entry.abandoned |= is_task_dirty(service, task, node.as_deref());
        }
    }
    slots
}

/// Whether a task is finished for good and **nobody is going to replace it**.
///
/// This is the derivable half of SwarmKit's `UpdatableTasksInSlot` fallback, and
/// the reason the updater needs it is convergence: a slot whose only tasks are
/// dead is normally the restart supervisor's
/// ([`crate::task::classify_slot`]), but a slot *that supervisor will not touch*
/// is a slot nothing would ever fill, and an update that reached one would
/// report itself complete with a replica missing. Two shapes:
///
/// - **a promotion that will never come.** A `stop-first` replacement is created
///   at `READY` and promoted once its predecessor stops. If it dies before that
///   — a pull that 404s, an image that will not start — it is terminal with a
///   desired state *below* the service's target, and the restart supervisor
///   deliberately ignores those (`docker create`d containers are not restarted,
///   `only_terminated_tasks_the_cluster_still_wants_are_judged`). Nobody but the
///   updater creates such a task, so nobody but the updater can clean up after
///   it. This is the case a live rollback found: the broken task sat `Rejected`
///   at desired `READY` and its slot stayed empty at 5/6 replicas while the
///   rollback declared itself complete.
/// - **a restart policy that refuses.** Desired state at the target, terminal,
///   and the policy alone would not replace it (condition `none`, or
///   `on-failure` after a clean exit).
///
/// Only the policy is consulted, never the supervisor's in-memory attempt
/// history: with a clean budget the two components reach the same verdict, so
/// there is no case where both create a replacement. A slot whose *attempts* are
/// exhausted stays the supervisor's — it is the one thing this cannot see, and
/// guessing would race a second task into a live slot.
fn abandoned(task: &Task, target: DesiredState) -> bool {
    if task.desired_state >= DesiredState::Shutdown {
        // Asked to stop, and it stopped. Nobody is waiting for it.
        return false;
    }
    if task.desired_state < target {
        return true;
    }
    crate::restart::decide(&task.spec.restart, task.status.state, 0)
        != crate::restart::RestartDecision::Restart
}

/// Where one slot stands, from its task set alone.
fn phase(
    slot: &SlotView,
    target: DesiredState,
    monitor: Duration,
    now: SystemTime,
    updating: bool,
) -> Phase {
    if !slot.stale.is_empty() {
        return Phase::Pending {
            started: slot.touched,
        };
    }
    if slot.clean.is_empty() {
        // No live task at all. Touched: this update's task is gone and its
        // replacement is the restart supervisor's to create — from the current
        // spec, so the slot converges without us, but it is still in flight.
        // Abandoned: nobody is coming, so it is the updater's to fill.
        // Otherwise: somebody else's slot — **unless an update is in flight**:
        // the supervisor's refill then lands *under the update's verdict*, and
        // completing now would call a rollback done with a slot serving
        // nothing (measured: a rollback whose refill tasks fail immediately
        // raced `finished` and reported RollbackCompleted instead of pausing).
        return match (slot.touched, slot.abandoned) {
            (true, _) => Phase::Watching,
            (false, true) => Phase::Pending { started: false },
            (false, false) if updating => Phase::Watching,
            (false, false) => Phase::Absent,
        };
    }
    if slot.clean.len() > 1 {
        // Two current-spec tasks in one slot: converge to one (SWK §7.3 step 2
        // makes the updater the component that does this).
        return Phase::Pending { started: true };
    }
    let task = &slot.clean[0];
    if task.desired_state < target {
        // Created at READY by a stop-first batch: it still needs promoting.
        return Phase::Pending { started: true };
    }
    if !slot.touched {
        // A task this update did not create, kept because the deep comparison
        // says it already matches the spec — the shape a rollback produces, where
        // the tasks it rolls *back to* are the ones that were serving all along.
        // There is nothing to observe about a container that has been running
        // since before the rollout began, and monitoring it would spend the
        // batch's budget on slots that need no work: measured as a rollback that
        // sat idle for two monitor windows before touching the one slot that
        // actually needed a task.
        return Phase::Settled;
    }
    if task.status.state < target.as_task_state() {
        // Pulling, cloning, starting: in flight, nothing to do but wait for the
        // next status event.
        return Phase::Watching;
    }
    // [`task_timestamp`] is `status.applied_at` when it is set: the manager
    // clock, stamped when the manager *applied* this status. That is the only
    // timestamp that means "when the task was observed running", and the
    // distinction is load-bearing here: the agent's own `status.timestamp` is
    // stamped when a step *begins*, so for a health-gated task — one that stays
    // `STARTING` until a probe passes — it can predate the moment the task
    // became `RUNNING` by the whole health-gate duration, which would spend the
    // failure-observation window before there was anything to observe.
    if elapsed(now, task_timestamp(task)) >= monitor {
        Phase::Settled
    } else {
        Phase::Watching
    }
}

/// The verdict on the failures this update has accumulated (SWK §7.3 step 7),
/// or `None` while it is within budget.
fn failure_verdict(
    service: &Service,
    tasks: &[Arc<Task>],
    phases: &Phases,
    config: &UpdateConfig,
    now: SystemTime,
) -> Option<StoreAction> {
    let state = service.update_status.as_ref()?.state;
    if !matches!(
        state,
        UpdateStateKind::Updating | UpdateStateKind::RollbackStarted
    ) {
        return None;
    }
    if config.failure_action == FailureAction::Continue {
        return None;
    }
    let failures = tasks
        .iter()
        .filter(|task| failed_under_this_spec(service, task))
        .count();
    if failures == 0 {
        return None;
    }
    let slots = phases
        .values()
        .filter(|p| **p != Phase::Absent)
        .count()
        .max(1);
    #[allow(clippy::cast_precision_loss)] // counts here are small by construction
    let ratio = failures as f32 / slots as f32;
    if ratio <= config.max_failure_ratio {
        tracing::debug!(
            service_id = %service.id,
            failures,
            slots,
            "task failures are within the update's budget"
        );
        return None;
    }

    // Rollbacks never roll back (architecture §5): a failing rollback pauses.
    if state == UpdateStateKind::RollbackStarted {
        let message = format!("rollback paused: {failures} of {slots} tasks failed");
        tracing::warn!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            failures,
            slots,
            from = describe_state(Some(state)),
            to = describe_state(Some(UpdateStateKind::RollbackPaused)),
            "rollback failed; pausing rather than rolling back again"
        );
        return Some(status_action(
            service,
            UpdateStateKind::RollbackPaused,
            &message,
            now,
        ));
    }

    match config.failure_action {
        FailureAction::Continue => None,
        FailureAction::Pause => {
            let message = format!("update paused: {failures} of {slots} tasks failed");
            tracing::warn!(
                service_id = %service.id,
                service = %service.spec.annotations.name,
                failures,
                slots,
                from = describe_state(Some(state)),
                to = describe_state(Some(UpdateStateKind::Paused)),
                "update paused by task failures"
            );
            Some(status_action(
                service,
                UpdateStateKind::Paused,
                &message,
                now,
            ))
        }
        FailureAction::Rollback => Some(rollback_action(service, failures, slots, now)),
    }
}

/// Whether `task` is a failure this update must answer for: stamped from the
/// spec being rolled out, and finished for a reason other than being asked to
/// stop.
///
/// `SHUTDOWN` is the one terminal state that means "as ordered", which is how
/// the updater's own cleanups (a duplicate task in a slot, a `start-first`
/// predecessor) stay out of the count. Everything else — `FAILED`, `REJECTED`,
/// `ORPHANED`, and a `COMPLETE` that nobody asked for — counts, as it does in
/// SwarmKit, where any task moving past `RUNNING` is a candidate failure.
fn failed_under_this_spec(service: &Service, task: &Task) -> bool {
    task.spec_version == Some(service.spec_version)
        && task.status.state.is_terminal()
        && task.status.state != TaskState::Shutdown
}

/// Swaps the spec back to `previous_spec` and enters `ROLLBACK_STARTED`
/// (SWK §7.3 step 7). The store's own spec-version stamping then makes every
/// task of the failed spec dirty, and the next pass rolls them in the same
/// batches — "the updater runs again in reverse".
fn rollback_action(
    service: &Service,
    failures: usize,
    slots: usize,
    now: SystemTime,
) -> StoreAction {
    let Some(previous) = service.previous_spec.clone() else {
        let message = format!(
            "update paused: {failures} of {slots} tasks failed and there is no previous spec to roll back to"
        );
        tracing::warn!(
            service_id = %service.id,
            service = %service.spec.annotations.name,
            failures,
            slots,
            "rollback requested with no previous spec; pausing instead"
        );
        return status_action(service, UpdateStateKind::Paused, &message, now);
    };
    let mut updated = (*service).clone();
    updated.spec = previous;
    // Cleared, as SwarmKit clears it: what was rolled back is not a target to
    // return to, and the state machine already forbids rolling back a rollback.
    updated.previous_spec = None;
    updated.update_status = Some(UpdateStatus {
        state: UpdateStateKind::RollbackStarted,
        started_at: Some(now),
        completed_at: None,
        message: format!("rolling back: {failures} of {slots} tasks failed"),
    });
    updated.meta.updated_at = now;
    tracing::warn!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        failures,
        slots,
        image = %updated.spec.task.container.image,
        from = describe_state(Some(UpdateStateKind::Updating)),
        to = describe_state(Some(UpdateStateKind::RollbackStarted)),
        "update failed; rolling back to the previous spec"
    );
    StoreAction::Update(StoreObject::Service(updated))
}

/// The work the dirty slots need, subject to `parallelism` and `delay`.
///
/// Two kinds of action, and only the second is rationed:
///
/// - **finishing** a slot this update already touched (promote its new task,
///   shut down what it replaces, drop a duplicate). A slot in flight must be
///   allowed to finish, or a batch could never drain.
/// - **starting** a slot that is still entirely on the old spec. This is what
///   `parallelism` bounds and what `delay` paces.
fn slot_work(
    service: &Service,
    slots: &BTreeMap<Unit, SlotView>,
    phases: &Phases,
    config: &UpdateConfig,
    monitor: Duration,
    now: SystemTime,
) -> Plan {
    let target = initial_desired_state(&service.spec);
    let mut actions: Vec<StoreAction> = Vec::new();
    let mut wake: Option<Duration> = None;

    let in_flight = phases
        .values()
        .filter(|phase| matches!(phase, Phase::Watching | Phase::Pending { started: true }))
        .count();
    let mut budget = if config.parallelism == 0 {
        usize::MAX
    } else {
        usize::try_from(config.parallelism)
            .unwrap_or(usize::MAX)
            .saturating_sub(in_flight)
    };

    // The pause that follows each finished slot (SWK §7.3 step 5). Level form:
    // no new slot starts until `delay` has passed since the most recent
    // current-spec task started serving.
    if let Some(since) = last_started(slots, target).filter(|_| !config.delay.is_zero()) {
        let waited = elapsed(now, since);
        if waited < config.delay {
            budget = 0;
            sooner(&mut wake, config.delay.saturating_sub(waited));
        }
    }

    for (unit, view) in slots {
        let slot = unit.0;
        match phases.get(unit) {
            Some(Phase::Pending { .. }) => {}
            // Absent, Settled: nothing to do. Watching: waiting on the monitor
            // window, which only needs a timer.
            Some(Phase::Watching) => {
                if let [task] = view.clean.as_slice()
                    && task.status.state >= target.as_task_state()
                {
                    let watched = elapsed(now, task_timestamp(task));
                    sooner(&mut wake, monitor.saturating_sub(watched));
                }
                continue;
            }
            _ => continue,
        }

        let (slot_actions, slot_wake) = if view.clean.is_empty() {
            if view.touched {
                // This update's task for the slot is gone; its replacement is
                // the restart supervisor's (see the module docs).
                continue;
            }
            if budget == 0 {
                continue;
            }
            budget -= 1;
            (start_slot(service, unit, view, config.order, target), None)
        } else {
            // The slot is in flight: finish it.
            finish_slot(service, slot, view, config.order, target, now)
        };
        if let Some(slot_wake) = slot_wake {
            sooner(&mut wake, slot_wake);
        }
        // One slot's actions are one unit: a `CREATE` without the `SHUTDOWN`
        // that goes with it would leave two live tasks in a slot, so a slot
        // that does not fit is left for the next pass rather than half-applied.
        // `- 1` leaves room for the `update_status` write the caller prepends.
        if actions.len() + slot_actions.len() > MAX_TX_ACTIONS - 1 {
            tracing::debug!(
                service_id = %service.id,
                slot,
                actions = actions.len(),
                "transaction is full; the rest of the batch waits for the next pass"
            );
            break;
        }
        actions.extend(slot_actions);
    }

    Plan { actions, wake }
}

/// Starts one slot: a replacement task, plus — for `stop-first` — the order to
/// stop what it replaces, in the same transaction so the slot is never empty
/// (the rule [`crate::restart`] documents at length).
fn start_slot(
    service: &Service,
    unit: &Unit,
    view: &SlotView,
    order: UpdateOrder,
    target: DesiredState,
) -> Vec<StoreAction> {
    let (slot, node) = unit;
    let mut actions = Vec::new();
    // A global service's replacement is pinned to the same node: that node *is*
    // the unit being updated (SWK §7.8).
    let mut replacement = match node {
        Some(node_id) => new_global_task(service, node_id),
        None => new_task(service, *slot),
    };
    let waits_for_a_predecessor =
        order == UpdateOrder::StopFirst && !(view.stale.is_empty() && view.stopping.is_empty());
    replacement.desired_state = if waits_for_a_predecessor {
        // Prepared but not started: promoted once the predecessor stops, so the
        // slot never runs two containers.
        DesiredState::Ready.min(target)
    } else {
        // Nothing to wait for — `start-first`, or a slot that is already empty
        // (an abandoned one, or one a rollback left behind). Creating it at
        // `READY` here would only cost a promotion round trip.
        target
    };
    tracing::info!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        task_id = %replacement.id,
        slot,
        replaces = view.stale.len(),
        order = describe_order(order),
        image = %replacement.spec.container.image,
        to = %replacement.desired_state,
        "updating slot: replacement task created"
    );
    actions.push(StoreAction::Create(StoreObject::Task(replacement)));
    if order == UpdateOrder::StopFirst {
        for old in &view.stale {
            actions.extend(shut_down(
                service,
                *slot,
                old,
                "replaced by an updated task",
            ));
        }
    }
    actions
}

/// Finishes a slot that already holds a current-spec task: keeps exactly one of
/// them, stops what it replaces, and promotes it when the order says so.
fn finish_slot(
    service: &Service,
    slot: u64,
    view: &SlotView,
    order: UpdateOrder,
    target: DesiredState,
    now: SystemTime,
) -> (Vec<StoreAction>, Option<Duration>) {
    let mut actions = Vec::new();
    let mut wake = None;
    // Callers reach this only for a slot that holds one; an empty slice would
    // mean the phase and the view disagree, and doing nothing is the safe
    // reading of that.
    let Some(keeper) = keeper(&view.clean) else {
        return (actions, wake);
    };

    // More than one task on the current spec: keep the one furthest along.
    for extra in view.clean.iter().filter(|task| task.id != keeper.id) {
        actions.extend(shut_down(
            service,
            slot,
            extra,
            "duplicate task in an updated slot",
        ));
    }

    match order {
        UpdateOrder::StopFirst => {
            for old in &view.stale {
                actions.extend(shut_down(service, slot, old, "replaced by an updated task"));
            }
            if keeper.desired_state < target && view.stale.is_empty() {
                match stop_pending(view, now) {
                    None => actions.extend(promote(service, slot, keeper, target)),
                    Some(remaining) => wake = Some(remaining),
                }
            }
        }
        UpdateOrder::StartFirst => {
            // Only once the replacement is observed serving (SWK §7.3 step 6).
            if keeper.status.state >= target.as_task_state() {
                for old in &view.stale {
                    actions.extend(shut_down(service, slot, old, "replaced by an updated task"));
                }
            }
        }
    }
    (actions, wake)
}

/// How long a `stop-first` promotion must still wait for the predecessors to
/// stop, or `None` when they are gone (or took too long — [`OLD_TASK_TIMEOUT`],
/// because a predecessor on a node that will never answer must not keep the
/// slot down).
fn stop_pending(view: &SlotView, now: SystemTime) -> Option<Duration> {
    let mut remaining = None;
    for stopping in &view.stopping {
        let waited = elapsed(now, stopping.meta.updated_at);
        if waited >= OLD_TASK_TIMEOUT {
            continue;
        }
        sooner(&mut remaining, OLD_TASK_TIMEOUT.saturating_sub(waited));
    }
    remaining
}

/// Raises `task` to `SHUTDOWN`, with the line an operator greps for.
fn shut_down(service: &Service, slot: u64, task: &Task, why: &'static str) -> Option<StoreAction> {
    let action = raise_desired_state(task, DesiredState::Shutdown)?;
    tracing::info!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        task_id = %task.id,
        slot,
        node_id = ?task.node_id,
        from = %task.desired_state,
        to = %DesiredState::Shutdown,
        reason = why,
        "updating slot: stopping the task it replaces"
    );
    Some(action)
}

/// Promotes a `stop-first` replacement now that its predecessor has stopped.
fn promote(service: &Service, slot: u64, task: &Task, target: DesiredState) -> Option<StoreAction> {
    let action = raise_desired_state(task, target)?;
    tracing::info!(
        service_id = %service.id,
        service = %service.spec.annotations.name,
        task_id = %task.id,
        slot,
        node_id = ?task.node_id,
        from = %task.desired_state,
        to = %target,
        "updating slot: promoting the replacement, its predecessor has stopped"
    );
    Some(action)
}

/// Which of a slot's current-spec tasks to keep: the one furthest along, then
/// the oldest, then by ID so the choice is stable across passes and replicas.
fn keeper(clean: &[Arc<Task>]) -> Option<&Arc<Task>> {
    clean.iter().max_by(|a, b| {
        a.status
            .state
            .cmp(&b.status.state)
            .then(b.meta.created_at.cmp(&a.meta.created_at))
            .then(b.id.cmp(&a.id))
    })
}

/// When the most recent current-spec task of any slot started serving — the
/// anchor of the inter-batch delay.
fn last_started(slots: &BTreeMap<Unit, SlotView>, target: DesiredState) -> Option<SystemTime> {
    slots
        .values()
        .flat_map(|view| view.clean.iter())
        .filter(|task| task.status.state >= target.as_task_state())
        .map(|task| task_timestamp(task))
        .max()
}

/// `now - then`, never negative: these are wall-clock timestamps written by
/// managers and agents whose clocks are only loosely tied together.
fn elapsed(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or(Duration::ZERO)
}

/// Keeps the earlier of the wake-up already planned and `candidate`.
fn sooner(current: &mut Option<Duration>, candidate: Duration) {
    *current = Some(match *current {
        Some(planned) => planned.min(candidate),
        None => candidate,
    });
}

/// Builds the `Update` action that publishes an update's progress.
///
/// `started_at` survives a state change within the same update (so an operator
/// sees when the rollout began, not when it last progressed); `completed_at` is
/// stamped when the update reaches a final state.
fn status_action(
    service: &Service,
    state: UpdateStateKind,
    message: &str,
    now: SystemTime,
) -> StoreAction {
    let previous = service.update_status.as_ref();
    let final_state = !matches!(
        state,
        UpdateStateKind::Updating | UpdateStateKind::RollbackStarted
    );
    let started_at = match previous {
        Some(previous) if previous.state == state || final_state => previous.started_at,
        _ => Some(now),
    };
    let mut updated = (*service).clone();
    updated.update_status = Some(UpdateStatus {
        state,
        started_at,
        completed_at: final_state.then_some(now),
        message: message.to_owned(),
    });
    updated.meta.updated_at = now;
    StoreAction::Update(StoreObject::Service(updated))
}

/// The operator-facing progress line, plain ASCII (`satl service inspect`'s
/// `UpdateStatus.Message`).
///
/// It counts whatever the service's unit is: slots for a replicated service,
/// **nodes** for a global one — "3 of 3 slots updated" would be a lie about a
/// service that has no slots.
fn progress_message(state: UpdateStateKind, phases: &Phases, shape: &Shape) -> String {
    let done = phases
        .values()
        .filter(|phase| **phase == Phase::Settled)
        .count();
    let units = shape.count();
    let what = shape.noun();
    match state {
        UpdateStateKind::Updating => format!("updating: {done} of {units} {what} updated"),
        UpdateStateKind::Completed => format!("update completed: {units} {what} updated"),
        UpdateStateKind::RollbackStarted => {
            format!("rolling back: {done} of {units} {what} rolled back")
        }
        UpdateStateKind::RollbackCompleted => {
            format!("rollback completed: {units} {what} rolled back")
        }
        // The pausing states carry the failure count instead; those messages are
        // written by `failure_verdict`.
        UpdateStateKind::Paused => "update paused".to_owned(),
        UpdateStateKind::RollbackPaused => "rollback paused".to_owned(),
    }
}

/// Greppable name of an update state, for logs.
fn describe_state(state: Option<UpdateStateKind>) -> &'static str {
    match state {
        None => "none",
        Some(UpdateStateKind::Updating) => "updating",
        Some(UpdateStateKind::Completed) => "completed",
        Some(UpdateStateKind::Paused) => "paused",
        Some(UpdateStateKind::RollbackStarted) => "rollback_started",
        Some(UpdateStateKind::RollbackCompleted) => "rollback_completed",
        Some(UpdateStateKind::RollbackPaused) => "rollback_paused",
    }
}

/// Greppable name of an update order, for logs.
fn describe_order(order: UpdateOrder) -> &'static str {
    match order {
        UpdateOrder::StopFirst => "stop-first",
        UpdateOrder::StartFirst => "start-first",
    }
}

/// Greppable name of a failure action, for logs.
fn describe_action(action: FailureAction) -> &'static str {
    match action {
        FailureAction::Pause => "pause",
        FailureAction::Continue => "continue",
        FailureAction::Rollback => "rollback",
    }
}

#[cfg(test)]
mod tests {
    use satl_core::{Endpoint, Version};

    use crate::testing::{planted_task, sample_service};

    use super::*;

    /// A service at a known spec version, with an `UpdateConfig` under test.
    fn service_at(version: u64, config: UpdateConfig) -> Service {
        let mut service = sample_service("web", 3);
        service.spec_version = Version(version);
        service.spec.update = Some(config);
        service
    }

    /// A task of `service`, stamped from `version`, in the given states.
    fn task_at(
        service: &Service,
        version: u64,
        state: TaskState,
        desired: DesiredState,
        age: Duration,
    ) -> Arc<Task> {
        let now = SystemTime::now();
        let mut task = planted_task(service, 1, state, desired, now - age);
        task.spec_version = Some(Version(version));
        task.status.applied_at = Some(now - age);
        task.endpoint = service.spec.endpoint.clone().map(|spec| Endpoint {
            spec,
            ports: Vec::new(),
        });
        Arc::new(task)
    }

    /// A slot holding exactly the given current-spec and old-spec tasks.
    fn slot(clean: Vec<Arc<Task>>, stale: Vec<Arc<Task>>, stopping: Vec<Arc<Task>>) -> SlotView {
        SlotView {
            touched: !clean.is_empty() || !stopping.is_empty(),
            abandoned: false,
            clean,
            stale,
            stopping,
        }
    }

    fn now() -> SystemTime {
        SystemTime::now()
    }

    #[test]
    fn the_monitor_window_is_extended_past_a_longer_delay() {
        let mut config = UpdateConfig {
            monitor: Duration::from_secs(5),
            delay: Duration::ZERO,
            ..UpdateConfig::default()
        };
        assert_eq!(monitoring_period(&config), Duration::from_secs(5));
        config.delay = Duration::from_secs(4);
        assert_eq!(monitoring_period(&config), Duration::from_secs(5));
        // Delay at least as long as the monitor: watch past the pause, so a
        // paced update still observes each task it started (SWK §7.3 step 4).
        config.delay = Duration::from_secs(5);
        assert_eq!(monitoring_period(&config), Duration::from_secs(6));
        config.delay = Duration::from_secs(30);
        assert_eq!(monitoring_period(&config), Duration::from_secs(31));
    }

    #[test]
    fn phases_read_a_slot_the_way_the_batch_needs_to() {
        let service = service_at(7, UpdateConfig::default());
        let monitor = Duration::from_secs(5);
        let running = |version, age| {
            task_at(
                &service,
                version,
                TaskState::Running,
                DesiredState::Running,
                age,
            )
        };

        // Untouched, entirely on the old spec: a slot to start.
        assert_eq!(
            phase(
                &slot(vec![], vec![running(1, Duration::ZERO)], vec![]),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Pending { started: false }
        );

        // Touched, both tasks present: in flight, with work to do.
        assert_eq!(
            phase(
                &slot(
                    vec![running(7, Duration::ZERO)],
                    vec![running(1, Duration::ZERO)],
                    vec![]
                ),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Pending { started: true }
        );

        // One current-spec task, running but not for long enough.
        assert_eq!(
            phase(
                &slot(vec![running(7, Duration::from_secs(1))], vec![], vec![]),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Watching
        );

        // ... and once it has been.
        assert_eq!(
            phase(
                &slot(vec![running(7, Duration::from_secs(6))], vec![], vec![]),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Settled
        );

        // Started but not serving yet: in flight, nothing to decide.
        assert_eq!(
            phase(
                &slot(
                    vec![task_at(
                        &service,
                        7,
                        TaskState::Preparing,
                        DesiredState::Running,
                        Duration::ZERO
                    )],
                    vec![],
                    vec![]
                ),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Watching
        );

        // Prepared and waiting for promotion: work, whatever its age.
        assert_eq!(
            phase(
                &slot(
                    vec![task_at(
                        &service,
                        7,
                        TaskState::Ready,
                        DesiredState::Ready,
                        Duration::from_mins(1)
                    )],
                    vec![],
                    vec![]
                ),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Pending { started: true }
        );
    }

    /// The two slot shapes that decide *who owns the slot*, which is where the
    /// updater and the restart supervisor could collide.
    #[test]
    fn phases_say_which_slots_belong_to_someone_else() {
        let service = service_at(7, UpdateConfig::default());
        let monitor = Duration::from_secs(5);
        let running = |version, age| {
            task_at(
                &service,
                version,
                TaskState::Running,
                DesiredState::Running,
                age,
            )
        };

        // Two current-spec tasks in one slot: converge to one (SWK §7.3 step 2).
        assert_eq!(
            phase(
                &slot(
                    vec![
                        running(7, Duration::from_mins(1)),
                        running(7, Duration::from_mins(1))
                    ],
                    vec![],
                    vec![]
                ),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Pending { started: true }
        );

        // Empty and never touched by this update: somebody else's slot.
        assert_eq!(
            phase(
                &slot(vec![], vec![], vec![]),
                DesiredState::Running,
                monitor,
                now(),
                false
            ),
            Phase::Absent
        );

        // Empty but touched: this update's task died and the restart supervisor
        // owes the slot a replacement. In flight, and not a slot to start again.
        let mut dead = slot(vec![], vec![], vec![]);
        dead.touched = true;
        assert_eq!(
            phase(&dead, DesiredState::Running, monitor, now(), false),
            Phase::Watching
        );
    }

    /// The measured race behind M6d's fix: mid-update, an empty untouched slot
    /// is the supervisor's pending refill, and the update must *wait* for it —
    /// a rollback whose refill tasks failed immediately raced `finished` and
    /// reported `RollbackCompleted` with a slot serving nothing, where the
    /// failures should have paused it. Steady state is unchanged: with no
    /// update in flight the same slot is Absent (not the updater's business).
    #[test]
    fn an_empty_slot_mid_update_is_in_flight_not_absent() {
        let monitor = Duration::from_secs(5);
        let empty = slot(vec![], vec![], vec![]);
        assert_eq!(
            phase(&empty, DesiredState::Running, monitor, now(), false),
            Phase::Absent
        );
        assert_eq!(
            phase(&empty, DesiredState::Running, monitor, now(), true),
            Phase::Watching
        );
    }

    /// A `docker create`d service (autostart=false) settles at READY: its
    /// target desired state is `Ready`, and waiting for RUNNING would hang the
    /// update forever.
    #[test]
    fn a_service_that_is_not_meant_to_run_settles_at_ready() {
        let service = service_at(7, UpdateConfig::default());
        let ready = task_at(
            &service,
            7,
            TaskState::Ready,
            DesiredState::Ready,
            Duration::from_secs(30),
        );
        assert_eq!(
            phase(
                &slot(vec![ready], vec![], vec![]),
                DesiredState::Ready,
                Duration::from_secs(5),
                now(),
                false
            ),
            Phase::Settled
        );
    }

    // ---- what an action turned out to be ---------------------------------

    fn service_of(action: &StoreAction) -> &Service {
        match action {
            StoreAction::Update(StoreObject::Service(service)) => service,
            other => panic!("expected a service update, got {other:?}"),
        }
    }

    fn created(actions: &[StoreAction]) -> Vec<&Task> {
        actions
            .iter()
            .filter_map(|action| match action {
                StoreAction::Create(StoreObject::Task(task)) => Some(task),
                _ => None,
            })
            .collect()
    }

    fn updated(actions: &[StoreAction]) -> Vec<&Task> {
        actions
            .iter()
            .filter_map(|action| match action {
                StoreAction::Update(StoreObject::Task(task)) => Some(task),
                _ => None,
            })
            .collect()
    }

    /// `slot_work` over a set of slots, with every phase derived the same way
    /// the planner derives it.
    fn work(service: &Service, slots: &BTreeMap<Unit, SlotView>, config: &UpdateConfig) -> Plan {
        let target = initial_desired_state(&service.spec);
        let monitor = monitoring_period(config);
        let now = now();
        let phases = slots
            .iter()
            .map(|(unit, view)| (unit.clone(), phase(view, target, monitor, now, true)))
            .collect();
        slot_work(service, slots, &phases, config, monitor, now)
    }

    /// A replicated service's unit: a slot number and no node.
    fn slot_unit(slot: u64) -> Unit {
        (slot, None)
    }

    fn slots_of(entries: Vec<(u64, SlotView)>) -> BTreeMap<Unit, SlotView> {
        entries
            .into_iter()
            .map(|(slot, view)| (slot_unit(slot), view))
            .collect()
    }

    fn phases_of(entries: Vec<(u64, Phase)>) -> Phases {
        entries
            .into_iter()
            .map(|(slot, phase)| (slot_unit(slot), phase))
            .collect()
    }

    // ---- units: slots, or nodes ------------------------------------------

    /// A replicated service's units are its slots; a global service's are the
    /// eligible nodes (SWK §7.8).
    #[test]
    fn a_shape_owns_its_slots_or_its_eligible_nodes() {
        let replicated = Shape::Replicated { replicas: 3 };
        let node = Id::generate();
        assert!(replicated.owns(&slot_unit(1)));
        assert!(replicated.owns(&slot_unit(3)));
        assert!(!replicated.owns(&slot_unit(4)), "the scale-down's business");
        assert!(
            !replicated.owns(&slot_unit(0)),
            "slot 0 is global-task territory (SWK §4.5)"
        );
        assert!(!replicated.owns(&(0, Some(node.clone()))));
        assert_eq!(replicated.count(), 3);

        let global = Shape::Global {
            nodes: BTreeSet::from([node.clone()]),
        };
        assert!(global.owns(&(0, Some(node.clone()))));
        assert!(
            !global.owns(&(0, Some(Id::generate()))),
            "a node that is not eligible belongs to the global orchestrator"
        );
        assert!(!global.owns(&slot_unit(1)));
        assert_eq!(global.count(), 1);
    }

    /// A global task's unit is its node; an unbound one has no unit at all.
    #[test]
    fn a_global_tasks_unit_is_the_node_it_is_pinned_to() {
        let mut service = service_at(7, UpdateConfig::default());
        service.spec.mode = ServiceMode::Global;
        let node = Id::generate();
        let mut task = planted_task(
            &service,
            0,
            TaskState::Running,
            DesiredState::Running,
            now(),
        );
        assert_eq!(
            unit_of(&task),
            None,
            "a global task with no node has nowhere to be updated"
        );
        task.node_id = Some(node.clone());
        assert_eq!(unit_of(&task), Some((0, Some(node))));

        let replicated = planted_task(
            &service,
            2,
            TaskState::Running,
            DesiredState::Running,
            now(),
        );
        assert_eq!(unit_of(&replicated), Some(slot_unit(2)));
    }

    /// The replacement a global unit starts is pinned to that unit's node, and
    /// carries slot 0 and the node-based task name (SWK §4.5).
    #[test]
    fn starting_a_global_unit_pins_the_replacement_to_its_node() {
        let mut service = service_at(7, UpdateConfig::default());
        service.spec.mode = ServiceMode::Global;
        let node = Id::generate();
        let old = task_at(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        );
        let unit = (0, Some(node.clone()));
        let actions = start_slot(
            &service,
            &unit,
            &slot(vec![], vec![old], vec![]),
            UpdateOrder::StopFirst,
            DesiredState::Running,
        );
        let created = created(&actions);
        let [replacement] = created.as_slice() else {
            panic!("expected exactly one replacement, got {created:?}");
        };
        assert_eq!(replacement.node_id.as_ref(), Some(&node));
        assert_eq!(replacement.slot, 0);
        assert!(
            replacement.annotations.name.contains(&node.to_string()),
            "the node ID takes the slot's place in the name: {}",
            replacement.annotations.name
        );
        assert_eq!(
            replacement.desired_state,
            DesiredState::Ready,
            "stop-first still waits for its predecessor"
        );
        assert_eq!(updated(&actions).len(), 1, "the predecessor is stopped");
    }

    // ---- failures --------------------------------------------------------

    #[test]
    fn a_failure_pauses_an_update_whose_action_is_pause() {
        let mut service = service_at(7, UpdateConfig::default());
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: "updating: 0 of 3 slots updated".to_owned(),
        });
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        let action = failure_verdict(
            &service,
            &[Arc::clone(&failed)],
            &phases,
            &UpdateConfig::default(),
            now(),
        )
        .expect("the default ratio of 0 tolerates nothing");
        let updated = service_of(&action);
        let status = updated.update_status.as_ref().expect("status");
        assert_eq!(status.state, UpdateStateKind::Paused);
        assert!(status.completed_at.is_some(), "a pause is a final state");
        assert!(status.message.contains("1 of 1 tasks failed"), "{status:?}");
        assert_eq!(updated.spec, service.spec, "a pause changes no spec");
    }

    #[test]
    fn a_failure_under_the_ratio_is_tolerated() {
        let mut service = service_at(7, UpdateConfig::default());
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let config = UpdateConfig {
            max_failure_ratio: 0.5,
            ..UpdateConfig::default()
        };
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        // One failure over four slots is 0.25: inside the budget.
        let four = phases_of(vec![
            (1, Phase::Pending { started: true }),
            (2, Phase::Settled),
            (3, Phase::Settled),
            (4, Phase::Settled),
        ]);
        assert!(failure_verdict(&service, &[Arc::clone(&failed)], &four, &config, now()).is_none());
        // One over two is 0.5, which is *not* over the ratio either: SwarmKit
        // compares strictly greater.
        let two = phases_of(vec![
            (1, Phase::Pending { started: true }),
            (2, Phase::Settled),
        ]);
        assert!(failure_verdict(&service, &[Arc::clone(&failed)], &two, &config, now()).is_none());
        // Two over three is 0.66: over.
        let another = task_at(
            &service,
            7,
            TaskState::Rejected,
            DesiredState::Running,
            Duration::ZERO,
        );
        let three = phases_of(vec![
            (1, Phase::Pending { started: true }),
            (2, Phase::Pending { started: true }),
            (3, Phase::Settled),
        ]);
        assert!(failure_verdict(&service, &[failed, another], &three, &config, now()).is_some());
    }

    #[test]
    fn failures_of_other_specs_and_ordered_shutdowns_do_not_count() {
        let mut service = service_at(7, UpdateConfig::default());
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        let cases = [
            // The predecessor this update stopped, reporting it stopped.
            task_at(
                &service,
                1,
                TaskState::Shutdown,
                DesiredState::Shutdown,
                Duration::ZERO,
            ),
            // A current-spec task the updater stopped itself (a duplicate).
            task_at(
                &service,
                7,
                TaskState::Shutdown,
                DesiredState::Shutdown,
                Duration::ZERO,
            ),
            // An old-spec task that crashed while waiting its turn: the restart
            // supervisor's business, not this update's.
            task_at(
                &service,
                1,
                TaskState::Failed,
                DesiredState::Running,
                Duration::ZERO,
            ),
            // Still running.
            task_at(
                &service,
                7,
                TaskState::Running,
                DesiredState::Running,
                Duration::ZERO,
            ),
        ];
        for task in cases {
            let state = task.status.state;
            assert!(
                failure_verdict(&service, &[task], &phases, &UpdateConfig::default(), now())
                    .is_none(),
                "{state} must not count as a failure of this update"
            );
        }
    }

    #[test]
    fn a_failure_rolls_back_when_the_action_says_so() {
        let config = UpdateConfig {
            failure_action: FailureAction::Rollback,
            ..UpdateConfig::default()
        };
        let mut service = service_at(7, config);
        let mut previous = service.spec.clone();
        previous.task.container.image = "127.0.0.1:5000/freebsd-nginx:working".to_owned();
        service.previous_spec = Some(previous.clone());
        service.spec.task.container.image = "127.0.0.1:5000/freebsd-nginx:broken".to_owned();
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        let action =
            failure_verdict(&service, &[failed], &phases, &config, now()).expect("rollback");
        let updated = service_of(&action);
        assert_eq!(updated.spec, previous, "the spec goes back");
        assert!(
            updated.previous_spec.is_none(),
            "cleared, so nothing can roll back to the broken spec"
        );
        let status = updated.update_status.as_ref().expect("status");
        assert_eq!(status.state, UpdateStateKind::RollbackStarted);
        assert!(status.completed_at.is_none(), "the rollback has just begun");
    }

    #[test]
    fn a_rollback_with_nowhere_to_go_pauses() {
        let config = UpdateConfig {
            failure_action: FailureAction::Rollback,
            ..UpdateConfig::default()
        };
        let mut service = service_at(7, config);
        service.previous_spec = None;
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        let action = failure_verdict(&service, &[failed], &phases, &config, now()).expect("pause");
        let updated = service_of(&action);
        let status = updated.update_status.as_ref().expect("status");
        assert_eq!(status.state, UpdateStateKind::Paused);
        assert!(status.message.contains("no previous spec"), "{status:?}");
        assert_eq!(updated.spec, service.spec);
    }

    /// The rule the state machine exists for: a rollback that fails pauses, and
    /// never rolls back again (architecture §5).
    #[test]
    fn a_failing_rollback_pauses_and_never_rolls_back_again() {
        let config = UpdateConfig {
            failure_action: FailureAction::Rollback,
            ..UpdateConfig::default()
        };
        let mut service = service_at(7, config);
        service.spec.rollback = Some(config);
        // A previous spec is present *and* the action says rollback: the only
        // thing that keeps this from rolling back twice is the state.
        service.previous_spec = Some(service.spec.clone());
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::RollbackStarted,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        let action =
            failure_verdict(&service, &[failed], &phases, &config, now()).expect("a verdict");
        let updated = service_of(&action);
        let status = updated.update_status.as_ref().expect("status");
        assert_eq!(status.state, UpdateStateKind::RollbackPaused);
        assert_eq!(updated.spec, service.spec, "the spec stays where it is");
        assert_eq!(
            updated.previous_spec, service.previous_spec,
            "and nothing is swapped back"
        );
    }

    #[test]
    fn failure_action_continue_never_stops_an_update() {
        let config = UpdateConfig {
            failure_action: FailureAction::Continue,
            ..UpdateConfig::default()
        };
        let mut service = service_at(7, config);
        service.update_status = Some(UpdateStatus {
            state: UpdateStateKind::Updating,
            started_at: Some(now()),
            completed_at: None,
            message: String::new(),
        });
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        assert!(failure_verdict(&service, &[failed], &phases, &config, now()).is_none());
    }

    #[test]
    fn a_service_with_no_update_in_flight_is_not_judged_for_failures() {
        let service = service_at(7, UpdateConfig::default());
        let failed = task_at(
            &service,
            7,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        let phases = phases_of(vec![(1, Phase::Pending { started: true })]);
        assert!(
            failure_verdict(
                &service,
                &[failed],
                &phases,
                &UpdateConfig::default(),
                now()
            )
            .is_none(),
            "a crash outside an update is the restart supervisor's business"
        );
    }

    // ---- batches, order and pacing ---------------------------------------

    #[test]
    fn stop_first_creates_the_replacement_ready_and_stops_the_predecessor() {
        let service = service_at(7, UpdateConfig::default());
        let old = task_at(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        );
        let slots = slots_of(vec![(1, slot(vec![], vec![Arc::clone(&old)], vec![]))]);
        let plan = work(&service, &slots, &UpdateConfig::default());

        let created = created(&plan.actions);
        assert_eq!(created.len(), 1);
        assert_eq!(
            created[0].desired_state,
            DesiredState::Ready,
            "prepared, not started: the predecessor is still serving"
        );
        assert_eq!(created[0].slot, 1);
        assert_eq!(created[0].spec_version, Some(service.spec_version));
        let updated = updated(&plan.actions);
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].id, old.id);
        assert_eq!(
            updated[0].desired_state,
            DesiredState::Shutdown,
            "and the order to stop it travels in the same transaction, so the \
             slot is never empty"
        );
    }

    #[test]
    fn start_first_starts_the_replacement_and_keeps_the_predecessor_until_it_serves() {
        let config = UpdateConfig {
            order: UpdateOrder::StartFirst,
            ..UpdateConfig::default()
        };
        let service = service_at(7, config);
        let old = task_at(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        );

        // Nothing new yet: create it, started, and leave the predecessor alone.
        let slots = slots_of(vec![(1, slot(vec![], vec![Arc::clone(&old)], vec![]))]);
        let plan = work(&service, &slots, &config);
        let created = created(&plan.actions);
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].desired_state, DesiredState::Running);
        assert!(
            updated(&plan.actions).is_empty(),
            "the old task keeps serving until the new one does"
        );

        // The replacement is up but not serving yet: still no shutdown.
        let starting = task_at(
            &service,
            7,
            TaskState::Starting,
            DesiredState::Running,
            Duration::ZERO,
        );
        let slots = slots_of(vec![(
            1,
            slot(vec![starting], vec![Arc::clone(&old)], vec![]),
        )]);
        assert!(updated(&work(&service, &slots, &config).actions).is_empty());

        // Serving: now the predecessor goes.
        let running = task_at(
            &service,
            7,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        );
        let slots = slots_of(vec![(
            1,
            slot(vec![running], vec![Arc::clone(&old)], vec![]),
        )]);
        let plan = work(&service, &slots, &config);
        let stopped = updated(&plan.actions);
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].id, old.id);
        assert_eq!(stopped[0].desired_state, DesiredState::Shutdown);
    }

    #[test]
    fn a_stop_first_replacement_is_promoted_once_its_predecessor_has_stopped() {
        let service = service_at(7, UpdateConfig::default());
        let ready = task_at(
            &service,
            7,
            TaskState::Ready,
            DesiredState::Ready,
            Duration::ZERO,
        );
        let mut stopping = (*task_at(
            &service,
            1,
            TaskState::Running,
            DesiredState::Shutdown,
            Duration::ZERO,
        ))
        .clone();
        stopping.meta.updated_at = now();
        let stopping = Arc::new(stopping);

        // The predecessor has not stopped yet: wait, and say when to look again.
        let slots = slots_of(vec![(
            1,
            slot(
                vec![Arc::clone(&ready)],
                vec![],
                vec![Arc::clone(&stopping)],
            ),
        )]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert!(plan.actions.is_empty());
        let wake = plan.wake.expect("a bounded wait");
        assert!(
            wake <= OLD_TASK_TIMEOUT && wake > Duration::ZERO,
            "{wake:?}"
        );

        // It stopped: promote.
        let slots = slots_of(vec![(1, slot(vec![Arc::clone(&ready)], vec![], vec![]))]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        let promoted = updated(&plan.actions);
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].id, ready.id);
        assert_eq!(promoted[0].desired_state, DesiredState::Running);

        // Or it never will: past the bound, the slot is promoted anyway rather
        // than staying down for a node that may never answer again.
        let mut stuck = (*stopping).clone();
        stuck.meta.updated_at = now() - OLD_TASK_TIMEOUT - Duration::from_secs(1);
        let slots = slots_of(vec![(
            1,
            slot(vec![Arc::clone(&ready)], vec![], vec![Arc::new(stuck)]),
        )]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert_eq!(updated(&plan.actions).len(), 1);
        assert!(plan.wake.is_none());
    }

    #[test]
    fn parallelism_bounds_how_many_slots_are_disturbed_at_once() {
        let service = service_at(7, UpdateConfig::default());
        let old = |slot_no| {
            let mut task = (*task_at(
                &service,
                1,
                TaskState::Running,
                DesiredState::Running,
                Duration::ZERO,
            ))
            .clone();
            task.slot = slot_no;
            Arc::new(task)
        };
        let six = || {
            slots_of(
                (1..=6)
                    .map(|slot_no| (slot_no, slot(vec![], vec![old(slot_no)], vec![])))
                    .collect(),
            )
        };

        // The default: one slot at a time.
        let plan = work(&service, &six(), &UpdateConfig::default());
        assert_eq!(created(&plan.actions).len(), 1);
        assert_eq!(created(&plan.actions)[0].slot, 1, "lowest slot first");

        // Two at a time.
        let config = UpdateConfig {
            parallelism: 2,
            ..UpdateConfig::default()
        };
        let plan = work(&service, &six(), &config);
        let started: Vec<u64> = created(&plan.actions).iter().map(|t| t.slot).collect();
        assert_eq!(started, vec![1, 2]);

        // Unlimited.
        let config = UpdateConfig {
            parallelism: 0,
            ..UpdateConfig::default()
        };
        let plan = work(&service, &six(), &config);
        assert_eq!(created(&plan.actions).len(), 6);
    }

    /// The batch is what `parallelism` bounds, and a slot stays in it until its
    /// replacement has been observed running for the monitor window. That is
    /// the health gate: with a healthcheck, RUNNING means healthy.
    #[test]
    fn a_slot_still_inside_its_monitor_window_holds_the_batch() {
        let service = service_at(7, UpdateConfig::default());
        let monitor = monitoring_period(&UpdateConfig::default());
        let stale = task_at(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        );
        let watched = |age| {
            let mut task =
                (*task_at(&service, 7, TaskState::Running, DesiredState::Running, age)).clone();
            task.slot = 1;
            Arc::new(task)
        };
        let mut second = (*stale).clone();
        second.slot = 2;
        let second = Arc::new(second);

        // Slot 1 is done but still being watched, slot 2 is untouched: the
        // batch of one is full.
        let slots = slots_of(vec![
            (
                1,
                slot(vec![watched(Duration::from_secs(1))], vec![], vec![]),
            ),
            (2, slot(vec![], vec![Arc::clone(&second)], vec![])),
        ]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert!(created(&plan.actions).is_empty(), "slot 2 waits its turn");
        let wake = plan.wake.expect("the monitor window closing");
        assert!(wake <= monitor, "{wake:?}");

        // Past the window: slot 1 settles and slot 2 starts.
        let slots = slots_of(vec![
            (
                1,
                slot(
                    vec![watched(monitor + Duration::from_secs(1))],
                    vec![],
                    vec![],
                ),
            ),
            (2, slot(vec![], vec![second], vec![])),
        ]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert_eq!(created(&plan.actions).len(), 1);
        assert_eq!(created(&plan.actions)[0].slot, 2);
    }

    #[test]
    fn the_delay_paces_the_batches() {
        let config = UpdateConfig {
            delay: Duration::from_secs(30),
            ..UpdateConfig::default()
        };
        let service = service_at(7, config);
        // Slot 1 is on the new spec and has been serving for 10s; slot 2 is
        // untouched. With a 30s delay, slot 2 must wait 20 more seconds — and
        // the monitor window, extended to delay + 1s, has not closed either.
        let done = {
            let mut task = (*task_at(
                &service,
                7,
                TaskState::Running,
                DesiredState::Running,
                Duration::from_secs(10),
            ))
            .clone();
            task.slot = 1;
            Arc::new(task)
        };
        let waiting = {
            let mut task = (*task_at(
                &service,
                1,
                TaskState::Running,
                DesiredState::Running,
                Duration::ZERO,
            ))
            .clone();
            task.slot = 2;
            Arc::new(task)
        };
        let slots = slots_of(vec![
            (1, slot(vec![done], vec![], vec![])),
            (2, slot(vec![], vec![waiting], vec![])),
        ]);
        let plan = work(&service, &slots, &config);
        assert!(created(&plan.actions).is_empty());
        let wake = plan.wake.expect("the delay expiring");
        assert!(
            wake <= Duration::from_secs(21) && wake > Duration::from_secs(19),
            "{wake:?}"
        );
    }

    /// SWK §7.3 step 2: a slot holding two tasks is dirty even when both are on
    /// the current spec, and the updater is what converges it back to one.
    #[test]
    fn two_current_spec_tasks_in_one_slot_converge_to_the_one_furthest_along() {
        let service = service_at(7, UpdateConfig::default());
        let running = task_at(
            &service,
            7,
            TaskState::Running,
            DesiredState::Running,
            Duration::from_secs(30),
        );
        let fresh = task_at(
            &service,
            7,
            TaskState::New,
            DesiredState::Running,
            Duration::ZERO,
        );
        let slots = slots_of(vec![(
            1,
            slot(
                vec![Arc::clone(&fresh), Arc::clone(&running)],
                vec![],
                vec![],
            ),
        )]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        let stopped = updated(&plan.actions);
        assert_eq!(stopped.len(), 1);
        assert_eq!(
            stopped[0].id, fresh.id,
            "the running one is kept, the newcomer goes"
        );
        assert_eq!(stopped[0].desired_state, DesiredState::Shutdown);
    }

    /// A slot whose new task died is not started again by the updater: the
    /// restart supervisor owns terminal tasks, and two loops must never race a
    /// replacement into one slot.
    #[test]
    fn a_slot_whose_replacement_died_is_left_to_the_restart_supervisor() {
        let service = service_at(7, UpdateConfig::default());
        let mut view = slot(vec![], vec![], vec![]);
        view.touched = true;
        let slots = slots_of(vec![(1, view)]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert!(plan.actions.is_empty());
    }

    /// A slot nobody will refill is the updater's, and only that kind: the
    /// derivable half of SwarmKit's `UpdatableTasksInSlot` fallback.
    #[test]
    fn a_slot_no_restart_policy_will_refill_is_taken_over() {
        let mut service = service_at(7, UpdateConfig::default());
        let monitor = Duration::from_secs(5);

        // restart-condition = none: the supervisor has already declined.
        service.spec.task.restart.condition = satl_core::RestartCondition::None;
        let dead = task_at(
            &service,
            1,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        assert!(abandoned(&dead, DesiredState::Running));
        let mut view = slot(vec![], vec![], vec![]);
        view.touched = false;
        view.abandoned = true;
        assert_eq!(
            phase(&view, DesiredState::Running, monitor, now(), false),
            Phase::Pending { started: false },
            "an update is what makes the old verdict irrelevant"
        );
        let slots = slots_of(vec![(1, view)]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        assert_eq!(created(&plan.actions).len(), 1, "the slot is filled");

        // A task the policy *would* restart stays the supervisor's, so that two
        // loops never race a replacement into one slot.
        service.spec.task.restart.condition = satl_core::RestartCondition::Any;
        let restartable = task_at(
            &service,
            1,
            TaskState::Failed,
            DesiredState::Running,
            Duration::ZERO,
        );
        assert!(!abandoned(&restartable, DesiredState::Running));

        // Nor is a task that was told to stop: nobody is waiting for it.
        let stopped = task_at(
            &service,
            1,
            TaskState::Shutdown,
            DesiredState::Shutdown,
            Duration::ZERO,
        );
        assert!(!abandoned(&stopped, DesiredState::Running));

        // on-failure plus a clean exit: not covered, so not coming back.
        service.spec.task.restart.condition = satl_core::RestartCondition::OnFailure;
        let complete = task_at(
            &service,
            1,
            TaskState::Complete,
            DesiredState::Running,
            Duration::ZERO,
        );
        assert!(abandoned(&complete, DesiredState::Running));
    }

    /// The shape a live rollback produced, and the reason [`abandoned`] exists:
    /// a `stop-first` replacement that died *before* its promotion sits terminal
    /// at desired `READY`, which the restart supervisor deliberately ignores.
    /// Nobody but the updater would ever fill that slot again.
    #[test]
    fn a_replacement_that_died_before_its_promotion_is_the_updaters_to_replace() {
        let service = service_at(7, UpdateConfig::default());
        // Exactly what the cluster showed: image not in the registry, task
        // REJECTED during prepare, desired state still READY.
        let rejected = task_at(
            &service,
            1,
            TaskState::Rejected,
            DesiredState::Ready,
            Duration::ZERO,
        );
        assert!(
            abandoned(&rejected, DesiredState::Running),
            "the restart supervisor does not restart tasks below their target, so \
             this slot is the updater's or nobody's"
        );

        // The same task in a service whose tasks are *meant* to stay at READY
        // (`satl create`, autostart=false) is a stopped container an operator
        // may still start by hand: Docker keeps it, and so does SatL.
        assert!(!abandoned(&rejected, DesiredState::Ready));

        let mut view = slot(vec![], vec![], vec![]);
        view.abandoned = true;
        let slots = slots_of(vec![(1, view)]);
        let plan = work(&service, &slots, &UpdateConfig::default());
        let created = created(&plan.actions);
        assert_eq!(created.len(), 1, "the slot is filled again");
        assert_eq!(created[0].slot, 1);
        assert_eq!(created[0].spec_version, Some(service.spec_version));
        assert_eq!(
            created[0].desired_state,
            DesiredState::Running,
            "an empty slot has no predecessor to wait for, so no promotion round \
             trip is needed"
        );
    }

    /// The monitor window is keyed on the **manager** clock
    /// (`status.applied_at`, via [`task_timestamp`]) and never on the agent's
    /// `status.timestamp`.
    ///
    /// The agent stamps `status.timestamp` when a *step begins*
    /// (`satl_agent::do_step`: `next.timestamp = now()` before it calls
    /// `Controller::start`), and with a healthcheck `start` does not return
    /// until a probe has passed (`start_inner` ends in `await_first_healthy`).
    /// So a health-gated task reports `RUNNING` carrying a timestamp from before
    /// the gate — by the whole `start_period` — while `applied_at` is stamped by
    /// the manager at the moment it applied that `RUNNING`
    /// (`satl_dispatcher::status`).
    ///
    /// Keying the window on the agent's field would therefore declare a batch
    /// settled before its task had been serving at all, and a task that failed
    /// seconds after starting would fall *outside* the window meant to catch it
    /// — quietly weakening the rollback trigger. This test is what fails if
    /// someone simplifies `task_timestamp` away.
    #[test]
    fn the_monitor_window_runs_from_the_manager_clock_not_the_agent_step() {
        let service = service_at(7, UpdateConfig::default());
        let monitor = Duration::from_secs(5);
        let mut task = (*task_at(
            &service,
            7,
            TaskState::Running,
            DesiredState::Running,
            Duration::ZERO,
        ))
        .clone();
        // What a health-gated start leaves behind: the step began 30 s ago (a
        // start period's worth), the manager applied RUNNING a moment ago.
        task.status.timestamp = SystemTime::now() - Duration::from_secs(30);
        task.status.applied_at = Some(SystemTime::now());
        let view = slot(vec![Arc::new(task.clone())], vec![], vec![]);
        assert_eq!(
            phase(&view, DesiredState::Running, monitor, now(), false),
            Phase::Watching,
            "the window has just opened: 30 s of health-gated startup is not 30 s \
             of observed running"
        );

        // And once the manager has been watching it for the window, it settles.
        task.status.applied_at = Some(SystemTime::now() - Duration::from_secs(6));
        let view = slot(vec![Arc::new(task)], vec![], vec![]);
        assert_eq!(
            phase(&view, DesiredState::Running, monitor, now(), false),
            Phase::Settled
        );
    }

    /// The measured bug behind every one-shot `satl run` executing its command
    /// twice: `start_container` flips the autostart label, which bumps
    /// `spec_version` without touching the task spec, so the completed
    /// restart-none task looked abandoned at the old version and the updater
    /// filled the slot with a replacement that re-ran the command. A finished
    /// task whose spec deep-equals the current one is the converged state;
    /// only a deep-dirty finished task (a real update over a dead slot) is the
    /// updater's to fill.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_annotations_only_bump_does_not_refill_a_finished_slot() {
        let cluster = crate::testing::TestCluster::start().await;
        let store = cluster.store();

        let mut service = sample_service("run", 1);
        service.spec.task.restart.condition = satl_core::RestartCondition::None;
        service
            .spec
            .annotations
            .labels
            .insert(crate::AUTOSTART_LABEL.to_owned(), "false".to_owned());
        let service_id = service.id.clone();
        store
            .propose(vec![StoreAction::Create(StoreObject::Service(service))])
            .await
            .expect("service created");
        let (service, old_version) = {
            let view = store.view();
            let service = (*view.service(&service_id).expect("service")).clone();
            (service.clone(), service.spec_version)
        };

        // The one-shot task ran to completion, stamped from the pre-flip spec.
        let now = SystemTime::now();
        let mut task = planted_task(&service, 1, TaskState::Complete, DesiredState::Running, now);
        task.spec_version = Some(old_version);
        task.status.applied_at = Some(now);
        store
            .propose(vec![StoreAction::Create(StoreObject::Task(task))])
            .await
            .expect("task planted");

        // What `start_container` does: an annotations-only change.
        crate::testing::update_spec(store, &service_id, |spec| {
            spec.annotations
                .labels
                .insert(crate::AUTOSTART_LABEL.to_owned(), "true".to_owned());
        })
        .await;

        {
            let view = store.view();
            let bumped = view.service(&service_id).expect("service").spec_version;
            assert_ne!(
                bumped, old_version,
                "the label flip must bump the version for this test to mean anything"
            );
            let plan = plan(&view, &service_id, SystemTime::now());
            assert!(
                plan.actions.is_empty(),
                "a finished task whose spec matches the current one is converged, \
                 not abandoned: {:?}",
                plan.actions
            );
        }

        // The counterpart, unchanged: a deep-dirty finished task is still the
        // updater's to fill.
        crate::testing::update_spec(store, &service_id, |spec| {
            spec.task.container.image = "127.0.0.1:5000/freebsd-nginx:2".to_owned();
        })
        .await;
        {
            let view = store.view();
            let plan = plan(&view, &service_id, SystemTime::now());
            let created = created(&plan.actions);
            assert_eq!(created.len(), 1, "a dirty finished slot is still filled");
            assert_eq!(
                created[0].spec.container.image,
                "127.0.0.1:5000/freebsd-nginx:2"
            );
        }

        cluster.shutdown().await;
    }
}
