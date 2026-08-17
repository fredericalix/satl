// SPDX-License-Identifier: BSD-2-Clause
//! Restart supervisor (SWK §7.4, plus the node-state half of SWK §7.8 and the
//! constraint enforcer of SWK §7.6).
//!
//! A task is one-shot and is never re-executed (architecture §4 rule 4):
//! "restart" always means *a replacement task in the same slot*. This loop
//! owns that machinery, and three things trigger it ([`Trigger`]):
//!
//! - **`Terminated`** (SWK §7.4) — the task reached a terminal observed state
//!   while its desired state was still `RUNNING`;
//! - **`InvalidNode`** (SWK §7.8: "node down/drain/delete → restart, i.e.
//!   replace, all its replicated tasks") — the node it was placed on is
//!   missing, `DOWN`, or draining;
//! - **`ConstraintsUnmet`** (SWK §7.6, the constraint enforcer) — the node
//!   still runs, but its labels or availability changed and it no longer
//!   satisfies the service's placement constraints.
//!
//! The decision rules for the two node-driven triggers live in
//! [`crate::node_enforcer`], which also explains why they are driven from this
//! loop rather than from loops of their own.
//!
//! All three triggers share one attempt history, one delay queue and one
//! replacement transaction, which is the point: `max_attempts` is a budget per
//! replica ([`crate::task::SlotTuple`]) and spec version, not per failure mode.
//!
//! Policy (SWK §7.4):
//!
//! - condition `none` never restarts; `on-failure` restarts everything but a
//!   clean exit (`COMPLETE`); `any` always restarts;
//! - `max_attempts` (0 = unlimited) is counted per replica **and** spec version
//!   — a service update resets the counter — and over `Restart.Window` when one
//!   is set, which turns the budget from a lifetime quota into a rate (see
//!   [`attempts_in_window`]). The count is **derived from the store**, not
//!   remembered: see [`RestartHistory`];
//! - `delay` (default 5 s) is honoured before the replacement is created,
//!   except on a **draining** node, where SWK §7.4 forces it to 0.
//!
//! # Stopping is not the same decision as replacing
//!
//! SWK §7.4 step 2 sets `DesiredState = SHUTDOWN` **before** consulting the
//! policy, and this loop now does the same — but only for the two node-driven
//! triggers, where it is a statement of fact rather than of policy: a node that
//! is draining, gone, or no longer allowed to run this task will not be running
//! it, so leaving the task at desired `RUNNING` records a wish the cluster
//! cannot grant. A `restart-condition = none` service therefore *does* lose its
//! tasks when its node is drained; it simply gains no replacements.
//!
//! The `Terminated` trigger keeps the older behaviour — a task nobody will
//! replace keeps its desired state — for a concrete reason: the rolling
//! updater reads exactly that shape to recognise a slot no restart policy will
//! refill ([`crate::update`]'s `abandoned`, the slot the live rollback of
//! `7e57984` left empty at 5/6 replicas). Raising the desired state of an
//! already-terminal task would hide that slot from the updater and change
//! nothing else, since the task has already stopped.
//!
//! # Never two replacements in one slot
//!
//! The predecessor's `SHUTDOWN` and its replacement's `CREATE` are proposed as
//! **one transaction**, so the store never exposes an intermediate state in
//! which the slot holds only stopped tasks. Before it commits, the slot is
//! [`Runnable`](crate::task::SlotState::Runnable) (the old task is still
//! wanted and not terminal, or terminal-but-`Held`); after it commits, it is
//! `Runnable` again through the replacement. Either way
//! [`crate::task::occupied_slots`] never sees it as free, so the replicated
//! orchestrator never adds a task of its own — the slot ownership rule
//! documented on [`crate::task::classify_slot`] holds unchanged. A rejected
//! proposal applies nothing at all, and the next pass re-derives the decision.
//!
//! Within this loop, a task is judged at most once per trigger kind, and
//! [`RestartSupervisor::pending`] holds at most one queued replacement per
//! task — so a crash *and* a node failure on the same task still produce a
//! single replacement.
//!
//! # Global services
//!
//! A global service's task is pinned to its node and its replica identity *is*
//! that node (SWK §4.5, slot 0). Two consequences:
//!
//! - a crash is handled here, and the replacement is created **on the same
//!   node** (SWK §7.4 step 4: "same slot, same node for global");
//! - a node that goes down, drains or stops matching is **not** handled here.
//!   There is no other node for a global task to move to, so the
//!   [`crate::global`] orchestrator shuts those tasks down instead of replacing
//!   them, exactly as SwarmKit's global orchestrator does. A replacement built
//!   here would be pinned to the same unusable node, or — worse, if it were
//!   left unbound — scheduled onto a node that already runs one.
//!
//! # Jobs
//!
//! A job service's tasks are skipped entirely, on every trigger: for a job a
//! `COMPLETE` task is a *success* and restarting it would re-run finished
//! work, and a failed one is retried by [`crate::jobs`] under the same
//! budget rules this loop would apply. Exactly one component owns a task's
//! lifecycle — the same reason the node-driven triggers of a global task
//! belong to [`crate::global`].
//!
//! Divergences from SwarmKit, all deliberate:
//!
//! - SwarmKit creates the replacement at desired `READY` and promotes it to
//!   `RUNNING` once the predecessor actually stopped (bounded by a 1 min
//!   timeout). Here the replacement is created at the predecessor's desired
//!   state directly. For the `Terminated` trigger the predecessor is already
//!   terminal, so there is nothing to wait for; for `InvalidNode` its agent is
//!   unreachable by definition, which is the very case SwarmKit also skips the
//!   wait for. The `READY`-then-promote dance itself now exists —
//!   [`crate::update`] uses it for every `stop-first` batch — so adopting it
//!   here is a small change, but it would only add a wait to a path that has
//!   nothing to wait for.
//! - the **delay queue is in memory** and a leadership change loses it, so an
//!   interrupted delay starts over rather than resuming with the time already
//!   served (SWK §7.9 resumes it from `Status.AppliedAt + delay`). A replacement
//!   that arrives one delay late is a pacing difference, not a correctness one,
//!   and the queue holds nothing a fresh pass cannot re-derive.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use satl_cluster::{ClusterStore, StoreView};
use satl_core::{
    DesiredState, Id, Node, ObjectKind, RestartCondition, RestartPolicy, StoreAction, StoreEvent,
    StoreObject, Task, TaskState, Version,
};
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::node_enforcer::{
    NodeInvalidity, constraints_unmet, evict_reason, evictable, node_invalidity,
};
use crate::propose::propose_with_retry;
use crate::task::{
    SlotTuple, is_global_task, new_global_task, new_task, raise_desired_state, task_timestamp,
};

/// Why a task needs replacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// It reached a terminal observed state while the cluster still wanted it
    /// running (SWK §7.4).
    Terminated,
    /// The node it was placed on can no longer run it (SWK §7.8).
    InvalidNode(NodeInvalidity),
    /// The node still runs, but no longer satisfies the service's placement
    /// constraints (SWK §7.6).
    ConstraintsUnmet,
}

/// A [`Trigger`] without its payload.
///
/// One judgement is remembered per task **and per trigger kind**, so a crash,
/// a node failure and a constraint change are decided independently — and a
/// node that recovers can have its verdict forgotten without disturbing the
/// crash bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TriggerKind {
    Terminated,
    InvalidNode,
    ConstraintsUnmet,
}

impl TriggerKind {
    /// Whether this verdict was about the task's *node* rather than the task,
    /// and is therefore void as soon as the node changes again.
    fn is_node_driven(self) -> bool {
        match self {
            Self::Terminated => false,
            Self::InvalidNode | Self::ConstraintsUnmet => true,
        }
    }
}

impl Trigger {
    /// This trigger without its payload.
    fn kind(self) -> TriggerKind {
        match self {
            Self::Terminated => TriggerKind::Terminated,
            Self::InvalidNode(_) => TriggerKind::InvalidNode,
            Self::ConstraintsUnmet => TriggerKind::ConstraintsUnmet,
        }
    }

    /// Short operator-facing reason, for logs.
    fn reason(self) -> &'static str {
        match self {
            Self::Terminated => "task terminated",
            Self::InvalidNode(why) => why.reason(),
            Self::ConstraintsUnmet => "node no longer satisfies the placement constraints",
        }
    }

    /// SWK §7.4: the restart delay is forced to 0 while the node is being
    /// drained — an operator emptying a node must not be paced by per-task
    /// back-off.
    fn skips_delay(self) -> bool {
        matches!(self, Self::InvalidNode(NodeInvalidity::Drained))
    }

    /// Whether the task must be stopped whatever the restart policy decides
    /// (SWK §7.4 step 2, and see the module docs).
    ///
    /// True for the node-driven triggers: the node will not be running this
    /// task, which is a fact and not a policy question. False for a task that
    /// has already stopped by itself.
    fn evicts(self) -> bool {
        match self {
            Self::Terminated => false,
            Self::InvalidNode(_) | Self::ConstraintsUnmet => true,
        }
    }

    /// Whether this trigger applies to a global service's task at all.
    ///
    /// A global task cannot move: the node-driven triggers belong to
    /// [`crate::global`], which shuts such a task down rather than replacing it
    /// somewhere else (see the module docs).
    fn applies_to_global(self) -> bool {
        matches!(self, Self::Terminated)
    }
}

/// One remembered judgement: which task, and what it was judged for.
type DecisionKey = (Id, TriggerKind);

/// What the restart policy says about one task that needs replacing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestartDecision {
    /// Create a replacement after the configured delay.
    Restart,
    /// The restart condition does not cover this termination.
    ConditionNotMet,
    /// `max_attempts` reached for this slot and spec version.
    AttemptsExhausted,
}

impl RestartDecision {
    /// Short reason for logs.
    fn reason(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::ConditionNotMet => "restart condition not met",
            Self::AttemptsExhausted => "max restart attempts reached",
        }
    }
}

/// Applies the restart policy (SWK §7.4 step 3).
///
/// `observed` is the task's current observed state — terminal for the
/// [`Trigger::Terminated`] path, whatever the dying node last reported for the
/// [`Trigger::InvalidNode`] path. Either way the policy is the same code and
/// the same budget: `attempts` is how many replacements this
/// `(service, slot, spec_version)` already got, from *any* trigger.
pub(crate) fn decide(
    policy: &RestartPolicy,
    observed: TaskState,
    attempts: u64,
) -> RestartDecision {
    let covered = match policy.condition {
        RestartCondition::None => false,
        // A clean exit is not a failure; everything else (FAILED, REJECTED,
        // ORPHANED) is.
        RestartCondition::OnFailure => observed != TaskState::Complete,
        RestartCondition::Any => true,
    };
    if !covered {
        return RestartDecision::ConditionNotMet;
    }
    if policy.max_attempts > 0 && attempts >= policy.max_attempts {
        return RestartDecision::AttemptsExhausted;
    }
    RestartDecision::Restart
}

/// How many past restarts count against a failure that happened at
/// `failure_at` (SWK §7.4 step 3, `Restart.Window`).
///
/// With no window the budget is for the lifetime of the slot's spec version, so
/// every recorded restart counts. With a window, only the restarts inside
/// `[failure_at - window, failure_at]` do — which is what makes `max_attempts`
/// a rate ("three times in five minutes") rather than a lifetime quota, and
/// lets a task that has been healthy for longer than the window be restarted
/// again.
///
/// Restarts recorded **after** the failure under evaluation are discounted, as
/// SwarmKit discounts them: a decision is about the state of the world when the
/// task died, and this loop can be judging a failure it learns about late.
fn attempts_in_window(history: &[SystemTime], window: Duration, failure_at: SystemTime) -> u64 {
    if window.is_zero() {
        return history.len() as u64;
    }
    history
        .iter()
        .filter(|at| match failure_at.duration_since(**at) {
            Ok(age) => age <= window,
            // Recorded after the failure: not this failure's history.
            Err(_) => false,
        })
        .count() as u64
}

/// Identifies the restart history of one replica (SWK's `SlotTuple` plus the
/// spec version, so a service update resets the counter).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RestartKey {
    /// Which replica: slot, plus the node for a global task (SWK §4.5).
    slot: SlotTuple,
    /// The spec version the replica's tasks were stamped from.
    spec_version: Option<Version>,
}

impl RestartKey {
    /// The key `task` is judged under, or `None` for a task with no service.
    fn of(task: &Task) -> Option<Self> {
        Some(Self {
            slot: SlotTuple::of(task)?,
            spec_version: task.spec_version,
        })
    }
}

/// Every replica's restart history, **derived from the store** rather than
/// remembered (SWK §7.9, `taskinit`'s third job).
///
/// SwarmKit keeps this in the supervisor's memory and rebuilds it once, at
/// leadership gain, by replaying task history: per slot, keep the tasks at the
/// newest spec version, sort by creation time, and count all but the first as
/// past restarts. SatL performs that same reconstruction **on every pass**,
/// which is strictly better and is why nothing here has to be seeded, replayed
/// or handed over:
///
/// - a new leader computes the same numbers from the same store, so a node that
///   fails right after an election does not get a fresh budget and a
///   crash-looping task cannot restart forever (the defect this closes);
/// - there is no in-memory counter to double-count against, and no ordering
///   requirement between "reconstruct" and "decide";
/// - it is level-triggered like every other decision in this crate: lose the
///   process, keep the answer.
///
/// The timestamps are each replacement task's `meta.created_at` — the manager
/// clock at the moment this loop created it, which is exactly what
/// [`record_attempt`](RestartHistory::attempts)-style bookkeeping used to store.
/// That makes the derivation faithful for `Restart.Window` too, where the count
/// is a rate rather than a total.
///
/// **What makes it sound is the reaper.** Per-replica history is pruned to
/// `max_attempts + 1` tasks for a service with bounded restarts
/// ([`crate::reaper`], SWK §4.6), and `max_attempts + 1` tasks is exactly the
/// count at which the budget is spent — so pruning can never hand a slot its
/// budget back. Only replicas with a bounded policy are indexed at all: an
/// unlimited one never reads the count.
///
/// Two ways it can read one attempt high, both bounded and both erring towards
/// *not* creating another task in a slot that already has one: a task the
/// updater created as a duplicate and immediately stopped, and a task still
/// waiting for the reaper to execute its `REMOVE`. SwarmKit's own reconstruction
/// counts both the same way.
#[derive(Debug, Default)]
pub(crate) struct RestartHistory {
    /// When each replacement of a replica was created, oldest first, with the
    /// replica's *first* task dropped (it is the original, not a restart).
    restarts: HashMap<RestartKey, Vec<SystemTime>>,
}

impl RestartHistory {
    /// Replays the store's task history into per-replica restart timestamps.
    fn from_view(view: &StoreView<'_>) -> Self {
        Self::replay(&view.tasks())
    }

    /// The pure half of [`Self::from_view`]: per replica, the creation time of
    /// every task but the first.
    fn replay(tasks: &[Arc<Task>]) -> Self {
        // Sorted by (created_at, id) so the "first task of the replica" is
        // picked deterministically when two tasks share a timestamp.
        let mut groups: HashMap<RestartKey, Vec<(SystemTime, Id)>> = HashMap::new();
        for task in tasks {
            // An unlimited policy never reads the count, and a crash-looping
            // task must not grow an index forever to prove it.
            if task.spec.restart.max_attempts == 0 {
                continue;
            }
            let Some(key) = RestartKey::of(task) else {
                continue;
            };
            groups
                .entry(key)
                .or_default()
                .push((task.meta.created_at, task.id.clone()));
        }
        let restarts = groups
            .into_iter()
            .map(|(key, mut tasks)| {
                tasks.sort();
                let timestamps = tasks.into_iter().skip(1).map(|(at, _)| at).collect();
                (key, timestamps)
            })
            .collect();
        Self { restarts }
    }

    /// How many restarts count against a failure of `key` observed at
    /// `failure_at`, under `policy`.
    fn attempts(&self, key: &RestartKey, policy: &RestartPolicy, failure_at: SystemTime) -> u64 {
        if policy.max_attempts == 0 {
            return 0;
        }
        let history = self.restarts.get(key).map_or(&[][..], Vec::as_slice);
        attempts_in_window(history, policy.window, failure_at)
    }
}

/// A restart waiting out its delay.
struct PendingRestart {
    /// When the action may be taken.
    at: Instant,
    /// The task being stopped, and possibly replaced.
    task_id: Id,
    /// Whether a replacement is created, or the task is only stopped (an
    /// eviction the restart policy refuses to answer — see [`Trigger::evicts`]).
    replace: bool,
    /// Why it is being replaced — re-checked against a fresh view before the
    /// transaction is built.
    trigger: Trigger,
}

/// Replaces tasks that stopped, or whose node can no longer run them,
/// according to their restart policy.
pub(crate) struct RestartSupervisor {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Judgements already taken, per task and trigger kind — each decision is
    /// derived from store state, so it is taken exactly once unless the
    /// premise changes (a proposal that failed, or a node that recovered).
    ///
    /// A dedup guard, never a decision: losing it costs a re-derivation, which
    /// yields the same verdict and an empty transaction.
    decided: HashSet<DecisionKey>,
    /// Restarts waiting out `Restart.Delay`; at most one entry per task.
    pending: Vec<PendingRestart>,
}

impl RestartSupervisor {
    pub(crate) fn new(store: ClusterStore, interval: Duration) -> Self {
        Self {
            store,
            interval,
            decided: HashSet::new(),
            pending: Vec::new(),
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.restart");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let next = self.pending.iter().map(|p| p.at).min();
                let delay_elapsed = async move {
                    match next {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    () = delay_elapsed => self.fire_due().await,
                    _ = ticker.tick() => self.full_pass(),
                    event = events.recv() => match event {
                        Ok(StoreEvent::Updated { new: StoreObject::Task(task), .. }) => {
                            self.observe_task(&task);
                        }
                        // Node liveness, availability and labels are written by
                        // the dispatcher and by the operator respectively; any
                        // of them can strand this node's tasks (SWK §7.8, §7.6).
                        Ok(StoreEvent::Created(StoreObject::Node(node))) => {
                            self.observe_node(&node, None);
                        }
                        Ok(StoreEvent::Updated { new: StoreObject::Node(node), old }) => {
                            let previous = match &old {
                                Some(StoreObject::Node(previous)) => Some(previous),
                                // Unavailable (a snapshot install replay): judged
                                // as a fresh node, which is the safe direction.
                                _ => None,
                            };
                            self.observe_node(&node, previous);
                        }
                        // A deleted node is `InvalidNode` too (SWK §7.1: `n == nil`).
                        Ok(StoreEvent::Removed { kind: ObjectKind::Node, id }) => {
                            self.evict_node_tasks(&id, Some(NodeInvalidity::Missing));
                        }
                        Ok(_) => {}
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full pass");
                            self.full_pass();
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("restart supervisor stopped");
        }
        .instrument(span))
        .await;
    }

    /// Judges one task change against every trigger.
    ///
    /// Every task status write in the cluster arrives here, so the order of the
    /// checks is a cost decision: the cheap predicates on the task itself first,
    /// then one node lookup, and the restart history — a scan of the store's
    /// tasks — only once something is actually going to be decided.
    fn observe_task(&mut self, task: &Task) {
        if !needs_decision(task) && !evictable(task) {
            return;
        }
        {
            // Sync scope: the `!Send` read guard never crosses an await.
            let view = self.store.view();
            if is_job_task(&view, task) {
                // A job's lifecycle belongs to the jobs loop: a `COMPLETE`
                // task is a success and is never restarted, and a failed one
                // is retried there ([`crate::jobs`]).
                return;
            }
        }
        if needs_decision(task) {
            let history = self.history();
            self.evaluate(task, Trigger::Terminated, &history);
        }
        if !evictable(task) {
            return;
        }
        let trigger = {
            // Sync scope: the `!Send` read guard never crosses an await.
            let view = self.store.view();
            let node = task.node_id.as_ref().and_then(|id| view.node(id));
            task_trigger(task, node.as_deref(), &view)
        };
        if let Some(trigger) = trigger {
            let history = self.history();
            self.evaluate(task, trigger, &history);
        }
    }

    /// Judges one node change: a node that can no longer run some of its tasks
    /// gives them up, and a node that is fine again gets its tasks' node-driven
    /// verdicts forgotten so a later change is decided afresh.
    ///
    /// `previous` is the store's former copy of the node, absent when the node
    /// was just created. It is what keeps this cheap: a node object is rewritten
    /// on **every heartbeat**, and re-evaluating placement constraints there
    /// would mean a full task scan every few seconds for a label change that
    /// almost never happens. So the §7.6 check runs only when the two fields it
    /// depends on actually moved — with the periodic pass as the usual
    /// self-healing fallback.
    fn observe_node(&mut self, node: &Node, previous: Option<&Node>) {
        if let Some(reason) = node_invalidity(Some(node)) {
            self.evict_node_tasks(&node.id, Some(reason));
            return;
        }
        // The node can run tasks again: every node-driven verdict about its
        // tasks was taken against a node that no longer exists in that state.
        // Forgotten *before* the constraint check, so a node whose labels flap
        // back and forth is judged afresh each time.
        self.forget_node_decisions(&node.id);
        if placement_inputs_changed(node, previous) {
            self.evict_node_tasks(&node.id, None);
        }
    }

    /// Queues the eviction of every task on `node_id` that the node can no
    /// longer run (SWK §7.8 when `reason` is set, SWK §7.6 otherwise).
    fn evict_node_tasks(&mut self, node_id: &Id, reason: Option<NodeInvalidity>) {
        let (work, history) = {
            let view = self.store.view();
            let node = view.node(node_id);
            let work: Vec<(Task, Trigger)> = view
                .tasks()
                .into_iter()
                .filter(|task| task.node_id.as_ref() == Some(node_id))
                .filter(|task| !is_job_task(&view, task))
                .filter_map(|task| {
                    let trigger = match reason {
                        Some(reason) if evictable(&task) => Trigger::InvalidNode(reason),
                        Some(_) => return None,
                        None => task_trigger(&task, node.as_deref(), &view)?,
                    };
                    Some(((*task).clone(), trigger))
                })
                .collect();
            (work, RestartHistory::from_view(&view))
        };
        if work.is_empty() {
            return;
        }
        let span = tracing::info_span!(
            "node_eviction",
            node_id = %node_id,
            reason = reason.map_or("placement constraints", NodeInvalidity::reason),
            tasks = work.len(),
        );
        let _entered = span.enter();
        tracing::info!("node can no longer run these tasks; giving them up");
        for (task, trigger) in work {
            self.evaluate(&task, trigger, &history);
        }
    }

    /// The restart history as the store currently tells it (SWK §7.9).
    fn history(&self) -> RestartHistory {
        let view = self.store.view();
        RestartHistory::from_view(&view)
    }

    /// `node_id` can run tasks again: drop the node-driven verdicts of its
    /// tasks, so a *later* change to the same node is judged from scratch —
    /// whether that is a second failure or a label that flapped back.
    ///
    /// Node objects are rewritten on every heartbeat, so this must stay free
    /// when there is nothing to forget.
    fn forget_node_decisions(&mut self, node_id: &Id) {
        if !self.decided.iter().any(|(_, kind)| kind.is_node_driven()) {
            return;
        }
        let on_node: HashSet<Id> = {
            let view = self.store.view();
            view.tasks()
                .iter()
                .filter(|task| task.node_id.as_ref() == Some(node_id))
                .map(|task| task.id.clone())
                .collect()
        };
        self.decided
            .retain(|(id, kind)| !kind.is_node_driven() || !on_node.contains(id));
    }

    /// Judges one task; queues the replacement when the policy allows it, and
    /// the bare shutdown when the trigger evicts but the policy refuses.
    fn evaluate(&mut self, task: &Task, trigger: Trigger, history: &RestartHistory) {
        let decision_key = (task.id.clone(), trigger.kind());
        if self.decided.contains(&decision_key) {
            return;
        }
        // At most one queued action per task, whatever the trigger: a crash and
        // a node failure on the same task must not produce two replacements.
        if self.pending.iter().any(|p| p.task_id == task.id) {
            return;
        }
        if is_global_task(task) && !trigger.applies_to_global() {
            // A global task cannot move; [`crate::global`] owns this case.
            self.decided.insert(decision_key);
            return;
        }
        let Some(key) = RestartKey::of(task) else {
            // Standalone tasks have no restart policy owner (M1 has none).
            self.decided.insert(decision_key);
            return;
        };
        let policy = task.spec.restart;
        let attempts = history.attempts(&key, &policy, task_timestamp(task));
        let decision = decide(&policy, task.status.state, attempts);
        self.decided.insert(decision_key);
        let replace = decision == RestartDecision::Restart;
        if !replace && !trigger.evicts() {
            tracing::info!(
                task_id = %task.id,
                service_id = %key.slot.service_id,
                slot = task.slot,
                node_id = ?task.node_id,
                state = %task.status.state,
                trigger = trigger.reason(),
                attempts,
                reason = decision.reason(),
                "task not restarted"
            );
            return;
        }
        // Nothing to pace when there is no replacement: the shutdown is the
        // whole action (SWK §7.4 step 2 takes it before the policy is read).
        let delay = if replace && !trigger.skips_delay() {
            policy.delay
        } else {
            Duration::ZERO
        };
        let what = if replace {
            "scheduling replacement task"
        } else {
            // Evicted with nobody to take its place: the slot legitimately
            // shrinks, and the reason says why no replacement is coming.
            "stopping task without a replacement"
        };
        tracing::info!(
            task_id = %task.id,
            service_id = %key.slot.service_id,
            slot = task.slot,
            node_id = ?task.node_id,
            state = %task.status.state,
            trigger = trigger.reason(),
            attempts,
            delay_ms = delay.as_millis(),
            reason = decision.reason(),
            "{what}"
        );
        self.pending.push(PendingRestart {
            at: Instant::now() + delay,
            task_id: task.id.clone(),
            replace,
            trigger,
        });
    }

    /// Applies the queued actions whose delay has elapsed.
    async fn fire_due(&mut self) {
        let now = Instant::now();
        let mut due = Vec::new();
        self.pending.retain(|pending| {
            if pending.at <= now {
                due.push((pending.task_id.clone(), pending.replace, pending.trigger));
                false
            } else {
                true
            }
        });
        for (task_id, replace, trigger) in due {
            self.restart(&task_id, replace, trigger).await;
        }
    }

    /// Shuts the old task down and creates its replacement, in one transaction
    /// so a slot is never briefly empty (see the module docs).
    async fn restart(&mut self, task_id: &Id, replace: bool, trigger: Trigger) {
        let result = propose_with_retry(&self.store, "restart task", |view| {
            let Some(old) = view.task(task_id) else {
                return Vec::new();
            };
            // Re-check under the fresh view: while the delay ran, the task may
            // have been shut down, removed or superseded — or, for a node
            // eviction, its node may have come back or its labels changed back.
            if !still_applicable(&old, trigger, view) {
                return Vec::new();
            }
            let Some(shutdown) = raise_desired_state(&old, DesiredState::Shutdown) else {
                return Vec::new();
            };
            let service = old.service_id.as_ref().and_then(|id| view.service(id));
            let Some(service) = service.filter(|_| replace) else {
                // Stop only: either the policy refuses a replacement, or the
                // service itself is gone (in which case the replicated loop is
                // already marking its tasks for removal).
                tracing::info!(
                    task_id = %old.id,
                    service_id = ?old.service_id,
                    slot = old.slot,
                    node_id = ?old.node_id,
                    trigger = trigger.reason(),
                    from = %old.desired_state,
                    to = %DesiredState::Shutdown,
                    "stopping a task its node can no longer run"
                );
                return vec![shutdown];
            };
            // Same slot — and, for a global service, the same node: its replica
            // identity *is* the node (SWK §7.4 step 4).
            let mut replacement = match old.node_id.as_ref().filter(|_| is_global_task(&old)) {
                Some(node_id) => new_global_task(&service, node_id),
                None => new_task(&service, old.slot),
            };
            // Created at the predecessor's desired state directly (see the
            // module docs). That is `Running` for every service task, and
            // `Ready` for a `docker create`d one, which must stay created.
            replacement.desired_state = old.desired_state;
            tracing::info!(
                task_id = %replacement.id,
                replaces = %old.id,
                service_id = %service.id,
                slot = old.slot,
                node_id = ?old.node_id,
                trigger = trigger.reason(),
                from = %old.status.state,
                to = %replacement.desired_state,
                "restarting task in the same slot"
            );
            vec![
                shutdown,
                StoreAction::Create(StoreObject::Task(replacement)),
            ]
        })
        .await;

        match result {
            // The attempt is recorded by the store itself: the replacement task
            // *is* the record (see [`RestartHistory`]).
            Ok(Some(_)) => {}
            Ok(None) => tracing::debug!(
                task_id = %task_id,
                trigger = trigger.reason(),
                "restart no longer applicable"
            ),
            Err(err) => {
                tracing::warn!(task_id = %task_id, error = %err, "restart deferred");
                // Nothing was applied: forget the verdict so the next pass
                // re-derives it (a failed proposal never stops this loop).
                self.decided.remove(&(task_id.clone(), trigger.kind()));
            }
        }
    }

    /// Catches events that were missed, and forgets bookkeeping for tasks that
    /// are gone.
    ///
    /// This is also the leader-change pass (SWK §7.9): it needs no replay step,
    /// because the restart history it judges against is derived from the store
    /// on every pass ([`RestartHistory`]).
    fn full_pass(&mut self) {
        let (work, history) = {
            let view = self.store.view();
            let tasks = view.tasks();
            let live: HashSet<Id> = tasks.iter().map(|t| t.id.clone()).collect();
            self.decided.retain(|(id, _)| live.contains(id));

            let mut work: Vec<(Task, Trigger)> = Vec::new();
            for task in &tasks {
                if is_job_task(&view, task) {
                    // Owned by the jobs loop, on every trigger.
                    continue;
                }
                if needs_decision(task) {
                    work.push(((**task).clone(), Trigger::Terminated));
                    continue;
                }
                let node = task.node_id.as_ref().and_then(|id| view.node(id));
                if let Some(trigger) = task_trigger(task, node.as_deref(), &view) {
                    work.push(((**task).clone(), trigger));
                }
            }
            (work, RestartHistory::from_view(&view))
        };
        for (task, trigger) in work {
            self.evaluate(&task, trigger, &history);
        }
    }
}

/// Which node-driven trigger applies to a live, bound task, if any: the node
/// being unfit for everything (SWK §7.8) takes precedence over its being unfit
/// for this task (SWK §7.6).
///
/// `node` is the store's current value for `task.node_id`.
fn task_trigger(task: &Task, node: Option<&Node>, view: &StoreView<'_>) -> Option<Trigger> {
    if !evictable(task) {
        return None;
    }
    if let Some(reason) = evict_reason(task, node) {
        return Some(Trigger::InvalidNode(reason));
    }
    let node = node?;
    let service = task.service_id.as_ref().and_then(|id| view.service(id))?;
    constraints_unmet(&service, task, node).then_some(Trigger::ConstraintsUnmet)
}

/// Whether the two node fields a placement decision reads — its labels and its
/// availability — differ from the node's previous copy (`None` = no previous
/// copy, so treat them as changed).
fn placement_inputs_changed(node: &Node, previous: Option<&Node>) -> bool {
    previous.is_none_or(|previous| {
        previous.spec.labels != node.spec.labels
            || previous.spec.availability != node.spec.availability
    })
}

/// A task the supervisor must judge: it stopped for good, yet the cluster
/// still wants it running.
fn needs_decision(task: &Task) -> bool {
    task.status.state.is_terminal() && task.desired_state == DesiredState::Running
}

/// Whether the task belongs to a job service — in which case this loop must
/// never touch it: a `COMPLETE` task is the job's success and is never
/// restarted, and a failed one is retried by the jobs loop under the same
/// budget rules ([`crate::jobs`]). One service lookup, on the path that was
/// already reading the store.
fn is_job_task(view: &StoreView<'_>, task: &Task) -> bool {
    task.service_id
        .as_ref()
        .and_then(|id| view.service(id))
        .is_some_and(|service| service.spec.mode.is_job())
}

/// Whether the verdict taken before the delay still holds, re-derived from a
/// fresh view rather than remembered.
fn still_applicable(task: &Task, trigger: Trigger, view: &StoreView<'_>) -> bool {
    match trigger {
        Trigger::Terminated => needs_decision(task),
        // Deliberately not "is it still invalid *for the same reason*": a node
        // that recovered during the delay keeps its task, and its slot does not
        // gain a second live task. Any node-driven reason still standing is
        // enough to go ahead.
        Trigger::InvalidNode(_) | Trigger::ConstraintsUnmet => {
            let node = task.node_id.as_ref().and_then(|id| view.node(id));
            task_trigger(task, node.as_deref(), view).is_some()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use crate::testing::{planted_node, planted_task, sample_service, with_restart};

    use super::*;

    fn policy(condition: RestartCondition, max_attempts: u64) -> RestartPolicy {
        RestartPolicy {
            condition,
            delay: Duration::from_millis(50),
            max_attempts,
            window: Duration::ZERO,
        }
    }

    #[test]
    fn condition_none_never_restarts() {
        let policy = policy(RestartCondition::None, 0);
        for state in [
            TaskState::Complete,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
        ] {
            assert_eq!(
                decide(&policy, state, 0),
                RestartDecision::ConditionNotMet,
                "{state}"
            );
        }
    }

    #[test]
    fn on_failure_ignores_clean_exits() {
        let policy = policy(RestartCondition::OnFailure, 0);
        assert_eq!(
            decide(&policy, TaskState::Complete, 0),
            RestartDecision::ConditionNotMet
        );
        for state in [
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Orphaned,
            TaskState::Shutdown,
        ] {
            assert_eq!(
                decide(&policy, state, 0),
                RestartDecision::Restart,
                "{state}"
            );
        }
    }

    #[test]
    fn any_restarts_every_termination() {
        let policy = policy(RestartCondition::Any, 0);
        for state in [
            TaskState::Complete,
            TaskState::Failed,
            TaskState::Rejected,
            TaskState::Shutdown,
        ] {
            assert_eq!(
                decide(&policy, state, 0),
                RestartDecision::Restart,
                "{state}"
            );
        }
    }

    #[test]
    fn max_attempts_caps_replacements() {
        let unlimited = policy(RestartCondition::Any, 0);
        assert_eq!(
            decide(&unlimited, TaskState::Failed, 9_999),
            RestartDecision::Restart
        );

        let bounded = policy(RestartCondition::Any, 2);
        assert_eq!(
            decide(&bounded, TaskState::Failed, 0),
            RestartDecision::Restart
        );
        assert_eq!(
            decide(&bounded, TaskState::Failed, 1),
            RestartDecision::Restart
        );
        assert_eq!(
            decide(&bounded, TaskState::Failed, 2),
            RestartDecision::AttemptsExhausted
        );
        assert_eq!(
            decide(&bounded, TaskState::Failed, 3),
            RestartDecision::AttemptsExhausted
        );
    }

    /// The node path feeds [`decide`] a *non-terminal* observed state — whatever
    /// the dying node last reported — and must still get the same policy.
    #[test]
    fn the_policy_also_judges_a_still_running_task_on_a_dead_node() {
        assert_eq!(
            decide(&policy(RestartCondition::None, 0), TaskState::Running, 0),
            RestartDecision::ConditionNotMet,
            "the policy wins over the node state"
        );
        assert_eq!(
            decide(
                &policy(RestartCondition::OnFailure, 0),
                TaskState::Running,
                0
            ),
            RestartDecision::Restart,
            "losing its node is not a clean exit"
        );
        assert_eq!(
            decide(&policy(RestartCondition::Any, 0), TaskState::Running, 0),
            RestartDecision::Restart
        );
        // One budget per (service, slot, spec_version), whoever spent it.
        assert_eq!(
            decide(&policy(RestartCondition::Any, 2), TaskState::Running, 2),
            RestartDecision::AttemptsExhausted
        );
    }

    #[test]
    fn only_a_draining_node_skips_the_restart_delay() {
        assert!(!Trigger::Terminated.skips_delay());
        assert!(Trigger::InvalidNode(NodeInvalidity::Drained).skips_delay());
        assert!(
            !Trigger::InvalidNode(NodeInvalidity::Down).skips_delay(),
            "a down node's tasks are still paced by the policy delay"
        );
        assert!(!Trigger::InvalidNode(NodeInvalidity::Missing).skips_delay());
        assert!(
            !Trigger::ConstraintsUnmet.skips_delay(),
            "a constraint change is not an operator waiting on a node"
        );
    }

    /// SWK §7.4 step 2: which triggers stop the task whatever the policy says.
    #[test]
    fn only_a_node_driven_trigger_evicts_regardless_of_the_policy() {
        assert!(Trigger::InvalidNode(NodeInvalidity::Drained).evicts());
        assert!(Trigger::InvalidNode(NodeInvalidity::Down).evicts());
        assert!(Trigger::InvalidNode(NodeInvalidity::Missing).evicts());
        assert!(
            Trigger::ConstraintsUnmet.evicts(),
            "a node that no longer qualifies must not keep running the task"
        );
        assert!(
            !Trigger::Terminated.evicts(),
            "an already-stopped task keeps its desired state, so the updater can \
             still see the slot nobody will refill (see the module docs)"
        );
    }

    /// A global task cannot move, so only its own crash is this loop's business
    /// (SWK §7.8: the global orchestrator owns the node cases).
    #[test]
    fn only_a_crash_is_judged_here_for_a_global_task() {
        assert!(Trigger::Terminated.applies_to_global());
        assert!(!Trigger::InvalidNode(NodeInvalidity::Drained).applies_to_global());
        assert!(!Trigger::InvalidNode(NodeInvalidity::Down).applies_to_global());
        assert!(!Trigger::ConstraintsUnmet.applies_to_global());
    }

    /// The §7.6 re-check is skipped on the node writes that cannot change its
    /// verdict — which is nearly all of them, since every heartbeat rewrites the
    /// node object.
    #[test]
    fn only_labels_and_availability_reopen_the_placement_question() {
        let node = planted_node("alpha");

        let mut heartbeat = node.clone();
        heartbeat.status.message = "still here".to_owned();
        heartbeat.meta.updated_at = SystemTime::now();
        assert!(
            !placement_inputs_changed(&heartbeat, Some(&node)),
            "a heartbeat must not cost a full task scan"
        );

        let mut relabelled = node.clone();
        relabelled
            .spec
            .labels
            .insert("zone".to_owned(), "b".to_owned());
        assert!(placement_inputs_changed(&relabelled, Some(&node)));

        let mut paused = node.clone();
        paused.spec.availability = satl_core::Availability::Pause;
        assert!(placement_inputs_changed(&paused, Some(&node)));

        assert!(
            placement_inputs_changed(&node, None),
            "no previous copy: judge it"
        );
    }

    /// The reconstruction SWK §7.9 does at leadership gain, done here on every
    /// pass: per replica, every task but the first is a past restart.
    #[test]
    fn restart_history_is_the_slots_task_history_minus_its_first_task() {
        let service = with_restart(
            sample_service("web", 2),
            RestartCondition::Any,
            Duration::ZERO,
            3,
        );
        let base = SystemTime::now() - Duration::from_hours(1);
        let at = |secs: u64| base + Duration::from_secs(secs);
        // Slot 1: the original plus two replacements. Slot 2: only the original.
        let tasks: Vec<Arc<Task>> = [(1, 0), (1, 10), (1, 20), (2, 5)]
            .into_iter()
            .map(|(slot, offset)| {
                Arc::new(planted_task(
                    &service,
                    slot,
                    TaskState::Failed,
                    DesiredState::Running,
                    at(offset),
                ))
            })
            .collect();

        let history = RestartHistory::replay(&tasks);
        let key = |slot| RestartKey {
            slot: SlotTuple {
                service_id: service.id.clone(),
                slot,
                node_id: None,
            },
            spec_version: Some(service.meta.version),
        };
        let policy = service.spec.task.restart;
        assert_eq!(
            history.attempts(&key(1), &policy, at(30)),
            2,
            "three tasks in the slot means two restarts"
        );
        assert_eq!(
            history.attempts(&key(2), &policy, at(30)),
            0,
            "a slot on its first task has spent nothing"
        );

        // The timestamps are the replacements' creation times, so a window
        // applies to a reconstructed history exactly as to a live one.
        let windowed = RestartPolicy {
            window: Duration::from_secs(15),
            ..policy
        };
        assert_eq!(history.attempts(&key(1), &windowed, at(30)), 1);
    }

    /// An unlimited policy never reads the count, so it is never indexed — a
    /// crash-looping task must not grow a list forever to prove it.
    #[test]
    fn an_unlimited_policy_keeps_no_history() {
        let service = with_restart(
            sample_service("web", 1),
            RestartCondition::Any,
            Duration::ZERO,
            0,
        );
        let now = SystemTime::now();
        let tasks: Vec<Arc<Task>> = (0..5)
            .map(|n| {
                Arc::new(planted_task(
                    &service,
                    1,
                    TaskState::Failed,
                    DesiredState::Running,
                    now - Duration::from_secs(n),
                ))
            })
            .collect();
        assert!(RestartHistory::replay(&tasks).restarts.is_empty());
    }

    /// A global service's replicas are its nodes (SWK §4.5), so one node's
    /// crash loop must not spend another node's budget.
    #[test]
    fn a_global_services_history_is_kept_per_node() {
        let mut service = with_restart(
            sample_service("agent", 1),
            RestartCondition::Any,
            Duration::ZERO,
            2,
        );
        service.spec.mode = satl_core::ServiceMode::Global;
        let now = SystemTime::now();
        let (a, b) = (Id::generate(), Id::generate());
        let on = |node: &Id, age: u64| {
            let task = planted_task(
                &service,
                0,
                TaskState::Failed,
                DesiredState::Running,
                now - Duration::from_secs(age),
            );
            Arc::new(crate::testing::assigned_to(task, node))
        };
        // Node a has burned two tasks; node b is on its first.
        let tasks = vec![on(&a, 30), on(&a, 20), on(&b, 25)];
        let history = RestartHistory::replay(&tasks);
        let key = |node: &Id| RestartKey {
            slot: SlotTuple {
                service_id: service.id.clone(),
                slot: 0,
                node_id: Some(node.clone()),
            },
            spec_version: Some(service.meta.version),
        };
        let policy = service.spec.task.restart;
        assert_eq!(history.attempts(&key(&a), &policy, now), 1);
        assert_eq!(
            history.attempts(&key(&b), &policy, now),
            0,
            "one node's crash loop is not another node's budget"
        );
    }

    #[test]
    fn triggers_are_remembered_per_kind_and_explain_themselves() {
        assert_eq!(Trigger::Terminated.kind(), TriggerKind::Terminated);
        assert_eq!(
            Trigger::InvalidNode(NodeInvalidity::Drained).kind(),
            Trigger::InvalidNode(NodeInvalidity::Down).kind(),
            "a node that went from down to draining is not judged twice"
        );
        assert_ne!(
            Trigger::Terminated.kind(),
            Trigger::InvalidNode(NodeInvalidity::Down).kind(),
            "a crash and a node failure are judged independently"
        );
        assert_eq!(Trigger::Terminated.reason(), "task terminated");
        assert_eq!(
            Trigger::InvalidNode(NodeInvalidity::Down).reason(),
            NodeInvalidity::Down.reason()
        );
    }

    #[test]
    fn only_terminated_tasks_the_cluster_still_wants_are_judged() {
        let service = sample_service("web", 1);
        let now = SystemTime::now();
        let cases = [
            (TaskState::Failed, DesiredState::Running, true),
            (TaskState::Complete, DesiredState::Running, true),
            (TaskState::Rejected, DesiredState::Running, true),
            // Already being stopped or removed: not our business.
            (TaskState::Failed, DesiredState::Shutdown, false),
            (TaskState::Failed, DesiredState::Remove, false),
            // Still alive.
            (TaskState::Running, DesiredState::Running, false),
            (TaskState::New, DesiredState::Running, false),
            // Created-not-started containers are not restarted either.
            (TaskState::Failed, DesiredState::Ready, false),
        ];
        for (state, desired, expected) in cases {
            let task = planted_task(&service, 1, state, desired, now);
            assert_eq!(needs_decision(&task), expected, "{state} / {desired}");
        }
    }

    /// The sliding window (SWK §7.4 step 3): `max_attempts` over
    /// `Restart.Window` is a rate, not a lifetime quota.
    #[test]
    fn the_window_bounds_which_attempts_count() {
        let now = SystemTime::now();
        let window = Duration::from_mins(1);
        let history = [
            now - Duration::from_mins(5),  // long past
            now - Duration::from_secs(90), // outside
            now - Duration::from_secs(30), // inside
            now - Duration::from_secs(1),  // inside
        ];

        assert_eq!(
            attempts_in_window(&history, Duration::ZERO, now),
            4,
            "no window: the whole history counts, as it did before"
        );
        assert_eq!(attempts_in_window(&history, window, now), 2);
        assert_eq!(
            attempts_in_window(&history, window, now - Duration::from_mins(1)),
            1,
            "judged against an older failure, only the minute before it counts \
             (now-90 is in, now-300 is too old, the two later ones had not \
             happened yet)"
        );
        assert_eq!(
            attempts_in_window(&[], window, now),
            0,
            "a slot with no history has spent nothing"
        );

        // A restart recorded *after* the failure under evaluation is discounted:
        // the decision is about the world as it was when the task died.
        assert_eq!(
            attempts_in_window(&[now + Duration::from_secs(5)], window, now),
            0
        );
    }

    /// The two halves together: a task that fails once a minute with a
    /// three-per-minute budget is restarted forever, where the same budget
    /// without a window gives up after three.
    #[test]
    fn a_window_lets_a_slot_earn_its_budget_back() {
        let now = SystemTime::now();
        let policy_windowed = RestartPolicy {
            condition: RestartCondition::Any,
            delay: Duration::ZERO,
            max_attempts: 3,
            window: Duration::from_mins(1),
        };
        let history: Vec<SystemTime> = (1..=3).map(|n| now - Duration::from_hours(n)).collect();

        let attempts = attempts_in_window(&history, policy_windowed.window, now);
        assert_eq!(attempts, 0, "all three are hours old");
        assert_eq!(
            decide(&policy_windowed, TaskState::Failed, attempts),
            RestartDecision::Restart
        );

        let no_window = RestartPolicy {
            window: Duration::ZERO,
            ..policy_windowed
        };
        let attempts = attempts_in_window(&history, no_window.window, now);
        assert_eq!(attempts, 3);
        assert_eq!(
            decide(&no_window, TaskState::Failed, attempts),
            RestartDecision::AttemptsExhausted
        );
    }
}
