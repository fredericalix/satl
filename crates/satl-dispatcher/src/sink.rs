// SPDX-License-Identifier: BSD-2-Clause
//! [`AssignmentSink`] — where applied assignments land on the worker.
//!
//! The session client ([`crate::agent`]) speaks the protocol; it does not
//! know about jails, ZFS or the local task DB. This trait is the seam between
//! the two, and it exists for two reasons:
//!
//! - the real sink ([`WorkerSink`]) drives a [`satl_agent::Worker`], which
//!   needs a full [`Executor`](satl_agent::Executor) — root, ocijail, ZFS —
//!   so a protocol test could not construct one. Behind the trait, the
//!   protocol is tested unprivileged against a recording double;
//! - it makes the pinned application order (secrets → configs → networks →
//!   tasks) an explicit sequence of calls that a test can assert on, rather
//!   than something buried in a stream loop.
//!
//! Secrets and configs are applied **synchronously**: they are in-memory map
//! writes ([`satl_agent::DependencyStore`]) and must be visible before the
//! task that references them is handed over. Networks are not: programming a
//! VTEP, a bridge and a table of FDB entries means `ifconfig` and ioctls, so
//! [`AssignmentSink::apply_network`] is async like the task methods.

use std::collections::{BTreeMap, BTreeSet};

use satl_core::{Config, DesiredState, Id, ResourceRequirements, Secret, Task};

use crate::assignment::NetworkAssignment;

/// The worker refused an assignment.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The local task DB failed, so the task must not be started: a task the
    /// agent cannot remember is a task it cannot clean up after a restart
    /// (SWK §14.2).
    #[error(transparent)]
    Worker(#[from] satl_agent::WorkerError),
}

/// Where the assignment stream's decisions are applied.
pub trait AssignmentSink: Send + Sync + 'static {
    /// Rebuild the task set from the local DB, keeping only `live` (the task
    /// IDs of the first `COMPLETE` snapshot).
    ///
    /// Called once per process, on the first snapshot: a running jail is
    /// re-attached rather than restarted, and a task no longer assigned is
    /// released (architecture §7.2).
    ///
    /// Returns the desired state each resumed task is now being driven at,
    /// which is the state **persisted locally** — not the one in the snapshot —
    /// and the resources that persisted definition carries. The caller needs
    /// the difference: a task resumed at `RUNNING` whose assignment says
    /// `SHUTDOWN` has to be handed over again, or the re-attached container is
    /// never asked to stop — and one whose limits moved while the agent was
    /// down has to be handed over so the live jail's rctl rules follow (M6g).
    fn init(
        &self,
        live: &BTreeSet<Id>,
    ) -> impl Future<Output = Result<BTreeMap<Id, (DesiredState, ResourceRequirements)>, SinkError>> + Send;

    /// The tasks the worker currently drives.
    fn task_ids(&self) -> impl Future<Output = BTreeSet<Id>> + Send;

    /// A task was assigned or updated.
    fn apply_task(&self, task: Task) -> impl Future<Output = Result<(), SinkError>> + Send;

    /// A task is no longer assigned: stop it and release its resources.
    fn remove_task(&self, task_id: &Id) -> impl Future<Output = Result<(), SinkError>> + Send;

    /// Replace the whole secret set (a `COMPLETE` snapshot).
    fn reset_secrets(&self, secrets: Vec<Secret>);

    /// Add or replace one secret.
    fn put_secret(&self, secret: Secret);

    /// Drop one secret.
    fn remove_secret(&self, id: &Id);

    /// Replace the whole config set (a `COMPLETE` snapshot).
    fn reset_configs(&self, configs: Vec<Config>);

    /// Add or replace one config.
    fn put_config(&self, config: Config);

    /// Drop one config.
    fn remove_config(&self, id: &Id);

    /// A network one of this node's tasks attaches to was assigned, or its
    /// endpoint table changed: program (or re-program) it.
    ///
    /// Called **before** the tasks that attach to it, and called again on
    /// every endpoint change anywhere in the cluster — that is how FDB updates
    /// reach a node (architecture §11.2). Implementations must therefore be
    /// **idempotent and reconciling**, not incremental: the assignment is the
    /// whole desired state of that network on this node, and `add` on an
    /// existing FDB entry replaces it (`docs/vxlan.md` §7).
    ///
    /// There is deliberately no `reset_networks` counterpart to
    /// [`Self::reset_secrets`]: a `COMPLETE` snapshot must not tear the
    /// overlay down and rebuild it, because that would flap live jails'
    /// connectivity on every re-registration. The applier re-applies each
    /// network in the snapshot and removes the ones it no longer holds;
    /// adopting interfaces left behind by a previous process is `satld`'s
    /// startup sweep, not this stream's job.
    ///
    /// The default implementation logs and succeeds, so a sink with no overlay
    /// to program — a test double, a node whose networking is not wired yet —
    /// still compiles and still runs the rest of the protocol.
    fn apply_network(
        &self,
        assignment: NetworkAssignment,
    ) -> impl Future<Output = Result<(), SinkError>> + Send {
        async move {
            tracing::debug!(
                network_id = %assignment.id(),
                endpoints = assignment.endpoints.len(),
                "this sink does not program networks; ignoring a network assignment"
            );
            Ok(())
        }
    }

    /// The last task attached to this network left (or the network is gone):
    /// tear it down on this node.
    ///
    /// Called **after** the tasks that were attached to it have been released
    /// ([`crate::assignment::ObjectRef::teardown_rank`]).
    fn remove_network(&self, id: &Id) -> impl Future<Output = Result<(), SinkError>> + Send {
        async move {
            tracing::debug!(
                network_id = %id,
                "this sink does not program networks; ignoring a network removal"
            );
            Ok(())
        }
    }

    /// A `COMPLETE` snapshot finished applying; `current` is the entire
    /// network set this node holds now.
    ///
    /// The applier's own diff removes networks *it* knew about, which covers
    /// everything except a fresh process meeting host interfaces an earlier
    /// one programmed: a restarted **worker** has no store to sweep them from
    /// at startup (a manager does — `satld`'s startup reconciliation), so the
    /// first snapshot is the earliest moment the stale set is knowable. The
    /// default does nothing; the daemon's overlay sink reconciles host state
    /// against `current` exactly once per process.
    fn networks_synced(&self, current: Vec<NetworkAssignment>) -> impl Future<Output = ()> + Send {
        async move {
            tracing::debug!(
                networks = current.len(),
                "this sink does not program networks; ignoring the snapshot's network set"
            );
        }
    }
}

/// The production sink: a [`satl_agent::Worker`] for tasks and a
/// [`satl_agent::DependencyStore`] for secrets and configs.
///
/// Both are shared with the rest of the daemon (the worker also serves
/// `satl ps`; the dependency store is read by task controllers when they
/// build a bundle), which is why this is a pair of `Arc`s rather than an
/// owner.
///
/// TODO(M3): networks fall through to [`AssignmentSink`]'s default no-op. The
/// overlay programmer (`satl-overlay`) is the third collaborator this struct
/// needs, and wiring it — including which of `apply_network`'s work belongs in
/// `spawn_blocking` — is the daemon's, in the change that lands the VTEP/FDB
/// implementation. Until then a manager still ships the assignments and the
/// worker still logs them, so the protocol half is testable on its own.
pub struct WorkerSink<R: satl_agent::StatusReporter> {
    worker: std::sync::Arc<satl_agent::Worker<R>>,
    deps: std::sync::Arc<satl_agent::DependencyStore>,
}

impl<R: satl_agent::StatusReporter> std::fmt::Debug for WorkerSink<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkerSink").finish_non_exhaustive()
    }
}

impl<R: satl_agent::StatusReporter> WorkerSink<R> {
    /// A sink over an existing worker and dependency store.
    #[must_use]
    pub fn new(
        worker: std::sync::Arc<satl_agent::Worker<R>>,
        deps: std::sync::Arc<satl_agent::DependencyStore>,
    ) -> Self {
        Self { worker, deps }
    }

    /// The worker being driven.
    #[must_use]
    pub fn worker(&self) -> &std::sync::Arc<satl_agent::Worker<R>> {
        &self.worker
    }

    /// The dependency store being fed.
    #[must_use]
    pub fn dependencies(&self) -> &std::sync::Arc<satl_agent::DependencyStore> {
        &self.deps
    }
}

impl<R: satl_agent::StatusReporter> AssignmentSink for WorkerSink<R> {
    async fn init(
        &self,
        live: &BTreeSet<Id>,
    ) -> Result<BTreeMap<Id, (DesiredState, ResourceRequirements)>, SinkError> {
        let report = self.worker.init_from_disk(live).await?;
        tracing::info!(
            resumed = report.resumed.len(),
            reattached = report.reattached.len(),
            died_while_down = report.died_while_down.len(),
            removed = report.removed.len(),
            driving = report.driving.len(),
            "rebuilt the task set from the local db"
        );
        Ok(report.driving)
    }

    async fn task_ids(&self) -> BTreeSet<Id> {
        self.worker.task_ids().await
    }

    async fn apply_task(&self, task: Task) -> Result<(), SinkError> {
        self.worker.apply(task).await.map_err(SinkError::from)
    }

    async fn remove_task(&self, task_id: &Id) -> Result<(), SinkError> {
        self.worker.remove(task_id).await.map_err(SinkError::from)
    }

    fn reset_secrets(&self, secrets: Vec<Secret>) {
        self.deps.reset_secrets(secrets);
    }

    fn put_secret(&self, secret: Secret) {
        self.deps.put_secret(secret);
    }

    fn remove_secret(&self, id: &Id) {
        self.deps.remove_secret(id);
    }

    fn reset_configs(&self, configs: Vec<Config>) {
        self.deps.reset_configs(configs);
    }

    fn put_config(&self, config: Config) {
        self.deps.put_config(config);
    }

    fn remove_config(&self, id: &Id) {
        self.deps.remove_config(id);
    }
}
