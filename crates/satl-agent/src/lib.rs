// SPDX-License-Identifier: BSD-2-Clause
//! Worker side of SatL: the task executor (architecture §7.2, §8.2; SWK
//! §14–§15). `satld` owns the dispatcher session and wires the subsystems;
//! everything below the assignment stream lives here.
//!
//! ```text
//!   assignments ──▶ Worker ──▶ TaskManager (one tokio task per task)
//!                     │             │
//!                     │             ├─▶ do_step   one-step state machine (SWK §15.4)
//!                     │             └─▶ Controller prepare/start/wait/shutdown/remove
//!                     ├─▶ TaskDb    <state_dir>/worker/tasks/<task_id> (CBOR, atomic)
//!                     └─▶ StatusReporter  → dispatcher (implemented by satld)
//! ```
//!
//! Modules:
//!
//! - [`executor`] — the bag of node-local subsystems ([`Executor`]);
//! - [`controller`] — the per-task driver ([`Controller`], [`TaskController`]);
//! - [`bundle`] — pure OCI-bundle planning (entrypoint/env/mount merge);
//! - [`do_step`] — SwarmKit's `exec.Do`, ported;
//! - [`task_manager`] — the per-task loop;
//! - [`worker`] — the task set, assignment application and restart resume;
//! - [`db`] — the local task database;
//! - [`deps`] — the in-memory secret/config set the dispatcher ships
//!   (invariant #7: secrets never reach disk);
//! - [`health`] — Docker HEALTHCHECK semantics: the probe that runs through
//!   `ocijail exec`, the health state machine, and the node-local registry
//!   `satl ps`/`satl inspect` read (health gates `RUNNING`);
//! - [`rctl`] — the rctl(8) wrapper and its racct degradation (§8.3);
//! - [`reporter`] — the [`StatusReporter`] seam satld implements;
//! - [`overlay`] — the [`TaskOverlay`] seam satld implements, through which a
//!   controller attaches its jail to the cluster's overlay networks.
//!
//! Pinned M1 contracts other crates build against:
//!
//! - **container ID = task ID = jail name** (architecture §3: jail(8) treats
//!   `.` as the hierarchy separator, so the dotted task *name* is unusable);
//! - logs at `<state_dir>/logs/<task_id>/{stdout,stderr}.log`, raw bytes,
//!   opened at jail create and inherited by the container for its whole life
//!   (docs/ocijail.md §3);
//! - the local task DB at `<state_dir>/worker/tasks/<task_id>` (CBOR, atomic
//!   write-rename), whose status is **canonical** over the manager's copy;
//! - desired `READY` means "prepared but not started" (Docker `created`),
//!   desired `RUNNING` means started.
//!
//! Deferred (M2+ / recorded in the M1 report): TTY allocation
//! (console-socket handshake), user *names* in `ContainerSpec.user` (needs
//! the image's `/etc/passwd`) and per-task registry credentials. Healthcheck
//! gating of `RUNNING` landed in M4 ([`health`]); secrets/configs delivery
//! (tmpfs materialization, [`materialize`]) landed in M5.

pub mod bundle;
pub mod controller;
pub mod db;
pub mod deps;
pub mod do_step;
pub mod error;
pub mod executor;
pub mod health;
mod materialize;
pub mod overlay;
pub mod rctl;
pub mod reporter;
pub mod runner;
pub mod task_manager;
pub mod worker;

#[cfg(test)]
mod testing;

pub use bundle::{
    DependencyPlan, PayloadFile, PlanError, ProcessPlan, SECRETS_TARGET_DIR, plan_bundle,
    plan_dependencies, plan_mounts, plan_process,
};
pub use controller::{Controller, ExitOutcome, TaskController};
pub use db::{DbError, TaskDb, TaskRecord};
pub use deps::DependencyStore;
pub use do_step::{Step, do_step};
pub use error::ControllerError;
pub use executor::{Datasets, Executor, ExecutorParts, HostFacts, LinuxEmulation};
pub use health::{
    HealthRegistry, HealthStatus, HealthTracker, ProbeResult, ProbeSettings, TaskHealth,
};
pub use overlay::{OverlayError, TaskOverlay};
pub use rctl::{LimitsOutcome, LimitsSkipped, Rctl, RctlError, RctlUsage, racct_enabled};
pub use reporter::{DiscardingReporter, StatusReporter};
pub use runner::{CommandOutput, CommandRunner, SystemRunner};
pub use task_manager::{Exit, RETRY_BACKOFF, TaskManager};
pub use worker::{InitReport, ResumeDecision, Worker, WorkerError, resume_decision};
