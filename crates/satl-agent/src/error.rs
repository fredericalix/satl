// SPDX-License-Identifier: BSD-2-Clause
//! Controller errors and their retry classification (SWK §15.4).
//!
//! The state machine only asks one question of a failure: *is it worth
//! retrying?* Retryable failures leave the observed state alone and are
//! re-attempted after the backoff; everything else is terminal — `REJECTED`
//! before `STARTING`, `FAILED` from `STARTING` on (architecture §8.2).
//!
//! Classification rules, mirroring SwarmKit's `Temporary`/`MakeTemporary`:
//!
//! - [`ControllerError::Cancelled`] — a task update or daemon shutdown
//!   cancelled the in-flight operation; nothing went wrong (SwarmKit retries
//!   on `context.Canceled`).
//! - [`ControllerError::Temporary`] — an explicit wrapper placed by the code
//!   that knows the failure is transient (registry 5xx, connect failures);
//!   unwrapped recursively.
//! - everything else is terminal. Notably ZFS, ocijail, ifconfig and rctl
//!   failures are *environment* problems an operator must fix: retrying them
//!   forever would hide the task instead of surfacing it.

use std::path::PathBuf;

use satl_image::ImageError;
use satl_net::NetError;
use satl_runtime::RuntimeError;
use satl_storage::{ContainerFsError, LayerStoreError, VolumeStoreError, ZfsError};

use crate::bundle::PlanError;
use crate::rctl::RctlError;

/// Anything a [`crate::controller::Controller`] step can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    /// The bundle could not be planned from the spec + image config.
    #[error(transparent)]
    Plan(#[from] PlanError),

    /// Image resolution, pull or metadata failure.
    #[error(transparent)]
    Image(#[from] ImageError),

    /// Layer application failure.
    #[error(transparent)]
    Layers(#[from] LayerStoreError),

    /// Container writable-layer failure.
    #[error(transparent)]
    ContainerFs(#[from] ContainerFsError),

    /// Named-volume failure.
    #[error(transparent)]
    Volumes(#[from] VolumeStoreError),

    /// Raw `zfs`(8) failure (dataset probes during adoption/cleanup).
    #[error(transparent)]
    Zfs(#[from] ZfsError),

    /// Networking failure (epair, bridge, pf).
    #[error(transparent)]
    Net(#[from] NetError),

    /// Overlay attachment failure: the VTEP, the overlay bridge, the task's
    /// epair on it, or the forwarding/ARP entries that reach its peers.
    ///
    /// Terminal like every other environment failure above. A container whose
    /// overlay attachment failed must not run: it would come up with no route
    /// to any peer and look healthy (`docs/vxlan.md` §6 — a broken overlay
    /// fails silently, which is why this is not a warning).
    #[error(transparent)]
    Overlay(#[from] crate::overlay::OverlayError),

    /// ocijail / OCI bundle failure.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    /// rctl(8) failure on a racct-enabled host.
    #[error(transparent)]
    Rctl(#[from] RctlError),

    /// Filesystem work owned by the agent (bundle dir, log sinks).
    #[error("task {task_id}: {what} failed at {path}: {source}")]
    Io {
        /// The task being driven.
        task_id: String,
        /// What was being attempted.
        what: &'static str,
        /// The path involved.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A `bind` mount names a host path that does not exist on this node.
    #[error(
        "task {task_id}: bind mount source {host_path:?} (for {target:?}) does not exist on \
         this node. Create it or use a named volume"
    )]
    BindSourceMissing {
        /// The task being driven.
        task_id: String,
        /// The missing host path.
        host_path: String,
        /// Where it would have been mounted.
        target: String,
    },

    /// A `linux/*` image was scheduled here but the linuxulator is not
    /// available (docs/linuxulator.md host requirements).
    #[error(
        "task {task_id}: image {image} resolved to a linux platform but this node has no \
         linuxulator. Load the linux kernel modules (linux_enable=\"YES\") or schedule the \
         task on a linux-capable node"
    )]
    LinuxEmulationUnavailable {
        /// The task being driven.
        task_id: String,
        /// The image reference.
        image: String,
    },

    /// A healthcheck probe could not be set up (the bundle's `config.json`,
    /// which is where a probe inherits the container's env, cwd and user).
    /// A probe that *runs* and fails is never an error — it is a failed probe.
    #[error(transparent)]
    Health(#[from] crate::health::HealthError),

    /// The task's healthcheck failed `retries` consecutive times outside its
    /// start period. Terminal: the task is `FAILED` and the orchestrator's
    /// restart supervisor replaces it (SWK §15.2 `ErrContainerUnhealthy`).
    #[error(
        "task {task_id}: the container is unhealthy after {streak} consecutive healthcheck \
         failures (last probe exit code {exit_code}); see the health log in `satl inspect`"
    )]
    Unhealthy {
        /// The task being driven.
        task_id: String,
        /// Consecutive failures at the moment the verdict was reached.
        streak: u32,
        /// Exit code of the last probe (`-1` when it could not be run).
        exit_code: i32,
    },

    /// The container died before its healthcheck ever passed, so the task never
    /// reached `RUNNING`. Reported with what the exit watch harvested, which
    /// says far more than "unhealthy" would.
    #[error("task {task_id}: {detail}, before its healthcheck first succeeded")]
    ExitedBeforeHealthy {
        /// The task being driven.
        task_id: String,
        /// What the exit watch harvested.
        detail: String,
    },

    /// The health prober task ended without a verdict — an internal failure,
    /// reported instead of waiting for a probe that will never run.
    #[error("task {task_id}: the health prober stopped without a verdict (agent bug)")]
    HealthProberGone {
        /// The task being driven.
        task_id: String,
    },

    /// `wait` was called on a task whose container was never created (or
    /// whose exit watch was lost). The task manager only reaches `wait` from
    /// `RUNNING`, so this means state and reality disagree.
    #[error("task {task_id}: no exit watch is armed; the container is not running on this node")]
    NoExitWatch {
        /// The task being driven.
        task_id: String,
    },

    /// A referenced secret/config has not been delivered by the dispatcher
    /// yet. **Retryable**: the dispatcher ships dependencies before the
    /// tasks that need them, so a gap only exists mid-resync (typically an
    /// agent restart racing its first `COMPLETE` snapshot) and closes on its
    /// own. Names the object, never quotes anything (invariant #7).
    #[error(
        "task {task_id}: {kind} {name} has not been delivered to this node yet; \
         waiting for the dispatcher stream"
    )]
    DependencyNotDelivered {
        /// The task being driven.
        task_id: String,
        /// `"secret"` or `"config"`.
        kind: &'static str,
        /// Name of the missing object.
        name: String,
    },

    /// A secret/config payload file could not be written (tmpfs or bundle
    /// dir). The error names the object and the path, never the payload.
    #[error("task {task_id}: {source}")]
    PayloadWrite {
        /// The task being driven.
        task_id: String,
        /// The failing write.
        #[source]
        source: crate::materialize::PayloadWriteError,
    },

    /// The registry answered 404 for the image's manifest: the image is not
    /// there. On a cluster the likely cause is node locality — a
    /// `satl build` lands in one node's local store and the other nodes
    /// cannot pull it (audit N3, api-compat #144). Still terminal: retrying
    /// a missing manifest only delays the verdict.
    #[error(
        "registry {registry}: no such manifest for {repository} ({reference}); the image may \
         exist only in another node's local store - push it to a registry the nodes can reach \
         (`satl tag` + `satl push`), or constrain the service to the node that has it"
    )]
    ManifestUnknown {
        /// Registry host that answered 404.
        registry: String,
        /// Repository the manifest was asked for.
        repository: String,
        /// The manifest reference (tag or digest) the registry does not know.
        reference: String,
    },

    /// The operation was cancelled (task update or daemon shutdown).
    #[error("task operation cancelled")]
    Cancelled,

    /// Explicitly-retryable wrapper (SwarmKit `MakeTemporary`).
    #[error(transparent)]
    Temporary(Box<ControllerError>),
}

impl ControllerError {
    /// Mark this failure retryable (SwarmKit `MakeTemporary`). Idempotent.
    #[must_use]
    pub fn temporary(self) -> Self {
        match self {
            Self::Temporary(_) => self,
            other => Self::Temporary(Box::new(other)),
        }
    }

    /// Whether the state machine should retry rather than fail the task
    /// (SwarmKit `IsTemporary`, unwrapping recursively).
    #[must_use]
    pub fn is_temporary(&self) -> bool {
        match self {
            Self::Cancelled | Self::DependencyNotDelivered { .. } => true,
            Self::Temporary(inner) => {
                // Recursive by construction; the wrapper itself is enough.
                let _ = inner;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_error() -> ControllerError {
        PlanError::TtyUnsupported {
            task_id: "t1".to_owned(),
        }
        .into()
    }

    #[test]
    fn terminal_by_default() {
        assert!(!plan_error().is_temporary());
    }

    #[test]
    fn cancellation_is_retryable() {
        assert!(ControllerError::Cancelled.is_temporary());
    }

    /// A health verdict must never be retried: retrying would leave the
    /// container running and the task `STARTING`/`RUNNING` forever, where the
    /// point is to fail the task so the restart supervisor replaces it.
    #[test]
    fn health_failures_are_terminal() {
        let failures = [
            ControllerError::Unhealthy {
                task_id: "t1".to_owned(),
                streak: 3,
                exit_code: 1,
            },
            ControllerError::ExitedBeforeHealthy {
                task_id: "t1".to_owned(),
                detail: "container exited with code 2".to_owned(),
            },
            ControllerError::HealthProberGone {
                task_id: "t1".to_owned(),
            },
        ];
        for failure in failures {
            assert!(!failure.is_temporary(), "{failure}");
            assert!(failure.to_string().contains("t1"), "{failure}");
        }
    }

    #[test]
    fn temporary_wrapper_is_idempotent_and_keeps_the_message() {
        let wrapped = plan_error().temporary();
        assert!(wrapped.is_temporary());
        assert!(wrapped.to_string().contains("TTY"), "{wrapped}");
        let twice = wrapped.temporary();
        assert!(twice.is_temporary());
        assert!(
            matches!(&twice, ControllerError::Temporary(inner) if !matches!(**inner, ControllerError::Temporary(_))),
            "double wrapping: {twice:?}"
        );
    }
}
