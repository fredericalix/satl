// SPDX-License-Identifier: BSD-2-Clause
//! `satl-runtime` — the runtime layer (architecture §8.1): OCI bundle
//! generation plus a typed driver for the `ocijail` binary. SatL never
//! implements a container runtime (invariant #6); this crate generates
//! `config.json` and drives `ocijail create/start/kill/delete/state/exec/
//! list/features`, with the FreeBSD-specific mechanisms ocijail leaves to
//! its caller:
//!
//! - [`spec`] — pure `config.json` generation (exactly the fields ocijail
//!   consumes; linuxulator/FreeBSD mount sets; vnet annotation);
//! - [`precheck`] — task-level platform gate (linuxulator loaded? systemd
//!   entrypoint?) producing operator-grade `REJECTED` reasons;
//! - [`devfs`] — SatL's own devfs ruleset (jail device set + `shm` unhidden
//!   so the `/dev/shm` tmpfs mount works);
//! - [`mounts`] — the mount-leak sweep ocijail's `delete` does not perform
//!   reliably;
//! - [`exit`] — exit-status harvesting via kqueue `EVFILT_PROC`/`NOTE_EXIT`
//!   (ocijail never reports exit codes);
//! - [`procs`] — signalling a process satld did not fork (a detached
//!   healthcheck probe that outlived its timeout);
//! - [`ocijail`] — the command wrapper itself (private `--root` state db,
//!   numeric signals, typed error catalogue);
//! - [`runtime`] — the [`Runtime`] trait composing the above.
//!
//! Ground truth for every behavioral claim: `docs/ocijail.md` and
//! `docs/linuxulator.md` (empirical studies of ocijail 0.6.0 on FreeBSD
//! 15.1), with fixtures captured from real transcripts under
//! `tests/fixtures/`.

pub mod devfs;
pub mod error;
pub mod exit;
pub mod jails;
pub mod mounts;
pub mod ocijail;
pub mod precheck;
pub mod procs;
mod runner;
pub mod runtime;
pub mod spec;

pub use devfs::{Devfs, DevfsError, EnsureOutcome, SATL_DEVFS_RULESET};
pub use error::RuntimeError;
pub use exit::{ExitStatus, ExitWatchError, wait_for_exit, watch_exit_blocking};
pub use jails::{JailError, JailState, Jails};
pub use mounts::{MountEntry, MountError, Mounts, orphan_mounts, task_of_mount};
pub use ocijail::{
    ExecOutcome, ExecSpec, Features, ListEntry, Ocijail, OcijailError, RuntimeState, RuntimeStatus,
};
pub use procs::{SignalError, signal_process};
pub use runner::{CommandOutput, CommandRunner, CreateStdio, StdioSink, SystemRunner};
pub use runtime::{CreatedContainer, DeleteReport, OcijailRuntime, Runtime};
pub use spec::{
    BundleMount, BundleSpec, ImagePlatform, JailUser, MountFstype, OciConfig, ProcessSpec,
    build_config, platform_mounts,
};
