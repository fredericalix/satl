// SPDX-License-Identifier: BSD-2-Clause
//! Crate-level error type composing the per-module wrapper errors, plus the
//! task-level precheck rejections that don't belong to any external command.

use std::path::PathBuf;

use crate::devfs::DevfsError;
use crate::exit::ExitWatchError;
use crate::mounts::MountError;
use crate::ocijail::OcijailError;

/// Any failure surfaced by `satl-runtime`. Operator-facing: messages name
/// the jail id and the exact external command where one was involved.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// An `ocijail` invocation failed.
    #[error(transparent)]
    Ocijail(#[from] OcijailError),

    /// Mount enumeration / leak cleanup failed.
    #[error(transparent)]
    Mounts(#[from] MountError),

    /// devfs ruleset management failed.
    #[error(transparent)]
    Devfs(#[from] DevfsError),

    /// The kqueue exit watch failed.
    #[error(transparent)]
    ExitWatch(#[from] ExitWatchError),

    /// The task has no entrypoint at all (ocijail would reject the config
    /// with `process.args must have at least one element`; caught earlier
    /// for a clearer error).
    #[error("container '{jail_id}' has an empty entrypoint (process.args must not be empty)")]
    EmptyEntrypoint {
        /// The jail id.
        jail_id: String,
    },

    /// The image wants systemd/init as PID 1 — rejected up front because
    /// runtime detection is useless (systemd exits 1 with zero output under
    /// the linuxulator; docs/linuxulator.md failure signatures).
    #[error(
        "container '{jail_id}': image runs {entrypoint:?} as PID 1; FreeBSD jails provide no \
         PID namespace or cgroups, so systemd/init cannot run (it dies silently under the \
         linuxulator). Use an image with a plain foreground entrypoint"
    )]
    EntrypointNeedsInit {
        /// The jail id.
        jail_id: String,
        /// The offending `args[0]`.
        entrypoint: String,
    },

    /// A `linux/*` image was scheduled on a host without the linuxulator.
    #[error(
        "container '{jail_id}' needs the linuxulator but it is not available on this host \
         (probe `{argv}` failed with {status}; stderr: {stderr:?}). Load the linux kernel \
         modules (linux_enable=\"YES\" in rc.conf, then `service linux start`) or schedule \
         the task on a linux-capable node",
        status = match exit_code { Some(code) => format!("exit code {code}"), None => "signal".to_owned() }
    )]
    LinuxulatorUnavailable {
        /// The jail id.
        jail_id: String,
        /// Full rendered probe command line.
        argv: String,
        /// Probe exit code.
        exit_code: Option<i32>,
        /// Probe stderr.
        stderr: String,
    },

    /// The bundle spec's rootfs is not an absolute path (ocijail would
    /// resolve it against the bundle — SatL always passes the absolute ZFS
    /// clone mountpoint).
    #[error("container '{jail_id}': rootfs path {path} must be absolute")]
    RootfsNotAbsolute {
        /// The jail id.
        jail_id: String,
        /// The offending path.
        path: PathBuf,
    },

    /// Writing `config.json` into the bundle directory failed.
    #[error("container '{jail_id}': cannot write bundle config {path}: {source}")]
    WriteBundle {
        /// The jail id.
        jail_id: String,
        /// The config.json path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl RuntimeError {
    /// Whether this wraps the typed "container unknown to ocijail" outcome.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Ocijail(error) if error.is_not_found())
    }
}
