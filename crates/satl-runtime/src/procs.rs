// SPDX-License-Identifier: BSD-2-Clause
//! Signalling a process this daemon did not fork.
//!
//! One caller, one reason: a healthcheck probe runs as `ocijail exec
//! --detach` (docs/ocijail.md §4.1), so the probe process is **not** satld's
//! child — the detached `ocijail` parent exits and the probe is reparented to
//! init. When a probe outlives its `timeout` it therefore cannot be killed
//! through a [`tokio::process::Child`] handle: there is none. It has to be
//! signalled by pid.
//!
//! Why a syscall and not a wrapper around `kill(1)`: CLAUDE.md's
//! external-command rule exists so that *external tools* are driven through
//! typed, fixture-tested wrappers whose errors carry an argv. `kill(2)` is
//! not a tool, it is a syscall — spawning `/bin/kill` to make it one would
//! add a fork, a PATH lookup and an exit-code parse to the one operation that
//! must not fail while we are already cleaning up. `nix` exposes it safely,
//! so the workspace-wide `unsafe_code = "deny"` still holds.
//!
//! Note what this does *not* do: it signals exactly the pid given, never a
//! process group. A probe that forked (`CMD-SHELL "a | b"`) can leave its
//! children behind, and negating the pid to reach the group would be
//! dangerous rather than thorough — a detached exec is not `setsid()`ed by
//! ocijail, so its process group can be satld's own. Anything a probe leaves
//! inside the jail is reaped by `jail_remove(2)` at `ocijail delete`
//! (docs/ocijail.md §4.3).

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

/// Failure of a [`signal_process`] call. `ESRCH` is **not** one of these: a
/// process that is already gone is the outcome the caller wanted.
#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    /// The signal number is not a valid FreeBSD signal.
    #[error("cannot signal pid {pid}: {signal} is not a valid signal number")]
    InvalidSignal {
        /// The pid that was to be signalled.
        pid: i32,
        /// The rejected signal number.
        signal: i32,
    },

    /// The pid is not a value `kill(2)` may target individually (0 means the
    /// caller's process group, negatives mean groups — never what we want).
    #[error("cannot signal pid {pid}: only a positive pid can be signalled")]
    InvalidPid {
        /// The rejected pid.
        pid: i32,
    },

    /// `kill(2)` failed for a reason other than "no such process".
    #[error("kill({pid}, {signal}) failed: {source}")]
    Kill {
        /// The pid that was signalled.
        pid: i32,
        /// The signal that was sent.
        signal: i32,
        /// OS error.
        #[source]
        source: Errno,
    },
}

/// Send `signal` to `pid`. Signal `0` delivers nothing and only performs
/// `kill(2)`'s existence check, which is how a caller asks "is this pid still
/// there?".
///
/// Returns `Ok(true)` when the signal was delivered and `Ok(false)` when the
/// process no longer exists (`ESRCH`) — a race the caller must treat as
/// success, since it means the process died on its own.
///
/// # Errors
///
/// [`SignalError`] for an invalid pid or signal, or any `kill(2)` failure
/// other than `ESRCH`.
pub fn signal_process(pid: i32, signal: i32) -> Result<bool, SignalError> {
    if pid <= 0 {
        return Err(SignalError::InvalidPid { pid });
    }
    let sig = if signal == 0 {
        None
    } else {
        Some(Signal::try_from(signal).map_err(|_| SignalError::InvalidSignal { pid, signal })?)
    };
    match nix::sys::signal::kill(Pid::from_raw(pid), sig) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(source) => Err(SignalError::Kill {
            pid,
            signal,
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_zero_probe_finds_this_process() {
        // Signal 0 delivers nothing but still performs the existence check.
        let me = std::process::id();
        assert!(signal_process(i32::try_from(me).unwrap(), 0).unwrap());
    }

    #[test]
    fn a_dead_pid_is_not_an_error() {
        // pid 0x7ffffff0 is far above any live pid on this host, and the
        // caller must be able to say "already gone" without a failure.
        let outcome = signal_process(0x7fff_fff0, 0);
        assert!(matches!(outcome, Ok(false)), "{outcome:?}");
    }

    #[test]
    fn non_positive_pids_and_bad_signals_are_rejected() {
        for pid in [0, -1, -4242] {
            assert!(matches!(
                signal_process(pid, 9),
                Err(SignalError::InvalidPid { .. })
            ));
        }
        let me = i32::try_from(std::process::id()).unwrap();
        assert!(matches!(
            signal_process(me, 4242),
            Err(SignalError::InvalidSignal { .. })
        ));
    }
}
