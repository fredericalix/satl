// SPDX-License-Identifier: BSD-2-Clause
//! Exit-code harvesting for container processes.
//!
//! ocijail never reports an exit code anywhere — not in `state`, not in
//! `list` (docs/ocijail.md §1.6). The container process is forked by
//! `ocijail create` and reparented to init, so it is **not** satld's child
//! and can never be `waitpid(2)`ed. The only way to learn how it died is a
//! kqueue `EVFILT_PROC`/`NOTE_EXIT` watch on the pid from `--pid-file`:
//! kqueue(2) stores the exit status in the event's `data` field "in the same
//! format as the status returned by wait(2)".
//!
//! Race handling: the watch should be armed right after `create` (before
//! `start`). If registration fails with `ESRCH` the process is already gone
//! and fully reaped — the code is unrecoverable and
//! [`ExitStatus::unknown()`] is returned (the caller still sees
//! `status=stopped` from `ocijail state`). A process that has exited but is
//! not yet reaped (a zombie) can still be attached to: FreeBSD activates the
//! knote immediately with the real exit status.
//!
//! Reaping: in production nothing needs to reap — init reaps the reparented
//! container process. In unit tests the watched process *is* our child, so
//! tests must still `wait()` on it after harvesting to avoid a zombie; the
//! watcher itself never reaps.
//!
//! Implementation notes: `nix` (feature `event`) provides a safe kqueue
//! wrapper, so the workspace-wide `unsafe_code = "deny"` holds — no unsafe
//! block was needed. `kevent(2)` blocks, so the async entry point
//! [`wait_for_exit`] runs the watch on the blocking thread pool
//! (`spawn_blocking`), per CLAUDE.md's async rules.

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

/// How a watched process terminated, decoded from the wait(2)-format status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitStatus {
    /// Exit code, when the process exited normally (`WIFEXITED`).
    pub code: Option<i32>,
    /// Terminating signal, when it was killed (`WIFSIGNALED`).
    pub signal: Option<i32>,
}

impl ExitStatus {
    /// The process was already gone (fully reaped) before the watch could be
    /// registered; its exit status is unrecoverable (docs/ocijail.md §1.6).
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            code: None,
            signal: None,
        }
    }

    /// Whether this is the [`ExitStatus::unknown`] outcome.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        self.code.is_none() && self.signal.is_none()
    }
}

/// Error from the kqueue exit watch. Carries the watched pid so the operator
/// can correlate with the jail's `--pid-file`.
#[derive(Debug, thiserror::Error)]
pub enum ExitWatchError {
    /// `kqueue(2)` could not be created.
    #[error("kqueue(2) failed while setting up the exit watch for pid {pid}: {source}")]
    KqueueCreate {
        /// The pid that was to be watched.
        pid: i32,
        /// OS error.
        #[source]
        source: Errno,
    },

    /// `kevent(2)` failed (registration for reasons other than ESRCH, or the
    /// blocking wait itself).
    #[error("kevent(2) failed while watching pid {pid} for exit: {source}")]
    Kevent {
        /// The watched pid.
        pid: i32,
        /// OS error.
        #[source]
        source: Errno,
    },

    /// The kernel returned an event whose wait(2) status is neither an exit
    /// nor a signal death — impossible for `NOTE_EXIT`; kept as a typed
    /// error instead of a panic path.
    #[error("NOTE_EXIT for pid {pid} carried undecodable wait status {status:#x}")]
    UndecodableStatus {
        /// The watched pid.
        pid: i32,
        /// The raw wait(2) status from the event's `data` field.
        status: i64,
    },

    /// The `spawn_blocking` task running the watch was cancelled (runtime
    /// shutdown).
    #[error("exit watch task for pid {pid} was cancelled before the process exited")]
    Cancelled {
        /// The watched pid.
        pid: i32,
    },
}

/// Decode a wait(2)-format status (see `sys/wait.h`):
/// low 7 bits `0` ⇒ exited, code in bits 8–15 (`WEXITSTATUS`);
/// low 7 bits `0177` ⇒ stopped (impossible for `NOTE_EXIT`);
/// anything else ⇒ killed by the signal in the low 7 bits (`WTERMSIG`).
fn decode_wait_status(pid: i32, status: i64) -> Result<ExitStatus, ExitWatchError> {
    #[allow(clippy::cast_possible_truncation)] // wait statuses fit in i32.
    let status32 = status as i32;
    let low = status32 & 0o177;
    if low == 0 {
        Ok(ExitStatus {
            code: Some((status32 >> 8) & 0xff),
            signal: None,
        })
    } else if low == 0o177 {
        Err(ExitWatchError::UndecodableStatus { pid, status })
    } else {
        Ok(ExitStatus {
            code: None,
            signal: Some(low),
        })
    }
}

/// Blocking exit watch: register `EVFILT_PROC`/`NOTE_EXIT` for `pid` and
/// wait until it fires. See the module docs for race and reaping semantics.
///
/// Call from a thread that may block ([`wait_for_exit`] wraps this in
/// `spawn_blocking`).
pub fn watch_exit_blocking(pid: i32) -> Result<ExitStatus, ExitWatchError> {
    let kq = Kqueue::new().map_err(|source| ExitWatchError::KqueueCreate { pid, source })?;
    let ident = usize::try_from(pid).map_err(|_| ExitWatchError::Kevent {
        pid,
        source: Errno::ESRCH,
    })?;
    let add = KEvent::new(
        ident,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    // Registration pass: with an empty eventlist, changelist errors come
    // back as -1/errno instead of EV_ERROR events.
    match kq.kevent(&[add], &mut [], None) {
        Ok(_) => {}
        Err(Errno::ESRCH) => {
            // Already exited *and* reaped: nothing left to observe.
            tracing::debug!(pid, "exit watch registration raced: process already reaped");
            return Ok(ExitStatus::unknown());
        }
        Err(source) => return Err(ExitWatchError::Kevent { pid, source }),
    }

    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_PROC,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    ); 1];
    loop {
        let received = match kq.kevent(&[], &mut events, None) {
            Ok(received) => received,
            Err(Errno::EINTR) => continue,
            Err(source) => return Err(ExitWatchError::Kevent { pid, source }),
        };
        if received == 0 {
            continue; // No timeout was set; spurious wakeup.
        }
        let event = events[0];
        if event.flags().contains(EvFlags::EV_ERROR) {
            let errno = Errno::from_raw(i32::try_from(event.data()).unwrap_or(0));
            if errno == Errno::ESRCH {
                return Ok(ExitStatus::unknown());
            }
            return Err(ExitWatchError::Kevent { pid, source: errno });
        }
        if event.fflags().contains(FilterFlag::NOTE_EXIT) {
            let status = decode_wait_status(pid, i64::try_from(event.data()).unwrap_or(0))?;
            tracing::debug!(pid, code = ?status.code, signal = ?status.signal,
                "harvested container exit status");
            return Ok(status);
        }
        // Not our fflags (cannot happen — we registered NOTE_EXIT only);
        // keep waiting rather than mis-reporting.
    }
}

/// Async exit watch: [`watch_exit_blocking`] on the blocking thread pool.
pub async fn wait_for_exit(pid: i32) -> Result<ExitStatus, ExitWatchError> {
    tokio::task::spawn_blocking(move || watch_exit_blocking(pid))
        .await
        .map_err(|_join_error| ExitWatchError::Cancelled { pid })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader};
    use std::process::{Command, Stdio};

    #[test]
    fn decode_exited() {
        // wait(2) status for exit(42): 42 << 8.
        assert_eq!(
            decode_wait_status(1, 42 << 8).unwrap(),
            ExitStatus {
                code: Some(42),
                signal: None
            }
        );
        assert_eq!(
            decode_wait_status(1, 0).unwrap(),
            ExitStatus {
                code: Some(0),
                signal: None
            }
        );
    }

    #[test]
    fn decode_signaled() {
        // SIGTERM = 15; core-dump bit 0200 must not leak into the signal.
        assert_eq!(
            decode_wait_status(1, 15).unwrap(),
            ExitStatus {
                code: None,
                signal: Some(15)
            }
        );
        assert_eq!(
            decode_wait_status(1, 0o200 | 6).unwrap(),
            ExitStatus {
                code: None,
                signal: Some(6)
            }
        );
    }

    #[test]
    fn decode_stopped_is_an_error() {
        assert!(decode_wait_status(1, 0o177).is_err());
    }

    /// Harvest a normal exit without ever waitpid()ing first. The child is
    /// gated on stdin so the watch is registered while it is provably alive;
    /// the zombie-attach fallback (module docs) covers the residual race.
    #[tokio::test]
    async fn harvests_exit_code_42() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "echo ready; read _gate; exit 42"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        // Wait until the child is definitely running its script.
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "ready");

        let watch = tokio::spawn(wait_for_exit(pid));
        // Give the watcher a moment to register, then release the gate.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(child.stdin.take());

        let status = watch.await.unwrap().unwrap();
        assert_eq!(status.code, Some(42), "status: {status:?}");
        assert_eq!(status.signal, None);

        // The test child is OUR child: reap it now that kqueue confirmed the
        // exit (in production the container pid is init's child — no reap).
        let reaped = child.wait().unwrap();
        assert_eq!(reaped.code(), Some(42));
    }

    /// Harvest a signal death (SIGTERM to a sleeping child).
    #[tokio::test]
    async fn harvests_termination_signal() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();

        let watch = tokio::spawn(wait_for_exit(pid));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();

        let status = watch.await.unwrap().unwrap();
        assert_eq!(status.signal, Some(15), "status: {status:?}");
        assert_eq!(status.code, None);
        child.wait().unwrap(); // reap
    }

    /// A pid that exited and was already reaped: registration gets ESRCH and
    /// the watch reports the typed unknown outcome.
    #[tokio::test]
    async fn already_reaped_process_yields_unknown() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        child.wait().unwrap(); // reap: pid is now gone from the process table
        let status = wait_for_exit(pid).await.unwrap();
        assert!(status.is_unknown(), "status: {status:?}");
    }

    /// An exited-but-unreaped child (zombie): FreeBSD lets `NOTE_EXIT` attach
    /// and fires it immediately with the real status.
    #[tokio::test]
    async fn zombie_attach_recovers_the_real_code() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        // Wait until the child is a zombie (exited, unreaped).
        loop {
            let stat = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            if String::from_utf8_lossy(&stat.stdout)
                .trim_start()
                .starts_with('Z')
            {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let status = wait_for_exit(pid).await.unwrap();
        assert_eq!(status.code, Some(7), "status: {status:?}");
        child.wait().unwrap(); // reap
    }
}
