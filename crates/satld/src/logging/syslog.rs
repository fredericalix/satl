// SPDX-License-Identifier: BSD-2-Clause
//! A [`MakeWriter`] that hands every formatted event to `syslogd` as its own
//! datagram on `/var/run/log`.
//!
//! # Why this exists
//!
//! The obvious way to get `satld`'s log into `/var/log/messages` is the one
//! `rc.d` used first: let the daemon write lines to stdout and let `daemon(8)
//! -S` forward them to syslog. That path **merges events**. `daemon(8)` reads
//! the child's pipe in chunks, and a chunk that happens to contain several
//! complete lines is handed to `syslog(3)` as *one* message with embedded
//! newlines; `syslogd`'s `printline()` then rewrites every control character it
//! finds, and a newline becomes a **space**. Two events written microseconds
//! apart by two threads therefore arrive as a single line of
//! `/var/log/messages` joined by a space — invalid JSON under
//! `--log-format json`, and a second timestamp in the middle of a text line.
//!
//! Measured on this platform (FreeBSD 15.1, `hack/experiments/log-merge/`):
//! 400 lines emitted as fast as a shell can `echo` them, through
//! `daemon -S`, produced 138 syslog lines carrying 174 records — up to **19
//! records on one line**, and **more than half of the records lost entirely**,
//! because merging inflates each datagram until it overruns `syslogd`'s
//! receive buffer. The same 400 lines through `logger(1)`, which calls
//! `syslog(3)` once per line, produced 400 lines and lost none.
//!
//! So the fix is to be `logger(1)`: one event, one datagram, one line. There
//! is no `daemon(8)` flag that asks for per-line forwarding — the batching is
//! in its reader — so the split has to happen here, on the writing side.
//!
//! # What it costs
//!
//! `syslogd`'s receive buffer is 16 KiB and its socket is not flow-controlled:
//! a `send` that does not fit returns `ENOBUFS` rather than blocking. Dropping
//! the event there would trade corruption for silent loss, so instead the send
//! is **retried** — spinning first, then in 500 µs sleeps — for up to
//! [`ENOBUFS_BUDGET`]. This is what `syslog(3)` itself does, and it means a
//! saturated `syslogd` applies backpressure to whichever thread is logging
//! instead of losing the line. That is not a new hazard: writing to a full
//! pipe blocked the same thread just as hard. Past the budget the line is
//! written to stderr, where `daemon(8) -S` still picks it up — degraded (that
//! path can merge) but never dropped.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tracing_subscriber::fmt::MakeWriter;

/// The local `syslogd` datagram socket.
const LOG_SOCKET: &str = "/var/run/log";

/// The syslog `<PRI>` every line carries: facility `LOG_DAEMON` (3) times 8,
/// plus severity `LOG_NOTICE` (5).
///
/// A single constant priority for every event, deliberately. It is what
/// `daemon(8) -S` used before this writer existed, so the routing stays
/// identical: the stock `/etc/syslog.conf` sends `*.notice` to
/// `/var/log/messages` and `daemon.info` to `/var/log/daemon.log`, and every
/// `satld` line lands in both whatever its tracing level. Mapping tracing
/// levels onto syslog severities would look tidier and would quietly move
/// every `INFO` and `DEBUG` line *out* of `/var/log/messages`, which is the
/// one file the operations guide tells an operator to read.
const PRIORITY: u8 = 3 * 8 + 5;

/// `ENOBUFS` as FreeBSD numbers it (`errno.h`).
///
/// Rust's [`io::ErrorKind`] has no variant for it — the error arrives as
/// `Uncategorized` — so the raw number is the only way to tell "`syslogd`'s
/// receive buffer is full, try again" apart from a socket that has really
/// failed. Observed as `os error 55` while measuring the burst behaviour
/// described above.
const ENOBUFS: i32 = 55;

/// How long one event's datagram is retried while `syslogd`'s receive buffer
/// is full before the writer gives up and falls back to stderr.
///
/// Long enough that no realistic burst reaches it (6000 datagrams from 8
/// threads at once needed 1332 retries and no fallback), short enough that a
/// wedged `syslogd` cannot stall the daemon indefinitely.
const ENOBUFS_BUDGET: Duration = Duration::from_secs(2);

/// How many `ENOBUFS` retries spin before the writer starts sleeping. A
/// contended buffer usually drains within a scheduler slice, and yielding is
/// cheaper than a timer.
const SPINS_BEFORE_SLEEPING: u32 = 8;

/// Sleep between `ENOBUFS` retries once spinning has not helped.
const RETRY_SLEEP: Duration = Duration::from_micros(500);

/// Writes each formatted event to `syslogd` as one datagram.
#[derive(Debug)]
pub struct SyslogWriter {
    /// `<PRI>tag[pid]: ` — everything before the event's own text. Built once:
    /// it is identical for every line, and it is what makes the result
    /// indistinguishable from what `daemon(8) -S -T satld` used to produce.
    prefix: String,
    /// The socket path, kept for reconnecting.
    path: PathBuf,
    /// The connected socket, absent until the first send and after a failure.
    ///
    /// A `Mutex` rather than a bare socket because a failed send has to
    /// *replace* it: `syslogd` unlinks and re-binds `/var/run/log` when it
    /// restarts, which leaves this socket connected to an inode nobody reads.
    socket: Mutex<Option<UnixDatagram>>,
    /// Whether the "syslog is unreachable" note has already been printed, so
    /// a broken socket does not also flood stderr.
    warned: AtomicBool,
}

impl SyslogWriter {
    /// A writer that tags its lines `tag[pid]` and sends them to the local
    /// `syslogd`.
    ///
    /// Nothing is connected yet — an unreachable `syslogd` must not stop the
    /// daemon from starting, and the socket is established (and re-established)
    /// on demand.
    pub fn new(tag: &str) -> Self {
        Self::to_socket(tag, Path::new(LOG_SOCKET))
    }

    /// The same writer pointed at an arbitrary socket path, for the tests in
    /// this module and in its parent.
    pub(super) fn to_socket(tag: &str, path: &Path) -> Self {
        Self {
            prefix: format!("<{PRIORITY}>{tag}[{}]: ", std::process::id()),
            path: path.to_path_buf(),
            socket: Mutex::new(None),
            warned: AtomicBool::new(false),
        }
    }

    /// The socket slot, recovering a poisoned lock: a panic while sending a log
    /// line must not silence the log for the rest of the process's life. The
    /// value behind it is an `Option<UnixDatagram>` with no invariant a panic
    /// could have broken.
    fn slot(&self) -> MutexGuard<'_, Option<UnixDatagram>> {
        self.socket.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends one line as one datagram, falling back to stderr if syslog cannot
    /// take it.
    ///
    /// `line` must not contain a newline — that is the entire point of this
    /// writer — which [`SyslogWriter::write`] guarantees by splitting first.
    fn emit(&self, line: &[u8]) {
        let mut message = Vec::with_capacity(self.prefix.len() + line.len());
        message.extend_from_slice(self.prefix.as_bytes());
        message.extend_from_slice(line);
        let Err(error) = self.send(&message) else {
            return;
        };
        // Never `tracing::warn!` from in here: this *is* the writer that
        // warning would be written through.
        if !self.warned.swap(true, Ordering::Relaxed) {
            eprintln!(
                "satld: cannot write the log to syslog on {}: {error}. \
                 Falling back to stderr, where daemon(8) -S may merge lines.",
                self.path.display()
            );
        }
        let mut fallback = Vec::with_capacity(line.len() + 1);
        fallback.extend_from_slice(line);
        fallback.push(b'\n');
        let _ = io::Write::write_all(&mut io::stderr(), &fallback);
    }

    /// Sends one datagram, reconnecting once if the socket has gone stale.
    fn send(&self, message: &[u8]) -> io::Result<()> {
        let mut slot = self.slot();
        let mut connected = false;
        loop {
            let socket = if let Some(socket) = slot.take() {
                socket
            } else {
                connected = true;
                connect(&self.path)?
            };
            match send_persistently(&socket, message) {
                Ok(()) => {
                    *slot = Some(socket);
                    return Ok(());
                }
                // The socket is dropped here, which closes it; the next pass
                // connects a fresh one. Only worth one retry: a socket this
                // send just created and that still failed is not stale, it is
                // broken.
                Err(error) if connected => return Err(error),
                Err(_) => {}
            }
        }
    }
}

/// Connects a datagram socket to `path`.
fn connect(path: &Path) -> io::Result<UnixDatagram> {
    let socket = UnixDatagram::unbound()?;
    socket.connect(path)?;
    Ok(socket)
}

/// Sends `message`, retrying while `syslogd`'s receive buffer is full.
fn send_persistently(socket: &UnixDatagram, message: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + ENOBUFS_BUDGET;
    let mut retries: u32 = 0;
    loop {
        match socket.send(message) {
            Ok(_) => return Ok(()),
            Err(error) if is_full(&error) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                retries += 1;
                if retries < SPINS_BEFORE_SLEEPING {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(RETRY_SLEEP);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// Whether an error means "the receiver is behind", as opposed to a socket
/// that has actually failed.
fn is_full(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ENOBUFS) || error.kind() == io::ErrorKind::WouldBlock
}

impl io::Write for &SyslogWriter {
    /// One datagram per line in `buf`.
    ///
    /// `tracing-subscriber`'s `fmt` layer formats an event into a thread-local
    /// buffer and hands the whole thing over in a single `write_all`, so in
    /// practice this is called once per event with exactly one trailing
    /// newline. Splitting anyway costs nothing and makes the invariant
    /// structural: whatever arrives here, no datagram ever carries a newline,
    /// so no line of `/var/log/messages` can ever carry two events.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for line in buf.split(|byte| *byte == b'\n') {
            let line = match line.split_last() {
                Some((b'\r', head)) => head,
                _ => line,
            };
            if !line.is_empty() {
                self.emit(line);
            }
        }
        // A datagram is all-or-nothing and `emit` has already dealt with
        // failure; reporting a short write would only make `write_all` send
        // the tail of a line a second time.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SyslogWriter {
    type Writer = &'a SyslogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Receives datagrams on a temporary socket.
    struct Receiver {
        socket: UnixDatagram,
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl Receiver {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("log");
            let socket = UnixDatagram::bind(&path).expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            Self {
                socket,
                _dir: dir,
                path,
            }
        }

        fn writer(&self, tag: &str) -> SyslogWriter {
            SyslogWriter::to_socket(tag, &self.path)
        }

        /// Reads one datagram, or `None` on timeout.
        fn recv(&self) -> Option<String> {
            let mut buf = vec![0u8; 64 * 1024];
            match self.socket.recv(&mut buf) {
                Ok(len) => Some(String::from_utf8_lossy(&buf[..len]).into_owned()),
                Err(_) => None,
            }
        }
    }

    /// The wire framing: `<PRI>tag[pid]: message`, the same shape
    /// `daemon(8) -S -T satld` produced, so `/var/log/messages` looks
    /// unchanged.
    #[test]
    fn a_datagram_is_priority_tag_pid_and_the_line() {
        let receiver = Receiver::new();
        let writer = receiver.writer("satldtest");
        (&writer).write_all(b"hello operator\n").expect("write");

        let got = receiver.recv().expect("a datagram");
        assert_eq!(
            got,
            format!("<29>satldtest[{}]: hello operator", std::process::id()),
            "priority must be daemon.notice (29) and the tag must carry the pid"
        );
    }

    /// The property the `daemon(8)` path broke: whatever is handed to the
    /// writer, one datagram never carries two events. Even a single `write`
    /// call holding several lines is split.
    #[test]
    fn several_lines_in_one_write_become_several_datagrams() {
        let receiver = Receiver::new();
        let writer = receiver.writer("satldtest");
        (&writer)
            .write_all(b"first line\nsecond line\nthird line\n")
            .expect("write");

        for expected in ["first line", "second line", "third line"] {
            let got = receiver.recv().expect("a datagram");
            assert!(
                got.ends_with(expected),
                "expected a datagram ending in {expected:?}, got {got:?}"
            );
            assert!(
                !got.contains('\n'),
                "a datagram must never contain a newline: {got:?}"
            );
        }
    }

    /// Blank lines carry no event, and a newline-free tail is still delivered
    /// rather than swallowed.
    #[test]
    fn blank_lines_are_dropped_and_an_unterminated_tail_is_kept() {
        let receiver = Receiver::new();
        let writer = receiver.writer("satldtest");
        (&writer)
            .write_all(b"\n\nkept\n\nno newline")
            .expect("write");

        assert!(receiver.recv().expect("a datagram").ends_with("kept"));
        assert!(
            receiver.recv().expect("a datagram").ends_with("no newline"),
            "a line without a trailing newline must still be sent"
        );
    }

    /// An unreachable syslogd degrades to stderr instead of panicking or
    /// blocking: the daemon has to keep running, and `daemon(8) -S` still
    /// picks stderr up.
    #[test]
    fn an_unreachable_socket_does_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = SyslogWriter::to_socket("satldtest", &dir.path().join("absent"));
        (&writer)
            .write_all(b"nobody is listening\n")
            .expect("write must still report success");
        assert!(
            writer.warned.load(Ordering::Relaxed),
            "the fallback must be reported once"
        );
    }

    /// A `syslogd` restart unlinks and re-binds the socket, which leaves the
    /// writer connected to an inode nobody reads. The next event must
    /// reconnect rather than disappear.
    #[test]
    fn a_replaced_socket_is_reconnected() {
        let receiver = Receiver::new();
        let writer = receiver.writer("satldtest");
        (&writer).write_all(b"before restart\n").expect("write");
        assert!(
            receiver
                .recv()
                .expect("a datagram")
                .ends_with("before restart")
        );

        // Rebind the path the way a restarting syslogd does.
        drop(receiver.socket);
        std::fs::remove_file(&receiver.path).expect("unlink");
        let fresh = UnixDatagram::bind(&receiver.path).expect("rebind");
        fresh
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");

        (&writer).write_all(b"after restart\n").expect("write");
        let mut buf = vec![0u8; 64 * 1024];
        let len = fresh.recv(&mut buf).expect("a datagram after the restart");
        assert!(
            String::from_utf8_lossy(&buf[..len]).ends_with("after restart"),
            "the writer must reconnect after syslogd replaces the socket"
        );
        assert!(
            !writer.warned.load(Ordering::Relaxed),
            "a reconnect is not a degradation and must not warn"
        );
    }

    /// The whole hop, against the host's real `syslogd` and its real
    /// `/var/log/messages`: the part no unit test can stand in for, because the
    /// corruption happened *inside* `syslogd` — its `printline()` rewriting an
    /// embedded newline as a space — and because the routing to
    /// `/var/log/messages` depends on this writer's priority agreeing with
    /// `/etc/syslog.conf`.
    ///
    /// Emits sequence-numbered events from several threads at once, then reads
    /// the log back and demands every one of them, each alone on its line.
    /// A regression that puts two events in one datagram, or that moves this
    /// facility/severity out of `/var/log/messages`, fails here.
    #[test]
    #[ignore = "integration: writes to the host syslogd; run via `make integration`"]
    fn syslogd_writes_every_event_on_its_own_line_of_var_log_messages() {
        const MESSAGES: &str = "/var/log/messages";
        const THREADS: usize = 4;
        const PER_THREAD: usize = 150;
        const MARKER: &str = "SYSLOGLINETEST";

        // A tag of its own, so the check never has to tell its own lines apart
        // from a running daemon's.
        let tag = format!("satld-logtest-{}", std::process::id());
        let writer = SyslogWriter::new(&tag);
        let before = std::fs::metadata(MESSAGES)
            .expect("stat /var/log/messages")
            .len();

        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                let writer = &writer;
                scope.spawn(move || {
                    // Past PIPE_BUF and past a typical read chunk, which is
                    // where the old path merged.
                    let padding = "p".repeat(700);
                    let mut sink = writer;
                    for seq in 0..PER_THREAD {
                        let line =
                            format!("{MARKER} thread={thread} seq={seq} padding={padding}\n");
                        sink.write_all(line.as_bytes()).expect("write");
                    }
                });
            }
        });

        // And one write carrying two events, which is what the old path
        // effectively handed to `syslog(3)`. It has to come out as two lines:
        // syslogd rewrites an embedded newline as a space, so a writer that
        // forwards this verbatim produces exactly the corruption being guarded
        // against, in the one place where it can actually be observed.
        {
            let mut sink = &writer;
            sink.write_all(
                format!(
                    "{MARKER} thread=9 seq=0 pair=first\n{MARKER} thread=9 seq=1 pair=second\n"
                )
                .as_bytes(),
            )
            .expect("write");
        }

        // syslogd writes asynchronously; give it a moment to catch up.
        std::thread::sleep(Duration::from_secs(3));

        let log = std::fs::read(MESSAGES).expect("read /var/log/messages");
        let log = String::from_utf8_lossy(&log);
        let appended: Vec<&str> = log
            .get(usize::try_from(before).unwrap_or(0)..)
            .unwrap_or(&log)
            .lines()
            .filter(|line| line.contains(&tag))
            .collect();

        let merged: Vec<&&str> = appended
            .iter()
            .filter(|line| line.matches(MARKER).count() != 1)
            .collect();
        assert!(
            merged.is_empty(),
            "{} of {} lines carry more than one event: {:?}",
            merged.len(),
            appended.len(),
            merged.first().map(|line| &line[..line.len().min(300)])
        );
        assert_eq!(
            appended.len(),
            THREADS * PER_THREAD + 2,
            "every event must reach /var/log/messages, on its own line \
             (a short count can also mean newsyslog rotated the file mid-test, \
             or that this writer's priority no longer routes there)"
        );
    }
}
