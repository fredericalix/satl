// SPDX-License-Identifier: BSD-2-Clause
//! Log wiring: how one `satld` event becomes one line an operator can parse.
//!
//! Three properties are load-bearing, and each of them was a bug found by
//! reading `/var/log/messages` rather than by a test:
//!
//! - **One event, one line.** Two events must never share a line. In text mode
//!   that shows up as a second timestamp mid-line; in JSON mode as two objects
//!   on one line, which is not JSON, and `--log-format json` is advertised as
//!   machine-readable. There were two independent ways to get it wrong, and
//!   this module closes both:
//!
//!   1. **Downstream.** `daemon(8) -S` reads the daemon's pipe in chunks and
//!      hands a whole chunk to `syslog(3)` as one message; `syslogd` rewrites
//!      the embedded newlines as spaces. [`LogTarget::Syslog`] takes
//!      `daemon(8)` out of the path entirely — [`syslog`] has the measurement.
//!   2. **In this process.** An event is one `write_all`, but a write larger
//!      than `PIPE_BUF` (512 bytes on FreeBSD) is not atomic on a pipe, so two
//!      threads sharing an unlocked handle can splice their lines into each
//!      other. Measured with the test in this module against an unlocked
//!      writer: **14 of 3200 lines torn**, mid-word. [`Serialized`] is the
//!      answer, and it is applied where the two targets cannot diverge.
//!
//! - **No colour where nothing renders it.** ANSI escapes in
//!   `/var/log/messages` turn every line into noise like
//!   `^[[2m2026-…^[[0m ^[[32m INFO^[[0m`, so colour is enabled only when the
//!   stream the log is *actually written to* is a terminal. Testing one stream
//!   and writing to another is how escapes reach a redirected file.
//!
//! - **Plain ASCII.** `syslogd` is not 8-bit clean; see
//!   `crates/satl-core/tests/ascii_messages.rs` and `docs/operations.md`.

mod syslog;

use std::io::{self, IsTerminal as _};
use std::sync::{Mutex, MutexGuard, PoisonError};

use clap::ValueEnum;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::logging::syslog::SyslogWriter;

/// The syslog tag `satld` lines carry, matching the `-T satld` that
/// `daemon(8)` used to supply.
const SYSLOG_TAG: &str = "satld";

/// Log output format (`--log-format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// Where log lines go (`--log-target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogTarget {
    /// This process's standard output — a terminal in the foreground, and
    /// whatever the shell redirected it to otherwise.
    ///
    /// Stdout rather than stderr because `satld --log-format json | jq` is a
    /// documented way to read this daemon.
    Stdout,
    /// The local `syslogd`, one datagram per event.
    ///
    /// What the `rc.d` service uses. Letting `daemon(8) -S` forward stdout
    /// instead merges events onto one line and loses some outright; [`syslog`]
    /// documents the measurement.
    Syslog,
}

/// Installs the global log subscriber. Called once, before anything logs.
pub fn init(format: LogFormat, target: LogTarget, log_level: &str) {
    // RUST_LOG wins when set; otherwise --log-level; otherwise "info".
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let dispatch = match target {
        LogTarget::Stdout => {
            let ansi = io::stdout().is_terminal();
            stream_dispatch(format, filter, ansi, io::stdout())
        }
        // Nothing renders escapes on the way to a log file.
        LogTarget::Syslog => dispatch(format, filter, false, SyslogWriter::new(SYSLOG_TAG)),
    };

    // `try_init` rather than `set_global_default`: it also installs the
    // `log`-to-`tracing` bridge, which is the only reason records from
    // dependencies that log through the `log` crate (rustls) are seen at all.
    if let Err(error) = dispatch.try_init() {
        // There is no subscriber, so this cannot be a `tracing` event.
        eprintln!("satld: cannot install the log subscriber: {error}");
    }
}

/// A [`MakeWriter`] that lets one event finish before the next one starts.
///
/// `tracing-subscriber`'s `fmt` layer formats an event into a thread-local
/// buffer and writes it with a single `write_all`, which sounds atomic and is
/// not: `write_all` loops over partial writes, and a pipe accepts at most
/// `PIPE_BUF` (512) bytes atomically. Two threads writing 700-byte events
/// through unlocked handles interleave, and the result is one line with two
/// timestamps and a truncated span name in the middle of it.
///
/// `tracing-subscriber` ships a `MakeWriter` impl for `Mutex<W>` that would do
/// this, but it `expect`s on a poisoned lock — so one panic while formatting a
/// line would turn every later log call into a panic. For a daemon whose log
/// is the only diagnosis available, recovering the guard is strictly better:
/// the value behind it is a file handle with no invariant a panic could have
/// broken.
struct Serialized<W>(Mutex<W>);

/// The exclusive handle [`Serialized`] hands out for the duration of one event.
struct SerializedGuard<'a, W>(MutexGuard<'a, W>);

impl<'a, W> MakeWriter<'a> for Serialized<W>
where
    W: io::Write + 'a,
{
    type Writer = SerializedGuard<'a, W>;

    fn make_writer(&'a self) -> Self::Writer {
        SerializedGuard(self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl<W> io::Write for SerializedGuard<'_, W>
where
    W: io::Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// A subscriber writing to one shared byte stream, serialised per event.
///
/// The one place the [`Serialized`] wrapper is applied, so that the daemon's
/// stdout and the pipe the test writes into cannot get different treatment:
/// take the wrapper away here and the concurrency test in this module tears.
fn stream_dispatch<W>(
    format: LogFormat,
    filter: EnvFilter,
    ansi: bool,
    stream: W,
) -> tracing::Dispatch
where
    W: io::Write + Send + Sync + 'static,
{
    dispatch(format, filter, ansi, Serialized(Mutex::new(stream)))
}

/// Builds the subscriber for one format/writer pair.
///
/// Separate from [`init`] so that tests can point a real subscriber at a pipe
/// or a socket they own, and so the two formats cannot drift in how they are
/// configured.
fn dispatch<W>(format: LogFormat, filter: EnvFilter, ansi: bool, writer: W) -> tracing::Dispatch
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    match format {
        LogFormat::Text => tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(ansi)
                .with_writer(writer)
                .finish(),
        ),
        LogFormat::Json => tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_ansi(ansi)
                .with_writer(writer)
                .finish(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixDatagram;
    use std::path::Path;
    use std::time::Duration;

    /// Threads logging at once, and events each of them emits. Enough of both
    /// that events genuinely overlap: the corruption this guards against needs
    /// two events microseconds apart on two threads.
    const THREADS: usize = 8;
    const EVENTS_PER_THREAD: usize = 400;
    const EVENTS: usize = THREADS * EVENTS_PER_THREAD;

    /// A [`MakeWriter`] handing out an *unlocked* pipe handle — what the
    /// tearing looks like without [`Serialized`]. Used by one test, as the
    /// control that proves the others are not passing by accident.
    struct UnlockedPipe(io::PipeWriter);

    impl<'a> MakeWriter<'a> for UnlockedPipe {
        type Writer = &'a io::PipeWriter;

        fn make_writer(&'a self) -> Self::Writer {
            &self.0
        }
    }

    /// Emits [`EVENTS`] events from [`THREADS`] threads through `dispatch`.
    ///
    /// Line lengths are varied on purpose. `PIPE_BUF` is 512 bytes on FreeBSD,
    /// so only events past that size can tear — and the merges seen in the
    /// field ran from 642 to 1174 characters.
    fn emit_concurrently(dispatch: &tracing::Dispatch) {
        std::thread::scope(|scope| {
            for thread in 0..THREADS {
                scope.spawn(move || {
                    tracing::dispatcher::with_default(dispatch, || {
                        for seq in 0..EVENTS_PER_THREAD {
                            // 0, 256, 512, 768, 1024 bytes of payload.
                            let detail = "x".repeat(256 * (seq % 5));
                            tracing::info!(thread, seq, detail = %detail, "concurrent log line");
                        }
                    });
                });
            }
        });
    }

    /// Runs [`emit_concurrently`] into a pipe and returns everything that came
    /// out the other end.
    ///
    /// A pipe on purpose: it is the file descriptor a supervised daemon is
    /// given, and the only common destination whose writes are not atomic.
    fn drain_pipe(dispatch: impl FnOnce(io::PipeWriter) -> tracing::Dispatch) -> String {
        let (mut reader, writer) = io::pipe().expect("pipe");
        let dispatch = dispatch(writer);

        // The pipe buffer holds a few kilobytes; without a reader draining it
        // concurrently the writers would block forever.
        let collector = std::thread::spawn(move || {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).expect("read the pipe");
            out
        });

        emit_concurrently(&dispatch);
        // Drops the last handle on the write end, so the reader sees EOF.
        drop(dispatch);

        String::from_utf8(collector.join().expect("collector thread")).expect("utf-8 output")
    }

    /// The daemon's own stdout path, pointed at a pipe.
    fn serialized(
        format: LogFormat,
        ansi: bool,
    ) -> impl FnOnce(io::PipeWriter) -> tracing::Dispatch {
        move |writer| stream_dispatch(format, EnvFilter::new("info"), ansi, writer)
    }

    /// How many timestamps a line carries. Two means two events share it.
    fn timestamps(line: &str) -> usize {
        // The `2026-08-10T` part of the ISO-8601 stamp, which both the text and
        // the JSON formats start their events with.
        line.match_indices('T')
            .filter(|(at, _)| {
                let Some(date) = at.checked_sub(10).and_then(|from| line.get(from..*at)) else {
                    return false;
                };
                let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
                digits(&date[0..4])
                    && &date[4..5] == "-"
                    && digits(&date[5..7])
                    && &date[7..8] == "-"
                    && digits(&date[8..10])
            })
            .count()
    }

    /// Lines carrying anything other than exactly one timestamp, with the
    /// count of lines inspected.
    fn merged(output: &str) -> (Vec<&str>, usize) {
        let lines: Vec<&str> = output.lines().collect();
        let merged = lines
            .iter()
            .copied()
            .filter(|line| timestamps(line) != 1)
            .collect();
        (merged, lines.len())
    }

    /// The defect, in text mode: two events sharing a line, which reads as a
    /// second timestamp in the middle of it.
    #[test]
    fn text_mode_never_merges_two_events_onto_one_line() {
        let output = drain_pipe(serialized(LogFormat::Text, false));
        let (merged, lines) = merged(&output);
        assert!(
            merged.is_empty(),
            "{} of {lines} lines carry something other than exactly one \
             timestamp; first: {:?}",
            merged.len(),
            merged.first().map(|line| &line[..line.len().min(300)])
        );
        assert_eq!(lines, EVENTS, "every event must produce exactly one line");
    }

    /// The same defect in JSON mode, where it is worse: two objects on one line
    /// is not JSON, and `--log-format json` is documented as machine-readable.
    #[test]
    fn every_json_line_parses_as_json() {
        let output = drain_pipe(serialized(LogFormat::Json, false));
        let lines: Vec<&str> = output.lines().collect();
        let broken: Vec<&&str> = lines
            .iter()
            .filter(|line| serde_json::from_str::<serde_json::Value>(line).is_err())
            .collect();
        assert!(
            broken.is_empty(),
            "{} of {} lines are not valid JSON; first: {:?}",
            broken.len(),
            lines.len(),
            broken.first().map(|line| &line[..line.len().min(300)])
        );
        assert_eq!(lines.len(), EVENTS, "every event must produce one object");
    }

    /// The control. Without [`Serialized`] the very same load tears lines on
    /// the very same pipe — which is what makes the two tests above evidence
    /// that the wrapper is doing the work, rather than evidence that this load
    /// never interleaves.
    ///
    /// Interleaving is a race, so the assertion is one-sided: it demands that
    /// the *serialised* writer stay clean under a load that has been observed
    /// to tear (14 of 3200 lines), and only reports what the unlocked one did.
    #[test]
    fn an_unlocked_writer_is_what_serializing_protects_against() {
        let unlocked = drain_pipe(|writer| {
            dispatch(
                LogFormat::Text,
                EnvFilter::new("info"),
                false,
                UnlockedPipe(writer),
            )
        });
        let (torn, lines) = merged(&unlocked);
        println!(
            "unlocked writer: {} of {lines} lines carry more than one event",
            torn.len()
        );

        let serialized = drain_pipe(serialized(LogFormat::Text, false));
        let (merged, lines) = merged(&serialized);
        assert!(
            merged.is_empty(),
            "the serialised writer tore {} of {lines} lines",
            merged.len()
        );
    }

    /// Colour is a per-stream decision, and a log file is never a terminal. An
    /// earlier defect filled `/var/log/messages` with `^[[2m` noise.
    #[test]
    fn output_carries_no_ansi_escapes_and_no_non_ascii_bytes() {
        for format in [LogFormat::Text, LogFormat::Json] {
            let output = drain_pipe(serialized(format, false));
            assert!(
                !output.contains('\u{1b}'),
                "{format:?} output contains an ANSI escape"
            );
            assert!(
                output.is_ascii(),
                "{format:?} output contains a non-ASCII byte, which syslogd mangles"
            );
        }
    }

    /// And the escapes really are suppressed by that flag, rather than by a
    /// formatter that has lost its colour wiring — otherwise the test above
    /// would prove nothing.
    #[test]
    fn colour_is_what_the_ansi_flag_says_it_is() {
        assert!(
            drain_pipe(serialized(LogFormat::Text, true)).contains('\u{1b}'),
            "with_ansi(true) must colour text output; if it does not, the \
             with_ansi(false) test proves nothing"
        );
    }

    /// The production path, end to end: the real subscriber, the real syslog
    /// writer, one socket, eight threads — and exactly one datagram per event,
    /// none of them carrying a newline. That is the property `daemon(8) -S`
    /// violated, so it is the one worth pinning down.
    #[test]
    fn the_syslog_target_sends_one_datagram_per_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("log");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        receiver
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("read timeout");

        // Drain concurrently: the socket's receive buffer is far smaller than
        // this burst, and the writer answers a full buffer with backpressure.
        let collector = std::thread::spawn(move || {
            let mut datagrams = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(len) = receiver.recv(&mut buf) {
                datagrams.push(String::from_utf8_lossy(&buf[..len]).into_owned());
                if datagrams.len() == EVENTS {
                    break;
                }
            }
            datagrams
        });

        let writer = SyslogWriter::to_socket(SYSLOG_TAG, Path::new(&path));
        let dispatch = dispatch(LogFormat::Json, EnvFilter::new("info"), false, writer);
        emit_concurrently(&dispatch);
        drop(dispatch);

        let datagrams = collector.join().expect("collector thread");
        assert_eq!(
            datagrams.len(),
            EVENTS,
            "every event must arrive as its own datagram, and none may be lost"
        );
        for datagram in &datagrams {
            assert!(
                !datagram.contains('\n'),
                "a datagram must never carry a newline, or syslogd turns it \
                 into a space and merges two events onto one line: {datagram:?}"
            );
            let body = datagram
                .split_once("]: ")
                .map_or(datagram.as_str(), |(_, body)| body);
            assert!(
                serde_json::from_str::<serde_json::Value>(body).is_ok(),
                "the body of a datagram must be one JSON object: {body:?}"
            );
        }
    }
}
