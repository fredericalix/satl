// SPDX-License-Identifier: BSD-2-Clause
//! `GET /containers/{id}/logs`: reading (and following) a task's log files.
//!
//! The pinned M1 contract (architecture §8.2) is that a container's stdio is
//! inherited from two files opened at jail-create time:
//!
//! ```text
//! <state_dir>/logs/<task_id>/stdout.log
//! <state_dir>/logs/<task_id>/stderr.log
//! ```
//!
//! They hold **raw bytes** — no framing, no per-line timestamps, no log
//! driver. So:
//!
//! - `tail=N` is computed by counting newlines backwards from the end of the
//!   file ([`tail`]);
//! - `follow=1` polls both files for appends every [`POLL_INTERVAL`] and
//!   stops once the task has finished *and* the last append has been read;
//! - `timestamps=1` cannot recover when a line was written, so each line is
//!   stamped with the time SatL read it, and lines are emitted one frame each
//!   so the API layer's per-frame timestamp lands where Docker puts it. A
//!   deviation, recorded in `docs/api-compat.md`;
//! - `since=` cannot be honoured for the same reason and is ignored.
//!
//! A missing file is an empty stream, not an error: a container that was
//! created but never started has no logs yet.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt as _};
use satl_api::model::{LogFrame, LogOptions, LogStream};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

/// How often a followed log file is polled for appends.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Most bytes read from one file in one round, so a runaway container cannot
/// make the daemon allocate without bound.
const MAX_READ: u64 = 8 * 1024 * 1024;

/// The last `lines` lines of `data`.
///
/// A trailing newline terminates the last line rather than starting an empty
/// one, so `tail(b"a\nb\n", 1) == b"b\n"`. Asking for more lines than there
/// are returns everything.
#[must_use]
pub fn tail(data: &[u8], lines: u64) -> &[u8] {
    if lines == 0 {
        return &[];
    }
    if data.is_empty() {
        return data;
    }
    let search_end = if data.ends_with(b"\n") {
        data.len() - 1
    } else {
        data.len()
    };
    let mut seen = 0u64;
    for index in (0..search_end).rev() {
        if data[index] == b'\n' {
            seen += 1;
            if seen == lines {
                return &data[index + 1..];
            }
        }
    }
    data
}

/// Split `data` into one payload per complete line, returning the trailing
/// partial line (if any) for the next round.
fn split_lines(data: &[u8]) -> (Vec<Bytes>, Vec<u8>) {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in data.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(Bytes::copy_from_slice(&data[start..=index]));
            start = index + 1;
        }
    }
    (lines, data[start..].to_vec())
}

/// One followed file.
struct Tail {
    path: PathBuf,
    stream: LogStream,
    offset: u64,
    partial: Vec<u8>,
}

impl Tail {
    /// Read whatever has been appended since the last round.
    ///
    /// A missing file, or one that shrank (the task was removed and
    /// recreated), resets the cursor instead of failing.
    async fn read(&mut self) -> Vec<u8> {
        let mut file = match tokio::fs::File::open(&self.path).await {
            Ok(file) => file,
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(path = %self.path.display(), error = %err, "cannot open log file");
                }
                return Vec::new();
            }
        };
        let len = match file.metadata().await {
            Ok(meta) => meta.len(),
            Err(err) => {
                tracing::debug!(path = %self.path.display(), error = %err, "cannot stat log file");
                return Vec::new();
            }
        };
        if len < self.offset {
            self.offset = 0;
            self.partial.clear();
        }
        if len == self.offset {
            return Vec::new();
        }
        let take = (len - self.offset).min(MAX_READ);
        if file
            .seek(std::io::SeekFrom::Start(self.offset))
            .await
            .is_err()
        {
            return Vec::new();
        }
        let mut buffer = vec![0u8; usize::try_from(take).unwrap_or(usize::MAX)];
        match file.read_exact(&mut buffer).await {
            Ok(read) => {
                buffer.truncate(read);
                self.offset += take;
                buffer
            }
            Err(err) => {
                tracing::debug!(path = %self.path.display(), error = %err, "cannot read log file");
                Vec::new()
            }
        }
    }
}

/// Everything one log stream needs between polls.
struct Follower {
    tails: Vec<Tail>,
    options: LogOptions,
    /// Whether the task this stream belongs to has stopped producing output.
    finished: Arc<dyn Fn() -> bool + Send + Sync>,
    pending: VecDeque<LogFrame>,
    /// Set once `finished()` was observed; one more read round runs after it
    /// so the container's final output is never truncated.
    draining: bool,
    done: bool,
    first: bool,
}

impl Follower {
    /// Turn a chunk into frames, honouring the per-line split that
    /// `timestamps=1` needs.
    fn push_frames(&mut self, index: usize, chunk: Vec<u8>) {
        if chunk.is_empty() {
            return;
        }
        let stream = self.tails[index].stream;
        let now = SystemTime::now();
        if !self.options.timestamps {
            self.pending.push_back(LogFrame {
                stream,
                timestamp: now,
                data: Bytes::from(chunk),
            });
            return;
        }
        let mut buffer = std::mem::take(&mut self.tails[index].partial);
        buffer.extend_from_slice(&chunk);
        let (lines, partial) = split_lines(&buffer);
        for data in lines {
            self.pending.push_back(LogFrame {
                stream,
                timestamp: now,
                data,
            });
        }
        // A partial line is only held back while more may still arrive.
        if self.options.follow && !self.draining {
            self.tails[index].partial = partial;
        } else if !partial.is_empty() {
            self.pending.push_back(LogFrame {
                stream,
                timestamp: now,
                data: Bytes::from(partial),
            });
        }
    }

    /// One read round over every followed file.
    async fn round(&mut self) {
        for index in 0..self.tails.len() {
            let chunk = self.tails[index].read().await;
            if self.first
                && !chunk.is_empty()
                && let Some(lines) = self.options.tail
            {
                let trimmed = tail(&chunk, lines).to_vec();
                self.push_frames(index, trimmed);
                continue;
            }
            self.push_frames(index, chunk);
        }
        self.first = false;
    }

    /// Produce the next frame, polling until one appears or the stream ends.
    async fn next(&mut self) -> Option<LogFrame> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Some(frame);
            }
            if self.done {
                return None;
            }
            self.round().await;
            if !self.pending.is_empty() {
                continue;
            }
            if !self.options.follow || self.draining {
                self.done = true;
                continue;
            }
            if (self.finished)() {
                // The task stopped: one final round, then end the stream.
                self.draining = true;
                continue;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

/// Stream the logs in `dir` according to `options`.
///
/// `finished` reports whether the task has reached a terminal state; a
/// followed stream ends after the first round that sees it true, so
/// `docker logs -f` returns when the container exits, as Docker does.
pub fn stream(
    dir: &std::path::Path,
    options: LogOptions,
    finished: Arc<dyn Fn() -> bool + Send + Sync>,
) -> BoxStream<'static, LogFrame> {
    let mut tails = Vec::new();
    if options.stdout {
        tails.push(Tail {
            path: dir.join("stdout.log"),
            stream: LogStream::Stdout,
            offset: 0,
            partial: Vec::new(),
        });
    }
    if options.stderr {
        tails.push(Tail {
            path: dir.join("stderr.log"),
            stream: LogStream::Stderr,
            offset: 0,
            partial: Vec::new(),
        });
    }
    let follower = Follower {
        tails,
        options,
        finished,
        pending: VecDeque::new(),
        draining: false,
        done: false,
        first: true,
    };
    futures_util::stream::unfold(follower, |mut follower| async move {
        follower.next().await.map(|frame| (frame, follower))
    })
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_counts_lines_from_the_end() {
        let data = b"one\ntwo\nthree\n";
        assert_eq!(tail(data, 1), b"three\n");
        assert_eq!(tail(data, 2), b"two\nthree\n");
        assert_eq!(tail(data, 3), &data[..]);
        assert_eq!(tail(data, 99), &data[..]);
        assert_eq!(tail(data, 0), b"");
    }

    #[test]
    fn tail_handles_a_missing_trailing_newline() {
        let data = b"one\ntwo";
        assert_eq!(tail(data, 1), b"two");
        assert_eq!(tail(data, 2), &data[..]);
        assert_eq!(tail(b"", 5), b"");
        assert_eq!(tail(b"single", 1), b"single");
    }

    #[test]
    fn split_lines_keeps_the_terminator_and_returns_the_remainder() {
        let (lines, partial) = split_lines(b"a\nb\nc");
        assert_eq!(
            lines,
            vec![Bytes::from_static(b"a\n"), Bytes::from_static(b"b\n")]
        );
        assert_eq!(partial, b"c");

        let (lines, partial) = split_lines(b"a\n");
        assert_eq!(lines.len(), 1);
        assert!(partial.is_empty());
    }

    fn options(edit: impl FnOnce(&mut LogOptions)) -> LogOptions {
        let mut options = LogOptions::default();
        edit(&mut options);
        options
    }

    async fn collect(dir: &std::path::Path, options: LogOptions) -> Vec<LogFrame> {
        stream(dir, options, Arc::new(|| true)).collect().await
    }

    #[tokio::test]
    async fn a_missing_log_directory_is_an_empty_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let frames = collect(&dir.path().join("nope"), LogOptions::default()).await;
        assert!(frames.is_empty());
    }

    #[tokio::test]
    async fn both_streams_are_read_and_tagged() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("stdout.log"), b"out\n").expect("write");
        std::fs::write(dir.path().join("stderr.log"), b"err\n").expect("write");

        let frames = collect(dir.path(), LogOptions::default()).await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream, LogStream::Stdout);
        assert_eq!(&frames[0].data[..], b"out\n");
        assert_eq!(frames[1].stream, LogStream::Stderr);
        assert_eq!(&frames[1].data[..], b"err\n");

        // Only stderr requested.
        let frames = collect(dir.path(), options(|o| o.stdout = false)).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].stream, LogStream::Stderr);
    }

    #[tokio::test]
    async fn tail_applies_to_the_first_read_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("stdout.log"), b"1\n2\n3\n4\n").expect("write");
        let frames = collect(
            dir.path(),
            options(|o| {
                o.stderr = false;
                o.tail = Some(2);
            }),
        )
        .await;
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0].data[..], b"3\n4\n");
    }

    #[tokio::test]
    async fn timestamps_split_the_payload_into_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("stdout.log"), b"a\nb\nc").expect("write");
        let frames = collect(
            dir.path(),
            options(|o| {
                o.stderr = false;
                o.timestamps = true;
            }),
        )
        .await;
        let payloads: Vec<&[u8]> = frames.iter().map(|frame| &frame.data[..]).collect();
        assert_eq!(payloads, vec![&b"a\n"[..], &b"b\n"[..], &b"c"[..]]);
    }

    #[tokio::test]
    async fn following_stops_once_the_task_finished_and_picks_up_appends() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stdout.log");
        std::fs::write(&path, b"first\n").expect("write");

        // "Finished" flips to true only after the appended line exists, so
        // the follower must do at least two rounds.
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_flag = Arc::clone(&flag);
        let writer_path = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(POLL_INTERVAL * 2).await;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&writer_path)
                .expect("append");
            std::io::Write::write_all(&mut file, b"second\n").expect("write");
            writer_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let finished = Arc::new(move || flag.load(std::sync::atomic::Ordering::SeqCst));
        let frames: Vec<LogFrame> = stream(
            dir.path(),
            options(|o| {
                o.stderr = false;
                o.follow = true;
            }),
            finished,
        )
        .collect()
        .await;
        let joined: Vec<u8> = frames.iter().flat_map(|f| f.data.to_vec()).collect();
        assert_eq!(joined, b"first\nsecond\n");
    }
}
