// SPDX-License-Identifier: BSD-2-Clause
//! Following a whole compose project's output, one prefixed stream.
//!
//! Possible only in the node-local world, and that is the whole reason it did
//! not exist before: logs are node-local (api-compat 81), so a project spread
//! over the cluster would need a log broker that SatL does not have. `satl
//! compose` pins every task to one node (api-compat 169), so every stream this
//! module opens goes to the daemon on the other end of the same unix socket.
//!
//! The shape is docker compose's: one line per line of output, prefixed with
//! `<service>-<slot>`, the prefixes padded to a common width and given a colour
//! each so two services are told apart at a glance. Colour is suppressed when
//! stdout is not a terminal, because a redirected log is read by `grep` more
//! often than by a person.
//!
//! **A partial line is not printed until it completes.** Interleaving happens
//! at line boundaries or not at all: two containers writing at once would
//! otherwise splice half of one line into the middle of another, and the result
//! is unreadable exactly when the output matters most. The cost is that a
//! prompt with no trailing newline is not shown until the stream ends, which is
//! what the flush at EOF is for.

use tokio::sync::mpsc;

use crate::client::{self, Host};
use crate::frames::FrameDecoder;
use crate::output::Streams;

/// One task's stream, and the prefix its lines carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// What the prefix reads, docker's `<service>-<slot>`.
    pub label: String,
    /// The container (task) id to read from.
    pub container: String,
}

/// What a follow asks the daemon for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Keep the streams open and print as output arrives.
    pub follow: bool,
    /// `tail` in docker's spelling: a count, or `all`.
    pub tail: String,
    /// Prefix each line with the daemon's timestamp.
    pub timestamps: bool,
}

/// Why a follow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Every stream reached EOF.
    Eof,
    /// The operator pressed Ctrl-C.
    Interrupted,
}

/// The eight colours a prefix cycles through, as SGR parameters.
///
/// Bright foregrounds only: they read on both a light and a dark terminal,
/// where the dim ones vanish on one of the two. Black and white are left out
/// for the same reason.
const COLOURS: [u8; 6] = [36, 33, 32, 35, 34, 31];

/// One decoded line on its way to the terminal.
struct Line {
    index: usize,
    stderr: bool,
    text: String,
}

/// Follow every source until EOF or Ctrl-C, writing prefixed lines in the
/// order they arrive.
///
/// # Errors
///
/// When a stream cannot be opened. A stream that *ends* is not an error: a
/// task that stops is an ordinary end of output, and with several sources the
/// others keep going.
pub async fn stream(
    host: &Host,
    sources: &[Source],
    options: &Options,
    streams: &mut Streams,
) -> anyhow::Result<Ending> {
    if sources.is_empty() {
        return Ok(Ending::Eof);
    }
    let width = sources
        .iter()
        .map(|source| source.label.chars().count())
        .max()
        .unwrap_or(0);
    let colour = streams.out_is_terminal();
    let (tx, mut rx) = mpsc::channel::<Line>(256);

    let mut readers = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        let path = crate::cmd::logs::logs_path(
            &source.container,
            options.follow,
            &options.tail,
            options.timestamps,
        );
        // Opened here rather than inside the task so that a source that cannot
        // be read at all is an error the operator sees, not a stream that
        // silently never produces a line.
        let body = client::stream(host, &hyper::Method::GET, &path, None).await?;
        let tx = tx.clone();
        readers.push(tokio::spawn(async move { pump(body, index, &tx).await }));
    }
    drop(tx);

    let ending = loop {
        tokio::select! {
            biased;
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    break Ending::Interrupted;
                }
            }
            line = rx.recv() => {
                let Some(line) = line else { break Ending::Eof };
                let rendered = render(&sources[line.index].label, width, line.index, colour);
                let payload = format!("{rendered}{}\n", line.text);
                if line.stderr {
                    streams.err(payload.as_bytes()).await;
                } else {
                    streams.out(payload.as_bytes()).await;
                }
            }
        }
    };
    for reader in readers {
        reader.abort();
    }
    Ok(ending)
}

/// The prefix one line carries, padded and optionally coloured.
fn render(label: &str, width: usize, index: usize, colour: bool) -> String {
    let pad = width.saturating_sub(label.chars().count());
    if colour {
        let sgr = COLOURS[index % COLOURS.len()];
        format!("\u{1b}[{sgr}m{label}\u{1b}[0m{:pad$} | ", "", pad = pad)
    } else {
        format!("{label}{:pad$} | ", "", pad = pad)
    }
}

/// Decode one container's frames into whole lines and send them on.
async fn pump(mut body: client::BodyStream, index: usize, tx: &mpsc::Sender<Line>) {
    let mut decoder = FrameDecoder::new();
    // One buffer per stream kind: stdout and stderr are separate line streams,
    // and a half-written stdout line must not swallow a stderr one.
    let mut pending = [String::new(), String::new()];
    while let Ok(Some(chunk)) = body.next_chunk().await {
        decoder.push(&chunk);
        while let Ok(Some(frame)) = decoder.next_frame() {
            let stderr = frame.stream.is_stderr();
            let slot = usize::from(stderr);
            pending[slot].push_str(&String::from_utf8_lossy(&frame.payload));
            while let Some(at) = pending[slot].find('\n') {
                let mut text: String = pending[slot].drain(..=at).collect();
                text.pop();
                if text.ends_with('\r') {
                    text.pop();
                }
                if tx
                    .send(Line {
                        index,
                        stderr,
                        text,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    // Whatever was written without a trailing newline: a prompt, or a line cut
    // short by the container dying. Dropping it would lose the last thing a
    // failing container said, which is usually the interesting one.
    for (slot, text) in pending.into_iter().enumerate() {
        if !text.is_empty() {
            let _ = tx
                .send(Line {
                    index,
                    stderr: slot == 1,
                    text,
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_padded_to_a_common_width_and_plain_without_a_terminal() {
        assert_eq!(render("web-1", 8, 0, false), "web-1    | ");
        assert_eq!(render("database-1", 10, 1, false), "database-1 | ");
    }

    #[test]
    fn a_terminal_gets_one_colour_per_source_and_the_padding_stays_outside_it() {
        let first = render("web-1", 5, 0, true);
        let second = render("db-1", 5, 1, true);
        assert!(first.starts_with("\u{1b}[36mweb-1\u{1b}[0m"), "{first}");
        assert!(second.starts_with("\u{1b}[33mdb-1\u{1b}[0m"), "{second}");
        // The reset comes before the padding, so a wide prefix does not paint
        // the gap and the columns line up whatever the colour.
        assert!(second.ends_with("\u{1b}[0m  | "), "{second:?}");
    }

    #[test]
    fn the_colour_cycle_wraps_rather_than_running_out() {
        let wrapped = render("x", 1, COLOURS.len(), true);
        let first = render("x", 1, 0, true);
        assert_eq!(wrapped, first);
    }
}
