// SPDX-License-Identifier: BSD-2-Clause
//! The assignment stream's sequence chain (`proto/dispatcher.proto`,
//! SWK §13.4) — the part implementers get wrong.
//!
//! Every message carries `applies_to` (the state the sender assumed the
//! receiver was in) and `results_in` (the state after applying it). The agent
//! remembers the last `results_in` it applied. If an incoming `applies_to`
//! does not equal it, the agent **drops the stream and re-opens it** for a
//! fresh `COMPLETE` snapshot. It must not try to patch the gap: an
//! incremental diff is only meaningful against the exact state it was
//! computed from, and "close enough" here means a task started with a secret
//! the cluster has already rotated.
//!
//! The markers are **opaque**: compare for equality, never parse, never
//! order. The generator below happens to produce `<stream nonce>-<counter>`,
//! which makes logs readable and makes markers from two streams provably
//! distinct — but nothing outside this module may depend on that shape.

use satl_core::Id;

/// Mints the marker chain for one assignment stream.
///
/// The nonce makes markers unique per stream, so a message from a previous
/// stream that arrives late can never satisfy the current stream's chain.
#[derive(Debug)]
pub struct SequenceGenerator {
    nonce: String,
    counter: u64,
    current: String,
}

impl SequenceGenerator {
    /// A generator for a fresh stream, with a random nonce.
    #[must_use]
    pub fn new() -> Self {
        Self::with_nonce(Id::generate().as_str())
    }

    /// A generator with a caller-chosen nonce (tests, and readable logs).
    #[must_use]
    pub fn with_nonce(nonce: &str) -> Self {
        Self {
            nonce: nonce.to_owned(),
            counter: 0,
            current: String::new(),
        }
    }

    /// The marker the receiver is assumed to hold: the `applies_to` of the
    /// next message. Empty before the first `COMPLETE`.
    #[must_use]
    pub fn current(&self) -> &str {
        &self.current
    }

    /// Advances the chain and returns the new `results_in`.
    pub fn advance(&mut self) -> String {
        self.counter += 1;
        self.current = format!("{}-{}", self.nonce, self.counter);
        self.current.clone()
    }
}

impl Default for SequenceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// The two message kinds, decoded from the wire enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A full snapshot; resets the receiver's state.
    Complete,
    /// A diff against `applies_to`.
    Incremental,
}

/// The stream lost its place in the chain, or opened on the wrong kind of
/// message. Either way the agent re-opens the stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SequenceGap {
    /// The first message on a stream was not a `COMPLETE` snapshot.
    #[error(
        "the assignment stream opened with an incremental message (applies_to {applies_to:?}); \
         the first message must be a complete snapshot"
    )]
    NotSnapshotFirst {
        /// What the message claimed to apply to.
        applies_to: String,
    },

    /// An incremental message assumed a state this agent is not in.
    #[error(
        "assignment sequence gap: the manager sent a diff against {applies_to:?} but this agent \
         holds {held:?}; dropping the stream and re-syncing from a fresh snapshot"
    )]
    Gap {
        /// The marker the message applies to.
        applies_to: String,
        /// The marker the agent actually holds.
        held: String,
    },

    /// A `COMPLETE` snapshot arrived with a non-empty `applies_to`, or a
    /// message carried no `results_in`. Both are protocol violations.
    #[error("malformed assignment message: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },
}

/// The receiver's end of the chain.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    held: Option<String>,
}

impl SequenceTracker {
    /// A tracker for a stream that has received nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The marker this agent currently holds, if any.
    #[must_use]
    pub fn held(&self) -> Option<&str> {
        self.held.as_deref()
    }

    /// Validates one message against the chain and, on success, adopts its
    /// `results_in`.
    ///
    /// # Errors
    ///
    /// [`SequenceGap`] — the caller must drop the stream and re-open it. It
    /// must **not** apply the message.
    pub fn accept(
        &mut self,
        kind: MessageKind,
        applies_to: &str,
        results_in: &str,
    ) -> Result<(), SequenceGap> {
        if results_in.is_empty() {
            return Err(SequenceGap::Malformed {
                reason: "results_in is empty; the receiver would have no state to chain from",
            });
        }
        match kind {
            MessageKind::Complete => {
                if !applies_to.is_empty() {
                    return Err(SequenceGap::Malformed {
                        reason: "a complete snapshot must have an empty applies_to: it replaces \
                                 the receiver's state rather than building on it",
                    });
                }
            }
            MessageKind::Incremental => match self.held.as_deref() {
                None => {
                    return Err(SequenceGap::NotSnapshotFirst {
                        applies_to: applies_to.to_owned(),
                    });
                }
                Some(held) if held != applies_to => {
                    return Err(SequenceGap::Gap {
                        applies_to: applies_to.to_owned(),
                        held: held.to_owned(),
                    });
                }
                Some(_) => {}
            },
        }
        self.held = Some(results_in.to_owned());
        Ok(())
    }

    /// Forgets the chain — used when the stream is re-opened, so the next
    /// message must be a snapshot again.
    pub fn reset(&mut self) {
        self.held = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generator_chains_and_never_repeats() {
        let mut generator = SequenceGenerator::with_nonce("stream");
        assert_eq!(generator.current(), "", "nothing has been sent yet");
        let first = generator.advance();
        assert_eq!(first, "stream-1");
        assert_eq!(generator.current(), first);
        let second = generator.advance();
        assert_ne!(first, second);
        assert_eq!(generator.current(), second);
    }

    #[test]
    fn two_streams_never_produce_the_same_marker() {
        let mut a = SequenceGenerator::new();
        let mut b = SequenceGenerator::new();
        assert_ne!(a.advance(), b.advance());
    }

    #[test]
    fn the_happy_path_is_a_snapshot_then_diffs() {
        let mut generator = SequenceGenerator::with_nonce("s");
        let mut tracker = SequenceTracker::new();

        let applies_to = generator.current().to_owned();
        let results_in = generator.advance();
        tracker
            .accept(MessageKind::Complete, &applies_to, &results_in)
            .expect("snapshot");
        assert_eq!(tracker.held(), Some("s-1"));

        for _ in 0..5 {
            let applies_to = generator.current().to_owned();
            let results_in = generator.advance();
            tracker
                .accept(MessageKind::Incremental, &applies_to, &results_in)
                .expect("diff");
            assert_eq!(tracker.held(), Some(results_in.as_str()));
        }
    }

    #[test]
    fn a_stream_may_not_open_with_a_diff() {
        let mut tracker = SequenceTracker::new();
        let error = tracker
            .accept(MessageKind::Incremental, "s-1", "s-2")
            .expect_err("refused");
        assert!(matches!(error, SequenceGap::NotSnapshotFirst { .. }));
        assert_eq!(tracker.held(), None, "nothing was adopted");
    }

    #[test]
    fn a_missed_message_is_a_gap_and_the_tracker_does_not_advance() {
        let mut tracker = SequenceTracker::new();
        tracker
            .accept(MessageKind::Complete, "", "s-1")
            .expect("snapshot");
        // s-2 never arrived.
        let error = tracker
            .accept(MessageKind::Incremental, "s-2", "s-3")
            .expect_err("gap");
        assert_eq!(
            error,
            SequenceGap::Gap {
                applies_to: "s-2".to_owned(),
                held: "s-1".to_owned()
            }
        );
        assert_eq!(
            tracker.held(),
            Some("s-1"),
            "a gap must never advance the chain: the agent re-syncs instead"
        );
        let message = error.to_string();
        assert!(message.contains("re-syncing"), "{message}");
    }

    #[test]
    fn a_marker_from_another_stream_does_not_satisfy_this_one() {
        let mut tracker = SequenceTracker::new();
        tracker
            .accept(MessageKind::Complete, "", "alpha-1")
            .expect("snapshot");
        assert!(
            tracker
                .accept(MessageKind::Incremental, "beta-1", "beta-2")
                .is_err()
        );
    }

    #[test]
    fn a_snapshot_resets_the_chain_whenever_it_arrives() {
        let mut tracker = SequenceTracker::new();
        tracker
            .accept(MessageKind::Complete, "", "s-1")
            .expect("snapshot");
        tracker
            .accept(MessageKind::Incremental, "s-1", "s-2")
            .expect("diff");
        tracker
            .accept(MessageKind::Complete, "", "t-1")
            .expect("re-sync");
        assert_eq!(tracker.held(), Some("t-1"));
        tracker
            .accept(MessageKind::Incremental, "t-1", "t-2")
            .expect("diff on the new chain");
    }

    #[test]
    fn malformed_markers_are_refused() {
        let mut tracker = SequenceTracker::new();
        assert!(matches!(
            tracker.accept(MessageKind::Complete, "s-1", "s-2"),
            Err(SequenceGap::Malformed { .. })
        ));
        assert!(matches!(
            tracker.accept(MessageKind::Complete, "", ""),
            Err(SequenceGap::Malformed { .. })
        ));
    }

    #[test]
    fn reset_forces_the_next_message_to_be_a_snapshot() {
        let mut tracker = SequenceTracker::new();
        tracker
            .accept(MessageKind::Complete, "", "s-1")
            .expect("snapshot");
        tracker.reset();
        assert_eq!(tracker.held(), None);
        assert!(matches!(
            tracker.accept(MessageKind::Incremental, "s-1", "s-2"),
            Err(SequenceGap::NotSnapshotFirst { .. })
        ));
    }
}
