// SPDX-License-Identifier: BSD-2-Clause
//! Docker multiplexed stream framing.
//!
//! Attached, non-tty container streams (`/containers/{id}/logs`, the hijacked
//! `/exec/{id}/start` duplex) are framed: an 8-byte header
//! `{stream: u8, 0, 0, 0, len: u32 big-endian}` followed by `len` payload
//! bytes. Frames are not aligned with the chunks the transport hands us, so
//! the decoder buffers and yields only complete frames.

use bytes::{Buf as _, Bytes, BytesMut};

/// Length of a frame header, in bytes.
pub const HEADER_LEN: usize = 8;

/// Which of the container's streams a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Stream 0 — only ever seen on the client-to-daemon direction.
    Stdin,
    /// Stream 1.
    Stdout,
    /// Stream 2.
    Stderr,
    /// Anything else; routed to stdout rather than dropped.
    Other(u8),
}

impl StreamKind {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Stdin,
            1 => Self::Stdout,
            2 => Self::Stderr,
            other => Self::Other(other),
        }
    }

    /// Frames of this kind belong on the process's stderr.
    pub fn is_stderr(self) -> bool {
        matches!(self, Self::Stderr)
    }
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Source stream.
    pub stream: StreamKind,
    /// Frame payload (may be empty).
    pub payload: Bytes,
}

/// Incremental decoder: feed it transport chunks, pull complete frames out.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    /// A decoder with an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a chunk as received from the transport.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pop the next complete frame, or `None` when more bytes are needed.
    ///
    /// A header whose three reserved bytes are non-zero means the daemon is
    /// not multiplexing (or we lost sync); that is an error rather than a
    /// silent mis-decode.
    pub fn next_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = &self.buf[..HEADER_LEN];
        if header[1] != 0 || header[2] != 0 || header[3] != 0 {
            anyhow::bail!(
                "invalid multiplexed frame header from the daemon: {}",
                hex(header)
            );
        }
        let stream = StreamKind::from_byte(header[0]);
        let mut len_bytes = [0_u8; 4];
        // Infallible: both slices are exactly 4 bytes long.
        len_bytes.copy_from_slice(&header[4..HEADER_LEN]);
        let Ok(len) = usize::try_from(u32::from_be_bytes(len_bytes)) else {
            anyhow::bail!("frame length does not fit in this platform's address space");
        };
        if self.buf.len() < HEADER_LEN + len {
            return Ok(None);
        }
        self.buf.advance(HEADER_LEN);
        let payload = self.buf.split_to(len).freeze();
        Ok(Some(Frame { stream, payload }))
    }

    /// Bytes buffered but not yet forming a complete frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame the way the daemon does, for goldens.
    fn frame(stream: u8, payload: &str) -> Vec<u8> {
        let mut out = vec![stream, 0, 0, 0];
        let len = u32::try_from(payload.len()).unwrap();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload.as_bytes());
        out
    }

    fn drain(decoder: &mut FrameDecoder) -> Vec<(StreamKind, String)> {
        let mut out = Vec::new();
        while let Some(frame) = decoder.next_frame().unwrap() {
            out.push((
                frame.stream,
                String::from_utf8(frame.payload.to_vec()).unwrap(),
            ));
        }
        out
    }

    #[test]
    fn decodes_a_single_frame() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&frame(1, "hello\n"));
        assert_eq!(
            drain(&mut decoder),
            vec![(StreamKind::Stdout, "hello\n".to_owned())]
        );
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn decodes_several_frames_from_one_chunk() {
        let mut chunk = frame(1, "out\n");
        chunk.extend_from_slice(&frame(2, "err\n"));
        chunk.extend_from_slice(&frame(1, "more\n"));
        let mut decoder = FrameDecoder::new();
        decoder.push(&chunk);
        assert_eq!(
            drain(&mut decoder),
            vec![
                (StreamKind::Stdout, "out\n".to_owned()),
                (StreamKind::Stderr, "err\n".to_owned()),
                (StreamKind::Stdout, "more\n".to_owned()),
            ]
        );
    }

    #[test]
    fn frame_split_across_chunks_is_reassembled() {
        let bytes = frame(2, "partial payload");
        let mut decoder = FrameDecoder::new();
        // Header split in the middle, then payload split again.
        decoder.push(&bytes[..3]);
        assert!(decoder.next_frame().unwrap().is_none());
        decoder.push(&bytes[3..9]);
        assert!(decoder.next_frame().unwrap().is_none());
        decoder.push(&bytes[9..]);
        assert_eq!(
            drain(&mut decoder),
            vec![(StreamKind::Stderr, "partial payload".to_owned())]
        );
    }

    #[test]
    fn byte_at_a_time_delivery_works() {
        let mut bytes = frame(1, "abc");
        bytes.extend_from_slice(&frame(2, "de"));
        let mut decoder = FrameDecoder::new();
        let mut got = Vec::new();
        for byte in bytes {
            decoder.push(&[byte]);
            got.extend(drain(&mut decoder));
        }
        assert_eq!(
            got,
            vec![
                (StreamKind::Stdout, "abc".to_owned()),
                (StreamKind::Stderr, "de".to_owned()),
            ]
        );
    }

    #[test]
    fn trailing_partial_frame_stays_buffered() {
        let complete = frame(1, "done\n");
        let partial = frame(1, "not yet");
        let mut decoder = FrameDecoder::new();
        decoder.push(&complete);
        decoder.push(&partial[..10]);
        assert_eq!(drain(&mut decoder).len(), 1);
        assert_eq!(decoder.pending(), 10);
    }

    #[test]
    fn empty_payload_frame_is_yielded() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&frame(1, ""));
        assert_eq!(
            drain(&mut decoder),
            vec![(StreamKind::Stdout, String::new())]
        );
    }

    #[test]
    fn unknown_stream_byte_is_kept_and_routed_to_stdout() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&frame(7, "odd"));
        let frame = decoder.next_frame().unwrap().unwrap();
        assert_eq!(frame.stream, StreamKind::Other(7));
        assert!(!frame.stream.is_stderr());
    }

    #[test]
    fn non_zero_reserved_bytes_are_rejected() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&[1, 0, 9, 0, 0, 0, 0, 1, b'x']);
        let err = decoder.next_frame().unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid multiplexed frame header from the daemon: 0100090000000001"),
            "{err}"
        );
    }

    #[test]
    fn large_length_waits_for_the_rest() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&[1, 0, 0, 0, 0, 1, 0, 0]); // 65536-byte payload announced
        decoder.push(&[b'x'; 128]);
        assert!(decoder.next_frame().unwrap().is_none());
        assert_eq!(decoder.pending(), HEADER_LEN + 128);
    }
}
