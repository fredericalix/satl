// SPDX-License-Identifier: BSD-2-Clause
//! Docker's multiplexed stream framing, used by `GET
//! /containers/{id}/logs` and by the hijacked `POST /exec/{id}/start`.
//!
//! Every chunk of output is prefixed with an 8-byte header:
//!
//! ```text
//! byte 0     stream: 1 = stdout, 2 = stderr
//! bytes 1-3  zero padding
//! bytes 4-7  payload length, big-endian u32
//! ```
//!
//! Frames carry no delimiter of their own — a reader must consume exactly
//! `length` bytes and may see a frame split across TCP/chunk boundaries.
//! SatL never emits the un-framed ("raw") variant: containers are always
//! treated as non-TTY in M1 (`docs/api-compat.md`).

use bytes::{BufMut, Bytes, BytesMut};

use crate::backend::model::{LogFrame, LogStream};
use crate::timefmt;

/// Length of a multiplexed frame header.
pub const HEADER_LEN: usize = 8;

/// Content type of a multiplexed stream (Docker Engine API v1.42+).
pub const MULTIPLEXED_CONTENT_TYPE: &str = "application/vnd.docker.multiplexed-stream";

/// Content type of the hijacked exec stream (Docker's raw-stream upgrade;
/// the payload is still multiplexed because SatL never allocates a TTY).
pub const RAW_STREAM_CONTENT_TYPE: &str = "application/vnd.docker.raw-stream";

/// Frames one payload for `stream`, splitting payloads that exceed `u32::MAX`
/// (which cannot be expressed in a single header) into consecutive frames.
#[must_use]
pub fn encode(stream: LogStream, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(payload.len() + HEADER_LEN);
    let max = u32::MAX as usize;
    let mut rest = payload;
    loop {
        let take = rest.len().min(max);
        out.put_u8(stream.as_byte());
        out.put_bytes(0, 3);
        // `take <= u32::MAX` by construction.
        out.put_u32(u32::try_from(take).unwrap_or(u32::MAX));
        out.put_slice(&rest[..take]);
        rest = &rest[take..];
        if rest.is_empty() {
            break;
        }
    }
    out.freeze()
}

/// Frames one [`LogFrame`], prefixing the payload with an RFC 3339 nanosecond
/// timestamp and a space when `timestamps` is set — exactly as Docker does,
/// i.e. inside the frame, counted in its length.
#[must_use]
pub fn encode_log_frame(frame: &LogFrame, timestamps: bool) -> Bytes {
    if timestamps {
        let stamp = timefmt::rfc3339_nano(frame.timestamp);
        let mut payload = BytesMut::with_capacity(stamp.len() + 1 + frame.data.len());
        payload.put_slice(stamp.as_bytes());
        payload.put_u8(b' ');
        payload.put_slice(&frame.data);
        encode(frame.stream, &payload)
    } else {
        encode(frame.stream, &frame.data)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn header_is_stream_byte_padding_and_big_endian_length() {
        let framed = encode(LogStream::Stdout, b"hello\n");
        assert_eq!(
            framed.as_ref(),
            b"\x01\x00\x00\x00\x00\x00\x00\x06hello\n".as_slice()
        );

        let framed = encode(LogStream::Stderr, b"boom");
        assert_eq!(
            framed.as_ref(),
            b"\x02\x00\x00\x00\x00\x00\x00\x04boom".as_slice()
        );
    }

    #[test]
    fn empty_payload_still_produces_a_header() {
        assert_eq!(
            encode(LogStream::Stdout, b"").as_ref(),
            b"\x01\x00\x00\x00\x00\x00\x00\x00".as_slice()
        );
    }

    #[test]
    fn length_is_encoded_big_endian_over_four_bytes() {
        let payload = vec![b'x'; 0x0001_0203];
        let framed = encode(LogStream::Stdout, &payload);
        assert_eq!(&framed[..HEADER_LEN], b"\x01\x00\x00\x00\x00\x01\x02\x03");
        assert_eq!(framed.len(), HEADER_LEN + payload.len());
    }

    #[test]
    fn timestamps_are_prefixed_inside_the_payload() {
        let frame = LogFrame {
            stream: LogStream::Stdout,
            timestamp: UNIX_EPOCH + Duration::new(1_770_000_000, 123_456_789),
            data: Bytes::from_static(b"ready\n"),
        };
        assert_eq!(
            encode_log_frame(&frame, true).as_ref(),
            b"\x01\x00\x00\x00\x00\x00\x00\x25\
              2026-02-02T02:40:00.123456789Z ready\n"
                .as_slice()
        );
        assert_eq!(
            encode_log_frame(&frame, false).as_ref(),
            b"\x01\x00\x00\x00\x00\x00\x00\x06ready\n".as_slice()
        );
    }
}
