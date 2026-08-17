// SPDX-License-Identifier: BSD-2-Clause
//! `satl logs` — fetch (and optionally follow) a container's output.
//!
//! Also home to the two frame pumps shared with `run` (log stream) and
//! `exec` (hijacked duplex).

use hyper::Method;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::client::{self, BodyStream, Host};
use crate::frames::FrameDecoder;
use crate::output::Streams;

/// Flags of `satl logs`.
#[derive(Debug, Clone, clap::Args)]
pub struct LogsArgs {
    /// Follow log output.
    #[arg(short, long)]
    pub follow: bool,

    /// Number of lines to show from the end of the logs.
    #[arg(long, default_value = "all", value_name = "N")]
    pub tail: String,

    /// Show timestamps.
    #[arg(short = 't', long)]
    pub timestamps: bool,

    /// Container to read from.
    #[arg(value_name = "CONTAINER")]
    pub container: String,
}

/// Stream a container's logs to stdout/stderr.
pub async fn execute(host: &Host, args: &LogsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let path = logs_path(&args.container, args.follow, &args.tail, args.timestamps);
    let body = client::stream(host, &Method::GET, &path, None).await?;
    pump_body(body, streams).await?;
    Ok(0)
}

/// Build the `/containers/{id}/logs` URL. Both streams are always requested:
/// the frame header tells them apart.
pub fn logs_path(container: &str, follow: bool, tail: &str, timestamps: bool) -> String {
    format!(
        "/containers/{container}/logs{}",
        client::query(&[
            ("follow", if follow { "1" } else { "0" }),
            ("stdout", "1"),
            ("stderr", "1"),
            ("tail", tail),
            ("timestamps", if timestamps { "1" } else { "0" }),
        ])
    )
}

/// Demultiplex a chunked response body onto the two streams.
pub async fn pump_body(mut body: BodyStream, streams: &mut Streams) -> anyhow::Result<()> {
    let mut decoder = FrameDecoder::new();
    while let Some(chunk) = body.next_chunk().await? {
        decoder.push(&chunk);
        drain(&mut decoder, streams).await?;
    }
    Ok(())
}

/// Demultiplex a raw reader (the hijacked exec duplex) onto the two streams.
pub async fn pump_reader<R>(reader: &mut R, streams: &mut Streams) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut decoder = FrameDecoder::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(|err| anyhow::anyhow!("reading the daemon stream failed: {err}"))?;
        if read == 0 {
            return Ok(());
        }
        decoder.push(&chunk[..read]);
        drain(&mut decoder, streams).await?;
    }
}

async fn drain(decoder: &mut FrameDecoder, streams: &mut Streams) -> anyhow::Result<()> {
    while let Some(frame) = decoder.next_frame()? {
        if frame.stream.is_stderr() {
            streams.err(&frame.payload).await;
        } else {
            streams.out(&frame.payload).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;

    #[test]
    fn query_is_docker_shaped() {
        assert_eq!(
            logs_path("web", true, "all", false),
            "/containers/web/logs?follow=1&stdout=1&stderr=1&tail=all&timestamps=0"
        );
        assert_eq!(
            logs_path("web", false, "10", true),
            "/containers/web/logs?follow=0&stdout=1&stderr=1&tail=10&timestamps=1"
        );
    }

    fn frame(stream: u8, payload: &str) -> Vec<u8> {
        let mut out = vec![stream, 0, 0, 0];
        let len = u32::try_from(payload.len()).unwrap();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload.as_bytes());
        out
    }

    #[tokio::test]
    async fn reader_pump_splits_streams() {
        let mut bytes = frame(1, "to stdout\n");
        bytes.extend_from_slice(&frame(2, "to stderr\n"));
        bytes.extend_from_slice(&frame(1, "more stdout\n"));
        let (mut streams, out, err) = testing::streams();
        let mut reader = std::io::Cursor::new(bytes);
        pump_reader(&mut reader, &mut streams).await.unwrap();
        assert_eq!(out.contents(), "to stdout\nmore stdout\n");
        assert_eq!(err.contents(), "to stderr\n");
    }

    #[tokio::test]
    async fn logs_command_demuxes_the_response_body() {
        use crate::stub::{Reply, Stub, frames};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/containers/web/logs",
            Reply::raw(200, frames(&[(1, "line one\n"), (2, "oops\n")])),
        );

        let (mut streams, out, err) = testing::streams();
        let args = LogsArgs {
            follow: true,
            tail: "20".to_owned(),
            timestamps: true,
            container: "web".to_owned(),
        };
        assert_eq!(execute(&stub.host(), &args, &mut streams).await.unwrap(), 0);
        assert_eq!(out.contents(), "line one\n");
        assert_eq!(err.contents(), "oops\n");
        assert_eq!(
            stub.first_call("GET /containers/web/logs").unwrap().query,
            "follow=1&stdout=1&stderr=1&tail=20&timestamps=1"
        );
    }

    #[tokio::test]
    async fn logs_command_surfaces_a_missing_container() {
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/containers/gone/logs",
            Reply::json(404, r#"{"message":"No such container: gone"}"#),
        );
        let (mut streams, _out, _err) = testing::streams();
        let args = LogsArgs {
            follow: false,
            tail: "all".to_owned(),
            timestamps: false,
            container: "gone".to_owned(),
        };
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Error response from daemon: No such container: gone"
        );
    }

    #[tokio::test]
    async fn reader_pump_reports_a_corrupt_header() {
        let (mut streams, _out, _err) = testing::streams();
        let mut reader = std::io::Cursor::new(vec![1, 1, 1, 1, 0, 0, 0, 1, b'x']);
        let err = pump_reader(&mut reader, &mut streams).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid multiplexed frame"),
            "{err}"
        );
    }
}
