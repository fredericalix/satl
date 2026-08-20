// SPDX-License-Identifier: BSD-2-Clause
//! `satl pull` — pull an image, rendering the daemon's JSON progress stream.
//!
//! Also used by `satl run` when the image is missing locally; the only
//! difference is that `run` sends the progress to stderr, as docker does, so
//! that stdout stays the container's.

use hyper::Method;

use crate::api::JsonMessage;
use crate::client::{self, Host};
use crate::ndjson::LineSplitter;
use crate::output::Streams;
use crate::parse::{self, ImageRef};

/// Flags of `satl pull`.
#[derive(Debug, Clone, clap::Args)]
pub struct PullArgs {
    /// Set platform if the image is multi-platform capable.
    #[arg(long, value_name = "PLATFORM")]
    pub platform: Option<String>,

    /// Image to pull.
    #[arg(value_name = "IMAGE")]
    pub image: String,
}

/// Which stream the progress goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `satl pull`: progress is the command's output.
    Stdout,
    /// `satl run`: progress is noise around the container's output.
    Stderr,
}

/// `satl pull IMAGE[:TAG]`.
pub async fn execute(host: &Host, args: &PullArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let reference = parse::parse_image_ref(&args.image)?;
    pull(
        host,
        &reference,
        args.platform.as_deref(),
        streams,
        Target::Stdout,
    )
    .await?;
    Ok(0)
}

/// `POST /images/create` and render every progress line until the stream ends.
pub async fn pull(
    host: &Host,
    reference: &ImageRef,
    platform: Option<&str>,
    streams: &mut Streams,
    target: Target,
) -> anyhow::Result<()> {
    let path = create_path(reference, platform);
    let mut body = client::stream(host, &Method::POST, &path, None).await?;
    let mut printer = ProgressPrinter::new(streams.out_is_terminal() && target == Target::Stdout);
    let mut lines = LineSplitter::default();
    while let Some(chunk) = body.next_chunk().await? {
        for line in lines.push(&chunk) {
            printer.emit(&line, streams, target).await?;
        }
    }
    if let Some(line) = lines.finish() {
        printer.emit(&line, streams, target).await?;
    }
    printer.close(streams, target).await;
    Ok(())
}

/// Build the `POST /images/create` URL.
pub fn create_path(reference: &ImageRef, platform: Option<&str>) -> String {
    let mut pairs = vec![
        ("fromImage", reference.name.as_str()),
        ("tag", &reference.tag),
    ];
    if let Some(platform) = platform {
        pairs.push(("platform", platform));
    }
    format!("/images/create{}", client::query(&pairs))
}

/// Renders progress messages. On a terminal, consecutive updates about the
/// same layer rewrite their line with `\r`; otherwise every message is a
/// plain line, which is what docker does when stdout is not a tty.
#[derive(Debug)]
struct ProgressPrinter {
    terminal: bool,
    open_id: Option<String>,
}

impl ProgressPrinter {
    fn new(terminal: bool) -> Self {
        Self {
            terminal,
            open_id: None,
        }
    }

    async fn emit(
        &mut self,
        line: &str,
        streams: &mut Streams,
        target: Target,
    ) -> anyhow::Result<()> {
        let message: JsonMessage = serde_json::from_str(line)
            .map_err(|err| anyhow::anyhow!("unreadable progress line from the daemon: {err}"))?;
        if let Some(error) = &message.error {
            anyhow::bail!("Error response from daemon: {error}");
        }
        let text = render_message(&message);
        if text.is_empty() {
            return Ok(());
        }
        let rewrite =
            self.terminal && !message.id.is_empty() && self.open_id.as_deref() == Some(&message.id);
        let payload = if rewrite {
            format!("\r\x1b[2K{text}")
        } else if self.open_id.is_some() {
            format!("\n{text}")
        } else {
            text
        };
        write(streams, target, payload.as_bytes()).await;
        if self.terminal && !message.id.is_empty() {
            self.open_id = Some(message.id.clone());
        } else {
            write(streams, target, b"\n").await;
            self.open_id = None;
        }
        Ok(())
    }

    async fn close(&mut self, streams: &mut Streams, target: Target) {
        if self.open_id.take().is_some() {
            write(streams, target, b"\n").await;
        }
    }
}

async fn write(streams: &mut Streams, target: Target, bytes: &[u8]) {
    match target {
        Target::Stdout => streams.out(bytes).await,
        Target::Stderr => streams.err(bytes).await,
    }
}

/// `id: status progress`, the way docker renders a `JSONMessage`.
fn render_message(message: &JsonMessage) -> String {
    let mut line = if message.id.is_empty() {
        message.status.clone()
    } else {
        format!("{}: {}", message.id, message.status)
    };
    if !message.progress.is_empty() {
        line.push(' ');
        line.push_str(&message.progress);
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;

    fn reference(image: &str) -> ImageRef {
        parse::parse_image_ref(image).unwrap()
    }

    #[test]
    fn create_url() {
        assert_eq!(
            create_path(&reference("nginx"), None),
            "/images/create?fromImage=nginx&tag=latest"
        );
        assert_eq!(
            create_path(
                &reference("127.0.0.1:5000/freebsd-nginx:v1"),
                Some("freebsd/amd64")
            ),
            "/images/create?fromImage=127.0.0.1%3A5000%2Ffreebsd-nginx&tag=v1&platform=freebsd%2Famd64"
        );
    }

    const STREAM: &[&str] = &[
        r#"{"status":"Pulling from library/freebsd-nginx","id":"v1"}"#,
        r#"{"status":"Pulling fs layer","progressDetail":{},"id":"a2abf6c4d29d"}"#,
        r#"{"status":"Downloading","progressDetail":{"current":539,"total":539},"progress":"[==================================================>]     539B/539B","id":"a2abf6c4d29d"}"#,
        r#"{"status":"Pull complete","id":"a2abf6c4d29d"}"#,
        r#"{"status":"Digest: sha256:0f0f0f0f"}"#,
        r#"{"status":"Status: Downloaded newer image for freebsd-nginx:v1"}"#,
    ];

    #[tokio::test]
    async fn non_terminal_output_is_one_line_per_message() {
        let (mut streams, out, _err) = testing::streams();
        let mut printer = ProgressPrinter::new(false);
        for line in STREAM {
            printer
                .emit(line, &mut streams, Target::Stdout)
                .await
                .unwrap();
        }
        printer.close(&mut streams, Target::Stdout).await;
        let expected = "\
v1: Pulling from library/freebsd-nginx
a2abf6c4d29d: Pulling fs layer
a2abf6c4d29d: Downloading [==================================================>]     539B/539B
a2abf6c4d29d: Pull complete
Digest: sha256:0f0f0f0f
Status: Downloaded newer image for freebsd-nginx:v1
";
        assert_eq!(out.contents(), expected);
    }

    #[tokio::test]
    async fn terminal_output_rewrites_the_line_of_the_current_layer() {
        let (mut streams, out, _err) = testing::streams();
        let mut printer = ProgressPrinter::new(true);
        for line in STREAM {
            printer
                .emit(line, &mut streams, Target::Stdout)
                .await
                .unwrap();
        }
        printer.close(&mut streams, Target::Stdout).await;
        let expected = concat!(
            "v1: Pulling from library/freebsd-nginx",
            "\na2abf6c4d29d: Pulling fs layer",
            "\r\x1b[2Ka2abf6c4d29d: Downloading [==================================================>]     539B/539B",
            "\r\x1b[2Ka2abf6c4d29d: Pull complete",
            "\nDigest: sha256:0f0f0f0f\n",
            "Status: Downloaded newer image for freebsd-nginx:v1\n",
        );
        assert_eq!(out.contents(), expected);
    }

    #[tokio::test]
    async fn run_sends_progress_to_stderr() {
        let (mut streams, out, err) = testing::streams();
        let mut printer = ProgressPrinter::new(false);
        printer
            .emit(STREAM[0], &mut streams, Target::Stderr)
            .await
            .unwrap();
        assert!(out.contents().is_empty());
        assert_eq!(err.contents(), "v1: Pulling from library/freebsd-nginx\n");
    }

    #[tokio::test]
    async fn pull_command_renders_the_whole_stream_on_stdout() {
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        let body = STREAM.join("\n").into_bytes();
        stub.on("POST", "/images/create", Reply::raw(200, body));

        let (mut streams, out, err) = testing::streams();
        let args = PullArgs {
            platform: Some("freebsd/amd64".to_owned()),
            image: "127.0.0.1:5000/freebsd-nginx:v1".to_owned(),
        };
        assert_eq!(execute(&stub.host(), &args, &mut streams).await.unwrap(), 0);

        assert!(err.contents().is_empty());
        let printed = out.contents();
        assert!(
            printed.starts_with("v1: Pulling from library/freebsd-nginx\n"),
            "{printed}"
        );
        assert!(
            printed.contains("a2abf6c4d29d: Pull complete\n"),
            "{printed}"
        );
        assert!(
            printed.ends_with("Status: Downloaded newer image for freebsd-nginx:v1\n"),
            "{printed}"
        );
        assert_eq!(
            stub.first_call("POST /images/create").unwrap().query,
            "fromImage=127.0.0.1%3A5000%2Ffreebsd-nginx&tag=v1&platform=freebsd%2Famd64"
        );
    }

    #[tokio::test]
    async fn pull_command_fails_on_an_error_in_the_stream() {
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/images/create",
            Reply::raw(
                200,
                concat!(
                    r#"{"status":"Pulling from library/nginx","id":"nope"}"#,
                    "\n",
                    r#"{"error":"manifest for nginx:nope not found","errorDetail":{"message":"manifest unknown"}}"#,
                    "\n",
                )
                .as_bytes()
                .to_vec(),
            ),
        );
        let (mut streams, _out, _err) = testing::streams();
        let args = PullArgs {
            platform: None,
            image: "nginx:nope".to_owned(),
        };
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Error response from daemon: manifest for nginx:nope not found"
        );
    }

    #[tokio::test]
    async fn an_error_message_fails_the_pull() {
        let (mut streams, _out, _err) = testing::streams();
        let mut printer = ProgressPrinter::new(false);
        let err = printer
            .emit(
                r#"{"error":"manifest for nginx:nope not found","errorDetail":{"message":"x"}}"#,
                &mut streams,
                Target::Stdout,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Error response from daemon: manifest for nginx:nope not found"
        );
    }
}
