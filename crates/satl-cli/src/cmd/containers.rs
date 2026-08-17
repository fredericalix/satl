// SPDX-License-Identifier: BSD-2-Clause
//! `satl stop`, `satl kill`, `satl rm`, `satl wait`.
//!
//! All four take several containers, act on each one independently, echo the
//! reference the operator typed on success (docker's behavior — not the
//! resolved ID), report failures on stderr and exit 1 if any element failed.

use crate::api::WaitResponse;
use crate::client::{self, Host};
use crate::cmd::{self, FAILURE};
use crate::output::Streams;

/// Flags of `satl stop`.
#[derive(Debug, Clone, clap::Args)]
pub struct StopArgs {
    /// Seconds to wait before killing the container.
    #[arg(short = 't', long = "time", value_name = "SECONDS")]
    pub time: Option<u32>,

    /// Containers to stop.
    #[arg(required = true, value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// Flags of `satl kill`.
#[derive(Debug, Clone, clap::Args)]
pub struct KillArgs {
    /// Signal to send.
    #[arg(short, long, value_name = "SIGNAL")]
    pub signal: Option<String>,

    /// Containers to signal.
    #[arg(required = true, value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// Flags of `satl rm`.
#[derive(Debug, Clone, clap::Args)]
pub struct RmArgs {
    /// Force the removal of a running container.
    #[arg(short, long)]
    pub force: bool,

    /// Remove anonymous volumes associated with the container.
    #[arg(short = 'v', long = "volumes")]
    pub volumes: bool,

    /// Containers to remove.
    #[arg(required = true, value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// Flags of `satl wait`.
#[derive(Debug, Clone, clap::Args)]
pub struct WaitArgs {
    /// Containers to wait for.
    #[arg(required = true, value_name = "CONTAINER")]
    pub containers: Vec<String>,
}

/// `satl stop [-t N] CONTAINER...`
pub async fn stop(host: &Host, args: &StopArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let query = args
        .time
        .map(|seconds| client::query(&[("t", &seconds.to_string())]))
        .unwrap_or_default();
    for_each(&args.containers, streams, |container| {
        let path = format!("/containers/{container}/stop{query}");
        async move { client::post_empty_ok(host, &path).await }
    })
    .await
}

/// `satl kill [-s SIGNAL] CONTAINER...`
pub async fn kill(host: &Host, args: &KillArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let query = args
        .signal
        .as_deref()
        .map(|signal| client::query(&[("signal", signal)]))
        .unwrap_or_default();
    for_each(&args.containers, streams, |container| {
        let path = format!("/containers/{container}/kill{query}");
        async move { client::post_empty_ok(host, &path).await }
    })
    .await
}

/// `satl rm [-f] [-v] CONTAINER...`
pub async fn rm(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let query = client::query(&[
        ("force", if args.force { "true" } else { "false" }),
        ("v", if args.volumes { "true" } else { "false" }),
    ]);
    for_each(&args.containers, streams, |container| {
        let path = format!("/containers/{container}{query}");
        async move { client::delete_ok(host, &path).await }
    })
    .await
}

/// `satl wait CONTAINER...` — prints each exit code and exits with the last
/// one (SatL deviation from docker, which always exits 0 on success).
pub async fn wait(host: &Host, args: &WaitArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut status = 0_u8;
    let mut failed = false;
    for container in &args.containers {
        let path = format!("/containers/{container}/wait");
        match client::post_empty_json::<WaitResponse>(host, &path).await {
            Ok(response) => {
                if let Some(error) = &response.error
                    && !error.message.is_empty()
                {
                    streams
                        .error(&format!("Error response from daemon: {}", error.message))
                        .await;
                    failed = true;
                    continue;
                }
                streams.outln(&response.status_code.to_string()).await;
                status = cmd::exit_code(response.status_code);
            }
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { status })
}

/// Run `action` for every reference, echoing successes and collecting
/// failures. Returns 1 as soon as any element failed.
async fn for_each<'a, F, Fut>(
    containers: &'a [String],
    streams: &mut Streams,
    action: F,
) -> anyhow::Result<u8>
where
    F: Fn(&'a str) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut failed = false;
    for container in containers {
        match action(container).await {
            Ok(()) => streams.outln(container).await,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[tokio::test]
    async fn stop_echoes_the_references_and_sends_the_timeout() {
        let stub = Stub::start().await;
        stub.on("POST", "/containers/web/stop", Reply::empty(204))
            .on("POST", "/containers/db/stop", Reply::empty(204));

        let (mut streams, out, err) = testing::streams();
        let args = StopArgs {
            time: Some(5),
            containers: names(&["web", "db"]),
        };
        let code = stop(&stub.host(), &args, &mut streams).await.unwrap();

        assert_eq!(code, 0);
        assert_eq!(out.contents(), "web\ndb\n");
        assert!(err.contents().is_empty());
        assert_eq!(
            stub.first_call("POST /containers/web/stop").unwrap().query,
            "t=5"
        );
    }

    #[tokio::test]
    async fn a_failing_element_is_reported_and_the_rest_still_run() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/containers/gone/stop",
            Reply::json(404, r#"{"message":"No such container: gone"}"#),
        )
        .on("POST", "/containers/web/stop", Reply::empty(204));

        let (mut streams, out, err) = testing::streams();
        let args = StopArgs {
            time: None,
            containers: names(&["gone", "web"]),
        };
        let code = stop(&stub.host(), &args, &mut streams).await.unwrap();

        assert_eq!(code, FAILURE);
        assert_eq!(out.contents(), "web\n");
        assert_eq!(
            err.contents(),
            "Error response from daemon: No such container: gone\n"
        );
    }

    #[tokio::test]
    async fn kill_sends_the_signal() {
        let stub = Stub::start().await;
        stub.on("POST", "/containers/web/kill", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        let args = KillArgs {
            signal: Some("SIGHUP".to_owned()),
            containers: names(&["web"]),
        };
        assert_eq!(kill(&stub.host(), &args, &mut streams).await.unwrap(), 0);
        assert_eq!(out.contents(), "web\n");
        assert_eq!(
            stub.first_call("POST /containers/web/kill").unwrap().query,
            "signal=SIGHUP"
        );
    }

    #[tokio::test]
    async fn rm_passes_force_and_volumes() {
        let stub = Stub::start().await;
        stub.on("DELETE", "/containers/web", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        let args = RmArgs {
            force: true,
            volumes: true,
            containers: names(&["web"]),
        };
        assert_eq!(rm(&stub.host(), &args, &mut streams).await.unwrap(), 0);
        assert_eq!(out.contents(), "web\n");
        assert_eq!(
            stub.first_call("DELETE /containers/web").unwrap().query,
            "force=true&v=true"
        );
    }

    #[tokio::test]
    async fn wait_prints_every_code_and_exits_with_the_last() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/containers/web/wait",
            Reply::json(200, r#"{"StatusCode":0}"#),
        )
        .on(
            "POST",
            "/containers/db/wait",
            Reply::json(200, r#"{"StatusCode":137}"#),
        );

        let (mut streams, out, _err) = testing::streams();
        let args = WaitArgs {
            containers: names(&["web", "db"]),
        };
        let code = wait(&stub.host(), &args, &mut streams).await.unwrap();

        assert_eq!(code, 137);
        assert_eq!(out.contents(), "0\n137\n");
    }

    #[tokio::test]
    async fn wait_reports_a_daemon_side_wait_failure() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/containers/web/wait",
            Reply::json(
                200,
                r#"{"StatusCode":0,"Error":{"Message":"container removed"}}"#,
            ),
        );

        let (mut streams, out, err) = testing::streams();
        let args = WaitArgs {
            containers: names(&["web"]),
        };
        let code = wait(&stub.host(), &args, &mut streams).await.unwrap();

        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "Error response from daemon: container removed\n"
        );
    }
}
