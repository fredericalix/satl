// SPDX-License-Identifier: BSD-2-Clause
//! `satl exec` — run a command in a running container.
//!
//! Two round trips plus a hijack: create the exec instance, `POST
//! /exec/{id}/start` with `Upgrade: tcp` and take the connection over, pump
//! the multiplexed frames, then read the exit code back from
//! `GET /exec/{id}/json`.

use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use crate::api::{ExecCreateBody, ExecCreateResponse, ExecInspect, ExecStartBody};
use crate::client::{self, Host};
use crate::cmd::{self, logs};
use crate::output::Streams;
use crate::parse;

/// How long to keep asking the daemon for a not-yet-final exit code.
const EXIT_CODE_POLLS: u32 = 40;
const EXIT_CODE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Flags of `satl exec`.
#[derive(Debug, Clone, clap::Args)]
pub struct ExecArgs {
    /// Keep STDIN open even if not attached.
    #[arg(short, long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (not supported yet).
    #[arg(short, long)]
    pub tty: bool,

    /// Set environment variables.
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Working directory inside the container.
    #[arg(short, long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// Username or UID.
    #[arg(short, long, value_name = "USER")]
    pub user: Option<String>,

    /// Container to run the command in.
    #[arg(value_name = "CONTAINER")]
    pub container: String,

    /// Command and arguments.
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<String>,
}

/// Run the command and exit with its exit code.
pub async fn execute(host: &Host, args: &ExecArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    if args.tty {
        anyhow::bail!(cmd::run::TTY_UNSUPPORTED);
    }
    let body = create_body(args, &lookup_env)?;

    let create_path = format!("/containers/{}/exec", args.container);
    let created: ExecCreateResponse = client::post_json(host, &create_path, Some(&body)).await?;
    if created.id.is_empty() {
        anyhow::bail!("the daemon did not return an exec instance ID");
    }

    let start_path = format!("/exec/{}/start", created.id);
    let hijacked = client::hijack(host, &start_path, &ExecStartBody::default()).await?;
    let (mut reader, writer) = tokio::io::split(hijacked);
    let stdin_task = args
        .interactive
        .then(|| tokio::spawn(forward_stdin(writer)));

    let pump = logs::pump_reader(&mut reader, streams).await;
    if let Some(task) = stdin_task {
        task.abort();
    }
    pump?;

    let status = exit_code(host, &created.id).await?;
    Ok(cmd::exit_code(status))
}

/// Build the exec body; `-t` is rejected before we get here, so `Tty` is
/// always false and both output streams are always attached.
fn create_body<F>(args: &ExecArgs, lookup: &F) -> anyhow::Result<ExecCreateBody>
where
    F: Fn(&str) -> Option<String>,
{
    let mut env = Vec::new();
    for value in &args.env {
        if let Some(resolved) = parse::parse_env(value, lookup)? {
            env.push(resolved);
        }
    }
    Ok(ExecCreateBody {
        attach_stdin: args.interactive,
        attach_stdout: true,
        attach_stderr: true,
        tty: false,
        env,
        working_dir: args.workdir.clone().unwrap_or_default(),
        user: args.user.clone().unwrap_or_default(),
        cmd: args.command.clone(),
    })
}

/// With `-i`, the hijacked connection carries our stdin verbatim (no framing
/// in this direction).
async fn forward_stdin<W>(mut writer: W)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut stdin = tokio::io::stdin();
    let _ = tokio::io::copy(&mut stdin, &mut writer).await;
    let _ = writer.flush().await;
}

/// The daemon may still be reaping the process when the stream closes; poll
/// until the exit code is final.
async fn exit_code(host: &Host, exec_id: &str) -> anyhow::Result<i64> {
    let path = format!("/exec/{exec_id}/json");
    for _ in 0..EXIT_CODE_POLLS {
        let inspect: ExecInspect = client::get_json(host, &path).await?;
        if !inspect.running
            && let Some(code) = inspect.exit_code
        {
            return Ok(code);
        }
        tokio::time::sleep(EXIT_CODE_POLL_INTERVAL).await;
    }
    anyhow::bail!("the daemon never reported an exit code for exec {exec_id}")
}

fn lookup_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(command: &[&str]) -> ExecArgs {
        ExecArgs {
            interactive: false,
            tty: false,
            env: Vec::new(),
            workdir: None,
            user: None,
            container: "web".to_owned(),
            command: command.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    #[test]
    fn body_attaches_both_output_streams_and_never_a_tty() {
        let body = create_body(&args(&["sh", "-c", "echo hi"]), &|_| None).unwrap();
        assert!(body.attach_stdout && body.attach_stderr);
        assert!(!body.attach_stdin);
        assert!(!body.tty);
        assert_eq!(body.cmd, vec!["sh", "-c", "echo hi"]);
    }

    #[test]
    fn interactive_attaches_stdin() {
        let mut args = args(&["sh"]);
        args.interactive = true;
        assert!(create_body(&args, &|_| None).unwrap().attach_stdin);
    }

    #[test]
    fn env_workdir_and_user_are_carried() {
        let mut args = args(&["env"]);
        args.env = vec!["FOO=bar".to_owned(), "HOME".to_owned(), "NOPE".to_owned()];
        args.workdir = Some("/srv".to_owned());
        args.user = Some("nobody".to_owned());
        let body =
            create_body(&args, &|name| (name == "HOME").then(|| "/root".to_owned())).unwrap();
        assert_eq!(body.env, vec!["FOO=bar", "HOME=/root"]);
        assert_eq!(body.working_dir, "/srv");
        assert_eq!(body.user, "nobody");
    }

    /// The create → hijack → pump → inspect path against the stub daemon.
    mod flow {
        use super::*;
        use crate::output::testing;
        use crate::stub::{Reply, Stub, frames};

        async fn stub_with_exec(inspect: Reply) -> Stub {
            let stub = Stub::start().await;
            stub.on(
                "POST",
                "/containers/web/exec",
                Reply::json(201, r#"{"Id":"exec123"}"#),
            )
            .on(
                "POST",
                "/exec/exec123/start",
                Reply::Hijack(frames(&[(1, "hello from the jail\n"), (2, "to stderr\n")])),
            )
            .on("GET", "/exec/exec123/json", inspect);
            stub
        }

        #[tokio::test]
        async fn pumps_frames_and_exits_with_the_exec_code() {
            let stub = stub_with_exec(Reply::json(200, r#"{"Running":false,"ExitCode":7}"#)).await;
            let (mut streams, out, err) = testing::streams();

            let code = execute(&stub.host(), &args(&["sh", "-c", "exit 7"]), &mut streams)
                .await
                .unwrap();

            assert_eq!(code, 7);
            assert_eq!(out.contents(), "hello from the jail\n");
            assert_eq!(err.contents(), "to stderr\n");
            assert_eq!(
                stub.routes(),
                vec![
                    "POST /containers/web/exec",
                    "POST /exec/exec123/start",
                    "GET /exec/exec123/json",
                ]
            );
            let create = stub.first_call("POST /containers/web/exec").unwrap();
            assert!(
                create.body.contains(r#""AttachStdout":true"#),
                "{}",
                create.body
            );
            assert!(create.body.contains(r#""Tty":false"#), "{}", create.body);
            let start = stub.first_call("POST /exec/exec123/start").unwrap();
            assert_eq!(start.body, r#"{"Detach":false,"Tty":false}"#);
        }

        #[tokio::test]
        async fn a_zero_exit_code_is_reported_as_success() {
            let stub = stub_with_exec(Reply::json(200, r#"{"Running":false,"ExitCode":0}"#)).await;
            let (mut streams, _out, _err) = testing::streams();
            let code = execute(&stub.host(), &args(&["true"]), &mut streams)
                .await
                .unwrap();
            assert_eq!(code, 0);
        }

        #[tokio::test]
        async fn the_exit_code_is_polled_until_the_daemon_reaped_the_process() {
            let stub = Stub::start().await;
            stub.on(
                "POST",
                "/containers/web/exec",
                Reply::json(201, r#"{"Id":"exec123"}"#),
            )
            .on("POST", "/exec/exec123/start", Reply::Hijack(Vec::new()))
            .on(
                "GET",
                "/exec/exec123/json",
                Reply::json(200, r#"{"Running":true}"#),
            )
            .on(
                "GET",
                "/exec/exec123/json",
                Reply::json(200, r#"{"Running":false,"ExitCode":2}"#),
            );

            let (mut streams, _out, _err) = testing::streams();
            let code = execute(&stub.host(), &args(&["false"]), &mut streams)
                .await
                .unwrap();
            assert_eq!(code, 2);
            assert_eq!(
                stub.routes()
                    .iter()
                    .filter(|r| *r == "GET /exec/exec123/json")
                    .count(),
                2
            );
        }

        #[tokio::test]
        async fn tty_is_refused_before_any_request() {
            let stub = Stub::start().await;
            let (mut streams, _out, _err) = testing::streams();
            let mut args = args(&["sh"]);
            args.tty = true;
            let err = execute(&stub.host(), &args, &mut streams)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("tty containers are not supported"),
                "{err}"
            );
            assert!(stub.routes().is_empty());
        }
    }
}
