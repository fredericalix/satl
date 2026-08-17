// SPDX-License-Identifier: BSD-2-Clause
//! `satl run` — create, (pull,) start and, unless detached, follow a
//! container to its exit code.
//!
//! Wire flow, matching docker's:
//!
//! 1. `POST /containers/create?name=&platform=`
//! 2. on `404 No such image` (and `--pull` allowing it): `POST /images/create`
//!    with progress on stderr, then retry the create once
//! 3. `POST /containers/{id}/start`
//! 4. detached: print the full ID and return; attached: follow the logs while
//!    waiting on `POST /containers/{id}/wait`, then exit with the container's
//!    code. `Ctrl-C` kills the container and we still report its code.
//!
//! Invariant #2 holds daemon-side: this create call becomes an anonymous
//! single-replica service, which is why the CLI never talks about tasks.

use std::collections::BTreeMap;
use std::time::Duration;

use hyper::{Method, StatusCode};

use crate::api::{CreateContainerBody, CreateContainerResponse, HostConfig, WaitResponse};
use crate::client::{self, DaemonError, Host};
use crate::cmd::{self, logs, pull};
use crate::output::Streams;
use crate::parse::{self, ImageRef};

/// Error text for `-t`, shared with `satl exec`.
pub const TTY_UNSUPPORTED: &str = "tty containers are not supported yet: rerun without -t/--tty (SatL runs jails without a \
     pseudo-terminal; tracked for a later milestone)";

/// How long to keep draining the log stream after the container exited.
const LOG_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// When to pull the image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum PullPolicy {
    /// Always pull before creating.
    Always,
    /// Pull only when the daemon says the image is missing (default).
    #[default]
    Missing,
    /// Never pull; a missing image is an error.
    Never,
}

/// Flags of `satl run`.
// Docker's run flags are inherently a pile of booleans; grouping them into
// sub-structs would only obscure the 1:1 mapping with `docker run`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RunArgs {
    /// Run the container in the background and print its ID.
    #[arg(short, long)]
    pub detach: bool,

    /// Assign a name to the container.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Publish a container's port(s) to the host.
    #[arg(
        short,
        long,
        value_name = "LIST",
        long_help = "Publish a container's port(s) to the host: \
                     [ip:][hostPort:]containerPort[/protocol]. The ip is accepted but not \
                     honored yet (a warning is printed)."
    )]
    pub publish: Vec<String>,

    /// Bind mount a volume.
    #[arg(
        short,
        long,
        value_name = "LIST",
        long_help = "Bind mount a volume: [source:]target[:ro|:rw]. The source is a host path \
                     or a volume name; an omitted source creates an anonymous volume."
    )]
    pub volume: Vec<String>,

    /// Mount a tmpfs directory.
    #[arg(
        long,
        value_name = "MOUNT",
        long_help = "Mount a tmpfs directory: /path[:options]."
    )]
    pub tmpfs: Vec<String>,

    /// Set environment variables.
    #[arg(short, long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Read environment variables from a file.
    #[arg(long = "env-file", value_name = "FILE")]
    pub env_file: Vec<String>,

    /// Working directory inside the container.
    #[arg(short, long = "workdir", value_name = "DIR")]
    pub workdir: Option<String>,

    /// Username or UID.
    #[arg(short, long, value_name = "USER")]
    pub user: Option<String>,

    /// Container host name.
    #[arg(long, value_name = "NAME")]
    pub hostname: Option<String>,

    /// Memory limit.
    #[arg(
        short = 'm',
        long,
        value_name = "BYTES",
        long_help = "Memory limit, with an optional binary unit suffix: 512m, 1g, 2.5g, or a \
                     plain byte count. Enforced through rctl(8)."
    )]
    pub memory: Option<String>,

    /// Number of CPUs.
    #[arg(
        long,
        value_name = "DECIMAL",
        long_help = "Number of CPUs; fractions allowed (0.5, 1.25). Enforced through rctl(8)."
    )]
    pub cpus: Option<String>,

    /// Restart policy to apply when a container exits.
    #[arg(
        long,
        value_name = "POLICY",
        long_help = "Restart policy to apply when a container exits: no, on-failure[:max] or \
                     always."
    )]
    pub restart: Option<String>,

    /// Set platform if the image is multi-platform capable.
    #[arg(long, value_name = "PLATFORM")]
    pub platform: Option<String>,

    /// Automatically remove the container when it exits.
    #[arg(long)]
    pub rm: bool,

    /// Set metadata on the container.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Overwrite the default entrypoint of the image.
    #[arg(long, value_name = "COMMAND")]
    pub entrypoint: Option<String>,

    /// Pull image before running.
    #[arg(long, value_enum, default_value_t = PullPolicy::Missing)]
    pub pull: PullPolicy,

    /// Keep STDIN open even if not attached.
    #[arg(short, long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY (not supported yet).
    #[arg(short, long)]
    pub tty: bool,

    /// Image to run.
    #[arg(value_name = "IMAGE")]
    pub image: String,

    /// Command and arguments to run in the container.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<String>,
}

/// What `run` did, so tests can assert without scraping stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Full container ID the daemon assigned.
    pub id: String,
    /// Process exit code to return.
    pub code: u8,
}

/// `satl run [OPTIONS] IMAGE [COMMAND] [ARG...]`.
pub async fn execute(host: &Host, args: &RunArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    Ok(run(host, args, streams).await?.code)
}

/// The flow, returning the container ID as well (used by tests).
pub async fn run(host: &Host, args: &RunArgs, streams: &mut Streams) -> anyhow::Result<Outcome> {
    if args.tty {
        anyhow::bail!(TTY_UNSUPPORTED);
    }
    let reference = parse::parse_image_ref(&args.image)?;
    let env_files = read_env_files(&args.env_file)?;
    let (body, warnings) = build_create_body(args, &env_files, &lookup_env)?;
    for warning in warnings {
        streams.warn(&warning).await;
    }

    let created = create(host, args, &reference, &body, streams).await?;
    for warning in &created.warnings {
        streams.warn(warning).await;
    }
    let id = created.id;

    client::post_empty_ok(host, &format!("/containers/{id}/start")).await?;

    if args.detach {
        streams.outln(&id).await;
        return Ok(Outcome { id, code: 0 });
    }

    let status = attach(host, &id, streams).await?;
    if args.rm {
        remove_quietly(host, &id, streams).await;
    }
    Ok(Outcome {
        id,
        code: cmd::exit_code(status),
    })
}

/// Create, pulling the image first (or on demand) as `--pull` dictates.
async fn create(
    host: &Host,
    args: &RunArgs,
    reference: &ImageRef,
    body: &CreateContainerBody,
    streams: &mut Streams,
) -> anyhow::Result<CreateContainerResponse> {
    let path = create_path(args);
    if args.pull == PullPolicy::Always {
        pull::pull(
            host,
            reference,
            args.platform.as_deref(),
            streams,
            pull::Target::Stderr,
        )
        .await?;
    }

    match client::post_json(host, &path, Some(body)).await {
        Ok(created) => Ok(created),
        Err(err) if args.pull == PullPolicy::Missing && is_missing_image(&err) => {
            streams
                .errln(&format!(
                    "Unable to find image '{}' locally",
                    reference.canonical()
                ))
                .await;
            pull::pull(
                host,
                reference,
                args.platform.as_deref(),
                streams,
                pull::Target::Stderr,
            )
            .await?;
            client::post_json(host, &path, Some(body)).await
        }
        Err(err) => Err(err),
    }
}

/// `POST /containers/create` with docker's query parameters.
pub fn create_path(args: &RunArgs) -> String {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(name) = &args.name {
        pairs.push(("name", name));
    }
    if let Some(platform) = &args.platform {
        pairs.push(("platform", platform));
    }
    format!("/containers/create{}", client::query(&pairs))
}

/// A create failure that means "the image is not in the local store".
fn is_missing_image(err: &anyhow::Error) -> bool {
    err.downcast_ref::<DaemonError>()
        .is_some_and(|daemon| daemon.status == StatusCode::NOT_FOUND)
}

/// Follow the container's output until it exits, forwarding `Ctrl-C` as a
/// kill, and return its exit status.
async fn attach(host: &Host, id: &str, streams: &mut Streams) -> anyhow::Result<i64> {
    let path = logs::logs_path(id, true, "all", false);
    let body = client::stream(host, &Method::GET, &path, None).await?;
    let wait_path = format!("/containers/{id}/wait");
    let kill_path = format!("/containers/{id}/kill");

    // Inner scope: the log pump borrows `streams` until it is dropped, and we
    // want the stream back afterwards to report any error.
    let (response, log_error, kill_error) = {
        let logs = logs::pump_body(body, streams);
        let wait = client::post_empty_json::<WaitResponse>(host, &wait_path);
        tokio::pin!(logs);
        tokio::pin!(wait);

        let mut logs_done = false;
        let mut interrupted = false;
        let mut log_error = None;
        let mut kill_error = None;
        let response = loop {
            tokio::select! {
                result = &mut logs, if !logs_done => {
                    logs_done = true;
                    log_error = result.err();
                }
                result = &mut wait => break result?,
                signal = tokio::signal::ctrl_c(), if !interrupted => {
                    interrupted = true;
                    if signal.is_ok() {
                        kill_error = client::post_empty_ok(host, &kill_path).await.err();
                    }
                }
            }
        };

        if !logs_done {
            // The container exited but its log stream is still open: keep
            // draining so the last lines are not lost. satld closes the
            // stream at exit, so this normally returns immediately; the
            // timeout only bounds a daemon that does not.
            if let Ok(result) = tokio::time::timeout(LOG_DRAIN_GRACE, &mut logs).await {
                log_error = result.err();
            }
        }
        (response, log_error, kill_error)
    };

    for err in [kill_error, log_error].into_iter().flatten() {
        streams.error(&format!("{err:#}")).await;
    }
    if let Some(error) = response.error
        && !error.message.is_empty()
    {
        anyhow::bail!("Error response from daemon: {}", error.message);
    }
    Ok(response.status_code)
}

/// `--rm` also sets `AutoRemove`, so the container may already be gone.
async fn remove_quietly(host: &Host, id: &str, streams: &mut Streams) {
    let path = format!("/containers/{id}{}", client::query(&[("v", "true")]));
    if let Err(err) = client::delete_ok(host, &path).await {
        let already_gone = err
            .downcast_ref::<DaemonError>()
            .is_some_and(|daemon| daemon.status == StatusCode::NOT_FOUND);
        if !already_gone {
            streams.error(&format!("{err:#}")).await;
        }
    }
}

fn read_env_files(paths: &[String]) -> anyhow::Result<Vec<String>> {
    paths
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .map_err(|err| anyhow::anyhow!("could not read env file {path}: {err}"))
        })
        .collect()
}

fn lookup_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Translate the flags into the create body. Pure: env files are read by the
/// caller and the environment is injected, so the whole flag matrix is
/// unit-testable.
pub fn build_create_body<F>(
    args: &RunArgs,
    env_files: &[String],
    lookup: &F,
) -> anyhow::Result<(CreateContainerBody, Vec<String>)>
where
    F: Fn(&str) -> Option<String>,
{
    let mut warnings = Vec::new();

    let mut ports = Vec::new();
    for value in &args.publish {
        let spec = parse::parse_publish(value)?;
        if let Some(ip) = &spec.ignored_ip {
            warnings.push(format!(
                "published port {value} binds to every address: publishing on a specific IP \
                 ({ip}) is not supported yet"
            ));
        }
        ports.push(spec);
    }
    let (exposed_ports, port_bindings) = parse::port_maps(&ports);

    let mut binds = Vec::new();
    for value in &args.volume {
        binds.push(parse::parse_volume(value)?.bind());
    }

    let mut tmpfs = BTreeMap::new();
    for value in &args.tmpfs {
        let (path, options) = parse::parse_tmpfs(value)?;
        tmpfs.insert(path, options);
    }

    let mut env = Vec::new();
    for contents in env_files {
        env.extend(parse::parse_env_file(contents, lookup)?);
    }
    for value in &args.env {
        if let Some(resolved) = parse::parse_env(value, lookup)? {
            env.push(resolved);
        }
    }

    let mut labels = BTreeMap::new();
    for value in &args.label {
        let (key, value) = parse::parse_label(value)?;
        labels.insert(key, value);
    }

    let host_config = HostConfig {
        binds,
        port_bindings,
        tmpfs,
        restart_policy: args
            .restart
            .as_deref()
            .map(parse::parse_restart)
            .transpose()?,
        memory: args
            .memory
            .as_deref()
            .map(parse::parse_memory)
            .transpose()?
            .unwrap_or(0),
        nano_cpus: args
            .cpus
            .as_deref()
            .map(parse::parse_nano_cpus)
            .transpose()?
            .unwrap_or(0),
        auto_remove: args.rm,
    };

    let body = CreateContainerBody {
        image: args.image.clone(),
        cmd: (!args.command.is_empty()).then(|| args.command.clone()),
        entrypoint: args
            .entrypoint
            .as_ref()
            .map(|entrypoint| vec![entrypoint.clone()]),
        env,
        working_dir: args.workdir.clone().unwrap_or_default(),
        user: args.user.clone().unwrap_or_default(),
        hostname: args.hostname.clone().unwrap_or_default(),
        labels,
        exposed_ports,
        open_stdin: args.interactive,
        tty: false,
        host_config,
    };
    Ok((body, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(image: &str) -> RunArgs {
        RunArgs {
            image: image.to_owned(),
            ..RunArgs::default()
        }
    }

    fn body(args: &RunArgs) -> CreateContainerBody {
        build_create_body(args, &[], &|_| None).unwrap().0
    }

    #[test]
    fn minimal_body_is_just_the_image() {
        assert_eq!(
            serde_json::to_string(&body(&args("nginx"))).unwrap(),
            r#"{"Image":"nginx","OpenStdin":false,"Tty":false,"HostConfig":{}}"#
        );
    }

    #[test]
    fn command_and_entrypoint() {
        let mut args = args("nginx");
        args.command = vec!["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()];
        args.entrypoint = Some("/bin/tini".to_owned());
        let body = body(&args);
        assert_eq!(body.cmd.unwrap(), vec!["sh", "-c", "echo hi"]);
        assert_eq!(body.entrypoint.unwrap(), vec!["/bin/tini"]);
    }

    #[test]
    fn publish_populates_both_maps() {
        let mut args = args("nginx");
        args.publish = vec!["8080:80".to_owned(), "53:53/udp".to_owned()];
        let body = body(&args);
        assert_eq!(
            body.exposed_ports.keys().collect::<Vec<_>>(),
            vec!["53/udp", "80/tcp"]
        );
        assert_eq!(
            body.host_config.port_bindings["80/tcp"][0].host_port,
            "8080"
        );
    }

    #[test]
    fn publishing_on_an_ip_warns_and_ignores_the_ip() {
        let mut args = args("nginx");
        args.publish = vec!["127.0.0.1:8080:80".to_owned()];
        let (body, warnings) = build_create_body(&args, &[], &|_| None).unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("127.0.0.1"), "{}", warnings[0]);
        assert_eq!(body.host_config.port_bindings["80/tcp"][0].host_ip, "");
    }

    #[test]
    fn volumes_tmpfs_and_labels() {
        let mut args = args("nginx");
        args.volume = vec![
            "web-data:/usr/share/nginx/html:ro".to_owned(),
            "/host/log:/var/log".to_owned(),
        ];
        args.tmpfs = vec!["/run:size=64m".to_owned()];
        args.label = vec!["role=web".to_owned()];
        let body = body(&args);
        assert_eq!(
            body.host_config.binds,
            vec!["web-data:/usr/share/nginx/html:ro", "/host/log:/var/log"]
        );
        assert_eq!(body.host_config.tmpfs["/run"], "size=64m");
        assert_eq!(body.labels["role"], "web");
    }

    #[test]
    fn env_file_then_flags_win() {
        let mut args = args("nginx");
        args.env = vec!["FROM_FLAG=1".to_owned(), "INHERITED".to_owned()];
        let files = vec!["FROM_FILE=2\n# comment\n".to_owned()];
        let (body, _) = build_create_body(&args, &files, &|name| {
            (name == "INHERITED").then(|| "yes".to_owned())
        })
        .unwrap();
        assert_eq!(
            body.env,
            vec!["FROM_FILE=2", "FROM_FLAG=1", "INHERITED=yes"]
        );
    }

    #[test]
    fn resources_and_restart_policy() {
        let mut args = args("nginx");
        args.memory = Some("512m".to_owned());
        args.cpus = Some("1.5".to_owned());
        args.restart = Some("on-failure:3".to_owned());
        args.rm = true;
        let body = body(&args);
        assert_eq!(body.host_config.memory, 536_870_912);
        assert_eq!(body.host_config.nano_cpus, 1_500_000_000);
        let policy = body.host_config.restart_policy.unwrap();
        assert_eq!(policy.name, "on-failure");
        assert_eq!(policy.maximum_retry_count, 3);
        assert!(body.host_config.auto_remove);
    }

    #[test]
    fn identity_flags() {
        let mut args = args("nginx");
        args.workdir = Some("/srv".to_owned());
        args.user = Some("www".to_owned());
        args.hostname = Some("web1".to_owned());
        args.interactive = true;
        let body = body(&args);
        assert_eq!(body.working_dir, "/srv");
        assert_eq!(body.user, "www");
        assert_eq!(body.hostname, "web1");
        assert!(body.open_stdin);
        assert!(!body.tty);
    }

    #[test]
    fn bad_flag_values_are_rejected_with_context() {
        let mut bad_port = args("nginx");
        bad_port.publish = vec!["nope".to_owned()];
        let err = build_create_body(&bad_port, &[], &|_| None).unwrap_err();
        assert!(err.to_string().contains("is not a port"), "{err}");

        let mut bad_memory = args("nginx");
        bad_memory.memory = Some("512x".to_owned());
        assert!(build_create_body(&bad_memory, &[], &|_| None).is_err());

        let mut bad_restart = args("nginx");
        bad_restart.restart = Some("always:2".to_owned());
        assert!(build_create_body(&bad_restart, &[], &|_| None).is_err());
    }

    #[test]
    fn create_query_carries_name_and_platform() {
        let mut args = args("nginx");
        assert_eq!(create_path(&args), "/containers/create");
        args.name = Some("web".to_owned());
        assert_eq!(create_path(&args), "/containers/create?name=web");
        args.platform = Some("freebsd/amd64".to_owned());
        assert_eq!(
            create_path(&args),
            "/containers/create?name=web&platform=freebsd%2Famd64"
        );
    }

    #[tokio::test]
    async fn tty_is_refused_with_a_clear_message() {
        let mut args = args("nginx");
        args.tty = true;
        let (mut streams, _out, _err) = crate::output::testing::streams();
        let host = Host::parse("unix:///nonexistent.sock").unwrap();
        let err = run(&host, &args, &mut streams).await.unwrap_err();
        assert!(
            err.to_string().contains("tty containers are not supported"),
            "{err}"
        );
    }

    /// End-to-end flows against a scripted stub daemon on a unix socket.
    mod flow {
        use super::*;
        use crate::output::testing;
        use crate::stub::{Reply, Stub, frames};

        const ID: &str = "b7c1d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3";
        const CREATE: &str = "POST /containers/create";
        const PULL: &str = "POST /images/create";

        fn created() -> Reply {
            Reply::json(201, &format!(r#"{{"Id":"{ID}","Warnings":[]}}"#))
        }

        fn no_such_image() -> Reply {
            Reply::json(404, r#"{"message":"No such image: nginx:latest"}"#)
        }

        fn progress() -> Reply {
            Reply::raw(
                200,
                concat!(
                    r#"{"status":"Pulling from library/nginx","id":"latest"}"#,
                    "\n",
                    r#"{"status":"Pull complete","id":"a2abf6c4d29d"}"#,
                    "\n",
                    r#"{"status":"Status: Downloaded newer image for nginx:latest"}"#,
                    "\n",
                )
                .as_bytes()
                .to_vec(),
            )
        }

        fn detached(image: &str) -> RunArgs {
            RunArgs {
                detach: true,
                ..args(image)
            }
        }

        #[tokio::test]
        async fn detached_run_creates_starts_and_prints_the_full_id() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", created()).on(
                "POST",
                &format!("/containers/{ID}/start"),
                Reply::empty(204),
            );

            let (mut streams, out, err) = testing::streams();
            let mut args = detached("nginx:1.25");
            args.name = Some("web".to_owned());
            args.publish = vec!["8080:80".to_owned()];
            let outcome = run(&stub.host(), &args, &mut streams).await.unwrap();

            assert_eq!(
                outcome,
                Outcome {
                    id: ID.to_owned(),
                    code: 0
                }
            );
            assert_eq!(out.contents(), format!("{ID}\n"));
            assert!(err.contents().is_empty(), "{}", err.contents());
            assert_eq!(
                stub.routes(),
                vec![CREATE.to_owned(), format!("POST /containers/{ID}/start")]
            );
            let call = stub.first_call(CREATE).unwrap();
            assert_eq!(call.query, "name=web");
            assert!(
                call.body.contains(r#""Image":"nginx:1.25""#),
                "{}",
                call.body
            );
            assert!(call.body.contains(r#""PortBindings""#), "{}", call.body);
        }

        #[tokio::test]
        async fn a_missing_image_is_pulled_and_the_create_retried() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", no_such_image())
                .on("POST", "/containers/create", created())
                .on("POST", "/images/create", progress())
                .on(
                    "POST",
                    &format!("/containers/{ID}/start"),
                    Reply::empty(204),
                );

            let (mut streams, out, err) = testing::streams();
            let outcome = run(&stub.host(), &detached("nginx"), &mut streams)
                .await
                .unwrap();

            assert_eq!(outcome.code, 0);
            assert_eq!(
                stub.routes(),
                vec![
                    CREATE.to_owned(),
                    PULL.to_owned(),
                    CREATE.to_owned(),
                    format!("POST /containers/{ID}/start"),
                ]
            );
            // Progress goes to stderr so stdout stays the container's.
            assert_eq!(out.contents(), format!("{ID}\n"));
            let progress = err.contents();
            assert!(
                progress.starts_with("Unable to find image 'nginx:latest' locally\n"),
                "{progress}"
            );
            assert!(
                progress.contains("a2abf6c4d29d: Pull complete\n"),
                "{progress}"
            );
            assert!(
                progress.ends_with("Status: Downloaded newer image for nginx:latest\n"),
                "{progress}"
            );
            let pull = stub.first_call(PULL).unwrap();
            assert_eq!(pull.query, "fromImage=nginx&tag=latest");
        }

        #[tokio::test]
        async fn pull_never_reports_the_daemon_error_without_pulling() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", no_such_image());

            let (mut streams, _out, _err) = testing::streams();
            let mut args = detached("nginx");
            args.pull = PullPolicy::Never;
            let err = run(&stub.host(), &args, &mut streams).await.unwrap_err();

            assert_eq!(
                err.to_string(),
                "Error response from daemon: No such image: nginx:latest"
            );
            assert_eq!(stub.routes(), vec![CREATE.to_owned()]);
        }

        #[tokio::test]
        async fn pull_always_pulls_before_creating() {
            let stub = Stub::start().await;
            stub.on("POST", "/images/create", progress())
                .on("POST", "/containers/create", created())
                .on(
                    "POST",
                    &format!("/containers/{ID}/start"),
                    Reply::empty(204),
                );

            let (mut streams, _out, _err) = testing::streams();
            let mut args = detached("nginx");
            args.pull = PullPolicy::Always;
            args.platform = Some("freebsd/amd64".to_owned());
            run(&stub.host(), &args, &mut streams).await.unwrap();

            assert_eq!(
                stub.routes(),
                vec![
                    PULL.to_owned(),
                    CREATE.to_owned(),
                    format!("POST /containers/{ID}/start"),
                ]
            );
            assert_eq!(
                stub.first_call(PULL).unwrap().query,
                "fromImage=nginx&tag=latest&platform=freebsd%2Famd64"
            );
            assert_eq!(
                stub.first_call(CREATE).unwrap().query,
                "platform=freebsd%2Famd64"
            );
        }

        #[tokio::test]
        async fn foreground_follows_the_logs_and_exits_with_the_container_code() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", created())
                .on(
                    "POST",
                    &format!("/containers/{ID}/start"),
                    Reply::empty(204),
                )
                .on(
                    "GET",
                    &format!("/containers/{ID}/logs"),
                    Reply::raw(
                        200,
                        frames(&[
                            (1, "listening on 0.0.0.0:80\n"),
                            (2, "warning: no config\n"),
                            (1, "bye\n"),
                        ]),
                    ),
                )
                .on(
                    "POST",
                    &format!("/containers/{ID}/wait"),
                    Reply::json(200, r#"{"StatusCode":3}"#),
                );

            let (mut streams, out, err) = testing::streams();
            let outcome = run(&stub.host(), &args("nginx"), &mut streams)
                .await
                .unwrap();

            assert_eq!(outcome.code, 3);
            assert_eq!(out.contents(), "listening on 0.0.0.0:80\nbye\n");
            assert_eq!(err.contents(), "warning: no config\n");
            let routes = stub.routes();
            assert!(
                routes.contains(&format!("GET /containers/{ID}/logs")),
                "{routes:?}"
            );
            assert!(
                routes.contains(&format!("POST /containers/{ID}/wait")),
                "{routes:?}"
            );
            let logs = stub
                .first_call(&format!("GET /containers/{ID}/logs"))
                .unwrap();
            assert_eq!(
                logs.query,
                "follow=1&stdout=1&stderr=1&tail=all&timestamps=0"
            );
        }

        #[tokio::test]
        async fn rm_removes_the_container_after_it_exits() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", created())
                .on(
                    "POST",
                    &format!("/containers/{ID}/start"),
                    Reply::empty(204),
                )
                .on(
                    "GET",
                    &format!("/containers/{ID}/logs"),
                    Reply::raw(200, frames(&[(1, "done\n")])),
                )
                .on(
                    "POST",
                    &format!("/containers/{ID}/wait"),
                    Reply::json(200, r#"{"StatusCode":0}"#),
                )
                .on("DELETE", &format!("/containers/{ID}"), Reply::empty(204));

            let (mut streams, _out, err) = testing::streams();
            let mut args = args("nginx");
            args.rm = true;
            let outcome = run(&stub.host(), &args, &mut streams).await.unwrap();

            assert_eq!(outcome.code, 0);
            assert!(err.contents().is_empty(), "{}", err.contents());
            let call = stub
                .first_call(&format!("DELETE /containers/{ID}"))
                .unwrap();
            assert_eq!(call.query, "v=true");
            // AutoRemove is set as well, so the daemon may have won the race.
            let create = stub.first_call(CREATE).unwrap();
            assert!(
                create.body.contains(r#""AutoRemove":true"#),
                "{}",
                create.body
            );
        }

        #[tokio::test]
        async fn an_already_removed_container_is_not_reported_as_an_error() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", created())
                .on(
                    "POST",
                    &format!("/containers/{ID}/start"),
                    Reply::empty(204),
                )
                .on(
                    "GET",
                    &format!("/containers/{ID}/logs"),
                    Reply::raw(200, Vec::new()),
                )
                .on(
                    "POST",
                    &format!("/containers/{ID}/wait"),
                    Reply::json(200, r#"{"StatusCode":0}"#),
                )
                .on(
                    "DELETE",
                    &format!("/containers/{ID}"),
                    Reply::json(404, r#"{"message":"No such container"}"#),
                );

            let (mut streams, _out, err) = testing::streams();
            let mut args = args("nginx");
            args.rm = true;
            run(&stub.host(), &args, &mut streams).await.unwrap();
            assert!(err.contents().is_empty(), "{}", err.contents());
        }

        #[tokio::test]
        async fn create_warnings_are_shown_before_the_id() {
            let stub = Stub::start().await;
            stub.on(
                "POST",
                "/containers/create",
                Reply::json(
                    201,
                    &format!(
                        r#"{{"Id":"{ID}","Warnings":["rctl is disabled: --memory ignored"]}}"#
                    ),
                ),
            )
            .on(
                "POST",
                &format!("/containers/{ID}/start"),
                Reply::empty(204),
            );

            let (mut streams, _out, err) = testing::streams();
            run(&stub.host(), &detached("nginx"), &mut streams)
                .await
                .unwrap();
            assert_eq!(
                err.contents(),
                "WARNING: rctl is disabled: --memory ignored\n"
            );
        }

        #[tokio::test]
        async fn a_failed_start_stops_the_flow() {
            let stub = Stub::start().await;
            stub.on("POST", "/containers/create", created()).on(
                "POST",
                &format!("/containers/{ID}/start"),
                Reply::json(500, r#"{"message":"ocijail create failed: jail(2) EPERM"}"#),
            );

            let (mut streams, out, _err) = testing::streams();
            let err = run(&stub.host(), &detached("nginx"), &mut streams)
                .await
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                "Error response from daemon: ocijail create failed: jail(2) EPERM"
            );
            assert!(out.contents().is_empty());
        }
    }
}
