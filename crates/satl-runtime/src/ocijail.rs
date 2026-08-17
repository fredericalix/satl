// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around the `ocijail` binary (the only OCI runtime SatL
//! drives — invariant #6). Contract per docs/ocijail.md.
//!
//! Key wrapper decisions, all grounded in the ocijail 0.6.0 study:
//!
//! - **Private state db**: every invocation passes `--root` so operator use
//!   of the bare `ocijail` CLI can never collide with satld (§1.1).
//! - **Numeric signals**: ocijail only parses uppercase un-prefixed signal
//!   names (`TERM`, not `SIGTERM`/`term`), so [`Ocijail::kill`] takes the
//!   signal number and sidesteps name parsing entirely (§4.2).
//! - **`NotFound`**: an unknown id fails with `opening state lock: No such
//!   file or directory` on every subcommand except `delete` (which exits 0
//!   and cleans nothing — the idempotency trap, §4.3). That message is
//!   mapped to [`OcijailError::NotFound`].
//! - **stdio inheritance**: the container process inherits fds 0/1/2 of
//!   `ocijail create` verbatim (§3), so `create`/`exec` take a
//!   [`CreateStdio`] whose handles are passed to the child unchanged. A
//!   consequence: on a failed create, the runtime's error text lands in the
//!   container's stderr *sink*, not on a capturable pipe. When the sink is a
//!   regular file the wrapper remembers the write offset before spawning and
//!   reads the error text back on failure, so errors still carry stderr.
//! - **Exit codes**: `state` never reports one; harvesting is
//!   [`crate::exit::wait_for_exit`] on the pid from `--pid-file` (§1.6).
//!   Any exit code > 1 from a non-`exec` subcommand is a CLI11 usage error,
//!   i.e. a bug in this wrapper (§6).

use std::collections::BTreeMap;
use std::io::Seek as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;

use crate::runner::{
    CommandOutput, CommandRunner, CreateStdio, StdioSink, SystemRunner, render_argv,
};

/// Default location of the `ocijail` binary (pkg `sysutils/ocijail`).
pub const DEFAULT_OCIJAIL_BINARY: &str = "/usr/local/bin/ocijail";

/// The exec `process.json` shares the schema of `config.json`'s `process`
/// object exactly (docs/ocijail.md §4.1).
pub type ExecSpec = crate::spec::ProcessSpec;

/// Container status as reported by `ocijail state`/`list`. No `paused`, no
/// exit codes. `running` is set *before* the workload execs and `stopped` is
/// only computed when someone calls `state`/`list`/`delete` — neither is a
/// liveness signal (docs/ocijail.md §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeStatus {
    /// Jail and mounts exist; the workload has not exec'd yet.
    Created,
    /// `start` ran; the workload may or may not still be alive.
    Running,
    /// The container process was observed dead.
    Stopped,
}

/// Parsed `ocijail state` output (one-line JSON on stdout).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RuntimeState {
    /// Container id (also the jail name).
    pub id: String,
    /// Container status.
    pub status: RuntimeStatus,
    /// Container process pid; absent once `status == stopped`.
    #[serde(default)]
    pub pid: Option<i32>,
    /// Bundle directory the container was created from.
    pub bundle: PathBuf,
    /// The config's annotations plus the injected `org.freebsd.jail.jid`.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    /// Hardcoded `"1.0.2"` in ocijail 0.6.0.
    #[serde(rename = "ociVersion", default)]
    pub oci_version: String,
}

impl RuntimeState {
    /// The jail id, parsed from the injected `org.freebsd.jail.jid`
    /// annotation (a string in the JSON).
    #[must_use]
    pub fn jid(&self) -> Option<i32> {
        self.annotations
            .get(crate::spec::ANNOTATION_JID)
            .and_then(|jid| jid.parse().ok())
    }
}

/// One row of `ocijail list -f json` (no annotations there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// Container id.
    pub id: String,
    /// Bundle directory.
    pub bundle: PathBuf,
    /// Container pid; `None` when stopped (printed as `0`).
    pub pid: Option<i32>,
    /// Container status.
    pub status: RuntimeStatus,
}

#[derive(Debug, Deserialize)]
struct RawListEntry {
    id: String,
    bundle: PathBuf,
    #[serde(default)]
    pid: i32,
    status: RuntimeStatus,
}

/// Parsed `ocijail features` output. Informational only — 0.6.0
/// underreports `ociVersionMax` (1.2.0, while `create` accepts 1.3.x), so
/// never gate on it (docs/ocijail.md §1.5).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    /// Supported hook kinds.
    pub hooks: Vec<String>,
    /// Recognized mount option names.
    pub mount_options: Vec<String>,
    /// Minimum accepted `ociVersion`.
    pub oci_version_min: String,
    /// Claimed (underreported) maximum `ociVersion`.
    pub oci_version_max: String,
}

/// Outcome of a non-detached `ocijail exec`: ocijail `jail_attach`es and
/// `execvp`s itself, so its exit code *is* the process's exit code
/// (docs/ocijail.md §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecOutcome {
    /// Process exit code; `None` when it died to a signal.
    pub exit_code: Option<i32>,
}

/// Error from an `ocijail` invocation. Every variant names the jail id where
/// one is involved and carries the full command line; command failures carry
/// exit status and stderr.
#[derive(Debug, thiserror::Error)]
pub enum OcijailError {
    /// The binary could not be spawned.
    #[error("failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The container id is unknown to ocijail (state db entry missing) —
    /// mapped from `opening state lock: No such file or directory`.
    #[error(
        "container '{id}' is unknown to ocijail (state db entry missing; from `{argv}`). \
         Note: a jail named '{id}' may still exist if satld crashed mid-create; \
         startup reconciliation handles that"
    )]
    NotFound {
        /// The container id.
        id: String,
        /// Full rendered command line.
        argv: String,
    },

    /// `create` refused a duplicate container id.
    #[error("container '{id}' already exists in ocijail's state db (from `{argv}`)")]
    AlreadyExists {
        /// The container id.
        id: String,
        /// Full rendered command line.
        argv: String,
    },

    /// A lifecycle command was issued in the wrong state (e.g. `start` on a
    /// running container, `delete` without `--force` on a running one).
    #[error("container '{id}': {message} (from `{argv}`)")]
    WrongState {
        /// The container id.
        id: String,
        /// ocijail's message, timestamp stripped.
        message: String,
        /// Full rendered command line.
        argv: String,
    },

    /// The command ran but exited unsuccessfully.
    #[error(
        "`{argv}` for container '{id}' failed with {status}; stderr: {stderr}",
        status = render_exit(*exit_code), stderr = render_raw(stderr)
    )]
    CommandFailed {
        /// The container id ('-' for id-less commands like `list`).
        id: String,
        /// Full rendered command line.
        argv: String,
        /// Exit code; `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr (for `create`/`exec`: read back from the stderr sink).
        stderr: String,
    },

    /// Exit code > 1 from a non-exec subcommand: CLI11 usage error, meaning
    /// this wrapper built a bad command line (docs/ocijail.md §6) — a SatL
    /// bug, please report it.
    #[error(
        "`{argv}` was rejected by ocijail's CLI parser ({status}). This is a satl-runtime \
         bug, please report it; stderr: {stderr}",
        status = render_exit(*exit_code), stderr = render_raw(stderr)
    )]
    UsageError {
        /// Full rendered command line.
        argv: String,
        /// Exit code (105 = validation, 106 = missing option).
        exit_code: Option<i32>,
        /// Raw stderr.
        stderr: String,
    },

    /// The command succeeded but its output did not have the expected shape.
    #[error(
        "unexpected output from `{argv}`: {reason}; raw stdout: {out}",
        out = render_raw(stdout)
    )]
    UnexpectedOutput {
        /// Full rendered command line.
        argv: String,
        /// Why the output was rejected.
        reason: String,
        /// Raw stdout.
        stdout: String,
    },

    /// The id is not usable as a jail name (docs/ocijail.md §7.10: the id
    /// *is* the jail name; `.` means jail hierarchy).
    #[error("container id {id:?} is not a valid jail name: {reason}")]
    InvalidId {
        /// The offending id.
        id: String,
        /// What is wrong with it.
        reason: String,
    },

    /// `create` requires an absolute bundle path — a relative one fails with
    /// a misleading "bundle directory must contain config.json"
    /// (docs/linuxulator.md).
    #[error("bundle path {path} must be absolute (ocijail resolves it against its own cwd)")]
    BundleNotAbsolute {
        /// The offending path.
        path: PathBuf,
    },

    /// Filesystem work around an invocation failed (pid file, process.json).
    #[error("{what} {path} for container '{id}': {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// The file involved.
        path: PathBuf,
        /// The container id.
        id: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The pid file did not contain a pid.
    #[error("pid file {path} for container '{id}' held {content:?}, not a pid")]
    PidFile {
        /// The pid file path.
        path: PathBuf,
        /// The container id.
        id: String,
        /// What the file actually held.
        content: String,
    },
}

impl OcijailError {
    /// Whether this is the typed "container unknown" outcome.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}

fn render_exit(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("exit code {code}"),
        None => "termination by signal".to_owned(),
    }
}

fn render_raw(raw: &str) -> String {
    let trimmed = raw.trim_end();
    if trimmed.is_empty() {
        "(empty)".to_owned()
    } else {
        format!("{trimmed:?}")
    }
}

/// Strip ocijail's non-RFC3339 timestamp prefix (`%Y-%m-%dT%H:%M:%S` +
/// 9-digit microseconds + `Z: `) from an error line (docs/ocijail.md §6).
fn strip_timestamp(line: &str) -> &str {
    match line.split_once(": ") {
        Some((head, rest))
            if head.len() >= 20
                && head.ends_with('Z')
                && head.starts_with(|c: char| c.is_ascii_digit()) =>
        {
            rest
        }
        _ => line,
    }
}

/// The id doubles as the jail name; enforce SatL's safe charset before it
/// reaches `jail_set(2)`.
fn validate_id(id: &str) -> Result<(), OcijailError> {
    let reason = if id.is_empty() {
        Some("empty".to_owned())
    } else if id.starts_with('-') {
        Some("leading '-' would parse as a flag".to_owned())
    } else {
        id.chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
            .map(|c| format!("character {c:?} not in [A-Za-z0-9_-] ('.' means jail hierarchy)"))
    };
    match reason {
        Some(reason) => Err(OcijailError::InvalidId {
            id: id.to_owned(),
            reason,
        }),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Pure argv builders (unit-tested without executing anything).
// ---------------------------------------------------------------------------

fn base_args(state_root: &Path) -> Vec<String> {
    vec!["--root".to_owned(), state_root.display().to_string()]
}

fn args_create(
    state_root: &Path,
    bundle: &Path,
    pid_file: &Path,
    console_socket: Option<&Path>,
    id: &str,
) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("create".to_owned());
    args.push("-b".to_owned());
    args.push(bundle.display().to_string());
    args.push("--pid-file".to_owned());
    args.push(pid_file.display().to_string());
    if let Some(socket) = console_socket {
        args.push("--console-socket".to_owned());
        args.push(socket.display().to_string());
    }
    args.push(id.to_owned());
    args
}

fn args_start(state_root: &Path, id: &str) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("start".to_owned());
    args.push(id.to_owned());
    args
}

fn args_kill(state_root: &Path, id: &str, signal: i32) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("kill".to_owned());
    args.push(id.to_owned());
    args.push(signal.to_string());
    args
}

fn args_delete(state_root: &Path, id: &str, force: bool) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("delete".to_owned());
    if force {
        args.push("--force".to_owned());
    }
    args.push(id.to_owned());
    args
}

fn args_state(state_root: &Path, id: &str) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("state".to_owned());
    args.push(id.to_owned());
    args
}

fn args_list(state_root: &Path) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("list".to_owned());
    args.push("-f".to_owned());
    args.push("json".to_owned());
    args
}

fn args_features(state_root: &Path) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("features".to_owned());
    args
}

fn args_exec(
    state_root: &Path,
    id: &str,
    process_file: &Path,
    detach: bool,
    pid_file: Option<&Path>,
) -> Vec<String> {
    let mut args = base_args(state_root);
    args.push("exec".to_owned());
    args.push("--process".to_owned());
    args.push(process_file.display().to_string());
    if detach {
        args.push("--detach".to_owned());
    }
    if let Some(pid_file) = pid_file {
        args.push("--pid-file".to_owned());
        args.push(pid_file.display().to_string());
    }
    args.push(id.to_owned());
    args
}

// ---------------------------------------------------------------------------
// stderr sink readback (see module docs).
// ---------------------------------------------------------------------------

/// Remembers where the stderr sink file stood before the child ran, so error
/// text the child wrote can be read back afterwards.
struct StderrReadback {
    file: std::fs::File,
    start: u64,
}

/// Duplicate the stderr sink handle and note its current offset. `None`
/// when the sink is `/dev/null` or not seekable (a pipe): error text is
/// then unrecoverable by the wrapper and stays in the caller's sink.
///
/// Readback also requires the sink to be opened **read**+write (satld's log
/// sink convention); a write-only handle degrades to an empty stderr in the
/// error, with the text still available in the sink itself.
fn prepare_readback(stdio: &CreateStdio) -> Option<StderrReadback> {
    match &stdio.stderr {
        StdioSink::File(file) => {
            let mut dup = file.try_clone().ok()?;
            let start = dup.stream_position().ok()?;
            Some(StderrReadback { file: dup, start })
        }
        StdioSink::Null => None,
    }
}

impl StderrReadback {
    /// Read what was written since [`prepare_readback`]. Runs on the
    /// blocking pool (error path only).
    async fn read(self) -> String {
        let Self { mut file, start } = self;
        tokio::task::spawn_blocking(move || {
            use std::io::{Read as _, SeekFrom};
            if file.seek(SeekFrom::Start(start)).is_err() {
                return String::new();
            }
            let mut text = String::new();
            let _ = file.read_to_string(&mut text);
            text
        })
        .await
        .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Counter making concurrent exec `process.json` file names unique.
static EXEC_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Typed async wrapper around the `ocijail` binary.
///
/// `state_root` is the private `--root` state db (satld-owned; never the
/// default `/var/run/ocijail`). `scratch_dir` is a satld-owned directory for
/// transient exec `process.json` files — they can carry secret env values,
/// so it must not be a world-readable location and files are written 0600.
#[derive(Debug, Clone)]
pub struct Ocijail<R = SystemRunner> {
    binary: PathBuf,
    state_root: PathBuf,
    scratch_dir: PathBuf,
    runner: R,
}

impl Ocijail<SystemRunner> {
    /// Wrapper executing the real binary at [`DEFAULT_OCIJAIL_BINARY`].
    pub fn system(state_root: impl Into<PathBuf>, scratch_dir: impl Into<PathBuf>) -> Self {
        Self::with_runner(SystemRunner, state_root, scratch_dir)
    }
}

impl<R: CommandRunner> Ocijail<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(
        runner: R,
        state_root: impl Into<PathBuf>,
        scratch_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_OCIJAIL_BINARY),
            state_root: state_root.into(),
            scratch_dir: scratch_dir.into(),
            runner,
        }
    }

    /// Override the path of the `ocijail` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// The `--root` state db this wrapper drives.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    async fn exec_cmd(&self, args: Vec<String>) -> Result<(String, CommandOutput), OcijailError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running ocijail");
        let output = self
            .runner
            .run(&self.binary, &args)
            .await
            .map_err(|source| OcijailError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Classify a failed invocation per the docs/ocijail.md §6 catalogue.
    fn classify(id: &str, argv: String, output: &CommandOutput) -> OcijailError {
        let stderr = output.stderr.as_str();
        if stderr.contains("opening state lock") {
            return OcijailError::NotFound {
                id: id.to_owned(),
                argv,
            };
        }
        if !id.is_empty() && stderr.contains(&format!("container {id} exists")) {
            return OcijailError::AlreadyExists {
                id: id.to_owned(),
                argv,
            };
        }
        if stderr.contains("not in \"") {
            let message = stderr
                .lines()
                .find(|line| line.contains("not in \""))
                .map_or(stderr, strip_timestamp)
                .trim()
                .to_owned();
            return OcijailError::WrongState {
                id: id.to_owned(),
                message,
                argv,
            };
        }
        if output.exit_code.is_some_and(|code| code > 1) {
            return OcijailError::UsageError {
                argv,
                exit_code: output.exit_code,
                stderr: stderr.to_owned(),
            };
        }
        OcijailError::CommandFailed {
            id: if id.is_empty() {
                "-".to_owned()
            } else {
                id.to_owned()
            },
            argv,
            exit_code: output.exit_code,
            stderr: stderr.to_owned(),
        }
    }

    async fn read_pid_file(&self, id: &str, path: &Path) -> Result<i32, OcijailError> {
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|source| OcijailError::Io {
                what: "reading pid file",
                path: path.to_owned(),
                id: id.to_owned(),
                source,
            })?;
        content.trim().parse().map_err(|_| OcijailError::PidFile {
            path: path.to_owned(),
            id: id.to_owned(),
            content,
        })
    }

    /// `ocijail create`: build the jail, perform all bundle mounts, fork the
    /// (not yet exec'd) container process. Returns the container pid from
    /// `pid_file` — arm [`crate::exit::wait_for_exit`] on it **before**
    /// calling [`Ocijail::start`] (docs/ocijail.md §1.4 gotcha).
    ///
    /// `stdio` handles are inherited by the container for its whole life;
    /// `console_socket` is required iff the config has `process.terminal:
    /// true` and must already be listening.
    pub async fn create(
        &self,
        id: &str,
        bundle: &Path,
        pid_file: &Path,
        console_socket: Option<&Path>,
        stdio: CreateStdio,
    ) -> Result<i32, OcijailError> {
        validate_id(id)?;
        if !bundle.is_absolute() {
            return Err(OcijailError::BundleNotAbsolute {
                path: bundle.to_owned(),
            });
        }
        let args = args_create(&self.state_root, bundle, pid_file, console_socket, id);
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, jail_id = id, "running ocijail create");
        let readback = prepare_readback(&stdio);
        let output = self
            .runner
            .run_with_stdio(&self.binary, &args, stdio)
            .await
            .map_err(|source| OcijailError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        if output.success() {
            return self.read_pid_file(id, pid_file).await;
        }
        // Error text went to the container's stderr sink (docs §3); recover
        // it when the sink is a readable file.
        let stderr = match readback {
            Some(readback) => readback.read().await,
            None => String::new(),
        };
        let failed = CommandOutput {
            exit_code: output.exit_code,
            stdout: String::new(),
            stderr,
        };
        Err(Self::classify(id, rendered, &failed))
    }

    /// `ocijail start`: release the create-fifo so the workload execs.
    /// Returns immediately — it does not wait for the exec, and it does not
    /// notice an already-dead created process (docs/ocijail.md §1.4).
    pub async fn start(&self, id: &str) -> Result<(), OcijailError> {
        validate_id(id)?;
        let (argv, output) = self.exec_cmd(args_start(&self.state_root, id)).await?;
        if output.success() {
            Ok(())
        } else {
            Err(Self::classify(id, argv, &output))
        }
    }

    /// `ocijail kill <id> <signal>` — numeric signal, delivered to the
    /// container init pid **only** (`--all` is a no-op flag in 0.6.0;
    /// orphans die at delete). On a stopped container this is a silent
    /// no-op, exit 0 (docs/ocijail.md §4.2).
    pub async fn kill(&self, id: &str, signal: i32) -> Result<(), OcijailError> {
        validate_id(id)?;
        let (argv, output) = self
            .exec_cmd(args_kill(&self.state_root, id, signal))
            .await?;
        if output.success() {
            Ok(())
        } else {
            Err(Self::classify(id, argv, &output))
        }
    }

    /// `ocijail delete [--force]`: `jail_remove(2)` (killing every process still
    /// inside), unmount the *recorded* bundle mounts, drop the state entry.
    ///
    /// **Idempotency trap** (docs/ocijail.md §4.3): deleting an id with no
    /// state entry exits 0 and cleans nothing — "never existed", "already
    /// deleted" and "state lost but jail alive" are indistinguishable here.
    /// Callers must follow up with [`crate::mounts::Mounts::unmount_all_under`]
    /// (the [`crate::runtime::Runtime::delete`] composition does).
    pub async fn delete(&self, id: &str, force: bool) -> Result<(), OcijailError> {
        validate_id(id)?;
        let (argv, output) = self
            .exec_cmd(args_delete(&self.state_root, id, force))
            .await?;
        if output.success() {
            Ok(())
        } else {
            Err(Self::classify(id, argv, &output))
        }
    }

    /// `ocijail state <id>`: parse the one-line state JSON. Calling this is
    /// also what makes ocijail notice a dead container (`created`/`running`
    /// → `stopped`).
    pub async fn state(&self, id: &str) -> Result<RuntimeState, OcijailError> {
        validate_id(id)?;
        let (argv, output) = self.exec_cmd(args_state(&self.state_root, id)).await?;
        if !output.success() {
            return Err(Self::classify(id, argv, &output));
        }
        serde_json::from_str(output.stdout.trim()).map_err(|error| OcijailError::UnexpectedOutput {
            argv,
            reason: format!("state JSON did not parse: {error}"),
            stdout: output.stdout,
        })
    }

    /// `ocijail list -f json`.
    ///
    /// **"No containers" has two shapes here, and neither is a failure**
    /// (measured on ocijail 0.6.0, docs/ocijail.md §1.5):
    ///
    /// - a state root that does not exist yet, because nothing was ever
    ///   created, throws inside ocijail's `directory_iterator` — so the
    ///   command *fails*, with that phrase on stderr;
    /// - a state root that exists but holds no readable entry prints the JSON
    ///   literal `null` (four bytes, no newline) and exits 0. `list.cpp`
    ///   default-constructs a `nlohmann::json`, which is of type null until
    ///   the first `push_back` turns it into an array, and prints it as it
    ///   stands.
    ///
    /// The second shape was reported as a parse failure, so every startup with
    /// no containers logged one at ERROR. A routine false ERROR is worse than
    /// no log at all: it is what teaches an operator to skip the one that
    /// matters. Deserializing into an `Option` keeps genuinely malformed
    /// output a genuine error — `null` is `None`, an array is `Some`, and
    /// anything else still fails with the argv and the raw stdout attached.
    pub async fn list(&self) -> Result<Vec<ListEntry>, OcijailError> {
        let (argv, output) = self.exec_cmd(args_list(&self.state_root)).await?;
        if !output.success() {
            if output.stderr.contains("directory_iterator")
                && output.stderr.contains("No such file or directory")
            {
                return Ok(Vec::new());
            }
            return Err(Self::classify("", argv, &output));
        }
        let raw: Option<Vec<RawListEntry>> =
            serde_json::from_str(output.stdout.trim()).map_err(|error| {
                OcijailError::UnexpectedOutput {
                    argv,
                    reason: format!("list JSON did not parse: {error}"),
                    stdout: output.stdout.clone(),
                }
            })?;
        Ok(raw
            .unwrap_or_default()
            .into_iter()
            .map(|entry| ListEntry {
                id: entry.id,
                bundle: entry.bundle,
                pid: (entry.pid != 0).then_some(entry.pid),
                status: entry.status,
            })
            .collect())
    }

    /// `ocijail features` (informational; see [`Features`]).
    pub async fn features(&self) -> Result<Features, OcijailError> {
        let (argv, output) = self.exec_cmd(args_features(&self.state_root)).await?;
        if !output.success() {
            return Err(Self::classify("", argv, &output));
        }
        serde_json::from_str(output.stdout.trim()).map_err(|error| OcijailError::UnexpectedOutput {
            argv,
            reason: format!("features JSON did not parse: {error}"),
            stdout: output.stdout,
        })
    }

    /// Write the transient `--process` file (0600; env may hold secrets).
    async fn write_process_file(
        &self,
        id: &str,
        process: &ExecSpec,
    ) -> Result<PathBuf, OcijailError> {
        let io_err = |what: &'static str, path: &Path, source: std::io::Error| OcijailError::Io {
            what,
            path: path.to_owned(),
            id: id.to_owned(),
            source,
        };
        tokio::fs::create_dir_all(&self.scratch_dir)
            .await
            .map_err(|e| io_err("creating exec scratch dir", &self.scratch_dir, e))?;
        let sequence = EXEC_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = self
            .scratch_dir
            .join(format!("exec-{id}-{}-{sequence}.json", std::process::id()));
        let json = serde_json::to_vec(process)
            .map_err(|e| io_err("serializing process.json", &path, e.into()))?;
        let mut file = {
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(&path)
                .await
                .map_err(|e| io_err("creating process.json", &path, e))?
        };
        file.write_all(&json)
            .await
            .map_err(|e| io_err("writing process.json", &path, e))?;
        file.flush()
            .await
            .map_err(|e| io_err("writing process.json", &path, e))?;
        Ok(path)
    }

    async fn remove_process_file(&self, path: &Path) {
        if let Err(error) = tokio::fs::remove_file(path).await {
            tracing::warn!(path = %path.display(), %error, "could not remove exec process.json");
        }
    }

    /// Non-detached `ocijail exec`: blocks until the exec'd process exits
    /// and returns its exit code (ocijail's own). `stdio` is the process's
    /// stdio. Works in `created` and even `stopped` state while the persist
    /// jail exists (docs/ocijail.md §4.1).
    ///
    /// Ambiguity note: exit codes are the *process's*, so a `NotFound` can
    /// only be told apart from "process exited 1" via the stderr sink —
    /// pass a file sink if that distinction matters.
    pub async fn exec(
        &self,
        id: &str,
        process: &ExecSpec,
        stdio: CreateStdio,
    ) -> Result<ExecOutcome, OcijailError> {
        validate_id(id)?;
        let process_file = self.write_process_file(id, process).await?;
        let args = args_exec(&self.state_root, id, &process_file, false, None);
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, jail_id = id, "running ocijail exec");
        let readback = prepare_readback(&stdio);
        let result = self.runner.run_with_stdio(&self.binary, &args, stdio).await;
        self.remove_process_file(&process_file).await;
        let output = result.map_err(|source| OcijailError::Spawn {
            argv: rendered.clone(),
            source,
        })?;
        if !output.success()
            && let Some(readback) = readback
        {
            let stderr = readback.read().await;
            if stderr.contains("opening state lock") {
                return Err(OcijailError::NotFound {
                    id: id.to_owned(),
                    argv: rendered,
                });
            }
        }
        Ok(ExecOutcome {
            exit_code: output.exit_code,
        })
    }

    /// Detached `ocijail exec --detach --pid-file`: returns the exec'd
    /// process's pid once in-jail validation of `args[0]` passed. Harvest
    /// its exit with [`crate::exit::wait_for_exit`].
    pub async fn exec_detached(
        &self,
        id: &str,
        process: &ExecSpec,
        stdio: CreateStdio,
        pid_file: &Path,
    ) -> Result<i32, OcijailError> {
        validate_id(id)?;
        let process_file = self.write_process_file(id, process).await?;
        let args = args_exec(&self.state_root, id, &process_file, true, Some(pid_file));
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, jail_id = id, "running ocijail exec --detach");
        let readback = prepare_readback(&stdio);
        let result = self.runner.run_with_stdio(&self.binary, &args, stdio).await;
        self.remove_process_file(&process_file).await;
        let output = result.map_err(|source| OcijailError::Spawn {
            argv: rendered.clone(),
            source,
        })?;
        if output.success() {
            return self.read_pid_file(id, pid_file).await;
        }
        let stderr = match readback {
            Some(readback) => readback.read().await,
            None => String::new(),
        };
        let failed = CommandOutput {
            exit_code: output.exit_code,
            stdout: String::new(),
            stderr,
        };
        Err(Self::classify(id, rendered, &failed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;
    use crate::spec::ProcessSpec;

    const FIXTURE_STATE_CREATED: &str =
        include_str!("../tests/fixtures/ocijail_state_created.json");
    const FIXTURE_STATE_RUNNING: &str =
        include_str!("../tests/fixtures/ocijail_state_running.json");
    const FIXTURE_STATE_STOPPED: &str =
        include_str!("../tests/fixtures/ocijail_state_stopped.json");
    const FIXTURE_STATE_VNET: &str = include_str!("../tests/fixtures/ocijail_state_vnet.json");
    const FIXTURE_LIST_RUNNING: &str = include_str!("../tests/fixtures/ocijail_list_running.json");
    /// Captured verbatim from `ocijail --root <empty-dir> list -f json`: the
    /// four bytes `null`, no newline, exit 0.
    const FIXTURE_LIST_EMPTY: &str = include_str!("../tests/fixtures/ocijail_list_empty.json");
    const FIXTURE_FEATURES: &str = include_str!("../tests/fixtures/ocijail_features.json");
    const FIXTURE_ERR_NOTFOUND: &str = include_str!("../tests/fixtures/ocijail_err_notfound.txt");
    const FIXTURE_ERR_EXISTS: &str = include_str!("../tests/fixtures/ocijail_err_exists.txt");
    const FIXTURE_ERR_WRONG_STATE: &str =
        include_str!("../tests/fixtures/ocijail_err_wrong_state.txt");
    const FIXTURE_ERR_LIST_NO_STATEDB: &str =
        include_str!("../tests/fixtures/ocijail_err_list_no_statedb.txt");

    fn wrapper(mock: &MockRunner) -> Ocijail<&MockRunner> {
        Ocijail::with_runner(mock, "/var/run/satld/ocijail", "/var/run/satld/exec")
    }

    fn exec_spec() -> ProcessSpec {
        ProcessSpec {
            terminal: false,
            user: None,
            args: vec!["/bin/sh".to_owned(), "-c".to_owned(), "exit 7".to_owned()],
            env: vec!["PATH=/bin".to_owned()],
            cwd: "/".to_owned(),
        }
    }

    // ---- argv builders ----------------------------------------------------

    #[test]
    fn argv_create_with_and_without_console_socket() {
        let root = Path::new("/var/run/satld/ocijail");
        assert_eq!(
            args_create(root, Path::new("/b/t1"), Path::new("/b/t1/pid"), None, "t1"),
            [
                "--root",
                "/var/run/satld/ocijail",
                "create",
                "-b",
                "/b/t1",
                "--pid-file",
                "/b/t1/pid",
                "t1"
            ]
        );
        assert_eq!(
            args_create(
                root,
                Path::new("/b/t1"),
                Path::new("/b/t1/pid"),
                Some(Path::new("/b/t1/console.sock")),
                "t1"
            )[7..],
            [
                "--console-socket".to_owned(),
                "/b/t1/console.sock".to_owned(),
                "t1".to_owned()
            ]
        );
    }

    #[test]
    fn argv_lifecycle_commands() {
        let root = Path::new("/r");
        assert_eq!(args_start(root, "t1"), ["--root", "/r", "start", "t1"]);
        assert_eq!(
            args_kill(root, "t1", 15),
            ["--root", "/r", "kill", "t1", "15"]
        );
        assert_eq!(
            args_kill(root, "t1", 9),
            ["--root", "/r", "kill", "t1", "9"]
        );
        assert_eq!(
            args_delete(root, "t1", false),
            ["--root", "/r", "delete", "t1"]
        );
        assert_eq!(
            args_delete(root, "t1", true),
            ["--root", "/r", "delete", "--force", "t1"]
        );
        assert_eq!(args_state(root, "t1"), ["--root", "/r", "state", "t1"]);
        assert_eq!(args_list(root), ["--root", "/r", "list", "-f", "json"]);
        assert_eq!(args_features(root), ["--root", "/r", "features"]);
        assert_eq!(
            args_exec(
                root,
                "t1",
                Path::new("/s/p.json"),
                true,
                Some(Path::new("/s/pid"))
            ),
            [
                "--root",
                "/r",
                "exec",
                "--process",
                "/s/p.json",
                "--detach",
                "--pid-file",
                "/s/pid",
                "t1"
            ]
        );
    }

    #[test]
    fn id_validation() {
        assert!(validate_id("1hvy0lj3x0b883f8e30fyp217").is_ok());
        assert!(validate_id("rtest-abc_1").is_ok());
        assert!(validate_id("").is_err());
        assert!(validate_id("a.b").is_err()); // jail hierarchy
        assert!(validate_id("a b").is_err());
        assert!(validate_id("-x").is_err());
        assert!(validate_id("a/b").is_err());
    }

    // ---- parsers against real captured fixtures ---------------------------

    #[test]
    fn parse_state_created_running_stopped() {
        let created: RuntimeState = serde_json::from_str(FIXTURE_STATE_CREATED.trim()).unwrap();
        assert_eq!(created.id, "expm1-happy");
        assert_eq!(created.status, RuntimeStatus::Created);
        assert_eq!(created.pid, Some(69307));
        assert_eq!(created.jid(), Some(40));
        assert_eq!(created.oci_version, "1.0.2");
        assert_eq!(
            created.bundle,
            PathBuf::from("/home/fralix/src/satl/hack/experiments/ocijail/bundles/happy")
        );

        let running: RuntimeState = serde_json::from_str(FIXTURE_STATE_RUNNING.trim()).unwrap();
        assert_eq!(running.status, RuntimeStatus::Running);
        assert_eq!(running.pid, Some(69307));

        // Stopped state has no pid at all.
        let stopped: RuntimeState = serde_json::from_str(FIXTURE_STATE_STOPPED.trim()).unwrap();
        assert_eq!(stopped.status, RuntimeStatus::Stopped);
        assert_eq!(stopped.pid, None);
        assert_eq!(stopped.jid(), Some(40));
    }

    #[test]
    fn parse_state_round_trips_annotations() {
        let vnet: RuntimeState = serde_json::from_str(FIXTURE_STATE_VNET.trim()).unwrap();
        assert_eq!(vnet.jid(), Some(51));
        assert_eq!(
            vnet.annotations
                .get(crate::spec::ANNOTATION_VNET)
                .map(String::as_str),
            Some("new")
        );
    }

    #[test]
    fn parse_features() {
        let features: Features = serde_json::from_str(FIXTURE_FEATURES.trim()).unwrap();
        assert!(features.hooks.contains(&"poststop".to_owned()));
        assert!(features.mount_options.contains(&"tmpcopyup".to_owned()));
        assert_eq!(features.oci_version_min, "1.0.0");
        // Underreported — never gate on this (docs/ocijail.md §1.5).
        assert_eq!(features.oci_version_max, "1.2.0");
    }

    #[test]
    fn timestamp_stripping() {
        assert_eq!(
            strip_timestamp(
                "2026-08-09T19:38:23000627007Z: delete: container not in \"stopped\" or \"created\" state (currently \"running\")"
            ),
            "delete: container not in \"stopped\" or \"created\" state (currently \"running\")"
        );
        assert_eq!(strip_timestamp("no timestamp here"), "no timestamp here");
    }

    // ---- wrapper behavior with the mock runner -----------------------------

    #[tokio::test]
    async fn state_parses_and_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_STATE_RUNNING, "");
        let oci = wrapper(&mock);
        let state = oci.state("expm1-happy").await.unwrap();
        assert_eq!(state.status, RuntimeStatus::Running);
        assert_eq!(
            mock.calls(),
            ["/usr/local/bin/ocijail --root /var/run/satld/ocijail state expm1-happy"]
        );
    }

    #[tokio::test]
    async fn unknown_id_maps_to_not_found() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_ERR_NOTFOUND);
        let oci = wrapper(&mock);
        let err = oci.state("expm1-does-not-exist").await.unwrap_err();
        assert!(err.is_not_found(), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("expm1-does-not-exist"), "{msg}");
        assert!(msg.contains("state expm1-does-not-exist"), "{msg}");
    }

    #[tokio::test]
    async fn create_reads_pid_file_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        std::fs::write(&pid_file, "69307\n").unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let oci = wrapper(&mock);
        let pid = oci
            .create(
                "t1",
                Path::new("/b/t1"),
                &pid_file,
                None,
                CreateStdio::null(),
            )
            .await
            .unwrap();
        assert_eq!(pid, 69307);
        assert!(
            mock.calls()[0].contains("create -b /b/t1 --pid-file"),
            "{:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn create_rejects_relative_bundle_and_bad_id() {
        let mock = MockRunner::new();
        let oci = wrapper(&mock);
        let err = oci
            .create(
                "t1",
                Path::new("bundles/t1"),
                Path::new("/p"),
                None,
                CreateStdio::null(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, OcijailError::BundleNotAbsolute { .. }),
            "{err}"
        );
        let err = oci
            .create(
                "t.1",
                Path::new("/b"),
                Path::new("/p"),
                None,
                CreateStdio::null(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OcijailError::InvalidId { .. }), "{err}");
        assert!(mock.calls().is_empty()); // nothing was executed
    }

    #[tokio::test]
    async fn create_duplicate_reads_error_back_from_stderr_sink() {
        let dir = tempfile::tempdir().unwrap();
        let sink_path = dir.path().join("stderr.log");
        // Log sinks are opened read+write so error text can be read back.
        let sink = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&sink_path)
            .unwrap();
        let mock = MockRunner::new();
        mock.push_stdio_output(1, FIXTURE_ERR_EXISTS);
        let oci = wrapper(&mock);
        let err = oci
            .create(
                "expm1-dup",
                Path::new("/b/dup"),
                &dir.path().join("pid"),
                None,
                CreateStdio {
                    stdin: StdioSink::Null,
                    stdout: StdioSink::Null,
                    stderr: StdioSink::File(sink),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OcijailError::AlreadyExists { .. }), "{err}");
        // The sink still holds the raw text for the operator.
        assert!(
            std::fs::read_to_string(&sink_path)
                .unwrap()
                .contains("container expm1-dup exists")
        );
    }

    #[tokio::test]
    async fn create_child_validation_error_carries_sink_text() {
        let dir = tempfile::tempdir().unwrap();
        let sink = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("stderr.log"))
            .unwrap();
        let mock = MockRunner::new();
        // Raw create-child message: no timestamp (docs/ocijail.md §6).
        mock.push_stdio_output(1, "/bin/no-such-binary: No such file or directory\n");
        let oci = wrapper(&mock);
        let err = oci
            .create(
                "t1",
                Path::new("/b/t1"),
                &dir.path().join("pid"),
                None,
                CreateStdio {
                    stdin: StdioSink::Null,
                    stdout: StdioSink::Null,
                    stderr: StdioSink::File(sink),
                },
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, OcijailError::CommandFailed { .. }), "{msg}");
        assert!(msg.contains("no-such-binary"), "{msg}");
        assert!(msg.contains("exit code 1"), "{msg}");
    }

    #[tokio::test]
    async fn delete_of_unknown_id_is_ok_by_design() {
        // docs/ocijail.md §4.3: exit 0, cleans nothing — Runtime::delete
        // compensates with the mount sweep.
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let oci = wrapper(&mock);
        oci.delete("never-existed", false).await.unwrap();
    }

    #[tokio::test]
    async fn delete_running_without_force_is_wrong_state() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "2026-08-09T19:38:23000627007Z: delete: container not in \"stopped\" or \"created\" state (currently \"running\")\n",
        );
        let oci = wrapper(&mock);
        let err = oci.delete("t1", false).await.unwrap_err();
        match &err {
            OcijailError::WrongState { message, .. } => {
                assert_eq!(
                    message,
                    "delete: container not in \"stopped\" or \"created\" state (currently \"running\")"
                );
            }
            other => panic!("expected WrongState, got {other}"),
        }
    }

    #[tokio::test]
    async fn start_wrong_state_uses_fixture_text() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_ERR_WRONG_STATE);
        let oci = wrapper(&mock);
        let err = oci.start("expm1-fail").await.unwrap_err();
        assert!(matches!(err, OcijailError::WrongState { .. }), "{err}");
    }

    #[tokio::test]
    async fn usage_error_is_flagged_as_wrapper_bug() {
        let mock = MockRunner::new();
        mock.push_output(
            106,
            "",
            "--process is required\nRun with --help for more information.\n",
        );
        let oci = wrapper(&mock);
        let err = oci.start("t1").await.unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, OcijailError::UsageError { .. }), "{msg}");
        assert!(msg.contains("satl-runtime bug"), "{msg}");
    }

    #[tokio::test]
    async fn list_parses_rows_and_maps_missing_statedb_to_empty() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_RUNNING, "");
        mock.push_output(1, "", FIXTURE_ERR_LIST_NO_STATEDB);
        let oci = wrapper(&mock);
        let rows = oci.list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "expm1-happy");
        assert_eq!(rows[0].pid, Some(69307));
        assert_eq!(rows[0].status, RuntimeStatus::Running);
        assert_eq!(oci.list().await.unwrap(), Vec::new());
    }

    /// An existing but empty state db prints `null`, not `[]`. That is the
    /// every-startup case on a node with no containers, so it must be the
    /// empty list it means and never an error — a routine ERROR line is how a
    /// log stops being read.
    #[tokio::test]
    async fn an_empty_state_db_prints_null_and_means_no_containers() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_EMPTY, "");
        // A future ocijail that printed a real empty array must work too.
        mock.push_output(0, "[]", "");
        let oci = wrapper(&mock);
        assert_eq!(oci.list().await.unwrap(), Vec::new());
        assert_eq!(oci.list().await.unwrap(), Vec::new());
    }

    /// ...and output that is neither is still a failure, carrying the argv and
    /// the raw stdout an operator needs. Swallowing `null` must not become
    /// swallowing garbage.
    #[tokio::test]
    async fn malformed_list_output_is_still_an_error() {
        let mock = MockRunner::new();
        mock.push_output(0, "{\"id\":\"t1\"}", "");
        mock.push_output(0, "not json at all", "");
        let oci = wrapper(&mock);
        for _ in 0..2 {
            let err = oci.list().await.unwrap_err();
            let message = err.to_string();
            assert!(
                matches!(err, OcijailError::UnexpectedOutput { .. }),
                "{message}"
            );
            assert!(message.contains("list -f json"), "{message}");
            assert!(message.contains("raw stdout"), "{message}");
        }
    }

    #[tokio::test]
    async fn exec_returns_the_process_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(7, "", "");
        let oci = Ocijail::with_runner(&mock, "/r", dir.path());
        let outcome = oci
            .exec("t1", &exec_spec(), CreateStdio::null())
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        let call = &mock.calls()[0];
        assert!(call.contains("exec --process"), "{call}");
        assert!(call.contains(&dir.path().display().to_string()), "{call}");
        assert!(call.ends_with(" t1"), "{call}");
        // The transient process.json is removed again.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn exec_detached_returns_pid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("exec.pid");
        std::fs::write(&pid_file, "69588").unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let oci = Ocijail::with_runner(&mock, "/r", dir.path().join("scratch"));
        let pid = oci
            .exec_detached("t1", &exec_spec(), CreateStdio::null(), &pid_file)
            .await
            .unwrap();
        assert_eq!(pid, 69588);
        assert!(
            mock.calls()[0].contains("--detach --pid-file"),
            "{:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let oci = wrapper(&mock);
        let err = oci.start("t1").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("start t1"), "{msg}");
        assert!(msg.contains("no such file"), "{msg}");
    }
}
