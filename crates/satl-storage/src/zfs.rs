// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around the `zfs`(8) command-line tool (M0 subset).
//!
//! Design rules (CLAUDE.md, "External command wrappers"):
//!
//! - No raw `Command::new` in business logic — everything goes through [`Zfs`].
//! - Process execution is injectable via [`CommandRunner`] so command
//!   construction and output parsing are unit-testable without privileges.
//! - Parsing lives in pure sync functions, tested against fixtures captured
//!   from a real FreeBSD host (`tests/fixtures/`).
//! - Every error carries the full argv that was run, the exit status, and the
//!   raw stderr: an operator reading the log must see exactly what `zfs`
//!   command was attempted and what it said.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

/// Default location of the `zfs` binary on FreeBSD.
pub const DEFAULT_ZFS_BINARY: &str = "/sbin/zfs";

/// Captured result of running an external command to completion.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Exit code; `None` when the process was terminated by a signal.
    pub exit_code: Option<i32>,
    /// Raw stdout, lossily decoded as UTF-8.
    pub stdout: String,
    /// Raw stderr, lossily decoded as UTF-8.
    pub stderr: String,
}

impl CommandOutput {
    fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Executes external commands. The real implementation is [`SystemRunner`];
/// tests inject a recording mock so no privileges (or `zfs` binary) are
/// needed to exercise the wrapper logic.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` to completion, capturing stdout and stderr.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when the process could not be spawned at all
    /// (binary missing, permission denied, ...).
    fn run(
        &self,
        program: &Path,
        args: &[String],
    ) -> impl Future<Output = io::Result<CommandOutput>> + Send;
}

/// [`CommandRunner`] that actually executes processes via [`tokio::process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        let output = match tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                satl_metrics::record_command_failure_for(program);
                return Err(error);
            }
        };
        let output = CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if !output.success() {
            satl_metrics::record_command_failure_for(program);
        }
        Ok(output)
    }
}

/// Error from a `zfs`(8) invocation.
///
/// Display output always includes the full command line and, where a process
/// ran, its exit status and raw stderr — this is an SRE tool, the operator
/// must be able to re-run and debug the exact command that failed.
#[derive(Debug, thiserror::Error)]
pub enum ZfsError {
    /// The `zfs` binary could not be spawned.
    #[error("failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("`{argv}` failed with {status}; stderr: {stderr}", status = render_exit(*exit_code), stderr = render_raw(stderr))]
    CommandFailed {
        /// Full rendered command line.
        argv: String,
        /// Exit code; `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr from the command.
        stderr: String,
    },

    /// The command succeeded but its output did not have the expected shape.
    #[error("unexpected output from `{argv}` ({status}): {reason}; raw stdout: {out}; raw stderr: {err}", status = render_exit(*exit_code), out = render_raw(stdout), err = render_raw(stderr))]
    UnexpectedOutput {
        /// Full rendered command line.
        argv: String,
        /// Exit code of the (successful) command.
        exit_code: Option<i32>,
        /// Why the output was rejected.
        reason: String,
        /// Raw stdout from the command.
        stdout: String,
        /// Raw stderr from the command.
        stderr: String,
    },

    /// A dataset exists but has no filesystem mountpoint (`none` or `legacy`).
    #[error(
        "dataset '{dataset}' has no usable mountpoint (mountpoint={value}, from `{argv}`); \
         set one with: zfs set mountpoint=<path> {dataset}"
    )]
    NotMounted {
        /// Dataset that was queried.
        dataset: String,
        /// The literal `mountpoint` property value (`none`, `legacy`, or `-`).
        value: String,
        /// Full rendered command line used to query the property.
        argv: String,
    },
}

impl ZfsError {
    /// Whether this failure is `zfs` saying the dataset simply is not there.
    ///
    /// The distinction a caller needs: "the node has no layers yet" is not the
    /// same event as "the pool is broken", and a sweep that treats the first as
    /// an error reports trouble on every fresh node.
    #[must_use]
    pub fn is_missing_dataset(&self) -> bool {
        match self {
            Self::CommandFailed { stderr, .. } => stderr_says_dataset_missing(stderr),
            _ => false,
        }
    }

    /// Whether this failure is `zfs` refusing because something has the
    /// dataset (or its mountpoint) open **right now**.
    ///
    /// The distinction a caller needs: "in use at this instant" is a state
    /// that ends by itself, where every other refusal does not. A destroy
    /// that treats the two alike either fails work that would have succeeded
    /// a second later, or retries for ever on something that will never
    /// change.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        match self {
            Self::CommandFailed { stderr, .. } => stderr_says_busy(stderr),
            _ => false,
        }
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

/// Render a program + args as a single shell-like command line for error
/// messages and logs. Arguments containing whitespace are quoted.
pub(crate) fn render_argv(program: &Path, args: &[String]) -> String {
    let mut line = program.display().to_string();
    for arg in args {
        line.push(' ');
        if arg.is_empty() || arg.chars().any(char::is_whitespace) {
            // Infallible: fmt::Write on String never errors.
            let _ = write!(line, "{arg:?}");
        } else {
            line.push_str(arg);
        }
    }
    line
}

/// One row of `zfs list -H -p -o name,mountpoint` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetInfo {
    /// Fully qualified dataset name (e.g. `zroot/satl/layers`).
    pub name: String,
    /// Filesystem mountpoint; `None` when the property is `none`, `legacy`,
    /// or `-` (no filesystem path to use).
    pub mountpoint: Option<PathBuf>,
}

/// One row of `zfs list -H -p -r -d 2 -t filesystem,snapshot -o name,origin,used`
/// output — a dataset *or* one of its snapshots, with the space it is charged.
///
/// The layer GC needs all three columns in one reading: `origin` is the clone
/// edge that says which layer a dataset was built on, the snapshot rows are how
/// `@final` is observed, and `used` is what a sweep reports having freed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetSpace {
    /// Fully qualified dataset or snapshot name.
    pub name: String,
    /// The snapshot this dataset was cloned from; `None` (printed as `-`) when
    /// it is not a clone. Always `None` on a snapshot row.
    pub origin: Option<String>,
    /// Bytes `zfs list -p -o used` charges to this dataset or snapshot.
    pub used: u64,
}

/// One row of `zfs list -H -p -r -o name,origin,mountpoint` output.
///
/// Used by startup reconciliation to tell clones (layer/container datasets,
/// `origin = Some(...)`) apart from plain filesystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetOriginInfo {
    /// Fully qualified dataset name (e.g. `zroot/satl/containers/task1`).
    pub name: String,
    /// The snapshot this dataset was cloned from; `None` (printed as `-`)
    /// when the dataset is not a clone.
    pub origin: Option<String>,
    /// Filesystem mountpoint; `None` when `none`, `legacy`, or `-`.
    pub mountpoint: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Pure argv builders — unit-tested without executing anything.
// ---------------------------------------------------------------------------

fn args_dataset_exists(name: &str) -> Vec<String> {
    ["list", "-H", "-o", "name", name]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_get_property(dataset: &str, property: &str) -> Vec<String> {
    ["get", "-H", "-p", "-o", "value", property, dataset]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_list_children(dataset: &str) -> Vec<String> {
    [
        "list",
        "-H",
        "-p",
        "-r",
        "-d",
        "1",
        "-o",
        "name,mountpoint",
        dataset,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn args_create(name: &str, options: &[(&str, &str)]) -> Vec<String> {
    let mut args = vec!["create".to_owned()];
    for (key, value) in options {
        args.push("-o".to_owned());
        args.push(format!("{key}={value}"));
    }
    args.push(name.to_owned());
    args
}

fn args_snapshot(dataset: &str, name: &str) -> Vec<String> {
    vec!["snapshot".to_owned(), format!("{dataset}@{name}")]
}

fn args_clone(snapshot: &str, target: &str, options: &[(&str, &str)]) -> Vec<String> {
    let mut args = vec!["clone".to_owned()];
    for (key, value) in options {
        args.push("-o".to_owned());
        args.push(format!("{key}={value}"));
    }
    args.push(snapshot.to_owned());
    args.push(target.to_owned());
    args
}

fn args_destroy(name: &str, recursive: bool) -> Vec<String> {
    let mut args = vec!["destroy".to_owned()];
    if recursive {
        args.push("-r".to_owned());
    }
    args.push(name.to_owned());
    args
}

fn args_list_filesystems(root: &str) -> Vec<String> {
    [
        "list",
        "-H",
        "-p",
        "-r",
        "-t",
        "filesystem",
        "-o",
        "name,mountpoint",
        root,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// `-d 2` because a layer store is exactly two levels deep: the layer datasets
/// are children of the root and their `@final` snapshots are children of those.
/// Both `-t` types in one invocation so the snapshot that proves a layer is
/// fully applied cannot be read at a different moment from the dataset itself.
fn args_list_space(root: &str) -> Vec<String> {
    [
        "list",
        "-H",
        "-p",
        "-r",
        "-d",
        "2",
        "-t",
        "filesystem,snapshot",
        "-o",
        "name,origin,used",
        root,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn args_list_with_origin(root: &str) -> Vec<String> {
    [
        "list",
        "-H",
        "-p",
        "-r",
        "-o",
        "name,origin,mountpoint",
        root,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

// ---------------------------------------------------------------------------
// Pure output parsers — unit-tested against fixtures of real zfs output.
// ---------------------------------------------------------------------------

/// `zfs list`/`zfs get` prints `cannot open '<name>': dataset does not exist`
/// on stderr (exit code 1) for a missing dataset.
fn stderr_says_dataset_missing(stderr: &str) -> bool {
    stderr.contains("does not exist")
}

/// `zfs destroy` prints `cannot unmount '<mountpoint>': pool or dataset is
/// busy` (exit code 1) while a process still has the mountpoint open, and
/// `cannot destroy '<dataset>': dataset is busy` for a held dataset. Both
/// carry the same tail.
///
/// Deliberately narrow. `filesystem has dependent clones` is the *other*
/// refusal a layer dataset draws, it means a container rootfs was cloned from
/// this layer, and it must stay fatal: waiting would never help and
/// destroying anyway is not on offer.
fn stderr_says_busy(stderr: &str) -> bool {
    stderr.contains("dataset is busy")
}

/// Parse output expected to be exactly one non-empty line (e.g.
/// `zfs get -H -p -o value <prop> <dataset>`).
fn parse_single_value(stdout: &str) -> Result<String, String> {
    let mut lines = stdout.lines();
    let Some(value) = lines.next() else {
        return Err("expected one line of output, got none".to_owned());
    };
    if lines.next().is_some() {
        return Err("expected exactly one line of output, got more".to_owned());
    }
    Ok(value.to_owned())
}

/// Parse the `mountpoint` property value into an optional path.
/// `none`, `legacy` and `-` mean "no filesystem mountpoint".
fn parse_mountpoint_value(value: &str) -> Option<PathBuf> {
    match value {
        "none" | "legacy" | "-" => None,
        path => Some(PathBuf::from(path)),
    }
}

/// Parse `zfs list -H -p -o name,mountpoint` output: one dataset per line,
/// tab-separated columns.
fn parse_name_mountpoint_table(stdout: &str) -> Result<Vec<DatasetInfo>, String> {
    let mut rows = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((name, mountpoint)) = line.split_once('\t') else {
            return Err(format!(
                "expected tab-separated `name<TAB>mountpoint`, got line {line:?}"
            ));
        };
        rows.push(DatasetInfo {
            name: name.to_owned(),
            mountpoint: parse_mountpoint_value(mountpoint),
        });
    }
    Ok(rows)
}

/// Parse the `origin` property value into an option. `-` means "not a clone".
fn parse_origin_value(value: &str) -> Option<String> {
    match value {
        "-" => None,
        origin => Some(origin.to_owned()),
    }
}

/// Parse `zfs list -H -p -r -d 2 -t filesystem,snapshot -o name,origin,used`
/// output: one dataset or snapshot per line, tab-separated columns.
fn parse_name_origin_used_table(stdout: &str) -> Result<Vec<DatasetSpace>, String> {
    let mut rows = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let mut columns = line.splitn(3, '\t');
        let (Some(name), Some(origin), Some(used)) =
            (columns.next(), columns.next(), columns.next())
        else {
            return Err(format!(
                "expected tab-separated `name<TAB>origin<TAB>used`, got line {line:?}"
            ));
        };
        // `-p` makes `used` an exact byte count; anything else means the flag
        // was lost and every size downstream would be wrong by 1024^n.
        let used = used.parse::<u64>().map_err(|_| {
            format!("expected `used` in bytes (zfs list -p), got {used:?} on line {line:?}")
        })?;
        rows.push(DatasetSpace {
            name: name.to_owned(),
            origin: parse_origin_value(origin),
            used,
        });
    }
    Ok(rows)
}

/// Parse `zfs list -H -p -r -o name,origin,mountpoint` output: one dataset
/// per line, tab-separated columns.
fn parse_name_origin_mountpoint_table(stdout: &str) -> Result<Vec<DatasetOriginInfo>, String> {
    let mut rows = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let mut columns = line.splitn(3, '\t');
        let (Some(name), Some(origin), Some(mountpoint)) =
            (columns.next(), columns.next(), columns.next())
        else {
            return Err(format!(
                "expected tab-separated `name<TAB>origin<TAB>mountpoint`, got line {line:?}"
            ));
        };
        rows.push(DatasetOriginInfo {
            name: name.to_owned(),
            origin: parse_origin_value(origin),
            mountpoint: parse_mountpoint_value(mountpoint),
        });
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around the `zfs`(8) binary.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock executor;
/// production code uses [`Zfs::system`].
#[derive(Debug, Clone)]
pub struct Zfs<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Zfs<SystemRunner> {
    /// Wrapper that executes the real `zfs` binary at [`DEFAULT_ZFS_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Zfs<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Zfs<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_ZFS_BINARY),
            runner,
        }
    }

    /// Override the path of the `zfs` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Run `zfs` with `args`; returns the rendered argv and captured output.
    /// Only spawn failures are errors here — callers interpret exit codes.
    async fn exec(&self, args: Vec<String>) -> Result<(String, CommandOutput), ZfsError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running zfs");
        let output = self
            .runner
            .run(&self.binary, &args)
            .await
            .map_err(|source| ZfsError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Whether `name` exists as a ZFS dataset.
    ///
    /// Runs `zfs list -H -o name <name>`; exit code 1 with a
    /// "does not exist" diagnostic maps to `Ok(false)`.
    pub async fn dataset_exists(&self, name: &str) -> Result<bool, ZfsError> {
        let (argv, output) = self.exec(args_dataset_exists(name)).await?;
        if output.success() {
            return Ok(true);
        }
        if output.exit_code == Some(1) && stderr_says_dataset_missing(&output.stderr) {
            return Ok(false);
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Read a single property value:
    /// `zfs get -H -p -o value <property> <dataset>`.
    pub async fn get_property(&self, dataset: &str, property: &str) -> Result<String, ZfsError> {
        let (argv, output) = self.exec(args_get_property(dataset, property)).await?;
        if !output.success() {
            return Err(ZfsError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_single_value(&output.stdout).map_err(|reason| ZfsError::UnexpectedOutput {
            argv,
            exit_code: output.exit_code,
            reason,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    /// List the direct children of `dataset` (the dataset itself is not
    /// included): `zfs list -H -p -r -d 1 -o name,mountpoint <dataset>`.
    pub async fn list_children(&self, dataset: &str) -> Result<Vec<DatasetInfo>, ZfsError> {
        let (argv, output) = self.exec(args_list_children(dataset)).await?;
        if !output.success() {
            return Err(ZfsError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        let rows = parse_name_mountpoint_table(&output.stdout).map_err(|reason| {
            ZfsError::UnexpectedOutput {
                argv,
                exit_code: output.exit_code,
                reason,
                stdout: output.stdout.clone(),
                stderr: output.stderr.clone(),
            }
        })?;
        // `-d 1` includes the dataset itself as the first row; drop it.
        Ok(rows.into_iter().filter(|row| row.name != dataset).collect())
    }

    /// Create a dataset: `zfs create [-o key=value]... <name>`.
    ///
    /// Deliberately no `-p`: intermediate datasets must exist already — the
    /// preflight creates each level explicitly so ownership stays clear.
    pub async fn create(&self, name: &str, options: &[(&str, &str)]) -> Result<(), ZfsError> {
        let (argv, output) = self.exec(args_create(name, options)).await?;
        if output.success() {
            tracing::info!(dataset = %name, "created zfs dataset");
            return Ok(());
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Whether the snapshot `dataset@name` exists.
    ///
    /// Naming a snapshot explicitly works with plain `zfs list` (verified on
    /// FreeBSD 15.1; see `tests/fixtures/zfs_list_snapshot_*.txt`), so this
    /// reuses the [`Zfs::dataset_exists`] probe.
    pub async fn snapshot_exists(&self, dataset: &str, name: &str) -> Result<bool, ZfsError> {
        self.dataset_exists(&format!("{dataset}@{name}")).await
    }

    /// Take a snapshot: `zfs snapshot <dataset>@<name>`.
    pub async fn snapshot(&self, dataset: &str, name: &str) -> Result<(), ZfsError> {
        let (argv, output) = self.exec(args_snapshot(dataset, name)).await?;
        if output.success() {
            tracing::info!(dataset = %dataset, snapshot = %name, "created zfs snapshot");
            return Ok(());
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Clone a snapshot into a new dataset:
    /// `zfs clone [-o key=value]... <snapshot> <target>`.
    ///
    /// (Named `clone_snapshot` rather than `clone` so it cannot shadow
    /// `Clone::clone` on this `#[derive(Clone)]` type.)
    pub async fn clone_snapshot(
        &self,
        snapshot: &str,
        target: &str,
        options: &[(&str, &str)],
    ) -> Result<(), ZfsError> {
        let (argv, output) = self.exec(args_clone(snapshot, target, options)).await?;
        if output.success() {
            tracing::info!(snapshot = %snapshot, dataset = %target, "cloned zfs snapshot");
            return Ok(());
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Destroy a dataset: `zfs destroy [-r] <dataset>`.
    ///
    /// `recursive` adds `-r` (destroy children and snapshots too).
    pub async fn destroy(&self, dataset: &str, recursive: bool) -> Result<(), ZfsError> {
        let (argv, output) = self.exec(args_destroy(dataset, recursive)).await?;
        if output.success() {
            tracing::info!(dataset = %dataset, recursive, "destroyed zfs dataset");
            return Ok(());
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Destroy a single snapshot: `zfs destroy <dataset>@<name>`.
    pub async fn destroy_snapshot(&self, dataset: &str, name: &str) -> Result<(), ZfsError> {
        let snapshot = format!("{dataset}@{name}");
        let (argv, output) = self.exec(args_destroy(&snapshot, false)).await?;
        if output.success() {
            tracing::info!(snapshot = %snapshot, "destroyed zfs snapshot");
            return Ok(());
        }
        Err(ZfsError::CommandFailed {
            argv,
            exit_code: output.exit_code,
            stderr: output.stderr,
        })
    }

    /// Recursively list all filesystems under (and including) `root`:
    /// `zfs list -H -p -r -t filesystem -o name,mountpoint <root>`.
    pub async fn list_filesystems(&self, root: &str) -> Result<Vec<DatasetInfo>, ZfsError> {
        let (argv, output) = self.exec(args_list_filesystems(root)).await?;
        if !output.success() {
            return Err(ZfsError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_name_mountpoint_table(&output.stdout).map_err(|reason| ZfsError::UnexpectedOutput {
            argv,
            exit_code: output.exit_code,
            reason,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        })
    }

    /// Every dataset and snapshot at most two levels under `root`, with its
    /// clone origin and the bytes it is charged:
    /// `zfs list -H -p -r -d 2 -t filesystem,snapshot -o name,origin,used <root>`.
    ///
    /// One invocation on purpose — the layer GC decides what to destroy from
    /// this reading, and a dataset read in one pass with its `@final` snapshot
    /// read in another is exactly how a live layer gets mistaken for a
    /// half-applied one.
    ///
    /// # Errors
    ///
    /// [`ZfsError::CommandFailed`] when `zfs` fails, [`ZfsError::UnexpectedOutput`]
    /// when a row is not `name<TAB>origin<TAB>used` with `used` in bytes.
    pub async fn list_space(&self, root: &str) -> Result<Vec<DatasetSpace>, ZfsError> {
        let (argv, output) = self.exec(args_list_space(root)).await?;
        if !output.success() {
            return Err(ZfsError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_name_origin_used_table(&output.stdout).map_err(|reason| ZfsError::UnexpectedOutput {
            argv,
            exit_code: output.exit_code,
            reason,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        })
    }

    /// Recursively list all datasets under (and including) `root` with their
    /// clone origin: `zfs list -H -p -r -o name,origin,mountpoint <root>`.
    ///
    /// Startup reconciliation uses the `origin` column to identify layer and
    /// container clones.
    pub async fn list_with_origin(&self, root: &str) -> Result<Vec<DatasetOriginInfo>, ZfsError> {
        let (argv, output) = self.exec(args_list_with_origin(root)).await?;
        if !output.success() {
            return Err(ZfsError::CommandFailed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        parse_name_origin_mountpoint_table(&output.stdout).map_err(|reason| {
            ZfsError::UnexpectedOutput {
                argv,
                exit_code: output.exit_code,
                reason,
                stdout: output.stdout.clone(),
                stderr: output.stderr.clone(),
            }
        })
    }

    /// The filesystem mountpoint of `dataset`.
    ///
    /// Fails with [`ZfsError::NotMounted`] when the `mountpoint` property is
    /// `none`, `legacy`, or `-`.
    pub async fn mountpoint_of(&self, dataset: &str) -> Result<PathBuf, ZfsError> {
        let value = self.get_property(dataset, "mountpoint").await?;
        parse_mountpoint_value(&value).ok_or_else(|| ZfsError::NotMounted {
            dataset: dataset.to_owned(),
            value,
            argv: render_argv(&self.binary, &args_get_property(dataset, "mountpoint")),
        })
    }
}

// ---------------------------------------------------------------------------
// Test support: a CommandRunner that records argv and replays canned outputs.
// ---------------------------------------------------------------------------

/// Mock [`CommandRunner`] for unit tests: records every rendered argv and
/// pops pre-loaded responses in FIFO order.
#[cfg(test)]
pub(crate) struct MockRunner {
    responses: std::sync::Mutex<std::collections::VecDeque<io::Result<CommandOutput>>>,
    calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl MockRunner {
    pub(crate) fn new() -> Self {
        Self {
            responses: std::sync::Mutex::new(std::collections::VecDeque::new()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn push_output(&self, exit_code: i32, stdout: &str, stderr: &str) {
        self.responses.lock().unwrap().push_back(Ok(CommandOutput {
            exit_code: Some(exit_code),
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }));
    }

    pub(crate) fn push_spawn_error(&self, kind: io::ErrorKind, message: &str) {
        self.responses
            .lock()
            .unwrap()
            .push_back(Err(io::Error::new(kind, message.to_owned())));
    }

    /// Rendered command lines of every call made so far.
    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl CommandRunner for &MockRunner {
    async fn run(&self, program: &Path, args: &[String]) -> io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(render_argv(program, args));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("MockRunner: unexpected call {}", render_argv(program, args)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_LIST_EXISTS: &str = include_str!("../tests/fixtures/zfs_list_name_exists.txt");
    const FIXTURE_LIST_MISSING: &str = include_str!("../tests/fixtures/zfs_list_name_missing.txt");
    const FIXTURE_GET_MOUNTPOINT: &str = include_str!("../tests/fixtures/zfs_get_mountpoint.txt");
    const FIXTURE_GET_MOUNTPOINT_NONE: &str =
        include_str!("../tests/fixtures/zfs_get_mountpoint_legacy.txt");
    const FIXTURE_GET_COMPRESSION: &str = include_str!("../tests/fixtures/zfs_get_compression.txt");
    const FIXTURE_CHILDREN: &str = include_str!("../tests/fixtures/zfs_list_children.txt");
    const FIXTURE_CHILDREN_MIXED: &str =
        include_str!("../tests/fixtures/zfs_list_children_mixed.txt");
    const FIXTURE_LIST_WITH_ORIGIN: &str =
        include_str!("../tests/fixtures/zfs_list_with_origin.txt");
    const FIXTURE_SPACE_LAYERS: &str = include_str!("../tests/fixtures/zfs_list_space_layers.txt");
    const FIXTURE_SPACE_STACKED: &str =
        include_str!("../tests/fixtures/zfs_list_space_stacked.txt");
    const FIXTURE_SNAPSHOT_EXISTS: &str =
        include_str!("../tests/fixtures/zfs_list_snapshot_exists.txt");
    const FIXTURE_SNAPSHOT_MISSING: &str =
        include_str!("../tests/fixtures/zfs_list_snapshot_missing.txt");

    // ---- argv builders ----------------------------------------------------

    #[test]
    fn argv_dataset_exists() {
        assert_eq!(
            args_dataset_exists("zroot/satl"),
            ["list", "-H", "-o", "name", "zroot/satl"]
        );
    }

    #[test]
    fn argv_get_property() {
        assert_eq!(
            args_get_property("zroot/satl", "mountpoint"),
            ["get", "-H", "-p", "-o", "value", "mountpoint", "zroot/satl"]
        );
    }

    #[test]
    fn argv_list_children() {
        assert_eq!(
            args_list_children("zroot/satl"),
            [
                "list",
                "-H",
                "-p",
                "-r",
                "-d",
                "1",
                "-o",
                "name,mountpoint",
                "zroot/satl"
            ]
        );
    }

    #[test]
    fn argv_create_without_options() {
        assert_eq!(
            args_create("zroot/satl/raft", &[]),
            ["create", "zroot/satl/raft"]
        );
    }

    #[test]
    fn argv_create_with_options() {
        assert_eq!(
            args_create(
                "zroot/satl",
                &[("mountpoint", "/var/db/satl"), ("compression", "zstd")]
            ),
            [
                "create",
                "-o",
                "mountpoint=/var/db/satl",
                "-o",
                "compression=zstd",
                "zroot/satl"
            ]
        );
    }

    #[test]
    fn argv_snapshot() {
        assert_eq!(
            args_snapshot("zroot/satl/layers/abc", "final"),
            ["snapshot", "zroot/satl/layers/abc@final"]
        );
    }

    #[test]
    fn argv_clone_without_options() {
        assert_eq!(
            args_clone("zroot/satl/layers/abc@final", "zroot/satl/layers/def", &[]),
            [
                "clone",
                "zroot/satl/layers/abc@final",
                "zroot/satl/layers/def"
            ]
        );
    }

    #[test]
    fn argv_clone_with_options() {
        assert_eq!(
            args_clone(
                "zroot/satl/layers/abc@final",
                "zroot/satl/containers/task1",
                &[("mountpoint", "/var/db/satl/containers/task1")]
            ),
            [
                "clone",
                "-o",
                "mountpoint=/var/db/satl/containers/task1",
                "zroot/satl/layers/abc@final",
                "zroot/satl/containers/task1"
            ]
        );
    }

    #[test]
    fn argv_destroy() {
        assert_eq!(
            args_destroy("zroot/satl/containers/task1", false),
            ["destroy", "zroot/satl/containers/task1"]
        );
        assert_eq!(
            args_destroy("zroot/satl/containers/task1", true),
            ["destroy", "-r", "zroot/satl/containers/task1"]
        );
    }

    #[test]
    fn argv_list_filesystems() {
        assert_eq!(
            args_list_filesystems("zroot/satl"),
            [
                "list",
                "-H",
                "-p",
                "-r",
                "-t",
                "filesystem",
                "-o",
                "name,mountpoint",
                "zroot/satl"
            ]
        );
    }

    #[test]
    fn argv_list_with_origin() {
        assert_eq!(
            args_list_with_origin("zroot/satl"),
            [
                "list",
                "-H",
                "-p",
                "-r",
                "-o",
                "name,origin,mountpoint",
                "zroot/satl"
            ]
        );
    }

    #[test]
    fn argv_rendering_quotes_whitespace() {
        let argv = render_argv(
            Path::new("/sbin/zfs"),
            &["create".to_owned(), "with space".to_owned()],
        );
        assert_eq!(argv, "/sbin/zfs create \"with space\"");
    }

    // ---- parsers against real captured fixtures ---------------------------

    #[test]
    fn parse_existing_dataset_list_output() {
        assert_eq!(parse_single_value(FIXTURE_LIST_EXISTS).unwrap(), "zroot");
    }

    #[test]
    fn missing_dataset_stderr_is_recognized() {
        // Fixture holds the stderr of `zfs list -H -o name <missing>`.
        assert!(stderr_says_dataset_missing(FIXTURE_LIST_MISSING));
        assert!(!stderr_says_dataset_missing(
            "cannot open 'zroot': permission denied"
        ));
    }

    #[test]
    fn parse_mountpoint_property() {
        let value = parse_single_value(FIXTURE_GET_MOUNTPOINT).unwrap();
        assert_eq!(value, "/var");
        assert_eq!(parse_mountpoint_value(&value), Some(PathBuf::from("/var")));
    }

    #[test]
    fn parse_unmounted_mountpoint_property() {
        // zroot/ROOT on the dev host has mountpoint=none.
        let value = parse_single_value(FIXTURE_GET_MOUNTPOINT_NONE).unwrap();
        assert_eq!(value, "none");
        assert_eq!(parse_mountpoint_value(&value), None);
        assert_eq!(parse_mountpoint_value("legacy"), None);
        assert_eq!(parse_mountpoint_value("-"), None);
    }

    #[test]
    fn parse_generic_property_value() {
        assert_eq!(parse_single_value(FIXTURE_GET_COMPRESSION).unwrap(), "off");
    }

    #[test]
    fn parse_single_value_rejects_empty_and_multiline() {
        assert!(parse_single_value("").is_err());
        assert!(parse_single_value("a\nb\n").is_err());
    }

    #[test]
    fn parse_children_table() {
        let rows = parse_name_mountpoint_table(FIXTURE_CHILDREN).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].name, "zroot/usr");
        assert_eq!(rows[0].mountpoint, Some(PathBuf::from("/usr")));
        assert_eq!(rows[3].name, "zroot/usr/src");
        assert_eq!(rows[3].mountpoint, Some(PathBuf::from("/usr/src")));
    }

    #[test]
    fn parse_children_table_with_unmounted_rows() {
        let rows = parse_name_mountpoint_table(FIXTURE_CHILDREN_MIXED).unwrap();
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].name, "zroot");
        assert_eq!(rows[0].mountpoint, None); // mountpoint=none
        assert_eq!(rows[2].name, "zroot/home");
        assert_eq!(rows[2].mountpoint, Some(PathBuf::from("/home")));
    }

    #[test]
    fn parse_children_table_rejects_malformed_line() {
        let err = parse_name_mountpoint_table("no-tab-here\n").unwrap_err();
        assert!(err.contains("no-tab-here"));
    }

    #[test]
    fn parse_origin_table() {
        // Fixture captured from a real clone tree on FreeBSD 15.1
        // (zroot/satl-agenttest, created and destroyed for the capture).
        let rows = parse_name_origin_mountpoint_table(FIXTURE_LIST_WITH_ORIGIN).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].name, "zroot/satl-agenttest");
        assert_eq!(rows[0].origin, None);
        assert_eq!(
            rows[0].mountpoint,
            Some(PathBuf::from("/tmp/satl-agenttest"))
        );
        assert_eq!(rows[2].name, "zroot/satl-agenttest/child");
        assert_eq!(
            rows[2].origin.as_deref(),
            Some("zroot/satl-agenttest/base@final")
        );
        assert_eq!(
            rows[2].mountpoint,
            Some(PathBuf::from("/tmp/satl-agenttest/child"))
        );
    }

    #[test]
    fn list_space_builds_expected_argv() {
        assert_eq!(
            args_list_space("zroot/satl/layers"),
            [
                "list",
                "-H",
                "-p",
                "-r",
                "-d",
                "2",
                "-t",
                "filesystem,snapshot",
                "-o",
                "name,origin,used",
                "zroot/satl/layers"
            ]
        );
    }

    #[test]
    fn parse_space_table_on_this_hosts_real_layer_store() {
        // Captured on the dev host: two base layers, each with @final.
        let rows = parse_name_origin_used_table(FIXTURE_SPACE_LAYERS).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].name, "zroot/satl/layers");
        assert_eq!(rows[0].used, 62_337_024);
        assert_eq!(rows[0].origin, None);
        assert!(rows[2].name.ends_with("@final"));
        assert_eq!(rows[2].used, 155_648);
    }

    #[test]
    fn parse_space_table_reads_the_clone_edge_of_a_stacked_layer() {
        // Captured from a real clone tree (created and destroyed for the
        // capture): base layer, a layer cloned from its @final, and a
        // half-applied clone with no @final of its own.
        let rows = parse_name_origin_used_table(FIXTURE_SPACE_STACKED).unwrap();
        assert_eq!(rows.len(), 6);
        let stacked = rows
            .iter()
            .find(|row| row.name.contains("bbbb2222") && !row.name.contains('@'))
            .expect("the stacked layer row");
        assert_eq!(
            stacked.origin.as_deref(),
            Some(
                "zroot/satl/layers/\
                 aaaa1111e92863fce933ed7c39c0e045631af0ed86d5cc0dfbdf9fdca426ce3c@final"
            )
        );
        assert_eq!(stacked.used, 69_632);
        // The half-applied one is a clone too, but has no @final row.
        assert!(
            !rows
                .iter()
                .any(|row| row.name.contains("cccc3333") && row.name.contains('@')),
            "the half-applied layer must have no snapshot in the capture"
        );
    }

    #[test]
    fn parse_space_table_rejects_a_non_numeric_used() {
        // `-p` lost: `used` comes back as "9.65M" and every size downstream
        // would be wrong by three orders of magnitude.
        let err = parse_name_origin_used_table("zroot/satl/layers/aa\t-\t9.65M\n").unwrap_err();
        assert!(err.contains("9.65M"), "{err}");
        assert!(err.contains("zfs list -p"), "{err}");
    }

    #[test]
    fn parse_space_table_rejects_a_two_column_line() {
        let err = parse_name_origin_used_table("name-only\t-\n").unwrap_err();
        assert!(err.contains("name-only"), "{err}");
    }

    #[tokio::test]
    async fn list_space_of_a_missing_root_is_recognisable() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "cannot open 'zroot/satl/layers': dataset does not exist\n",
        );
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.list_space("zroot/satl/layers").await.unwrap_err();
        assert!(
            err.is_missing_dataset(),
            "a node with no layers root is not a broken pool: {err}"
        );
    }

    #[tokio::test]
    async fn a_real_failure_is_not_a_missing_dataset() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "internal error: out of memory\n");
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.list_space("zroot/satl/layers").await.unwrap_err();
        assert!(!err.is_missing_dataset(), "{err}");
    }

    /// `is_busy` decides whether a failed destroy is worth waiting out, so its
    /// narrowness is the whole point: "dependent clones" is a permanent
    /// refusal and must not be retried, and a spawn failure is not a refusal
    /// at all.
    #[tokio::test]
    async fn only_a_busy_dataset_reads_as_busy() {
        let busy = |stderr: &str| ZfsError::CommandFailed {
            argv: "/sbin/zfs destroy -r zroot/satl/layers/abc".to_owned(),
            exit_code: Some(1),
            stderr: stderr.to_owned(),
        };
        assert!(
            busy("cannot unmount '/var/db/satl/layers/abc': pool or dataset is busy\n").is_busy()
        );
        assert!(busy("cannot destroy 'zroot/satl/layers/abc': dataset is busy\n").is_busy());
        assert!(
            !busy("cannot destroy 'zroot/satl/layers/abc': filesystem has dependent clones\n")
                .is_busy(),
            "dependent clones is permanent; waiting cannot clear it"
        );
        assert!(!busy("cannot open 'zroot/nope': dataset does not exist\n").is_busy());

        let mock = MockRunner::new();
        mock.push_spawn_error(io::ErrorKind::NotFound, "no zfs binary");
        let zfs = Zfs::with_runner(&mock);
        let spawn_failure = zfs
            .destroy("zroot/satl/layers/abc", true)
            .await
            .unwrap_err();
        assert!(!spawn_failure.is_busy(), "{spawn_failure}");
    }

    #[test]
    fn parse_origin_table_rejects_two_column_line() {
        let err = parse_name_origin_mountpoint_table("name-only\t-\n").unwrap_err();
        assert!(err.contains("name-only"));
    }

    // ---- wrapper behavior with the mock runner -----------------------------

    #[tokio::test]
    async fn dataset_exists_true_on_success() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_EXISTS, "");
        let zfs = Zfs::with_runner(&mock);
        assert!(zfs.dataset_exists("zroot").await.unwrap());
        assert_eq!(mock.calls(), ["/sbin/zfs list -H -o name zroot"]);
    }

    #[tokio::test]
    async fn dataset_exists_false_on_missing() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_LIST_MISSING);
        let zfs = Zfs::with_runner(&mock);
        assert!(
            !zfs.dataset_exists("zroot/satl-does-not-exist")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn dataset_exists_error_keeps_argv_status_stderr() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "cannot open 'zroot': permission denied\n");
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.dataset_exists("zroot").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/sbin/zfs list -H -o name zroot"), "{msg}");
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("permission denied"), "{msg}");
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv() {
        let mock = MockRunner::new();
        mock.push_spawn_error(io::ErrorKind::NotFound, "no such file");
        let zfs = Zfs::with_runner(&mock).with_binary("/nonexistent/zfs");
        let err = zfs.dataset_exists("zroot").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/zfs list -H -o name zroot"),
            "{msg}"
        );
        assert!(msg.contains("no such file"), "{msg}");
    }

    #[tokio::test]
    async fn get_property_returns_trimmed_single_value() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_GET_MOUNTPOINT, "");
        let zfs = Zfs::with_runner(&mock);
        let value = zfs.get_property("zroot/var", "mountpoint").await.unwrap();
        assert_eq!(value, "/var");
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs get -H -p -o value mountpoint zroot/var"]
        );
    }

    #[tokio::test]
    async fn get_property_rejects_multiline_output() {
        let mock = MockRunner::new();
        mock.push_output(0, "one\ntwo\n", "");
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.get_property("zroot", "mountpoint").await.unwrap_err();
        assert!(matches!(err, ZfsError::UnexpectedOutput { .. }), "{err}");
    }

    #[tokio::test]
    async fn list_children_drops_the_dataset_itself() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_CHILDREN, "");
        let zfs = Zfs::with_runner(&mock);
        let children = zfs.list_children("zroot/usr").await.unwrap();
        let names: Vec<&str> = children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["zroot/usr/obj", "zroot/usr/ports", "zroot/usr/src"]);
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs list -H -p -r -d 1 -o name,mountpoint zroot/usr"]
        );
    }

    #[tokio::test]
    async fn create_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let zfs = Zfs::with_runner(&mock);
        zfs.create("zroot/satl/raft", &[("compression", "zstd")])
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs create -o compression=zstd zroot/satl/raft"]
        );
    }

    #[tokio::test]
    async fn create_failure_carries_full_context() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "cannot create 'zroot/satl/raft': permission denied\n",
        );
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.create("zroot/satl/raft", &[]).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("/sbin/zfs create zroot/satl/raft"), "{msg}");
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("permission denied"), "{msg}");
    }

    #[tokio::test]
    async fn snapshot_exists_true_and_false_on_real_output() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SNAPSHOT_EXISTS, "");
        mock.push_output(1, "", FIXTURE_SNAPSHOT_MISSING);
        let zfs = Zfs::with_runner(&mock);
        assert!(
            zfs.snapshot_exists("zroot/satl-agenttest/base", "final")
                .await
                .unwrap()
        );
        assert!(
            !zfs.snapshot_exists("zroot/satl-agenttest/base", "nope")
                .await
                .unwrap()
        );
        assert_eq!(
            mock.calls(),
            [
                "/sbin/zfs list -H -o name zroot/satl-agenttest/base@final",
                "/sbin/zfs list -H -o name zroot/satl-agenttest/base@nope",
            ]
        );
    }

    #[tokio::test]
    async fn snapshot_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let zfs = Zfs::with_runner(&mock);
        zfs.snapshot("zroot/satl/layers/abc", "final")
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs snapshot zroot/satl/layers/abc@final"]
        );
    }

    #[tokio::test]
    async fn snapshot_failure_carries_full_context() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "cannot create snapshot 'zroot/satl/layers/abc@final': permission denied\n",
        );
        let zfs = Zfs::with_runner(&mock);
        let err = zfs
            .snapshot("zroot/satl/layers/abc", "final")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/sbin/zfs snapshot zroot/satl/layers/abc@final"),
            "{msg}"
        );
        assert!(msg.contains("exit code 1"), "{msg}");
        assert!(msg.contains("permission denied"), "{msg}");
    }

    #[tokio::test]
    async fn clone_snapshot_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let zfs = Zfs::with_runner(&mock);
        zfs.clone_snapshot(
            "zroot/satl/layers/abc@final",
            "zroot/satl/containers/task1",
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs clone zroot/satl/layers/abc@final zroot/satl/containers/task1"]
        );
    }

    #[tokio::test]
    async fn destroy_recursive_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let zfs = Zfs::with_runner(&mock);
        zfs.destroy("zroot/satl/containers/task1", true)
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs destroy -r zroot/satl/containers/task1"]
        );
    }

    #[tokio::test]
    async fn destroy_failure_carries_full_context() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "cannot destroy 'zroot/satl/layers/abc': filesystem has dependent clones\n",
        );
        let zfs = Zfs::with_runner(&mock);
        let err = zfs
            .destroy("zroot/satl/layers/abc", false)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("/sbin/zfs destroy zroot/satl/layers/abc"),
            "{msg}"
        );
        assert!(msg.contains("dependent clones"), "{msg}");
    }

    #[tokio::test]
    async fn destroy_snapshot_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "");
        let zfs = Zfs::with_runner(&mock);
        zfs.destroy_snapshot("zroot/satl/layers/abc", "final")
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs destroy zroot/satl/layers/abc@final"]
        );
    }

    #[tokio::test]
    async fn list_filesystems_parses_rows() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_CHILDREN, "");
        let zfs = Zfs::with_runner(&mock);
        let rows = zfs.list_filesystems("zroot/usr").await.unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].name, "zroot/usr");
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs list -H -p -r -t filesystem -o name,mountpoint zroot/usr"]
        );
    }

    #[tokio::test]
    async fn list_with_origin_parses_clone_rows() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_WITH_ORIGIN, "");
        let zfs = Zfs::with_runner(&mock);
        let rows = zfs.list_with_origin("zroot/satl-agenttest").await.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[2].origin.as_deref(),
            Some("zroot/satl-agenttest/base@final")
        );
        assert_eq!(
            mock.calls(),
            ["/sbin/zfs list -H -p -r -o name,origin,mountpoint zroot/satl-agenttest"]
        );
    }

    #[tokio::test]
    async fn mountpoint_of_returns_path() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_GET_MOUNTPOINT, "");
        let zfs = Zfs::with_runner(&mock);
        assert_eq!(
            zfs.mountpoint_of("zroot/var").await.unwrap(),
            PathBuf::from("/var")
        );
    }

    #[tokio::test]
    async fn mountpoint_of_rejects_unmounted_dataset() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_GET_MOUNTPOINT_NONE, "");
        let zfs = Zfs::with_runner(&mock);
        let err = zfs.mountpoint_of("zroot/ROOT").await.unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, ZfsError::NotMounted { .. }), "{msg}");
        assert!(
            msg.contains("zfs set mountpoint=<path> zroot/ROOT"),
            "{msg}"
        );
    }
}
