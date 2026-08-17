// SPDX-License-Identifier: BSD-2-Clause
//! `POST /containers/{id}/exec` and `POST /exec/{id}/start`: the in-memory
//! exec registry and the `ocijail exec` run behind it.
//!
//! Docker's exec is a two-step API — create an instance, then start it — so
//! the daemon has to remember instances between the two calls. They are
//! deliberately **not** cluster state: an exec is node-local, ephemeral, and
//! meaningless after a restart (invariant #1 is about *cluster* state; there
//! is nothing here a manager would replicate). The registry is therefore a
//! plain in-memory map, and an exec id that survives a restart answers 404.
//!
//! M1 limitations, all recorded in `docs/api-compat.md`:
//!
//! - **no TTY** — the API layer rejects `Tty=true` before reaching here;
//! - **no stdin** — accepted and discarded (the API layer drains it);
//! - **output is delivered when the process exits**, not incrementally:
//!   `ocijail exec` is driven with its stdio pointed at scratch files, and
//!   turning those into a live pipe needs an fd the wrapper cannot take
//!   without `unsafe` (which the workspace denies). Short commands — the
//!   `docker exec <c> <cmd>` case — behave identically; a long-running exec
//!   buffers.
//! - **environment** is the task spec's plus the request's; the image's own
//!   `ENV` is not re-read here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::stream::StreamExt as _;
use satl_api::model::{
    BackendError, ExecConfig, ExecId, ExecInspect, ExecStream, LogFrame, LogStream, Result,
};
use satl_core::{Id, Task};
use satl_runtime::{CreateStdio, ExecSpec, JailUser, Runtime as _, StdioSink};
use tracing::Instrument as _;

/// Exit code reported when the runtime could not tell us one (the process
/// died to a signal, or ocijail failed before it ran).
pub const UNKNOWN_EXIT_CODE: i64 = 255;

/// One exec instance's mutable state.
#[derive(Debug, Clone, Copy, Default)]
struct ExecState {
    started: bool,
    running: bool,
    exit_code: Option<i64>,
}

/// One registered exec instance.
struct ExecEntry {
    container: Id,
    config: ExecConfig,
    /// Resolved process description, built at create time so a bad request
    /// fails on `create` rather than on `start`.
    process: ExecSpec,
    state: Mutex<ExecState>,
}

/// The daemon's exec instances.
#[derive(Default)]
pub struct ExecRegistry {
    entries: Mutex<BTreeMap<String, Arc<ExecEntry>>>,
}

impl std::fmt::Debug for ExecRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.lock().map_or(0, |entries| entries.len());
        f.debug_struct("ExecRegistry")
            .field("instances", &count)
            .finish()
    }
}

/// Parse Docker's `User` field, which SatL only supports numerically.
///
/// Resolving a user *name* needs the image's `/etc/passwd`, which the daemon
/// would have to read out of the container's rootfs — deferred with the same
/// restriction `ContainerSpec.user` has (satl-agent module docs).
fn parse_user(user: Option<&str>) -> Result<Option<JailUser>> {
    let Some(user) = user.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let (uid, gid) = match user.split_once(':') {
        Some((uid, gid)) => (uid, Some(gid)),
        None => (user, None),
    };
    let numeric = |value: &str, what: &str| {
        value.parse::<u32>().map_err(|_| {
            BackendError::invalid(format!(
                "unsupported {what} {value:?}: SatL resolves numeric ids only \
                 (use `1001` or `1001:1001`)"
            ))
        })
    };
    let uid = numeric(uid, "user")?;
    let gid = match gid {
        Some(gid) => numeric(gid, "group")?,
        None => uid,
    };
    Ok(Some(JailUser {
        uid,
        gid,
        additional_gids: Vec::new(),
    }))
}

/// Build the process description for an exec against `task`.
fn plan_process(task: &Task, config: &ExecConfig) -> Result<ExecSpec> {
    if config.cmd.is_empty() {
        return Err(BackendError::invalid("no command specified"));
    }
    let mut env = task.spec.container.env.clone();
    env.extend(config.env.iter().cloned());
    let cwd = config
        .working_dir
        .clone()
        .or_else(|| task.spec.container.dir.clone())
        .unwrap_or_else(|| "/".to_owned());
    Ok(ExecSpec {
        terminal: false,
        user: parse_user(config.user.as_deref())?,
        args: config.cmd.clone(),
        env,
        cwd,
    })
}

/// Open a scratch file that can be written by the runtime and read back by
/// the daemon.
fn scratch_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// Read a scratch file, dropping it afterwards.
async fn take_output(path: &std::path::Path) -> Vec<u8> {
    let data = tokio::fs::read(path).await.unwrap_or_default();
    if let Err(error) = tokio::fs::remove_file(path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(path = %path.display(), %error, "cannot remove exec scratch file");
    }
    data
}

impl ExecRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Arc<ExecEntry>>> {
        // A poisoned lock only means some other request panicked while
        // holding it; the map itself is still consistent.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register an exec instance against `task`.
    pub fn create(&self, task: &Task, config: ExecConfig) -> Result<ExecId> {
        let process = plan_process(task, &config)?;
        let id = Id::generate().to_string();
        let entry = Arc::new(ExecEntry {
            container: task.id.clone(),
            config,
            process,
            state: Mutex::new(ExecState::default()),
        });
        self.entries().insert(id.clone(), entry);
        tracing::info!(exec_id = %id, task_id = %task.id, "exec instance registered");
        Ok(ExecId::new(id))
    }

    fn get(&self, exec_id: &str) -> Result<Arc<ExecEntry>> {
        self.entries()
            .get(exec_id)
            .cloned()
            .ok_or_else(|| BackendError::not_found(format!("No such exec instance: {exec_id}")))
    }

    /// The instance's current state, as `GET /exec/{id}/json` reports it.
    pub fn inspect(&self, exec_id: &str) -> Result<ExecInspect> {
        let entry = self.get(exec_id)?;
        let state = *entry
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(ExecInspect {
            id: exec_id.to_owned(),
            container_id: entry.container.to_string(),
            running: state.running,
            exit_code: state.exit_code,
            pid: None,
            cmd: entry.config.cmd.clone(),
            tty: false,
            open_stdin: entry.config.attach_stdin,
            open_stdout: entry.config.attach_stdout,
            open_stderr: entry.config.attach_stderr,
        })
    }

    /// Run a registered instance.
    ///
    /// `scratch_dir` holds the stdio files for the duration of the run.
    pub fn start(
        &self,
        exec_id: &str,
        executor: Arc<satl_agent::Executor>,
        scratch_dir: &std::path::Path,
    ) -> Result<ExecStream> {
        let entry = self.get(exec_id)?;
        {
            let mut state = entry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.started {
                return Err(BackendError::conflict(format!(
                    "exec instance {exec_id} has already been started"
                )));
            }
            state.started = true;
            state.running = true;
        }

        std::fs::create_dir_all(scratch_dir).map_err(|source| {
            BackendError::internal(format!(
                "cannot create the exec scratch directory {}: {source}",
                scratch_dir.display()
            ))
        })?;
        let stdout_path = scratch_dir.join(format!("exec-{exec_id}.out"));
        let stderr_path = scratch_dir.join(format!("exec-{exec_id}.err"));
        let open = |path: &std::path::Path| {
            scratch_file(path).map_err(|source| {
                BackendError::internal(format!(
                    "cannot open the exec output file {}: {source}",
                    path.display()
                ))
            })
        };
        let stdio = CreateStdio {
            stdin: StdioSink::Null,
            stdout: StdioSink::File(open(&stdout_path)?),
            stderr: StdioSink::File(open(&stderr_path)?),
        };

        let (frames_tx, frames_rx) = tokio::sync::mpsc::unbounded_channel::<LogFrame>();
        let (exit_tx, exit) = tokio::sync::oneshot::channel::<i64>();
        let jail_id = entry.container.as_str().to_owned();
        let process = entry.process.clone();
        let want_stdout = entry.config.attach_stdout;
        let want_stderr = entry.config.attach_stderr;
        let exec_id_owned = exec_id.to_owned();
        let state_handle = Arc::clone(&entry);

        // Attached to the future, not entered with a guard: an `Entered` held
        // across an await stays entered on the worker thread while this task is
        // parked, so every unrelated task the runtime later polls on that
        // thread inherits it as a parent.
        let span = tracing::info_span!(
            "exec_run",
            exec_id = %exec_id_owned,
            task_id = %jail_id,
        );
        tokio::spawn(
            async move {
                let outcome = executor.runtime().exec(&jail_id, &process, stdio).await;
                let exit_code = match &outcome {
                    Ok(outcome) => outcome.exit_code.map_or(UNKNOWN_EXIT_CODE, i64::from),
                    Err(error) => {
                        tracing::warn!(%error, "exec failed");
                        UNKNOWN_EXIT_CODE
                    }
                };

                let send = |stream: LogStream, data: Vec<u8>| {
                    if data.is_empty() {
                        return;
                    }
                    let _ = frames_tx.send(LogFrame {
                        stream,
                        timestamp: std::time::SystemTime::now(),
                        data: Bytes::from(data),
                    });
                };
                let stdout = take_output(&stdout_path).await;
                let stderr = take_output(&stderr_path).await;
                if want_stdout {
                    send(LogStream::Stdout, stdout);
                }
                if want_stderr {
                    send(LogStream::Stderr, stderr);
                }
                // The error text ocijail wrote lands on stderr; when the client
                // asked for neither stream, at least say so in the log.
                if let Err(error) = outcome {
                    tracing::debug!(%error, "exec error detail");
                }

                {
                    let mut state = state_handle
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.running = false;
                    state.exit_code = Some(exit_code);
                }
                tracing::info!(exit_code, "exec instance finished");
                // A dropped receiver means the client hung up first.
                let _ = exit_tx.send(exit_code);
            }
            .instrument(span),
        );

        let frames = futures_util::stream::unfold(frames_rx, |mut rx| async move {
            rx.recv().await.map(|frame| (frame, rx))
        })
        .boxed();
        Ok(ExecStream { frames, exit })
    }

    /// Drop every instance belonging to `container` (its task is gone).
    pub fn forget_container(&self, container: &Id) {
        self.entries()
            .retain(|_, entry| &entry.container != container);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cmd: &[&str]) -> ExecConfig {
        ExecConfig {
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            attach_stdout: true,
            attach_stderr: true,
            ..ExecConfig::default()
        }
    }

    #[test]
    fn numeric_users_are_accepted_in_both_forms() {
        assert_eq!(parse_user(None).expect("none"), None);
        assert_eq!(parse_user(Some("")).expect("empty"), None);
        assert_eq!(
            parse_user(Some("1001")).expect("uid"),
            Some(JailUser {
                uid: 1001,
                gid: 1001,
                additional_gids: Vec::new()
            })
        );
        assert_eq!(
            parse_user(Some("1001:2002")).expect("uid:gid"),
            Some(JailUser {
                uid: 1001,
                gid: 2002,
                additional_gids: Vec::new()
            })
        );
    }

    #[test]
    fn user_names_are_rejected_with_an_actionable_message() {
        let err = parse_user(Some("www")).expect_err("names are unsupported");
        assert!(matches!(err, BackendError::InvalidParameter(_)), "{err:?}");
        assert!(err.to_string().contains("numeric"), "{err}");
    }

    #[test]
    fn the_process_plan_merges_env_and_defaults_the_cwd() {
        let mut task = crate::backend::tests::sample_task("web");
        task.spec.container.env = vec!["A=1".to_owned()];
        let mut cfg = config(&["echo", "hi"]);
        cfg.env = vec!["B=2".to_owned()];
        let process = plan_process(&task, &cfg).expect("a plan");
        assert_eq!(process.args, ["echo", "hi"]);
        assert_eq!(process.env, ["A=1", "B=2"]);
        assert_eq!(process.cwd, "/");
        assert!(!process.terminal);

        task.spec.container.dir = Some("/srv".to_owned());
        assert_eq!(plan_process(&task, &cfg).expect("a plan").cwd, "/srv");
        cfg.working_dir = Some("/tmp".to_owned());
        assert_eq!(plan_process(&task, &cfg).expect("a plan").cwd, "/tmp");
    }

    #[test]
    fn an_empty_command_is_rejected() {
        let task = crate::backend::tests::sample_task("web");
        let err = plan_process(&task, &config(&[])).expect_err("no command");
        assert!(matches!(err, BackendError::InvalidParameter(_)), "{err:?}");
    }

    #[test]
    fn instances_are_registered_inspectable_and_forgettable() {
        let task = crate::backend::tests::sample_task("web");
        let registry = ExecRegistry::new();
        let id = registry
            .create(&task, config(&["echo", "hi"]))
            .expect("registered");

        let inspect = registry.inspect(id.as_str()).expect("inspect");
        assert_eq!(inspect.container_id, task.id.to_string());
        assert!(!inspect.running);
        assert_eq!(inspect.exit_code, None);
        assert_eq!(inspect.cmd, ["echo", "hi"]);
        assert!(!inspect.tty);

        registry.forget_container(&task.id);
        let err = registry.inspect(id.as_str()).expect_err("gone");
        assert!(matches!(err, BackendError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn an_unknown_instance_is_not_found() {
        let registry = ExecRegistry::new();
        let err = registry.inspect("nope").expect_err("unknown");
        assert!(matches!(err, BackendError::NotFound(_)), "{err:?}");
    }
}
