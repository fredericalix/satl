// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `route`(8) — default route inside a VNET jail.
//!
//! ## The route-in-jail idiom (established live, FreeBSD 15.1, 2026-08-09)
//!
//! `route`(8) supports `-j jail` natively (`route: usage: route [-j jail]
//! [-46dnqtv] command ...`), so no `jexec` is needed:
//!
//! ```text
//! $ route -j satlnt-rt add default 10.77.77.1
//! add net default: gateway 10.77.77.1
//! (exit 0)
//! ```
//!
//! Verified with a throwaway `jail -c name=satlnt-rt vnet persist` jail plus
//! an epair: `-j` accepts a jail **name or numeric jid** interchangeably, and
//! the route lands in the jail's vnet (confirmed via `jexec satlnt-rt
//! netstat -rn -f inet` and a successful in-jail ping through the gateway).
//! Captured outputs live in `tests/fixtures/route_add_*.txt`.
//!
//! Re-adding an existing default route fails with exit code 1,
//! `route: message indicates error: File exists` on stderr and
//! `add net default: gateway <gw> fib 0: route already in table` on stdout —
//! [`Route::add_default_in_jail`] treats that as idempotent success
//! (`Ok(false)`).

use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `route` binary on FreeBSD.
pub const DEFAULT_ROUTE_BINARY: &str = "/sbin/route";

/// Error from a `route`(8) invocation. Every variant names the jail involved
/// and carries the full argv + exit status + stderr of the failed command.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// The `route` binary could not be spawned.
    #[error("route ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted, naming the jail involved.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("route ({context}): {failure}")]
    Failed {
        /// What was being attempted, naming the jail involved.
        context: String,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },
}

// ---------------------------------------------------------------------------
// Pure argv builders and output classifiers.
// ---------------------------------------------------------------------------

fn args_add_default(jail: &str, gateway: Ipv4Addr) -> Vec<String> {
    ["-j", jail, "add", "default", &gateway.to_string()]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_delete_default(jail: &str) -> Vec<String> {
    ["-j", jail, "delete", "default"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_get_default() -> Vec<String> {
    ["-n", "get", "default"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_add_host(destination: Ipv4Addr, gateway: Ipv4Addr) -> Vec<String> {
    [
        "-n",
        "add",
        "-host",
        &destination.to_string(),
        &gateway.to_string(),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Whether a failed `route add` means the route was already present.
/// Real capture: stdout `add net default: gateway 10.77.77.1 fib 0: route
/// already in table`, stderr `route: message indicates error: File exists`.
fn output_says_route_exists(output: &CommandOutput) -> bool {
    output.stdout.contains("route already in table") || output.stderr.contains("File exists")
}

/// `route -n get default` on a host with no default route.
fn output_says_route_missing(output: &CommandOutput) -> bool {
    output.stderr.contains("not been found") || output.stdout.contains("not been found")
}

/// Pull the `interface:` field out of `route -n get default` output.
///
/// The command prints an indented `key: value` block; only the interface is
/// of interest here. Returns `None` if the field is absent, which is treated
/// as "no egress interface" rather than an error.
fn parse_default_interface(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "interface").then(|| value.trim().to_owned())
    })
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around the `route`(8) binary.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock executor;
/// production code uses [`Route::system`].
#[derive(Debug, Clone)]
pub struct Route<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Route<SystemRunner> {
    /// Wrapper that executes the real binary at [`DEFAULT_ROUTE_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Route<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Route<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_ROUTE_BINARY),
            runner,
        }
    }

    /// Override the path of the `route` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    async fn exec(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), RouteError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running route");
        let output = self
            .runner
            .run(&self.binary, &args, None)
            .await
            .map_err(|source| RouteError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Install the default route inside a VNET jail:
    /// `route -j <jail> add default <gateway>`. `jail` may be a jail name or
    /// a numeric jid.
    ///
    /// Returns `Ok(true)` when the route was added, `Ok(false)` when an
    /// identical default route was already in the jail's table (idempotent).
    pub async fn add_default_in_jail(
        &self,
        jail: &str,
        gateway: Ipv4Addr,
    ) -> Result<bool, RouteError> {
        let context = format!("add default route via {gateway} in jail '{jail}'");
        let (argv, output) = self.exec(&context, args_add_default(jail, gateway)).await?;
        if output.success() {
            tracing::info!(jail = %jail, gateway = %gateway, "added in-jail default route");
            return Ok(true);
        }
        if output_says_route_exists(&output) {
            tracing::debug!(jail = %jail, gateway = %gateway, "default route already in table");
            return Ok(false);
        }
        Err(RouteError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }

    /// Install the host route that closes the loopback-publish loop
    /// (`docs/api-compat.md` #35, measured in `hack/experiments/lo0rdr`):
    /// `route -n add -host 198.18.0.1 127.0.0.1`, the destination being
    /// [`satl_core::defaults::LOOPBACK_PUBLISH_SNAT`].
    ///
    /// The `nat on lo0` rule in `satl/rdr` rewrites a host-local client's
    /// source to that dummy; this route makes the task's reply to it
    /// non-local, so the reply is forwarded back out `lo0`, re-enters it, and
    /// both pf states get their reverse traversal in order (un-rdr, then
    /// un-nat). Without the route the reply is unroutable and the connection
    /// hangs.
    ///
    /// Returns `Ok(true)` when the route was added, `Ok(false)` when it was
    /// already in the table (idempotent — the caller re-ensures it every
    /// pass, because the route survives nothing).
    pub async fn ensure_loopback_snat_route(&self) -> Result<bool, RouteError> {
        let destination = satl_core::defaults::LOOPBACK_PUBLISH_SNAT;
        let gateway = Ipv4Addr::LOCALHOST;
        let context = format!("add the loopback-publish host route {destination} -> {gateway}");
        let (argv, output) = self
            .exec(&context, args_add_host(destination, gateway))
            .await?;
        if output.success() {
            return Ok(true);
        }
        if output_says_route_exists(&output) {
            tracing::debug!(
                destination = %destination,
                "loopback-publish host route already in table"
            );
            return Ok(false);
        }
        Err(RouteError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }

    /// The interface carrying the host's default route (`route -n get
    /// default`), i.e. the interface container traffic is NAT-ed out of.
    ///
    /// Returns `Ok(None)` when the host has no default route: a valid state
    /// for an isolated node, and the caller decides whether that is fatal
    /// (for SatL it only means containers get no outbound connectivity).
    pub async fn default_egress_interface(&self) -> Result<Option<String>, RouteError> {
        let context = "look up the interface of the default route".to_owned();
        let (argv, output) = self.exec(&context, args_get_default()).await?;
        if !output.success() {
            // `route: route has not been found` is the no-default-route case.
            if output_says_route_missing(&output) {
                return Ok(None);
            }
            return Err(RouteError::Failed {
                context,
                failure: Failure::new(argv, &output),
            });
        }
        Ok(parse_default_interface(&output.stdout))
    }

    /// Remove the default route inside a VNET jail:
    /// `route -j <jail> delete default`.
    pub async fn delete_default_in_jail(&self, jail: &str) -> Result<(), RouteError> {
        let context = format!("delete default route in jail '{jail}'");
        let (argv, output) = self.exec(&context, args_delete_default(jail)).await?;
        if output.success() {
            tracing::info!(jail = %jail, "deleted in-jail default route");
            return Ok(());
        }
        Err(RouteError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_ADD_OK: &str = include_str!("../tests/fixtures/route_add_default.txt");
    const FIXTURE_EXISTS_STDOUT: &str =
        include_str!("../tests/fixtures/route_add_exists_stdout.txt");
    const FIXTURE_EXISTS_STDERR: &str =
        include_str!("../tests/fixtures/route_add_exists_stderr.txt");

    fn gw(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn argv_builders() {
        assert_eq!(
            args_add_default("satlnt-rt", gw("10.77.77.1")),
            ["-j", "satlnt-rt", "add", "default", "10.77.77.1"]
        );
        assert_eq!(
            args_add_default("42", gw("10.88.0.1")),
            ["-j", "42", "add", "default", "10.88.0.1"]
        );
        assert_eq!(
            args_delete_default("satlnt-rt"),
            ["-j", "satlnt-rt", "delete", "default"]
        );
    }

    #[test]
    fn already_exists_output_is_recognized_on_either_stream() {
        // Real captured streams from the re-add case.
        let both = CommandOutput {
            exit_code: Some(1),
            stdout: FIXTURE_EXISTS_STDOUT.to_owned(),
            stderr: FIXTURE_EXISTS_STDERR.to_owned(),
        };
        assert!(output_says_route_exists(&both));
        let stdout_only = CommandOutput {
            exit_code: Some(1),
            stdout: FIXTURE_EXISTS_STDOUT.to_owned(),
            stderr: String::new(),
        };
        assert!(output_says_route_exists(&stdout_only));
        let unrelated = CommandOutput {
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "route: bad address: nonsense\n".to_owned(),
        };
        assert!(!output_says_route_exists(&unrelated));
    }

    #[tokio::test]
    async fn add_default_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_ADD_OK, "");
        let route = Route::with_runner(&mock);
        assert!(
            route
                .add_default_in_jail("satlnt-rt", gw("10.77.77.1"))
                .await
                .unwrap()
        );
        assert_eq!(
            mock.calls(),
            ["/sbin/route -j satlnt-rt add default 10.77.77.1"]
        );
    }

    #[tokio::test]
    async fn add_default_is_idempotent_on_existing_route() {
        let mock = MockRunner::new();
        mock.push_output(1, FIXTURE_EXISTS_STDOUT, FIXTURE_EXISTS_STDERR);
        let route = Route::with_runner(&mock);
        assert!(
            !route
                .add_default_in_jail("satlnt-rt", gw("10.77.77.1"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn add_default_failure_names_jail_and_carries_context() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "route: bad address: 10.88.0.\n");
        let route = Route::with_runner(&mock);
        let err = route
            .add_default_in_jail("satlnt-it", gw("10.88.0.1"))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("jail 'satlnt-it'"), "{text}");
        assert!(
            text.contains("/sbin/route -j satlnt-it add default 10.88.0.1"),
            "{text}"
        );
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("bad address"), "{text}");
    }

    #[tokio::test]
    async fn delete_default_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "delete net default\n", "");
        let route = Route::with_runner(&mock);
        route.delete_default_in_jail("42").await.unwrap();
        assert_eq!(mock.calls(), ["/sbin/route -j 42 delete default"]);
    }

    // ---- the loopback-publish host route -------------------------------------

    #[tokio::test]
    async fn loopback_snat_route_builds_expected_argv_on_fresh_add() {
        let mock = MockRunner::new();
        mock.push_output(0, "add host 198.18.0.1: gateway 127.0.0.1\n", "");
        let route = Route::with_runner(&mock);
        assert!(route.ensure_loopback_snat_route().await.unwrap());
        assert_eq!(
            mock.calls(),
            ["/sbin/route -n add -host 198.18.0.1 127.0.0.1"]
        );
    }

    #[tokio::test]
    async fn loopback_snat_route_is_idempotent_when_already_in_table() {
        let mock = MockRunner::new();
        // Same failure shape as the default-route re-add: exit 1, the
        // "already in table" note on stdout, "File exists" on stderr.
        mock.push_output(
            1,
            "add host 198.18.0.1: gateway 127.0.0.1 fib 0: route already in table\n",
            "route: message indicates error: File exists\n",
        );
        let route = Route::with_runner(&mock);
        assert!(!route.ensure_loopback_snat_route().await.unwrap());
    }

    #[tokio::test]
    async fn loopback_snat_route_failure_carries_argv_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(
            1,
            "",
            "route: writing to routing socket: Operation not permitted\n",
        );
        let route = Route::with_runner(&mock);
        let err = route.ensure_loopback_snat_route().await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("/sbin/route -n add -host 198.18.0.1 127.0.0.1"),
            "{text}"
        );
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("Operation not permitted"), "{text}");
    }

    /// Real `route -n get default` output captured on the dev host.
    const DEFAULT_ROUTE: &str = include_str!("../tests/fixtures/route_get_default.txt");

    #[test]
    fn parses_the_egress_interface_from_real_output() {
        assert_eq!(
            parse_default_interface(DEFAULT_ROUTE),
            Some("ice0".to_owned())
        );
    }

    #[test]
    fn parses_no_interface_when_the_field_is_absent() {
        let without = DEFAULT_ROUTE
            .lines()
            .filter(|line| !line.trim_start().starts_with("interface:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_default_interface(&without), None);
    }

    #[tokio::test]
    async fn default_egress_interface_reads_the_route_table() {
        let mock = MockRunner::new();
        mock.push_output(0, DEFAULT_ROUTE, "");
        let route = Route::with_runner(&mock);
        let egress = route.default_egress_interface().await.expect("a lookup");
        assert_eq!(egress, Some("ice0".to_owned()));
        assert_eq!(mock.calls(), ["/sbin/route -n get default"]);
    }

    #[tokio::test]
    async fn a_host_without_a_default_route_reports_no_egress() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "route: route has not been found\n");
        let route = Route::with_runner(&mock);
        assert_eq!(
            route.default_egress_interface().await.expect("a lookup"),
            None
        );
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let route = Route::with_runner(&mock).with_binary("/nonexistent/route");
        let err = route
            .add_default_in_jail("satlnt-rt", gw("10.77.77.1"))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("/nonexistent/route -j satlnt-rt add default 10.77.77.1"),
            "{text}"
        );
        assert!(text.contains("no such file"), "{text}");
    }
}
