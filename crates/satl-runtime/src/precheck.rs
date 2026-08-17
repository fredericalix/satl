// SPDX-License-Identifier: BSD-2-Clause
//! Task-level platform gate, run before any bundle is written or jail
//! created. Fails fast with operator-grade errors so tasks are `REJECTED`
//! with a real explanation instead of ocijail's confusing exec error
//! (docs/ocijail.md §5, docs/linuxulator.md detection heuristics).
//!
//! ## Linuxulator probe choice
//!
//! The probe is `sysctl -n compat.linux.osrelease` through the command
//! runner, chosen over parsing `kldstat` because:
//!
//! - the oid is registered by `linux_common.ko` and exists exactly when the
//!   linuxulator ABI modules are loaded — one stable string, no output
//!   format to parse (a missing oid is `sysctl: unknown oid ...`, exit 1);
//! - it doubles as documentation: its value is the `uname -r` containers
//!   will see (docs/linuxulator.md host requirements);
//! - going through the [`CommandRunner`] keeps the check unit-testable with
//!   the same mock as every other wrapper.

use std::path::Path;

use crate::error::RuntimeError;
use crate::runner::{CommandRunner, render_argv};
use crate::spec::ImagePlatform;

/// Default location of the `sysctl` binary on FreeBSD.
pub const DEFAULT_SYSCTL_BINARY: &str = "/sbin/sysctl";

/// The oid whose presence signals "linuxulator loaded".
pub const LINUX_PROBE_OID: &str = "compat.linux.osrelease";

fn args_probe() -> Vec<String> {
    vec!["-n".to_owned(), LINUX_PROBE_OID.to_owned()]
}

/// Entrypoint basenames that mean "this image expects to boot an init
/// system as PID 1" (docs/linuxulator.md: in official images `/sbin/init`
/// is only ever an init system; systemd may live at `/usr/lib/systemd/systemd`).
const INIT_BASENAMES: [&str; 2] = ["systemd", "init"];

fn entrypoint_basename(entrypoint: &str) -> &str {
    entrypoint.rsplit('/').next().unwrap_or(entrypoint)
}

/// Gate a task on its resolved platform and entrypoint.
///
/// - Empty `args` is always rejected (clearer than ocijail's
///   `malformed_config`).
/// - For [`ImagePlatform::Linux`]: reject systemd/init entrypoints (they die
///   silently — no PID namespace, no cgroups; runtime detection is useless),
///   then verify the linuxulator is loaded via the sysctl probe.
/// - For [`ImagePlatform::Freebsd`]: no probe needed.
///
/// `jail_id` is only used in error messages (operator-facing errors name the
/// jail).
pub async fn check_platform<R: CommandRunner>(
    runner: &R,
    jail_id: &str,
    platform: ImagePlatform,
    args: &[String],
) -> Result<(), RuntimeError> {
    let Some(entrypoint) = args.first() else {
        return Err(RuntimeError::EmptyEntrypoint {
            jail_id: jail_id.to_owned(),
        });
    };
    if platform == ImagePlatform::Freebsd {
        return Ok(());
    }

    if INIT_BASENAMES.contains(&entrypoint_basename(entrypoint)) {
        return Err(RuntimeError::EntrypointNeedsInit {
            jail_id: jail_id.to_owned(),
            entrypoint: entrypoint.clone(),
        });
    }

    let binary = Path::new(DEFAULT_SYSCTL_BINARY);
    let probe_args = args_probe();
    let rendered = render_argv(binary, &probe_args);
    tracing::debug!(command = %rendered, jail_id, "probing linuxulator availability");
    let output = runner.run(binary, &probe_args).await.map_err(|source| {
        RuntimeError::LinuxulatorUnavailable {
            jail_id: jail_id.to_owned(),
            argv: rendered.clone(),
            exit_code: None,
            stderr: source.to_string(),
        }
    })?;
    if output.exit_code == Some(0) {
        tracing::debug!(
            jail_id,
            osrelease = %output.stdout.trim(),
            "linuxulator available"
        );
        Ok(())
    } else {
        Err(RuntimeError::LinuxulatorUnavailable {
            jail_id: jail_id.to_owned(),
            argv: rendered,
            exit_code: output.exit_code,
            stderr: output.stderr.trim_end().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_OSRELEASE: &str = include_str!("../tests/fixtures/sysctl_linux_osrelease.txt");
    const FIXTURE_UNKNOWN_OID: &str = include_str!("../tests/fixtures/sysctl_unknown_oid.txt");

    fn sh_args() -> Vec<String> {
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()]
    }

    #[tokio::test]
    async fn freebsd_platform_needs_no_probe() {
        let mock = MockRunner::new();
        check_platform(&&mock, "t1", ImagePlatform::Freebsd, &sh_args())
            .await
            .unwrap();
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn linux_platform_probes_the_sysctl() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_OSRELEASE, "");
        check_platform(&&mock, "t1", ImagePlatform::Linux, &sh_args())
            .await
            .unwrap();
        assert_eq!(mock.calls(), ["/sbin/sysctl -n compat.linux.osrelease"]);
    }

    #[tokio::test]
    async fn missing_linuxulator_is_an_operator_grade_error() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_UNKNOWN_OID);
        let err = check_platform(&&mock, "t1", ImagePlatform::Linux, &sh_args())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("t1"), "{msg}");
        assert!(
            msg.contains("/sbin/sysctl -n compat.linux.osrelease"),
            "{msg}"
        );
        assert!(msg.contains("linux_enable"), "{msg}");
        assert!(msg.contains("unknown oid"), "{msg}");
    }

    #[tokio::test]
    async fn systemd_and_init_entrypoints_are_rejected_without_probing() {
        let mock = MockRunner::new();
        for entrypoint in ["/usr/lib/systemd/systemd", "/sbin/init", "systemd", "init"] {
            let args = vec![entrypoint.to_owned(), "--system".to_owned()];
            let err = check_platform(&&mock, "t1", ImagePlatform::Linux, &args)
                .await
                .unwrap_err();
            let msg = err.to_string();
            assert!(
                matches!(err, RuntimeError::EntrypointNeedsInit { .. }),
                "{entrypoint}: {msg}"
            );
            assert!(msg.contains("dies silently"), "{msg}");
            assert!(msg.contains("PID namespace"), "{msg}");
        }
        // The heuristic is a basename match, not a substring match.
        mock.push_output(0, FIXTURE_OSRELEASE, "");
        let args = vec!["/usr/bin/systemd-detect-virt".to_owned()];
        check_platform(&&mock, "t1", ImagePlatform::Linux, &args)
            .await
            .unwrap();
        assert!(mock.calls().len() == 1);
    }

    #[tokio::test]
    async fn empty_args_are_rejected_on_any_platform() {
        let mock = MockRunner::new();
        for platform in [ImagePlatform::Freebsd, ImagePlatform::Linux] {
            let err = check_platform(&&mock, "t1", platform, &[])
                .await
                .unwrap_err();
            assert!(matches!(err, RuntimeError::EmptyEntrypoint { .. }), "{err}");
        }
        assert!(mock.calls().is_empty());
    }
}
