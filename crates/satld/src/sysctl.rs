// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `sysctl`(8) (M0: read-only, `-n` values).
//!
//! Follows the external-command-wrapper rules (CLAUDE.md): typed functions,
//! pure fixture-tested parsing, and errors that carry the full command line,
//! exit status, and raw stderr.
//!
//! This module is satld-local for M0 and moves to `satl-agent` with the node
//! description work (architecture §8.3).

use std::path::PathBuf;

use anyhow::{Context as _, bail};

/// Default location of the `sysctl` binary on FreeBSD.
pub const DEFAULT_SYSCTL_BINARY: &str = "/sbin/sysctl";

/// Typed async wrapper around the `sysctl` binary.
#[derive(Debug, Clone)]
pub struct Sysctl {
    binary: PathBuf,
}

impl Default for Sysctl {
    fn default() -> Self {
        Self::system()
    }
}

/// Build the argv for `sysctl -n <oid>` (pure; unit-tested).
fn args_get(oid: &str) -> Vec<String> {
    vec!["-n".to_owned(), oid.to_owned()]
}

/// Parse `sysctl -n` output: exactly one non-empty line (pure; fixture-tested).
fn parse_value(stdout: &str) -> Result<String, String> {
    let mut lines = stdout.lines();
    let Some(value) = lines.next() else {
        return Err("expected one line of output, got none".to_owned());
    };
    if lines.next().is_some() {
        return Err("expected exactly one line of output, got more".to_owned());
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("expected a non-empty value".to_owned());
    }
    Ok(value.to_owned())
}

/// Parse a numeric sysctl value such as `hw.physmem` (pure; fixture-tested).
fn parse_u64(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|err| format!("expected an unsigned integer, got {value:?}: {err}"))
}

impl Sysctl {
    /// Wrapper for the real binary at [`DEFAULT_SYSCTL_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_SYSCTL_BINARY),
        }
    }

    /// Read a sysctl value: `sysctl -n <oid>`.
    pub async fn get(&self, oid: &str) -> anyhow::Result<String> {
        let args = args_get(oid);
        let rendered = format!("{} {}", self.binary.display(), args.join(" "));
        let output = tokio::process::Command::new(&self.binary)
            .args(&args)
            .output()
            .await
            .with_context(|| format!("failed to spawn `{rendered}`"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "`{rendered}` failed with {status}; stderr: {stderr:?}",
                status = output.status,
                stderr = stderr.trim_end(),
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_value(&stdout).map_err(|reason| {
            anyhow::anyhow!("unexpected output from `{rendered}`: {reason}; raw stdout: {stdout:?}")
        })
    }

    /// Read a numeric sysctl value (e.g. `hw.physmem`).
    pub async fn get_u64(&self, oid: &str) -> anyhow::Result<u64> {
        let value = self.get(oid).await?;
        parse_u64(&value)
            .map_err(|reason| anyhow::anyhow!("sysctl -n {oid} returned {value:?}: {reason}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PHYSMEM: &str = include_str!("../tests/fixtures/sysctl_hw_physmem.txt");
    const FIXTURE_OSRELEASE: &str = include_str!("../tests/fixtures/sysctl_kern_osrelease.txt");
    const FIXTURE_UNKNOWN_OID: &str = include_str!("../tests/fixtures/sysctl_unknown_oid.txt");

    #[test]
    fn argv_for_get() {
        assert_eq!(args_get("hw.physmem"), ["-n", "hw.physmem"]);
    }

    #[test]
    fn parses_physmem_fixture_as_u64() {
        let value = parse_value(FIXTURE_PHYSMEM).unwrap();
        assert_eq!(parse_u64(&value).unwrap(), 68_258_983_936);
    }

    #[test]
    fn parses_osrelease_fixture() {
        assert_eq!(parse_value(FIXTURE_OSRELEASE).unwrap(), "15.1-RELEASE-p2");
    }

    #[test]
    fn unknown_oid_stderr_is_not_a_value() {
        // stderr fixture: `sysctl: unknown oid 'kern.nosuchthing'` — sanity-
        // check that the failure diagnostic never parses as a number.
        let line = parse_value(FIXTURE_UNKNOWN_OID).unwrap();
        assert!(parse_u64(&line).is_err());
    }

    #[test]
    fn rejects_empty_and_multiline_output() {
        assert!(parse_value("").is_err());
        assert!(parse_value("\n").is_err());
        assert!(parse_value("a\nb\n").is_err());
    }

    #[test]
    fn rejects_non_numeric_u64() {
        assert!(parse_u64("15.1-RELEASE-p2").is_err());
        assert!(parse_u64("-1").is_err());
    }
}
