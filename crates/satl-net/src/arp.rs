// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `arp`(8) — static entries in the **host's** link-layer
//! table.
//!
//! Why this exists (M6d): a node relaying mesh traffic forwards to task
//! addresses *through its own stack*. For a task on another node the ARP
//! reply never arrives — SatL's VXLAN never floods, so broadcast ARP reaches
//! only the blackhole default remote — and the relaying node must carry a
//! static entry instead (measured in `hack/experiments/mesh`). Jails are a
//! different path (`satl-overlay`'s `__jail-arp` helper): a jail's table
//! cannot be written from outside it, while the host's can.
//!
//! ## The lying exit status (CLAUDE.md gotcha)
//!
//! `arp -s` reports `cannot locate <ip>` on stderr and **exits 0** for an
//! address that is not on-link — exit status is not evidence. So [`Arp::set`]
//! verifies by reading the entry back, and returns what the read-back says.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use satl_core::MacAddr;

use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `arp` binary on FreeBSD.
pub const DEFAULT_ARP_BINARY: &str = "/usr/sbin/arp";

/// Error from an `arp`(8) invocation. Every variant carries the full command
/// line; command failures carry exit status and raw stderr.
#[derive(Debug, thiserror::Error)]
pub enum ArpError {
    /// The `arp` binary could not be spawned.
    #[error("arp ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("arp ({context}): {failure}")]
    Failed {
        /// What was being attempted.
        context: String,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },

    /// `arp -s` claimed success but the read-back disagrees — the one shape
    /// this wrapper exists to catch (see the module docs).
    #[error("arp ({context}): `arp -s {addr}` exited 0 but the entry reads back as: {readback:?}")]
    Unverified {
        /// What was being attempted.
        context: String,
        /// The address that was to be set.
        addr: Ipv4Addr,
        /// What `arp -n <addr>` actually reports.
        readback: String,
    },
}

fn args_set(addr: Ipv4Addr, mac: MacAddr) -> Vec<String> {
    ["-s", &addr.to_string(), &mac.to_string()]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_delete(addr: Ipv4Addr) -> Vec<String> {
    ["-d", &addr.to_string()]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn args_show(addr: Ipv4Addr) -> Vec<String> {
    ["-n", &addr.to_string()]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// Parse `arp -n <addr>` output into the entry's MAC. Real shapes (FreeBSD
/// 15.1, fixtures):
///
/// ```text
/// ? (10.2.9.9) at 02:42:0a:02:09:09 on vtnet1 permanent [ethernet]
/// 10.90.0.9 (10.90.0.9) -- no entry
/// ```
///
/// An incomplete resolution reads `at (incomplete)`; it is a non-answer like
/// the absence of an entry.
fn parse_show(addr: Ipv4Addr, stdout: &str) -> Option<MacAddr> {
    let line = stdout.lines().next()?;
    if line.contains("no entry") || line.contains("(incomplete)") {
        return None;
    }
    // `arp -n <addr>` answers for that address only; a line that does not
    // name it is not an answer to the question asked.
    if !line.contains(&format!("({addr})")) {
        return None;
    }
    let at = line.split_whitespace().position(|word| word == "at")?;
    let mac = line.split_whitespace().nth(at + 1)?;
    mac.parse().ok()
}

/// Typed async wrapper around the `arp`(8) binary, host table only.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock
/// executor; production code uses [`Arp::system`].
#[derive(Debug, Clone)]
pub struct Arp<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Arp<SystemRunner> {
    /// Wrapper executing the real `arp` binary.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl<R: CommandRunner> Arp<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_ARP_BINARY),
            runner,
        }
    }

    async fn exec(&self, context: &str, args: Vec<String>) -> Result<CommandOutput, ArpError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running arp");
        self.runner
            .run(&self.binary, &args, None)
            .await
            .map_err(|source| ArpError::Spawn {
                context: context.to_owned(),
                argv: rendered,
                source,
            })
    }

    /// The entry for `addr`, if one resolves (static or learned).
    pub async fn get(&self, addr: Ipv4Addr) -> Result<Option<MacAddr>, ArpError> {
        let context = format!("show entry for {addr}");
        let output = self.exec(&context, args_show(addr)).await?;
        // `-- no entry` exits 1; that is the answer, not a failure.
        Ok(parse_show(addr, &output.stdout))
    }

    /// Install a static entry `addr -> mac`, verified by read-back.
    ///
    /// # Errors
    ///
    /// [`ArpError::Unverified`] when `arp -s` exited 0 but the entry is not
    /// there — the historical `cannot locate <ip>` shape (CLAUDE.md).
    pub async fn set(&self, addr: Ipv4Addr, mac: MacAddr) -> Result<(), ArpError> {
        let context = format!("set entry {addr} -> {mac}");
        let output = self.exec(&context, args_set(addr, mac)).await?;
        if !output.success() {
            return Err(ArpError::Failed {
                context,
                failure: Failure::new(render_argv(&self.binary, &args_set(addr, mac)), &output),
            });
        }
        let readback = self.get(addr).await?;
        if readback == Some(mac) {
            return Ok(());
        }
        Err(ArpError::Unverified {
            context,
            addr,
            readback: match readback {
                Some(other) => format!("{addr} at {other}"),
                None => format!("{addr}: no entry"),
            },
        })
    }

    /// Delete the entry for `addr`. Idempotent: deleting what nothing holds
    /// is success (`arp: delete <ip>: No such file or directory` — measured,
    /// exit 1).
    pub async fn delete(&self, addr: Ipv4Addr) -> Result<(), ArpError> {
        let context = format!("delete entry for {addr}");
        let output = self.exec(&context, args_delete(addr)).await?;
        if !output.success() && !output.stderr.contains("No such file or directory") {
            return Err(ArpError::Failed {
                context,
                failure: Failure::new(render_argv(&self.binary, &args_delete(addr)), &output),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    /// Real captures (FreeBSD 15.1, cluster VM).
    const FIXTURE_PERMANENT: &str = include_str!("../tests/fixtures/arp_show_permanent.txt");
    const FIXTURE_NO_ENTRY: &str = include_str!("../tests/fixtures/arp_show_no_entry.txt");

    #[test]
    fn show_output_parses_the_mac() {
        let mac = parse_show("10.2.9.9".parse().unwrap(), FIXTURE_PERMANENT).unwrap();
        assert_eq!(mac.to_string(), "02:42:0a:02:09:09");
    }

    #[test]
    fn no_entry_and_incomplete_are_no_answer() {
        assert_eq!(
            parse_show("10.90.0.9".parse().unwrap(), FIXTURE_NO_ENTRY),
            None
        );
        assert_eq!(
            parse_show(
                "10.90.0.9".parse().unwrap(),
                "? (10.90.0.9) at (incomplete) on satl-br4096 [ethernet]\n"
            ),
            None
        );
        assert_eq!(parse_show("10.90.0.9".parse().unwrap(), ""), None);
    }

    #[tokio::test]
    async fn set_verifies_by_readback() {
        let mock = MockRunner::new();
        mock.push_ok();
        mock.push_output(0, FIXTURE_PERMANENT, "");
        let arp = Arp::with_runner(&mock);
        arp.set(
            "10.2.9.9".parse().unwrap(),
            "02:42:0a:02:09:09".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/usr/sbin/arp -s 10.2.9.9 02:42:0a:02:09:09",
                "/usr/sbin/arp -n 10.2.9.9",
            ]
        );
    }

    /// The whole point of the wrapper: `arp -s` exits 0 and prints `cannot
    /// locate <ip>` for an off-link address (CLAUDE.md) — the read-back
    /// catches what the exit status hides.
    #[tokio::test]
    async fn set_reports_an_exit_zero_that_lied() {
        let mock = MockRunner::new();
        mock.push_output(0, "", "arp: cannot locate 10.90.0.9\n");
        mock.push_output(1, "", FIXTURE_NO_ENTRY);
        let arp = Arp::with_runner(&mock);
        let err = arp
            .set(
                "10.90.0.9".parse().unwrap(),
                "02:42:0a:02:09:09".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ArpError::Unverified { .. }), "{err}");
        assert!(err.to_string().contains("10.90.0.9"), "{err}");
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let mock = MockRunner::new();
        mock.push_output(0, "10.90.0.9 (10.90.0.9) deleted\n", "");
        mock.push_output(1, "", "arp: delete 10.90.0.9: No such file or directory\n");
        let arp = Arp::with_runner(&mock);
        arp.delete("10.90.0.9".parse().unwrap()).await.unwrap();
        arp.delete("10.90.0.9".parse().unwrap()).await.unwrap();
        assert_eq!(
            mock.calls(),
            ["/usr/sbin/arp -d 10.90.0.9"; 2].map(str::to_owned)
        );
    }
}
