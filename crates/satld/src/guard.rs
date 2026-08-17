// SPDX-License-Identifier: BSD-2-Clause
//! The pf cleartext guard and the enc0/IPsec substrate for encrypted overlay
//! networks (M6, `--opt encrypted`).
//!
//! The measured design is `hack/experiments/esp/README.md` §7: an encrypted
//! network's VXLAN port must accept ESP-encapsulated datagrams and **drop
//! cleartext** ones, and the inbound `require` SP does not do that dropping
//! on FreeBSD 15.1 (§"Consequences", item 4) — pf does, via `if_enc`(4):
//!
//! - `net.enc.in.ipsec_filter_mask=2` presents packets to pfil(9) — and thus
//!   pf — on `enc0` **after** the ESP header is stripped (the default 1
//!   presents them as ESP, which a UDP rule cannot match);
//! - with `enc0` up, the [`satl_net::guard_rules`] anchor rules then pass the
//!   decapsulated flow (`no state` — load-bearing, §7 G4) and block the same
//!   ports on the underlay, where cleartext is the only thing that can
//!   arrive.
//!
//! Both are a function of "this node hosts at least one encrypted network":
//! the substrate is set and the guard anchor loaded on the first, the anchor
//! is flushed when the last one leaves. The sysctl is deliberately **not**
//! restored on the way down: it is node-wide, a third-party `IPsec` user may
//! have appeared in the meantime and would break if its filter presentation
//! changed under it, and the mask alone is inert without matching SAs — the
//! same reasoning the experiment records (§"Consequences", item 7).
//!
//! Everything is warn-and-retry, never fatal: a guard that cannot be
//! installed degrades confidentiality, not availability, and the next
//! reconcile pass (assignment-driven or the periodic resync) retries.
//! Success is logged once, on the transition, not on every pass.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use satl_net::{
    ANCHOR_GUARD, CommandRunner, ENC_IFACE, Ifconfig, PfCtl, SystemRunner, guard_rules,
};

use crate::sysctl::DEFAULT_SYSCTL_BINARY;

/// The sysctl assignment enabling decapsulated presentation on `enc0`
/// (`net.enc.in.ipsec_filter_mask=2`, measured — see the module docs).
const FILTER_MASK_ASSIGNMENT: &str = "net.enc.in.ipsec_filter_mask=2";

/// Why one guard operation failed. Follows the wrapper rules (CLAUDE.md):
/// the error says what was attempted and carries the full argv, exit status
/// and stderr of the failed command.
#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    /// The `sysctl` assignment failed.
    #[error("guard: `{argv}` failed (exit {exit_code:?}); stderr: {stderr}")]
    Sysctl {
        /// Full rendered command line.
        argv: String,
        /// Exit code, `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr.
        stderr: String,
    },

    /// A command could not be spawned at all.
    #[error("guard: failed to spawn `{argv}`: {source}")]
    Spawn {
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The `pfctl` anchor operation failed.
    #[error(transparent)]
    Pf(#[from] satl_net::PfError),

    /// The `ifconfig enc0 up` failed.
    #[error(transparent)]
    Ifconfig(#[from] satl_net::IfconfigError),
}

/// Whether the node-wide enc0/IPsec substrate has been set up.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Substrate {
    /// Never attempted in this process.
    #[default]
    Untouched,
    /// `net.enc.in.ipsec_filter_mask=2` set and `enc0` up. Never reversed —
    /// see the module docs for why.
    Ready,
    /// The last attempt failed; retried on the next pass, warned about once
    /// per failure streak rather than once per pass.
    Failed,
}

/// The reconciled state, behind a mutex that is **never held across an
/// `.await`** (read, drop, run the command, re-acquire to record).
#[derive(Debug, Default)]
struct GuardState {
    substrate: Substrate,
    /// Whether the guard anchor currently holds our rules.
    installed: bool,
}

/// The guard reconciler: one per daemon, driven by the overlay manager on
/// every network pass. Generic over the command runner so the install/remove
/// transitions are unit-testable with no live `pfctl`/`sysctl`/`ifconfig`.
#[derive(Debug)]
pub struct Guard<R = SystemRunner> {
    sysctl: PathBuf,
    runner: R,
    pf: PfCtl<R>,
    ifconfig: Ifconfig<R>,
    state: Mutex<GuardState>,
}

impl Guard<SystemRunner> {
    /// A guard executing the real binaries.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Guard<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner + Clone> Guard<R> {
    /// A guard using `runner` for every command (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            sysctl: PathBuf::from(DEFAULT_SYSCTL_BINARY),
            runner: runner.clone(),
            pf: PfCtl::with_runner(runner.clone()),
            ifconfig: Ifconfig::with_runner(runner),
            state: Mutex::new(GuardState::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GuardState> {
        // A poisoned mutex still holds a coherent state here (no update is
        // ever left half-done: each mutation is a single field store), so
        // recovering is safe and avoids an unwrap.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Move the guard towards `wanted`: with at least one encrypted network
    /// on this node, the substrate is ensured and the anchor loaded; with
    /// none left, the anchor is flushed. Idempotent; every failure is a
    /// warning and a retry on the next pass, never an error to the caller.
    pub async fn reconcile(&self, wanted: bool, underlay_if: &str) {
        if wanted {
            if let Err(error) = self.ensure_substrate().await {
                let mut state = self.lock();
                if state.substrate != Substrate::Failed {
                    tracing::warn!(
                        %error,
                        "cannot set up the enc0/IPsec substrate; the cleartext guard \
                         is inert without it and every pass will retry"
                    );
                }
                state.substrate = Substrate::Failed;
            }
            if let Err(error) = self.install(underlay_if).await {
                tracing::warn!(
                    %error,
                    "cannot install the overlay cleartext guard; encrypted networks \
                     are unprotected until the next pass retries"
                );
            }
        } else if let Err(error) = self.remove().await {
            tracing::warn!(
                %error,
                "cannot remove the overlay cleartext guard; the next pass will retry"
            );
        }
    }

    /// `sysctl net.enc.in.ipsec_filter_mask=2` plus `ifconfig enc0 up`, once
    /// per process (and again after a failure). `Ok(())` is also the answer
    /// when the substrate is already [`Substrate::Ready`].
    async fn ensure_substrate(&self) -> Result<(), GuardError> {
        if self.lock().substrate == Substrate::Ready {
            return Ok(());
        }
        let args = vec![FILTER_MASK_ASSIGNMENT.to_owned()];
        let rendered = format!("{} {}", self.sysctl.display(), args.join(" "));
        let output = self
            .runner
            .run(&self.sysctl, &args, None)
            .await
            .map_err(|source| GuardError::Spawn {
                argv: rendered.clone(),
                source,
            })?;
        // Both steps are independent and idempotent: a failed sysctl must not
        // also skip `enc0 up` (and vice versa on the next pass), or a single
        // transient failure would strand the other half of the substrate.
        let sysctl_result = if output.success() {
            Ok(())
        } else {
            Err(GuardError::Sysctl {
                argv: rendered,
                exit_code: output.exit_code,
                stderr: output.stderr,
            })
        };
        let ifconfig_result = self.ifconfig.up(ENC_IFACE).await.map_err(GuardError::from);
        sysctl_result.and(ifconfig_result)?;
        let mut state = self.lock();
        if state.substrate != Substrate::Ready {
            tracing::info!(
                assignment = FILTER_MASK_ASSIGNMENT,
                iface = ENC_IFACE,
                "enc0/IPsec substrate ready: decapsulated packets are now \
                 presented to pf on enc0 (node-wide, left in place when the \
                 last encrypted network leaves)"
            );
        }
        state.substrate = Substrate::Ready;
        Ok(())
    }

    /// Load the guard anchor if it is not already loaded.
    async fn install(&self, underlay_if: &str) -> Result<(), GuardError> {
        if self.lock().installed {
            return Ok(());
        }
        self.pf
            .load_anchor(ANCHOR_GUARD, &guard_rules(underlay_if))
            .await?;
        self.lock().installed = true;
        tracing::info!(
            anchor = ANCHOR_GUARD,
            underlay_if,
            "overlay cleartext guard installed: VXLAN on encrypted ports must \
             now arrive ESP-encapsulated"
        );
        Ok(())
    }

    /// Flush the guard anchor if it is loaded. The substrate stays — see the
    /// module docs.
    async fn remove(&self) -> Result<(), GuardError> {
        if !self.lock().installed {
            return Ok(());
        }
        self.pf.flush_anchor(ANCHOR_GUARD).await?;
        self.lock().installed = false;
        tracing::info!(
            anchor = ANCHOR_GUARD,
            "overlay cleartext guard removed: no encrypted network left on this node"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::path::Path;

    /// Runner replaying canned outputs and recording argv + stdin, in the
    /// house style of `satl_net::runner::MockRunner` (which is crate-private).
    #[derive(Debug, Default)]
    struct MockRunner {
        responses: Mutex<VecDeque<io::Result<satl_net::CommandOutput>>>,
        calls: Mutex<Vec<String>>,
        stdins: Mutex<Vec<Option<String>>>,
    }

    impl MockRunner {
        fn push_output(&self, exit_code: i32, stdout: &str, stderr: &str) {
            self.lock_responses().push_back(Ok(satl_net::CommandOutput {
                exit_code: Some(exit_code),
                stdout: stdout.to_owned(),
                stderr: stderr.to_owned(),
            }));
        }

        fn push_ok(&self) {
            self.push_output(0, "", "");
        }

        fn lock_responses(&self) -> MutexGuard<'_, VecDeque<io::Result<satl_net::CommandOutput>>> {
            self.responses
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }

        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        fn stdins(&self) -> Vec<Option<String>> {
            self.stdins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl CommandRunner for &MockRunner {
        async fn run(
            &self,
            program: &Path,
            args: &[String],
            stdin: Option<&str>,
        ) -> io::Result<satl_net::CommandOutput> {
            let mut rendered = program.display().to_string();
            for arg in args {
                rendered.push(' ');
                rendered.push_str(arg);
            }
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(rendered.clone());
            self.stdins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(stdin.map(str::to_owned));
            self.lock_responses()
                .pop_front()
                .unwrap_or_else(|| panic!("MockRunner: unexpected call {rendered}"))
        }
    }

    #[tokio::test]
    async fn the_first_encrypted_network_sets_the_substrate_and_loads_the_anchor() {
        let mock = MockRunner::default();
        mock.push_ok();
        mock.push_ok();
        mock.push_ok();
        let guard = Guard::with_runner(&mock);

        guard.reconcile(true, "vtnet1").await;

        assert_eq!(
            mock.calls(),
            [
                "/sbin/sysctl net.enc.in.ipsec_filter_mask=2",
                "/sbin/ifconfig enc0 up",
                "/sbin/pfctl -a satl/guard -f -",
            ]
        );
        // The anchor rules are the measured guard text for this underlay.
        assert_eq!(mock.stdins()[2], Some(guard_rules("vtnet1")));
    }

    #[tokio::test]
    async fn a_steady_state_reconcile_runs_nothing() {
        let mock = MockRunner::default();
        mock.push_ok();
        mock.push_ok();
        mock.push_ok();
        let guard = Guard::with_runner(&mock);
        guard.reconcile(true, "vtnet1").await;
        let before = mock.calls().len();

        guard.reconcile(true, "vtnet1").await;
        assert_eq!(
            mock.calls().len(),
            before,
            "no command on an unchanged pass"
        );

        // And a node that never had an encrypted network runs nothing either.
        let quiet = MockRunner::default();
        Guard::with_runner(&quiet).reconcile(false, "vtnet1").await;
        assert!(quiet.calls().is_empty());
    }

    #[tokio::test]
    async fn the_last_encrypted_network_leaving_flushes_the_anchor_but_keeps_the_sysctl() {
        let mock = MockRunner::default();
        for _ in 0..5 {
            mock.push_ok();
        }
        let guard = Guard::with_runner(&mock);
        guard.reconcile(true, "vtnet1").await;

        guard.reconcile(false, "vtnet1").await;
        assert_eq!(
            mock.calls()[3..],
            [
                "/sbin/pfctl -a satl/guard -F nat",
                "/sbin/pfctl -a satl/guard -F rules",
            ]
        );
        // Notably absent: any restore of net.enc.in.ipsec_filter_mask. The
        // mask is node-wide and a third-party IPsec user may rely on it now;
        // without matching SAs it is inert (module docs).

        // A further empty pass is a no-op, and a new encrypted network
        // reinstalls only the anchor (the substrate is still ready).
        guard.reconcile(false, "vtnet1").await;
        assert_eq!(mock.calls().len(), 5);
        mock.push_ok();
        guard.reconcile(true, "vtnet1").await;
        assert_eq!(mock.calls()[5..], ["/sbin/pfctl -a satl/guard -f -"]);
    }

    #[tokio::test]
    async fn a_failed_substrate_is_retried_while_the_anchor_still_installs() {
        let mock = MockRunner::default();
        // sysctl fails; enc0 up and the anchor load succeed.
        mock.push_output(1, "", "sysctl: unknown oid 'net.enc.in.ipsec_filter_mask'");
        mock.push_ok();
        mock.push_ok();
        let guard = Guard::with_runner(&mock);
        guard.reconcile(true, "vtnet1").await;
        // The guard went in anyway: the substrate failing must not also
        // abandon the block rule, and neither failure may be fatal.
        assert!(guard.lock().installed);
        assert_eq!(guard.lock().substrate, Substrate::Failed);

        // The next pass retries the substrate (sysctl and enc0 up, both
        // idempotent) but not the already-loaded anchor.
        mock.push_ok();
        mock.push_ok();
        guard.reconcile(true, "vtnet1").await;
        assert_eq!(
            mock.calls()[3..],
            [
                "/sbin/sysctl net.enc.in.ipsec_filter_mask=2",
                "/sbin/ifconfig enc0 up",
            ]
        );
        assert_eq!(guard.lock().substrate, Substrate::Ready);
    }

    #[tokio::test]
    async fn a_failed_anchor_load_is_retried_on_the_next_pass() {
        let mock = MockRunner::default();
        mock.push_ok();
        mock.push_ok();
        mock.push_output(1, "", "pfctl: syntax error");
        let guard = Guard::with_runner(&mock);
        guard.reconcile(true, "vtnet1").await;
        assert!(!guard.lock().installed);

        mock.push_ok();
        guard.reconcile(true, "vtnet1").await;
        assert!(guard.lock().installed);
        // The substrate was ready, so the retry is the anchor load alone.
        assert_eq!(mock.calls()[3..], ["/sbin/pfctl -a satl/guard -f -"]);
    }
}
