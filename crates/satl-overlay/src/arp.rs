// SPDX-License-Identifier: BSD-2-Clause
//! Static ARP entries inside a task jail's VNET: **the interface**
//! ([`JailArp`]), plus the `jexec <jail> arp` implementation of it.
//!
//! **Static ARP for remote overlay endpoints is mandatory, not an
//! optimisation** (`docs/vxlan.md` §4). A broadcast ARP request leaving a
//! bridge is encapsulated to the vxlan interface's single default remote and
//! nowhere else, so on any cluster with more than two nodes ARP simply cannot
//! resolve a peer. Every remote endpoint therefore needs an entry in every
//! local jail's own table — and each VNET jail has its own table, so this is
//! per (local task, remote endpoint), not per node.
//!
//! **Measured**, so that it is not taken on faith
//! (`hack/experiments/jail-arp/captures/30-premise-and-mechanism.txt` §3): two
//! nodes of one overlay, both FDB directions programmed, both jails up — and a
//! ping between them at **100 % loss** with the requester's table holding
//! `10.79.9.12 (incomplete)`. The vxlan interface's `Opkts` stayed 0 while
//! `Oerrs` rose by four: the ARP broadcasts went to the default remote and
//! nowhere else. One static entry per side, nothing else changed, and the same
//! ping answers in 0.07 ms.
//!
//! ## Two mechanisms, and which is the default
//!
//! | | [`Arp`] (this module) | [`crate::arphelper::ArpHelper`] |
//! |---|---|---|
//! | how | `jexec <jail> arp` | re-exec `satld __jail-arp`, `jail_attach` + `PF_ROUTE` |
//! | needs | an `arp`(8) **inside** the jail | nothing in the jail |
//! | works for a container | **no** — see [`ArpError::MissingBinary`] | yes |
//! | works for `path=/` | yes | yes |
//!
//! [`Arp`] is kept for `path=/` jails and for tests — it is the readable path,
//! and every fixture in this module was captured from it — but **the default for
//! a task is the helper**, because a task's rootfs is an OCI image.
//!
//! ## Why not `arp -j`, or `route -j`
//!
//! `ifconfig` and `route` both have a `-j` flag and `satl-net` uses them;
//! `arp`(8) is the one tool without one. `route -j` cannot substitute: modern
//! FreeBSD keeps ARP in the link-layer table and requires `RTF_LLDATA`, which
//! `route`(8) never sets. Measured on FreeBSD 15.1:
//!
//! ```text
//! # route -j <jail> add -host 10.79.0.21 -link -iface 02:42:0a:4f:00:15
//! route: interface '02:42:0a:4f:00:15' does not exist
//! # route -j <jail> add -host 10.79.0.22 -link 02:42:0a:4f:00:16 -static
//! route: message indicates error: Invalid argument
//! ```
//!
//! What is left is the routing socket `arp`(8) itself uses, from inside the
//! jail's stack — [`crate::lltable`] for the mechanism,
//! [`crate::arphelper`] for the child that can safely enter it.
//!
//! ## Two silent failures
//!
//! Measured while writing this module (`tests/fixtures/arp_*.txt`):
//!
//! - **`arp -s` exits 0 when it fails.** An address that is not on-link for
//!   any interface in that stack gives `arp: set: cannot locate <ip>` on
//!   stderr and **exit status 0**. `docs/vxlan.md` §4 records the message but
//!   not the exit status; taking the exit status at face value would report a
//!   programmed overlay that silently drops every packet to that peer.
//! - `arp -d` on an absent entry exits **1** with
//!   `arp: delete <ip>: No such file or directory`, which is the idempotent
//!   case and is mapped to `Ok(false)`.
//!
//! ## Which entries are SatL's
//!
//! `arp -an` carries no ownership marker, and a jail's table also holds the
//! kernel's permanent entry for the jail's own address and a *learned* entry
//! for its gateway. Deleting either would be a silent black hole
//! (`docs/vxlan.md` §8: the cached entry survives the address it points at).
//! [`ArpEntry::is_overlay_static`] is the ownership test.

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use satl_core::MacAddr;

use crate::lltable::LlEntry;
use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `jexec` binary on FreeBSD.
pub const DEFAULT_JEXEC_BINARY: &str = "/usr/sbin/jexec";

/// Command name `jexec` resolves **inside the jail**.
pub const DEFAULT_ARP_COMMAND: &str = "arp";

/// One entry of a jail's ARP table, from either mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    /// The address the entry resolves.
    pub ip: Ipv4Addr,
    /// Its MAC; `None` for an incomplete (unresolved) entry.
    pub mac: Option<MacAddr>,
    /// Interface the entry is attached to.
    pub iface: String,
    /// Whether the entry never expires and is never replaced by an ARP reply.
    pub permanent: bool,
    /// Whether the kernel marked the entry immutable (`RTF_PINNED`, i.e.
    /// `LLE_IFADDR`): it is the jail's **own** address.
    ///
    /// Only the routing-socket mechanism can see this — `arp -an` does not print
    /// it — so an entry read through [`Arp`] always reports `false` and the
    /// caller has to exclude the jail's own addresses itself. See
    /// [`Self::is_overlay_static`].
    pub pinned: bool,
    /// The entry as the source rendered it, for diagnostics.
    pub raw: String,
}

impl ArpEntry {
    /// The same entry as [`crate::lltable`] read it out of the kernel.
    #[must_use]
    pub fn from_ll(entry: &LlEntry) -> Self {
        Self {
            ip: entry.ip,
            mac: entry.mac,
            iface: entry.iface.clone().unwrap_or_default(),
            permanent: entry.permanent(),
            pinned: entry.pinned(),
            raw: format!(
                "{} at {} on {} ifindex {} flags {:#x} expire {}",
                entry.ip,
                entry
                    .mac
                    .map_or_else(|| "(incomplete)".to_owned(), |mac| mac.to_string()),
                entry.iface.as_deref().unwrap_or("?"),
                entry.ifindex,
                entry.flags,
                entry.expire,
            ),
        }
    }

    /// Whether this entry is one SatL's overlay programming installed.
    ///
    /// The test is `permanent && !pinned && mac == MacAddr::from_ipv4(ip)`.
    /// All three parts are load-bearing:
    ///
    /// - the derived MAC excludes every kernel-generated address, so a
    ///   learned gateway entry (`58:9c:fc:...`) is never mistaken for ours;
    /// - `permanent` excludes a *dynamically learned* entry for a local peer,
    ///   whose MAC **is** the derived one (the node sets it on the epair) but
    ///   which SatL did not install and must not account for;
    /// - `pinned` excludes the jail's own address, which otherwise passes both
    ///   other tests: the kernel installs it permanent with the interface's MAC,
    ///   which SatL derived from that very address.
    ///
    /// `pinned` is only observable through the routing socket. Read through
    /// `arp -an` it is always `false`, so callers must *still* exclude the
    /// jail's own addresses by address; [`crate::program`] does, for both
    /// mechanisms.
    #[must_use]
    pub fn is_overlay_static(&self) -> bool {
        self.permanent && !self.pinned && self.mac == Some(MacAddr::from_ipv4(self.ip))
    }
}

/// Error from ARP programming inside a jail.
#[derive(Debug, thiserror::Error)]
pub enum ArpError {
    /// The `jexec` binary could not be spawned.
    #[error("arp ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted, naming the jail.
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
        /// What was being attempted, naming the jail.
        context: String,
        /// The failed command with argv, exit status and stderr.
        failure: Failure,
    },

    /// **The silent failure.** `arp -s` exited 0 but refused the entry
    /// because the address is not on-link for any interface in that jail's
    /// stack.
    #[error(
        "arp: jail '{jail}' refused the static entry {ip} -> {mac}: `arp -s` \
         printed {diagnostic:?} and still exited 0. The address must be \
         on-link for some interface in that jail's stack; check that the \
         task's epair holds an address in the same subnet and is up \
         (docs/vxlan.md section 4)"
    )]
    NotOnLink {
        /// The jail the entry was destined for.
        jail: String,
        /// The address that could not be located.
        ip: Ipv4Addr,
        /// The MAC that would have been installed.
        mac: MacAddr,
        /// What `arp` printed.
        diagnostic: String,
    },

    /// The jail does not exist (it died between the assignment and this call).
    #[error("arp ({context}): jail '{jail}' does not exist")]
    NoSuchJail {
        /// What was being attempted.
        context: String,
        /// The missing jail.
        jail: String,
    },

    /// `arp`(8) is not usable **inside** the jail — which is the normal case for
    /// a container, and the reason this whole module is not the default.
    ///
    /// `jexec` execs the command from the jail's own filesystem. Measured on
    /// this host against four real containers
    /// (`hack/experiments/jail-arp/captures/10-jexec-cannot-work.txt`), there
    /// are two shapes of failure and both are fatal:
    ///
    /// ```text
    /// # jexec 6 arp -an                       # a rootfs with no arp at all
    /// jexec: execvp: arp: No such file or directory
    /// # jexec 3 arp -an                       # a Linux image WITH /sbin/arp
    /// arp: can't open '/proc/net/arp': No such file or directory
    /// # jexec 3 arp -s 10.79.0.12 02:42:0a:4f:00:0c
    /// arp: ioctl 0x8955 failed: Invalid argument
    /// ```
    ///
    /// The second is the nastier one: the binary exists, so a "does it exist"
    /// check would pass, but it is *Linux's* `arp` speaking Linux's ARP ABI
    /// (`0x8955` is Linux's `SIOCSARP`) under the linuxulator. It can never
    /// program a FreeBSD link-layer table.
    ///
    /// **What replaced it:** [`crate::arphelper::ArpHelper`], which re-executes
    /// `satld` with a hidden subcommand, calls `jail_attach`(2) in that
    /// short-lived child and programs the entries through a `PF_ROUTE` socket
    /// with `RTF_LLDATA` ([`crate::lltable`]). Nothing is placed in the
    /// container's filesystem — materialising an `arp`(8) there was rejected
    /// outright: an operator must not find files SatL put in their image, and
    /// read-only and distroless images make it impossible anyway.
    ///
    /// This variant therefore survives only for `path=/` jails and tests, where
    /// [`Arp`] is still the readable path.
    #[error(
        "arp: jail '{jail}' has no usable `{command}` in its own filesystem \
         ({diagnostic}). jexec runs the jail's own binary, and a container image \
         either ships no arp(8) or ships Linux's, which cannot program a FreeBSD \
         link-layer table. Use the routing-socket helper (satl-overlay's \
         ArpHelper) for task jails; the jexec path only works for path=/ jails"
    )]
    MissingBinary {
        /// The jail with no usable `arp`.
        jail: String,
        /// The command that could not be executed.
        command: String,
        /// What `jexec` printed.
        diagnostic: String,
    },

    /// The re-exec helper could not be spoken to, or answered something this
    /// build does not understand.
    #[error(
        "arp: the routing-socket helper for jail '{jail}' did not answer \
         usefully (`{argv}`, {status}): {source}; stderr: {stderr}"
    )]
    Helper {
        /// The jail the batch was for.
        jail: String,
        /// The command line that was run.
        argv: String,
        /// How the child exited, rendered ([`crate::runner::render_exit`]).
        status: String,
        /// Whatever the child wrote to stderr, rendered.
        stderr: String,
        /// The protocol or I/O error underneath.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// `arp -an` output did not have the expected shape.
    #[error(
        "arp ({context}): unexpected output from `{argv}`: {reason}; \
         raw stdout: {stdout:?}"
    )]
    UnexpectedOutput {
        /// What was being attempted.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Why the output was rejected.
        reason: String,
        /// Raw stdout from the command.
        stdout: String,
    },
}

// ---------------------------------------------------------------------------
// The interface both mechanisms implement
// ---------------------------------------------------------------------------

/// One jail's worth of static-ARP work.
///
/// Batched per jail on purpose: the routing-socket mechanism costs one process
/// spawn per call, so a per-entry API would mean one `satld` re-exec per remote
/// endpoint per local task per pass. Per jail it is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArpBatch {
    /// Entries to install or replace. `add` replaces an existing MAC, so a
    /// changed entry is one `add` and never a delete plus an add.
    pub add: Vec<(Ipv4Addr, MacAddr)>,
    /// Addresses to stop resolving.
    pub remove: Vec<Ipv4Addr>,
}

impl ArpBatch {
    /// Whether there is nothing to do — in which case a caller can skip the
    /// spawn entirely.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }

    /// How many entries this batch touches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.add.len() + self.remove.len()
    }
}

/// What programming one [`ArpBatch`] achieved.
///
/// Partial success is the normal shape: one off-link address must not cost the
/// other entries, and the reconciler's delta is idempotent, so the next pass
/// retries exactly what is still missing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArpApplied {
    /// Entries installed **and confirmed by a read-back**.
    pub added: Vec<(Ipv4Addr, MacAddr)>,
    /// Entries that were present and are now gone.
    pub removed: Vec<Ipv4Addr>,
    /// Entries that were already absent — the idempotent case.
    pub absent: Vec<Ipv4Addr>,
    /// Per-entry failures, rendered.
    pub failures: Vec<String>,
}

/// Programming and reading one jail's ARP table, whatever the mechanism.
///
/// Two implementations: [`Arp`] (`jexec arp`, for `path=/` jails and tests) and
/// [`crate::arphelper::ArpHelper`] (the re-exec helper, **the default for a
/// task**). [`crate::program::Programmer`] is generic over this trait so a whole
/// reconciliation pass can be exercised against either, or against neither.
///
/// Not object-safe, and deliberately not made so: both implementations are known
/// at compile time and static dispatch keeps the futures nameable.
pub trait JailArp: Send + Sync {
    /// Apply one batch to `jail`'s table.
    ///
    /// # Errors
    ///
    /// Only for failures that make the *whole* batch meaningless — the jail is
    /// gone, the mechanism could not run. Per-entry failures belong in
    /// [`ArpApplied::failures`].
    fn apply(
        &self,
        jail: &str,
        batch: &ArpBatch,
    ) -> impl Future<Output = Result<ArpApplied, ArpError>> + Send;

    /// The jail's whole ARP table.
    ///
    /// # Errors
    ///
    /// When the table could not be read. An unreadable table must never be
    /// reported as an empty one: the reconciler would conclude that nothing is
    /// programmed.
    fn list(&self, jail: &str) -> impl Future<Output = Result<Vec<ArpEntry>, ArpError>> + Send;

    /// The entries in `jail` that SatL's overlay programming installed:
    /// [`ArpEntry::is_overlay_static`] minus `own_addresses`.
    ///
    /// `own_addresses` are the jail's own overlay addresses. The routing-socket
    /// mechanism also marks them `RTF_PINNED`, but `arp -an` does not, so they
    /// are excluded by address here for both.
    fn list_owned(
        &self,
        jail: &str,
        own_addresses: &[Ipv4Addr],
    ) -> impl Future<Output = Result<Vec<ArpEntry>, ArpError>> + Send {
        async move {
            Ok(self
                .list(jail)
                .await?
                .into_iter()
                .filter(|entry| entry.is_overlay_static() && !own_addresses.contains(&entry.ip))
                .collect())
        }
    }
}

// ---------------------------------------------------------------------------
// Pure argv builders
// ---------------------------------------------------------------------------

fn args_set(jail: &str, command: &str, ip: Ipv4Addr, mac: MacAddr) -> Vec<String> {
    vec![
        jail.to_owned(),
        command.to_owned(),
        "-s".to_owned(),
        ip.to_string(),
        mac.to_string(),
    ]
}

fn args_delete(jail: &str, command: &str, ip: Ipv4Addr) -> Vec<String> {
    vec![
        jail.to_owned(),
        command.to_owned(),
        "-d".to_owned(),
        ip.to_string(),
    ]
}

fn args_list(jail: &str, command: &str) -> Vec<String> {
    vec![jail.to_owned(), command.to_owned(), "-an".to_owned()]
}

// ---------------------------------------------------------------------------
// Pure output classifiers and parsers
// ---------------------------------------------------------------------------

/// `arp: set: cannot locate <ip>` — printed on stderr **with exit status 0**.
fn stderr_says_cannot_locate(stderr: &str) -> bool {
    stderr.contains("cannot locate")
}

/// `arp: delete <ip>: No such file or directory`, exit 1.
fn stderr_says_no_such_entry(stderr: &str) -> bool {
    stderr.contains("No such file or directory")
}

/// `jexec: jail "<name>" not found`, exit 1.
fn stderr_says_no_such_jail(stderr: &str) -> bool {
    stderr.contains("jexec:") && stderr.contains("not found")
}

/// `jexec: execvp: arp: No such file or directory`, exit 1.
fn stderr_says_missing_binary(stderr: &str) -> bool {
    stderr.contains("jexec: execvp:")
}

/// Parse one `arp -an` row:
///
/// ```text
/// ? (10.79.0.13) at 02:42:0a:4f:00:0d on ovtest-ep0b permanent [ethernet]
/// ? (10.79.0.1) at 58:9c:fc:10:cd:b0 on ovtest-ep0b expires in 1199 seconds [ethernet]
/// ```
///
/// Returns `None` for a row that is not an entry (blank, or a shape this does
/// not recognize) so an unfamiliar row is skipped rather than failing a whole
/// reconciliation pass — the caller only ever *removes* rows it positively
/// identified as its own.
fn parse_arp_row(row: &str) -> Option<ArpEntry> {
    let row = row.trim();
    if row.is_empty() {
        return None;
    }
    let mut words = row.split_whitespace();
    let ip: Ipv4Addr =
        words.find_map(|word| word.strip_prefix('(')?.strip_suffix(')')?.parse().ok())?;
    let mut mac = None;
    let mut iface = None;
    let mut permanent = false;
    while let Some(word) = words.next() {
        match word {
            // `at (incomplete)` leaves `mac` as None.
            "at" => mac = words.next().and_then(|value| value.parse().ok()),
            "on" => iface = words.next().map(str::to_owned),
            "permanent" => permanent = true,
            _ => {}
        }
    }
    Some(ArpEntry {
        ip,
        mac,
        iface: iface.unwrap_or_default(),
        permanent,
        // `arp -an` does not print RTF_PINNED, so this mechanism cannot tell a
        // jail's own address from a peer's. Callers exclude it by address.
        pinned: false,
        raw: row.to_owned(),
    })
}

/// Parse a whole `arp -an` listing.
fn parse_arp_list(stdout: &str) -> Vec<ArpEntry> {
    stdout.lines().filter_map(parse_arp_row).collect()
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

/// Typed async wrapper around `jexec <jail> arp`.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock executor;
/// production code uses [`Arp::system`].
#[derive(Debug, Clone)]
pub struct Arp<R = SystemRunner> {
    jexec: PathBuf,
    command: String,
    runner: R,
}

impl Arp<SystemRunner> {
    /// Wrapper that executes the real `jexec` binary.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Arp<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Arp<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            jexec: PathBuf::from(DEFAULT_JEXEC_BINARY),
            command: DEFAULT_ARP_COMMAND.to_owned(),
            runner,
        }
    }

    /// Override the `jexec` binary path.
    #[must_use]
    pub fn with_jexec(mut self, binary: impl Into<PathBuf>) -> Self {
        self.jexec = binary.into();
        self
    }

    /// Override the command `jexec` runs inside the jail — an absolute path to
    /// an `arp`(8) the wiring wave materialized in the task's rootfs, for
    /// instance (see [`ArpError::MissingBinary`]).
    #[must_use]
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = command.into();
        self
    }

    async fn exec(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), ArpError> {
        let rendered = render_argv(&self.jexec, &args);
        tracing::debug!(command = %rendered, "running jexec arp");
        let output = self
            .runner
            .run(&self.jexec, &args)
            .await
            .map_err(|source| ArpError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Map the two `jexec`-level failures every call shares.
    fn jexec_error(&self, context: &str, jail: &str, output: &CommandOutput) -> Option<ArpError> {
        if stderr_says_no_such_jail(&output.stderr) {
            return Some(ArpError::NoSuchJail {
                context: context.to_owned(),
                jail: jail.to_owned(),
            });
        }
        if stderr_says_missing_binary(&output.stderr) {
            return Some(ArpError::MissingBinary {
                jail: jail.to_owned(),
                command: self.command.clone(),
                diagnostic: output.stderr.trim_end().to_owned(),
            });
        }
        None
    }

    /// Install a permanent ARP entry in `jail`'s stack:
    /// `jexec <jail> arp -s <ip> <mac>`.
    ///
    /// Re-running with a different MAC **replaces** the entry (measured: exit
    /// 0, no output), so a moved endpoint needs no delete first.
    ///
    /// The exit status is not trusted: a refusal is exit 0 with a diagnostic on
    /// stderr, and is returned as [`ArpError::NotOnLink`].
    #[tracing::instrument(skip(self), fields(ip = %ip, mac = %mac))]
    pub async fn set(&self, jail: &str, ip: Ipv4Addr, mac: MacAddr) -> Result<(), ArpError> {
        let context = format!("set static arp {ip} -> {mac} in jail '{jail}'");
        let (argv, output) = self
            .exec(&context, args_set(jail, &self.command, ip, mac))
            .await?;
        if let Some(err) = self.jexec_error(&context, jail, &output) {
            return Err(err);
        }
        // Checked before `success()`, because a refusal *is* a success by exit
        // status.
        if stderr_says_cannot_locate(&output.stderr) {
            return Err(ArpError::NotOnLink {
                jail: jail.to_owned(),
                ip,
                mac,
                diagnostic: output.stderr.trim_end().to_owned(),
            });
        }
        if output.success() {
            tracing::debug!(jail = %jail, "installed static arp entry");
            return Ok(());
        }
        Err(ArpError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }

    /// Delete an ARP entry from `jail`'s stack: `jexec <jail> arp -d <ip>`.
    /// `Ok(false)` when there was no such entry.
    #[tracing::instrument(skip(self), fields(ip = %ip))]
    pub async fn delete(&self, jail: &str, ip: Ipv4Addr) -> Result<bool, ArpError> {
        let context = format!("delete arp entry {ip} in jail '{jail}'");
        let (argv, output) = self
            .exec(&context, args_delete(jail, &self.command, ip))
            .await?;
        if let Some(err) = self.jexec_error(&context, jail, &output) {
            return Err(err);
        }
        if output.success() {
            tracing::debug!(jail = %jail, "deleted arp entry");
            return Ok(true);
        }
        if stderr_says_no_such_entry(&output.stderr) {
            return Ok(false);
        }
        Err(ArpError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }
}

impl<R: CommandRunner> JailArp for Arp<R> {
    /// One `jexec` per entry: this path is for `path=/` jails and tests, where a
    /// process spawn per entry costs nothing worth optimising.
    async fn apply(&self, jail: &str, batch: &ArpBatch) -> Result<ArpApplied, ArpError> {
        let mut applied = ArpApplied::default();
        // Make before break, matching the reconciler's own ordering.
        for (ip, mac) in &batch.add {
            match self.set(jail, *ip, *mac).await {
                Ok(()) => applied.added.push((*ip, *mac)),
                // A jail that died makes the whole batch moot.
                Err(err @ ArpError::NoSuchJail { .. }) => return Err(err),
                Err(err) => applied.failures.push(err.to_string()),
            }
        }
        for ip in &batch.remove {
            match self.delete(jail, *ip).await {
                Ok(true) => applied.removed.push(*ip),
                Ok(false) => applied.absent.push(*ip),
                Err(err @ ArpError::NoSuchJail { .. }) => return Err(err),
                Err(err) => applied.failures.push(err.to_string()),
            }
        }
        Ok(applied)
    }

    /// The jail's whole ARP table: `jexec <jail> arp -an`.
    async fn list(&self, jail: &str) -> Result<Vec<ArpEntry>, ArpError> {
        let context = format!("list arp entries in jail '{jail}'");
        let (argv, output) = self.exec(&context, args_list(jail, &self.command)).await?;
        if let Some(err) = self.jexec_error(&context, jail, &output) {
            return Err(err);
        }
        if output.success() {
            return Ok(parse_arp_list(&output.stdout));
        }
        Err(ArpError::Failed {
            context,
            failure: Failure::new(argv, &output),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_LIST: &str = include_str!("../tests/fixtures/arp_list_jail.txt");
    const FIXTURE_LIST_MIXED: &str = include_str!("../tests/fixtures/arp_list_mixed.txt");
    const FIXTURE_CANNOT_LOCATE: &str = include_str!("../tests/fixtures/arp_set_cannot_locate.txt");
    const FIXTURE_DELETE_OK: &str = include_str!("../tests/fixtures/arp_delete_ok.txt");
    const FIXTURE_DELETE_MISSING: &str = include_str!("../tests/fixtures/arp_delete_missing.txt");
    const FIXTURE_MISSING_BINARY: &str = include_str!("../tests/fixtures/arp_missing_binary.txt");
    const FIXTURE_MISSING_JAIL: &str = include_str!("../tests/fixtures/arp_missing_jail.txt");

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("valid MAC")
    }

    // ---- argv builders -----------------------------------------------------

    #[test]
    fn argv_builders() {
        assert_eq!(
            args_set(
                "satl-t1",
                "arp",
                ip("10.100.0.12"),
                mac("02:42:0a:64:00:0c")
            ),
            ["satl-t1", "arp", "-s", "10.100.0.12", "02:42:0a:64:00:0c"]
        );
        assert_eq!(
            args_delete("satl-t1", "arp", ip("10.100.0.12")),
            ["satl-t1", "arp", "-d", "10.100.0.12"]
        );
        assert_eq!(args_list("satl-t1", "arp"), ["satl-t1", "arp", "-an"]);
        // An absolute path materialized inside the rootfs works the same way.
        assert_eq!(
            args_list("satl-t1", "/sbin/satl-arp"),
            ["satl-t1", "/sbin/satl-arp", "-an"]
        );
    }

    // ---- parsers against real captured fixtures ----------------------------

    #[test]
    fn parse_list_of_static_entries() {
        let entries = parse_arp_list(FIXTURE_LIST);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].ip, ip("10.79.0.13"));
        assert_eq!(entries[0].mac, Some(mac("02:42:0a:4f:00:0d")));
        assert_eq!(entries[0].iface, "ovtest-ep0b");
        assert!(entries[0].permanent);
        assert!(entries.iter().all(ArpEntry::is_overlay_static));
    }

    #[test]
    fn ownership_test_separates_ours_from_the_kernels() {
        // The mixed fixture holds, in order: a *learned* gateway entry with
        // the host bridge's MAC, one entry SatL installed, and the jail's own
        // permanent address.
        let entries = parse_arp_list(FIXTURE_LIST_MIXED);
        assert_eq!(entries.len(), 3);

        let gateway = &entries[0];
        assert_eq!(gateway.ip, ip("10.79.0.1"));
        assert!(!gateway.permanent, "the gateway is learned, not permanent");
        assert!(
            !gateway.is_overlay_static(),
            "deleting a learned gateway entry is the silent black hole of \
             docs/vxlan.md §8"
        );

        let ours = &entries[1];
        assert_eq!(ours.ip, ip("10.79.0.12"));
        assert!(ours.is_overlay_static());

        let own = &entries[2];
        assert_eq!(own.ip, ip("10.79.0.11"));
        // The jail's own address passes the test through *this* mechanism, and
        // that is why callers must exclude it by address: `arp -an` does not
        // print RTF_PINNED, so `pinned` is always false here.
        assert!(!own.pinned, "arp -an cannot report RTF_PINNED");
        assert!(own.is_overlay_static());
        // Read through the routing socket the same entry is excluded by the
        // kernel's own marker, with nothing for the caller to remember.
        let via_kernel = ArpEntry::from_ll(&LlEntry {
            ip: own.ip,
            mac: own.mac,
            ifindex: 22,
            iface: Some(own.iface.clone()),
            // 0xc05 | RTF_PINNED, which is what the kernel reports for
            // LLE_IFADDR (measured, captures/30-premise-and-mechanism.txt §4).
            flags: 0x0010_0c05,
            expire: 0,
        });
        assert!(via_kernel.permanent && via_kernel.pinned);
        assert!(
            !via_kernel.is_overlay_static(),
            "RTF_PINNED is the kernel telling us this address is the stack's own"
        );
    }

    #[test]
    fn incomplete_entries_parse_without_a_mac() {
        let entry = parse_arp_row("? (10.100.0.9) at (incomplete) on satl-ep7b [ethernet]")
            .expect("recognized");
        assert_eq!(entry.ip, ip("10.100.0.9"));
        assert_eq!(entry.mac, None);
        assert!(!entry.permanent);
        assert!(!entry.is_overlay_static());
    }

    #[test]
    fn unrecognized_rows_are_skipped_not_fatal() {
        assert!(parse_arp_row("").is_none());
        assert!(parse_arp_row("   ").is_none());
        assert!(parse_arp_row("arp: something odd").is_none());
        assert!(parse_arp_list("arp: something odd\n").is_empty());
    }

    #[test]
    fn a_derived_mac_on_a_wrong_address_is_not_ours() {
        // 02:42:0a:64:00:0c is mac_of(10.100.0.12); on 10.100.0.13 it is not
        // the derived MAC, so it is not an entry this crate installed.
        let entry =
            parse_arp_row("? (10.100.0.13) at 02:42:0a:64:00:0c on satl-ep1b permanent [ethernet]")
                .expect("recognized");
        assert!(!entry.is_overlay_static());
    }

    #[test]
    fn stderr_classifiers() {
        assert!(stderr_says_cannot_locate(FIXTURE_CANNOT_LOCATE));
        assert!(!stderr_says_cannot_locate(FIXTURE_DELETE_MISSING));
        assert!(stderr_says_no_such_entry(FIXTURE_DELETE_MISSING));
        assert!(!stderr_says_no_such_entry(FIXTURE_CANNOT_LOCATE));
        assert!(stderr_says_no_such_jail(FIXTURE_MISSING_JAIL));
        assert!(!stderr_says_no_such_jail(FIXTURE_MISSING_BINARY));
        assert!(stderr_says_missing_binary(FIXTURE_MISSING_BINARY));
        assert!(!stderr_says_missing_binary(FIXTURE_MISSING_JAIL));
        assert_eq!(FIXTURE_DELETE_OK.trim(), "10.79.0.13 (10.79.0.13) deleted");
    }

    // ---- wrapper behavior with the mock runner -----------------------------

    #[tokio::test]
    async fn set_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_ok();
        let arp = Arp::with_runner(&mock);
        arp.set("satl-t1", ip("10.100.0.12"), mac("02:42:0a:64:00:0c"))
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/usr/sbin/jexec satl-t1 arp -s 10.100.0.12 02:42:0a:64:00:0c"]
        );
    }

    #[tokio::test]
    async fn set_rejects_the_exit_zero_failure() {
        // The whole point: exit status 0, and the entry was not installed.
        let mock = MockRunner::new();
        mock.push_output(0, "", FIXTURE_CANNOT_LOCATE);
        let arp = Arp::with_runner(&mock);
        let err = arp
            .set("satl-t1", ip("10.80.0.5"), mac("02:42:0a:50:00:05"))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ArpError::NotOnLink { .. }), "{err:?}");
        assert!(text.contains("still exited 0"), "{text}");
        assert!(text.contains("cannot locate"), "{text}");
        assert!(text.contains("on-link"), "{text}");
    }

    #[tokio::test]
    async fn delete_maps_absent_entry_to_false() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_DELETE_OK, "");
        mock.push_output(1, "", FIXTURE_DELETE_MISSING);
        let arp = Arp::with_runner(&mock);
        assert!(arp.delete("satl-t1", ip("10.79.0.13")).await.unwrap());
        assert!(!arp.delete("satl-t1", ip("10.79.0.13")).await.unwrap());
    }

    #[tokio::test]
    async fn missing_binary_in_the_jail_is_a_named_error() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MISSING_BINARY);
        let arp = Arp::with_runner(&mock);
        let err = arp
            .set("satl-t1", ip("10.100.0.12"), mac("02:42:0a:64:00:0c"))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ArpError::MissingBinary { .. }), "{err:?}");
        assert!(text.contains("jexec runs the jail's own binary"), "{text}");
        // The message must name what replaced this path, or an operator reading
        // it in /var/log/messages has nowhere to go.
        assert!(text.contains("ArpHelper"), "{text}");
        assert!(text.contains("path=/ jails"), "{text}");
    }

    #[tokio::test]
    async fn missing_jail_is_a_named_error() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MISSING_JAIL);
        let arp = Arp::with_runner(&mock);
        let err = arp.list("satl-gone").await.unwrap_err();
        assert!(matches!(err, ArpError::NoSuchJail { .. }), "{err:?}");
        assert!(err.to_string().contains("satl-gone"), "{err}");
    }

    #[tokio::test]
    async fn list_owned_filters_the_jails_own_address_and_learned_entries() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_MIXED, "");
        let arp = Arp::with_runner(&mock);
        let owned = arp
            .list_owned("satl-t1", &[ip("10.79.0.11")])
            .await
            .unwrap();
        assert_eq!(
            owned.iter().map(|entry| entry.ip).collect::<Vec<_>>(),
            [ip("10.79.0.12")]
        );
    }

    #[tokio::test]
    async fn set_with_a_custom_in_jail_command() {
        let mock = MockRunner::new();
        mock.push_ok();
        let arp = Arp::with_runner(&mock).with_command("/sbin/satl-arp");
        arp.set("satl-t1", ip("10.100.0.12"), mac("02:42:0a:64:00:0c"))
            .await
            .unwrap();
        assert!(
            mock.calls()[0].contains("/sbin/satl-arp -s"),
            "{:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let arp = Arp::with_runner(&mock).with_jexec("/nonexistent/jexec");
        let err = arp.list("satl-t1").await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("/nonexistent/jexec satl-t1 arp -an"),
            "{text}"
        );
        assert!(text.contains("no such file"), "{text}");
    }
}
