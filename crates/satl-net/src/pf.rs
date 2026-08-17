// SPDX-License-Identifier: BSD-2-Clause
//! SatL's pf(4) anchors: rule-text generation and anchor loading.
//!
//! ## Anchor ownership (invariant — CLAUDE.md, architecture §11)
//!
//! SatL owns the `satl/*` anchors and **never** touches rules outside them:
//!
//! - `satl/nat` — outbound NAT for local bridge subnets,
//! - `satl/rdr` — port publishing (rdr to task addresses),
//! - `satl/guard` — the cleartext guard of encrypted overlay networks
//!   ([`guard_rules`], M6): filter rules, which is why they get their own
//!   anchor — `satl/nat` and `satl/rdr` are translation anchors and cannot
//!   hold them. No new `/etc/pf.conf` line is needed: the existing wildcard
//!   filter anchor (`anchor "satl/*"`) already references it.
//!
//! [`PfCtl`] enforces this in code: it refuses to load or flush any anchor
//! that is not `satl` or `satl/...`.
//!
//! ## Operator hookup (`/etc/pf.conf`)
//!
//! The daemon does not edit `/etc/pf.conf`. The operator must delegate the
//! SatL anchors once — translation anchors belong in the translation
//! section (before filter rules):
//!
//! ```text
//! # /etc/pf.conf — SatL hookup (see docs/operations.md)
//! nat-anchor "satl/*"
//! rdr-anchor "satl/*"
//! anchor "satl/*"
//! ```
//!
//! Everything else in `pf.conf` remains operator-owned; SatL loads, reloads
//! and flushes rules exclusively *inside* its anchors via `pfctl -a`.
//!
//! ## Idempotent model
//!
//! There are no incremental edits: on every change the **full** ruleset of
//! an anchor is regenerated ([`nat_rules`], [`rdr_rules`]) and loaded
//! atomically with `pfctl -a <anchor> -f -` (rules on stdin), which replaces
//! the anchor's previous contents in one transaction.
//!
//! ## Dev-machine constraint
//!
//! On the shared dev host only `pfctl -nf -` (parse-only dry run,
//! [`PfCtl::check_syntax`]) may execute; anchor loads live behind the
//! `SATL_PF_LIVE=1` guard and run on the cluster VMs. `pfctl -n` needs pf.ko
//! present (FreeBSD 15 pfctl speaks netlink to the kernel even to parse);
//! where the module is missing pfctl fails with `pfctl: Failed to open
//! netlink: No such file or directory` (captured in
//! `tests/fixtures/pfctl_unavailable.txt`), surfaced as
//! [`PfError::Unavailable`] so tests can skip instead of fail.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use satl_core::PortProtocol;

use crate::ipam::SubnetV4;
use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `pfctl` binary on FreeBSD.
pub const DEFAULT_PFCTL_BINARY: &str = "/sbin/pfctl";

/// The anchor holding SatL's outbound NAT rules.
pub const ANCHOR_NAT: &str = "satl/nat";

/// The anchor holding SatL's port-publishing rdr rules.
pub const ANCHOR_RDR: &str = "satl/rdr";

/// The anchor holding the cleartext guard of encrypted overlay networks.
pub const ANCHOR_GUARD: &str = "satl/guard";

/// The `if_enc`(4) interface ESP-decapsulated packets are presented on.
pub const ENC_IFACE: &str = "enc0";

/// Generate the full `satl/guard` anchor ruleset: the cleartext guard that
/// must be present while a node hosts at least one encrypted overlay network
/// (M6, `--opt encrypted`).
///
/// The measured design (`hack/experiments/esp/README.md` §7, whose
/// `run-guard.sh` is the reference implementation): with
/// `net.enc.in.ipsec_filter_mask=2`, ESP-decapsulated packets are presented
/// to pf on `enc0` **after** the ESP header is stripped, while cleartext
/// VXLAN only ever arrives on the underlay interface — so the two paths are
/// distinguishable and cleartext can be dropped without touching the
/// decapsulated flow. Two load-bearing details, both measured:
///
/// - the `no state` on the `enc0` pass rule is **mandatory** (§7 G4): pf
///   consults the state table before the ruleset, and the decapsulated
///   packet has the same tuple as the cleartext one, so a stateful pass
///   creates the very floating state that then lets cleartext bypass the
///   block;
/// - the range is the allocator's whole encrypted-port space
///   ([`satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE`]), not the ports of
///   the networks currently present, so the ruleset is static while ≥1
///   encrypted network exists and a new encrypted network needs no reload.
#[must_use]
pub fn guard_rules(underlay_if: &str) -> String {
    let range = &satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE;
    let (first, last) = (range.start(), range.end());
    format!(
        "block in log quick on {underlay_if} proto udp from any to any port {first}:{last}\n\
         pass in quick on {ENC_IFACE} proto udp from any to any port {first}:{last} no state\n"
    )
}

/// One published port: traffic to `host_port` on the node is redirected to
/// `task_ip:task_port` inside the local bridge network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPublish {
    /// Transport protocol.
    pub proto: PortProtocol,
    /// Port on the host that is published.
    pub host_port: u16,
    /// Address of the task on the local bridge network.
    pub task_ip: Ipv4Addr,
    /// Port the task listens on.
    pub task_port: u16,
}

fn proto_keyword(proto: PortProtocol) -> &'static str {
    match proto {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    }
}

/// Generate the full `satl/nat` anchor ruleset: outbound NAT for `subnet`
/// leaving through `egress_if`, using the interface's current address
/// (parenthesized, so address changes don't require a reload).
#[must_use]
pub fn nat_rules(subnet: SubnetV4, egress_if: &str) -> String {
    format!("nat on {egress_if} inet from {subnet} to any -> ({egress_if})\n")
}

/// One redirection pool: the `(host port, protocol, task port)` triple a
/// published port reduces to. Several tasks of one service can run on one
/// node — two replicas that the scheduler placed together, or the old and the
/// new task of a slot during an update — and they all listen on the same
/// container port under the same published one, so they share one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoolKey {
    /// Port on the host that is published.
    pub host_port: u16,
    /// Transport protocol.
    pub proto: PortProtocol,
    /// Port the tasks listen on.
    pub task_port: u16,
}

/// The pf table backing one pool: `satl_p8080_tcp_80` for the pool
/// `(:8080/tcp -> :80)`. Carrying the task port in the name keeps two pools
/// that share a published port (different container ports) distinct.
/// At most 21 characters, well under `PF_TABLE_NAME_SIZE` (32).
#[must_use]
pub fn table_name(key: &PoolKey) -> String {
    format!(
        "satl_p{}_{}_{}",
        key.host_port,
        proto_keyword(key.proto),
        key.task_port
    )
}

/// Group publishes into pools: the triple is the key, the task addresses the
/// members. Deterministic (BTreeMap/BTreeSet) and duplicate-collapsing,
/// which is what makes it safe for two writers to contribute the same
/// redirect (see [`crate::NetworkManager`]).
#[must_use]
pub fn pool_publishes(publishes: &[PortPublish]) -> BTreeMap<PoolKey, BTreeSet<Ipv4Addr>> {
    let mut pools: BTreeMap<PoolKey, BTreeSet<Ipv4Addr>> = BTreeMap::new();
    for publish in publishes {
        pools
            .entry(PoolKey {
                host_port: publish.host_port,
                proto: publish.proto,
                task_port: publish.task_port,
            })
            .or_default()
            .insert(publish.task_ip);
    }
    pools
}

/// Generate the full `satl/rdr` anchor ruleset for `pools`.
///
/// **Table-backed: the ruleset is static and membership is dynamic.** One
/// `table` declaration plus one `rdr` rule per pool, targeting the table —
/// never an inline address list:
///
/// ```text
/// table <satl_p8080_tcp_80> persist
/// rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin
/// ```
///
/// A membership change (a task starts, dies, is rescheduled) then goes
/// through `pfctl -T replace` ([`PfCtl::replace_table`]) and the anchor is
/// **not** reloaded, so a health-driven pool update no longer rewrites the
/// whole ruleset. The rule text is a pure function of the pool *keys*:
/// reloading happens only when the set of published triples itself changes
/// ([`crate::NetworkManager`] splits the two).
///
/// Why not an inline `{ a, b }` list, as before: measured on FreeBSD 15.1,
/// `rdr -> <table> round-robin` is accepted while `rdr -> { a, b }
/// source-hash` is not — a table-backed pool unlocks `source-hash`
/// (per-client-IP stickiness) later, and weighted or least-connection
/// balancing exists in no form in FreeBSD's pf (Docker Swarm's IPVS is
/// round-robin with no operator choice either: parity, not a shortfall).
///
/// `round-robin` is unconditional: with one member it distributes to that
/// member, and the text must not depend on membership anyway (see above).
/// Deterministic: pools are emitted in key order, so identical pool sets
/// always produce identical rule text (golden-testable, cheap to diff).
#[must_use]
pub fn rdr_rules(pools: &BTreeMap<PoolKey, BTreeSet<Ipv4Addr>>) -> String {
    let mut rules = String::new();
    for key in pools.keys() {
        let table = table_name(key);
        let host = key.host_port;
        let proto = proto_keyword(key.proto);
        let task = key.task_port;
        // Infallible: fmt::Write on String never errors.
        let _ = writeln!(rules, "table <{table}> persist");
        let _ = writeln!(
            rules,
            "rdr pass inet proto {proto} from any to any port {host} -> <{table}> port {task} round-robin"
        );
    }
    rules
}

/// What the ingress mesh needs to render its half of the `satl/rdr` anchor
/// (M6d): the return-path SNAT and the MSS clamp. Filled by the port sweep
/// from the ingress network's store object; `None` everywhere else (workers,
/// clusters with no ingress publishing, a node whose gateway is not yet
/// allocated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshEgress {
    /// This node's gateway address on the ingress overlay
    /// (`Network.node_gateways`): the SNAT source, so replies return through
    /// this relaying node (measured in `hack/experiments/mesh`: without it the
    /// reply bypasses the relay and the handshake never completes).
    pub gateway: Ipv4Addr,
    /// The ingress overlay's bridge interface (`satl-br<vni>`).
    pub bridge: String,
    /// The ingress overlay's subnet.
    pub subnet: SubnetV4,
    /// The clamp value: overlay MTU minus 40 (IPv4 + TCP headers).
    pub max_mss: u16,
}

/// The mesh's half of the ruleset, for [`MeshEgress`] + the same pools
/// [`rdr_rules`] renders. Two rule shapes:
///
/// - one **return-path SNAT per pool**: `nat pass inet proto tcp from any to
///   <satl_p8080_tcp_80> port 80 -> <gateway>`. Keyed on the pool's table and
///   task port, so it matches exactly the traffic an `rdr` just rewrote —
///   task-to-task overlay traffic (source inside the subnet) and the egress
///   NAT in `satl/nat` (another interface, another subnet) never match it
///   (measured disjoint in `hack/experiments/mesh`). The price is recorded in
///   `plan-m6.md`: the application sees the relaying node's gateway address,
///   not the client's; DSR was rejected (it would need pf inside every task's
///   VNET), and the opt-in remedy is M6e's PROXY-protocol mode.
/// - one **MSS clamp** out of the overlay bridge: a client negotiates its MSS
///   against the 1500-MTU underlay, then its packets enter a 1450-MTU overlay.
///   PMTUD covers the happy path (the relaying node is on the path and can
///   ICMP too-big itself — measured), so this is insurance against
///   ICMP-filtered internet paths, and costs one `match` rule.
///
/// Emitted **after** [`rdr_rules`]' output, the SNAT rules first and the
/// clamp last: pf.conf(5) parses a ruleset in statement order (options,
/// normalization, queueing, translation, filtering), a `table` declaration
/// after a translation rule is rejected, and `match` is a *filter-section*
/// statement even with `scrub` in it — measured the hard way on the cluster
/// VMs, where the inverse order failed `pfctl -nf -` with "Rules must be in
/// order". Keeping the whole anchor deterministic is what makes the
/// unchanged-detection in `NetworkManager::write_rdr` work.
#[must_use]
pub fn mesh_rules(mesh: &MeshEgress, pools: &BTreeMap<PoolKey, BTreeSet<Ipv4Addr>>) -> String {
    // No pool, no mesh rules: the clamp and the SNAT exist to serve relayed
    // traffic, and an anchor holding only them would be noise.
    if pools.is_empty() {
        return String::new();
    }
    let mut rules = String::new();
    for key in pools.keys() {
        let table = table_name(key);
        let proto = proto_keyword(key.proto);
        let task = key.task_port;
        let gateway = mesh.gateway;
        // Infallible: fmt::Write on String never errors.
        let _ = writeln!(
            rules,
            "nat pass inet proto {proto} from any to <{table}> port {task} -> {gateway}"
        );
    }
    let _ = writeln!(
        rules,
        "match out on {} inet proto tcp from any to {} scrub (max-mss {})",
        mesh.bridge, mesh.subnet, mesh.max_mss
    );
    rules
}

/// Error from a `pfctl`(8) invocation.
#[derive(Debug, thiserror::Error)]
pub enum PfError {
    /// The `pfctl` binary could not be spawned.
    #[error("pfctl ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted, naming the anchor involved.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully (includes syntax errors
    /// from `-n`; the ruleset that was being loaded is included).
    #[error("pfctl ({context}): {failure}; ruleset: {rules:?}")]
    Failed {
        /// What was being attempted, naming the anchor involved.
        context: String,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
        /// The ruleset text involved (empty for flush/show).
        rules: String,
    },

    /// pf is not usable on this host (pf.ko not loaded / no netlink / no
    /// permission). Real capture: `pfctl: Failed to open netlink: No such
    /// file or directory`.
    #[error("pfctl ({context}): pf unavailable on this host: {failure}")]
    Unavailable {
        /// What was being attempted.
        context: String,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },

    /// Refused to touch an anchor outside `satl/*` (ownership invariant).
    #[error(
        "refusing to operate on pf anchor '{anchor}': SatL only owns 'satl' and 'satl/*' \
         (CLAUDE.md invariant)"
    )]
    ForeignAnchor {
        /// The refused anchor name.
        anchor: String,
    },

    /// Refused to touch a table that is not a SatL pool table (ownership
    /// invariant, same scope as [`PfError::ForeignAnchor`]).
    #[error("refusing to operate on pf table '{table}': SatL only owns its 'satl_p*' pool tables")]
    ForeignTable {
        /// The refused table name.
        table: String,
    },
}

// ---------------------------------------------------------------------------
// Pure argv builders and output classifiers.
// ---------------------------------------------------------------------------

fn to_args<const N: usize>(parts: [&str; N]) -> Vec<String> {
    parts.into_iter().map(str::to_owned).collect()
}

fn args_check_syntax() -> Vec<String> {
    to_args(["-nf", "-"])
}

fn args_load_anchor(anchor: &str) -> Vec<String> {
    to_args(["-a", anchor, "-f", "-"])
}

fn args_flush_anchor(anchor: &str, what: &str) -> Vec<String> {
    to_args(["-a", anchor, "-F", what])
}

fn args_show_anchor(anchor: &str, what: &str) -> Vec<String> {
    to_args(["-a", anchor, "-s", what])
}

fn args_replace_table(anchor: &str, table: &str) -> Vec<String> {
    to_args(["-a", anchor, "-t", table, "-T", "replace"])
}

fn args_flush_table(anchor: &str, table: &str) -> Vec<String> {
    to_args(["-a", anchor, "-t", table, "-T", "flush"])
}

fn args_kill_table(anchor: &str, table: &str) -> Vec<String> {
    to_args(["-a", anchor, "-t", table, "-T", "kill"])
}

fn args_show_table(anchor: &str, table: &str) -> Vec<String> {
    to_args(["-a", anchor, "-t", table, "-T", "show"])
}

/// Whether SatL may touch `anchor` (ownership invariant).
fn is_owned_anchor(anchor: &str) -> bool {
    anchor == "satl" || anchor.starts_with("satl/")
}

/// Whether SatL may touch `table` (ownership invariant): the only tables it
/// manages are the pool tables [`table_name`] mints, inside its own anchors.
fn is_owned_table(table: &str) -> bool {
    table.starts_with("satl_p")
}

/// pf is not usable at all (as opposed to rejecting the ruleset): pfctl
/// could not reach the kernel. Covers the missing-module netlink failure
/// (real capture on the dev host), the classic missing `/dev/pf`, and
/// unprivileged access.
fn stderr_says_pf_unavailable(stderr: &str) -> bool {
    stderr.contains("Failed to open netlink")
        || stderr.contains("/dev/pf")
        || stderr.contains("Operation not permitted")
        || stderr.contains("Permission denied")
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around the `pfctl`(8) binary, restricted to SatL's
/// own anchors.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock
/// executor; production code uses [`PfCtl::system`].
#[derive(Debug, Clone)]
pub struct PfCtl<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl PfCtl<SystemRunner> {
    /// Wrapper that executes the real binary at [`DEFAULT_PFCTL_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for PfCtl<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> PfCtl<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_PFCTL_BINARY),
            runner,
        }
    }

    /// Override the path of the `pfctl` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    async fn exec(
        &self,
        context: &str,
        args: Vec<String>,
        stdin: Option<&str>,
    ) -> Result<(String, CommandOutput), PfError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running pfctl");
        let output = self
            .runner
            .run(&self.binary, &args, stdin)
            .await
            .map_err(|source| PfError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    fn interpret(
        context: &str,
        argv: String,
        output: &CommandOutput,
        rules: &str,
    ) -> Result<(), PfError> {
        if output.success() {
            return Ok(());
        }
        let failure = Failure::new(argv, output);
        if stderr_says_pf_unavailable(&output.stderr) {
            return Err(PfError::Unavailable {
                context: context.to_owned(),
                failure,
            });
        }
        Err(PfError::Failed {
            context: context.to_owned(),
            failure,
            rules: rules.to_owned(),
        })
    }

    /// Parse-only dry run: `pfctl -nf -` with `rules` on stdin. Never
    /// touches the live ruleset — the only pfctl invocation permitted on
    /// the shared dev host.
    pub async fn check_syntax(&self, rules: &str) -> Result<(), PfError> {
        let context = "syntax-check ruleset (dry run)";
        let (argv, output) = self.exec(context, args_check_syntax(), Some(rules)).await?;
        Self::interpret(context, argv, &output, rules)
    }

    /// Atomically replace the contents of `anchor` with `rules`:
    /// `pfctl -a <anchor> -f -` (rules on stdin).
    ///
    /// Only `satl/*` anchors are accepted. **Never run on the shared dev
    /// host** — integration tests gate this behind `SATL_PF_LIVE=1`.
    pub async fn load_anchor(&self, anchor: &str, rules: &str) -> Result<(), PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        let context = format!("load anchor '{anchor}'");
        let (argv, output) = self
            .exec(&context, args_load_anchor(anchor), Some(rules))
            .await?;
        Self::interpret(&context, argv, &output, rules)?;
        // Debug, not info: the callers re-assert their anchors periodically
        // (`NetworkManager::reconcile_published_ports`) and only they can tell
        // a ruleset that changed from one that was merely re-asserted, so they
        // own the operator-facing line.
        tracing::debug!(anchor = %anchor, rules = %rules.trim_end(), "loaded pf anchor");
        Ok(())
    }

    /// Flush all translation and filter rules inside `anchor`:
    /// `pfctl -a <anchor> -F nat` then `-F rules`. States are deliberately
    /// left alone (`-F states` is not anchor-scoped on FreeBSD).
    ///
    /// Only `satl/*` anchors are accepted; same live-host guard as
    /// [`PfCtl::load_anchor`].
    pub async fn flush_anchor(&self, anchor: &str) -> Result<(), PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        for what in ["nat", "rules"] {
            let context = format!("flush {what} in anchor '{anchor}'");
            let (argv, output) = self
                .exec(&context, args_flush_anchor(anchor, what), None)
                .await?;
            Self::interpret(&context, argv, &output, "")?;
        }
        tracing::debug!(anchor = %anchor, "flushed pf anchor");
        Ok(())
    }

    /// Show the current contents of `anchor` (translation rules followed by
    /// filter rules): `pfctl -a <anchor> -s nat` + `-s rules`.
    pub async fn show_anchor(&self, anchor: &str) -> Result<String, PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        let mut combined = String::new();
        for what in ["nat", "rules"] {
            let context = format!("show {what} in anchor '{anchor}'");
            let (argv, output) = self
                .exec(&context, args_show_anchor(anchor, what), None)
                .await?;
            Self::interpret(&context, argv, &output, "")?;
            combined.push_str(&output.stdout);
        }
        Ok(combined)
    }

    /// Replace the membership of a pool table:
    /// `pfctl -a <anchor> -t <table> -T replace <addrs…>`.
    ///
    /// This is the whole point of the table-backed pool ([`rdr_rules`]): a
    /// membership change touches only the table, never the ruleset. `replace`
    /// is atomic from the reader's side, and — the empirical fact M6c was
    /// built on — it leaves established states alone: a connection already
    /// translated to a departing member keeps flowing, only new connections
    /// are balanced over the new membership (measured in
    /// `crates/satld/tests/pf_table.rs`).
    ///
    /// An empty `addrs` flushes the table instead (`-T replace` with no
    /// address is a usage error).
    pub async fn replace_table(
        &self,
        anchor: &str,
        table: &str,
        addrs: &[Ipv4Addr],
    ) -> Result<(), PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        if !is_owned_table(table) {
            return Err(PfError::ForeignTable {
                table: table.to_owned(),
            });
        }
        if addrs.is_empty() {
            let context = format!("flush table '{table}' in anchor '{anchor}'");
            let (argv, output) = self
                .exec(&context, args_flush_table(anchor, table), None)
                .await?;
            return Self::interpret(&context, argv, &output, "");
        }
        let context = format!("replace table '{table}' in anchor '{anchor}'");
        let mut arguments = args_replace_table(anchor, table);
        arguments.extend(addrs.iter().map(ToString::to_string));
        let (argv, output) = self.exec(&context, arguments, None).await?;
        Self::interpret(&context, argv, &output, "")?;
        tracing::debug!(anchor = %anchor, table = %table, members = addrs.len(), "replaced pf table membership");
        Ok(())
    }

    /// Show the membership of a pool table:
    /// `pfctl -a <anchor> -t <table> -T show`.
    pub async fn show_table(&self, anchor: &str, table: &str) -> Result<String, PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        if !is_owned_table(table) {
            return Err(PfError::ForeignTable {
                table: table.to_owned(),
            });
        }
        let context = format!("show table '{table}' in anchor '{anchor}'");
        let (argv, output) = self
            .exec(&context, args_show_table(anchor, table), None)
            .await?;
        Self::interpret(&context, argv, &output, "")?;
        Ok(output.stdout)
    }

    /// Destroy a pool table entirely: `pfctl -a <anchor> -t <table> -T kill`.
    ///
    /// Needed because the tables are declared **`persist`**: flushing or
    /// reloading the anchor removes the *rules*, but a persist table lingers
    /// with its members (measured on FreeBSD 15.1 — after `-F nat`/`-F
    /// rules`, `-T show` still listed the addresses). A pool whose triple
    /// disappeared must have its table killed, or `-T show` keeps reporting
    /// live membership for a dead pool.
    pub async fn kill_table(&self, anchor: &str, table: &str) -> Result<(), PfError> {
        if !is_owned_anchor(anchor) {
            return Err(PfError::ForeignAnchor {
                anchor: anchor.to_owned(),
            });
        }
        if !is_owned_table(table) {
            return Err(PfError::ForeignTable {
                table: table.to_owned(),
            });
        }
        let context = format!("kill table '{table}' in anchor '{anchor}'");
        let (argv, output) = self
            .exec(&context, args_kill_table(anchor, table), None)
            .await?;
        Self::interpret(&context, argv, &output, "")?;
        tracing::debug!(anchor = %anchor, table = %table, "killed pf table");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_UNAVAILABLE: &str = include_str!("../tests/fixtures/pfctl_unavailable.txt");

    fn subnet(s: &str) -> SubnetV4 {
        s.parse().unwrap()
    }

    fn sample_publishes() -> Vec<PortPublish> {
        vec![
            PortPublish {
                proto: PortProtocol::Udp,
                host_port: 8053,
                task_ip: "10.88.0.3".parse().unwrap(),
                task_port: 53,
            },
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 80,
            },
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8443,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 443,
            },
        ]
    }

    // ---- golden rule texts --------------------------------------------------

    #[test]
    fn nat_rules_golden() {
        assert_eq!(
            nat_rules(subnet("10.88.0.0/24"), "ice0"),
            "nat on ice0 inet from 10.88.0.0/24 to any -> (ice0)\n"
        );
    }

    #[test]
    fn table_names_carry_the_whole_triple() {
        let key = PoolKey {
            host_port: 8080,
            proto: PortProtocol::Tcp,
            task_port: 80,
        };
        assert_eq!(table_name(&key), "satl_p8080_tcp_80");
        let other = PoolKey {
            task_port: 8080,
            ..key
        };
        assert_eq!(table_name(&other), "satl_p8080_tcp_8080");
        assert!(
            table_name(&other).len() < 32,
            "PF_TABLE_NAME_SIZE is 32, the name must fit"
        );
        assert!(is_owned_table(&table_name(&key)));
    }

    #[test]
    fn mesh_rules_golden_and_sorted() {
        let mesh = MeshEgress {
            gateway: "10.100.0.4".parse().unwrap(),
            bridge: "satl-br4096".to_owned(),
            subnet: subnet("10.100.0.0/24"),
            max_mss: 1410,
        };
        let pools = pool_publishes(&sample_publishes());
        assert_eq!(
            mesh_rules(&mesh, &pools),
            "nat pass inet proto udp from any to <satl_p8053_udp_53> port 53 -> 10.100.0.4\n\
             nat pass inet proto tcp from any to <satl_p8080_tcp_80> port 80 -> 10.100.0.4\n\
             nat pass inet proto tcp from any to <satl_p8443_tcp_443> port 443 -> 10.100.0.4\n\
             match out on satl-br4096 inet proto tcp from any to 10.100.0.0/24 scrub (max-mss 1410)\n"
        );
    }

    /// pf.conf(5) statement order in the combined anchor, whatever the pool
    /// set: tables and rdr (translation) first, the nat rules after them, the
    /// `match` clamp (a filter-section statement) last. The inverse failed
    /// `pfctl -nf -` on the cluster VMs with "Rules must be in order".
    #[test]
    fn the_full_anchor_puts_mesh_rules_last() {
        let mesh = MeshEgress {
            gateway: "10.100.0.4".parse().unwrap(),
            bridge: "satl-br4096".to_owned(),
            subnet: subnet("10.100.0.0/24"),
            max_mss: 1410,
        };
        let pools = pool_publishes(&sample_publishes());
        let full = format!("{}{}", rdr_rules(&pools), mesh_rules(&mesh, &pools));
        let table_at = full.find("table <").unwrap();
        let nat_at = full.find("nat pass").unwrap();
        let match_at = full.find("match out").unwrap();
        assert!(table_at < nat_at && nat_at < match_at, "{full}");
    }

    /// No pool, no mesh rules: the clamp and the SNAT exist to serve relayed
    /// traffic, and an anchor holding only them would be noise.
    #[test]
    fn mesh_rules_without_pools_is_empty() {
        let mesh = MeshEgress {
            gateway: "10.100.0.4".parse().unwrap(),
            bridge: "satl-br4096".to_owned(),
            subnet: subnet("10.100.0.0/24"),
            max_mss: 1410,
        };
        assert_eq!(mesh_rules(&mesh, &BTreeMap::new()), "");
    }

    #[test]
    fn rdr_rules_golden_and_sorted() {
        // Input deliberately unsorted; output must be sorted by host port,
        // each pool a table declaration plus one static rule.
        let rules = rdr_rules(&pool_publishes(&sample_publishes()));
        assert_eq!(
            rules,
            "table <satl_p8053_udp_53> persist\n\
             rdr pass inet proto udp from any to any port 8053 -> <satl_p8053_udp_53> port 53 round-robin\n\
             table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n\
             table <satl_p8443_tcp_443> persist\n\
             rdr pass inet proto tcp from any to any port 8443 -> <satl_p8443_tcp_443> port 443 round-robin\n"
        );
    }

    #[test]
    fn rdr_rules_empty_and_deterministic() {
        assert_eq!(rdr_rules(&BTreeMap::new()), "");
        let mut reversed = sample_publishes();
        reversed.reverse();
        assert_eq!(
            rdr_rules(&pool_publishes(&sample_publishes())),
            rdr_rules(&pool_publishes(&reversed))
        );
    }

    /// Two tasks of one service on one node: one pool, one rule — never two
    /// rules with the same match (the second could never be reached). The
    /// members are in the table, not in the rule text.
    #[test]
    fn several_tasks_on_one_node_share_one_pool() {
        let publishes = vec![
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.5".parse().unwrap(),
                task_port: 80,
            },
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 80,
            },
        ];
        let pools = pool_publishes(&publishes);
        assert_eq!(pools.len(), 1);
        let members: Vec<String> = pools
            .values()
            .next()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(members, ["10.88.0.2", "10.88.0.5"]);
        assert_eq!(
            rdr_rules(&pools),
            "table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n"
        );
    }

    /// The same redirect contributed twice — the agent's edge-triggered
    /// publish and the node's convergence pass both name it — collapses to
    /// one pool member.
    #[test]
    fn the_same_redirect_twice_is_one_pool_member() {
        let one = PortPublish {
            proto: PortProtocol::Tcp,
            host_port: 8080,
            task_ip: "10.88.0.2".parse().unwrap(),
            task_port: 80,
        };
        let pools = pool_publishes(&[one.clone(), one]);
        assert_eq!(pools.len(), 1);
        assert_eq!(pools.values().next().unwrap().len(), 1);
    }

    /// Same published port, different container port, is a different pool:
    /// grouping is by the whole triple, so two services cannot be merged into
    /// one pool whose members do not answer on the same port.
    #[test]
    fn different_task_ports_are_not_pooled_together() {
        let publishes = vec![
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 80,
            },
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.3".parse().unwrap(),
                task_port: 8080,
            },
        ];
        assert_eq!(
            rdr_rules(&pool_publishes(&publishes)),
            "table <satl_p8080_tcp_80> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_80> port 80 round-robin\n\
             table <satl_p8080_tcp_8080> persist\n\
             rdr pass inet proto tcp from any to any port 8080 -> <satl_p8080_tcp_8080> port 8080 round-robin\n"
        );
    }

    // ---- the encrypted-overlay cleartext guard -------------------------------

    #[test]
    fn guard_rules_golden() {
        // The measured design (hack/experiments/esp/README.md section 7):
        // cleartext VXLAN on an encrypted port only ever arrives on the
        // underlay; ESP-decapsulated traffic is presented on enc0. The
        // `no state` on the pass rule is load-bearing (G4): a stateful pass
        // lets later cleartext bypass the block through the state table.
        assert_eq!(
            guard_rules("vtnet1"),
            "block in log quick on vtnet1 proto udp from any to any port 4790:4999\n\
             pass in quick on enc0 proto udp from any to any port 4790:4999 no state\n"
        );
        // The range is the allocator's encrypted-port space, not a literal.
        let range = &satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE;
        assert!(guard_rules("vtnet1").contains(&format!("{}:{}", range.start(), range.end())));
    }

    // ---- anchor ownership guard ---------------------------------------------

    #[tokio::test]
    async fn foreign_anchors_are_refused_without_running_pfctl() {
        let mock = MockRunner::new();
        let pf = PfCtl::with_runner(&mock);
        for anchor in ["", "satly", "other/nat", "satl2/rdr"] {
            assert!(matches!(
                pf.load_anchor(anchor, "").await.unwrap_err(),
                PfError::ForeignAnchor { .. }
            ));
            assert!(matches!(
                pf.flush_anchor(anchor).await.unwrap_err(),
                PfError::ForeignAnchor { .. }
            ));
            assert!(matches!(
                pf.show_anchor(anchor).await.unwrap_err(),
                PfError::ForeignAnchor { .. }
            ));
            assert!(matches!(
                pf.replace_table(anchor, "satl_p8080_tcp_80", &[])
                    .await
                    .unwrap_err(),
                PfError::ForeignAnchor { .. }
            ));
        }
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn foreign_tables_are_refused_without_running_pfctl() {
        let mock = MockRunner::new();
        let pf = PfCtl::with_runner(&mock);
        for table in ["", "other", "satl", "satl_nat_src"] {
            assert!(matches!(
                pf.replace_table(ANCHOR_RDR, table, &["10.88.0.2".parse().unwrap()])
                    .await
                    .unwrap_err(),
                PfError::ForeignTable { .. }
            ));
            assert!(matches!(
                pf.show_table(ANCHOR_RDR, table).await.unwrap_err(),
                PfError::ForeignTable { .. }
            ));
        }
        assert!(mock.calls().is_empty());
    }

    // ---- wrapper behavior with the mock runner ------------------------------

    #[tokio::test]
    async fn check_syntax_pipes_rules_on_stdin() {
        let mock = MockRunner::new();
        mock.push_ok();
        let pf = PfCtl::with_runner(&mock);
        let rules = nat_rules(subnet("10.88.0.0/24"), "ice0");
        pf.check_syntax(&rules).await.unwrap();
        assert_eq!(mock.calls(), ["/sbin/pfctl -nf -"]);
        assert_eq!(mock.stdins(), [Some(rules)]);
    }

    #[tokio::test]
    async fn load_anchor_builds_expected_argv_and_stdin() {
        let mock = MockRunner::new();
        mock.push_ok();
        let pf = PfCtl::with_runner(&mock);
        let rules = rdr_rules(&pool_publishes(&sample_publishes()));
        pf.load_anchor(ANCHOR_RDR, &rules).await.unwrap();
        assert_eq!(mock.calls(), ["/sbin/pfctl -a satl/rdr -f -"]);
        assert_eq!(mock.stdins(), [Some(rules)]);
    }

    #[tokio::test]
    async fn replace_table_builds_expected_argv_with_addresses() {
        let mock = MockRunner::new();
        mock.push_ok();
        let pf = PfCtl::with_runner(&mock);
        pf.replace_table(
            ANCHOR_RDR,
            "satl_p8080_tcp_80",
            &["10.88.0.2".parse().unwrap(), "10.88.0.5".parse().unwrap()],
        )
        .await
        .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T replace 10.88.0.2 10.88.0.5"]
        );
    }

    /// `-T replace` with no address is a usage error; an empty membership is
    /// a flush instead.
    #[tokio::test]
    async fn replace_table_with_no_address_flushes() {
        let mock = MockRunner::new();
        mock.push_ok();
        let pf = PfCtl::with_runner(&mock);
        pf.replace_table(ANCHOR_RDR, "satl_p8080_tcp_80", &[])
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T flush"]
        );
    }

    #[tokio::test]
    async fn show_table_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, "   10.88.0.2\n   10.88.0.5\n", "");
        let pf = PfCtl::with_runner(&mock);
        let shown = pf
            .show_table(ANCHOR_RDR, "satl_p8080_tcp_80")
            .await
            .unwrap();
        assert_eq!(shown, "   10.88.0.2\n   10.88.0.5\n");
        assert_eq!(
            mock.calls(),
            ["/sbin/pfctl -a satl/rdr -t satl_p8080_tcp_80 -T show"]
        );
    }

    #[tokio::test]
    async fn flush_anchor_flushes_nat_then_rules() {
        let mock = MockRunner::new();
        mock.push_ok();
        mock.push_ok();
        let pf = PfCtl::with_runner(&mock);
        pf.flush_anchor(ANCHOR_NAT).await.unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/sbin/pfctl -a satl/nat -F nat",
                "/sbin/pfctl -a satl/nat -F rules",
            ]
        );
    }

    #[tokio::test]
    async fn show_anchor_concatenates_nat_and_rules() {
        let mock = MockRunner::new();
        mock.push_output(
            0,
            "nat on ice0 inet from 10.88.0.0/24 to any -> (ice0)\n",
            "",
        );
        mock.push_output(0, "", "");
        let pf = PfCtl::with_runner(&mock);
        let shown = pf.show_anchor(ANCHOR_NAT).await.unwrap();
        assert_eq!(
            shown,
            "nat on ice0 inet from 10.88.0.0/24 to any -> (ice0)\n"
        );
        assert_eq!(
            mock.calls(),
            [
                "/sbin/pfctl -a satl/nat -s nat",
                "/sbin/pfctl -a satl/nat -s rules",
            ]
        );
    }

    #[tokio::test]
    async fn unavailable_pf_is_a_distinct_error() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_UNAVAILABLE);
        let pf = PfCtl::with_runner(&mock);
        let err = pf.check_syntax("pass all\n").await.unwrap_err();
        assert!(matches!(err, PfError::Unavailable { .. }), "{err}");
        let text = err.to_string();
        assert!(text.contains("pf unavailable"), "{text}");
        assert!(text.contains("Failed to open netlink"), "{text}");
    }

    #[tokio::test]
    async fn syntax_error_carries_ruleset_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "stdin:1: syntax error\n");
        let pf = PfCtl::with_runner(&mock);
        let err = pf.check_syntax("rdr nonsense\n").await.unwrap_err();
        match &err {
            PfError::Failed { rules, .. } => assert_eq!(rules, "rdr nonsense\n"),
            other => panic!("expected Failed, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("/sbin/pfctl -nf -"), "{text}");
        assert!(text.contains("syntax error"), "{text}");
        assert!(text.contains("rdr nonsense"), "{text}");
    }

    // ---- real pfctl validation (best effort on the dev host) -----------------
    //
    // Every generated ruleset is pushed through a real `pfctl -nf -` parse
    // when the host allows it. On hosts where pf.ko is not loaded (the dev
    // machine — see module docs) pfctl cannot even parse, so the check is
    // skipped; the cluster VMs run it for real, and `tests/integration.rs`
    // has an #[ignore]-gated variant that *requires* it.

    async fn validate_with_real_pfctl(rules: &str) {
        if !std::path::Path::new(DEFAULT_PFCTL_BINARY).exists() {
            eprintln!("skipping real pfctl validation: {DEFAULT_PFCTL_BINARY} missing");
            return;
        }
        match PfCtl::system().check_syntax(rules).await {
            Ok(()) => {}
            Err(PfError::Unavailable { .. }) => {
                eprintln!("skipping real pfctl validation: pf unavailable on this host");
            }
            Err(other) => panic!("pfctl rejected generated ruleset {rules:?}: {other}"),
        }
    }

    #[tokio::test]
    async fn generated_nat_rules_pass_real_pfctl_parse() {
        validate_with_real_pfctl(&nat_rules(subnet("10.88.0.0/24"), "ice0")).await;
    }

    #[tokio::test]
    async fn generated_rdr_rules_pass_real_pfctl_parse() {
        validate_with_real_pfctl(&rdr_rules(&pool_publishes(&sample_publishes()))).await;
    }

    /// The table-backed pool form has its own parse test: `-> <table> port N
    /// round-robin` is a different production of pf.conf's grammar
    /// (redirhost table, then portspec, then pooltype) and a wrong order
    /// parses nowhere. Measured on FreeBSD 15.1 (`docs/roadmap.md`, M6):
    /// `rdr -> <table> round-robin` and `source-hash` are both accepted;
    /// `{ a, b } source-hash` is not.
    #[tokio::test]
    async fn generated_table_backed_rules_pass_real_pfctl_parse() {
        let publishes = vec![
            PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().unwrap(),
                task_port: 80,
            },
            PortPublish {
                proto: PortProtocol::Udp,
                host_port: 8053,
                task_ip: "10.88.0.3".parse().unwrap(),
                task_port: 53,
            },
            PortPublish {
                proto: PortProtocol::Udp,
                host_port: 8053,
                task_ip: "10.88.0.4".parse().unwrap(),
                task_port: 53,
            },
        ];
        validate_with_real_pfctl(&rdr_rules(&pool_publishes(&publishes))).await;
    }

    /// The mesh half (M6d): a table-referencing `nat pass` and the
    /// `match ... scrub (max-mss N)` clamp are both forms the M6 measurement
    /// matrix already accepted — keep them parse-checked like the rest.
    #[tokio::test]
    async fn generated_mesh_rules_pass_real_pfctl_parse() {
        let mesh = MeshEgress {
            gateway: "10.100.0.4".parse().unwrap(),
            bridge: "satl-br4096".to_owned(),
            subnet: subnet("10.100.0.0/24"),
            max_mss: 1410,
        };
        let pools = pool_publishes(&sample_publishes());
        validate_with_real_pfctl(&format!(
            "{}{}",
            mesh_rules(&mesh, &pools),
            rdr_rules(&pools)
        ))
        .await;
    }
}
