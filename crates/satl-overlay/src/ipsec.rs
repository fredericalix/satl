// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `setkey`(8) for ESP transport-mode security
//! associations (SAD) and policies (SPD), plus the pure desired-state
//! reconciler for overlay data-plane encryption (M6, `--opt encrypted`).
//!
//! Everything here is coded against `hack/experiments/esp/README.md`, which is
//! measured ground truth from the cluster VMs; the parsers are tested against
//! fixtures copied verbatim from that experiment's captures
//! (`hack/experiments/esp/captures/q2-setkey.txt`). The facts that shape the
//! API:
//!
//! 1. **SPIs are derived, never random** — FNV-1a/32 over
//!    `local.octets() || tag.to_be_bytes() || remote.octets()`, exactly
//!    libnetwork's `buildSPI`, so both ends compute the same value for the
//!    same key. Direction is baked into the argument order; the
//!    [`outbound_spi`]/[`inbound_spi`] helpers make it impossible to swap.
//! 2. **`aes-gcm-16` key material is 160 bits**: the 128-bit AES key followed
//!    by a 32-bit salt, and the salt is the SA's own SPI (big-endian), exactly
//!    libnetwork's `buildAeadAlgo` ([`aead_key_hex`]).
//! 3. **The source selector of an outbound SP is `[any]`, mandatorily** —
//!    `if_vxlan` picks the outer source port as a per-flow hash, so a pinned
//!    `[<port>]` source selector never matches (experiment §2), and pinning
//!    the port with `vxlanportrange` would defeat the pf cleartext guard
//!    (experiment §7, G5).
//! 4. **Rotation choreography is adds-before-deletes**: the kernel emits with
//!    the first-added matching SA and switches only when it is deleted
//!    (experiment §6), so a reconcile pass must always apply every add before
//!    any delete. [`plan_security`] returns operations in that order; the
//!    order IS the rotation protocol.
//!
//! Same command-seam idiom as [`crate::vxlan`]: one module per tool, typed
//! functions, no raw `Command` in business logic, unit tests for command
//! construction and output parsing (CLAUDE.md, "External command wrappers").
//! Reads (`setkey -D` / `-DP`) go through [`CommandRunner`]; mutations are
//! batched as a script fed to `setkey -c` on stdin through [`PipedRunner`]
//! (measured working, experiment §2).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use satl_core::NetworkKey;

use crate::runner::{
    CommandOutput, CommandRunner, Failure, PipedRunner, SystemRunner, render_argv,
};

/// Default location of the `setkey` binary on FreeBSD.
pub const DEFAULT_SETKEY_BINARY: &str = "/sbin/setkey";

/// Timeout for one `setkey -c` batch. setkey(8) never blocks on I/O; this is
/// only the hung-child net every [`PipedRunner`] caller must have.
const SETKEY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// SPI derivation (libnetwork-compatible)
// ---------------------------------------------------------------------------

/// FNV-1a/32 offset basis.
const FNV1A_32_OFFSET: u32 = 2_166_136_261;

/// FNV-1a/32 prime.
const FNV1A_32_PRIME: u32 = 16_777_619;

/// FNV-1a/32 over `local.octets() || tag.to_be_bytes() || remote.octets()` —
/// exactly libnetwork's `buildSPI`. The direction of the SA is encoded in the
/// argument order, so callers should go through [`outbound_spi`] /
/// [`inbound_spi`] instead of calling this directly.
fn spi(local: Ipv4Addr, tag: u32, remote: Ipv4Addr) -> u32 {
    let mut hash = FNV1A_32_OFFSET;
    for byte in local
        .octets()
        .into_iter()
        .chain(tag.to_be_bytes())
        .chain(remote.octets())
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV1A_32_PRIME);
    }
    hash
}

/// The SPI of the SA this node uses to **emit** to `peer` under `tag`.
#[must_use]
pub fn outbound_spi(me: Ipv4Addr, tag: u32, peer: Ipv4Addr) -> u32 {
    spi(me, tag, peer)
}

/// The SPI of the SA this node uses to **receive** from `peer` under `tag` —
/// the same value the peer computes as its outbound SPI towards this node.
#[must_use]
pub fn inbound_spi(me: Ipv4Addr, tag: u32, peer: Ipv4Addr) -> u32 {
    spi(peer, tag, me)
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

/// The `aes-gcm-16` key argument for `setkey`: the 128-bit AES key followed by
/// the 32-bit salt, rendered as one lowercase-hex `0x...` string (160 bits,
/// RFC 4106; `man setkey`, "Encryption Algorithms"). The salt is the SA's own
/// SPI in big-endian, exactly libnetwork's `buildAeadAlgo`.
#[must_use]
pub fn aead_key_hex(key: &[u8; 16], spi: u32) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(2 + 40);
    hex.push_str("0x");
    for byte in key.iter().chain(spi.to_be_bytes().iter()) {
        // Infallible: fmt::Write on String never errors.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Direction of a security policy or association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Packets arriving at this node.
    In,
    /// Packets leaving this node.
    Out,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A port selector in an SP address: `[any]` or `[<port>]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortSelector {
    /// `[any]` — the only acceptable source selector for SatL (module docs,
    /// point 3).
    Any,
    /// `[<port>]`.
    Port(u16),
}

impl fmt::Display for PortSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Port(port) => write!(f, "{port}"),
        }
    }
}

/// One SAD entry, as SatL programs it and as `setkey -D` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityAssociation {
    /// Source address of the protected traffic.
    pub src: Ipv4Addr,
    /// Destination address of the protected traffic.
    pub dst: Ipv4Addr,
    /// Security Parameter Index.
    pub spi: u32,
}

/// One SPD entry, as SatL programs it and as `setkey -DP` reports it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityPolicy {
    /// Source address of the selector.
    pub src: Ipv4Addr,
    /// Source port selector.
    pub src_port: PortSelector,
    /// Destination address of the selector.
    pub dst: Ipv4Addr,
    /// Destination port selector.
    pub dst_port: PortSelector,
    /// Upper-layer protocol of the selector (`udp` for everything SatL
    /// installs; kept as text so a foreign entry parses rather than errors).
    pub protocol: String,
    /// Policy direction.
    pub direction: Direction,
}

/// The one SP shape SatL installs: `<me>[any] <peer>[<port>] udp -P out
/// ipsec esp/transport/<me>-<peer>/require`.
#[must_use]
pub fn desired_sp(me: Ipv4Addr, peer: Ipv4Addr, port: u16) -> SecurityPolicy {
    SecurityPolicy {
        src: me,
        src_port: PortSelector::Any,
        dst: peer,
        dst_port: PortSelector::Port(port),
        protocol: "udp".to_owned(),
        direction: Direction::Out,
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error from the `IPsec` wrapper. Every variant names what was attempted and
/// carries the full argv, exit status and raw output of the failed command.
#[derive(Debug, thiserror::Error)]
pub enum IpsecError {
    /// The binary could not be spawned.
    #[error("ipsec ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("ipsec ({context}): {failure}")]
    Failed {
        /// What was being attempted.
        context: String,
        /// The failed command with argv, exit status and stderr.
        failure: Failure,
    },

    /// The command succeeded but its output did not have the expected shape.
    #[error(
        "ipsec ({context}): unexpected output from `{argv}`: {reason}; \
         raw stdout: {stdout:?}; raw stderr: {stderr:?}"
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
        /// Raw stderr from the command.
        stderr: String,
    },
}

// ---------------------------------------------------------------------------
// Pure script builders (setkey -c syntax, one statement per line)
// ---------------------------------------------------------------------------

fn script_add_sa(sa: &SecurityAssociation, key: &[u8; 16]) -> String {
    format!(
        "add {} {} esp {:#x} -m transport -E aes-gcm-16 {} ;",
        sa.src,
        sa.dst,
        sa.spi,
        aead_key_hex(key, sa.spi)
    )
}

fn script_delete_sa(sa: &SecurityAssociation) -> String {
    format!("delete {} {} esp {:#x} ;", sa.src, sa.dst, sa.spi)
}

fn script_add_sp(sp: &SecurityPolicy) -> String {
    format!(
        "spdadd {}[{}] {}[{}] {} -P {} ipsec esp/transport/{}-{}/require ;",
        sp.src, sp.src_port, sp.dst, sp.dst_port, sp.protocol, sp.direction, sp.src, sp.dst
    )
}

fn script_delete_sp(sp: &SecurityPolicy) -> String {
    format!(
        "spddelete {}[{}] {}[{}] {} -P {} ;",
        sp.src, sp.src_port, sp.dst, sp.dst_port, sp.protocol, sp.direction
    )
}

/// What may reach a log line or an error message in place of a batch script:
/// the script with every `aes-gcm-16` key argument replaced by
/// `0x<redacted>`.
///
/// ESP key material must never appear in a log (the daemon's output goes to
/// syslog, where it is world-visible and rotated into files that outlive the
/// key). SPIs, addresses and ports stay visible — they are not secret (the
/// SPI is on the wire) and they are what an operator greps for when
/// diagnosing a failed `setkey -c`.
fn redact_script_keys(script: &str) -> String {
    let mut redacted = String::with_capacity(script.len());
    let mut redact_next = false;
    // Line structure is preserved exactly; within a line the tokens are split
    // on any whitespace run, because a `setkey` stderr echo does not promise
    // the single spacing of SatL's own scripts — and missing the key field
    // over a double space would leak it into the error text.
    for (line_number, line) in script.split('\n').enumerate() {
        if line_number > 0 {
            redacted.push('\n');
        }
        for (index, token) in line.split_whitespace().enumerate() {
            if index > 0 {
                redacted.push(' ');
            }
            if redact_next && token.starts_with("0x") {
                redacted.push_str("0x<redacted>");
            } else {
                redacted.push_str(token);
            }
            redact_next = token == "aes-gcm-16";
        }
    }
    redacted
}

// ---------------------------------------------------------------------------
// Pure output parsers
// ---------------------------------------------------------------------------

/// Parse `setkey -D` output. The empty SAD prints `No SAD entries.`
/// (measured, `hack/experiments/esp/captures/q0-preflight.txt`).
fn parse_sad(stdout: &str) -> Result<Vec<SecurityAssociation>, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "No SAD entries." {
        return Ok(Vec::new());
    }
    let mut sas = Vec::new();
    let mut current: Option<(Ipv4Addr, Ipv4Addr)> = None;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            // A detail line of the current entry; the `esp mode=... spi=...`
            // line is the one that completes it. Lifetime and counter lines
            // are ignored.
            if let Some(spi) = parse_spi_field(line)
                && let Some((src, dst)) = current.take()
            {
                sas.push(SecurityAssociation { src, dst, spi });
            }
            continue;
        }
        // An entry header: `<src> <dst>` (hack/experiments/esp/captures/
        // q2-setkey.txt). Anything else is not a SAD dump.
        let mut words = line.split_whitespace();
        let (Some(src), Some(dst), None) = (words.next(), words.next(), words.next()) else {
            return Err(format!("expected a '<src> <dst>' SA header, got {line:?}"));
        };
        let src = src
            .parse()
            .map_err(|_| format!("SA source {src:?} is not an IPv4 address"))?;
        let dst = dst
            .parse()
            .map_err(|_| format!("SA destination {dst:?} is not an IPv4 address"))?;
        current = Some((src, dst));
    }
    Ok(sas)
}

/// The SPI out of an `esp mode=transport spi=244944898(0x0e999002) reqid=...`
/// line — the hexadecimal rendering in parentheses, never the decimal (a
/// value like `spi=10` would otherwise be ambiguous).
fn parse_spi_field(line: &str) -> Option<u32> {
    let field = line
        .split_whitespace()
        .find_map(|word| word.strip_prefix("spi="))?;
    let start = field.find("(0x")? + 3;
    let end = field[start..].find(')')? + start;
    u32::from_str_radix(&field[start..end], 16).ok()
}

/// Parse an `<addr>` or `<addr>[<port|any>]` SP selector.
fn parse_addr_selector(token: &str) -> Result<(Ipv4Addr, PortSelector), String> {
    let bad_addr = || format!("SP address in {token:?} is not an IPv4 address");
    match token.split_once('[') {
        Some((addr, selector)) => {
            let selector = selector
                .strip_suffix(']')
                .ok_or_else(|| format!("unterminated port selector in {token:?}"))?;
            let selector = if selector == "any" {
                PortSelector::Any
            } else {
                PortSelector::Port(
                    selector
                        .parse()
                        .map_err(|_| format!("port selector in {token:?} is not a port number"))?,
                )
            };
            Ok((addr.parse().map_err(|_| bad_addr())?, selector))
        }
        // setkey prints a selectorless address bare; it selects every port.
        None => Ok((token.parse().map_err(|_| bad_addr())?, PortSelector::Any)),
    }
}

/// Parse `setkey -DP` output. The empty SPD prints `No SPD entries.`.
fn parse_spd(stdout: &str) -> Result<Vec<SecurityPolicy>, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "No SPD entries." {
        return Ok(Vec::new());
    }
    let mut sps = Vec::new();
    let mut current: Option<(Ipv4Addr, PortSelector, Ipv4Addr, PortSelector, String)> = None;
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            // A detail line: `<direction> ipsec` completes the entry; the
            // `esp/transport/...` and `spid=...` lines are ignored.
            let direction = match line.split_whitespace().next() {
                Some("in") => Some(Direction::In),
                Some("out") => Some(Direction::Out),
                _ => None,
            };
            if let Some(direction) = direction
                && let Some((src, src_port, dst, dst_port, protocol)) = current.take()
            {
                sps.push(SecurityPolicy {
                    src,
                    src_port,
                    dst,
                    dst_port,
                    protocol,
                    direction,
                });
            }
            continue;
        }
        // An entry header: `<src>[<sel>] <dst>[<sel>] <protocol>`.
        let mut words = line.split_whitespace();
        let (Some(src), Some(dst), Some(protocol)) = (words.next(), words.next(), words.next())
        else {
            return Err(format!(
                "expected a '<src>[port] <dst>[port] <protocol>' SP header, got {line:?}"
            ));
        };
        let (src, src_port) = parse_addr_selector(src)?;
        let (dst, dst_port) = parse_addr_selector(dst)?;
        current = Some((src, src_port, dst, dst_port, protocol.to_owned()));
    }
    Ok(sps)
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

/// Typed async wrapper around `setkey`(8).
///
/// Generic over the runner pair so unit tests can inject a mock executor;
/// production code uses [`Ipsec::system`]. Mutations are batched through
/// `setkey -c` on stdin; presence checks parse `setkey -D` / `-DP` first, so
/// every `ensure_*` is idempotent and every `remove_*` is absent-is-fine.
#[derive(Debug, Clone)]
pub struct Ipsec<R = SystemRunner> {
    setkey: PathBuf,
    runner: R,
}

impl Ipsec<SystemRunner> {
    /// Wrapper that executes the real binary.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Ipsec<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner + PipedRunner> Ipsec<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            setkey: PathBuf::from(DEFAULT_SETKEY_BINARY),
            runner,
        }
    }

    /// Override the `setkey` binary path.
    #[must_use]
    pub fn with_setkey(mut self, binary: impl Into<PathBuf>) -> Self {
        self.setkey = binary.into();
        self
    }

    async fn exec(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), IpsecError> {
        let rendered = render_argv(&self.setkey, &args);
        tracing::debug!(command = %rendered, "running");
        let output = self
            .runner
            .run(&self.setkey, &args)
            .await
            .map_err(|source| IpsecError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    /// Feed a script to `setkey -c` on stdin.
    ///
    /// The script contains ESP key material, so it is **never** logged or put
    /// in an error as-is: the debug line and any failure carry only
    /// [`redact_script_keys`] output.
    async fn batch(&self, context: &str, script: String) -> Result<(), IpsecError> {
        let args = vec!["-c".to_owned()];
        let rendered = render_argv(&self.setkey, &args);
        tracing::debug!(command = %rendered, script = %redact_script_keys(&script), "running");
        let output = self
            .runner
            .run_piped(&self.setkey, &args, script, SETKEY_TIMEOUT)
            .await
            .map_err(|source| IpsecError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        if output.success() {
            return Ok(());
        }
        // setkey may echo the offending script line back on stderr; scrub the
        // key field before it reaches an operator-facing error.
        let scrubbed = CommandOutput {
            exit_code: output.exit_code,
            stdout: redact_script_keys(&output.stdout),
            stderr: redact_script_keys(&output.stderr),
        };
        Err(IpsecError::Failed {
            context: context.to_owned(),
            failure: Failure::new(rendered, &scrubbed),
        })
    }

    /// The current SAD, parsed from `setkey -D`.
    pub async fn sas(&self) -> Result<Vec<SecurityAssociation>, IpsecError> {
        let context = "dump the SAD";
        let flag = vec!["-D".to_owned()];
        let (rendered, output) = self.exec(context, flag.clone()).await?;
        if !output.success() {
            return Err(IpsecError::Failed {
                context: context.to_owned(),
                failure: Failure::new(rendered, &output),
            });
        }
        parse_sad(&output.stdout).map_err(|reason| IpsecError::UnexpectedOutput {
            context: context.to_owned(),
            argv: render_argv(&self.setkey, &flag),
            reason,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        })
    }

    /// The current SPD, parsed from `setkey -DP`.
    pub async fn sps(&self) -> Result<Vec<SecurityPolicy>, IpsecError> {
        let context = "dump the SPD";
        let flag = vec!["-DP".to_owned()];
        let (rendered, output) = self.exec(context, flag.clone()).await?;
        if !output.success() {
            return Err(IpsecError::Failed {
                context: context.to_owned(),
                failure: Failure::new(rendered, &output),
            });
        }
        parse_spd(&output.stdout).map_err(|reason| IpsecError::UnexpectedOutput {
            context: context.to_owned(),
            argv: render_argv(&self.setkey, &flag),
            reason,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        })
    }

    /// Install the SA between `me` and `peer` under `spi` if it is not already
    /// there; `Ok(false)` when it was (idempotent). `direction` decides the
    /// address order of the `add` statement: `Out` is `add <me> <peer>`, `In`
    /// is `add <peer> <me>`.
    pub async fn ensure_sa(
        &self,
        me: Ipv4Addr,
        peer: Ipv4Addr,
        spi: u32,
        key: &[u8; 16],
        direction: Direction,
    ) -> Result<bool, IpsecError> {
        let (src, dst) = match direction {
            Direction::Out => (me, peer),
            Direction::In => (peer, me),
        };
        let wanted = SecurityAssociation { src, dst, spi };
        if self.sas().await?.contains(&wanted) {
            return Ok(false);
        }
        let context = format!("add SA {src} -> {dst} spi {spi:#x}");
        self.batch(&context, script_add_sa(&wanted, key) + "\n")
            .await?;
        tracing::info!(src = %src, dst = %dst, spi = %format!("{spi:#x}"), "installed ESP SA");
        Ok(true)
    }

    /// Remove the SA(s) between `me` and `peer` under `spi`; `Ok(false)` when
    /// none was installed (absent is fine).
    pub async fn remove_sa(
        &self,
        me: Ipv4Addr,
        peer: Ipv4Addr,
        spi: u32,
    ) -> Result<bool, IpsecError> {
        let matches: Vec<SecurityAssociation> = self
            .sas()
            .await?
            .into_iter()
            .filter(|sa| {
                sa.spi == spi
                    && ((sa.src == me && sa.dst == peer) || (sa.src == peer && sa.dst == me))
            })
            .collect();
        if matches.is_empty() {
            return Ok(false);
        }
        let context = format!("delete SA(s) between {me} and {peer} spi {spi:#x}");
        let script = matches
            .iter()
            .map(|sa| script_delete_sa(sa) + "\n")
            .collect();
        self.batch(&context, script).await?;
        for sa in &matches {
            tracing::info!(src = %sa.src, dst = %sa.dst, spi = %format!("{:#x}", sa.spi), "removed ESP SA");
        }
        Ok(true)
    }

    /// Install the outbound SP `<me>[any] <peer>[<port>] udp -P out ipsec
    /// esp/transport/<me>-<peer>/require` if absent; `Ok(false)` when it was
    /// already there.
    pub async fn ensure_sp(
        &self,
        me: Ipv4Addr,
        peer: Ipv4Addr,
        port: u16,
    ) -> Result<bool, IpsecError> {
        let wanted = desired_sp(me, peer, port);
        if self.sps().await?.contains(&wanted) {
            return Ok(false);
        }
        let context = format!("add SP {me}[any] -> {peer}[{port}] udp out");
        self.batch(&context, script_add_sp(&wanted) + "\n").await?;
        tracing::info!(src = %me, dst = %peer, port, "installed IPsec policy");
        Ok(true)
    }

    /// Remove that SP; `Ok(false)` when it was not installed.
    pub async fn remove_sp(
        &self,
        me: Ipv4Addr,
        peer: Ipv4Addr,
        port: u16,
    ) -> Result<bool, IpsecError> {
        let wanted = desired_sp(me, peer, port);
        if !self.sps().await?.contains(&wanted) {
            return Ok(false);
        }
        let context = format!("delete SP {me}[any] -> {peer}[{port}] udp out");
        self.batch(&context, script_delete_sp(&wanted) + "\n")
            .await?;
        tracing::info!(src = %me, dst = %peer, port, "removed IPsec policy");
        Ok(true)
    }

    /// Apply a whole [`SecurityPlan`] as one `setkey -c` batch, in plan order.
    ///
    /// The batch is the unit the rotation protocol is measured against: every
    /// add lands before any delete ([`plan_security`]), and one `setkey -c`
    /// feeds them in exactly that order. An empty plan runs nothing. The
    /// script carries key material, so — as with every mutation here — only
    /// its [`redact_script_keys`] form may reach a log line or an error.
    pub async fn apply(&self, plan: &SecurityPlan) -> Result<(), IpsecError> {
        if plan.is_empty() {
            return Ok(());
        }
        let context = format!("apply a security plan of {} operation(s)", plan.ops.len());
        self.batch(&context, plan.script()).await
    }
}

// ---------------------------------------------------------------------------
// The desired-state reconciler (pure)
// ---------------------------------------------------------------------------

/// One encrypted network's security requirements towards one remote peer: the
/// network's VXLAN port and its keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSecurity {
    /// Remote peer's underlay (VTEP) address.
    pub peer: Ipv4Addr,
    /// The network's VXLAN UDP port (`Network::vxlan_port`).
    pub port: u16,
    /// The network's keyring (`Network::keys`); at most one entry is
    /// `primary`.
    pub keys: Vec<NetworkKey>,
}

/// The kernel state to reconcile against, as parsed by [`Ipsec::sas`] and
/// [`Ipsec::sps`]. **Must cover every SA/SP SatL manages on this node** — the
/// reconciler plans to delete anything present that is not desired, so a
/// partial view tears down the entries it cannot see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresentSecurity {
    /// Current SAD.
    pub sas: Vec<SecurityAssociation>,
    /// Current SPD.
    pub sps: Vec<SecurityPolicy>,
}

/// One setkey operation, in plan order.
#[derive(Clone, PartialEq, Eq)]
pub enum SecurityOp {
    /// `add` an SA.
    AddSa {
        /// The SA tuple.
        sa: SecurityAssociation,
        /// The 16-byte AES key (rendered with the SPI salt at apply time).
        key: [u8; 16],
    },
    /// `spdadd` an SP.
    AddSp(SecurityPolicy),
    /// `spddelete` an SP.
    RemoveSp(SecurityPolicy),
    /// `delete` an SA.
    RemoveSa(SecurityAssociation),
}

impl fmt::Debug for SecurityOp {
    /// Never prints the key material of an `AddSa` — same rule as
    /// `satl_core::NetworkKey`'s manual impl: keys must not leak into logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddSa { sa, key } => f
                .debug_struct("AddSa")
                .field("sa", sa)
                .field("key", &format_args!("<redacted, {} bytes>", key.len()))
                .finish(),
            Self::AddSp(sp) => f.debug_tuple("AddSp").field(sp).finish(),
            Self::RemoveSp(sp) => f.debug_tuple("RemoveSp").field(sp).finish(),
            Self::RemoveSa(sa) => f.debug_tuple("RemoveSa").field(sa).finish(),
        }
    }
}

/// What a reconcile pass must apply, in order: SA adds, then SP adds, then SP
/// deletes, then SA deletes.
///
/// The ordering is not an implementation detail, it is the measured rotation
/// protocol (`hack/experiments/esp/README.md` §6): the kernel emits with the
/// first-added matching SA and switches only when that SA is deleted, so a
/// pass must add the new inbound and outbound SAs *before* deleting the old
/// outbound SA (the delete is what promotes the new SPI) and the old inbound
/// SA (pruned only after every peer could have switched).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityPlan {
    /// Operations in apply order.
    pub ops: Vec<SecurityOp>,
}

impl SecurityPlan {
    /// Whether the plan changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The whole plan as one `setkey -c` script, in apply order.
    ///
    /// **The returned string contains ESP key material** (every `add` line
    /// carries the `-E aes-gcm-16 0x…` argument): feed it to `setkey -c`,
    /// never to a log line, `Debug`, or error message. The only loggable form
    /// is [`redact_script_keys`] output (what [`Ipsec::batch`] uses).
    #[must_use]
    pub fn script(&self) -> String {
        let mut script = String::new();
        for op in &self.ops {
            let line = match op {
                SecurityOp::AddSa { sa, key } => script_add_sa(sa, key),
                SecurityOp::AddSp(sp) => script_add_sp(sp),
                SecurityOp::RemoveSp(sp) => script_delete_sp(sp),
                SecurityOp::RemoveSa(sa) => script_delete_sa(sa),
            };
            script.push_str(&line);
            script.push('\n');
        }
        script
    }
}

/// Compute the desired security state for `me` from the per-(network, peer)
/// view and diff it against the parsed kernel state.
///
/// Desired, per [`PeerSecurity`]:
///
/// - an **inbound** SA (`<peer> -> <me>`) for **every** key in the ring,
///   under [`inbound_spi`];
/// - the **outbound** SA (`<me> -> <peer>`) for the **primary** key only,
///   under [`outbound_spi`];
/// - one outbound SP ([`desired_sp`]).
///
/// Anything present but not desired is deleted; anything desired but absent
/// is added. See [`SecurityPlan`] for why adds always precede deletes.
#[must_use]
pub fn plan_security(
    me: Ipv4Addr,
    desired: &[PeerSecurity],
    present: &PresentSecurity,
) -> SecurityPlan {
    // BTreeMap/BTreeSet so the plan order is deterministic: sorted by
    // (src, dst, spi) for SAs and by (src, dst, port) for SPs.
    let mut desired_assocs: BTreeMap<SecurityAssociation, [u8; 16]> = BTreeMap::new();
    let mut desired_policies: BTreeSet<SecurityPolicy> = BTreeSet::new();
    for ps in desired {
        // Reception accepts every key in the ring.
        for key in &ps.keys {
            let sa = SecurityAssociation {
                src: ps.peer,
                dst: me,
                spi: inbound_spi(me, key.tag, ps.peer),
            };
            desired_assocs.entry(sa).or_insert(key.key);
        }
        // Emission uses the primary key only.
        if let Some(primary) = ps.keys.iter().find(|key| key.primary) {
            let sa = SecurityAssociation {
                src: me,
                dst: ps.peer,
                spi: outbound_spi(me, primary.tag, ps.peer),
            };
            desired_assocs.entry(sa).or_insert(primary.key);
        }
        desired_policies.insert(desired_sp(me, ps.peer, ps.port));
    }

    let present_assocs: BTreeSet<SecurityAssociation> = present.sas.iter().copied().collect();
    let present_policies: BTreeSet<SecurityPolicy> = present.sps.iter().cloned().collect();

    // The order of these four loops IS the rotation protocol
    // (hack/experiments/esp/README.md section 6): adds before deletes, and
    // policies before associations on the way down so no packet outlives the
    // SA it needs on the way up.
    let mut ops = Vec::new();
    for (sa, key) in &desired_assocs {
        if !present_assocs.contains(sa) {
            ops.push(SecurityOp::AddSa { sa: *sa, key: *key });
        }
    }
    for sp in &desired_policies {
        if !present_policies.contains(sp) {
            ops.push(SecurityOp::AddSp(sp.clone()));
        }
    }
    for sp in &present_policies {
        if !desired_policies.contains(sp) {
            ops.push(SecurityOp::RemoveSp(sp.clone()));
        }
    }
    for sa in &present_assocs {
        if !desired_assocs.contains_key(sa) {
            ops.push(SecurityOp::RemoveSa(*sa));
        }
    }
    SecurityPlan { ops }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_SAD: &str = include_str!("../tests/fixtures/setkey_dump_sad.txt");
    const FIXTURE_SPD_ANY: &str = include_str!("../tests/fixtures/setkey_dump_spd_any.txt");

    const ME: Ipv4Addr = Ipv4Addr::new(10, 2, 2, 47);
    const PEER: Ipv4Addr = Ipv4Addr::new(10, 2, 1, 50);
    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn test_key(tag: u32) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&tag.to_be_bytes());
        key
    }

    fn network_key(tag: u32, primary: bool) -> NetworkKey {
        NetworkKey {
            tag,
            key: test_key(tag),
            primary,
        }
    }

    /// A keyring whose primary is `primary_tag`, with `other_tags` as the
    /// accepted-but-not-emitting keys.
    fn keyring(primary_tag: u32, other_tags: &[u32]) -> Vec<NetworkKey> {
        let mut keys: Vec<NetworkKey> = other_tags
            .iter()
            .map(|&tag| network_key(tag, false))
            .collect();
        keys.push(network_key(primary_tag, true));
        keys
    }

    fn sa(src: Ipv4Addr, dst: Ipv4Addr, spi: u32) -> SecurityAssociation {
        SecurityAssociation { src, dst, spi }
    }

    /// The kernel state a fully-applied plan leaves behind.
    fn applied(plan: &SecurityPlan) -> PresentSecurity {
        let mut present = PresentSecurity::default();
        for op in &plan.ops {
            match op {
                SecurityOp::AddSa { sa, .. } => present.sas.push(*sa),
                SecurityOp::AddSp(sp) => present.sps.push(sp.clone()),
                SecurityOp::RemoveSa(_) | SecurityOp::RemoveSp(_) => {}
            }
        }
        present
    }

    // ---- SPI derivation -----------------------------------------------------

    #[test]
    fn spi_matches_the_libnetwork_fnv1a_vector() {
        // FNV-1a/32 (offset basis 2166136261, prime 16777619) over
        // local.octets() || tag.to_be_bytes() || remote.octets(), i.e. the
        // byte string [10,2,2,47, 0,0,0,1, 10,2,1,50]: start
        // h = 0x811c9dc5, then per byte h = (h ^ b) * 0x01000193 mod 2^32.
        // Recomputed independently of this crate (python3, same byte order as
        // libnetwork's buildSPI): 0x4e8b0136.
        assert_eq!(spi(ME, 1, PEER), 0x4e8b_0136);
        // A second vector against tag-order mistakes (tag bytes between the
        // addresses, big-endian): 0x647b96af.
        assert_eq!(spi(ME, 0x0e99_9001, PEER), 0x647b_96af);
    }

    #[test]
    fn direction_helpers_cannot_be_swapped() {
        let tag = 42;
        // A's outbound towards B is B's inbound from A: one value, two names.
        assert_eq!(outbound_spi(ME, tag, PEER), inbound_spi(PEER, tag, ME));
        assert_eq!(inbound_spi(ME, tag, PEER), outbound_spi(PEER, tag, ME));
        // And the two directions differ, so a swap is never silent.
        assert_ne!(outbound_spi(ME, tag, PEER), inbound_spi(ME, tag, PEER));
    }

    // ---- key material -------------------------------------------------------

    #[test]
    fn aead_key_hex_is_the_aes_key_then_the_spi_salt() {
        // 128-bit key, then the 32-bit big-endian SPI as the RFC 4106 salt.
        assert_eq!(
            aead_key_hex(&KEY, 0x0e99_9001),
            "0x00112233445566778899aabbccddeeff0e999001"
        );
        assert_eq!(aead_key_hex(&KEY, 0x0e99_9001).len(), 2 + 40);
    }

    // ---- script builders -----------------------------------------------------

    #[test]
    fn script_lines_match_the_measured_setkey_syntax() {
        // Ground truth: hack/experiments/esp/captures/q2-setkey.txt (the
        // heredocs fed to `setkey -c`) and `man setkey` on FreeBSD 15.1.
        let out = sa(ME, PEER, 0x0e99_9001);
        assert_eq!(
            script_add_sa(&out, &KEY),
            "add 10.2.2.47 10.2.1.50 esp 0xe999001 -m transport -E aes-gcm-16 \
             0x00112233445566778899aabbccddeeff0e999001 ;"
        );
        assert_eq!(
            script_delete_sa(&out),
            "delete 10.2.2.47 10.2.1.50 esp 0xe999001 ;"
        );
        let sp = desired_sp(ME, PEER, 4790);
        assert_eq!(
            script_add_sp(&sp),
            "spdadd 10.2.2.47[any] 10.2.1.50[4790] udp -P out ipsec \
             esp/transport/10.2.2.47-10.2.1.50/require ;"
        );
        assert_eq!(
            script_delete_sp(&sp),
            "spddelete 10.2.2.47[any] 10.2.1.50[4790] udp -P out ;"
        );
    }

    // ---- parsers against real captured fixtures ------------------------------

    #[test]
    fn parse_sad_reads_the_real_dump_format() {
        // Fixture: verbatim `setkey -D` output from node1,
        // hack/experiments/esp/captures/q2-setkey.txt (Q2).
        let sas = parse_sad(FIXTURE_SAD).unwrap();
        assert_eq!(sas, [sa(PEER, ME, 0x0e99_9002), sa(ME, PEER, 0x0e99_9001),]);
        // The empty SAD (hack/experiments/esp/captures/q0-preflight.txt).
        assert_eq!(parse_sad("No SAD entries.\n").unwrap(), []);
        assert_eq!(parse_sad("").unwrap(), []);
    }

    #[test]
    fn parse_spd_reads_any_selectors_and_directions() {
        // Fixture: verbatim `setkey -DP` output of the [any]-selector variant
        // from node1, hack/experiments/esp/captures/q2-setkey.txt (Q2c).
        let sps = parse_spd(FIXTURE_SPD_ANY).unwrap();
        assert_eq!(sps.len(), 2);
        let inbound = &sps[0];
        assert_eq!(inbound.direction, Direction::In);
        assert_eq!(inbound.src, PEER);
        assert_eq!(inbound.src_port, PortSelector::Any);
        assert_eq!(inbound.dst, ME);
        assert_eq!(inbound.dst_port, PortSelector::Port(4790));
        assert_eq!(inbound.protocol, "udp");
        let outbound = &sps[1];
        assert_eq!(outbound.direction, Direction::Out);
        assert_eq!(*outbound, desired_sp(ME, PEER, 4790));
        assert_eq!(parse_spd("No SPD entries.\n").unwrap(), vec![]);
    }

    #[test]
    fn parsers_reject_output_that_is_not_a_dump() {
        assert!(parse_sad("setkey: invalid flag\n").is_err());
        assert!(parse_sad("10.2.2.47\n").is_err());
        assert!(parse_sad("10.2.2.47 nope\n").is_err());
        assert!(parse_spd("garbage\n").is_err());
        assert!(parse_spd("10.2.2.47[any] nope[4790] udp\n").is_err());
        assert!(parse_spd("10.2.2.47[zz] 10.2.1.50[4790] udp\n").is_err());
    }

    // ---- wrapper behavior with the mock runner -------------------------------

    #[tokio::test]
    async fn ensure_sa_checks_first_and_batches_the_add() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SAD entries.\n", "");
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        let added = ipsec
            .ensure_sa(ME, PEER, 0x0e99_9001, &KEY, Direction::Out)
            .await
            .unwrap();
        assert!(added);
        assert_eq!(mock.calls(), ["/sbin/setkey -D", "/sbin/setkey -c"]);
        assert_eq!(
            mock.stdins(),
            [
                "add 10.2.2.47 10.2.1.50 esp 0xe999001 -m transport -E aes-gcm-16 \
             0x00112233445566778899aabbccddeeff0e999001 ;\n"
            ]
        );
    }

    #[tokio::test]
    async fn ensure_sa_inbound_reverses_the_address_order() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SAD entries.\n", "");
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        ipsec
            .ensure_sa(ME, PEER, 0x0e99_9002, &KEY, Direction::In)
            .await
            .unwrap();
        assert_eq!(
            mock.stdins(),
            [
                "add 10.2.1.50 10.2.2.47 esp 0xe999002 -m transport -E aes-gcm-16 \
             0x00112233445566778899aabbccddeeff0e999002 ;\n"
            ]
        );
    }

    #[tokio::test]
    async fn ensure_sa_is_a_noop_when_the_sa_is_already_there() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SAD, "");
        let ipsec = Ipsec::with_runner(&mock);
        let added = ipsec
            .ensure_sa(ME, PEER, 0x0e99_9001, &KEY, Direction::Out)
            .await
            .unwrap();
        assert!(!added);
        assert_eq!(mock.calls(), ["/sbin/setkey -D"]);
    }

    #[tokio::test]
    async fn remove_sa_is_absent_is_fine() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SAD entries.\n", "");
        let ipsec = Ipsec::with_runner(&mock);
        assert!(!ipsec.remove_sa(ME, PEER, 0x0e99_9001).await.unwrap());
        assert_eq!(mock.calls(), ["/sbin/setkey -D"]);
    }

    #[tokio::test]
    async fn remove_sa_deletes_the_matching_tuple() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SAD, "");
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        assert!(ipsec.remove_sa(ME, PEER, 0x0e99_9001).await.unwrap());
        assert_eq!(
            mock.stdins(),
            ["delete 10.2.2.47 10.2.1.50 esp 0xe999001 ;\n"]
        );
    }

    #[tokio::test]
    async fn ensure_sp_adds_the_any_source_selector_policy() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SPD entries.\n", "");
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        assert!(ipsec.ensure_sp(ME, PEER, 4790).await.unwrap());
        assert_eq!(
            mock.stdins(),
            ["spdadd 10.2.2.47[any] 10.2.1.50[4790] udp -P out ipsec \
             esp/transport/10.2.2.47-10.2.1.50/require ;\n"]
        );
    }

    #[tokio::test]
    async fn ensure_sp_is_a_noop_when_present() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SPD_ANY, "");
        let ipsec = Ipsec::with_runner(&mock);
        assert!(!ipsec.ensure_sp(ME, PEER, 4790).await.unwrap());
        assert_eq!(mock.calls(), ["/sbin/setkey -DP"]);
    }

    #[tokio::test]
    async fn remove_sp_is_absent_is_fine() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SPD entries.\n", "");
        let ipsec = Ipsec::with_runner(&mock);
        assert!(!ipsec.remove_sp(ME, PEER, 4790).await.unwrap());
        assert_eq!(mock.calls(), ["/sbin/setkey -DP"]);
    }

    #[tokio::test]
    async fn remove_sp_deletes_the_matching_policy() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SPD_ANY, "");
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        assert!(ipsec.remove_sp(ME, PEER, 4790).await.unwrap());
        assert_eq!(
            mock.stdins(),
            ["spddelete 10.2.2.47[any] 10.2.1.50[4790] udp -P out ;\n"]
        );
    }

    #[tokio::test]
    async fn a_parse_error_carries_the_command_and_the_raw_output() {
        let mock = MockRunner::new();
        mock.push_output(0, "this is not a SAD dump\n", "");
        let ipsec = Ipsec::with_runner(&mock);
        let err = ipsec.sas().await.unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, IpsecError::UnexpectedOutput { .. }),
            "{err:?}"
        );
        assert!(text.contains("/sbin/setkey -D"), "{text}");
        assert!(text.contains("this is not a SAD dump"), "{text}");
    }

    #[tokio::test]
    async fn a_failed_batch_carries_the_command_status_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SAD entries.\n", "");
        mock.push_output(1, "", "setkey: syntax error at line 1\n");
        let ipsec = Ipsec::with_runner(&mock);
        let err = ipsec
            .ensure_sa(ME, PEER, 0x0e99_9001, &KEY, Direction::Out)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, IpsecError::Failed { .. }), "{err:?}");
        assert!(text.contains("/sbin/setkey -c"), "{text}");
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("syntax error"), "{text}");
    }

    // ---- the reconciler -------------------------------------------------------

    #[test]
    fn a_fresh_converge_adds_every_inbound_sa_the_primary_outbound_sa_and_the_sp() {
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(1, &[2]),
        }];
        let plan = plan_security(ME, &desired, &PresentSecurity::default());
        // 3 SA adds (inbound for tags 1 and 2, outbound for the primary 1),
        // then the SP add. No removes.
        assert_eq!(plan.ops.len(), 4);
        assert!(
            plan.ops[..3]
                .iter()
                .all(|op| matches!(op, SecurityOp::AddSa { .. }))
        );
        assert!(matches!(&plan.ops[3], SecurityOp::AddSp(sp) if *sp == desired_sp(ME, PEER, 4790)));
        // The only outbound SA is the primary's.
        let outbound: Vec<_> = plan
            .ops
            .iter()
            .filter_map(|op| match op {
                SecurityOp::AddSa { sa, .. } if sa.src == ME => Some(*sa),
                _ => None,
            })
            .collect();
        assert_eq!(outbound, [sa(ME, PEER, outbound_spi(ME, 1, PEER))]);
        // Every key is accepted inbound.
        for tag in [1, 2] {
            let want = sa(PEER, ME, inbound_spi(ME, tag, PEER));
            assert!(
                plan.ops
                    .iter()
                    .any(|op| matches!(op, SecurityOp::AddSa { sa, .. } if *sa == want)),
                "missing inbound SA for tag {tag}"
            );
        }
        // Converging again against the applied state is a no-op.
        assert!(plan_security(ME, &desired, &applied(&plan)).is_empty());
    }

    #[test]
    fn a_promote_pass_adds_the_new_outbound_sa_and_deletes_the_old_in_one_pass() {
        // Ring before rotation: primary tag 1. The append phase already ran:
        // the new inbound SA (tag 2) is in the SAD. Now the ring promotes
        // tag 2 to primary while still accepting tag 1.
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(2, &[1]),
        }];
        let present = PresentSecurity {
            sas: vec![
                sa(ME, PEER, outbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 2, PEER)),
            ],
            sps: vec![desired_sp(ME, PEER, 4790)],
        };
        let plan = plan_security(ME, &desired, &present);
        // The add comes first: the new outbound SA exists before the old one
        // is deleted, and the delete is what makes the kernel switch SPIs
        // (hack/experiments/esp/README.md section 6).
        assert_eq!(
            plan.ops,
            [
                SecurityOp::AddSa {
                    sa: sa(ME, PEER, outbound_spi(ME, 2, PEER)),
                    key: test_key(2),
                },
                SecurityOp::RemoveSa(sa(ME, PEER, outbound_spi(ME, 1, PEER))),
            ]
        );
    }

    #[test]
    fn a_prune_pass_deletes_only_the_pruned_inbound_sa() {
        // Rotation finished: the ring is down to primary tag 2. The kernel
        // still holds the old inbound SA for tag 1.
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(2, &[]),
        }];
        let present = PresentSecurity {
            sas: vec![
                sa(ME, PEER, outbound_spi(ME, 2, PEER)),
                sa(PEER, ME, inbound_spi(ME, 2, PEER)),
                sa(PEER, ME, inbound_spi(ME, 1, PEER)),
            ],
            sps: vec![desired_sp(ME, PEER, 4790)],
        };
        let plan = plan_security(ME, &desired, &present);
        assert_eq!(
            plan.ops,
            [SecurityOp::RemoveSa(sa(PEER, ME, inbound_spi(ME, 1, PEER)))]
        );
    }

    #[test]
    fn an_empty_assignment_set_yields_a_full_teardown_plan() {
        let present = PresentSecurity {
            sas: vec![
                sa(ME, PEER, outbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 1, PEER)),
            ],
            sps: vec![desired_sp(ME, PEER, 4790)],
        };
        let plan = plan_security(ME, &[], &present);
        assert_eq!(plan.ops.len(), 3);
        // The SP goes first (no new packets are matched to IPsec), then the
        // SAs.
        assert!(
            matches!(&plan.ops[0], SecurityOp::RemoveSp(sp) if *sp == desired_sp(ME, PEER, 4790))
        );
        assert!(
            plan.ops[1..]
                .iter()
                .all(|op| matches!(op, SecurityOp::RemoveSa(_)))
        );
    }

    #[test]
    fn a_matching_state_yields_an_empty_plan() {
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(1, &[2]),
        }];
        let present = PresentSecurity {
            sas: vec![
                sa(ME, PEER, outbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 2, PEER)),
            ],
            sps: vec![desired_sp(ME, PEER, 4790)],
        };
        assert!(plan_security(ME, &desired, &present).is_empty());
    }

    #[test]
    fn two_encrypted_networks_sharing_a_peer_have_independent_security() {
        let third = Ipv4Addr::new(10, 2, 3, 60);
        let desired = [
            PeerSecurity {
                peer: PEER,
                port: 4790,
                keys: keyring(1, &[]),
            },
            PeerSecurity {
                peer: PEER,
                port: 4791,
                keys: keyring(7, &[]),
            },
            PeerSecurity {
                peer: third,
                port: 4790,
                keys: keyring(1, &[]),
            },
        ];
        let plan = plan_security(ME, &desired, &PresentSecurity::default());
        // Three distinct SPs — (PEER, 4790), (PEER, 4791), (third, 4790) —
        // and six distinct SAs: the shared peer gets independent SPIs via the
        // per-network tags, and the same tag towards two peers differs too.
        let sas: BTreeSet<_> = plan
            .ops
            .iter()
            .filter_map(|op| match op {
                SecurityOp::AddSa { sa, .. } => Some(*sa),
                _ => None,
            })
            .collect();
        assert_eq!(sas.len(), 6);
        let sps: BTreeSet<_> = plan
            .ops
            .iter()
            .filter_map(|op| match op {
                SecurityOp::AddSp(sp) => Some(sp.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(sps.len(), 3);
        // Tearing down the (PEER, 4791) network touches exactly its own SP
        // and two SAs, leaving the other network on the same peer intact.
        let remaining = [desired[0].clone(), desired[2].clone()];
        let teardown = plan_security(ME, &remaining, &applied(&plan));
        assert_eq!(
            teardown.ops,
            [
                SecurityOp::RemoveSp(desired_sp(ME, PEER, 4791)),
                SecurityOp::RemoveSa(sa(PEER, ME, inbound_spi(ME, 7, PEER))),
                SecurityOp::RemoveSa(sa(ME, PEER, outbound_spi(ME, 7, PEER))),
            ]
        );
    }

    #[test]
    fn the_plan_renders_as_one_setkey_script_in_apply_order() {
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(2, &[1]),
        }];
        let present = PresentSecurity {
            sas: vec![
                sa(ME, PEER, outbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 1, PEER)),
                sa(PEER, ME, inbound_spi(ME, 2, PEER)),
            ],
            sps: vec![desired_sp(ME, PEER, 4790)],
        };
        let script = plan_security(ME, &desired, &present).script();
        let add_pos = script.find("add 10.2.2.47 10.2.1.50").unwrap();
        let delete_pos = script.find("delete 10.2.2.47 10.2.1.50").unwrap();
        assert!(add_pos < delete_pos, "adds before deletes:\n{script}");
    }

    // ---- applying a whole plan -------------------------------------------------

    #[tokio::test]
    async fn apply_sends_the_whole_plan_as_one_setkey_batch() {
        let mock = MockRunner::new();
        mock.push_ok();
        let ipsec = Ipsec::with_runner(&mock);
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: keyring(2, &[1]),
        }];
        let plan = plan_security(ME, &desired, &PresentSecurity::default());
        ipsec.apply(&plan).await.unwrap();
        // One `setkey -c` invocation, never one per operation: the batch is
        // the rotation protocol's atomicity unit.
        assert_eq!(mock.calls(), ["/sbin/setkey -c"]);
        assert_eq!(mock.stdins(), [plan.script()]);
    }

    #[tokio::test]
    async fn apply_of_an_empty_plan_runs_nothing() {
        let mock = MockRunner::new();
        let ipsec = Ipsec::with_runner(&mock);
        ipsec.apply(&SecurityPlan::default()).await.unwrap();
        assert!(mock.calls().is_empty());
    }

    // ---- key material never reaches logs, Debug or errors ---------------------

    #[test]
    fn redact_script_keys_hides_only_the_key_field() {
        let script = script_add_sa(&sa(ME, PEER, 0x0e99_9001), &KEY)
            + "\n"
            + &script_delete_sa(&sa(ME, PEER, 0x0e99_9002))
            + "\n"
            + &script_add_sp(&desired_sp(ME, PEER, 4790))
            + "\n";
        // SPIs, addresses and ports stay visible (operators grep for them);
        // only the key field is redacted.
        assert_eq!(
            redact_script_keys(&script),
            "add 10.2.2.47 10.2.1.50 esp 0xe999001 -m transport -E aes-gcm-16 \
             0x<redacted> ;\n\
             delete 10.2.2.47 10.2.1.50 esp 0xe999002 ;\n\
             spdadd 10.2.2.47[any] 10.2.1.50[4790] udp -P out ipsec \
             esp/transport/10.2.2.47-10.2.1.50/require ;\n"
        );
    }

    /// The redactor cannot assume the tidy single spacing of SatL's own
    /// scripts: `setkey` may echo an offending line back on stderr with its
    /// own spacing, and a token split on exactly one space would then miss
    /// the key field and leak it into the error text.
    #[test]
    fn redact_script_keys_tolerates_sloppy_whitespace() {
        let echoed = "setkey: syntax error: add 10.2.2.47  10.2.1.50 esp 0xe999001 \
                      -m transport -E  aes-gcm-16   0x00112233445566778899aabbccddeeff0e999001 ;";
        let redacted = redact_script_keys(echoed);
        assert!(
            !redacted.contains("00112233445566778899aabbccddeeff"),
            "{redacted}"
        );
        assert!(redacted.contains("0x<redacted>"), "{redacted}");
    }

    #[test]
    fn a_plan_debug_never_contains_key_material() {
        let desired = [PeerSecurity {
            peer: PEER,
            port: 4790,
            keys: vec![NetworkKey {
                tag: 1,
                key: KEY,
                primary: true,
            }],
        }];
        let plan = plan_security(ME, &desired, &PresentSecurity::default());
        let debug = format!("{plan:?}");
        // The raw AES key must not appear...
        assert!(
            !debug.contains("00112233445566778899aabbccddeeff"),
            "{debug}"
        );
        // ...while the redaction marker (same shape as NetworkKey's Debug)
        // and the diagnosis-relevant fields do.
        assert!(debug.contains("<redacted, 16 bytes>"), "{debug}");
        assert!(debug.contains("10.2.2.47"), "{debug}");
        assert!(
            debug.contains(&format!("{:?}", outbound_spi(ME, 1, PEER))),
            "{debug}"
        );
    }

    #[tokio::test]
    async fn a_failed_batch_error_never_contains_key_material() {
        let mock = MockRunner::new();
        mock.push_output(0, "No SAD entries.\n", "");
        // Defensive: if setkey ever echoes the offending script line back on
        // stderr, the key field must still not reach the error.
        mock.push_output(
            1,
            "",
            "setkey: syntax error: add 10.2.2.47 10.2.1.50 esp 0xe999001 -m transport \
             -E aes-gcm-16 0x00112233445566778899aabbccddeeff0e999001\n",
        );
        let ipsec = Ipsec::with_runner(&mock);
        let err = ipsec
            .ensure_sa(ME, PEER, 0x0e99_9001, &KEY, Direction::Out)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("00112233445566778899aabbccddeeff"), "{text}");
        assert!(text.contains("0x<redacted>"), "{text}");
    }
}
