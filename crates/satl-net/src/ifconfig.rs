// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `ifconfig`(8) — bridge/epair lifecycle, groups,
//! descriptions, addressing, and VNET jail plumbing.
//!
//! Every idiom below was verified live on FreeBSD 15.1 (2026-08-09); the
//! captured outputs live in `tests/fixtures/ifconfig_*.txt`:
//!
//! - `ifconfig bridge create name <n>` creates and renames in one command
//!   and prints the final name on stdout. **Gotcha**: when `<n>` is already
//!   taken the kernel has still created an auto-named `bridgeN` (printed on
//!   stdout) before the rename fails with `ioctl SIOCSIFNAME (set name):
//!   File exists` — [`Ifconfig::create_bridge`] destroys that leaked
//!   interface before returning the error.
//! - `ifconfig epair create` prints the `a` end (`epairNa`); the `b` end is
//!   the same name with the trailing `a` swapped for `b`.
//! - `ifconfig <epair>b vnet <jail>` moves the `b` end into a VNET jail
//!   (accepts jail name or numeric jid). The interface keeps its
//!   *description* across the move and across the automatic return to the
//!   host when the jail dies, but **loses its interface group** — orphan
//!   reconciliation must therefore identify returned `b` ends by
//!   description, not group (see `crate::manager`).
//! - `ifconfig -j <jail> ...` configures interfaces inside a jail from the
//!   host (addresses, `up`, listing).
//! - `ifconfig -g <group>` prints group members one per line; unknown or
//!   empty groups print nothing and exit 0.
//! - A missing interface fails with exit code 1 and
//!   `ifconfig: interface <name> does not exist` on stderr, which
//!   [`Ifconfig::exists`] / [`Ifconfig::destroy_if_exists`] map to `false`.
//!
//! ## Read-back, not exit codes (M3)
//!
//! `ifconfig` reports success for interfaces the kernel refused to bring to
//! life (`docs/vxlan.md` §2 point 5: `UP`, `status: active`, exit 0, and no
//! `RUNNING`). Everything the overlay depends on — MTU, MAC, membership,
//! addresses — is therefore *read back* through [`Ifconfig::state`] /
//! [`Ifconfig::jail_state`] and compared, never assumed from an exit status.
//!
//! Two further facts, measured on this host on 2026-08-10 (fixtures
//! `ifconfig_show_*`, `ifconfig_*_stderr.txt`):
//!
//! - **A bridge member's MTU cannot be set at all.**
//!   `ifconfig epair4a mtu 1450` on a member of a 1450-MTU bridge fails with
//!   `ioctl SIOCSIFMTU (set mtu): Operation not supported` — the same value,
//!   the same bridge. The MTU of a member is the bridge's, and `addm` rewrites
//!   it (an epair created at 1500 becomes 1450 the moment it joins, and one
//!   created at 1400 is raised to 1450). So an epair's own MTU must be set
//!   **before** `addm`, and afterwards only [`Ifconfig::set_mtu`] on the
//!   *bridge* moves it. [`IfconfigError::MtuLockedByBridge`] says so.
//! - **`addm`/`deletem` have idiomatic already-done errors**
//!   (`BRDGADD <if>: File exists (Interface is already a member of this
//!   bridge)`, `BRDGDEL <if>: No such file or directory (Interface is not a
//!   bridge member)`), which [`Ifconfig::bridge_addm_if_absent`] and
//!   [`Ifconfig::bridge_deletem_if_member`] turn into `Ok(false)` — idempotency
//!   without a probe-then-act race.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use satl_core::MacAddr;

use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `ifconfig` binary on FreeBSD.
pub const DEFAULT_IFCONFIG_BINARY: &str = "/sbin/ifconfig";

/// Longest interface name the kernel accepts: `IFNAMSIZ - 1`. A 16-character
/// `ifconfig <clone> name` fails with
/// `ioctl SIOCSIFNAME (set name): File name too long`.
pub const MAX_IFACE_NAME_LEN: usize = 15;

/// Everything one `ifconfig <iface>` show reports, parsed.
///
/// This is the read-back type: the overlay's correctness lives in the MTU, the
/// MAC and the bridge membership, and none of the three can be trusted from an
/// exit status (module docs). Fields are what the fixtures under
/// `tests/fixtures/ifconfig_show_*.txt` actually contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceState {
    /// Interface name as printed.
    pub name: String,
    /// The flag word, printed by `ifconfig` in hex without a `0x` prefix.
    pub flags_raw: u32,
    /// Flag names from inside the angle brackets, in order.
    pub flags: Vec<String>,
    /// MTU, from the same header line.
    pub mtu: u32,
    /// Interface description — SatL's ownership marker.
    pub descr: Option<String>,
    /// Current link-layer address (the `ether` line, not `hwaddr`).
    pub ether: Option<MacAddr>,
    /// Assigned IPv4 addresses.
    pub inet: Vec<Ipv4Addr>,
    /// Bridge members, when this interface is a bridge.
    pub members: Vec<String>,
    /// Interface groups this interface belongs to.
    pub groups: Vec<String>,
}

impl IfaceState {
    /// `IFF_UP` — administratively up. **Not** a health signal on its own: a
    /// vxlan interface the driver refused reports `UP` too
    /// (`docs/vxlan.md` §2 point 5).
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.has_flag("UP")
    }

    /// `IFF_DRV_RUNNING` — the driver initialized the interface. The only
    /// health signal `ifconfig` gives.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.has_flag("RUNNING")
    }

    /// Whether the flag word contains `flag` by name.
    #[must_use]
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|name| name == flag)
    }

    /// Whether `iface` is a member of this bridge.
    #[must_use]
    pub fn has_member(&self, iface: &str) -> bool {
        self.members.iter().any(|member| member == iface)
    }

    /// Whether this interface is in interface group `group`.
    #[must_use]
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|name| name == group)
    }

    /// The flag word rendered the way `ifconfig` prints it, for error messages
    /// an operator will compare against `docs/vxlan.md` §2.
    #[must_use]
    pub fn rendered_flags(&self) -> String {
        format!("{:x}<{}>", self.flags_raw, self.flags.join(","))
    }
}

/// The two ends of a freshly created epair(4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpairPair {
    /// Host-facing end (stays on the host, member of the bridge).
    pub a: String,
    /// Jail-facing end (moved into the task's VNET jail).
    pub b: String,
}

/// Error from an `ifconfig`(8) invocation. Every variant names the interface
/// (and jail, where relevant) and carries the full argv + exit status +
/// stderr of the failed command.
#[derive(Debug, thiserror::Error)]
pub enum IfconfigError {
    /// The `ifconfig` binary could not be spawned.
    #[error("ifconfig ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted, naming the interface/jail involved.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("ifconfig ({context}): {failure}")]
    Failed {
        /// What was being attempted, naming the interface/jail involved.
        context: String,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },

    /// The command succeeded but its output did not have the expected shape.
    #[error(
        "ifconfig ({context}): unexpected output from `{argv}`: {reason}; \
         raw stdout: {stdout:?}; raw stderr: {stderr:?}"
    )]
    UnexpectedOutput {
        /// What was being attempted, naming the interface/jail involved.
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

    /// `create_bridge` raced or repeated: the name is already in use. The
    /// auto-named interface the kernel leaked before the rename failed has
    /// been destroyed (unless `leak_cleaned` is false — then it is still
    /// present and named in `leaked`).
    #[error(
        "ifconfig (create bridge '{bridge}'): name already in use; kernel leaked '{leaked}' \
         (cleaned up: {leak_cleaned}); {failure}"
    )]
    BridgeNameInUse {
        /// The requested bridge name.
        bridge: String,
        /// The auto-named interface created before the rename failed.
        leaked: String,
        /// Whether the leaked interface was successfully destroyed.
        leak_cleaned: bool,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },

    /// `SIOCSIFMTU` was refused with `Operation not supported`, which on
    /// FreeBSD 15.1 means the interface is a **bridge member**: a member's MTU
    /// is the bridge's and cannot be set on the member at all — not even to the
    /// value it already has (measured; see the module docs).
    #[error(
        "ifconfig (set mtu {mtu} on '{iface}'): the kernel refused with \
         `Operation not supported`, which means '{iface}' is a bridge member; \
         a member's MTU is its bridge's and can only be changed by setting the \
         MTU on the bridge (which propagates to every member). Set an \
         interface's MTU before `addm`. {failure}"
    )]
    MtuLockedByBridge {
        /// The interface whose MTU was refused.
        iface: String,
        /// The MTU that was attempted.
        mtu: u32,
        /// The failed command with argv, exit status, and stderr.
        failure: Failure,
    },
}

// ---------------------------------------------------------------------------
// Pure argv builders — unit-tested without executing anything.
// ---------------------------------------------------------------------------

fn to_args<const N: usize>(parts: [&str; N]) -> Vec<String> {
    parts.into_iter().map(str::to_owned).collect()
}

fn args_create_bridge(name: &str) -> Vec<String> {
    to_args(["bridge", "create", "name", name])
}

fn args_create_epair() -> Vec<String> {
    to_args(["epair", "create"])
}

fn args_destroy(iface: &str) -> Vec<String> {
    to_args([iface, "destroy"])
}

fn args_show(iface: &str) -> Vec<String> {
    to_args([iface])
}

fn args_bridge_addm(bridge: &str, member: &str) -> Vec<String> {
    to_args([bridge, "addm", member])
}

fn args_bridge_deletem(bridge: &str, member: &str) -> Vec<String> {
    to_args([bridge, "deletem", member])
}

fn args_set_group(iface: &str, group: &str) -> Vec<String> {
    to_args([iface, "group", group])
}

fn args_list_group(group: &str) -> Vec<String> {
    to_args(["-g", group])
}

fn args_set_descr(iface: &str, text: &str) -> Vec<String> {
    to_args([iface, "description", text])
}

fn args_add_inet(iface: &str, cidr: &str) -> Vec<String> {
    to_args([iface, "inet", cidr])
}

fn args_remove_inet(iface: &str, addr: &str) -> Vec<String> {
    to_args([iface, "inet", addr, "-alias"])
}

fn args_set_ether(iface: &str, mac: &str) -> Vec<String> {
    to_args([iface, "ether", mac])
}

fn args_up(iface: &str) -> Vec<String> {
    to_args([iface, "up"])
}

fn args_set_mtu(iface: &str, mtu: u32) -> Vec<String> {
    vec![iface.to_owned(), "mtu".to_owned(), mtu.to_string()]
}

fn args_disable_txcsum(iface: &str) -> Vec<String> {
    to_args([iface, "-txcsum"])
}

fn args_move_to_jail(iface: &str, jail: &str) -> Vec<String> {
    to_args([iface, "vnet", jail])
}

fn args_jail_add_inet(jail: &str, iface: &str, cidr: &str) -> Vec<String> {
    to_args(["-j", jail, iface, "inet", cidr])
}

fn args_jail_up(jail: &str, iface: &str) -> Vec<String> {
    to_args(["-j", jail, iface, "up"])
}

fn args_jail_show(jail: &str, iface: &str) -> Vec<String> {
    to_args(["-j", jail, iface])
}

fn args_jail_set_mtu(jail: &str, iface: &str, mtu: u32) -> Vec<String> {
    vec![
        "-j".to_owned(),
        jail.to_owned(),
        iface.to_owned(),
        "mtu".to_owned(),
        mtu.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Pure output parsers — unit-tested against fixtures of real output.
// ---------------------------------------------------------------------------

/// `ifconfig <name>` (and `<name> destroy`) print
/// `ifconfig: interface <name> does not exist` on stderr, exit code 1.
fn stderr_says_iface_missing(stderr: &str) -> bool {
    stderr.contains("does not exist")
}

/// `ifconfig bridge create name <taken>` fails the rename with
/// `ifconfig: ioctl SIOCSIFNAME (set name): File exists` on stderr after the
/// kernel already created an auto-named interface (printed on stdout).
fn stderr_says_name_in_use(stderr: &str) -> bool {
    stderr.contains("SIOCSIFNAME") && stderr.contains("File exists")
}

/// `ifconfig <bridge> addm <member>` on an existing member:
/// `BRDGADD epair4a: File exists (Interface is already a member of this bridge)`.
fn stderr_says_already_member(stderr: &str) -> bool {
    stderr.contains("BRDGADD") && stderr.contains("already a member")
}

/// `ifconfig <bridge> deletem <member>` on a non-member:
/// `BRDGDEL ice1: No such file or directory (Interface is not a bridge member)`.
fn stderr_says_not_a_member(stderr: &str) -> bool {
    stderr.contains("BRDGDEL") && stderr.contains("not a bridge member")
}

/// `ifconfig <iface> mtu <n>` on a bridge member:
/// `ioctl SIOCSIFMTU (set mtu): Operation not supported`.
fn stderr_says_mtu_unsupported(stderr: &str) -> bool {
    stderr.contains("SIOCSIFMTU") && stderr.contains("Operation not supported")
}

/// `ifconfig <iface> inet <addr> -alias` for an address the interface does not
/// carry: `ioctl (SIOCDIFADDR): Can't assign requested address`.
fn stderr_says_address_absent(stderr: &str) -> bool {
    stderr.contains("SIOCDIFADDR")
}

/// Parse `ifconfig epair create` output: a single line naming the `a` end.
fn parse_epair_create(stdout: &str) -> Result<EpairPair, String> {
    let mut lines = stdout.lines();
    let Some(a) = lines.next() else {
        return Err("expected the new epair name on stdout, got nothing".to_owned());
    };
    if lines.next().is_some() {
        return Err("expected exactly one line of output, got more".to_owned());
    }
    let Some(stem) = a.strip_suffix('a') else {
        return Err(format!("expected a name ending in 'a', got {a:?}"));
    };
    if !stem.starts_with("epair") {
        return Err(format!("expected an 'epairNa' name, got {a:?}"));
    }
    Ok(EpairPair {
        a: a.to_owned(),
        b: format!("{stem}b"),
    })
}

/// Parse `ifconfig -g <group>` output: one interface name per line; an
/// unknown or empty group prints nothing (exit 0 either way).
fn parse_group_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Extract the `description:` value from `ifconfig <iface>` show output.
/// The line format is `\tdescription: <text>`; absent when never set.
fn parse_description(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("description: "))
        .map(str::to_owned)
}

/// Extract the IPv4 addresses from `ifconfig <iface>` show output. The line
/// format is `\tinet <addr> netmask 0x... [broadcast ...]`.
fn parse_inet_addresses(stdout: &str) -> Vec<Ipv4Addr> {
    stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("inet "))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|addr| addr.parse().ok())
        .collect()
}

/// The link-layer address from the `\tether <mac>` line.
///
/// An epair end whose MAC SatL set carries **both** `ether` (the current,
/// derived address) and `hwaddr` (the kernel's original) — the derived one is
/// what the overlay's FDB and ARP entries are computed against, so only `ether`
/// is read here.
fn parse_ether(stdout: &str) -> Option<MacAddr> {
    stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("ether "))
        .find_map(|rest| rest.split_whitespace().next()?.parse().ok())
}

/// Bridge member names from the `\tmember: <iface> flags=...` lines.
fn parse_bridge_members(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("member: "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// Interface group names from the `\tgroups: <a> <b>` line.
fn parse_groups(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("groups: "))
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect()
}

/// Whether `ifconfig <iface>` show output carries `TXCSUM` in its interface
/// options line (`\toptions=680003<RXCSUM,TXCSUM,LINKSTATE,...>`).
///
/// The match is against the exact token: `TXCSUM_IPV6` is a different
/// capability and must not count (SatL assigns no IPv6, and the measured
/// fix left it untouched). The `nd6 options=...` line does not match
/// because its trimmed line starts with `nd6`, not `options=`.
fn options_have_txcsum(stdout: &str) -> bool {
    stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("options="))
        .filter_map(|rest| rest.trim_end_matches('>').split_once('<'))
        .flat_map(|(_, names)| names.split(','))
        .any(|name| name == "TXCSUM")
}

/// The `u32` following `key` on a whitespace-separated line.
fn parse_trailing_u32(line: &str, key: &str) -> Option<u32> {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == key {
            return words.next()?.parse().ok();
        }
    }
    None
}

/// Parse the whole of `ifconfig <iface>` show output.
///
/// The header line is
/// `satl-br42: flags=1008843<UP,BROADCAST,RUNNING,...> metric 0 mtu 1450`; the
/// flag word is **hexadecimal without a `0x` prefix** and the names inside the
/// brackets are the authority (`RUNNING` = `IFF_DRV_RUNNING`, the only health
/// signal `ifconfig` gives — `docs/vxlan.md` §2 point 5).
pub(crate) fn parse_iface_state(stdout: &str) -> Result<IfaceState, String> {
    let header = stdout
        .lines()
        .next()
        .ok_or_else(|| "expected at least one line of `ifconfig` output".to_owned())?;
    let (name, rest) = header
        .split_once(": ")
        .ok_or_else(|| format!("expected '<iface>: flags=...', got {header:?}"))?;
    let flags = rest
        .split_whitespace()
        .find_map(|word| word.strip_prefix("flags="))
        .ok_or_else(|| format!("no flags= field in {header:?}"))?;
    let (raw, names) = flags
        .trim_end_matches('>')
        .split_once('<')
        .ok_or_else(|| format!("expected 'flags=<hex><NAMES>' in {header:?}"))?;
    let flags_raw = u32::from_str_radix(raw, 16)
        .map_err(|e| format!("flag word {raw:?} is not hexadecimal: {e}"))?;
    let mtu =
        parse_trailing_u32(header, "mtu").ok_or_else(|| format!("no mtu field in {header:?}"))?;
    Ok(IfaceState {
        name: name.to_owned(),
        flags_raw,
        flags: names
            .split(',')
            .filter(|flag| !flag.is_empty())
            .map(str::to_owned)
            .collect(),
        mtu,
        descr: parse_description(stdout),
        ether: parse_ether(stdout),
        inet: parse_inet_addresses(stdout),
        members: parse_bridge_members(stdout),
        groups: parse_groups(stdout),
    })
}

// ---------------------------------------------------------------------------
// The wrapper itself.
// ---------------------------------------------------------------------------

/// Typed async wrapper around the `ifconfig`(8) binary.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock executor;
/// production code uses [`Ifconfig::system`].
#[derive(Debug, Clone)]
pub struct Ifconfig<R = SystemRunner> {
    binary: PathBuf,
    runner: R,
}

impl Ifconfig<SystemRunner> {
    /// Wrapper that executes the real binary at [`DEFAULT_IFCONFIG_BINARY`].
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Ifconfig<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Ifconfig<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            binary: PathBuf::from(DEFAULT_IFCONFIG_BINARY),
            runner,
        }
    }

    /// Override the path of the `ifconfig` binary.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Run `ifconfig` with `args`; returns the rendered argv and captured
    /// output. Only spawn failures are errors here — callers interpret exit
    /// codes.
    async fn exec(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), IfconfigError> {
        let rendered = render_argv(&self.binary, &args);
        tracing::debug!(command = %rendered, "running ifconfig");
        let output = self
            .runner
            .run(&self.binary, &args, None)
            .await
            .map_err(|source| IfconfigError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    fn fail(context: &str, argv: String, output: &CommandOutput) -> IfconfigError {
        IfconfigError::Failed {
            context: context.to_owned(),
            failure: Failure::new(argv, output),
        }
    }

    /// Create a bridge(4) named `name` in one command:
    /// `ifconfig bridge create name <name>`.
    ///
    /// On a name collision the kernel has already created an auto-named
    /// `bridgeN` before the rename fails; that leak is destroyed here and
    /// the call returns [`IfconfigError::BridgeNameInUse`].
    pub async fn create_bridge(&self, name: &str) -> Result<(), IfconfigError> {
        let context = format!("create bridge '{name}'");
        let (argv, output) = self.exec(&context, args_create_bridge(name)).await?;
        if output.success() {
            tracing::info!(bridge = %name, "created bridge");
            return Ok(());
        }
        if stderr_says_name_in_use(&output.stderr) {
            // The kernel prints the leaked auto-assigned name on stdout.
            let leaked = output.stdout.trim().to_owned();
            let mut leak_cleaned = false;
            if !leaked.is_empty() {
                leak_cleaned = self.destroy_if_exists(&leaked).await.is_ok();
                tracing::warn!(
                    bridge = %name,
                    leaked = %leaked,
                    leak_cleaned,
                    "bridge name collision leaked an auto-named interface"
                );
            }
            return Err(IfconfigError::BridgeNameInUse {
                bridge: name.to_owned(),
                leaked,
                leak_cleaned,
                failure: Failure::new(argv, &output),
            });
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Create an epair(4): `ifconfig epair create`. The kernel prints the
    /// `a` end; the `b` end is derived by suffix swap (verified idiom).
    pub async fn create_epair(&self) -> Result<EpairPair, IfconfigError> {
        let context = "create epair";
        let (argv, output) = self.exec(context, args_create_epair()).await?;
        if !output.success() {
            return Err(Self::fail(context, argv, &output));
        }
        let pair = parse_epair_create(&output.stdout).map_err(|reason| {
            IfconfigError::UnexpectedOutput {
                context: context.to_owned(),
                argv,
                reason,
                stdout: output.stdout.clone(),
                stderr: output.stderr.clone(),
            }
        })?;
        tracing::info!(epair_a = %pair.a, epair_b = %pair.b, "created epair");
        Ok(pair)
    }

    /// Destroy an interface: `ifconfig <iface> destroy`. Destroying either
    /// end of an epair destroys the pair (even when the other end sits in a
    /// jail — verified live).
    pub async fn destroy(&self, iface: &str) -> Result<(), IfconfigError> {
        let context = format!("destroy interface '{iface}'");
        let (argv, output) = self.exec(&context, args_destroy(iface)).await?;
        if output.success() {
            tracing::info!(iface = %iface, "destroyed interface");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Destroy `iface` if it exists; `Ok(false)` when it was already gone
    /// (idempotent teardown building block).
    pub async fn destroy_if_exists(&self, iface: &str) -> Result<bool, IfconfigError> {
        let context = format!("destroy interface '{iface}' (if it exists)");
        let (argv, output) = self.exec(&context, args_destroy(iface)).await?;
        if output.success() {
            tracing::info!(iface = %iface, "destroyed interface");
            return Ok(true);
        }
        if output.exit_code == Some(1) && stderr_says_iface_missing(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Whether `iface` exists: `ifconfig <iface>`; exit 1 with a
    /// "does not exist" diagnostic maps to `Ok(false)`.
    pub async fn exists(&self, iface: &str) -> Result<bool, IfconfigError> {
        let context = format!("probe interface '{iface}'");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if output.success() {
            return Ok(true);
        }
        if output.exit_code == Some(1) && stderr_says_iface_missing(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Add `member` to `bridge`: `ifconfig <bridge> addm <member>`.
    pub async fn bridge_addm(&self, bridge: &str, member: &str) -> Result<(), IfconfigError> {
        let context = format!("add member '{member}' to bridge '{bridge}'");
        let (argv, output) = self
            .exec(&context, args_bridge_addm(bridge, member))
            .await?;
        if output.success() {
            tracing::debug!(bridge = %bridge, member = %member, "added bridge member");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Add `member` to `bridge`, tolerating an existing membership:
    /// `Ok(true)` when it was added, `Ok(false)` when it already was a member.
    ///
    /// Idempotent without a probe-then-act race: the kernel's
    /// `BRDGADD <if>: File exists (Interface is already a member of this
    /// bridge)` is the answer, not a failure.
    pub async fn bridge_addm_if_absent(
        &self,
        bridge: &str,
        member: &str,
    ) -> Result<bool, IfconfigError> {
        let context = format!("add member '{member}' to bridge '{bridge}' (if absent)");
        let (argv, output) = self
            .exec(&context, args_bridge_addm(bridge, member))
            .await?;
        if output.success() {
            tracing::info!(bridge = %bridge, member = %member, "added bridge member");
            return Ok(true);
        }
        if stderr_says_already_member(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Remove `member` from `bridge`: `ifconfig <bridge> deletem <member>`.
    /// `Ok(false)` when it was not a member (idempotent teardown).
    ///
    /// Destroying a bridge already un-bridges its members without destroying
    /// them (verified live) — this exists so a teardown can *say* it detached
    /// an interface it does not own, in particular the overlay's VTEP.
    pub async fn bridge_deletem_if_member(
        &self,
        bridge: &str,
        member: &str,
    ) -> Result<bool, IfconfigError> {
        let context = format!("remove member '{member}' from bridge '{bridge}' (if a member)");
        let (argv, output) = self
            .exec(&context, args_bridge_deletem(bridge, member))
            .await?;
        if output.success() {
            tracing::info!(bridge = %bridge, member = %member, "removed bridge member");
            return Ok(true);
        }
        if stderr_says_not_a_member(&output.stderr) || stderr_says_iface_missing(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Add `iface` to interface group `group`: `ifconfig <iface> group <g>`.
    ///
    /// Group membership does **not** survive a `vnet` move — a `b` end that
    /// auto-returned from a dead jail is no longer in the group (verified
    /// live; identify it by description instead).
    ///
    /// FreeBSD rejects group names ending in a digit (`ifconfig:
    /// setifgroup: group names may not end in a digit`, verified live) —
    /// the kernel reserves the trailing-digit namespace for per-interface
    /// groups like `epair`. SatL's production group `satl` is fine.
    pub async fn set_group(&self, iface: &str, group: &str) -> Result<(), IfconfigError> {
        let context = format!("add interface '{iface}' to group '{group}'");
        let (argv, output) = self.exec(&context, args_set_group(iface, group)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// List the members of interface group `group`: `ifconfig -g <group>`.
    /// Unknown or empty groups yield an empty list.
    pub async fn list_group(&self, group: &str) -> Result<Vec<String>, IfconfigError> {
        let context = format!("list interface group '{group}'");
        let (argv, output) = self.exec(&context, args_list_group(group)).await?;
        if output.success() {
            return Ok(parse_group_list(&output.stdout));
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the description of `iface`: `ifconfig <iface> description <text>`.
    ///
    /// Descriptions survive `vnet` moves and the automatic return to the
    /// host when a jail dies (verified live) — this is SatL's ownership
    /// marker (`satl:<task-id>` convention, architecture §11.1).
    pub async fn set_descr(&self, iface: &str, text: &str) -> Result<(), IfconfigError> {
        let context = format!("set description on interface '{iface}'");
        let (argv, output) = self.exec(&context, args_set_descr(iface, text)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Read the description of `iface` from `ifconfig <iface>` show output;
    /// `Ok(None)` when no description is set.
    pub async fn get_descr(&self, iface: &str) -> Result<Option<String>, IfconfigError> {
        let context = format!("read description of interface '{iface}'");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if output.success() {
            return Ok(parse_description(&output.stdout));
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Read everything `ifconfig <iface>` reports: flags (`UP`/`RUNNING`),
    /// MTU, description, MAC, addresses, bridge members, groups.
    ///
    /// The read-back primitive. Every overlay invariant is verified through
    /// this rather than trusted from an exit status (module docs).
    pub async fn state(&self, iface: &str) -> Result<IfaceState, IfconfigError> {
        let context = format!("read state of interface '{iface}'");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if !output.success() {
            return Err(Self::fail(&context, argv, &output));
        }
        Self::state_from(&context, argv, &output)
    }

    /// [`Self::state`], with a missing interface reported as `Ok(None)`.
    pub async fn state_if_exists(&self, iface: &str) -> Result<Option<IfaceState>, IfconfigError> {
        let context = format!("read state of interface '{iface}' (if it exists)");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if output.success() {
            return Self::state_from(&context, argv, &output).map(Some);
        }
        if output.exit_code == Some(1) && stderr_says_iface_missing(&output.stderr) {
            return Ok(None);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// [`Self::state`] for an interface inside a jail's VNET:
    /// `ifconfig -j <jail> <iface>`.
    ///
    /// This is how the in-jail epair end's MTU and derived MAC are verified —
    /// the end nothing propagates to (`docs/vxlan.md` §5).
    pub async fn jail_state(&self, jail: &str, iface: &str) -> Result<IfaceState, IfconfigError> {
        let context = format!("read state of interface '{iface}' in jail '{jail}'");
        let (argv, output) = self.exec(&context, args_jail_show(jail, iface)).await?;
        if !output.success() {
            return Err(Self::fail(&context, argv, &output));
        }
        Self::state_from(&context, argv, &output)
    }

    fn state_from(
        context: &str,
        argv: String,
        output: &CommandOutput,
    ) -> Result<IfaceState, IfconfigError> {
        parse_iface_state(&output.stdout).map_err(|reason| IfconfigError::UnexpectedOutput {
            context: context.to_owned(),
            argv,
            reason,
            stdout: output.stdout.clone(),
            stderr: output.stderr.clone(),
        })
    }

    /// Read the IPv4 addresses currently assigned to `iface` from
    /// `ifconfig <iface>` show output (idempotency probe for gateway
    /// assignment).
    pub async fn get_inet(&self, iface: &str) -> Result<Vec<Ipv4Addr>, IfconfigError> {
        let context = format!("read inet addresses of interface '{iface}'");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if output.success() {
            return Ok(parse_inet_addresses(&output.stdout));
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Assign an IPv4 address in CIDR form: `ifconfig <iface> inet <cidr>`.
    pub async fn add_inet(&self, iface: &str, cidr: &str) -> Result<(), IfconfigError> {
        let context = format!("assign inet {cidr} to interface '{iface}'");
        let (argv, output) = self.exec(&context, args_add_inet(iface, cidr)).await?;
        if output.success() {
            tracing::debug!(iface = %iface, cidr = %cidr, "assigned inet address");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Remove an IPv4 address: `ifconfig <iface> inet <addr> -alias`.
    /// `Ok(false)` when the interface did not carry it.
    ///
    /// Removing an address a jail is still using is a **silent black hole**
    /// (`docs/vxlan.md` §8: the jail's cached ARP entry survives, so packets
    /// keep going to a MAC that no longer answers, with 100 % loss and no
    /// error). Only ever remove an address no endpoint is pointed at.
    pub async fn remove_inet(&self, iface: &str, addr: Ipv4Addr) -> Result<bool, IfconfigError> {
        let context = format!("remove inet {addr} from interface '{iface}'");
        let text = addr.to_string();
        let (argv, output) = self.exec(&context, args_remove_inet(iface, &text)).await?;
        if output.success() {
            tracing::info!(iface = %iface, addr = %addr, "removed inet address");
            return Ok(true);
        }
        if stderr_says_address_absent(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the link-layer address: `ifconfig <iface> ether <mac>`.
    ///
    /// Works on an epair end on the host, **before** the `vnet` move, and the
    /// address survives the move (verified live). SatL always sets it from
    /// [`satl_core::MacAddr::from_ipv4`] rather than letting the kernel pick,
    /// because the derivation is a wire format: unicast VXLAN never floods, so
    /// every node computes a peer's MAC from its overlay address alone to
    /// program static FDB and ARP entries (`docs/vxlan.md` §4).
    pub async fn set_ether(&self, iface: &str, mac: MacAddr) -> Result<(), IfconfigError> {
        let context = format!("set ether {mac} on interface '{iface}'");
        let text = mac.to_string();
        let (argv, output) = self.exec(&context, args_set_ether(iface, &text)).await?;
        if output.success() {
            tracing::debug!(iface = %iface, mac = %mac, "set derived link-layer address");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Turn IPv4 TX checksum offload off on `iface` if it is on:
    /// `ifconfig <iface>` to read the options line, then
    /// `ifconfig <iface> -txcsum` only when it carries `TXCSUM`.
    ///
    /// Exists for `lo0` (api-compat #35, measured on the cluster): a
    /// loopback-originated packet never carries a real TCP checksum — the
    /// stack sets "already verified" mbuf flags instead — and vxlan
    /// encapsulation to a remote node loses those flags, so a
    /// localhost-to-published-port connection relayed over the mesh arrives
    /// with a wrong inner checksum and is silently dropped. `-txcsum` makes
    /// the stack compute real checksums; `TXCSUM_IPV6` is deliberately left
    /// alone (SatL assigns no IPv6, and the measured fix did not touch it).
    ///
    /// Returns `Ok(true)` when the flag was cleared, `Ok(false)` when it was
    /// already off (idempotent — the caller re-ensures it every pass).
    pub async fn disable_txcsum_if_set(&self, iface: &str) -> Result<bool, IfconfigError> {
        let context = format!("read TXCSUM offload on interface '{iface}'");
        let (argv, output) = self.exec(&context, args_show(iface)).await?;
        if !output.success() {
            return Err(Self::fail(&context, argv, &output));
        }
        if !options_have_txcsum(&output.stdout) {
            return Ok(false);
        }
        let context = format!("disable TXCSUM offload on interface '{iface}'");
        let (argv, output) = self.exec(&context, args_disable_txcsum(iface)).await?;
        if output.success() {
            return Ok(true);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Bring `iface` up: `ifconfig <iface> up`.
    pub async fn up(&self, iface: &str) -> Result<(), IfconfigError> {
        let context = format!("bring interface '{iface}' up");
        let (argv, output) = self.exec(&context, args_up(iface)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the MTU of `iface`: `ifconfig <iface> mtu <mtu>`.
    ///
    /// Fails with [`IfconfigError::MtuLockedByBridge`] when `iface` is already
    /// a bridge member — set an epair's MTU before `addm`, and afterwards set
    /// it on the bridge (see the module docs).
    pub async fn set_mtu(&self, iface: &str, mtu: u32) -> Result<(), IfconfigError> {
        let context = format!("set mtu {mtu} on interface '{iface}'");
        let (argv, output) = self.exec(&context, args_set_mtu(iface, mtu)).await?;
        if output.success() {
            tracing::debug!(iface = %iface, mtu, "set mtu");
            return Ok(());
        }
        if stderr_says_mtu_unsupported(&output.stderr) {
            return Err(IfconfigError::MtuLockedByBridge {
                iface: iface.to_owned(),
                mtu,
                failure: Failure::new(argv, &output),
            });
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the MTU of an interface inside a jail:
    /// `ifconfig -j <jail> <iface> mtu <mtu>`.
    ///
    /// The in-jail epair end is not a bridge member, so **nothing propagates
    /// its MTU** — it is the one the container's TCP MSS comes from, and the
    /// one a forgotten −50 silently fragments every full-size frame on
    /// (`docs/vxlan.md` §5, §6 case B).
    pub async fn jail_set_mtu(
        &self,
        jail: &str,
        iface: &str,
        mtu: u32,
    ) -> Result<(), IfconfigError> {
        let context = format!("set mtu {mtu} on interface '{iface}' in jail '{jail}'");
        let (argv, output) = self
            .exec(&context, args_jail_set_mtu(jail, iface, mtu))
            .await?;
        if output.success() {
            tracing::debug!(iface = %iface, jail = %jail, mtu, "set in-jail mtu");
            return Ok(());
        }
        if stderr_says_mtu_unsupported(&output.stderr) {
            return Err(IfconfigError::MtuLockedByBridge {
                iface: iface.to_owned(),
                mtu,
                failure: Failure::new(argv, &output),
            });
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Move `iface` into a VNET jail: `ifconfig <iface> vnet <jail>`.
    /// `jail` may be a jail name or a numeric jid (both verified live).
    pub async fn move_to_jail(&self, iface: &str, jail: &str) -> Result<(), IfconfigError> {
        let context = format!("move interface '{iface}' into jail '{jail}'");
        let (argv, output) = self.exec(&context, args_move_to_jail(iface, jail)).await?;
        if output.success() {
            tracing::info!(iface = %iface, jail = %jail, "moved interface into jail");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Assign an IPv4 address to an interface inside a jail:
    /// `ifconfig -j <jail> <iface> inet <cidr>`.
    pub async fn jail_add_inet(
        &self,
        jail: &str,
        iface: &str,
        cidr: &str,
    ) -> Result<(), IfconfigError> {
        let context = format!("assign inet {cidr} to interface '{iface}' in jail '{jail}'");
        let (argv, output) = self
            .exec(&context, args_jail_add_inet(jail, iface, cidr))
            .await?;
        if output.success() {
            tracing::debug!(iface = %iface, jail = %jail, cidr = %cidr, "assigned in-jail inet address");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Bring an interface inside a jail up: `ifconfig -j <jail> <iface> up`.
    pub async fn jail_up(&self, jail: &str, iface: &str) -> Result<(), IfconfigError> {
        let context = format!("bring interface '{iface}' up in jail '{jail}'");
        let (argv, output) = self.exec(&context, args_jail_up(jail, iface)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_EPAIR_CREATE: &str = include_str!("../tests/fixtures/ifconfig_epair_create.txt");
    const FIXTURE_BRIDGE_CREATE: &str =
        include_str!("../tests/fixtures/ifconfig_bridge_create_name.txt");
    const FIXTURE_CONFLICT_STDOUT: &str =
        include_str!("../tests/fixtures/ifconfig_bridge_create_conflict_stdout.txt");
    const FIXTURE_CONFLICT_STDERR: &str =
        include_str!("../tests/fixtures/ifconfig_bridge_create_conflict_stderr.txt");
    const FIXTURE_LIST_GROUP: &str = include_str!("../tests/fixtures/ifconfig_list_group.txt");
    const FIXTURE_MISSING: &str = include_str!("../tests/fixtures/ifconfig_missing_iface.txt");
    const FIXTURE_SHOW_EPAIR: &str = include_str!("../tests/fixtures/ifconfig_show_epair.txt");
    const FIXTURE_SHOW_BRIDGE: &str = include_str!("../tests/fixtures/ifconfig_show_bridge.txt");
    const FIXTURE_SHOW_NO_DESCR: &str =
        include_str!("../tests/fixtures/ifconfig_show_no_descr.txt");
    // M3 overlay fixtures, captured on this host on 2026-08-10.
    const FIXTURE_SHOW_VTEP: &str = include_str!("../tests/fixtures/ifconfig_show_vtep.txt");
    const FIXTURE_SHOW_OVERLAY_BRIDGE: &str =
        include_str!("../tests/fixtures/ifconfig_show_overlay_bridge.txt");
    const FIXTURE_SHOW_BRIDGE_PRE_UP: &str =
        include_str!("../tests/fixtures/ifconfig_show_bridge_pre_up.txt");
    const FIXTURE_SHOW_EPAIR_A_BRIDGED: &str =
        include_str!("../tests/fixtures/ifconfig_show_epair_a_bridged.txt");
    const FIXTURE_SHOW_EPAIR_B_IN_JAIL: &str =
        include_str!("../tests/fixtures/ifconfig_show_epair_b_in_jail.txt");
    const FIXTURE_SHOW_EPAIR_B_DEFAULT_MTU: &str =
        include_str!("../tests/fixtures/ifconfig_show_epair_b_default_mtu.txt");
    const FIXTURE_LIST_GROUP_BRIDGE: &str =
        include_str!("../tests/fixtures/ifconfig_list_group_bridge.txt");
    const FIXTURE_ADDM_EXISTS: &str =
        include_str!("../tests/fixtures/ifconfig_bridge_addm_exists_stderr.txt");
    const FIXTURE_DELETEM_NOT_MEMBER: &str =
        include_str!("../tests/fixtures/ifconfig_bridge_deletem_not_member_stderr.txt");
    const FIXTURE_MTU_REFUSED: &str =
        include_str!("../tests/fixtures/ifconfig_mtu_member_refused_stderr.txt");
    const FIXTURE_ALIAS_ABSENT: &str =
        include_str!("../tests/fixtures/ifconfig_inet_alias_absent_stderr.txt");
    const FIXTURE_JAIL_NOT_FOUND: &str =
        include_str!("../tests/fixtures/ifconfig_jail_not_found_stderr.txt");
    const FIXTURE_ETHER_MALFORMED: &str =
        include_str!("../tests/fixtures/ifconfig_ether_malformed_stderr.txt");
    // Captured on this host on 2026-08-25 (`ifconfig lo0`), TXCSUM set.
    const FIXTURE_SHOW_LO0: &str = include_str!("../tests/fixtures/ifconfig_lo0.txt");

    // ---- argv builders ------------------------------------------------------

    #[test]
    fn argv_builders() {
        assert_eq!(
            args_create_bridge("satl0"),
            ["bridge", "create", "name", "satl0"]
        );
        assert_eq!(args_create_epair(), ["epair", "create"]);
        assert_eq!(args_destroy("epair0a"), ["epair0a", "destroy"]);
        assert_eq!(args_show("epair0a"), ["epair0a"]);
        assert_eq!(
            args_bridge_addm("satl0", "epair0a"),
            ["satl0", "addm", "epair0a"]
        );
        assert_eq!(
            args_set_group("epair0a", "satl"),
            ["epair0a", "group", "satl"]
        );
        assert_eq!(args_list_group("satl"), ["-g", "satl"]);
        assert_eq!(
            args_set_descr("epair0a", "satl:0123456789abcdefghijklmno"),
            ["epair0a", "description", "satl:0123456789abcdefghijklmno"]
        );
        assert_eq!(
            args_add_inet("satl0", "10.88.0.1/24"),
            ["satl0", "inet", "10.88.0.1/24"]
        );
        assert_eq!(args_up("satl0"), ["satl0", "up"]);
        assert_eq!(args_set_mtu("satl0", 1450), ["satl0", "mtu", "1450"]);
        assert_eq!(
            args_move_to_jail("epair0b", "42"),
            ["epair0b", "vnet", "42"]
        );
        assert_eq!(
            args_jail_add_inet("42", "epair0b", "10.88.0.2/24"),
            ["-j", "42", "epair0b", "inet", "10.88.0.2/24"]
        );
        assert_eq!(args_jail_up("42", "epair0b"), ["-j", "42", "epair0b", "up"]);
    }

    #[test]
    fn overlay_argv_builders() {
        assert_eq!(
            args_bridge_deletem("satl-br42", "satl-vx42"),
            ["satl-br42", "deletem", "satl-vx42"]
        );
        assert_eq!(
            args_set_ether("epair0b", "02:42:0a:64:00:0b"),
            ["epair0b", "ether", "02:42:0a:64:00:0b"]
        );
        assert_eq!(
            args_remove_inet("satl-br42", "10.100.0.9"),
            ["satl-br42", "inet", "10.100.0.9", "-alias"]
        );
        assert_eq!(
            args_jail_show("satl-t1", "epair0b"),
            ["-j", "satl-t1", "epair0b"]
        );
        assert_eq!(
            args_jail_set_mtu("satl-t1", "epair0b", 1450),
            ["-j", "satl-t1", "epair0b", "mtu", "1450"]
        );
    }

    // ---- IfaceState against real captured show output ------------------------

    #[test]
    fn parse_vtep_state() {
        let state = parse_iface_state(FIXTURE_SHOW_VTEP).unwrap();
        assert_eq!(state.name, "ntx-vx0");
        assert_eq!(state.flags_raw, 0x0100_8843);
        assert!(state.is_up());
        assert!(state.is_running(), "the only health signal");
        assert_eq!(state.mtu, 1450, "vxlan default on a 1500 underlay");
        assert_eq!(state.descr.as_deref(), Some("satl:vxlan:ntxnet"));
        assert_eq!(state.groups, ["vxlan"]);
        assert!(state.members.is_empty());
        assert_eq!(
            state.rendered_flags(),
            "1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP>"
        );
    }

    #[test]
    fn parse_overlay_bridge_state_with_members_and_gateway() {
        let state = parse_iface_state(FIXTURE_SHOW_OVERLAY_BRIDGE).unwrap();
        assert_eq!(state.name, "ntx-br0");
        assert!(state.is_up() && state.is_running());
        assert_eq!(state.mtu, 1450);
        assert_eq!(state.descr.as_deref(), Some("satl:overlay:ntxnet"));
        assert_eq!(state.inet, ["10.79.0.2".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(state.members, ["epair4a", "ntx-vx0"]);
        assert!(state.has_member("ntx-vx0"));
        assert!(!state.has_member("ntx-vx1"));
        assert_eq!(state.groups, ["bridge", "ntxg"]);
        assert!(state.in_group("ntxg"));
    }

    #[test]
    fn a_bridge_that_was_never_brought_up_is_not_running() {
        // Captured after `addm` + `mtu 1450`, before `up`: flags=8802, and the
        // MTU is already the member's. `addm ... up` would have brought the
        // *bridge* up, not the member (docs/vxlan.md §4).
        let state = parse_iface_state(FIXTURE_SHOW_BRIDGE_PRE_UP).unwrap();
        assert_eq!(state.flags_raw, 0x8802);
        assert!(!state.is_up());
        assert!(!state.is_running());
        assert_eq!(state.mtu, 1450);
        assert_eq!(state.members, ["ntx-vx0"]);
        assert!(state.inet.is_empty());
    }

    #[test]
    fn parse_epair_ends_reads_the_derived_mac_not_the_kernels() {
        let host = parse_iface_state(FIXTURE_SHOW_EPAIR_A_BRIDGED).unwrap();
        assert_eq!(host.name, "epair4a");
        assert!(host.is_up() && host.is_running());
        assert_eq!(host.mtu, 1450, "forced by the bridge on addm");
        assert!(host.has_flag("PROMISC"), "a bridge member is promiscuous");

        let jailed = parse_iface_state(FIXTURE_SHOW_EPAIR_B_IN_JAIL).unwrap();
        assert_eq!(jailed.name, "epair4b");
        assert!(jailed.is_up() && jailed.is_running());
        assert_eq!(jailed.mtu, 1450, "set explicitly; nothing propagates here");
        // The b end carries both `ether` (derived) and `hwaddr` (the kernel's);
        // only the derived one is the overlay's wire format.
        assert_eq!(
            jailed.ether,
            Some(MacAddr::from_ipv4("10.79.0.11".parse().unwrap()))
        );
        assert_eq!(jailed.inet, ["10.79.0.11".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(
            jailed.descr.as_deref(),
            Some("satl:overlay:ntxnet:ntxtask00000000000001x")
        );
    }

    #[test]
    fn an_untouched_epair_b_end_shows_the_1500_trap() {
        // The whole reason the b end is set explicitly: a fresh epair end is
        // 1500 and stays 1500 — it is not a bridge member, so the bridge's
        // 1450 never reaches it (docs/vxlan.md §5).
        let state = parse_iface_state(FIXTURE_SHOW_EPAIR_B_DEFAULT_MTU).unwrap();
        assert_eq!(state.mtu, 1500);
        assert!(!state.is_up());
        assert!(state.is_running(), "the epair link is up regardless");
        // The kernel's own address, not a derived one: no `02:42:` prefix. A
        // read-back that finds this instead of `mac(ip)` means the overlay's
        // FDB and ARP entries point at nothing.
        let ether = state.ether.expect("an epair always has an ether line");
        assert_ne!(&ether.octets()[..2], &[0x02, 0x42]);
        assert_ne!(ether, MacAddr::from_ipv4("10.79.0.11".parse().unwrap()));
    }

    #[test]
    fn parse_iface_state_rejects_garbage() {
        assert!(parse_iface_state("").is_err());
        assert!(parse_iface_state("no colon here\n").is_err());
        assert!(parse_iface_state("satl0: metric 0 mtu 1500\n").is_err());
        assert!(parse_iface_state("satl0: flags=zz<UP> metric 0 mtu 1500\n").is_err());
        assert!(parse_iface_state("satl0: flags=8843<UP> metric 0\n").is_err());
    }

    #[test]
    fn driver_group_listing_enumerates_bridges() {
        assert_eq!(
            parse_group_list(FIXTURE_LIST_GROUP_BRIDGE),
            ["satl0", "ntx-br0"]
        );
    }

    #[test]
    fn idempotency_stderr_signatures_are_recognized() {
        assert!(stderr_says_already_member(FIXTURE_ADDM_EXISTS));
        assert!(!stderr_says_already_member(FIXTURE_DELETEM_NOT_MEMBER));
        assert!(stderr_says_not_a_member(FIXTURE_DELETEM_NOT_MEMBER));
        assert!(!stderr_says_not_a_member(FIXTURE_ADDM_EXISTS));
        assert!(stderr_says_mtu_unsupported(FIXTURE_MTU_REFUSED));
        assert!(!stderr_says_mtu_unsupported(
            "ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument\n"
        ));
        assert!(stderr_says_address_absent(FIXTURE_ALIAS_ABSENT));
        assert!(!stderr_says_address_absent(FIXTURE_JAIL_NOT_FOUND));
        // A missing interface, in or out of a jail, keeps its own signature.
        assert!(stderr_says_iface_missing(FIXTURE_MISSING));
    }

    // ---- parsers against real captured fixtures -----------------------------

    #[test]
    fn parse_epair_create_output() {
        let pair = parse_epair_create(FIXTURE_EPAIR_CREATE).unwrap();
        assert_eq!(pair.a, "epair0a");
        assert_eq!(pair.b, "epair0b");
    }

    #[test]
    fn parse_epair_create_rejects_garbage() {
        assert!(parse_epair_create("").is_err());
        assert!(parse_epair_create("epair0a\nepair1a\n").is_err());
        assert!(parse_epair_create("bridge0\n").is_err());
        assert!(parse_epair_create("tap0a\n").is_err());
    }

    #[test]
    fn parse_bridge_create_prints_final_name() {
        // `ifconfig bridge create name satlnt-br0` prints the final name.
        assert_eq!(FIXTURE_BRIDGE_CREATE.trim(), "satlnt-br0");
    }

    #[test]
    fn parse_group_listing() {
        assert_eq!(
            parse_group_list(FIXTURE_LIST_GROUP),
            ["satlnt-br0", "epair0a"]
        );
        assert!(parse_group_list("").is_empty());
    }

    #[test]
    fn missing_iface_stderr_is_recognized() {
        assert!(stderr_says_iface_missing(FIXTURE_MISSING));
        assert!(!stderr_says_iface_missing(
            "ifconfig: ioctl SIOCSIFNAME (set name): File exists"
        ));
    }

    #[test]
    fn name_in_use_stderr_is_recognized() {
        assert!(stderr_says_name_in_use(FIXTURE_CONFLICT_STDERR));
        assert!(!stderr_says_name_in_use(FIXTURE_MISSING));
    }

    #[test]
    fn parse_description_from_show_output() {
        assert_eq!(
            parse_description(FIXTURE_SHOW_EPAIR).as_deref(),
            Some("satl:0123456789abcdefghijklmno")
        );
        assert_eq!(
            parse_description(FIXTURE_SHOW_BRIDGE).as_deref(),
            Some("satl:network:satlnt")
        );
        assert_eq!(parse_description(FIXTURE_SHOW_NO_DESCR), None);
    }

    #[test]
    fn parse_inet_addresses_from_show_output() {
        // Bridge fixture carries `inet 10.77.77.1 netmask 0xffffff00 ...`.
        assert_eq!(
            parse_inet_addresses(FIXTURE_SHOW_BRIDGE),
            ["10.77.77.1".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        // The epair fixture has no inet line.
        assert!(parse_inet_addresses(FIXTURE_SHOW_EPAIR).is_empty());
    }

    // ---- wrapper behavior with the mock runner ------------------------------

    #[tokio::test]
    async fn create_bridge_builds_expected_argv() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_BRIDGE_CREATE, "");
        let ifc = Ifconfig::with_runner(&mock);
        ifc.create_bridge("satlnt-br0").await.unwrap();
        assert_eq!(
            mock.calls(),
            ["/sbin/ifconfig bridge create name satlnt-br0"]
        );
    }

    #[tokio::test]
    async fn create_bridge_name_collision_destroys_leak() {
        let mock = MockRunner::new();
        mock.push_output(1, FIXTURE_CONFLICT_STDOUT, FIXTURE_CONFLICT_STDERR);
        mock.push_ok(); // destroy of the leaked bridge1
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc.create_bridge("satlnt-br0").await.unwrap_err();
        match &err {
            IfconfigError::BridgeNameInUse {
                bridge,
                leaked,
                leak_cleaned,
                ..
            } => {
                assert_eq!(bridge, "satlnt-br0");
                assert_eq!(leaked, "bridge1");
                assert!(leak_cleaned);
            }
            other => panic!("expected BridgeNameInUse, got {other:?}"),
        }
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig bridge create name satlnt-br0",
                "/sbin/ifconfig bridge1 destroy",
            ]
        );
        let text = err.to_string();
        assert!(text.contains("SIOCSIFNAME"), "{text}");
        assert!(text.contains("exit code 1"), "{text}");
    }

    #[tokio::test]
    async fn create_epair_parses_pair() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_EPAIR_CREATE, "");
        let ifc = Ifconfig::with_runner(&mock);
        let pair = ifc.create_epair().await.unwrap();
        assert_eq!(pair.a, "epair0a");
        assert_eq!(pair.b, "epair0b");
        assert_eq!(mock.calls(), ["/sbin/ifconfig epair create"]);
    }

    #[tokio::test]
    async fn destroy_if_exists_maps_missing_to_false() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MISSING);
        let ifc = Ifconfig::with_runner(&mock);
        assert!(!ifc.destroy_if_exists("satlnt-nope").await.unwrap());
    }

    #[tokio::test]
    async fn destroy_error_names_interface_and_carries_context() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "ifconfig: SIOCIFDESTROY: Device busy\n");
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc.destroy("epair7a").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("destroy interface 'epair7a'"), "{text}");
        assert!(text.contains("/sbin/ifconfig epair7a destroy"), "{text}");
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("Device busy"), "{text}");
    }

    #[tokio::test]
    async fn exists_true_false_and_error() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_EPAIR, "");
        mock.push_output(1, "", FIXTURE_MISSING);
        mock.push_output(1, "", "ifconfig: permission denied\n");
        let ifc = Ifconfig::with_runner(&mock);
        assert!(ifc.exists("epair0a").await.unwrap());
        assert!(!ifc.exists("satlnt-nope").await.unwrap());
        assert!(ifc.exists("epair0a").await.is_err());
    }

    #[tokio::test]
    async fn list_group_parses_members() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_GROUP, "");
        let ifc = Ifconfig::with_runner(&mock);
        assert_eq!(
            ifc.list_group("satlnt").await.unwrap(),
            ["satlnt-br0", "epair0a"]
        );
        assert_eq!(mock.calls(), ["/sbin/ifconfig -g satlnt"]);
    }

    #[tokio::test]
    async fn get_descr_reads_show_output() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_EPAIR, "");
        mock.push_output(0, FIXTURE_SHOW_NO_DESCR, "");
        let ifc = Ifconfig::with_runner(&mock);
        assert_eq!(
            ifc.get_descr("epair0a").await.unwrap().as_deref(),
            Some("satl:0123456789abcdefghijklmno")
        );
        assert_eq!(ifc.get_descr("satlnt-br0").await.unwrap(), None);
    }

    #[tokio::test]
    async fn jail_ops_build_expected_argv() {
        let mock = MockRunner::new();
        mock.push_ok();
        mock.push_ok();
        mock.push_ok();
        let ifc = Ifconfig::with_runner(&mock);
        ifc.move_to_jail("epair0b", "satlnt-it").await.unwrap();
        ifc.jail_add_inet("satlnt-it", "epair0b", "10.88.0.2/24")
            .await
            .unwrap();
        ifc.jail_up("satlnt-it", "epair0b").await.unwrap();
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair0b vnet satlnt-it",
                "/sbin/ifconfig -j satlnt-it epair0b inet 10.88.0.2/24",
                "/sbin/ifconfig -j satlnt-it epair0b up",
            ]
        );
    }

    #[tokio::test]
    async fn jail_error_names_iface_and_jail() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "ifconfig: jail \"satlnt-gone\" not found\n");
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc
            .jail_add_inet("satlnt-gone", "epair0b", "10.88.0.2/24")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("epair0b"), "{text}");
        assert!(text.contains("satlnt-gone"), "{text}");
        assert!(text.contains("not found"), "{text}");
    }

    #[tokio::test]
    async fn overlay_wrappers_build_expected_argv() {
        let mock = MockRunner::new();
        mock.push_ok(); // set_ether
        mock.push_ok(); // set_mtu (a end, before addm)
        mock.push_ok(); // bridge_addm_if_absent
        mock.push_output(1, "", FIXTURE_ADDM_EXISTS); // already a member
        mock.push_ok(); // bridge_deletem_if_member
        mock.push_output(1, "", FIXTURE_DELETEM_NOT_MEMBER); // not a member
        mock.push_ok(); // jail_set_mtu
        mock.push_ok(); // remove_inet
        mock.push_output(1, "", FIXTURE_ALIAS_ABSENT); // address not there
        let ifc = Ifconfig::with_runner(&mock);
        let mac = MacAddr::from_ipv4("10.100.0.11".parse().unwrap());
        ifc.set_ether("epair0b", mac).await.unwrap();
        ifc.set_mtu("epair0a", 1450).await.unwrap();
        assert!(
            ifc.bridge_addm_if_absent("satl-br42", "epair0a")
                .await
                .unwrap()
        );
        assert!(
            !ifc.bridge_addm_if_absent("satl-br42", "epair0a")
                .await
                .unwrap()
        );
        assert!(
            ifc.bridge_deletem_if_member("satl-br42", "satl-vx42")
                .await
                .unwrap()
        );
        assert!(
            !ifc.bridge_deletem_if_member("satl-br42", "satl-vx42")
                .await
                .unwrap()
        );
        ifc.jail_set_mtu("satl-t1", "epair0b", 1450).await.unwrap();
        assert!(
            ifc.remove_inet("satl-br42", "10.100.0.9".parse().unwrap())
                .await
                .unwrap()
        );
        assert!(
            !ifc.remove_inet("satl-br42", "10.100.0.9".parse().unwrap())
                .await
                .unwrap()
        );
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair0b ether 02:42:0a:64:00:0b",
                "/sbin/ifconfig epair0a mtu 1450",
                "/sbin/ifconfig satl-br42 addm epair0a",
                "/sbin/ifconfig satl-br42 addm epair0a",
                "/sbin/ifconfig satl-br42 deletem satl-vx42",
                "/sbin/ifconfig satl-br42 deletem satl-vx42",
                "/sbin/ifconfig -j satl-t1 epair0b mtu 1450",
                "/sbin/ifconfig satl-br42 inet 10.100.0.9 -alias",
                "/sbin/ifconfig satl-br42 inet 10.100.0.9 -alias",
            ]
        );
    }

    #[tokio::test]
    async fn set_ether_failure_names_the_interface_and_quotes_the_kernel() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_ETHER_MALFORMED);
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc
            .set_ether(
                "epair0b",
                MacAddr::from_ipv4("10.100.0.11".parse().unwrap()),
            )
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("set ether 02:42:0a:64:00:0b"), "{text}");
        assert!(text.contains("epair0b"), "{text}");
        assert!(text.contains("malformed link-level address"), "{text}");
    }

    #[tokio::test]
    async fn set_mtu_on_a_bridge_member_explains_itself() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MTU_REFUSED);
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc.set_mtu("epair4a", 1450).await.unwrap_err();
        match &err {
            IfconfigError::MtuLockedByBridge { iface, mtu, .. } => {
                assert_eq!(iface, "epair4a");
                assert_eq!(*mtu, 1450);
            }
            other => panic!("expected MtuLockedByBridge, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("bridge member"), "{text}");
        assert!(text.contains("before `addm`"), "{text}");
        assert!(text.contains("/sbin/ifconfig epair4a mtu 1450"), "{text}");
        assert!(text.contains("Operation not supported"), "{text}");
    }

    #[tokio::test]
    async fn state_reads_back_and_missing_is_none() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_OVERLAY_BRIDGE, "");
        mock.push_output(1, "", FIXTURE_MISSING);
        mock.push_output(0, FIXTURE_SHOW_EPAIR_B_IN_JAIL, "");
        mock.push_output(1, "", FIXTURE_JAIL_NOT_FOUND);
        let ifc = Ifconfig::with_runner(&mock);
        let bridge = ifc.state("ntx-br0").await.unwrap();
        assert!(bridge.has_member("ntx-vx0"));
        assert_eq!(ifc.state_if_exists("satlnt-nope").await.unwrap(), None);
        let jailed = ifc.jail_state("ntx-j1", "epair4b").await.unwrap();
        assert_eq!(jailed.mtu, 1450);
        // A missing jail is a real failure, and the error says which jail.
        let err = ifc.jail_state("ntx-nojail", "epair4b").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("ntx-nojail"), "{text}");
        assert!(text.contains("jail not found"), "{text}");
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig ntx-br0",
                "/sbin/ifconfig satlnt-nope",
                "/sbin/ifconfig -j ntx-j1 epair4b",
                "/sbin/ifconfig -j ntx-nojail epair4b",
            ]
        );
    }

    #[tokio::test]
    async fn state_rejects_unparsable_output_with_the_raw_text() {
        let mock = MockRunner::new();
        mock.push_output(0, "surprise\n", "");
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc.state("satl-br42").await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("read state of interface 'satl-br42'"),
            "{text}"
        );
        assert!(text.contains("surprise"), "{text}");
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv_and_context() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let ifc = Ifconfig::with_runner(&mock).with_binary("/nonexistent/ifconfig");
        let err = ifc.up("satl0").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/nonexistent/ifconfig satl0 up"), "{text}");
        assert!(text.contains("bring interface 'satl0' up"), "{text}");
        assert!(text.contains("no such file"), "{text}");
    }

    // ---- lo0 TXCSUM offload (api-compat #35) --------------------------------

    /// The fixture is a real `ifconfig lo0` from this host with
    /// `options=680003<RXCSUM,TXCSUM,LINKSTATE,RXCSUM_IPV6,TXCSUM_IPV6>`.
    /// The parser must match the exact `TXCSUM` token in the options line:
    /// `TXCSUM_IPV6` — present in the fixture, and left on during the
    /// measured fix — must not count, and neither must the `nd6 options=`
    /// line.
    #[test]
    fn txcsum_is_parsed_as_an_exact_options_token() {
        assert!(options_have_txcsum(FIXTURE_SHOW_LO0));
        // The same output with the TXCSUM token removed: TXCSUM_IPV6 stays,
        // and must not satisfy the parser.
        let without = FIXTURE_SHOW_LO0.replacen("TXCSUM,", "", 1);
        assert!(without.contains("TXCSUM_IPV6"), "{without}");
        assert!(!options_have_txcsum(&without));
        // No options line at all (the header alone) is "off".
        assert!(!options_have_txcsum(
            FIXTURE_SHOW_LO0.lines().next().unwrap()
        ));
        assert!(!options_have_txcsum(""));
    }

    #[tokio::test]
    async fn txcsum_present_is_disabled_and_reported() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_LO0, "");
        mock.push_ok();
        let ifc = Ifconfig::with_runner(&mock);
        assert!(ifc.disable_txcsum_if_set("lo0").await.unwrap());
        assert_eq!(
            mock.calls(),
            ["/sbin/ifconfig lo0", "/sbin/ifconfig lo0 -txcsum"]
        );
    }

    #[tokio::test]
    async fn txcsum_already_off_is_a_read_only_no_op() {
        let mock = MockRunner::new();
        mock.push_output(0, &FIXTURE_SHOW_LO0.replacen("TXCSUM,", "", 1), "");
        let ifc = Ifconfig::with_runner(&mock);
        assert!(!ifc.disable_txcsum_if_set("lo0").await.unwrap());
        // The read alone: nothing was written.
        assert_eq!(mock.calls(), ["/sbin/ifconfig lo0"]);
    }

    #[tokio::test]
    async fn txcsum_disable_failure_carries_argv_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_LO0, "");
        mock.push_output(
            1,
            "",
            "ifconfig: ioctl (SIOCSIFCAP): Operation not permitted\n",
        );
        let ifc = Ifconfig::with_runner(&mock);
        let err = ifc.disable_txcsum_if_set("lo0").await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("disable TXCSUM offload on interface 'lo0'"),
            "{text}"
        );
        assert!(text.contains("/sbin/ifconfig lo0 -txcsum"), "{text}");
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("Operation not permitted"), "{text}");
    }
}
