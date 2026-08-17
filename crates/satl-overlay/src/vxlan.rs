// SPDX-License-Identifier: BSD-2-Clause
//! Typed wrapper around `ifconfig`(8) for the VXLAN VTEP lifecycle.
//!
//! Everything here is coded against `docs/vxlan.md`, which is measured ground
//! truth from the cluster VMs; the fixtures in `tests/fixtures/vxlan_*.txt`
//! were re-captured on the dev host while writing this module, so the parsers
//! are tested against output this exact kernel produced. The four facts that
//! shape the API:
//!
//! 1. **`ifconfig <driver> create` prints the name the kernel chose and clone
//!    units are never recycled** (`docs/vxlan.md` §2 point 1), so the caller
//!    must read the name back — never assume `vxlan0`. [`Vxlan::create_vtep`]
//!    does create + rename as one step and destroys the clone if the rename
//!    fails, so an interrupted call cannot leave an unattributable interface
//!    behind.
//! 2. **`vxlanremote` is mandatory** (§2 point 4) and every broadcast,
//!    multicast and unknown-unicast frame goes to it without consulting the
//!    FDB. [`VtepSpec::default_remote`] must therefore be a deliberately
//!    unroutable underlay address: pointed at a real peer it makes a *missing*
//!    FDB entry work anyway, which is how an FDB bug survives a two-node test.
//! 3. **`ifconfig` lies about health** (§2 point 5): an interface the driver
//!    refused to initialize still reports `UP`, still says `status: active`,
//!    and `ifconfig` still exits 0. `RUNNING` in the flag word is the only
//!    signal — `1008843` healthy against `1008803` broken — and the reason is
//!    only ever in `/var/log/messages`. [`Vxlan::verify_running`] is therefore
//!    mandatory after every `up`, and its error names the log to read.
//! 4. **The MTU must be set explicitly** (§1, §5): the driver computes its
//!    default from the constant `ETHERMTU`, not from the underlay, so it is
//!    right by coincidence on a 1500-byte underlay and wrong everywhere else.
//!
//! Ownership follows `satl-net`'s convention (`docs/networking.md`, "Ownership
//! markers"): an **interface description** rather than an interface group,
//! because a description survives a `vnet` move into a jail and the automatic
//! return to the host when the jail dies while group membership does not. A
//! vxlan interface never enters a jail, but using one marker for all of SatL's
//! interfaces keeps the startup sweep single-minded — and the driver's own
//! `vxlan` group ([`VXLAN_GROUP`]) is what enumerates candidates, since it
//! costs one `ifconfig -g vxlan` instead of a scan of every interface on the
//! host.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::runner::{CommandOutput, CommandRunner, Failure, SystemRunner, render_argv};

/// Default location of the `ifconfig` binary on FreeBSD.
pub const DEFAULT_IFCONFIG_BINARY: &str = "/sbin/ifconfig";

/// Default location of the `kldload` binary on FreeBSD.
pub const DEFAULT_KLDLOAD_BINARY: &str = "/sbin/kldload";

/// Kernel module backing vxlan(4). **Not in GENERIC** — `satld` must load it
/// (`docs/vxlan.md` §2) or `ifconfig vxlan create` fails.
pub const VXLAN_KLD: &str = "if_vxlan";

/// Interface group the driver puts every vxlan interface in, so
/// `ifconfig -g vxlan` enumerates them (`docs/vxlan.md` §2 point 2).
pub const VXLAN_GROUP: &str = "vxlan";

/// IANA VXLAN UDP port, and the only one SatL uses. One socket per
/// (local address, port) is shared by every VNI on the node
/// (`docs/vxlan.md` §2 point 6).
pub const VXLAN_PORT: u16 = 4789;

/// Bytes an IPv4 VXLAN tunnel adds to every frame: 14 Ethernet + 8 UDP +
/// 8 VXLAN + 20 IPv4, from `vxlan_setup_interface_hdrlen()`
/// (`docs/vxlan.md` §1).
pub const VXLAN_ENCAP_OVERHEAD_V4: u32 = 50;

/// Same for an IPv6 VTEP (40-byte outer header). SatL assigns no IPv6 VTEP
/// yet; the constant exists so the arithmetic is never a literal.
pub const VXLAN_ENCAP_OVERHEAD_V6: u32 = 70;

/// The measured underlay MTU on the cluster VMs, and the driver's assumed
/// `ETHERMTU`. A per-network MTU must come from a *measurement*
/// (`hack/experiments/vxlan/00-underlay-mtu.sh`), never from this constant.
pub const DEFAULT_UNDERLAY_MTU: u32 = 1500;

/// Overlay MTU on a 1500-byte IPv4 underlay: 1450 (`docs/vxlan.md` §1).
pub const DEFAULT_OVERLAY_MTU: u32 = overlay_mtu_v4(DEFAULT_UNDERLAY_MTU);

/// Bytes ESP in transport mode with `aes-gcm-16` adds to every outer
/// datagram: SPI+seq 8 + IV 8 + pad-length/next-header 2 + ICV 16 = 34
/// (RFC 4106). There are 0-3 further bytes of 4-byte alignment padding, which
/// the MTU arithmetic ignores because the boundary case needs none — measured
/// in `hack/experiments/esp/README.md` §4.
pub const ESP_TRANSPORT_OVERHEAD: u32 = 34;

/// Total per-packet overhead of an **encrypted** IPv4 VXLAN tunnel: 50 VXLAN
/// (including the inner Ethernet header) + 34 ESP = 84 (same source).
pub const VXLAN_ESP_ENCAP_OVERHEAD_V4: u32 = VXLAN_ENCAP_OVERHEAD_V4 + ESP_TRANSPORT_OVERHEAD;

/// Overlay MTU of an encrypted network on a 1500-byte underlay: **1416**
/// (1500 − 84). The boundary measurement of `hack/experiments/esp/README.md`
/// §4 is the ground truth: inner IP 1416 yields an outer datagram of exactly
/// 1500; 1417 already fragments (silently — vxlan clears the outer DF bit, so
/// "ping succeeds" is not evidence).
pub const DEFAULT_OVERLAY_MTU_ENCRYPTED: u32 = overlay_mtu_v4_encrypted(DEFAULT_UNDERLAY_MTU);

/// Smallest MTU the kernel accepts on an Ethernet-like interface
/// (`ETHERMIN` = `ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN` = 46).
pub const ETHERMIN: u32 = 46;

/// Longest interface name the kernel accepts: `IFNAMSIZ - 1`. Measured —
/// a 16-character `ifconfig <clone> name` fails with
/// `ioctl SIOCSIFNAME (set name): File name too long`.
pub const MAX_IFACE_NAME_LEN: usize = 15;

/// Largest VNI a 24-bit VXLAN network identifier can hold
/// (`VXLAN_VNI_MASK`, `net/if_vxlan.h`).
pub const VNI_MAX: u32 = 0x00FF_FFFF;

/// Per-interface FDB ceiling (`vxlanmaxaddr`) — **the default *and* the hard
/// maximum** the driver will accept as a *setting*.
///
/// `docs/vxlan.md` §3 says to "raise it with `ifconfig <if> vxlanmaxaddr N` for
/// large networks". That is not possible: `VXLAN_FTABLE_MAX` is 2000 and the
/// driver rejects anything above it. Measured on FreeBSD 15.1:
///
/// ```text
/// # ifconfig ovtest-vxM vxlanmaxaddr 2001
/// ifconfig: VXLAN_CMD_SET_FTABLE_MAX: Invalid argument      (exit 1)
/// # ifconfig ovtest-vxM vxlanmaxaddr 2000                   (exit 0)
/// ```
///
/// Worse, a **create-time** value above the ceiling is accepted silently:
/// `ifconfig vxlan create ... vxlanmaxaddr 4000` exits 0 and the interface comes
/// up with `ftable.max` = 2000. That is why [`VtepSpec`] has no `ftable_max`
/// field and [`Vxlan::set_ftable_max`] validates the range itself: a limit that
/// looks set and is not is exactly the failure mode this crate exists to avoid.
///
/// ## It is not a limit on *static* entries, and `ftable_nospace` never fires
///
/// An earlier version of this comment claimed that 2000 was "a real
/// architectural ceiling" on endpoints per network per node, and that
/// `net.link.vxlan.<unit>.stats.ftable_nospace` was how an operator would find
/// out it had been reached. **Both halves are false.** The count check and the
/// `ftable_nospace++` live only in `vxlan_ftable_update_locked()`, which the
/// driver calls from the *learning* path and which is gated behind
/// `VXLAN_FLAG_LEARN`; `vxlan_ctrl_ftable_entry_add()` — the ioctl this crate
/// uses — has no count check at all. Measured
/// (`hack/experiments/jail-arp/captures/40-ftable-dump-ceiling.txt`):
///
/// ```text
/// expjarp-vxdump: ftable count 2500 max 2000 timeout 1200
/// net.link.vxlan.0.stats.ftable_nospace: 0
/// ```
///
/// 2500 static entries installed on an interface whose `max` is 2000, and the
/// counter stayed at zero. With `-vxlanlearn`, which is the only configuration
/// SatL creates, nothing ever consults `ftable_max`.
///
/// The real ceiling on a SatL overlay is a different one: the *read-back*.
/// `net.link.vxlan.<unit>.ftable.dump` is a fixed one-page buffer and stops at
/// about 81 IPv4 entries with no marker
/// ([`crate::ftable::FtableError::DumpTruncated`]).
pub const FTABLE_MAX: u32 = 2000;

/// Overlay MTU for an IPv4 VTEP over an underlay of `underlay_mtu`.
///
/// This is the whole of the "VXLAN MTU" gotcha: 50 bytes, every time, and the
/// driver's default is *not* derived from the underlay
/// (`docs/vxlan.md` §1). Saturates rather than wrapping so a nonsensically
/// small underlay yields 0 and is caught by [`VtepSpec::validate`].
#[must_use]
pub const fn overlay_mtu_v4(underlay_mtu: u32) -> u32 {
    underlay_mtu.saturating_sub(VXLAN_ENCAP_OVERHEAD_V4)
}

/// Overlay MTU for an **encrypted** IPv4 VTEP: underlay minus
/// [`VXLAN_ESP_ENCAP_OVERHEAD_V4`] (84), because every datagram additionally
/// expands by [`ESP_TRANSPORT_OVERHEAD`] once ESP wraps it
/// (`hack/experiments/esp/README.md` §4). A separate function rather than a
/// parameter on [`overlay_mtu_v4`] so existing (cleartext) call sites keep
/// their signature; satld picks per network.
#[must_use]
pub const fn overlay_mtu_v4_encrypted(underlay_mtu: u32) -> u32 {
    underlay_mtu.saturating_sub(VXLAN_ESP_ENCAP_OVERHEAD_V4)
}

/// Overlay MTU for an IPv6 VTEP over an underlay of `underlay_mtu`.
#[must_use]
pub const fn overlay_mtu_v6(underlay_mtu: u32) -> u32 {
    underlay_mtu.saturating_sub(VXLAN_ENCAP_OVERHEAD_V6)
}

/// Deterministic VTEP interface name for a VNI: `satl-vx<vni>`.
///
/// Derived from the VNI rather than the network name because the name has to
/// fit [`MAX_IFACE_NAME_LEN`]: `satl-vx` is 7 characters and a 24-bit VNI is
/// at most 8 digits, so this form always fits, while `satl-vx-<network>`
/// leaves 7 characters for a user-chosen name and would truncate or collide.
/// The human-readable binding lives in the interface description instead.
#[must_use]
pub fn vtep_iface_name(vni: u32) -> String {
    format!("satl-vx{vni}")
}

/// Ownership marker for a VTEP: `<marker>:vxlan:<network>`.
///
/// Mirrors `satl-net`'s `<group>:network:<name>` on bridges, with a distinct
/// middle segment so a sweep can tell a VTEP from a bridge without looking at
/// the interface type.
#[must_use]
pub fn vtep_descr(marker: &str, network: &str) -> String {
    format!("{marker}:vxlan:{network}")
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// What a unicast VTEP is created with.
///
/// Learning is always off and is not a field: the FDB is control-plane state,
/// and a learned entry that ages out after 20 minutes is not something a
/// reconciler can reason about (`docs/vxlan.md` §3, "Learning is off").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtepSpec {
    /// VXLAN network identifier, ≤ [`VNI_MAX`].
    pub vni: u32,
    /// This node's underlay address (`vxlanlocal`).
    pub local: Ipv4Addr,
    /// The mandatory default remote (`vxlanremote`) — **a blackhole**.
    ///
    /// Every broadcast, multicast and unknown-unicast frame is sent here
    /// without an FDB lookup. Pointing it at a real peer hides missing FDB
    /// entries; pointing it at an unroutable underlay address turns the
    /// interface's `Oerrs` counter into "BUM traffic a correctly programmed
    /// overlay never needed to send" (`docs/vxlan.md` §2 point 4).
    pub default_remote: Ipv4Addr,
    /// Overlay MTU, i.e. `overlay_mtu_v4(measured underlay MTU)`.
    pub mtu: u32,
    /// Custom VXLAN UDP port (`vxlanlocalport`/`vxlanremoteport`), for
    /// encrypted networks whose SPs select on the port: the allocator assigns
    /// one per encrypted network from 4790..=4999 (`Network::vxlan_port`).
    /// `None` keeps the IANA default [`VXLAN_PORT`] (4789). Note the measured
    /// parameter names on 15.1: `vxlanport` does **not** exist
    /// (`hack/experiments/esp/README.md` §1).
    pub vxlan_port: Option<u16>,
}

impl VtepSpec {
    /// A spec with [`DEFAULT_OVERLAY_MTU`] and the default VXLAN port.
    #[must_use]
    pub fn new(vni: u32, local: Ipv4Addr, default_remote: Ipv4Addr) -> Self {
        Self {
            vni,
            local,
            default_remote,
            mtu: DEFAULT_OVERLAY_MTU,
            vxlan_port: None,
        }
    }

    /// Overrides the MTU.
    #[must_use]
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets a custom VXLAN UDP port (both local and remote), for an encrypted
    /// network.
    #[must_use]
    pub fn with_vxlan_port(mut self, port: u16) -> Self {
        self.vxlan_port = Some(port);
        self
    }

    /// Rejects what the kernel would reject anyway, before spawning anything,
    /// so the error names the field instead of quoting an `ifconfig` failure.
    pub fn validate(&self) -> Result<(), VxlanError> {
        let reject = |reason: &str| {
            Err(VxlanError::InvalidSpec {
                reason: reason.to_owned(),
            })
        };
        if self.vni > VNI_MAX {
            return reject(&format!(
                "vni {} exceeds the 24-bit maximum {VNI_MAX}",
                self.vni
            ));
        }
        if self.local.is_unspecified() || self.local.is_multicast() || self.local.is_broadcast() {
            return reject(&format!(
                "vxlanlocal {} must be a concrete unicast underlay address",
                self.local
            ));
        }
        if self.default_remote.is_unspecified()
            || self.default_remote.is_multicast()
            || self.default_remote.is_broadcast()
        {
            return reject(&format!(
                "vxlanremote {} must be a concrete unicast address (the kernel \
                 rejects INADDR_ANY and multicast, and SatL wants a blackhole \
                 on the underlay prefix, docs/vxlan.md §2)",
                self.default_remote
            ));
        }
        if self.default_remote == self.local {
            return reject(
                "vxlanremote equals vxlanlocal: the default remote must be an \
                 unroutable address, not this node",
            );
        }
        if self.mtu < ETHERMIN {
            return reject(&format!(
                "mtu {} is below ETHERMIN ({ETHERMIN}); did the underlay \
                 measurement fail?",
                self.mtu
            ));
        }
        Ok(())
    }
}

/// A VTEP interface SatL created, with the clone unit it was born as.
///
/// The unit matters because **the per-interface sysctl tree is keyed by the
/// clone unit, not the name**, and nothing maps a unit back to a name
/// (`docs/vxlan.md` §2 point 3). Remembering it at creation time is the cheap
/// way to reach `net.link.vxlan.<unit>.ftable.dump`; after a daemon restart
/// the unit is gone and [`crate::ftable::Ftable::resolve_unit`] has to
/// re-derive it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtepIface {
    /// Final interface name (after the rename).
    pub name: String,
    /// Clone unit the kernel assigned (`vxlanN` → `N`).
    pub unit: u32,
}

/// A vxlan interface carrying SatL's ownership marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedVtep {
    /// Interface name.
    pub name: String,
    /// Raw description text.
    pub descr: String,
    /// Network name parsed out of `<marker>:vxlan:<network>`; `None` when the
    /// description carries the marker but not this shape (a marker from
    /// another SatL component, or a future convention).
    pub network: Option<String>,
}

/// The first line of `ifconfig <iface>`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceFlags {
    /// Interface name as printed.
    pub name: String,
    /// The flag word, printed by `ifconfig` in hex without a `0x` prefix.
    pub raw: u32,
    /// The names inside the angle brackets, in order.
    pub names: Vec<String>,
    /// MTU from the same line.
    pub mtu: u32,
}

impl IfaceFlags {
    /// `IFF_UP` — administratively up. **Not** a health signal for a vxlan
    /// interface.
    #[must_use]
    pub fn is_up(&self) -> bool {
        self.has("UP")
    }

    /// `IFF_DRV_RUNNING` — the driver initialized the interface. For vxlan(4)
    /// this is the *only* health signal (`docs/vxlan.md` §2 point 5).
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.has("RUNNING")
    }

    fn has(&self, flag: &str) -> bool {
        self.names.iter().any(|name| name == flag)
    }

    /// The flag word rendered the way `ifconfig` prints it.
    #[must_use]
    pub fn rendered(&self) -> String {
        format!("{:x}<{}>", self.raw, self.names.join(","))
    }
}

/// The `vxlan vni ... local ... remote ...` line of `ifconfig <iface>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtepConfig {
    /// VXLAN network identifier.
    pub vni: u32,
    /// Local (source) VTEP address and port.
    pub local: Option<(Ipv4Addr, u16)>,
    /// Default remote address and port; `None` when the interface has none
    /// (printed as `remote :`), which is one of the two silent failures.
    pub remote: Option<(Ipv4Addr, u16)>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error from the VTEP lifecycle. Every variant names the interface and
/// carries the full argv, exit status and stderr of the failed command.
#[derive(Debug, thiserror::Error)]
pub enum VxlanError {
    /// A spec was rejected before anything was executed.
    #[error("vxlan: invalid VTEP spec: {reason}")]
    InvalidSpec {
        /// Which field, and why.
        reason: String,
    },

    /// A requested interface name does not fit `IFNAMSIZ`.
    #[error(
        "vxlan: interface name '{name}' is {len} characters; the kernel accepts \
         at most {MAX_IFACE_NAME_LEN} (SIOCSIFNAME: File name too long)"
    )]
    NameTooLong {
        /// The offending name.
        name: String,
        /// Its length.
        len: usize,
    },

    /// The binary could not be spawned.
    #[error("vxlan ({context}): failed to spawn `{argv}`: {source}")]
    Spawn {
        /// What was being attempted, naming the interface involved.
        context: String,
        /// Full rendered command line.
        argv: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The command ran but exited unsuccessfully.
    #[error("vxlan ({context}): {failure}")]
    Failed {
        /// What was being attempted, naming the interface involved.
        context: String,
        /// The failed command with argv, exit status and stderr.
        failure: Failure,
    },

    /// The command succeeded but its output did not have the expected shape.
    #[error(
        "vxlan ({context}): unexpected output from `{argv}`: {reason}; \
         raw stdout: {stdout:?}; raw stderr: {stderr:?}"
    )]
    UnexpectedOutput {
        /// What was being attempted, naming the interface involved.
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

    /// The interface does not exist.
    #[error("vxlan ({context}): interface '{iface}' does not exist")]
    NoSuchIface {
        /// What was being attempted.
        context: String,
        /// The missing interface.
        iface: String,
    },

    /// `ifconfig <clone> name <name>` failed because the name is taken. The
    /// clone the kernel had already created has been destroyed.
    #[error(
        "vxlan (create VTEP '{name}'): name already in use; the clone '{clone}' \
         created for it was destroyed (cleaned up: {clone_cleaned}); {failure}"
    )]
    NameInUse {
        /// The requested name.
        name: String,
        /// The clone that had to be discarded.
        clone: String,
        /// Whether that clone was successfully destroyed.
        clone_cleaned: bool,
        /// The failed rename.
        failure: Failure,
    },

    /// **The silent failure.** The interface is `UP` and `ifconfig` exited 0,
    /// but the driver never initialized it.
    #[error(
        "vxlan: interface '{iface}' is UP but not RUNNING (flags={flags}): the \
         driver refused to initialize it and `ifconfig` reported success \
         anyway. The reason is only in /var/log/messages, and says either \
         `{iface}: cannot initialize interface: destination address type is \
         not supported` (no vxlanremote) or `{iface}: network identifier <vni> \
         already exists in this socket` (a VNI already used by another \
         interface on this local address and port). See docs/vxlan.md section 2."
    )]
    NotRunning {
        /// The unhealthy interface.
        iface: String,
        /// Its flag word, rendered as `ifconfig` prints it.
        flags: String,
    },

    /// An existing interface's configuration differs from the requested spec,
    /// so it cannot be adopted.
    #[error(
        "vxlan: interface '{iface}' exists but is configured differently \
         ({mismatch}); destroy it before re-creating, or reconcile the spec"
    )]
    SpecMismatch {
        /// The interface that could not be adopted.
        iface: String,
        /// What differs.
        mismatch: String,
    },
}

// ---------------------------------------------------------------------------
// Pure argv builders
// ---------------------------------------------------------------------------

fn to_args<const N: usize>(parts: [&str; N]) -> Vec<String> {
    parts.into_iter().map(str::to_owned).collect()
}

/// `ifconfig vxlan create vxlanid <vni> vxlanlocal <a> vxlanremote <b>
/// -vxlanlearn` — the unicast create form of `docs/vxlan.md` §2, plus
/// `vxlanlocalport <p> vxlanremoteport <p>` when the spec carries a custom
/// port (the measured parameter names; there is no `vxlanport`,
/// `hack/experiments/esp/README.md` §1).
fn args_create(spec: &VtepSpec) -> Vec<String> {
    let mut args = vec![
        "vxlan".to_owned(),
        "create".to_owned(),
        "vxlanid".to_owned(),
        spec.vni.to_string(),
        "vxlanlocal".to_owned(),
        spec.local.to_string(),
        "vxlanremote".to_owned(),
        spec.default_remote.to_string(),
    ];
    if let Some(port) = spec.vxlan_port {
        args.push("vxlanlocalport".to_owned());
        args.push(port.to_string());
        args.push("vxlanremoteport".to_owned());
        args.push(port.to_string());
    }
    args.push("-vxlanlearn".to_owned());
    args
}

fn args_rename(from: &str, to: &str) -> Vec<String> {
    to_args([from, "name", to])
}

fn args_show(iface: &str) -> Vec<String> {
    to_args([iface])
}

fn args_destroy(iface: &str) -> Vec<String> {
    to_args([iface, "destroy"])
}

fn args_up(iface: &str) -> Vec<String> {
    to_args([iface, "up"])
}

fn args_down(iface: &str) -> Vec<String> {
    to_args([iface, "down"])
}

fn args_set_mtu(iface: &str, mtu: u32) -> Vec<String> {
    vec![iface.to_owned(), "mtu".to_owned(), mtu.to_string()]
}

fn args_set_descr(iface: &str, text: &str) -> Vec<String> {
    to_args([iface, "description", text])
}

fn args_list_group(group: &str) -> Vec<String> {
    to_args(["-g", group])
}

fn args_flush_all(iface: &str) -> Vec<String> {
    to_args([iface, "vxlanflushall"])
}

fn args_set_ftable_max(iface: &str, max: u32) -> Vec<String> {
    vec![iface.to_owned(), "vxlanmaxaddr".to_owned(), max.to_string()]
}

fn args_kldload(module: &str) -> Vec<String> {
    // -n: succeed silently when the module is already loaded.
    to_args(["-n", module])
}

// ---------------------------------------------------------------------------
// Pure output parsers
// ---------------------------------------------------------------------------

/// `ifconfig: interface <name> does not exist`, exit 1.
fn stderr_says_iface_missing(stderr: &str) -> bool {
    stderr.contains("does not exist")
}

/// `ifconfig: ioctl SIOCSIFNAME (set name): File exists` — the rename target
/// is taken. Note the different shape from `satl-net`'s `bridge create name
/// <taken>`: because create and rename are separate commands here, the clone
/// name is already known and does not have to be recovered from stdout.
fn stderr_says_name_in_use(stderr: &str) -> bool {
    stderr.contains("SIOCSIFNAME") && stderr.contains("File exists")
}

/// Parse `ifconfig vxlan create ...` output: one line, `vxlanN`.
fn parse_clone_name(stdout: &str) -> Result<(String, u32), String> {
    let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
    let Some(name) = lines.next().map(str::trim) else {
        return Err("expected the new interface name on stdout, got nothing".to_owned());
    };
    if lines.next().is_some() {
        return Err("expected exactly one line of output, got more".to_owned());
    }
    let Some(unit) = name.strip_prefix("vxlan") else {
        return Err(format!("expected a 'vxlanN' clone name, got {name:?}"));
    };
    let unit: u32 = unit
        .parse()
        .map_err(|_| format!("expected a numeric clone unit, got {name:?}"))?;
    Ok((name.to_owned(), unit))
}

/// Parse the first line of `ifconfig <iface>`:
/// `satl-vx4096: flags=1008843<UP,BROADCAST,RUNNING,...> metric 0 mtu 1450`.
///
/// The flag word is **hexadecimal without a `0x` prefix** — `1008843` is
/// `0x1008843` = `UP|BROADCAST|RUNNING|SIMPLEX|MULTICAST|LOWER_UP`, and
/// `1008803` is the same minus `RUNNING` (`0x40`, `IFF_DRV_RUNNING`). The
/// names are the authority for [`IfaceFlags::is_running`]; the raw word is
/// kept for the error message an operator will compare against
/// `docs/vxlan.md` §2.
fn parse_iface_flags(stdout: &str) -> Result<IfaceFlags, String> {
    let line = stdout
        .lines()
        .next()
        .ok_or_else(|| "expected at least one line of `ifconfig` output".to_owned())?;
    let (name, rest) = line
        .split_once(": ")
        .ok_or_else(|| format!("expected '<iface>: flags=...' , got {line:?}"))?;
    let flags = rest
        .split_whitespace()
        .find_map(|word| word.strip_prefix("flags="))
        .ok_or_else(|| format!("no flags= field in {line:?}"))?;
    let (raw, names) = flags
        .split_once('<')
        .ok_or_else(|| format!("expected 'flags=<hex><NAMES>', got {flags:?}"))?;
    let names = names
        .strip_suffix('>')
        .ok_or_else(|| format!("unterminated flag name list in {flags:?}"))?;
    let raw = u32::from_str_radix(raw, 16)
        .map_err(|_| format!("flag word {raw:?} is not hexadecimal"))?;
    let mtu = parse_trailing_u32(rest, "mtu").ok_or_else(|| format!("no mtu field in {line:?}"))?;
    Ok(IfaceFlags {
        name: name.to_owned(),
        raw,
        names: names
            .split(',')
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect(),
        mtu,
    })
}

/// The `u32` following `key` in a whitespace-separated line.
fn parse_trailing_u32(line: &str, key: &str) -> Option<u32> {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == key {
            return words.next()?.parse().ok();
        }
    }
    None
}

/// Extract the `description:` value from `ifconfig <iface>` show output.
fn parse_description(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("description: "))
        .map(str::to_owned)
}

/// Parse `vxlan vni 4096 local 127.0.0.1:4789 remote 127.0.0.254:4789` out of
/// show output. `remote :` (no destination) parses to `remote: None`, which is
/// the misconfiguration of `docs/vxlan.md` §2 point 4 — it is data, not a
/// parse error, because the caller has to be able to *report* it.
fn parse_vtep_config(stdout: &str) -> Option<VtepConfig> {
    let line = stdout
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with("vxlan vni "))?;
    let mut words = line.split_whitespace();
    let mut vni = None;
    let mut local = None;
    let mut remote = None;
    while let Some(word) = words.next() {
        match word {
            "vni" => vni = words.next().and_then(|value| value.parse().ok()),
            "local" => local = words.next().and_then(parse_addr_port),
            "remote" | "group" => remote = words.next().and_then(parse_addr_port),
            _ => {}
        }
    }
    Some(VtepConfig {
        vni: vni?,
        local,
        remote,
    })
}

/// `10.2.2.47:4789` → `(10.2.2.47, 4789)`; `:` (the unset form) → `None`.
fn parse_addr_port(text: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr, port) = text.rsplit_once(':')?;
    Some((addr.parse().ok()?, port.parse().unwrap_or(VXLAN_PORT)))
}

/// Parse `ifconfig -g <group>`: one interface name per line; an unknown or
/// empty group prints nothing and exits 0.
fn parse_group_list(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Classify a description against the ownership marker.
fn parse_owned(name: &str, descr: &str, marker: &str) -> Option<OwnedVtep> {
    let prefix = format!("{marker}:");
    let rest = descr.strip_prefix(&prefix)?;
    Some(OwnedVtep {
        name: name.to_owned(),
        descr: descr.to_owned(),
        network: rest.strip_prefix("vxlan:").map(str::to_owned),
    })
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

/// Typed async wrapper around `ifconfig`(8) for VXLAN VTEPs.
///
/// Generic over a [`CommandRunner`] so unit tests can inject a mock executor;
/// production code uses [`Vxlan::system`].
#[derive(Debug, Clone)]
pub struct Vxlan<R = SystemRunner> {
    ifconfig: PathBuf,
    kldload: PathBuf,
    marker: String,
    runner: R,
}

impl Vxlan<SystemRunner> {
    /// Wrapper that executes the real binaries.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Vxlan<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Vxlan<R> {
    /// Wrapper using `runner` to execute commands (test injection point).
    pub fn with_runner(runner: R) -> Self {
        Self {
            ifconfig: PathBuf::from(DEFAULT_IFCONFIG_BINARY),
            kldload: PathBuf::from(DEFAULT_KLDLOAD_BINARY),
            marker: "satl".to_owned(),
            runner,
        }
    }

    /// Override the `ifconfig` binary path.
    #[must_use]
    pub fn with_ifconfig(mut self, binary: impl Into<PathBuf>) -> Self {
        self.ifconfig = binary.into();
        self
    }

    /// Override the `kldload` binary path.
    #[must_use]
    pub fn with_kldload(mut self, binary: impl Into<PathBuf>) -> Self {
        self.kldload = binary.into();
        self
    }

    /// Override the ownership marker (default `satl`), which prefixes every
    /// interface description this wrapper writes and recognizes.
    #[must_use]
    pub fn with_marker(mut self, marker: impl Into<String>) -> Self {
        self.marker = marker.into();
        self
    }

    /// The ownership marker in use.
    #[must_use]
    pub fn marker(&self) -> &str {
        &self.marker
    }

    async fn exec(
        &self,
        binary: &Path,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), VxlanError> {
        let rendered = render_argv(binary, &args);
        tracing::debug!(command = %rendered, "running");
        let output = self
            .runner
            .run(binary, &args)
            .await
            .map_err(|source| VxlanError::Spawn {
                context: context.to_owned(),
                argv: rendered.clone(),
                source,
            })?;
        Ok((rendered, output))
    }

    async fn ifconfig(
        &self,
        context: &str,
        args: Vec<String>,
    ) -> Result<(String, CommandOutput), VxlanError> {
        self.exec(&self.ifconfig, context, args).await
    }

    fn fail(context: &str, argv: String, output: &CommandOutput) -> VxlanError {
        VxlanError::Failed {
            context: context.to_owned(),
            failure: Failure::new(argv, output),
        }
    }

    fn check_name(name: &str) -> Result<(), VxlanError> {
        if name.len() > MAX_IFACE_NAME_LEN {
            return Err(VxlanError::NameTooLong {
                name: name.to_owned(),
                len: name.len(),
            });
        }
        Ok(())
    }

    /// `kldload -n if_vxlan`: load the driver if it is not already loaded.
    /// Idempotent thanks to `-n`.
    ///
    /// `if_vxlan` is **not in the GENERIC kernel** (`docs/vxlan.md` §2). An
    /// earlier version of this comment claimed that without this call every
    /// `create` fails with a confusing `ifconfig: SIOCIFCREATE2` error; that is
    /// **wrong**. `ifmaybeload()` in `sbin/ifconfig/ifconfig.c` derives a module
    /// name from the clone name and loads it, so `ifconfig` does it for us.
    /// Measured with the driver unloaded
    /// (`hack/experiments/jail-arp/captures/50-ifconfig-loads-the-driver.txt`):
    ///
    /// ```text
    /// # kldunload if_vxlan
    /// # ifconfig vxlan create vxlanid 4194299 vxlanlocal 127.0.0.1 ...
    /// vxlan0                                                   (exit 0)
    /// # kldstat -n if_vxlan
    /// 19    1 0xffffffff836f9000     7420 if_vxlan.ko
    /// ```
    ///
    /// So this call is not load-bearing for correctness. It is kept because it
    /// makes the dependency explicit and turns "this kernel has no `if_vxlan` at
    /// all" into a start-up failure with a real error message, instead of a
    /// per-network one at the first `create`.
    pub async fn ensure_module(&self) -> Result<(), VxlanError> {
        let context = format!("load kernel module '{VXLAN_KLD}'");
        let (argv, output) = self
            .exec(&self.kldload, &context, args_kldload(VXLAN_KLD))
            .await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Create a unicast VTEP and rename it to `name`, as one step.
    ///
    /// Two facts make this a single method rather than two: the kernel picks
    /// the clone name and never recycles units, and a crash between create and
    /// rename leaves a `vxlanN` interface with no ownership marker that
    /// reconciliation cannot attribute (`docs/vxlan.md` §2 points 1–2). If the
    /// rename fails the clone is destroyed here.
    ///
    /// The interface is left **down** and unmarked; use [`Self::ensure_vtep`]
    /// for the whole sequence.
    pub async fn create_vtep(&self, spec: &VtepSpec, name: &str) -> Result<VtepIface, VxlanError> {
        spec.validate()?;
        Self::check_name(name)?;
        let context = format!("create VTEP '{name}' (vni {})", spec.vni);
        let (argv, output) = self.ifconfig(&context, args_create(spec)).await?;
        if !output.success() {
            return Err(Self::fail(&context, argv, &output));
        }
        let (clone, unit) =
            parse_clone_name(&output.stdout).map_err(|reason| VxlanError::UnexpectedOutput {
                context: context.clone(),
                argv,
                reason,
                stdout: output.stdout.clone(),
                stderr: output.stderr.clone(),
            })?;
        tracing::debug!(clone = %clone, unit, vni = spec.vni, "created vxlan clone");

        let (argv, output) = self
            .ifconfig(&context, args_rename(&clone, name))
            .await
            .inspect_err(|_| {
                tracing::error!(clone = %clone, name = %name, "rename could not be attempted");
            })?;
        if output.success() {
            tracing::info!(
                iface = %name,
                clone = %clone,
                unit,
                vni = spec.vni,
                local = %spec.local,
                default_remote = %spec.default_remote,
                "created VTEP"
            );
            return Ok(VtepIface {
                name: name.to_owned(),
                unit,
            });
        }
        // The clone exists and carries no marker: destroy it rather than leak
        // an unattributable interface.
        let clone_cleaned = self.destroy_if_exists(&clone).await.unwrap_or(false);
        if stderr_says_name_in_use(&output.stderr) {
            return Err(VxlanError::NameInUse {
                name: name.to_owned(),
                clone,
                clone_cleaned,
                failure: Failure::new(argv, &output),
            });
        }
        tracing::warn!(
            clone = %clone,
            name = %name,
            clone_cleaned,
            "rename failed; discarded the clone"
        );
        Err(Self::fail(&context, argv, &output))
    }

    /// Rename an interface: `ifconfig <from> name <to>`.
    pub async fn rename(&self, from: &str, to: &str) -> Result<(), VxlanError> {
        Self::check_name(to)?;
        let context = format!("rename interface '{from}' to '{to}'");
        let (argv, output) = self.ifconfig(&context, args_rename(from, to)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the MTU: `ifconfig <iface> mtu <mtu>`.
    ///
    /// Doing this **latches `VXLAN_FLAG_USER_MTU`** and the driver stops
    /// recomputing the MTU for the rest of the interface's life
    /// (`docs/vxlan.md` §5) — which is what SatL wants, since the driver's own
    /// arithmetic uses the constant `ETHERMTU` and not the underlay's MTU.
    pub async fn set_mtu(&self, iface: &str, mtu: u32) -> Result<(), VxlanError> {
        let context = format!("set mtu {mtu} on interface '{iface}'");
        let (argv, output) = self.ifconfig(&context, args_set_mtu(iface, mtu)).await?;
        if output.success() {
            tracing::debug!(iface = %iface, mtu, "set overlay MTU");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Bring the interface up: `ifconfig <iface> up`.
    ///
    /// **Exit status means nothing here.** Always follow with
    /// [`Self::verify_running`].
    pub async fn up(&self, iface: &str) -> Result<(), VxlanError> {
        let context = format!("bring interface '{iface}' up");
        let (argv, output) = self.ifconfig(&context, args_up(iface)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Take the interface down: `ifconfig <iface> down`. Static FDB entries
    /// survive a down/up flap (`docs/vxlan.md` §3), so a flap needs no
    /// re-programming.
    pub async fn down(&self, iface: &str) -> Result<(), VxlanError> {
        let context = format!("bring interface '{iface}' down");
        let (argv, output) = self.ifconfig(&context, args_down(iface)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the ownership marker: `ifconfig <iface> description <text>`.
    pub async fn set_descr(&self, iface: &str, text: &str) -> Result<(), VxlanError> {
        let context = format!("set description on interface '{iface}'");
        let (argv, output) = self.ifconfig(&context, args_set_descr(iface, text)).await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Set the per-interface FDB ceiling: `ifconfig <iface> vxlanmaxaddr <n>`.
    ///
    /// `max` must be in `1..=`[`FTABLE_MAX`] — see that constant for why it
    /// cannot be raised past 2000 and why a create-time value above it is
    /// accepted and then ignored. Out-of-range values are rejected here rather
    /// than passed to the kernel, so the caller gets a reason instead of
    /// `Invalid argument`.
    ///
    /// The lower bound is **this wrapper's rule, not the kernel's**: the driver
    /// accepts `vxlanmaxaddr 0` happily. Refusing it here is deliberate, since a
    /// ceiling of zero can only be a caller's arithmetic mistake.
    ///
    /// SatL has no use for this at all with learning off: nothing consults
    /// `ftable_max` on the static-entry path, and `ftable_nospace` never
    /// increments (measured — see [`FTABLE_MAX`]). It exists so that an operator
    /// diagnosing an adopted interface can put the value back.
    pub async fn set_ftable_max(&self, iface: &str, max: u32) -> Result<(), VxlanError> {
        if max == 0 || max > FTABLE_MAX {
            return Err(VxlanError::InvalidSpec {
                reason: format!(
                    "vxlanmaxaddr {max} is outside 1..={FTABLE_MAX}: the driver's \
                     VXLAN_FTABLE_MAX is a hard ceiling (EINVAL above it), and 0 \
                     would leave the interface unable to hold any entry"
                ),
            });
        }
        let context = format!("set vxlanmaxaddr {max} on interface '{iface}'");
        let (argv, output) = self
            .ifconfig(&context, args_set_ftable_max(iface, max))
            .await?;
        if output.success() {
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// `ifconfig <iface> vxlanflushall`: drop **every** FDB entry, static
    /// included (plain `vxlanflush` only drops dynamic ones, and SatL has
    /// none). The way to reach a known-empty FDB when the programmed state
    /// cannot be read back.
    pub async fn flush_ftable(&self, iface: &str) -> Result<(), VxlanError> {
        let context = format!("flush all FDB entries of interface '{iface}'");
        let (argv, output) = self.ifconfig(&context, args_flush_all(iface)).await?;
        if output.success() {
            tracing::info!(iface = %iface, "flushed the whole VXLAN FDB");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Destroy the interface: `ifconfig <iface> destroy`. Takes its FDB with
    /// it, so a destroy/create cycle needs a full re-push
    /// (`docs/vxlan.md` §3).
    pub async fn destroy(&self, iface: &str) -> Result<(), VxlanError> {
        let context = format!("destroy interface '{iface}'");
        let (argv, output) = self.ifconfig(&context, args_destroy(iface)).await?;
        if output.success() {
            tracing::info!(iface = %iface, "destroyed VTEP");
            return Ok(());
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Destroy `iface` if it exists; `Ok(false)` when it was already gone.
    pub async fn destroy_if_exists(&self, iface: &str) -> Result<bool, VxlanError> {
        let context = format!("destroy interface '{iface}' (if it exists)");
        let (argv, output) = self.ifconfig(&context, args_destroy(iface)).await?;
        if output.success() {
            tracing::info!(iface = %iface, "destroyed VTEP");
            return Ok(true);
        }
        if output.exit_code == Some(1) && stderr_says_iface_missing(&output.stderr) {
            return Ok(false);
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// Raw `ifconfig <iface>` output, or `Ok(None)` when the interface is
    /// gone (which races with teardown all the time).
    async fn show(&self, context: &str, iface: &str) -> Result<Option<String>, VxlanError> {
        let (argv, output) = self.ifconfig(context, args_show(iface)).await?;
        if output.success() {
            return Ok(Some(output.stdout));
        }
        if output.exit_code == Some(1) && stderr_says_iface_missing(&output.stderr) {
            return Ok(None);
        }
        Err(Self::fail(context, argv, &output))
    }

    /// Whether `iface` exists.
    pub async fn exists(&self, iface: &str) -> Result<bool, VxlanError> {
        let context = format!("probe interface '{iface}'");
        Ok(self.show(&context, iface).await?.is_some())
    }

    /// The flag word and MTU of `iface`.
    pub async fn flags(&self, iface: &str) -> Result<IfaceFlags, VxlanError> {
        let context = format!("read flags of interface '{iface}'");
        let stdout = self
            .show(&context, iface)
            .await?
            .ok_or_else(|| VxlanError::NoSuchIface {
                context: context.clone(),
                iface: iface.to_owned(),
            })?;
        parse_iface_flags(&stdout).map_err(|reason| VxlanError::UnexpectedOutput {
            context,
            argv: render_argv(&self.ifconfig, &args_show(iface)),
            reason,
            stdout,
            stderr: String::new(),
        })
    }

    /// **The health check.** `Ok(())` only when the flag word contains
    /// `RUNNING`; otherwise [`VxlanError::NotRunning`], whose message points
    /// at `/var/log/messages` and names both kernel diagnostics that produce
    /// this state.
    ///
    /// Must be called after every `up`. Note that programming an FDB entry is
    /// *not* a health check: it succeeds on a dead interface, because the
    /// kernel only needs the destination address family and not a working
    /// socket (`docs/vxlan.md` §2 point 5).
    pub async fn verify_running(&self, iface: &str) -> Result<IfaceFlags, VxlanError> {
        let flags = self.flags(iface).await?;
        if flags.is_running() {
            tracing::debug!(iface = %iface, flags = %flags.rendered(), "VTEP is RUNNING");
            return Ok(flags);
        }
        tracing::error!(
            iface = %iface,
            flags = %flags.rendered(),
            "VTEP is UP but not RUNNING; the driver refused it, so read /var/log/messages"
        );
        Err(VxlanError::NotRunning {
            iface: iface.to_owned(),
            flags: flags.rendered(),
        })
    }

    /// The `vxlan vni/local/remote` configuration of `iface`, parsed from show
    /// output; `Ok(None)` when the interface is not a vxlan interface (no such
    /// line) or does not exist.
    pub async fn vtep_config(&self, iface: &str) -> Result<Option<VtepConfig>, VxlanError> {
        let context = format!("read VTEP configuration of interface '{iface}'");
        Ok(self
            .show(&context, iface)
            .await?
            .as_deref()
            .and_then(parse_vtep_config))
    }

    /// The description of `iface`; `Ok(None)` when unset or the interface is
    /// gone.
    pub async fn descr(&self, iface: &str) -> Result<Option<String>, VxlanError> {
        let context = format!("read description of interface '{iface}'");
        Ok(self
            .show(&context, iface)
            .await?
            .as_deref()
            .and_then(parse_description))
    }

    /// Every vxlan interface on the host: `ifconfig -g vxlan`. The driver puts
    /// them in that group itself, so this needs no cooperation from SatL and
    /// finds interfaces from a previous, crashed daemon too.
    pub async fn list_vxlan(&self) -> Result<Vec<String>, VxlanError> {
        let context = format!("list interface group '{VXLAN_GROUP}'");
        let (argv, output) = self
            .ifconfig(&context, args_list_group(VXLAN_GROUP))
            .await?;
        if output.success() {
            return Ok(parse_group_list(&output.stdout));
        }
        Err(Self::fail(&context, argv, &output))
    }

    /// The vxlan interfaces carrying SatL's ownership marker — the startup
    /// reconciliation sweep.
    ///
    /// A vxlan interface *without* the marker is deliberately not returned:
    /// SatL never destroys an interface it cannot prove is its own. Such
    /// interfaces are logged at `warn` so an operator sees an un-renamed clone
    /// from an interrupted `create` (which is also what
    /// [`Self::create_vtep`]'s cleanup path exists to prevent).
    pub async fn list_owned(&self) -> Result<Vec<OwnedVtep>, VxlanError> {
        let mut owned = Vec::new();
        for name in self.list_vxlan().await? {
            let context = format!("read description of interface '{name}'");
            // The interface can vanish between listing and probing.
            let Some(stdout) = self.show(&context, &name).await? else {
                continue;
            };
            let Some(descr) = parse_description(&stdout) else {
                tracing::warn!(
                    iface = %name,
                    "vxlan interface with no description: not SatL's, or an \
                     un-renamed clone from an interrupted create"
                );
                continue;
            };
            if let Some(entry) = parse_owned(&name, &descr, &self.marker) {
                owned.push(entry);
            } else {
                tracing::debug!(
                    iface = %name,
                    descr = %descr,
                    "vxlan interface described by someone else; left alone"
                );
            }
        }
        owned.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(owned)
    }

    /// Bring a VTEP for `network` to the desired state, idempotently: create
    /// it if absent, adopt it if it already matches, then mark it, set the
    /// MTU, bring it up and **verify `RUNNING`**.
    ///
    /// Adoption is deliberately strict: an existing interface whose VNI, local
    /// address or default remote differs is [`VxlanError::SpecMismatch`]
    /// rather than silently reconfigured, because changing a live VTEP's VNI
    /// blackholes every task attached to it. The returned [`VtepIface`] has
    /// the clone unit only when this call created the interface — on adoption
    /// the unit is unknowable from the name (`docs/vxlan.md` §2 point 3) and
    /// [`crate::ftable::Ftable::resolve_unit`] has to probe for it.
    pub async fn ensure_vtep(
        &self,
        spec: &VtepSpec,
        name: &str,
        network: &str,
    ) -> Result<Option<VtepIface>, VxlanError> {
        spec.validate()?;
        Self::check_name(name)?;
        let created = if self.exists(name).await? {
            self.check_adoptable(spec, name).await?;
            tracing::info!(iface = %name, network = %network, "adopted existing VTEP");
            None
        } else {
            Some(self.create_vtep(spec, name).await?)
        };
        self.set_descr(name, &vtep_descr(&self.marker, network))
            .await?;
        self.set_mtu(name, spec.mtu).await?;
        self.up(name).await?;
        self.verify_running(name).await?;
        Ok(created)
    }

    async fn check_adoptable(&self, spec: &VtepSpec, name: &str) -> Result<(), VxlanError> {
        let Some(config) = self.vtep_config(name).await? else {
            return Err(VxlanError::SpecMismatch {
                iface: name.to_owned(),
                mismatch: "the interface exists but is not a vxlan interface".to_owned(),
            });
        };
        let mut mismatches = Vec::new();
        if config.vni != spec.vni {
            mismatches.push(format!("vni {} != requested {}", config.vni, spec.vni));
        }
        // The port is part of the configuration: an encrypted network's VTEP
        // must listen on the network's allocator-assigned port, and a
        // cleartext one on the default 4789. Adopting an interface on the
        // wrong port would put its traffic outside the SP selectors.
        let want_port = spec.vxlan_port.unwrap_or(VXLAN_PORT);
        match config.local {
            Some((addr, port)) if addr == spec.local && port == want_port => {}
            Some((addr, port)) if addr == spec.local => {
                mismatches.push(format!("vxlanlocal port {port} != requested {want_port}"));
            }
            Some((addr, _)) => {
                mismatches.push(format!("vxlanlocal {addr} != requested {}", spec.local));
            }
            None => mismatches.push("vxlanlocal is unset".to_owned()),
        }
        match config.remote {
            Some((addr, port)) if addr == spec.default_remote && port == want_port => {}
            Some((addr, port)) if addr == spec.default_remote => {
                mismatches.push(format!("vxlanremote port {port} != requested {want_port}"));
            }
            Some((addr, _)) => mismatches.push(format!(
                "vxlanremote {addr} != requested {}",
                spec.default_remote
            )),
            None => mismatches.push(
                "vxlanremote is unset, so the driver never initialized this \
                 interface (docs/vxlan.md section 2)"
                    .to_owned(),
            ),
        }
        if mismatches.is_empty() {
            return Ok(());
        }
        Err(VxlanError::SpecMismatch {
            iface: name.to_owned(),
            mismatch: mismatches.join("; "),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    const FIXTURE_CREATE: &str = include_str!("../tests/fixtures/vxlan_create.txt");
    const FIXTURE_SHOW_RUNNING: &str = include_str!("../tests/fixtures/vxlan_show_running.txt");
    const FIXTURE_SHOW_NOT_RUNNING: &str =
        include_str!("../tests/fixtures/vxlan_show_not_running.txt");
    const FIXTURE_SHOW_NO_REMOTE: &str = include_str!("../tests/fixtures/vxlan_show_no_remote.txt");
    const FIXTURE_LIST_GROUP: &str = include_str!("../tests/fixtures/vxlan_list_group.txt");
    const FIXTURE_MISSING: &str = include_str!("../tests/fixtures/vxlan_missing_iface.txt");
    const FIXTURE_RENAME_CONFLICT: &str =
        include_str!("../tests/fixtures/vxlan_rename_conflict_stderr.txt");

    fn spec() -> VtepSpec {
        VtepSpec::new(
            4096,
            Ipv4Addr::new(10, 2, 2, 47),
            Ipv4Addr::new(10, 2, 255, 254),
        )
    }

    // ---- constants and pure arithmetic --------------------------------------

    #[test]
    fn overlay_mtu_is_underlay_minus_fifty() {
        assert_eq!(overlay_mtu_v4(1500), 1450);
        assert_eq!(DEFAULT_OVERLAY_MTU, 1450);
        assert_eq!(overlay_mtu_v4(9000), 8950);
        assert_eq!(overlay_mtu_v6(1500), 1430);
        // Saturating, not wrapping: a bogus measurement yields 0, which
        // VtepSpec::validate then rejects.
        assert_eq!(overlay_mtu_v4(10), 0);
    }

    #[test]
    fn encrypted_overlay_mtu_is_underlay_minus_84() {
        // 50 VXLAN (incl. inner Ethernet) + 34 ESP transport mode
        // (SPI+seq 8 + IV 8 + pad-len/next 2 + ICV 16), measured in
        // hack/experiments/esp/README.md section 4: inner IP 1416 yields
        // outer exactly 1500, 1417 fragments.
        assert_eq!(ESP_TRANSPORT_OVERHEAD, 34);
        assert_eq!(VXLAN_ESP_ENCAP_OVERHEAD_V4, 84);
        assert_eq!(overlay_mtu_v4_encrypted(1500), 1416);
        assert_eq!(DEFAULT_OVERLAY_MTU_ENCRYPTED, 1416);
        // Saturating, like the cleartext variant.
        assert_eq!(overlay_mtu_v4_encrypted(10), 0);
    }

    #[test]
    fn vtep_names_fit_ifnamsiz() {
        assert_eq!(vtep_iface_name(4096), "satl-vx4096");
        // The largest 24-bit VNI still fits IFNAMSIZ - 1.
        let widest = vtep_iface_name(VNI_MAX);
        assert_eq!(widest, "satl-vx16777215");
        assert_eq!(widest.len(), MAX_IFACE_NAME_LEN);
    }

    #[test]
    fn descr_marks_ownership() {
        assert_eq!(vtep_descr("satl", "mynet"), "satl:vxlan:mynet");
    }

    #[test]
    fn spec_validation_rejects_what_the_kernel_would() {
        assert!(spec().validate().is_ok());
        let bad = |spec: VtepSpec| spec.validate().unwrap_err().to_string();
        let mut s = spec();
        s.vni = VNI_MAX + 1;
        assert!(bad(s).contains("24-bit"));
        let mut s = spec();
        s.default_remote = Ipv4Addr::UNSPECIFIED;
        assert!(bad(s).contains("vxlanremote"));
        let mut s = spec();
        s.default_remote = Ipv4Addr::new(239, 99, 0, 1);
        assert!(bad(s).contains("vxlanremote"));
        let mut s = spec();
        s.default_remote = s.local;
        assert!(bad(s).contains("equals vxlanlocal"));
        let mut s = spec();
        s.local = Ipv4Addr::UNSPECIFIED;
        assert!(bad(s).contains("vxlanlocal"));
        let mut s = spec();
        s.mtu = 10;
        assert!(bad(s).contains("ETHERMIN"));
    }

    #[tokio::test]
    async fn set_ftable_max_refuses_out_of_range_without_executing_anything() {
        let mock = MockRunner::new();
        let vxlan = Vxlan::with_runner(&mock);
        for value in [0, FTABLE_MAX + 1, 8000] {
            let err = vxlan
                .set_ftable_max("satl-vx4096", value)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("hard ceiling"), "{value}: {err}");
        }
        assert!(
            mock.calls().is_empty(),
            "the kernel's bare EINVAL is never worth surfacing: {:?}",
            mock.calls()
        );
        mock.push_ok();
        vxlan
            .set_ftable_max("satl-vx4096", FTABLE_MAX)
            .await
            .unwrap();
    }

    // ---- argv builders -----------------------------------------------------

    #[test]
    fn argv_builders() {
        assert_eq!(
            args_create(&spec()),
            [
                "vxlan",
                "create",
                "vxlanid",
                "4096",
                "vxlanlocal",
                "10.2.2.47",
                "vxlanremote",
                "10.2.255.254",
                "-vxlanlearn",
            ]
        );
        assert_eq!(
            args_rename("vxlan0", "satl-vx4096"),
            ["vxlan0", "name", "satl-vx4096"]
        );
        assert_eq!(args_show("satl-vx4096"), ["satl-vx4096"]);
        assert_eq!(args_destroy("satl-vx4096"), ["satl-vx4096", "destroy"]);
        assert_eq!(args_up("satl-vx4096"), ["satl-vx4096", "up"]);
        assert_eq!(args_down("satl-vx4096"), ["satl-vx4096", "down"]);
        assert_eq!(
            args_set_mtu("satl-vx4096", 1450),
            ["satl-vx4096", "mtu", "1450"]
        );
        assert_eq!(
            args_set_descr("satl-vx4096", "satl:vxlan:mynet"),
            ["satl-vx4096", "description", "satl:vxlan:mynet"]
        );
        assert_eq!(args_list_group("vxlan"), ["-g", "vxlan"]);
        assert_eq!(
            args_flush_all("satl-vx4096"),
            ["satl-vx4096", "vxlanflushall"]
        );
        assert_eq!(
            args_set_ftable_max("satl-vx4096", 1000),
            ["satl-vx4096", "vxlanmaxaddr", "1000"]
        );
        assert_eq!(args_kldload("if_vxlan"), ["-n", "if_vxlan"]);
    }

    #[test]
    fn args_create_with_a_custom_port_renders_both_port_parameters() {
        // The measured parameter names on 15.1 are vxlanlocalport /
        // vxlanremoteport; `vxlanport` does not exist
        // (hack/experiments/esp/README.md section 1).
        assert_eq!(
            args_create(&spec().with_vxlan_port(4790)),
            [
                "vxlan",
                "create",
                "vxlanid",
                "4096",
                "vxlanlocal",
                "10.2.2.47",
                "vxlanremote",
                "10.2.255.254",
                "vxlanlocalport",
                "4790",
                "vxlanremoteport",
                "4790",
                "-vxlanlearn",
            ]
        );
    }

    // ---- parsers against real captured fixtures ----------------------------

    #[test]
    fn parse_clone_name_reads_the_unit() {
        assert_eq!(
            parse_clone_name(FIXTURE_CREATE).unwrap(),
            ("vxlan0".to_owned(), 0)
        );
        assert_eq!(
            parse_clone_name("vxlan17\n").unwrap(),
            ("vxlan17".to_owned(), 17)
        );
        for bad in ["", "bridge0\n", "vxlan\n", "vxlanX\n", "vxlan0\nvxlan1\n"] {
            assert!(parse_clone_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn healthy_flag_word_has_running() {
        let flags = parse_iface_flags(FIXTURE_SHOW_RUNNING).unwrap();
        assert_eq!(flags.name, "satl-vx4096");
        // ifconfig prints the flag word in hex without a prefix: the healthy
        // 1008843 of docs/vxlan.md §2 is 0x1008843.
        assert_eq!(flags.raw, 0x0100_8843);
        assert!(flags.is_up());
        assert!(flags.is_running());
        assert_eq!(flags.mtu, 1450);
        assert!(
            flags
                .rendered()
                .starts_with("1008843<UP,BROADCAST,RUNNING,")
        );
    }

    #[test]
    fn duplicate_vni_flag_word_has_no_running() {
        let flags = parse_iface_flags(FIXTURE_SHOW_NOT_RUNNING).unwrap();
        assert_eq!(flags.raw, 0x0100_8803);
        assert!(
            flags.is_up(),
            "the interface still reports UP — that is the trap"
        );
        assert!(!flags.is_running());
        assert_eq!(flags.mtu, 1450);
        // The one differing bit is IFF_DRV_RUNNING.
        assert_eq!(0x0100_8843 - flags.raw, 0x40);
    }

    #[test]
    fn remoteless_interface_shows_1470_and_no_running() {
        let flags = parse_iface_flags(FIXTURE_SHOW_NO_REMOTE).unwrap();
        assert!(!flags.is_running());
        // 1500 - 30: with no destination the driver cannot know whether to
        // reserve 20 bytes for IPv4 or 40 for IPv6 (docs/vxlan.md §1).
        assert_eq!(flags.mtu, 1470);
    }

    #[test]
    fn parse_iface_flags_rejects_garbage() {
        for bad in [
            "",
            "satl-vx4096 flags=1008843<UP>\n",
            "satl-vx4096: metric 0 mtu 1450\n",
            "satl-vx4096: flags=1008843UP metric 0 mtu 1450\n",
            "satl-vx4096: flags=zzz<UP> metric 0 mtu 1450\n",
            "satl-vx4096: flags=1008843<UP metric 0 mtu 1450\n",
            "satl-vx4096: flags=1008843<UP> metric 0\n",
        ] {
            assert!(
                parse_iface_flags(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn parse_vtep_config_from_show_output() {
        let config = parse_vtep_config(FIXTURE_SHOW_RUNNING).unwrap();
        assert_eq!(config.vni, 4096);
        assert_eq!(config.local, Some((Ipv4Addr::LOCALHOST, 4789)));
        assert_eq!(config.remote, Some((Ipv4Addr::new(127, 0, 0, 254), 4789)));
    }

    #[test]
    fn remoteless_config_parses_to_none() {
        // `remote :` is data, not a parse error: the caller has to report it.
        let config = parse_vtep_config(FIXTURE_SHOW_NO_REMOTE).unwrap();
        assert_eq!(config.vni, 4098);
        assert_eq!(config.local, Some((Ipv4Addr::LOCALHOST, 4789)));
        assert_eq!(config.remote, None);
    }

    #[test]
    fn parse_vtep_config_absent_on_a_non_vxlan_interface() {
        assert!(parse_vtep_config("lo0: flags=8049<UP> metric 0 mtu 16384\n").is_none());
    }

    #[test]
    fn parse_description_and_group_list() {
        assert_eq!(
            parse_description(FIXTURE_SHOW_RUNNING).as_deref(),
            Some("satl:vxlan:ovtestnet")
        );
        assert_eq!(parse_description(FIXTURE_SHOW_NO_REMOTE), None);
        assert_eq!(
            parse_group_list(FIXTURE_LIST_GROUP),
            ["satl-vx4096", "satl-vx-dup", "satl-vx-norem"]
        );
        assert!(parse_group_list("").is_empty());
    }

    #[test]
    fn ownership_is_decided_by_the_description() {
        assert_eq!(
            parse_owned("satl-vx4096", "satl:vxlan:mynet", "satl"),
            Some(OwnedVtep {
                name: "satl-vx4096".to_owned(),
                descr: "satl:vxlan:mynet".to_owned(),
                network: Some("mynet".to_owned()),
            })
        );
        // A marker we own but a shape we do not recognize: still ours.
        assert_eq!(
            parse_owned("satl-vx1", "satl:something-else", "satl")
                .unwrap()
                .network,
            None
        );
        // Someone else's interface: never ours to touch.
        assert!(parse_owned("vxlan0", "not-satl:vxlan:mynet", "satl").is_none());
        assert!(parse_owned("vxlan0", "", "satl").is_none());
    }

    #[test]
    fn error_stderr_classifiers() {
        assert!(stderr_says_iface_missing(FIXTURE_MISSING));
        assert!(!stderr_says_iface_missing(FIXTURE_RENAME_CONFLICT));
        assert!(stderr_says_name_in_use(FIXTURE_RENAME_CONFLICT));
        assert!(!stderr_says_name_in_use(FIXTURE_MISSING));
    }

    // ---- wrapper behavior with the mock runner -----------------------------

    #[tokio::test]
    async fn create_vtep_with_a_custom_port_passes_vxlanlocalport_and_vxlanremoteport() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_CREATE, "");
        mock.push_output(0, "satl-vx9999\n", "");
        let vxlan = Vxlan::with_runner(&mock);
        let spec = VtepSpec::new(
            9999,
            Ipv4Addr::new(10, 2, 2, 47),
            Ipv4Addr::new(10, 2, 255, 254),
        )
        .with_vxlan_port(4790);
        let iface = vxlan.create_vtep(&spec, "satl-vx9999").await.unwrap();
        assert_eq!(iface.name, "satl-vx9999");
        assert_eq!(
            mock.calls()[0],
            "/sbin/ifconfig vxlan create vxlanid 9999 vxlanlocal 10.2.2.47 \
             vxlanremote 10.2.255.254 vxlanlocalport 4790 vxlanremoteport 4790 -vxlanlearn"
        );
    }

    #[tokio::test]
    async fn ensure_vtep_refuses_to_adopt_an_interface_on_a_different_port() {
        // The fixture interface listens on the default 4789; the spec wants
        // the encrypted network's allocator-assigned 4790.
        let spec = VtepSpec::new(4096, Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 254))
            .with_vxlan_port(4790);
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // exists
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // vtep_config
        let vxlan = Vxlan::with_runner(&mock);
        let err = vxlan
            .ensure_vtep(&spec, "satl-vx4096", "encnet")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, VxlanError::SpecMismatch { .. }), "{err:?}");
        assert!(text.contains("port"), "{text}");
        assert!(text.contains("4789"), "{text}");
        assert!(text.contains("4790"), "{text}");
    }

    #[tokio::test]
    async fn create_vtep_creates_then_renames() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_CREATE, "");
        mock.push_output(0, "satl-vx4096\n", "");
        let vxlan = Vxlan::with_runner(&mock);
        let iface = vxlan.create_vtep(&spec(), "satl-vx4096").await.unwrap();
        assert_eq!(iface.name, "satl-vx4096");
        assert_eq!(iface.unit, 0);
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig vxlan create vxlanid 4096 vxlanlocal 10.2.2.47 \
                 vxlanremote 10.2.255.254 -vxlanlearn",
                "/sbin/ifconfig vxlan0 name satl-vx4096",
            ]
        );
    }

    #[tokio::test]
    async fn create_vtep_destroys_the_clone_when_the_rename_fails() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_CREATE, "");
        mock.push_output(1, "", FIXTURE_RENAME_CONFLICT);
        mock.push_ok(); // destroy vxlan0
        let vxlan = Vxlan::with_runner(&mock);
        let err = vxlan.create_vtep(&spec(), "satl-vx4096").await.unwrap_err();
        match &err {
            VxlanError::NameInUse {
                name,
                clone,
                clone_cleaned,
                ..
            } => {
                assert_eq!(name, "satl-vx4096");
                assert_eq!(clone, "vxlan0");
                assert!(clone_cleaned, "the unattributable clone must be destroyed");
            }
            other => panic!("expected NameInUse, got {other:?}"),
        }
        assert_eq!(mock.calls().len(), 3);
        assert_eq!(mock.calls()[2], "/sbin/ifconfig vxlan0 destroy");
    }

    #[tokio::test]
    async fn create_vtep_rejects_a_too_long_name_without_executing_anything() {
        let mock = MockRunner::new();
        let vxlan = Vxlan::with_runner(&mock);
        let err = vxlan
            .create_vtep(&spec(), "satl-vx-a-very-long-name")
            .await
            .unwrap_err();
        assert!(matches!(err, VxlanError::NameTooLong { .. }), "{err:?}");
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn verify_running_accepts_the_healthy_interface() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_RUNNING, "");
        let vxlan = Vxlan::with_runner(&mock);
        let flags = vxlan.verify_running("satl-vx4096").await.unwrap();
        assert!(flags.is_running());
    }

    #[tokio::test]
    async fn verify_running_rejects_up_but_not_running_and_names_the_log() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_NOT_RUNNING, "");
        let vxlan = Vxlan::with_runner(&mock);
        let err = vxlan.verify_running("satl-vx-dup").await.unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, VxlanError::NotRunning { .. }), "{err:?}");
        assert!(text.contains("UP but not RUNNING"), "{text}");
        assert!(text.contains("/var/log/messages"), "{text}");
        assert!(text.contains("already exists in this socket"), "{text}");
        assert!(text.contains("1008803"), "{text}");
    }

    #[tokio::test]
    async fn destroy_if_exists_maps_missing_to_false() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MISSING);
        let vxlan = Vxlan::with_runner(&mock);
        assert!(!vxlan.destroy_if_exists("satl-vx-nope").await.unwrap());
    }

    #[tokio::test]
    async fn destroy_error_carries_argv_status_and_stderr() {
        let mock = MockRunner::new();
        mock.push_output(1, "", "ifconfig: SIOCIFDESTROY: Device busy\n");
        let vxlan = Vxlan::with_runner(&mock);
        let err = vxlan.destroy("satl-vx4096").await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("destroy interface 'satl-vx4096'"), "{text}");
        assert!(
            text.contains("/sbin/ifconfig satl-vx4096 destroy"),
            "{text}"
        );
        assert!(text.contains("exit code 1"), "{text}");
        assert!(text.contains("Device busy"), "{text}");
    }

    #[tokio::test]
    async fn list_owned_skips_undescribed_and_foreign_interfaces() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_GROUP, "");
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // satl-vx4096, ours
        mock.push_output(0, FIXTURE_SHOW_NOT_RUNNING, ""); // satl-vx-dup, ours
        mock.push_output(0, FIXTURE_SHOW_NO_REMOTE, ""); // no description
        let vxlan = Vxlan::with_runner(&mock);
        let owned = vxlan.list_owned().await.unwrap();
        assert_eq!(
            owned
                .iter()
                .map(|entry| (entry.name.as_str(), entry.network.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("satl-vx-dup", Some("dupnet")),
                ("satl-vx4096", Some("ovtestnet")),
            ]
        );
    }

    #[tokio::test]
    async fn list_owned_tolerates_an_interface_vanishing_mid_sweep() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_LIST_GROUP, "");
        mock.push_output(0, FIXTURE_SHOW_RUNNING, "");
        mock.push_output(1, "", FIXTURE_MISSING); // torn down under us
        mock.push_output(1, "", FIXTURE_MISSING);
        let vxlan = Vxlan::with_runner(&mock);
        let owned = vxlan.list_owned().await.unwrap();
        assert_eq!(owned.len(), 1);
    }

    #[tokio::test]
    async fn ensure_vtep_creates_marks_sets_mtu_ups_and_verifies() {
        let mock = MockRunner::new();
        mock.push_output(1, "", FIXTURE_MISSING); // exists? no
        mock.push_output(0, FIXTURE_CREATE, ""); // create
        mock.push_output(0, "satl-vx4096\n", ""); // rename
        mock.push_ok(); // description
        mock.push_ok(); // mtu
        mock.push_ok(); // up
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // verify RUNNING
        let vxlan = Vxlan::with_runner(&mock);
        let created = vxlan
            .ensure_vtep(&spec(), "satl-vx4096", "ovtestnet")
            .await
            .unwrap();
        assert_eq!(created.unwrap().unit, 0);
        assert_eq!(
            mock.calls()[3..],
            [
                "/sbin/ifconfig satl-vx4096 description satl:vxlan:ovtestnet",
                "/sbin/ifconfig satl-vx4096 mtu 1450",
                "/sbin/ifconfig satl-vx4096 up",
                "/sbin/ifconfig satl-vx4096",
            ]
        );
    }

    #[tokio::test]
    async fn ensure_vtep_adopts_a_matching_interface_without_creating() {
        // The fixture is vni 4096 local 127.0.0.1 remote 127.0.0.254.
        let spec = VtepSpec::new(4096, Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 254));
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // exists
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // vtep_config
        mock.push_ok(); // description
        mock.push_ok(); // mtu
        mock.push_ok(); // up
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // verify
        let vxlan = Vxlan::with_runner(&mock);
        let created = vxlan
            .ensure_vtep(&spec, "satl-vx4096", "ovtestnet")
            .await
            .unwrap();
        assert!(created.is_none(), "adoption cannot know the clone unit");
        assert!(
            !mock.calls().iter().any(|call| call.contains("create")),
            "{:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn ensure_vtep_refuses_to_adopt_a_different_configuration() {
        let mock = MockRunner::new();
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // exists
        mock.push_output(0, FIXTURE_SHOW_RUNNING, ""); // vni 4096 local 127.0.0.1
        let vxlan = Vxlan::with_runner(&mock);
        // spec() wants local 10.2.2.47 and remote 10.2.255.254.
        let err = vxlan
            .ensure_vtep(&spec(), "satl-vx4096", "ovtestnet")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, VxlanError::SpecMismatch { .. }), "{err:?}");
        assert!(text.contains("vxlanlocal 127.0.0.1"), "{text}");
        assert!(text.contains("vxlanremote 127.0.0.254"), "{text}");
    }

    #[tokio::test]
    async fn spawn_failure_reports_argv_and_context() {
        let mock = MockRunner::new();
        mock.push_spawn_error(std::io::ErrorKind::NotFound, "no such file");
        let vxlan = Vxlan::with_runner(&mock).with_ifconfig("/nonexistent/ifconfig");
        let err = vxlan.up("satl-vx4096").await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("/nonexistent/ifconfig satl-vx4096 up"),
            "{text}"
        );
        assert!(text.contains("no such file"), "{text}");
    }

    #[tokio::test]
    async fn ensure_module_uses_dash_n_so_it_is_idempotent() {
        let mock = MockRunner::new();
        mock.push_ok();
        let vxlan = Vxlan::with_runner(&mock);
        vxlan.ensure_module().await.unwrap();
        assert_eq!(mock.calls(), ["/sbin/kldload -n if_vxlan"]);
    }
}
