// SPDX-License-Identifier: BSD-2-Clause
//! The node-local half of a cluster **overlay** network: one bridge per
//! network with the network's VTEP as a member, this node's overlay gateway
//! address on it, and one epair per local task (architecture §11.2,
//! implementation facts in `docs/vxlan.md` §4, §5, §8).
//!
//! ```text
//!  satl-vx<vni>  (vxlan, mtu = underlay − 50)   ← created and owned by satl-overlay
//!       │                                          (this module only consumes its name)
//!  satl-br<vni> (bridge, mtu set explicitly, carries THIS node's gateway)
//!       │
//!  epairNa (member, mtu from the bridge) ── epairNb  in the task's VNET jail
//!                                            mtu set explicitly, ether mac(ip)
//! ```
//!
//! Four things separate this from [`crate::manager`]'s node-local bridge, and
//! each of them is a silent failure when it is missed:
//!
//! 1. **The VTEP belongs to `satl-overlay`.** Its name arrives as
//!    [`OverlaySegment::vtep`]; nothing here creates, renames, `up`s or
//!    destroys a vxlan interface. It *is* read back, because a VTEP the driver
//!    refused still reports `UP` and still exits 0 — `RUNNING` is the only
//!    health signal (`docs/vxlan.md` §2 point 5), and bridging a dead VTEP
//!    yields an overlay that passes every local test and carries nothing.
//!    The dependency direction is fixed by `docs/architecture.md` §2, which
//!    allows `satl-overlay → satl-net` and therefore forbids the reverse: the
//!    VTEP name, and the overlay MTU, are **parameters**, never imports.
//! 2. **The gateway is per node.** [`satl_core::Network::node_gateways`] holds
//!    one address per participating node because every node's bridge is on one
//!    L2 segment: a shared gateway address is a duplicate address, and the ARP
//!    race decides whose responder answers *and* whose host receives the other
//!    node's egress traffic (`docs/vxlan.md` §8, measured). `.1` of the subnet
//!    is reserved and belongs to nobody, so [`OverlaySegment::validate`]
//!    rejects it as this node's gateway.
//! 3. **The MTU is explicit in two places.** `man 4 bridge`: the bridge's MTU
//!    propagates to every member, so the bridge covers the VTEP and the epair
//!    `a` ends. The `b` end inside the jail is **not** a member and nothing
//!    propagates to it — it is the end the container's TCP MSS comes from, and
//!    a forgotten −50 there passes every functional test while splitting every
//!    full-size frame in two (`docs/vxlan.md` §6 case B: works, byte-exact,
//!    twice the packets, loss amplified, invisible in throughput). It is set
//!    explicitly on both ends and **read back** on both.
//!    Measured while writing this module: a bridge member's MTU cannot be set
//!    at all (`SIOCSIFMTU: Operation not supported`, even to the value it
//!    already has), so the epair MTUs are set *before* `addm`.
//! 4. **The MAC is derived, not kernel-assigned.**
//!    [`satl_core::MacAddr::from_ipv4`] (`02:42:` + the four IPv4 octets) is a
//!    wire format: unicast VXLAN never floods, so both ends of the cluster
//!    compute a peer's MAC from store state alone to program static FDB and
//!    ARP entries. It is set on the jail-side end before the `vnet` move (it
//!    survives the move) and read back inside the jail — and **on the bridge
//!    itself** (M6d), whose derived MAC is the one of this node's gateway
//!    address: the mesh put gateways in jails' ARP tables, and a reply to a
//!    gateway whose bridge kept its kernel-assigned MAC goes nowhere
//!    (measured on the cluster).
//!
//! Ownership follows `docs/networking.md` — the interface **description** is
//! the marker, because it survives the `vnet` move and the jail's death while
//! interface groups do not. The grammar is in [`crate::manager`]'s docs; the
//! rows that matter here are `<group>:overlay:<net>` on the bridge,
//! `<group>:overlay:<net>:<task-id>` on both epair ends, and
//! `<group>:vxlan:<net>` on the VTEP — the last of which is classified
//! ([`OwnedKind::Vtep`]) only so that no teardown path here can touch it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;

use satl_core::{Ipv4Cidr, MacAddr};

use crate::ifconfig::{EpairPair, IfaceState, IfconfigError, MAX_IFACE_NAME_LEN};
use crate::manager::{AttachStep, NetError, NetworkManager, OwnedKind, classify_marker};
use crate::runner::CommandRunner;

/// Marker segment identifying an overlay bridge or attachment.
pub const OVERLAY_MARKER: &str = "overlay";

/// Marker segment identifying a VTEP — `satl-overlay`'s interface, listed here
/// because this crate must recognise what it may not destroy.
pub const VTEP_MARKER: &str = "vxlan";

/// The MTU an Ethernet underlay is assumed to have when sanity-checking a
/// configured overlay MTU. An overlay MTU at or above it means the −50 was
/// probably forgotten (`docs/vxlan.md` §6 case B), which is worth a loud log
/// line and is not an error: a jumbo underlay would legitimately exceed it.
pub const SUSPICIOUS_OVERLAY_MTU: u32 = 1500;

/// Smallest MTU the kernel accepts on an Ethernet-like interface (`ETHERMIN`).
pub const ETHERMIN: u32 = 46;

/// Deterministic bridge name for an overlay network: `satl-br<vni>`.
///
/// Derived from the VNI for the same reason `satl-overlay`'s VTEP name is
/// (`satl-vx<vni>`): the name must fit [`MAX_IFACE_NAME_LEN`], and `satl-br-`
/// plus a user-chosen network name would truncate or collide. The
/// human-readable binding lives in the interface description.
#[must_use]
pub fn overlay_bridge_name(vni: u32) -> String {
    format!("satl-br{vni}")
}

/// Which network stack an interface was read back in — the host's or a jail's.
///
/// Worth naming because the two are genuinely different stacks and reading the
/// wrong one is a fast route to a confident wrong conclusion
/// (`docs/vxlan.md` §6, "Counters live in two different stacks").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stack {
    /// The host's network stack.
    Host,
    /// A jail's VNET, by jail name or jid.
    Jail(String),
}

impl fmt::Display for Stack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => f.write_str("on the host"),
            Self::Jail(jail) => write!(f, "in jail '{jail}'"),
        }
    }
}

/// Error from the overlay segment plumbing. Every variant names the network and
/// the interface (and the jail, where there is one).
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// A segment description was rejected before anything was executed.
    #[error("overlay network '{network}': invalid segment: {reason}")]
    InvalidSegment {
        /// The network being configured.
        network: String,
        /// Why it was rejected.
        reason: String,
    },

    /// An attachment request was rejected before anything was executed.
    #[error("overlay network '{network}': invalid attachment for task {task_id}: {reason}")]
    InvalidAttachment {
        /// The network being attached to.
        network: String,
        /// The task being attached.
        task_id: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The network's VTEP does not exist on this node.
    #[error(
        "overlay network '{network}': VTEP interface '{vtep}' does not exist. The vxlan \
         interface is created and owned by satl-overlay (docs/vxlan.md section 2) and satl-net \
         only bridges it; program the VTEP first, then ensure the segment"
    )]
    VtepMissing {
        /// The network whose VTEP is missing.
        network: String,
        /// The interface name that was expected.
        vtep: String,
    },

    /// The VTEP exists but the driver never initialized it.
    #[error(
        "overlay network '{network}': VTEP interface '{vtep}' is not usable (flags={flags}): \
         vxlan(4) reports UP and `ifconfig` exits 0 for an interface it refused to \
         initialize, and RUNNING is the only health signal (docs/vxlan.md section 2 point 5). \
         The reason is in /var/log/messages; expect `cannot initialize interface: \
         destination address type is not supported` (no vxlanremote) or `network \
         identifier <vni> already exists in this socket`. Bridging it would build an \
         overlay that carries nothing while looking correct"
    )]
    VtepUnhealthy {
        /// The network whose VTEP is unhealthy.
        network: String,
        /// The interface name.
        vtep: String,
        /// Flag word as `ifconfig` prints it.
        flags: String,
    },

    /// The interface named as the VTEP carries another network's marker —
    /// bridging it would splice two overlays together.
    #[error(
        "overlay network '{network}': interface '{vtep}' is the VTEP of network \
         '{other}' (description {descr:?}); bridging it here would join two overlay \
         networks into one L2 segment"
    )]
    VtepBelongsToAnotherNetwork {
        /// The network being configured.
        network: String,
        /// The interface name that was passed.
        vtep: String,
        /// The network the interface actually serves.
        other: String,
        /// Its raw description.
        descr: String,
    },

    /// An interface came back with the wrong MTU.
    #[error(
        "overlay network '{network}': interface '{iface}' {stack} has mtu {got}, expected \
         {want}. On the overlay this is not cosmetic: a too-large MTU still works, but every \
         full-size frame is fragmented and reassembled, doubling the packet count and \
         amplifying loss, invisibly to every functional test and to throughput \
         (docs/vxlan.md sections 5 and 6, case B)"
    )]
    MtuMismatch {
        /// The network being configured.
        network: String,
        /// The interface read back.
        iface: String,
        /// Which stack it was read in.
        stack: Stack,
        /// The MTU that was set.
        want: u32,
        /// The MTU the kernel reports.
        got: u32,
    },

    /// An interface came back with the wrong link-layer address.
    #[error(
        "overlay network '{network}': interface '{iface}' {stack} has ether {got}, expected \
         the derived {want}. The MAC is a wire format: unicast VXLAN never floods, so every \
         node programs static FDB and ARP entries from mac(ip) computed out of store state \
         (docs/vxlan.md section 4); a kernel-assigned address there is unreachable from every \
         other node"
    )]
    MacMismatch {
        /// The network being configured.
        network: String,
        /// The interface read back.
        iface: String,
        /// Which stack it was read in.
        stack: Stack,
        /// The derived MAC that was set.
        want: MacAddr,
        /// What the kernel reports (rendered; `(none)` when absent).
        got: String,
    },

    /// An interface came back without an address it was given.
    #[error(
        "overlay network '{network}': interface '{iface}' {stack} does not carry {want}; \
         it has {got:?}"
    )]
    AddressMissing {
        /// The network being configured.
        network: String,
        /// The interface read back.
        iface: String,
        /// Which stack it was read in.
        stack: Stack,
        /// The address that should be there.
        want: Ipv4Addr,
        /// The addresses that are.
        got: Vec<Ipv4Addr>,
    },

    /// An interface came back down, or up but not running.
    #[error(
        "overlay network '{network}': interface '{iface}' {stack} is not usable \
         (flags={flags}): UP={up}, RUNNING={running}. A bridge member that is not UP \
         forwards nothing while still showing RUNNING (docs/vxlan.md section 4), and `ifconfig \
         <bridge> addm <member> up` brings up the bridge, not the member"
    )]
    IfaceNotUsable {
        /// The network being configured.
        network: String,
        /// The interface read back.
        iface: String,
        /// Which stack it was read in.
        stack: Stack,
        /// Flag word as `ifconfig` prints it.
        flags: String,
        /// Whether `UP` was set.
        up: bool,
        /// Whether `RUNNING` was set.
        running: bool,
    },

    /// A bridge came back without a member it was given.
    #[error(
        "overlay network '{network}': bridge '{bridge}' does not have '{member}' as a \
         member; its members are {members:?}"
    )]
    MemberMissing {
        /// The network being configured.
        network: String,
        /// The bridge read back.
        bridge: String,
        /// The member that should be there.
        member: String,
        /// The members that are.
        members: Vec<String>,
    },

    /// A teardown refused to destroy an interface that is not SatL's, or not
    /// this network's.
    #[error(
        "overlay network '{network}': refusing to destroy interface '{iface}': its \
         description is {descr:?}, expected {expected:?}; SatL only destroys interfaces \
         carrying its own ownership marker (docs/networking.md)"
    )]
    NotOurs {
        /// The network being torn down.
        network: String,
        /// The interface that was going to be destroyed.
        iface: String,
        /// Its actual description, if any.
        descr: Option<String>,
        /// The marker that was expected.
        expected: String,
    },
}

/// One overlay network's local segment, as this node should have it.
///
/// Everything here comes from the store, from the allocator, or from a
/// measurement — nothing is defaulted, because every default in this struct
/// would be a silently wrong overlay:
///
/// - `vtep` is `satl-overlay`'s interface name for the network on this node
///   (see the module docs on the dependency direction);
/// - `subnet` is [`satl_core::Network::subnet`];
/// - `gateway` is this node's entry in [`satl_core::Network::node_gateways`],
///   whose prefix length comes from `subnet`;
/// - `mtu` is `satl_overlay::overlay_mtu_v4(measured underlay MTU)`, i.e.
///   underlay − 50.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlaySegment {
    /// Network name — the ownership marker and every log line use it.
    pub network: String,
    /// Bridge interface name, conventionally [`overlay_bridge_name`].
    pub bridge: String,
    /// The network's VTEP on this node. **Created and owned by
    /// `satl-overlay`**; this crate only makes it a bridge member.
    pub vtep: String,
    /// The network's subnet (`Network::subnet`).
    pub subnet: Ipv4Cidr,
    /// This node's gateway address on the network (`Network::node_gateways`).
    pub gateway: Ipv4Addr,
    /// Overlay MTU: measured underlay MTU − 50.
    pub mtu: u32,
}

impl OverlaySegment {
    /// A segment whose bridge name follows [`overlay_bridge_name`].
    #[must_use]
    pub fn new(
        network: impl Into<String>,
        vni: u32,
        vtep: impl Into<String>,
        subnet: Ipv4Cidr,
        gateway: Ipv4Addr,
        mtu: u32,
    ) -> Self {
        Self {
            network: network.into(),
            bridge: overlay_bridge_name(vni),
            vtep: vtep.into(),
            subnet,
            gateway,
            mtu,
        }
    }

    /// Reject what the kernel or the addressing rules would reject anyway, and
    /// what neither would catch: the reserved `.1`, and a gateway from another
    /// network's subnet.
    pub fn validate(&self) -> Result<(), OverlayError> {
        let reject = |reason: String| {
            Err(OverlayError::InvalidSegment {
                network: self.network.clone(),
                reason,
            })
        };
        if !valid_marker_segment(&self.network) {
            return reject(format!(
                "network name {:?} must be non-empty and contain no ':' (the ownership \
                 marker grammar separates on it)",
                self.network
            ));
        }
        for (what, iface) in [("bridge", &self.bridge), ("VTEP", &self.vtep)] {
            if iface.is_empty() || iface.len() > MAX_IFACE_NAME_LEN {
                return reject(format!(
                    "{what} interface name {iface:?} must be 1..={MAX_IFACE_NAME_LEN} \
                     characters (IFNAMSIZ - 1)"
                ));
            }
            if iface.chars().any(char::is_whitespace) {
                return reject(format!(
                    "{what} interface name {iface:?} contains whitespace"
                ));
            }
        }
        if self.bridge == self.vtep {
            return reject(format!(
                "bridge and VTEP are the same interface {:?}",
                self.bridge
            ));
        }
        if self.subnet.prefix_len() > 30 {
            return reject(format!(
                "subnet {} has no room for a gateway and endpoints",
                self.subnet
            ));
        }
        if !self.subnet.contains(self.gateway) {
            return reject(format!(
                "gateway {} is outside the network's subnet {}",
                self.gateway, self.subnet
            ));
        }
        if self.gateway == self.subnet.network() || self.gateway == self.subnet.broadcast() {
            return reject(format!(
                "gateway {} is the network or broadcast address of {}",
                self.gateway, self.subnet
            ));
        }
        if Some(self.gateway) == self.subnet.gateway() {
            return reject(format!(
                "gateway {} is the reserved .1 of {}: on an overlay that address belongs to \
                 nobody, because every node's bridge is on one L2 segment and a shared \
                 gateway address is a duplicate address; the ARP race then decides whose \
                 DNS responder answers and whose host takes the other node's egress \
                 traffic (docs/vxlan.md section 8). Each node gets its own address from \
                 Network::node_gateways",
                self.gateway, self.subnet
            ));
        }
        if self.mtu < ETHERMIN {
            return reject(format!(
                "mtu {} is below ETHERMIN ({ETHERMIN}); did the underlay measurement fail?",
                self.mtu
            ));
        }
        Ok(())
    }

    /// The address to assign to the bridge, in CIDR form.
    fn gateway_cidr(&self) -> String {
        format!("{}/{}", self.gateway, self.subnet.prefix_len())
    }
}

/// A marker segment: non-empty and free of the `:` the grammar separates on.
fn valid_marker_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains(':')
}

/// The host side of an ensured overlay segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayBridge {
    /// Network name.
    pub network: String,
    /// Bridge interface name.
    pub bridge: String,
    /// The VTEP that is a member of it.
    pub vtep: String,
    /// This node's gateway address, assigned to the bridge.
    pub gateway: Ipv4Addr,
    /// The network's subnet.
    pub subnet: Ipv4Cidr,
    /// Overlay MTU, verified on the bridge and on the VTEP.
    pub mtu: u32,
}

/// What to attach to an overlay network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAttach {
    /// The task being attached (ownership marker, logs).
    pub task_id: String,
    /// Its VNET jail, as `ifconfig -j` takes it (name or jid).
    pub jail: String,
    /// The task's address on this network, from cluster IPAM
    /// (`NetworkAttachment::addresses`).
    pub ip: Ipv4Addr,
    /// Install a default route via this network's gateway inside the jail.
    ///
    /// Off by default, and that is the interesting case: the overlay subnet is
    /// on-link through the epair, so intra-overlay traffic needs no route, and
    /// a task that is also on the node-local bridge takes its default route
    /// from there (that is where NAT and published ports live —
    /// `docs/networking.md`). Two default routes would race. Turn this on only
    /// for a task whose *only* attachment is this overlay.
    pub default_route: bool,
}

impl OverlayAttach {
    /// An attachment with no default route (see [`Self::default_route`]).
    pub fn new(task_id: impl Into<String>, jail: impl Into<String>, ip: Ipv4Addr) -> Self {
        Self {
            task_id: task_id.into(),
            jail: jail.into(),
            ip,
            default_route: false,
        }
    }

    /// Also install a default route via the network's gateway in the jail.
    #[must_use]
    pub fn with_default_route(mut self, default_route: bool) -> Self {
        self.default_route = default_route;
        self
    }
}

/// A task's plumbing on one overlay network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayAttachment {
    /// The network attached to.
    pub network: String,
    /// Host-side epair end (bridge member).
    pub epair_a: String,
    /// Jail-side epair end.
    pub epair_b: String,
    /// The task's address on this network.
    pub ip: Ipv4Addr,
    /// The derived MAC set on the jail-side end.
    pub mac: MacAddr,
    /// Overlay MTU, verified on both ends.
    pub mtu: u32,
}

/// What a [`NetworkManager::sweep_overlay`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlaySweep {
    /// Epair ends destroyed because their (network, task) is not desired here.
    pub destroyed_epairs: Vec<String>,
    /// Overlay bridges destroyed because the network has no local presence.
    pub destroyed_bridges: Vec<String>,
    /// Epair ends kept for tasks that should still be attached.
    pub adopted_epairs: Vec<String>,
    /// Overlay bridges kept, to be re-ensured by
    /// [`NetworkManager::ensure_overlay_segment`].
    pub adopted_bridges: Vec<String>,
    /// VTEPs seen and deliberately left alone — `satl-overlay` owns their
    /// lifecycle.
    pub preserved_vteps: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pure verification of a read-back interface state.
// ---------------------------------------------------------------------------

/// What one interface must look like once it has been programmed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Expected<'a> {
    network: &'a str,
    stack: Stack,
    mtu: u32,
    running: bool,
    up: bool,
    mac: Option<MacAddr>,
    address: Option<Ipv4Addr>,
    member: Option<&'a str>,
}

impl Expected<'_> {
    /// Compare a read-back state against the expectation. Order matters only
    /// for which error an operator sees first, and it goes from the coarsest
    /// symptom (the interface is not usable) to the finest (a missing member).
    fn check(&self, state: &IfaceState) -> Result<(), OverlayError> {
        let network = self.network.to_owned();
        if (self.up && !state.is_up()) || (self.running && !state.is_running()) {
            return Err(OverlayError::IfaceNotUsable {
                network,
                iface: state.name.clone(),
                stack: self.stack.clone(),
                flags: state.rendered_flags(),
                up: state.is_up(),
                running: state.is_running(),
            });
        }
        if state.mtu != self.mtu {
            return Err(OverlayError::MtuMismatch {
                network,
                iface: state.name.clone(),
                stack: self.stack.clone(),
                want: self.mtu,
                got: state.mtu,
            });
        }
        if let Some(want) = self.mac
            && state.ether != Some(want)
        {
            return Err(OverlayError::MacMismatch {
                network,
                iface: state.name.clone(),
                stack: self.stack.clone(),
                want,
                got: state
                    .ether
                    .map_or_else(|| "(none)".to_owned(), |mac| mac.to_string()),
            });
        }
        if let Some(want) = self.address
            && !state.inet.contains(&want)
        {
            return Err(OverlayError::AddressMissing {
                network,
                iface: state.name.clone(),
                stack: self.stack.clone(),
                want,
                got: state.inet.clone(),
            });
        }
        if let Some(member) = self.member
            && !state.has_member(member)
        {
            return Err(OverlayError::MemberMissing {
                network,
                bridge: state.name.clone(),
                member: member.to_owned(),
                members: state.members.clone(),
            });
        }
        Ok(())
    }
}

impl<R: CommandRunner> NetworkManager<R> {
    /// Ownership marker of an overlay network's bridge.
    fn overlay_network_descr(&self, network: &str) -> String {
        format!("{}:{OVERLAY_MARKER}:{network}", self.config.group)
    }

    /// Ownership marker of a task's epair ends on an overlay network.
    fn overlay_task_descr(&self, network: &str, task_id: &str) -> String {
        format!("{}:{OVERLAY_MARKER}:{network}:{task_id}", self.config.group)
    }

    /// Ensure this node's local segment of an overlay network:
    ///
    /// 1. the VTEP exists and is `RUNNING` — read back, never created here;
    /// 2. the bridge exists, is group- and description-tagged;
    /// 3. the VTEP is a member;
    /// 4. **the bridge's MTU is set explicitly**, which is what gives the VTEP
    ///    and every epair `a` end the right MTU;
    /// 5. the bridge carries this node's gateway address, and any *other*
    ///    address of this network's subnet is removed (a stale gateway on a
    ///    shared L2 segment steals another node's traffic);
    /// 6. the bridge is up;
    /// 7. all of it is read back and verified.
    ///
    /// Idempotent: safe to call on every reconciliation pass.
    #[tracing::instrument(
        skip_all,
        fields(
            network = %segment.network,
            bridge = %segment.bridge,
            vtep = %segment.vtep,
            gateway = %segment.gateway,
            mtu = segment.mtu,
        )
    )]
    pub async fn ensure_overlay_segment(
        &self,
        segment: &OverlaySegment,
    ) -> Result<OverlayBridge, NetError> {
        segment.validate()?;
        if segment.mtu >= SUSPICIOUS_OVERLAY_MTU {
            tracing::warn!(
                mtu = segment.mtu,
                "overlay MTU is at or above a standard Ethernet underlay's: unless this \
                 underlay really is jumbo, the 50 bytes of VXLAN encapsulation were \
                 forgotten. That configuration works, and it fragments every full-size \
                 frame, doubling packet counts and amplifying loss, invisibly \
                 (docs/vxlan.md section 6, case B)"
            );
        }

        // 1. The VTEP: satl-overlay's interface. Read it, never touch it.
        let vtep = self
            .ifconfig
            .state_if_exists(&segment.vtep)
            .await?
            .ok_or_else(|| OverlayError::VtepMissing {
                network: segment.network.clone(),
                vtep: segment.vtep.clone(),
            })?;
        if !vtep.is_running() || !vtep.is_up() {
            return Err(OverlayError::VtepUnhealthy {
                network: segment.network.clone(),
                vtep: segment.vtep.clone(),
                flags: vtep.rendered_flags(),
            }
            .into());
        }
        self.check_vtep_identity(segment, &vtep)?;

        // 2. The bridge, created or adopted.
        self.ensure_overlay_bridge_iface(segment).await?;

        // 3. The VTEP as a member, and 4. the MTU, which propagates to it and
        // to every epair `a` end (man 4 bridge; verified live).
        self.ifconfig
            .bridge_addm_if_absent(&segment.bridge, &segment.vtep)
            .await?;
        self.ifconfig.set_mtu(&segment.bridge, segment.mtu).await?;

        // 5. This node's gateway address, and nobody else's.
        self.ensure_gateway_address(segment).await?;

        // 6. Up, and 7. read everything back — `ifconfig` exits 0 for
        // interfaces that do not work.
        self.ifconfig.up(&segment.bridge).await?;
        let bridge = self.ifconfig.state(&segment.bridge).await?;
        Expected {
            network: &segment.network,
            stack: Stack::Host,
            mtu: segment.mtu,
            running: true,
            up: true,
            mac: None,
            address: Some(segment.gateway),
            member: Some(&segment.vtep),
        }
        .check(&bridge)?;
        // The bridge's MTU is only useful if it actually reached the VTEP.
        let vtep = self.ifconfig.state(&segment.vtep).await?;
        Expected {
            network: &segment.network,
            stack: Stack::Host,
            mtu: segment.mtu,
            running: true,
            up: true,
            mac: None,
            address: None,
            member: None,
        }
        .check(&vtep)?;

        tracing::info!("overlay segment ensured");
        Ok(OverlayBridge {
            network: segment.network.clone(),
            bridge: segment.bridge.clone(),
            vtep: segment.vtep.clone(),
            gateway: segment.gateway,
            subnet: segment.subnet,
            mtu: segment.mtu,
        })
    }

    /// Create the overlay bridge, or adopt one that is already there and repair
    /// the markers an interrupted run may have left half-written. Refuses a
    /// bridge of that name carrying a description that is not SatL's at all.
    async fn ensure_overlay_bridge_iface(&self, segment: &OverlaySegment) -> Result<(), NetError> {
        let descr = self.overlay_network_descr(&segment.network);
        let Some(state) = self.ifconfig.state_if_exists(&segment.bridge).await? else {
            self.ifconfig.create_bridge(&segment.bridge).await?;
            self.ifconfig
                .set_group(&segment.bridge, &self.config.group)
                .await?;
            self.ifconfig.set_descr(&segment.bridge, &descr).await?;
            return Ok(());
        };
        // Description writes are idempotent; group adds are not, so probe.
        if state.descr.as_deref() != Some(descr.as_str()) {
            if let Some(existing) = &state.descr
                && classify_marker(&self.config.group, existing).is_none()
            {
                return Err(OverlayError::NotOurs {
                    network: segment.network.clone(),
                    iface: segment.bridge.clone(),
                    descr: state.descr.clone(),
                    expected: descr,
                }
                .into());
            }
            self.ifconfig.set_descr(&segment.bridge, &descr).await?;
        }
        if !state.in_group(&self.config.group) {
            self.ifconfig
                .set_group(&segment.bridge, &self.config.group)
                .await?;
        }
        tracing::debug!("adopted existing overlay bridge");
        Ok(())
    }

    /// Put this node's gateway address on the bridge, and take off any *other*
    /// address of the network's subnet.
    ///
    /// A leftover gateway from a previous allocation is not inert: every node's
    /// bridge is on one L2 segment, so it answers ARP for another node's
    /// gateway and takes that node's jails' traffic (`docs/vxlan.md` §8,
    /// measured). Addresses outside the network's subnet are the operator's and
    /// are left alone.
    async fn ensure_gateway_address(&self, segment: &OverlaySegment) -> Result<(), NetError> {
        let before = self.ifconfig.state(&segment.bridge).await?;
        for stale in before
            .inet
            .iter()
            .copied()
            .filter(|addr| *addr != segment.gateway && segment.subnet.contains(*addr))
        {
            tracing::warn!(
                stale = %stale,
                gateway = %segment.gateway,
                "overlay bridge carries an address of this network's subnet that is not \
                 this node's gateway; removing it. Every node's bridge is on one L2 \
                 segment, so a leftover address answers ARP for another node's gateway \
                 and takes its traffic (docs/vxlan.md section 8)"
            );
            self.ifconfig.remove_inet(&segment.bridge, stale).await?;
        }
        if !before.inet.contains(&segment.gateway) {
            self.ifconfig
                .add_inet(&segment.bridge, &segment.gateway_cidr())
                .await?;
        }
        // The bridge's MAC is the derived MAC of this node's gateway, not the
        // kernel-assigned one: the derived MAC is a wire format — every peer
        // computes a gateway's MAC from its address alone (module docs, point
        // 4), so a jail's static ARP entry and a peer's FDB entry for a
        // gateway only resolve to its node if the bridge actually carries it.
        // Measured on the cluster (M6d): a task's reply to its own node's
        // gateway went to the derived MAC the bridge did not have and was
        // dropped, and the mesh relay died with it.
        let want = MacAddr::from_ipv4(segment.gateway);
        if before.ether != Some(want) {
            self.ifconfig.set_ether(&segment.bridge, want).await?;
        }
        Ok(())
    }

    /// Refuse a VTEP that carries another network's marker: bridging it would
    /// splice two overlays into one L2 segment. A VTEP with no marker, or a
    /// marker this version does not understand, is only logged — an operator
    /// may hand-manage one, and a hard failure there would be worse than a
    /// warning.
    fn check_vtep_identity(
        &self,
        segment: &OverlaySegment,
        vtep: &IfaceState,
    ) -> Result<(), OverlayError> {
        let Some(descr) = &vtep.descr else {
            tracing::warn!(
                vtep = %segment.vtep,
                "VTEP carries no ownership marker; SatL's own VTEPs are described \
                 '<group>:{VTEP_MARKER}:<network>' (docs/networking.md)"
            );
            return Ok(());
        };
        match classify_marker(&self.config.group, descr) {
            Some(OwnedKind::Vtep { network }) if network == segment.network => Ok(()),
            Some(OwnedKind::Vtep { network }) => Err(OverlayError::VtepBelongsToAnotherNetwork {
                network: segment.network.clone(),
                vtep: segment.vtep.clone(),
                other: network,
                descr: descr.clone(),
            }),
            _ => {
                tracing::warn!(
                    vtep = %segment.vtep,
                    descr = %descr,
                    "VTEP's description is not a '<group>:{VTEP_MARKER}:<network>' marker"
                );
                Ok(())
            }
        }
    }

    /// Attach a task's VNET jail to an overlay network.
    ///
    /// In order, because the order is load-bearing:
    ///
    /// 1. create the epair and tag both ends with the ownership marker;
    /// 2. **set the derived MAC** on the jail-side end, on the host, before the
    ///    `vnet` move (it survives the move);
    /// 3. **set the overlay MTU on both ends** — before `addm`, because a
    ///    bridge member's MTU cannot be set at all (measured: `SIOCSIFMTU:
    ///    Operation not supported`, even to the value it already has);
    /// 4. add the host end to the bridge and bring **it** up (`addm ... up`
    ///    would bring up the bridge, not the member), then read it back;
    /// 5. move the other end into the jail, address it, set its MTU again
    ///    inside the jail — it is not a bridge member, so nothing propagates
    ///    to it — bring it and `lo0` up;
    /// 6. optionally install the default route;
    /// 7. read the in-jail end back and verify MTU, MAC and address.
    ///
    /// Any failure rolls the epair back (destroying either end destroys the
    /// pair) and reports the step. Addresses are **not** allocated here: an
    /// overlay address comes from cluster IPAM in the Raft store, so there is
    /// nothing node-local to release.
    #[tracing::instrument(
        skip_all,
        fields(
            network = %segment.network,
            task_id = %attach.task_id,
            jail = %attach.jail,
            ip = %attach.ip,
            mtu = segment.mtu,
        )
    )]
    pub async fn attach_task_overlay(
        &self,
        segment: &OverlaySegment,
        attach: &OverlayAttach,
    ) -> Result<OverlayAttachment, NetError> {
        segment.validate()?;
        Self::validate_attachment(segment, attach)?;
        let mac = MacAddr::from_ipv4(attach.ip);

        let attach_err = |step: AttachStep, rolled_back: bool, source: NetError| NetError::Attach {
            task_id: attach.task_id.clone(),
            jail: attach.jail.clone(),
            step,
            rolled_back,
            source: Box::new(source),
        };

        let pair = self
            .ifconfig
            .create_epair()
            .await
            .map_err(|err| attach_err(AttachStep::CreateEpair, true, err.into()))?;

        if let Err((step, source)) = self.plumb_overlay(segment, attach, &pair, mac).await {
            let rolled_back = self.rollback_epair(&pair.a, &pair.b).await;
            return Err(attach_err(step, rolled_back, source));
        }

        tracing::info!(
            epair_a = %pair.a,
            epair_b = %pair.b,
            mac = %mac,
            "task attached to overlay network"
        );
        Ok(OverlayAttachment {
            network: segment.network.clone(),
            epair_a: pair.a,
            epair_b: pair.b,
            ip: attach.ip,
            mac,
            mtu: segment.mtu,
        })
    }

    /// Reject an attachment request before anything is executed: a task id that
    /// would corrupt the marker grammar, and any address that is not a usable
    /// endpoint address of this network on this node.
    fn validate_attachment(
        segment: &OverlaySegment,
        attach: &OverlayAttach,
    ) -> Result<(), OverlayError> {
        let reject = |reason: String| {
            Err(OverlayError::InvalidAttachment {
                network: segment.network.clone(),
                task_id: attach.task_id.clone(),
                reason,
            })
        };
        if !valid_marker_segment(&attach.task_id) {
            return reject(format!(
                "task id {:?} must be non-empty and contain no ':' (the ownership marker \
                 grammar separates on it)",
                attach.task_id
            ));
        }
        if attach.jail.is_empty() {
            return reject("jail name is empty".to_owned());
        }
        if !segment.subnet.contains(attach.ip) {
            return reject(format!(
                "address {} is outside the network's subnet {}",
                attach.ip, segment.subnet
            ));
        }
        if attach.ip == segment.gateway {
            return reject(format!(
                "address {} is this node's gateway address for the network",
                attach.ip
            ));
        }
        if Some(attach.ip) == segment.subnet.gateway() {
            return reject(format!(
                "address {} is the reserved .1 of {}, which belongs to no node and no task \
                 on an overlay network (docs/vxlan.md section 8)",
                attach.ip, segment.subnet
            ));
        }
        if attach.ip == segment.subnet.network() || attach.ip == segment.subnet.broadcast() {
            return reject(format!(
                "address {} is the network or broadcast address of {}",
                attach.ip, segment.subnet
            ));
        }
        Ok(())
    }

    /// The failable plumbing after the epair exists; returns the failed step so
    /// the caller can roll back. See [`Self::attach_task_overlay`] for why the
    /// order is what it is.
    async fn plumb_overlay(
        &self,
        segment: &OverlaySegment,
        attach: &OverlayAttach,
        pair: &EpairPair,
        mac: MacAddr,
    ) -> Result<(), (AttachStep, NetError)> {
        let (epair_a, epair_b) = (pair.a.as_str(), pair.b.as_str());
        let (jail, ip) = (attach.jail.as_str(), attach.ip);
        let descr = self.overlay_task_descr(&segment.network, &attach.task_id);
        let step = |s: AttachStep| move |e: IfconfigError| (s, e.into());

        self.ifconfig
            .set_descr(epair_a, &descr)
            .await
            .map_err(step(AttachStep::TagInterfaces))?;
        self.ifconfig
            .set_group(epair_a, &self.config.group)
            .await
            .map_err(step(AttachStep::TagInterfaces))?;
        self.ifconfig
            .set_descr(epair_b, &descr)
            .await
            .map_err(step(AttachStep::TagInterfaces))?;

        // The derived MAC, on the host, before the move.
        self.ifconfig
            .set_ether(epair_b, mac)
            .await
            .map_err(step(AttachStep::SetMac))?;

        // Both MTUs, before `addm` locks the host end's.
        self.ifconfig
            .set_mtu(epair_a, segment.mtu)
            .await
            .map_err(step(AttachStep::SetMtu))?;
        self.ifconfig
            .set_mtu(epair_b, segment.mtu)
            .await
            .map_err(step(AttachStep::SetMtu))?;

        self.ifconfig
            .bridge_addm_if_absent(&segment.bridge, epair_a)
            .await
            .map_err(step(AttachStep::JoinBridge))?;
        self.ifconfig
            .up(epair_a)
            .await
            .map_err(step(AttachStep::HostSideUp))?;
        let host = self
            .ifconfig
            .state(epair_a)
            .await
            .map_err(step(AttachStep::Verify))?;
        Expected {
            network: &segment.network,
            stack: Stack::Host,
            mtu: segment.mtu,
            running: true,
            up: true,
            mac: None,
            address: None,
            member: None,
        }
        .check(&host)
        .map_err(|e| (AttachStep::Verify, e.into()))?;

        self.ifconfig
            .move_to_jail(epair_b, jail)
            .await
            .map_err(step(AttachStep::MoveToJail))?;

        let cidr = format!("{ip}/{}", segment.subnet.prefix_len());
        self.ifconfig
            .jail_add_inet(jail, epair_b, &cidr)
            .await
            .map_err(step(AttachStep::AssignAddress))?;
        // Explicit, in the jail: this end is not a bridge member, so the
        // bridge's MTU never reaches it (docs/vxlan.md §5).
        self.ifconfig
            .jail_set_mtu(jail, epair_b, segment.mtu)
            .await
            .map_err(step(AttachStep::SetMtu))?;
        self.ifconfig
            .jail_up(jail, epair_b)
            .await
            .map_err(step(AttachStep::BringUp))?;
        self.ifconfig
            .jail_up(jail, "lo0")
            .await
            .map_err(step(AttachStep::BringUp))?;

        if attach.default_route {
            self.route
                .add_default_in_jail(jail, segment.gateway)
                .await
                .map_err(|e| (AttachStep::DefaultRoute, e.into()))?;
        }

        let jailed = self
            .ifconfig
            .jail_state(jail, epair_b)
            .await
            .map_err(step(AttachStep::Verify))?;
        Expected {
            network: &segment.network,
            stack: Stack::Jail(jail.to_owned()),
            mtu: segment.mtu,
            running: true,
            up: true,
            mac: Some(mac),
            address: Some(ip),
            member: None,
        }
        .check(&jailed)
        .map_err(|e| (AttachStep::Verify, e.into()))?;
        Ok(())
    }

    /// Best-effort rollback: destroying either end of an epair destroys the
    /// pair, and either end may already be gone or inside a jail.
    async fn rollback_epair(&self, epair_a: &str, epair_b: &str) -> bool {
        match self.ifconfig.destroy_if_exists(epair_a).await {
            Ok(true) => true,
            Ok(false) => match self.ifconfig.destroy_if_exists(epair_b).await {
                Ok(_) => true,
                Err(err) => {
                    tracing::error!(iface = %epair_b, error = %err, "rollback: failed to destroy epair b end");
                    false
                }
            },
            Err(err) => {
                tracing::error!(iface = %epair_a, error = %err, "rollback: failed to destroy epair a end");
                false
            }
        }
    }

    /// Detach a task from an overlay network: destroy its epair. Idempotent,
    /// and handles both post-jail states (the `b` end still in the jail, or
    /// auto-returned to the host after the jail died).
    ///
    /// Nothing else is released: the address is cluster-allocated, the bridge
    /// stays for the network's other tasks, and the VTEP is `satl-overlay`'s.
    #[tracing::instrument(
        skip_all,
        fields(
            network = %attachment.network,
            task_id = %task_id,
            epair_a = %attachment.epair_a,
        )
    )]
    pub async fn detach_task_overlay(
        &self,
        task_id: &str,
        attachment: &OverlayAttachment,
    ) -> Result<(), NetError> {
        if self.ifconfig.destroy_if_exists(&attachment.epair_a).await? {
            tracing::info!(iface = %attachment.epair_a, "destroyed overlay task epair");
            return Ok(());
        }
        let destroyed_b = self.ifconfig.destroy_if_exists(&attachment.epair_b).await?;
        tracing::info!(
            iface_a = %attachment.epair_a,
            iface_b = %attachment.epair_b,
            destroyed_b,
            "overlay task epair a end already gone"
        );
        Ok(())
    }

    /// Destroy this node's segment of an overlay network: the bridge and any
    /// epair of *this* network still on it. `Ok(false)` when the bridge was
    /// already gone.
    ///
    /// The VTEP is **detached, never destroyed** — `satl-overlay` owns it, and
    /// destroying a bridge leaves its members alive anyway (verified live); the
    /// explicit `deletem` is there so the log says what happened. Members that
    /// are not this network's are left in place, with a warning: SatL only
    /// destroys interfaces carrying its own marker.
    #[tracing::instrument(
        skip_all,
        fields(network = %segment.network, bridge = %segment.bridge, vtep = %segment.vtep)
    )]
    pub async fn destroy_overlay_segment(
        &self,
        segment: &OverlaySegment,
    ) -> Result<bool, NetError> {
        self.destroy_overlay_bridge(&segment.network, &segment.bridge, Some(&segment.vtep))
            .await
    }

    /// The shared teardown of one overlay bridge, used by
    /// [`Self::destroy_overlay_segment`] and by the sweep (which learns the
    /// VTEP's name from the interface markers, or does not find one).
    async fn destroy_overlay_bridge(
        &self,
        network: &str,
        bridge: &str,
        vtep: Option<&str>,
    ) -> Result<bool, NetError> {
        let Some(state) = self.ifconfig.state_if_exists(bridge).await? else {
            return Ok(false);
        };
        let expected = self.overlay_network_descr(network);
        if state.descr.as_deref() != Some(expected.as_str()) {
            return Err(OverlayError::NotOurs {
                network: network.to_owned(),
                iface: bridge.to_owned(),
                descr: state.descr.clone(),
                expected,
            }
            .into());
        }
        if let Some(vtep) = vtep
            && self.ifconfig.bridge_deletem_if_member(bridge, vtep).await?
        {
            tracing::info!(vtep = %vtep, "detached VTEP from the overlay bridge (not destroyed)");
        }
        for member in &state.members {
            if Some(member.as_str()) == vtep {
                continue;
            }
            match self.classify_iface(member).await? {
                Some(OwnedKind::OverlayTask {
                    network: owner,
                    task_id,
                }) if owner == network => {
                    // An interrupted teardown left a task's epair bridged.
                    if self.ifconfig.destroy_if_exists(member).await? {
                        tracing::warn!(
                            iface = %member,
                            task_id = %task_id,
                            "destroyed an orphaned epair still on the overlay bridge"
                        );
                    }
                }
                Some(OwnedKind::Vtep { network: owner }) => {
                    tracing::warn!(
                        iface = %member,
                        vtep_network = %owner,
                        "leaving a VTEP bridged here: satl-overlay owns its lifecycle"
                    );
                }
                other => {
                    tracing::warn!(
                        iface = %member,
                        kind = ?other,
                        "leaving a bridge member SatL does not own; it is only un-bridged"
                    );
                }
            }
        }
        let destroyed = self.ifconfig.destroy_if_exists(bridge).await?;
        if destroyed {
            tracing::info!("destroyed overlay bridge");
        }
        Ok(destroyed)
    }

    /// Classify one interface by its description, tolerating a vanished
    /// interface (teardown racing reconciliation).
    async fn classify_iface(&self, iface: &str) -> Result<Option<OwnedKind>, NetError> {
        let Some(state) = self.ifconfig.state_if_exists(iface).await? else {
            return Ok(None);
        };
        Ok(state
            .descr
            .as_deref()
            .and_then(|descr| classify_marker(&self.config.group, descr)))
    }

    /// Reconcile every overlay interface on this node against what should be
    /// here: `desired` maps a network name to the tasks of that network running
    /// locally.
    ///
    /// - an epair whose `(network, task)` is not desired is destroyed — this is
    ///   the epair-leak gotcha (CLAUDE.md), which for an overlay also leaves
    ///   members on a bridge;
    /// - a bridge whose network is **absent from `desired`** is destroyed,
    ///   after detaching the VTEP. A network *present* with an empty task set
    ///   is left alone: that is a network whose segment has just been ensured
    ///   and whose first task has not attached yet;
    /// - a VTEP is never touched, only reported.
    ///
    /// Everything kept is reported too, so the caller can re-ensure segments
    /// ([`Self::ensure_overlay_segment`] repairs markers, MTU and gateway) and
    /// re-adopt attachments rather than rebuilding them.
    #[tracing::instrument(skip_all, fields(networks = desired.len()))]
    pub async fn sweep_overlay(
        &self,
        desired: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<OverlaySweep, NetError> {
        let mut sweep = OverlaySweep::default();
        let mut bridges: Vec<(String, String)> = Vec::new();
        let mut vteps: BTreeMap<String, String> = BTreeMap::new();
        let mut epairs: Vec<(String, String, String)> = Vec::new();
        for iface in self.list_owned().await? {
            match iface.kind {
                OwnedKind::OverlayNetwork { network } => bridges.push((network, iface.name)),
                OwnedKind::Vtep { network } => {
                    vteps.insert(network, iface.name.clone());
                    sweep.preserved_vteps.push(iface.name);
                }
                OwnedKind::OverlayTask { network, task_id } => {
                    epairs.push((network, task_id, iface.name));
                }
                OwnedKind::Network { .. } | OwnedKind::Task { .. } => {}
            }
        }

        // Epairs first, so a bridge teardown finds nothing of ours left on it.
        for (network, task_id, iface) in epairs {
            let wanted = desired
                .get(&network)
                .is_some_and(|tasks| tasks.contains(&task_id));
            if wanted {
                sweep.adopted_epairs.push(iface);
                continue;
            }
            // Destroying the first end of a pair removes the second, which
            // then reports itself as already gone.
            if self.ifconfig.destroy_if_exists(&iface).await? {
                tracing::warn!(
                    network = %network,
                    task_id = %task_id,
                    iface = %iface,
                    "destroyed orphaned overlay epair"
                );
                sweep.destroyed_epairs.push(iface);
            }
        }

        for (network, bridge) in bridges {
            if desired.contains_key(&network) {
                sweep.adopted_bridges.push(bridge);
                continue;
            }
            let vtep = vteps.get(&network).map(String::as_str);
            if self.destroy_overlay_bridge(&network, &bridge, vtep).await? {
                tracing::warn!(
                    network = %network,
                    bridge = %bridge,
                    "destroyed the overlay bridge of a network with no local tasks"
                );
                sweep.destroyed_bridges.push(bridge);
            }
        }

        tracing::info!(
            destroyed_epairs = sweep.destroyed_epairs.len(),
            destroyed_bridges = sweep.destroyed_bridges.len(),
            adopted_epairs = sweep.adopted_epairs.len(),
            adopted_bridges = sweep.adopted_bridges.len(),
            preserved_vteps = sweep.preserved_vteps.len(),
            "overlay sweep complete"
        );
        Ok(sweep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{NetworkManagerConfig, PfMode};
    use crate::runner::MockRunner;

    const MISSING: &str = "ifconfig: interface satlnt-nope does not exist\n";
    const VTEP: &str = include_str!("../tests/fixtures/ifconfig_show_vtep.txt");
    const BRIDGE: &str = include_str!("../tests/fixtures/ifconfig_show_overlay_bridge.txt");
    const EPAIR_A: &str = include_str!("../tests/fixtures/ifconfig_show_epair_a_bridged.txt");
    const EPAIR_B: &str = include_str!("../tests/fixtures/ifconfig_show_epair_b_in_jail.txt");
    const EPAIR_B_1500: &str =
        include_str!("../tests/fixtures/ifconfig_show_epair_b_default_mtu.txt");

    fn cidr(text: &str) -> Ipv4Cidr {
        text.parse().unwrap()
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    /// Parse a captured `ifconfig` show output into the read-back type.
    fn parse_state(text: &str) -> IfaceState {
        crate::ifconfig::parse_iface_state(text).expect("fixture parses")
    }

    /// A segment matching the captured fixtures: bridge `ntx-br0` on network
    /// `ntxnet`, VTEP `ntx-vx0`, subnet `10.79.0.0/24`, this node's gateway
    /// `.2` (never `.1`), MTU 1450.
    fn segment() -> OverlaySegment {
        OverlaySegment {
            network: "ntxnet".to_owned(),
            bridge: "ntx-br0".to_owned(),
            vtep: "ntx-vx0".to_owned(),
            subnet: cidr("10.79.0.0/24"),
            gateway: ip("10.79.0.2"),
            mtu: 1450,
        }
    }

    fn manager<'a>(dir: &std::path::Path, mock: &'a MockRunner) -> NetworkManager<&'a MockRunner> {
        NetworkManager::with_runner(
            NetworkManagerConfig {
                network: "satl".to_owned(),
                bridge: "satl0".to_owned(),
                group: "satl".to_owned(),
                state_dir: dir.to_path_buf(),
                pool: crate::ipam::DEFAULT_LOCAL_BRIDGE_POOL,
                egress_if: None,
                pf_mode: PfMode::Disabled,
            },
            mock,
        )
        .unwrap()
    }

    // ---- naming and validation ---------------------------------------------

    #[test]
    fn bridge_names_are_derived_from_the_vni_and_always_fit() {
        assert_eq!(overlay_bridge_name(4096), "satl-br4096");
        // The widest possible 24-bit VNI still fits IFNAMSIZ - 1.
        assert_eq!(overlay_bridge_name(0x00FF_FFFF).len(), 15);
        assert!(overlay_bridge_name(0x00FF_FFFF).len() <= MAX_IFACE_NAME_LEN);
    }

    #[test]
    fn a_valid_segment_passes() {
        segment().validate().unwrap();
        // The constructor's bridge name follows the convention.
        let built = OverlaySegment::new(
            "web",
            4096,
            "satl-vx4096",
            cidr("10.100.0.0/24"),
            ip("10.100.0.2"),
            1450,
        );
        assert_eq!(built.bridge, "satl-br4096");
        built.validate().unwrap();
    }

    #[test]
    fn the_reserved_dot_one_is_never_this_nodes_gateway() {
        let mut seg = segment();
        seg.gateway = ip("10.79.0.1");
        let err = seg.validate().unwrap_err();
        let text = err.to_string();
        assert!(text.contains("reserved .1"), "{text}");
        assert!(text.contains("duplicate address"), "{text}");
        assert!(text.contains("node_gateways"), "{text}");
    }

    #[test]
    fn segment_validation_rejects_the_rest() {
        let cases: Vec<(OverlaySegment, &str)> = vec![
            (
                OverlaySegment {
                    network: "has:colon".to_owned(),
                    ..segment()
                },
                "marker grammar",
            ),
            (
                OverlaySegment {
                    network: String::new(),
                    ..segment()
                },
                "non-empty",
            ),
            (
                OverlaySegment {
                    bridge: "satl-br-a-very-long-name".to_owned(),
                    ..segment()
                },
                "IFNAMSIZ",
            ),
            (
                OverlaySegment {
                    vtep: String::new(),
                    ..segment()
                },
                "IFNAMSIZ",
            ),
            (
                OverlaySegment {
                    vtep: "ntx-br0".to_owned(),
                    ..segment()
                },
                "same interface",
            ),
            (
                OverlaySegment {
                    gateway: ip("10.80.0.2"),
                    ..segment()
                },
                "outside the network's subnet",
            ),
            (
                OverlaySegment {
                    gateway: ip("10.79.0.0"),
                    ..segment()
                },
                "network or broadcast",
            ),
            (
                OverlaySegment {
                    gateway: ip("10.79.0.255"),
                    ..segment()
                },
                "network or broadcast",
            ),
            (
                OverlaySegment {
                    subnet: cidr("10.79.0.0/31"),
                    ..segment()
                },
                "no room",
            ),
            (
                OverlaySegment {
                    mtu: 20,
                    ..segment()
                },
                "ETHERMIN",
            ),
        ];
        for (seg, expected) in cases {
            let err = seg.validate().unwrap_err().to_string();
            assert!(err.contains(expected), "{err} should mention {expected:?}");
        }
    }

    // ---- pure read-back verification ---------------------------------------

    #[test]
    fn verification_catches_the_forgotten_fifty_bytes() {
        let state = parse_state(EPAIR_B_1500);
        let err = Expected {
            network: "ntxnet",
            stack: Stack::Jail("ntx-j1".to_owned()),
            mtu: 1450,
            running: true,
            up: false,
            mac: None,
            address: None,
            member: None,
        }
        .check(&state)
        .unwrap_err();
        match &err {
            OverlayError::MtuMismatch {
                iface,
                stack,
                want,
                got,
                ..
            } => {
                assert_eq!(iface, "epair4b");
                assert_eq!(*stack, Stack::Jail("ntx-j1".to_owned()));
                assert_eq!((*want, *got), (1450, 1500));
            }
            other => panic!("expected MtuMismatch, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("in jail 'ntx-j1'"), "{text}");
        assert!(text.contains("fragmented"), "{text}");
    }

    #[test]
    fn verification_accepts_the_real_captured_states() {
        let jailed = parse_state(EPAIR_B);
        Expected {
            network: "ntxnet",
            stack: Stack::Jail("ntx-j1".to_owned()),
            mtu: 1450,
            running: true,
            up: true,
            mac: Some(MacAddr::from_ipv4(ip("10.79.0.11"))),
            address: Some(ip("10.79.0.11")),
            member: None,
        }
        .check(&jailed)
        .unwrap();

        let bridge = parse_state(BRIDGE);
        Expected {
            network: "ntxnet",
            stack: Stack::Host,
            mtu: 1450,
            running: true,
            up: true,
            mac: None,
            address: Some(ip("10.79.0.2")),
            member: Some("ntx-vx0"),
        }
        .check(&bridge)
        .unwrap();
    }

    #[test]
    fn verification_catches_a_kernel_mac_a_missing_address_and_a_missing_member() {
        let jailed = parse_state(EPAIR_B);
        let wrong_mac = Expected {
            network: "ntxnet",
            stack: Stack::Jail("ntx-j1".to_owned()),
            mtu: 1450,
            running: true,
            up: true,
            // The address the store says this endpoint has, i.e. a different
            // derived MAC than the one actually on the interface.
            mac: Some(MacAddr::from_ipv4(ip("10.79.0.12"))),
            address: None,
            member: None,
        }
        .check(&jailed)
        .unwrap_err();
        assert!(
            matches!(wrong_mac, OverlayError::MacMismatch { .. }),
            "{wrong_mac:?}"
        );
        assert!(wrong_mac.to_string().contains("wire format"));

        let missing_addr = Expected {
            network: "ntxnet",
            stack: Stack::Jail("ntx-j1".to_owned()),
            mtu: 1450,
            running: true,
            up: true,
            mac: None,
            address: Some(ip("10.79.0.77")),
            member: None,
        }
        .check(&jailed)
        .unwrap_err();
        assert!(
            matches!(missing_addr, OverlayError::AddressMissing { .. }),
            "{missing_addr:?}"
        );

        let bridge = parse_state(BRIDGE);
        let missing_member = Expected {
            network: "ntxnet",
            stack: Stack::Host,
            mtu: 1450,
            running: true,
            up: true,
            mac: None,
            address: None,
            member: Some("ntx-vx9"),
        }
        .check(&bridge)
        .unwrap_err();
        match &missing_member {
            OverlayError::MemberMissing { members, .. } => {
                assert_eq!(members, &["epair4a", "ntx-vx0"]);
            }
            other => panic!("expected MemberMissing, got {other:?}"),
        }
    }

    #[test]
    fn verification_catches_an_interface_that_is_up_but_not_running() {
        // A vxlan interface the driver refused: UP, status active, exit 0, no
        // RUNNING (docs/vxlan.md §2 point 5).
        let broken = VTEP.replace(
            "1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP>",
            "1008803<UP,BROADCAST,SIMPLEX,MULTICAST,LOWER_UP>",
        );
        let state = parse_state(&broken);
        assert!(state.is_up() && !state.is_running());
        let err = Expected {
            network: "ntxnet",
            stack: Stack::Host,
            mtu: 1450,
            running: true,
            up: true,
            mac: None,
            address: None,
            member: None,
        }
        .check(&state)
        .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("UP=true, RUNNING=false"), "{text}");
    }

    // ---- ensure_overlay_segment --------------------------------------------

    #[tokio::test]
    async fn ensure_creates_the_bridge_and_verifies_everything() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, VTEP, ""); // state_if_exists(vtep)
        mock.push_output(1, "", MISSING); // state_if_exists(bridge) -> missing
        mock.push_output(0, "ntx-br0\n", ""); // create_bridge
        mock.push_ok(); // group
        mock.push_ok(); // description
        mock.push_ok(); // addm vtep
        mock.push_ok(); // mtu on the bridge
        // state(bridge): exists, no address yet
        mock.push_output(
            0,
            &BRIDGE.replace(
                "\tinet 10.79.0.2 netmask 0xffffff00 broadcast 10.79.0.255\n",
                "",
            ),
            "",
        );
        mock.push_ok(); // add_inet gateway
        mock.push_ok(); // ether: the derived MAC of this node's gateway
        mock.push_ok(); // up
        let bridge_derived = BRIDGE.replace("58:9c:fc:10:cd:b0", "02:42:0a:4f:00:02");
        mock.push_output(0, &bridge_derived, ""); // verify bridge
        mock.push_output(0, VTEP, ""); // verify the MTU reached the VTEP
        let mgr = manager(dir.path(), &mock);
        let out = mgr.ensure_overlay_segment(&segment()).await.unwrap();
        assert_eq!(out.bridge, "ntx-br0");
        assert_eq!(out.vtep, "ntx-vx0");
        assert_eq!(out.gateway, ip("10.79.0.2"));
        assert_eq!(out.mtu, 1450);
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig ntx-vx0",
                "/sbin/ifconfig ntx-br0",
                "/sbin/ifconfig bridge create name ntx-br0",
                "/sbin/ifconfig ntx-br0 group satl",
                "/sbin/ifconfig ntx-br0 description satl:overlay:ntxnet",
                // The VTEP joins first, then the MTU is set explicitly on the
                // bridge — which is what gives every member the overlay MTU.
                "/sbin/ifconfig ntx-br0 addm ntx-vx0",
                "/sbin/ifconfig ntx-br0 mtu 1450",
                "/sbin/ifconfig ntx-br0",
                "/sbin/ifconfig ntx-br0 inet 10.79.0.2/24",
                // The bridge's MAC is the gateway's derived MAC: every peer
                // computes it from the address alone (M6d).
                "/sbin/ifconfig ntx-br0 ether 02:42:0a:4f:00:02",
                "/sbin/ifconfig ntx-br0 up",
                "/sbin/ifconfig ntx-br0",
                "/sbin/ifconfig ntx-vx0",
            ]
        );
    }

    #[tokio::test]
    async fn ensure_adopts_an_existing_bridge_and_removes_a_stale_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        // A bridge left by a previous run: right marker, but carrying another
        // node's gateway address as well as ours.
        let stale = BRIDGE.replace(
            "\tinet 10.79.0.2 netmask 0xffffff00 broadcast 10.79.0.255\n",
            "\tinet 10.79.0.2 netmask 0xffffff00 broadcast 10.79.0.255\n\
             \tinet 10.79.0.3 netmask 0xffffff00 broadcast 10.79.0.255\n",
        );
        mock.push_output(0, VTEP, ""); // vtep
        mock.push_output(0, &stale, ""); // bridge exists, description already ours
        mock.push_ok(); // group repair: the captured bridge is not in `satl`
        mock.push_ok(); // addm (already a member in reality; Ok here)
        mock.push_ok(); // mtu
        mock.push_output(0, &stale, ""); // read addresses
        mock.push_ok(); // remove_inet 10.79.0.3
        mock.push_ok(); // ether: the derived MAC of this node's gateway
        mock.push_ok(); // up
        let bridge_derived = BRIDGE.replace("58:9c:fc:10:cd:b0", "02:42:0a:4f:00:02");
        mock.push_output(0, &bridge_derived, ""); // verify
        mock.push_output(0, VTEP, ""); // verify vtep mtu
        let mgr = manager(dir.path(), &mock);
        mgr.ensure_overlay_segment(&segment()).await.unwrap();
        let calls = mock.calls();
        assert!(
            calls.contains(&"/sbin/ifconfig ntx-br0 inet 10.79.0.3 -alias".to_owned()),
            "{calls:?}"
        );
        // Ours is already there, so it is not re-added.
        assert!(
            !calls.iter().any(|c| c.contains("inet 10.79.0.2/24")),
            "{calls:?}"
        );
        // The description was already ours, so it was not rewritten; the group
        // marker was missing (interrupted tagging) and was repaired.
        assert!(
            !calls.iter().any(|c| c.contains("description")),
            "{calls:?}"
        );
        assert!(
            calls.contains(&"/sbin/ifconfig ntx-br0 group satl".to_owned()),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn ensure_refuses_a_missing_or_unhealthy_vtep_and_never_creates_one() {
        let dir = tempfile::tempdir().unwrap();
        // Missing.
        let mock = MockRunner::new();
        mock.push_output(1, "", MISSING);
        let mgr = manager(dir.path(), &mock);
        let err = mgr.ensure_overlay_segment(&segment()).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("owned by satl-overlay"), "{text}");
        assert_eq!(mock.calls(), ["/sbin/ifconfig ntx-vx0"], "no vxlan create");

        // Present, UP, not RUNNING: the documented silent failure.
        let mock = MockRunner::new();
        mock.push_output(
            0,
            &VTEP.replace(
                "1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP>",
                "1008803<UP,BROADCAST,SIMPLEX,MULTICAST,LOWER_UP>",
            ),
            "",
        );
        let mgr = manager(dir.path(), &mock);
        let err = mgr.ensure_overlay_segment(&segment()).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("RUNNING is the only health signal"), "{text}");
        assert!(text.contains("/var/log/messages"), "{text}");
        assert_eq!(mock.calls().len(), 1, "nothing else was attempted");
    }

    #[tokio::test]
    async fn ensure_refuses_another_networks_vtep() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(
            0,
            &VTEP.replace("satl:vxlan:ntxnet", "satl:vxlan:other"),
            "",
        );
        let mgr = manager(dir.path(), &mock);
        let err = mgr.ensure_overlay_segment(&segment()).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("VTEP of network 'other'"), "{text}");
        assert!(text.contains("join two overlay networks"), "{text}");
    }

    #[tokio::test]
    async fn ensure_refuses_a_bridge_name_owned_by_something_else() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, VTEP, "");
        mock.push_output(
            0,
            &BRIDGE.replace("satl:overlay:ntxnet", "podman:cni-podman0"),
            "",
        );
        let mgr = manager(dir.path(), &mock);
        let err = mgr.ensure_overlay_segment(&segment()).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("refusing to destroy"), "{text}");
        assert!(text.contains("podman:cni-podman0"), "{text}");
    }

    // ---- attach / detach ----------------------------------------------------

    #[tokio::test]
    async fn attach_sets_mac_and_both_mtus_before_addm_and_verifies_both_ends() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "epair4a\n", ""); // epair create
        mock.push_ok(); // descr a
        mock.push_ok(); // group a
        mock.push_ok(); // descr b
        mock.push_ok(); // ether b
        mock.push_ok(); // mtu a
        mock.push_ok(); // mtu b
        mock.push_ok(); // addm a
        mock.push_ok(); // up a
        mock.push_output(0, EPAIR_A, ""); // verify a
        mock.push_ok(); // vnet
        mock.push_ok(); // -j inet
        mock.push_ok(); // -j mtu
        mock.push_ok(); // -j up b
        mock.push_ok(); // -j up lo0
        mock.push_output(0, EPAIR_B, ""); // verify b
        let mgr = manager(dir.path(), &mock);
        let att = mgr
            .attach_task_overlay(
                &segment(),
                &OverlayAttach::new("ntxtask00000000000001x", "ntx-j1", ip("10.79.0.11")),
            )
            .await
            .unwrap();
        assert_eq!(att.epair_a, "epair4a");
        assert_eq!(att.epair_b, "epair4b");
        assert_eq!(att.mac, MacAddr::from_ipv4(ip("10.79.0.11")));
        assert_eq!(att.mac.to_string(), "02:42:0a:4f:00:0b");
        assert_eq!(att.mtu, 1450);
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair create",
                "/sbin/ifconfig epair4a description satl:overlay:ntxnet:ntxtask00000000000001x",
                "/sbin/ifconfig epair4a group satl",
                "/sbin/ifconfig epair4b description satl:overlay:ntxnet:ntxtask00000000000001x",
                // The derived MAC, on the host, before the move.
                "/sbin/ifconfig epair4b ether 02:42:0a:4f:00:0b",
                // Both MTUs before `addm`: a member's MTU cannot be set at all.
                "/sbin/ifconfig epair4a mtu 1450",
                "/sbin/ifconfig epair4b mtu 1450",
                "/sbin/ifconfig ntx-br0 addm epair4a",
                "/sbin/ifconfig epair4a up",
                "/sbin/ifconfig epair4a",
                "/sbin/ifconfig epair4b vnet ntx-j1",
                "/sbin/ifconfig -j ntx-j1 epair4b inet 10.79.0.11/24",
                // Again in the jail: nothing propagates to this end.
                "/sbin/ifconfig -j ntx-j1 epair4b mtu 1450",
                "/sbin/ifconfig -j ntx-j1 epair4b up",
                "/sbin/ifconfig -j ntx-j1 lo0 up",
                "/sbin/ifconfig -j ntx-j1 epair4b",
            ]
        );
    }

    #[tokio::test]
    async fn attach_can_add_a_default_route_but_does_not_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "epair4a\n", "");
        for _ in 0..8 {
            mock.push_ok();
        }
        mock.push_output(0, EPAIR_A, "");
        for _ in 0..5 {
            mock.push_ok();
        }
        mock.push_output(0, "add net default: gateway 10.79.0.2\n", ""); // route
        mock.push_output(0, EPAIR_B, "");
        let mgr = manager(dir.path(), &mock);
        mgr.attach_task_overlay(
            &segment(),
            &OverlayAttach::new("ntxtask00000000000001x", "ntx-j1", ip("10.79.0.11"))
                .with_default_route(true),
        )
        .await
        .unwrap();
        assert!(
            mock.calls()
                .contains(&"/sbin/route -j ntx-j1 add default 10.79.0.2".to_owned()),
            "{:?}",
            mock.calls()
        );
    }

    #[tokio::test]
    async fn attach_rolls_the_epair_back_when_the_in_jail_mtu_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "epair4a\n", "");
        for _ in 0..8 {
            mock.push_ok();
        }
        mock.push_output(0, EPAIR_A, ""); // verify a: fine
        for _ in 0..5 {
            mock.push_ok();
        }
        // The in-jail end came back at 1500 while looking perfect otherwise:
        // case B, the silent one (docs/vxlan.md §6).
        mock.push_output(0, &EPAIR_B.replace("mtu 1450", "mtu 1500"), "");
        mock.push_ok(); // rollback: destroy epair4a
        let mgr = manager(dir.path(), &mock);
        let err = mgr
            .attach_task_overlay(
                &segment(),
                &OverlayAttach::new("ntxtask00000000000001x", "ntx-j1", ip("10.79.0.11")),
            )
            .await
            .unwrap_err();
        match &err {
            NetError::Attach {
                step, rolled_back, ..
            } => {
                assert_eq!(step, &AttachStep::Verify);
                assert!(rolled_back);
            }
            other => panic!("expected Attach, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("verify"), "{text}");
        assert!(text.contains("has mtu 1500, expected 1450"), "{text}");
        assert_eq!(
            mock.calls().last().unwrap(),
            "/sbin/ifconfig epair4a destroy"
        );
    }

    #[tokio::test]
    async fn attach_validates_the_address_against_the_subnet() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        let mgr = manager(dir.path(), &mock);
        for (address, expected) in [
            ("10.80.0.11", "outside the network's subnet"),
            ("10.79.0.1", "reserved .1"),
            ("10.79.0.2", "this node's gateway"),
            ("10.79.0.0", "network or broadcast"),
            ("10.79.0.255", "network or broadcast"),
        ] {
            let err = mgr
                .attach_task_overlay(
                    &segment(),
                    &OverlayAttach::new("ntxtask00000000000001x", "ntx-j1", ip(address)),
                )
                .await
                .unwrap_err();
            let text = err.to_string();
            assert!(text.contains(expected), "{address}: {text}");
        }
        // A task id carrying the marker separator would corrupt the grammar.
        let err = mgr
            .attach_task_overlay(
                &segment(),
                &OverlayAttach::new("has:colon", "ntx-j1", ip("10.79.0.11")),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("marker grammar"), "{err}");
        // Nothing was executed for any of them.
        assert!(mock.calls().is_empty(), "{:?}", mock.calls());
    }

    #[tokio::test]
    async fn detach_is_idempotent_and_handles_a_returned_b_end() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_ok(); // first: a end exists
        mock.push_output(1, "", MISSING); // second: a gone
        mock.push_ok(); // b returned to the host
        mock.push_output(1, "", MISSING); // third: both gone
        mock.push_output(1, "", MISSING);
        let mgr = manager(dir.path(), &mock);
        let att = OverlayAttachment {
            network: "ntxnet".to_owned(),
            epair_a: "epair4a".to_owned(),
            epair_b: "epair4b".to_owned(),
            ip: ip("10.79.0.11"),
            mac: MacAddr::from_ipv4(ip("10.79.0.11")),
            mtu: 1450,
        };
        for _ in 0..3 {
            mgr.detach_task_overlay("ntxtask00000000000001x", &att)
                .await
                .unwrap();
        }
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig epair4a destroy",
                "/sbin/ifconfig epair4a destroy",
                "/sbin/ifconfig epair4b destroy",
                "/sbin/ifconfig epair4a destroy",
                "/sbin/ifconfig epair4b destroy",
            ]
        );
    }

    // ---- teardown and sweep -------------------------------------------------

    #[tokio::test]
    async fn destroying_a_segment_detaches_the_vtep_and_destroys_only_our_members() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        // The bridge has our VTEP, one of our orphaned epairs, and a member
        // that is not ours at all.
        let bridge = BRIDGE.replace(
            "\tmember: epair4a flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n\
             \t        port 21 priority 128 path cost 2000 vlan protocol 802.1q\n",
            "\tmember: epair4a flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n\
             \t        port 21 priority 128 path cost 2000 vlan protocol 802.1q\n\
             \tmember: ice1 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n\
             \t        port 22 priority 128 path cost 2000 vlan protocol 802.1q\n",
        );
        mock.push_output(0, &bridge, ""); // state_if_exists(bridge)
        mock.push_ok(); // deletem vtep
        mock.push_output(0, EPAIR_A, ""); // classify epair4a -> ours
        mock.push_ok(); // destroy epair4a
        mock.push_output(
            0,
            "ice1: flags=8843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n",
            "",
        ); // ice1: no marker
        mock.push_ok(); // destroy bridge
        let mgr = manager(dir.path(), &mock);
        assert!(mgr.destroy_overlay_segment(&segment()).await.unwrap());
        assert_eq!(
            mock.calls(),
            [
                "/sbin/ifconfig ntx-br0",
                "/sbin/ifconfig ntx-br0 deletem ntx-vx0",
                "/sbin/ifconfig epair4a",
                "/sbin/ifconfig epair4a destroy",
                "/sbin/ifconfig ice1",
                "/sbin/ifconfig ntx-br0 destroy",
            ],
            "the VTEP is detached, never destroyed; a foreign member is left alone"
        );
    }

    #[tokio::test]
    async fn destroying_a_segment_is_idempotent_and_ownership_checked() {
        let dir = tempfile::tempdir().unwrap();
        // Already gone.
        let mock = MockRunner::new();
        mock.push_output(1, "", MISSING);
        let mgr = manager(dir.path(), &mock);
        assert!(!mgr.destroy_overlay_segment(&segment()).await.unwrap());

        // Same name, someone else's interface.
        let mock = MockRunner::new();
        mock.push_output(
            0,
            &BRIDGE.replace("satl:overlay:ntxnet", "satl:overlay:other"),
            "",
        );
        let mgr = manager(dir.path(), &mock);
        let err = mgr.destroy_overlay_segment(&segment()).await.unwrap_err();
        assert!(err.to_string().contains("refusing to destroy"), "{err}");
        assert_eq!(mock.calls(), ["/sbin/ifconfig ntx-br0"]);
    }

    #[tokio::test]
    async fn sweep_destroys_undesired_epairs_keeps_desired_ones_and_never_touches_a_vtep() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        // list_owned: satl group, then the epair/bridge/vxlan driver groups.
        mock.push_output(0, "ntx-br0\nepair4a\n", ""); // group satl
        mock.push_output(0, "epair4a\nepair4b\nepair7a\n", ""); // group epair
        mock.push_output(0, "ntx-br0\nntx-br1\n", ""); // group bridge
        mock.push_output(0, "ntx-vx0\nntx-vx1\n", ""); // group vxlan
        // get_descr for the union, in BTreeSet order:
        // epair4a epair4b epair7a ntx-br0 ntx-br1 ntx-vx0 ntx-vx1
        let descr =
            |text: &str| format!("x: flags=8843<UP> metric 0 mtu 1450\n\tdescription: {text}\n");
        mock.push_output(0, &descr("satl:overlay:ntxnet:keepme"), "");
        mock.push_output(0, &descr("satl:overlay:ntxnet:keepme"), "");
        mock.push_output(0, &descr("satl:overlay:gone:orphan"), "");
        mock.push_output(0, &descr("satl:overlay:ntxnet"), "");
        mock.push_output(0, &descr("satl:overlay:gone"), "");
        mock.push_output(0, &descr("satl:vxlan:ntxnet"), "");
        mock.push_output(0, &descr("satl:vxlan:gone"), "");
        // The orphaned epair of network `gone`.
        mock.push_ok(); // destroy epair7a
        // Network `gone` has no desired tasks: its bridge goes, its VTEP stays.
        mock.push_output(0, &descr("satl:overlay:gone"), ""); // state_if_exists(ntx-br1)
        mock.push_ok(); // deletem ntx-vx1
        mock.push_ok(); // destroy ntx-br1
        let mgr = manager(dir.path(), &mock);
        let desired: BTreeMap<String, BTreeSet<String>> =
            BTreeMap::from([("ntxnet".to_owned(), BTreeSet::from(["keepme".to_owned()]))]);
        let sweep = mgr.sweep_overlay(&desired).await.unwrap();
        assert_eq!(sweep.destroyed_epairs, ["epair7a"]);
        assert_eq!(sweep.destroyed_bridges, ["ntx-br1"]);
        assert_eq!(sweep.adopted_epairs, ["epair4a", "epair4b"]);
        assert_eq!(sweep.adopted_bridges, ["ntx-br0"]);
        assert_eq!(sweep.preserved_vteps, ["ntx-vx0", "ntx-vx1"]);
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.contains("ntx-vx0 destroy")),
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.contains("ntx-vx1 destroy")),
            "{calls:?}"
        );
        assert!(
            calls.contains(&"/sbin/ifconfig ntx-br1 deletem ntx-vx1".to_owned()),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn sweep_leaves_a_network_with_no_tasks_yet_alone() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockRunner::new();
        mock.push_output(0, "ntx-br0\n", ""); // group satl
        mock.push_output(0, "", ""); // group epair
        mock.push_output(0, "ntx-br0\n", ""); // group bridge
        mock.push_output(0, "", ""); // group vxlan
        mock.push_output(
            0,
            "ntx-br0: flags=8843<UP> metric 0 mtu 1450\n\tdescription: satl:overlay:ntxnet\n",
            "",
        );
        let mgr = manager(dir.path(), &mock);
        // Present as a key with no tasks: the segment was just ensured and its
        // first task has not attached yet.
        let desired: BTreeMap<String, BTreeSet<String>> =
            BTreeMap::from([("ntxnet".to_owned(), BTreeSet::new())]);
        let sweep = mgr.sweep_overlay(&desired).await.unwrap();
        assert_eq!(sweep.adopted_bridges, ["ntx-br0"]);
        assert!(sweep.destroyed_bridges.is_empty());
    }
}
