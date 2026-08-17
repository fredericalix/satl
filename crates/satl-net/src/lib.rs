// SPDX-License-Identifier: BSD-2-Clause
//! Node-local networking for SatL: VNET jail plumbing (epair/bridge), pf
//! `satl/*` anchors, local IPAM, and orphan reconciliation. Lands in M1.
//! See `docs/architecture.md` §11.1 and §15.
//!
//! Layout:
//!
//! - [`runner`] — injectable process execution (the crate's local
//!   `CommandRunner` seam, mirroring `satl-storage::zfs`);
//! - [`ifconfig`] / [`route`] — typed wrappers around `ifconfig`(8) and
//!   `route`(8), every idiom verified live on FreeBSD 15.1 and parsed
//!   against real captured fixtures;
//! - [`pf`] — `satl/nat` + `satl/rdr` rule generation and anchor loading
//!   (full-ruleset regeneration, never incremental; anchor ownership
//!   enforced in code);
//! - [`ipam`] — node-local /24-per-network allocation from the
//!   `10.88.0.0/16` pool with atomic JSON persistence;
//! - [`manager`] — [`NetworkManager`], composing all of the above:
//!   `ensure_host_network`, `attach_task`/`detach_task` with rollback,
//!   `list_owned`/`destroy_orphans` reconciliation, port publishing;
//! - [`overlay`] — the node-local half of a **cluster overlay** network (M3):
//!   a bridge per overlay network with `satl-overlay`'s VTEP as a member, this
//!   node's per-node gateway address on it, and epairs carrying the overlay
//!   MTU explicitly on both ends and the derived MAC inside the jail.
//!
//! The overlay's vxlan interface is **not** this crate's: `satl-overlay`
//! creates and owns it (`docs/architecture.md` §2 allows
//! `satl-overlay → satl-net`, so the reverse edge does not exist), and
//! [`OverlaySegment::vtep`] is the name of the interface to bridge.

pub mod arp;
pub mod ifconfig;
pub mod ipam;
pub mod manager;
pub mod overlay;
pub mod pf;
pub mod route;
pub mod runner;

pub use arp::{Arp, ArpError};
pub use ifconfig::{EpairPair, IfaceState, Ifconfig, IfconfigError, MAX_IFACE_NAME_LEN};
pub use ipam::{DEFAULT_LOCAL_BRIDGE_POOL, IpamError, LocalIpam, NETWORK_PREFIX_LEN, SubnetV4};
pub use manager::{
    AttachStep, HostNetwork, NetError, NetworkManager, NetworkManagerConfig, OwnedIface, OwnedKind,
    PfMode, PortReconcile, TaskAttachment, TaskRedirects,
};
pub use overlay::{
    ETHERMIN, OVERLAY_MARKER, OverlayAttach, OverlayAttachment, OverlayBridge, OverlayError,
    OverlaySegment, OverlaySweep, SUSPICIOUS_OVERLAY_MTU, Stack, VTEP_MARKER, overlay_bridge_name,
};
pub use pf::{
    ANCHOR_GUARD, ANCHOR_NAT, ANCHOR_RDR, ENC_IFACE, MeshEgress, PfCtl, PfError, PoolKey,
    PortPublish, guard_rules, mesh_rules, nat_rules, pool_publishes, rdr_rules, table_name,
};
pub use route::{Route, RouteError};
pub use runner::{CommandOutput, CommandRunner, Failure, SystemRunner};
