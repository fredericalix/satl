// SPDX-License-Identifier: BSD-2-Clause
//! VXLAN overlay: VTEP/FDB programming and the embedded DNS responder.
//! Lands in M3. See `docs/architecture.md` §11.
//!
//! This wave implements the **service-discovery half**: SatL resolves service
//! names to the addresses of their running tasks, shuffled per query, with no
//! VIP and no data-path load balancer (architecture §11.5 — FreeBSD has no
//! IPVS, and pf-based per-connection balancing would add state and failure
//! modes). Layout:
//!
//! - [`endpoints`] — the [`EndpointTable`]: per network, service name and task
//!   name → the addresses of the **running** tasks behind them. Pure state; it
//!   holds the four rules that make DNS round-robin a load balancer.
//! - [`dns`] — a hand-rolled RFC 1035 subset (one question, `A`/`AAAA`, class
//!   `IN`), written rather than depended on because it faces untrusted
//!   datagrams from inside containers. Never panics, never loops.
//! - [`scopes`] — the [`ScopeTable`]: source address → the querying task and
//!   the networks its queries may be answered from, in attachment order. What
//!   a client may resolve is decided by *which task is asking*, never by which
//!   socket it reached; a source belonging to no local task resolves nothing.
//! - [`server`] — the tokio UDP responder: answers from the table, forwards
//!   the rest to the host's resolvers under a timeout and a bounded number of
//!   in-flight forwards. **Bind addresses are a parameter** (gateway-per-network
//!   or one-per-node is a data-plane decision); every socket answers the same
//!   way, from the querying task's scope.
//! - [`resolv`] — reading the host's `resolv.conf` and rendering the one a
//!   container gets.
//!
//! Not here, on purpose: TCP (a truncated round-robin answer is a usable
//! answer — [`dns`] sets `TC` and stops), EDNS0, zone data, and any record
//! type beyond `A`/`AAAA`.
//!
//! # The data plane (architecture §11.2, spec `docs/vxlan.md`)
//!
//! The other half: the VXLAN tunnel itself and the entries that carry frames
//! across it. Every idiom is coded against `docs/vxlan.md`, which is measured
//! ground truth from the cluster VMs, and the parsers are tested against
//! output captured from the same kernel (`tests/fixtures/`).
//!
//! - [`runner`] — the crate's injectable process-execution seam, so every
//!   external-command wrapper is unit-testable unprivileged.
//! - [`vxlan`] — the VTEP interface lifecycle: create a unicast interface with
//!   a **blackhole default remote**, rename it atomically, set the MTU
//!   explicitly, bring it up, and **verify `RUNNING`** — the only health
//!   signal vxlan(4) gives, since `ifconfig` reports success for an interface
//!   the driver refused.
//! - [`ftable`] — the static forwarding table, through the one ioctl
//!   `ifconfig`(8) does not expose. One of the crate's two `unsafe` submodules,
//!   whose struct layouts are asserted against the kernel's.
//! - [`arp`] — static ARP inside a task jail's VNET, which is mandatory rather
//!   than an optimisation: a broadcast ARP request only ever reaches the
//!   blackhole default remote. Holds the [`JailArp`] interface and the
//!   `jexec arp` implementation of it, which works only for `path=/` jails.
//! - [`lltable`] — the mechanism that works for a **container**: `jail_attach`(2)
//!   plus a `PF_ROUTE` socket with `RTF_LLDATA`, which is what `arp`(8) does
//!   internally. An OCI image ships no usable `arp`(8), and SatL puts no files
//!   in one. Second home of the crate's `unsafe`, same discipline as [`ftable`].
//! - [`arphelper`] — the process boundary that makes [`lltable`] safe to use from
//!   a multi-threaded daemon: `satld` **re-executes itself** with a hidden
//!   subcommand, and the short-lived child attaches to the jail. The default
//!   [`JailArp`] for a task.
//! - [`program`] — the reconciler. [`OverlayDelta::between`] is pure and is
//!   where all the reasoning lives; [`Programmer`] reads the kernel, applies a
//!   delta and reports what it did.
//! - [`ipsec`] — ESP transport-mode SAs/SPs through `setkey`(8) for encrypted
//!   networks (M6): libnetwork-compatible SPI derivation, `aes-gcm-16` key
//!   rendering, idempotent ensure/remove operations, and the pure
//!   desired-state reconciler whose adds-before-deletes order IS the measured
//!   key-rotation protocol (`hack/experiments/esp/README.md` §6).
//!
//! The shape of the whole thing, per overlay network on a node hosting at
//! least one of its tasks:
//!
//! ```text
//!  satl-vx<vni>  (vxlan, mtu = underlay - 50, -vxlanlearn,
//!       │         vxlanremote = blackhole)          ── FDB: mac(ip) -> peer VTEP
//!  satl-br-<net> (bridge, mtu set explicitly)
//!       │
//!  epairNa ──────────────────────────── epairNb  in the jail's VNET
//!                                        mtu set explicitly (nothing
//!                                        propagates to it), ether mac(ip),
//!                                        arp -s for every other endpoint
//! ```
//!
//! The bridge and the epairs are `satl-net`'s (`NetworkManager`); this crate
//! owns the vxlan interface, the FDB and the in-jail ARP tables.

pub mod arp;
pub mod arphelper;
pub mod dns;
pub mod endpoints;
pub mod ftable;
pub mod ipsec;
pub mod lltable;
pub mod program;
pub mod resolv;
pub mod runner;
pub mod scopes;
pub mod server;
pub mod vxlan;

pub use arp::{
    Arp, ArpApplied, ArpBatch, ArpEntry, ArpError, DEFAULT_ARP_COMMAND, DEFAULT_JEXEC_BINARY,
    JailArp,
};
pub use arphelper::{
    ArpHelper, DEFAULT_TIMEOUT, EntryResult, Fatal, HELPER_SUBCOMMAND, OpKind, Outcome,
    PROTOCOL_VERSION, ProtocolError, Request, Response, child_main, execute, parse_request,
    parse_response, render_request, render_response,
};
pub use dns::{
    AnswerReply, MAX_UDP_PAYLOAD, Name, NameError, ParseError, Query, Question, Rcode, StatusReply,
    encode_query, parse_query,
};
pub use endpoints::{EndpointRecord, EndpointTable, Family, Lookup, records_for_task};
pub use ftable::{
    FlushScope, Ftable, FtableEntry, FtableError, FtableOps, FtableReader, FtableRecord,
    UNIT_PROBE_MAC, VXLAN_FE_FLAG_DYNAMIC, VXLAN_FE_FLAG_STATIC, VtepInfo,
};
pub use ipsec::{
    Direction, Ipsec, IpsecError, PeerSecurity, PortSelector, PresentSecurity, SecurityAssociation,
    SecurityOp, SecurityPlan, SecurityPolicy, aead_key_hex, desired_sp, inbound_spi, outbound_spi,
    plan_security,
};
pub use lltable::{
    ETHER_ADDR_LEN, LinkTarget, LlEntry, LlError, RouteSocket, attach, attach_to, resolve_jid,
    table,
};
pub use program::{
    Applied, ArpBinding, ArpRemoval, DesiredOverlay, LocalEndpoint, OverlayDelta, ProgramError,
    ProgrammedState, Programmer, RemoteEndpoint,
};
pub use resolv::{DNS_PORT, HostResolvConf, MAX_NAMESERVERS, OverlayResolvConf, ResolvConfError};
pub use runner::{CommandOutput, CommandRunner, Failure, PipedRunner, SystemRunner};
pub use scopes::{QueryScope, ScopeTable, TaskScope, scope_for_task};
pub use server::{DnsServer, DnsServerConfig, DnsServerError, DnsStats, Upstream};
pub use vxlan::{
    DEFAULT_OVERLAY_MTU, DEFAULT_OVERLAY_MTU_ENCRYPTED, DEFAULT_UNDERLAY_MTU,
    ESP_TRANSPORT_OVERHEAD, FTABLE_MAX, IfaceFlags, MAX_IFACE_NAME_LEN, OwnedVtep, VNI_MAX,
    VXLAN_ENCAP_OVERHEAD_V4, VXLAN_ENCAP_OVERHEAD_V6, VXLAN_ESP_ENCAP_OVERHEAD_V4, VXLAN_GROUP,
    VXLAN_KLD, VXLAN_PORT, VtepConfig, VtepIface, VtepSpec, Vxlan, VxlanError, overlay_mtu_v4,
    overlay_mtu_v4_encrypted, overlay_mtu_v6, vtep_descr, vtep_iface_name,
};
