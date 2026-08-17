// SPDX-License-Identifier: BSD-2-Clause
//! The overlay data-plane reconciler: desired endpoints in, kernel state out.
//!
//! Split in two on purpose. [`OverlayDelta::between`] is **pure**: it takes the
//! endpoint table a network has on this node and the state currently
//! programmed, and computes what to change. [`Programmer`] is the impure half:
//! it reads the current state, applies a delta and reports what it did. All the
//! reasoning is in the pure half, where it is exhaustively testable.
//!
//! ## What has to be programmed, and where
//!
//! Per overlay network on a node hosting at least one of its tasks
//! (`docs/vxlan.md` §7):
//!
//! | For | Entry | Where |
//! |---|---|---|
//! | each **remote** endpoint | MAC → remote VTEP | the vxlan FDB, once per node |
//! | each **other** endpoint | overlay IP → MAC | the ARP table of every local jail |
//!
//! Two asymmetries drive the whole design:
//!
//! - **The FDB is per node, the ARP tables are per jail.** Adding one remote
//!   endpoint is one FDB entry plus one ARP entry *per local task*.
//! - **A local endpoint gets no FDB entry.** Its MAC lives on the bridge, so a
//!   frame for it must be switched locally; an FDB entry would hand it to a
//!   VTEP. When a task migrates onto this node its stale entry therefore has to
//!   go, which falls out of the diff for free.
//!
//! ## ARP for local peers too
//!
//! `docs/vxlan.md` §7 requires static ARP for *remote* endpoints. This module
//! programs it for **every** endpoint on the network except the jail's own
//! addresses, local peers included, for two reasons:
//!
//! - it removes the last broadcast ARP from the segment. A broadcast is flooded
//!   to the vxlan member and handed to the blackhole default remote, so
//!   resolving a *local* peer by broadcast pollutes the signal `docs/vxlan.md`
//!   §2 wants to mean "something is trying to reach an endpoint the control
//!   plane has not programmed".
//!
//!   **That signal is weaker than it looks, in two ways worth writing down.**
//!   Measured in
//!   `hack/experiments/jail-arp/captures/30-premise-and-mechanism.txt` §3: three
//!   pings to an unresolved peer left the vxlan interface at `Opkts 0` with
//!   `Oerrs` up by four, so the flooded ARP requests were counted as errors —
//!   but only because that experiment's blackhole was an address `ip_output()`
//!   could not deliver to at all. Point the default remote at an address that
//!   *routes* and merely discards, and the very same frames are transmitted
//!   successfully and land in `Opkts` instead. `Oerrs` is therefore a property of
//!   the blackhole's unreachability, not of BUM traffic as such.
//!
//!   And the jail's own counters never show it either: `arpresolve()` returns
//!   `EWOULDBLOCK` while an address is unresolved and `ether_output()` masks that
//!   to success, so the frames the container thought it sent are counted as
//!   sent. `Oerrs > 0` is a useful hint; `Oerrs == 0` proves nothing. The design
//!   conclusion is unchanged either way: do not leave any peer to broadcast;
//! - the ARP table then depends only on *which* endpoints exist, never on
//!   where they live, because the MAC is a pure function of the address. A task
//!   migrating between nodes changes FDB entries and no ARP entry anywhere.
//!
//! ## Ownership, and what is never touched
//!
//! - The **whole FDB of a SatL-owned vxlan interface is SatL's**: learning is
//!   off, so anything in it was put there by this code (or by an interrupted
//!   [`crate::ftable::FtableReader::resolve_unit`] probe) and anything not
//!   desired is removed.
//! - An **ARP table is shared** with the jail's own stack. Only entries that
//!   pass [`crate::arp::ArpEntry::is_overlay_static`] and are not one of that
//!   jail's own addresses are ever removed — never the learned gateway entry,
//!   whose removal `docs/vxlan.md` §8 shows to be a silent black hole.
//! - A jail present in the programmed state but absent from the desired state
//!   is **left alone** and reported in [`OverlayDelta::unmanaged_jails`].
//!   Detaching a task is an explicit teardown, not a diff outcome: the desired
//!   state carries no addresses for such a jail, so a diff cannot tell an
//!   entry of ours from the jail's own.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use satl_core::{Ipv4Cidr, MacAddr};

use crate::arp::{ArpApplied, ArpBatch, ArpError, JailArp};
use crate::arphelper::ArpHelper;
use crate::ftable::{FlushScope, Ftable, FtableEntry, FtableError, FtableOps, FtableReader};
use crate::runner::{CommandRunner, SystemRunner};

// ---------------------------------------------------------------------------
// Desired state
// ---------------------------------------------------------------------------

/// A task of this network running on **this** node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalEndpoint {
    /// Jail name or jid, as `jexec` takes it.
    pub jail: String,
    /// The task's address on this network.
    pub ip: Ipv4Addr,
}

impl LocalEndpoint {
    /// A local endpoint.
    pub fn new(jail: impl Into<String>, ip: Ipv4Addr) -> Self {
        Self {
            jail: jail.into(),
            ip,
        }
    }
}

/// An endpoint of this network living on another node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RemoteEndpoint {
    /// The endpoint's address on this network.
    pub ip: Ipv4Addr,
    /// Underlay address of the node hosting it — its VTEP.
    pub vtep: Ipv4Addr,
}

impl RemoteEndpoint {
    /// A remote endpoint.
    #[must_use]
    pub fn new(ip: Ipv4Addr, vtep: Ipv4Addr) -> Self {
        Self { ip, vtep }
    }
}

/// Everything one overlay network wants programmed on one node.
///
/// This is the shape the wiring wave has to produce from the dispatcher's
/// assignment stream and the store's endpoint records: local attachments with
/// their jails, remote endpoints with their nodes' VTEPs, and this node's own
/// VTEP so a contradiction can be spotted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredOverlay {
    /// The network's VTEP interface on this node.
    pub iface: String,
    /// This node's underlay address, i.e. the interface's `vxlanlocal`.
    pub local_vtep: Ipv4Addr,
    /// Tasks of this network running here.
    pub local: Vec<LocalEndpoint>,
    /// Endpoints of this network elsewhere in the cluster.
    pub remote: Vec<RemoteEndpoint>,
    /// This network's subnet: which ARP entries in a jail belong to **this**
    /// network and may therefore be removed by its passes.
    ///
    /// **A jail can be on several overlay networks, and they share one ARP
    /// table.** The jail has one epair per network but a single VNET, so
    /// `arp -an` inside it lists every network's entries together. Without a
    /// way to attribute them, each network's pass sees the others' entries as
    /// unwanted and deletes them — measured on the cluster VMs as a permanent
    /// `arp +1 -1` on both networks every resync, with whichever ran last
    /// working and the other answering `Host is down`.
    ///
    /// The subnet is the attribution: overlay subnets are allocated disjoint
    /// from one cluster pool (architecture §11.3), so an address inside this
    /// one is this network's and an address outside it is somebody else's.
    ///
    /// `None` means "cannot attribute", and then a pass removes nothing it did
    /// not find in its own desired set — the same ownership discipline as the
    /// interface markers: unattributable means untouched. Production always
    /// sets it (`satld` takes it from the network's `OverlaySegment`); it is an
    /// `Option` for the tests and probes that reconcile one network and have no
    /// subnet to speak of.
    pub subnet: Option<Ipv4Cidr>,
}

impl DesiredOverlay {
    /// An empty desired state for `iface`.
    pub fn new(iface: impl Into<String>, local_vtep: Ipv4Addr) -> Self {
        Self {
            iface: iface.into(),
            local_vtep,
            local: Vec::new(),
            remote: Vec::new(),
            subnet: None,
        }
    }

    /// Declares the network's subnet, so that a jail shared with another
    /// overlay network keeps that network's ARP entries. See
    /// [`DesiredOverlay::subnet`] — always set this outside tests.
    #[must_use]
    pub fn with_subnet(mut self, subnet: Ipv4Cidr) -> Self {
        self.subnet = Some(subnet);
        self
    }

    /// Whether an address seen in a jail is one this network may manage.
    fn owns(&self, ip: Ipv4Addr) -> bool {
        self.subnet.is_none_or(|subnet| subnet.contains(ip))
    }

    /// Adds a local attachment.
    #[must_use]
    pub fn with_local(mut self, endpoints: impl IntoIterator<Item = LocalEndpoint>) -> Self {
        self.local.extend(endpoints);
        self
    }

    /// Adds remote endpoints.
    #[must_use]
    pub fn with_remote(mut self, endpoints: impl IntoIterator<Item = RemoteEndpoint>) -> Self {
        self.remote.extend(endpoints);
        self
    }

    /// The addresses each local jail holds on this network.
    fn own_addresses(&self) -> BTreeMap<&str, BTreeSet<Ipv4Addr>> {
        let mut out: BTreeMap<&str, BTreeSet<Ipv4Addr>> = BTreeMap::new();
        for endpoint in &self.local {
            out.entry(endpoint.jail.as_str())
                .or_default()
                .insert(endpoint.ip);
        }
        out
    }

    /// Fold the endpoint lists into the two tables the kernel actually holds.
    ///
    /// Order-independent by construction (everything lands in a `BTreeMap`)
    /// and deterministic in the face of contradictory input: a duplicated
    /// address keeps the **numerically smallest** VTEP and records the clash
    /// in `conflicts` rather than depending on input order.
    fn normalize(&self) -> Normalized {
        let mut conflicts = Vec::new();
        let local_addresses: BTreeSet<Ipv4Addr> =
            self.local.iter().map(|endpoint| endpoint.ip).collect();

        // --- the FDB: remote endpoints only.
        let mut ftable: BTreeMap<MacAddr, Ipv4Addr> = BTreeMap::new();
        let mut remote_addresses: BTreeSet<Ipv4Addr> = BTreeSet::new();
        for endpoint in &self.remote {
            if endpoint.vtep == self.local_vtep {
                conflicts.push(format!(
                    "endpoint {} is listed as remote but its VTEP {} is this \
                     node's own; no FDB entry programmed (a self-pointing entry \
                     would send the frame back into the tunnel)",
                    endpoint.ip, endpoint.vtep
                ));
                continue;
            }
            if local_addresses.contains(&endpoint.ip) {
                conflicts.push(format!(
                    "endpoint {} is both local and remote (at VTEP {}); treated \
                     as local, so no FDB entry is programmed for it",
                    endpoint.ip, endpoint.vtep
                ));
                continue;
            }
            if endpoint.vtep.is_unspecified()
                || endpoint.vtep.is_multicast()
                || endpoint.vtep.is_broadcast()
            {
                conflicts.push(format!(
                    "endpoint {} has an unusable VTEP {}; skipped",
                    endpoint.ip, endpoint.vtep
                ));
                continue;
            }
            remote_addresses.insert(endpoint.ip);
            let mac = MacAddr::from_ipv4(endpoint.ip);
            match ftable.get(&mac) {
                Some(existing) if *existing == endpoint.vtep => {}
                Some(existing) => {
                    let (keep, drop) = if *existing <= endpoint.vtep {
                        (*existing, endpoint.vtep)
                    } else {
                        (endpoint.vtep, *existing)
                    };
                    conflicts.push(format!(
                        "endpoint {} is claimed by two VTEPs ({keep} and {drop}); \
                         keeping {keep}",
                        endpoint.ip
                    ));
                    ftable.insert(mac, keep);
                }
                None => {
                    ftable.insert(mac, endpoint.vtep);
                }
            }
        }

        // --- the ARP tables: every endpoint except the jail's own addresses.
        let every_address: BTreeSet<Ipv4Addr> = local_addresses
            .iter()
            .chain(remote_addresses.iter())
            .copied()
            .collect();
        let mut arp: BTreeMap<String, BTreeMap<Ipv4Addr, MacAddr>> = BTreeMap::new();
        for (jail, own) in self.own_addresses() {
            let table = arp.entry(jail.to_owned()).or_default();
            for ip in &every_address {
                if own.contains(ip) {
                    continue;
                }
                table.insert(*ip, MacAddr::from_ipv4(*ip));
            }
        }

        Normalized {
            ftable,
            arp,
            conflicts,
        }
    }
}

/// The desired kernel tables, folded out of an endpoint list.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Normalized {
    ftable: BTreeMap<MacAddr, Ipv4Addr>,
    arp: BTreeMap<String, BTreeMap<Ipv4Addr, MacAddr>>,
    conflicts: Vec<String>,
}

// ---------------------------------------------------------------------------
// Current state
// ---------------------------------------------------------------------------

/// What is currently programmed, as read from the kernel.
///
/// `ftable` is the whole forwarding table of the interface (SatL owns all of
/// it). `arp` holds, per jail, only the entries that passed
/// [`crate::arp::ArpEntry::is_overlay_static`] — see the module docs on
/// ownership.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgrammedState {
    /// Inner MAC → remote VTEP, from `net.link.vxlan.<unit>.ftable.dump`.
    pub ftable: BTreeMap<MacAddr, Ipv4Addr>,
    /// Per jail: overlay IP → MAC, from `arp -an`.
    pub arp: BTreeMap<String, BTreeMap<Ipv4Addr, MacAddr>>,
}

impl ProgrammedState {
    /// Nothing programmed — what a freshly created interface, or one whose FDB
    /// was just flushed with `vxlanflushall`, looks like.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// The delta
// ---------------------------------------------------------------------------

/// One ARP entry to install.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArpBinding {
    /// Jail whose stack the entry goes into.
    pub jail: String,
    /// Overlay address the entry resolves.
    pub ip: Ipv4Addr,
    /// MAC it resolves to.
    pub mac: MacAddr,
}

/// One ARP entry to remove.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArpRemoval {
    /// Jail whose stack the entry is in.
    pub jail: String,
    /// Overlay address to stop resolving.
    pub ip: Ipv4Addr,
}

/// The changes that take the kernel from a [`ProgrammedState`] to a
/// [`DesiredOverlay`].
///
/// Four properties, each with its own test:
///
/// 1. **Idempotent** — a delta computed against a state that already matches
///    is empty, and applying a delta twice changes nothing the second time.
/// 2. **Order-independent** — shuffling the input endpoint lists yields an
///    identical delta, because everything is folded through `BTreeMap`s.
/// 3. **Never a delete of something still wanted.** An entry that is already
///    correct is never touched. The two kernels differ on what a change costs,
///    and the lists reflect it exactly:
///
///    - `arp -s` **overwrites** an existing address's MAC (measured), so a
///      changed ARP entry is a single `arp_add` and `arp_add`/`arp_remove`
///      never share a key;
///    - `VXLAN_CMD_FTABLE_ENTRY_ADD` **refuses** an existing MAC with `EEXIST`,
///      whatever the VTEP (measured; `docs/vxlan.md` §7 claims otherwise and is
///      wrong). A changed VTEP therefore goes in [`Self::ftable_replace`],
///      which the applier performs as one ordered remove-then-add — never as an
///      independent removal that could be reordered against its own re-add.
///
///    So `ftable_add`, `ftable_replace` and `ftable_remove` have pairwise
///    disjoint key sets, and only a MAC whose VTEP actually changed is ever
///    briefly absent.
/// 4. **Conservative** — nothing is removed that was not positively identified
///    as SatL's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayDelta {
    /// The VTEP interface these FDB changes apply to.
    pub iface: String,
    /// Entries whose MAC is not in the table yet.
    pub ftable_add: Vec<FtableEntry>,
    /// Entries whose MAC is in the table pointing at a different VTEP; applied
    /// as remove-then-add, because the kernel refuses to overwrite.
    pub ftable_replace: Vec<FtableEntry>,
    /// Inner MACs to withdraw.
    pub ftable_remove: Vec<MacAddr>,
    /// ARP entries to install or replace (`arp -s` overwrites).
    pub arp_add: Vec<ArpBinding>,
    /// ARP entries to withdraw.
    pub arp_remove: Vec<ArpRemoval>,
    /// Jails found in the programmed state that the desired state says nothing
    /// about; their entries are left untouched.
    pub unmanaged_jails: Vec<String>,
    /// Contradictions in the desired state, resolved deterministically. Worth
    /// logging: every one of them means the control plane disagrees with
    /// itself.
    pub conflicts: Vec<String>,
}

impl OverlayDelta {
    /// Compute the delta from `current` to `desired`.
    ///
    /// Pure: no I/O, no clock, no randomness. See the type docs for the four
    /// properties this guarantees.
    #[must_use]
    pub fn between(desired: &DesiredOverlay, current: &ProgrammedState) -> Self {
        let want = desired.normalize();
        let own = desired.own_addresses();

        // --- FDB. The interface's whole table is ours, so anything not wanted
        // is withdrawn; anything wanted is installed if its MAC is absent and
        // replaced if the MAC is there pointing somewhere else.
        let mut ftable_add = Vec::new();
        let mut ftable_replace = Vec::new();
        for (mac, vtep) in &want.ftable {
            let entry = FtableEntry {
                mac: *mac,
                vtep: *vtep,
            };
            match current.ftable.get(mac) {
                Some(programmed) if programmed == vtep => {}
                Some(_) => ftable_replace.push(entry),
                None => ftable_add.push(entry),
            }
        }
        let ftable_remove: Vec<MacAddr> = current
            .ftable
            .keys()
            .filter(|mac| !want.ftable.contains_key(*mac))
            .copied()
            .collect();

        // --- ARP, per jail.
        let mut arp_add = Vec::new();
        let mut arp_remove = Vec::new();
        let mut unmanaged_jails = Vec::new();
        for (jail, wanted) in &want.arp {
            let programmed = current.arp.get(jail);
            for (ip, mac) in wanted {
                if programmed.and_then(|table| table.get(ip)) != Some(mac) {
                    arp_add.push(ArpBinding {
                        jail: jail.clone(),
                        ip: *ip,
                        mac: *mac,
                    });
                }
            }
            let own_here = own.get(jail.as_str());
            for ip in programmed.map(BTreeMap::keys).into_iter().flatten() {
                // Never withdraw a jail's own address: the kernel installs a
                // permanent entry for it with the very MAC SatL derived, so it
                // looks exactly like one of ours.
                if own_here.is_some_and(|addresses| addresses.contains(ip)) {
                    continue;
                }
                if !wanted.contains_key(ip) {
                    arp_remove.push(ArpRemoval {
                        jail: jail.clone(),
                        ip: *ip,
                    });
                }
            }
        }
        for jail in current.arp.keys() {
            if !want.arp.contains_key(jail) {
                unmanaged_jails.push(jail.clone());
            }
        }

        // Deterministic output regardless of input order. The BTreeMap walks
        // above already produce sorted output; sorting again is cheap and makes
        // the guarantee local to this function.
        ftable_add.sort_unstable();
        ftable_replace.sort_unstable();
        arp_add.sort();
        arp_remove.sort();
        unmanaged_jails.sort();

        Self {
            iface: desired.iface.clone(),
            ftable_add,
            ftable_replace,
            ftable_remove,
            arp_add,
            arp_remove,
            unmanaged_jails,
            conflicts: want.conflicts,
        }
    }

    /// Whether there is nothing to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ftable_add.is_empty()
            && self.ftable_replace.is_empty()
            && self.ftable_remove.is_empty()
            && self.arp_add.is_empty()
            && self.arp_remove.is_empty()
    }

    /// How many kernel operations applying this delta performs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ftable_add.len()
            + self.ftable_replace.len()
            + self.ftable_remove.len()
            + self.arp_add.len()
            + self.arp_remove.len()
    }

    /// One-line description for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}: fdb +{} ~{} -{}, arp +{} -{}",
            self.iface,
            self.ftable_add.len(),
            self.ftable_replace.len(),
            self.ftable_remove.len(),
            self.arp_add.len(),
            self.arp_remove.len()
        )
    }

    /// The ARP half regrouped as one [`ArpBatch`] per jail, in jail order.
    ///
    /// The delta lists entries flat because that is how the diff produces them;
    /// the mechanisms want them per jail, since that is the unit a jail's stack
    /// is reachable in. Within a batch the order is preserved, so `add` still
    /// precedes `remove` (make before break).
    #[must_use]
    pub fn arp_batches(&self) -> BTreeMap<String, ArpBatch> {
        let mut batches: BTreeMap<String, ArpBatch> = BTreeMap::new();
        for binding in &self.arp_add {
            batches
                .entry(binding.jail.clone())
                .or_default()
                .add
                .push((binding.ip, binding.mac));
        }
        for removal in &self.arp_remove {
            batches
                .entry(removal.jail.clone())
                .or_default()
                .remove
                .push(removal.ip);
        }
        batches
    }
}

/// Fold one jail's [`ArpApplied`] into the pass-wide [`Applied`].
fn absorb_arp(jail: &str, outcome: ArpApplied, applied: &mut Applied) {
    applied
        .arp_added
        .extend(outcome.added.into_iter().map(|(ip, mac)| ArpBinding {
            jail: jail.to_owned(),
            ip,
            mac,
        }));
    applied
        .arp_removed
        .extend(outcome.removed.into_iter().map(|ip| ArpRemoval {
            jail: jail.to_owned(),
            ip,
        }));
    applied
        .arp_absent
        .extend(outcome.absent.into_iter().map(|ip| ArpRemoval {
            jail: jail.to_owned(),
            ip,
        }));
    applied.failures.extend(outcome.failures);
}

// ---------------------------------------------------------------------------
// Applying it
// ---------------------------------------------------------------------------

/// What one [`Programmer::apply`] pass actually did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// FDB entries newly installed.
    pub ftable_added: Vec<FtableEntry>,
    /// FDB entries repointed at a different VTEP (remove-then-add).
    pub ftable_replaced: Vec<FtableEntry>,
    /// FDB entries that were present and are now gone.
    pub ftable_removed: Vec<MacAddr>,
    /// FDB entries that were already absent when withdrawn (the idempotent
    /// `ENOENT` case).
    pub ftable_absent: Vec<MacAddr>,
    /// ARP entries installed or replaced.
    pub arp_added: Vec<ArpBinding>,
    /// ARP entries that were present and are now gone.
    pub arp_removed: Vec<ArpRemoval>,
    /// ARP entries that were already absent when withdrawn.
    pub arp_absent: Vec<ArpRemoval>,
    /// Per-item failures, rendered. A partial pass is safe: the delta is
    /// idempotent, so the next pass retries exactly what is still missing.
    pub failures: Vec<String>,
    /// Whether this pass had to **flush the whole forwarding table** and re-push
    /// it because the read-back was unusable
    /// ([`Programmer::reconcile`], [`FtableError::DumpTruncated`]).
    ///
    /// Worth surfacing rather than hiding: it means the network is past the dump
    /// sysctl's one-page ceiling, so every future pass will do the same until the
    /// endpoint count drops. An operator seeing this repeatedly is looking at a
    /// scaling limit, not a transient.
    pub ftable_flushed: bool,
}

impl Applied {
    /// Whether every operation in the delta succeeded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }

    /// One-line description for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "fdb +{} ~{} -{} (absent {}), arp +{} -{} (absent {}), failures {}",
            self.ftable_added.len(),
            self.ftable_replaced.len(),
            self.ftable_removed.len(),
            self.ftable_absent.len(),
            self.arp_added.len(),
            self.arp_removed.len(),
            self.arp_absent.len(),
            self.failures.len()
        )
    }
}

/// Error from reading the currently programmed state.
#[derive(Debug, thiserror::Error)]
pub enum ProgramError {
    /// The forwarding table could not be read.
    #[error(transparent)]
    Ftable(#[from] FtableError),

    /// A jail's ARP table could not be read.
    #[error(transparent)]
    Arp(#[from] ArpError),

    /// The forwarding-table flush that a truncated read-back forces did not run
    /// to completion (the blocking task was cancelled or panicked).
    #[error(
        "overlay: the forwarding-table flush did not run to completion \
         ({reason}); the table is in an unknown state and the next pass will \
         try again"
    )]
    FlushLost {
        /// What went wrong with the blocking task.
        reason: String,
    },

    /// The interface's clone unit no longer has a sysctl node — the interface
    /// was destroyed under the reconciler.
    #[error(
        "overlay: vxlan clone unit {unit} (interface '{iface}') has no sysctl \
         node any more; the interface was destroyed, so its forwarding table is \
         gone and must be re-pushed after it is re-created"
    )]
    UnitGone {
        /// The interface being reconciled.
        iface: String,
        /// The unit that vanished.
        unit: u32,
    },
}

/// Reads and applies overlay data-plane state.
///
/// Generic over the FDB implementation, the **ARP mechanism** and the command
/// runner, so a whole reconciliation pass can be exercised with no kernel: pass
/// `Arc<FakeFtable>` and a mock runner.
///
/// `A` is what makes a task's ARP entries programmable at all. The default is
/// [`ArpHelper`], the re-exec mechanism, because a task's rootfs is an OCI image
/// with no usable `arp`(8) ([`crate::arp::ArpError::MissingBinary`]);
/// [`crate::arp::Arp`] also implements [`JailArp`] and stays available for
/// `path=/` jails and tests.
#[derive(Debug, Clone)]
pub struct Programmer<F = Ftable, A = ArpHelper, R = SystemRunner> {
    ftable: F,
    arp: A,
    reader: FtableReader<R>,
}

impl<A: JailArp> Programmer<Ftable, A, SystemRunner> {
    /// Programmer driving the real kernel, with `arp` as the ARP mechanism.
    ///
    /// For a daemon that is `ArpHelper::from_current_exe()?`; there is no
    /// argument-free constructor because the helper's path is configuration the
    /// caller owns, not something this crate may assume.
    pub fn system(arp: A) -> Self {
        Self {
            ftable: Ftable::new(),
            arp,
            reader: FtableReader::system(),
        }
    }
}

impl<F, A, R> Programmer<F, A, R>
where
    F: FtableOps + Clone + 'static,
    A: JailArp,
    R: CommandRunner,
{
    /// Programmer over injected pieces.
    pub fn new(ftable: F, arp: A, reader: FtableReader<R>) -> Self {
        Self {
            ftable,
            arp,
            reader,
        }
    }

    /// The ARP mechanism, for callers that need it directly.
    pub fn arp(&self) -> &A {
        &self.arp
    }

    /// The FDB dump reader.
    pub fn reader(&self) -> &FtableReader<R> {
        &self.reader
    }

    /// Read what is currently programmed for one network on this node.
    ///
    /// `unit` is the vxlan interface's **clone unit** — the sysctl tree is
    /// keyed by it and nothing maps a unit back to a name
    /// (`docs/vxlan.md` §2 point 3). Remember it from
    /// [`crate::vxlan::Vxlan::create_vtep`], or recover it once with
    /// [`FtableReader::resolve_unit`] after adopting an interface.
    ///
    /// A jail that has gone away is skipped rather than failing the pass: its
    /// ARP table went with it, so there is nothing to reconcile.
    pub async fn read_state(
        &self,
        desired: &DesiredOverlay,
        unit: u32,
    ) -> Result<ProgrammedState, ProgramError> {
        Ok(ProgrammedState {
            ftable: self.read_ftable(desired, unit).await?,
            arp: self.read_arp(desired).await?,
        })
    }

    /// The forwarding table currently programmed on `unit`.
    ///
    /// Verified against the entry count the ioctl reports, so a table too large
    /// for the dump sysctl's one-page buffer comes back as
    /// [`FtableError::DumpTruncated`] rather than as a plausible-looking
    /// fragment ([`FtableReader::dump_verified`]).
    async fn read_ftable(
        &self,
        desired: &DesiredOverlay,
        unit: u32,
    ) -> Result<BTreeMap<MacAddr, Ipv4Addr>, ProgramError> {
        let dump = self
            .reader
            .dump_verified(&self.ftable, &desired.iface, unit)
            .await?;
        let Some(dump) = dump else {
            return Err(ProgramError::UnitGone {
                iface: desired.iface.clone(),
                unit,
            });
        };
        Ok(dump
            .into_iter()
            .map(|(mac, record)| (mac, record.entry.vtep))
            .collect())
    }

    /// The ARP entries of ours currently in each local jail.
    ///
    /// "Ours" is two filters, not one: `list_owned` drops the jail's own
    /// addresses and anything the kernel learned, and the subnet drops the
    /// entries of the *other* overlay networks the same jail is on — they live
    /// in one VNET and therefore in one ARP table, and a pass that cannot tell
    /// them apart deletes them (see [`DesiredOverlay::subnet`]).
    async fn read_arp(
        &self,
        desired: &DesiredOverlay,
    ) -> Result<BTreeMap<String, BTreeMap<Ipv4Addr, MacAddr>>, ProgramError> {
        let mut arp = BTreeMap::new();
        for (jail, own) in desired.own_addresses() {
            let own: Vec<Ipv4Addr> = own.into_iter().collect();
            match self.arp.list_owned(jail, &own).await {
                Ok(entries) => {
                    let table: BTreeMap<Ipv4Addr, MacAddr> = entries
                        .into_iter()
                        .filter(|entry| desired.owns(entry.ip))
                        .filter_map(|entry| entry.mac.map(|mac| (entry.ip, mac)))
                        .collect();
                    arp.insert(jail.to_owned(), table);
                }
                // The task died between the assignment and this pass.
                Err(ArpError::NoSuchJail { .. }) => {
                    tracing::debug!(jail = %jail, "jail is gone; nothing to reconcile in it");
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(arp)
    }

    /// Apply a delta, best effort, and report what happened.
    ///
    /// Never returns `Err`: every operation in a delta is independent and the
    /// delta is idempotent, so on a partial failure the useful behaviour is to
    /// do everything that can be done and report the rest — the next pass
    /// retries exactly what is still missing. Callers decide whether
    /// [`Applied::is_complete`] warrants an alarm.
    ///
    /// **Additions run before replacements, and removals last** (make before
    /// break). The three key sets are disjoint, so the order cannot change the
    /// result; doing it this way means a new endpoint is reachable before an old
    /// one is withdrawn, and the only entry ever briefly absent is one whose
    /// VTEP genuinely changed.
    ///
    /// The whole FDB batch runs inside one `spawn_blocking`: the ioctls are
    /// short in-kernel table updates rather than I/O, but they are syscalls,
    /// and CLAUDE.md invariant 4 keeps those off the async runtime. Batching
    /// costs one hop per pass instead of one per entry.
    #[tracing::instrument(skip_all, fields(iface = %delta.iface, delta = %delta.summary()))]
    pub async fn apply(&self, delta: &OverlayDelta) -> Applied {
        let mut applied = Applied::default();
        for conflict in &delta.conflicts {
            tracing::warn!(iface = %delta.iface, conflict = %conflict, "contradictory desired overlay state");
        }
        for jail in &delta.unmanaged_jails {
            tracing::debug!(
                iface = %delta.iface,
                jail = %jail,
                "jail has programmed entries but is not in the desired state; left alone"
            );
        }
        if delta.is_empty() {
            tracing::debug!("overlay data plane already reconciled");
            return applied;
        }

        self.apply_ftable(delta, &mut applied).await;
        self.apply_arp(delta, &mut applied).await;

        if applied.is_complete() {
            tracing::info!(applied = %applied.summary(), "programmed overlay data plane");
        } else {
            tracing::warn!(
                applied = %applied.summary(),
                failures = ?applied.failures,
                "overlay data plane only partially programmed; will retry"
            );
        }
        applied
    }

    async fn apply_ftable(&self, delta: &OverlayDelta, applied: &mut Applied) {
        if delta.ftable_add.is_empty()
            && delta.ftable_replace.is_empty()
            && delta.ftable_remove.is_empty()
        {
            return;
        }
        let ftable = self.ftable.clone();
        let iface = delta.iface.clone();
        let wanted = delta.ftable_add.clone();
        let changed = delta.ftable_replace.clone();
        let unwanted = delta.ftable_remove.clone();
        let batch = tokio::task::spawn_blocking(move || {
            let mut outcome = Applied::default();
            // Make before break: install, repoint, withdraw.
            for entry in wanted {
                match ftable.add(&iface, entry) {
                    Ok(()) => outcome.ftable_added.push(entry),
                    // The read-back was stale — the MAC is already there. The
                    // kernel refuses to overwrite, so fall back to a replace
                    // rather than leaving the endpoint pointed at the old node.
                    Err(err) if err.is_already_exists() => {
                        tracing::warn!(
                            iface = %iface,
                            entry = %entry,
                            "FDB read-back was stale; repointing the existing entry"
                        );
                        match ftable.replace(&iface, entry) {
                            Ok(_) => outcome.ftable_replaced.push(entry),
                            Err(err) => outcome.failures.push(err.to_string()),
                        }
                    }
                    Err(err) => outcome.failures.push(err.to_string()),
                }
            }
            for entry in changed {
                match ftable.replace(&iface, entry) {
                    Ok(_) => outcome.ftable_replaced.push(entry),
                    Err(err) => outcome.failures.push(err.to_string()),
                }
            }
            for mac in unwanted {
                match ftable.remove(&iface, mac) {
                    Ok(true) => outcome.ftable_removed.push(mac),
                    Ok(false) => outcome.ftable_absent.push(mac),
                    Err(err) => outcome.failures.push(err.to_string()),
                }
            }
            outcome
        })
        .await;
        match batch {
            Ok(outcome) => {
                applied.ftable_added = outcome.ftable_added;
                applied.ftable_replaced = outcome.ftable_replaced;
                applied.ftable_removed = outcome.ftable_removed;
                applied.ftable_absent = outcome.ftable_absent;
                applied.failures.extend(outcome.failures);
            }
            Err(err) => applied
                .failures
                .push(format!("FDB batch did not run to completion: {err}")),
        }
    }

    /// Apply the ARP half, **one batch per jail**.
    ///
    /// Batching is not an optimisation detail: the default mechanism spawns a
    /// child process per call ([`crate::arphelper`]), so per-entry calls would be
    /// one `satld` re-exec per remote endpoint per local task per pass. Grouping
    /// by jail makes it one per jail, and the ordering guarantee survives because
    /// each batch installs before it withdraws.
    async fn apply_arp(&self, delta: &OverlayDelta, applied: &mut Applied) {
        for (jail, batch) in delta.arp_batches() {
            if batch.is_empty() {
                continue;
            }
            match self.arp.apply(&jail, &batch).await {
                Ok(outcome) => absorb_arp(&jail, outcome, applied),
                // A jail that died is not a failure: its table went with it.
                Err(ArpError::NoSuchJail { .. }) => tracing::debug!(
                    jail = %jail,
                    "jail vanished before its ARP entries could be programmed"
                ),
                Err(err) => applied.failures.push(err.to_string()),
            }
        }
    }

    /// Read, diff and apply in one call — the reconciliation pass.
    ///
    /// ## When the forwarding table cannot be read
    ///
    /// The dump sysctl silently stops at about 81 IPv4 entries
    /// ([`FtableError::DumpTruncated`]), which a busy network on a busy node will
    /// reach. A truncated read-back is **not** a state to diff against: every
    /// missing entry would look absent, every pass would re-issue an `add`, and
    /// every `add` would come back `EEXIST` — churn that looks like a working
    /// reconciler.
    ///
    /// So this pass does the only safe thing: **flush the whole table and
    /// re-push the full desired set**, and say so. That is safe here and nowhere
    /// else, because SatL runs its VTEPs with `-vxlanlearn`, so every entry in
    /// the table was put there by this code and the store can reconstruct all of
    /// it. The cost is a brief window in which remote endpoints are unreachable,
    /// which is why it is a warning and not a routine path.
    pub async fn reconcile(
        &self,
        desired: &DesiredOverlay,
        unit: u32,
    ) -> Result<Applied, ProgramError> {
        let arp = self.read_arp(desired).await?;
        let (ftable, flushed) = match self.read_ftable(desired, unit).await {
            Ok(ftable) => (ftable, false),
            Err(ProgramError::Ftable(err)) if err.is_dump_truncated() => {
                tracing::warn!(
                    iface = %desired.iface,
                    unit,
                    error = %err,
                    "the VXLAN forwarding table cannot be read back, so it cannot \
                     be diffed; flushing it and re-pushing every entry. This is \
                     safe only because learning is off: every entry in it is ours"
                );
                self.flush_ftable(&desired.iface).await?;
                (BTreeMap::new(), true)
            }
            Err(err) => return Err(err),
        };

        let delta = OverlayDelta::between(desired, &ProgrammedState { ftable, arp });
        let mut applied = self.apply(&delta).await;
        applied.ftable_flushed = flushed;
        Ok(applied)
    }

    /// `vxlanflushall` on `iface`, off the async runtime.
    async fn flush_ftable(&self, iface: &str) -> Result<(), ProgramError> {
        let ftable = self.ftable.clone();
        let iface = iface.to_owned();
        tokio::task::spawn_blocking(move || ftable.flush(&iface, FlushScope::All))
            .await
            .map_err(|err| ProgramError::FlushLost {
                reason: err.to_string(),
            })?
            .map_err(ProgramError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arp::Arp;
    use crate::ftable::testing::FakeFtable;
    use crate::runner::MockRunner;
    use std::sync::Arc;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn mac_of(text: &str) -> MacAddr {
        MacAddr::from_ipv4(ip(text))
    }

    const NODE1: &str = "10.2.2.47";
    const NODE2: &str = "10.2.1.50";
    const NODE3: &str = "10.2.3.124";

    /// Two local tasks on this node, two endpoints elsewhere.
    fn desired() -> DesiredOverlay {
        DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_local([
                LocalEndpoint::new("satl-t1", ip("10.100.0.11")),
                LocalEndpoint::new("satl-t2", ip("10.100.0.12")),
            ])
            .with_remote([
                RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE2)),
                RemoteEndpoint::new(ip("10.100.0.31"), ip(NODE3)),
            ])
    }

    // ---- normalization -----------------------------------------------------

    #[test]
    fn only_remote_endpoints_get_fdb_entries() {
        let want = desired().normalize();
        assert_eq!(
            want.ftable,
            BTreeMap::from([
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.31"), ip(NODE3)),
            ])
        );
        assert!(
            !want.ftable.contains_key(&mac_of("10.100.0.11")),
            "a local endpoint's MAC lives on the bridge; an FDB entry would \
             hand its frames to a VTEP"
        );
    }

    #[test]
    fn every_jail_learns_every_other_endpoint() {
        let want = desired().normalize();
        assert_eq!(want.arp.len(), 2);
        // satl-t1 holds .11, so it learns .12 (local peer) plus both remotes.
        assert_eq!(
            want.arp["satl-t1"].keys().copied().collect::<Vec<_>>(),
            [ip("10.100.0.12"), ip("10.100.0.21"), ip("10.100.0.31")]
        );
        assert_eq!(
            want.arp["satl-t2"].keys().copied().collect::<Vec<_>>(),
            [ip("10.100.0.11"), ip("10.100.0.21"), ip("10.100.0.31")]
        );
        // MACs are always the derived ones.
        assert_eq!(
            want.arp["satl-t1"][&ip("10.100.0.21")],
            mac_of("10.100.0.21")
        );
    }

    #[test]
    fn a_task_with_two_addresses_learns_neither_of_its_own() {
        let desired = DesiredOverlay::new("satl-vx4096", ip(NODE1)).with_local([
            LocalEndpoint::new("satl-t1", ip("10.100.0.11")),
            LocalEndpoint::new("satl-t1", ip("10.100.0.19")),
        ]);
        let want = desired.normalize();
        assert!(want.arp["satl-t1"].is_empty());
    }

    #[test]
    fn a_self_pointing_remote_endpoint_is_a_reported_conflict() {
        let desired = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_local([LocalEndpoint::new("satl-t1", ip("10.100.0.11"))])
            .with_remote([RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE1))]);
        let want = desired.normalize();
        assert!(
            want.ftable.is_empty(),
            "must not point an entry at ourselves"
        );
        assert_eq!(want.conflicts.len(), 1);
        assert!(
            want.conflicts[0].contains("this node's own"),
            "{:?}",
            want.conflicts
        );
        // And with no FDB entry there is no point resolving it either.
        assert!(want.arp["satl-t1"].is_empty());
    }

    #[test]
    fn an_endpoint_that_is_both_local_and_remote_is_treated_as_local() {
        let desired = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_local([LocalEndpoint::new("satl-t1", ip("10.100.0.11"))])
            .with_remote([RemoteEndpoint::new(ip("10.100.0.11"), ip(NODE2))]);
        let want = desired.normalize();
        assert!(want.ftable.is_empty());
        assert_eq!(want.conflicts.len(), 1);
        assert!(want.conflicts[0].contains("both local and remote"));
    }

    #[test]
    fn two_vteps_claiming_one_endpoint_resolve_deterministically() {
        let build = |order: [(&str, &str); 2]| {
            DesiredOverlay::new("satl-vx4096", ip(NODE1))
                .with_remote(order.map(|(addr, vtep)| RemoteEndpoint::new(ip(addr), ip(vtep))))
                .normalize()
        };
        let a = build([("10.100.0.21", NODE2), ("10.100.0.21", NODE3)]);
        let b = build([("10.100.0.21", NODE3), ("10.100.0.21", NODE2)]);
        assert_eq!(a.ftable, b.ftable, "input order must not decide the winner");
        assert_eq!(a.ftable[&mac_of("10.100.0.21")], ip(NODE2));
        assert_eq!(a.conflicts, b.conflicts);
        assert!(a.conflicts[0].contains("claimed by two VTEPs"));
    }

    #[test]
    fn an_unusable_vtep_is_skipped_and_reported() {
        let want = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_remote([
                RemoteEndpoint::new(ip("10.100.0.21"), ip("0.0.0.0")),
                RemoteEndpoint::new(ip("10.100.0.22"), ip("239.99.0.1")),
                RemoteEndpoint::new(ip("10.100.0.23"), ip(NODE2)),
            ])
            .normalize();
        assert_eq!(want.ftable.len(), 1);
        assert_eq!(want.conflicts.len(), 2);
    }

    // ---- the delta: the four properties ------------------------------------

    #[test]
    fn from_nothing_everything_is_added_and_nothing_removed() {
        let delta = OverlayDelta::between(&desired(), &ProgrammedState::empty());
        assert_eq!(delta.iface, "satl-vx4096");
        assert_eq!(
            delta.ftable_add,
            [
                FtableEntry {
                    mac: mac_of("10.100.0.21"),
                    vtep: ip(NODE2)
                },
                FtableEntry {
                    mac: mac_of("10.100.0.31"),
                    vtep: ip(NODE3)
                },
            ]
        );
        assert!(delta.ftable_remove.is_empty());
        // 2 jails x 3 peers.
        assert_eq!(delta.arp_add.len(), 6);
        assert!(delta.arp_remove.is_empty());
        assert!(delta.conflicts.is_empty());
        assert_eq!(delta.len(), 8);
        assert_eq!(delta.summary(), "satl-vx4096: fdb +2 ~0 -0, arp +6 -0");
    }

    /// Programmed state that exactly satisfies `desired()`.
    fn steady_state() -> ProgrammedState {
        let want = desired().normalize();
        ProgrammedState {
            ftable: want.ftable,
            arp: want.arp,
        }
    }

    #[test]
    fn property_idempotent_a_matching_state_yields_an_empty_delta() {
        let delta = OverlayDelta::between(&desired(), &steady_state());
        assert!(delta.is_empty(), "{delta:?}");
        assert_eq!(delta.len(), 0);
    }

    #[test]
    fn property_order_independent() {
        let base = OverlayDelta::between(&desired(), &ProgrammedState::empty());
        let shuffled = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_remote([
                RemoteEndpoint::new(ip("10.100.0.31"), ip(NODE3)),
                RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE2)),
            ])
            .with_local([
                LocalEndpoint::new("satl-t2", ip("10.100.0.12")),
                LocalEndpoint::new("satl-t1", ip("10.100.0.11")),
            ]);
        assert_eq!(
            OverlayDelta::between(&shuffled, &ProgrammedState::empty()),
            base
        );
    }

    #[test]
    fn property_a_changed_vtep_is_a_replace_and_never_a_bare_removal() {
        // The .21 endpoint moved from node2 to node3, and its ARP MAC is
        // unchanged (the MAC is a function of the address, not the location).
        let mut moved = desired();
        moved.remote = vec![
            RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE3)),
            RemoteEndpoint::new(ip("10.100.0.31"), ip(NODE3)),
        ];
        let delta = OverlayDelta::between(&moved, &steady_state());
        assert_eq!(
            delta.ftable_replace,
            [FtableEntry {
                mac: mac_of("10.100.0.21"),
                vtep: ip(NODE3)
            }]
        );
        assert!(
            delta.ftable_add.is_empty(),
            "the kernel refuses a bare add on an existing MAC: {delta:?}"
        );
        assert!(
            delta.ftable_remove.is_empty(),
            "a changed VTEP must not surface as an independent removal: {delta:?}"
        );
        assert!(
            delta.arp_add.is_empty() && delta.arp_remove.is_empty(),
            "migration must not touch any ARP entry: {delta:?}"
        );
        // The three lists never share a key, in any scenario.
        let keys = |entries: &[FtableEntry]| -> BTreeSet<MacAddr> {
            entries.iter().map(|entry| entry.mac).collect()
        };
        let added = keys(&delta.ftable_add);
        let replaced = keys(&delta.ftable_replace);
        let removed: BTreeSet<MacAddr> = delta.ftable_remove.iter().copied().collect();
        assert!(added.is_disjoint(&replaced));
        assert!(added.is_disjoint(&removed));
        assert!(replaced.is_disjoint(&removed));
    }

    #[test]
    fn an_entry_that_is_already_correct_is_left_completely_alone() {
        // The whole point of the read-back: re-running against a table that
        // already matches must not touch the kernel at all, because a `remove`
        // plus an `add` would blackhole the endpoint in between.
        let delta = OverlayDelta::between(&desired(), &steady_state());
        assert!(delta.ftable_add.is_empty());
        assert!(delta.ftable_replace.is_empty());
        assert!(delta.ftable_remove.is_empty());
    }

    #[test]
    fn a_wrong_arp_mac_is_replaced_not_deleted() {
        let mut current = steady_state();
        current
            .arp
            .get_mut("satl-t1")
            .unwrap()
            .insert(ip("10.100.0.21"), mac_of("10.100.0.99"));
        let delta = OverlayDelta::between(&desired(), &current);
        assert_eq!(
            delta.arp_add,
            [ArpBinding {
                jail: "satl-t1".to_owned(),
                ip: ip("10.100.0.21"),
                mac: mac_of("10.100.0.21")
            }]
        );
        assert!(delta.arp_remove.is_empty(), "{delta:?}");
    }

    #[test]
    fn a_departed_endpoint_is_withdrawn_everywhere() {
        let mut shrunk = desired();
        shrunk
            .remote
            .retain(|endpoint| endpoint.ip != ip("10.100.0.31"));
        let delta = OverlayDelta::between(&shrunk, &steady_state());
        assert_eq!(delta.ftable_remove, [mac_of("10.100.0.31")]);
        assert!(delta.ftable_add.is_empty());
        assert_eq!(
            delta.arp_remove,
            [
                ArpRemoval {
                    jail: "satl-t1".to_owned(),
                    ip: ip("10.100.0.31")
                },
                ArpRemoval {
                    jail: "satl-t2".to_owned(),
                    ip: ip("10.100.0.31")
                },
            ]
        );
        assert!(delta.arp_add.is_empty());
    }

    #[test]
    fn a_task_migrating_onto_this_node_loses_its_stale_fdb_entry() {
        // .21 was remote at node2; it is now a local task here.
        let migrated = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_local([
                LocalEndpoint::new("satl-t1", ip("10.100.0.11")),
                LocalEndpoint::new("satl-t2", ip("10.100.0.12")),
                LocalEndpoint::new("satl-t3", ip("10.100.0.21")),
            ])
            .with_remote([RemoteEndpoint::new(ip("10.100.0.31"), ip(NODE3))]);
        let delta = OverlayDelta::between(&migrated, &steady_state());
        assert_eq!(
            delta.ftable_remove,
            [mac_of("10.100.0.21")],
            "a local endpoint must not be reachable through a VTEP: {delta:?}"
        );
        assert!(delta.ftable_add.is_empty());
        // The new jail has to learn everyone; the existing jails keep their
        // entry for .21 untouched, because the MAC did not change.
        assert_eq!(
            delta
                .arp_add
                .iter()
                .map(|binding| (binding.jail.as_str(), binding.ip))
                .collect::<Vec<_>>(),
            [
                ("satl-t3", ip("10.100.0.11")),
                ("satl-t3", ip("10.100.0.12")),
                ("satl-t3", ip("10.100.0.31")),
            ]
        );
        assert!(delta.arp_remove.is_empty());
    }

    #[test]
    fn property_conservative_a_jails_own_address_is_never_withdrawn() {
        let mut current = steady_state();
        // The kernel's own permanent entry for the jail's address looks
        // exactly like one of ours, and the desired table deliberately does
        // not contain it.
        current
            .arp
            .get_mut("satl-t1")
            .unwrap()
            .insert(ip("10.100.0.11"), mac_of("10.100.0.11"));
        let delta = OverlayDelta::between(&desired(), &current);
        assert!(
            delta.arp_remove.is_empty(),
            "removing a jail's own ARP entry is never right: {delta:?}"
        );
        assert!(delta.arp_add.is_empty());
    }

    #[test]
    fn property_conservative_an_unknown_jail_is_left_alone() {
        let mut current = steady_state();
        current.arp.insert(
            "satl-other".to_owned(),
            BTreeMap::from([(ip("10.100.0.21"), mac_of("10.100.0.21"))]),
        );
        let delta = OverlayDelta::between(&desired(), &current);
        assert!(delta.is_empty());
        assert_eq!(delta.unmanaged_jails, ["satl-other"]);
    }

    #[test]
    fn a_leaked_unit_probe_entry_is_cleaned_up_by_the_next_pass() {
        let mut current = steady_state();
        current
            .ftable
            .insert(crate::ftable::UNIT_PROBE_MAC, ip("10.2.255.254"));
        let delta = OverlayDelta::between(&desired(), &current);
        assert_eq!(delta.ftable_remove, [crate::ftable::UNIT_PROBE_MAC]);
    }

    #[test]
    fn tearing_a_network_down_withdraws_everything() {
        let empty = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_local([LocalEndpoint::new("satl-t1", ip("10.100.0.11"))]);
        let delta = OverlayDelta::between(&empty, &steady_state());
        assert_eq!(delta.ftable_remove.len(), 2);
        assert!(delta.ftable_add.is_empty());
        assert_eq!(
            delta.arp_remove,
            [
                ArpRemoval {
                    jail: "satl-t1".to_owned(),
                    ip: ip("10.100.0.12")
                },
                ArpRemoval {
                    jail: "satl-t1".to_owned(),
                    ip: ip("10.100.0.21")
                },
                ArpRemoval {
                    jail: "satl-t1".to_owned(),
                    ip: ip("10.100.0.31")
                },
            ]
        );
        assert_eq!(delta.unmanaged_jails, ["satl-t2"]);
    }

    #[test]
    fn a_network_with_no_local_task_programs_nothing() {
        let delta = OverlayDelta::between(
            &DesiredOverlay::new("satl-vx4096", ip(NODE1))
                .with_remote([RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE2))]),
            &ProgrammedState::empty(),
        );
        // The FDB is still programmed — a node can host the VTEP without a
        // task — but there is no jail to hold an ARP entry.
        assert_eq!(delta.ftable_add.len(), 1);
        assert!(delta.arp_add.is_empty());
    }

    // ---- applying it -------------------------------------------------------

    /// A programmer wired to the **`jexec`** ARP mechanism, because that is the
    /// one whose calls a `MockRunner` can record argv for. The helper mechanism
    /// has its own tests in [`crate::arphelper`].
    fn programmer(
        ftable: &Arc<FakeFtable>,
        mock: &'static MockRunner,
    ) -> Programmer<Arc<FakeFtable>, Arp<&'static MockRunner>, &'static MockRunner> {
        Programmer::new(
            Arc::clone(ftable),
            Arp::with_runner(mock),
            FtableReader::with_runner(mock),
        )
    }

    #[tokio::test]
    async fn apply_installs_before_withdrawing() {
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload(
            "satl-vx4096",
            &[
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.99"), ip(NODE3)),
            ],
        );
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        // arp_add x6, then arp_remove x0 for this delta.
        for _ in 0..6 {
            mock.push_ok();
        }
        let prog = programmer(&ftable, mock);
        let delta = OverlayDelta::between(
            &desired(),
            &ProgrammedState {
                ftable: BTreeMap::from([
                    (mac_of("10.100.0.21"), ip(NODE2)),
                    (mac_of("10.100.0.99"), ip(NODE3)),
                ]),
                arp: BTreeMap::new(),
            },
        );
        let applied = prog.apply(&delta).await;
        assert!(applied.is_complete(), "{applied:?}");
        // .21 was already correct, .31 was missing, .99 is gone.
        assert_eq!(
            applied.ftable_added,
            [FtableEntry {
                mac: mac_of("10.100.0.31"),
                vtep: ip(NODE3)
            }]
        );
        assert_eq!(applied.ftable_removed, [mac_of("10.100.0.99")]);
        assert_eq!(applied.arp_added.len(), 6);
        // The add came before the remove in the FDB call log.
        let calls = ftable.calls();
        let add_at = calls
            .iter()
            .position(|call| call.starts_with("add"))
            .unwrap();
        let remove_at = calls
            .iter()
            .position(|call| call.starts_with("remove"))
            .unwrap();
        assert!(add_at < remove_at, "{calls:?}");
    }

    #[tokio::test]
    async fn apply_performs_a_replacement_as_one_ordered_remove_then_add() {
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload("satl-vx4096", &[(mac_of("10.100.0.21"), ip(NODE2))]);
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        let prog = programmer(&ftable, mock);
        let moved = DesiredOverlay::new("satl-vx4096", ip(NODE1))
            .with_remote([RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE3))]);
        let delta = OverlayDelta::between(
            &moved,
            &ProgrammedState {
                ftable: BTreeMap::from([(mac_of("10.100.0.21"), ip(NODE2))]),
                arp: BTreeMap::new(),
            },
        );
        let applied = prog.apply(&delta).await;
        assert!(applied.is_complete(), "{applied:?}");
        assert_eq!(applied.ftable_replaced.len(), 1);
        assert!(applied.ftable_added.is_empty() && applied.ftable_removed.is_empty());
        assert_eq!(
            ftable.calls(),
            [
                "remove satl-vx4096 02:42:0a:64:00:15",
                "add satl-vx4096 02:42:0a:64:00:15 -> 10.2.3.124",
            ]
        );
        assert_eq!(
            ftable.table("satl-vx4096")[&mac_of("10.100.0.21")],
            ip(NODE3)
        );
        assert!(applied.summary().contains("fdb +0 ~1 -0"));
    }

    #[tokio::test]
    async fn apply_recovers_when_the_read_back_was_stale() {
        // The delta says "add", but the MAC is already in the table pointing
        // somewhere else — a state only a racing read-back can produce. A bare
        // add is EEXIST, so the applier must fall back to a replace instead of
        // leaving the endpoint at its old node.
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload("satl-vx4096", &[(mac_of("10.100.0.21"), ip(NODE2))]);
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        let prog = programmer(&ftable, mock);
        let delta = OverlayDelta::between(
            &DesiredOverlay::new("satl-vx4096", ip(NODE1))
                .with_remote([RemoteEndpoint::new(ip("10.100.0.21"), ip(NODE3))]),
            &ProgrammedState::empty(),
        );
        assert_eq!(delta.ftable_add.len(), 1, "the stale diff says 'add'");
        let applied = prog.apply(&delta).await;
        assert!(applied.is_complete(), "{applied:?}");
        assert_eq!(applied.ftable_replaced.len(), 1);
        assert!(applied.ftable_added.is_empty());
        assert_eq!(
            ftable.table("satl-vx4096")[&mac_of("10.100.0.21")],
            ip(NODE3)
        );
    }

    #[tokio::test]
    async fn apply_is_idempotent_against_the_kernel() {
        let ftable = Arc::new(FakeFtable::new());
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        for _ in 0..6 {
            mock.push_ok();
        }
        let prog = programmer(&ftable, mock);
        let delta = OverlayDelta::between(&desired(), &ProgrammedState::empty());
        let first = prog.apply(&delta).await;
        assert_eq!(first.ftable_added.len(), 2);
        // Re-computing against what is now programmed yields nothing to do.
        let current = ProgrammedState {
            ftable: ftable.table("satl-vx4096"),
            arp: steady_state().arp,
        };
        let second = OverlayDelta::between(&desired(), &current);
        assert!(second.is_empty(), "{second:?}");
        let applied = prog.apply(&second).await;
        assert_eq!(applied, Applied::default());
    }

    #[tokio::test]
    async fn apply_reports_per_item_failures_and_keeps_going() {
        let ftable = Arc::new(FakeFtable::failing_add(libc::EPERM));
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        // First ARP set fails with the exit-0 refusal, the rest succeed.
        mock.push_output(0, "", "arp: set: cannot locate 10.100.0.12\n");
        for _ in 0..5 {
            mock.push_ok();
        }
        let prog = programmer(&ftable, mock);
        let delta = OverlayDelta::between(&desired(), &ProgrammedState::empty());
        let applied = prog.apply(&delta).await;
        assert!(!applied.is_complete());
        // Two FDB adds failed, one ARP set failed.
        assert_eq!(applied.failures.len(), 3, "{:?}", applied.failures);
        assert!(
            applied
                .failures
                .iter()
                .any(|text| text.contains("PRIV_NET_VXLAN"))
        );
        assert!(applied.failures.iter().any(|text| text.contains("on-link")));
        // ...and the five ARP entries that could be installed were.
        assert_eq!(applied.arp_added.len(), 5);
        assert!(applied.summary().contains("failures 3"));
    }

    #[tokio::test]
    async fn apply_tolerates_a_jail_that_died_mid_pass() {
        let ftable = Arc::new(FakeFtable::new());
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        for _ in 0..6 {
            mock.push_output(1, "", "jexec: jail \"satl-t1\" not found\n");
        }
        let prog = programmer(&ftable, mock);
        let delta = OverlayDelta::between(&desired(), &ProgrammedState::empty());
        let applied = prog.apply(&delta).await;
        assert!(
            applied.is_complete(),
            "a dead jail is not a programming failure: {applied:?}"
        );
        assert!(applied.arp_added.is_empty());
    }

    #[tokio::test]
    async fn read_state_reads_the_dump_and_every_jails_owned_entries() {
        let ftable = Arc::new(FakeFtable::new());
        // The read-back is checked against the count the ioctl reports, so the
        // fake kernel has to hold the entry the dump claims.
        ftable.preload("satl-vx4096", &[(mac_of("10.100.0.21"), ip(NODE2))]);
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(
            0,
            "\nS 0x02 02:42:0A:64:00:15       10.2.1.50 00040577\n",
            "",
        ); // the dump
        mock.push_output(
            0,
            "? (10.100.0.11) at 02:42:0a:64:00:0b on satl-ep1b permanent [ethernet]\n\
             ? (10.100.0.21) at 02:42:0a:64:00:15 on satl-ep1b permanent [ethernet]\n\
             ? (10.100.0.1) at 58:9c:fc:10:cd:b0 on satl-ep1b expires in 1199 seconds [ethernet]\n",
            "",
        ); // satl-t1
        mock.push_output(0, "", ""); // satl-t2: empty table
        let prog = programmer(&ftable, mock);
        let state = prog.read_state(&desired(), 3).await.unwrap();
        assert_eq!(
            state.ftable,
            BTreeMap::from([(mac_of("10.100.0.21"), ip(NODE2))])
        );
        // The jail's own address and the learned gateway are both excluded.
        assert_eq!(
            state.arp["satl-t1"],
            BTreeMap::from([(ip("10.100.0.21"), mac_of("10.100.0.21"))])
        );
        assert!(state.arp["satl-t2"].is_empty());
        assert_eq!(
            mock.calls()[0],
            "/sbin/sysctl -n net.link.vxlan.3.ftable.dump"
        );
    }

    /// A jail on two overlay networks has one VNET and therefore one ARP
    /// table. Reconciling network A must not see network B's entries at all,
    /// or it removes them — and B's next pass removes A's, forever.
    ///
    /// Measured on the cluster VMs before the subnet was passed in: both
    /// networks logged `arp +1 -1` on every resync and the one that had not run
    /// last answered `ping: sendto: Host is down` from inside the jail, while
    /// the FDB and the DNS answer were both correct. Nothing else in the delta
    /// shows it, which is why the assertion here is on the *read-back*.
    #[tokio::test]
    async fn a_jail_on_two_networks_keeps_the_other_networks_arp_entries() {
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload("satl-vx4096", &[(mac_of("10.100.0.21"), ip(NODE2))]);
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(
            0,
            "\nS 0x02 02:42:0A:64:00:15       10.2.1.50 00040577\n",
            "",
        ); // the dump
        // satl-t1 is on 10.100.0.0/24 *and* on 10.100.1.0/24: both networks'
        // static entries are in the one table, on the two different epairs.
        mock.push_output(
            0,
            "? (10.100.0.21) at 02:42:0a:64:00:15 on satl-ep1b permanent [ethernet]\n\
             ? (10.100.1.21) at 02:42:0a:64:01:15 on satl-ep2b permanent [ethernet]\n",
            "",
        ); // satl-t1
        mock.push_output(0, "", ""); // satl-t2
        let prog = programmer(&ftable, mock);

        let subnet: Ipv4Cidr = "10.100.0.0/24".parse().expect("valid subnet");
        let state = prog
            .read_state(&desired().with_subnet(subnet), 3)
            .await
            .unwrap();
        assert_eq!(
            state.arp["satl-t1"],
            BTreeMap::from([(ip("10.100.0.21"), mac_of("10.100.0.21"))]),
            "the other network's entry is not this network's to see"
        );

        // And therefore not this network's to remove: the delta against a
        // desired state that still wants 10.100.0.21 is empty, where without
        // the subnet it would carry a removal for 10.100.1.21.
        let delta = OverlayDelta::between(&desired().with_subnet(subnet), &state);
        assert!(
            delta.arp_remove.is_empty(),
            "would delete another network's entries: {:?}",
            delta.arp_remove
        );
    }

    #[tokio::test]
    async fn read_state_refuses_a_dump_the_ioctl_count_contradicts() {
        // The measured failure: the dump sysctl is a fixed one-page buffer and
        // silently stops at about 81 IPv4 entries
        // (hack/experiments/jail-arp/captures/40-ftable-dump-ceiling.txt). Here
        // the kernel holds three entries and the dump shows one.
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload(
            "satl-vx4096",
            &[
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.22"), ip(NODE2)),
                (mac_of("10.100.0.23"), ip(NODE3)),
            ],
        );
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(
            0,
            "\nS 0x02 02:42:0A:64:00:15       10.2.1.50 00040577\n",
            "",
        );
        let prog = programmer(&ftable, mock);
        let err = prog.read_state(&desired(), 3).await.unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(&err, ProgramError::Ftable(inner) if inner.is_dump_truncated()),
            "{err:?}"
        );
        assert!(text.contains("listed 1 entries"), "{text}");
        assert!(text.contains("reports 3"), "{text}");
        assert!(text.contains("net.link.vxlan.3.ftable.dump"), "{text}");
        assert!(
            text.contains("flush it and re-push"),
            "the message must say what to do: {text}"
        );
    }

    #[tokio::test]
    async fn reconcile_flushes_and_repushes_when_the_dump_is_truncated() {
        // Three entries programmed, two of them wanted; the dump shows one. The
        // only safe response is to flush and push the whole desired set, because
        // learning is off and therefore nothing in the table is anyone else's.
        let ftable = Arc::new(FakeFtable::new());
        ftable.preload(
            "satl-vx4096",
            &[
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.99"), ip(NODE3)),
                (mac_of("10.100.0.98"), ip(NODE3)),
            ],
        );
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(0, "", ""); // satl-t1 arp -an
        mock.push_output(0, "", ""); // satl-t2 arp -an
        mock.push_output(
            0,
            "\nS 0x02 02:42:0A:64:00:15       10.2.1.50 00040577\n",
            "",
        ); // the truncated dump
        for _ in 0..6 {
            mock.push_ok(); // the six ARP entries
        }
        let prog = programmer(&ftable, mock);
        let applied = prog.reconcile(&desired(), 3).await.expect("reconcile");

        assert!(
            applied.ftable_flushed,
            "the caller has to be able to see this happened: {applied:?}"
        );
        assert!(applied.is_complete(), "{applied:?}");
        // Flushed, then every wanted entry re-pushed — and the two entries that
        // were not wanted are gone with the flush rather than by a diff.
        assert!(
            ftable.calls().contains(&"flush satl-vx4096 All".to_owned()),
            "{:?}",
            ftable.calls()
        );
        assert_eq!(applied.ftable_added.len(), 2, "{applied:?}");
        assert!(applied.ftable_removed.is_empty(), "{applied:?}");
        assert_eq!(
            ftable.table("satl-vx4096"),
            BTreeMap::from([
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.31"), ip(NODE3)),
            ]),
            "the table must end up exactly the desired set"
        );
    }

    #[tokio::test]
    async fn reconcile_reports_a_flush_it_could_not_perform() {
        let ftable = Arc::new(FakeFtable::failing_flush(libc::EPERM));
        ftable.preload(
            "satl-vx4096",
            &[
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.99"), ip(NODE3)),
            ],
        );
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(0, "", "");
        mock.push_output(0, "", "");
        mock.push_output(
            0,
            "\nS 0x02 02:42:0A:64:00:15       10.2.1.50 00040577\n",
            "",
        );
        let prog = programmer(&ftable, mock);
        let err = prog.reconcile(&desired(), 3).await.unwrap_err();
        // Nothing is programmed on top of a table that could not be cleared: the
        // next pass tries the whole thing again.
        assert!(err.to_string().contains("FLUSH"), "{err}");
    }

    #[tokio::test]
    async fn read_state_reports_a_destroyed_interface() {
        let ftable = Arc::new(FakeFtable::new());
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(
            1,
            "",
            "sysctl: unknown oid 'net.link.vxlan.7.ftable.dump'\n",
        );
        let prog = programmer(&ftable, mock);
        let err = prog.read_state(&desired(), 7).await.unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ProgramError::UnitGone { .. }), "{err:?}");
        assert!(text.contains("re-pushed"), "{text}");
    }

    #[tokio::test]
    async fn reconcile_reads_diffs_and_applies() {
        let ftable = Arc::new(FakeFtable::new());
        let mock: &'static MockRunner = Box::leak(Box::new(MockRunner::new()));
        mock.push_output(0, "\n", ""); // empty dump
        mock.push_output(0, "", ""); // satl-t1 arp -an
        mock.push_output(0, "", ""); // satl-t2 arp -an
        for _ in 0..6 {
            mock.push_ok(); // six arp -s
        }
        let prog = programmer(&ftable, mock);
        let applied = prog.reconcile(&desired(), 0).await.unwrap();
        assert!(applied.is_complete(), "{applied:?}");
        assert_eq!(applied.ftable_added.len(), 2);
        assert_eq!(applied.arp_added.len(), 6);
        assert_eq!(
            ftable.table("satl-vx4096"),
            BTreeMap::from([
                (mac_of("10.100.0.21"), ip(NODE2)),
                (mac_of("10.100.0.31"), ip(NODE3)),
            ])
        );
    }
}
