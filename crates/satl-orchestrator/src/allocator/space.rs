// SPDX-License-Identifier: BSD-2-Clause
//! The allocator's address spaces (architecture §11.3, SWK §9.1): cluster
//! subnets, VXLAN VNIs, per-network VTEP ports and the per-network host
//! addresses.
//!
//! All four are **pure** and share one shape:
//!
//! - [`claim`](SubnetSpace::claim) records something the store already says is
//!   allocated. This is the restore half of the two-phase walk (SWK §9.2) and
//!   it never invents a value.
//! - `allocate` hands out the lowest free value. It can only ever run after
//!   every `claim` of the same pass, which is what stops a new leader from
//!   re-handing-out an in-use subnet, VNI or address.
//!
//! Nothing here knows about store objects: a space is authoritative about
//! *what* is taken and by which object **ID**, and returns [`SpaceError`]. The
//! planner turns that into an [`AllocError`](super::error::AllocError) with the
//! network/task/pool names in it, because that is where the names live.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

use satl_core::{Id, Ipv4Cidr};

/// Why a space refused a claim or an allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpaceError {
    /// The value is already held by that object.
    Occupied(Id),
    /// The space has nothing free left.
    Exhausted,
    /// The value does not belong to this space (address outside the subnet).
    Outside,
    /// The value is reserved (network address, broadcast, `.1`, or an
    /// operator-requested gateway).
    Reserved,
}

// ---------------------------------------------------------------------------
// Subnets
// ---------------------------------------------------------------------------

/// Carves fixed-size subnets out of the cluster's address pools
/// (`ClusterSpec::default_address_pool` at `ClusterSpec::subnet_size`).
///
/// Claims are checked for **overlap**, not equality: an operator-requested
/// `10.100.0.0/16` and an allocator-carved `10.100.4.0/24` are different
/// values that must not both be handed out.
#[derive(Debug, Clone)]
pub(crate) struct SubnetSpace {
    pools: Vec<Ipv4Cidr>,
    subnet_size: u8,
    owners: BTreeMap<Ipv4Cidr, Id>,
}

impl SubnetSpace {
    /// A space carving `subnet_size`-long subnets from `pools`, in order.
    pub(crate) fn new(pools: Vec<Ipv4Cidr>, subnet_size: u8) -> Self {
        Self {
            pools,
            subnet_size,
            owners: BTreeMap::new(),
        }
    }

    /// The pools, as configured — for error messages.
    pub(crate) fn pools(&self) -> &[Ipv4Cidr] {
        &self.pools
    }

    /// The prefix length handed out.
    pub(crate) fn subnet_size(&self) -> u8 {
        self.subnet_size
    }

    /// Records `subnet` as held by `network` (restore, or an operator-requested
    /// subnet). Idempotent for the same owner.
    pub(crate) fn claim(&mut self, subnet: Ipv4Cidr, network: &Id) -> Result<(), SpaceError> {
        let key = subnet.network_cidr();
        if let Some(holder) = self.overlapping_owner(key, network) {
            return Err(SpaceError::Occupied(holder));
        }
        self.owners.insert(key, network.clone());
        Ok(())
    }

    /// The lowest free subnet in the pools, claimed for `network`.
    pub(crate) fn allocate(&mut self, network: &Id) -> Result<Ipv4Cidr, SpaceError> {
        let subnet_size = self.subnet_size;
        let candidate = self
            .pools
            .clone()
            .into_iter()
            .flat_map(|pool| pool.subnets(subnet_size))
            .find(|candidate| self.overlapping_owner(*candidate, network).is_none())
            .ok_or(SpaceError::Exhausted)?;
        self.owners.insert(candidate, network.clone());
        Ok(candidate)
    }

    /// The owner of any subnet overlapping `subnet`, ignoring `network` itself.
    fn overlapping_owner(&self, subnet: Ipv4Cidr, network: &Id) -> Option<Id> {
        self.owners
            .iter()
            .find(|(held, holder)| {
                *holder != network
                    && (held.contains_subnet(subnet) || subnet.contains_subnet(**held))
            })
            .map(|(_, holder)| holder.clone())
    }
}

// ---------------------------------------------------------------------------
// VNIs
// ---------------------------------------------------------------------------

/// The VXLAN network identifier space (architecture §11.2).
///
/// Allocation is bounded to the configured range — SatL leaves the low VNIs to
/// hand-configured networks — but a *claim* accepts any value, so a network
/// carrying a VNI from outside the range still blocks it for everyone else.
#[derive(Debug, Clone)]
pub(crate) struct VniSpace {
    range: RangeInclusive<u32>,
    owners: BTreeMap<u32, Id>,
}

impl VniSpace {
    /// A space handing out VNIs from `range`.
    pub(crate) fn new(range: RangeInclusive<u32>) -> Self {
        Self {
            range,
            owners: BTreeMap::new(),
        }
    }

    /// The allocation range — for error messages.
    pub(crate) fn range(&self) -> &RangeInclusive<u32> {
        &self.range
    }

    /// Records `vni` as held by `network` (restore). Idempotent for the same
    /// owner.
    pub(crate) fn claim(&mut self, vni: u32, network: &Id) -> Result<(), SpaceError> {
        match self.owners.get(&vni) {
            Some(holder) if holder != network => Err(SpaceError::Occupied(holder.clone())),
            _ => {
                self.owners.insert(vni, network.clone());
                Ok(())
            }
        }
    }

    /// The lowest free VNI in the range, claimed for `network`. Holes left by
    /// deleted networks are reused.
    pub(crate) fn allocate(&mut self, network: &Id) -> Result<u32, SpaceError> {
        let vni = self
            .range
            .clone()
            .find(|candidate| !self.owners.contains_key(candidate))
            .ok_or(SpaceError::Exhausted)?;
        self.owners.insert(vni, network.clone());
        Ok(vni)
    }

    /// Releases whatever `network` holds; returns the freed VNI.
    pub(crate) fn release(&mut self, network: &Id) -> Option<u32> {
        let vni = *self
            .owners
            .iter()
            .find(|(_, holder)| *holder == network)
            .map(|(vni, _)| vni)?;
        self.owners.remove(&vni);
        Some(vni)
    }
}

// ---------------------------------------------------------------------------
// VTEP ports
// ---------------------------------------------------------------------------

/// The per-network VTEP UDP port space of encrypted overlay networks
/// ([`Network::vxlan_port`](satl_core::Network::vxlan_port)).
///
/// Same shape as [`VniSpace`]: allocation is bounded to the pool
/// ([`OVERLAY_VXLAN_PORT_RANGE`](satl_core::defaults::OVERLAY_VXLAN_PORT_RANGE)),
/// but a *claim* accepts any value, so a network carrying a port from outside
/// the pool still blocks it for everyone else.
#[derive(Debug, Clone)]
pub(crate) struct VtepPortSpace {
    range: RangeInclusive<u16>,
    owners: BTreeMap<u16, Id>,
}

impl VtepPortSpace {
    /// A space handing out VTEP ports from `range`.
    pub(crate) fn new(range: RangeInclusive<u16>) -> Self {
        Self {
            range,
            owners: BTreeMap::new(),
        }
    }

    /// The allocation range — for error messages.
    pub(crate) fn range(&self) -> &RangeInclusive<u16> {
        &self.range
    }

    /// Records `port` as held by `network` (restore). Idempotent for the same
    /// owner.
    pub(crate) fn claim(&mut self, port: u16, network: &Id) -> Result<(), SpaceError> {
        match self.owners.get(&port) {
            Some(holder) if holder != network => Err(SpaceError::Occupied(holder.clone())),
            _ => {
                self.owners.insert(port, network.clone());
                Ok(())
            }
        }
    }

    /// The lowest free port in the range, claimed for `network`. Holes left by
    /// deleted networks are reused.
    pub(crate) fn allocate(&mut self, network: &Id) -> Result<u16, SpaceError> {
        let port = self
            .range
            .clone()
            .find(|candidate| !self.owners.contains_key(candidate))
            .ok_or(SpaceError::Exhausted)?;
        self.owners.insert(port, network.clone());
        Ok(port)
    }

    /// Releases whatever `network` holds; returns the freed port.
    pub(crate) fn release(&mut self, network: &Id) -> Option<u16> {
        let port = *self
            .owners
            .iter()
            .find(|(_, holder)| *holder == network)
            .map(|(port, _)| port)?;
        self.owners.remove(&port);
        Some(port)
    }
}

// ---------------------------------------------------------------------------
// Host addresses
// ---------------------------------------------------------------------------

/// The host addresses of one network's subnet: one per task, plus one per node
/// that participates in the network.
///
/// Owners are object IDs — tasks **and** nodes, in one space on purpose. A
/// node's gateway address for an overlay network lives on that node's bridge, on
/// the same L2 segment as every task attached to the network (architecture
/// §11.3, SWK §9.1), so the two can never be allowed to collide.
///
/// Three addresses are reserved: the network address, the broadcast address and
/// `.1`. `.1` is the gateway convention, and on an overlay it is deliberately
/// assigned to nobody — an operator reading `10.100.0.1` in a subnet must not be
/// looking at one arbitrary node's address. [`AddressSpace::reserve`] adds an
/// operator-requested gateway to the set on the same terms.
///
/// `ip_range` narrows what is allocated from without changing what the subnet
/// *is*.
///
/// Allocation is first-free from a cursor, so filling a large subnet stays
/// linear overall rather than quadratic. The cursor is per-pass: the allocator
/// rebuilds this space from the store on every pass, so a released address is
/// handed out again by the next one.
#[derive(Debug, Clone)]
pub(crate) struct AddressSpace {
    subnet: Ipv4Cidr,
    reserved: BTreeSet<Ipv4Addr>,
    range: Ipv4Cidr,
    owners: BTreeMap<Ipv4Addr, Id>,
    by_owner: BTreeMap<Id, Ipv4Addr>,
    cursor: u64,
}

impl AddressSpace {
    /// A space over `subnet`, allocating from `range` (pass `subnet` again for
    /// the whole subnet), with the network address, the broadcast address and
    /// `.1` reserved.
    pub(crate) fn new(subnet: Ipv4Cidr, range: Ipv4Cidr) -> Self {
        let mut reserved = BTreeSet::from([subnet.network(), subnet.broadcast()]);
        reserved.extend(subnet.gateway());
        Self {
            subnet,
            reserved,
            range,
            owners: BTreeMap::new(),
            by_owner: BTreeMap::new(),
            cursor: 0,
        }
    }

    /// Reserves one more address, which is then held by no one.
    ///
    /// This is how an operator-requested `--gateway` is honoured on an overlay
    /// network: it names no single node, so the only thing it can still mean is
    /// "keep this address free" (architecture §11.3).
    pub(crate) fn reserve(&mut self, ip: Ipv4Addr) {
        self.reserved.insert(ip);
    }

    /// The subnet this space covers.
    pub(crate) fn subnet(&self) -> Ipv4Cidr {
        self.subnet
    }

    /// Whether `ip` is one of the addresses no owner may hold.
    pub(crate) fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        self.reserved.contains(&ip)
    }

    /// How many addresses can be handed out in total — for error messages.
    pub(crate) fn capacity(&self) -> u64 {
        let reserved = self
            .reserved
            .iter()
            .filter(|ip| self.range.contains(**ip))
            .count();
        self.range
            .size()
            .saturating_sub(u64::try_from(reserved).unwrap_or(u64::MAX))
    }

    /// Records `ip` as held by `owner` (restore).
    pub(crate) fn claim(&mut self, ip: Ipv4Addr, owner: &Id) -> Result<(), SpaceError> {
        if !self.subnet.contains(ip) {
            return Err(SpaceError::Outside);
        }
        if self.is_reserved(ip) {
            return Err(SpaceError::Reserved);
        }
        if let Some(holder) = self.owners.get(&ip)
            && holder != owner
        {
            return Err(SpaceError::Occupied(holder.clone()));
        }
        self.owners.insert(ip, owner.clone());
        self.by_owner.insert(owner.clone(), ip);
        Ok(())
    }

    /// The address `owner` already holds, or the lowest free one.
    pub(crate) fn allocate(&mut self, owner: &Id) -> Result<Ipv4Addr, SpaceError> {
        if let Some(existing) = self.by_owner.get(owner) {
            return Ok(*existing);
        }
        let size = self.range.size();
        let start = self.cursor;
        for step in 0..size {
            let offset = (start + step) % size;
            let candidate = u32::try_from(offset)
                .ok()
                .and_then(|offset| self.range.host(offset));
            let Some(ip) = candidate else { continue };
            if self.is_reserved(ip) || self.owners.contains_key(&ip) {
                continue;
            }
            self.cursor = (offset + 1) % size;
            self.owners.insert(ip, owner.clone());
            self.by_owner.insert(owner.clone(), ip);
            return Ok(ip);
        }
        Err(SpaceError::Exhausted)
    }

    /// Releases whatever `owner` holds; returns the freed address.
    pub(crate) fn release(&mut self, owner: &Id) -> Option<Ipv4Addr> {
        let ip = self.by_owner.remove(owner)?;
        self.owners.remove(&ip);
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use satl_core::defaults::{OVERLAY_VNI_RANGE, OVERLAY_VXLAN_PORT_RANGE};

    use super::*;

    fn cidr(text: &str) -> Ipv4Cidr {
        text.parse().expect("valid CIDR")
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn id(n: u8) -> Id {
        // Deterministic, distinguishable IDs; the space only compares them.
        format!("{n:0>25}").parse().expect("25 base36 chars")
    }

    // ---- subnets -----------------------------------------------------------

    fn pool_space() -> SubnetSpace {
        SubnetSpace::new(vec![cidr("10.100.0.0/14")], 24)
    }

    #[test]
    fn subnets_are_carved_in_order_from_the_pool() {
        let mut space = pool_space();
        assert_eq!(space.allocate(&id(1)), Ok(cidr("10.100.0.0/24")));
        assert_eq!(space.allocate(&id(2)), Ok(cidr("10.100.1.0/24")));
        assert_eq!(space.allocate(&id(3)), Ok(cidr("10.100.2.0/24")));
        assert_eq!(space.subnet_size(), 24);
        assert_eq!(space.pools(), [cidr("10.100.0.0/14")]);
    }

    #[test]
    fn a_claimed_subnet_is_skipped_by_the_next_allocation() {
        let mut space = pool_space();
        // Restore: the store already says network 1 holds 10.100.0.0/24.
        assert_eq!(space.claim(cidr("10.100.0.0/24"), &id(1)), Ok(()));
        assert_eq!(space.allocate(&id(2)), Ok(cidr("10.100.1.0/24")));
        // Re-claiming for the same owner is idempotent.
        assert_eq!(space.claim(cidr("10.100.0.0/24"), &id(1)), Ok(()));
        assert_eq!(space.allocate(&id(3)), Ok(cidr("10.100.2.0/24")));
    }

    #[test]
    fn holes_are_reused_and_claims_may_land_anywhere_in_the_pool() {
        let mut space = pool_space();
        space.claim(cidr("10.100.0.0/24"), &id(1)).expect("claim");
        space.claim(cidr("10.100.2.0/24"), &id(2)).expect("claim");
        // The hole at .1 is handed out before .3.
        assert_eq!(space.allocate(&id(3)), Ok(cidr("10.100.1.0/24")));
        assert_eq!(space.allocate(&id(4)), Ok(cidr("10.100.3.0/24")));
    }

    #[test]
    fn overlapping_claims_are_refused_whatever_the_prefix_length() {
        let mut space = pool_space();
        space.claim(cidr("10.100.0.0/16"), &id(1)).expect("claim");
        // Inside the claimed /16.
        assert_eq!(
            space.claim(cidr("10.100.4.0/24"), &id(2)),
            Err(SpaceError::Occupied(id(1)))
        );
        // Containing the claimed /16.
        assert_eq!(
            space.claim(cidr("10.100.0.0/14"), &id(3)),
            Err(SpaceError::Occupied(id(1)))
        );
        // The /16 swallows the first 256 candidates of the pool.
        assert_eq!(space.allocate(&id(4)), Ok(cidr("10.101.0.0/24")));
    }

    #[test]
    fn several_pools_are_used_in_order() {
        let mut space = SubnetSpace::new(vec![cidr("10.1.0.0/24"), cidr("10.2.0.0/23")], 24);
        assert_eq!(space.allocate(&id(1)), Ok(cidr("10.1.0.0/24")));
        assert_eq!(space.allocate(&id(2)), Ok(cidr("10.2.0.0/24")));
        assert_eq!(space.allocate(&id(3)), Ok(cidr("10.2.1.0/24")));
        assert_eq!(space.allocate(&id(4)), Err(SpaceError::Exhausted));
    }

    #[test]
    fn an_exhausted_pool_is_a_typed_error() {
        // A /23 holds exactly two /24s.
        let mut space = SubnetSpace::new(vec![cidr("10.99.0.0/23")], 24);
        space.allocate(&id(1)).expect("first");
        space.allocate(&id(2)).expect("second");
        assert_eq!(space.allocate(&id(3)), Err(SpaceError::Exhausted));
    }

    #[test]
    fn a_pool_with_no_room_for_the_subnet_size_allocates_nothing() {
        // Asking for /16s out of a /24 pool: the pool cannot be split upwards.
        let mut space = SubnetSpace::new(vec![cidr("10.99.0.0/24")], 16);
        assert_eq!(space.allocate(&id(1)), Err(SpaceError::Exhausted));
        // No pool at all behaves the same way.
        let mut empty = SubnetSpace::new(Vec::new(), 24);
        assert_eq!(empty.allocate(&id(1)), Err(SpaceError::Exhausted));
    }

    // ---- VNIs --------------------------------------------------------------

    #[test]
    fn vnis_start_at_the_bottom_of_the_range() {
        let mut space = VniSpace::new(OVERLAY_VNI_RANGE);
        assert_eq!(space.allocate(&id(1)), Ok(4096));
        assert_eq!(space.allocate(&id(2)), Ok(4097));
        assert_eq!(space.range(), &OVERLAY_VNI_RANGE);
    }

    #[test]
    fn claimed_vnis_are_never_handed_out_again() {
        let mut space = VniSpace::new(OVERLAY_VNI_RANGE);
        space.claim(4096, &id(1)).expect("claim");
        space.claim(4098, &id(2)).expect("claim");
        // The hole at 4097 is filled first, then it continues past 4098.
        assert_eq!(space.allocate(&id(3)), Ok(4097));
        assert_eq!(space.allocate(&id(4)), Ok(4099));
        assert_eq!(space.claim(4096, &id(9)), Err(SpaceError::Occupied(id(1))));
        // Idempotent for the same owner.
        assert_eq!(space.claim(4096, &id(1)), Ok(()));
    }

    #[test]
    fn a_vni_from_outside_the_range_is_still_blocked() {
        let mut space = VniSpace::new(OVERLAY_VNI_RANGE);
        // A hand-configured low VNI recorded on a network.
        space.claim(42, &id(1)).expect("claim");
        assert_eq!(space.claim(42, &id(2)), Err(SpaceError::Occupied(id(1))));
        // Allocation still only picks from the range.
        assert_eq!(space.allocate(&id(3)), Ok(4096));
    }

    #[test]
    fn releasing_a_vni_frees_it_for_the_next_network() {
        let mut space = VniSpace::new(OVERLAY_VNI_RANGE);
        assert_eq!(space.allocate(&id(1)), Ok(4096));
        assert_eq!(space.allocate(&id(2)), Ok(4097));
        assert_eq!(space.release(&id(1)), Some(4096));
        assert_eq!(space.release(&id(1)), None, "idempotent");
        assert_eq!(space.allocate(&id(3)), Ok(4096), "the hole is reused");
    }

    #[test]
    fn an_exhausted_vni_range_is_a_typed_error() {
        let mut space = VniSpace::new(4096..=4097);
        space.allocate(&id(1)).expect("first");
        space.allocate(&id(2)).expect("second");
        assert_eq!(space.allocate(&id(3)), Err(SpaceError::Exhausted));
    }

    // ---- VTEP ports ----------------------------------------------------------

    #[test]
    fn vtep_ports_start_at_the_bottom_of_the_pool() {
        let mut space = VtepPortSpace::new(OVERLAY_VXLAN_PORT_RANGE);
        assert_eq!(space.allocate(&id(1)), Ok(4790));
        assert_eq!(space.allocate(&id(2)), Ok(4791));
        assert_eq!(space.range(), &OVERLAY_VXLAN_PORT_RANGE);
    }

    #[test]
    fn claimed_vtep_ports_are_never_handed_out_again() {
        let mut space = VtepPortSpace::new(OVERLAY_VXLAN_PORT_RANGE);
        space.claim(4790, &id(1)).expect("claim");
        space.claim(4792, &id(2)).expect("claim");
        // The hole at 4791 is filled first, then it continues past 4792.
        assert_eq!(space.allocate(&id(3)), Ok(4791));
        assert_eq!(space.allocate(&id(4)), Ok(4793));
        assert_eq!(space.claim(4790, &id(9)), Err(SpaceError::Occupied(id(1))));
        // Idempotent for the same owner.
        assert_eq!(space.claim(4790, &id(1)), Ok(()));
    }

    #[test]
    fn a_vtep_port_from_outside_the_pool_is_still_blocked() {
        let mut space = VtepPortSpace::new(OVERLAY_VXLAN_PORT_RANGE);
        // A port recorded before the pool existed, or by hand.
        space.claim(4789, &id(1)).expect("claim");
        assert_eq!(space.claim(4789, &id(2)), Err(SpaceError::Occupied(id(1))));
        // Allocation still only picks from the pool.
        assert_eq!(space.allocate(&id(3)), Ok(4790));
    }

    #[test]
    fn releasing_a_vtep_port_frees_it_for_the_next_network() {
        let mut space = VtepPortSpace::new(OVERLAY_VXLAN_PORT_RANGE);
        assert_eq!(space.allocate(&id(1)), Ok(4790));
        assert_eq!(space.allocate(&id(2)), Ok(4791));
        assert_eq!(space.release(&id(1)), Some(4790));
        assert_eq!(space.release(&id(1)), None, "idempotent");
        assert_eq!(space.allocate(&id(3)), Ok(4790), "the hole is reused");
    }

    /// The pool boundary, driven directly with a narrow pool rather than by
    /// creating 210 networks (mirrors `an_exhausted_vni_range_is_a_typed_error`).
    #[test]
    fn an_exhausted_vtep_port_pool_is_a_typed_error() {
        let mut space = VtepPortSpace::new(4790..=4791);
        space.allocate(&id(1)).expect("first");
        space.allocate(&id(2)).expect("second");
        assert_eq!(space.allocate(&id(3)), Err(SpaceError::Exhausted));
    }

    // ---- host addresses ----------------------------------------------------

    fn address_space() -> AddressSpace {
        let subnet = cidr("10.100.4.0/24");
        AddressSpace::new(subnet, subnet)
    }

    #[test]
    fn addresses_start_after_the_gateway_and_are_stable() {
        let mut space = address_space();
        assert_eq!(space.allocate(&id(1)), Ok(ip("10.100.4.2")));
        assert_eq!(space.allocate(&id(2)), Ok(ip("10.100.4.3")));
        // Stable: the same owner gets the same address back.
        assert_eq!(space.allocate(&id(1)), Ok(ip("10.100.4.2")));
        assert_eq!(space.subnet(), cidr("10.100.4.0/24"));
        assert!(space.is_reserved(ip("10.100.4.1")), "the .1 convention");
        assert_eq!(space.capacity(), 253, ".2 through .254");
    }

    /// Tasks and node gateways share one space, so an address handed to one is
    /// never handed to the other (`docs/vxlan.md` §8: they are on one L2
    /// segment).
    #[test]
    fn tasks_and_node_gateways_never_collide() {
        let mut space = address_space();
        let (task, node, other_node) = (id(1), id(2), id(3));
        assert_eq!(space.allocate(&task), Ok(ip("10.100.4.2")));
        assert_eq!(space.allocate(&node), Ok(ip("10.100.4.3")));
        assert_eq!(space.allocate(&other_node), Ok(ip("10.100.4.4")));
        // Each owner keeps what it has, whoever asks again.
        assert_eq!(space.allocate(&node), Ok(ip("10.100.4.3")));
        assert_eq!(space.allocate(&task), Ok(ip("10.100.4.2")));
        // And the other order: a claimed node gateway blocks the address for
        // tasks.
        let mut space = address_space();
        assert_eq!(space.claim(ip("10.100.4.2"), &node), Ok(()));
        assert_eq!(
            space.claim(ip("10.100.4.2"), &task),
            Err(SpaceError::Occupied(node.clone()))
        );
        assert_eq!(space.allocate(&task), Ok(ip("10.100.4.3")));
    }

    #[test]
    fn reserved_addresses_are_never_allocated_or_claimed() {
        let mut space = address_space();
        for reserved in ["10.100.4.0", "10.100.4.1", "10.100.4.255"] {
            assert!(space.is_reserved(ip(reserved)), "{reserved}");
            assert_eq!(space.claim(ip(reserved), &id(1)), Err(SpaceError::Reserved));
        }
        assert!(!space.is_reserved(ip("10.100.4.2")));
        // Fill the subnet: 253 usable addresses, none of them reserved.
        let mut handed_out = Vec::new();
        for task in 0..253u8 {
            handed_out.push(space.allocate(&id(task)).expect("address"));
        }
        assert!(handed_out.iter().all(|ip| !space.is_reserved(*ip)));
        assert_eq!(handed_out.len(), 253);
        assert_eq!(space.allocate(&id(254)), Err(SpaceError::Exhausted));
    }

    /// An operator-requested `--gateway` is an *extra* reservation: `.1` stays
    /// reserved too, because an overlay's real gateways are per node.
    #[test]
    fn an_extra_reservation_is_held_by_nobody_and_dot_one_still_is_too() {
        let subnet = cidr("10.100.4.0/24");
        let mut space = AddressSpace::new(subnet, subnet);
        space.reserve(ip("10.100.4.254"));
        assert!(space.is_reserved(ip("10.100.4.254")));
        assert!(space.is_reserved(ip("10.100.4.1")), ".1 is not given away");
        assert_eq!(
            space.claim(ip("10.100.4.254"), &id(2)),
            Err(SpaceError::Reserved)
        );
        assert_eq!(space.capacity(), 252, ".2 through .253");
        // Both reservations are skipped by allocation, wherever the cursor is.
        for owner in 1..=252u8 {
            let ip = space.allocate(&id(owner)).expect("address");
            assert!(!space.is_reserved(ip), "{ip}");
        }
        assert_eq!(space.allocate(&id(0)), Err(SpaceError::Exhausted));
    }

    #[test]
    fn claims_outside_the_subnet_and_double_claims_are_refused() {
        let mut space = address_space();
        assert_eq!(
            space.claim(ip("10.100.5.2"), &id(1)),
            Err(SpaceError::Outside)
        );
        assert_eq!(space.claim(ip("10.100.4.9"), &id(1)), Ok(()));
        assert_eq!(space.claim(ip("10.100.4.9"), &id(1)), Ok(()), "idempotent");
        assert_eq!(
            space.claim(ip("10.100.4.9"), &id(2)),
            Err(SpaceError::Occupied(id(1)))
        );
        // The claimed address is not handed out to anyone else.
        assert_eq!(space.allocate(&id(3)), Ok(ip("10.100.4.2")));
        for task in 4..12u8 {
            let ip = space.allocate(&id(task)).expect("address");
            assert_ne!(ip.to_string(), "10.100.4.9");
        }
    }

    /// A `/29` — `.1` gateway, `.2`–`.6` usable, `.7` broadcast — is small
    /// enough to walk the cursor all the way round.
    #[test]
    fn releasing_frees_the_address_and_the_cursor_wraps_onto_it() {
        let subnet = cidr("10.100.4.0/29");
        let mut space = AddressSpace::new(subnet, subnet);
        assert_eq!(space.capacity(), 5);
        assert_eq!(space.allocate(&id(1)), Ok(ip("10.100.4.2")));
        assert_eq!(space.allocate(&id(2)), Ok(ip("10.100.4.3")));
        assert_eq!(space.release(&id(1)), Some(ip("10.100.4.2")));
        assert_eq!(space.release(&id(1)), None, "idempotent");
        // The cursor is past the hole, so it keeps going forward first…
        assert_eq!(space.allocate(&id(3)), Ok(ip("10.100.4.4")));
        assert_eq!(space.allocate(&id(4)), Ok(ip("10.100.4.5")));
        assert_eq!(space.allocate(&id(5)), Ok(ip("10.100.4.6")));
        // …and then wraps onto the freed address rather than giving up.
        assert_eq!(space.allocate(&id(6)), Ok(ip("10.100.4.2")));
        assert_eq!(space.allocate(&id(7)), Err(SpaceError::Exhausted));
    }

    #[test]
    fn an_ip_range_narrows_what_tasks_get_without_changing_the_subnet() {
        let subnet = cidr("10.100.4.0/24");
        // Tasks only from 10.100.4.128/25.
        let mut space = AddressSpace::new(subnet, cidr("10.100.4.128/25"));
        assert_eq!(space.subnet(), subnet, "the subnet is still the /24");
        assert_eq!(space.allocate(&id(1)), Ok(ip("10.100.4.128")));
        assert_eq!(space.allocate(&id(2)), Ok(ip("10.100.4.129")));
        assert_eq!(space.capacity(), 127, ".128 through .254");
        // Addresses outside the range are still claimable (restore of an
        // allocation made before the range was narrowed).
        assert_eq!(space.claim(ip("10.100.4.10"), &id(3)), Ok(()));
        // And the range fills up long before the subnet does.
        for task in 10..137u8 {
            if space.allocate(&id(task)).is_err() {
                break;
            }
        }
        assert_eq!(space.allocate(&id(200)), Err(SpaceError::Exhausted));
    }

    #[test]
    fn a_slash_30_subnet_holds_exactly_one_owner() {
        let subnet = cidr("10.100.4.0/30");
        let mut space = AddressSpace::new(subnet, subnet);
        assert_eq!(space.capacity(), 1);
        assert_eq!(space.allocate(&id(1)), Ok(ip("10.100.4.2")));
        assert_eq!(space.allocate(&id(2)), Err(SpaceError::Exhausted));
    }
}
