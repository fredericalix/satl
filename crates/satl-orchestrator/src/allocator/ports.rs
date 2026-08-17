// SPDX-License-Identifier: BSD-2-Clause
//! Ingress published-port allocation (SWK §9.5, architecture §11.4).
//!
//! Per protocol, two bit spaces — SwarmKit's shape, kept deliberately:
//!
//! - the **master** space, `1..=65535`, is the authoritative record of every
//!   ingress port in use, whether the operator asked for it explicitly or the
//!   allocator picked it;
//! - the **dynamic** space, `30000..=32767`, is the pool auto-assigned ports
//!   come from. An explicit request that lands inside the dynamic range claims
//!   both spaces, so the pool can never hand it out a second time.
//!
//! Only `ingress` ports are allocated. `host`-mode ports are recorded verbatim
//! (architecture §11.4: per-node exclusivity is a scheduler filter, not a
//! cluster allocation), so they never enter either space.
//!
//! **Sticky reallocation** is the property that matters to operators: a service
//! update must not reshuffle published ports. It falls out of two things —
//! restore claims every port the store already records for a service, and the
//! auto-assign path first looks for a previously assigned port with the same
//! `(name, protocol, target_port)` key. See [`PortSpace::allocate_service`].

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use satl_core::defaults::{INGRESS_PORT_MASTER_RANGE, INGRESS_PORT_RANGE};
use satl_core::{Endpoint, EndpointSpec, Id, PortConfig, PortProtocol, PublishMode};

use super::space::SpaceError;

/// A fixed-range bitmap of `u16` values — the port spaces of SWK §9.5.
///
/// Hand-rolled on purpose: 64 Ki bits is 8 KiB, the operations are three lines
/// each, and a dependency would buy nothing.
#[derive(Debug, Clone)]
struct Bitmap {
    base: u16,
    len: usize,
    words: Vec<u64>,
}

impl Bitmap {
    /// An empty bitmap covering `range`.
    fn new(range: &RangeInclusive<u16>) -> Self {
        let base = *range.start();
        let len = usize::from(range.end().saturating_sub(base)) + 1;
        Self {
            base,
            len,
            words: vec![0; len.div_ceil(64)],
        }
    }

    /// Bit index of `value`, or `None` when it is outside the range.
    fn index(&self, value: u16) -> Option<usize> {
        let offset = usize::from(value.checked_sub(self.base)?);
        (offset < self.len).then_some(offset)
    }

    /// Whether `value` is inside the covered range. Test-only: production code
    /// never asks, it just sets (out-of-range sets are no-ops by design).
    #[cfg(test)]
    fn covers(&self, value: u16) -> bool {
        self.index(value).is_some()
    }

    /// Marks `value` as used. Values outside the range are ignored — the
    /// caller has already decided which spaces a port belongs to.
    fn set(&mut self, value: u16) {
        if let Some(index) = self.index(value) {
            self.words[index / 64] |= 1u64 << (index % 64);
        }
    }

    /// Whether `value` is marked used (false when outside the range).
    /// Test-only: allocation goes through [`Bitmap::first_free`], which reads
    /// the words directly.
    #[cfg(test)]
    fn is_set(&self, value: u16) -> bool {
        self.index(value)
            .is_some_and(|index| self.words[index / 64] & (1u64 << (index % 64)) != 0)
    }

    /// The lowest unused value in the range.
    ///
    /// `trailing_ones` on the first non-saturated word gives the first zero
    /// bit, so this is a scan over words (1 Ki of them at most), not bits.
    fn first_free(&self) -> Option<u16> {
        let (word_index, word) = self
            .words
            .iter()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)?;
        let index = word_index * 64 + usize::try_from(word.trailing_ones()).ok()?;
        if index >= self.len {
            return None;
        }
        u16::try_from(usize::from(self.base) + index).ok()
    }
}

/// One protocol's pair of spaces plus who holds each port.
#[derive(Debug, Clone)]
struct ProtocolPorts {
    master: Bitmap,
    dynamic: Bitmap,
    owners: BTreeMap<u16, Id>,
}

impl ProtocolPorts {
    fn new() -> Self {
        Self {
            master: Bitmap::new(&INGRESS_PORT_MASTER_RANGE),
            dynamic: Bitmap::new(&INGRESS_PORT_RANGE),
            owners: BTreeMap::new(),
        }
    }

    /// Records `port` as held by `service`, in the master space and — when it
    /// falls inside it — in the dynamic space too.
    fn claim(&mut self, port: u16, service: &Id) -> Result<(), SpaceError> {
        if let Some(holder) = self.owners.get(&port)
            && holder != service
        {
            return Err(SpaceError::Occupied(holder.clone()));
        }
        self.master.set(port);
        self.dynamic.set(port);
        self.owners.insert(port, service.clone());
        Ok(())
    }

    /// The lowest free port of the dynamic pool, claimed for `service`.
    fn allocate_dynamic(&mut self, service: &Id) -> Result<u16, SpaceError> {
        let port = self.dynamic.first_free().ok_or(SpaceError::Exhausted)?;
        self.claim(port, service)?;
        Ok(port)
    }
}

/// The ingress port spaces of the whole cluster, one pair per protocol.
#[derive(Debug, Clone)]
pub(crate) struct PortSpace {
    tcp: ProtocolPorts,
    udp: ProtocolPorts,
}

impl PortSpace {
    /// Empty spaces — restore fills them from the store.
    pub(crate) fn new() -> Self {
        Self {
            tcp: ProtocolPorts::new(),
            udp: ProtocolPorts::new(),
        }
    }

    fn protocol(&mut self, protocol: PortProtocol) -> &mut ProtocolPorts {
        match protocol {
            PortProtocol::Tcp => &mut self.tcp,
            PortProtocol::Udp => &mut self.udp,
        }
    }

    /// Which service holds `port`, if anyone.
    fn owner(&self, protocol: PortProtocol, port: u16) -> Option<&Id> {
        match protocol {
            PortProtocol::Tcp => self.tcp.owners.get(&port),
            PortProtocol::Udp => self.udp.owners.get(&port),
        }
    }

    /// Restore: records every ingress port of an already-allocated endpoint as
    /// held by `service` (SWK §9.2). Returns the ports that could not be
    /// claimed because another service already holds them.
    pub(crate) fn claim_endpoint(
        &mut self,
        service: &Id,
        endpoint: &Endpoint,
    ) -> Vec<(PortConfig, SpaceError)> {
        let mut conflicts = Vec::new();
        for port in ingress_ports(&endpoint.ports) {
            if port.published_port == 0 {
                // Not actually allocated (an endpoint written before the
                // allocation completed); nothing to claim.
                continue;
            }
            if let Err(err) = self
                .protocol(port.protocol)
                .claim(port.published_port, service)
            {
                conflicts.push((port.clone(), err));
            }
        }
        conflicts
    }

    /// Allocates the published ports of `spec` for `service`, reusing what
    /// `previous` (the endpoint currently in the store) already has.
    ///
    /// Rules, in order:
    ///
    /// 1. `host`-mode ports are copied verbatim — never allocated.
    /// 2. an explicit `published_port` is claimed as asked; it is an error if
    ///    another service holds it, or if the same spec asks for it twice.
    /// 3. `published_port == 0` is auto-assigned: **sticky** first — the port
    ///    `previous` holds for the same `(name, protocol, target_port)` — then
    ///    the lowest free port of the dynamic pool.
    ///
    /// The returned ports are in spec order, so the endpoint is a stable
    /// function of the spec and of what was already allocated.
    pub(crate) fn allocate_service(
        &mut self,
        service: &Id,
        spec: &EndpointSpec,
        previous: Option<&Endpoint>,
    ) -> Result<Vec<PortConfig>, PortError> {
        let mut allocated = Vec::with_capacity(spec.ports.len());
        let mut claimed_here: BTreeSet<(PortProtocol, u16)> = BTreeSet::new();
        for wanted in &spec.ports {
            if wanted.publish_mode == PublishMode::Host {
                allocated.push(wanted.clone());
                continue;
            }
            let mut port = wanted.clone();
            if port.published_port == 0 {
                port.published_port = self.sticky(service, wanted, previous, &claimed_here);
            }
            if port.published_port == 0 {
                port.published_port = self
                    .protocol(port.protocol)
                    .allocate_dynamic(service)
                    .map_err(|_| PortError::DynamicExhausted {
                        protocol: port.protocol,
                    })?;
            } else if !claimed_here.insert((port.protocol, port.published_port)) {
                return Err(PortError::Duplicate {
                    port: port.published_port,
                    protocol: port.protocol,
                });
            } else if let Err(SpaceError::Occupied(holder)) = self
                .protocol(port.protocol)
                .claim(port.published_port, service)
            {
                return Err(PortError::Occupied {
                    port: port.published_port,
                    protocol: port.protocol,
                    holder,
                });
            }
            claimed_here.insert((port.protocol, port.published_port));
            allocated.push(port);
        }
        Ok(allocated)
    }

    /// The port `previous` already published for the same
    /// `(name, protocol, target_port)`, if it is still this service's to keep.
    /// `0` when there is nothing to reuse.
    fn sticky(
        &self,
        service: &Id,
        wanted: &PortConfig,
        previous: Option<&Endpoint>,
        claimed_here: &BTreeSet<(PortProtocol, u16)>,
    ) -> u16 {
        let Some(previous) = previous else { return 0 };
        let candidate = ingress_ports(&previous.ports).find(|port| {
            port.name == wanted.name
                && port.protocol == wanted.protocol
                && port.target_port == wanted.target_port
                && port.published_port != 0
        });
        let Some(candidate) = candidate else { return 0 };
        if claimed_here.contains(&(candidate.protocol, candidate.published_port)) {
            return 0;
        }
        // Restore claimed it for us; if anyone else holds it now, it is not
        // ours to keep and the caller falls back to a fresh allocation.
        let held_by_us = self
            .owner(candidate.protocol, candidate.published_port)
            .is_some_and(|holder| holder == service);
        if held_by_us {
            candidate.published_port
        } else {
            0
        }
    }
}

/// The ingress entries of a port list (host-mode ports are not allocated).
fn ingress_ports(ports: &[PortConfig]) -> impl Iterator<Item = &PortConfig> {
    ports
        .iter()
        .filter(|port| port.publish_mode == PublishMode::Ingress)
}

/// Why a service's ports could not be allocated. The planner adds the service
/// name (see [`super::error::AllocError`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PortError {
    /// Another service publishes that port.
    Occupied {
        /// The contended published port.
        port: u16,
        /// Its protocol.
        protocol: PortProtocol,
        /// The service that holds it.
        holder: Id,
    },
    /// The same spec asks for one published port twice.
    Duplicate {
        /// The repeated published port.
        port: u16,
        /// Its protocol.
        protocol: PortProtocol,
    },
    /// No free port left in the dynamic range.
    DynamicExhausted {
        /// The protocol whose pool is full.
        protocol: PortProtocol,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        format!("{n:0>25}").parse().expect("25 base36 chars")
    }

    fn port(name: &str, target: u16, published: u16) -> PortConfig {
        PortConfig {
            name: name.to_owned(),
            protocol: PortProtocol::Tcp,
            target_port: target,
            published_port: published,
            publish_mode: PublishMode::Ingress,
        }
    }

    fn spec(ports: Vec<PortConfig>) -> EndpointSpec {
        EndpointSpec {
            mode: satl_core::EndpointMode::DnsRR,
            ports,
        }
    }

    fn endpoint(ports: Vec<PortConfig>) -> Endpoint {
        Endpoint {
            spec: spec(ports.clone()),
            ports,
        }
    }

    // ---- the bitmaps -------------------------------------------------------

    #[test]
    fn bitmap_covers_only_its_range() {
        let mut map = Bitmap::new(&INGRESS_PORT_RANGE);
        assert!(map.covers(30000));
        assert!(map.covers(32767));
        assert!(!map.covers(29999));
        assert!(!map.covers(32768));
        assert_eq!(map.first_free(), Some(30000));
        map.set(30000);
        assert!(map.is_set(30000));
        assert_eq!(map.first_free(), Some(30001));
        // Out-of-range sets are no-ops, not panics.
        map.set(80);
        assert!(!map.is_set(80));
    }

    #[test]
    fn bitmap_fills_and_reports_exhaustion() {
        let mut map = Bitmap::new(&(1..=130));
        for value in 1..=130 {
            assert_eq!(map.first_free(), Some(value));
            map.set(value);
        }
        assert_eq!(map.first_free(), None);
        assert!(map.is_set(64), "word boundaries");
        assert!(map.is_set(65));
        assert!(map.is_set(128));
    }

    #[test]
    fn the_master_space_spans_every_port() {
        let map = Bitmap::new(&INGRESS_PORT_MASTER_RANGE);
        assert!(map.covers(1));
        assert!(map.covers(80));
        assert!(map.covers(65535));
        assert!(!map.covers(0), "port 0 is not publishable");
    }

    // ---- allocation --------------------------------------------------------

    #[test]
    fn auto_assigned_ports_come_from_the_dynamic_range() {
        let mut space = PortSpace::new();
        let ports = space
            .allocate_service(
                &id(1),
                &spec(vec![port("http", 80, 0), port("api", 8080, 0)]),
                None,
            )
            .expect("allocated");
        assert_eq!(ports[0].published_port, 30000);
        assert_eq!(ports[1].published_port, 30001);
        assert_eq!(ports[0].target_port, 80, "target ports are untouched");
        assert_eq!(ports[0].name, "http", "and so are the names");
    }

    #[test]
    fn explicit_ports_are_claimed_as_asked_in_both_spaces() {
        let mut space = PortSpace::new();
        let ports = space
            .allocate_service(
                &id(1),
                &spec(vec![port("http", 80, 8080), port("dyn", 90, 30000)]),
                None,
            )
            .expect("allocated");
        assert_eq!(ports[0].published_port, 8080);
        assert_eq!(ports[1].published_port, 30000);
        // 30000 was inside the dynamic range, so the pool must skip it.
        let other = space
            .allocate_service(&id(2), &spec(vec![port("x", 1, 0)]), None)
            .expect("allocated");
        assert_eq!(other[0].published_port, 30001);
    }

    #[test]
    fn another_services_port_is_a_conflict_naming_the_holder() {
        let mut space = PortSpace::new();
        space
            .allocate_service(&id(1), &spec(vec![port("http", 80, 8080)]), None)
            .expect("allocated");
        let err = space
            .allocate_service(&id(2), &spec(vec![port("http", 80, 8080)]), None)
            .expect_err("conflict");
        assert_eq!(
            err,
            PortError::Occupied {
                port: 8080,
                protocol: PortProtocol::Tcp,
                holder: id(1),
            }
        );
    }

    #[test]
    fn the_same_spec_may_not_ask_for_one_port_twice() {
        let mut space = PortSpace::new();
        let err = space
            .allocate_service(
                &id(1),
                &spec(vec![port("a", 80, 8080), port("b", 81, 8080)]),
                None,
            )
            .expect_err("duplicate");
        assert_eq!(
            err,
            PortError::Duplicate {
                port: 8080,
                protocol: PortProtocol::Tcp,
            }
        );
    }

    #[test]
    fn protocols_have_separate_spaces() {
        let mut space = PortSpace::new();
        let mut udp = port("http", 80, 8080);
        udp.protocol = PortProtocol::Udp;
        let ports = space
            .allocate_service(&id(1), &spec(vec![port("http", 80, 8080), udp]), None)
            .expect("tcp/8080 and udp/8080 do not collide");
        assert_eq!(ports[0].published_port, 8080);
        assert_eq!(ports[1].published_port, 8080);
        // And the dynamic pools are independent too.
        let mut udp_dynamic = port("d", 1, 0);
        udp_dynamic.protocol = PortProtocol::Udp;
        let both = space
            .allocate_service(&id(2), &spec(vec![port("d", 1, 0), udp_dynamic]), None)
            .expect("allocated");
        assert_eq!(both[0].published_port, 30000);
        assert_eq!(both[1].published_port, 30000);
    }

    #[test]
    fn host_mode_ports_are_recorded_verbatim_and_never_allocated() {
        let mut space = PortSpace::new();
        let mut host = port("http", 80, 8080);
        host.publish_mode = PublishMode::Host;
        let mut host_zero = port("api", 90, 0);
        host_zero.publish_mode = PublishMode::Host;
        let ports = space
            .allocate_service(&id(1), &spec(vec![host, host_zero]), None)
            .expect("allocated");
        assert_eq!(ports[0].published_port, 8080, "verbatim");
        assert_eq!(ports[1].published_port, 0, "still not allocated");
        // Neither entered the master space: another service may publish 8080
        // in ingress mode.
        space
            .allocate_service(&id(2), &spec(vec![port("http", 80, 8080)]), None)
            .expect("host mode did not claim 8080");
    }

    // ---- sticky reallocation ----------------------------------------------

    #[test]
    fn an_update_keeps_the_previously_assigned_port() {
        let mut space = PortSpace::new();
        let service = id(1);
        let first = space
            .allocate_service(&service, &spec(vec![port("http", 80, 0)]), None)
            .expect("allocated");
        assert_eq!(first[0].published_port, 30000);
        let previous = endpoint(first);

        // A new pass: restore claims what the store records, then the service
        // is updated with an extra port.
        let mut space = PortSpace::new();
        assert!(
            space.claim_endpoint(&service, &previous).is_empty(),
            "restore claims cleanly"
        );
        let updated = space
            .allocate_service(
                &service,
                &spec(vec![port("http", 80, 0), port("metrics", 9100, 0)]),
                Some(&previous),
            )
            .expect("allocated");
        assert_eq!(
            updated[0].published_port, 30000,
            "the http port did not move"
        );
        assert_eq!(
            updated[1].published_port, 30001,
            "the new port takes the next free one"
        );
    }

    #[test]
    fn reordering_the_spec_does_not_reshuffle_published_ports() {
        let mut space = PortSpace::new();
        let service = id(1);
        let first = space
            .allocate_service(
                &service,
                &spec(vec![port("http", 80, 0), port("api", 8080, 0)]),
                None,
            )
            .expect("allocated");
        assert_eq!(
            (first[0].published_port, first[1].published_port),
            (30000, 30001)
        );
        let previous = endpoint(first);

        let mut space = PortSpace::new();
        space.claim_endpoint(&service, &previous);
        let reordered = space
            .allocate_service(
                &service,
                &spec(vec![port("api", 8080, 0), port("http", 80, 0)]),
                Some(&previous),
            )
            .expect("allocated");
        assert_eq!(reordered[0].name, "api");
        assert_eq!(reordered[0].published_port, 30001, "api keeps 30001");
        assert_eq!(reordered[1].published_port, 30000, "http keeps 30000");
    }

    #[test]
    fn the_sticky_key_is_name_protocol_and_target_port() {
        let mut space = PortSpace::new();
        let service = id(1);
        let previous = endpoint(vec![port("http", 80, 30000)]);
        space.claim_endpoint(&service, &previous);

        // Same name, different target port: not the same port, so a fresh one.
        let changed_target = space
            .allocate_service(
                &service,
                &spec(vec![port("http", 8080, 0)]),
                Some(&previous),
            )
            .expect("allocated");
        assert_eq!(changed_target[0].published_port, 30001);

        // Same target, different name: also a fresh one.
        let mut space = PortSpace::new();
        space.claim_endpoint(&service, &previous);
        let renamed = space
            .allocate_service(&service, &spec(vec![port("web", 80, 0)]), Some(&previous))
            .expect("allocated");
        assert_eq!(renamed[0].published_port, 30001);

        // Same key but a different protocol: fresh as well.
        let mut space = PortSpace::new();
        space.claim_endpoint(&service, &previous);
        let mut udp = port("http", 80, 0);
        udp.protocol = PortProtocol::Udp;
        let other_protocol = space
            .allocate_service(&service, &spec(vec![udp]), Some(&previous))
            .expect("allocated");
        assert_eq!(
            other_protocol[0].published_port, 30000,
            "the UDP pool is untouched, so it starts at the bottom"
        );
    }

    #[test]
    fn a_port_now_held_by_another_service_is_not_stuck_to() {
        let mut space = PortSpace::new();
        let previous = endpoint(vec![port("http", 80, 30000)]);
        // Someone else got 30000 in the meantime (an explicit request).
        space
            .allocate_service(&id(2), &spec(vec![port("x", 1, 30000)]), None)
            .expect("allocated");
        let ports = space
            .allocate_service(&id(1), &spec(vec![port("http", 80, 0)]), Some(&previous))
            .expect("allocated");
        assert_eq!(ports[0].published_port, 30001, "fell back to a fresh port");
    }

    #[test]
    fn restore_reports_a_port_two_services_both_recorded() {
        let mut space = PortSpace::new();
        let shared = endpoint(vec![port("http", 80, 8080)]);
        assert!(space.claim_endpoint(&id(1), &shared).is_empty());
        let conflicts = space.claim_endpoint(&id(2), &shared);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0.published_port, 8080);
        assert_eq!(conflicts[0].1, SpaceError::Occupied(id(1)));
    }

    #[test]
    fn an_unallocated_endpoint_entry_claims_nothing() {
        let mut space = PortSpace::new();
        // published_port 0: written by the API before allocation ran.
        let pending = endpoint(vec![port("http", 80, 0)]);
        assert!(space.claim_endpoint(&id(1), &pending).is_empty());
        let ports = space
            .allocate_service(&id(1), &spec(vec![port("http", 80, 0)]), Some(&pending))
            .expect("allocated");
        assert_eq!(ports[0].published_port, 30000);
    }

    #[test]
    fn an_exhausted_dynamic_pool_is_a_typed_error() {
        let mut space = PortSpace::new();
        let service = id(1);
        // Fill the whole dynamic range with explicit requests.
        let ports: Vec<PortConfig> = INGRESS_PORT_RANGE
            .map(|published| port(&format!("p{published}"), published, published))
            .collect();
        space
            .allocate_service(&service, &spec(ports), None)
            .expect("the whole pool, explicitly");
        let err = space
            .allocate_service(&id(2), &spec(vec![port("late", 1, 0)]), None)
            .expect_err("nothing left to auto-assign");
        assert_eq!(
            err,
            PortError::DynamicExhausted {
                protocol: PortProtocol::Tcp,
            }
        );
        // Explicit ports outside the dynamic range still work.
        space
            .allocate_service(&id(3), &spec(vec![port("http", 80, 8080)]), None)
            .expect("the master space is far from full");
    }
}
