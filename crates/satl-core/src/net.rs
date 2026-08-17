// SPDX-License-Identifier: BSD-2-Clause
//! IPv4 addressing values and the derived overlay MAC (architecture §11.2,
//! §11.3).
//!
//! The store keeps addressing as text — `Network.subnet`,
//! `Network.node_gateways`, `NetworkAttachment.addresses` — because that is
//! what the Docker API speaks.
//! Every component that reasons about those strings (the cluster allocator,
//! the overlay agent, the DNS responder) needs the same arithmetic, so the
//! parsing and the arithmetic live here, in the crate at the root of the
//! dependency graph, and are pure.
//!
//! [`Ipv4Cidr`] deliberately allows host bits: `10.100.4.0/24` (a subnet) and
//! `10.100.4.5/24` (an address within it) are both written in CIDR form in the
//! store, and only the caller knows which one it is asking for
//! ([`Ipv4Cidr::is_network_address`] tells them apart).
//!
//! `satl-net`'s node-local `SubnetV4` is the same idea for the node-local
//! bridge pool, minus host bits; TODO(M3): make it a re-export of this type
//! next time that crate is touched, so there is one CIDR type in the tree.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{InvalidCidr, InvalidMac};

/// An IPv4 address with a prefix length, e.g. `10.100.4.0/24`.
///
/// Serialized as its display string, so it round-trips through the Docker API
/// and the store unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Builds `addr/prefix_len`; the only rejected input is a prefix length
    /// above 32. Host bits are kept verbatim (see the module docs).
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, InvalidCidr> {
        if prefix_len > 32 {
            return Err(InvalidCidr {
                value: format!("{addr}/{prefix_len}"),
                reason: "prefix length exceeds 32",
            });
        }
        Ok(Self { addr, prefix_len })
    }

    /// The address as written (host bits included).
    pub fn addr(self) -> Ipv4Addr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// The netmask of this prefix length.
    pub fn mask(self) -> u32 {
        mask_of(self.prefix_len)
    }

    /// The network address (host bits cleared).
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    /// This CIDR with its host bits cleared — the subnet it belongs to.
    #[must_use]
    pub fn network_cidr(self) -> Self {
        Self {
            addr: self.network(),
            prefix_len: self.prefix_len,
        }
    }

    /// The broadcast address (host bits set).
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    /// Whether the address is written without host bits — i.e. whether this
    /// value denotes a subnet rather than an address inside one.
    pub fn is_network_address(self) -> bool {
        self.addr == self.network()
    }

    /// Whether `ip` falls inside this subnet.
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.network())
    }

    /// Whether `other` is entirely inside this subnet.
    pub fn contains_subnet(self, other: Self) -> bool {
        other.prefix_len >= self.prefix_len
            && self.contains(other.network())
            && self.contains(other.broadcast())
    }

    /// The `n`-th address of the subnet (network address + `n`), or `None`
    /// when that would leave it.
    pub fn host(self, n: u32) -> Option<Ipv4Addr> {
        let candidate = u32::from(self.network()).checked_add(n)?;
        let ip = Ipv4Addr::from(candidate);
        self.contains(ip).then_some(ip)
    }

    /// The SatL gateway convention: `.1` of the subnet (architecture §11.3).
    /// `None` for prefixes with no room for one (`/31`, `/32`).
    ///
    /// On a node-local bridge network this *is* the gateway — the bridge's
    /// address. On a cluster overlay it is reserved and assigned to nobody: the
    /// gateway there is per node (`Network::node_gateways`), and handing `.1` to
    /// one arbitrary node would make what an operator reads in the subnet a
    /// trap.
    pub fn gateway(self) -> Option<Ipv4Addr> {
        (self.prefix_len <= 30).then(|| self.host(1)).flatten()
    }

    /// How many addresses the subnet spans, broadcast and network included.
    pub fn size(self) -> u64 {
        1u64 << (32 - u32::from(self.prefix_len.min(32)))
    }

    /// The subnets of length `prefix_len` this one splits into, in ascending
    /// order. Empty when `prefix_len` is shorter than this subnet's own (a
    /// subnet cannot be carved into larger pieces) or above 32.
    pub fn subnets(self, prefix_len: u8) -> Subnets {
        let (count, step) = if prefix_len > 32 || prefix_len < self.prefix_len {
            (0, 1)
        } else {
            (
                1u64 << (u32::from(prefix_len) - u32::from(self.prefix_len)),
                1u64 << (32 - u32::from(prefix_len)),
            )
        };
        Subnets {
            base: u32::from(self.network()),
            prefix_len,
            step,
            index: 0,
            count,
        }
    }
}

/// Netmask for a prefix length, saturating at `/32`.
fn mask_of(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        n if n >= 32 => u32::MAX,
        n => u32::MAX << (32 - u32::from(n)),
    }
}

/// Iterator over the equally sized subnets of an [`Ipv4Cidr`], as returned by
/// [`Ipv4Cidr::subnets`].
#[derive(Debug, Clone)]
pub struct Subnets {
    base: u32,
    prefix_len: u8,
    step: u64,
    index: u64,
    count: u64,
}

impl Iterator for Subnets {
    type Item = Ipv4Cidr;

    fn next(&mut self) -> Option<Ipv4Cidr> {
        if self.index >= self.count {
            return None;
        }
        let offset = self.index.checked_mul(self.step)?;
        // Infallible by construction: `count * step` is exactly the size of
        // the subnet being split, so base + offset stays inside it. Handled
        // as a `None` rather than an unwrap so a future arithmetic slip ends
        // the iteration instead of killing the allocator.
        let addr = u32::try_from(u64::from(self.base) + offset).ok()?;
        self.index += 1;
        Some(Ipv4Cidr {
            addr: Ipv4Addr::from(addr),
            prefix_len: self.prefix_len,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.count - self.index).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = InvalidCidr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &'static str| InvalidCidr {
            value: s.to_owned(),
            reason,
        };
        let (addr, prefix_len) = s
            .split_once('/')
            .ok_or_else(|| invalid("expected CIDR form a.b.c.d/len"))?;
        let addr: Ipv4Addr = addr.parse().map_err(|_| invalid("invalid IPv4 address"))?;
        let prefix_len: u8 = prefix_len
            .parse()
            .map_err(|_| invalid("invalid prefix length"))?;
        Self::new(addr, prefix_len)
    }
}

impl TryFrom<String> for Ipv4Cidr {
    type Error = InvalidCidr;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Ipv4Cidr> for String {
    fn from(value: Ipv4Cidr) -> Self {
        value.to_string()
    }
}

/// Organizationally-unique prefix of every SatL overlay endpoint MAC —
/// libnetwork's `02:42` (locally administered, unicast).
pub const OVERLAY_MAC_PREFIX: [u8; 2] = [0x02, 0x42];

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// The overlay MAC of an endpoint: `02:42:` followed by the four octets of
    /// its IPv4 address, exactly as libnetwork derives it.
    ///
    /// **Load-bearing for the overlay** (architecture §11.2): the VXLAN data
    /// plane runs in unicast mode with **no multicast and no flooding**, so
    /// every node must be able to program a static FDB entry and a static ARP
    /// entry for every remote endpoint *without* ever learning one. Because
    /// the MAC is a pure function of the address, the control plane only has
    /// to distribute `(task IP, node VTEP)` — the MAC is recomputed on both
    /// sides, the node side *sets* this MAC on the jail's interface, and the
    /// FDB is programmed from store state alone. Change this derivation and
    /// every FDB entry in the cluster becomes wrong: it is a wire format, not
    /// an implementation detail.
    pub const fn from_ipv4(ip: Ipv4Addr) -> Self {
        let [a, b, c, d] = ip.octets();
        Self([OVERLAY_MAC_PREFIX[0], OVERLAY_MAC_PREFIX[1], a, b, c, d])
    }

    /// Builds a MAC from raw octets.
    pub const fn from_octets(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The raw octets.
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddr {
    /// Lower-case, colon-separated — ifconfig(8)'s `ether` format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [o0, o1, o2, o3, o4, o5] = self.0;
        write!(f, "{o0:02x}:{o1:02x}:{o2:02x}:{o3:02x}:{o4:02x}:{o5:02x}")
    }
}

impl FromStr for MacAddr {
    type Err = InvalidMac;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidMac {
            value: s.to_owned(),
        };
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or_else(invalid)?;
            if part.len() != 2 {
                return Err(invalid());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
        }
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(octets))
    }
}

impl TryFrom<String> for MacAddr {
    type Error = InvalidMac;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<MacAddr> for String {
    fn from(value: MacAddr) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Ipv4Cidr {
        s.parse().expect("valid CIDR")
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().expect("valid address")
    }

    #[test]
    fn parse_display_roundtrip() {
        for text in [
            "10.100.0.0/14",
            "10.100.4.0/24",
            "10.100.4.5/24",
            "0.0.0.0/0",
        ] {
            assert_eq!(cidr(text).to_string(), text);
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "10.100.0.0",
            "10.100.0.0/33",
            "10.100.0.0/x",
            "banana/24",
            "/24",
        ] {
            assert!(bad.parse::<Ipv4Cidr>().is_err(), "{bad} should be rejected");
        }
        let err = "10.0.0.0/33".parse::<Ipv4Cidr>().expect_err("bad prefix");
        assert!(err.to_string().contains("10.0.0.0/33"), "{err}");
    }

    #[test]
    fn network_broadcast_and_host_bits() {
        let subnet = cidr("10.100.4.0/24");
        assert!(subnet.is_network_address());
        assert_eq!(subnet.network(), ip("10.100.4.0"));
        assert_eq!(subnet.broadcast(), ip("10.100.4.255"));
        assert_eq!(subnet.gateway(), Some(ip("10.100.4.1")));
        assert_eq!(subnet.size(), 256);

        let address = cidr("10.100.4.5/24");
        assert!(!address.is_network_address());
        assert_eq!(address.network(), ip("10.100.4.0"));
        assert_eq!(address.network_cidr(), subnet);
        assert_eq!(address.broadcast(), ip("10.100.4.255"));
    }

    #[test]
    fn edge_prefix_lengths() {
        let whole = cidr("0.0.0.0/0");
        assert_eq!(whole.mask(), 0);
        assert_eq!(whole.size(), 1 << 32);
        assert_eq!(whole.broadcast(), ip("255.255.255.255"));
        assert!(whole.contains(ip("8.8.8.8")));

        let single = cidr("10.0.0.7/32");
        assert_eq!(single.mask(), u32::MAX);
        assert_eq!(single.size(), 1);
        assert_eq!(single.network(), ip("10.0.0.7"));
        assert_eq!(single.broadcast(), ip("10.0.0.7"));
        assert_eq!(single.gateway(), None, "no room for a gateway");
        assert_eq!(cidr("10.0.0.0/31").gateway(), None);
        assert_eq!(cidr("10.0.0.0/30").gateway(), Some(ip("10.0.0.1")));
    }

    #[test]
    fn containment() {
        let pool = cidr("10.100.0.0/14");
        assert!(pool.contains(ip("10.100.0.0")));
        assert!(pool.contains(ip("10.103.255.255")));
        assert!(!pool.contains(ip("10.104.0.0")));
        assert!(!pool.contains(ip("10.99.255.255")));

        assert!(pool.contains_subnet(cidr("10.100.4.0/24")));
        assert!(pool.contains_subnet(cidr("10.103.255.0/24")));
        assert!(pool.contains_subnet(pool));
        assert!(!pool.contains_subnet(cidr("10.104.0.0/24")));
        assert!(
            !cidr("10.100.4.0/24").contains_subnet(pool),
            "a /24 does not contain its /14"
        );
    }

    #[test]
    fn host_addresses_stay_inside_the_subnet() {
        let subnet = cidr("10.100.4.0/24");
        assert_eq!(subnet.host(0), Some(ip("10.100.4.0")));
        assert_eq!(subnet.host(1), Some(ip("10.100.4.1")));
        assert_eq!(subnet.host(255), Some(ip("10.100.4.255")));
        assert_eq!(subnet.host(256), None);
        // Host bits in the value do not shift the numbering.
        assert_eq!(cidr("10.100.4.9/24").host(2), Some(ip("10.100.4.2")));
        assert_eq!(cidr("255.255.255.255/32").host(1), None, "no overflow");
    }

    #[test]
    fn carving_a_pool_into_subnets() {
        let pool = cidr("10.100.0.0/14");
        let carved: Vec<Ipv4Cidr> = pool.subnets(24).collect();
        assert_eq!(carved.len(), 1024, "a /14 holds 1024 /24s");
        assert_eq!(carved[0], cidr("10.100.0.0/24"));
        assert_eq!(carved[1], cidr("10.100.1.0/24"));
        assert_eq!(carved[256], cidr("10.101.0.0/24"));
        assert_eq!(carved[1023], cidr("10.103.255.0/24"));
        assert!(carved.iter().all(|s| pool.contains_subnet(*s)));

        // Same length: exactly itself. Shorter: nothing.
        assert_eq!(pool.subnets(14).collect::<Vec<_>>(), vec![pool]);
        assert_eq!(pool.subnets(13).count(), 0);
        assert_eq!(pool.subnets(33).count(), 0);
        // Host bits in the pool do not offset the carving.
        assert_eq!(
            cidr("10.100.7.9/14").subnets(24).next(),
            Some(cidr("10.100.0.0/24"))
        );
        // The whole space, at the coarsest useful granularity.
        assert_eq!(cidr("0.0.0.0/0").subnets(8).count(), 256);
        assert_eq!(
            cidr("0.0.0.0/0").subnets(8).last(),
            Some(cidr("255.0.0.0/8"))
        );
        // size_hint feeds Vec::with_capacity; keep it exact.
        assert_eq!(pool.subnets(24).size_hint(), (1024, Some(1024)));
    }

    #[test]
    fn serde_uses_the_display_string() {
        let subnet = cidr("10.100.4.0/24");
        assert_eq!(
            serde_json::to_string(&subnet).expect("serialize"),
            "\"10.100.4.0/24\""
        );
        let back: Ipv4Cidr = serde_json::from_str("\"10.100.4.0/24\"").expect("deserialize");
        assert_eq!(back, subnet);
        assert!(serde_json::from_str::<Ipv4Cidr>("\"10.100.4.0/99\"").is_err());
    }

    // ---- MAC ---------------------------------------------------------------

    #[test]
    fn overlay_mac_is_02_42_plus_the_address() {
        assert_eq!(
            MacAddr::from_ipv4(ip("10.100.4.5")).octets(),
            [0x02, 0x42, 10, 100, 4, 5]
        );
        assert_eq!(
            MacAddr::from_ipv4(ip("10.100.4.5")).to_string(),
            "02:42:0a:64:04:05"
        );
        // Every octet is carried through, including the extremes.
        assert_eq!(
            MacAddr::from_ipv4(ip("255.255.255.255")).to_string(),
            "02:42:ff:ff:ff:ff"
        );
        assert_eq!(
            MacAddr::from_ipv4(ip("0.0.0.0")).to_string(),
            "02:42:00:00:00:00"
        );
    }

    #[test]
    fn overlay_macs_are_locally_administered_unicast_and_collision_free_per_address() {
        let mac = MacAddr::from_ipv4(ip("10.100.4.5"));
        let first = mac.octets()[0];
        assert_eq!(first & 0b10, 0b10, "locally administered bit set");
        assert_eq!(first & 0b1, 0, "unicast (not a group address)");

        // Distinct addresses must never share a MAC: that is what lets the
        // FDB be programmed without learning.
        let a = MacAddr::from_ipv4(ip("10.100.4.5"));
        let b = MacAddr::from_ipv4(ip("10.100.5.4"));
        assert_ne!(a, b);
        assert_eq!(OVERLAY_MAC_PREFIX, [0x02, 0x42]);
    }

    #[test]
    fn mac_parse_roundtrip_and_rejections() {
        let mac = MacAddr::from_ipv4(ip("10.100.4.5"));
        assert_eq!("02:42:0a:64:04:05".parse::<MacAddr>(), Ok(mac));
        assert_eq!("02:42:0A:64:04:05".parse::<MacAddr>(), Ok(mac));
        for bad in [
            "02:42:0a:64:04",
            "02:42:0a:64:04:05:06",
            "02-42-0a-64-04-05",
            "02:42:0a:64:04:zz",
            "2:42:0a:64:04:05",
            "",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad} should be rejected");
        }
        assert_eq!(
            serde_json::to_string(&mac).expect("serialize"),
            "\"02:42:0a:64:04:05\""
        );
    }
}
