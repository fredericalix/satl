// SPDX-License-Identifier: BSD-2-Clause
//! Node-local IPAM: /24 subnets carved from the local bridge pool, per-task
//! IPv4 allocation, JSON file persistence (architecture §11.1).
//!
//! Cluster-scoped (overlay) IPAM is allocator-owned and lives in Raft
//! (architecture §11.3) — this module is only for node-local bridge
//! networks, where allocations never need cluster consensus.
//!
//! Model:
//!
//! - The pool defaults to [`DEFAULT_LOCAL_BRIDGE_POOL`] (`10.88.0.0/16`,
//!   architecture §15 "Default local bridge pool"; podman's convention,
//!   avoiding the OVH underlay `10.2.0.0/16`).
//! - Every network gets the first free /24 from the pool.
//! - Within a subnet, `.0` is the network address, `.1` the gateway (the
//!   bridge address on the host), `.255` broadcast; tasks get `.2`–`.254`.
//! - Allocation is **stable**: allocating again for the same task returns
//!   the same address (agent restarts and retries must not leak).
//! - Persistence: one JSON file per network (`<dir>/<network>.json`),
//!   written atomically (temp file + rename) on every mutation and reloaded
//!   verbatim by [`LocalIpam::open`].

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Default pool for node-local bridge networks (architecture §15).
///
/// `satl-core::defaults` does not carry this constant yet; when it grows one
/// this must become a re-export.
pub const DEFAULT_LOCAL_BRIDGE_POOL: SubnetV4 = SubnetV4 {
    addr: Ipv4Addr::new(10, 88, 0, 0),
    prefix_len: 16,
};

/// Prefix length of the subnet every local network receives.
pub const NETWORK_PREFIX_LEN: u8 = 24;

/// An IPv4 subnet in CIDR form, e.g. `10.88.0.0/24`.
///
/// Serialized as its display string (`"10.88.0.0/24"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SubnetV4 {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl SubnetV4 {
    /// Construct a subnet; `addr` must be the network address (host bits
    /// zero) and `prefix_len` at most 32.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, IpamError> {
        if prefix_len > 32 {
            return Err(IpamError::InvalidSubnet {
                subnet: format!("{addr}/{prefix_len}"),
                reason: "prefix length exceeds 32".to_owned(),
            });
        }
        let candidate = Self { addr, prefix_len };
        if candidate.network() != addr {
            return Err(IpamError::InvalidSubnet {
                subnet: format!("{addr}/{prefix_len}"),
                reason: format!("host bits set (network address is {})", candidate.network()),
            });
        }
        Ok(candidate)
    }

    fn mask(self) -> u32 {
        if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix_len))
        }
    }

    /// The network address (host bits zero).
    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & self.mask())
    }

    /// The broadcast address (host bits one).
    #[must_use]
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` falls inside this subnet.
    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & self.mask()) == u32::from(self.network())
    }

    /// The `n`-th host address (network address + `n`); `None` when it
    /// would leave the subnet.
    #[must_use]
    pub fn host(self, n: u32) -> Option<Ipv4Addr> {
        let base = u32::from(self.network());
        let candidate = base.checked_add(n)?;
        let ip = Ipv4Addr::from(candidate);
        self.contains(ip).then_some(ip)
    }

    /// The gateway convention for SatL local networks: `.1`.
    #[must_use]
    pub fn gateway(self) -> Ipv4Addr {
        // Infallible for prefix lengths <= 30, which NETWORK_PREFIX_LEN
        // guarantees for every subnet LocalIpam hands out.
        self.host(1).unwrap_or(self.addr)
    }
}

impl fmt::Display for SubnetV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for SubnetV4 {
    type Err = IpamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| IpamError::InvalidSubnet {
            subnet: s.to_owned(),
            reason: reason.to_owned(),
        };
        let (addr_part, len_part) = s
            .split_once('/')
            .ok_or_else(|| invalid("expected CIDR form a.b.c.d/len"))?;
        let addr: Ipv4Addr = addr_part
            .parse()
            .map_err(|_| invalid("invalid IPv4 address"))?;
        let prefix_len: u8 = len_part
            .parse()
            .map_err(|_| invalid("invalid prefix length"))?;
        Self::new(addr, prefix_len)
    }
}

impl TryFrom<String> for SubnetV4 {
    type Error = IpamError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<SubnetV4> for String {
    fn from(value: SubnetV4) -> Self {
        value.to_string()
    }
}

/// Error from the node-local IPAM.
#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    /// A subnet string or (address, prefix) pair was malformed.
    #[error("invalid subnet '{subnet}': {reason}")]
    InvalidSubnet {
        /// The offending subnet text.
        subnet: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Network names become file names; restrict them accordingly.
    #[error(
        "invalid network name '{name}': only [a-z0-9._-] (max 64 chars, no leading dot) \
         are allowed"
    )]
    InvalidNetworkName {
        /// The offending name.
        name: String,
    },

    /// The pool has no free /24 left for a new network.
    #[error(
        "local bridge pool {pool} exhausted: all {capacity} /{prefix} subnets are in use, \
         cannot create network '{network}'"
    )]
    PoolExhausted {
        /// The pool being carved.
        pool: SubnetV4,
        /// How many subnets the pool holds.
        capacity: u32,
        /// Subnet prefix length handed to networks.
        prefix: u8,
        /// The network that could not be created.
        network: String,
    },

    /// A network's subnet has no free host address left.
    #[error(
        "subnet {subnet} of network '{network}' exhausted: all {capacity} host addresses \
         are allocated, cannot allocate for task {task_id}"
    )]
    SubnetExhausted {
        /// The exhausted subnet.
        subnet: SubnetV4,
        /// The network it belongs to.
        network: String,
        /// Usable host addresses in the subnet (`.2`–`.254` for a /24).
        capacity: u32,
        /// The task that could not be served.
        task_id: String,
    },

    /// A persisted state file failed to load or validate.
    #[error("corrupt IPAM state file {file}: {reason}")]
    Corrupt {
        /// Path of the offending file.
        file: PathBuf,
        /// Why it was rejected.
        reason: String,
    },

    /// Filesystem I/O failed.
    #[error("IPAM I/O on {path}: {source}")]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Persisted (and in-memory) state of one network. The JSON on disk is this
/// struct verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkState {
    /// Network name (must match the file stem).
    name: String,
    /// The /24 this network owns.
    subnet: SubnetV4,
    /// task id → allocated address.
    allocations: BTreeMap<String, Ipv4Addr>,
}

/// Node-local IPAM: pure logic plus JSON file persistence.
///
/// Not thread-safe by itself — callers (the [`crate::manager::NetworkManager`])
/// wrap it in a mutex.
#[derive(Debug)]
pub struct LocalIpam {
    dir: PathBuf,
    pool: SubnetV4,
    networks: BTreeMap<String, NetworkState>,
}

fn valid_network_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

impl LocalIpam {
    /// Open (or initialize) the IPAM state directory with the default pool
    /// [`DEFAULT_LOCAL_BRIDGE_POOL`].
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, IpamError> {
        Self::open_with_pool(dir, DEFAULT_LOCAL_BRIDGE_POOL)
    }

    /// Open (or initialize) the IPAM state directory, carving networks out
    /// of `pool`. Existing `<network>.json` files are loaded and validated.
    pub fn open_with_pool(dir: impl Into<PathBuf>, pool: SubnetV4) -> Result<Self, IpamError> {
        let dir = dir.into();
        if pool.prefix_len() > NETWORK_PREFIX_LEN {
            return Err(IpamError::InvalidSubnet {
                subnet: pool.to_string(),
                reason: format!(
                    "pool prefix must be <= /{NETWORK_PREFIX_LEN} to carve /{NETWORK_PREFIX_LEN} networks"
                ),
            });
        }
        std::fs::create_dir_all(&dir).map_err(|source| IpamError::Io {
            path: dir.clone(),
            source,
        })?;
        let mut networks = BTreeMap::new();
        let entries = std::fs::read_dir(&dir).map_err(|source| IpamError::Io {
            path: dir.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| IpamError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let state = Self::load_network_file(&path, pool)?;
            networks.insert(state.name.clone(), state);
        }
        // Cross-network validation: no two networks may own the same subnet.
        let mut seen: BTreeMap<Ipv4Addr, &str> = BTreeMap::new();
        for state in networks.values() {
            if let Some(other) = seen.insert(state.subnet.network(), &state.name) {
                return Err(IpamError::Corrupt {
                    file: dir.join(format!("{}.json", state.name)),
                    reason: format!(
                        "subnet {} is owned by both '{}' and '{}'",
                        state.subnet, other, state.name
                    ),
                });
            }
        }
        Ok(Self {
            dir,
            pool,
            networks,
        })
    }

    fn load_network_file(path: &Path, pool: SubnetV4) -> Result<NetworkState, IpamError> {
        let corrupt = |reason: String| IpamError::Corrupt {
            file: path.to_path_buf(),
            reason,
        };
        let bytes = std::fs::read(path).map_err(|source| IpamError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let state: NetworkState =
            serde_json::from_slice(&bytes).map_err(|e| corrupt(format!("invalid JSON: {e}")))?;
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if state.name != stem {
            return Err(corrupt(format!(
                "network name '{}' does not match file stem '{stem}'",
                state.name
            )));
        }
        if !valid_network_name(&state.name) {
            return Err(corrupt(format!("invalid network name '{}'", state.name)));
        }
        if state.subnet.prefix_len() != NETWORK_PREFIX_LEN {
            return Err(corrupt(format!(
                "subnet {} is not a /{NETWORK_PREFIX_LEN}",
                state.subnet
            )));
        }
        if !pool.contains(state.subnet.network()) {
            return Err(corrupt(format!(
                "subnet {} is outside the pool {pool}",
                state.subnet
            )));
        }
        let mut used: BTreeMap<Ipv4Addr, &str> = BTreeMap::new();
        for (task, ip) in &state.allocations {
            if !state.subnet.contains(*ip) {
                return Err(corrupt(format!(
                    "allocation {ip} for task {task} is outside subnet {}",
                    state.subnet
                )));
            }
            let reserved = [
                state.subnet.network(),
                state.subnet.gateway(),
                state.subnet.broadcast(),
            ];
            if reserved.contains(ip) {
                return Err(corrupt(format!(
                    "allocation {ip} for task {task} is a reserved address"
                )));
            }
            if let Some(other) = used.insert(*ip, task) {
                return Err(corrupt(format!(
                    "address {ip} allocated to both task {other} and task {task}"
                )));
            }
        }
        Ok(state)
    }

    /// Atomic write: serialize to `<file>.tmp`, fsync, rename over the
    /// final name.
    fn persist(&self, network: &str) -> Result<(), IpamError> {
        // Presence is guaranteed by the callers, which mutate the entry
        // first; treat absence as a no-op rather than panicking.
        let Some(state) = self.networks.get(network) else {
            return Ok(());
        };
        let final_path = self.dir.join(format!("{network}.json"));
        let tmp_path = self.dir.join(format!("{network}.json.tmp"));
        let io_err = |path: &Path| {
            let path = path.to_path_buf();
            move |source: std::io::Error| IpamError::Io {
                path: path.clone(),
                source,
            }
        };
        let payload = serde_json::to_vec_pretty(state).map_err(|e| IpamError::Corrupt {
            file: final_path.clone(),
            reason: format!("serialization failed: {e}"),
        })?;
        let mut file = std::fs::File::create(&tmp_path).map_err(io_err(&tmp_path))?;
        file.write_all(&payload).map_err(io_err(&tmp_path))?;
        file.sync_all().map_err(io_err(&tmp_path))?;
        drop(file);
        std::fs::rename(&tmp_path, &final_path).map_err(io_err(&final_path))?;
        Ok(())
    }

    /// Ensure `network` exists, carving the first free /24 from the pool if
    /// needed; returns its subnet.
    pub fn ensure_network(&mut self, network: &str) -> Result<SubnetV4, IpamError> {
        if !valid_network_name(network) {
            return Err(IpamError::InvalidNetworkName {
                name: network.to_owned(),
            });
        }
        if let Some(state) = self.networks.get(network) {
            return Ok(state.subnet);
        }
        let shift = NETWORK_PREFIX_LEN - self.pool.prefix_len();
        // Capacity fits u32: shift <= 24.
        let capacity: u32 = 1 << shift;
        let used: Vec<Ipv4Addr> = self.networks.values().map(|s| s.subnet.network()).collect();
        let base = u32::from(self.pool.network());
        let step: u32 = 1 << (32 - u32::from(NETWORK_PREFIX_LEN));
        let subnet = (0..capacity)
            .map(|i| Ipv4Addr::from(base + i * step))
            .find(|candidate| !used.contains(candidate))
            .ok_or_else(|| IpamError::PoolExhausted {
                pool: self.pool,
                capacity,
                prefix: NETWORK_PREFIX_LEN,
                network: network.to_owned(),
            })?;
        // Infallible: candidate network addresses are aligned by construction.
        let subnet = SubnetV4::new(subnet, NETWORK_PREFIX_LEN)?;
        self.networks.insert(
            network.to_owned(),
            NetworkState {
                name: network.to_owned(),
                subnet,
                allocations: BTreeMap::new(),
            },
        );
        self.persist(network)?;
        tracing::info!(network = %network, subnet = %subnet, "created local network");
        Ok(subnet)
    }

    /// Allocate an address for `task_id` on `network` (creating the network
    /// if needed). Stable: a task that already holds an address gets the
    /// same one back.
    pub fn allocate(&mut self, network: &str, task_id: &str) -> Result<Ipv4Addr, IpamError> {
        let subnet = self.ensure_network(network)?;
        // Infallible: ensure_network just inserted or found it.
        let Some(state) = self.networks.get_mut(network) else {
            return Err(IpamError::InvalidNetworkName {
                name: network.to_owned(),
            });
        };
        if let Some(existing) = state.allocations.get(task_id) {
            return Ok(*existing);
        }
        let used: Vec<Ipv4Addr> = state.allocations.values().copied().collect();
        // Hosts .2 ..= .254 for a /24 (.0 network, .1 gateway, .255 broadcast).
        let last_host = u32::from(subnet.broadcast()) - u32::from(subnet.network()) - 1;
        let capacity = last_host - 1; // minus the gateway
        let ip = (2..=last_host)
            .filter_map(|n| subnet.host(n))
            .find(|candidate| !used.contains(candidate))
            .ok_or_else(|| IpamError::SubnetExhausted {
                subnet,
                network: network.to_owned(),
                capacity,
                task_id: task_id.to_owned(),
            })?;
        state.allocations.insert(task_id.to_owned(), ip);
        self.persist(network)?;
        tracing::info!(network = %network, task_id = %task_id, ip = %ip, "allocated task address");
        Ok(ip)
    }

    /// Release every address held by `task_id` (across all networks);
    /// returns the released `(network, address)` pairs. Idempotent.
    pub fn release(&mut self, task_id: &str) -> Result<Vec<(String, Ipv4Addr)>, IpamError> {
        let mut released = Vec::new();
        let names: Vec<String> = self.networks.keys().cloned().collect();
        for name in names {
            let removed = self
                .networks
                .get_mut(&name)
                .and_then(|state| state.allocations.remove(task_id));
            if let Some(ip) = removed {
                self.persist(&name)?;
                tracing::info!(network = %name, task_id = %task_id, ip = %ip, "released task address");
                released.push((name, ip));
            }
        }
        Ok(released)
    }

    /// The gateway address (`.1`) of `network`, if the network exists.
    #[must_use]
    pub fn gateway(&self, network: &str) -> Option<Ipv4Addr> {
        self.networks.get(network).map(|s| s.subnet.gateway())
    }

    /// The subnet of `network`, if the network exists.
    #[must_use]
    pub fn subnet(&self, network: &str) -> Option<SubnetV4> {
        self.networks.get(network).map(|s| s.subnet)
    }

    /// The address held by `task_id` on `network`, if any.
    #[must_use]
    pub fn address_of(&self, network: &str, task_id: &str) -> Option<Ipv4Addr> {
        self.networks
            .get(network)
            .and_then(|s| s.allocations.get(task_id))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn subnet(s: &str) -> SubnetV4 {
        s.parse().unwrap()
    }

    // ---- SubnetV4 -----------------------------------------------------------

    #[test]
    fn subnet_parse_display_roundtrip() {
        let s = subnet("10.88.4.0/24");
        assert_eq!(s.to_string(), "10.88.4.0/24");
        assert_eq!(s.network(), ip("10.88.4.0"));
        assert_eq!(s.gateway(), ip("10.88.4.1"));
        assert_eq!(s.broadcast(), ip("10.88.4.255"));
        assert_eq!(s.prefix_len(), 24);
    }

    #[test]
    fn subnet_rejects_garbage() {
        assert!("10.88.0.0".parse::<SubnetV4>().is_err());
        assert!("10.88.0.0/33".parse::<SubnetV4>().is_err());
        assert!("10.88.0.0/abc".parse::<SubnetV4>().is_err());
        assert!("banana/24".parse::<SubnetV4>().is_err());
        // Host bits set.
        assert!("10.88.0.1/24".parse::<SubnetV4>().is_err());
    }

    #[test]
    fn subnet_contains_and_host() {
        let s = subnet("10.88.0.0/24");
        assert!(s.contains(ip("10.88.0.1")));
        assert!(s.contains(ip("10.88.0.254")));
        assert!(!s.contains(ip("10.88.1.1")));
        assert_eq!(s.host(2), Some(ip("10.88.0.2")));
        assert_eq!(s.host(255), Some(ip("10.88.0.255")));
        assert_eq!(s.host(256), None);
    }

    #[test]
    fn subnet_serde_as_string() {
        let s = subnet("10.88.7.0/24");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"10.88.7.0/24\"");
        let back: SubnetV4 = serde_json::from_str("\"10.88.7.0/24\"").unwrap();
        assert_eq!(back, s);
        assert!(serde_json::from_str::<SubnetV4>("\"10.88.7.9/24\"").is_err());
    }

    #[test]
    fn default_pool_matches_architecture_table() {
        assert_eq!(DEFAULT_LOCAL_BRIDGE_POOL.to_string(), "10.88.0.0/16");
    }

    // ---- allocation ---------------------------------------------------------

    #[test]
    fn networks_get_sequential_free_slash24s() {
        let dir = tempfile::tempdir().unwrap();
        let mut ipam = LocalIpam::open(dir.path()).unwrap();
        assert_eq!(ipam.ensure_network("satl").unwrap(), subnet("10.88.0.0/24"));
        assert_eq!(ipam.ensure_network("web").unwrap(), subnet("10.88.1.0/24"));
        // Idempotent.
        assert_eq!(ipam.ensure_network("satl").unwrap(), subnet("10.88.0.0/24"));
        assert_eq!(ipam.gateway("satl"), Some(ip("10.88.0.1")));
        assert_eq!(ipam.subnet("web"), Some(subnet("10.88.1.0/24")));
        assert_eq!(ipam.gateway("missing"), None);
    }

    #[test]
    fn allocation_starts_at_dot2_and_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let mut ipam = LocalIpam::open(dir.path()).unwrap();
        let first = ipam.allocate("satl", "task-a").unwrap();
        assert_eq!(first, ip("10.88.0.2"));
        let second = ipam.allocate("satl", "task-b").unwrap();
        assert_eq!(second, ip("10.88.0.3"));
        // Stable re-allocation.
        assert_eq!(ipam.allocate("satl", "task-a").unwrap(), first);
        assert_eq!(ipam.address_of("satl", "task-a"), Some(first));
    }

    #[test]
    fn release_frees_the_address_for_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let mut ipam = LocalIpam::open(dir.path()).unwrap();
        let a = ipam.allocate("satl", "task-a").unwrap();
        let _b = ipam.allocate("satl", "task-b").unwrap();
        let released = ipam.release("task-a").unwrap();
        assert_eq!(released, vec![("satl".to_owned(), a)]);
        // Idempotent release.
        assert!(ipam.release("task-a").unwrap().is_empty());
        // Freed address is handed out again (first-free scan).
        assert_eq!(ipam.allocate("satl", "task-c").unwrap(), a);
    }

    #[test]
    fn subnet_exhaustion_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut ipam = LocalIpam::open(dir.path()).unwrap();
        // .2 ..= .254 → 253 usable addresses.
        for i in 0..253 {
            ipam.allocate("satl", &format!("task-{i}")).unwrap();
        }
        let err = ipam.allocate("satl", "task-overflow").unwrap_err();
        match &err {
            IpamError::SubnetExhausted {
                subnet: s,
                network,
                capacity,
                task_id,
            } => {
                assert_eq!(*s, subnet("10.88.0.0/24"));
                assert_eq!(network, "satl");
                assert_eq!(*capacity, 253);
                assert_eq!(task_id, "task-overflow");
            }
            other => panic!("expected SubnetExhausted, got {other:?}"),
        }
        let text = err.to_string();
        assert!(text.contains("10.88.0.0/24"), "{text}");
        assert!(text.contains("task-overflow"), "{text}");
    }

    #[test]
    fn pool_exhaustion_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        // A /23 pool only holds two /24 networks.
        let mut ipam = LocalIpam::open_with_pool(dir.path(), subnet("10.99.0.0/23")).unwrap();
        ipam.ensure_network("one").unwrap();
        ipam.ensure_network("two").unwrap();
        let err = ipam.ensure_network("three").unwrap_err();
        match &err {
            IpamError::PoolExhausted {
                pool,
                capacity,
                network,
                ..
            } => {
                assert_eq!(*pool, subnet("10.99.0.0/23"));
                assert_eq!(*capacity, 2);
                assert_eq!(network, "three");
            }
            other => panic!("expected PoolExhausted, got {other:?}"),
        }
    }

    #[test]
    fn reload_from_disk_preserves_allocations() {
        let dir = tempfile::tempdir().unwrap();
        let a;
        let b;
        {
            let mut ipam = LocalIpam::open(dir.path()).unwrap();
            a = ipam.allocate("satl", "task-a").unwrap();
            b = ipam.allocate("web", "task-b").unwrap();
            ipam.release("task-b").unwrap();
        }
        let mut reloaded = LocalIpam::open(dir.path()).unwrap();
        assert_eq!(reloaded.subnet("satl"), Some(subnet("10.88.0.0/24")));
        assert_eq!(reloaded.subnet("web"), Some(subnet("10.88.1.0/24")));
        assert_eq!(reloaded.address_of("satl", "task-a"), Some(a));
        assert_eq!(reloaded.address_of("web", "task-b"), None);
        // Stable across reload too.
        assert_eq!(reloaded.allocate("satl", "task-a").unwrap(), a);
        // Released address is free again after reload.
        assert_eq!(reloaded.allocate("web", "task-c").unwrap(), b);
        // No temp files left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn corrupt_files_are_rejected_with_reason() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.json"), b"{ not json").unwrap();
        let err = LocalIpam::open(dir.path()).unwrap_err();
        match &err {
            IpamError::Corrupt { file, reason } => {
                assert!(file.ends_with("bad.json"), "{}", file.display());
                assert!(reason.contains("invalid JSON"), "{reason}");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_name_and_out_of_pool_subnets_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("satl.json"),
            br#"{"name":"other","subnet":"10.88.0.0/24","allocations":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            LocalIpam::open(dir.path()).unwrap_err(),
            IpamError::Corrupt { .. }
        ));

        std::fs::write(
            dir.path().join("satl.json"),
            br#"{"name":"satl","subnet":"192.168.0.0/24","allocations":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            LocalIpam::open(dir.path()).unwrap_err(),
            IpamError::Corrupt { .. }
        ));

        // Allocation on the gateway address.
        std::fs::write(
            dir.path().join("satl.json"),
            br#"{"name":"satl","subnet":"10.88.0.0/24","allocations":{"t":"10.88.0.1"}}"#,
        )
        .unwrap();
        assert!(matches!(
            LocalIpam::open(dir.path()).unwrap_err(),
            IpamError::Corrupt { .. }
        ));
    }

    #[test]
    fn duplicate_subnet_ownership_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("one.json"),
            br#"{"name":"one","subnet":"10.88.0.0/24","allocations":{}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("two.json"),
            br#"{"name":"two","subnet":"10.88.0.0/24","allocations":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            LocalIpam::open(dir.path()).unwrap_err(),
            IpamError::Corrupt { .. }
        ));
    }

    #[test]
    fn network_names_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let mut ipam = LocalIpam::open(dir.path()).unwrap();
        for bad in ["", "UPPER", "has space", "../escape", ".hidden", "a/b"] {
            assert!(
                matches!(
                    ipam.ensure_network(bad),
                    Err(IpamError::InvalidNetworkName { .. })
                ),
                "{bad:?} should be rejected"
            );
        }
        ipam.ensure_network("ok-name_0.9").unwrap();
    }
}
