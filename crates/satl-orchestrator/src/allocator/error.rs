// SPDX-License-Identifier: BSD-2-Clause
//! Why an allocation could not be made.
//!
//! Every variant names the object that wanted the resource **and** the
//! resource involved — a pool, a subnet, a VNI, a port — because these
//! messages are what an operator sees when `satl network create` leaves a
//! network unallocated or a task stuck in `NEW`. "Allocation failed" without
//! the network name and the pool is not an actionable error.
//!
//! None of these are fatal. The allocator logs them, defers the object, and
//! retries on the next deallocation or after
//! [`ALLOCATOR_RETRY`](satl_core::defaults::ALLOCATOR_RETRY) (SWK §9.3).

use satl_core::{Id, InvalidCidr, PortProtocol};

/// A failed allocation, ready to be logged against its object.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AllocError {
    /// The cluster's address pool configuration cannot be used at all.
    #[error(
        "cluster address pool {pool:?} is unusable: {reason}; \
         set a usable pool with `satl swarm init --default-addr-pool`"
    )]
    InvalidPool {
        /// The offending pool as configured on the cluster object.
        pool: String,
        /// Why it was rejected.
        reason: String,
    },

    /// `ClusterSpec::subnet_size` is not a prefix length subnets can be carved
    /// at.
    #[error(
        "cluster subnet size /{subnet_size} is unusable: must be between /1 and /30 \
         (a /31 or /32 has no room for a gateway and a task)"
    )]
    InvalidSubnetSize {
        /// The configured subnet size.
        subnet_size: u8,
    },

    /// No free subnet left in the pools.
    #[error(
        "no free /{subnet_size} subnet left in the cluster address pool(s) [{pools}] \
         for network '{network}' ({network_id})"
    )]
    PoolExhausted {
        /// Name of the network that could not be allocated.
        network: String,
        /// Its ID.
        network_id: Id,
        /// The pools that were searched, comma-separated.
        pools: String,
        /// The prefix length being carved.
        subnet_size: u8,
    },

    /// The subnet is (or overlaps) one another network already holds.
    #[error(
        "subnet {subnet} of network '{network}' ({network_id}) overlaps the subnet already \
         allocated to network {holder}"
    )]
    SubnetOverlap {
        /// Name of the network that wanted the subnet.
        network: String,
        /// Its ID.
        network_id: Id,
        /// The contended subnet.
        subnet: String,
        /// The network holding the overlapping subnet.
        holder: Id,
    },

    /// A subnet, gateway or IP range on a network spec (or already recorded on
    /// the network) is not usable.
    #[error("network '{network}' ({network_id}): {reason}")]
    InvalidNetworkAddressing {
        /// Name of the offending network.
        network: String,
        /// Its ID.
        network_id: Id,
        /// What exactly was wrong, naming the value.
        reason: String,
    },

    /// The VNI recorded on a network is held by another network.
    #[error("VNI {vni} of network '{network}' ({network_id}) is already held by network {holder}")]
    VniOverlap {
        /// Name of the network that wanted the VNI.
        network: String,
        /// Its ID.
        network_id: Id,
        /// The contended VNI.
        vni: u32,
        /// The network holding it.
        holder: Id,
    },

    /// Every VNI in the allocation range is in use.
    #[error("no free VXLAN VNI left in {start}..={end} for network '{network}' ({network_id})")]
    VniExhausted {
        /// Name of the network that could not be allocated.
        network: String,
        /// Its ID.
        network_id: Id,
        /// First VNI of the allocation range.
        start: u32,
        /// Last VNI of the allocation range.
        end: u32,
    },

    /// The VTEP port recorded on an encrypted network is held by another
    /// network.
    #[error(
        "VXLAN port {port} of network '{network}' ({network_id}) is already held by network {holder}"
    )]
    VxlanPortOverlap {
        /// Name of the network that wanted the port.
        network: String,
        /// Its ID.
        network_id: Id,
        /// The contended VTEP port.
        port: u16,
        /// The network holding it.
        holder: Id,
    },

    /// Every VTEP port in the encrypted-overlay pool is in use.
    #[error(
        "no free VXLAN port left in the encrypted-overlay pool {start}..={end} for \
         network '{network}' ({network_id}): remove an encrypted network or split its services"
    )]
    VxlanPortExhausted {
        /// Name of the network that could not be allocated.
        network: String,
        /// Its ID.
        network_id: Id,
        /// First port of the pool.
        start: u16,
        /// Last port of the pool.
        end: u16,
    },

    /// A second ingress network was created (SWK §9.3).
    #[error(
        "network '{network}' ({network_id}) cannot be the ingress network: network {holder} \
         already is, and a cluster has exactly one"
    )]
    SecondIngressNetwork {
        /// Name of the rejected network.
        network: String,
        /// Its ID.
        network_id: Id,
        /// The network that already holds the ingress role.
        holder: Id,
    },

    /// A task asks for a network that does not exist.
    #[error(
        "task {task} of service '{service}' attaches to network '{target}', which does not exist"
    )]
    UnknownNetwork {
        /// The task that cannot be allocated.
        task: Id,
        /// Its service's name (empty for a task without one).
        service: String,
        /// The unresolvable network name or ID from the task spec.
        target: String,
    },

    /// The network's subnet has no free address left.
    #[error(
        "subnet {subnet} of network '{network}' is full ({capacity} usable addresses): \
         no address left for task {task}"
    )]
    SubnetExhausted {
        /// Name of the network.
        network: String,
        /// Its subnet.
        subnet: String,
        /// How many addresses the subnet can hand out in total.
        capacity: u64,
        /// The task that could not be served.
        task: Id,
    },

    /// The network's subnet has no free address left for a node's gateway.
    #[error(
        "subnet {subnet} of network '{network}' is full ({capacity} usable addresses): \
         no gateway address left for node {node}, which runs tasks on it"
    )]
    NodeGatewayExhausted {
        /// Name of the network.
        network: String,
        /// Its subnet.
        subnet: String,
        /// How many addresses the subnet can hand out in total.
        capacity: u64,
        /// The node that could not be served.
        node: Id,
    },

    /// A gateway address recorded for a node on a network cannot be reclaimed —
    /// the subnet changed under it, or a task records the same address.
    ///
    /// Never healed: the address is live on that node's overlay bridge, and
    /// moving it under running jails is a silent black hole (`docs/vxlan.md`
    /// §8).
    #[error(
        "gateway address {address} recorded for node {node} on network '{network}' cannot be \
         reclaimed: {reason}"
    )]
    InvalidNodeGateway {
        /// Name of the network the gateway is on.
        network: String,
        /// The node whose gateway it is.
        node: Id,
        /// The address as recorded on the network.
        address: String,
        /// Why it could not be reclaimed.
        reason: String,
    },

    /// An address already recorded on a task cannot be reclaimed on restore —
    /// the subnet changed under it, or two tasks record the same address.
    #[error(
        "address {address} recorded for task {task} on network '{network}' cannot be \
         reclaimed: {reason}"
    )]
    InvalidTaskAddress {
        /// The task carrying the address.
        task: Id,
        /// Name of the network it is on.
        network: String,
        /// The address as recorded on the task.
        address: String,
        /// Why it could not be reclaimed.
        reason: String,
    },

    /// Another service already publishes that port.
    #[error(
        "published port {port}/{protocol} requested by service '{service}' ({service_id}) \
         is already published by service {holder}"
    )]
    PortOccupied {
        /// Name of the service that wanted the port.
        service: String,
        /// Its ID.
        service_id: Id,
        /// The contended published port.
        port: u16,
        /// Its protocol.
        protocol: PortProtocol,
        /// The service holding it.
        holder: Id,
    },

    /// One endpoint spec asks for the same published port twice.
    #[error(
        "service '{service}' ({service_id}) publishes port {port}/{protocol} twice: \
         each published port may appear once per protocol"
    )]
    PortDuplicate {
        /// Name of the offending service.
        service: String,
        /// Its ID.
        service_id: Id,
        /// The repeated published port.
        port: u16,
        /// Its protocol.
        protocol: PortProtocol,
    },

    /// The auto-assign range is full.
    #[error(
        "no free {protocol} port left in the ingress range {start}..={end} for \
         service '{service}' ({service_id})"
    )]
    PortRangeExhausted {
        /// Name of the service that could not be allocated.
        service: String,
        /// Its ID.
        service_id: Id,
        /// The protocol whose pool is full.
        protocol: PortProtocol,
        /// First port of the dynamic range.
        start: u16,
        /// Last port of the dynamic range.
        end: u16,
    },
}

impl AllocError {
    /// Builds an [`AllocError::InvalidNetworkAddressing`] from a CIDR parse
    /// failure, saying which field carried the bad value.
    pub(crate) fn bad_cidr(network: &str, network_id: &Id, field: &str, err: &InvalidCidr) -> Self {
        Self::InvalidNetworkAddressing {
            network: network.to_owned(),
            network_id: network_id.clone(),
            reason: format!("{field}: {err}"),
        }
    }
}
