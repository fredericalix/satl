// SPDX-License-Identifier: BSD-2-Clause
//! Shared domain types for SatL: store objects, task state machine, IDs,
//! naming rules, defaults, and error types. See `docs/architecture.md` §3–§4
//! (data model, task model) and §15 (constants); field semantics follow the
//! SwarmKit behavioral spec (SWK §3–§4) with the FreeBSD adaptations noted
//! per type.
//!
//! This crate is dependency-light by design (no async, no I/O): it is the
//! root of the workspace dependency graph (architecture §2).

pub mod constraint;
pub mod defaults;
pub mod error;
pub mod health;
pub mod id;
pub mod meta;
pub mod naming;
pub mod net;
pub mod objects;
pub mod state;
pub mod store;

pub use constraint::{Constraint, Constraints};
pub use error::{
    InvalidCidr, InvalidConstraint, InvalidId, InvalidMac, InvalidName, InvalidTransition,
    ValidationError,
};
pub use health::{AppliedProbeDefaults, PublishedProbe, detection_bound, harden_published_probe};
pub use id::Id;
pub use meta::{Meta, Version};
pub use net::{Ipv4Cidr, MacAddr};
pub use objects::{
    Annotations, Availability, CaConfig, CertificateStatus, Cluster, ClusterSpec, Config,
    ConfigReference, ConfigSpec, ContainerSpec, DispatcherConfig, DnsConfig, Endpoint,
    EndpointMode, EndpointSpec, EngineDescription, FailureAction, FileTarget, HealthConfig,
    IpamConfig, JoinTokens, ManagerStatus, Mount, MountType, Network, NetworkAttachment,
    NetworkAttachmentConfig, NetworkDriver, NetworkKey, NetworkSpec, Node, NodeDescription,
    NodeRole, NodeSpec, NodeState, NodeStatus, Placement, PlacementPreference, Platform,
    PortConfig, PortProtocol, PublishMode, PullOptions, RaftConfig, Reachability,
    ResourceRequirements, Resources, RestartCondition, RestartPolicy, RootRotation, Secret,
    SecretReference, SecretSpec, Service, ServiceMode, ServiceSpec, SpreadPreference, Task,
    TaskDefaults, TaskSpec, UpdateConfig, UpdateOrder, UpdateStateKind, UpdateStatus,
};
pub use state::{ContainerStatus, DesiredState, PortStatus, TaskState, TaskStatus};
pub use store::{ObjectKind, StoreAction, StoreEvent, StoreObject};
