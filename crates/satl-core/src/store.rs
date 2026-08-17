// SPDX-License-Identifier: BSD-2-Clause
//! Shared store-transaction types (architecture §6.1).
//!
//! A store write is a list of [`StoreAction`]s — one Raft proposal is one
//! atomic transaction, bounded by [`crate::defaults::MAX_TX_ACTIONS`] and
//! [`crate::defaults::MAX_TX_BYTES`]. After apply, per-object [`StoreEvent`]s
//! plus a final `Commit(version)` marker are published on the watch feed.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::id::Id;
use crate::meta::Version;
use crate::objects::{Cluster, Config, Network, Node, Secret, Service, Task};

/// The seven store object kinds (architecture §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// The singleton [`Cluster`] object.
    Cluster,
    /// A [`Node`].
    Node,
    /// A [`Service`].
    Service,
    /// A [`Task`].
    Task,
    /// A [`Network`].
    Network,
    /// A [`Secret`].
    Secret,
    /// A [`Config`].
    Config,
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Cluster => "cluster",
            Self::Node => "node",
            Self::Service => "service",
            Self::Task => "task",
            Self::Network => "network",
            Self::Secret => "secret",
            Self::Config => "config",
        };
        f.write_str(name)
    }
}

/// One store object of any kind.
// Variant sizes deliberately span the seven store objects; these are
// short-lived transport values that the store Arc-wraps on insert
// (architecture §6.1), so boxing every construction/match site isn't worth it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreObject {
    /// A [`Cluster`].
    Cluster(Cluster),
    /// A [`Node`].
    Node(Node),
    /// A [`Service`].
    Service(Service),
    /// A [`Task`].
    Task(Task),
    /// A [`Network`].
    Network(Network),
    /// A [`Secret`].
    Secret(Secret),
    /// A [`Config`].
    Config(Config),
}

impl StoreObject {
    /// The kind of the wrapped object.
    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        match self {
            Self::Cluster(_) => ObjectKind::Cluster,
            Self::Node(_) => ObjectKind::Node,
            Self::Service(_) => ObjectKind::Service,
            Self::Task(_) => ObjectKind::Task,
            Self::Network(_) => ObjectKind::Network,
            Self::Secret(_) => ObjectKind::Secret,
            Self::Config(_) => ObjectKind::Config,
        }
    }

    /// The wrapped object's ID.
    #[must_use]
    pub fn id(&self) -> &Id {
        match self {
            Self::Cluster(o) => &o.id,
            Self::Node(o) => &o.id,
            Self::Service(o) => &o.id,
            Self::Task(o) => &o.id,
            Self::Network(o) => &o.id,
            Self::Secret(o) => &o.id,
            Self::Config(o) => &o.id,
        }
    }
}

/// One mutation within a store transaction (architecture §6.1).
// See the size-spread note on `StoreObject`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreAction {
    /// Insert a new object; fails if the ID exists.
    Create(StoreObject),
    /// Replace an existing object; subject to optimistic concurrency on
    /// `meta.version` (architecture §3).
    Update(StoreObject),
    /// Delete an object by kind and ID.
    Remove {
        /// Kind of the object to remove.
        kind: ObjectKind,
        /// ID of the object to remove.
        id: Id,
    },
}

/// One entry on the watch feed, published after a transaction applies
/// (architecture §6.1).
// See the size-spread note on `StoreObject`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreEvent {
    /// An object was created.
    Created(StoreObject),
    /// An object was replaced. `old` is `None` when the previous value is
    /// unavailable (e.g. replay after snapshot install).
    Updated {
        /// The previous value, when known.
        old: Option<StoreObject>,
        /// The new value.
        new: StoreObject,
    },
    /// An object was removed.
    Removed {
        /// Kind of the removed object.
        kind: ObjectKind,
        /// ID of the removed object.
        id: Id,
    },
    /// End-of-transaction marker carrying the applied Raft log index.
    Commit(Version),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::meta::Meta;
    use crate::objects::{Annotations, IpamConfig, NetworkDriver, NetworkSpec, SecretSpec};

    use super::*;

    fn sample_network() -> Network {
        Network {
            id: Id::generate(),
            meta: Meta::new(),
            spec: NetworkSpec {
                annotations: Annotations {
                    name: "backend".to_owned(),
                    labels: BTreeMap::new(),
                },
                driver: NetworkDriver::Bridge,
                ipam: Some(IpamConfig::default()),
                internal: false,
                attachable: false,
                ingress: false,
                encrypted: false,
            },
            vni: None,
            vxlan_port: None,
            subnet: None,
            node_gateways: BTreeMap::new(),
            keys: Vec::new(),
            keys_updated_at: None,
        }
    }

    fn sample_secret() -> Secret {
        Secret {
            id: Id::generate(),
            meta: Meta::new(),
            spec: SecretSpec::new(
                Annotations {
                    name: "db.password".to_owned(),
                    labels: BTreeMap::new(),
                },
                vec![42],
            )
            .unwrap(),
        }
    }

    #[test]
    fn kind_and_id_accessors() {
        let network = sample_network();
        let network_id = network.id.clone();
        let object = StoreObject::Network(network);
        assert_eq!(object.kind(), ObjectKind::Network);
        assert_eq!(object.id(), &network_id);

        let secret = sample_secret();
        let secret_id = secret.id.clone();
        let object = StoreObject::Secret(secret);
        assert_eq!(object.kind(), ObjectKind::Secret);
        assert_eq!(object.id(), &secret_id);
    }

    #[test]
    fn object_kind_display_matches_serde() {
        let kinds = [
            ObjectKind::Cluster,
            ObjectKind::Node,
            ObjectKind::Service,
            ObjectKind::Task,
            ObjectKind::Network,
            ObjectKind::Secret,
            ObjectKind::Config,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{kind}\""));
        }
    }

    #[test]
    fn store_action_serde_roundtrip() {
        let actions = vec![
            StoreAction::Create(StoreObject::Network(sample_network())),
            StoreAction::Update(StoreObject::Secret(sample_secret())),
            StoreAction::Remove {
                kind: ObjectKind::Task,
                id: Id::generate(),
            },
        ];
        let json = serde_json::to_string(&actions).unwrap();
        let back: Vec<StoreAction> = serde_json::from_str(&json).unwrap();
        assert_eq!(actions, back);
    }

    #[test]
    fn store_event_serde_roundtrip() {
        let network = sample_network();
        let mut updated = network.clone();
        updated.vni = Some(4097);
        let events = vec![
            StoreEvent::Created(StoreObject::Network(network.clone())),
            StoreEvent::Updated {
                old: Some(StoreObject::Network(network)),
                new: StoreObject::Network(updated),
            },
            StoreEvent::Removed {
                kind: ObjectKind::Network,
                id: Id::generate(),
            },
            StoreEvent::Commit(Version(99)),
        ];
        let json = serde_json::to_string(&events).unwrap();
        let back: Vec<StoreEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(events, back);
    }
}
