// SPDX-License-Identifier: BSD-2-Clause
//! Wire encoding: `satl-core` objects ↔ `satl.internal.v1` envelopes.
//!
//! The rule pinned in `proto/common.proto` and `proto/README.md`: every
//! `bytes payload` is the **authoritative** `ciborium` CBOR encoding of the
//! named `satl-core` type, and the sibling scalars (`state`, `desired_state`,
//! `role`, `availability`, `meta.version`) are **mirrors** the protocol
//! routes, filters and logs on. A receiver that finds them inconsistent
//! trusts the payload and logs the discrepancy — [`decode_task`] does exactly
//! that rather than failing, because a mirror is a hint and the payload is
//! the value.
//!
//! proto3 enums are open: an unknown value arrives as a bare `i32`. Every
//! decode here goes through `try_from` **and** rejects the `*_UNSPECIFIED`
//! zero value, which the proto documents as "never sent deliberately;
//! receiving it is a protocol error".

use std::time::{Duration, SystemTime};

use satl_core::{
    Availability, Config, DesiredState, Id, Meta, Node, NodeDescription, NodeRole, Secret, Task,
    TaskState, TaskStatus, Version,
};
use satl_proto::v1;

use crate::assignment::NetworkAssignment;

/// A message could not be encoded or decoded.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// A CBOR payload could not be decoded into its `satl-core` type.
    #[error("{kind} {id}: cbor payload is not a valid {kind}: {reason}")]
    Payload {
        /// Which envelope.
        kind: &'static str,
        /// The envelope's ID, for the operator.
        id: String,
        /// The ciborium error text.
        reason: String,
    },

    /// A CBOR payload could not be produced.
    #[error("{kind} {id}: cannot encode the cbor payload: {reason}")]
    Encode {
        /// Which envelope.
        kind: &'static str,
        /// The envelope's ID.
        id: String,
        /// The ciborium error text.
        reason: String,
    },

    /// A required envelope field was empty.
    #[error("{kind}: {field} is missing")]
    Missing {
        /// Which envelope.
        kind: &'static str,
        /// The absent field.
        field: &'static str,
    },

    /// An open proto3 enum carried a value this build does not know, or the
    /// `*_UNSPECIFIED` zero value.
    #[error("{enum_name}: value {value} is not a legal {enum_name} on this build")]
    Enum {
        /// Which enum.
        enum_name: &'static str,
        /// The value received.
        value: i32,
    },

    /// An ID field did not parse.
    #[error("{kind}: {field} {value:?} is not a valid object id: {reason}")]
    Id {
        /// Which envelope.
        kind: &'static str,
        /// The field holding the ID.
        field: &'static str,
        /// The value received.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// An observed task state arrived that is desired-only
    /// (`TASK_STATE_REMOVE`, architecture §4 rule 5).
    #[error(
        "task {task_id}: {state} is a desired-state marker and can never be an observed state; \
         the agent must not report it"
    )]
    DesiredOnlyState {
        /// The task involved.
        task_id: String,
        /// The illegal state.
        state: TaskState,
    },
}

// ---------------------------------------------------------------------------
// CBOR payloads
// ---------------------------------------------------------------------------

/// CBOR-encode any payload, naming the envelope in the error.
pub fn to_cbor<T: serde::Serialize>(
    kind: &'static str,
    id: &str,
    value: &T,
) -> Result<Vec<u8>, CodecError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|error| CodecError::Encode {
        kind,
        id: id.to_owned(),
        reason: error.to_string(),
    })?;
    Ok(bytes)
}

/// CBOR-decode a payload, naming the envelope in the error.
pub fn from_cbor<T: serde::de::DeserializeOwned>(
    kind: &'static str,
    id: &str,
    bytes: &[u8],
) -> Result<T, CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Missing {
            kind,
            field: "payload",
        });
    }
    ciborium::from_reader(bytes).map_err(|error: ciborium::de::Error<std::io::Error>| {
        CodecError::Payload {
            kind,
            id: id.to_owned(),
            reason: error.to_string(),
        }
    })
}

fn parse_id(kind: &'static str, field: &'static str, value: &str) -> Result<Id, CodecError> {
    value.parse::<Id>().map_err(|error| CodecError::Id {
        kind,
        field,
        value: value.to_owned(),
        reason: error.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

/// Mirror of an observed task state on the wire.
#[must_use]
pub fn task_state_to_proto(state: TaskState) -> v1::TaskState {
    match state {
        TaskState::New => v1::TaskState::New,
        TaskState::Pending => v1::TaskState::Pending,
        TaskState::Assigned => v1::TaskState::Assigned,
        TaskState::Accepted => v1::TaskState::Accepted,
        TaskState::Preparing => v1::TaskState::Preparing,
        TaskState::Ready => v1::TaskState::Ready,
        TaskState::Starting => v1::TaskState::Starting,
        TaskState::Running => v1::TaskState::Running,
        TaskState::Complete => v1::TaskState::Complete,
        TaskState::Shutdown => v1::TaskState::Shutdown,
        TaskState::Failed => v1::TaskState::Failed,
        TaskState::Rejected => v1::TaskState::Rejected,
        TaskState::Remove => v1::TaskState::Remove,
        TaskState::Orphaned => v1::TaskState::Orphaned,
    }
}

/// The observed task state a wire value denotes.
///
/// `TASK_STATE_NEW` is the zero value here and is a legal state (SwarmKit's
/// numbering has no `UNSPECIFIED` for observed state), so only genuinely
/// unknown values are rejected.
pub fn task_state_from_proto(value: i32) -> Result<TaskState, CodecError> {
    let state = v1::TaskState::try_from(value).map_err(|_| CodecError::Enum {
        enum_name: "TaskState",
        value,
    })?;
    Ok(match state {
        v1::TaskState::New => TaskState::New,
        v1::TaskState::Pending => TaskState::Pending,
        v1::TaskState::Assigned => TaskState::Assigned,
        v1::TaskState::Accepted => TaskState::Accepted,
        v1::TaskState::Preparing => TaskState::Preparing,
        v1::TaskState::Ready => TaskState::Ready,
        v1::TaskState::Starting => TaskState::Starting,
        v1::TaskState::Running => TaskState::Running,
        v1::TaskState::Complete => TaskState::Complete,
        v1::TaskState::Shutdown => TaskState::Shutdown,
        v1::TaskState::Failed => TaskState::Failed,
        v1::TaskState::Rejected => TaskState::Rejected,
        v1::TaskState::Remove => TaskState::Remove,
        v1::TaskState::Orphaned => TaskState::Orphaned,
    })
}

/// Mirror of a desired state on the wire.
#[must_use]
pub fn desired_state_to_proto(state: DesiredState) -> v1::DesiredState {
    match state {
        DesiredState::Ready => v1::DesiredState::Ready,
        DesiredState::Running => v1::DesiredState::Running,
        DesiredState::Complete => v1::DesiredState::Complete,
        DesiredState::Shutdown => v1::DesiredState::Shutdown,
        DesiredState::Remove => v1::DesiredState::Remove,
    }
}

/// The desired state a wire value denotes; `UNSPECIFIED` is a protocol error.
pub fn desired_state_from_proto(value: i32) -> Result<DesiredState, CodecError> {
    let state = v1::DesiredState::try_from(value).map_err(|_| CodecError::Enum {
        enum_name: "DesiredState",
        value,
    })?;
    match state {
        v1::DesiredState::Unspecified => Err(CodecError::Enum {
            enum_name: "DesiredState",
            value,
        }),
        v1::DesiredState::Ready => Ok(DesiredState::Ready),
        v1::DesiredState::Running => Ok(DesiredState::Running),
        v1::DesiredState::Complete => Ok(DesiredState::Complete),
        v1::DesiredState::Shutdown => Ok(DesiredState::Shutdown),
        v1::DesiredState::Remove => Ok(DesiredState::Remove),
    }
}

/// Mirror of a node role on the wire.
#[must_use]
pub fn role_to_proto(role: NodeRole) -> v1::NodeRole {
    match role {
        NodeRole::Worker => v1::NodeRole::Worker,
        NodeRole::Manager => v1::NodeRole::Manager,
    }
}

/// Mirror of an availability on the wire.
#[must_use]
pub fn availability_to_proto(availability: Availability) -> v1::Availability {
    match availability {
        Availability::Active => v1::Availability::Active,
        Availability::Pause => v1::Availability::Pause,
        Availability::Drain => v1::Availability::Drain,
    }
}

/// Metadata mirror.
#[must_use]
pub fn meta_to_proto(meta: &Meta) -> v1::Meta {
    v1::Meta {
        version: Some(v1::Version {
            index: meta.version.0,
        }),
        created_at: Some(prost_types::Timestamp::from(meta.created_at)),
        updated_at: Some(prost_types::Timestamp::from(meta.updated_at)),
    }
}

/// The object version a metadata mirror carries, if any.
#[must_use]
pub fn meta_version(meta: Option<&v1::Meta>) -> Option<Version> {
    meta.and_then(|meta| meta.version.as_ref())
        .map(|version| Version(version.index))
}

/// A `google.protobuf.Duration` for a heartbeat period.
///
/// Negative or absurd durations cannot be produced here: the input is a
/// [`Duration`], and the conversion only fails on values beyond protobuf's
/// range, which we clamp rather than propagate — a manager that cannot tell
/// an agent when to beat next would take the node down for a rounding
/// problem.
#[must_use]
pub fn duration_to_proto(duration: Duration) -> prost_types::Duration {
    prost_types::Duration::try_from(duration).unwrap_or(prost_types::Duration {
        seconds: i64::MAX,
        nanos: 0,
    })
}

/// The heartbeat period a `google.protobuf.Duration` denotes.
///
/// A missing, negative or unrepresentable value is refused: the server
/// dictates the period and the agent must not silently substitute one.
pub fn duration_from_proto(
    duration: Option<prost_types::Duration>,
) -> Result<Duration, CodecError> {
    let duration = duration.ok_or(CodecError::Missing {
        kind: "HeartbeatResponse",
        field: "period",
    })?;
    Duration::try_from(duration).map_err(|_| CodecError::Missing {
        kind: "HeartbeatResponse",
        field: "period (negative or out of range)",
    })
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

/// A task, as the assignment stream ships it (payload + routing mirrors).
pub fn encode_task(task: &Task) -> Result<v1::Task, CodecError> {
    Ok(v1::Task {
        id: task.id.to_string(),
        meta: Some(meta_to_proto(&task.meta)),
        state: task_state_to_proto(task.status.state) as i32,
        desired_state: desired_state_to_proto(task.desired_state) as i32,
        payload: to_cbor("Task", task.id.as_str(), task)?,
    })
}

/// A task ID only, for an `ACTION_REMOVE` change (the proto allows an empty
/// payload there: removal only needs the ID).
#[must_use]
pub fn task_removal(task_id: &Id) -> v1::Task {
    v1::Task {
        id: task_id.to_string(),
        meta: None,
        state: v1::TaskState::New as i32,
        desired_state: v1::DesiredState::Remove as i32,
        payload: Vec::new(),
    }
}

/// The task an envelope carries.
///
/// The payload wins over the mirrors; a disagreement is logged, not fatal
/// (`proto/common.proto`: "trust `payload` and log the discrepancy").
pub fn decode_task(envelope: &v1::Task) -> Result<Task, CodecError> {
    let task: Task = from_cbor("Task", &envelope.id, &envelope.payload)?;
    if let Ok(mirror) = task_state_from_proto(envelope.state)
        && mirror != task.status.state
    {
        tracing::warn!(
            task_id = %task.id,
            mirror = %mirror,
            payload = %task.status.state,
            "task envelope state mirror disagrees with its payload; trusting the payload"
        );
    }
    if let Ok(mirror) = desired_state_from_proto(envelope.desired_state)
        && mirror != task.desired_state
    {
        tracing::warn!(
            task_id = %task.id,
            mirror = %mirror,
            payload = %task.desired_state,
            "task envelope desired-state mirror disagrees with its payload; trusting the payload"
        );
    }
    Ok(task)
}

/// A secret, as the assignment stream ships it.
///
/// The payload is sensitive: it travels only over mTLS, is held in agent
/// memory and is materialized exclusively into a per-task tmpfs
/// (invariant #7). Never log this value.
pub fn encode_secret(secret: &Secret) -> Result<v1::Secret, CodecError> {
    Ok(v1::Secret {
        id: secret.id.to_string(),
        meta: Some(meta_to_proto(&secret.meta)),
        payload: to_cbor("Secret", secret.id.as_str(), secret)?,
    })
}

/// A secret ID only, for an `ACTION_REMOVE` change.
#[must_use]
pub fn secret_removal(id: &Id) -> v1::Secret {
    v1::Secret {
        id: id.to_string(),
        meta: None,
        payload: Vec::new(),
    }
}

/// The secret an envelope carries.
pub fn decode_secret(envelope: &v1::Secret) -> Result<Secret, CodecError> {
    from_cbor("Secret", &envelope.id, &envelope.payload)
}

/// A config, as the assignment stream ships it.
pub fn encode_config(config: &Config) -> Result<v1::Config, CodecError> {
    Ok(v1::Config {
        id: config.id.to_string(),
        meta: Some(meta_to_proto(&config.meta)),
        payload: to_cbor("Config", config.id.as_str(), config)?,
    })
}

/// A config ID only, for an `ACTION_REMOVE` change.
#[must_use]
pub fn config_removal(id: &Id) -> v1::Config {
    v1::Config {
        id: id.to_string(),
        meta: None,
        payload: Vec::new(),
    }
}

/// The config an envelope carries.
pub fn decode_config(envelope: &v1::Config) -> Result<Config, CodecError> {
    from_cbor("Config", &envelope.id, &envelope.payload)
}

/// A network and its endpoint table, as the assignment stream ships it.
///
/// The `meta` mirror is the **network object**'s version. It is not a change
/// indicator for this envelope: the endpoint table moves without the network
/// object being written (`proto/dispatcher.proto`), so the version can repeat
/// across two envelopes that differ. It is sent because it is what an operator
/// reading a log needs to correlate with `satl network inspect`.
pub fn encode_network(assignment: &NetworkAssignment) -> Result<v1::NetworkAssignment, CodecError> {
    let id = assignment.id();
    Ok(v1::NetworkAssignment {
        id: id.to_string(),
        meta: Some(meta_to_proto(&assignment.network.meta)),
        payload: to_cbor("NetworkAssignment", id.as_str(), assignment)?,
    })
}

/// A network ID only, for an `ACTION_REMOVE` change.
#[must_use]
pub fn network_removal(id: &Id) -> v1::NetworkAssignment {
    v1::NetworkAssignment {
        id: id.to_string(),
        meta: None,
        payload: Vec::new(),
    }
}

/// The network assignment an envelope carries.
pub fn decode_network(envelope: &v1::NetworkAssignment) -> Result<NetworkAssignment, CodecError> {
    let assignment: NetworkAssignment =
        from_cbor("NetworkAssignment", &envelope.id, &envelope.payload)?;
    let id = parse_id("NetworkAssignment", "id", &envelope.id)?;
    if *assignment.id() != id {
        tracing::warn!(
            mirror = %id,
            payload = %assignment.id(),
            "network envelope id disagrees with its payload; trusting the payload"
        );
    }
    Ok(assignment)
}

/// A node object, as the session stream ships it to its own agent.
pub fn encode_node(node: &Node) -> Result<v1::Node, CodecError> {
    Ok(v1::Node {
        id: node.id.to_string(),
        meta: Some(meta_to_proto(&node.meta)),
        role: role_to_proto(node.spec.role) as i32,
        availability: availability_to_proto(node.spec.availability) as i32,
        payload: to_cbor("Node", node.id.as_str(), node)?,
    })
}

/// The node an envelope carries.
pub fn decode_node(envelope: &v1::Node) -> Result<Node, CodecError> {
    from_cbor("Node", &envelope.id, &envelope.payload)
}

/// The node description an agent sends at registration.
pub fn encode_description(description: &NodeDescription) -> Result<Vec<u8>, CodecError> {
    to_cbor("NodeDescription", &description.hostname, description)
}

/// The node description a `SessionRequest` carries; `None` when the field is
/// empty (legal when resuming a known session).
pub fn decode_description(bytes: &[u8]) -> Result<Option<NodeDescription>, CodecError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    from_cbor("NodeDescription", "", bytes).map(Some)
}

/// One coalesced status update, with its mirrored state.
pub fn encode_status(
    task_id: &Id,
    status: &TaskStatus,
) -> Result<v1::TaskStatusUpdate, CodecError> {
    Ok(v1::TaskStatusUpdate {
        task_id: task_id.to_string(),
        state: task_state_to_proto(status.state) as i32,
        status: to_cbor("TaskStatus", task_id.as_str(), status)?,
    })
}

/// The `(task, status)` pair an update carries.
///
/// Rejects `TASK_STATE_REMOVE` on either the mirror or the payload: it is a
/// desired-state marker and is never a legal observed state
/// (`proto/dispatcher.proto`, architecture §4 rule 5).
pub fn decode_status(update: &v1::TaskStatusUpdate) -> Result<(Id, TaskStatus), CodecError> {
    let id = parse_id("TaskStatusUpdate", "task_id", &update.task_id)?;
    let mirror = task_state_from_proto(update.state)?;
    if mirror == TaskState::Remove {
        return Err(CodecError::DesiredOnlyState {
            task_id: update.task_id.clone(),
            state: mirror,
        });
    }
    let status: TaskStatus = from_cbor("TaskStatus", &update.task_id, &update.status)?;
    if status.state == TaskState::Remove {
        return Err(CodecError::DesiredOnlyState {
            task_id: update.task_id.clone(),
            state: status.state,
        });
    }
    if status.state != mirror {
        tracing::warn!(
            task_id = %id,
            mirror = %mirror,
            payload = %status.state,
            "status update state mirror disagrees with its payload; trusting the payload"
        );
    }
    Ok((id, status))
}

/// A `SystemTime` for `applied_at`, so tests can pin the manager clock.
#[must_use]
pub fn now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn task_roundtrips_through_the_envelope() {
        let task = testing::task_at(TaskState::Running, DesiredState::Running);
        let envelope = encode_task(&task).expect("encode");
        assert_eq!(envelope.id, task.id.to_string());
        assert_eq!(envelope.state(), v1::TaskState::Running);
        assert_eq!(envelope.desired_state(), v1::DesiredState::Running);
        assert_eq!(
            meta_version(envelope.meta.as_ref()),
            Some(task.meta.version)
        );
        assert_eq!(decode_task(&envelope).expect("decode"), task);
    }

    #[test]
    fn the_payload_wins_over_a_lying_mirror() {
        let task = testing::task_at(TaskState::Running, DesiredState::Running);
        let mut envelope = encode_task(&task).expect("encode");
        envelope.state = v1::TaskState::New as i32;
        envelope.desired_state = v1::DesiredState::Shutdown as i32;
        let decoded = decode_task(&envelope).expect("decode");
        assert_eq!(decoded.status.state, TaskState::Running);
        assert_eq!(decoded.desired_state, DesiredState::Running);
    }

    #[test]
    fn secrets_and_configs_roundtrip() {
        let secret = testing::secret("db.password", b"hunter2");
        let envelope = encode_secret(&secret).expect("encode");
        assert_eq!(decode_secret(&envelope).expect("decode"), secret);

        let config = testing::config("nginx.conf", b"server {}");
        let envelope = encode_config(&config).expect("encode");
        assert_eq!(decode_config(&envelope).expect("decode"), config);
    }

    #[test]
    fn node_and_description_roundtrip() {
        let node = testing::node(NodeRole::Worker);
        let envelope = encode_node(&node).expect("encode");
        assert_eq!(envelope.role(), v1::NodeRole::Worker);
        assert_eq!(envelope.availability(), v1::Availability::Active);
        assert_eq!(decode_node(&envelope).expect("decode"), node);

        let description = testing::description("worker-1");
        let bytes = encode_description(&description).expect("encode");
        assert_eq!(
            decode_description(&bytes).expect("decode"),
            Some(description)
        );
        assert_eq!(decode_description(&[]).expect("empty"), None);
    }

    #[test]
    fn removals_carry_only_the_id() {
        let id = Id::generate();
        assert_eq!(task_removal(&id).id, id.to_string());
        assert!(task_removal(&id).payload.is_empty());
        assert!(secret_removal(&id).payload.is_empty());
        assert!(config_removal(&id).payload.is_empty());
        assert_eq!(network_removal(&id).id, id.to_string());
        assert!(network_removal(&id).payload.is_empty());
        assert!(network_removal(&id).meta.is_none());
    }

    #[test]
    fn a_network_and_its_endpoint_table_roundtrip() {
        let network = testing::overlay_network("blue");
        let assignment = NetworkAssignment::new(network.clone()).with_endpoint(
            crate::assignment::NetworkEndpoint {
                task_id: Id::generate(),
                node_id: Id::generate(),
                addr: "10.100.4.5".parse().expect("addr"),
                vtep: "10.2.0.2".parse().expect("addr"),
                service_name: "web".to_owned(),
                task_name: "web.1.x".to_owned(),
                aliases: vec!["www".to_owned()],
                state: satl_core::TaskState::Running,
            },
        );
        let envelope = encode_network(&assignment).expect("encode");
        assert_eq!(envelope.id, network.id.to_string());
        assert_eq!(
            meta_version(envelope.meta.as_ref()),
            Some(network.meta.version)
        );
        let decoded = decode_network(&envelope).expect("decode");
        assert_eq!(decoded, assignment);
        assert_eq!(decoded.endpoints.len(), 1);
    }

    /// An endpoint encoded before the DNS fields existed must still decode:
    /// names empty, state `NEW` — a value the DNS table never answers from,
    /// so an old manager degrades a worker's DNS to silence, never to a wrong
    /// or permanently-stale answer.
    #[test]
    fn a_pre_dns_endpoint_payload_still_decodes() {
        #[derive(serde::Serialize)]
        struct OldEndpoint {
            task_id: Id,
            node_id: Id,
            addr: std::net::Ipv4Addr,
            vtep: std::net::Ipv4Addr,
        }
        let old = OldEndpoint {
            task_id: Id::generate(),
            node_id: Id::generate(),
            addr: "10.100.4.5".parse().expect("addr"),
            vtep: "10.2.0.2".parse().expect("addr"),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&old, &mut bytes).expect("encode");
        let decoded: crate::assignment::NetworkEndpoint =
            ciborium::from_reader(bytes.as_slice()).expect("an old payload must decode");
        assert_eq!(decoded.task_id, old.task_id);
        assert_eq!(decoded.addr, old.addr);
        assert!(decoded.service_name.is_empty());
        assert!(decoded.task_name.is_empty());
        assert!(decoded.aliases.is_empty());
        assert_eq!(decoded.state, satl_core::TaskState::New);
    }

    /// Wire compat across the keyring change, in both directions:
    ///
    /// - a payload encoded by a pre-keys build (no `encrypted`, no `keys`, no
    ///   `keys_updated_at`) decodes here with an empty ring and an
    ///   unencrypted spec — the model's `#[serde(default)]` at work;
    /// - a payload encoded *with* a keyring decodes on the pre-keys shape —
    ///   serde's derive skips unknown map keys, so a mixed-version cluster
    ///   mid-upgrade keeps its assignment stream up on both sides (the old
    ///   build simply cannot program encryption, same as it never could).
    ///
    /// Same pattern as [`a_pre_dns_endpoint_payload_still_decodes`]: the old
    /// shape is restated locally, because the old type no longer exists.
    #[test]
    fn a_keyring_assignment_is_wire_compatible_with_a_pre_keys_build() {
        use std::collections::BTreeMap;

        use satl_core::{Annotations, IpamConfig, NetworkDriver};

        use crate::assignment::{GatewayAttachment, NetworkEndpoint};

        /// `NetworkAssignment` as a pre-keys build encoded and decoded it.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct PreKeysAssignment {
            network: PreKeysNetwork,
            endpoints: BTreeMap<Id, NetworkEndpoint>,
            #[serde(default)]
            gateways: BTreeMap<Id, GatewayAttachment>,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct PreKeysNetwork {
            id: Id,
            meta: Meta,
            spec: PreKeysNetworkSpec,
            vni: Option<u32>,
            subnet: Option<String>,
            #[serde(default)]
            node_gateways: BTreeMap<Id, String>,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct PreKeysNetworkSpec {
            annotations: Annotations,
            driver: NetworkDriver,
            ipam: Option<IpamConfig>,
            internal: bool,
            attachable: bool,
            ingress: bool,
        }

        // Old -> new: the payload a pre-keys build produced.
        let network = testing::overlay_network("blue");
        let old = PreKeysAssignment {
            network: PreKeysNetwork {
                id: network.id.clone(),
                meta: network.meta,
                spec: PreKeysNetworkSpec {
                    annotations: network.spec.annotations.clone(),
                    driver: network.spec.driver,
                    ipam: network.spec.ipam.clone(),
                    internal: network.spec.internal,
                    attachable: network.spec.attachable,
                    ingress: network.spec.ingress,
                },
                vni: network.vni,
                subnet: network.subnet.clone(),
                node_gateways: network.node_gateways.clone(),
            },
            endpoints: BTreeMap::new(),
            gateways: BTreeMap::new(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&old, &mut bytes).expect("encode");
        let decoded: NetworkAssignment =
            ciborium::from_reader(bytes.as_slice()).expect("a pre-keys payload must decode");
        assert_eq!(decoded.network.id, network.id);
        assert!(
            !decoded.network.spec.encrypted,
            "absent means not encrypted"
        );
        assert!(
            decoded.network.keys.is_empty(),
            "absent means an empty ring"
        );
        assert_eq!(decoded.network.keys_updated_at, None);

        // New -> old: the payload a keyring build produces, read by the old
        // shape — the unknown fields are skipped, not an error.
        let keyed = NetworkAssignment::new(testing::encrypted_overlay("blue"));
        let mut bytes = Vec::new();
        ciborium::into_writer(&keyed, &mut bytes).expect("encode");
        let decoded: PreKeysAssignment = ciborium::from_reader(bytes.as_slice())
            .expect("a keyed payload must decode on the pre-keys shape");
        assert_eq!(decoded.network.id, keyed.network.id);
        assert_eq!(decoded.network.spec.ingress, keyed.network.spec.ingress);
    }

    /// The endpoint table moves without the network object being written, so
    /// the `meta` mirror can repeat across two different payloads. A receiver
    /// must not use it to decide "unchanged" — the encoding has to keep both
    /// tables distinguishable.
    #[test]
    fn two_endpoint_tables_of_the_same_network_version_encode_differently() {
        let network = testing::overlay_network("blue");
        let empty = NetworkAssignment::new(network.clone());
        let populated = empty
            .clone()
            .with_endpoint(crate::assignment::NetworkEndpoint {
                task_id: Id::generate(),
                node_id: Id::generate(),
                addr: "10.100.4.5".parse().expect("addr"),
                vtep: "10.2.0.2".parse().expect("addr"),
                service_name: String::new(),
                task_name: String::new(),
                aliases: Vec::new(),
                state: satl_core::TaskState::Running,
            });
        let first = encode_network(&empty).expect("encode");
        let second = encode_network(&populated).expect("encode");
        assert_eq!(
            meta_version(first.meta.as_ref()),
            meta_version(second.meta.as_ref()),
            "same network object, same version"
        );
        assert_ne!(first.payload, second.payload);
    }

    #[test]
    fn an_empty_network_payload_is_refused() {
        let envelope = v1::NetworkAssignment {
            id: Id::generate().to_string(),
            meta: None,
            payload: Vec::new(),
        };
        assert!(matches!(
            decode_network(&envelope),
            Err(CodecError::Missing {
                field: "payload",
                ..
            })
        ));
    }

    #[test]
    fn every_task_state_mirrors_onto_the_wire_and_back() {
        for state in testing::ALL_STATES {
            let value = task_state_to_proto(state) as i32;
            assert_eq!(task_state_from_proto(value).expect("known"), state);
            assert_eq!(value, i32::from(state.value()), "{state}");
        }
    }

    #[test]
    fn every_desired_state_mirrors_onto_the_wire_and_back() {
        for state in [
            DesiredState::Ready,
            DesiredState::Running,
            DesiredState::Complete,
            DesiredState::Shutdown,
            DesiredState::Remove,
        ] {
            let value = desired_state_to_proto(state) as i32;
            assert_eq!(desired_state_from_proto(value).expect("known"), state);
        }
    }

    #[test]
    fn unknown_and_unspecified_enum_values_are_refused() {
        assert!(matches!(
            task_state_from_proto(513),
            Err(CodecError::Enum { .. })
        ));
        assert!(matches!(
            desired_state_from_proto(0),
            Err(CodecError::Enum { .. })
        ));
        assert!(matches!(
            desired_state_from_proto(7),
            Err(CodecError::Enum { .. })
        ));
    }

    #[test]
    fn status_updates_roundtrip_and_refuse_the_remove_marker() {
        let id = Id::generate();
        let status = TaskStatus::new(TaskState::Running, "started");
        let update = encode_status(&id, &status).expect("encode");
        let (decoded_id, decoded) = decode_status(&update).expect("decode");
        assert_eq!(decoded_id, id);
        assert_eq!(decoded, status);

        // The mirror alone is enough to reject it...
        let mut poisoned = update.clone();
        poisoned.state = v1::TaskState::Remove as i32;
        assert!(matches!(
            decode_status(&poisoned),
            Err(CodecError::DesiredOnlyState { .. })
        ));

        // ...and so is the payload, which is the authoritative copy.
        let removal = TaskStatus::new(TaskState::Remove, "should never be reported");
        let mut sneaky = encode_status(&id, &removal).expect("encode");
        sneaky.state = v1::TaskState::Shutdown as i32;
        assert!(matches!(
            decode_status(&sneaky),
            Err(CodecError::DesiredOnlyState { .. })
        ));
    }

    #[test]
    fn an_empty_payload_is_a_missing_payload_not_a_default_object() {
        let envelope = v1::Task {
            id: Id::generate().to_string(),
            meta: None,
            state: v1::TaskState::Assigned as i32,
            desired_state: v1::DesiredState::Running as i32,
            payload: Vec::new(),
        };
        assert!(matches!(
            decode_task(&envelope),
            Err(CodecError::Missing {
                field: "payload",
                ..
            })
        ));
    }

    #[test]
    fn heartbeat_periods_roundtrip() {
        let period = Duration::from_millis(5_500);
        let wire = duration_to_proto(period);
        assert_eq!(duration_from_proto(Some(wire)).expect("decode"), period);
        assert!(duration_from_proto(None).is_err());
        assert!(
            duration_from_proto(Some(prost_types::Duration {
                seconds: -1,
                nanos: 0
            }))
            .is_err(),
            "a negative period would make the agent beat immediately, forever"
        );
    }

    #[test]
    fn a_bad_task_id_names_the_field_and_the_value() {
        let update = v1::TaskStatusUpdate {
            task_id: "not-an-id".to_owned(),
            state: v1::TaskState::Running as i32,
            status: vec![0xa0],
        };
        let error = decode_status(&update).expect_err("rejected");
        let message = error.to_string();
        assert!(message.contains("not-an-id"), "{message}");
        assert!(message.contains("task_id"), "{message}");
    }
}
