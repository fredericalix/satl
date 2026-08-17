// SPDX-License-Identifier: BSD-2-Clause
//! The filter pipeline (SWK §8.3).
//!
//! Each filter is configured once per task group ([`Filter::set_task`], which
//! also answers whether the filter applies at all), then asked about every
//! candidate node ([`Filter::check`]). The pipeline short-circuits on the
//! first failure and counts it; [`Pipeline::explain`] turns those counts into
//! the operator-facing reason that ends up in `Task.Status.Err` as
//! `no suitable node (…)`.
//!
//! Order matters and is SwarmKit's: cheapest and most likely first.
//!
//! | # | Filter | Enabled when | A node passes if |
//! |---|---|---|---|
//! | 1 | [`NodeReadyFilter`] | always | status `Ready` and availability `Active` |
//! | 2 | [`ResourceFilter`] | the task reserves CPU or memory | the reservation fits in capacity − reservations already on the node |
//! | 3 | [`ConstraintFilter`] | `placement.constraints` is non-empty | every expression matches (SWK §8.7) |
//! | 4 | [`PlatformFilter`] | `placement.platforms` is non-empty | the node's platform matches one entry |
//! | 5 | [`HostPortFilter`] | the task publishes host-mode ports | no `(protocol, port)` pair is already bound there |
//! | 6 | [`MaxReplicasFilter`] | `placement.max_replicas > 0` | active tasks of this service < `max_replicas` |
//!
//! SwarmKit's Plugin and Volumes filters are dropped: Docker plugins do not
//! exist here and CSI volumes are out of scope (architecture §14).

use satl_core::{Availability, Constraints, Id, Node, NodeState, Platform, Task, TaskSpec};

use crate::node_info::{HostPort, NodeInfo};

/// Whether `node` accepts new tasks at all (SWK §8.3 filter 1): status `Ready`
/// and availability `Active`.
///
/// Exposed because placement is not only the scheduler's question: the global
/// orchestrator has to decide which nodes a global service should have a task
/// on (SWK §7.8), and a second reading of "schedulable" would drift from this
/// one — it would create tasks the scheduler then refuses.
#[must_use]
pub fn accepts_new_tasks(node: &Node) -> bool {
    node.status.state == NodeState::Ready && node.spec.availability == Availability::Active
}

/// The requirements a task spec states about a node **itself** — placement
/// constraints (SWK §8.7) and supported platforms (SWK §8.3 filter 4) — parsed
/// once and answerable for any number of nodes.
///
/// This is the half of the filter pipeline that depends on nothing but the node
/// object: no resource totals, no bound ports, no per-service task counts. That
/// makes it the part the global orchestrator can evaluate itself, and it is the
/// same code the [`ConstraintFilter`] and [`PlatformFilter`] run.
#[derive(Debug, Default, Clone)]
pub struct PlacementRequirements {
    constraints: Constraints,
    platforms: Vec<Platform>,
}

impl PlacementRequirements {
    /// Reads them off a task spec.
    ///
    /// An unparseable constraint expression is dropped rather than failing every
    /// node, exactly as [`ConstraintFilter`] drops it: the parse error was
    /// reported to the operator when they wrote it, and refusing every node here
    /// would take a whole service down for a typo.
    #[must_use]
    pub fn of(spec: &TaskSpec) -> Self {
        let constraints = if spec.placement.constraints.is_empty() {
            Constraints::default()
        } else {
            match Constraints::parse_all(&spec.placement.constraints) {
                Ok(constraints) => constraints,
                Err(error) => {
                    tracing::warn!(%error, "ignoring unparseable placement constraints");
                    Constraints::default()
                }
            }
        };
        Self {
            constraints,
            platforms: spec.placement.platforms.clone(),
        }
    }

    /// Whether `node` satisfies all of them.
    #[must_use]
    pub fn satisfied_by(&self, node: &Node) -> bool {
        self.constraints.matches(node) && platform_supported(&self.platforms, node)
    }
}

/// Whether `node` reports a platform one of `supported` accepts; an empty list
/// means the image did not say, so anything goes (SWK §8.3 filter 4).
fn platform_supported(supported: &[Platform], node: &Node) -> bool {
    if supported.is_empty() {
        return true;
    }
    let Some(description) = node.description.as_ref() else {
        // A node that has not described itself cannot be shown to run this
        // image, and the scheduler would refuse it too.
        return false;
    };
    supported
        .iter()
        .any(|wanted| platform_matches(wanted, &description.platform))
}

/// One check a node must pass to run a task (SWK §8.3).
pub trait Filter: Send {
    /// Filter name, for logs.
    fn name(&self) -> &'static str;

    /// Configures the filter for `task`; returns whether it applies.
    fn set_task(&mut self, task: &Task) -> bool;

    /// Whether `node` passes.
    fn check(&self, node: &NodeInfo) -> bool;

    /// Why `rejected` nodes did not pass.
    fn explain(&self, rejected: usize) -> String;
}

/// `"<n> nodes"`, or `"1 node"` — the shape every SwarmKit explanation uses.
fn nodes(count: usize) -> String {
    if count == 1 {
        "1 node".to_owned()
    } else {
        format!("{count} nodes")
    }
}

/// Node must be reachable and accept new tasks (SWK §8.3 filter 1): status
/// `Ready` and availability `Active`.
///
/// `Pause` and `Drain` both stop new placements; the difference (drain also
/// evicts what already runs) is the orchestrators' business, not the
/// scheduler's.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeReadyFilter;

impl Filter for NodeReadyFilter {
    fn name(&self) -> &'static str {
        "ready"
    }

    fn set_task(&mut self, _task: &Task) -> bool {
        true
    }

    fn check(&self, node: &NodeInfo) -> bool {
        accepts_new_tasks(node.node())
    }

    fn explain(&self, rejected: usize) -> String {
        format!("{} not available for new tasks", nodes(rejected))
    }
}

/// Reserved CPU and memory must fit in what is left on the node (SWK §8.3
/// filter 2).
///
/// Only *reservations* are considered — limits are enforced by rctl(8) on the
/// node (architecture §8.3) and never influence placement. A node that has
/// not described itself reports zero capacity, so it takes no reserving task.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResourceFilter {
    nano_cpus: i64,
    memory_bytes: i64,
}

impl Filter for ResourceFilter {
    fn name(&self) -> &'static str {
        "resource"
    }

    fn set_task(&mut self, task: &Task) -> bool {
        let Some(reservations) = task.spec.resources.reservations else {
            return false;
        };
        if reservations.nano_cpus == 0 && reservations.memory_bytes == 0 {
            return false;
        }
        self.nano_cpus = reservations.nano_cpus;
        self.memory_bytes = reservations.memory_bytes;
        true
    }

    fn check(&self, node: &NodeInfo) -> bool {
        let available = node.available();
        self.nano_cpus <= available.nano_cpus && self.memory_bytes <= available.memory_bytes
    }

    fn explain(&self, rejected: usize) -> String {
        format!("insufficient resources on {}", nodes(rejected))
    }
}

/// Every placement constraint must match the node (SWK §8.3 filter 4, §8.7).
///
/// Expressions are validated by the API on service creation; an expression
/// that fails to parse here disables the filter rather than excluding every
/// node, exactly as SwarmKit does — the parse error was already reported to
/// the user at the point they could act on it.
#[derive(Debug, Default, Clone)]
pub struct ConstraintFilter {
    constraints: Constraints,
}

impl Filter for ConstraintFilter {
    fn name(&self) -> &'static str {
        "constraint"
    }

    fn set_task(&mut self, task: &Task) -> bool {
        let expressions = &task.spec.placement.constraints;
        if expressions.is_empty() {
            return false;
        }
        match Constraints::parse_all(expressions) {
            Ok(constraints) => {
                self.constraints = constraints;
                true
            }
            Err(err) => {
                tracing::warn!(
                    task_id = %task.id,
                    error = %err,
                    "ignoring unparseable placement constraints",
                );
                false
            }
        }
    }

    fn check(&self, node: &NodeInfo) -> bool {
        self.constraints.matches(node.node())
    }

    fn explain(&self, rejected: usize) -> String {
        format!(
            "scheduling constraints not satisfied on {}",
            nodes(rejected)
        )
    }
}

/// The node's platform must be one the image supports (SWK §8.3 filter 5).
///
/// `x86_64` and `aarch64` are normalised to the OCI spellings `amd64` and
/// `arm64` on both sides; an empty OS or architecture in the requested
/// platform is a wildcard. The platform list comes from the image's manifest
/// list at service creation (architecture §9), so a `linux/amd64`-only image
/// lands only on nodes reporting a `linux` platform — the linuxulator case is
/// handled by the resolved `ContainerSpec.platform`, not here.
#[derive(Debug, Default, Clone)]
pub struct PlatformFilter {
    supported: Vec<Platform>,
}

impl Filter for PlatformFilter {
    fn name(&self) -> &'static str {
        "platform"
    }

    fn set_task(&mut self, task: &Task) -> bool {
        self.supported.clone_from(&task.spec.placement.platforms);
        !self.supported.is_empty()
    }

    fn check(&self, node: &NodeInfo) -> bool {
        platform_supported(&self.supported, node.node())
    }

    fn explain(&self, rejected: usize) -> String {
        format!("unsupported platform on {}", nodes(rejected))
    }
}

/// Whether `wanted` (from the image) accepts `node`'s platform.
fn platform_matches(wanted: &Platform, node: &Platform) -> bool {
    let arch_ok =
        wanted.arch.is_empty() || normalize_arch(&wanted.arch) == normalize_arch(&node.arch);
    let os_ok = wanted.os.is_empty() || wanted.os == node.os;
    arch_ok && os_ok
}

/// Maps `uname`-style architecture names to the OCI spellings.
fn normalize_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Host-mode published ports must be free on the node (SWK §8.3 filter 6).
///
/// Only `host` mode with an explicit published port can conflict: ingress
/// ports are allocated cluster-wide and port 0 means "auto-assign"
/// (architecture §11.4).
#[derive(Debug, Default, Clone)]
pub struct HostPortFilter {
    ports: Vec<HostPort>,
}

impl Filter for HostPortFilter {
    fn name(&self) -> &'static str {
        "host-port"
    }

    fn set_task(&mut self, task: &Task) -> bool {
        self.ports = task
            .endpoint
            .iter()
            .flat_map(|endpoint| endpoint.ports.iter())
            .filter(|port| {
                port.publish_mode == satl_core::PublishMode::Host && port.published_port != 0
            })
            .map(|port| HostPort {
                protocol: port.protocol,
                published_port: port.published_port,
            })
            .collect();
        !self.ports.is_empty()
    }

    fn check(&self, node: &NodeInfo) -> bool {
        !self.ports.iter().any(|port| node.host_port_in_use(*port))
    }

    fn explain(&self, rejected: usize) -> String {
        format!("host-mode port already in use on {}", nodes(rejected))
    }
}

/// A node may not exceed `placement.max_replicas` tasks of one service
/// (SWK §8.3 filter 7).
#[derive(Debug, Default, Clone)]
pub struct MaxReplicasFilter {
    service_id: Option<Id>,
    max_replicas: u64,
}

impl Filter for MaxReplicasFilter {
    fn name(&self) -> &'static str {
        "max-replicas"
    }

    fn set_task(&mut self, task: &Task) -> bool {
        self.max_replicas = task.spec.placement.max_replicas;
        self.service_id.clone_from(&task.service_id);
        self.max_replicas > 0
    }

    fn check(&self, node: &NodeInfo) -> bool {
        let active = node.active_tasks_for(self.service_id.as_ref());
        u64::try_from(active).unwrap_or(u64::MAX) < self.max_replicas
    }

    fn explain(&self, _rejected: usize) -> String {
        // SwarmKit's wording, node count and all (`filter.go`). Operators and
        // tooling match on these strings, so the grammar stays as-is
        // (architecture §13: Docker API compatibility is a contract).
        "max replicas per node limit exceed".to_owned()
    }
}

/// The ordered filter pipeline, with per-filter rejection counts.
pub struct Pipeline {
    filters: Vec<Box<dyn Filter>>,
    enabled: Vec<bool>,
    rejected: Vec<usize>,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    /// The pipeline in SWK §8.3 order.
    pub fn new() -> Self {
        Self::with_filters(vec![
            Box::new(NodeReadyFilter),
            Box::new(ResourceFilter::default()),
            Box::new(ConstraintFilter::default()),
            Box::new(PlatformFilter::default()),
            Box::new(HostPortFilter::default()),
            Box::new(MaxReplicasFilter::default()),
        ])
    }

    /// A pipeline over an explicit filter list (tests).
    pub fn with_filters(filters: Vec<Box<dyn Filter>>) -> Self {
        let len = filters.len();
        Self {
            filters,
            enabled: vec![false; len],
            rejected: vec![0; len],
        }
    }

    /// Enables the filters that apply to `task` and resets the counters.
    pub fn set_task(&mut self, task: &Task) {
        for (index, filter) in self.filters.iter_mut().enumerate() {
            self.enabled[index] = filter.set_task(task);
            self.rejected[index] = 0;
        }
    }

    /// Whether `node` passes every enabled filter, short-circuiting on the
    /// first failure and counting it.
    ///
    /// A node that passes clears every counter: the explanation describes the
    /// nodes examined since the last success, which is what an operator wants
    /// to read when the batch ends up short (SwarmKit's `Pipeline.Process`).
    pub fn check(&mut self, node: &NodeInfo) -> bool {
        for (index, filter) in self.filters.iter().enumerate() {
            if self.enabled[index] && !filter.check(node) {
                self.rejected[index] += 1;
                return false;
            }
        }
        for count in &mut self.rejected {
            *count = 0;
        }
        true
    }

    /// The operator-facing reason no node was found, most-frequent failure
    /// first.
    pub fn explain(&self) -> String {
        let mut reasons: Vec<(usize, String)> = self
            .filters
            .iter()
            .enumerate()
            .filter(|(index, _)| self.rejected[*index] > 0)
            .map(|(index, filter)| (self.rejected[index], filter.explain(self.rejected[index])))
            .collect();
        if reasons.is_empty() {
            // No node even reached the pipeline.
            return "no nodes in the cluster".to_owned();
        }
        reasons.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
        reasons
            .into_iter()
            .map(|(_, reason)| reason)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use satl_core::{Availability, DesiredState, NodeState, PortProtocol, PublishMode, TaskState};

    use crate::node_info::NodeInfo;
    use crate::testing::{
        NodeBuilder, gib, host_port, planted_node, planted_task, reserve, sample_service,
    };

    use super::*;

    /// Bookkeeping for a node with nothing on it yet.
    fn node_info(node: satl_core::Node) -> NodeInfo {
        NodeInfo::new(Arc::new(node), SystemTime::now())
    }

    /// The node-only half of the pipeline, as the global orchestrator reads it
    /// (SWK §7.8): the same verdicts as the filters, without a `NodeInfo`.
    #[test]
    fn placement_requirements_answer_the_filters_questions() {
        let mut spec = sample_service("web", 1).spec.task;
        assert!(
            PlacementRequirements::of(&spec).satisfied_by(&NodeBuilder::new("n1").build()),
            "no constraints and no platform list: every node qualifies"
        );

        spec.placement.constraints = vec!["node.labels.zone == a".to_owned()];
        let requirements = PlacementRequirements::of(&spec);
        assert!(requirements.satisfied_by(&NodeBuilder::new("n1").label("zone", "a").build()));
        assert!(!requirements.satisfied_by(&NodeBuilder::new("n2").label("zone", "b").build()));
        assert!(!requirements.satisfied_by(&NodeBuilder::new("n3").build()));

        // A typo disables the check rather than emptying the cluster.
        spec.placement.constraints = vec!["this is not an expression".to_owned()];
        assert!(PlacementRequirements::of(&spec).satisfied_by(&NodeBuilder::new("n1").build()));

        spec.placement.constraints.clear();
        spec.placement.platforms = vec![Platform {
            os: "freebsd".to_owned(),
            arch: "amd64".to_owned(),
        }];
        let requirements = PlacementRequirements::of(&spec);
        assert!(requirements.satisfied_by(&NodeBuilder::new("n1").build()));
        assert!(
            !requirements.satisfied_by(&NodeBuilder::new("n2").platform("linux", "amd64").build())
        );
        assert!(
            !requirements.satisfied_by(&NodeBuilder::new("n3").no_description().build()),
            "a node that has not described itself cannot be shown to run the image"
        );
    }

    #[test]
    fn only_a_ready_active_node_accepts_new_tasks() {
        for (state, availability, expected) in [
            (NodeState::Ready, Availability::Active, true),
            (NodeState::Ready, Availability::Pause, false),
            (NodeState::Ready, Availability::Drain, false),
            (NodeState::Down, Availability::Active, false),
            (NodeState::Unknown, Availability::Active, false),
            (NodeState::Disconnected, Availability::Active, false),
        ] {
            assert_eq!(
                accepts_new_tasks(&planted_node(state, availability)),
                expected,
                "{state:?} / {availability:?}"
            );
        }
    }

    fn pending_task() -> Task {
        let service = sample_service("web", 1);
        planted_task(
            &service,
            1,
            TaskState::Pending,
            DesiredState::Running,
            SystemTime::now(),
        )
    }

    #[test]
    fn ready_filter_accepts_only_ready_active_nodes() {
        let filter = NodeReadyFilter;
        let cases = [
            (NodeState::Ready, Availability::Active, true),
            (NodeState::Ready, Availability::Pause, false),
            (NodeState::Ready, Availability::Drain, false),
            (NodeState::Down, Availability::Active, false),
            (NodeState::Unknown, Availability::Active, false),
            (NodeState::Disconnected, Availability::Active, false),
        ];
        for (state, availability, expected) in cases {
            let info = node_info(planted_node(state, availability));
            assert_eq!(
                filter.check(&info),
                expected,
                "{state:?} / {availability:?}"
            );
        }
        assert_eq!(filter.explain(1), "1 node not available for new tasks");
        assert_eq!(filter.explain(3), "3 nodes not available for new tasks");
    }

    #[test]
    fn resource_filter_is_disabled_without_reservations() {
        let mut filter = ResourceFilter::default();
        let mut task = pending_task();
        assert!(!filter.set_task(&task), "no resource requirements at all");

        reserve(&mut task, 0, 0);
        assert!(
            !filter.set_task(&task),
            "an all-zero reservation reserves nothing"
        );

        reserve(&mut task, 1, 0);
        assert!(filter.set_task(&task));
    }

    #[test]
    fn resource_filter_fits_reservations_into_what_is_left() {
        let node = NodeBuilder::new("alpha")
            .resources(4_000_000_000, gib(8))
            .build();
        let cases = [
            (0_i64, gib(1), true),
            (4_000_000_000, gib(8), true), // exactly the capacity fits
            (4_000_000_001, gib(8), false),
            (1_000_000_000, gib(9), false),
        ];
        for (nano_cpus, memory_bytes, expected) in cases {
            let mut task = pending_task();
            reserve(&mut task, nano_cpus, memory_bytes);
            let mut filter = ResourceFilter::default();
            assert!(filter.set_task(&task));
            let info = node_info(node.clone());
            assert_eq!(
                filter.check(&info),
                expected,
                "{nano_cpus} nanocpus / {memory_bytes} bytes"
            );
        }
        assert_eq!(
            ResourceFilter::default().explain(2),
            "insufficient resources on 2 nodes"
        );
    }

    #[test]
    fn resource_filter_counts_reservations_already_on_the_node() {
        let service = sample_service("web", 2);
        let mut running = planted_task(
            &service,
            1,
            TaskState::Running,
            DesiredState::Running,
            SystemTime::now(),
        );
        reserve(&mut running, 3_000_000_000, gib(6));

        let mut info = node_info(
            NodeBuilder::new("alpha")
                .resources(4_000_000_000, gib(8))
                .build(),
        );
        info.add_task(&Arc::new(running));

        let mut small = pending_task();
        reserve(&mut small, 1_000_000_000, gib(2));
        let mut filter = ResourceFilter::default();
        assert!(filter.set_task(&small));
        assert!(filter.check(&info), "1 CPU and 2 GiB are still free");

        let mut large = pending_task();
        reserve(&mut large, 2_000_000_000, gib(2));
        let mut filter = ResourceFilter::default();
        assert!(filter.set_task(&large));
        assert!(!filter.check(&info), "only 1 CPU is left");
    }

    #[test]
    fn constraint_filter_uses_the_expression_language() {
        let node = node_info(
            NodeBuilder::new("alpha")
                .label("zone", "a")
                .engine_label("tier", "ssd")
                .build(),
        );
        let cases = [
            (vec!["node.labels.zone == a"], true),
            (vec!["node.labels.zone == b"], false),
            (vec!["node.labels.zone != b"], true),
            (vec!["node.hostname == alpha"], true),
            (vec!["engine.labels.tier == ssd"], true),
            (
                vec!["node.labels.zone == a", "engine.labels.tier == hdd"],
                false,
            ),
            (
                vec!["node.labels.zone == a", "engine.labels.tier == ssd"],
                true,
            ),
        ];
        for (constraints, expected) in cases {
            let mut task = pending_task();
            task.spec.placement.constraints = constraints.iter().map(|c| (*c).to_owned()).collect();
            let mut filter = ConstraintFilter::default();
            assert!(filter.set_task(&task), "{constraints:?}");
            assert_eq!(filter.check(&node), expected, "{constraints:?}");
        }

        // No constraints: the filter does not apply at all.
        let mut filter = ConstraintFilter::default();
        assert!(!filter.set_task(&pending_task()));

        // Unparseable constraints disable the filter (validated at the API).
        let mut task = pending_task();
        task.spec.placement.constraints = vec!["node.labels.zone <> a".to_owned()];
        let mut filter = ConstraintFilter::default();
        assert!(!filter.set_task(&task));

        assert_eq!(
            ConstraintFilter::default().explain(1),
            "scheduling constraints not satisfied on 1 node"
        );
    }

    #[test]
    fn platform_filter_normalizes_and_wildcards() {
        let node =
            |os: &str, arch: &str| node_info(NodeBuilder::new("alpha").platform(os, arch).build());
        let platform = |os: &str, arch: &str| Platform {
            os: os.to_owned(),
            arch: arch.to_owned(),
        };
        let cases = [
            (vec![platform("freebsd", "amd64")], "freebsd", "amd64", true),
            (
                vec![platform("freebsd", "amd64")],
                "freebsd",
                "arm64",
                false,
            ),
            (vec![platform("linux", "amd64")], "freebsd", "amd64", false),
            // uname spellings normalise on both sides.
            (
                vec![platform("freebsd", "x86_64")],
                "freebsd",
                "amd64",
                true,
            ),
            (
                vec![platform("freebsd", "amd64")],
                "freebsd",
                "x86_64",
                true,
            ),
            (vec![platform("linux", "aarch64")], "linux", "arm64", true),
            // Empty fields are wildcards.
            (vec![platform("", "amd64")], "freebsd", "amd64", true),
            (vec![platform("freebsd", "")], "freebsd", "arm64", true),
            (vec![platform("", "")], "anything", "whatever", true),
            // Any entry matching is enough.
            (
                vec![platform("linux", "amd64"), platform("freebsd", "amd64")],
                "freebsd",
                "amd64",
                true,
            ),
        ];
        for (platforms, os, arch, expected) in cases {
            let mut task = pending_task();
            task.spec.placement.platforms.clone_from(&platforms);
            let mut filter = PlatformFilter::default();
            assert!(filter.set_task(&task), "{platforms:?}");
            assert_eq!(
                filter.check(&node(os, arch)),
                expected,
                "{platforms:?} vs {os}/{arch}"
            );
        }

        // An empty platform list disables the filter.
        let mut filter = PlatformFilter::default();
        assert!(!filter.set_task(&pending_task()));

        // A node that never described itself has no platform to match.
        let mut task = pending_task();
        task.spec.placement.platforms = vec![platform("freebsd", "amd64")];
        let mut filter = PlatformFilter::default();
        assert!(filter.set_task(&task));
        assert!(!filter.check(&node_info(
            NodeBuilder::new("alpha").no_description().build()
        )));

        assert_eq!(
            PlatformFilter::default().explain(2),
            "unsupported platform on 2 nodes"
        );
    }

    #[test]
    fn host_port_filter_rejects_conflicting_bindings() {
        let service = sample_service("web", 2);
        let now = SystemTime::now();
        let mut running = planted_task(&service, 1, TaskState::Running, DesiredState::Running, now);
        host_port(&mut running, PortProtocol::Tcp, 8080);
        let mut info = node_info(NodeBuilder::new("alpha").build());
        info.add_task(&Arc::new(running));

        // Same protocol and port: conflict.
        let mut task = pending_task();
        host_port(&mut task, PortProtocol::Tcp, 8080);
        let mut filter = HostPortFilter::default();
        assert!(filter.set_task(&task));
        assert!(!filter.check(&info));

        // Same port, other protocol: no conflict.
        let mut task = pending_task();
        host_port(&mut task, PortProtocol::Udp, 8080);
        let mut filter = HostPortFilter::default();
        assert!(filter.set_task(&task));
        assert!(filter.check(&info));

        // Another port entirely.
        let mut task = pending_task();
        host_port(&mut task, PortProtocol::Tcp, 8081);
        let mut filter = HostPortFilter::default();
        assert!(filter.set_task(&task));
        assert!(filter.check(&info));

        assert_eq!(
            HostPortFilter::default().explain(1),
            "host-mode port already in use on 1 node"
        );
    }

    #[test]
    fn host_port_filter_ignores_ingress_and_auto_assigned_ports() {
        let mut task = pending_task();
        // Ingress ports are allocated cluster-wide, not per node.
        task.endpoint = Some(satl_core::Endpoint {
            spec: satl_core::EndpointSpec::default(),
            ports: vec![satl_core::PortConfig {
                name: "http".to_owned(),
                protocol: PortProtocol::Tcp,
                target_port: 80,
                published_port: 8080,
                publish_mode: PublishMode::Ingress,
            }],
        });
        let mut filter = HostPortFilter::default();
        assert!(!filter.set_task(&task));

        // Host mode with published port 0 means "auto-assign": no conflict.
        host_port(&mut task, PortProtocol::Tcp, 0);
        let mut filter = HostPortFilter::default();
        assert!(!filter.set_task(&task));
    }

    #[test]
    fn max_replicas_filter_counts_active_tasks_of_the_service() {
        let service = sample_service("web", 4);
        let now = SystemTime::now();
        let mut info = node_info(NodeBuilder::new("alpha").build());
        let mut task = planted_task(&service, 1, TaskState::Pending, DesiredState::Running, now);
        task.spec.placement.max_replicas = 2;

        let mut filter = MaxReplicasFilter::default();
        assert!(filter.set_task(&task));
        assert!(filter.check(&info), "no tasks on the node yet");

        info.add_task(&Arc::new(planted_task(
            &service,
            2,
            TaskState::Running,
            DesiredState::Running,
            now,
        )));
        assert!(filter.check(&info), "1 < 2");

        info.add_task(&Arc::new(planted_task(
            &service,
            3,
            TaskState::Running,
            DesiredState::Running,
            now,
        )));
        assert!(!filter.check(&info), "2 is the limit");

        // Tasks of another service do not count.
        let other = sample_service("api", 1);
        let mut other_task =
            planted_task(&other, 1, TaskState::Pending, DesiredState::Running, now);
        other_task.spec.placement.max_replicas = 2;
        let mut filter = MaxReplicasFilter::default();
        assert!(filter.set_task(&other_task));
        assert!(filter.check(&info));

        // 0 means uncapped: the filter does not apply.
        let mut filter = MaxReplicasFilter::default();
        assert!(!filter.set_task(&pending_task()));

        assert_eq!(
            MaxReplicasFilter::default().explain(7),
            "max replicas per node limit exceed"
        );
    }

    #[test]
    fn pipeline_counts_rejections_and_explains_most_frequent_first() {
        let mut task = pending_task();
        reserve(&mut task, 8_000_000_000, gib(64));
        let mut pipeline = Pipeline::new();
        pipeline.set_task(&task);

        // One node is unavailable, two are too small.
        assert!(!pipeline.check(&node_info(planted_node(
            NodeState::Ready,
            Availability::Drain
        ))));
        for name in ["beta", "gamma"] {
            assert!(
                !pipeline.check(&node_info(
                    NodeBuilder::new(name)
                        .resources(1_000_000_000, gib(1))
                        .build()
                ))
            );
        }
        assert_eq!(
            pipeline.explain(),
            "insufficient resources on 2 nodes; 1 node not available for new tasks"
        );

        // A node that passes resets the counters.
        assert!(
            pipeline.check(&node_info(
                NodeBuilder::new("delta")
                    .resources(16_000_000_000, gib(128))
                    .build()
            ))
        );
        assert_eq!(pipeline.explain(), "no nodes in the cluster");
    }

    #[test]
    fn pipeline_short_circuits_on_the_first_failing_filter() {
        // A drained node that is also too small counts once, against Ready.
        let mut task = pending_task();
        reserve(&mut task, 8_000_000_000, gib(64));
        let mut pipeline = Pipeline::new();
        pipeline.set_task(&task);
        let node = NodeBuilder::new("alpha")
            .availability(Availability::Drain)
            .resources(1, 1)
            .build();
        assert!(!pipeline.check(&node_info(node)));
        assert_eq!(pipeline.explain(), "1 node not available for new tasks");
    }

    #[test]
    fn filters_report_their_names() {
        let names: Vec<&str> = Pipeline::new()
            .filters
            .iter()
            .map(|filter| filter.name())
            .collect();
        assert_eq!(
            names,
            [
                "ready",
                "resource",
                "constraint",
                "platform",
                "host-port",
                "max-replicas"
            ],
            "SWK §8.3 order"
        );
    }

    #[test]
    fn node_info_is_what_filters_see() {
        // Guards the trait shape: filters take NodeInfo, never the store.
        let info: NodeInfo = node_info(planted_node(NodeState::Ready, Availability::Active));
        let filter: Box<dyn Filter> = Box::new(NodeReadyFilter);
        assert!(filter.check(&info));
    }
}
