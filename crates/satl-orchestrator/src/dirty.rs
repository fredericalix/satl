// SPDX-License-Identifier: BSD-2-Clause
//! Dirtiness: which tasks of a service are not on its current spec
//! (SWK §7.2).
//!
//! This is the question the rolling updater is built on, and the one place a
//! wrong answer is expensive in both directions: a false "dirty" replaces
//! running containers for nothing, a false "clean" leaves a service on an old
//! image and reports success.
//!
//! # The asymmetry of the version fast path
//!
//! [`Service::spec_version`] moves only when the spec does, and
//! [`Task::spec_version`] records the value a task was stamped from (the
//! contract pinned in `4116ab6`). That makes equality a fast path for **clean
//! only**:
//!
//! - equal versions ⇒ the task was stamped from exactly this spec ⇒ clean, and
//!   the deep comparison is skipped;
//! - unequal versions prove **nothing**. A task written before the field
//!   existed carries `None`; a spec that changed and changed back leaves every
//!   task on an older version with an identical spec. Both land here, and the
//!   deep comparison decides.
//!
//! Reading it the other way round (unequal ⇒ dirty) would mark every
//! pre-existing task dirty and roll every service once, forever.
//!
//! # SwarmKit's exemptions, and which ones SatL has
//!
//! - **placement-only changes take the placement fast path** (rule 2): when
//!   the only difference is [`Placement`] and the node the task already runs
//!   on still satisfies the new constraints, the task is kept. Replacing it
//!   would move nothing — and the constraint enforcer (SWK §7.6) is the
//!   component that evicts a task whose node stopped qualifying.
//! - **resources-only changes are re-applied, not rolled** (rule 3, M6g):
//!   rctl limits attach to the jail, not the container, so a new memory or
//!   CPU cap is written to the live jail by [`crate::update`]'s in-place
//!   resize and the task keeps serving. Docker's own vertical scaling of a
//!   running container (`docker update`) is the same non-event; rolling a
//!   database for a memory cap is an incident.
//! - **pull options are not a respec** for a task that already pulled its
//!   image: a registry-credential rotation must not restart the world.
//! - `TaskSpec::force_update` participates in the deep comparison, so bumping
//!   it dirties every task of the service. That is its only purpose.
//!
//! SwarmKit's list also exempts things SatL has no equivalent for, so they are
//! absent rather than unimplemented: per-service **log drivers** (rejected by
//! the API, `docs/api-compat.md`), **generic resources**, **CSI volumes** and
//! **job iterations** (all deferred, architecture §14).

use satl_core::{Constraints, EndpointSpec, Node, Service, Task, TaskSpec, TaskState};

/// Whether `task` must be replaced to bring its service to the current spec
/// (SWK §7.2 `IsTaskDirty`).
///
/// `node` is the node the task is bound to, when it is bound and the node
/// still exists; it is only read by the placement fast path.
pub(crate) fn is_task_dirty(service: &Service, task: &Task, node: Option<&Node>) -> bool {
    // Rule 1 — the fast path, and clean only (see the module docs).
    if task.spec_version == Some(service.spec_version) {
        return false;
    }

    let wanted = &service.spec.task;
    let ignore_pull_options = already_pulled(task);

    // Rule 2 — only the placement changed, and the node still qualifies.
    // "Only" includes the endpoint: a port change rides no exemption.
    if placement_only_change(&task.spec, wanted, ignore_pull_options)
        && node_satisfies(wanted, node)
        && !endpoint_changed(service, task)
    {
        return false;
    }

    // Rule 3 — only the resources changed: rctl re-applies to the live jail
    // (M6g), no replacement. The resize itself is the updater's in-place
    // mutation; a database is not rolled for a memory cap.
    if resources_only_change(&task.spec, wanted, ignore_pull_options)
        && !endpoint_changed(service, task)
    {
        return false;
    }

    // Rule 4 — the deep comparison decides.
    !specs_match(&task.spec, wanted, ignore_pull_options) || endpoint_changed(service, task)
}

/// Whether two task specs are the same workload, optionally ignoring the
/// image pull options (SWK §7.2's `PullOptions` exemption).
fn specs_match(task_spec: &TaskSpec, wanted: &TaskSpec, ignore_pull_options: bool) -> bool {
    if !ignore_pull_options {
        return task_spec == wanted;
    }
    let mut probe = task_spec.clone();
    probe
        .container
        .pull_options
        .clone_from(&wanted.container.pull_options);
    probe == *wanted
}

/// Whether [`Placement`] is the *only* difference between the task's spec and
/// the service's.
///
/// The pull-options exemption is applied here too, so a task that already
/// pulled its image and differs in placement plus registry credentials still
/// takes the placement path. SwarmKit checks placement before applying that
/// exemption and would call such a task dirty; the exemption's reason ("a
/// credential rotation must not restart the world") applies to both rules, and
/// applying it once, consistently, is the smaller surprise.
///
/// [`Placement`]: satl_core::Placement
fn placement_only_change(
    task_spec: &TaskSpec,
    wanted: &TaskSpec,
    ignore_pull_options: bool,
) -> bool {
    if task_spec.placement == wanted.placement {
        return false;
    }
    let mut probe = task_spec.clone();
    probe.placement = wanted.placement.clone();
    specs_match(&probe, wanted, ignore_pull_options)
}

/// Whether [`ResourceRequirements`] is the *only* difference between the
/// task's spec and the service's (M6g). Such a task is not dirty — rctl
/// limits are re-applied to the live jail — but it is not fully converged
/// either: [`crate::update`] detects the same condition to push the new
/// resources into the task in place. Keeping the two on one predicate is
/// what guarantees a task the updater resizes is a task the roller would
/// have replaced without the exemption.
///
/// [`ResourceRequirements`]: satl_core::ResourceRequirements
pub(crate) fn resources_only_change(
    task_spec: &TaskSpec,
    wanted: &TaskSpec,
    ignore_pull_options: bool,
) -> bool {
    if task_spec.resources == wanted.resources {
        return false;
    }
    let mut probe = task_spec.clone();
    probe.resources = wanted.resources;
    specs_match(&probe, wanted, ignore_pull_options)
}

/// Whether `node` still satisfies the constraints of the *service's current*
/// placement.
///
/// Shared with the constraint enforcer
/// ([`crate::node_enforcer::constraints_unmet`]), which asks the same question
/// about a task whose *node* changed rather than whose service did — one
/// implementation, because a disagreement between them would mean a task the
/// updater keeps and the enforcer evicts.
///
/// An unbound task (no node yet) is not held back by this: it has not been
/// placed, so the scheduler will apply the new constraints itself. A task
/// bound to a node that is gone from the store is not kept — the restart
/// supervisor owns that case (SWK §7.8) and a replacement is coming anyway.
///
/// An unparseable constraint expression is treated as satisfied, exactly as
/// the scheduler's [`ConstraintFilter`] treats it: the parse error was
/// reported to the operator when they wrote it, and refusing every node here
/// would replace every task of the service for a typo.
///
/// [`ConstraintFilter`]: https://docs.rs/satl-sched
pub(crate) fn node_satisfies(wanted: &TaskSpec, node: Option<&Node>) -> bool {
    let expressions = &wanted.placement.constraints;
    if expressions.is_empty() {
        return true;
    }
    let Some(node) = node else {
        return false;
    };
    match Constraints::parse_all(expressions) {
        Ok(constraints) => constraints.matches(node),
        Err(error) => {
            tracing::warn!(
                node_id = %node.id,
                %error,
                "unparseable placement constraint treated as satisfied"
            );
            true
        }
    }
}

/// Whether the task's copy of the endpoint spec differs from the service's
/// (SWK §7.2 rule 3, second half): a published port added, removed or
/// renumbered has to reach the tasks.
///
/// A missing endpoint spec and an empty one are the same request — the
/// allocator already treats them alike (`plan_endpoint` allocates nothing for
/// either) — so the comparison normalises `None` rather than calling a service
/// dirty for gaining an endpoint spec that asks for nothing.
fn endpoint_changed(service: &Service, task: &Task) -> bool {
    let empty = EndpointSpec::default();
    let wanted = service.spec.endpoint.as_ref().unwrap_or(&empty);
    let carried = task
        .endpoint
        .as_ref()
        .map_or(&empty, |endpoint| &endpoint.spec);
    carried != wanted
}

/// Whether the task has already pulled its image, in SwarmKit's exact terms:
/// observed `READY <= state <= RUNNING` and desired `<= RUNNING`.
///
/// Below `READY` the image is not on the node yet, so new pull options are
/// what the pull will use and changing them is a real respec. Above `RUNNING`
/// the task is finished and nothing is being kept.
fn already_pulled(task: &Task) -> bool {
    (TaskState::Ready..=TaskState::Running).contains(&task.status.state)
        && task.desired_state <= satl_core::DesiredState::Running
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use satl_core::{
        Availability, DesiredState, EndpointMode, Id, NodeState, PullOptions, Version,
    };

    use crate::testing::{planted_node, planted_task, sample_service, with_published_port};

    use super::*;

    /// A task stamped from `service`'s current spec, in the given observed
    /// state — the shape the fast path and the exemptions are judged on.
    fn stamped(service: &Service, state: TaskState) -> Task {
        let mut task = planted_task(service, 1, state, DesiredState::Running, SystemTime::now());
        task.spec = service.spec.task.clone();
        task.spec_version = Some(service.spec_version);
        task.endpoint = service
            .spec
            .endpoint
            .clone()
            .map(|spec| satl_core::Endpoint {
                spec,
                ports: Vec::new(),
            });
        task
    }

    /// The same task, but stamped from a *different* spec version, so every
    /// case below goes through the deep comparison rather than the fast path.
    fn stale_stamp(task: &mut Task) {
        task.spec_version = Some(Version(1));
    }

    #[test]
    fn equal_spec_versions_are_clean_whatever_the_specs_say() {
        let mut service = sample_service("web", 1);
        service.spec_version = Version(7);
        let mut task = stamped(&service, TaskState::Running);
        // A spec that could not be more different: the fast path must still win,
        // because equal versions mean the task *was* stamped from this spec and
        // a divergence here is a bug elsewhere, not a reason to roll.
        task.spec.container.image = "totally-different:9".to_owned();
        assert!(!is_task_dirty(&service, &task, None));
    }

    #[test]
    fn unequal_spec_versions_alone_prove_nothing() {
        let mut service = sample_service("web", 1);
        service.spec_version = Version(7);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        assert!(
            !is_task_dirty(&service, &task, None),
            "same spec under an older version is clean: this is the trap"
        );
        // And a task written before the field existed.
        task.spec_version = None;
        assert!(!is_task_dirty(&service, &task, None));
    }

    #[test]
    fn a_changed_image_is_dirty() {
        let service = sample_service("web", 1);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.container.image = "127.0.0.1:5000/freebsd-nginx:0".to_owned();
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn force_update_dirties_everything() {
        let mut service = sample_service("web", 1);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        service.spec.task.force_update = 1;
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn pull_options_are_exempt_once_the_image_is_on_the_node() {
        let mut service = sample_service("web", 1);
        service.spec.task.container.pull_options = Some(PullOptions {
            registry_auth: "rotated".to_owned(),
        });

        // Already pulled: READY <= observed <= RUNNING, desired <= RUNNING.
        for state in [TaskState::Ready, TaskState::Starting, TaskState::Running] {
            let mut task = stamped(&service, state);
            stale_stamp(&mut task);
            task.spec.container.pull_options = None;
            assert!(
                !is_task_dirty(&service, &task, None),
                "{state}: a credential rotation must not restart the world"
            );
        }

        // Not pulled yet: the new options are the ones the pull will use.
        for state in [TaskState::New, TaskState::Pending, TaskState::Preparing] {
            let mut task = stamped(&service, state);
            stale_stamp(&mut task);
            task.spec.container.pull_options = None;
            assert!(is_task_dirty(&service, &task, None), "{state}");
        }

        // Finished: nothing is being kept.
        let mut task = stamped(&service, TaskState::Complete);
        stale_stamp(&mut task);
        task.spec.container.pull_options = None;
        assert!(is_task_dirty(&service, &task, None));

        // On its way out: same.
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.desired_state = DesiredState::Shutdown;
        task.spec.container.pull_options = None;
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn an_image_change_is_dirty_even_for_a_pulled_task() {
        let mut service = sample_service("web", 1);
        service.spec.task.container.pull_options = Some(PullOptions {
            registry_auth: "rotated".to_owned(),
        });
        service.spec.task.container.image = "next:2".to_owned();
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.container.pull_options = None;
        task.spec.container.image = "next:1".to_owned();
        assert!(
            is_task_dirty(&service, &task, None),
            "the exemption covers the credentials, never the image"
        );
    }

    #[test]
    fn a_placement_only_change_keeps_a_task_whose_node_still_qualifies() {
        let mut service = sample_service("web", 1);
        let node = planted_node("node1");
        service.spec.task.placement.constraints = vec!["node.hostname == node1".to_owned()];

        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.node_id = Some(node.id.clone());

        assert!(
            !is_task_dirty(&service, &task, Some(&node)),
            "the node the task already runs on satisfies the new constraint"
        );
    }

    #[test]
    fn a_placement_only_change_replaces_a_task_whose_node_no_longer_qualifies() {
        let mut service = sample_service("web", 1);
        let node = planted_node("node1");
        service.spec.task.placement.constraints = vec!["node.hostname == node2".to_owned()];

        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.node_id = Some(node.id.clone());

        assert!(is_task_dirty(&service, &task, Some(&node)));
        assert!(
            is_task_dirty(&service, &task, None),
            "a task bound to a node the store no longer has is not kept"
        );
    }

    #[test]
    fn a_placement_change_plus_another_change_is_dirty_whatever_the_node_says() {
        let mut service = sample_service("web", 1);
        let node = planted_node("node1");
        service.spec.task.placement.constraints = vec!["node.hostname == node1".to_owned()];
        service.spec.task.container.image = "next:2".to_owned();

        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.spec.container.image = "next:1".to_owned();
        task.node_id = Some(node.id.clone());

        assert!(is_task_dirty(&service, &task, Some(&node)));
    }

    #[test]
    fn an_unschedulable_node_does_not_make_a_placement_change_clean() {
        let mut service = sample_service("web", 1);
        let mut node = planted_node("node1");
        node.status.state = NodeState::Down;
        node.spec.availability = Availability::Drain;
        // The constraint matches the node, and node state is deliberately not
        // part of the question: a task on a down node is the restart
        // supervisor's business (SWK §7.8), and replacing it *as dirty* would
        // spend the update's failure budget on a node failure.
        service.spec.task.placement.constraints = vec!["node.hostname == node1".to_owned()];
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.node_id = Some(node.id.clone());
        assert!(!is_task_dirty(&service, &task, Some(&node)));
    }

    #[test]
    fn an_unparseable_constraint_keeps_the_task() {
        let mut service = sample_service("web", 1);
        let node = planted_node("node1");
        service.spec.task.placement.constraints = vec!["this is not an expression".to_owned()];
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.node_id = Some(node.id.clone());
        assert!(!is_task_dirty(&service, &task, Some(&node)));
    }

    #[test]
    fn a_changed_endpoint_spec_is_dirty() {
        let service = with_published_port(sample_service("web", 1), "http", 80, 8080);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        // The task carries the port it was created with; the service now asks
        // for another one.
        let mut carried = service.spec.endpoint.clone().expect("endpoint");
        carried.ports[0].published_port = 8081;
        task.endpoint = Some(satl_core::Endpoint {
            spec: carried,
            ports: Vec::new(),
        });
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn an_allocated_endpoint_is_not_a_change() {
        let service = with_published_port(sample_service("web", 1), "http", 80, 8080);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        // What the allocator writes: the same spec, plus the ports it assigned.
        task.endpoint = Some(satl_core::Endpoint {
            spec: service.spec.endpoint.clone().expect("endpoint"),
            ports: service.spec.endpoint.clone().expect("endpoint").ports,
        });
        assert!(
            !is_task_dirty(&service, &task, None),
            "the allocated ports are not part of the request"
        );
    }

    #[test]
    fn a_missing_endpoint_spec_and_an_empty_one_are_the_same_request() {
        let mut service = sample_service("web", 1);
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        assert!(task.endpoint.is_none());
        service.spec.endpoint = Some(EndpointSpec {
            mode: EndpointMode::DnsRR,
            ports: Vec::new(),
        });
        assert!(!is_task_dirty(&service, &task, None));
    }

    #[test]
    fn a_resources_only_change_is_clean() {
        // M6g: the hot-resize exemption — rctl re-applies to the live jail,
        // the task is not rolled.
        let mut service = sample_service("web", 1);
        service.spec.task.resources.limits = Some(satl_core::Resources {
            nano_cpus: 0,
            memory_bytes: 256 * 1024 * 1024,
        });
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.resources.limits = Some(satl_core::Resources {
            nano_cpus: 0,
            memory_bytes: 128 * 1024 * 1024,
        });
        assert!(!is_task_dirty(&service, &task, None));
        // And reservations alone are the same non-event.
        service.spec.task.resources.reservations = Some(satl_core::Resources {
            nano_cpus: 500_000_000,
            memory_bytes: 0,
        });
        assert!(!is_task_dirty(&service, &task, None));
    }

    #[test]
    fn a_resources_change_plus_another_change_is_dirty() {
        let mut service = sample_service("web", 1);
        service.spec.task.resources.limits = Some(satl_core::Resources {
            nano_cpus: 0,
            memory_bytes: 256 * 1024 * 1024,
        });
        service.spec.task.container.image = "next:2".to_owned();
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.resources.limits = None;
        task.spec.container.image = "next:1".to_owned();
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn a_resources_only_change_with_an_endpoint_change_is_dirty() {
        // "Only" includes the endpoint: a port change rides no exemption.
        let mut service = with_published_port(sample_service("web", 1), "http", 80, 8080);
        service.spec.task.resources.limits = Some(satl_core::Resources {
            nano_cpus: 0,
            memory_bytes: 256 * 1024 * 1024,
        });
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.resources.limits = None;
        let mut carried = service.spec.endpoint.clone().expect("endpoint");
        carried.ports[0].published_port = 8081;
        task.endpoint = Some(satl_core::Endpoint {
            spec: carried,
            ports: Vec::new(),
        });
        assert!(is_task_dirty(&service, &task, None));
    }

    #[test]
    fn a_placement_only_change_with_an_endpoint_change_is_dirty() {
        // The same guard on the placement exemption: placement masking must
        // not hide a port change behind a qualifying node.
        let node = planted_node("node1");
        let mut service = with_published_port(sample_service("web", 1), "http", 80, 8080);
        service.spec.task.placement.constraints = vec!["node.hostname == node1".to_owned()];
        let mut task = stamped(&service, TaskState::Running);
        stale_stamp(&mut task);
        task.spec.placement.constraints.clear();
        task.node_id = Some(node.id.clone());
        let mut carried = service.spec.endpoint.clone().expect("endpoint");
        carried.ports[0].published_port = 8081;
        task.endpoint = Some(satl_core::Endpoint {
            spec: carried,
            ports: Vec::new(),
        });
        assert!(is_task_dirty(&service, &task, Some(&node)));
    }

    #[test]
    fn a_task_of_another_service_is_judged_on_its_own_spec() {
        // Sanity: `is_task_dirty` never looks at service_id. The caller filters.
        let service = sample_service("web", 1);
        let other = sample_service("api", 1);
        let mut task = stamped(&other, TaskState::Running);
        task.spec_version = Some(Version(1));
        task.service_id = Some(Id::generate());
        assert!(!is_task_dirty(&service, &task, None), "same task spec");
    }
}
