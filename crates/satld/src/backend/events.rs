// SPDX-License-Identifier: BSD-2-Clause
//! `GET /events`: the store watch feed, rendered as Docker events.
//!
//! Docker's event model is per-container lifecycle; SatL's is per-object
//! store transactions. The mapping is one-directional and lossy on purpose —
//! only the transitions a Docker client acts on are emitted (SWK's store
//! events carry far more):
//!
//! | store event | Docker event |
//! |---|---|
//! | task created | `container create` |
//! | task observed state reaches `RUNNING` | `container start` |
//! | task observed state becomes terminal | `container die` (+ `exitCode`) |
//! | task removed | `container destroy` |
//! | image pulled | `image pull` |
//! | image tagged | `image tag` |
//!
//! Image events do not come from the store (images are node-local, not
//! cluster objects), so the backend injects them on its own channel and the
//! two sources are merged.
//!
//! `?since=` is accepted and ignored: the store's watch feed is not
//! resumable in M1 (architecture §14, SWK §10) and no event history is kept.
//! Recorded in `docs/api-compat.md`.

use std::collections::BTreeMap;
use std::time::SystemTime;

use satl_api::model::{EventActor, EventMessage};
use satl_core::{ObjectKind, StoreEvent, StoreObject, Task, TaskState};

/// Docker's `scope` for events a single daemon produced.
const SCOPE: &str = "local";

/// Object kind of a container event.
const CONTAINER: &str = "container";

/// Object kind of an image event.
const IMAGE: &str = "image";

/// The attributes every container event carries.
fn container_actor(task: &Task) -> EventActor {
    let mut attributes = BTreeMap::from([
        ("name".to_owned(), super::names::container_name(task)),
        ("image".to_owned(), task.spec.container.image.clone()),
    ]);
    for (key, value) in &task.spec.container.labels {
        attributes.insert(key.clone(), value.clone());
    }
    EventActor {
        id: task.id.to_string(),
        attributes,
    }
}

/// A container event for `task`.
fn container_event(task: &Task, action: &str) -> EventMessage {
    EventMessage {
        kind: CONTAINER.to_owned(),
        action: action.to_owned(),
        actor: container_actor(task),
        scope: SCOPE.to_owned(),
        time: SystemTime::now(),
    }
}

/// The `image pull` event the backend injects after a successful pull.
#[must_use]
pub fn image_pull(reference: &str) -> EventMessage {
    image_event("pull", reference)
}

/// The `image tag` event the backend injects after a successful tag; the
/// actor is the *new* reference.
#[must_use]
pub fn image_tag(reference: &str) -> EventMessage {
    image_event("tag", reference)
}

/// The `image untag` event the backend injects when a record is forgotten,
/// by `satl images rm` or by the `-a` half of a prune. Docker emits `untag`
/// for exactly this, and it is what makes a removal visible in `satl events`.
#[must_use]
pub fn image_untag(reference: &str) -> EventMessage {
    image_event("untag", reference)
}

/// An image event for `reference` (pull, tag, untag) — node-local, so injected
/// by the backend rather than mapped from a store event.
fn image_event(action: &str, reference: &str) -> EventMessage {
    EventMessage {
        kind: IMAGE.to_owned(),
        action: action.to_owned(),
        actor: EventActor {
            id: reference.to_owned(),
            attributes: BTreeMap::from([("name".to_owned(), reference.to_owned())]),
        },
        scope: SCOPE.to_owned(),
        time: SystemTime::now(),
    }
}

/// Map one store event to a Docker event, if it is one a client cares about.
///
/// `Removed` carries no object, so a `destroy` event only knows the ID; the
/// caller supplies the last known task when it has one.
#[must_use]
pub fn from_store_event(event: &StoreEvent) -> Option<EventMessage> {
    match event {
        StoreEvent::Created(StoreObject::Task(task)) => Some(container_event(task, "create")),
        StoreEvent::Updated {
            old: Some(StoreObject::Task(old)),
            new: StoreObject::Task(new),
        } => transition_event(old.status.state, new),
        StoreEvent::Removed {
            kind: ObjectKind::Task,
            id,
        } => Some(EventMessage {
            kind: CONTAINER.to_owned(),
            action: "destroy".to_owned(),
            actor: EventActor {
                id: id.to_string(),
                attributes: BTreeMap::new(),
            },
            scope: SCOPE.to_owned(),
            time: SystemTime::now(),
        }),
        // Everything else — other object kinds, and updates whose previous
        // value is unavailable (snapshot replay), where there is no
        // transition to report.
        StoreEvent::Created(_)
        | StoreEvent::Updated { .. }
        | StoreEvent::Removed { .. }
        | StoreEvent::Commit(_) => None,
    }
}

/// The event a task's observed-state transition produces, if any.
fn transition_event(from: TaskState, new: &Task) -> Option<EventMessage> {
    let to = new.status.state;
    if to == from {
        return None;
    }
    if to == TaskState::Running {
        return Some(container_event(new, "start"));
    }
    if to.is_terminal() && !from.is_terminal() {
        let mut event = container_event(new, "die");
        let exit_code = new
            .status
            .container
            .as_ref()
            .and_then(|container| container.exit_code)
            .unwrap_or(0);
        event
            .actor
            .attributes
            .insert("exitCode".to_owned(), exit_code.to_string());
        return Some(event);
    }
    None
}

#[cfg(test)]
mod tests {
    use satl_core::{ContainerStatus, Id, StoreObject, TaskStatus, Version};

    use super::*;

    fn task(state: TaskState) -> Task {
        let mut task = crate::backend::tests::sample_task("web");
        task.status = TaskStatus::new(state, "test");
        task
    }

    fn updated(from: TaskState, to: TaskState) -> StoreEvent {
        let old = task(from);
        let mut new = old.clone();
        new.status = TaskStatus::new(to, "test");
        StoreEvent::Updated {
            old: Some(StoreObject::Task(old)),
            new: StoreObject::Task(new),
        }
    }

    #[test]
    fn task_creation_is_a_container_create() {
        let task = task(TaskState::New);
        let event = from_store_event(&StoreEvent::Created(StoreObject::Task(task.clone())))
            .expect("an event");
        assert_eq!(event.kind, "container");
        assert_eq!(event.action, "create");
        assert_eq!(event.actor.id, task.id.to_string());
        assert_eq!(
            event.actor.attributes.get("name").map(String::as_str),
            Some("web")
        );
        assert_eq!(event.scope, "local");
    }

    #[test]
    fn reaching_running_is_a_start() {
        let event =
            from_store_event(&updated(TaskState::Starting, TaskState::Running)).expect("an event");
        assert_eq!(event.action, "start");
    }

    #[test]
    fn intermediate_transitions_produce_nothing() {
        for (from, to) in [
            (TaskState::New, TaskState::Pending),
            (TaskState::Assigned, TaskState::Accepted),
            (TaskState::Preparing, TaskState::Ready),
            (TaskState::Ready, TaskState::Starting),
        ] {
            assert!(
                from_store_event(&updated(from, to)).is_none(),
                "{from} -> {to}"
            );
        }
        // A status re-report is not a transition.
        assert!(from_store_event(&updated(TaskState::Running, TaskState::Running)).is_none());
    }

    #[test]
    fn terminal_transitions_are_a_die_with_the_exit_code() {
        let old = task(TaskState::Running);
        let mut new = old.clone();
        new.status = TaskStatus::new(TaskState::Failed, "failed");
        new.status.container = Some(ContainerStatus {
            jail_id: Some(new.id.as_str().to_owned()),
            pid: Some(42),
            exit_code: Some(3),
        });
        let event = from_store_event(&StoreEvent::Updated {
            old: Some(StoreObject::Task(old)),
            new: StoreObject::Task(new),
        })
        .expect("an event");
        assert_eq!(event.action, "die");
        assert_eq!(
            event.actor.attributes.get("exitCode").map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn a_missing_exit_code_reports_zero() {
        let event =
            from_store_event(&updated(TaskState::Running, TaskState::Complete)).expect("an event");
        assert_eq!(
            event.actor.attributes.get("exitCode").map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn task_removal_is_a_destroy() {
        let id = Id::generate();
        let event = from_store_event(&StoreEvent::Removed {
            kind: ObjectKind::Task,
            id: id.clone(),
        })
        .expect("an event");
        assert_eq!(event.action, "destroy");
        assert_eq!(event.actor.id, id.to_string());
    }

    #[test]
    fn non_task_events_are_ignored() {
        assert!(from_store_event(&StoreEvent::Commit(Version(7))).is_none());
        assert!(
            from_store_event(&StoreEvent::Removed {
                kind: ObjectKind::Service,
                id: Id::generate(),
            })
            .is_none()
        );
    }

    #[test]
    fn image_pulls_are_image_events() {
        let event = image_pull("docker.io/library/nginx:1.27");
        assert_eq!(event.kind, "image");
        assert_eq!(event.action, "pull");
        assert_eq!(event.actor.id, "docker.io/library/nginx:1.27");
    }

    #[test]
    fn image_tags_are_image_events() {
        let event = image_tag("registry.example.com/mirror/nginx:1.27");
        assert_eq!(event.kind, "image");
        assert_eq!(event.action, "tag");
        assert_eq!(event.actor.id, "registry.example.com/mirror/nginx:1.27");
        assert_eq!(
            event.actor.attributes["name"],
            "registry.example.com/mirror/nginx:1.27"
        );
    }
}
