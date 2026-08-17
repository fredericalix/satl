// SPDX-License-Identifier: BSD-2-Clause
//! Container naming and identifier resolution.
//!
//! A SatL container is a Task of a single-replica anonymous service
//! (invariant #2), so the Docker-visible identifiers map like this:
//!
//! | Docker | SatL |
//! |---|---|
//! | container ID | Task ID (25-char base36) |
//! | container name | Service name |
//!
//! Resolution accepts all three forms Docker accepts — full ID, unambiguous
//! ID prefix, name — and is the single place that knows a service may own
//! more than one task: a restart policy replaces a terminated task with a new
//! one in the same slot and the reaper keeps a bounded history (SWK §4.6), so
//! "the container called `web`" means *its newest task*.

use std::sync::Arc;

use satl_api::model::BackendError;
use satl_cluster::StoreView;
use satl_core::{DesiredState, Id, Service, Task};

/// Docker-style name halves. Two 32-word lists give 1024 combinations, which
/// is plenty for a node-local daemon that retries on collision.
const ADJECTIVES: [&str; 32] = [
    "admiring",
    "amazing",
    "blissful",
    "bold",
    "brave",
    "clever",
    "cool",
    "dazzling",
    "eager",
    "elastic",
    "focused",
    "friendly",
    "gallant",
    "gifted",
    "happy",
    "hopeful",
    "jolly",
    "keen",
    "kind",
    "laughing",
    "lucid",
    "modest",
    "nifty",
    "optimistic",
    "peaceful",
    "quirky",
    "relaxed",
    "serene",
    "sharp",
    "tender",
    "vibrant",
    "zealous",
];

/// Surnames of people who did notable work on operating systems, filesystems
/// and networking — Docker's convention, with a FreeBSD accent.
const SURNAMES: [&str; 32] = [
    "bostic",
    "cheriton",
    "clarke",
    "dijkstra",
    "engelbart",
    "hamming",
    "hopper",
    "joy",
    "kamp",
    "karels",
    "kernighan",
    "knuth",
    "lamport",
    "leffler",
    "liskov",
    "lovelace",
    "mckusick",
    "moore",
    "nelson",
    "newton",
    "noether",
    "perlman",
    "postel",
    "rhodes",
    "ritchie",
    "shannon",
    "thompson",
    "torek",
    "turing",
    "watson",
    "wilson",
    "zuse",
];

/// The `<adjective>_<surname>` name at a pair of indices (wrapping).
#[must_use]
pub fn name_at(adjective: usize, surname: usize) -> String {
    format!(
        "{}_{}",
        ADJECTIVES[adjective % ADJECTIVES.len()],
        SURNAMES[surname % SURNAMES.len()]
    )
}

/// A weak, dependency-free source of variation: the wall clock's nanosecond
/// field mixed with a process-wide counter. Name generation only needs
/// "usually different"; collisions are resolved by `taken` below.
fn spin() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as usize);
    nanos.wrapping_add(COUNTER.fetch_add(0x9E37_79B9, Ordering::Relaxed))
}

/// Generate a container name no one has taken yet.
///
/// Tries `<adjective>_<surname>` combinations first and falls back to a
/// numeric suffix, which keeps the name valid under the service naming rule
/// (`satl_core::naming`: alphanumeric first and last character).
pub fn generate_name(mut taken: impl FnMut(&str) -> bool) -> String {
    for attempt in 0..64 {
        let seed = spin().wrapping_add(attempt);
        let name = name_at(seed, seed / ADJECTIVES.len() + attempt);
        if !taken(&name) {
            return name;
        }
    }
    // Pathological: every tried combination exists. Suffix until it does not.
    let base = name_at(spin(), spin() / ADJECTIVES.len());
    for suffix in 1..u32::MAX {
        let name = format!("{base}{suffix}");
        if !taken(&name) {
            return name;
        }
    }
    base
}

/// Whether a task is on its way out (the reaper will delete it).
#[must_use]
pub fn is_removing(task: &Task) -> bool {
    task.desired_state == DesiredState::Remove
}

/// Sort key picking the task a Docker client means when it names a service:
/// prefer one that is not being removed, then the most recently created.
fn freshness(task: &Task) -> (bool, std::time::SystemTime, &str) {
    (!is_removing(task), task.meta.created_at, task.id.as_str())
}

/// The newest task among `tasks` (see [`freshness`]).
#[must_use]
pub fn newest(tasks: &[Arc<Task>]) -> Option<Arc<Task>> {
    tasks
        .iter()
        .max_by(|a, b| freshness(a).cmp(&freshness(b)))
        .map(Arc::clone)
}

/// Every task of `service`.
#[must_use]
pub fn tasks_of(view: &StoreView<'_>, service: &Id) -> Vec<Arc<Task>> {
    view.tasks()
        .into_iter()
        .filter(|task| task.service_id.as_ref() == Some(service))
        .collect()
}

/// The container rows a Docker client should see: the newest task of every
/// `(service, slot)` pair, paired with its service.
///
/// Restart history would otherwise show up as several containers with the
/// same name (a deviation recorded in `docs/api-compat.md`).
#[must_use]
pub fn visible_containers(view: &StoreView<'_>) -> Vec<(Arc<Service>, Arc<Task>)> {
    let mut rows: Vec<(Arc<Service>, Arc<Task>)> = Vec::new();
    for service in view.services() {
        let tasks = tasks_of(view, &service.id);
        let mut slots: Vec<u64> = tasks.iter().map(|task| task.slot).collect();
        slots.sort_unstable();
        slots.dedup();
        for slot in slots {
            let in_slot: Vec<Arc<Task>> = tasks
                .iter()
                .filter(|task| task.slot == slot)
                .map(Arc::clone)
                .collect();
            if let Some(task) = newest(&in_slot) {
                rows.push((Arc::clone(&service), task));
            }
        }
    }
    rows
}

/// Resolve a Docker container reference to a task.
///
/// Order: exact task ID, then service name, then unambiguous ID prefix — the
/// order Docker resolves in, so a name can never be shadowed by a prefix.
pub fn resolve_task(view: &StoreView<'_>, reference: &str) -> Result<Arc<Task>, BackendError> {
    let reference = reference.trim().trim_start_matches('/');
    if reference.is_empty() {
        return Err(BackendError::not_found("No such container: "));
    }

    if let Ok(id) = reference.parse::<Id>()
        && let Some(task) = view.task(&id)
    {
        return Ok(task);
    }

    if let Some(service) = view.service_by_name(reference)
        && let Some(task) = newest(&tasks_of(view, &service.id))
    {
        return Ok(task);
    }

    let mut matches: Vec<Arc<Task>> = view
        .tasks()
        .into_iter()
        .filter(|task| task.id.as_str().starts_with(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "No such container: {reference}"
        ))),
        1 => Ok(matches.remove(0)),
        n => Err(BackendError::conflict(format!(
            "multiple IDs found with provided prefix: {reference} ({n} containers)"
        ))),
    }
}

/// Resolve a `docker service` reference: exact ID, then name, then an
/// unambiguous ID prefix — the same order (and for the same reason) as
/// [`resolve_task`].
pub fn resolve_service(view: &StoreView<'_>, reference: &str) -> Result<Service, BackendError> {
    let reference = reference.trim();
    if reference.is_empty() {
        return Err(BackendError::not_found("no service id or name given"));
    }
    if let Ok(id) = reference.parse::<Id>()
        && let Some(service) = view.service(&id)
    {
        return Ok((*service).clone());
    }
    if let Some(service) = view.service_by_name(reference) {
        return Ok((*service).clone());
    }
    let matches: Vec<Arc<Service>> = view
        .services()
        .into_iter()
        .filter(|service| service.id.as_str().starts_with(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "service {reference} not found"
        ))),
        1 => Ok((*matches[0]).clone()),
        n => Err(BackendError::conflict(format!(
            "multiple services found with provided prefix: {reference} ({n} services)"
        ))),
    }
}

/// Resolve a reference to a task and its owning service.
pub fn resolve(
    view: &StoreView<'_>,
    reference: &str,
) -> Result<(Arc<Task>, Option<Arc<Service>>), BackendError> {
    let task = resolve_task(view, reference)?;
    let service = task
        .service_id
        .as_ref()
        .and_then(|id| view.service(id))
        .clone();
    Ok((task, service))
}

/// [`resolve_task`] over a plain task list — the worker path, where the
/// containers this node can name are exactly the tasks its local DB records
/// (a worker holds no store and no service objects).
///
/// Same order as the store variant: exact task ID, container name (the
/// owning service's name travels on the task), then unambiguous ID prefix.
pub fn resolve_local(tasks: &[Task], reference: &str) -> Result<Task, BackendError> {
    let reference = reference.trim().trim_start_matches('/');
    if reference.is_empty() {
        return Err(BackendError::not_found("No such container: "));
    }
    if let Some(task) = tasks.iter().find(|task| task.id.as_str() == reference) {
        return Ok(task.clone());
    }
    let named: Vec<&Task> = tasks
        .iter()
        .filter(|task| container_name(task) == reference || task.annotations.name == reference)
        .collect();
    if !named.is_empty() {
        // Several tasks of one service on one node share the service name;
        // the newest is the one `docker ps` shows (api-compat #34).
        let arcs: Vec<Arc<Task>> = named.into_iter().cloned().map(Arc::new).collect();
        if let Some(task) = newest(&arcs) {
            return Ok((*task).clone());
        }
    }
    let mut matches: Vec<&Task> = tasks
        .iter()
        .filter(|task| task.id.as_str().starts_with(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "No such container: {reference}"
        ))),
        1 => Ok(matches.remove(0).clone()),
        n => Err(BackendError::conflict(format!(
            "multiple IDs found with provided prefix: {reference} ({n} containers)"
        ))),
    }
}

/// The container name of a task: its service's name (SatL has no separate
/// container object), falling back to the task's own name.
#[must_use]
pub fn container_name(task: &Task) -> String {
    if task.service_annotations.name.is_empty() {
        task.annotations.name.clone()
    } else {
        task.service_annotations.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime};

    use satl_core::{Annotations, Meta, TaskState, TaskStatus};

    use super::*;

    fn task(created: SystemTime, desired: DesiredState) -> Task {
        let id = Id::generate();
        Task {
            annotations: Annotations::default(),
            meta: Meta {
                created_at: created,
                ..Meta::new()
            },
            spec: crate::backend::tests::empty_task_spec(),
            spec_version: None,
            service_id: None,
            slot: 1,
            node_id: None,
            service_annotations: Annotations::default(),
            status: TaskStatus::new(TaskState::Running, "test"),
            desired_state: desired,
            networks: Vec::new(),
            endpoint: None,
            job_iteration: None,
            id,
        }
    }

    #[test]
    fn generated_names_are_valid_service_names() {
        for _ in 0..200 {
            let name = generate_name(|_| false);
            satl_core::naming::validate_service_name(&name)
                .unwrap_or_else(|err| panic!("{name} is not a valid service name: {err}"));
            assert!(name.contains('_'), "{name}");
        }
    }

    #[test]
    fn generation_avoids_taken_names_and_still_validates() {
        // Everything without a digit is taken: the suffix path must run.
        let name = generate_name(|candidate| !candidate.chars().any(|c| c.is_ascii_digit()));
        assert!(name.chars().any(|c| c.is_ascii_digit()), "{name}");
        satl_core::naming::validate_service_name(&name).expect("suffixed name is still valid");
    }

    #[test]
    fn generation_is_usually_varied() {
        let names: BTreeSet<String> = (0..50).map(|_| generate_name(|_| false)).collect();
        assert!(names.len() > 20, "names barely varied: {names:?}");
    }

    #[test]
    fn name_at_wraps_both_halves() {
        assert_eq!(name_at(0, 0), "admiring_bostic");
        assert_eq!(name_at(ADJECTIVES.len(), SURNAMES.len()), "admiring_bostic");
    }

    #[test]
    fn newest_prefers_live_tasks_then_the_latest() {
        let base = SystemTime::now();
        let old = task(base, DesiredState::Running);
        let new = task(base + Duration::from_secs(10), DesiredState::Running);
        let newest_removing = task(base + Duration::from_secs(20), DesiredState::Remove);
        let tasks = vec![
            Arc::new(old.clone()),
            Arc::new(newest_removing),
            Arc::new(new.clone()),
        ];
        assert_eq!(newest(&tasks).expect("a task").id, new.id);

        // With nothing live, the newest removing task is still an answer.
        let only_removing = vec![Arc::new(task(base, DesiredState::Remove))];
        assert!(newest(&only_removing).is_some());
        assert!(newest(&[]).is_none());
    }

    #[test]
    fn container_name_prefers_the_service_name() {
        let mut task = task(SystemTime::now(), DesiredState::Running);
        task.annotations.name = "web.1.abc".to_owned();
        assert_eq!(container_name(&task), "web.1.abc");
        task.service_annotations.name = "web".to_owned();
        assert_eq!(container_name(&task), "web");
    }
}
