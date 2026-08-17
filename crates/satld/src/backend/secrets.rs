// SPDX-License-Identifier: BSD-2-Clause
//! The `/secrets` and `/configs` half of the REST backend (architecture
//! §12.4, SWK §3.8; Docker Engine API v1.43).
//!
//! Both object kinds live in one module because they are the same object with
//! one difference — a secret's payload never leaves the store through the API
//! (invariant #7) while a config's does — and every rule below applies to
//! both:
//!
//! - **reads are local, writes go to the leader**, as everywhere else in this
//!   backend (`swarm.rs`); a worker gets the Docker 503 refusal from
//!   [`DaemonBackend::manager`].
//! - **a payload is never logged.** These handlers log names, IDs and byte
//!   counts. `SecretSpec`'s `Debug` redacts its data, so even a `?spec` in a
//!   future span cannot leak one; the discipline here is to never reach for the
//!   bytes at all.
//! - **removal is refused while something still references the object.** A
//!   secret deleted from under a service is a task that cannot be prepared:
//!   the dependency is missing at plan time and the replica never starts. That
//!   is worse than a 409, and unlike a network (`networks.rs`) it cannot be
//!   repaired by anything the operator can see, so the refusal names the
//!   services to fix first.

use std::sync::Arc;

use satl_api::model::{BackendError, ConfigCreated, Result, SecretCreated};
use satl_cluster::StoreView;
use satl_core::{
    Config, ConfigSpec, Id, Meta, ObjectKind, Secret, SecretSpec, Service, ServiceSpec,
    StoreAction, StoreObject, Task,
};

use super::DaemonBackend;

/// How many users an in-use refusal names before it summarizes the rest.
///
/// Four is enough to act on and short enough to read in a terminal; a
/// twenty-service refusal that scrolls is a refusal nobody reads.
const MAX_NAMED_USERS: usize = 4;

impl DaemonBackend {
    // -- secrets ------------------------------------------------------------

    pub(super) async fn create_secret_impl(&self, spec: SecretSpec) -> Result<SecretCreated> {
        let manager = self.manager()?;
        let name = spec.annotations.name.clone();
        {
            let view = manager.store.view();
            if view.secret_by_name(&name).is_some() {
                return Err(BackendError::conflict(format!(
                    "a secret named {name} already exists"
                )));
            }
        }
        let bytes = spec.data().len();
        let secret = Secret {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
        };
        let id = secret.id.clone();
        self.propose_via_leader(
            "create the secret",
            vec![StoreAction::Create(StoreObject::Secret(secret))],
        )
        .await?;
        // The size is operational information; the payload is not logged, here
        // or anywhere.
        tracing::info!(secret_id = %id, name = %name, bytes, "secret created");
        Ok(SecretCreated { id: id.to_string() })
    }

    pub(super) fn list_secrets_impl(&self) -> Result<Vec<Secret>> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let mut secrets: Vec<Secret> = view
            .secrets()
            .into_iter()
            .map(|secret| (*secret).clone())
            .collect();
        secrets.sort_by(|a, b| a.spec.annotations.name.cmp(&b.spec.annotations.name));
        Ok(secrets)
    }

    pub(super) fn inspect_secret_impl(&self, id_or_name: &str) -> Result<Secret> {
        let manager = self.manager()?;
        let view = manager.store.view();
        resolve_secret(&view, id_or_name)
    }

    pub(super) async fn remove_secret_impl(&self, id_or_name: &str) -> Result<()> {
        let manager = self.manager()?;
        let secret = {
            let view = manager.store.view();
            let secret = resolve_secret(&view, id_or_name)?;
            // Checked before proposing, and re-checked by nobody: a reference
            // added concurrently loses the race, which is why the orchestrator
            // treats a missing dependency as a task failure rather than a
            // panic (architecture §12.4).
            if let Some(reason) = in_use_reason(
                "secret",
                &secret.spec.annotations.name,
                &secret_users(&secret.id, &view.services(), &view.tasks()),
            ) {
                return Err(BackendError::conflict(reason));
            }
            secret
        };
        self.propose_via_leader(
            "remove the secret",
            vec![StoreAction::Remove {
                kind: ObjectKind::Secret,
                id: secret.id.clone(),
            }],
        )
        .await?;
        tracing::info!(
            secret_id = %secret.id,
            name = %secret.spec.annotations.name,
            "secret removed"
        );
        Ok(())
    }

    // -- configs ------------------------------------------------------------

    pub(super) async fn create_config_impl(&self, spec: ConfigSpec) -> Result<ConfigCreated> {
        let manager = self.manager()?;
        let name = spec.annotations.name.clone();
        {
            let view = manager.store.view();
            if view.config_by_name(&name).is_some() {
                return Err(BackendError::conflict(format!(
                    "a config named {name} already exists"
                )));
            }
        }
        let bytes = spec.data().len();
        let config = Config {
            id: Id::generate(),
            meta: Meta::new(),
            spec,
        };
        let id = config.id.clone();
        self.propose_via_leader(
            "create the config",
            vec![StoreAction::Create(StoreObject::Config(config))],
        )
        .await?;
        tracing::info!(config_id = %id, name = %name, bytes, "config created");
        Ok(ConfigCreated { id: id.to_string() })
    }

    pub(super) fn list_configs_impl(&self) -> Result<Vec<Config>> {
        let manager = self.manager()?;
        let view = manager.store.view();
        let mut configs: Vec<Config> = view
            .configs()
            .into_iter()
            .map(|config| (*config).clone())
            .collect();
        configs.sort_by(|a, b| a.spec.annotations.name.cmp(&b.spec.annotations.name));
        Ok(configs)
    }

    pub(super) fn inspect_config_impl(&self, id_or_name: &str) -> Result<Config> {
        let manager = self.manager()?;
        let view = manager.store.view();
        resolve_config(&view, id_or_name)
    }

    pub(super) async fn remove_config_impl(&self, id_or_name: &str) -> Result<()> {
        let manager = self.manager()?;
        let config = {
            let view = manager.store.view();
            let config = resolve_config(&view, id_or_name)?;
            if let Some(reason) = in_use_reason(
                "config",
                &config.spec.annotations.name,
                &config_users(&config.id, &view.services(), &view.tasks()),
            ) {
                return Err(BackendError::conflict(reason));
            }
            config
        };
        self.propose_via_leader(
            "remove the config",
            vec![StoreAction::Remove {
                kind: ObjectKind::Config,
                id: config.id.clone(),
            }],
        )
        .await?;
        tracing::info!(
            config_id = %config.id,
            name = %config.spec.annotations.name,
            "config removed"
        );
        Ok(())
    }
}

/// A secret by ID, ID prefix or name — the three forms Docker accepts, in the
/// order [`names::resolve_service`](super::names::resolve_service) uses, so a
/// name is never shadowed by a prefix.
fn resolve_secret(view: &StoreView<'_>, id_or_name: &str) -> Result<Secret> {
    let reference = id_or_name.trim();
    if reference.is_empty() {
        return Err(BackendError::not_found("no secret id or name given"));
    }
    if let Ok(id) = reference.parse::<Id>()
        && let Some(secret) = view.secret(&id)
    {
        return Ok((*secret).clone());
    }
    if let Some(secret) = view.secret_by_name(reference) {
        return Ok((*secret).clone());
    }
    let matches: Vec<Arc<Secret>> = view
        .secrets()
        .into_iter()
        .filter(|secret| secret.id.matches_prefix(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "no such secret: {reference}"
        ))),
        1 => Ok((*matches[0]).clone()),
        n => Err(BackendError::conflict(format!(
            "secret {reference} is ambiguous: it matches {n} secrets"
        ))),
    }
}

/// A config by ID, ID prefix or name (see [`resolve_secret`]).
fn resolve_config(view: &StoreView<'_>, id_or_name: &str) -> Result<Config> {
    let reference = id_or_name.trim();
    if reference.is_empty() {
        return Err(BackendError::not_found("no config id or name given"));
    }
    if let Ok(id) = reference.parse::<Id>()
        && let Some(config) = view.config(&id)
    {
        return Ok((*config).clone());
    }
    if let Some(config) = view.config_by_name(reference) {
        return Ok((*config).clone());
    }
    let matches: Vec<Arc<Config>> = view
        .configs()
        .into_iter()
        .filter(|config| config.id.matches_prefix(reference))
        .collect();
    match matches.len() {
        0 => Err(BackendError::not_found(format!(
            "no such config: {reference}"
        ))),
        1 => Ok((*matches[0]).clone()),
        n => Err(BackendError::conflict(format!(
            "config {reference} is ambiguous: it matches {n} configs"
        ))),
    }
}

/// Checks a service spec's secret/config references against the store and
/// normalizes them, in place.
///
/// References are resolved **by ID** (the API refuses one without an ID), so
/// this does two things: it refuses a reference to an object that does not
/// exist — the alternative is a service whose every task fails at prepare time
/// with a dependency that was never there — and it overwrites `secret_name`
/// with the store's spelling, which is SwarmKit's own normalization: the name
/// on the reference is a display copy, and a stale one would be what
/// `satl service inspect` shows.
pub(super) fn resolve_spec_references(view: &StoreView<'_>, spec: &mut ServiceSpec) -> Result<()> {
    for reference in &mut spec.task.container.secrets {
        let secret = view.secret(&reference.secret_id).ok_or_else(|| {
            BackendError::invalid(format!("secret not found: {}", reference.secret_id))
        })?;
        reference
            .secret_name
            .clone_from(&secret.spec.annotations.name);
    }
    for reference in &mut spec.task.container.configs {
        let config = view.config(&reference.config_id).ok_or_else(|| {
            BackendError::invalid(format!("config not found: {}", reference.config_id))
        })?;
        reference
            .config_name
            .clone_from(&config.spec.annotations.name);
    }
    Ok(())
}

/// Everything that references the secret `id`: the services whose task
/// template names it, plus the non-terminal tasks whose own spec does.
///
/// Both halves matter. A service is the durable reason — its next task would
/// be unpreparable — and a live task is the immediate one: it is running with
/// the payload materialized, and a restart after the secret is gone would not
/// come back. A terminal task is history, not a use (the same rule as
/// `networks::in_use_reason`).
fn secret_users(id: &Id, services: &[Arc<Service>], tasks: &[Arc<Task>]) -> Vec<String> {
    let from_services = services
        .iter()
        .filter(|service| {
            service
                .spec
                .task
                .container
                .secrets
                .iter()
                .any(|reference| &reference.secret_id == id)
        })
        .map(|service| service.spec.annotations.name.clone());
    let from_tasks = tasks
        .iter()
        .filter(|task| !task.status.state.is_terminal())
        .filter(|task| {
            task.spec
                .container
                .secrets
                .iter()
                .any(|reference| &reference.secret_id == id)
        })
        .map(|task| task.service_annotations.name.clone());
    dedup(from_services.chain(from_tasks))
}

/// Everything that references the config `id` (see [`secret_users`]).
fn config_users(id: &Id, services: &[Arc<Service>], tasks: &[Arc<Task>]) -> Vec<String> {
    let from_services = services
        .iter()
        .filter(|service| {
            service
                .spec
                .task
                .container
                .configs
                .iter()
                .any(|reference| &reference.config_id == id)
        })
        .map(|service| service.spec.annotations.name.clone());
    let from_tasks = tasks
        .iter()
        .filter(|task| !task.status.state.is_terminal())
        .filter(|task| {
            task.spec
                .container
                .configs
                .iter()
                .any(|reference| &reference.config_id == id)
        })
        .map(|task| task.service_annotations.name.clone());
    dedup(from_services.chain(from_tasks))
}

/// Sorted, de-duplicated user names (a service and its own tasks are one user).
fn dedup(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut names: Vec<String> = names.filter(|name| !name.is_empty()).collect();
    names.sort();
    names.dedup();
    names
}

/// Why a secret/config cannot be removed, or `None` when nothing uses it.
fn in_use_reason(kind: &str, name: &str, users: &[String]) -> Option<String> {
    if users.is_empty() {
        return None;
    }
    let listed = users
        .iter()
        .take(MAX_NAMED_USERS)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let rest = users.len().saturating_sub(MAX_NAMED_USERS);
    let listed = if rest > 0 {
        format!("{listed} and {rest} more")
    } else {
        listed
    };
    Some(format!(
        "{kind} {name} is in use by the following service(s): {listed}. Update or remove them first"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use satl_core::{
        Annotations, ConfigReference, FileTarget, SecretReference, ServiceMode, TaskState,
        TaskStatus,
    };

    use super::*;

    fn secret_reference(id: &Id, name: &str) -> SecretReference {
        SecretReference {
            secret_id: id.clone(),
            secret_name: name.to_owned(),
            file: FileTarget {
                name: name.to_owned(),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode: 0o444,
            },
        }
    }

    fn config_reference(id: &Id, name: &str) -> ConfigReference {
        ConfigReference {
            config_id: id.clone(),
            config_name: name.to_owned(),
            file: FileTarget {
                name: format!("/etc/{name}"),
                uid: "0".to_owned(),
                gid: "0".to_owned(),
                mode: 0o444,
            },
        }
    }

    fn service(name: &str, edit: impl FnOnce(&mut satl_core::ContainerSpec)) -> Arc<Service> {
        let mut task = super::super::tests::empty_task_spec();
        edit(&mut task.container);
        Arc::new(Service {
            id: Id::generate(),
            meta: Meta::new(),
            spec: ServiceSpec {
                annotations: Annotations {
                    name: name.to_owned(),
                    labels: BTreeMap::new(),
                },
                task,
                mode: ServiceMode::Replicated { replicas: 1 },
                update: None,
                rollback: None,
                endpoint: None,
            },
            endpoint: None,
            spec_version: satl_core::Version(0),
            previous_spec: None,
            update_status: None,
        })
    }

    fn task(
        service: &str,
        state: TaskState,
        edit: impl FnOnce(&mut satl_core::ContainerSpec),
    ) -> Arc<Task> {
        let mut task = super::super::tests::sample_task(service);
        task.status = TaskStatus::new(state, "test");
        edit(&mut task.spec.container);
        Arc::new(task)
    }

    /// The 409 an operator sees: a secret a service references cannot be
    /// removed, and neither can one a live task holds. History does not count.
    #[test]
    fn a_referenced_secret_is_in_use_but_a_terminal_tasks_is_not() {
        let id = Id::generate();
        let other = Id::generate();

        let by_service = service("web", |container| {
            container.secrets = vec![secret_reference(&id, "db_password")];
        });
        let users = secret_users(&id, &[Arc::clone(&by_service)], &[]);
        assert_eq!(users, ["web"]);
        let reason = in_use_reason("secret", "db_password", &users).expect("a refusal");
        assert!(
            reason.contains("secret db_password is in use by the following service(s): web"),
            "{reason}"
        );
        assert!(reason.contains("Update or remove them first"), "{reason}");

        // A running task counts even when no service does (an anonymous
        // `satl run` container, or a service already removed).
        let live = task("api", TaskState::Running, |container| {
            container.secrets = vec![secret_reference(&id, "db_password")];
        });
        assert_eq!(secret_users(&id, &[], &[Arc::clone(&live)]), ["api"]);

        // A terminal task is history: it holds nothing.
        let dead = task("api", TaskState::Shutdown, |container| {
            container.secrets = vec![secret_reference(&id, "db_password")];
        });
        assert!(secret_users(&id, &[], &[dead]).is_empty());

        // A service and its own tasks are one user, not two.
        assert_eq!(
            secret_users(&id, &[Arc::clone(&by_service)], &[live]),
            ["api", "web"]
        );

        // Another secret's users are not this secret's.
        assert!(secret_users(&other, &[by_service], &[]).is_empty());
        assert_eq!(in_use_reason("secret", "unused", &[]), None);
    }

    #[test]
    fn a_referenced_config_is_in_use_too() {
        let id = Id::generate();
        let by_service = service("web", |container| {
            container.configs = vec![config_reference(&id, "nginx_conf")];
        });
        let users = config_users(&id, &[by_service], &[]);
        assert_eq!(users, ["web"]);
        let reason = in_use_reason("config", "nginx_conf", &users).expect("a refusal");
        assert!(
            reason.starts_with("config nginx_conf is in use"),
            "{reason}"
        );
    }

    /// A long list is summarized rather than scrolled.
    #[test]
    fn an_in_use_refusal_caps_the_names_it_lists() {
        let users: Vec<String> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let reason = in_use_reason("secret", "token", &users).expect("a refusal");
        assert!(reason.contains("a, b, c, d and 2 more"), "{reason}");
        assert!(!reason.contains("e, f"), "{reason}");
    }
}
