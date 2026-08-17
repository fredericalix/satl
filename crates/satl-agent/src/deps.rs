// SPDX-License-Identifier: BSD-2-Clause
//! [`DependencyStore`] — the secrets and configs the node's tasks reference
//! (SWK §13.4, §14.2; architecture §7.2, §12.4).
//!
//! **Secrets never touch a worker's disk** (CLAUDE.md invariant #7). The
//! dispatcher ships them over mTLS with the first task that references them
//! and withdraws them when the last one goes away; between those two moments
//! they live *here*, in process memory, and nowhere else. The local task DB
//! ([`crate::db`]) persists task snapshots, which carry secret **references**
//! (`secret_id`, `secret_name`, file target) — never payloads. Materializing
//! a payload is a tmpfs mount inside the jail and nothing else.
//!
//! Configs are not sensitive, but they live in the same place for one
//! reason: the dispatcher reference-counts both the same way, so the agent
//! must be able to drop both the same way. A config *may* be written to disk
//! by the bundle layer; a secret may not.
//!
//! The store is a plain map behind a lock rather than a channel: the
//! assignment stream writes it in the pinned order (secrets → configs →
//! tasks) before the tasks that need it are handed to the [`Worker`], and
//! task controllers read it while preparing a bundle. There is no ordering
//! subtlety left for a queue to solve.
//!
//! [`Worker`]: crate::worker::Worker

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use satl_core::{Config, Id, Secret};

/// The node's in-memory secret and config set.
///
/// Cheap to share (`Arc`); every method takes `&self`.
#[derive(Debug, Default)]
pub struct DependencyStore {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    secrets: BTreeMap<Id, Arc<Secret>>,
    configs: BTreeMap<Id, Arc<Config>>,
}

impl DependencyStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the whole secret set.
    ///
    /// This is the `COMPLETE` snapshot path: the snapshot is authoritative,
    /// so anything not in it is gone (`proto/dispatcher.proto` — "secrets and
    /// configs are replaced wholesale").
    pub fn reset_secrets(&self, secrets: impl IntoIterator<Item = Secret>) {
        let secrets: BTreeMap<Id, Arc<Secret>> = secrets
            .into_iter()
            .map(|secret| (secret.id.clone(), Arc::new(secret)))
            .collect();
        let mut inner = self.write();
        tracing::debug!(
            was = inner.secrets.len(),
            now = secrets.len(),
            "secret set replaced from a complete assignment snapshot"
        );
        inner.secrets = secrets;
    }

    /// Adds or replaces one secret.
    pub fn put_secret(&self, secret: Secret) {
        let id = secret.id.clone();
        let replaced = self.write().secrets.insert(id.clone(), Arc::new(secret));
        tracing::debug!(secret_id = %id, replaced = replaced.is_some(), "secret assigned");
    }

    /// Drops one secret. Missing is fine (the dispatcher may re-send a
    /// removal after a re-sync).
    pub fn remove_secret(&self, id: &Id) {
        if self.write().secrets.remove(id).is_some() {
            tracing::debug!(secret_id = %id, "secret withdrawn");
        }
    }

    /// One secret, if the node holds it.
    #[must_use]
    pub fn secret(&self, id: &Id) -> Option<Arc<Secret>> {
        self.read().secrets.get(id).cloned()
    }

    /// The IDs of every secret held.
    #[must_use]
    pub fn secret_ids(&self) -> BTreeSet<Id> {
        self.read().secrets.keys().cloned().collect()
    }

    /// Replaces the whole config set (`COMPLETE` snapshot path).
    pub fn reset_configs(&self, configs: impl IntoIterator<Item = Config>) {
        let configs: BTreeMap<Id, Arc<Config>> = configs
            .into_iter()
            .map(|config| (config.id.clone(), Arc::new(config)))
            .collect();
        let mut inner = self.write();
        tracing::debug!(
            was = inner.configs.len(),
            now = configs.len(),
            "config set replaced from a complete assignment snapshot"
        );
        inner.configs = configs;
    }

    /// Adds or replaces one config.
    pub fn put_config(&self, config: Config) {
        let id = config.id.clone();
        let replaced = self.write().configs.insert(id.clone(), Arc::new(config));
        tracing::debug!(config_id = %id, replaced = replaced.is_some(), "config assigned");
    }

    /// Drops one config. Missing is fine.
    pub fn remove_config(&self, id: &Id) {
        if self.write().configs.remove(id).is_some() {
            tracing::debug!(config_id = %id, "config withdrawn");
        }
    }

    /// One config, if the node holds it.
    #[must_use]
    pub fn config(&self, id: &Id) -> Option<Arc<Config>> {
        self.read().configs.get(id).cloned()
    }

    /// The IDs of every config held.
    #[must_use]
    pub fn config_ids(&self) -> BTreeSet<Id> {
        self.read().configs.keys().cloned().collect()
    }

    /// Whether every secret and config `task` references is present.
    ///
    /// The controller uses this as a gate: a task whose dependencies have not
    /// arrived yet must not be prepared, because the dispatcher ships
    /// dependencies *before* the task that needs them and a missing one means
    /// the stream is mid-resync.
    #[must_use]
    pub fn has_dependencies_of(&self, task: &satl_core::Task) -> bool {
        let inner = self.read();
        task.spec
            .container
            .secrets
            .iter()
            .all(|reference| inner.secrets.contains_key(&reference.secret_id))
            && task
                .spec
                .container
                .configs
                .iter()
                .all(|reference| inner.configs.contains_key(&reference.config_id))
    }

    /// Reads through a poisoned lock: a panic while holding it cannot leave
    /// the map in a torn state (every mutation is a single map operation), so
    /// refusing to serve secrets afterwards would take the node down for
    /// nothing.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use satl_core::{Annotations, ConfigSpec, Meta, SecretSpec};
    use std::collections::BTreeMap as Map;

    fn secret(name: &str, data: &[u8]) -> Secret {
        Secret {
            id: Id::generate(),
            meta: Meta::new(),
            spec: SecretSpec::new(
                Annotations {
                    name: name.to_owned(),
                    labels: Map::new(),
                },
                data.to_vec(),
            )
            .expect("valid"),
        }
    }

    fn config(name: &str, data: &[u8]) -> Config {
        Config {
            id: Id::generate(),
            meta: Meta::new(),
            spec: ConfigSpec::new(
                Annotations {
                    name: name.to_owned(),
                    labels: Map::new(),
                },
                data.to_vec(),
            )
            .expect("valid"),
        }
    }

    #[test]
    fn a_secret_can_be_put_read_and_withdrawn() {
        let store = DependencyStore::new();
        let secret = secret("db.password", b"hunter2");
        let id = secret.id.clone();
        assert!(store.secret(&id).is_none());
        store.put_secret(secret.clone());
        assert_eq!(store.secret(&id).as_deref(), Some(&secret));
        assert_eq!(store.secret_ids(), BTreeSet::from([id.clone()]));
        store.remove_secret(&id);
        assert!(store.secret(&id).is_none());
        // Removing twice is not an error: a re-sync may repeat a removal.
        store.remove_secret(&id);
    }

    #[test]
    fn a_complete_snapshot_replaces_the_whole_set() {
        let store = DependencyStore::new();
        let stale = secret("stale", b"old");
        store.put_secret(stale.clone());
        let fresh = secret("fresh", b"new");
        store.reset_secrets([fresh.clone()]);
        assert!(
            store.secret(&stale.id).is_none(),
            "a secret absent from the snapshot must be gone"
        );
        assert_eq!(store.secret(&fresh.id).as_deref(), Some(&fresh));
    }

    #[test]
    fn configs_behave_the_same_way() {
        let store = DependencyStore::new();
        let one = config("nginx.conf", b"server {}");
        let two = config("mime.types", b"text/plain txt;");
        store.reset_configs([one.clone(), two.clone()]);
        assert_eq!(store.config_ids(), BTreeSet::from([one.id.clone(), two.id]));
        store.remove_config(&one.id);
        assert!(store.config(&one.id).is_none());
    }

    #[test]
    fn dependency_gate_needs_every_reference_present() {
        let store = DependencyStore::new();
        let secret = secret("db.password", b"hunter2");
        let config = config("nginx.conf", b"server {}");
        let mut task = testing::task();
        task.spec
            .container
            .secrets
            .push(satl_core::SecretReference {
                secret_id: secret.id.clone(),
                secret_name: secret.spec.annotations.name.clone(),
                file: satl_core::FileTarget {
                    name: "db.password".to_owned(),
                    uid: "0".to_owned(),
                    gid: "0".to_owned(),
                    mode: 0o444,
                },
            });
        task.spec
            .container
            .configs
            .push(satl_core::ConfigReference {
                config_id: config.id.clone(),
                config_name: config.spec.annotations.name.clone(),
                file: satl_core::FileTarget {
                    name: "nginx.conf".to_owned(),
                    uid: "0".to_owned(),
                    gid: "0".to_owned(),
                    mode: 0o444,
                },
            });

        assert!(!store.has_dependencies_of(&task));
        store.put_secret(secret);
        assert!(!store.has_dependencies_of(&task), "the config is missing");
        store.put_config(config);
        assert!(store.has_dependencies_of(&task));
    }

    #[test]
    fn a_task_without_references_is_always_satisfied() {
        let store = DependencyStore::new();
        assert!(store.has_dependencies_of(&testing::task()));
    }
}
