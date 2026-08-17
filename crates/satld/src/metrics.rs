// SPDX-License-Identifier: BSD-2-Clause
//! The metrics collector: the periodic feed behind `satl_metrics`' gauges.
//!
//! Everything that is a *reading* rather than an *event* is refreshed here on
//! the dataset sweep's 20 s cadence (which is also the cadence `plan-m6.md`
//! gives the rctl usage reads): raft state, the store's task/service counts,
//! dispatcher sessions, the node certificate's expiry, the local container
//! states, and per-task rctl usage. Counters and histograms (health checks,
//! API requests, command failures, reconcile passes) are fed at the event
//! site instead — see `satl_metrics`' global helpers.
//!
//! A worker has no raft and no store: its cluster series read `none`/0 and
//! its node-local series stay accurate.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cluster::ClusterSlot;
use crate::node::NodeRuntime;

/// Collector cadence: the dataset sweep's 20 s (`reconcile.rs`), so the
/// rctl reads and the mount/dataset sweeps share one rhythm.
const COLLECT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// Host facts behind `engine_daemon_engine_info` and the cpu/memory gauges,
/// assembled once in `main` where the build identity and host facts live.
pub struct EngineFacts {
    /// The info-metric label set (`graphdriver` keeps Docker's label name;
    /// SatL has exactly one storage driver, and its name is "zfs").
    pub labels: satl_metrics::EngineInfoLabels,
    /// Host CPU count.
    pub cpus: i64,
    /// Host physical memory, bytes.
    pub memory_bytes: i64,
}

/// Start everything metrics: stamp the engine info, spawn the collector, and
/// serve `/metrics` when the operator configured an address. The handles are
/// returned so the daemon's shutdown awaits them with the other sweeps.
pub fn spawn(
    metrics: satl_metrics::Metrics,
    addr: Option<std::net::SocketAddr>,
    facts: &EngineFacts,
    slot: Arc<ClusterSlot>,
    node: Arc<NodeRuntime>,
    shutdown: CancellationToken,
) -> Vec<tokio::task::JoinHandle<()>> {
    metrics.set_engine_info(&facts.labels, facts.cpus, facts.memory_bytes);
    let mut handles = vec![spawn_collector(
        metrics.clone(),
        slot,
        node,
        shutdown.clone(),
    )];
    if let Some(addr) = addr {
        handles.push(tokio::spawn(async move {
            if let Err(error) = satl_metrics::serve(addr, metrics, shutdown.cancelled_owned()).await
            {
                tracing::error!(%addr, %error, "metrics endpoint failed");
            }
        }));
    }
    handles
}

/// Spawn the collector loop; stops when `shutdown` is cancelled.
fn spawn_collector(
    metrics: satl_metrics::Metrics,
    slot: Arc<ClusterSlot>,
    node: Arc<NodeRuntime>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(COLLECT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    collect_cluster(&metrics, &slot);
                    collect_node(&metrics, &node).await;
                }
            }
        }
    })
}

/// Raft, store counts, dispatcher sessions — the manager view. A worker
/// (or a daemon whose cluster is still starting) reports `none`/zeros.
fn collect_cluster(metrics: &satl_metrics::Metrics, slot: &ClusterSlot) {
    let Some(core) = slot.get() else {
        return;
    };
    let Some(manager) = core.manager.as_ref() else {
        metrics.set_raft("none", 0, 0, 0);
        metrics.set_tasks(&[]);
        metrics.set_services(0);
        return;
    };
    let raft = manager.store.metrics();
    metrics.set_raft(
        raft.role(),
        raft.leader_id
            .map_or(0, |id| i64::try_from(id).unwrap_or(0)),
        i64::try_from(raft.term).unwrap_or(i64::MAX),
        raft.last_applied
            .map_or(0, |index| i64::try_from(index).unwrap_or(i64::MAX)),
    );
    {
        // The view guard is !Send: take the counts and drop it before any
        // await (architecture §6.2). This function is sync precisely so the
        // guard cannot leak across one.
        let view = manager.store.view();
        let mut counts: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
        for task in view.tasks() {
            *counts.entry(task.status.state.to_string()).or_default() += 1;
        }
        let counts: Vec<(String, i64)> = counts.into_iter().collect();
        let services = i64::try_from(view.services().len()).unwrap_or(i64::MAX);
        drop(view);
        metrics.set_tasks(&counts);
        metrics.set_services(services);
    }
    metrics.set_dispatcher_sessions(
        i64::try_from(manager.dispatcher.open_sessions()).unwrap_or(i64::MAX),
    );
}

/// Node-local readings: container states (Docker's three), per-task rctl
/// usage, node certificate expiry.
async fn collect_node(metrics: &satl_metrics::Metrics, node: &NodeRuntime) {
    match node.task_db.list().await {
        Ok(records) => {
            let mut running = 0_i64;
            let mut stopped = 0_i64;
            for record in &records {
                if record.status.state == satl_core::TaskState::Running {
                    running += 1;
                } else if record.status.state.is_terminal() {
                    stopped += 1;
                }
            }
            // No pause support anywhere in SatL: `paused` stays 0.
            metrics.set_container_states(running, 0, stopped);

            let rctl = node.executor.rctl();
            let mut usages = Vec::new();
            for record in &records {
                if record.status.state != satl_core::TaskState::Running {
                    continue;
                }
                let task_id = record.task.id.to_string();
                match rctl.usage(&task_id).await {
                    Ok(Some(usage)) => {
                        usages.push((task_id, usage.memory_bytes, usage.cpu_seconds));
                    }
                    // racct off or teardown race: simply nothing to report.
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(%task_id, %error, "rctl usage read failed; series skipped");
                    }
                }
            }
            metrics.set_container_usages(&usages);
        }
        Err(error) => {
            tracing::warn!(%error, "metrics collector could not list the local task DB");
        }
    }

    // The certificate is re-read from disk each pass, so a renewal swapping
    // the identity is reflected without any wiring into the renewal loop.
    match crate::identity::load(&node.state_dir) {
        Ok(Some(identity)) => match satl_ca::certificate_validity(&identity.cert_pem) {
            Ok((_, not_after)) => {
                let epoch = not_after
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
                metrics.set_node_certificate_not_after(epoch);
            }
            Err(error) => {
                tracing::debug!(%error, "metrics collector could not parse the node certificate");
            }
        },
        // No identity yet (never joined): nothing to report.
        Ok(None) => {}
        Err(error) => {
            tracing::debug!(%error, "metrics collector could not read the node identity");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worker shape: no manager core, so the cluster series read
    /// `none`/zeros and nothing panics on the missing store.
    #[tokio::test]
    async fn a_worker_reports_no_raft_and_no_store_counts() {
        let metrics = satl_metrics::Metrics::new();
        let (slot, _control) = ClusterSlot::new();
        // Publish a worker-shaped core (no manager part).
        let (_agent_tx, agent_rx) =
            tokio::sync::watch::channel(satl_dispatcher::AgentState::default());
        slot.publish(Arc::new(crate::cluster::ClusterCore {
            manager: None,
            node_id: satl_core::Id::generate(),
            role: satl_core::NodeRole::Worker,
            cluster_id: "cluster".to_owned(),
            advertise_addr: String::new(),
            agent: agent_rx,
        }));
        collect_cluster(&metrics, &slot);
        let out = metrics.encode();
        assert!(out.contains("satl_raft_role{role=\"none\"} 1"), "{out}");
        assert!(out.contains("satl_services 0"), "{out}");
    }
}
