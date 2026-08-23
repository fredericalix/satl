// SPDX-License-Identifier: BSD-2-Clause
//! Startup reconciliation: adopt what survived, destroy what leaked.
//!
//! `satld` may have been killed at any point — mid-`prepare`, between
//! `ocijail create` and `start`, or during a teardown. Jails, ZFS clones and
//! epairs all outlive the process (that is the point: a running container
//! survives a daemon restart), so the first thing a fresh daemon does is
//! reconcile what exists on the node against what the store says should
//! exist (architecture §7.2; CLAUDE.md's VNET-cleanup gotcha).
//!
//! The pass, in order — later steps depend on earlier ones having released
//! their resources, and **every step tolerates the failure of the others**:
//! one broken subsystem must not leave the node un-reconciled.
//!
//! 1. Rebuilding the worker's task set is deliberately **not** here: the agent
//!    session owns it (its first `COMPLETE` snapshot calls
//!    `Worker::init_from_disk`, once per process). Doing it here too resumed
//!    every task a second time — see the comment in [`run`].
//! 2. `ocijail list` — a jail whose id is not a live task is deleted, with
//!    the mount sweep ocijail's own `delete` does not do reliably
//!    (docs/ocijail.md §4.4).
//! 3. rctl rules — a `jail:<task id>` rule subject whose prison no longer
//!    exists is removed. Rules survive their jail's death and nothing else
//!    ever removes them; `rctl -r` on a dead subject works (measured — the
//!    old belief that only a reboot purged them was wrong). Only subjects
//!    matching the task-id shape are eligible: another tool may manage its
//!    own jails' rules, and those are never touched.
//! 4. leftover container mounts — everything mounted under
//!    `<containers root>/<task id>` for a task nobody claims is unmounted.
//!    These are `MNT_IGNORE`, so no standard tool shows them; the whole story
//!    is in [`sweep_mounts`]. This runs **before** step 5, because a dataset
//!    cannot be destroyed while anything is mounted below it.
//! 5. container datasets — a `<containers_root>/<task id>` clone with no
//!    live task is destroyed.
//! 6. epairs — every interface tagged `satl:<task id>` for an unknown task is
//!    destroyed and its address released.
//! 7. the `satl/rdr` pf anchor is regenerated from the live tasks' published
//!    ports: redirects are restored for adopted containers and stale ones —
//!    which nothing else removes after a restart — are dropped.
//!
//! Steps 2–6 only ever touch ids that are *not* live tasks, so a container
//! that is running and known is never disturbed.
//!
//! ## The periodic pass
//!
//! Startup is not enough for one of these resources. A container rootfs cannot
//! be destroyed while its jail is still dying (`docs/jail-teardown.md`), and a
//! jail can take more than a minute to die, so a task's own `remove` may have
//! to give up and leave the dataset behind. If the only sweep were this one, a
//! daemon that never restarts would never reclaim it — an edge-triggered
//! attempt that can be lost, exactly the shape that produced the node-status
//! bug in the commit before this one.
//!
//! So [`spawn_dataset_sweep`] re-runs the disk half of this pass on a timer, as
//! a level: every mount and every dataset with no live task goes, whichever step
//! left it there. The task's own retry is still the fast path — this is the
//! safety net, the same division of labour as the overlay's `spawn_resync`.
//!
//! Both halves of that periodic pass require **two consecutive passes to agree**
//! before they touch anything, for the reason spelled out on [`DatasetSweeper`]:
//! the claim set is assembled from readings that are each momentarily incomplete
//! at different times, and one disagreeing pass must not cost a live task its
//! rootfs or its `/tmp`.
//!
//! ## Publishing ports is a level too
//!
//! [`spawn_port_sweep`] re-runs step 5 on a timer, for a different reason: the
//! `satl/rdr` anchor is the *only* place a service's published ports become
//! real, and nothing on this node is told when a service is published. An
//! ingress port is assigned centrally, by the allocator on the leader
//! (`satl_orchestrator::allocator`), and it reaches this node as a field of a
//! task object in the replicated store — not as an event, not on the
//! assignment stream. A node that published only on the edges it happens to
//! see would therefore never publish an ingress port at all, which is exactly
//! the defect this loop closes; and a node that published on the edge only
//! would lose the redirect of any task whose allocation arrived late, whose
//! leader changed mid-flight, or whose pfctl load failed once.
//!
//! So the pass computes what the anchor *should* hold from the live task set
//! and hands the whole thing to `satl_net`, which reloads pf only when the
//! text changes ([`satl_net::NetworkManager::reconcile_published_ports`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use satl_agent::LinuxEmulation;
use satl_cluster::ClusterStore;
use satl_core::{DesiredState, Id};
use satl_dispatcher::assignment::belongs_to;
use satl_net::PortPublish;
use satl_runtime::Runtime as _;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cluster::ClusterSlot;
use crate::node::NodeRuntime;
use crate::sysctl::Sysctl;

/// How often the node re-checks its container datasets against the live task
/// set.
///
/// The dataset a task deferred is reclaimed within one of these of the jail
/// finally dying. Slow on purpose: it is two `zfs list`s and a store read, and
/// nothing here is latency critical — the task is long gone as far as the
/// cluster is concerned, only the disk space and the leftovers audit care.
const DATASET_SWEEP_INTERVAL: Duration = Duration::from_secs(20);

/// How often the node re-derives the `satl/rdr` anchor from the live task set.
///
/// This is also the worst-case delay before a newly allocated ingress port is
/// answered on this node, which is why it is short where the dataset sweep is
/// long: nothing else publishes it. The cost of a pass with nothing to do is a
/// store read, a few in-memory IPAM lookups and a string compare — pf is only
/// invoked when the ruleset text changes.
const PORT_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// How often that pass re-asserts the anchor even when nothing changed.
///
/// The "nothing changed" shortcut compares against what *this process* last
/// loaded, which is a belief about the kernel rather than a reading of it:
/// `pfctl -a satl/rdr -F nat` in a root shell leaves the two disagreeing
/// forever. Re-asserting on a slow cycle bounds that at one minute, for two
/// pfctl invocations a minute on a node with published ports (and one on a node
/// with none). Reading the anchor back instead would be better still, but
/// `pfctl -s nat` prints its own normalisation of a ruleset (`port = http-alt`
/// for `port 8080`), so a text comparison against it would be a parser with a
/// bug for every service name in `/etc/services`.
const PORT_REASSERT_EVERY: u32 = 12;

/// How often the node re-probes `compat.linux.osrelease`.
///
/// The linuxulator can appear (`kldload linux`) or vanish (`kldunload`, only
/// possible with no linux process running) at any time, and the startup probe
/// alone made a post-boot `kldload` invisible until a daemon restart. The
/// probe is one `sysctl -n` every 10 s; the flip lands in the shared
/// [`LinuxEmulation`] handle, which the executor's prepare gate and platform
/// policy and the node describer all read live, and the 20 s description
/// refresh then re-registers the session, so the cluster sees the change
/// within about 30 s.
const LINUX_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Orphaned jails deleted.
    pub jails_destroyed: Vec<String>,
    /// rctl rule sets purged because their (SatL-shaped) jail subject no
    /// longer exists.
    pub rctl_rules_purged: Vec<String>,
    /// Orphaned container datasets destroyed.
    pub datasets_destroyed: Vec<String>,
    /// Orphaned epair interfaces destroyed (node-local bridge networks).
    pub epairs_destroyed: Vec<String>,
    /// Orphaned overlay epair interfaces destroyed.
    pub overlay_epairs_destroyed: Vec<String>,
    /// Overlay bridges destroyed because no live local task wanted them.
    pub overlay_bridges_destroyed: Vec<String>,
    /// VTEPs destroyed because no live local task wanted their network.
    pub vteps_destroyed: Vec<String>,
    /// Leftover container mounts unmounted (`MNT_IGNORE`, so nothing else on
    /// the node could see them — see [`sweep_mounts`]).
    pub mounts_unmounted: Vec<String>,
    /// Tasks whose published ports were reinstalled in the `satl/rdr` anchor.
    pub ports_republished: usize,
}

impl ReconcileReport {
    /// Whether the pass had to destroy anything at all.
    #[must_use]
    pub fn destroyed_anything(&self) -> bool {
        !self.jails_destroyed.is_empty()
            || !self.rctl_rules_purged.is_empty()
            || !self.datasets_destroyed.is_empty()
            || !self.mounts_unmounted.is_empty()
            || !self.epairs_destroyed.is_empty()
            || !self.overlay_epairs_destroyed.is_empty()
            || !self.overlay_bridges_destroyed.is_empty()
            || !self.vteps_destroyed.is_empty()
    }
}

/// The tasks this node is supposed to be running, from the store.
///
/// Returns each live task's desired state so the dispatcher can seed its
/// bookkeeping and not re-apply what reconciliation already adopted.
#[must_use]
pub fn live_tasks(store: &ClusterStore, node_id: &Id) -> BTreeMap<Id, DesiredState> {
    // Scope the view: its guard is !Send.
    let view = store.view();
    view.tasks()
        .into_iter()
        .filter(|task| belongs_to(task, node_id))
        .map(|task| (task.id.clone(), task.desired_state))
        .collect()
}

/// This node's tasks as the **local task DB** records them, status merged
/// (the persisted status is canonical over the assignment's copy, §7.2).
///
/// This is a worker's only claim set: its records *are* what the dispatcher
/// told it to run, persisted (architecture §7.2), so on a node with no store
/// they play the store's role in every sweep below.
async fn local_tasks(node: &NodeRuntime) -> Vec<Arc<satl_core::Task>> {
    match node.task_db.list().await {
        Ok(records) => records
            .into_iter()
            .map(|record| {
                let mut task = record.task;
                task.status = record.status;
                Arc::new(task)
            })
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "cannot read the local task db; treating it as empty");
            Vec::new()
        }
    }
}

/// Run the startup pass. Never fails: every step logs its own trouble and the
/// next one still runs.
#[tracing::instrument(skip_all, fields(node_id = %node_id))]
pub async fn run(store: &ClusterStore, node_id: &Id, node: &NodeRuntime) -> ReconcileReport {
    let live = live_tasks(store, node_id);
    let live_ids: BTreeSet<Id> = live.keys().cloned().collect();
    let live_names: BTreeSet<String> = live_ids.iter().map(|id| id.as_str().to_owned()).collect();
    tracing::info!(live = live_ids.len(), "startup reconciliation started");

    let mut report = ReconcileReport::default();

    // 1. Rebuilding the worker's task set is **the agent session's job**, not
    //    ours: the dispatcher's first COMPLETE snapshot calls
    //    `Worker::init_from_disk`, and that snapshot — not a store read from
    //    whichever manager happens to answer us — is the authoritative live
    //    set. Doing it here as well resumed every task twice, replacing each
    //    task manager (and each controller re-attached to a live container)
    //    with a second one for no gain.
    //
    //    It is *not* what stranded containers on a returning node: that was
    //    the agent taking the snapshot's desired state as proof of what the
    //    worker had been told (see `AssignmentApplier::apply_snapshot`).
    //
    //    The sweeps below need no worker involvement: they compare what is on
    //    the node against the *store*, which is available now.

    // 2. Jails ocijail still knows about that no live task claims.
    sweep_jails(node, &live_names, &mut report).await;

    // 3. rctl rules whose jail is gone. Rules survive the jail's death and
    //    nothing else removes them; the live set is jls's, not the store's
    //    (see sweep_rctl_rules).
    sweep_rctl_rules(node, &mut report).await;

    // 4. Leftover container mounts, *before* the datasets under them: a
    //    dataset cannot be destroyed while anything is mounted below it.
    sweep_mounts(node, &live_names, &mut report).await;

    // 5. Container datasets with no live task.
    sweep_datasets(node, &live_names, &mut report).await;

    // 6. Epairs tagged for a task nobody claims. Node-local ones only:
    //    `destroy_orphans` matches `<group>:<task-id>`, and an overlay epair is
    //    `<group>:overlay:<net>:<task-id>`, which step 8 owns.
    match node.executor.network().destroy_orphans(&live_names).await {
        Ok(destroyed) => report.epairs_destroyed = destroyed,
        Err(error) => tracing::error!(%error, "sweeping orphaned epairs failed"),
    }

    // 7. Rebuild the pf redirect anchor from live task state. Forced: the
    //    anchor may hold whatever the previous process left, and this process
    //    has no record of it.
    report.ports_republished = reconcile_ports(store, node_id, node, true)
        .await
        .map_or(0, |outcome| outcome.tasks);

    // 8. Overlays: adopt the VTEPs, bridges and epairs of networks that still
    //    have a live local task, destroy the rest.
    let overlay = node
        .overlay
        .reconcile_startup(wanted_overlays(store, node_id))
        .await;
    report.overlay_epairs_destroyed = overlay.destroyed_epairs;
    report.overlay_bridges_destroyed = overlay.destroyed_bridges;
    report.vteps_destroyed = overlay.destroyed_vteps;

    tracing::info!(
        jails_destroyed = report.jails_destroyed.len(),
        rctl_rules_purged = report.rctl_rules_purged.len(),
        datasets_destroyed = report.datasets_destroyed.len(),
        mounts_unmounted = report.mounts_unmounted.len(),
        epairs_destroyed = report.epairs_destroyed.len(),
        overlay_epairs_destroyed = report.overlay_epairs_destroyed.len(),
        overlay_bridges_destroyed = report.overlay_bridges_destroyed.len(),
        vteps_destroyed = report.vteps_destroyed.len(),
        ports_republished = report.ports_republished,
        "startup reconciliation complete"
    );
    report
}

/// The startup pass of a node with **no store**: the same node-local sweeps,
/// with the claim set read from the local task DB — which on a worker *is*
/// what the dispatcher last assigned, persisted (architecture §7.2).
///
/// One step is deliberately absent: the overlay sweep. Its "wanted" list
/// needs the network objects, which a worker only ever holds in memory (they
/// arrive on the assignment stream), so at startup there is nothing safe to
/// diff the host against — destroying by absence here would tear live tunnels
/// off surviving jails. The sweep runs at the first `COMPLETE` snapshot
/// instead, the earliest moment the claim set is complete
/// (`OverlayManager::sweep_after_snapshot`); until then the interfaces sit
/// untouched, exactly like the jails they serve.
#[tracing::instrument(skip_all, fields(node_id = %node_id))]
pub async fn run_worker(node_id: &Id, node: &NodeRuntime) -> ReconcileReport {
    let tasks = local_tasks(node).await;
    let live_names: BTreeSet<String> = tasks
        .iter()
        .map(|task| task.id.as_str().to_owned())
        .collect();
    tracing::info!(
        live = live_names.len(),
        "startup reconciliation started (worker: claims from the local task db)"
    );

    let mut report = ReconcileReport::default();
    sweep_jails(node, &live_names, &mut report).await;
    sweep_rctl_rules(node, &mut report).await;
    sweep_mounts(node, &live_names, &mut report).await;
    sweep_datasets(node, &live_names, &mut report).await;
    match node.executor.network().destroy_orphans(&live_names).await {
        Ok(destroyed) => report.epairs_destroyed = destroyed,
        Err(error) => tracing::error!(%error, "sweeping orphaned epairs failed"),
    }
    report.ports_republished = reconcile_ports_over(&tasks, node_id, node, true, None)
        .await
        .map_or(0, |outcome| outcome.tasks);

    tracing::info!(
        jails_destroyed = report.jails_destroyed.len(),
        rctl_rules_purged = report.rctl_rules_purged.len(),
        datasets_destroyed = report.datasets_destroyed.len(),
        epairs_destroyed = report.epairs_destroyed.len(),
        mounts_unmounted = report.mounts_unmounted.len(),
        ports_republished = report.ports_republished,
        "startup reconciliation complete (worker; overlay sweep waits for the first snapshot)"
    );
    report
}

/// The overlay networks this node should be hosting, from the store.
///
/// One entry per overlay network with at least one **live** local task, carrying
/// the network object and each task's address on it. Everything an overlay
/// interface can be attributed to is in here, so anything on the host that is not
/// is a leftover.
///
/// A task in a terminal state is deliberately excluded: its jail is gone or
/// going, so its epair is a leftover and its address must stop being answered.
/// A task that has not reached `STARTING` is *included* — it has no jail yet, but
/// its network does need a segment, and the reconciler tolerates a jail that is
/// not there (`satl_overlay::Programmer` skips a vanished jail rather than
/// failing the pass).
fn wanted_overlays(store: &ClusterStore, node_id: &Id) -> Vec<crate::overlay::WantedNetwork> {
    // Scope the view: its guard is !Send.
    let view = store.view();
    let mut wanted: BTreeMap<Id, crate::overlay::WantedNetwork> = BTreeMap::new();
    for task in view.tasks() {
        if !belongs_to(&task, node_id) || task.status.state.is_terminal() {
            continue;
        }
        for attachment in &task.networks {
            let Some(network) = view.network(&attachment.network_id) else {
                continue;
            };
            if network.spec.driver != satl_core::NetworkDriver::Overlay {
                continue;
            }
            let Some(ip) = attachment
                .addresses
                .iter()
                .filter_map(|text| text.parse::<satl_core::Ipv4Cidr>().ok())
                .map(satl_core::Ipv4Cidr::addr)
                .next()
            else {
                continue;
            };
            wanted
                .entry(network.id.clone())
                .or_insert_with(|| crate::overlay::WantedNetwork {
                    network: (*network).clone(),
                    tasks: Vec::new(),
                })
                .tasks
                .push(crate::overlay::WantedTask {
                    task_id: task.id.clone(),
                    // Container ID = task ID = jail name (a pinned M1 contract).
                    jail: task.id.as_str().to_owned(),
                    ip,
                });
        }
    }
    wanted.into_values().collect()
}

/// Converge `satl/rdr` on the tasks that are actually running here.
///
/// The whole anchor is a function of the live task set, recomputed here and
/// handed to `satl_net` in one piece — there are no incremental edits and no
/// memory of what the last pass did. That is what makes it repair itself: the
/// published-port set the network manager keeps is in-process only, so a
/// restarted daemon starts with an empty one while the anchor still holds
/// whatever the previous process left; and an ingress port is never announced
/// to this node at all, it simply appears on the task object once the
/// allocator has assigned it.
///
/// Two things are deliberately *not* done here. Nothing is allocated: a port
/// the allocator has not assigned yet is `0` and is skipped, so the task
/// becomes published on a later pass rather than on an address this node made
/// up. And nothing is removed for a task this node still claims but the store
/// has not caught up with (`keep` below) — the store's copy of a task's status
/// travels through the leader, so it necessarily lags this node's own agent.
async fn reconcile_ports(
    store: &ClusterStore,
    node_id: &Id,
    node: &NodeRuntime,
    force: bool,
) -> Option<satl_net::PortReconcile> {
    let (tasks, mesh) = {
        // Scope the view: its guard is !Send.
        let view = store.view();
        (view.tasks(), mesh_context(&view, node_id))
    };
    reconcile_ports_over(&tasks, node_id, node, force, mesh.as_ref()).await
}

/// The ingress network's contribution to a manager's port pass (M6d): the
/// egress view rendered into the `satl/rdr` anchor (SNAT source + MSS clamp),
/// and the network id whose task attachments carry the pool members'
/// addresses. `None` when the cluster has no ingress network (nothing
/// publishes an ingress port — the network is created lazily, SWK §9.3) or
/// this node's gateway on it is not allocated yet; both resolve on a later
/// pass.
struct MeshContext {
    /// SNAT source, bridge and clamp rendered by `satl_net::mesh_rules`.
    egress: satl_net::MeshEgress,
    /// The ingress network's id.
    network: Id,
}

/// Read the mesh half of the pass out of the store.
fn mesh_context(view: &satl_cluster::StoreView<'_>, node_id: &Id) -> Option<MeshContext> {
    let ingress = view
        .networks()
        .into_iter()
        .find(|network| network.spec.ingress)?;
    let gateway = ingress.node_gateways.get(node_id)?.parse().ok()?;
    let subnet = ingress.subnet.as_deref()?.parse().ok()?;
    let vni = ingress.vni?;
    Some(MeshContext {
        egress: satl_net::MeshEgress {
            gateway,
            bridge: satl_net::overlay_bridge_name(vni),
            subnet,
            // The overlay MTU minus IPv4 + TCP headers: 1450 -> 1410 on the
            // measured OVH underlay (docs/vxlan.md).
            max_mss: u16::try_from(satl_overlay::DEFAULT_OVERLAY_MTU - 40).unwrap_or(u16::MAX),
        },
        network: ingress.id.clone(),
    })
}

/// A task's address on the ingress network, from its attachment. Remote tasks
/// carry it on the task object — node-local IPAM has no entry for them.
fn ingress_address(task: &satl_core::Task, network: &Id) -> Option<std::net::Ipv4Addr> {
    let attachment = task
        .networks
        .iter()
        .find(|attachment| &attachment.network_id == network)?;
    let cidr = attachment.addresses.first()?;
    cidr.split('/').next()?.parse().ok()
}

/// Which address one published port redirects to, from this node's point of
/// view — the whole mesh routing decision in one pure function:
///
/// - **host mode** is node-local by definition: a local task's bridge
///   address, and another node's task is never published here;
/// - **ingress mode with a mesh** (managers, once the ingress network
///   exists): the task's ingress attachment address, local or remote — that
///   is what a replica-less node relays to. A local task without its
///   attachment yet (created before M6d, or the allocator a pass behind)
///   falls back to its bridge address, the pre-mesh behavior, so nothing
///   goes dark in between;
/// - **ingress mode without a mesh** (workers, no ingress network): the
///   pre-M6d behavior — node-local only.
fn resolve_port_publish(
    task: &satl_core::Task,
    port: &satl_core::PortConfig,
    local: bool,
    local_addr: Option<std::net::Ipv4Addr>,
    mesh: Option<&MeshContext>,
) -> Option<PortPublish> {
    let task_ip = match port.publish_mode {
        satl_core::PublishMode::Host if local => local_addr,
        satl_core::PublishMode::Host => None,
        satl_core::PublishMode::Ingress => match mesh {
            Some(mesh) => match ingress_address(task, &mesh.network) {
                Some(addr) => Some(addr),
                None if local => local_addr,
                None => None,
            },
            None if local => local_addr,
            None => None,
        },
    }?;
    Some(PortPublish {
        proto: port.protocol,
        host_port: port.published_port,
        task_ip,
        task_port: port.target_port,
    })
}

/// The task-set half of [`reconcile_ports`], shared with the worker path
/// (whose tasks come from the local DB rather than a store — and which has no
/// store to read the ingress network from, so it passes `mesh: None` and
/// keeps the pre-mesh, node-local behavior).
async fn reconcile_ports_over(
    tasks: &[Arc<satl_core::Task>],
    node_id: &Id,
    node: &NodeRuntime,
    force: bool,
    mesh: Option<&MeshContext>,
) -> Option<satl_net::PortReconcile> {
    let network = node.executor.network();
    let (running, (alive, dead)) = (
        running_task_ports(tasks, node_id, mesh.map(|mesh| &mesh.network)),
        task_verdicts(tasks, node_id),
    );
    // What must not be dropped: everything this node's worker holds — a
    // container whose controller published its ports a millisecond ago is in
    // neither the desired set nor the store yet — plus everything the store
    // still considers live, whose redirect a transient IPAM miss must not cost
    // it. Minus what the store reports terminal, which is the one statement
    // that *does* mean "drop it": the worker keeps a finished task until its
    // assignment is withdrawn, and a redirect outliving its container points at
    // an address IPAM will hand to the next one.
    //
    // The set is deliberately node-local: a remote task's redirect is the
    // store's business alone (it is in `wanted` while healthy and drops out
    // the pass the store reports it terminal), and this node's worker knows
    // nothing about it.
    let mut keep: BTreeSet<String> = alive;
    keep.extend(
        node.worker
            .task_ids()
            .await
            .into_iter()
            .map(|id| id.as_str().to_owned()),
    );
    keep.retain(|task_id| !dead.contains(task_id));
    // A proxy-mode task's port must not linger on the pf path either: the
    // second-opinion keep union protects entries for tasks this node still
    // holds, so proxy tasks are excepted from it.
    let proxy_tasks: BTreeSet<String> = tasks
        .iter()
        .filter(|task| {
            satl_core::defaults::proxy_protocol_enabled(&task.service_annotations.labels)
        })
        .map(|task| task.id.as_str().to_owned())
        .collect();
    keep.retain(|task_id| !proxy_tasks.contains(task_id));

    let mut wanted: BTreeMap<String, Vec<PortPublish>> = BTreeMap::new();
    // The proxy-mode set (M6e): ports of services labeled
    // `satl.publish.proxy_protocol=v2` go to `satld`'s userspace proxy
    // instead of the pf pool — never both, or the kernel's rdr wins the race
    // for the packet and the proxy sees nothing.
    let mut proxy_wanted: BTreeMap<(u16, satl_core::PortProtocol), Vec<(std::net::Ipv4Addr, u16)>> =
        BTreeMap::new();
    for (task, ports) in running {
        let local = belongs_to(&task, node_id);
        // Read the bridge address once per task, and only for a local one: a
        // remote task has no entry in this node's IPAM by construction.
        let local_addr = if local {
            address_of_local(network, &node.network_name, &task.id)
        } else {
            None
        };
        let proxy_mode =
            satl_core::defaults::proxy_protocol_enabled(&task.service_annotations.labels);
        let publishes: Vec<PortPublish> = ports
            .iter()
            .filter_map(|port| {
                let publish = resolve_port_publish(&task, port, local, local_addr, mesh)?;
                if proxy_mode && port.protocol == satl_core::PortProtocol::Tcp {
                    proxy_wanted
                        .entry((port.published_port, port.protocol))
                        .or_default()
                        .push((publish.task_ip, publish.task_port));
                    return None;
                }
                Some(publish)
            })
            .collect();
        if !publishes.is_empty() {
            wanted.insert(task.id.as_str().to_owned(), publishes);
        }
    }
    node.proxy.update(proxy_wanted).await;

    let summary = describe_redirects(&wanted);
    match network
        .reconcile_published_ports(wanted, &keep, force, mesh.map(|mesh| mesh.egress.clone()))
        .await
    {
        Ok(report) => {
            if report.changed {
                tracing::info!(
                    tasks = report.tasks,
                    redirects = report.redirects,
                    published = %summary,
                    mesh = mesh.is_some(),
                    "published ports converged; the satl/rdr anchor was reloaded"
                );
            }
            Some(report)
        }
        Err(error) => {
            tracing::error!(
                %error,
                published = %summary,
                "converging the satl/rdr anchor failed; published ports may be stale \
                 until the next pass"
            );
            None
        }
    }
}

/// The local bridge address IPAM has on record for a task, with the one line
/// its absence deserves: normal for a task that reached STARTING in the store
/// before its controller attached it.
fn address_of_local(
    network: &satl_net::NetworkManager,
    network_name: &str,
    task_id: &Id,
) -> Option<std::net::Ipv4Addr> {
    let addr = network.address_of(network_name, task_id.as_str());
    if addr.is_none() {
        tracing::debug!(
            task_id = %task_id,
            "no address on record yet; its published ports wait for the next pass"
        );
    }
    addr
}

/// The published redirects, as one greppable line: `<task id>=<port>/<proto>-><ip>:<port>`.
fn describe_redirects(wanted: &BTreeMap<String, Vec<PortPublish>>) -> String {
    let mut out = String::new();
    for (task_id, ports) in wanted {
        for port in ports {
            if !out.is_empty() {
                out.push(' ');
            }
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "{task_id}={host}/{proto}->{ip}:{target}",
                    host = port.host_port,
                    proto = port.proto,
                    ip = port.task_ip,
                    target = port.task_port
                ),
            );
        }
    }
    if out.is_empty() {
        out.push_str("none");
    }
    out
}

/// Published ports of the tasks running on this node, by task.
///
/// **Both publish modes**, because both end up in the same anchor and neither
/// is announced to this node any other way. What separates them is upstream:
/// a host-mode port is whatever the spec asked for, while an ingress port is
/// assigned by the cluster allocator — so `published_port == 0` means "not
/// allocated yet" and the task simply is not published until it is
/// (`satl_orchestrator::allocator::ports`, SWK §9.5).
///
/// Observed state and desired state are both consulted, and they answer two
/// different questions. Observed state (`>= STARTING`, not terminal) is "does
/// this task have a container to send packets to". Desired state
/// (`< SHUTDOWN`) is "does the cluster still want it": a manager writes
/// `SHUTDOWN`/`REMOVE` *before* the agent acts on it (architecture §4 rule 3,
/// desired state never decreases), so it is the one statement about a stopping
/// task that is never late — where the store's copy of the *observed* state
/// necessarily lags this node's own agent by a round trip through the leader.
///
/// Without the desired-state half, this pass republishes a redirect the agent
/// has just removed, because the store still shows the task RUNNING for one
/// more round trip; the redirect then points at a container that is going away
/// until the next pass, and on a node running two tasks of the service pf's
/// round-robin pool (api-compat 76) sends every other connection into it.
/// Measured on the cluster: removed at 38.837, put back at 38.977, dropped
/// again at 43.976.
///
/// This cannot unpublish a task that is still serving, because it does not
/// remove anything: removal is decided by `keep` in [`reconcile_ports_over`],
/// which this filter does not touch. All that is withheld is the *authority to
/// publish* — a task already redirected keeps its entry until its own agent
/// takes it away at container stop (`unpublish_ports`) or the store reports it
/// terminal. What is withheld is a redirect that does not exist yet, for a task
/// the cluster has already decided to stop; creating one could only add a
/// failing member to the pool.
///
/// What this does *not* close: a container that exits on its own, where no
/// manager wrote a desired state and the store's lagging copy of the observed
/// state is the only signal a manager-side pass has. That window is the same
/// round trip, bounded by one pass, and the agent's own removal is what ends it.
/// Closing it too would mean deriving the wanted set from the node's own worker
/// rather than from the store, which is a different pass.
fn running_task_ports(
    tasks: &[Arc<satl_core::Task>],
    node_id: &Id,
    ingress: Option<&Id>,
) -> Vec<(Arc<satl_core::Task>, Vec<satl_core::PortConfig>)> {
    tasks
        .iter()
        .filter(|task| {
            // With a mesh (managers, once the ingress network exists) the
            // pool is cluster-wide: every healthy task publishing an ingress
            // port is a candidate member, wherever it runs. Without one —
            // workers, or a cluster with no ingress publishing — the pass is
            // node-local, the pre-M6d behavior.
            (ingress.is_some() || belongs_to(task, node_id))
                && task.status.state >= satl_core::TaskState::Starting
                && !task.status.state.is_terminal()
                && task.desired_state < DesiredState::Shutdown
        })
        .filter_map(|task| {
            let ports: Vec<satl_core::PortConfig> = task
                .endpoint
                .iter()
                .flat_map(|endpoint| &endpoint.ports)
                .filter(|port| port.published_port != 0)
                .cloned()
                .collect();
            (!ports.is_empty()).then(|| (Arc::clone(task), ports))
        })
        .collect()
}

/// What the store says about this node's tasks, in the only two categories the
/// port pass cares about: `(still live, finished)`.
///
/// A task in neither is one the store has never heard of, which is exactly the
/// case where the store must not be allowed to remove anything.
fn task_verdicts(
    tasks: &[Arc<satl_core::Task>],
    node_id: &Id,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut alive = BTreeSet::new();
    let mut dead = BTreeSet::new();
    for task in tasks {
        if !belongs_to(task, node_id) {
            continue;
        }
        let id = task.id.as_str().to_owned();
        if task.status.state.is_terminal() {
            dead.insert(id);
        } else {
            alive.insert(id);
        }
    }
    (alive, dead)
}

// ---------------------------------------------------------------------------
// The periodic dataset sweep
// ---------------------------------------------------------------------------

/// What one periodic pass remembers from the last one.
///
/// Two jobs, both about not doing damage and not making noise:
///
/// - **two strikes.** A dataset is destroyed only if it was unclaimed on two
///   consecutive passes. The claim set is read from two places that are both
///   momentarily incomplete at different times (the store just after a
///   leadership change, the worker just after a restart), and one pass in which
///   they disagree with the disk must not be enough to destroy a live task's
///   rootfs.
/// - **one line per problem.** A dataset that stays busy is expected — that is
///   what the deferral is for — so it is reported once and then only at debug
///   until it either goes away or comes back.
#[derive(Debug, Default)]
pub struct DatasetSweeper {
    /// Datasets that had no live task on the previous pass.
    unclaimed: BTreeSet<String>,
    /// Datasets whose failure to be destroyed has already been reported.
    reported: BTreeSet<String>,
}

impl DatasetSweeper {
    /// The datasets to destroy this pass: those unclaimed now *and* last time.
    ///
    /// Also forgets everything that is no longer on disk, so neither set can
    /// grow without bound on a node that churns tasks.
    fn plan(&mut self, present: &[String], live: &BTreeSet<String>) -> Vec<String> {
        let on_disk: BTreeSet<String> = present.iter().cloned().collect();
        self.reported.retain(|id| on_disk.contains(id));
        let unclaimed: BTreeSet<String> = on_disk
            .into_iter()
            .filter(|id| !live.contains(id))
            .collect();
        let due = unclaimed
            .iter()
            .filter(|id| self.unclaimed.contains(*id))
            .cloned()
            .collect();
        self.unclaimed = unclaimed;
        due
    }

    /// Whether this failure is the first one for `id`, i.e. worth a warn.
    fn first_failure(&mut self, id: &str) -> bool {
        self.reported.insert(id.to_owned())
    }

    /// A dataset that is gone: anything remembered about it goes with it.
    fn forget(&mut self, id: &str) {
        self.unclaimed.remove(id);
        self.reported.remove(id);
    }
}

/// The mount half of the periodic pass, with the same two-strike rule.
///
/// Keyed by **task id**, not by mountpoint: the three or six mounts of one task
/// stand or fall together, and a claim set that was momentarily missing a task
/// must not cost that task its `/tmp` on the strength of one reading. Unmounting
/// a live container's `/tmp` would not lose a dataset, but it would break a
/// running container in a way nothing reports.
#[derive(Debug, Default)]
pub struct MountSweeper {
    /// Task ids whose mounts were unclaimed on the previous pass.
    unclaimed: BTreeSet<String>,
}

impl MountSweeper {
    /// The task ids whose leftover mounts may be unmounted this pass: those
    /// unclaimed now *and* last time. `present` is every task id that has a
    /// mount under the containers root.
    fn plan(&mut self, present: &BTreeSet<String>, live: &BTreeSet<String>) -> BTreeSet<String> {
        let unclaimed: BTreeSet<String> = present
            .iter()
            .filter(|id| !live.contains(*id))
            .cloned()
            .collect();
        let due = unclaimed
            .iter()
            .filter(|id| self.unclaimed.contains(*id))
            .cloned()
            .collect();
        self.unclaimed = unclaimed;
        due
    }

    /// What this pass saw as unclaimed but is not allowed to act on yet.
    fn awaiting_agreement(&self) -> &BTreeSet<String> {
        &self.unclaimed
    }
}

/// Start the node's periodic passes: the dataset sweep, the port sweep and
/// the linuxulator re-probe.
///
/// All belong to the *node* rather than to a cluster (see each), and all are
/// cancelled by the daemon's own shutdown token, so they are started and
/// stopped together.
pub fn spawn_node_sweeps(
    slot: &Arc<ClusterSlot>,
    node: &Arc<NodeRuntime>,
    sysctl: Sysctl,
    shutdown: &CancellationToken,
) -> [JoinHandle<()>; 3] {
    [
        spawn_dataset_sweep(Arc::clone(slot), Arc::clone(node), shutdown.clone()),
        spawn_port_sweep(Arc::clone(slot), Arc::clone(node), shutdown.clone()),
        spawn_linux_probe(sysctl, node.linux.clone(), shutdown.clone()),
    ]
}

/// What one linuxulator re-probe observed, when it observed a change at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxTransition {
    /// `kldload linux` happened: `linux/*` images become selectable.
    BecameAvailable,
    /// `linux.ko` is gone: new `linux/*` tasks will be rejected on this node.
    BecameUnavailable,
}

/// Record `probed` in the shared handle and name the transition, if any.
///
/// Pure with respect to logging so the log-on-transition-only rule is unit
/// testable: `Some` exactly when the value flipped, `None` on steady state.
fn record_linux_probe(linux: &LinuxEmulation, probed: bool) -> Option<LinuxTransition> {
    match (linux.set(probed), probed) {
        (false, true) => Some(LinuxTransition::BecameAvailable),
        (true, false) => Some(LinuxTransition::BecameUnavailable),
        _ => None,
    }
}

/// Re-probe the linuxulator every [`LINUX_PROBE_INTERVAL`], flipping the
/// shared [`LinuxEmulation`] handle and logging transitions in both
/// directions (see [`LINUX_PROBE_INTERVAL`] for why this exists).
///
/// Node-local like the other sweeps: kernel modules belong to the host and
/// outlive any one cluster. The probe is `tokio::process`-based
/// ([`Sysctl::get`]), so nothing here blocks the runtime (invariant #4).
pub fn spawn_linux_probe(
    sysctl: Sysctl,
    linux: LinuxEmulation,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(LINUX_PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; skip it, since the startup probe in
        // `node::build` has just run and logged its result.
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    let probed = crate::node::probe_linux_emulation(&sysctl).await;
                    match record_linux_probe(&linux, probed) {
                        Some(LinuxTransition::BecameAvailable) => tracing::info!(
                            "linuxulator is now available; linux/* images may be selected \
                             (the node description update follows within 20s)"
                        ),
                        Some(LinuxTransition::BecameUnavailable) => tracing::warn!(
                            "linuxulator is no longer available; new linux/* tasks on this \
                             node will be rejected, running linux tasks are unaffected \
                             (service linux start to restore)"
                        ),
                        None => {}
                    }
                }
            }
        }
    })
}

/// Re-run the dataset sweep every [`DATASET_SWEEP_INTERVAL`].
///
/// Reads the cluster through the slot rather than through one store handle:
/// a `swarm join` or `swarm leave` replaces the cluster runtime under the
/// daemon, and this loop belongs to the *node*, whose datasets outlive any one
/// cluster.
pub fn spawn_dataset_sweep(
    slot: Arc<ClusterSlot>,
    node: Arc<NodeRuntime>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DATASET_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; skip it, since the startup pass has just
        // swept everything there was to sweep.
        ticker.tick().await;
        let mut sweeper = DatasetSweeper::default();
        let mut mounts = MountSweeper::default();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => {
                    if let Some(core) = slot.get() {
                        let start = std::time::Instant::now();
                        let claimed =
                            claimed_tasks(core.store(), &core.node_id, &node).await;
                        // Mounts first: a dataset cannot be destroyed while
                        // anything is mounted below it.
                        mount_sweep_pass(&node, &claimed, &mut mounts).await;
                        dataset_sweep_pass(&node, &claimed, &mut sweeper).await;
                        satl_metrics::observe_reconcile_pass(
                            "dataset",
                            "ok",
                            start.elapsed().as_secs_f64(),
                        );
                    } else {
                        satl_metrics::observe_reconcile_pass("dataset", "skipped", 0.0);
                    }
                }
            }
        }
    })
}

/// Re-derive the `satl/rdr` anchor every [`PORT_SWEEP_INTERVAL`] — and,
/// on a manager, **on every store event that can move a pool member**.
///
/// Hangs off the *node*, not off a cluster, for the same reason the dataset
/// sweep does: the anchor is host state that outlives any one cluster, and a
/// `swarm join` or `swarm leave` replaces the cluster runtime underneath. When
/// the slot is empty there is no store to derive anything from, so the pass
/// waits rather than flushing — a daemon between clusters must not tear the
/// redirects off containers that are still running.
///
/// Why the event feed, not just the timer (M6d): the mesh made pool
/// membership cluster-wide, and a store-driven membership necessarily lags a
/// task's own lifecycle by one status round trip. A rolling update stopping a
/// task would otherwise leave a black hole in every node's pool for up to one
/// sweep interval — measured on the cluster as lost requests during
/// `rolling_update`, where the pre-mesh, edge-triggered removal was
/// effectively instant. Waking on task/network store events brings the pool
/// update to one event loop's latency; an unchanged pass costs one store
/// read and no pfctl, and the periodic tick remains as the level (and the
/// only driver on a worker, which has no store).
pub fn spawn_port_sweep(
    slot: Arc<ClusterSlot>,
    node: Arc<NodeRuntime>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PORT_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; skip it, since the startup pass has just
        // written the anchor.
        ticker.tick().await;
        let mut passes: u32 = 0;
        loop {
            // Subscribed per pass: the receiver starts at the feed's tail, and
            // a `swarm join`/`leave` replacing the runtime underneath is picked
            // up on the next wake rather than never.
            let mut events = slot
                .get()
                .and_then(|core| core.store().cloned())
                .map(|store| store.watch());
            let wake = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                _ = ticker.tick() => Wake::Tick,
                received = async {
                    match events.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => match received {
                    Ok(event) => {
                        if pool_relevant(&event) {
                            Wake::StoreEvent
                        } else {
                            continue;
                        }
                    }
                    // Events were lost: the pass is the resync.
                    Err(_) => Wake::StoreEvent,
                },
            };
            let force = match wake {
                Wake::Tick => {
                    passes = passes.wrapping_add(1);
                    passes.is_multiple_of(PORT_REASSERT_EVERY)
                }
                Wake::StoreEvent => false,
            };
            if let Some(core) = slot.get() {
                let start = std::time::Instant::now();
                if let Some(store) = core.store() {
                    reconcile_ports(store, &core.node_id, &node, force).await;
                } else {
                    // A worker's task DB is its assignment set,
                    // persisted; the anchor is a function of it.
                    let tasks = local_tasks(&node).await;
                    reconcile_ports_over(&tasks, &core.node_id, &node, force, None).await;
                }
                satl_metrics::observe_reconcile_pass("port", "ok", start.elapsed().as_secs_f64());
            } else {
                satl_metrics::observe_reconcile_pass("port", "skipped", 0.0);
            }
        }
    })
}

/// What woke the port sweep.
enum Wake {
    /// The periodic level.
    Tick,
    /// A pool-relevant store event (or a lost feed, which the pass resyncs).
    StoreEvent,
}

/// Whether a store event can change a pool's membership: a task's state,
/// ports or attachments moving, or the ingress network's allocation changing
/// the mesh half. Anything else (services, nodes, secrets, commit markers)
/// cannot, and waking for it would only spin the pass.
fn pool_relevant(event: &satl_core::StoreEvent) -> bool {
    use satl_core::{ObjectKind, StoreEvent, StoreObject};
    match event {
        StoreEvent::Created(object) | StoreEvent::Updated { new: object, .. } => {
            matches!(object, StoreObject::Task(_) | StoreObject::Network(_))
        }
        StoreEvent::Removed { kind, .. } => {
            matches!(kind, ObjectKind::Task | ObjectKind::Network)
        }
        StoreEvent::Commit(_) => false,
    }
}

/// One periodic pass: destroy every container dataset no live task claims.
/// `store` is `None` on a worker, whose claims come from the local task DB.
async fn dataset_sweep_pass(
    node: &NodeRuntime,
    live: &BTreeSet<String>,
    sweeper: &mut DatasetSweeper,
) {
    let present = match node.executor.container_fs().list().await {
        Ok(datasets) => datasets,
        Err(error) => {
            tracing::warn!(%error, "the periodic sweep cannot list container datasets");
            return;
        }
    };
    if present.is_empty() {
        sweeper.plan(&present, &BTreeSet::new());
        return;
    }
    for task_id in sweeper.plan(&present, live) {
        let dataset = format!("{}/{task_id}", node.datasets.containers_root);
        match node.executor.container_fs().destroy(&task_id).await {
            Ok(()) => {
                sweeper.forget(&task_id);
                tracing::info!(
                    task_id = %task_id,
                    %dataset,
                    "the periodic sweep destroyed a container dataset no live task claims"
                );
            }
            Err(error) if sweeper.first_failure(&task_id) => tracing::warn!(
                task_id = %task_id,
                %dataset,
                %error,
                "the periodic sweep cannot destroy this container dataset yet; it will \
                 try again on the next pass"
            ),
            Err(error) => tracing::debug!(
                task_id = %task_id,
                %dataset,
                %error,
                "container dataset still not destroyable"
            ),
        }
    }
}

/// One periodic mount pass: unmount everything under the containers root that
/// belongs to a task nothing claims, on the second consecutive pass that agrees.
///
/// Why this needs a level of its own rather than riding on the dataset sweep:
/// the two failure modes are different. A dataset is left behind by a removal
/// that could not finish, and it disappears as soon as the jail dies. A mount is
/// left behind by something *outside* SatL force-unmounting the dataset under it
/// (measured: `tests/cluster/reset.sh` doing exactly that, 54 task ids' worth
/// per node), and once the dataset is gone the dataset sweep has nothing left to
/// notice. So this pass keys on the mount table, which is the only place the
/// leftover still exists — and on `mount -p`, because these mounts are
/// `MNT_IGNORE` and plain `mount` does not list them at all.
async fn mount_sweep_pass(node: &NodeRuntime, live: &BTreeSet<String>, sweeper: &mut MountSweeper) {
    let Some(root) = containers_root_path(node).await else {
        return;
    };
    let mounts = node.executor.runtime().mounts();
    let entries = match mounts.list().await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "the periodic sweep cannot read the mount table");
            return;
        }
    };
    let present: BTreeSet<String> = entries
        .iter()
        .filter_map(|entry| satl_runtime::task_of_mount(entry, &root))
        .collect();
    if present.is_empty() {
        sweeper.plan(&present, &BTreeSet::new());
        return;
    }
    let due = sweeper.plan(&present, live);
    let deferred: Vec<&String> = sweeper
        .awaiting_agreement()
        .iter()
        .filter(|id| !due.contains(*id))
        .collect();
    if !deferred.is_empty() {
        tracing::debug!(
            tasks = ?deferred,
            "leftover container mounts seen for the first time; they need a second \
             agreeing pass before anything is unmounted"
        );
    }
    if due.is_empty() {
        return;
    }
    match mounts
        .unmount_orphans_under(&root, &union_of(live, &present, &due))
        .await
    {
        Ok(unmounted) if unmounted.is_empty() => {}
        Ok(unmounted) => tracing::info!(
            tasks = due.len(),
            mounts = unmounted.len(),
            "the periodic sweep unmounted leftover container mounts no live task claims"
        ),
        Err(error) => tracing::warn!(
            containers_root = %root.display(),
            %error,
            "the periodic sweep cannot read the mount table to unmount leftovers"
        ),
    }
}

/// The claim set to hand the unmount call: everything present that is **not**
/// due this pass, so a task still awaiting its second agreeing pass is treated
/// as claimed and left alone.
fn union_of(
    live: &BTreeSet<String>,
    present: &BTreeSet<String>,
    due: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut keep = live.clone();
    keep.extend(present.iter().filter(|id| !due.contains(*id)).cloned());
    keep
}

/// Every task id that may legitimately own a container dataset on this node.
///
/// The union of two views on purpose. The **store** is the cluster's opinion,
/// and it holds a task from the moment it is created — including one whose
/// rootfs the agent is cloning right now. The **worker** is this node's own,
/// and it holds what the dispatcher actually told this node to run, which
/// survives a store this node has not caught up with. A dataset claimed by
/// neither is a leftover.
///
/// On a worker (`store` is `None`), the cluster's opinion is the **local task
/// DB**: it is on disk before a session exists, so a worker cut off from its
/// managers never watches this sweep destroy a live task's rootfs.
async fn claimed_tasks(
    store: Option<&ClusterStore>,
    node_id: &Id,
    node: &NodeRuntime,
) -> BTreeSet<String> {
    let mut claimed: BTreeSet<String> = match store {
        Some(store) => {
            // Scope the view: its guard is !Send.
            let view = store.view();
            view.tasks()
                .into_iter()
                .filter(|task| belongs_to(task, node_id))
                .map(|task| task.id.as_str().to_owned())
                .collect()
        }
        None => local_tasks(node)
            .await
            .into_iter()
            .map(|task| task.id.as_str().to_owned())
            .collect(),
    };
    claimed.extend(
        node.worker
            .task_ids()
            .await
            .into_iter()
            .map(|id| id.as_str().to_owned()),
    );
    claimed
}

/// Delete every jail in ocijail's state db whose id is not a live task.
async fn sweep_jails(node: &NodeRuntime, live: &BTreeSet<String>, report: &mut ReconcileReport) {
    let states = match node.executor.runtime().reconcile_list().await {
        Ok(states) => states,
        Err(error) => {
            tracing::error!(%error, "cannot list containers from the ocijail state db");
            return;
        }
    };
    for state in states {
        if live.contains(&state.id) {
            tracing::debug!(jail_id = %state.id, status = ?state.status, "adopted container");
            continue;
        }
        let rootfs = self_rootfs(node, &state.id).await;
        tracing::warn!(
            jail_id = %state.id,
            status = ?state.status,
            rootfs = %rootfs.display(),
            "destroying a container no live task claims"
        );
        match node
            .executor
            .runtime()
            .delete(&state.id, &rootfs, true)
            .await
        {
            Ok(_) => report.jails_destroyed.push(state.id),
            Err(error) => {
                tracing::error!(jail_id = %state.id, %error, "deleting the orphaned container failed");
            }
        }
    }
}

/// Remove the rctl rules of every SatL-shaped jail subject whose prison is
/// gone.
///
/// Rules survive their jail's death and nothing else removes them — the
/// audit measured four rule sets from the previous day still installed
/// after a full `reset.sh` and a ZFS dataset destroy. The same audit proved
/// the old belief wrong: `rctl -r jail:<dead>` returns 0 and drops the
/// rules (`No such process` is what a filter matching *no rule* returns,
/// not what a dead subject returns), so a reboot is not the only purge.
///
/// The live set is `jls`'s, not the store's: the question here is whether
/// the *subject* exists in the kernel, and `jls -d` is ground truth for
/// that. A dying prison still counts as live — its rules become purgeable
/// once the prison is fully gone, and the next startup's pass reaps them
/// rather than this one racing the teardown. Which subjects are eligible at
/// all is the wrapper's task-id-shape filter: a third party's rules are
/// never touched, however dead its jail.
///
/// Warn-not-fail throughout: a node with racct off has no rules and spawns
/// no `rctl`; a listing failure skips the purge for this pass.
async fn sweep_rctl_rules(node: &NodeRuntime, report: &mut ReconcileReport) {
    let rctl = node.executor.rctl();
    if !rctl.racct_enabled() {
        return;
    }
    let live: BTreeSet<String> = match node.executor.jails().list().await {
        Ok(jails) => jails.into_iter().map(|(name, _state)| name).collect(),
        Err(error) => {
            tracing::warn!(%error, "cannot list prisons; skipping the orphan rctl rule purge");
            return;
        }
    };
    match rctl.purge_orphan_rules(&live).await {
        Ok(purged) => report.rctl_rules_purged = purged,
        Err(error) => {
            tracing::warn!(%error, "cannot list rctl rules; orphan rules survive until the next pass");
        }
    }
}

/// The path container rootfs datasets are mounted under, or `None` when the
/// containers dataset has no mountpoint to look below.
async fn containers_root_path(node: &NodeRuntime) -> Option<std::path::PathBuf> {
    match node
        .executor
        .zfs()
        .mountpoint_of(&node.datasets.containers_root)
        .await
    {
        Ok(path) => Some(path),
        Err(error) => {
            tracing::warn!(
                dataset = %node.datasets.containers_root,
                %error,
                "cannot resolve where container datasets are mounted; skipping the \
                 leftover mount sweep"
            );
            None
        }
    }
}

/// Unmount every mount under `<containers root>/<task id>` whose task nothing
/// claims.
///
/// **This closes a leak that was invisible to every audit we had.** ocijail
/// performs its bundle mounts (devfs, fdescfs, the per-task tmpfs `/tmp`, and
/// linprocfs/linsysfs/`/dev/shm` for a Linux image) with `MNT_IGNORE`, so plain
/// `mount`(8) lists none of them — only `mount -p` and `mount -v` do
/// (mount(8) on `-v`: "show all file systems, including those that were mounted
/// with the `MNT_IGNORE` flag"). Measured on the cluster nodes: 54, 54 and 56
/// stale tmpfs, three mounts each for 54 task ids long gone, while the leftovers
/// audit -- which looked at jails, epairs and datasets -- reported every node
/// clean.
///
/// They did not come from the removal path. A task's own `remove` calls
/// `ocijail delete`, which unmounts, and `satl-runtime` sweeps whatever is left
/// under the rootfs afterwards; across 247 removals on those nodes the log says
/// "no leaked mounts" 247 times and never once reports a sweep. What orphaned
/// them was `umount -f` on the *rootfs dataset itself* while its `MNT_IGNORE`
/// submounts were still there (`tests/cluster/reset.sh` enumerated mounts with
/// plain `mount`, so it could not see them to unmount them first). Measured:
/// `zfs destroy` **refuses** while a submount exists -- `cannot unmount
/// '<path>': pool or dataset is busy` -- but a forced unmount of the parent
/// succeeds and leaves the children mounted on nothing, after which `zfs
/// destroy` succeeds and `statfs` on the orphans fails, so `df` stops showing
/// them too.
///
/// So this sweep is a level, like the dataset sweep it runs in front of, and it
/// runs *first*: a container dataset cannot be destroyed while anything is
/// mounted under it.
async fn sweep_mounts(node: &NodeRuntime, live: &BTreeSet<String>, report: &mut ReconcileReport) {
    let Some(root) = containers_root_path(node).await else {
        return;
    };
    match node
        .executor
        .runtime()
        .mounts()
        .unmount_orphans_under(&root, live)
        .await
    {
        Ok(unmounted) => {
            report.mounts_unmounted = unmounted
                .into_iter()
                .map(|node| node.display().to_string())
                .collect();
        }
        Err(error) => tracing::error!(
            containers_root = %root.display(),
            %error,
            "cannot sweep leftover container mounts"
        ),
    }
}

/// Destroy every container dataset whose task is not live.
async fn sweep_datasets(node: &NodeRuntime, live: &BTreeSet<String>, report: &mut ReconcileReport) {
    let datasets = match node.executor.container_fs().list().await {
        Ok(datasets) => datasets,
        Err(error) => {
            tracing::error!(%error, "cannot list container datasets");
            return;
        }
    };
    for task_id in datasets {
        if live.contains(&task_id) {
            continue;
        }
        tracing::warn!(
            task_id = %task_id,
            dataset = %format!("{}/{task_id}", node.datasets.containers_root),
            "destroying a container dataset no live task claims"
        );
        match node.executor.container_fs().destroy(&task_id).await {
            Ok(()) => report.datasets_destroyed.push(task_id),
            Err(error) => {
                tracing::error!(task_id = %task_id, %error, "destroying the orphaned dataset failed");
            }
        }
    }
}

/// Where an orphan's rootfs is, for the mount sweep. A missing dataset means
/// there is nothing mounted under it either, so a path that cannot exist is
/// the right answer (the sweep then finds nothing).
async fn self_rootfs(node: &NodeRuntime, task_id: &str) -> std::path::PathBuf {
    let dataset = format!("{}/{task_id}", node.datasets.containers_root);
    match node.executor.zfs().mountpoint_of(&dataset).await {
        Ok(path) => path,
        Err(error) => {
            tracing::debug!(
                %dataset,
                %error,
                "no dataset for this container; sweeping mounts under a non-existent rootfs"
            );
            std::path::PathBuf::from("/nonexistent")
        }
    }
}

#[cfg(test)]
mod tests {
    use satl_core::{
        Endpoint, EndpointMode, EndpointSpec, PortConfig, PortProtocol, PublishMode, Task,
        TaskState, TaskStatus,
    };

    use super::*;

    #[test]
    fn a_clean_report_destroyed_nothing() {
        assert!(!ReconcileReport::default().destroyed_anything());
    }

    // ---- the linuxulator re-probe ------------------------------------------

    /// The re-probe must log only on change: `Some` exactly when the value
    /// flips, `None` on steady state, in both directions.
    #[test]
    fn linux_probe_reports_transitions_only() {
        let linux = LinuxEmulation::new(false);
        assert_eq!(record_linux_probe(&linux, false), None);
        assert_eq!(
            record_linux_probe(&linux, true),
            Some(LinuxTransition::BecameAvailable)
        );
        assert_eq!(record_linux_probe(&linux, true), None);
        assert_eq!(
            record_linux_probe(&linux, false),
            Some(LinuxTransition::BecameUnavailable)
        );
        assert_eq!(record_linux_probe(&linux, false), None);
    }

    /// The helper must also have recorded the probed value in the handle,
    /// transition or not: the gate reads the handle, not the log.
    #[test]
    fn linux_probe_always_records_the_probed_value() {
        let linux = LinuxEmulation::new(true);
        record_linux_probe(&linux, false);
        assert!(!linux.get());
        record_linux_probe(&linux, false);
        assert!(!linux.get());
        record_linux_probe(&linux, true);
        assert!(linux.get());
    }

    // ---- what a node publishes ---------------------------------------------

    fn node(n: u8) -> Id {
        format!("{n:0>25}").parse().expect("25 base36 chars")
    }

    fn port(published: u16, target: u16, mode: PublishMode) -> PortConfig {
        PortConfig {
            name: String::new(),
            protocol: PortProtocol::Tcp,
            target_port: target,
            published_port: published,
            publish_mode: mode,
        }
    }

    /// A task of this node with nothing but the fields the port pass reads.
    fn task(node_id: &Id, state: TaskState, ports: Vec<PortConfig>) -> Arc<Task> {
        let mut task = crate::backend::tests::sample_task("web");
        task.node_id = Some(node_id.clone());
        task.status = TaskStatus::new(state, "test");
        task.desired_state = DesiredState::Running;
        task.endpoint = Some(Endpoint {
            spec: EndpointSpec {
                mode: EndpointMode::DnsRR,
                ports: Vec::new(),
            },
            ports,
        });
        Arc::new(task)
    }

    /// The defect this pass exists for: an ingress port is the default a
    /// `docker service create -p 8080:80` produces, and it must reach the
    /// anchor exactly like a host-mode one.
    #[test]
    fn both_publish_modes_are_published() {
        let me = node(1);
        let tasks = vec![
            task(
                &me,
                TaskState::Running,
                vec![port(8080, 80, PublishMode::Ingress)],
            ),
            task(
                &me,
                TaskState::Running,
                vec![port(9090, 80, PublishMode::Host)],
            ),
        ];
        let published = running_task_ports(&tasks, &me, None);
        assert_eq!(published.len(), 2, "{published:?}");
        let mut ports: Vec<u16> = published
            .iter()
            .flat_map(|(_, ports)| ports.iter().map(|port| port.published_port))
            .collect();
        ports.sort_unstable();
        assert_eq!(ports, [8080, 9090]);
    }

    /// A port the allocator has not assigned yet is `0`. Publishing it would
    /// mean inventing one, and inventing one means two nodes disagreeing about
    /// where a service answers.
    #[test]
    fn an_unallocated_port_is_not_published() {
        let me = node(1);
        let tasks = vec![task(
            &me,
            TaskState::Running,
            vec![port(0, 80, PublishMode::Ingress)],
        )];
        assert!(running_task_ports(&tasks, &me, None).is_empty());
    }

    /// Before STARTING there is no container and no address; after a terminal
    /// state there is no container any more. Neither may hold a redirect.
    #[test]
    fn only_tasks_with_a_container_are_published() {
        let me = node(1);
        for state in [
            TaskState::New,
            TaskState::Assigned,
            TaskState::Preparing,
            TaskState::Ready,
            TaskState::Complete,
            TaskState::Failed,
            TaskState::Shutdown,
        ] {
            let tasks = vec![task(&me, state, vec![port(8080, 80, PublishMode::Ingress)])];
            assert!(
                running_task_ports(&tasks, &me, None).is_empty(),
                "a task in {state:?} must not be published"
            );
        }
        for state in [TaskState::Starting, TaskState::Running] {
            let tasks = vec![task(&me, state, vec![port(8080, 80, PublishMode::Ingress)])];
            assert_eq!(
                running_task_ports(&tasks, &me, None).len(),
                1,
                "a task in {state:?} must be published"
            );
        }
    }

    /// The measured defect: a task the cluster has ordered to stop still reads
    /// `RUNNING` in the store for one round trip after its agent stopped it, so
    /// publishing on observed state alone re-creates the redirect the agent has
    /// just removed. Desired state is written by a manager before the agent
    /// acts, so it is never late.
    #[test]
    fn a_task_ordered_to_stop_is_not_published() {
        let me = node(1);
        for desired in [DesiredState::Shutdown, DesiredState::Remove] {
            for observed in [TaskState::Starting, TaskState::Running] {
                let mut stopping = task(&me, observed, vec![port(8080, 80, PublishMode::Ingress)]);
                Arc::get_mut(&mut stopping)
                    .expect("sole reference")
                    .desired_state = desired;
                assert!(
                    running_task_ports(&[stopping], &me, None).is_empty(),
                    "a task observed {observed:?} at desired {desired:?} must not be published"
                );
            }
        }
    }

    /// The other side of the same filter, so nobody widens it to "anything but
    /// RUNNING": a replacement task prepared at desired `READY` and a task at
    /// desired `RUNNING` are both still wanted, and `COMPLETE` (a job running
    /// to its end) is below `SHUTDOWN` on purpose.
    #[test]
    fn a_task_the_cluster_still_wants_is_published() {
        let me = node(1);
        for desired in [
            DesiredState::Ready,
            DesiredState::Running,
            DesiredState::Complete,
        ] {
            let mut wanted = task(
                &me,
                TaskState::Running,
                vec![port(8080, 80, PublishMode::Ingress)],
            );
            Arc::get_mut(&mut wanted)
                .expect("sole reference")
                .desired_state = desired;
            assert_eq!(
                running_task_ports(&[wanted], &me, None).len(),
                1,
                "a running task at desired {desired:?} must keep its redirect"
            );
        }
    }

    /// Without a mesh (a worker, or a cluster with no ingress network), the
    /// pass is node-local: this node publishes its own tasks, and another
    /// node's task of the same service is none of its business — the pre-M6d
    /// semantics, kept on exactly the paths that have no store view.
    #[test]
    fn without_a_mesh_another_nodes_task_is_never_published_here() {
        let me = node(1);
        let elsewhere = node(2);
        let tasks = vec![task(
            &elsewhere,
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Ingress)],
        )];
        assert!(running_task_ports(&tasks, &me, None).is_empty());
    }

    /// The mesh inverts that: once the ingress network exists, a remote
    /// healthy task is a pool member *here*.
    #[test]
    fn the_mesh_publishes_a_remote_healthy_task() {
        let me = node(1);
        let elsewhere = node(2);
        let ingress = node(42);
        let tasks = vec![task(
            &elsewhere,
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Ingress)],
        )];
        assert_eq!(running_task_ports(&tasks, &me, Some(&ingress)).len(), 1);
        // Terminal or stopping remote tasks leave the pool, same as local ones.
        let stopped = vec![task(
            &elsewhere,
            TaskState::Failed,
            vec![port(8080, 80, PublishMode::Ingress)],
        )];
        assert!(running_task_ports(&stopped, &me, Some(&ingress)).is_empty());
    }

    // ---- the address one published port redirects to (M6d) ------------------

    fn mesh(network: &Id) -> MeshContext {
        MeshContext {
            egress: satl_net::MeshEgress {
                gateway: "10.100.0.4".parse().unwrap(),
                bridge: "satl-br4096".to_owned(),
                subnet: "10.100.0.0/24".parse().unwrap(),
                max_mss: 1410,
            },
            network: network.clone(),
        }
    }

    /// `task`, plus an attachment to `network` carrying `addr`.
    fn task_attached(node_id: &Id, ports: Vec<PortConfig>, network: &Id, addr: &str) -> Arc<Task> {
        let mut task = task(node_id, TaskState::Running, ports);
        Arc::get_mut(&mut task)
            .expect("sole reference")
            .networks
            .push(satl_core::NetworkAttachment {
                network_id: network.clone(),
                addresses: vec![format!("{addr}/24")],
                aliases: Vec::new(),
            });
        task
    }

    #[test]
    fn the_mesh_routes_to_the_ingress_address_local_or_remote() {
        let me = node(1);
        let ingress = node(42);
        let mesh = mesh(&ingress);
        let local_addr = Some(std::net::Ipv4Addr::new(10, 88, 0, 2));
        let overlay: std::net::Ipv4Addr = "10.100.0.7".parse().unwrap();

        // A local task with its attachment: the overlay address wins over the
        // bridge address (one code path, one loop-safety argument).
        let local = task_attached(
            &me,
            vec![port(8080, 80, PublishMode::Ingress)],
            &ingress,
            "10.100.0.7",
        );
        let publish = resolve_port_publish(
            &local,
            &local.endpoint.as_ref().unwrap().ports[0],
            true,
            local_addr,
            Some(&mesh),
        )
        .unwrap();
        assert_eq!(publish.task_ip, overlay);

        // A remote task: same, from the task object alone.
        let remote = task_attached(
            &node(2),
            vec![port(8080, 80, PublishMode::Ingress)],
            &ingress,
            "10.100.0.7",
        );
        let publish = resolve_port_publish(
            &remote,
            &remote.endpoint.as_ref().unwrap().ports[0],
            false,
            None,
            Some(&mesh),
        )
        .unwrap();
        assert_eq!(publish.task_ip, overlay);
    }

    #[test]
    fn the_mesh_falls_back_for_a_local_task_without_an_attachment() {
        let me = node(1);
        let ingress = node(42);
        let mesh = mesh(&ingress);
        let local_addr = Some(std::net::Ipv4Addr::new(10, 88, 0, 2));
        let legacy = task(
            &me,
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Ingress)],
        );
        let publish = resolve_port_publish(
            &legacy,
            &legacy.endpoint.as_ref().unwrap().ports[0],
            true,
            local_addr,
            Some(&mesh),
        )
        .unwrap();
        assert_eq!(publish.task_ip, std::net::Ipv4Addr::new(10, 88, 0, 2));
        // A remote task without an attachment, though, has nothing to target.
        let remote = task(
            &node(2),
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Ingress)],
        );
        assert!(
            resolve_port_publish(
                &remote,
                &remote.endpoint.as_ref().unwrap().ports[0],
                false,
                None,
                Some(&mesh),
            )
            .is_none()
        );
    }

    #[test]
    fn host_mode_stays_node_local_mesh_or_not() {
        let me = node(1);
        let ingress = node(42);
        let mesh = mesh(&ingress);
        let local_addr = Some(std::net::Ipv4Addr::new(10, 88, 0, 2));
        let local = task(
            &me,
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Host)],
        );
        assert_eq!(
            resolve_port_publish(
                &local,
                &local.endpoint.as_ref().unwrap().ports[0],
                true,
                local_addr,
                Some(&mesh),
            )
            .unwrap()
            .task_ip,
            std::net::Ipv4Addr::new(10, 88, 0, 2)
        );
        let remote = task(
            &node(2),
            TaskState::Running,
            vec![port(8080, 80, PublishMode::Host)],
        );
        assert!(
            resolve_port_publish(
                &remote,
                &remote.endpoint.as_ref().unwrap().ports[0],
                false,
                None,
                Some(&mesh),
            )
            .is_none()
        );
    }

    #[test]
    fn only_pool_moving_events_wake_the_port_sweep() {
        use satl_core::{ObjectKind, StoreEvent, StoreObject};
        let task = task(&node(1), TaskState::Running, vec![]);
        assert!(pool_relevant(&StoreEvent::Created(StoreObject::Task(
            (*task).clone()
        ))));
        assert!(pool_relevant(&StoreEvent::Removed {
            kind: ObjectKind::Task,
            id: Id::generate(),
        }));
        assert!(!pool_relevant(&StoreEvent::Removed {
            kind: ObjectKind::Service,
            id: Id::generate(),
        }));
        assert!(!pool_relevant(&StoreEvent::Commit(satl_core::Version(1))));
    }

    /// The store's verdict on a task decides whether a redirect the pass did
    /// not ask for may survive: silence is not a verdict, terminal is.
    #[test]
    fn the_store_speaks_only_about_the_tasks_it_holds() {
        let me = node(1);
        let running = task(&me, TaskState::Running, Vec::new());
        let finished = task(&me, TaskState::Complete, Vec::new());
        let theirs = task(&node(2), TaskState::Running, Vec::new());
        let tasks = vec![
            Arc::clone(&running),
            Arc::clone(&finished),
            Arc::clone(&theirs),
        ];
        let (alive, dead) = task_verdicts(&tasks, &me);
        assert_eq!(alive, BTreeSet::from([running.id.as_str().to_owned()]));
        assert_eq!(dead, BTreeSet::from([finished.id.as_str().to_owned()]));
    }

    #[test]
    fn the_published_summary_is_one_greppable_line() {
        let mut wanted = BTreeMap::new();
        wanted.insert(
            "task1".to_owned(),
            vec![PortPublish {
                proto: PortProtocol::Tcp,
                host_port: 8080,
                task_ip: "10.88.0.2".parse().expect("test address"),
                task_port: 80,
            }],
        );
        assert_eq!(describe_redirects(&wanted), "task1=8080/tcp->10.88.0.2:80");
        assert_eq!(describe_redirects(&BTreeMap::new()), "none");
    }

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn live(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_dataset_is_destroyed_only_after_two_unclaimed_passes() {
        let mut sweeper = DatasetSweeper::default();
        assert!(
            sweeper.plan(&ids(&["a"]), &live(&[])).is_empty(),
            "one pass is never enough: the claim set can be momentarily incomplete"
        );
        assert_eq!(sweeper.plan(&ids(&["a"]), &live(&[])), ids(&["a"]));
    }

    #[test]
    fn a_dataset_claimed_on_the_second_pass_is_spared() {
        let mut sweeper = DatasetSweeper::default();
        assert!(sweeper.plan(&ids(&["a"]), &live(&[])).is_empty());
        assert!(
            sweeper.plan(&ids(&["a"]), &live(&["a"])).is_empty(),
            "the task turned up in the claim set, so its rootfs is not a leftover"
        );
        // ... and the strike is spent: it has to be unclaimed twice again.
        assert!(sweeper.plan(&ids(&["a"]), &live(&[])).is_empty());
    }

    #[test]
    fn a_live_task_is_never_planned_for_destruction() {
        let mut sweeper = DatasetSweeper::default();
        for _ in 0..5 {
            assert!(
                sweeper
                    .plan(&ids(&["a", "b"]), &live(&["a", "b"]))
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_failure_is_reported_once_and_forgotten_when_the_dataset_goes() {
        let mut sweeper = DatasetSweeper::default();
        sweeper.plan(&ids(&["a"]), &live(&[]));
        assert!(
            sweeper.first_failure("a"),
            "the first failure is worth a line"
        );
        assert!(!sweeper.first_failure("a"), "the next ones are not");
        sweeper.forget("a");
        assert!(
            sweeper.first_failure("a"),
            "a dataset that came back is news again"
        );
    }

    #[test]
    fn a_dataset_that_left_the_disk_is_forgotten() {
        let mut sweeper = DatasetSweeper::default();
        sweeper.plan(&ids(&["a"]), &live(&[]));
        sweeper.first_failure("a");
        sweeper.plan(&ids(&[]), &live(&[]));
        assert!(
            sweeper.first_failure("a"),
            "nothing is remembered about a dataset that is no longer there"
        );
    }

    // ---- the mount half of the periodic pass -------------------------------

    #[test]
    fn leftover_mounts_are_unmounted_only_after_two_agreeing_passes() {
        let mut sweeper = MountSweeper::default();
        let present = live(&["a"]);
        assert!(
            sweeper.plan(&present, &live(&[])).is_empty(),
            "one pass is never enough, here as everywhere else"
        );
        assert_eq!(sweeper.plan(&present, &live(&[])), live(&["a"]));
    }

    /// A stopped container is a claimed task: its `/tmp` is part of a container
    /// an operator can still inspect, and unmounting it breaks that container
    /// without anything reporting why.
    #[test]
    fn a_claimed_tasks_mounts_are_never_planned() {
        let mut sweeper = MountSweeper::default();
        let present = live(&["stopped", "running"]);
        for _ in 0..5 {
            assert!(sweeper.plan(&present, &present).is_empty());
        }
    }

    #[test]
    fn a_task_that_reappears_in_the_claim_set_keeps_its_mounts() {
        let mut sweeper = MountSweeper::default();
        let present = live(&["a"]);
        assert!(sweeper.plan(&present, &live(&[])).is_empty());
        assert!(
            sweeper.plan(&present, &live(&["a"])).is_empty(),
            "the task turned up, so its mounts are not leftovers"
        );
        assert!(
            sweeper.plan(&present, &live(&[])).is_empty(),
            "strike spent"
        );
    }

    /// A task on its first strike must be treated as claimed by the unmount
    /// call, or the "second pass" rule would be decorative.
    #[test]
    fn the_keep_set_protects_tasks_still_awaiting_agreement() {
        let claimed = live(&["running"]);
        let present = live(&["running", "first-strike", "due"]);
        let due = live(&["due"]);
        let keep = union_of(&claimed, &present, &due);
        assert!(keep.contains("running"));
        assert!(
            keep.contains("first-strike"),
            "a task seen unclaimed only once must not be unmounted"
        );
        assert!(!keep.contains("due"));
    }

    #[test]
    fn mounts_gone_from_the_table_stop_being_remembered() {
        let mut sweeper = MountSweeper::default();
        sweeper.plan(&live(&["a"]), &live(&[]));
        assert_eq!(sweeper.awaiting_agreement(), &live(&["a"]));
        assert!(sweeper.plan(&live(&[]), &live(&[])).is_empty());
        assert!(sweeper.awaiting_agreement().is_empty());
    }

    #[test]
    fn any_destruction_shows_in_the_summary() {
        let report = ReconcileReport {
            jails_destroyed: vec!["abc".to_owned()],
            ..ReconcileReport::default()
        };
        assert!(report.destroyed_anything());
        let report = ReconcileReport {
            epairs_destroyed: vec!["epair0a".to_owned()],
            ..ReconcileReport::default()
        };
        assert!(report.destroyed_anything());
        let report = ReconcileReport {
            mounts_unmounted: vec!["/var/db/satl/containers/abc/tmp".to_owned()],
            ..ReconcileReport::default()
        };
        assert!(
            report.destroyed_anything(),
            "a leftover mount is a leftover: the audit has to see it"
        );
    }
}
