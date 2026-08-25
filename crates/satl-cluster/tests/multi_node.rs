// SPDX-License-Identifier: BSD-2-Clause
//! Three managers, in one process, on loopback, over real mTLS gRPC.
//!
//! This is the mechanical half of M2's definition of done, proven before the
//! OVH VMs are involved: init → two joins → a proposal replicates to all
//! three → the leader dies → a new leader is elected → the store still serves
//! reads → a member is removed and re-joins with a fresh raft ID → quorum
//! safety refuses a removal that would break the cluster.
//!
//! Everything runs **unprivileged**: loopback TCP, tempdirs, and certificates
//! minted by an in-memory test CA. No `#[ignore]`, no root, no FreeBSD
//! specifics — `make check` runs it.
//!
//! Raft timings are [`RaftTiming::fast`] so elections take milliseconds
//! instead of the production 10–20 s.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use satl_ca::RoleRequirement;
use satl_cluster::membership::{self, Departing, MembershipError};
use satl_cluster::node::RaftTiming;
use satl_cluster::server::ManagerContext;
use satl_cluster::testing::TestCa;
use satl_cluster::{ClusterStore, NodeError, RaftNode, RaftNodeConfig};
use satl_core::{
    Annotations, Id, IpamConfig, Meta, Network, NetworkDriver, NetworkSpec, NodeRole, StoreAction,
    StoreObject,
};

/// What a real handover must beat in [`a_leader_demotes_itself_under_write_load`].
///
/// Comfortably above one election round at `RaftTiming::fast()` and far below
/// the `leader_lease + election_timeout` a lease expiry would cost, so the
/// assertion separates the two mechanisms rather than timing the machine.
const LEADERSHIP_TRANSFER_BUDGET: Duration = Duration::from_secs(5);

/// Upper bound on every "wait until" in these tests. Generous relative to the
/// fast raft timings, so a loaded build machine does not turn a pass into a
/// flake, but short enough that a genuine hang fails the run quickly.
const SETTLE: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// One in-process manager.
struct TestManager {
    store: ClusterStore,
    node: RaftNode,
    addr: String,
    dir: tempfile::TempDir,
}

impl TestManager {
    fn raft_id(&self) -> u64 {
        self.node.raft_id()
    }

    fn is_leader(&self) -> bool {
        self.store.metrics().is_leader
    }

    fn context(&self) -> ManagerContext {
        self.node
            .manager_slot()
            .get()
            .expect("a started manager has its context installed")
    }

    async fn shutdown(self) {
        self.node.shutdown().await.expect("clean shutdown");
        drop(self.dir);
    }
}

/// A loopback address nothing is listening on.
///
/// Binding, reading the port and closing is racy in principle; in practice
/// the kernel does not hand the same ephemeral port straight back, and the
/// alternative — binding with port 0 inside `RaftNode` — cannot work, because
/// the advertise address has to be known before the bootstrap membership is
/// committed.
fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

fn manager_config(
    dir: &tempfile::TempDir,
    name: &str,
    identity: std::sync::Arc<satl_ca::LiveIdentity>,
) -> RaftNodeConfig {
    let addr = free_addr();
    RaftNodeConfig {
        raft_dir: dir.path().join("raft"),
        node_name: name.to_owned(),
        listen_addr: Some(addr.parse::<SocketAddr>().expect("loopback addr")),
        advertise_addr: addr,
        identity: Some(identity),
        timing: RaftTiming::fast(),
        dek: None,
    }
}

/// Proposes on a freshly elected leader, tolerating only the one race the
/// test does not mean to exercise.
///
/// `is_leader()` reads a metrics flag that is set when the node wins the
/// election, but a raft leader cannot serve writes until the blank entry it
/// appends on election has committed -- and leadership can move again in
/// between. A propose in that window comes back `NotLeader`, which is the
/// protocol working, not a defect. Anything else (a deterministic rejection,
/// a raft fault) fails the test at once, so this stays a test of "the new
/// leader accepts writes" rather than a retry that would swallow a real one.
///
/// Observed once as a `make check` flake under heavy load before this existed;
/// eleven subsequent runs, eight of them under CPU contention, did not
/// reproduce it.
async fn propose_on_new_leader(
    manager: &TestManager,
    actions: Vec<StoreAction>,
) -> satl_core::Version {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match manager.store.propose(actions.clone()).await {
            Ok(version) => return version,
            Err(satl_cluster::ProposeError::NotLeader { leader_hint })
                if Instant::now() < deadline =>
            {
                tracing::debug!(
                    ?leader_hint,
                    "leadership still settling; retrying the proposal"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(other) => panic!("the new leader must accept proposals: {other}"),
        }
    }
}
async fn bootstrap(ca: &TestCa, name: &str) -> TestManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = manager_config(&dir, name, ca.live_identity(NodeRole::Manager));
    let addr = cfg.advertise_addr.clone();
    let (store, node) = RaftNode::start(cfg)
        .await
        .expect("bootstrap manager starts");
    TestManager {
        store,
        node,
        addr,
        dir,
    }
}

/// Joins an existing cluster through `remote`.
async fn join(ca: &TestCa, name: &str, remote: &str) -> TestManager {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = manager_config(&dir, name, ca.live_identity(NodeRole::Manager));
    let addr = cfg.advertise_addr.clone();
    let (store, node) = RaftNode::join(cfg, remote)
        .await
        .unwrap_or_else(|err| panic!("{name} joins {remote}: {err}"));
    TestManager {
        store,
        node,
        addr,
        dir,
    }
}

/// Polls `check` until it returns true, or fails the test after [`SETTLE`].
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + SETTLE;
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out after {SETTLE:?} waiting for: {what}");
}

fn sample_network(name: &str) -> Network {
    Network {
        id: Id::generate(),
        meta: Meta::new(),
        spec: NetworkSpec {
            annotations: Annotations {
                name: name.to_owned(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The full happy path plus a leader failure:
///
/// bootstrap → two joins → membership of three → a proposal on the leader
/// replicates to every follower → a follower forwards a mutation to the
/// leader (architecture §6.5) → the leader is killed → the survivors elect a
/// new leader → reads still work → the new leader still accepts proposals.
///
/// Deliberately one long test: forming a three-node cluster is the expensive
/// part, and splitting these assertions across tests would form it four
/// times without checking anything more.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn three_managers_form_replicate_and_survive_losing_the_leader() {
    let ca = TestCa::new();

    let first = bootstrap(&ca, "alpha").await;
    assert!(
        first.is_leader(),
        "the bootstrap node leads its own cluster"
    );
    assert_eq!(first.store.raft_members().len(), 1);
    assert!(
        first.store.view().cluster().is_some(),
        "the first manager seeds the default cluster object"
    );

    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    // Every member sees a three-voter configuration (each joiner is admitted
    // as a learner and promoted once it starts replicating).
    for (name, manager) in [("alpha", &first), ("beta", &second), ("gamma", &third)] {
        eventually(&format!("{name} sees three voting raft members"), || {
            manager
                .store
                .raft_members()
                .iter()
                .filter(|m| m.voter)
                .count()
                == 3
        })
        .await;
    }
    // Raft IDs are distinct and nonzero.
    let ids = [first.raft_id(), second.raft_id(), third.raft_id()];
    assert!(ids.iter().all(|id| *id != 0), "{ids:?}");
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        3,
        "the leader must hand out distinct raft IDs: {ids:?}"
    );

    // A proposal on the leader reaches every replica.
    let network = sample_network("frontend");
    let network_id = network.id.clone();
    let version = first
        .store
        .propose(vec![StoreAction::Create(StoreObject::Network(network))])
        .await
        .expect("the leader accepts the proposal");
    for (name, manager) in [("beta", &second), ("gamma", &third)] {
        let id = network_id.clone();
        eventually(&format!("{name} replicated the network"), || {
            manager.store.view().network(&id).is_some()
        })
        .await;
    }
    assert_eq!(
        second
            .store
            .view()
            .network(&network_id)
            .expect("replicated")
            .meta
            .version,
        version,
        "replicas carry the version the leader stamped"
    );

    // A follower forwards a mutation to the leader in one hop.
    assert!(!second.is_leader(), "beta is a follower");
    let forwarded = sample_network("backend");
    let forwarded_id = forwarded.id.clone();
    second
        .node
        .leader_client()
        .propose(
            vec![StoreAction::Create(StoreObject::Network(forwarded))],
            satl_cluster::forward::local_identity(),
        )
        .await
        .expect("a follower forwards to the leader");
    let id = forwarded_id.clone();
    eventually("the leader applied the forwarded transaction", || {
        first.store.view().network(&id).is_some()
    })
    .await;

    // Kill the leader; the survivors must elect a new one.
    let dead_raft_id = first.raft_id();
    first.shutdown().await;
    eventually("a new leader is elected among the survivors", || {
        second.is_leader() || third.is_leader()
    })
    .await;
    let (leader, follower) = if second.is_leader() {
        (&second, &third)
    } else {
        (&third, &second)
    };
    assert_ne!(
        leader.store.metrics().leader_id,
        Some(dead_raft_id),
        "the dead node must not still be believed to lead"
    );

    // Reads still work on both survivors, from the local applied store.
    for manager in [&second, &third] {
        assert!(
            manager.store.view().network(&network_id).is_some(),
            "a survivor still serves reads"
        );
        assert!(manager.store.view().cluster().is_some());
    }

    // And the new leader still accepts writes.
    let after = sample_network("after-election");
    let after_id = after.id.clone();
    propose_on_new_leader(
        leader,
        vec![StoreAction::Create(StoreObject::Network(after))],
    )
    .await;
    let id = after_id.clone();
    eventually(
        "the other survivor replicated the post-election write",
        || follower.store.view().network(&id).is_some(),
    )
    .await;

    second.shutdown().await;
    third.shutdown().await;
}

/// Removal: quorum safety refuses a removal that would leave the cluster
/// without a majority (SWK §11.5), the raft ID of a removed member is
/// blacklisted for good (SWK §11.1), and a node re-joining after being
/// removed is given a **new** ID.
#[tokio::test]
async fn removal_respects_quorum_and_never_reuses_a_raft_id() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    eventually("the cluster has three voting members", || {
        first
            .store
            .raft_members()
            .iter()
            .filter(|m| m.voter)
            .count()
            == 3
    })
    .await;
    assert!(first.is_leader(), "alpha still leads");

    let leader_ctx = first.context();
    let beta_raft_id = second.raft_id();
    let gamma_raft_id = third.raft_id();

    // Take gamma down and let its liveness age out of the window.
    third.shutdown().await;
    tokio::time::sleep(RaftTiming::fast().liveness_window() + Duration::from_millis(500)).await;

    // Removing beta now would leave {alpha, gamma} with only alpha
    // reachable: one of the two needed for quorum. Refuse.
    let err = membership::remove_member(&leader_ctx, beta_raft_id, Departing::LeavesConsensus)
        .await
        .expect_err("removing a live member while another is down must be refused");
    match err {
        MembershipError::QuorumWouldBreak {
            raft_id,
            remaining,
            reachable,
            needed,
        } => {
            assert_eq!(raft_id, beta_raft_id);
            assert_eq!((remaining, reachable, needed), (2, 1, 2));
        }
        other => panic!("expected a quorum refusal, got {other}"),
    }

    // Removing the member that is already down is safe and must succeed.
    let members = membership::remove_member(&leader_ctx, gamma_raft_id, Departing::LeavesConsensus)
        .await
        .expect("dropping the unreachable member keeps quorum");
    assert_eq!(members.len(), 2, "{members:?}");
    assert!(!members.iter().any(|m| m.raft_id == gamma_raft_id));

    // Its raft ID is blacklisted, on the leader and on the follower.
    for manager in [&first, &second] {
        let id = gamma_raft_id;
        eventually("the removed raft ID is blacklisted everywhere", || {
            manager.store.removed_raft_ids().contains(&id)
        })
        .await;
    }

    // A node re-joining from a clean directory gets a brand-new raft ID.
    let rejoined = join(&ca, "gamma-again", &first.addr).await;
    assert_ne!(
        rejoined.raft_id(),
        gamma_raft_id,
        "a removed raft ID must never be handed out again"
    );
    assert!(
        !first.store.removed_raft_ids().contains(&rejoined.raft_id()),
        "the new ID must not itself be blacklisted"
    );
    eventually("the cluster is three members again", || {
        first.store.raft_members().len() == 3
    })
    .await;

    rejoined.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
}

/// Demotion is **raft-first** (SWK §12.3): the node leaves consensus, and
/// only once it is no longer a member does its role become `worker`. Issuing
/// a worker certificate to a live raft member could cost the cluster its
/// quorum, so the order is the whole point.
#[tokio::test]
async fn demotion_leaves_consensus_before_flipping_the_role() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    eventually("the cluster has three voting members", || {
        first
            .store
            .raft_members()
            .iter()
            .filter(|m| m.voter)
            .count()
            == 3
    })
    .await;

    let gamma_id = third.node.node_id().clone();
    let gamma_raft_id = third.raft_id();
    // The joiner's node object records its manager status.
    let node = first
        .store
        .view()
        .node(&gamma_id)
        .expect("the leader recorded the joiner's node object");
    assert_eq!(node.spec.role, NodeRole::Manager);
    assert_eq!(
        node.manager_status.as_ref().map(|m| m.raft_id),
        Some(gamma_raft_id)
    );

    membership::demote_to_worker(&first.context(), &gamma_id)
        .await
        .expect("demotion succeeds while a quorum remains");

    // Phase 1: out of consensus.
    assert!(
        !first
            .store
            .raft_members()
            .iter()
            .any(|m| m.raft_id == gamma_raft_id),
        "the demoted node must be out of the raft configuration"
    );
    assert!(
        first.store.removed_raft_ids().contains(&gamma_raft_id),
        "its raft ID is blacklisted like any other removal"
    );
    // Phase 2: and only then is it a worker with no manager status.
    let node = first.store.view().node(&gamma_id).expect("node object");
    assert_eq!(node.spec.role, NodeRole::Worker);
    assert!(node.manager_status.is_none());

    // Demotion is idempotent.
    membership::demote_to_worker(&first.context(), &gamma_id)
        .await
        .expect("demoting an already-demoted node is a no-op");

    third.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
}

/// Demoting the **leader** must finish the job, not stop at consensus.
///
/// The half it used to skip is the role write. Phase 1 takes the node out of
/// consensus, and a node out of consensus stops receiving replication -- so
/// the departing node's own store freezes, and a role write built from it
/// loses the optimistic-concurrency check for ever. Measured on the testbed:
/// ten seconds of retries against a store stuck at version 25 while the leader
/// was at 45, leaving the node out of consensus with its manager role intact.
///
/// The leader now writes both halves while it still holds a moving store, so
/// what this pins is the *outcome as the survivors see it*: role worker, no
/// manager status. Reading it from the survivors and not from the demoted node
/// is the point -- the demoted node cannot see its own demotion.
#[tokio::test(flavor = "multi_thread")]
async fn demoting_the_leader_also_flips_its_role() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    eventually("the cluster has three voting members", || {
        first
            .store
            .raft_members()
            .iter()
            .filter(|m| m.voter)
            .count()
            == 3
    })
    .await;
    assert!(first.is_leader(), "alpha bootstrapped and leads");

    let alpha_id = first.node.node_id().clone();
    membership::demote_to_worker(&first.context(), &alpha_id)
        .await
        .expect("demoting the current leader completes");

    for (name, manager) in [("beta", &second), ("gamma", &third)] {
        let id = alpha_id.clone();
        eventually(
            &format!("{name} sees alpha as a worker with no manager status"),
            || {
                manager.store.view().node(&id).is_some_and(|node| {
                    node.spec.role == NodeRole::Worker && node.manager_status.is_none()
                })
            },
        )
        .await;
    }

    third.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
}

/// A leader asked to remove **itself** hands leadership over first and tells
/// the caller to retry against the new leader (SWK §11.5): a departing leader
/// cannot reliably observe its own removal commit.
#[tokio::test]
async fn a_leader_removing_itself_hands_leadership_over_first() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    eventually("the cluster has three voting members", || {
        first
            .store
            .raft_members()
            .iter()
            .filter(|m| m.voter)
            .count()
            == 3
    })
    .await;
    assert!(first.is_leader());

    let alpha_raft_id = first.raft_id();
    // The leader yields first — a departing leader cannot reliably observe
    // its own removal commit (SWK 11.5) — and the removal is then finished
    // by whoever won, over Control.LeaveRaft: the caller gets the completed
    // removal, not a "retry elsewhere" (proto/control.proto: "lets the new
    // leader do the removal").
    let members =
        membership::remove_member(&first.context(), alpha_raft_id, Departing::LeavesConsensus)
            .await
            .expect("the removal completes: yield leadership, then forwarded to the new leader");
    assert_eq!(members.len(), 2, "{members:?}");
    assert!(
        members.iter().all(|m| m.raft_id != alpha_raft_id),
        "the departing leader is out of the returned membership: {members:?}"
    );

    // Leadership really moved, and it moved to somebody else.
    eventually("another manager leads", || {
        second.is_leader() || third.is_leader()
    })
    .await;
    assert!(!first.is_leader(), "alpha stepped down");

    // The survivors agree on the two-member configuration.
    eventually(
        "the membership settles at two voters on the survivors",
        || second.store.raft_members().len() == 2 && third.store.raft_members().len() == 2,
    )
    .await;

    third.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
}

/// A leader that removes itself **while the cluster is being written to**.
///
/// This is the case the old code could never finish, and the reason the
/// existing test above passed against it: openraft 0.9 had no transfer call,
/// so `yield_leadership` stopped the local ticker and waited for a follower to
/// campaign on its own -- which only happens once that follower's leader lease
/// expires, and **every replicated write refreshes it**. An idle three-node
/// cluster at test timings expires its leases in under a second and hides the
/// defect completely; a `satld` that is reporting node and task status never
/// does, which is why the cluster suite hit it and the unit tests did not.
///
/// The write generator is therefore the load-bearing part of this test, not
/// decoration. Remove it and this passes against the broken implementation.
#[tokio::test(flavor = "multi_thread")]
async fn a_leader_demotes_itself_under_write_load() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let second = join(&ca, "beta", &first.addr).await;
    let third = join(&ca, "gamma", &first.addr).await;

    eventually("the cluster has three voting members", || {
        first
            .store
            .raft_members()
            .iter()
            .filter(|m| m.voter)
            .count()
            == 3
    })
    .await;
    assert!(first.is_leader());

    // Keep the followers' leases alive for as long as the handover takes.
    let writer_store = first.store.clone();
    let writing = Arc::new(AtomicBool::new(true));
    let writer_flag = Arc::clone(&writing);
    let writer = tokio::spawn(async move {
        while writer_flag.load(Ordering::Acquire) {
            // Rejections are fine: the point is traffic, not the outcome, and
            // once alpha stops leading these start failing by design.
            let _ = writer_store
                .propose(vec![StoreAction::Create(StoreObject::Network(
                    sample_network("load"),
                ))])
                .await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let alpha_raft_id = first.raft_id();
    let started = Instant::now();
    let members =
        membership::remove_member(&first.context(), alpha_raft_id, Departing::LeavesConsensus)
            .await
            .expect("the removal completes even while the cluster is taking writes");
    let elapsed = started.elapsed();

    writing.store(false, Ordering::Release);
    writer.await.expect("the write generator exits cleanly");

    assert!(
        elapsed < LEADERSHIP_TRANSFER_BUDGET,
        "the handover took {elapsed:?}: a real transfer is one broadcast and one \
         election round, not a wait for a lease to expire"
    );
    assert_eq!(members.len(), 2, "{members:?}");
    assert!(
        members.iter().all(|m| m.raft_id != alpha_raft_id),
        "the departing leader is out of the returned membership: {members:?}"
    );

    eventually("another manager leads", || {
        second.is_leader() || third.is_leader()
    })
    .await;
    assert!(!first.is_leader(), "alpha stepped down");

    third.shutdown().await;
    second.shutdown().await;
    first.shutdown().await;
}

/// A node that already holds cluster state refuses to join another cluster
/// (architecture §1.2's dirty-state rule, SWK §12.3's `IsStateDirty`).
#[tokio::test]
async fn a_node_with_existing_state_refuses_to_join() {
    let ca = TestCa::new();
    let first = bootstrap(&ca, "alpha").await;
    let remote = first.addr.clone();

    // A second cluster's manager, shut down with its state on disk.
    let other_ca = TestCa::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = manager_config(&dir, "loner", other_ca.live_identity(NodeRole::Manager));
    let (_store, node) = RaftNode::start(cfg.clone()).await.expect("loner starts");
    node.shutdown().await.expect("clean shutdown");

    let Err(err) = RaftNode::join(cfg, &remote).await else {
        panic!("a node that already has cluster state must not join another cluster")
    };
    match err {
        NodeError::DirtyState { reason, .. } => {
            assert!(
                !reason.is_empty(),
                "the refusal must say what was found: {reason}"
            );
        }
        other => panic!("expected a dirty-state refusal, got {other}"),
    }

    first.shutdown().await;
}

/// The mTLS authorization interceptor (architecture §12.5): a worker
/// certificate cannot call a manager-only `Control` RPC, and a certificate
/// from a different cluster's CA cannot get past the handshake at all.
#[tokio::test]
async fn manager_rpcs_reject_workers_and_foreign_clusters() {
    use satl_proto::v2::control_client::ControlClient;

    let ca = TestCa::new();
    let leader = bootstrap(&ca, "alpha").await;

    // A worker of the *same* cluster: the handshake succeeds (the CA issued
    // its certificate), the role check does not.
    let worker = ca.live_identity(NodeRole::Worker);
    let channels = satl_cluster::transport::PeerChannels::new(&worker).expect("worker channels");
    let channel = channels.channel(&leader.addr).expect("channel");
    let mut client = ControlClient::new(channel);
    let status = client
        .cluster_info(satl_proto::v2::ClusterInfoRequest {})
        .await
        .expect_err("a worker must not read cluster info");
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");
    assert!(
        status.message().contains("satl-worker"),
        "the refusal should name the offending OU: {status}"
    );

    // A manager of the same cluster is admitted.
    let manager = ca.live_identity(NodeRole::Manager);
    let channels = satl_cluster::transport::PeerChannels::new(&manager).expect("manager channels");
    let channel = channels.channel(&leader.addr).expect("channel");
    let mut client = ControlClient::new(channel);
    let info = client
        .cluster_info(satl_proto::v2::ClusterInfoRequest {})
        .await
        .expect("a manager may read cluster info")
        .into_inner();
    assert_eq!(info.members.len(), 1);
    assert_eq!(info.leader_raft_id, leader.raft_id());
    assert!(info.applied, "a single-node leader is always caught up");
    assert!(info.cluster.is_some(), "the cluster object is included");

    // A manager from a *different* cluster's CA cannot even complete mTLS.
    let foreign_ca = TestCa::new();
    let foreign = foreign_ca.live_identity(NodeRole::Manager);
    let channels = satl_cluster::transport::PeerChannels::new(&foreign).expect("foreign channels");
    let channel = channels.channel(&leader.addr).expect("channel");
    let mut client = ControlClient::new(channel);
    let status = client
        .cluster_info(satl_proto::v2::ClusterInfoRequest {})
        .await
        .expect_err("a foreign CA must not be trusted");
    assert!(
        matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::Unauthenticated | tonic::Code::Unknown
        ),
        "expected a transport-level refusal, got {status}"
    );

    // The role requirement constants are the ones architecture §7 lists.
    assert_eq!(
        satl_cluster::transport::RAFT_ROLE,
        RoleRequirement::Manager,
        "the Raft service is manager-only"
    );

    leader.shutdown().await;
}
