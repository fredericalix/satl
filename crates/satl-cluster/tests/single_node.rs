// SPDX-License-Identifier: BSD-2-Clause
//! End-to-end single-node lifecycle: the unit-scale version of the M0
//! definition of done — "kill satld → restart → state recovered".
//!
//! start → becomes leader → seeded Cluster+Node exist → propose a service
//! create → watch feed sees the events → stop the whole node → start again
//! from the same directory → contents fully recovered, still leader, no
//! duplicate seeding, proposals still work.

use std::collections::BTreeMap;

use satl_core::{
    Annotations, ContainerSpec, Id, Meta, Network, NetworkDriver, NetworkSpec, NodeRole,
    ObjectKind, Placement, ResourceRequirements, RestartPolicy, Service, ServiceMode, ServiceSpec,
    StoreAction, StoreEvent, StoreObject, TaskSpec, Version,
};

use satl_cluster::{ProposalRejection, ProposeError, RaftNode, RaftNodeConfig};

fn sample_service(name: &str) -> Service {
    Service {
        id: Id::generate(),
        meta: Meta::new(),
        spec: ServiceSpec {
            annotations: Annotations {
                name: name.to_owned(),
                labels: BTreeMap::new(),
            },
            task: TaskSpec {
                container: ContainerSpec {
                    image: "registry.example.com/web:1".to_owned(),
                    labels: BTreeMap::new(),
                    command: vec![],
                    args: vec![],
                    hostname: None,
                    env: vec![],
                    dir: None,
                    user: None,
                    groups: vec![],
                    tty: false,
                    open_stdin: false,
                    read_only: false,
                    stop_signal: None,
                    stop_grace_period: None,
                    healthcheck: None,
                    hosts: vec![],
                    dns_config: None,
                    mounts: vec![],
                    secrets: vec![],
                    configs: vec![],
                    pull_options: None,
                    platform: None,
                },
                resources: ResourceRequirements::default(),
                restart: RestartPolicy::default(),
                placement: Placement::default(),
                networks: vec![],
                force_update: 0,
            },
            mode: ServiceMode::Replicated { replicas: 2 },
            update: None,
            rollback: None,
            endpoint: None,
        },
        endpoint: None,
        spec_version: satl_core::Version(0),
        previous_spec: None,
        update_status: None,
    }
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
            ipam: None,
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

// One long scenario on purpose: the boot → mutate → restart → verify flow
// only proves recovery if it runs as a single ordered sequence.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn single_node_recovers_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = RaftNodeConfig {
        raft_dir: dir.path().join("raft"),
        node_name: "alpha".to_owned(),
        ..Default::default()
    };

    // ---- First boot: fresh cluster -------------------------------------
    let (store, node) = RaftNode::start(cfg.clone()).await.unwrap();
    let node_id = node.node_id().clone();
    let raft_id = node.raft_id();

    let metrics = store.metrics();
    assert!(metrics.is_leader, "single node must lead: {metrics:?}");
    assert_eq!(metrics.node_raft_id, raft_id);
    assert_eq!(metrics.leader_id, Some(raft_id));

    // Seeded objects (architecture §1.2).
    let cluster_version;
    {
        let view = store.view();
        let cluster = view.cluster().expect("default cluster seeded");
        assert_eq!(cluster.spec.annotations.name, "default");
        cluster_version = cluster.meta.version;

        let own = view.node(&node_id).expect("own node object seeded");
        assert_eq!(own.spec.role, NodeRole::Manager);
        let manager = own.manager_status.as_ref().expect("manager status");
        assert_eq!(manager.raft_id, raft_id);
        assert!(manager.leader);
        assert_eq!(view.nodes().len(), 1);
        assert_eq!(
            view.node_by_name("alpha").map(|n| n.id.clone()),
            Some(node_id.clone())
        );
    }

    // Propose a service create and observe it on the watch feed.
    let mut watch = store.watch();
    let service = sample_service("web");
    let service_id = service.id.clone();
    let version = store
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .unwrap();

    let created = watch.recv().await.unwrap();
    match created {
        StoreEvent::Created(StoreObject::Service(s)) => {
            assert_eq!(s.id, service_id);
            assert_eq!(s.meta.version, version);
        }
        other => panic!("expected Created(Service), got {other:?}"),
    }
    assert_eq!(watch.recv().await.unwrap(), StoreEvent::Commit(version));

    {
        let view = store.view();
        let s = view.service(&service_id).expect("service stored");
        assert_eq!(s.meta.version, version);
        assert_eq!(
            view.service_by_name("web").map(|s| s.id.clone()),
            Some(service_id.clone())
        );
        assert_eq!(
            view.get(ObjectKind::Service, &service_id)
                .map(|o| o.id().clone()),
            Some(service_id.clone())
        );
    }

    // Optimistic concurrency: a stale update is deterministically rejected.
    let mut stale = (*store.view().service(&service_id).unwrap()).clone();
    stale.meta.version = Version(0);
    let err = store
        .propose(vec![StoreAction::Update(StoreObject::Service(stale))])
        .await
        .unwrap_err();
    match err {
        ProposeError::Rejected(ProposalRejection::SequenceConflict {
            kind,
            id,
            expected,
            found,
        }) => {
            assert_eq!(kind, ObjectKind::Service);
            assert_eq!(id, service_id);
            assert_eq!(expected, version.0);
            assert_eq!(found, 0);
        }
        other => panic!("expected SequenceConflict, got {other}"),
    }

    // ---- Stop everything ------------------------------------------------
    node.shutdown().await.unwrap();
    drop(store);
    drop(watch);

    // ---- Restart from the same directory --------------------------------
    let (store, node) = RaftNode::start(cfg).await.unwrap();

    // Same identity, still leader.
    assert_eq!(node.node_id(), &node_id);
    assert_eq!(node.raft_id(), raft_id);
    let metrics = store.metrics();
    assert!(metrics.is_leader, "restarted node must lead: {metrics:?}");

    // State fully recovered, no duplicate seeding, versions preserved.
    {
        let view = store.view();
        let cluster = view.cluster().expect("cluster recovered");
        assert_eq!(cluster.spec.annotations.name, "default");
        assert_eq!(cluster.meta.version, cluster_version, "no re-seeding");
        assert_eq!(view.nodes().len(), 1, "no duplicate node object");

        let s = view.service(&service_id).expect("service recovered");
        assert_eq!(s.meta.version, version);
        assert_eq!(s.spec.annotations.name, "web");
        assert_eq!(
            view.service_by_name("web").map(|s| s.id.clone()),
            Some(service_id.clone()),
            "name index rebuilt"
        );
    }

    // Proposals still work after recovery, and versions keep increasing.
    let mut watch = store.watch();
    let network = sample_network("backend");
    let network_id = network.id.clone();
    let version2 = store
        .propose(vec![StoreAction::Create(StoreObject::Network(network))])
        .await
        .unwrap();
    assert!(version2 > version);

    let created = watch.recv().await.unwrap();
    match created {
        StoreEvent::Created(StoreObject::Network(n)) => assert_eq!(n.id, network_id),
        other => panic!("expected Created(Network), got {other:?}"),
    }
    assert_eq!(watch.recv().await.unwrap(), StoreEvent::Commit(version2));
    assert!(store.view().network_by_name("backend").is_some());

    node.shutdown().await.unwrap();
}

/// `Service::spec_version` moves only when the spec does.
///
/// The rolling updater writes `update_status` on the very object it is rolling,
/// so a version that moved on those writes would mark every task of the service
/// dirty on every tick and roll it forever. That is why the FSM carries the old
/// value forward when the spec is untouched, and why the dirtiness check can use
/// equality as a fast path at all.
#[tokio::test]
async fn the_spec_version_moves_only_when_the_spec_changes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = RaftNodeConfig {
        raft_dir: dir.path().join("raft"),
        node_name: "alpha".to_owned(),
        ..Default::default()
    };
    let (store, node) = RaftNode::start(cfg).await.unwrap();

    // A proposer cannot choose the value: the FSM owns it, deliberately, because
    // every replica must land on the same number and the only inputs identical
    // everywhere are the stored object and the applying log index.
    let mut service = sample_service("web");
    service.spec_version = Version(9_999);
    let service_id = service.id.clone();
    let created_at = store
        .propose(vec![StoreAction::Create(StoreObject::Service(service))])
        .await
        .unwrap();

    let created = store.view().service(&service_id).unwrap().as_ref().clone();
    assert_eq!(
        created.spec_version, created_at,
        "a service's first spec version is its creation index, not what the proposer asked for"
    );

    // A write that leaves the spec alone -- exactly what the updater does on
    // every tick.
    let mut rolling = created.clone();
    rolling.update_status = Some(satl_core::UpdateStatus {
        state: satl_core::UpdateStateKind::Updating,
        started_at: None,
        completed_at: None,
        message: "rolling".to_owned(),
    });
    let rolled_at = store
        .propose(vec![StoreAction::Update(StoreObject::Service(rolling))])
        .await
        .unwrap();
    assert!(rolled_at > created_at);

    let rolled = store.view().service(&service_id).unwrap().as_ref().clone();
    assert_eq!(rolled.meta.version, rolled_at, "the object was written");
    assert_eq!(
        rolled.spec_version, created_at,
        "but its spec was not, so the spec version must stand"
    );

    // A real spec change.
    let mut scaled = rolled.clone();
    scaled.spec.mode = ServiceMode::Replicated { replicas: 5 };
    let scaled_at = store
        .propose(vec![StoreAction::Update(StoreObject::Service(scaled))])
        .await
        .unwrap();

    assert_eq!(
        store.view().service(&service_id).unwrap().spec_version,
        scaled_at,
        "a changed spec takes the applying index as its new version"
    );

    node.shutdown().await.unwrap();
}
