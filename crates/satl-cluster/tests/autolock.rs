// SPDX-License-Identifier: BSD-2-Clause
//! Autolock boot path: a manager whose DEK is sealed under the unlock key
//! (KEK) refuses to open its raft state without it, and boots once the key
//! has unsealed the DEK in memory — with no plain `dek` file ever written.
//!
//! The HTTP half of the locked boot (the unlock-only listener) is satld's;
//! what this file pins is the storage half: `is_locked`, the refusal, and
//! the `RaftNodeConfig::dek` injection.

use satl_cluster::{
    DEK_FILE, Dek, RaftNode, RaftNodeConfig, SEALED_DEK_FILE, generate_unlock_key, is_locked,
    kek_from_unlock_key,
};

/// Boots once, then simulates autolock: seal the DEK under a fresh unlock
/// key and remove the plain file, exactly as satld's watcher does.
async fn boot_then_lock(dir: &std::path::Path) -> (String, Dek) {
    let (store, raft) = RaftNode::start(RaftNodeConfig {
        raft_dir: dir.to_path_buf(),
        node_name: "alpha".to_owned(),
        ..Default::default()
    })
    .await
    .expect("first boot");
    let dek = raft.dek();
    raft.shutdown().await.expect("clean shutdown");
    drop(store);

    let key = generate_unlock_key();
    let kek = kek_from_unlock_key(&key).expect("generated key parses");
    dek.seal_to(&kek, &dir.join(SEALED_DEK_FILE))
        .expect("seal the DEK");
    std::fs::remove_file(dir.join(DEK_FILE)).expect("remove the plain DEK");
    (key, dek)
}

/// A locked raft directory is refused by name when no key is handed in, and
/// opens with the DEK the unlock key unseals.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_manager_boots_only_with_the_unlock_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let raft_dir = dir.path().join("raft");
    let (key, dek) = boot_then_lock(&raft_dir).await;
    assert!(is_locked(&raft_dir));

    // No injected DEK: the boot refuses, naming the missing key file —
    // satld's locked listener is what answers instead of this error.
    let refused = RaftNode::start(RaftNodeConfig {
        raft_dir: raft_dir.clone(),
        node_name: "alpha".to_owned(),
        ..Default::default()
    })
    .await;
    let err = match refused {
        Ok((_store, raft)) => {
            raft.shutdown().await.expect("clean shutdown");
            panic!("a locked store must not open without the key");
        }
        Err(err) => err,
    };
    assert!(err.to_string().contains(DEK_FILE), "{err}");

    // The wrong key does not unseal the DEK (AEAD authentication).
    let wrong = kek_from_unlock_key(&generate_unlock_key()).expect("key parses");
    assert!(Dek::open_sealed(&wrong, &raft_dir.join(SEALED_DEK_FILE)).is_err());

    // The right one does, and the node boots with it — in memory only.
    let kek = kek_from_unlock_key(&key).expect("key parses");
    let unsealed = Dek::open_sealed(&kek, &raft_dir.join(SEALED_DEK_FILE)).expect("unseal");
    let (store, raft) = RaftNode::start(RaftNodeConfig {
        raft_dir: raft_dir.clone(),
        node_name: "alpha".to_owned(),
        dek: Some(unsealed),
        ..Default::default()
    })
    .await
    .expect("an unlocked manager boots");
    assert!(
        !raft_dir.join(DEK_FILE).exists(),
        "no plain key file is written after an unlock boot"
    );
    // The store is fully readable: the seeded Cluster object is there.
    assert!(store.view().cluster().is_some());
    raft.shutdown().await.expect("clean shutdown");
    drop(store);
    drop(dek);
}
