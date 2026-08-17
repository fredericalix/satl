// SPDX-License-Identifier: BSD-2-Clause
//! End-to-end exercise of the join flow across the crate's public API
//! (architecture §12.2, SWK §16.2/§16.3), in the order the daemon will call
//! it. This is also the compile-time check that everything wave 4 needs is
//! actually re-exported.

use std::collections::BTreeMap;
use std::time::SystemTime;

use rand::SeedableRng as _;
use rand::rngs::StdRng;
use satl_ca::{
    CertStore, JoinToken, JoinTokens, NodeIdentity, NodeKeyPair, PeerIdentity, RoleRequirement,
    RootCa, certificate_matches_key, client_config, next_renewal, root_store, server_config,
    verify_issued_cert,
};
use satl_core::{Id, NodeRole};

const CLUSTER: &str = "3n2ff1rvrc4mn3s2fu6zlt6tw";

/// Manager side: mint the cluster's CA and tokens once.
fn bootstrap() -> (RootCa, JoinTokens) {
    let root = RootCa::generate(CLUSTER).expect("root CA");
    let tokens = JoinTokens::generate(root.bundle());
    (root, tokens)
}

#[test]
fn a_worker_joins_with_the_worker_token() {
    let (root, tokens) = bootstrap();

    // --- joiner: parse the token the operator pasted -------------------
    let printed = tokens.worker.to_string();
    let token = JoinToken::parse(&printed).expect("token parses");

    // --- joiner: fetch the root CA over an untrusted channel and pin it -
    let bundle = root.bundle().to_vec();
    token.verify_ca_bundle(&bundle).expect("bundle is pinned");
    let pool = root_store(&bundle).expect("trust anchors");

    // --- CA: the token decides the role --------------------------------
    let role = tokens
        .role_for(token.secret())
        .expect("the worker token grants a role");
    assert_eq!(role, NodeRole::Worker);

    // --- joiner: key + CSR ---------------------------------------------
    let key = NodeKeyPair::generate().expect("node key");
    let csr = key.csr_der().expect("csr");

    // --- CA: mint the node id and sign ---------------------------------
    let node_id = Id::generate();
    let cert = root
        .sign_node_csr(&csr, &node_id, role, CLUSTER, satl_ca::NODE_CERT_VALIDITY)
        .expect("signed")
        .into_string();

    // --- joiner: verify what came back ---------------------------------
    let identity = verify_issued_cert(&cert, &node_id, role, &pool).expect("verified");
    assert_eq!(identity.node_id, node_id);
    assert_eq!(identity.role, NodeRole::Worker);
    assert_eq!(identity.cluster_id, CLUSTER);
    certificate_matches_key(&cert, &key).expect("certifies this node's key");

    // --- joiner: persist, then reload as the daemon would on restart ----
    let dir = tempfile::tempdir().expect("tempdir");
    let store = CertStore::open(dir.path().join("certs")).expect("store");
    assert!(store.load().expect("load").is_none(), "nothing stored yet");
    let stored = NodeIdentity::new(
        cert,
        key.key_pem(),
        String::from_utf8(bundle).expect("utf8"),
    );
    store.save(&stored).expect("save");
    let reloaded = store.load().expect("load").expect("identity present");
    assert_eq!(reloaded, stored);

    // --- both sides build TLS configurations from it --------------------
    server_config(&reloaded).expect("server config");
    client_config(&reloaded, satl_ca::SAN_MANAGER).expect("client config");

    // --- and the dispatcher's interceptor authorizes it -----------------
    let peer = PeerIdentity::from_pem(reloaded.cert_pem.as_bytes()).expect("peer identity");
    peer.authorize(RoleRequirement::WorkerOrManager, CLUSTER, &())
        .expect("workers may open a dispatcher session");
    peer.authorize(RoleRequirement::Manager, CLUSTER, &())
        .expect_err("workers may not drive raft");

    // --- renewal is scheduled inside the certificate's own window -------
    let (not_before, not_after) =
        satl_ca::certificate_validity(&reloaded.cert_pem).expect("validity");
    let at = next_renewal(not_before, not_after, &mut StdRng::seed_from_u64(1));
    assert!(at > SystemTime::now(), "renewal is in the future");
    assert!(at < not_after, "renewal happens before expiry");
}

#[test]
fn the_manager_token_grants_the_manager_role() {
    let (root, tokens) = bootstrap();
    let token = JoinToken::parse(&tokens.manager.to_string()).expect("parses");
    assert_eq!(tokens.role_for(token.secret()), Some(NodeRole::Manager));

    let key = NodeKeyPair::generate().expect("key");
    let node_id = Id::generate();
    let cert = root
        .sign_node_csr(
            &key.csr_der().expect("csr"),
            &node_id,
            NodeRole::Manager,
            CLUSTER,
            satl_ca::NODE_CERT_VALIDITY,
        )
        .expect("signed")
        .into_string();

    let pool = root_store(root.bundle()).expect("pool");
    // A manager certificate is not accepted where a worker one was expected.
    assert!(verify_issued_cert(&cert, &node_id, NodeRole::Worker, &pool).is_err());
    let identity = verify_issued_cert(&cert, &node_id, NodeRole::Manager, &pool).expect("verified");
    identity
        .authorize(RoleRequirement::Manager, CLUSTER, &())
        .expect("managers may drive raft");
}

/// SWK §16.2: the digest covers the whole bundle, so a MITM that serves the
/// real root *plus* one of its own is caught before any key is generated.
#[test]
fn a_mitm_appending_its_own_root_is_caught_by_the_token_digest() {
    let (root, tokens) = bootstrap();
    let attacker = RootCa::generate(CLUSTER).expect("attacker root");

    let mut tampered = root.bundle().to_vec();
    tampered.extend_from_slice(attacker.bundle());

    // The tampered bundle is perfectly valid PEM and would happily become a
    // trust store...
    assert_eq!(root_store(&tampered).expect("parses").roots.len(), 2);
    // ...but it does not match the digest the operator's token pinned.
    let err = tokens
        .worker
        .verify_ca_bundle(&tampered)
        .expect_err("appended root must be rejected");
    assert!(err.to_string().contains("man-in-the-middle"), "{err}");

    // Serving only the attacker's root is caught the same way.
    assert!(tokens.worker.verify_ca_bundle(attacker.bundle()).is_err());
    tokens
        .worker
        .verify_ca_bundle(root.bundle())
        .expect("the genuine bundle still verifies");
}

/// A node removed from the cluster stays locked out until its certificate
/// expires (SWK §16.7).
#[test]
fn a_blacklisted_node_is_refused_even_with_a_valid_certificate() {
    let (root, _) = bootstrap();
    let key = NodeKeyPair::generate().expect("key");
    let node_id = Id::generate();
    let cert = root
        .sign_node_csr(
            &key.csr_der().expect("csr"),
            &node_id,
            NodeRole::Worker,
            CLUSTER,
            satl_ca::NODE_CERT_VALIDITY,
        )
        .expect("signed")
        .into_string();

    let pool = root_store(root.bundle()).expect("pool");
    let identity =
        verify_issued_cert(&cert, &node_id, NodeRole::Worker, &pool).expect("still valid");

    let mut blacklist = BTreeMap::new();
    blacklist.insert(node_id.to_string(), SystemTime::now());
    let err = identity
        .authorize(RoleRequirement::WorkerOrManager, CLUSTER, &blacklist)
        .expect_err("removed node must be refused");
    assert!(
        err.to_string().contains("removed from the cluster"),
        "{err}"
    );
}

/// Rotating a token invalidates the old one without touching the CA, so nodes
/// already in the cluster keep working (SWK §16.2).
#[test]
fn rotating_a_token_does_not_disturb_the_ca() {
    let (root, tokens) = bootstrap();
    let rotated = tokens.rotate(NodeRole::Worker);

    assert_eq!(rotated.role_for(tokens.worker.secret()), None);
    assert_eq!(
        rotated.role_for(rotated.worker.secret()),
        Some(NodeRole::Worker)
    );
    assert_eq!(
        rotated.role_for(tokens.manager.secret()),
        Some(NodeRole::Manager),
        "the manager token is untouched"
    );
    rotated
        .worker
        .verify_ca_bundle(root.bundle())
        .expect("the pinned root is unchanged");
}
