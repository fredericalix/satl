// SPDX-License-Identifier: BSD-2-Clause
//! Test scaffolding for multi-node clusters: a throwaway cluster CA and the
//! identities its members present.
//!
//! Kept in the crate (rather than in `tests/`) so the unit tests, the
//! in-process integration tests and any later crate that needs a fake cluster
//! all mint identities the same way. Nothing here touches the filesystem
//! outside a caller-supplied directory, and nothing needs root: the
//! multi-node tests run unprivileged on loopback.

use std::sync::Arc;

use satl_ca::{LiveIdentity, NODE_CERT_VALIDITY, NodeIdentity, NodeKeyPair, RootCa};
use satl_core::{Id, NodeRole};

/// A self-signed cluster CA that issues member identities for tests.
#[derive(Debug)]
pub struct TestCa {
    root: RootCa,
    cluster_id: String,
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCa {
    /// Generates a fresh CA for a fresh cluster id.
    ///
    /// # Panics
    ///
    /// If key generation fails, which would mean the crypto provider is
    /// unusable and every other test would fail too.
    #[must_use]
    pub fn new() -> Self {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("generating a test root CA");
        Self { root, cluster_id }
    }

    /// The cluster id stamped as `O` into every certificate this CA issues.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// The CA bundle every member trusts.
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        self.root.cert_pem()
    }

    /// A fresh identity for a randomly generated node id.
    ///
    /// # Panics
    ///
    /// If signing fails; see [`TestCa::new`].
    #[must_use]
    pub fn identity(&self, role: NodeRole) -> NodeIdentity {
        self.identity_for(&Id::generate(), role)
    }

    /// A fresh identity for `node_id`, so a test can pin the CN.
    ///
    /// # Panics
    ///
    /// If signing fails; see [`TestCa::new`].
    #[must_use]
    pub fn identity_for(&self, node_id: &Id, role: NodeRole) -> NodeIdentity {
        let key = NodeKeyPair::generate().expect("generating a test node key");
        let cert = self
            .root
            .sign_node_csr(
                &key.csr_der().expect("serializing a test CSR"),
                node_id,
                role,
                &self.cluster_id,
                NODE_CERT_VALIDITY,
            )
            .expect("signing a test node certificate");
        NodeIdentity::new(
            cert.into_string(),
            key.key_pem(),
            self.root.cert_pem().to_owned(),
        )
    }

    /// [`TestCa::identity`], wrapped as the live identity the server and
    /// transport constructors take.
    ///
    /// # Panics
    ///
    /// If the material this CA just issued does not build a TLS
    /// configuration, which would fail every other test too.
    #[must_use]
    pub fn live_identity(&self, role: NodeRole) -> Arc<LiveIdentity> {
        LiveIdentity::new(self.identity(role)).expect("test identity builds a live identity")
    }
}

/// A manager identity from a one-off CA, for tests that only need *an*
/// identity and do not care which cluster it belongs to.
#[must_use]
pub fn test_identity() -> NodeIdentity {
    TestCa::new().identity(NodeRole::Manager)
}

/// [`test_identity`] in its live, swappable form.
///
/// # Panics
///
/// If the freshly issued material does not build a TLS configuration; see
/// [`TestCa::new`].
#[must_use]
pub fn test_live_identity() -> Arc<LiveIdentity> {
    LiveIdentity::new(test_identity()).expect("test identity builds a live identity")
}

/// A shared manager identity, so repeated calls in one test do not each pay
/// for a key generation.
#[must_use]
pub fn shared_test_identity() -> Arc<NodeIdentity> {
    Arc::new(test_identity())
}
