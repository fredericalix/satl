// SPDX-License-Identifier: BSD-2-Clause
//! The joiner side of issuance (architecture §12.2, SWK §16.3 steps 1 and 4).
//!
//! A node generates its own ECDSA P-256 key, keeps it, and sends only a CSR.
//! The subject in that CSR is a placeholder: the CA overwrites it
//! ([`crate::RootCa::sign_node_csr`]), so this side deliberately asks for
//! nothing — no SANs, no key usages, no extensions.
//!
//! When the certificate comes back, the joiner checks it before writing it to
//! disk: it must chain to the root the join token pinned, and it must say what
//! the node was told it would say (`CN` = the assigned node id, `OU` = the
//! granted role). Skipping that check would let a compromised manager hand a
//! worker a manager certificate — or hand it someone else's identity.

use std::fmt;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, UnixTime};
use satl_core::{Id, NodeRole};
use tracing::debug;

use crate::tls::{self, PeerIdentity, PeerIdentityError};

/// Placeholder subject SatL puts in its CSRs.
///
/// It is never certified: the signer replaces the whole subject (SWK §16.3
/// step 5). It exists only because an empty `Name` is awkward for third-party
/// tooling to display.
pub const CSR_PLACEHOLDER_CN: &str = "satl-node";

/// Failures on the joiner side of certificate issuance.
#[derive(Debug, thiserror::Error)]
pub enum CsrError {
    /// Key generation failed.
    #[error("failed to generate the node ECDSA P-256 key pair: {source}")]
    GenerateKey {
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// The stored node key does not parse.
    #[error("failed to parse the node private key ({len} bytes of PEM): {source}")]
    ParseKey {
        /// Size of the input.
        len: usize,
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// Serializing the CSR failed.
    #[error("failed to serialize the certificate signing request for this node: {source}")]
    SerializeCsr {
        /// Underlying rcgen error.
        source: rcgen::Error,
    },

    /// The issued certificate could not be read at all.
    #[error("the certificate issued to this node could not be parsed: {source}")]
    Identity {
        /// Underlying parse failure.
        #[from]
        source: PeerIdentityError,
    },

    /// The trust anchors are empty or unusable.
    #[error(
        "cannot verify the certificate issued to this node: the pinned root CA store is empty or \
         unusable ({source}); the root CA bundle fetched at join time was rejected"
    )]
    RootStore {
        /// Underlying rustls error.
        source: rustls::server::VerifierBuilderError,
    },

    /// The certificate does not chain to the pinned root.
    #[error(
        "the certificate issued to node {node_id} does not chain to the pinned cluster root CA \
         ({roots} trust anchor(s)): {source}. Refusing to install it"
    )]
    UntrustedChain {
        /// Node the certificate claims to be.
        node_id: String,
        /// How many anchors were tried.
        roots: usize,
        /// Underlying rustls error.
        source: rustls::Error,
    },

    /// The certificate names a different node than the one that asked.
    #[error(
        "the certificate issued to this node carries CN={found}, but this node was assigned the \
         id {expected}. Refusing to install someone else's identity"
    )]
    WrongNodeId {
        /// CN found in the certificate.
        found: String,
        /// Node id the CA said it had assigned.
        expected: String,
    },

    /// The certificate grants a different role than the one requested.
    #[error(
        "the certificate issued to node {node_id} carries OU={found} (role {found_role:?}), but \
         this node joined for the role {expected:?}: the manager has not converged on the \
         requested role yet, or the join token used was the other one"
    )]
    WrongRole {
        /// Node the certificate is for.
        node_id: String,
        /// OU found in the certificate.
        found: &'static str,
        /// Role the OU denotes.
        found_role: NodeRole,
        /// Role that was expected.
        expected: NodeRole,
    },

    /// The certificate certifies a key this node does not hold.
    #[error(
        "the certificate issued to this node certifies a different public key than the one in \
         the node's private key; the CSR was replaced in flight"
    )]
    KeyMismatch,
}

/// A node's own key pair: generated locally, never leaves the node.
///
/// `Debug` redacts the private key.
pub struct NodeKeyPair {
    key: KeyPair,
}

impl NodeKeyPair {
    /// Generates a fresh ECDSA P-256 key pair (architecture §12.1).
    pub fn generate() -> Result<Self, CsrError> {
        let key = KeyPair::generate().map_err(|source| CsrError::GenerateKey { source })?;
        debug!("generated node key pair (ECDSA P-256)");
        Ok(Self { key })
    }

    /// Reloads a key pair from stored PKCS#8 PEM.
    pub fn from_key_pem(key_pem: &str) -> Result<Self, CsrError> {
        let key = KeyPair::from_pem(key_pem).map_err(|source| CsrError::ParseKey {
            len: key_pem.len(),
            source,
        })?;
        Ok(Self { key })
    }

    /// Serializes a PKCS#10 CSR, self-signed with this key.
    ///
    /// Carries no extensions and a placeholder subject on purpose: everything
    /// but the public key is the signer's decision.
    pub fn csr_der(&self) -> Result<Vec<u8>, CsrError> {
        Ok(self.csr()?.der().to_vec())
    }

    /// [`NodeKeyPair::csr_der`], PEM-encoded.
    pub fn csr_pem(&self) -> Result<String, CsrError> {
        self.csr()?
            .pem()
            .map_err(|source| CsrError::SerializeCsr { source })
    }

    fn csr(&self) -> Result<rcgen::CertificateSigningRequest, CsrError> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CSR_PLACEHOLDER_CN);
        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params
            .serialize_request(&self.key)
            .map_err(|source| CsrError::SerializeCsr { source })
    }

    /// The private key as PKCS#8 PEM. **Never log this.**
    #[must_use]
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// The raw public key bytes (the `subjectPublicKey` of the SPKI).
    #[must_use]
    pub fn public_key_raw(&self) -> &[u8] {
        self.key.public_key_raw()
    }
}

impl fmt::Debug for NodeKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeKeyPair")
            .field("algorithm", &"ECDSA P-256")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Checks a certificate the CA issued before installing it (SWK §16.3 step 4).
///
/// Verifies, in order:
/// 1. the PEM parses and carries the SatL subject encoding;
/// 2. `CN` is the node id the CA said it assigned;
/// 3. `OU` is the role this node joined for;
/// 4. the chain validates against `root_pool` — the root pinned by the join
///    token digest, *not* the system trust store.
///
/// Returns the identity peers will see for this node.
///
/// Chain validation runs through rustls' `WebPkiClientVerifier` because SatL
/// leaves are client certificates as much as server certificates, and worker
/// leaves carry no SANs at all (invariant #3: managers never dial workers), so
/// a server-side verifier with its mandatory name check would not apply.
pub fn verify_issued_cert(
    cert_pem: &str,
    expected_node_id: &Id,
    expected_role: NodeRole,
    root_pool: &RootCertStore,
) -> Result<PeerIdentity, CsrError> {
    let chain = tls::certificates(cert_pem.as_bytes())?;
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or(PeerIdentityError::NoCertificate)?;

    let identity = PeerIdentity::from_certificate(leaf)?;
    if identity.node_id != *expected_node_id {
        return Err(CsrError::WrongNodeId {
            found: identity.node_id.to_string(),
            expected: expected_node_id.to_string(),
        });
    }
    if identity.role != expected_role {
        return Err(CsrError::WrongRole {
            node_id: identity.node_id.to_string(),
            found: crate::role_ou(identity.role),
            found_role: identity.role,
            expected: expected_role,
        });
    }

    let verifier = WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(root_pool.clone()),
        tls::crypto_provider(),
    )
    .build()
    .map_err(|source| CsrError::RootStore { source })?;
    verifier
        .verify_client_cert(leaf, intermediates, UnixTime::now())
        .map_err(|source| CsrError::UntrustedChain {
            node_id: identity.node_id.to_string(),
            roots: root_pool.roots.len(),
            source,
        })?;

    debug!(
        node_id = %identity.node_id,
        role = crate::role_ou(identity.role),
        cluster_id = %identity.cluster_id,
        "issued certificate verified against the pinned root CA"
    );
    Ok(identity)
}

/// Checks that `cert_pem` certifies `key`'s public key.
///
/// Run alongside [`verify_issued_cert`]: it is what proves the CA signed *this
/// node's* CSR and not one substituted in flight.
pub fn certificate_matches_key(cert_pem: &str, key: &NodeKeyPair) -> Result<(), CsrError> {
    let der = tls::first_certificate(cert_pem.as_bytes())?;
    if certified_public_key(&der)? == key.public_key_raw() {
        Ok(())
    } else {
        Err(CsrError::KeyMismatch)
    }
}

fn certified_public_key(der: &CertificateDer<'_>) -> Result<Vec<u8>, PeerIdentityError> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|err| PeerIdentityError::Parse {
            reason: err.to_string(),
        })?;
    Ok(cert.public_key().subject_public_key.data.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData as _;

    use crate::root::RootCa;
    use crate::tls::root_store;

    const CLUSTER: &str = "3n2ff1rvrc4mn3s2fu6zlt6tw";

    struct Fixture {
        root: RootCa,
        pool: RootCertStore,
        node: NodeKeyPair,
        id: Id,
    }

    fn fixture(role: NodeRole) -> (Fixture, String) {
        let root = RootCa::generate(CLUSTER).expect("root");
        let pool = root_store(root.bundle()).expect("root store");
        let node = NodeKeyPair::generate().expect("node key");
        let id = Id::generate();
        let cert = root
            .sign_node_csr(
                &node.csr_der().expect("csr"),
                &id,
                role,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign")
            .into_string();
        (
            Fixture {
                root,
                pool,
                node,
                id,
            },
            cert,
        )
    }

    #[test]
    fn generated_keys_are_distinct_and_serialize_as_pkcs8() {
        let a = NodeKeyPair::generate().expect("key");
        let b = NodeKeyPair::generate().expect("key");
        assert_ne!(a.public_key_raw(), b.public_key_raw());
        assert!(a.key_pem().contains("PRIVATE KEY"));
        let back = NodeKeyPair::from_key_pem(&a.key_pem()).expect("reload");
        assert_eq!(back.public_key_raw(), a.public_key_raw());
        assert!(NodeKeyPair::from_key_pem("nope").is_err());
    }

    #[test]
    fn csr_is_self_signed_and_carries_the_placeholder_subject() {
        let node = NodeKeyPair::generate().expect("key");
        let der = node.csr_der().expect("csr");
        let parsed = rcgen::CertificateSigningRequestParams::from_der(&der.as_slice().into())
            .expect("CSR parses and its self-signature verifies");
        assert_eq!(parsed.public_key.der_bytes(), node.public_key_raw());
        assert_eq!(
            parsed
                .params
                .distinguished_name
                .get(&DnType::CommonName)
                .map(|v| format!("{v:?}")),
            Some(format!(
                "{:?}",
                rcgen::DnValue::Utf8String(CSR_PLACEHOLDER_CN.to_owned())
            ))
        );
        assert!(node.csr_pem().expect("pem").contains("CERTIFICATE REQUEST"));
    }

    #[test]
    fn a_valid_certificate_is_accepted() {
        let (fx, cert) = fixture(NodeRole::Manager);
        let identity =
            verify_issued_cert(&cert, &fx.id, NodeRole::Manager, &fx.pool).expect("accepted");
        assert_eq!(identity.node_id, fx.id);
        assert_eq!(identity.role, NodeRole::Manager);
        assert_eq!(identity.cluster_id, CLUSTER);
        certificate_matches_key(&cert, &fx.node).expect("key matches");
    }

    #[test]
    fn a_worker_certificate_without_sans_is_accepted() {
        let (fx, cert) = fixture(NodeRole::Worker);
        verify_issued_cert(&cert, &fx.id, NodeRole::Worker, &fx.pool).expect("accepted");
    }

    #[test]
    fn a_certificate_from_a_foreign_ca_is_rejected() {
        let (fx, _) = fixture(NodeRole::Worker);
        let foreign = RootCa::generate(CLUSTER).expect("other root");
        let cert = foreign
            .sign_node_csr(
                &fx.node.csr_der().expect("csr"),
                &fx.id,
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign")
            .into_string();
        let err = verify_issued_cert(&cert, &fx.id, NodeRole::Worker, &fx.pool)
            .expect_err("foreign CA must be rejected");
        assert!(matches!(err, CsrError::UntrustedChain { .. }), "{err}");
        // ...and it verifies fine against its own root, so the test is about
        // the trust anchor and nothing else.
        let own_pool = root_store(foreign.bundle()).expect("pool");
        verify_issued_cert(&cert, &fx.id, NodeRole::Worker, &own_pool).expect("own root accepts");
    }

    #[test]
    fn a_certificate_for_another_node_is_rejected() {
        let (fx, cert) = fixture(NodeRole::Worker);
        let other = Id::generate();
        let err = verify_issued_cert(&cert, &other, NodeRole::Worker, &fx.pool)
            .expect_err("wrong CN must be rejected");
        assert!(matches!(err, CsrError::WrongNodeId { .. }), "{err}");
    }

    #[test]
    fn a_certificate_for_another_role_is_rejected() {
        let (fx, cert) = fixture(NodeRole::Worker);
        let err = verify_issued_cert(&cert, &fx.id, NodeRole::Manager, &fx.pool)
            .expect_err("wrong OU must be rejected");
        match err {
            CsrError::WrongRole {
                found_role,
                expected,
                ..
            } => {
                assert_eq!(found_role, NodeRole::Worker);
                assert_eq!(expected, NodeRole::Manager);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn an_empty_root_pool_is_an_error_not_an_acceptance() {
        let (fx, cert) = fixture(NodeRole::Worker);
        let empty = RootCertStore::empty();
        let err = verify_issued_cert(&cert, &fx.id, NodeRole::Worker, &empty)
            .expect_err("an empty pool must never accept");
        assert!(matches!(err, CsrError::RootStore { .. }), "{err}");
    }

    #[test]
    fn garbage_pem_is_rejected() {
        let (fx, _) = fixture(NodeRole::Worker);
        for input in [
            "",
            "not pem",
            "-----BEGIN CERTIFICATE-----\nzz\n-----END CERTIFICATE-----",
        ] {
            assert!(
                verify_issued_cert(input, &fx.id, NodeRole::Worker, &fx.pool).is_err(),
                "input {input:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_certificate_for_a_different_key_is_detected() {
        let (fx, _) = fixture(NodeRole::Worker);
        let other_key = NodeKeyPair::generate().expect("key");
        let cert = fx
            .root
            .sign_node_csr(
                &other_key.csr_der().expect("csr"),
                &fx.id,
                NodeRole::Worker,
                CLUSTER,
                crate::NODE_CERT_VALIDITY,
            )
            .expect("sign")
            .into_string();
        // Chain and subject are fine...
        verify_issued_cert(&cert, &fx.id, NodeRole::Worker, &fx.pool).expect("chain is valid");
        // ...but it is not this node's key.
        let err = certificate_matches_key(&cert, &fx.node).expect_err("key mismatch");
        assert!(matches!(err, CsrError::KeyMismatch), "{err}");
        certificate_matches_key(&cert, &other_key).expect("matches the right key");
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let node = NodeKeyPair::generate().expect("key");
        let rendered = format!("{node:?}");
        let body: String = node
            .key_pem()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!body.is_empty());
        assert!(!rendered.contains(&body), "{rendered}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(rendered.contains("redacted"));
    }
}
