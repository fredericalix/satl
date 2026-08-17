// SPDX-License-Identifier: BSD-2-Clause
//! rustls configuration, peer identity extraction and the RPC authorization
//! matrix (architecture §12.1/§12.5, SWK §16.1/§16.7).
//!
//! # Cipher policy
//!
//! Architecture §12.1 pins ECDHE key exchange with AES-GCM or
//! ChaCha20-Poly1305. The provider built here is rustls' aws-lc-rs provider
//! restricted to exactly that, minus the RSA suites — every SatL certificate
//! is ECDSA P-256, so an RSA-authenticated suite could never be negotiated
//! anyway and offering it only widens the surface. TLS 1.3 is preferred; 1.2
//! stays enabled because the remote Docker REST endpoint (§12.5) is reachable
//! by third-party clients.
//!
//! One provider is shared process-wide, and it is the same rustls major
//! version (0.23, aws-lc-rs backend) the image client already links, so the
//! workspace has exactly one rustls and one crypto backend.
//!
//! # Authorization
//!
//! [`PeerIdentity::from_certificate`] turns the peer's leaf certificate back
//! into `CN`/`OU`/`O` and [`PeerIdentity::authorize`] applies SWK §16.7: OU
//! must satisfy the service's [`RoleRequirement`], O must equal this cluster's
//! id, and CN must not be blacklisted. The tonic interceptors call exactly
//! this; the per-service requirement is architecture §7's table.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use satl_core::{Id, NodeRole};
use x509_parser::x509::AttributeTypeAndValue;

use crate::live::LiveIdentity;
use crate::store::NodeIdentity;
use crate::{OU_MANAGER, OU_WORKER, role_from_ou, role_ou};

/// TLS versions SatL negotiates, most preferred first.
pub(crate) static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// ECDHE + AEAD only, ECDSA authentication only (architecture §12.1).
static CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// Plain ECDHE groups: the post-quantum hybrids rustls offers by default are
/// dropped so the handshake stays the one §12.1 describes (and the client
/// hello stays small on a 1500-byte MTU underlay).
static KX_GROUPS: &[&'static dyn rustls::crypto::SupportedKxGroup] = &[
    aws_lc_rs::kx_group::X25519,
    aws_lc_rs::kx_group::SECP256R1,
    aws_lc_rs::kx_group::SECP384R1,
];

static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

/// The process-wide crypto provider: aws-lc-rs restricted to SatL's suites.
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::clone(PROVIDER.get_or_init(|| {
        let base = aws_lc_rs::default_provider();
        Arc::new(CryptoProvider {
            cipher_suites: CIPHER_SUITES.to_vec(),
            kx_groups: KX_GROUPS.to_vec(),
            ..base
        })
    }))
}

/// A certificate could not be read, or does not carry a SatL identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerIdentityError {
    /// The PEM input held no certificate.
    #[error("no certificate found in the PEM input")]
    NoCertificate,

    /// The PEM input could not be read.
    #[error("failed to read PEM certificate data: {reason}")]
    Pem {
        /// What the reader objected to.
        reason: String,
    },

    /// The DER did not parse as X.509.
    #[error("failed to parse the peer certificate: {reason}")]
    Parse {
        /// What the parser objected to.
        reason: String,
    },

    /// The subject has no usable common name.
    #[error(
        "peer certificate has no single CN: SatL certificates carry exactly one, the node id \
         (architecture section 12.1)"
    )]
    MissingCommonName,

    /// The common name is not a node id.
    #[error("peer certificate CN {cn:?} is not a valid node id: {reason}")]
    InvalidCommonName {
        /// The CN found.
        cn: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The subject has no usable organizational unit.
    #[error(
        "peer certificate (CN={cn}) has no single OU: SatL certificates carry exactly one, the \
         role ({OU_MANAGER} or {OU_WORKER})"
    )]
    MissingOrganizationalUnit {
        /// The CN found, to name the offending peer.
        cn: String,
    },

    /// The organizational unit is not a SatL role.
    #[error(
        "peer certificate (CN={cn}) carries OU={ou:?}, which is not a SatL role (expected \
         {OU_MANAGER} or {OU_WORKER})"
    )]
    UnknownRole {
        /// The CN found.
        cn: String,
        /// The OU found.
        ou: String,
    },

    /// The subject has no usable organization.
    #[error(
        "peer certificate (CN={cn}) has no single O: SatL certificates carry exactly one, the \
         cluster id"
    )]
    MissingOrganization {
        /// The CN found.
        cn: String,
    },

    /// A validity timestamp is outside the representable range.
    #[error("peer certificate (CN={cn}) has an unrepresentable validity timestamp {timestamp}")]
    InvalidValidity {
        /// The CN found.
        cn: String,
        /// The offending POSIX timestamp.
        timestamp: i64,
    },
}

/// Building a rustls configuration failed.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The identity's certificate or CA bundle could not be read.
    #[error("failed to read the node's TLS material: {source}")]
    Material {
        /// Underlying parse failure.
        #[from]
        source: PeerIdentityError,
    },

    /// The identity holds no usable private key.
    #[error(
        "the node's private key ({len} bytes of PEM) holds no PKCS#8/SEC1 private key; expected \
         the key written by satl at join time"
    )]
    NoPrivateKey {
        /// Size of the input.
        len: usize,
    },

    /// The CA bundle produced no trust anchors.
    #[error(
        "the cluster CA bundle ({len} bytes of PEM) yielded no usable trust anchor: {source}. \
         Refusing to build a TLS configuration that trusts nothing"
    )]
    NoTrustAnchors {
        /// Size of the input.
        len: usize,
        /// Underlying rustls error.
        source: rustls::server::VerifierBuilderError,
    },

    /// The expected server name is not a valid DNS name.
    #[error("{name:?} is not a valid TLS server name: {source}")]
    ServerName {
        /// The offending name.
        name: String,
        /// Underlying rustls error.
        source: rustls_pki_types::InvalidDnsNameError,
    },

    /// rustls refused the configuration (key/certificate mismatch, unsupported
    /// key type, …).
    #[error("rustls rejected the {side} configuration for this node: {source}")]
    Config {
        /// `server` or `client`.
        side: &'static str,
        /// Underlying rustls error.
        source: rustls::Error,
    },
}

/// Which roles a gRPC service accepts (architecture §7, SWK §16.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleRequirement {
    /// Any certificate the cluster CA issued (`Health`).
    Any,
    /// Managers only (`Raft`, `Control`).
    Manager,
    /// Workers and managers (`Dispatcher`).
    WorkerOrManager,
}

impl RoleRequirement {
    /// Whether `role` is in the requirement's OU set.
    #[must_use]
    pub fn accepts(self, role: NodeRole) -> bool {
        match self {
            Self::Any | Self::WorkerOrManager => true,
            Self::Manager => role == NodeRole::Manager,
        }
    }

    /// The OU set, for error messages.
    #[must_use]
    pub fn allowed_ous(self) -> &'static str {
        match self {
            Self::Any | Self::WorkerOrManager => "satl-manager, satl-worker",
            Self::Manager => OU_MANAGER,
        }
    }
}

/// A peer failed the authorization check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    /// The peer's role is not accepted by this service.
    #[error(
        "node {node_id} presented OU={ou} but this RPC requires one of [{allowed}]; a {ou} \
         certificate cannot call it"
    )]
    WrongRole {
        /// Peer node id.
        node_id: String,
        /// OU the peer presented.
        ou: &'static str,
        /// OUs the service accepts.
        allowed: &'static str,
    },

    /// The peer belongs to a different cluster.
    #[error(
        "node {node_id} presented a certificate for cluster {presented}, but this is cluster \
         {expected}: the node was issued its certificate by a different cluster's CA"
    )]
    WrongCluster {
        /// Peer node id.
        node_id: String,
        /// Cluster id in the peer's certificate.
        presented: String,
        /// This cluster's id.
        expected: String,
    },

    /// The peer's certificate is blacklisted (node removed, SWK §16.7).
    #[error(
        "node {node_id} has been removed from the cluster: its certificate is blacklisted until \
         it expires. Re-join the node with a fresh join token to get a new identity"
    )]
    Blacklisted {
        /// Peer node id.
        node_id: String,
    },
}

/// The set of certificate CNs barred from the cluster.
///
/// Implemented for `Cluster.blacklisted_certs` (`BTreeMap<String,
/// SystemTime>`, CN to expiry) and for a bare `BTreeSet<String>`; `()` means
/// "nothing is blacklisted". Pruning expired entries is the manager's job
/// (architecture §12.3), not this check's.
pub trait CertBlacklist {
    /// Whether `cn` is barred.
    fn contains_cn(&self, cn: &str) -> bool;
}

impl CertBlacklist for BTreeMap<String, SystemTime> {
    fn contains_cn(&self, cn: &str) -> bool {
        self.contains_key(cn)
    }
}

impl CertBlacklist for BTreeSet<String> {
    fn contains_cn(&self, cn: &str) -> bool {
        self.contains(cn)
    }
}

impl CertBlacklist for () {
    fn contains_cn(&self, _cn: &str) -> bool {
        false
    }
}

/// Who the peer on the other end of an mTLS connection is (architecture
/// §12.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// `CN`: the peer's node id.
    pub node_id: Id,
    /// `OU`: the peer's role.
    pub role: NodeRole,
    /// `O`: the cluster the peer belongs to.
    pub cluster_id: String,
}

impl PeerIdentity {
    /// Reads `CN`/`OU`/`O` back out of a peer's leaf certificate.
    ///
    /// Each must appear exactly once: a certificate with two CNs or two OUs is
    /// ambiguous and is refused rather than resolved by picking one.
    pub fn from_certificate(cert: &CertificateDer<'_>) -> Result<Self, PeerIdentityError> {
        let (_, parsed) =
            x509_parser::parse_x509_certificate(cert).map_err(|err| PeerIdentityError::Parse {
                reason: err.to_string(),
            })?;
        let subject = parsed.subject();

        let cn = single_attribute(subject.iter_common_name())
            .ok_or(PeerIdentityError::MissingCommonName)?;
        let node_id = cn
            .parse::<Id>()
            .map_err(|err| PeerIdentityError::InvalidCommonName {
                cn: cn.clone(),
                reason: err.to_string(),
            })?;
        let ou = single_attribute(subject.iter_organizational_unit())
            .ok_or_else(|| PeerIdentityError::MissingOrganizationalUnit { cn: cn.clone() })?;
        let role = role_from_ou(&ou).ok_or_else(|| PeerIdentityError::UnknownRole {
            cn: cn.clone(),
            ou: ou.clone(),
        })?;
        let cluster_id = single_attribute(subject.iter_organization())
            .ok_or_else(|| PeerIdentityError::MissingOrganization { cn: cn.clone() })?;

        Ok(Self {
            node_id,
            role,
            cluster_id,
        })
    }

    /// [`PeerIdentity::from_certificate`] on the first certificate of a PEM
    /// blob.
    pub fn from_pem(cert_pem: &[u8]) -> Result<Self, PeerIdentityError> {
        Self::from_certificate(&first_certificate(cert_pem)?)
    }

    /// The peer's `OU` string.
    #[must_use]
    pub fn ou(&self) -> &'static str {
        role_ou(self.role)
    }

    /// Applies the RPC authorization matrix (SWK §16.7).
    ///
    /// Three checks, in the order an operator would want them reported: role,
    /// cluster, blacklist. Authentication itself — that the certificate chains
    /// to the cluster root — has already happened in rustls by the time this
    /// runs.
    pub fn authorize(
        &self,
        required: RoleRequirement,
        cluster_id: &str,
        blacklist: &impl CertBlacklist,
    ) -> Result<(), AuthzError> {
        if !required.accepts(self.role) {
            return Err(AuthzError::WrongRole {
                node_id: self.node_id.to_string(),
                ou: self.ou(),
                allowed: required.allowed_ous(),
            });
        }
        if self.cluster_id != cluster_id {
            return Err(AuthzError::WrongCluster {
                node_id: self.node_id.to_string(),
                presented: self.cluster_id.clone(),
                expected: cluster_id.to_owned(),
            });
        }
        if blacklist.contains_cn(self.node_id.as_str()) {
            return Err(AuthzError::Blacklisted {
                node_id: self.node_id.to_string(),
            });
        }
        Ok(())
    }
}

/// The `(not_before, not_after)` of the first certificate in `cert_pem`.
///
/// Feeds [`crate::renewal::next_renewal`]: the renewal window is computed from
/// the certificate's own validity, not from when the file happened to be
/// written.
pub fn certificate_validity(cert_pem: &str) -> Result<(SystemTime, SystemTime), PeerIdentityError> {
    let der = first_certificate(cert_pem.as_bytes())?;
    let (_, parsed) =
        x509_parser::parse_x509_certificate(&der).map_err(|err| PeerIdentityError::Parse {
            reason: err.to_string(),
        })?;
    let cn = single_attribute(parsed.subject().iter_common_name()).unwrap_or_default();
    let not_before = to_system_time(parsed.validity().not_before.timestamp(), &cn)?;
    let not_after = to_system_time(parsed.validity().not_after.timestamp(), &cn)?;
    Ok((not_before, not_after))
}

fn to_system_time(timestamp: i64, cn: &str) -> Result<SystemTime, PeerIdentityError> {
    let invalid = || PeerIdentityError::InvalidValidity {
        cn: cn.to_owned(),
        timestamp,
    };
    let magnitude = Duration::from_secs(timestamp.unsigned_abs());
    if timestamp >= 0 {
        SystemTime::UNIX_EPOCH
            .checked_add(magnitude)
            .ok_or_else(invalid)
    } else {
        SystemTime::UNIX_EPOCH
            .checked_sub(magnitude)
            .ok_or_else(invalid)
    }
}

/// The single value of an X.509 subject attribute, or `None` if the attribute
/// is absent, repeated, or not valid UTF-8.
pub(crate) fn single_attribute<'a>(
    mut attributes: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>,
) -> Option<String> {
    let first = attributes.next()?;
    if attributes.next().is_some() {
        return None;
    }
    first.as_str().ok().map(str::to_owned)
}

/// Every certificate in a PEM blob, in order (leaf first, by convention).
pub fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PeerIdentityError> {
    let mut reader = std::io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| PeerIdentityError::Pem {
            reason: err.to_string(),
        })?;
    if certs.is_empty() {
        return Err(PeerIdentityError::NoCertificate);
    }
    Ok(certs)
}

/// The first certificate in a PEM blob.
pub fn first_certificate(pem: &[u8]) -> Result<CertificateDer<'static>, PeerIdentityError> {
    certificates(pem)?
        .into_iter()
        .next()
        .ok_or(PeerIdentityError::NoCertificate)
}

/// The one recovery a node whose certificate chains to a dropped root has,
/// spelled the same way wherever the daemon prints it.
///
/// A root CA rotation (architecture §12.3) ends by dropping the old root. A
/// node that was offline across the whole rotation therefore holds a
/// certificate nobody trusts and trusts a root nobody presents: both
/// directions of every handshake fail, and no amount of waiting fixes it
/// because the material it needs is only handed out to a *joining* node.
///
/// This constant is the way out, and it is a constant because three places
/// have to say it and an operator must be able to `grep -a` for one sentence:
/// the manager refusing an inbound handshake
/// (`satl_cluster::server`), the stranded node refusing its own outbound one
/// ([`crate::live`]), and `docs/operations.md`. It has to stay literally true
/// of what the code does — `42cae3c` shipped this hint while the join it
/// recommends could not succeed against a non-leader manager, and an
/// instruction that fails is worse than none.
///
/// Plain ASCII, no line-internal newlines: it is logged.
pub const REJOIN_AFTER_ROTATION_HINT: &str = "whichever node missed the rotation must rejoin: 'satl swarm leave --force' there, then \
     'satl swarm join' with a token freshly printed by 'satl swarm join-token worker|manager' on \
     any manager (docs/operations.md, root CA rotation)";

/// A trust store holding every certificate in `ca_pem`.
pub fn root_store(ca_pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(ca_pem)? {
        roots.add(cert).map_err(|source| TlsError::Config {
            side: "trust store",
            source,
        })?;
    }
    Ok(roots)
}

pub(crate) fn private_key(key_pem: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = std::io::BufReader::new(key_pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .ok()
        .flatten()
        .ok_or(TlsError::NoPrivateKey { len: key_pem.len() })
}

/// The mTLS server configuration for a node (architecture §12.1), from a
/// point-in-time snapshot of its material.
///
/// Client certificates are **required** and must chain to the cluster root:
/// there is no anonymous access to any gRPC service. Per-service role checks
/// happen afterwards, in the interceptor, via [`PeerIdentity::authorize`].
///
/// A configuration built here is frozen at this identity; the daemon's
/// long-lived listeners use [`crate::live_server_config`] over a
/// [`LiveIdentity`] instead, so certificate renewal reaches them without a
/// restart (§12.3).
pub fn server_config(identity: &NodeIdentity) -> Result<ServerConfig, TlsError> {
    crate::live::live_server_config(&LiveIdentity::new(identity.clone())?)
}

/// The mTLS client configuration for a node, from a point-in-time snapshot
/// of its material.
///
/// `expected_server_name` is pinned into the verifier rather than left to the
/// dial site: peers are dialed by address (architecture §6), but the name
/// their certificate must carry is always `satl-manager` — or `satl-ca` while
/// bootstrapping. Pinning it here means a caller cannot weaken the check by
/// passing the peer's IP as the server name.
///
/// Like [`server_config`], this is frozen at this identity; the daemon's
/// cached channels use [`crate::live_client_config`] over a [`LiveIdentity`]
/// so reconnects pick up a renewed certificate (§12.3).
pub fn client_config(
    identity: &NodeIdentity,
    expected_server_name: &str,
) -> Result<ClientConfig, TlsError> {
    crate::live::live_client_config(&LiveIdentity::new(identity.clone())?, expected_server_name)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use rustls::{ClientConnection, Connection, ServerConnection};
    use rustls_pki_types::ServerName;

    use super::*;
    use crate::csr::NodeKeyPair;
    use crate::root::RootCa;
    use crate::{NODE_CERT_VALIDITY, SAN_MANAGER};

    const CLUSTER: &str = "3n2ff1rvrc4mn3s2fu6zlt6tw";

    fn identity_for(root: &RootCa, role: NodeRole) -> (NodeIdentity, Id) {
        let key = NodeKeyPair::generate().expect("node key");
        let id = Id::generate();
        let cert = root
            .sign_node_csr(
                &key.csr_der().expect("csr"),
                &id,
                role,
                CLUSTER,
                NODE_CERT_VALIDITY,
            )
            .expect("sign");
        (
            NodeIdentity::new(
                cert.into_string(),
                key.key_pem(),
                root.cert_pem().to_owned(),
            ),
            id,
        )
    }

    fn transfer(src: &mut Connection, dst: &mut Connection) -> Result<(), rustls::Error> {
        let mut buf = Vec::new();
        while src.wants_write() {
            src.write_tls(&mut buf).expect("writing to a Vec");
        }
        let mut cursor = buf.as_slice();
        while !cursor.is_empty() {
            dst.read_tls(&mut cursor).expect("reading from a slice");
            dst.process_new_packets()?;
        }
        Ok(())
    }

    /// Drives a full in-memory handshake and returns the identity each side
    /// saw, or the first error either side raised.
    fn handshake(
        client_config: ClientConfig,
        server_config: ServerConfig,
        server_name: &str,
    ) -> Result<PeerIdentity, rustls::Error> {
        let name = ServerName::try_from(server_name.to_owned()).expect("valid server name");
        let mut client: Connection = ClientConnection::new(Arc::new(client_config), name)?.into();
        let mut server: Connection = ServerConnection::new(Arc::new(server_config))?.into();

        for _ in 0..16 {
            transfer(&mut client, &mut server)?;
            transfer(&mut server, &mut client)?;
            if !client.is_handshaking() && !server.is_handshaking() {
                let peer = server
                    .peer_certificates()
                    .and_then(<[CertificateDer<'_>]>::first)
                    .expect("client certificate is mandatory");
                return Ok(PeerIdentity::from_certificate(peer).expect("peer identity"));
            }
        }
        panic!("handshake did not converge");
    }

    #[test]
    fn provider_offers_only_ecdhe_aead_suites() {
        let provider = crypto_provider();
        assert_eq!(provider.cipher_suites.len(), CIPHER_SUITES.len());
        for suite in &provider.cipher_suites {
            let name = format!("{:?}", suite.suite());
            assert!(
                name.contains("GCM") || name.contains("CHACHA20_POLY1305"),
                "non-AEAD suite offered: {name}"
            );
            assert!(!name.contains("RSA"), "RSA suite offered: {name}");
            if name.starts_with("TLS_ECDHE") {
                assert!(name.contains("ECDSA"), "non-ECDSA TLS1.2 suite: {name}");
            }
        }
        assert!(!provider.kx_groups.is_empty());
        // The same Arc is handed out every time.
        assert!(Arc::ptr_eq(&crypto_provider(), &provider));
    }

    #[test]
    fn a_valid_peer_completes_the_handshake_and_is_identified() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let (server_identity, server_id) = identity_for(&root, NodeRole::Manager);
        let (client_identity, client_id) = identity_for(&root, NodeRole::Worker);

        let identity = handshake(
            client_config(&client_identity, SAN_MANAGER).expect("client config"),
            server_config(&server_identity).expect("server config"),
            SAN_MANAGER,
        )
        .expect("handshake succeeds");

        assert_eq!(identity.node_id, client_id);
        assert_eq!(identity.role, NodeRole::Worker);
        assert_eq!(identity.cluster_id, CLUSTER);
        assert_ne!(identity.node_id, server_id);
    }

    #[test]
    fn a_client_from_a_foreign_ca_is_rejected() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let foreign = RootCa::generate(CLUSTER).expect("foreign root");
        let (server_identity, _) = identity_for(&root, NodeRole::Manager);
        let (mut client_identity, _) = identity_for(&foreign, NodeRole::Worker);
        // The client still trusts our root (so it gets past server
        // verification); the server must reject its certificate.
        client_identity.ca_pem = root.cert_pem().to_owned();

        let err = handshake(
            client_config(&client_identity, SAN_MANAGER).expect("client config"),
            server_config(&server_identity).expect("server config"),
            SAN_MANAGER,
        )
        .expect_err("foreign client certificate must be rejected");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_server_from_a_foreign_ca_is_rejected() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let foreign = RootCa::generate(CLUSTER).expect("foreign root");
        let (server_identity, _) = identity_for(&foreign, NodeRole::Manager);
        let (client_identity, _) = identity_for(&root, NodeRole::Worker);

        let err = handshake(
            client_config(&client_identity, SAN_MANAGER).expect("client config"),
            server_config(&server_identity).expect("server config"),
            SAN_MANAGER,
        )
        .expect_err("foreign server certificate must be rejected");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_worker_cannot_serve_tls_under_the_manager_name() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let (server_identity, _) = identity_for(&root, NodeRole::Worker);
        let (client_identity, _) = identity_for(&root, NodeRole::Manager);

        let err = handshake(
            client_config(&client_identity, SAN_MANAGER).expect("client config"),
            server_config(&server_identity).expect("server config"),
            SAN_MANAGER,
        )
        .expect_err("a worker certificate carries no satl-manager SAN");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "unexpected error: {err}"
        );
    }

    /// The pinned name wins over whatever the dial site passes, so dialing a
    /// manager by an unrelated name still verifies against `satl-manager`.
    #[test]
    fn the_pinned_server_name_overrides_the_dialed_name() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let (server_identity, _) = identity_for(&root, NodeRole::Manager);
        let (client_identity, _) = identity_for(&root, NodeRole::Worker);

        handshake(
            client_config(&client_identity, SAN_MANAGER).expect("client config"),
            server_config(&server_identity).expect("server config"),
            "some-node.internal",
        )
        .expect("pinned name is what gets verified");
    }

    #[test]
    fn config_building_rejects_broken_material() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let (identity, _) = identity_for(&root, NodeRole::Manager);

        let no_cert = NodeIdentity::new(
            String::new(),
            identity.key_pem.clone(),
            identity.ca_pem.clone(),
        );
        assert!(matches!(
            server_config(&no_cert),
            Err(TlsError::Material { .. })
        ));

        let no_key = NodeIdentity::new(
            identity.cert_pem.clone(),
            "-----BEGIN NOTHING-----".to_owned(),
            identity.ca_pem.clone(),
        );
        assert!(matches!(
            server_config(&no_key),
            Err(TlsError::NoPrivateKey { .. })
        ));

        let no_ca = NodeIdentity::new(
            identity.cert_pem.clone(),
            identity.key_pem.clone(),
            String::new(),
        );
        assert!(matches!(
            server_config(&no_ca),
            Err(TlsError::Material { .. })
        ));

        let err = client_config(&identity, "not a dns name!").expect_err("bad server name");
        assert!(matches!(err, TlsError::ServerName { .. }), "{err}");

        // A certificate that does not match the key.
        let (other, _) = identity_for(&root, NodeRole::Manager);
        let mismatched =
            NodeIdentity::new(other.cert_pem, identity.key_pem.clone(), identity.ca_pem);
        assert!(matches!(
            server_config(&mismatched),
            Err(TlsError::Config { .. })
        ));
    }

    #[test]
    fn peer_identity_parses_what_the_signer_produced() {
        let root = RootCa::generate(CLUSTER).expect("root");
        for role in [NodeRole::Manager, NodeRole::Worker] {
            let (identity, id) = identity_for(&root, role);
            let peer = PeerIdentity::from_pem(identity.cert_pem.as_bytes()).expect("identity");
            assert_eq!(peer.node_id, id);
            assert_eq!(peer.role, role);
            assert_eq!(peer.cluster_id, CLUSTER);
            assert_eq!(peer.ou(), role_ou(role));
        }
    }

    #[test]
    fn peer_identity_rejects_certificates_without_a_satl_subject() {
        // The root itself: CN=satl-ca is not a node id.
        let root = RootCa::generate(CLUSTER).expect("root");
        let err = PeerIdentity::from_pem(root.bundle()).expect_err("root is not a node");
        assert!(
            matches!(err, PeerIdentityError::InvalidCommonName { .. }),
            "{err}"
        );

        // A certificate with a node-id CN but no OU.
        let key = rcgen::KeyPair::generate().expect("key");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, Id::generate().as_str());
        dn.push(rcgen::DnType::OrganizationName, CLUSTER);
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).expect("self signed");
        let err = PeerIdentity::from_pem(cert.pem().as_bytes()).expect_err("no OU");
        assert!(
            matches!(err, PeerIdentityError::MissingOrganizationalUnit { .. }),
            "{err}"
        );

        // An unknown OU.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, Id::generate().as_str());
        dn.push(rcgen::DnType::OrganizationalUnitName, "swarm-manager");
        dn.push(rcgen::DnType::OrganizationName, CLUSTER);
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).expect("self signed");
        let err = PeerIdentity::from_pem(cert.pem().as_bytes()).expect_err("unknown OU");
        assert!(
            matches!(err, PeerIdentityError::UnknownRole { .. }),
            "{err}"
        );

        // No O at all.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, Id::generate().as_str());
        dn.push(rcgen::DnType::OrganizationalUnitName, OU_WORKER);
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).expect("self signed");
        let err = PeerIdentity::from_pem(cert.pem().as_bytes()).expect_err("no O");
        assert!(
            matches!(err, PeerIdentityError::MissingOrganization { .. }),
            "{err}"
        );

        assert!(matches!(
            PeerIdentity::from_pem(b"not pem"),
            Err(PeerIdentityError::NoCertificate)
        ));
    }

    #[test]
    fn authorize_matrix() {
        let manager = PeerIdentity {
            node_id: Id::generate(),
            role: NodeRole::Manager,
            cluster_id: CLUSTER.to_owned(),
        };
        let worker = PeerIdentity {
            node_id: Id::generate(),
            role: NodeRole::Worker,
            cluster_id: CLUSTER.to_owned(),
        };

        // Manager-only services (Raft, Control).
        manager
            .authorize(RoleRequirement::Manager, CLUSTER, &())
            .expect("managers may call manager services");
        let err = worker
            .authorize(RoleRequirement::Manager, CLUSTER, &())
            .expect_err("workers may not");
        assert!(matches!(err, AuthzError::WrongRole { .. }), "{err}");
        assert!(err.to_string().contains(OU_WORKER));

        // Dispatcher: either role.
        for peer in [&manager, &worker] {
            peer.authorize(RoleRequirement::WorkerOrManager, CLUSTER, &())
                .expect("dispatcher accepts both roles");
            peer.authorize(RoleRequirement::Any, CLUSTER, &())
                .expect("health accepts both roles");
        }

        // Wrong cluster.
        let err = manager
            .authorize(RoleRequirement::Manager, "another-cluster", &())
            .expect_err("cross-cluster call must be refused");
        match err {
            AuthzError::WrongCluster {
                presented,
                expected,
                ..
            } => {
                assert_eq!(presented, CLUSTER);
                assert_eq!(expected, "another-cluster");
            }
            other => panic!("unexpected error: {other}"),
        }

        // Blacklisted CN, in both blacklist shapes.
        let mut map = BTreeMap::new();
        map.insert(manager.node_id.to_string(), SystemTime::now());
        let err = manager
            .authorize(RoleRequirement::Manager, CLUSTER, &map)
            .expect_err("removed node must be locked out");
        assert!(matches!(err, AuthzError::Blacklisted { .. }), "{err}");
        worker
            .authorize(RoleRequirement::WorkerOrManager, CLUSTER, &map)
            .expect("another node's blacklisting is not this node's problem");

        let set: BTreeSet<String> = [manager.node_id.to_string()].into_iter().collect();
        assert!(
            manager
                .authorize(RoleRequirement::Manager, CLUSTER, &set)
                .is_err()
        );

        // Role is checked before the cluster, and the cluster before the
        // blacklist: an operator sees the most specific reason first.
        let err = worker
            .authorize(RoleRequirement::Manager, "another-cluster", &map)
            .expect_err("refused");
        assert!(matches!(err, AuthzError::WrongRole { .. }), "{err}");
    }

    #[test]
    fn role_requirement_ou_sets() {
        assert!(RoleRequirement::Manager.accepts(NodeRole::Manager));
        assert!(!RoleRequirement::Manager.accepts(NodeRole::Worker));
        assert!(RoleRequirement::WorkerOrManager.accepts(NodeRole::Worker));
        assert!(RoleRequirement::Any.accepts(NodeRole::Worker));
        assert_eq!(RoleRequirement::Manager.allowed_ous(), OU_MANAGER);
        assert!(RoleRequirement::Any.allowed_ous().contains(OU_WORKER));
    }

    #[test]
    fn certificate_validity_matches_the_issued_span() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let (identity, _) = identity_for(&root, NodeRole::Worker);
        let (not_before, not_after) =
            certificate_validity(&identity.cert_pem).expect("validity parses");
        let span = not_after
            .duration_since(not_before)
            .expect("not_after is later");
        assert_eq!(
            span,
            NODE_CERT_VALIDITY + crate::CERT_BACKDATE,
            "span should be validity + backdate"
        );
        assert!(not_before < SystemTime::now(), "certificate is backdated");
        assert!(certificate_validity("nope").is_err());
    }

    #[test]
    fn root_store_needs_at_least_one_anchor() {
        let root = RootCa::generate(CLUSTER).expect("root");
        assert_eq!(root_store(root.bundle()).expect("store").roots.len(), 1);
        assert!(root_store(b"").is_err());

        // Two roots in one bundle (what a rotation produces) both land.
        let second = RootCa::generate(CLUSTER).expect("root");
        let mut bundle = root.bundle().to_vec();
        bundle.write_all(second.bundle()).expect("writing to a Vec");
        assert_eq!(root_store(&bundle).expect("store").roots.len(), 2);
    }
}
