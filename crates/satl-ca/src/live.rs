// SPDX-License-Identifier: BSD-2-Clause
//! The node's **live** TLS identity: certificate, key and trust anchors held
//! behind swappable slots, so a renewed certificate takes effect on the next
//! handshake instead of on the next daemon restart (architecture §12.3,
//! SWK §16.4).
//!
//! # Why a resolver and not a rebuilt config
//!
//! rustls resolves the certificate a server presents through
//! [`ResolvesServerCert`], **per handshake**; the client-side equivalent is
//! [`ResolvesClientCert`]. Building the `ServerConfig`/`ClientConfig` around
//! resolvers that read a shared [`LiveIdentity`] means the configs themselves
//! — and everything built on top of them: the listener's `TlsAcceptor`, every
//! cached tonic channel and its connector closure — never have to be rebuilt
//! or invalidated. One [`LiveIdentity::swap`] and every *new* handshake, on
//! either side, presents and verifies with the new material.
//!
//! Established connections are deliberately untouched: TLS authenticates at
//! handshake time and never re-checks the peer certificate afterwards, so an
//! open raft stream or dispatcher session keeps working on the identity it
//! was opened with until it next reconnects. That is the correct behavior —
//! severing healthy connections on every renewal would turn a routine
//! maintenance event into churn.
//!
//! # Trust anchors are swappable too
//!
//! The same swap replaces the verifiers built from the identity's CA bundle
//! (the client-certificate verifier on the server side, the pinned-name
//! server verifier on the client side), so a bundle that grows a second root
//! — what an M5 CA rotation produces — is honoured by new handshakes without
//! a restart. One caveat is pinned at construction: the *root hint subjects*
//! a server sends in its `CertificateRequest`
//! ([`ClientCertVerifier::root_hint_subjects`] returns a borrow, so a
//! swappable wrapper cannot serve a value that changes). SatL's own clients
//! ignore the hints — every node
//! holds exactly one certificate and always presents it — so within SatL the
//! staleness is unobservable; an M5 rotation that changes the root *subject*
//! should rebuild the configs anyway when it regenerates everything else.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use satl_core::NodeRole;

use crate::store::NodeIdentity;
use crate::tls::{
    self, PROTOCOL_VERSIONS, PeerIdentity, TlsError, certificate_validity, crypto_provider,
};

/// The current TLS material of a node, swappable at runtime.
///
/// One per daemon: the internal gRPC server, the `NodeCA` bootstrap listener
/// and every outbound mTLS channel are built over the same instance, so the
/// renewal loop swaps *once* and all of them follow.
pub struct LiveIdentity {
    identity: RwLock<NodeIdentity>,
    certified: RwLock<Arc<CertifiedKey>>,
    client_verifier: RwLock<Arc<dyn ClientCertVerifier>>,
    server_verifier: RwLock<Arc<WebPkiServerVerifier>>,
}

/// What a [`LiveIdentity::swap`] installed, for the caller's log line.
#[derive(Debug, Clone)]
pub struct IdentitySwap {
    /// Start of the new certificate's validity (backdated for skew).
    pub not_before: SystemTime,
    /// End of the new certificate's validity.
    pub not_after: SystemTime,
    /// `not_after` as human-readable UTC text, for the operator's log.
    pub not_after_text: String,
    /// The role (`OU`) the new certificate carries.
    pub role: NodeRole,
}

/// Everything derived from one `NodeIdentity`, built **before** any slot is
/// written so a swap either happens whole or not at all.
struct Material {
    certified: Arc<CertifiedKey>,
    client_verifier: Arc<dyn ClientCertVerifier>,
    server_verifier: Arc<WebPkiServerVerifier>,
}

impl Material {
    fn build(identity: &NodeIdentity) -> Result<Self, TlsError> {
        let chain = tls::certificates(identity.cert_pem.as_bytes())?;
        let key = tls::private_key(&identity.key_pem)?;
        let certified =
            CertifiedKey::from_der(chain, key, &crypto_provider()).map_err(|source| {
                TlsError::Config {
                    side: "identity",
                    source,
                }
            })?;

        let roots = tls::root_store(identity.ca_pem.as_bytes())?;
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots.clone()), crypto_provider())
                .build()
                .map_err(|source| TlsError::NoTrustAnchors {
                    len: identity.ca_pem.len(),
                    source,
                })?;
        let server_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
                .build()
                .map_err(|source| TlsError::NoTrustAnchors {
                    len: identity.ca_pem.len(),
                    source,
                })?;

        Ok(Self {
            certified: Arc::new(certified),
            client_verifier,
            server_verifier,
        })
    }
}

/// Reads a slot, recovering from poisoning: the data is a plain `Arc` (or an
/// owned PEM snapshot), so a panic in some other thread mid-write left
/// nothing half-initialized worth refusing over — and a TLS handshake that
/// panics the whole daemon on a poisoned lock would be strictly worse.
fn read_slot<T: Clone>(slot: &RwLock<T>) -> T {
    match slot.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Writes a slot, recovering from poisoning (see [`read_slot`]).
fn write_slot<T>(slot: &RwLock<T>, value: T) {
    match slot.write() {
        Ok(mut guard) => *guard = value,
        Err(poisoned) => *poisoned.into_inner() = value,
    }
}

impl LiveIdentity {
    /// Builds the live identity from the node's on-disk material.
    ///
    /// Fails exactly where [`crate::server_config`] would: unreadable
    /// certificate, missing private key, empty CA bundle, key/certificate
    /// mismatch.
    pub fn new(identity: NodeIdentity) -> Result<Arc<Self>, TlsError> {
        let material = Material::build(&identity)?;
        Ok(Arc::new(Self {
            identity: RwLock::new(identity),
            certified: RwLock::new(material.certified),
            client_verifier: RwLock::new(material.client_verifier),
            server_verifier: RwLock::new(material.server_verifier),
        }))
    }

    /// Replaces the certificate, key and trust anchors.
    ///
    /// Every piece is parsed and validated **before** the first slot is
    /// written, so a rejected identity leaves the old one fully in place.
    /// New handshakes — inbound accepts and outbound (re)dials alike — use
    /// the new material immediately; established connections are untouched
    /// (module docs).
    pub fn swap(&self, identity: NodeIdentity) -> Result<IdentitySwap, TlsError> {
        let material = Material::build(&identity)?;
        let (not_before, not_after) = certificate_validity(&identity.cert_pem)?;
        let role = PeerIdentity::from_pem(identity.cert_pem.as_bytes())?.role;

        write_slot(&self.certified, material.certified);
        write_slot(&self.client_verifier, material.client_verifier);
        write_slot(&self.server_verifier, material.server_verifier);
        write_slot(&self.identity, identity);

        Ok(IdentitySwap {
            not_before,
            not_after,
            not_after_text: format_utc(not_after),
            role,
        })
    }

    /// A snapshot of the current identity (PEM), for callers that need the
    /// raw material: the authorizer's own-certificate parse, persistence.
    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        read_slot(&self.identity)
    }

    /// The certificate and key presented on the next handshake.
    #[must_use]
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        read_slot(&self.certified)
    }

    fn client_verifier(&self) -> Arc<dyn ClientCertVerifier> {
        read_slot(&self.client_verifier)
    }

    fn server_verifier(&self) -> Arc<WebPkiServerVerifier> {
        read_slot(&self.server_verifier)
    }
}

impl fmt::Debug for LiveIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NodeIdentity redacts its key material; still, keep this terse.
        f.debug_struct("LiveIdentity").finish_non_exhaustive()
    }
}

/// `SystemTime` as human-readable UTC (ASCII, syslog-safe).
fn format_utc(at: SystemTime) -> String {
    time::OffsetDateTime::from(at).to_string()
}

// ---------------------------------------------------------------------------
// rustls seams
// ---------------------------------------------------------------------------

/// [`ResolvesServerCert`] over a [`LiveIdentity`]: every inbound handshake
/// presents whatever certificate is current *now*.
#[derive(Debug)]
struct LiveServerCertResolver {
    live: Arc<LiveIdentity>,
}

impl ResolvesServerCert for LiveServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.live.certified_key())
    }
}

/// [`ResolvesClientCert`] over a [`LiveIdentity`]: every outbound handshake
/// presents whatever certificate is current *now*.
///
/// Hints and signature schemes are ignored, exactly as rustls' own
/// single-certificate resolver ignores them: a SatL node has one certificate
/// and always presents it (module docs).
#[derive(Debug)]
struct LiveClientCertResolver {
    live: Arc<LiveIdentity>,
}

impl ResolvesClientCert for LiveClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.live.certified_key())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A mandatory client-certificate verifier that delegates to the verifier a
/// [`LiveIdentity`] currently holds, so swapped trust anchors apply to new
/// handshakes.
///
/// The root hint subjects are copied out of the verifier present at
/// construction and never change afterwards (module docs explain why that is
/// sound for SatL).
#[derive(Debug)]
struct LiveClientVerifier {
    live: Arc<LiveIdentity>,
    hints: Vec<DistinguishedName>,
}

impl LiveClientVerifier {
    fn new(live: Arc<LiveIdentity>) -> Self {
        let hints = live.client_verifier().root_hint_subjects().to_vec();
        Self { live, hints }
    }
}

impl ClientCertVerifier for LiveClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.live
            .client_verifier()
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.live
            .client_verifier()
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.live
            .client_verifier()
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.live.client_verifier().supported_verify_schemes()
    }
}

/// Web PKI verification of the *server*, delegating to the verifier a
/// [`LiveIdentity`] currently holds, with the expected server name fixed at
/// configuration time instead of taken from the dial site — peers are dialed
/// by address, but the name their certificate must carry is always
/// `satl-manager` (or `satl-ca` while bootstrapping). Pinning it here means a
/// caller cannot weaken the check by passing the peer's IP as the server
/// name.
#[derive(Debug)]
struct LivePinnedServerVerifier {
    live: Arc<LiveIdentity>,
    expected: ServerName<'static>,
    /// Rate limiter for [`Self::diagnose`], as whole seconds since
    /// `UNIX_EPOCH`; `0` means "never logged".
    last_diagnosis: AtomicU64,
}

/// How often one client config repeats the trust-anchor diagnosis.
///
/// A stranded node's dispatcher session and raft dials both retry under
/// backoff, so without a limiter the same paragraph lands in
/// `/var/log/messages` several times a minute for as long as the node stays
/// stranded — and the operator who has to read that file is the person the
/// paragraph is for. Once a minute is frequent enough that `grep -a` finds it
/// in any window worth looking at.
const DIAGNOSIS_INTERVAL_SECS: u64 = 60;

/// Whether the diagnosis may be printed again, given the last time it was
/// (whole seconds since `UNIX_EPOCH`, `0` for never) and the time now.
///
/// A pure function over an injected clock, like everything in
/// [`crate::renewal`], so the arithmetic is tested rather than trusted: a
/// limiter that never opens turns the one message an operator needs into
/// silence, and one that never closes buries the log it lives in. `now` moving
/// *backwards* (a clock step, which these nodes do see) must open it rather
/// than wedge it shut for a minute.
#[must_use]
fn diagnosis_is_due(last: u64, now: u64) -> bool {
    last == 0 || now < last || now - last >= DIAGNOSIS_INTERVAL_SECS
}

/// What a rejected outbound handshake means, from the two certificates alone.
///
/// The distinction is the whole value of the message: the two cases need
/// different actions from the operator, and the daemon can tell them apart.
#[derive(Debug, PartialEq, Eq)]
enum TrustFailure {
    /// The peer's certificate names another cluster: these nodes are not in the
    /// same swarm at all.
    DifferentCluster,
    /// Same cluster, chains that do not meet: one side is anchored on a root
    /// the other has dropped.
    DroppedRoot,
}

/// Classifies a rejection from this node's cluster id and the peer's.
///
/// `None` for either side means the certificate would not parse, which is not
/// evidence of a different cluster — so it falls back to the rotation
/// diagnosis rather than telling an operator to re-join a node that is in the
/// right cluster after all.
#[must_use]
fn classify(mine: Option<&str>, theirs: Option<&str>) -> TrustFailure {
    match (mine, theirs) {
        (Some(mine), Some(theirs)) if mine != theirs => TrustFailure::DifferentCluster,
        _ => TrustFailure::DroppedRoot,
    }
}

/// Whether a rejection is the chain failing to reach this node's anchors, as
/// opposed to a certificate that *does* chain but is unacceptable for some
/// other reason.
///
/// Both spellings occur between SatL nodes and mean the same thing to an
/// operator, which is why both are here and why guessing one was not enough:
/// `UnknownIssuer` when the peer presents a chain whose top is a root this node
/// has never held, and **`BadSignature`** when it presents a single leaf whose
/// issuer name matches an anchor this node holds but whose signature was made
/// by a different key — which is exactly what a leaf from a dropped root looks
/// like, since every root of a given cluster carries the same `CN=satl-ca`.
/// Measured on the three VMs: a node re-issued under a rotated root is refused
/// with `invalid peer certificate: BadSignature`, not `UnknownIssuer`.
///
/// Deliberately *not* included: `Expired` (its own documented condition, with
/// its own section in `docs/operations.md` — blaming a rotation there would
/// send an operator the wrong way) and `NotValidForName` (a SAN bug, not a
/// trust-anchor one).
fn is_trust_path_failure(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer | rustls::CertificateError::BadSignature
        )
    )
}

impl LivePinnedServerVerifier {
    /// Says, at most once per [`DIAGNOSIS_INTERVAL_SECS`], why a peer this node
    /// dialled was rejected — when the reason is one an operator has to act on.
    ///
    /// # This fires less often than you would expect, and that is the design
    ///
    /// A node that slept through *one* root CA rotation still verifies its
    /// peers fine: their leaves carry the cross-signed intermediate, so the
    /// chain bridges back to the root this node still holds (§12.3 — that
    /// bridging is the whole point). The failure is one-directional: the
    /// managers reject *its* leaf, and it sees their fatal alert, not a
    /// verification error of its own. So this hook stays quiet in that case by
    /// construction, and the operator-facing message for it is the manager's
    /// (`satl_cluster::server`). Measured on the three VMs.
    ///
    /// What does reach here is every case with no bridge left: a peer from a
    /// different cluster, and a node more than one rotation behind.
    ///
    /// A rejection between two SatL nodes has two causes and they need
    /// different actions, so the message names which one it is:
    ///
    /// - the peer's certificate says a **different cluster**: the two nodes are
    ///   not in the same swarm at all (a node that left, or one that
    ///   re-initialized itself), and joining is the only thing that fixes it;
    /// - the same cluster: one of the two slept through a root CA rotation and
    ///   is anchored on a root the other has dropped
    ///   ([`REJOIN_AFTER_ROTATION_HINT`](crate::REJOIN_AFTER_ROTATION_HINT)).
    ///
    /// Which of the two nodes missed the rotation is deliberately *not*
    /// asserted: this side sees only that the chains do not meet. The peer's
    /// node id is logged instead, which is what lets an operator decide.
    /// Nothing here is on a success path — it runs only after a rejection.
    fn diagnose(&self, end_entity: &CertificateDer<'_>, error: &rustls::Error) {
        if !is_trust_path_failure(error) {
            return;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        if !diagnosis_is_due(self.last_diagnosis.load(Ordering::Relaxed), now) {
            return;
        }
        self.last_diagnosis.store(now, Ordering::Relaxed);

        let mine = PeerIdentity::from_pem(self.live.identity().cert_pem.as_bytes()).ok();
        let theirs = PeerIdentity::from_certificate(end_entity).ok();
        let peer_node = theirs
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |peer| peer.node_id.to_string());
        let peer_cluster = theirs.as_ref().map(|peer| peer.cluster_id.as_str());
        let my_cluster = mine.as_ref().map(|me| me.cluster_id.as_str());
        match classify(my_cluster, peer_cluster) {
            TrustFailure::DifferentCluster => tracing::warn!(
                peer_node_id = %peer_node,
                peer_cluster_id = peer_cluster.unwrap_or("unknown"),
                cluster_id = my_cluster.unwrap_or("unknown"),
                "refused an outbound internal TLS connection: the peer presented a certificate \
                 for a different cluster. These two nodes are not members of the same swarm; one \
                 of them left it or re-initialized itself. Join it back with 'satl swarm join' \
                 and a token from a manager of the cluster it belongs in"
            ),
            TrustFailure::DroppedRoot => tracing::warn!(
                peer_node_id = %peer_node,
                cluster_id = my_cluster.unwrap_or("unknown"),
                "refused an outbound internal TLS connection: the peer's certificate does not \
                 verify against this node's trust anchors, and the peer will reject this node's \
                 certificate for the same reason. That is what a root CA rotation ('satl ca \
                 rotate') leaves behind when a node was offline across it: {}",
                crate::REJOIN_AFTER_ROTATION_HINT
            ),
        }
    }
}

impl ServerCertVerifier for LivePinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.live
            .server_verifier()
            .verify_server_cert(
                end_entity,
                intermediates,
                &self.expected,
                ocsp_response,
                now,
            )
            .inspect_err(|error| self.diagnose(end_entity, error))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.live
            .server_verifier()
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.live
            .server_verifier()
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.live.server_verifier().supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// Configuration builders
// ---------------------------------------------------------------------------

/// The mTLS server configuration over a [`LiveIdentity`] (architecture
/// §12.1, §12.3).
///
/// Client certificates are **required** and must chain to the trust anchors
/// the live identity currently holds; the certificate presented is the one it
/// currently holds. Build the configuration once — renewals reach it through
/// the live identity, not through a rebuild.
pub fn live_server_config(live: &Arc<LiveIdentity>) -> Result<ServerConfig, TlsError> {
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(|source| TlsError::Config {
            side: "server",
            source,
        })?
        .with_client_cert_verifier(Arc::new(LiveClientVerifier::new(Arc::clone(live))))
        .with_cert_resolver(Arc::new(LiveServerCertResolver {
            live: Arc::clone(live),
        }));
    tracing::debug!("built live mTLS server configuration");
    Ok(config)
}

/// The mTLS client configuration over a [`LiveIdentity`].
///
/// `expected_server_name` is pinned into the verifier rather than left to
/// the dial site (see [`LivePinnedServerVerifier`]). Certificate and trust
/// anchors are read from the live identity on every handshake, so cached
/// channels built over this configuration present a renewed identity on
/// their next (re)connect.
///
/// **Session resumption is disabled**, deliberately: a resumed TLS session
/// re-attaches the identities of the *original* handshake and re-verifies
/// nothing, so a reconnect after a renewal (or a promotion, which is a
/// renewal, §12.3) would keep presenting the old certificate for as long as
/// tickets stay valid. SatL's internal connections are long-lived — a
/// handshake is a rare event — so resumption buys nothing worth that.
/// (Go's `crypto/tls` client, and therefore SwarmKit, has no session cache
/// by default either.)
pub fn live_client_config(
    live: &Arc<LiveIdentity>,
    expected_server_name: &str,
) -> Result<ClientConfig, TlsError> {
    let expected = ServerName::try_from(expected_server_name.to_owned()).map_err(|source| {
        TlsError::ServerName {
            name: expected_server_name.to_owned(),
            source,
        }
    })?;
    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(|source| TlsError::Config {
            side: "client",
            source,
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LivePinnedServerVerifier {
            live: Arc::clone(live),
            expected,
            last_diagnosis: AtomicU64::new(0),
        }))
        .with_client_cert_resolver(Arc::new(LiveClientCertResolver {
            live: Arc::clone(live),
        }));
    config.resumption = rustls::client::Resumption::disabled();
    tracing::debug!(
        server_name = expected_server_name,
        "built live mTLS client configuration"
    );
    Ok(config)
}

/// A TLS server configuration that presents the live identity's certificate
/// and accepts connections **without** a client certificate: the `NodeCA`
/// bootstrap listener, where a first-time joiner has nothing to present
/// (`proto/ca.proto`).
pub fn live_anonymous_server_config(live: &Arc<LiveIdentity>) -> Result<ServerConfig, TlsError> {
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(PROTOCOL_VERSIONS)
        .map_err(|source| TlsError::Config {
            side: "server",
            source,
        })?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LiveServerCertResolver {
            live: Arc::clone(live),
        }));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::{ClientConnection, Connection, ServerConnection};

    use super::*;
    use crate::csr::NodeKeyPair;
    use crate::root::RootCa;
    use crate::{NODE_CERT_VALIDITY, SAN_MANAGER};
    use satl_core::Id;

    const CLUSTER: &str = "3n2ff1rvrc4mn3s2fu6zlt6tw";

    fn identity_for(
        root: &RootCa,
        node_id: &Id,
        role: NodeRole,
        validity: Duration,
    ) -> NodeIdentity {
        let key = NodeKeyPair::generate().expect("node key");
        let cert = root
            .sign_node_csr(
                &key.csr_der().expect("csr"),
                node_id,
                role,
                CLUSTER,
                validity,
            )
            .expect("sign");
        NodeIdentity::new(
            cert.into_string(),
            key.key_pem(),
            root.cert_pem().to_owned(),
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

    /// Drives a full in-memory handshake and returns the leaf certificate
    /// each side saw of the other: `(client's view of the server, server's
    /// view of the client)`.
    ///
    /// Takes the configs behind `Arc` **so the tests reuse one config across
    /// handshakes**: proving the swap works must not be allowed to degrade
    /// into proving that a rebuilt config works.
    fn handshake(
        client_config: &Arc<ClientConfig>,
        server_config: &Arc<ServerConfig>,
    ) -> Result<(CertificateDer<'static>, CertificateDer<'static>), rustls::Error> {
        let name = ServerName::try_from(SAN_MANAGER).expect("valid server name");
        let mut client: Connection = ClientConnection::new(Arc::clone(client_config), name)?.into();
        let mut server: Connection = ServerConnection::new(Arc::clone(server_config))?.into();

        for _ in 0..16 {
            transfer(&mut client, &mut server)?;
            transfer(&mut server, &mut client)?;
            if !client.is_handshaking() && !server.is_handshaking() {
                let server_cert = client
                    .peer_certificates()
                    .and_then(<[CertificateDer<'_>]>::first)
                    .expect("the server always presents a certificate");
                let client_cert = server
                    .peer_certificates()
                    .and_then(<[CertificateDer<'_>]>::first)
                    .expect("client certificates are mandatory");
                return Ok((
                    server_cert.clone().into_owned(),
                    client_cert.clone().into_owned(),
                ));
            }
        }
        panic!("handshake did not converge");
    }

    /// The `(node_id, not_after)` of a DER certificate seen on the wire.
    fn seen(cert: &CertificateDer<'static>) -> (Id, SystemTime) {
        let identity = PeerIdentity::from_certificate(cert).expect("peer identity");
        let (_, parsed) = x509_parser::parse_x509_certificate(cert).expect("x509");
        let not_after = SystemTime::UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(parsed.validity().not_after.timestamp()).expect("after 1970"),
            );
        (identity.node_id, not_after)
    }

    #[test]
    fn a_swapped_server_certificate_is_presented_on_the_next_handshake() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let server_id = Id::generate();
        let live = LiveIdentity::new(identity_for(
            &root,
            &server_id,
            NodeRole::Manager,
            NODE_CERT_VALIDITY,
        ))
        .expect("live identity");
        let client = LiveIdentity::new(identity_for(
            &root,
            &Id::generate(),
            NodeRole::Worker,
            NODE_CERT_VALIDITY,
        ))
        .expect("client identity");

        // Built once, used for every handshake in this test: the swap must
        // reach them through the live identity, not through a rebuild.
        let client_config =
            Arc::new(live_client_config(&client, SAN_MANAGER).expect("client config"));
        let server_config = Arc::new(live_server_config(&live).expect("server config"));

        let (server_cert, _) = handshake(&client_config, &server_config).expect("first handshake");
        let (seen_id, first_not_after) = seen(&server_cert);
        assert_eq!(seen_id, server_id);

        // The swap: same node, shorter validity — a renewal in miniature.
        let renewed = identity_for(&root, &server_id, NodeRole::Manager, NODE_CERT_VALIDITY / 2);
        let report = live.swap(renewed.clone()).expect("swap");
        assert_eq!(report.role, NodeRole::Manager);
        let (_, renewed_not_after) =
            certificate_validity(&renewed.cert_pem).expect("validity parses");
        assert_eq!(report.not_after, renewed_not_after);
        assert!(!report.not_after_text.is_empty());
        assert!(report.not_after_text.is_ascii());

        // Same configs, new handshake: the renewed certificate is what the
        // client now sees on the wire.
        let (server_cert, _) =
            handshake(&client_config, &server_config).expect("handshake after the swap");
        let (seen_id, second_not_after) = seen(&server_cert);
        assert_eq!(seen_id, server_id);
        assert_ne!(
            first_not_after, second_not_after,
            "the presented certificate must have changed"
        );
        assert_eq!(second_not_after, report.not_after);
    }

    #[test]
    fn a_swapped_client_certificate_is_presented_on_the_next_dial() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let live_client = LiveIdentity::new(identity_for(
            &root,
            &Id::generate(),
            NodeRole::Worker,
            NODE_CERT_VALIDITY,
        ))
        .expect("client identity");
        let server = LiveIdentity::new(identity_for(
            &root,
            &Id::generate(),
            NodeRole::Manager,
            NODE_CERT_VALIDITY,
        ))
        .expect("server identity");

        let client_config =
            Arc::new(live_client_config(&live_client, SAN_MANAGER).expect("client config"));
        let server_config = Arc::new(live_server_config(&server).expect("server config"));

        let (_, client_cert) = handshake(&client_config, &server_config).expect("first handshake");
        let (_, first_not_after) = seen(&client_cert);

        // A renewal that also changes the role: worker promoted to manager.
        let promoted_id = PeerIdentity::from_pem(live_client.identity().cert_pem.as_bytes())
            .expect("own identity")
            .node_id;
        let renewed = identity_for(
            &root,
            &promoted_id,
            NodeRole::Manager,
            NODE_CERT_VALIDITY / 2,
        );
        let report = live_client.swap(renewed).expect("swap");
        assert_eq!(report.role, NodeRole::Manager);

        // The same cached ClientConfig presents the new certificate — this is
        // what a tonic channel reconnect does after a renewal.
        let (_, client_cert) =
            handshake(&client_config, &server_config).expect("handshake after the swap");
        let (seen_id, second_not_after) = seen(&client_cert);
        assert_eq!(seen_id, promoted_id);
        assert_ne!(first_not_after, second_not_after);
        let role = PeerIdentity::from_certificate(&client_cert)
            .expect("client identity")
            .role;
        assert_eq!(role, NodeRole::Manager, "the server sees the new role");
    }

    #[test]
    fn swapped_trust_anchors_admit_what_the_new_bundle_trusts() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let second_root = RootCa::generate(CLUSTER).expect("second root");
        let server_id = Id::generate();
        let live = LiveIdentity::new(identity_for(
            &root,
            &server_id,
            NodeRole::Manager,
            NODE_CERT_VALIDITY,
        ))
        .expect("server identity");

        // A client whose certificate chains to the *second* root, but which
        // trusts the first (so it accepts the server; only the server's
        // client verification is under test).
        let key = NodeKeyPair::generate().expect("client key");
        let cert = second_root
            .sign_node_csr(
                &key.csr_der().expect("csr"),
                &Id::generate(),
                NodeRole::Worker,
                CLUSTER,
                NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let stranger = LiveIdentity::new(NodeIdentity::new(
            cert.into_string(),
            key.key_pem(),
            root.cert_pem().to_owned(),
        ))
        .expect("stranger identity");

        let client_config =
            Arc::new(live_client_config(&stranger, SAN_MANAGER).expect("client config"));
        let server_config = Arc::new(live_server_config(&live).expect("server config"));

        let err = handshake(&client_config, &server_config)
            .expect_err("a client from an untrusted root must be refused");
        assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "{err}");

        // Swap the server's identity to one whose CA bundle carries both
        // roots — the shape an M5 rotation produces.
        let key = NodeKeyPair::generate().expect("server key");
        let cert = root
            .sign_node_csr(
                &key.csr_der().expect("csr"),
                &server_id,
                NodeRole::Manager,
                CLUSTER,
                NODE_CERT_VALIDITY,
            )
            .expect("sign");
        let mut bundle = root.cert_pem().to_owned();
        bundle.push_str(second_root.cert_pem());
        live.swap(NodeIdentity::new(cert.into_string(), key.key_pem(), bundle))
            .expect("swap");

        // The same server config now admits the second root's client.
        handshake(&client_config, &server_config)
            .expect("the swapped trust anchors admit the new root");
    }

    #[test]
    fn a_rejected_swap_leaves_the_old_identity_fully_in_place() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let server_id = Id::generate();
        let identity = identity_for(&root, &server_id, NodeRole::Manager, NODE_CERT_VALIDITY);
        let live = LiveIdentity::new(identity.clone()).expect("live identity");

        // A certificate that does not match the key must be refused whole.
        let other = identity_for(&root, &server_id, NodeRole::Manager, NODE_CERT_VALIDITY);
        let mismatched = NodeIdentity::new(
            other.cert_pem,
            identity.key_pem.clone(),
            identity.ca_pem.clone(),
        );
        let err = live.swap(mismatched).expect_err("key mismatch");
        assert!(matches!(err, TlsError::Config { .. }), "{err}");
        assert_eq!(live.identity(), identity, "nothing was half-swapped");

        // And the old identity still handshakes.
        let client = LiveIdentity::new(identity_for(
            &root,
            &Id::generate(),
            NodeRole::Worker,
            NODE_CERT_VALIDITY,
        ))
        .expect("client identity");
        let client_config =
            Arc::new(live_client_config(&client, SAN_MANAGER).expect("client config"));
        let server_config = Arc::new(live_server_config(&live).expect("server config"));
        handshake(&client_config, &server_config).expect("old identity still serves");
    }

    #[test]
    fn the_anonymous_config_serves_the_live_certificate_without_client_auth() {
        let root = RootCa::generate(CLUSTER).expect("root");
        let server_id = Id::generate();
        let live = LiveIdentity::new(identity_for(
            &root,
            &server_id,
            NodeRole::Manager,
            NODE_CERT_VALIDITY,
        ))
        .expect("server identity");
        let server_config = Arc::new(live_anonymous_server_config(&live).expect("config"));

        // A client with no certificate at all: the bootstrap joiner.
        let roots = tls::root_store(root.cert_pem().as_bytes()).expect("roots");
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(crypto_provider())
                .with_protocol_versions(PROTOCOL_VERSIONS)
                .expect("versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let name = ServerName::try_from(crate::SAN_CA).expect("valid server name");
        let mut client: Connection = ClientConnection::new(Arc::clone(&client_config), name)
            .expect("client")
            .into();
        let mut server: Connection = ServerConnection::new(Arc::clone(&server_config))
            .expect("server")
            .into();
        for _ in 0..16 {
            transfer(&mut client, &mut server).expect("client to server");
            transfer(&mut server, &mut client).expect("server to client");
            if !client.is_handshaking() && !server.is_handshaking() {
                let cert = client
                    .peer_certificates()
                    .and_then(<[CertificateDer<'_>]>::first)
                    .expect("server certificate");
                let (seen_id, _) = seen(&cert.clone().into_owned());
                assert_eq!(seen_id, server_id);
                assert!(server.peer_certificates().is_none(), "no client cert asked");
                return;
            }
        }
        panic!("handshake did not converge");
    }

    #[test]
    fn the_trust_diagnosis_is_rate_limited_but_never_silenced() {
        // Never logged: due immediately, or the one message an operator needs
        // is the one they never see.
        assert!(diagnosis_is_due(0, 1_000_000));
        // Inside the window: suppressed. A stranded node retries under backoff,
        // and this paragraph is long.
        assert!(!diagnosis_is_due(1_000, 1_000));
        assert!(!diagnosis_is_due(
            1_000,
            1_000 + DIAGNOSIS_INTERVAL_SECS - 1
        ));
        // At the window and beyond: due again, for as long as the node stays
        // stranded.
        assert!(diagnosis_is_due(1_000, 1_000 + DIAGNOSIS_INTERVAL_SECS));
        assert!(diagnosis_is_due(1_000, 10_000));
        // A clock that stepped backwards must open the limiter, not wedge it:
        // subtracting would underflow and (saturating) look like "just logged"
        // for a whole minute of real time.
        assert!(diagnosis_is_due(1_000_000, 5));
    }

    #[test]
    fn both_spellings_of_a_broken_trust_path_are_diagnosed() {
        use rustls::CertificateError as E;
        // Measured on the VMs: a leaf from a dropped root is refused as
        // BadSignature, not UnknownIssuer, because every root of a cluster
        // carries the same CN. Matching only UnknownIssuer made this hook
        // unreachable in the one case it was written for.
        assert!(is_trust_path_failure(&rustls::Error::InvalidCertificate(
            E::BadSignature
        )));
        assert!(is_trust_path_failure(&rustls::Error::InvalidCertificate(
            E::UnknownIssuer
        )));
        // Expired has its own documented condition and its own operator
        // procedure; blaming a rotation for it would send them the wrong way.
        assert!(!is_trust_path_failure(&rustls::Error::InvalidCertificate(
            E::Expired
        )));
        assert!(!is_trust_path_failure(&rustls::Error::InvalidCertificate(
            E::NotValidForName
        )));
        assert!(!is_trust_path_failure(
            &rustls::Error::NoCertificatesPresented
        ));
    }

    #[test]
    fn a_rejection_blames_a_different_cluster_only_when_it_can_prove_one() {
        assert_eq!(
            classify(Some("cluster-a"), Some("cluster-b")),
            TrustFailure::DifferentCluster
        );
        assert_eq!(
            classify(Some("cluster-a"), Some("cluster-a")),
            TrustFailure::DroppedRoot
        );
        // An unparseable certificate on either side is not evidence of a
        // different cluster, and telling an operator to re-join a node that is
        // in the right cluster would send them the wrong way.
        assert_eq!(classify(Some("cluster-a"), None), TrustFailure::DroppedRoot);
        assert_eq!(classify(None, Some("cluster-b")), TrustFailure::DroppedRoot);
        assert_eq!(classify(None, None), TrustFailure::DroppedRoot);
    }

    /// The hint both sides of a refused handshake print is one constant, and it
    /// has to keep naming the two commands an operator runs. The live scenario
    /// greps for `satl swarm leave --force` in both messages
    /// (`tests/cluster/run.sh`, `ca_rotate`); dropping it here would turn that
    /// into a red run rather than a silent regression, but naming it makes the
    /// contract explicit.
    #[test]
    fn the_rejoin_hint_names_the_commands_and_stays_loggable() {
        let hint = crate::REJOIN_AFTER_ROTATION_HINT;
        assert!(hint.contains("satl swarm leave --force"), "{hint}");
        assert!(hint.contains("satl swarm join"), "{hint}");
        assert!(hint.contains("satl swarm join-token"), "{hint}");
        assert!(hint.is_ascii(), "the log is plain ASCII: {hint}");
        assert!(!hint.contains('\n'), "one log line: {hint}");
    }
}
