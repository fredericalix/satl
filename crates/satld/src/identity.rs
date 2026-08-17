// SPDX-License-Identifier: BSD-2-Clause
//! Node identity: the certificate this node presents, where it comes from,
//! and the `NodeCA` service that hands them out (architecture §12, SWK §16).
//!
//! A node reaches a usable identity by exactly one of three paths, and which
//! one it takes is decided by what is already on disk:
//!
//! ```text
//!   <state_dir>/certs holds a cert?     ──▶ RESTART   load it; the CN is the
//!                                                     node id, full stop
//!   no cert, no join asked for          ──▶ INIT      generate the cluster's
//!                                                     root CA + both tokens,
//!                                                     self-issue a manager
//!                                                     certificate
//!   no cert, `swarm join` in flight     ──▶ JOIN      NodeCA.GetRootCACertificate
//!                                                     → verify the token digest
//!                                                     → CSR → IssueNodeCertificate
//!                                                     → poll → verify → persist
//! ```
//!
//! # The certificate is the identity
//!
//! `CN = node id`, `OU = role`, `O = cluster id` (§12.1). Nothing else in the
//! daemon is allowed to have an opinion about those three values: the raft
//! directory's `node-id` file is cross-checked against the CN by
//! `satl_cluster` and a disagreement is fatal, the role comes from the OU (so
//! promotion and demotion happen *through renewal*), and the authorizer takes
//! the cluster id from O.
//!
//! # Why INIT has to run after the store exists
//!
//! The cluster id is the `Cluster` object's id, and that object is created by
//! `satl_cluster`'s seeding pass inside `RaftNode::start`. So a fresh node
//! brings raft up **once without a listener**, reads the cluster id it just
//! seeded, mints the CA against it, writes the CA and the tokens onto the
//! `Cluster` object, and then restarts raft with the identity and the
//! listener ([`crate::cluster`]). The extra bring-up costs one open/close of
//! an empty log and happens once in a node's lifetime.
//!
//! # Upgrades
//!
//! A node that predates the CA has raft state, a `node-id` file and no
//! certificate. It takes the INIT path with one difference that matters: the
//! node id is **not** minted, it is the one already on disk, and the
//! `Cluster` object is updated in place rather than created. That is what
//! keeps an existing single-node install — its node id, its services, its
//! running containers — working across the upgrade.
//!
//! # Never logged
//!
//! Join tokens and private keys never appear in a log line, an error message
//! or a `Debug` rendering. [`satl_ca::JoinToken`] redacts itself; the key
//! material lives in [`satl_ca::NodeIdentity`], which does the same.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use satl_ca::{
    CertStore, JoinToken, JoinTokens, NodeIdentity, NodeKeyPair, RootCa, certificate_matches_key,
    verify_issued_cert,
};
use satl_cluster::{ClusterStore, LeaderClient, ProposeError};
use satl_core::{
    Availability, CertificateStatus, Cluster, Id, Meta, Node, NodeRole, NodeSpec, NodeState,
    NodeStatus, StoreAction, StoreObject,
};
use satl_proto::v1;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

use crate::cluster::DeferredStore;

/// How long the CA remembers a certificate it just issued so the joiner's
/// `NodeCertificateStatus` poll can pick it up.
///
/// The signature is synchronous — there is no signing queue to wait on — so
/// this only has to outlive one poll round-trip. It is generous anyway: the
/// entries are a few kilobytes and a joiner that crashed mid-flight simply
/// asks again.
pub const ISSUED_CACHE_TTL: Duration = Duration::from_mins(5);

/// How long a joiner keeps polling `NodeCertificateStatus` before giving up.
pub const JOIN_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between `NodeCertificateStatus` polls.
const JOIN_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Timeout on each individual `NodeCA` RPC.
const CA_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Identity errors. The daemon turns these into `anyhow` context; the
/// messages name what was attempted, because an operator reading them is
/// usually mid-join.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The certificate store could not be read or written.
    #[error("certificate store at {dir}: {source}")]
    Store {
        /// Directory the store lives in.
        dir: PathBuf,
        /// Underlying failure.
        #[source]
        source: satl_ca::StoreError,
    },

    /// Root CA generation, parsing or signing failed.
    #[error("cluster root CA: {0}")]
    Root(#[from] satl_ca::RootCaError),

    /// Key generation, CSR serialization or verification of an issued
    /// certificate failed.
    #[error("node key material: {0}")]
    Csr(#[from] satl_ca::CsrError),

    /// A certificate could not be parsed into an identity.
    #[error("certificate subject: {0}")]
    Peer(#[from] satl_ca::PeerIdentityError),

    /// The join token is not a `SATL-1-…` token, or does not match.
    #[error("join token: {0}")]
    Token(#[from] satl_ca::TokenError),

    /// A trust store could not be built from the fetched bundle.
    #[error("trust anchors: {0}")]
    Tls(#[from] satl_ca::TlsError),

    /// The cluster object is missing the CA material the node needs.
    #[error(
        "this cluster has no root CA on its Cluster object: it was initialized by a daemon that \
         predates the embedded CA and has not completed its identity migration yet"
    )]
    NoClusterCa,

    /// Writing the CA onto the Cluster object failed.
    #[error("cannot record the cluster CA in the store: {0}")]
    Propose(#[from] ProposeError),

    /// Talking to a remote manager's `NodeCA` failed.
    #[error("NodeCA {op} at {addr}: {message}")]
    Rpc {
        /// RPC that failed.
        op: &'static str,
        /// Address dialled.
        addr: String,
        /// What went wrong.
        message: String,
    },

    /// Every manager the join reached redirected it, and following the
    /// redirects never landed on a leader.
    #[error(
        "the manager at {addr} redirected this join to {leader}, and following the redirect did \
         not reach a leader either: no manager in this cluster is currently the raft leader, so \
         no certificate can be signed. Wait for an election ('satl node ls' on a manager shows a \
         Leader once it settles) and re-run 'satl swarm join'"
    )]
    JoinRedirectLoop {
        /// Last address asked.
        addr: String,
        /// Address it pointed at.
        leader: String,
    },

    /// The CA never produced a certificate within [`JOIN_POLL_TIMEOUT`].
    ///
    /// The signature itself is synchronous, so reaching this means the manager
    /// that signed stopped being able to hand the result back — it restarted,
    /// or lost leadership between signing and the poll. Retrying is the right
    /// move and is safe: a join mints a fresh node id either way.
    #[error(
        "the cluster CA at {addr} signed nothing for node {node_id} within {timeout:?}. That \
         manager accepted the request and then stopped answering for it, which is what a restart \
         or a lost election mid-join looks like. Re-run the command; if it keeps happening, check \
         that manager's /var/log/messages"
    )]
    IssueTimeout {
        /// Address polled.
        addr: String,
        /// Node id the CA assigned.
        node_id: String,
        /// How long the joiner waited.
        timeout: Duration,
    },
}

impl IdentityError {
    fn store(dir: &Path, source: satl_ca::StoreError) -> Self {
        Self::Store {
            dir: dir.to_path_buf(),
            source,
        }
    }

    fn rpc(op: &'static str, addr: &str, message: impl std::fmt::Display) -> Self {
        Self::Rpc {
            op,
            addr: addr.to_owned(),
            message: message.to_string(),
        }
    }
}

/// Where this node's certificate, key and CA bundle live.
#[must_use]
pub fn certs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("certs")
}

/// Opens the certificate store under `state_dir`.
pub fn open_store(state_dir: &Path) -> Result<CertStore, IdentityError> {
    let dir = certs_dir(state_dir);
    CertStore::open(&dir).map_err(|source| IdentityError::store(&dir, source))
}

/// Loads this node's identity, or `None` on a node that has never had one.
///
/// **Restart path.** Nothing is validated beyond parseability here: an
/// expired certificate still identifies the node, and the renewal loop is
/// what replaces it.
pub fn load(state_dir: &Path) -> Result<Option<NodeIdentity>, IdentityError> {
    let dir = certs_dir(state_dir);
    open_store(state_dir)?
        .load()
        .map_err(|source| IdentityError::store(&dir, source))
}

/// The three facts a certificate pins (§12.1), read back out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// `CN` — the node id, authoritative over every other source.
    pub node_id: Id,
    /// `OU` — the role this node currently holds.
    pub role: NodeRole,
    /// `O` — the cluster this node belongs to.
    pub cluster_id: String,
}

/// Reads the subject out of an identity's certificate.
pub fn subject(identity: &NodeIdentity) -> Result<Subject, IdentityError> {
    let peer = satl_ca::PeerIdentity::from_pem(identity.cert_pem.as_bytes())?;
    Ok(Subject {
        node_id: peer.node_id,
        role: peer.role,
        cluster_id: peer.cluster_id,
    })
}

/// Writes `identity` to `<state_dir>/certs` (key `0600`, atomic rename).
pub fn save(state_dir: &Path, identity: &NodeIdentity) -> Result<(), IdentityError> {
    let dir = certs_dir(state_dir);
    open_store(state_dir)?
        .save(identity)
        .map_err(|source| IdentityError::store(&dir, source))
}

/// Removes this node's certificate material.
///
/// Used by `swarm leave --force` and by `swarm join`, both of which give the
/// node a *different* identity than the one it holds; leaving the old one on
/// disk would let a restart resurrect it.
pub fn wipe(state_dir: &Path) -> std::io::Result<()> {
    let dir = certs_dir(state_dir);
    match std::fs::remove_dir_all(&dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Init path
// ---------------------------------------------------------------------------

/// What [`initialize`] produced.
#[derive(Debug)]
pub struct Initialized {
    /// The identity to hand to `RaftNode`.
    pub identity: NodeIdentity,
    /// Whether the cluster's CA was generated here (`true`) or loaded from a
    /// `Cluster` object that already carried one (`false`, the "this manager
    /// lost its certificates" case).
    pub ca_generated: bool,
}

/// Gives a manager with cluster state but no certificate one.
///
/// Two cases, both of which end with a manager certificate on disk and a
/// `Cluster` object carrying the root CA and both join tokens:
///
/// - the cluster has no CA yet (fresh init, or the upgrade of a pre-CA
///   install): generate the root for `cluster_id`, mint both tokens, and
///   write all three onto the `Cluster` object;
/// - the cluster already has one (this manager lost its `certs` directory):
///   load the root out of the store and re-issue against it, leaving the
///   tokens alone.
///
/// `node_id` is the node's existing id — the raft directory's, on an upgrade
/// — so the identity that comes out of here never renames the node.
/// `validity` is [`Config::effective_cert_validity`](crate::config::Config):
/// 90 days, unless the testing knob shortened it.
pub async fn initialize(
    state_dir: &Path,
    store: &ClusterStore,
    node_id: &Id,
    validity: Duration,
) -> Result<Initialized, IdentityError> {
    let cluster = {
        let view = store.view();
        view.cluster().map(|c| (*c).clone())
    };
    let Some(cluster) = cluster else {
        return Err(IdentityError::NoClusterCa);
    };
    let cluster_id = cluster.id.to_string();

    // On a cluster that already carries a CA, sign with whatever currently
    // signs — during a rotation that is the new root (§12.3) — and trust the
    // stored bundle. On a fresh cluster, mint the root here.
    let (signer, trust_bundle, ca_generated) = if let Some(signer) = signing_ca_of(&cluster) {
        let bundle = cluster.root_ca_cert.clone().unwrap_or_default();
        (signer?, bundle, false)
    } else {
        let root = RootCa::generate(&cluster_id)?;
        let bundle = root.bundle().to_vec();
        (
            ClusterSigner {
                root,
                intermediate: None,
            },
            bundle,
            true,
        )
    };

    let identity = self_issue(
        &signer,
        node_id,
        NodeRole::Manager,
        &cluster_id,
        validity,
        &trust_bundle,
    )?;
    save(state_dir, &identity)?;

    if ca_generated {
        let tokens = JoinTokens::generate(&trust_bundle);
        seed_cluster_ca(store, &signer.root, &tokens).await?;
    }

    tracing::info!(
        node_id = %node_id,
        cluster_id = %cluster_id,
        role = satl_ca::OU_MANAGER,
        ca_generated,
        certs_dir = %certs_dir(state_dir).display(),
        "node identity issued"
    );
    Ok(Initialized {
        identity,
        ca_generated,
    })
}

/// Signs a certificate for this node with the cluster CA it already holds.
///
/// Used by [`initialize`] and by the renewal loop on a manager: both are the
/// leader-local shortcut of `NodeCA.IssueNodeCertificate`, without the
/// round-trip through its own gRPC service.
///
/// `trust_bundle` is the cluster's current root CA bundle — what the issued
/// chain is verified against and what the identity installs as trust
/// anchors. It is passed separately from the signer because the two diverge
/// during a rotation: the signer is the new root, the bundle carries old +
/// new (§12.3).
pub fn self_issue(
    signer: &ClusterSigner,
    node_id: &Id,
    role: NodeRole,
    cluster_id: &str,
    validity: Duration,
    trust_bundle: &[u8],
) -> Result<NodeIdentity, IdentityError> {
    let key = NodeKeyPair::generate()?;
    let cert = signer.sign_node_csr(&key.csr_der()?, node_id, role, cluster_id, validity)?;
    let pool = satl_ca::root_store(trust_bundle)?;
    verify_issued_cert(&cert, node_id, role, &pool)?;
    certificate_matches_key(&cert, &key)?;
    Ok(NodeIdentity::new(
        cert,
        key.key_pem(),
        String::from_utf8_lossy(trust_bundle).into_owned(),
    ))
}

/// The root CA held on a `Cluster` object, if it holds one.
///
/// `encrypted_root_ca_key` holds the PEM of the root's private key. The "at
/// rest" protection is the raft log's own (§12.4: every entry payload and
/// every snapshot is XChaCha20-Poly1305-sealed with the per-manager DEK); an
/// operator-held KEK on top of that is deferred (§14).
///
/// This is the *stored* root — the first certificate of the trust bundle.
/// The root that **signs** is [`signing_ca_of`]'s: during a rotation the two
/// differ (§12.3).
pub fn root_ca_of(cluster: &Cluster) -> Option<Result<RootCa, IdentityError>> {
    let cert = cluster.root_ca_cert.as_ref()?;
    let key = cluster.encrypted_root_ca_key.as_ref()?;
    let root = load_root(cert, key);
    Some(root)
}

fn load_root(cert: &[u8], key: &[u8]) -> Result<RootCa, IdentityError> {
    let cert = String::from_utf8_lossy(cert).into_owned();
    let key = String::from_utf8_lossy(key).into_owned();
    RootCa::from_pem(&cert, &key).map_err(IdentityError::from)
}

/// The material node certificates are signed with (§12.3).
///
/// Outside a rotation: the cluster root, no intermediate. During one: the
/// **new** root's key, with the cross-signed intermediate appended to every
/// issued leaf so the chain verifies against the old trust anchor too
/// (SWK §16.5).
#[derive(Clone)]
pub struct ClusterSigner {
    /// The CA that signs.
    pub root: RootCa,
    /// Cross-signed intermediate (PEM) appended to issued leaves, present
    /// exactly while a rotation is in flight.
    pub intermediate: Option<String>,
}

impl ClusterSigner {
    /// Signs a node CSR and returns the full chain this node should present:
    /// the leaf, plus the cross-signed intermediate during a rotation.
    pub fn sign_node_csr(
        &self,
        csr_der: &[u8],
        node_id: &Id,
        role: NodeRole,
        cluster_id: &str,
        validity: Duration,
    ) -> Result<String, IdentityError> {
        let leaf = self
            .root
            .sign_node_csr(csr_der, node_id, role, cluster_id, validity)?;
        Ok(match &self.intermediate {
            Some(intermediate) => format!("{}{}", leaf.as_str(), intermediate),
            None => leaf.into_string(),
        })
    }

    /// Digest of the signing root's certificate — what a node's
    /// `certificate_issuer` records and the rotation reconciler compares.
    #[must_use]
    pub fn issuer_digest(&self) -> String {
        self.root.cert_digest()
    }
}

impl std::fmt::Debug for ClusterSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterSigner")
            .field("issuer_digest", &self.issuer_digest())
            .field("cross_signed", &self.intermediate.is_some())
            .finish_non_exhaustive()
    }
}

/// The signer for a `Cluster` object's current state: the rotation's new
/// root while one is in flight, the stored root otherwise (§12.3).
pub fn signing_ca_of(cluster: &Cluster) -> Option<Result<ClusterSigner, IdentityError>> {
    if let Some(rotation) = &cluster.root_rotation {
        let signer =
            load_root(&rotation.new_root_cert, &rotation.encrypted_new_root_key).map(|root| {
                ClusterSigner {
                    root,
                    intermediate: Some(
                        String::from_utf8_lossy(&rotation.cross_signed_cert).into_owned(),
                    ),
                }
            });
        return Some(signer);
    }
    let root = root_ca_of(cluster)?;
    Some(root.map(|root| ClusterSigner {
        root,
        intermediate: None,
    }))
}

/// Writes the root CA and both join tokens onto the `Cluster` object.
async fn seed_cluster_ca(
    store: &ClusterStore,
    root: &RootCa,
    tokens: &JoinTokens,
) -> Result<(), IdentityError> {
    let action = {
        let view = store.view();
        let Some(cluster) = view.cluster() else {
            return Err(IdentityError::NoClusterCa);
        };
        let mut updated = (*cluster).clone();
        updated.root_ca_cert = Some(root.cert_pem().as_bytes().to_vec());
        updated.encrypted_root_ca_key = Some(root.key_pem().as_bytes().to_vec());
        updated.join_tokens = satl_core::JoinTokens::from(tokens);
        updated.meta.updated_at = SystemTime::now();
        StoreAction::Update(StoreObject::Cluster(updated))
    };
    store.propose(vec![action]).await?;
    tracing::info!("cluster root CA and join tokens recorded in the store");
    Ok(())
}

// ---------------------------------------------------------------------------
// Join path
// ---------------------------------------------------------------------------

/// An identity obtained from a remote cluster's CA.
#[derive(Debug)]
pub struct Joined {
    /// The identity to persist and start raft with.
    pub identity: NodeIdentity,
    /// The node id the CA assigned (the certificate's CN).
    pub node_id: Id,
    /// The role the token granted.
    pub role: NodeRole,
}

/// How many `satl-leader-addr` redirects the join flow follows before it
/// gives up.
///
/// One is enough in a healthy cluster — a follower knows the leader — and the
/// bound is what stops two managers that disagree about leadership from
/// bouncing a joiner between them forever. It is the same shape as the
/// renewal path's hop bound and as raft's own join
/// (`satl_cluster::membership`, architecture §6.5).
const JOIN_REDIRECT_HOPS: usize = 2;

/// Runs the join flow against `ca_addr` (architecture §12.2).
///
/// The order is the security-relevant part and it does not bend:
///
/// 1. `GetRootCACertificate` over a connection that verifies **nothing** —
///    there is nothing to verify against yet;
/// 2. the token's digest is checked against the received bundle *before*
///    anything else is trusted. A mismatch aborts here, and it is the only
///    thing standing between a joiner and a MITM on first contact;
/// 3. from then on every call runs over a connection pinned to that bundle;
/// 4. the returned certificate is verified against the same pinned bundle and
///    against the key that made the CSR before it is written to disk.
///
/// # Only the leader signs, and the joiner does not have to know which one
///
/// `GetRootCACertificate` is public material and any manager serves it, but
/// `IssueNodeCertificate` is leader-only: a follower answers
/// `FAILED_PRECONDITION` with the leader's raft address in
/// [`LEADER_ADDR_METADATA`](satl_cluster::LEADER_ADDR_METADATA). That redirect
/// is **followed here**, up to [`JOIN_REDIRECT_HOPS`] times, with the address
/// mapped through [`ca_endpoint_of`](crate::config::ca_endpoint_of) — the
/// metadata carries the peer's `2377` raft address and the bootstrap `NodeCA`
/// listens one above it.
///
/// Not following it is what stranded a node in `42cae3c`: the operator was
/// told to rejoin, did exactly that against a manager that happened not to be
/// the leader, and the join failed. An operator pointing `satl swarm join` at
/// *a* manager has no way to know which one leads, and being asked to find out
/// would make every documented recovery a coin flip.
///
/// The pinned bundle does not change across a redirect, and must not: the
/// digest check in step 2 is what authenticates this cluster, and the leader's
/// certificate has to chain to the very bundle the token pinned.
pub async fn join_remote(
    ca_addr: &str,
    token_text: &str,
    availability: Availability,
) -> Result<Joined, IdentityError> {
    let token = JoinToken::parse(token_text)?;

    // Step 1: the bundle, over an unverified connection.
    let bundle = fetch_root_ca(ca_addr).await?;

    // Step 2: pin it. Everything after this point is authenticated by the
    // digest the operator carried out of band.
    token.verify_ca_bundle(&bundle)?;
    let pool = satl_ca::root_store(&bundle)?;
    tracing::info!(
        ca_addr,
        bundle_len = bundle.len(),
        "cluster root CA fetched and pinned by the join token digest"
    );

    // Steps 3 and 4. The certificate is polled from whichever manager signed
    // it: the issued-cache is local to the signer, so `signer` — not
    // `ca_addr` — is what `poll_certificate` must ask.
    let key = NodeKeyPair::generate()?;
    let csr = key.csr_pem()?;
    let mut signer = ca_addr.to_owned();
    let mut hops = 0;
    let (node_id, role) = loop {
        match issue(&signer, &bundle, &csr, token_text, availability).await {
            Ok(issued) => break issued,
            Err(IssueHop::Failed(error)) => return Err(error),
            Err(IssueHop::Redirect(leader)) => {
                let next = crate::config::ca_endpoint_of(&leader);
                hops += 1;
                if hops >= JOIN_REDIRECT_HOPS || next == signer {
                    return Err(IdentityError::JoinRedirectLoop {
                        addr: signer,
                        leader: next,
                    });
                }
                tracing::info!(
                    from = %signer,
                    to = %next,
                    leader_raft_addr = %leader,
                    "the manager we asked is not the raft leader; following its redirect to \
                     the leader's NodeCA"
                );
                signer = next;
            }
        }
    };
    let cert = poll_certificate(&signer, &bundle, &node_id).await?;

    verify_issued_cert(&cert, &node_id, role, &pool)?;
    certificate_matches_key(&cert, &key)?;
    let identity = NodeIdentity::new(
        cert,
        key.key_pem(),
        String::from_utf8_lossy(&bundle).into_owned(),
    );
    tracing::info!(
        node_id = %node_id,
        role = satl_ca::role_ou(role),
        ca_addr = %signer,
        "node certificate issued by the cluster CA"
    );
    Ok(Joined {
        identity,
        node_id,
        role,
    })
}

/// The client-side channel for the first, unauthenticated call.
async fn fetch_root_ca(addr: &str) -> Result<Vec<u8>, IdentityError> {
    let channel = crate::channels::unverified_tls_channel(addr)
        .map_err(|err| IdentityError::rpc("GetRootCACertificate", addr, err))?;
    let mut client = v1::node_ca_client::NodeCaClient::new(channel);
    let mut request = Request::new(v1::GetRootCaCertificateRequest {});
    request.set_timeout(CA_RPC_TIMEOUT);
    let response = client
        .get_root_ca_certificate(request)
        .await
        .map_err(|status| IdentityError::rpc("GetRootCACertificate", addr, status))?;
    let bundle = response.into_inner().root_ca_bundle;
    if bundle.is_empty() {
        return Err(IdentityError::rpc(
            "GetRootCACertificate",
            addr,
            "the manager returned an empty root CA bundle",
        ));
    }
    Ok(bundle)
}

/// One bootstrap `IssueNodeCertificate` hop, over the token-pinned channel.
///
/// The `Err(IssueHop::Redirect)` arm is not an error the caller reports: it is
/// a follower saying "ask the leader", and [`join_remote`] follows it.
async fn issue(
    addr: &str,
    bundle: &[u8],
    csr_pem: &str,
    token: &str,
    availability: Availability,
) -> Result<(Id, NodeRole), IssueHop> {
    let channel = crate::channels::pinned_tls_channel(addr, bundle)
        .map_err(|err| IssueHop::failed(addr, err))?;
    let mut client = v1::node_ca_client::NodeCaClient::new(channel);
    let mut request = Request::new(v1::IssueNodeCertificateRequest {
        csr: csr_pem.as_bytes().to_vec(),
        token: token.to_owned(),
        availability: proto_availability(availability) as i32,
    });
    request.set_timeout(CA_RPC_TIMEOUT);
    let response = match client.issue_node_certificate(request).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            if let Some(leader) = satl_cluster::forward::leader_addr_from_status(&status) {
                return Err(IssueHop::Redirect(leader));
            }
            return Err(IssueHop::failed(addr, status));
        }
    };
    let node_id = response.node_id.parse::<Id>().map_err(|err| {
        IssueHop::failed(addr, format!("the CA returned an unusable node id: {err}"))
    })?;
    let role = role_from_proto(response.role)
        .ok_or_else(|| IssueHop::failed(addr, "the CA returned an unspecified role"))?;
    Ok((node_id, role))
}

async fn poll_certificate(
    addr: &str,
    bundle: &[u8],
    node_id: &Id,
) -> Result<String, IdentityError> {
    let channel = crate::channels::pinned_tls_channel(addr, bundle)
        .map_err(|err| IdentityError::rpc("NodeCertificateStatus", addr, err))?;
    let mut client = v1::node_ca_client::NodeCaClient::new(channel);
    let deadline = SystemTime::now() + JOIN_POLL_TIMEOUT;
    loop {
        let mut request = Request::new(v1::NodeCertificateStatusRequest {
            node_id: node_id.to_string(),
        });
        request.set_timeout(CA_RPC_TIMEOUT);
        let response = client
            .node_certificate_status(request)
            .await
            .map_err(|status| IdentityError::rpc("NodeCertificateStatus", addr, status))?
            .into_inner();
        if response.status == v1::CertificateStatus::Issued as i32
            && !response.certificate.is_empty()
        {
            return Ok(String::from_utf8_lossy(&response.certificate).into_owned());
        }
        if SystemTime::now() >= deadline {
            return Err(IdentityError::IssueTimeout {
                addr: addr.to_owned(),
                node_id: node_id.to_string(),
                timeout: JOIN_POLL_TIMEOUT,
            });
        }
        tokio::time::sleep(JOIN_POLL_INTERVAL).await;
    }
}

/// Renews this node's certificate against a manager's `NodeCA` over mTLS —
/// the renewal path of a node that holds **no store** (a worker), and the
/// vehicle of every live role change (§12.3: the CA signs the role the store
/// records, so renewing after a promotion/demotion is what applies it).
///
/// The existing certificate authenticates the request (the mTLS server's
/// `NodeCA` registration is `RoleRequirement::Any`); the token field stays
/// empty. Only the leader signs, so a `FAILED_PRECONDITION` carrying
/// `satl-leader-addr` metadata is followed once per attempt, and every
/// address in `managers` is tried before giving up. The certificate is
/// polled from the manager that signed it (the issued-cache is local to the
/// signer), verified against the trust anchors this node already holds, and
/// swapped into `live` — the next handshake presents it, no restart.
pub async fn renew_remote(
    state_dir: &Path,
    live: &Arc<satl_ca::LiveIdentity>,
    managers: &[String],
) -> Result<Subject, IdentityError> {
    if managers.is_empty() {
        return Err(IdentityError::rpc(
            "IssueNodeCertificate",
            "(none)",
            "no manager address to renew against",
        ));
    }
    let channels = crate::channels::MtlsChannels::new(live)
        .map_err(|error| IdentityError::rpc("IssueNodeCertificate", "mtls", error))?;
    let key = NodeKeyPair::generate()?;
    let csr = key.csr_pem()?;

    let mut last: Option<IdentityError> = None;
    for addr in managers {
        // One redirect per attempt: a follower answers with the leader's
        // address, and the leader is who both signs and caches the result.
        let mut target = addr.clone();
        for _hop in 0..2 {
            match issue_renewal(&channels, &target, &csr).await {
                Ok((node_id, role)) => {
                    let cert = poll_certificate_mtls(&channels, &target, &node_id).await?;
                    let current = live.identity();
                    let pool = satl_ca::root_store(current.ca_pem.as_bytes())?;
                    verify_issued_cert(&cert, &node_id, role, &pool)?;
                    certificate_matches_key(&cert, &key)?;
                    let identity = NodeIdentity::new(cert, key.key_pem(), current.ca_pem.clone());
                    save(state_dir, &identity)?;
                    let subject = subject(&identity)?;
                    live.swap(identity).map_err(IdentityError::from)?;
                    tracing::info!(
                        node_id = %subject.node_id,
                        role = satl_ca::role_ou(subject.role),
                        ca = %target,
                        "node certificate renewed by a manager's NodeCA and swapped live"
                    );
                    return Ok(subject);
                }
                Err(IssueHop::Redirect(leader)) => {
                    tracing::debug!(from = %target, to = %leader, "renewal redirected to the leader");
                    target = leader;
                }
                Err(IssueHop::Failed(error)) => {
                    tracing::warn!(manager = %target, %error, "renewal attempt failed");
                    last = Some(error);
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        IdentityError::rpc(
            "IssueNodeCertificate",
            managers.first().map_or("(none)", String::as_str),
            "every manager redirected without answering",
        )
    }))
}

/// One `IssueNodeCertificate` hop: issued, redirected, or failed.
///
/// Shared by both callers of that RPC — the bootstrap join over the
/// token-pinned channel ([`issue`]) and the mTLS renewal ([`issue_renewal`]) —
/// because only the leader signs and *both* therefore have to follow the
/// `satl-leader-addr` redirect. Keeping one enum is what makes it hard to fix
/// the redirect on one path and leave the other stranded, which is exactly
/// what `42cae3c` shipped.
enum IssueHop {
    Redirect(String),
    Failed(IdentityError),
}

impl IssueHop {
    fn failed(addr: &str, message: impl std::fmt::Display) -> Self {
        Self::Failed(IdentityError::rpc("IssueNodeCertificate", addr, message))
    }
}

async fn issue_renewal(
    channels: &crate::channels::MtlsChannels,
    addr: &str,
    csr_pem: &str,
) -> Result<(Id, NodeRole), IssueHop> {
    let channel = channels.channel(addr).map_err(|error| {
        IssueHop::Failed(IdentityError::rpc("IssueNodeCertificate", addr, error))
    })?;
    let mut client = v1::node_ca_client::NodeCaClient::new(channel);
    let mut request = Request::new(v1::IssueNodeCertificateRequest {
        csr: csr_pem.as_bytes().to_vec(),
        token: String::new(),
        availability: v1::Availability::Unspecified as i32,
    });
    request.set_timeout(CA_RPC_TIMEOUT);
    match client.issue_node_certificate(request).await {
        Ok(response) => {
            let response = response.into_inner();
            let node_id = response.node_id.parse::<Id>().map_err(|error| {
                IssueHop::Failed(IdentityError::rpc(
                    "IssueNodeCertificate",
                    addr,
                    format!("the CA returned an unusable node id: {error}"),
                ))
            })?;
            let role = role_from_proto(response.role).ok_or_else(|| {
                IssueHop::Failed(IdentityError::rpc(
                    "IssueNodeCertificate",
                    addr,
                    "the CA returned an unspecified role",
                ))
            })?;
            Ok((node_id, role))
        }
        Err(status) => {
            if let Some(leader) = satl_cluster::forward::leader_addr_from_status(&status) {
                return Err(IssueHop::Redirect(leader));
            }
            Err(IssueHop::Failed(IdentityError::rpc(
                "IssueNodeCertificate",
                addr,
                status,
            )))
        }
    }
}

/// Polls `NodeCertificateStatus` over the authenticated channel until the
/// signer hands the certificate back.
async fn poll_certificate_mtls(
    channels: &crate::channels::MtlsChannels,
    addr: &str,
    node_id: &Id,
) -> Result<String, IdentityError> {
    let channel = channels
        .channel(addr)
        .map_err(|error| IdentityError::rpc("NodeCertificateStatus", addr, error))?;
    let mut client = v1::node_ca_client::NodeCaClient::new(channel);
    let deadline = SystemTime::now() + JOIN_POLL_TIMEOUT;
    loop {
        let mut request = Request::new(v1::NodeCertificateStatusRequest {
            node_id: node_id.to_string(),
        });
        request.set_timeout(CA_RPC_TIMEOUT);
        let response = client
            .node_certificate_status(request)
            .await
            .map_err(|status| IdentityError::rpc("NodeCertificateStatus", addr, status))?
            .into_inner();
        if response.status == v1::CertificateStatus::Issued as i32
            && !response.certificate.is_empty()
        {
            return Ok(String::from_utf8_lossy(&response.certificate).into_owned());
        }
        if SystemTime::now() >= deadline {
            return Err(IdentityError::IssueTimeout {
                addr: addr.to_owned(),
                node_id: node_id.to_string(),
                timeout: JOIN_POLL_TIMEOUT,
            });
        }
        tokio::time::sleep(JOIN_POLL_INTERVAL).await;
    }
}

/// The proto spelling of an availability.
fn proto_availability(availability: Availability) -> v1::Availability {
    match availability {
        Availability::Active => v1::Availability::Active,
        Availability::Pause => v1::Availability::Pause,
        Availability::Drain => v1::Availability::Drain,
    }
}

/// The domain spelling of a proto availability; `None` for `UNSPECIFIED`.
fn availability_from_proto(value: i32) -> Option<Availability> {
    match v1::Availability::try_from(value).ok()? {
        v1::Availability::Unspecified => None,
        v1::Availability::Active => Some(Availability::Active),
        v1::Availability::Pause => Some(Availability::Pause),
        v1::Availability::Drain => Some(Availability::Drain),
    }
}

/// The domain spelling of a proto role; `None` for `UNSPECIFIED`.
fn role_from_proto(value: i32) -> Option<NodeRole> {
    match v1::NodeRole::try_from(value).ok()? {
        v1::NodeRole::Unspecified => None,
        v1::NodeRole::Worker => Some(NodeRole::Worker),
        v1::NodeRole::Manager => Some(NodeRole::Manager),
    }
}

/// The proto spelling of a role.
fn proto_role(role: NodeRole) -> v1::NodeRole {
    match role {
        NodeRole::Worker => v1::NodeRole::Worker,
        NodeRole::Manager => v1::NodeRole::Manager,
    }
}

// ---------------------------------------------------------------------------
// NodeCA service
// ---------------------------------------------------------------------------

/// The `NodeCA` gRPC service (`proto/ca.proto`).
///
/// **This is the only place `Node` objects are born** (§12.2): a node exists
/// in the cluster because the CA issued it a certificate, not because it
/// showed up on the dispatcher. That ordering is what lets the dispatcher
/// treat "unknown node" as an error rather than as a registration.
///
/// Leader-only, like every other write path: a follower answers
/// `FAILED_PRECONDITION` with the leader's address in the
/// [`satl_cluster::LEADER_ADDR_METADATA`] response metadata, and the joiner
/// redials. Signing is synchronous — the root key is right there on the
/// `Cluster` object — so the `PENDING` state the proto allows for is only
/// ever seen by a caller that polls a manager which did not sign.
#[derive(Clone)]
pub struct NodeCaService {
    store: DeferredStore,
    /// Certificates issued recently, so the status poll can serve them.
    issued: IssuedCache,
    /// `cert_validity` from this daemon's config: a **testing** override of
    /// the cluster's `node_cert_expiry`, `None` in production
    /// ([`crate::config::Config::cert_validity`]).
    validity_override: Option<Duration>,
}

/// Certificates this manager signed recently, kept only long enough for the
/// joiner's status poll to collect them ([`ISSUED_CACHE_TTL`]).
///
/// Deliberately *not* replicated: an issued certificate is public material
/// the holder already has, and putting it in the raft log would grow every
/// snapshot for no benefit. The cost is that a joiner must poll the manager
/// that signed — which it does, since it holds one channel for the whole flow
/// and every manager but the leader redirects.
#[derive(Clone, Default)]
struct IssuedCache {
    inner: Arc<Mutex<BTreeMap<Id, IssuedCert>>>,
}

/// One recently issued certificate.
#[derive(Debug, Clone)]
struct IssuedCert {
    pem: String,
    at: SystemTime,
}

impl IssuedCache {
    fn remember(&self, node_id: &Id, pem: &str) {
        let now = SystemTime::now();
        let Ok(mut issued) = self.inner.lock() else {
            tracing::error!("the issued-certificate cache is poisoned; the status poll will retry");
            return;
        };
        issued.retain(|_, entry| {
            now.duration_since(entry.at)
                .is_ok_and(|age| age < ISSUED_CACHE_TTL)
        });
        issued.insert(
            node_id.clone(),
            IssuedCert {
                pem: pem.to_owned(),
                at: now,
            },
        );
    }

    fn recall(&self, node_id: &Id) -> Option<String> {
        let issued = self.inner.lock().ok()?;
        issued.get(node_id).map(|entry| entry.pem.clone())
    }
}

/// The DER bytes of a CSR that arrived over the wire.
///
/// `proto/ca.proto` pins the field as PEM, and that is what the joiner sends;
/// `satl_ca`'s signer takes DER. Raw DER is accepted too, so a client that
/// sends the unarmoured form is not punished for it — the signer verifies the
/// CSR's self-signature either way, which is the check that matters.
fn csr_der(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if !bytes.starts_with(b"-----") {
        return Ok(bytes.to_vec());
    }
    let mut reader = std::io::BufReader::new(bytes);
    match rustls_pemfile::csr(&mut reader) {
        Ok(Some(der)) => Ok(der.as_ref().to_vec()),
        Ok(None) => Err(format!(
            "the request carries {} bytes of PEM but no CERTIFICATE REQUEST block",
            bytes.len()
        )),
        Err(error) => Err(format!(
            "unreadable PEM certificate signing request: {error}"
        )),
    }
}

/// The role a presented token grants, or `None` when it matches neither of
/// the cluster's tokens.
///
/// The comparison is [`JoinTokens::role_for_token`]'s, which is constant time
/// — a timing oracle on the secret half of a join token would let an attacker
/// recover it byte by byte.
#[must_use]
pub fn role_for_token(cluster: &Cluster, token: &JoinToken) -> Option<NodeRole> {
    JoinTokens::try_from(&cluster.join_tokens)
        .ok()?
        .role_for_token(token)
}

impl std::fmt::Debug for NodeCaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCaService").finish_non_exhaustive()
    }
}

impl NodeCaService {
    /// A CA service over `store`, which the daemon installs a moment after
    /// the gRPC server this is registered on starts
    /// ([`DeferredStore`](crate::cluster::DeferredStore)).
    ///
    /// `validity_override` is the config file's `cert_validity` testing knob;
    /// pass `None` outside a renewal-test cluster.
    #[must_use]
    pub fn new(store: DeferredStore, validity_override: Option<Duration>) -> Self {
        Self {
            store,
            issued: IssuedCache::default(),
            validity_override,
        }
    }

    /// The tonic service, with SatL's message-size limits applied.
    #[must_use]
    pub fn server(&self) -> v1::node_ca_server::NodeCaServer<Self> {
        v1::node_ca_server::NodeCaServer::new(self.clone())
            .max_decoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
            .max_encoding_message_size(satl_proto::MAX_MESSAGE_SIZE)
    }

    /// Refuses unless this node is the raft leader, redirecting otherwise.
    fn require_leader(&self) -> Result<(), Status> {
        let store = self.store.get()?;
        if store.metrics().is_leader {
            return Ok(());
        }
        Err(satl_cluster::forward::leader_redirect_status(
            store.leader_addr().as_deref(),
            "this manager is not the raft leader; certificates are signed by the leader. \
             Retry against the manager in the satl-leader-addr metadata",
        ))
    }

    /// The cluster object, or `UNAVAILABLE` on a manager whose store has not
    /// caught up yet.
    fn cluster(&self) -> Result<Cluster, Status> {
        let view = self.store.get()?.view();
        view.cluster().map(|c| (*c).clone()).ok_or_else(|| {
            Status::unavailable("this manager has no Cluster object yet; retry in a moment")
        })
    }

    fn signer(cluster: &Cluster) -> Result<ClusterSigner, Status> {
        signing_ca_of(cluster)
            .ok_or_else(|| {
                Status::failed_precondition(
                    "this cluster has no root CA on its Cluster object; the leader has not \
                     finished initializing the embedded CA",
                )
            })?
            .map_err(|err| Status::internal(err.to_string()))
    }

    /// Creates (or updates) the `Node` object for a node being issued a
    /// certificate. This is the birth of the object (§12.2).
    ///
    /// `issuer_digest` is the digest of the root that signs — recorded so the
    /// rotation reconciler can tell converged nodes from pending ones without
    /// ever seeing a certificate (§12.3).
    async fn ensure_node(
        &self,
        node_id: &Id,
        role: NodeRole,
        availability: Availability,
        issuer_digest: &str,
    ) -> Result<(), Status> {
        let store = self.store.get()?.clone();
        let action = {
            let view = store.view();
            match view.node(node_id) {
                None => StoreAction::Create(StoreObject::Node(Node {
                    id: node_id.clone(),
                    meta: Meta::new(),
                    spec: NodeSpec {
                        name: None,
                        labels: BTreeMap::new(),
                        role,
                        availability,
                    },
                    description: None,
                    status: NodeStatus {
                        state: NodeState::Unknown,
                        message: "certificate issued; waiting for the first session".to_owned(),
                        addr: String::new(),
                    },
                    manager_status: None,
                    certificate_status: CertificateStatus::Issued,
                    certificate_issuer: Some(issuer_digest.to_owned()),
                })),
                Some(existing) => {
                    let mut updated = (*existing).clone();
                    updated.certificate_status = CertificateStatus::Issued;
                    updated.certificate_issuer = Some(issuer_digest.to_owned());
                    updated.meta.updated_at = SystemTime::now();
                    StoreAction::Update(StoreObject::Node(updated))
                }
            }
        };
        store
            .propose(vec![action])
            .await
            .map_err(|err| Status::internal(format!("cannot record the node object: {err}")))?;
        Ok(())
    }
}

#[tonic::async_trait]
impl v1::node_ca_server::NodeCa for NodeCaService {
    /// Public material only; served by any manager, leader or not, because a
    /// joiner needs it before it can find the leader.
    async fn get_root_ca_certificate(
        &self,
        _request: Request<v1::GetRootCaCertificateRequest>,
    ) -> Result<Response<v1::GetRootCaCertificateResponse>, Status> {
        let cluster = self.cluster()?;
        let bundle = cluster.root_ca_cert.clone().ok_or_else(|| {
            Status::failed_precondition("this cluster has no root CA on its Cluster object")
        })?;
        Ok(Response::new(v1::GetRootCaCertificateResponse {
            root_ca_bundle: bundle,
        }))
    }

    async fn issue_node_certificate(
        &self,
        request: Request<v1::IssueNodeCertificateRequest>,
    ) -> Result<Response<v1::IssueNodeCertificateResponse>, Status> {
        self.require_leader()?;
        let renewal_of = request
            .extensions()
            .get::<satl_ca::PeerIdentity>()
            .cloned()
            .or_else(|| {
                request
                    .peer_certs()
                    .and_then(|certs| certs.first().cloned())
                    .and_then(|leaf| satl_ca::PeerIdentity::from_certificate(&leaf).ok())
            });
        let message = request.into_inner();
        let cluster = self.cluster()?;
        let cluster_id = cluster.id.to_string();
        let signer = Self::signer(&cluster)?;

        // Who is asking, and what does that grant them? A token selects the
        // role; an existing certificate renews the role the *store* records,
        // which is how promotion and demotion take effect (§12.3).
        let (node_id, role, availability) = if message.token.is_empty() {
            let peer = renewal_of.ok_or_else(|| {
                Status::unauthenticated(
                    "IssueNodeCertificate needs either a join token or a connection presenting \
                     a valid cluster certificate (renewal)",
                )
            })?;
            if peer.cluster_id != cluster_id {
                return Err(Status::permission_denied(format!(
                    "certificate for cluster {} presented to cluster {cluster_id}",
                    peer.cluster_id
                )));
            }
            let store = self.store.get()?;
            let node = store.view().node(&peer.node_id).map(|n| (*n).clone());
            let (role, availability) = node.map_or((peer.role, Availability::Active), |node| {
                (node.spec.role, node.spec.availability)
            });
            (peer.node_id, role, availability)
        } else {
            let token = JoinToken::parse(&message.token)
                .map_err(|err| Status::unauthenticated(err.to_string()))?;
            let role = role_for_token(&cluster, &token).ok_or_else(|| {
                Status::unauthenticated(
                    "the presented join token does not match this cluster's worker or manager \
                     token; it may have been rotated",
                )
            })?;
            let availability =
                availability_from_proto(message.availability).unwrap_or(Availability::Active);
            (Id::generate(), role, availability)
        };

        // The Node object first: a certificate whose node object does not
        // exist would let a node open a session the dispatcher must refuse.
        self.ensure_node(&node_id, role, availability, &signer.issuer_digest())
            .await?;

        let csr = csr_der(&message.csr).map_err(Status::invalid_argument)?;
        // The daemon-local testing knob wins over the cluster's expiry so a
        // renewal-test cluster issues short certificates to joiners too;
        // production leaves it unset and signs with the cluster's value.
        let validity = self
            .validity_override
            .unwrap_or(cluster.spec.ca.node_cert_expiry);
        let cert = signer
            .sign_node_csr(&csr, &node_id, role, &cluster_id, validity)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        self.issued.remember(&node_id, &cert);

        tracing::info!(
            node_id = %node_id,
            role = satl_ca::role_ou(role),
            cluster_id = %cluster_id,
            renewal = message.token.is_empty(),
            issuer = %signer.issuer_digest(),
            cross_signed = signer.intermediate.is_some(),
            "node certificate signed"
        );
        Ok(Response::new(v1::IssueNodeCertificateResponse {
            node_id: node_id.to_string(),
            role: proto_role(role) as i32,
        }))
    }

    async fn node_certificate_status(
        &self,
        request: Request<v1::NodeCertificateStatusRequest>,
    ) -> Result<Response<v1::NodeCertificateStatusResponse>, Status> {
        let node_id = request
            .into_inner()
            .node_id
            .parse::<Id>()
            .map_err(|err| Status::invalid_argument(format!("unusable node id: {err}")))?;
        if let Some(pem) = self.issued.recall(&node_id) {
            return Ok(Response::new(v1::NodeCertificateStatusResponse {
                status: v1::CertificateStatus::Issued as i32,
                certificate: pem.into_bytes(),
            }));
        }
        // Not this manager's signature. A node object without a cached
        // certificate means somebody else signed it (or this manager
        // restarted); `PENDING` tells the caller to keep polling, `UNKNOWN`
        // that the id means nothing here at all.
        let known = self.store.get()?.view().node(&node_id).is_some();
        Ok(Response::new(v1::NodeCertificateStatusResponse {
            status: if known {
                v1::CertificateStatus::Pending as i32
            } else {
                v1::CertificateStatus::Unknown as i32
            },
            certificate: Vec::new(),
        }))
    }
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

/// How often the renewal loops re-check their levels when nothing happens —
/// a backstop under the store/session watch, so a missed or lagged event can
/// delay a rotation step, never lose it.
const LEVEL_RECHECK: Duration = Duration::from_secs(30);

/// Re-issues this node's certificate (§12.3, SWK §16.4) — the manager side.
///
/// Level-triggered over three facts, re-read from the store on every wake
/// (a store event, [`LEVEL_RECHECK`], or the renewal timer):
///
/// 1. **Trust anchors follow the store's bundle.** When
///    `Cluster.root_ca_cert` stops matching the CA bundle this node holds —
///    a root rotation growing it to two roots, or shrinking it back to the
///    new one — the bundle is persisted to `<state_dir>/certs` and swapped
///    into `live`, so the next handshake verifies against it. The
///    certificate and key are untouched.
/// 2. **A `Rotate` mark on this node's object is a "renew now".** The
///    rotation reconciler sets it (architecture §12.3); the renewal
///    re-issues from the store's *signing* CA — the new root during a
///    rotation — and records the issuer digest back on the node object,
///    which is what the reconciler reads as convergence.
/// 3. **The periodic window.** A random point in the 50–80 % validity
///    window, drawn **once per certificate** (herd avoidance would be lost
///    if every wake redrew it).
///
/// Every renewal is written to `<state_dir>/certs` and then **swapped into
/// `live`**, the [`satl_ca::LiveIdentity`] every TLS surface of this daemon
/// resolves through: the internal gRPC listener, the `NodeCA` bootstrap
/// listener, the raft/forwarding channels and the agent's dispatcher
/// channels all present and verify with the new material on their next
/// handshake, with no restart. Established connections keep the identity
/// they were opened with until they reconnect — TLS authenticates at
/// handshake time, and severing healthy connections on a routine renewal
/// would be churn for nothing.
///
/// `validity` is the daemon's effective certificate validity
/// ([`crate::config::Config::effective_cert_validity`]).
// One loop on purpose: the three renewal triggers share state (schedule, mark
// guard) and splitting them would reintroduce the flap this shape prevents.
#[allow(clippy::too_many_lines)]
pub fn spawn_renewal(
    state_dir: PathBuf,
    store: ClusterStore,
    leader: LeaderClient,
    node_id: Id,
    live: Arc<satl_ca::LiveIdentity>,
    validity: Duration,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut events = store.watch();
        let mut attempt: u32 = 0;
        // The renewal point drawn for the certificate currently held, so a
        // wake that renews nothing does not redraw it (herd avoidance).
        let mut scheduled: Option<(String, SystemTime)> = None;
        // The digest of the root this loop last issued under: what keeps a
        // stale `Rotate` mark (the store write recording the renewal not yet
        // applied locally) from turning every event into another renewal.
        let mut last_issued: Option<String> = None;
        loop {
            // The levels, from the local applied store.
            let (bundle, marked, signer_digest) = {
                let view = store.view();
                let cluster = view.cluster();
                let bundle = cluster
                    .as_ref()
                    .and_then(|cluster| cluster.root_ca_cert.clone());
                let signer_digest = cluster
                    .as_ref()
                    .map(|cluster| match &cluster.root_rotation {
                        Some(rotation) => satl_ca::token::bundle_digest(&rotation.new_root_cert),
                        None => satl_ca::token::bundle_digest(
                            cluster.root_ca_cert.as_deref().unwrap_or_default(),
                        ),
                    });
                let marked = view
                    .node(&node_id)
                    .is_some_and(|node| node.certificate_status == CertificateStatus::Rotate);
                (bundle, marked, signer_digest)
            };

            // Level 1: trust anchors.
            if let Some(bundle) = &bundle {
                match sync_trust_bundle(&state_dir, &live, bundle) {
                    Ok(Some(len)) => tracing::info!(
                        node_id = %node_id,
                        bundle_len = len,
                        "cluster trust bundle changed; persisted and swapped live"
                    ),
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        node_id = %node_id,
                        %error,
                        "cannot apply the cluster's new trust bundle; keeping the previous anchors"
                    ),
                }
            }

            // Level 2: the reconciler's re-issue mark.
            let rotate_now = marked && signer_digest.is_some() && last_issued != signer_digest;
            if rotate_now {
                tracing::info!(
                    node_id = %node_id,
                    issuer = signer_digest.as_deref().unwrap_or("?"),
                    "certificate marked for re-issue (root CA rotation); renewing now"
                );
            }

            // Level 3: the periodic window (drawn once per certificate).
            let delay = if rotate_now {
                Duration::ZERO
            } else {
                let identity_now = live.identity();
                let target = match &scheduled {
                    Some((pem, at)) if *pem == identity_now.cert_pem => Some(*at),
                    _ => match renewal_target(&identity_now) {
                        Ok(at) => {
                            attempt = 0;
                            scheduled = Some((identity_now.cert_pem.clone(), at));
                            Some(at)
                        }
                        Err(error) => {
                            attempt = attempt.saturating_add(1);
                            let backoff = satl_ca::retry_backoff(attempt);
                            tracing::warn!(
                                %error,
                                attempt,
                                retry_in_secs = backoff.as_secs(),
                                "cannot schedule certificate renewal"
                            );
                            None
                        }
                    },
                };
                match target {
                    Some(at) => at
                        .duration_since(SystemTime::now())
                        .unwrap_or(Duration::ZERO),
                    None => satl_ca::retry_backoff(attempt),
                }
            };

            let renews_on_expiry = delay <= LEVEL_RECHECK;
            tokio::select! {
                // Biased: with a zero delay (a rotation mark) the sleep arm
                // must win over the store events the rotation itself emits,
                // or the loop spins re-announcing the mark until the random
                // pick lands on the sleep.
                biased;
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(delay.min(LEVEL_RECHECK)) => {
                    if !renews_on_expiry {
                        continue; // a level re-check, not the renewal point
                    }
                    match renew_once(&state_dir, &store, &node_id, validity) {
                        Ok((renewed, issuer)) => {
                            attempt = 0;
                            scheduled = None;
                            match live.swap(renewed) {
                                Ok(swap) => tracing::info!(
                                    node_id = %node_id,
                                    role = satl_ca::role_ou(swap.role),
                                    not_after = %swap.not_after_text,
                                    issuer = %issuer,
                                    server_config_swapped = true,
                                    client_config_swapped = true,
                                    "node certificate renewed and live TLS configuration swapped"
                                ),
                                // Unreachable in practice: the material was
                                // verified during issuance. If it happens
                                // anyway the old (still valid) identity keeps
                                // serving and the disk copy is already the
                                // new one, so the next daemon restart heals
                                // it; say exactly that.
                                Err(error) => tracing::error!(
                                    node_id = %node_id,
                                    %error,
                                    server_config_swapped = false,
                                    client_config_swapped = false,
                                    "node certificate renewed on disk but the live TLS swap failed; \
                                     the previous certificate keeps serving until it expires or the \
                                     daemon restarts"
                                ),
                            }
                            last_issued = Some(issuer.clone());
                            record_issuer(&store, &leader, &node_id, &issuer).await;
                        }
                        Err(error) => {
                            attempt = attempt.saturating_add(1);
                            tracing::warn!(
                                node_id = %node_id,
                                %error,
                                attempt,
                                "certificate renewal failed; will retry"
                            );
                            tokio::select! {
                                () = shutdown.cancelled() => return,
                                () = tokio::time::sleep(satl_ca::retry_backoff(attempt)) => {}
                            }
                        }
                    }
                }
                event = events.recv() => {
                    if event.is_err() {
                        // Lagged or closed: resubscribe. The levels are
                        // re-read from the store on every pass, so nothing
                        // is reconstructed from the missed events.
                        events = store.watch();
                    }
                }
            }
        }
    })
}

/// The worker-side renewal loop: like [`spawn_renewal`], but the re-issue
/// goes to a manager's `NodeCA` over mTLS ([`renew_remote`]) because this
/// node holds no store. Its levels come from the agent session instead:
/// the pushed root CA bundle (level 1), the `Rotate` mark on this node's
/// own object (level 2) and the certificate's renewal window (level 3).
// One loop on purpose: the three renewal triggers share state (schedule, mark
// guard) and splitting them would reintroduce the flap this shape prevents.
#[allow(clippy::too_many_lines)]
pub fn spawn_remote_renewal(
    state_dir: PathBuf,
    live: Arc<satl_ca::LiveIdentity>,
    state: tokio::sync::watch::Receiver<satl_dispatcher::AgentState>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state = state;
        let mut attempt: u32 = 0;
        let mut scheduled: Option<(String, SystemTime)> = None;
        // The bundle in force when this loop last renewed for a `Rotate`
        // mark. The mark clears in the store the moment the NodeCA signs
        // (the signer records `Issued`), but the session pushing that back
        // here lags — without this guard the stale mark would read as
        // "renew again" and flap.
        let mut renewed_for: Option<Vec<u8>> = None;
        loop {
            let (bundle, marked, managers, connected) = {
                let current = state.borrow_and_update();
                let managers: Vec<String> = current
                    .managers
                    .iter()
                    .map(|peer| peer.addr.clone())
                    .filter(|addr| !addr.is_empty())
                    .collect();
                let marked = current
                    .node
                    .as_ref()
                    .is_some_and(|node| node.certificate_status == CertificateStatus::Rotate);
                (
                    current.root_ca.clone(),
                    marked,
                    managers,
                    current.connected(),
                )
            };

            // Level 1: trust anchors follow the session's pushed bundle.
            if let Some(bundle) = &bundle {
                match sync_trust_bundle(&state_dir, &live, bundle) {
                    Ok(Some(len)) => tracing::info!(
                        bundle_len = len,
                        "cluster trust bundle changed; persisted and swapped live"
                    ),
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        %error,
                        "cannot apply the cluster's new trust bundle; keeping the previous anchors"
                    ),
                }
            }

            // Level 2: the reconciler's re-issue mark.
            if marked && bundle.is_some() && renewed_for != bundle {
                tracing::info!(
                    "certificate marked for re-issue (root CA rotation); renewing through a \
                     manager's NodeCA now"
                );
                match renew_remote(&state_dir, &live, &managers).await {
                    Ok(subject) => {
                        attempt = 0;
                        scheduled = None;
                        renewed_for.clone_from(&bundle);
                        tracing::info!(
                            node_id = %subject.node_id,
                            role = satl_ca::role_ou(subject.role),
                            "node certificate re-issued for the root rotation and swapped live"
                        );
                        // Wait for the session to catch up with the store's
                        // `Issued` before reading the mark again.
                        tokio::select! {
                            () = shutdown.cancelled() => return,
                            _ = state.changed() => {}
                        }
                    }
                    Err(error) => {
                        attempt = attempt.saturating_add(1);
                        renewal_failure_hint(&error, connected);
                        tracing::warn!(
                            %error,
                            attempt,
                            "rotation-triggered certificate renewal failed; will retry"
                        );
                        tokio::select! {
                            () = shutdown.cancelled() => return,
                            () = tokio::time::sleep(satl_ca::retry_backoff(attempt)) => {}
                        }
                    }
                }
                continue;
            }

            // Level 3: the periodic window (drawn once per certificate).
            let identity_now = live.identity();
            let target = match &scheduled {
                Some((pem, at)) if *pem == identity_now.cert_pem => Some(*at),
                _ => match renewal_target(&identity_now) {
                    Ok(at) => {
                        attempt = 0;
                        scheduled = Some((identity_now.cert_pem.clone(), at));
                        Some(at)
                    }
                    Err(error) => {
                        attempt = attempt.saturating_add(1);
                        let backoff = satl_ca::retry_backoff(attempt);
                        tracing::warn!(
                            %error,
                            attempt,
                            retry_in_secs = backoff.as_secs(),
                            "cannot schedule certificate renewal"
                        );
                        None
                    }
                },
            };
            let delay = match target {
                Some(at) => at
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO),
                None => satl_ca::retry_backoff(attempt),
            };

            let renews_on_expiry = delay <= LEVEL_RECHECK;
            tokio::select! {
                // Biased for the same reason as the manager loop: a due renewal
                // must win over a burst of session updates.
                biased;
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(delay.min(LEVEL_RECHECK)) => {
                    if !renews_on_expiry {
                        continue;
                    }
                    match renew_remote(&state_dir, &live, &managers).await {
                        Ok(subject) => {
                            attempt = 0;
                            scheduled = None;
                            tracing::info!(
                                node_id = %subject.node_id,
                                role = satl_ca::role_ou(subject.role),
                                "node certificate renewed and live TLS configuration swapped"
                            );
                        }
                        Err(error) => {
                            attempt = attempt.saturating_add(1);
                            renewal_failure_hint(&error, connected);
                            tracing::warn!(
                                %error,
                                attempt,
                                "certificate renewal failed; will retry"
                            );
                            tokio::select! {
                                () = shutdown.cancelled() => return,
                                () = tokio::time::sleep(satl_ca::retry_backoff(attempt)) => {}
                            }
                        }
                    }
                }
                changed = state.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    })
}

/// Installs a changed trust bundle, keeping this node's certificate and key:
/// the new anchors are persisted to `<state_dir>/certs` first, then swapped
/// into the live identity so the next handshake verifies against them.
/// Returns the bundle length when something changed, `None` when the bundle
/// already matched.
fn sync_trust_bundle(
    state_dir: &Path,
    live: &Arc<satl_ca::LiveIdentity>,
    bundle: &[u8],
) -> Result<Option<usize>, IdentityError> {
    let current = live.identity();
    let new_ca = String::from_utf8_lossy(bundle).into_owned();
    if current.ca_pem == new_ca {
        return Ok(None);
    }
    let identity = NodeIdentity::new(current.cert_pem.clone(), current.key_pem.clone(), new_ca);
    save(state_dir, &identity)?;
    live.swap(identity)?;
    Ok(Some(bundle.len()))
}

/// Records which root signed this node's current certificate on its own
/// `Node` object — the fact the rotation reconciler reads as convergence
/// (§12.3). Best-effort with a bounded read-modify-write retry: a record
/// that never lands only means the reconciler re-marks the node and the
/// next renewal writes it again (level-triggered, nothing is lost).
async fn record_issuer(store: &ClusterStore, leader: &LeaderClient, node_id: &Id, issuer: &str) {
    for _ in 0_u8..3 {
        let action = {
            let view = store.view();
            let Some(node) = view.node(node_id) else {
                tracing::warn!(
                    node_id = %node_id,
                    "no node object to record the certificate issuer on"
                );
                return;
            };
            if node.certificate_issuer.as_deref() == Some(issuer)
                && node.certificate_status == CertificateStatus::Issued
            {
                return;
            }
            let mut updated = (*node).clone();
            updated.certificate_status = CertificateStatus::Issued;
            updated.certificate_issuer = Some(issuer.to_owned());
            updated.meta.updated_at = SystemTime::now();
            StoreAction::Update(StoreObject::Node(updated))
        };
        match leader
            .propose(vec![action], satl_cluster::forward::local_identity())
            .await
        {
            Ok(_) => {
                tracing::debug!(node_id = %node_id, issuer, "certificate issuer recorded");
                return;
            }
            Err(satl_cluster::ForwardError::Rejected(rejection)) => {
                tracing::debug!(
                    node_id = %node_id,
                    %rejection,
                    "recording the certificate issuer raced another write; retrying"
                );
                // Give the local replica a beat to apply the winning write
                // before re-reading it.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => {
                tracing::warn!(
                    node_id = %node_id,
                    %error,
                    "cannot record the certificate issuer; the rotation reconciler will \
                     re-mark this node and the next renewal will retry"
                );
                return;
            }
        }
    }
    tracing::warn!(
        node_id = %node_id,
        "recording the certificate issuer kept racing other writes; the rotation \
         reconciler will re-mark this node"
    );
}

/// The operator-facing diagnosis of a renewal refused over TLS while the
/// dispatcher session is down: the one state a node cannot recover from on
/// its own is a certificate chaining to a rotated-out root (§12.3), and the
/// way back in is a rejoin, so say exactly that.
fn renewal_failure_hint(error: &IdentityError, connected: bool) {
    if connected {
        return;
    }
    let text = error.to_string();
    let cert_like = [
        "certificate",
        "Certificate",
        "handshake",
        "Handshake",
        "UnknownIssuer",
        "tls",
    ]
    .iter()
    .any(|needle| text.contains(needle));
    if cert_like {
        tracing::error!(
            "the cluster refuses this node's TLS certificate and its dispatcher session is \
             down. If the cluster's root CA was rotated while this node was offline, its \
             certificate chains to a root the cluster no longer trusts and cannot be renewed. \
             The way back in is a rejoin: run 'satl swarm leave --force' on this node, then \
             'satl swarm join' with a fresh token from 'satl swarm join-token worker' on a \
             manager (docs/operations.md, certificate operations)."
        );
    }
}

/// The instant `identity`'s certificate should renew: a random point in the
/// 50-80 % validity window, drawn once and remembered by the caller.
fn renewal_target(identity: &NodeIdentity) -> Result<SystemTime, IdentityError> {
    let (not_before, not_after) = satl_ca::certificate_validity(&identity.cert_pem)?;
    let mut rng = rand::rng();
    Ok(satl_ca::next_renewal(not_before, not_after, &mut rng))
}

/// One renewal: re-issue from the cluster's signing CA — the rotation's new
/// root while one is in flight (§12.3) — and persist. Returns the identity
/// and the issuer digest to record on the node object.
fn renew_once(
    state_dir: &Path,
    store: &ClusterStore,
    node_id: &Id,
    validity: Duration,
) -> Result<(NodeIdentity, String), IdentityError> {
    let (cluster, role) = {
        let view = store.view();
        let cluster = view
            .cluster()
            .map(|c| (*c).clone())
            .ok_or(IdentityError::NoClusterCa)?;
        let role = view
            .node(node_id)
            .map_or(NodeRole::Manager, |node| node.spec.role);
        (cluster, role)
    };
    let signer = signing_ca_of(&cluster).ok_or(IdentityError::NoClusterCa)??;
    let bundle = cluster
        .root_ca_cert
        .clone()
        .ok_or(IdentityError::NoClusterCa)?;
    let identity = self_issue(
        &signer,
        node_id,
        role,
        cluster.id.as_ref(),
        validity,
        &bundle,
    )?;
    save(state_dir, &identity)?;
    Ok((identity, signer.issuer_digest()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain (non-rotating) signer over `root`, trusting `root` alone.
    fn signer_of(root: &RootCa) -> ClusterSigner {
        ClusterSigner {
            root: root.clone(),
            intermediate: None,
        }
    }

    /// `self_issue` against a single root, as every pre-rotation call was.
    fn self_issue_plain(
        root: &RootCa,
        node_id: &Id,
        role: NodeRole,
        cluster_id: &str,
        validity: Duration,
    ) -> Result<NodeIdentity, IdentityError> {
        self_issue(
            &signer_of(root),
            node_id,
            role,
            cluster_id,
            validity,
            root.bundle(),
        )
    }

    fn cluster_with(root: Option<&RootCa>, tokens: Option<&JoinTokens>) -> Cluster {
        let mut cluster = Cluster {
            id: Id::generate(),
            meta: Meta::new(),
            spec: satl_core::ClusterSpec {
                annotations: satl_core::Annotations {
                    name: "default".to_owned(),
                    labels: BTreeMap::new(),
                },
                raft: satl_core::RaftConfig::default(),
                dispatcher: satl_core::DispatcherConfig::default(),
                ca: satl_core::CaConfig::default(),
                task_defaults: satl_core::TaskDefaults::default(),
                // A cluster with no pool would leave the allocator falling back to
                // its compiled-in default, so the operator could never see or
                // change what overlay networks are carved from. Seed the
                // documented defaults (architecture §15) explicitly.
                default_address_pool: vec![satl_core::defaults::DEFAULT_OVERLAY_POOL.to_owned()],
                subnet_size: satl_core::defaults::DEFAULT_SUBNET_SIZE,
                autolock: false,
                unlock_key: None,
            },
            join_tokens: satl_core::JoinTokens::default(),
            blacklisted_certs: BTreeMap::new(),
            root_ca_cert: None,
            encrypted_root_ca_key: None,
            root_rotation: None,
        };
        if let Some(root) = root {
            cluster.root_ca_cert = Some(root.cert_pem().as_bytes().to_vec());
            cluster.encrypted_root_ca_key = Some(root.key_pem().as_bytes().to_vec());
        }
        if let Some(tokens) = tokens {
            cluster.join_tokens = satl_core::JoinTokens::from(tokens);
        }
        cluster
    }

    #[test]
    fn a_cluster_without_ca_material_has_no_root() {
        let cluster = cluster_with(None, None);
        assert!(root_ca_of(&cluster).is_none());
    }

    #[test]
    fn the_root_ca_round_trips_through_the_cluster_object() {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let cluster = cluster_with(Some(&root), None);
        let reloaded = root_ca_of(&cluster).expect("present").expect("parses");
        assert_eq!(reloaded.cert_pem(), root.cert_pem());
        assert_eq!(reloaded.cluster_id(), Some(cluster_id.as_str()));
    }

    #[test]
    fn a_self_issued_certificate_carries_the_node_id_role_and_cluster() {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let node_id = Id::generate();
        let identity = self_issue_plain(
            &root,
            &node_id,
            NodeRole::Manager,
            &cluster_id,
            satl_ca::NODE_CERT_VALIDITY,
        )
        .expect("issued");
        let subject = subject(&identity).expect("subject");
        assert_eq!(subject.node_id, node_id);
        assert_eq!(subject.role, NodeRole::Manager);
        assert_eq!(subject.cluster_id, cluster_id);
        // And it is usable as both ends of an mTLS connection.
        satl_ca::server_config(&identity).expect("server config");
        satl_ca::client_config(&identity, satl_ca::SAN_MANAGER).expect("client config");
    }

    #[test]
    fn the_identity_survives_a_save_and_load_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let node_id = Id::generate();
        assert!(load(dir.path()).expect("load").is_none());

        let identity = self_issue_plain(
            &root,
            &node_id,
            NodeRole::Worker,
            &cluster_id,
            satl_ca::NODE_CERT_VALIDITY,
        )
        .expect("issued");
        save(dir.path(), &identity).expect("save");
        let reloaded = load(dir.path()).expect("load").expect("present");
        assert_eq!(reloaded, identity);
        // The CN is authoritative: reloading recovers the same node id.
        assert_eq!(subject(&reloaded).expect("subject").node_id, node_id);

        wipe(dir.path()).expect("wipe");
        assert!(load(dir.path()).expect("load").is_none());
        // Wiping twice is not an error.
        wipe(dir.path()).expect("second wipe");
    }

    #[test]
    fn the_token_that_matches_selects_the_role() {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let tokens = JoinTokens::generate(root.bundle());
        let cluster = cluster_with(Some(&root), Some(&tokens));

        let worker = JoinToken::parse(&tokens.worker.to_string()).expect("parses");
        let manager = JoinToken::parse(&tokens.manager.to_string()).expect("parses");
        assert_eq!(role_for_token(&cluster, &worker), Some(NodeRole::Worker));
        assert_eq!(role_for_token(&cluster, &manager), Some(NodeRole::Manager));

        // A token from a different cluster grants nothing.
        let other = JoinTokens::generate(b"a different bundle");
        let stranger = JoinToken::parse(&other.manager.to_string()).expect("parses");
        assert_eq!(role_for_token(&cluster, &stranger), None);

        // Neither does one on a cluster that has not minted tokens yet.
        let pristine = cluster_with(Some(&root), None);
        assert_eq!(role_for_token(&pristine, &manager), None);
    }

    #[test]
    fn a_bundle_that_does_not_match_the_token_digest_is_refused() {
        let root = RootCa::generate(Id::generate().as_ref()).expect("root");
        let tokens = JoinTokens::generate(root.bundle());
        // The real bundle passes...
        tokens
            .manager
            .verify_ca_bundle(root.bundle())
            .expect("the genuine bundle is pinned");
        // ...and a MITM's substituted root does not.
        let attacker = RootCa::generate(Id::generate().as_ref()).expect("root");
        assert!(tokens.manager.verify_ca_bundle(attacker.bundle()).is_err());
    }

    #[test]
    fn issued_certificates_are_remembered_then_forgotten() {
        let cache = IssuedCache::default();
        let node_id = Id::generate();
        assert!(cache.recall(&node_id).is_none());
        cache.remember(&node_id, "PEM");
        assert_eq!(cache.recall(&node_id).as_deref(), Some("PEM"));

        // An entry older than the TTL is swept by the next insertion.
        {
            let mut issued = cache.inner.lock().expect("lock");
            if let Some(entry) = issued.get_mut(&node_id) {
                entry.at = SystemTime::now() - ISSUED_CACHE_TTL - Duration::from_secs(1);
            }
        }
        cache.remember(&Id::generate(), "OTHER");
        assert!(cache.recall(&node_id).is_none());
    }

    #[test]
    fn a_csr_is_accepted_in_either_encoding() {
        // `proto/ca.proto` pins the field as PEM and `satl_ca`'s signer takes
        // DER, so the conversion is the thing under test: whatever comes out
        // must be signable. (Comparing bytes would not work — each call to
        // `csr_pem`/`csr_der` re-signs, and ECDSA signatures are randomized.)
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let key = NodeKeyPair::generate().expect("key");
        let node_id = Id::generate();

        for encoded in [
            key.csr_pem().expect("pem").into_bytes(),
            key.csr_der().expect("der"),
        ] {
            let der = csr_der(&encoded).expect("a usable csr");
            let cert = root
                .sign_node_csr(
                    &der,
                    &node_id,
                    NodeRole::Worker,
                    &cluster_id,
                    satl_ca::NODE_CERT_VALIDITY,
                )
                .expect("the converted csr is signable");
            certificate_matches_key(cert.as_str(), &key).expect("it certifies this node's key");
        }

        // PEM that holds something else entirely is refused, by name.
        let error = csr_der(b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
            .expect_err("not a csr");
        assert!(error.contains("CERTIFICATE REQUEST"), "{error}");
    }

    #[test]
    fn proto_role_and_availability_round_trip() {
        for role in [NodeRole::Worker, NodeRole::Manager] {
            assert_eq!(role_from_proto(proto_role(role) as i32), Some(role));
        }
        assert_eq!(role_from_proto(v1::NodeRole::Unspecified as i32), None);
        for availability in [
            Availability::Active,
            Availability::Pause,
            Availability::Drain,
        ] {
            assert_eq!(
                availability_from_proto(proto_availability(availability) as i32),
                Some(availability)
            );
        }
        assert_eq!(
            availability_from_proto(v1::Availability::Unspecified as i32),
            None
        );
    }

    #[test]
    fn renewal_is_scheduled_inside_the_certificates_own_window() {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let identity = self_issue_plain(
            &root,
            &Id::generate(),
            NodeRole::Manager,
            &cluster_id,
            satl_ca::NODE_CERT_VALIDITY,
        )
        .expect("issued");
        let target = renewal_target(&identity).expect("target");
        let delay = target
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        // 50-80% of a 90-day validity, minus the hour of backdating.
        assert!(delay > Duration::from_hours(40 * 24), "{delay:?}");
        assert!(delay < Duration::from_hours(75 * 24), "{delay:?}");
    }

    /// The testing knob end to end at the issuance layer: a five-minute
    /// validity yields a certificate whose renewal point is minutes away —
    /// in the future (no hot loop), before expiry (renewal happens while the
    /// certificate is still valid).
    #[test]
    fn a_short_validity_schedules_a_renewal_within_minutes() {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let validity = Duration::from_mins(5);
        let identity = self_issue_plain(
            &root,
            &Id::generate(),
            NodeRole::Manager,
            &cluster_id,
            validity,
        )
        .expect("issued");
        let target = renewal_target(&identity).expect("target");
        let delay = target
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        assert!(delay > Duration::ZERO, "{delay:?}: would hot-loop");
        assert!(delay < validity, "{delay:?}: would renew after expiry");
    }
}

// ---------------------------------------------------------------------------
// The join flow against a manager that is not the leader
// ---------------------------------------------------------------------------

/// `join_remote` against a real `NodeCA` server that is **not** the leader.
///
/// This is the regression guard for the defect `42cae3c` shipped: only the
/// leader signs, a follower answers with `satl-leader-addr`, and the join used
/// to give up there. Every documented recovery from a root CA rotation ends in
/// `satl swarm join`, and an operator pointing it at a manager cannot know
/// which one holds leadership — so a join that only works against the leader
/// makes the documented recovery a coin flip. Measured live on the three VMs
/// before the fix: same token, same second, refused by a follower and accepted
/// by the leader.
///
/// The servers here are the real `proto/ca.proto` service over the real
/// bootstrap TLS (`live_anonymous_server_config`, no client certificate), so
/// what is exercised is the whole client path — channel, pinning, redirect,
/// and the poll that has to follow the redirect too because the issued-cache
/// is local to the signer.
///
/// The `2377 -> 2378` mapping is exercised on purpose rather than sidestepped:
/// the redirect metadata carries the leader's **raft** address and the
/// bootstrap listener is one port above it, so the follower advertises
/// `port - 1` and the test only passes if the client applies the mapping.
#[cfg(test)]
mod join_redirect_tests {
    use std::sync::Arc;

    use satl_ca::{JoinTokens, RootCa};
    use satl_core::{Availability, Id, NodeRole};
    use satl_proto::v1;
    use tokio_util::sync::CancellationToken;
    use tonic::{Request, Response, Status};

    use super::*;

    /// What a fake manager does with an `IssueNodeCertificate` call.
    #[derive(Clone)]
    enum Behaviour {
        /// Sign it, and remember the certificate for the status poll.
        Leader,
        /// Refuse with the redirect a follower sends: the leader's *raft*
        /// address in `satl-leader-addr` metadata.
        RedirectTo(String),
    }

    /// A `NodeCA` server standing in for one manager.
    #[derive(Clone)]
    struct FakeCa {
        root: RootCa,
        cluster_id: String,
        tokens: JoinTokens,
        behaviour: Behaviour,
        /// Certificates this manager signed, by node id, as the real
        /// `IssuedCache` holds them.
        issued: Arc<Mutex<BTreeMap<String, String>>>,
        /// How many `IssueNodeCertificate` calls landed here.
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[tonic::async_trait]
    impl v1::node_ca_server::NodeCa for FakeCa {
        async fn get_root_ca_certificate(
            &self,
            _request: Request<v1::GetRootCaCertificateRequest>,
        ) -> Result<Response<v1::GetRootCaCertificateResponse>, Status> {
            Ok(Response::new(v1::GetRootCaCertificateResponse {
                root_ca_bundle: self.root.bundle().to_vec(),
            }))
        }

        async fn issue_node_certificate(
            &self,
            request: Request<v1::IssueNodeCertificateRequest>,
        ) -> Result<Response<v1::IssueNodeCertificateResponse>, Status> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Behaviour::RedirectTo(leader) = &self.behaviour {
                return Err(satl_cluster::forward::leader_redirect_status(
                    Some(leader.as_str()),
                    "this manager is not the raft leader; certificates are signed by the leader",
                ));
            }
            let message = request.into_inner();
            let token = JoinToken::parse(&message.token)
                .map_err(|err| Status::unauthenticated(err.to_string()))?;
            let role = self
                .tokens
                .role_for_token(&token)
                .ok_or_else(|| Status::unauthenticated("token does not match"))?;
            let node_id = Id::generate();
            let der = csr_der(&message.csr).map_err(Status::invalid_argument)?;
            let cert = signer_of_root(&self.root)
                .sign_node_csr(
                    &der,
                    &node_id,
                    role,
                    &self.cluster_id,
                    satl_ca::NODE_CERT_VALIDITY,
                )
                .map_err(|err| Status::internal(err.to_string()))?;
            self.issued
                .lock()
                .expect("issued cache")
                .insert(node_id.to_string(), cert.as_str().to_owned());
            Ok(Response::new(v1::IssueNodeCertificateResponse {
                node_id: node_id.to_string(),
                role: proto_role(role) as i32,
            }))
        }

        async fn node_certificate_status(
            &self,
            request: Request<v1::NodeCertificateStatusRequest>,
        ) -> Result<Response<v1::NodeCertificateStatusResponse>, Status> {
            let id = request.into_inner().node_id;
            let cached = self.issued.lock().expect("issued cache").get(&id).cloned();
            Ok(Response::new(match cached {
                Some(pem) => v1::NodeCertificateStatusResponse {
                    status: v1::CertificateStatus::Issued as i32,
                    certificate: pem.into_bytes(),
                },
                None => v1::NodeCertificateStatusResponse {
                    status: v1::CertificateStatus::Unknown as i32,
                    certificate: Vec::new(),
                },
            }))
        }
    }

    fn signer_of_root(root: &RootCa) -> ClusterSigner {
        ClusterSigner {
            root: root.clone(),
            intermediate: None,
        }
    }

    /// Serves `FakeCa` on `port` (0 for an ephemeral one) exactly as
    /// `cluster::bootstrap_ca` does, and returns the address it bound.
    async fn serve(ca: FakeCa, port: u16, cancel: CancellationToken) -> String {
        let identity = self_issue(
            &signer_of_root(&ca.root),
            &Id::generate(),
            NodeRole::Manager,
            &ca.cluster_id,
            satl_ca::NODE_CERT_VALIDITY,
            ca.root.bundle(),
        )
        .expect("manager identity");
        let live = satl_ca::LiveIdentity::new(identity).expect("live identity");
        let tls = satl_ca::live_anonymous_server_config(&live).expect("anonymous tls");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr").to_string();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let service = v1::node_ca_server::NodeCaServer::new(ca);
        tokio::spawn(async move {
            let incoming = accept_tls(listener, acceptor, cancel.clone());
            let _ = tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async move { cancel.cancelled().await })
                .await;
        });
        addr
    }

    /// The accept loop of `cluster::async_stream`, duplicated here rather than
    /// made public for a test.
    fn accept_tls(
        listener: tokio::net::TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
        shutdown: CancellationToken,
    ) -> tokio_stream::wrappers::ReceiverStream<
        Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>, std::io::Error>,
    > {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = shutdown.cancelled() => return,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else { return };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let _ = tx.send(Ok(tls)).await;
                    }
                });
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    /// A cluster's CA material, its tokens, and a fake manager builder.
    fn fixture() -> (RootCa, String, JoinTokens) {
        let cluster_id = Id::generate().to_string();
        let root = RootCa::generate(&cluster_id).expect("root");
        let tokens = JoinTokens::generate(root.bundle());
        (root, cluster_id, tokens)
    }

    fn fake(
        root: &RootCa,
        cluster_id: &str,
        tokens: &JoinTokens,
        behaviour: Behaviour,
    ) -> (FakeCa, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            FakeCa {
                root: root.clone(),
                cluster_id: cluster_id.to_owned(),
                tokens: tokens.clone(),
                behaviour,
                issued: Arc::new(Mutex::new(BTreeMap::new())),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    #[tokio::test]
    async fn a_join_pointed_at_a_follower_is_signed_by_the_leader() {
        let (root, cluster_id, tokens) = fixture();
        let cancel = CancellationToken::new();

        // The leader first, so its address is known when the follower is
        // built. Its bootstrap port is ephemeral; what the follower puts in
        // the redirect metadata is one *below* it, because the metadata
        // carries a raft address and `ca_endpoint_of` adds one.
        let (leader, leader_calls) = fake(&root, &cluster_id, &tokens, Behaviour::Leader);
        let leader_addr = serve(leader, 0, cancel.clone()).await;
        let leader_port: u16 = leader_addr
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .expect("leader port");
        let advertised_raft_addr = format!("127.0.0.1:{}", leader_port - 1);

        let (follower, follower_calls) = fake(
            &root,
            &cluster_id,
            &tokens,
            Behaviour::RedirectTo(advertised_raft_addr.clone()),
        );
        let follower_addr = serve(follower, 0, cancel.clone()).await;

        let joined = join_remote(
            &follower_addr,
            &tokens.worker.to_string(),
            Availability::Active,
        )
        .await
        .expect("the join follows the follower's redirect to the leader");

        assert_eq!(joined.role, NodeRole::Worker, "the worker token's role");
        assert_eq!(
            follower_calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the follower was asked exactly once before the redirect was followed"
        );
        assert_eq!(
            leader_calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the leader is who signed"
        );
        // The certificate verified against the pinned bundle inside
        // `join_remote`; here, that the identity is coherent end to end.
        let subject = subject(&joined.identity).expect("subject");
        assert_eq!(subject.node_id, joined.node_id);
        assert_eq!(subject.cluster_id, cluster_id);
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_manager_that_redirects_to_itself_fails_with_the_election_hint() {
        let (root, cluster_id, tokens) = fixture();
        let cancel = CancellationToken::new();

        // Bind a fixed port so the address the fake advertises can be its own
        // (minus one, which `ca_endpoint_of` adds back).
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("probe");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let (fake_ca, calls) = fake(
            &root,
            &cluster_id,
            &tokens,
            Behaviour::RedirectTo(format!("127.0.0.1:{}", port - 1)),
        );
        let addr = serve(fake_ca, port, cancel.clone()).await;

        let error = join_remote(&addr, &tokens.worker.to_string(), Availability::Active)
            .await
            .expect_err("a self-redirect cannot be followed");
        assert!(
            matches!(error, IdentityError::JoinRedirectLoop { .. }),
            "{error}"
        );
        let text = error.to_string();
        assert!(text.contains("no manager in this cluster"), "{text}");
        assert!(text.contains("satl swarm join"), "{text}");
        // One call, then the loop is cut: a joiner must not hammer a manager
        // that keeps pointing at itself.
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        cancel.cancel();
    }
}
