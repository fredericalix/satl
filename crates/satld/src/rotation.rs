// SPDX-License-Identifier: BSD-2-Clause
//! Root CA rotation: starting one, and the leader-only reconciler that
//! drives it to completion (architecture §12.3, SWK §16.5).
//!
//! The whole rotation is **state in the store, level-triggered, resumable**:
//!
//! ```text
//!   start (any manager, forwarded to the leader):
//!       Cluster.root_rotation = { new root, its key, cross-signed cert }
//!       Cluster.root_ca_cert  = old + new       (the transitional bundle)
//!       Cluster.join_tokens   = regenerated     (digest pins the bundle)
//!
//!   reconciler (leader only, every tick):
//!       nodes whose certificate_issuer != digest(new root)
//!           not yet marked → CertificateStatus::Rotate, in batches
//!       every node converged →
//!           Cluster.root_ca_cert = new root alone
//!           Cluster.encrypted_root_ca_key = new key
//!           Cluster.join_tokens = regenerated again
//!           Cluster.root_rotation = None
//! ```
//!
//! Nothing here talks to a node. The marks travel through the store and the
//! dispatcher session, the renewals come back through `NodeCA` (workers) or
//! the manager renewal loop, and each renewal records its issuer digest on
//! the node object — which is the only fact this reconciler reads. A
//! leadership change mid-rotation costs nothing: the next leader's
//! reconciler reads the same `Cluster.root_rotation` and continues.
//!
//! Every log line here names digests, never keys and never token secrets.

use std::time::{Duration, SystemTime};

use satl_ca::{JoinTokens, RootCa};
use satl_cluster::{ClusterStore, ProposeError};
use satl_core::{CertificateStatus, Cluster, RootRotation, StoreAction, StoreObject};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

/// How often the reconciler re-reads the store (SWK §16.5: 3 s tick).
const TICK: Duration = Duration::from_secs(3);

/// How many nodes are marked `Rotate` per pass (SWK §16.5: batches of 30) —
/// what keeps a large cluster's re-issue sweep from stampeding the signer.
const MARK_BATCH: usize = 30;

/// Errors preparing a rotation. The daemon surfaces these through the REST
/// backend; the messages are operator-facing.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// A rotation is already running.
    #[error(
        "a root CA rotation is already in progress (started {started_at:?}, new root digest \
         {new_digest}). It completes when every node holds a certificate from the new root; \
         'satl node ls' shows which nodes are still converging, and a node that will never \
         come back must be removed ('satl node rm --force <node>') for the rotation to finish"
    )]
    InProgress {
        /// When the running rotation started.
        started_at: SystemTime,
        /// Digest of the rotation's new root.
        new_digest: String,
    },

    /// The cluster has no CA to rotate away from.
    #[error("this cluster has no root CA on its Cluster object; nothing to rotate")]
    NoCurrentRoot,

    /// Minting or cross-signing the new root failed.
    #[error("cannot mint the new root CA: {0}")]
    Mint(#[from] satl_ca::RootCaError),

    /// The stored CA material is unreadable.
    #[error("cannot load the current root CA: {0}")]
    Identity(#[from] crate::identity::IdentityError),
}

/// The `Cluster` update that **starts** a rotation, built from `cluster` as
/// currently read (optimistic concurrency rejects it if the object moved).
///
/// Pure store-object construction: generates the new root, cross-signs it
/// with the old one, installs the transitional two-root bundle and
/// regenerates both join tokens over it — the token digest pins the whole
/// bundle (§12.2), so the old tokens die the moment the bundle grows.
/// `force_rotate` is the counter value the caller is applying (Docker's
/// `CAConfig.ForceRotate` semantics).
pub fn start_rotation(cluster: &Cluster, force_rotate: u64) -> Result<Cluster, RotationError> {
    if let Some(rotation) = &cluster.root_rotation {
        return Err(RotationError::InProgress {
            started_at: rotation.started_at,
            new_digest: satl_ca::token::bundle_digest(&rotation.new_root_cert),
        });
    }
    let old_root = crate::identity::root_ca_of(cluster).ok_or(RotationError::NoCurrentRoot)??;

    let cluster_id = cluster.id.to_string();
    let new_root = RootCa::generate(&cluster_id)?;
    let cross_signed = old_root.cross_sign(&new_root)?;

    let mut bundle = old_root.cert_pem().as_bytes().to_vec();
    bundle.extend_from_slice(new_root.cert_pem().as_bytes());
    let tokens = JoinTokens::generate(&bundle);

    let mut updated = cluster.clone();
    updated.root_rotation = Some(RootRotation {
        new_root_cert: new_root.cert_pem().as_bytes().to_vec(),
        encrypted_new_root_key: new_root.key_pem().as_bytes().to_vec(),
        cross_signed_cert: cross_signed.as_str().as_bytes().to_vec(),
        started_at: SystemTime::now(),
    });
    updated.root_ca_cert = Some(bundle);
    updated.join_tokens = satl_core::JoinTokens::from(&tokens);
    updated.spec.ca.force_rotate = force_rotate;
    updated.meta.updated_at = SystemTime::now();

    tracing::info!(
        old_digest = %old_root.cert_digest(),
        new_digest = %new_root.cert_digest(),
        force_rotate,
        "root CA rotation prepared: transitional trust bundle (old + new roots), \
         cross-signed intermediate, join tokens regenerated"
    );
    Ok(updated)
}

/// Spawns the leader-only rotation reconciler.
///
/// Runs while this node leads (the leadership supervisor cancels it on
/// loss); every [`TICK`] it re-reads the store and takes the one step the
/// current state calls for — marking a batch, finishing, or nothing. A
/// `SequenceConflict` from racing another writer is not handled specially:
/// the next tick re-reads and re-decides.
pub fn spawn_reconciler(store: ClusterStore, cancel: CancellationToken) -> JoinHandle<()> {
    let span = tracing::info_span!("ca_rotation");
    tokio::spawn(
        async move {
            // What the last pass reported it was waiting on, so an unchanged
            // situation is announced once rather than every three seconds.
            // Reset by a leadership change, which is correct: the new leader's
            // operator has not seen the old leader's line.
            let mut announced: Option<String> = None;
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(TICK) => {}
                }
                if let Err(error) = reconcile_once(&store, &mut announced).await {
                    // Losing leadership mid-propose lands here; the
                    // supervisor cancels this task moments later.
                    tracing::debug!(%error, "rotation reconcile pass did not commit");
                }
            }
        }
        .instrument(span),
    )
}

/// One reconcile pass. Reads the store, proposes at most one transaction.
///
/// `announced` carries the last "waiting on" summary this reconciler printed,
/// so a rotation held open by an unreachable node says so **once** instead of
/// every [`TICK`] — and says it again the moment the set of blockers changes.
/// A rotation that cannot finish is the situation an operator has to be told
/// about: before this, the only trace of it was a `DEBUG` line, so a cluster
/// could sit mid-rotation indefinitely with nothing in `/var/log/messages`
/// naming the node to remove or revive.
async fn reconcile_once(
    store: &ClusterStore,
    announced: &mut Option<String>,
) -> Result<(), ProposeError> {
    // Snapshot what the decision needs, then drop the view before awaiting.
    let (cluster, nodes) = {
        let view = store.view();
        let Some(cluster) = view.cluster() else {
            return Ok(());
        };
        if cluster.root_rotation.is_none() {
            return Ok(());
        }
        (
            (*cluster).clone(),
            view.nodes()
                .into_iter()
                .map(|node| (*node).clone())
                .collect::<Vec<_>>(),
        )
    };
    let Some(rotation) = cluster.root_rotation.clone() else {
        return Ok(());
    };
    let target = satl_ca::token::bundle_digest(&rotation.new_root_cert);

    let unconverged: Vec<&satl_core::Node> = nodes
        .iter()
        .filter(|node| node.certificate_issuer.as_deref() != Some(target.as_str()))
        .collect();

    if unconverged.is_empty() {
        *announced = None;
        return finish_rotation(store, &cluster, &rotation, &target).await;
    }

    let to_mark: Vec<StoreAction> = unconverged
        .iter()
        .filter(|node| node.certificate_status != CertificateStatus::Rotate)
        .take(MARK_BATCH)
        .map(|node| {
            let mut updated = (*node).clone();
            updated.certificate_status = CertificateStatus::Rotate;
            updated.meta.updated_at = SystemTime::now();
            StoreAction::Update(StoreObject::Node(updated))
        })
        .collect();

    if to_mark.is_empty() {
        // Every unconverged node already carries its mark; their renewals are
        // in flight. Nothing to write — but say where the rotation stands, and
        // separate the two cases, because they need different actions: a node
        // that is merely renewing needs patience, one the cluster reports
        // `Down` needs an operator (revive it, or `satl node rm --force` it so
        // the rotation can finish).
        let summary = waiting_summary(&unconverged);
        if announced.as_deref() == Some(summary.as_str()) {
            tracing::debug!(
                new_digest = %target,
                waiting_on = unconverged.len(),
                total = nodes.len(),
                "root CA rotation waiting for marked nodes to re-issue"
            );
        } else {
            *announced = Some(summary.clone());
            tracing::info!(
                new_digest = %target,
                waiting_on = unconverged.len(),
                total = nodes.len(),
                nodes = %summary,
                "root CA rotation is waiting; it cannot drop the old root until every node \
                 holds a certificate from the new one. A node listed 'down' here will never \
                 re-issue on its own: bring it back, or remove it with 'satl node rm --force \
                 <node>' and the next pass finishes the rotation"
            );
        }
        return Ok(());
    }

    let marked = to_mark.len();
    store.propose(to_mark).await?;
    tracing::info!(
        new_digest = %target,
        marked,
        converged = nodes.len() - unconverged.len(),
        total = nodes.len(),
        "root CA rotation: marked nodes for certificate re-issue"
    );
    Ok(())
}

/// `<node id>=<state>` for every node still holding the rotation open, sorted
/// so an unchanged situation produces an identical string.
///
/// Node ids rather than hostnames on purpose: `Node::description` is optional
/// (a node that never opened a session has none), and `satl node ls` shows the
/// id, so this is the field an operator can join the two on.
fn waiting_summary(unconverged: &[&satl_core::Node]) -> String {
    let mut parts: Vec<String> = unconverged
        .iter()
        .map(|node| {
            let state = match node.status.state {
                satl_core::NodeState::Down => "down",
                satl_core::NodeState::Ready => "ready",
                satl_core::NodeState::Disconnected => "disconnected",
                satl_core::NodeState::Unknown => "unknown",
            };
            format!("{}={state}", node.id)
        })
        .collect();
    parts.sort();
    parts.join(",")
}

/// The final step: every node is issued under the new root, so install it
/// alone — trust bundle, signing key, fresh join tokens — and clear the
/// rotation state. One atomic proposal.
async fn finish_rotation(
    store: &ClusterStore,
    cluster: &Cluster,
    rotation: &RootRotation,
    target: &str,
) -> Result<(), ProposeError> {
    let old_digest = cluster
        .root_ca_cert
        .as_deref()
        .map(satl_ca::token::bundle_digest)
        .unwrap_or_default();

    let tokens = JoinTokens::generate(&rotation.new_root_cert);
    let mut updated = cluster.clone();
    updated.root_ca_cert = Some(rotation.new_root_cert.clone());
    updated.encrypted_root_ca_key = Some(rotation.encrypted_new_root_key.clone());
    updated.join_tokens = satl_core::JoinTokens::from(&tokens);
    updated.root_rotation = None;
    updated.meta.updated_at = SystemTime::now();

    store
        .propose(vec![StoreAction::Update(StoreObject::Cluster(updated))])
        .await?;
    tracing::info!(
        new_digest = %target,
        transitional_digest = %old_digest,
        "root CA rotation completed: old root dropped, new root is the sole trust \
         anchor, join tokens regenerated"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use satl_core::{Id, Meta};

    use super::*;

    fn cluster_with_ca() -> (Cluster, RootCa) {
        let id = Id::generate();
        let root = RootCa::generate(id.as_ref()).expect("root");
        let tokens = JoinTokens::generate(root.bundle());
        let cluster = Cluster {
            id,
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
                default_address_pool: vec![satl_core::defaults::DEFAULT_OVERLAY_POOL.to_owned()],
                subnet_size: satl_core::defaults::DEFAULT_SUBNET_SIZE,
                autolock: false,
                unlock_key: None,
            },
            join_tokens: satl_core::JoinTokens::from(&tokens),
            blacklisted_certs: BTreeMap::new(),
            root_ca_cert: Some(root.cert_pem().as_bytes().to_vec()),
            encrypted_root_ca_key: Some(root.key_pem().as_bytes().to_vec()),
            root_rotation: None,
        };
        (cluster, root)
    }

    #[test]
    fn starting_a_rotation_builds_the_transitional_state() {
        let (cluster, old_root) = cluster_with_ca();
        let old_tokens = cluster.join_tokens.clone();

        let updated = start_rotation(&cluster, 1).expect("rotation starts");
        let rotation = updated.root_rotation.as_ref().expect("rotation state");

        // The transitional bundle is exactly old + new, in that order.
        let bundle = updated.root_ca_cert.as_ref().expect("bundle");
        let bundle_text = String::from_utf8_lossy(bundle);
        assert!(bundle_text.starts_with(old_root.cert_pem()));
        let new_text = String::from_utf8_lossy(&rotation.new_root_cert);
        assert!(bundle_text.ends_with(new_text.as_ref()));
        assert_eq!(
            bundle_text.matches("BEGIN CERTIFICATE").count(),
            2,
            "the transitional bundle carries two roots"
        );

        // The old signing key is untouched until completion; the new key is
        // in the rotation state.
        assert_eq!(updated.encrypted_root_ca_key, cluster.encrypted_root_ca_key);
        let new_root = RootCa::from_pem(
            &String::from_utf8_lossy(&rotation.new_root_cert),
            &String::from_utf8_lossy(&rotation.encrypted_new_root_key),
        )
        .expect("new root parses and matches its key");

        // The cross-signed certificate bridges new subject to old issuer:
        // a leaf under the new root + the intermediate verifies against the
        // old root alone (proven in satl-ca's own tests; here we check the
        // stored bytes are that certificate).
        let cross = String::from_utf8_lossy(&rotation.cross_signed_cert);
        assert!(cross.contains("BEGIN CERTIFICATE"));
        assert_ne!(cross.as_ref(), new_root.cert_pem());

        // Tokens were regenerated over the transitional bundle: both changed,
        // and both pin the new bundle's digest.
        assert_ne!(updated.join_tokens.worker, old_tokens.worker);
        assert_ne!(updated.join_tokens.manager, old_tokens.manager);
        let worker = satl_ca::JoinToken::parse(&updated.join_tokens.worker).expect("parses");
        worker
            .verify_ca_bundle(bundle)
            .expect("the new worker token pins the transitional bundle");
        assert_eq!(updated.spec.ca.force_rotate, 1);
    }

    #[test]
    fn a_second_rotation_is_refused_while_one_runs() {
        let (cluster, _) = cluster_with_ca();
        let updated = start_rotation(&cluster, 1).expect("first rotation");
        let error = start_rotation(&updated, 2).expect_err("second refused");
        assert!(matches!(error, RotationError::InProgress { .. }), "{error}");
        let text = error.to_string();
        assert!(text.contains("already in progress"), "{text}");
        assert!(text.contains("satl node rm"), "{text}");
        // The refusal names the digest, never key material or token secrets.
        assert!(!text.contains("PRIVATE KEY"), "{text}");
    }

    #[test]
    fn the_waiting_summary_is_stable_and_names_the_node_needing_an_operator() {
        let node = |state: satl_core::NodeState| satl_core::Node {
            id: Id::generate(),
            meta: Meta::new(),
            spec: satl_core::NodeSpec {
                name: None,
                labels: BTreeMap::new(),
                role: satl_core::NodeRole::Manager,
                availability: satl_core::Availability::Active,
            },
            description: None,
            status: satl_core::NodeStatus {
                state,
                message: String::new(),
                addr: String::new(),
            },
            manager_status: None,
            certificate_status: CertificateStatus::Rotate,
            certificate_issuer: None,
        };
        let down = node(satl_core::NodeState::Down);
        let ready = node(satl_core::NodeState::Ready);

        // Same set, either order, one string: the announce-once check in
        // `reconcile_once` compares strings, so an unstable order would print
        // the paragraph on every tick.
        let one = waiting_summary(&[&down, &ready]);
        let other = waiting_summary(&[&ready, &down]);
        assert_eq!(one, other, "the summary must not depend on iteration order");

        // The state is what tells an operator which node to act on, and the
        // log line's advice ("a node listed 'down' ...") depends on this exact
        // spelling.
        assert!(one.contains(&format!("{}=down", down.id)), "{one}");
        assert!(one.contains(&format!("{}=ready", ready.id)), "{one}");

        // A different set is a different string, or the change would go
        // unannounced.
        assert_ne!(one, waiting_summary(&[&down]));
    }

    #[test]
    fn a_cluster_without_a_ca_cannot_rotate() {
        let (mut cluster, _) = cluster_with_ca();
        cluster.root_ca_cert = None;
        cluster.encrypted_root_ca_key = None;
        let error = start_rotation(&cluster, 1).expect_err("no CA to rotate");
        assert!(matches!(error, RotationError::NoCurrentRoot), "{error}");
    }
}
