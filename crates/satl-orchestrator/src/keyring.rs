// SPDX-License-Identifier: BSD-2-Clause
//! The encrypted-overlay keyring loop: key generation and the 12h rotation
//! of `Network.keys` for networks whose spec asks for data-plane encryption
//! (`--opt encrypted`).
//!
//! # Why three phases
//!
//! The measured FreeBSD behavior (hack/experiments/esp/README.md, Q6): the
//! kernel keeps the **first-added** outbound SA, so on the wire "promote" is
//! really "delete the old outbound SA" — there is no other way to select
//! among equal SAs. The node reconciler derives all of that from the ring's
//! contents; this loop's whole job is to move the ring through the states,
//! in order, with settling time between them so every node has picked the
//! ring up before it moves on:
//!
//! ```text
//!   (empty)  --generate-->  [K1p]
//!   [K1p]    --append--->   [K1p, K2]        (K2 accepted on reception)
//!   [K1p,K2] --promote-->   [K1, K2p]        (nodes switch emission to K2
//!   [K1,K2p] --prune---->   [K1, K2p]         by deleting K1's outbound SA)
//!                            ^ ring keeps at most 2 keys: primary + previous
//! ```
//!
//! (append to a steady 2-key ring gives 3 keys mid-rotation; prune brings it
//! back to primary + immediately-previous, libnetwork's ring shape.)
//!
//! # Store-driven, never timer-driven
//!
//! Every phase decision derives from the ring's shape and
//! `Network.keys_updated_at`, re-read from the store on every pass — the
//! loop holds no timers beyond its tick, so a leadership change mid-rotation
//! resumes from store state alone (SWK §7.9) and a restore from a snapshot
//! converges the same way. Distribution to nodes is the dispatcher's
//! business (task 3); programming the SAD/SPD is the node's (task 4).
//!
//! # Ingress stays unencrypted
//!
//! The dispatcher's one broadcast exception is the ingress network (SWK §9.1:
//! every node holds its assignment, task or not), so a keyring on it would
//! reach every node in the cluster, participant or not. Nothing in
//! `plan_ring` would prevent that — it keys off `spec.encrypted` alone — so
//! the rule is upheld at construction: `Network::default_ingress` never sets
//! the flag, the API rejects a second ingress network, and no network-update
//! path exists that could flip an existing network's flag.

use std::time::{Duration, SystemTime};

use satl_cluster::{ClusterStore, StoreView};
use satl_core::{Id, Network, NetworkKey, ObjectKind, StoreAction, StoreEvent, StoreObject};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::propose::propose_with_retry;

/// Rotation cadence per encrypted network: Docker's 12h, which also bounds
/// ESP sequence-number exhaustion (moby/moby#52005).
pub const ROTATE_AFTER: Duration = Duration::from_hours(12);

/// Settling time between rotation phases (60 s, on the order of the overlay
/// resync interval): every node must have picked the ring up before it moves
/// on.
pub const PHASE_SETTLE: Duration = Duration::from_mins(1);

/// Ring size in the steady state: the primary plus the immediately-previous
/// key, which stays accepted on reception for stragglers (libnetwork's
/// shape). Mid-rotation the ring holds one more.
const STEADY_KEYS: usize = 2;

/// The keyring's timing knobs.
///
/// The defaults are the production values, [`ROTATE_AFTER`] and
/// [`PHASE_SETTLE`]; satld's `keyring_rotate_after_secs` /
/// `keyring_phase_settle_secs` config keys override them so a cluster test
/// can watch a whole rotation in minutes instead of half a day. Every phase
/// decision derives from the ring and `now`, so a cadence changes *when* the
/// ring moves, never *how*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// How old the ring may get before a fresh key is appended.
    pub rotate_after: Duration,
    /// Settling time between rotation phases: every node must have picked
    /// the ring up before it moves on.
    pub phase_settle: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            rotate_after: ROTATE_AFTER,
            phase_settle: PHASE_SETTLE,
        }
    }
}

/// One step of the keyring's lifecycle, planned from store state alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RingChange {
    /// The network is encrypted and its ring is empty: create the first key.
    Generate,
    /// The ring is due for rotation: add a fresh key, non-primary.
    Append,
    /// The appended key has settled: make it the (only) primary.
    Promote,
    /// The promoted ring has settled: drop every key but the primary and
    /// the immediately-previous one.
    Prune,
}

impl RingChange {
    /// The phase name, for tracing fields.
    fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Append => "append",
            Self::Promote => "promote",
            Self::Prune => "prune",
        }
    }
}

/// Decides the keyring's next step for one network, from its stored state
/// alone. Pure and idempotent: applying the returned change and planning
/// again at the same `now` yields `None`.
fn plan_ring(now: SystemTime, network: &Network, cadence: &Cadence) -> Option<RingChange> {
    if !network.spec.encrypted {
        // Never touched — even a stale ring is left alone: the node side
        // keys off `spec.encrypted` too.
        return None;
    }
    if network.keys.is_empty() {
        // New network, or a store restored from before this feature.
        return Some(RingChange::Generate);
    }
    let age = ring_age(now, network);
    if !network.keys.last().is_some_and(|key| key.primary) {
        // Appended state: the new key is accepted on reception everywhere;
        // once it has settled it becomes the emission key.
        return (age >= cadence.phase_settle).then_some(RingChange::Promote);
    }
    if network.keys.len() > STEADY_KEYS {
        // Promoted state: the keys older than the previous one are dead
        // weight once the new primary has settled.
        return (age >= cadence.phase_settle).then_some(RingChange::Prune);
    }
    // Steady state: one key, or primary + previous. Rotation is due.
    (age >= cadence.rotate_after).then_some(RingChange::Append)
}

/// How long ago the ring last changed. A missing timestamp (ring written
/// before this field existed) is an unknown age, treated as overdue so the
/// ring converges instead of never rotating; a future one is clock skew,
/// treated as just changed.
fn ring_age(now: SystemTime, network: &Network) -> Duration {
    match network.keys_updated_at {
        Some(changed) => now.duration_since(changed).unwrap_or(Duration::ZERO),
        None => Duration::MAX,
    }
}

/// Applies a planned change to the network's ring and stamps
/// `keys_updated_at` — the timestamp the next phase decision derives from.
fn apply(change: RingChange, network: &mut Network, now: SystemTime) {
    match change {
        RingChange::Generate => network.keys.push(random_key(&network.keys, true)),
        RingChange::Append => network.keys.push(random_key(&network.keys, false)),
        RingChange::Promote => {
            // Exactly one primary, the newest: nodes switch emission to it
            // by deleting the old outbound SA (experiment Q6).
            for key in &mut network.keys {
                key.primary = false;
            }
            if let Some(newest) = network.keys.last_mut() {
                newest.primary = true;
            }
        }
        RingChange::Prune => {
            // The primary is the newest key after a promote; keep it and
            // the immediately-previous one, which stays accepted on
            // reception for stragglers (libnetwork's ring shape).
            let surplus = network.keys.len().saturating_sub(STEADY_KEYS);
            network.keys.drain(..surplus);
        }
    }
    network.keys_updated_at = Some(now);
}

/// A fresh key: 16 random bytes under a random non-zero tag, unique within
/// the ring (SPIs derive from tags, FNV-1a libnetwork-style). Same CSPRNG
/// as the store's DEK (satl-cluster) and object IDs (satl-core).
fn random_key(existing_keys: &[NetworkKey], primary: bool) -> NetworkKey {
    use rand::Rng as _;

    let mut rng = rand::rng();
    let mut key = [0_u8; 16];
    rng.fill_bytes(&mut key);
    let tag = loop {
        let mut bytes = [0_u8; 4];
        rng.fill_bytes(&mut bytes);
        let tag = u32::from_le_bytes(bytes);
        if tag != 0 && existing_keys.iter().all(|existing| existing.tag != tag) {
            break tag;
        }
    };
    NetworkKey { tag, key, primary }
}

/// Generates and rotates the data-plane keys of encrypted networks.
pub(crate) struct Keyring {
    store: ClusterStore,
    /// Period of the full self-healing pass.
    interval: Duration,
    /// Rotation cadence: the production constants, or a test override from
    /// satld's config.
    cadence: Cadence,
    /// Whether a network changed since the last commit marker.
    dirty: bool,
}

impl Keyring {
    pub(crate) fn new(store: ClusterStore, interval: Duration, cadence: Cadence) -> Self {
        Self {
            store,
            interval,
            cadence,
            dirty: false,
        }
    }

    /// Runs until `shutdown` is cancelled or the store closes its watch feed.
    pub(crate) async fn run(mut self, shutdown: CancellationToken) {
        let span = tracing::info_span!("orchestrator.keyring");
        // Boxed: the loop holds a `StoreEvent` across await points, and that
        // enum spans every store object (clippy::large_futures).
        Box::pin(async move {
            let mut events = self.store.watch();
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    // The first tick fires immediately: that is the initial
                    // full pass (also the leader-change replay, SWK §7.9).
                    _ = ticker.tick() => self.full_pass().await,
                    event = events.recv() => match event {
                        Ok(event) => self.observe(event).await,
                        Err(RecvError::Lagged(missed)) => {
                            tracing::warn!(missed, "watch feed lagged; re-syncing from a full pass");
                            self.dirty = false;
                            self.full_pass().await;
                        }
                        Err(RecvError::Closed) => break,
                    },
                }
            }
            tracing::debug!("keyring loop stopped");
        }
        .instrument(span))
        .await;
    }

    /// Notes that a transaction touched a network, reconciling when its
    /// commit marker arrives. Rotation itself is time-driven; the fast path
    /// exists so a freshly created encrypted network gets its first key at
    /// once rather than one tick late.
    async fn observe(&mut self, event: StoreEvent) {
        match event {
            StoreEvent::Created(StoreObject::Network(_))
            | StoreEvent::Updated {
                new: StoreObject::Network(_),
                ..
            }
            | StoreEvent::Removed {
                kind: ObjectKind::Network,
                ..
            } => self.dirty = true,
            StoreEvent::Commit(_) if std::mem::take(&mut self.dirty) => {
                self.full_pass().await;
            }
            _ => {}
        }
    }

    /// Reconciles every network's keyring.
    async fn full_pass(&self) {
        let network_ids: Vec<Id> = {
            let view = self.store.view();
            view.networks().iter().map(|n| n.id.clone()).collect()
        };
        tracing::debug!(networks = network_ids.len(), "keyring full pass");
        for network_id in network_ids {
            reconcile(&self.store, &network_id, &self.cadence).await;
        }
    }
}

/// Reconciles one network's keyring, retrying on sequence conflicts.
async fn reconcile(store: &ClusterStore, network_id: &Id, cadence: &Cadence) {
    let result = propose_with_retry(store, "keyring reconcile", |view| {
        reconcile_actions(view, network_id, cadence)
    })
    .await;
    if let Err(err) = result {
        // Never fatal: the periodic pass re-derives the same decision.
        tracing::warn!(network_id = %network_id, error = %err, "keyring reconciliation deferred");
    }
}

/// Derives the store transaction that moves one network's ring one step.
/// Pure apart from `now` and the CSPRNG, both re-taken per attempt: the
/// phase decision never comes from a timer the loop holds.
fn reconcile_actions(view: &StoreView<'_>, network_id: &Id, cadence: &Cadence) -> Vec<StoreAction> {
    let Some(network) = view.network(network_id) else {
        return Vec::new();
    };
    let now = SystemTime::now();
    let Some(change) = plan_ring(now, &network, cadence) else {
        return Vec::new();
    };
    let mut network = (*network).clone();
    apply(change, &mut network, now);
    tracing::info!(
        network_id = %network.id,
        network = %network.spec.annotations.name,
        phase = change.as_str(),
        keys = network.keys.len(),
        "keyring transition"
    );
    vec![StoreAction::Update(StoreObject::Network(network))]
}

#[cfg(test)]
mod tests {
    use satl_cluster::ProposeError;
    use satl_core::NetworkDriver;

    use super::*;
    use crate::testing::{TestCluster, planted_network};

    /// A fixed point in time, seconds after the epoch.
    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// A deterministic key for hand-built rings.
    fn key(tag: u32, primary: bool) -> NetworkKey {
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&tag.to_le_bytes());
        NetworkKey {
            tag,
            key: bytes,
            primary,
        }
    }

    /// An encrypted overlay network with the given ring, last changed `at`.
    fn encrypted_ring(keys: Vec<NetworkKey>, at: SystemTime) -> Network {
        let mut network = planted_network("secure", NetworkDriver::Overlay);
        network.spec.encrypted = true;
        network.keys = keys;
        network.keys_updated_at = Some(at);
        network
    }

    // ------------------------------------------------------------------
    // Pure phase logic
    // ------------------------------------------------------------------

    #[test]
    fn empty_ring_on_encrypted_network_generates_one_primary_key() {
        let mut network = encrypted_ring(Vec::new(), t(0));
        network.keys_updated_at = None;
        assert_eq!(
            plan_ring(t(100), &network, &Cadence::default()),
            Some(RingChange::Generate)
        );
        apply(RingChange::Generate, &mut network, t(100));
        assert_eq!(network.keys.len(), 1);
        let generated = &network.keys[0];
        assert!(generated.primary, "the first key is the emission key");
        assert_ne!(generated.tag, 0, "tags are non-zero");
        assert_eq!(network.keys_updated_at, Some(t(100)));
    }

    #[test]
    fn unencrypted_network_is_never_touched() {
        // No ring: nothing to generate.
        let plain = planted_network("plain", NetworkDriver::Overlay);
        assert_eq!(plan_ring(t(100), &plain, &Cadence::default()), None);
        // A stale ring on a network whose encryption was turned off in the
        // spec is left alone: the node side keys off `spec.encrypted`.
        let stale = encrypted_ring(vec![key(1, true)], t(0));
        let mut stale = stale;
        stale.spec.encrypted = false;
        assert_eq!(plan_ring(t(1_000_000), &stale, &Cadence::default()), None);
    }

    #[test]
    fn ring_younger_than_the_rotation_interval_is_left_alone() {
        let now = t(1_000_000);
        let network = encrypted_ring(
            vec![key(1, true)],
            now - ROTATE_AFTER + Duration::from_secs(1),
        );
        assert_eq!(plan_ring(now, &network, &Cadence::default()), None);
    }

    #[test]
    fn ring_at_the_rotation_boundary_appends_a_non_primary_key() {
        let now = t(1_000_000);
        let mut network = encrypted_ring(vec![key(1, true)], now - ROTATE_AFTER);
        assert_eq!(
            plan_ring(now, &network, &Cadence::default()),
            Some(RingChange::Append)
        );
        apply(RingChange::Append, &mut network, now);
        assert_eq!(network.keys.len(), 2);
        assert!(network.keys[0].primary, "the old key stays primary");
        assert!(!network.keys[1].primary, "the new key is reception-only");
        assert_ne!(network.keys[0].tag, network.keys[1].tag);
        assert_eq!(network.keys_updated_at, Some(now));
    }

    #[test]
    fn steady_two_key_ring_appends_a_third() {
        let now = t(1_000_000);
        let mut network = encrypted_ring(vec![key(1, false), key(2, true)], now - ROTATE_AFTER);
        assert_eq!(
            plan_ring(now, &network, &Cadence::default()),
            Some(RingChange::Append)
        );
        apply(RingChange::Append, &mut network, now);
        assert_eq!(network.keys.len(), 3);
        assert_eq!(
            network.keys.iter().filter(|k| k.primary).count(),
            1,
            "still exactly one primary"
        );
        assert!(!network.keys[2].primary);
    }

    #[test]
    fn settled_append_is_promoted() {
        let now = t(1_000_000);
        let mut network = encrypted_ring(
            vec![key(1, true), key(2, false)],
            now - PHASE_SETTLE - Duration::from_secs(1),
        );
        assert_eq!(
            plan_ring(now, &network, &Cadence::default()),
            Some(RingChange::Promote)
        );
        apply(RingChange::Promote, &mut network, now);
        assert_eq!(network.keys.len(), 2);
        assert!(!network.keys[0].primary, "the old primary is demoted");
        assert!(network.keys[1].primary, "the newest key is promoted");
        assert_eq!(network.keys.iter().filter(|k| k.primary).count(), 1);
        assert_eq!(network.keys_updated_at, Some(now));
    }

    #[test]
    fn settled_promote_is_pruned_to_primary_and_previous() {
        let now = t(1_000_000);
        let mut network = encrypted_ring(
            vec![key(1, false), key(2, false), key(3, true)],
            now - PHASE_SETTLE - Duration::from_secs(1),
        );
        assert_eq!(
            plan_ring(now, &network, &Cadence::default()),
            Some(RingChange::Prune)
        );
        apply(RingChange::Prune, &mut network, now);
        assert_eq!(network.keys.len(), STEADY_KEYS);
        assert_eq!(network.keys[0].tag, 2, "the immediately-previous key stays");
        assert!(!network.keys[0].primary);
        assert_eq!(network.keys[1].tag, 3, "the primary is untouched");
        assert!(network.keys[1].primary);
        assert_eq!(network.keys_updated_at, Some(now));
    }

    #[test]
    fn fresh_append_is_never_promoted_before_its_delay() {
        let now = t(1_000_000);
        for age in [
            Duration::ZERO,
            PHASE_SETTLE.saturating_sub(Duration::from_secs(1)),
        ] {
            let network = encrypted_ring(vec![key(1, true), key(2, false)], now - age);
            assert_eq!(
                plan_ring(now, &network, &Cadence::default()),
                None,
                "age {age:?}"
            );
        }
    }

    #[test]
    fn freshly_promoted_ring_is_never_pruned_before_its_delay() {
        let now = t(1_000_000);
        for age in [
            Duration::ZERO,
            PHASE_SETTLE.saturating_sub(Duration::from_secs(1)),
        ] {
            let network =
                encrypted_ring(vec![key(1, false), key(2, false), key(3, true)], now - age);
            assert_eq!(
                plan_ring(now, &network, &Cadence::default()),
                None,
                "age {age:?}"
            );
        }
    }

    #[test]
    fn an_applied_change_proposes_nothing_on_a_second_pass() {
        let now = t(1_000_000);
        let cases: Vec<(RingChange, Network)> = vec![
            (RingChange::Generate, encrypted_ring(Vec::new(), t(0))),
            (
                RingChange::Append,
                encrypted_ring(vec![key(1, true)], now - ROTATE_AFTER),
            ),
            (
                RingChange::Promote,
                encrypted_ring(vec![key(1, true), key(2, false)], now - PHASE_SETTLE),
            ),
            (
                RingChange::Prune,
                encrypted_ring(
                    vec![key(1, false), key(2, false), key(3, true)],
                    now - PHASE_SETTLE,
                ),
            ),
        ];
        for (change, mut network) in cases {
            apply(change, &mut network, now);
            assert_eq!(
                plan_ring(now, &network, &Cadence::default()),
                None,
                "{change:?} must be idempotent"
            );
        }
    }

    /// The 12h boundary across a failover: the decision is a pure function
    /// of the stored ring and timestamp, so a new leader with no memory of
    /// the old one's ticks reaches the same conclusion at the same instant.
    #[test]
    fn failover_reconstructs_the_same_decision_from_store_state() {
        let appended_at = t(1_000_000);
        // The old leader appended and crashed before doing anything else.
        let mut store_state = encrypted_ring(vec![key(1, true)], appended_at - ROTATE_AFTER);
        apply(RingChange::Append, &mut store_state, appended_at);

        // What the old leader would have decided, had it lived.
        let continuity: Vec<Option<RingChange>> = [Duration::ZERO, PHASE_SETTLE, ROTATE_AFTER]
            .into_iter()
            .map(|later| plan_ring(appended_at + later, &store_state, &Cadence::default()))
            .collect();
        // What the new leader decides, from the store alone.
        let failover: Vec<Option<RingChange>> = [Duration::ZERO, PHASE_SETTLE, ROTATE_AFTER]
            .into_iter()
            .map(|later| plan_ring(appended_at + later, &store_state, &Cadence::default()))
            .collect();
        assert_eq!(continuity, failover);
        assert_eq!(
            failover,
            vec![None, Some(RingChange::Promote), Some(RingChange::Promote)],
            "append settles into promote; the next append is 12h after this change"
        );
    }

    /// A ring whose timestamp is missing (written before the field existed)
    /// or in the future (clock skew) still converges: unknown age is
    /// overdue, future age is fresh.
    #[test]
    fn missing_or_future_timestamps_converge() {
        let now = t(1_000_000);
        let mut legacy = encrypted_ring(vec![key(1, true)], t(0));
        legacy.keys_updated_at = None;
        assert_eq!(
            plan_ring(now, &legacy, &Cadence::default()),
            Some(RingChange::Append)
        );

        let skewed = encrypted_ring(vec![key(1, true)], now + Duration::from_hours(1));
        assert_eq!(
            plan_ring(now, &skewed, &Cadence::default()),
            None,
            "future means just changed"
        );
    }

    // ------------------------------------------------------------------
    // The configurable cadence (satld's keyring_*_secs testing knobs)
    // ------------------------------------------------------------------

    /// The production cadence is exactly the named constants: a default
    /// `Cadence` changes no decision.
    #[test]
    fn the_default_cadence_is_the_named_constants() {
        let cadence = Cadence::default();
        assert_eq!(cadence.rotate_after, ROTATE_AFTER);
        assert_eq!(cadence.phase_settle, PHASE_SETTLE);
    }

    /// A short cadence — what a cluster test injects — moves every time
    /// boundary with it: rotation comes due at `rotate_after`, the phases
    /// settle after `phase_settle`, and the decisions the default cadence
    /// would defer are taken.
    #[test]
    fn a_short_cadence_moves_every_boundary_with_it() {
        let cadence = Cadence {
            rotate_after: Duration::from_mins(2),
            phase_settle: Duration::from_secs(10),
        };
        let now = t(1_000_000);

        // Rotation: due at 120s under this cadence, not under the default.
        let ring = encrypted_ring(vec![key(1, true)], now - Duration::from_mins(2));
        assert_eq!(plan_ring(now, &ring, &cadence), Some(RingChange::Append));
        assert_eq!(plan_ring(now, &ring, &Cadence::default()), None);
        let young = encrypted_ring(vec![key(1, true)], now - Duration::from_secs(119));
        assert_eq!(plan_ring(now, &young, &cadence), None);

        // Promote and prune settle after 10s, not 60.
        let appended = encrypted_ring(
            vec![key(1, true), key(2, false)],
            now - Duration::from_secs(10),
        );
        assert_eq!(
            plan_ring(now, &appended, &cadence),
            Some(RingChange::Promote)
        );
        assert_eq!(plan_ring(now, &appended, &Cadence::default()), None);

        let promoted = encrypted_ring(
            vec![key(1, false), key(2, false), key(3, true)],
            now - Duration::from_secs(10),
        );
        assert_eq!(plan_ring(now, &promoted, &cadence), Some(RingChange::Prune));
        assert_eq!(plan_ring(now, &promoted, &Cadence::default()), None);
    }

    #[test]
    fn generated_keys_are_random_and_unique_within_the_ring() {
        let now = t(1_000_000);
        let mut network = encrypted_ring(Vec::new(), t(0));
        apply(RingChange::Generate, &mut network, now);
        let first = network.keys[0].clone();
        apply(RingChange::Append, &mut network, now + ROTATE_AFTER);
        let second = &network.keys[1];
        assert_ne!(first.tag, second.tag);
        assert_ne!(first.key, second.key);
    }

    // ------------------------------------------------------------------
    // The loop against a real single-node store
    // ------------------------------------------------------------------

    fn spawn(store: &ClusterStore, shutdown: &CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(
            Keyring::new(store.clone(), Duration::from_millis(50), Cadence::default())
                .run(shutdown.clone()),
        )
    }

    async fn create_network(store: &ClusterStore, network: Network) {
        store
            .propose(vec![StoreAction::Create(StoreObject::Network(network))])
            .await
            .expect("network created");
    }

    /// Rewrites `keys_updated_at` the way a test fast-forwards time,
    /// retrying the optimistic concurrency race against the loop under test.
    async fn rewind_keys_timestamp(store: &ClusterStore, network_id: &Id, at: SystemTime) {
        for _ in 0..50 {
            let mut network = {
                let view = store.view();
                (*view.network(network_id).expect("network is gone")).clone()
            };
            network.keys_updated_at = Some(at);
            match store
                .propose(vec![StoreAction::Update(StoreObject::Network(network))])
                .await
            {
                Ok(_) => return,
                Err(ProposeError::Rejected(_)) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(err) => panic!("failed to rewind the keyring timestamp: {err}"),
            }
        }
        panic!("never won the race to rewind the keyring timestamp");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_encrypted_network_gets_a_key_on_the_first_tick() {
        let cluster = TestCluster::start().await;
        let shutdown = CancellationToken::new();
        let loop_handle = spawn(cluster.store(), &shutdown);

        let network = encrypted_ring(Vec::new(), t(0));
        let network_id = network.id.clone();
        create_network(cluster.store(), network).await;

        let keyed = cluster
            .wait_for("the first key", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.len() == 1)
                    .map(|n| (*n).clone())
            })
            .await;
        assert!(keyed.keys[0].primary);
        assert_ne!(keyed.keys[0].tag, 0);
        assert!(keyed.keys_updated_at.is_some());
        let version = keyed.meta.version;

        // Steady state: the loop never rewrites a ring that needs nothing.
        cluster
            .stays(Duration::from_millis(500), "the ring flapped", |view| {
                view.network(&network_id)
                    .is_some_and(|n| n.meta.version == version && n.keys.len() == 1)
            })
            .await;

        shutdown.cancel();
        loop_handle.await.expect("loop joins");
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unencrypted_networks_are_left_alone_by_the_loop() {
        let cluster = TestCluster::start().await;
        let shutdown = CancellationToken::new();
        let loop_handle = spawn(cluster.store(), &shutdown);

        let network = planted_network("plain", NetworkDriver::Overlay);
        let network_id = network.id.clone();
        create_network(cluster.store(), network).await;

        cluster
            .stays(
                Duration::from_millis(500),
                "an unencrypted network grew a key",
                |view| {
                    view.network(&network_id)
                        .is_some_and(|n| n.keys.is_empty() && n.keys_updated_at.is_none())
                },
            )
            .await;

        shutdown.cancel();
        loop_handle.await.expect("loop joins");
        cluster.shutdown().await;
    }

    /// The whole rotation through the real store: append, promote, prune,
    /// each phase fast-forwarded by rewinding the stored timestamp — exactly
    /// what a leader failover replays.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_loop_walks_the_ring_through_append_promote_prune() {
        let cluster = TestCluster::start().await;
        let shutdown = CancellationToken::new();
        let loop_handle = spawn(cluster.store(), &shutdown);

        // A network due for rotation: one primary key, 13h old.
        let old = SystemTime::now() - ROTATE_AFTER - Duration::from_hours(1);
        let network = encrypted_ring(vec![key(7, true)], old);
        let network_id = network.id.clone();
        create_network(cluster.store(), network).await;

        // Append: a second, non-primary key appears.
        let appended = cluster
            .wait_for("the rotation append", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.len() == 2)
                    .map(|n| (*n).clone())
            })
            .await;
        assert!(appended.keys[0].primary);
        assert!(!appended.keys[1].primary);

        // Promote: fast-forward past the settling delay.
        rewind_keys_timestamp(
            cluster.store(),
            &network_id,
            SystemTime::now() - PHASE_SETTLE - Duration::from_secs(1),
        )
        .await;
        let promoted = cluster
            .wait_for("the promote", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.last().is_some_and(|k| k.primary))
                    .map(|n| (*n).clone())
            })
            .await;
        assert_eq!(promoted.keys.iter().filter(|k| k.primary).count(), 1);
        let primary_tag = promoted.keys[1].tag;

        // A second rotation makes the ring 3 keys, so the prune has work:
        // append, promote again, then the prune drops the oldest.
        rewind_keys_timestamp(
            cluster.store(),
            &network_id,
            SystemTime::now() - ROTATE_AFTER - Duration::from_secs(1),
        )
        .await;
        cluster
            .wait_for("the second append", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.len() == 3)
                    .map(|n| (*n).clone())
            })
            .await;
        rewind_keys_timestamp(
            cluster.store(),
            &network_id,
            SystemTime::now() - PHASE_SETTLE - Duration::from_secs(1),
        )
        .await;
        cluster
            .wait_for("the second promote", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.last().is_some_and(|k| k.primary))
                    .map(|n| (*n).clone())
            })
            .await;
        rewind_keys_timestamp(
            cluster.store(),
            &network_id,
            SystemTime::now() - PHASE_SETTLE - Duration::from_secs(1),
        )
        .await;
        let pruned = cluster
            .wait_for("the prune", |view| {
                view.network(&network_id)
                    .filter(|n| n.keys.len() == STEADY_KEYS)
                    .map(|n| (*n).clone())
            })
            .await;
        assert!(pruned.keys[1].primary, "the primary survives the prune");
        assert_ne!(pruned.keys[1].tag, primary_tag, "rotation moved on");
        assert_eq!(
            pruned.keys[0].tag, primary_tag,
            "the previous primary stays accepted on reception"
        );
        assert!(!pruned.keys[0].primary);

        shutdown.cancel();
        loop_handle.await.expect("loop joins");
        cluster.shutdown().await;
    }
}
