// SPDX-License-Identifier: BSD-2-Clause
//! Node liveness: sessions, heartbeat TTLs, `DOWN`, and the 24 h orphaning
//! timer (architecture §7.1, SWK §13.1–§13.2).
//!
//! Pure and clock-injected: every method takes the `now` it should reason
//! from, so the whole state machine — including a 24 h timer — is testable in
//! microseconds with no sleeping and no `tokio::time::pause`.
//!
//! ```text
//!            register                 TTL expires            24 h
//!   UNKNOWN ──────────▶ READY ───────────────────▶ DOWN ─────────────▶ tasks ORPHANED
//!      ▲                  │                          │
//!      └──────────────────┘                          └── register ──▶ READY
//!        leadership change                             (a node that comes back
//!        (grace × 2)                                    keeps its tasks)
//! ```
//!
//! Three rules are easy to miss:
//!
//! - **The server dictates the heartbeat period** and arms `TTL = 3 × period`
//!   from the value it actually sent. An agent that is told 5.4 s gets a
//!   16.2 s TTL, not 15 s — otherwise the jitter meant to spread agents out
//!   would systematically eat into their margin.
//! - **A leadership change is not a failure.** The new leader has never heard
//!   from anyone, so it marks every non-`DOWN` node `UNKNOWN` with a
//!   **doubled** grace period, giving agents time to find it before their TTL
//!   runs out. Nodes already `DOWN` keep their orphaning clock: leadership
//!   churn must not resurrect them.
//! - **Every node in the store owes the new leader a registration.** The rule
//!   above only re-times nodes this manager already tracks — and a manager
//!   that just won its first election tracks nobody. The nodes it has never
//!   heard from get an *expectation* ([`Liveness::expect`], seeded from the
//!   store at leadership gain): the same `UNKNOWN` + doubled grace, but with
//!   **no session**, so nothing validates against it. A live agent replaces
//!   its expectation by registering; a dead node's expectation expires through
//!   the ordinary sweep into `DOWN` — which is what lets the orchestrator
//!   evict a killed *leader's* tasks, not just a killed follower's.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rand::{Rng, RngExt as _};
use satl_core::defaults::{HEARTBEAT_PERIOD, HEARTBEAT_TTL_FACTOR, NODE_DOWN_ORPHAN_AFTER};
use satl_core::{Id, NodeState};

use crate::UNKNOWN_GRACE_FACTOR;

/// Jitter applied to the dictated heartbeat period (architecture §15:
/// 5 s ± 500 ms).
pub const HEARTBEAT_JITTER: Duration = Duration::from_millis(500);

/// Heartbeat tuning. The defaults are architecture §15; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Base period dictated to agents.
    pub period: Duration,
    /// Maximum absolute jitter applied to each dictated period.
    pub jitter: Duration,
    /// TTL as a multiple of the dictated period.
    pub ttl_factor: u32,
    /// Extra factor granted to nodes moved to `UNKNOWN` by a leadership
    /// change.
    pub unknown_grace_factor: u32,
    /// How long a node stays `DOWN` before its tasks are orphaned.
    pub orphan_after: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            period: HEARTBEAT_PERIOD,
            jitter: HEARTBEAT_JITTER,
            ttl_factor: HEARTBEAT_TTL_FACTOR,
            unknown_grace_factor: UNKNOWN_GRACE_FACTOR,
            orphan_after: NODE_DOWN_ORPHAN_AFTER,
        }
    }
}

impl HeartbeatConfig {
    /// A period to dictate to one agent: `period ± jitter`, uniform.
    ///
    /// Jitter is per-node and per-beat so that agents registered together do
    /// not stay in lockstep.
    pub fn dictate<R: Rng + ?Sized>(&self, rng: &mut R) -> Duration {
        if self.jitter.is_zero() {
            return self.period;
        }
        let jitter = self.jitter.as_secs_f64();
        let offset = rng.random_range(-jitter..jitter);
        let seconds = (self.period.as_secs_f64() + offset).max(0.001);
        Duration::from_secs_f64(seconds)
    }

    /// The TTL armed for an agent that was told to beat every `period`.
    #[must_use]
    pub fn ttl(&self, period: Duration) -> Duration {
        period.saturating_mul(self.ttl_factor)
    }

    /// The grace granted to a node after a leadership change, whether it was
    /// re-timed ([`Liveness::leadership_gained`]) or seeded from the store
    /// ([`Liveness::expect`]): the base session TTL, doubled (SWK §13.2).
    ///
    /// Deliberately derived, not a fresh constant: 2 × 3 × 5 s = 30 s at the
    /// defaults. Measured on the cluster VMs (2026-08-12), an agent finds the
    /// new leader and re-registers 2.9–7.5 s after `raft leadership gained` —
    /// session teardown, redirect chase, register — so the doubled TTL covers
    /// the worst observed case about four times over while staying far below
    /// the scenario timeouts that wait on the resulting `DOWN`.
    #[must_use]
    pub fn unknown_grace(&self) -> Duration {
        self.ttl(self.period)
            .saturating_mul(self.unknown_grace_factor)
    }
}

/// Why a dispatcher RPC was refused on liveness grounds.
///
/// The proto pins the mapping: unknown node ⇒ `NOT_FOUND` ("node not
/// registered"), stale session ⇒ `FAILED_PRECONDITION` ("session invalid").
/// In both cases the agent's only correct reaction is to open a fresh
/// `Session`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRejection {
    /// No session has ever registered for this node on this manager.
    #[error(
        "node {node_id} is not registered with this manager: open a Session before calling any \
         other dispatcher rpc"
    )]
    NotRegistered {
        /// The node that called.
        node_id: Id,
    },

    /// The session ID does not match the one this manager issued — the agent
    /// re-registered, or is talking to a manager that superseded its session.
    #[error(
        "session {presented} is not valid for node {node_id} (this manager holds {held}): \
         re-register with a fresh Session"
    )]
    SessionInvalid {
        /// The node that called.
        node_id: Id,
        /// The session it presented.
        presented: String,
        /// The session this manager holds.
        held: String,
    },
}

/// One node's session and liveness bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    /// The session this manager issued, or `None` for a node it merely
    /// *expects* to register ([`Liveness::expect`]): an expectation carries a
    /// deadline but no credential, so no RPC can ever validate against it.
    ///
    /// `Option<String>` rather than a sentinel string on purpose — a sentinel
    /// would have to be compared against whatever an agent presents, and the
    /// proto's default `session_id` is the empty string.
    pub session_id: Option<String>,
    /// The period this manager last dictated.
    pub period: Duration,
    /// When the TTL runs out.
    pub expires_at: Instant,
    /// Liveness as the store should see it.
    pub state: NodeState,
}

/// What one [`Liveness::sweep`] found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// Nodes whose TTL expired in this sweep: they are now `DOWN` and their
    /// sessions are invalid.
    pub went_down: Vec<Id>,
    /// Nodes that have been `DOWN` for the orphaning period: every task of
    /// theirs in `[ASSIGNED, RUNNING]` must be marked `ORPHANED`.
    pub orphan: Vec<Id>,
}

impl Sweep {
    /// Whether the sweep found anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.went_down.is_empty() && self.orphan.is_empty()
    }
}

/// Sessions and TTLs for every node this manager has heard from.
///
/// Session IDs live **here and nowhere else**: they are never persisted and
/// never reused (SWK §13.1), so a manager restart invalidates every session,
/// which is exactly the intent — the agents re-register and re-report.
#[derive(Debug)]
pub struct Liveness {
    config: HeartbeatConfig,
    nodes: BTreeMap<Id, NodeEntry>,
    /// When each `DOWN` node went down, for the orphaning timer.
    down_since: BTreeMap<Id, Instant>,
    /// Nodes already orphaned, so the timer fires once.
    orphaned: BTreeMap<Id, Instant>,
}

impl Liveness {
    /// An empty tracker.
    #[must_use]
    pub fn new(config: HeartbeatConfig) -> Self {
        Self {
            config,
            nodes: BTreeMap::new(),
            down_since: BTreeMap::new(),
            orphaned: BTreeMap::new(),
        }
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> HeartbeatConfig {
        self.config
    }

    /// Registers a session, superseding any session the node held.
    ///
    /// Returns the superseded session ID, whose streams the caller must tear
    /// down (SWK §13.1: "re-registration invalidates the previous session's
    /// streams").
    pub fn register(
        &mut self,
        node_id: &Id,
        session_id: String,
        period: Duration,
        now: Instant,
    ) -> Option<String> {
        let expires_at = now + self.config.ttl(period);
        let previous = self.nodes.insert(
            node_id.clone(),
            NodeEntry {
                session_id: Some(session_id),
                period,
                expires_at,
                state: NodeState::Ready,
            },
        );
        self.down_since.remove(node_id);
        self.orphaned.remove(node_id);
        // An expectation has no streams to tear down, so superseding one is
        // not a re-registration and reports nothing.
        previous.and_then(|entry| entry.session_id)
    }

    /// Expects `node_id` to register within the leadership-change grace
    /// period, reporting whether an expectation was actually seeded.
    ///
    /// This is how a **new leader** starts a clock against a node it has never
    /// heard from (SWK §13.2: on leadership change *every* non-`DOWN` node is
    /// marked `UNKNOWN` with the doubled grace — the swarmkit dispatcher seeds
    /// its node set from the store, not from the sessions it holds, precisely
    /// so a node that never shows up expires into `DOWN`). The entry is
    /// `UNKNOWN` with no session: [`Liveness::validate`] refuses every RPC
    /// against it, a live agent replaces it wholesale by registering, and a
    /// dead node rides the ordinary [`Liveness::sweep`] into `DOWN` — no
    /// second eviction path, just a TTL for a session that never existed.
    ///
    /// A node this manager already tracks — a session **or** a previous
    /// expectation — is left alone: seeding must never shorten a live TTL,
    /// resurrect a `DOWN` entry, or re-arm a clock that is already running.
    /// Re-seeding after a leadership flap is therefore idempotent, and the
    /// clock *restarts* (fresh entry, fresh `now`) rather than accumulates,
    /// because [`Liveness::leadership_lost`] cleared the map in between.
    pub fn expect(&mut self, node_id: &Id, now: Instant) -> bool {
        if self.nodes.contains_key(node_id) {
            return false;
        }
        self.nodes.insert(
            node_id.clone(),
            NodeEntry {
                session_id: None,
                period: self.config.period,
                expires_at: now + self.config.unknown_grace(),
                state: NodeState::Unknown,
            },
        );
        true
    }

    /// Validates `(node, session)` for any dispatcher RPC.
    pub fn validate(&self, node_id: &Id, session_id: &str) -> Result<(), SessionRejection> {
        let entry = self
            .nodes
            .get(node_id)
            .ok_or_else(|| SessionRejection::NotRegistered {
                node_id: node_id.clone(),
            })?;
        // An expectation is not a registration: this manager never issued the
        // node a session, whatever the node presents.
        let Some(held) = entry.session_id.as_deref() else {
            return Err(SessionRejection::NotRegistered {
                node_id: node_id.clone(),
            });
        };
        if held != session_id || entry.state == NodeState::Down {
            return Err(SessionRejection::SessionInvalid {
                node_id: node_id.clone(),
                presented: session_id.to_owned(),
                held: held.to_owned(),
            });
        }
        Ok(())
    }

    /// Records a heartbeat and re-arms the TTL, returning the period the
    /// agent must use next.
    ///
    /// A heartbeat from a node that had gone `DOWN` is refused: its session
    /// is invalid, and letting it resurrect the node would skip the
    /// registration where the store learns the node is back.
    pub fn heartbeat(
        &mut self,
        node_id: &Id,
        session_id: &str,
        period: Duration,
        now: Instant,
    ) -> Result<Duration, SessionRejection> {
        self.validate(node_id, session_id)?;
        let ttl = self.config.ttl(period);
        let entry = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| SessionRejection::NotRegistered {
                node_id: node_id.clone(),
            })?;
        entry.period = period;
        entry.expires_at = now + ttl;
        entry.state = NodeState::Ready;
        Ok(period)
    }

    /// This manager just became leader: it has heard from nobody, so every
    /// node that is not already `DOWN` moves to `UNKNOWN` with a doubled
    /// grace period (SWK §13.2).
    ///
    /// Nodes are *kept*, not dropped: their sessions stay valid, so an agent
    /// that finds the new leader with its old session… does not exist —
    /// sessions are per-manager, and the agent will re-register. What the
    /// grace buys is the time to do so before the node is declared `DOWN`.
    pub fn leadership_gained(&mut self, now: Instant) {
        let grace = self.config.unknown_grace();
        let mut moved = 0_usize;
        for entry in self.nodes.values_mut() {
            if entry.state == NodeState::Down {
                continue;
            }
            entry.state = NodeState::Unknown;
            entry.expires_at = now + grace;
            moved += 1;
        }
        if moved > 0 {
            tracing::info!(
                nodes = moved,
                grace_ms = grace.as_millis(),
                "leadership changed: nodes moved to unknown state with a doubled grace period"
            );
        }
    }

    /// This manager lost leadership: every session is void, because sessions
    /// are per-manager and the agents will register with the new leader.
    pub fn leadership_lost(&mut self) -> Vec<(Id, String)> {
        let sessions: Vec<(Id, String)> = self
            .nodes
            .iter()
            .filter_map(|(id, entry)| Some((id.clone(), entry.session_id.clone()?)))
            .collect();
        self.nodes.clear();
        self.down_since.clear();
        self.orphaned.clear();
        sessions
    }

    /// Expires TTLs and fires the orphaning timer.
    ///
    /// Idempotent: a node is reported in `went_down` once (the transition),
    /// and in `orphan` once (the 24 h mark).
    pub fn sweep(&mut self, now: Instant) -> Sweep {
        let mut sweep = Sweep::default();
        for (node_id, entry) in &mut self.nodes {
            if entry.state == NodeState::Down || now < entry.expires_at {
                continue;
            }
            entry.state = NodeState::Down;
            self.down_since.insert(node_id.clone(), now);
            sweep.went_down.push(node_id.clone());
        }
        for (node_id, since) in &self.down_since {
            if self.orphaned.contains_key(node_id) {
                continue;
            }
            if now.duration_since(*since) >= self.config.orphan_after {
                sweep.orphan.push(node_id.clone());
            }
        }
        for node_id in &sweep.orphan {
            self.orphaned.insert(node_id.clone(), now);
        }
        sweep
    }

    /// Drops a node entirely (the node object was removed from the cluster).
    pub fn forget(&mut self, node_id: &Id) -> Option<String> {
        self.down_since.remove(node_id);
        self.orphaned.remove(node_id);
        self.nodes
            .remove(node_id)
            .and_then(|entry| entry.session_id)
    }

    /// The liveness state of one node, if it is known.
    #[must_use]
    pub fn state(&self, node_id: &Id) -> Option<NodeState> {
        self.nodes.get(node_id).map(|entry| entry.state)
    }

    /// Every node this manager tracks, in any state.
    #[must_use]
    pub fn node_ids(&self) -> Vec<Id> {
        self.nodes.keys().cloned().collect()
    }

    /// Every node this manager tracks, with the state the store should show
    /// for it.
    ///
    /// This is the whole projection in one read, which is what the store has
    /// to be reconciled against: the transitions above are edges, and an edge
    /// that is missed or overwritten is never re-sent. Taken as a set instead,
    /// it is a level, and the sweep can re-assert it on every pass.
    #[must_use]
    pub fn states(&self) -> Vec<(Id, NodeState)> {
        self.nodes
            .iter()
            .map(|(id, entry)| (id.clone(), entry.state))
            .collect()
    }

    /// The session this manager holds for a node, if any — `None` both for an
    /// untracked node and for one it only [`expect`](Self::expect)s.
    #[must_use]
    pub fn session(&self, node_id: &Id) -> Option<&str> {
        self.nodes
            .get(node_id)
            .and_then(|entry| entry.session_id.as_deref())
    }

    /// How long until the next thing happens (a TTL expiry or an orphaning),
    /// so the sweep loop can sleep exactly that long instead of polling.
    #[must_use]
    pub fn next_deadline(&self, now: Instant) -> Option<Duration> {
        let ttl = self
            .nodes
            .values()
            .filter(|entry| entry.state != NodeState::Down)
            .map(|entry| entry.expires_at.saturating_duration_since(now))
            .min();
        let orphan = self
            .down_since
            .iter()
            .filter(|(node_id, _)| !self.orphaned.contains_key(*node_id))
            .map(|(_, since)| (*since + self.config.orphan_after).saturating_duration_since(now))
            .min();
        match (ttl, orphan) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (only, None) | (None, only) => only,
        }
    }

    /// How many nodes are tracked (any state).
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether no node is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    const PERIOD: Duration = Duration::from_secs(5);

    fn config() -> HeartbeatConfig {
        HeartbeatConfig::default()
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    #[test]
    fn the_dictated_period_stays_inside_the_jitter_band() {
        let config = config();
        let mut rng = rng();
        for _ in 0..10_000 {
            let period = config.dictate(&mut rng);
            assert!(
                period >= PERIOD.saturating_sub(config.jitter)
                    && period <= PERIOD.saturating_add(config.jitter),
                "{period:?} outside 5 s ± 500 ms"
            );
        }
    }

    #[test]
    fn the_ttl_is_three_times_the_period_actually_dictated() {
        let config = config();
        assert_eq!(config.ttl(PERIOD), Duration::from_secs(15));
        assert_eq!(
            config.ttl(Duration::from_millis(5_400)),
            Duration::from_millis(16_200),
            "the ttl follows the jittered period, not the base one"
        );
    }

    #[test]
    fn an_unregistered_node_is_not_found_and_a_stale_session_is_invalid() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let now = Instant::now();
        assert!(matches!(
            liveness.validate(&node, "s1"),
            Err(SessionRejection::NotRegistered { .. })
        ));
        liveness.register(&node, "s1".to_owned(), PERIOD, now);
        liveness.validate(&node, "s1").expect("current session");
        assert!(matches!(
            liveness.validate(&node, "s0"),
            Err(SessionRejection::SessionInvalid { .. })
        ));
    }

    #[test]
    fn re_registration_supersedes_the_previous_session() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let now = Instant::now();
        assert_eq!(liveness.register(&node, "s1".to_owned(), PERIOD, now), None);
        assert_eq!(
            liveness.register(&node, "s2".to_owned(), PERIOD, now),
            Some("s1".to_owned()),
            "the caller must tear down the superseded session's streams"
        );
        assert!(liveness.validate(&node, "s1").is_err());
        liveness.validate(&node, "s2").expect("new session");
    }

    #[test]
    fn a_node_goes_down_exactly_at_the_ttl_and_only_once() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);

        // Beating keeps it alive.
        for beat in 1..=10 {
            let now = start + PERIOD * beat;
            liveness
                .heartbeat(&node, "s1", PERIOD, now)
                .expect("heartbeat");
            assert!(liveness.sweep(now).is_empty());
        }

        let last = start + PERIOD * 10;
        // One tick before the TTL: still up.
        assert!(
            liveness
                .sweep(last + Duration::from_secs(14) + Duration::from_millis(999))
                .is_empty()
        );
        let sweep = liveness.sweep(last + Duration::from_secs(15));
        assert_eq!(sweep.went_down, vec![node.clone()]);
        assert_eq!(liveness.state(&node), Some(NodeState::Down));
        assert!(
            liveness.sweep(last + Duration::from_secs(20)).is_empty(),
            "a node goes down once, not on every sweep"
        );
    }

    #[test]
    fn a_down_nodes_session_is_invalid_so_it_must_re_register() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);
        liveness.sweep(start + Duration::from_secs(15));
        assert!(matches!(
            liveness.heartbeat(&node, "s1", PERIOD, start + Duration::from_secs(16)),
            Err(SessionRejection::SessionInvalid { .. })
        ));
        liveness.register(
            &node,
            "s2".to_owned(),
            PERIOD,
            start + Duration::from_secs(17),
        );
        assert_eq!(liveness.state(&node), Some(NodeState::Ready));
    }

    #[test]
    fn tasks_are_orphaned_after_twenty_four_hours_down_and_not_before() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);
        let down_at = start + Duration::from_secs(15);
        assert_eq!(liveness.sweep(down_at).went_down, vec![node.clone()]);

        assert!(
            liveness
                .sweep(down_at + Duration::from_hours(23))
                .orphan
                .is_empty(),
            "23 hours is not 24"
        );
        let sweep = liveness.sweep(down_at + NODE_DOWN_ORPHAN_AFTER);
        assert_eq!(sweep.orphan, vec![node.clone()]);
        assert!(
            liveness
                .sweep(down_at + Duration::from_hours(48))
                .orphan
                .is_empty(),
            "orphaning fires once"
        );
    }

    #[test]
    fn a_node_that_comes_back_before_the_orphan_timer_keeps_its_tasks() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);
        let down_at = start + Duration::from_secs(15);
        liveness.sweep(down_at);
        let back = down_at + Duration::from_hours(12);
        liveness.register(&node, "s2".to_owned(), PERIOD, back);
        assert_eq!(liveness.state(&node), Some(NodeState::Ready));
        assert!(
            liveness
                .sweep(back + Duration::from_hours(20))
                .orphan
                .is_empty(),
            "the orphan clock is reset by a fresh registration"
        );
    }

    #[test]
    fn a_leadership_change_doubles_the_grace_period() {
        let mut liveness = Liveness::new(config());
        let alive = Id::generate();
        let start = Instant::now();
        liveness.register(&alive, "a1".to_owned(), PERIOD, start);
        let elected = start + Duration::from_secs(1);
        liveness.leadership_gained(elected);
        assert_eq!(liveness.state(&alive), Some(NodeState::Unknown));
        assert!(
            liveness.sweep(elected + Duration::from_secs(29)).is_empty(),
            "the grace period is 2 × 3 × 5 s = 30 s"
        );
        assert_eq!(
            liveness.sweep(elected + Duration::from_secs(30)).went_down,
            vec![alive.clone()]
        );
    }

    /// Leadership churn must not resurrect a node that is already down, nor
    /// restart its orphaning clock — otherwise a flapping control plane could
    /// keep a dead node's tasks alive forever.
    #[test]
    fn a_leadership_change_does_not_resurrect_a_down_node() {
        let mut liveness = Liveness::new(config());
        let dead = Id::generate();
        let start = Instant::now();
        liveness.register(&dead, "d1".to_owned(), PERIOD, start);
        let down_at = start + Duration::from_secs(15);
        assert_eq!(liveness.sweep(down_at).went_down, vec![dead.clone()]);

        liveness.leadership_gained(down_at + Duration::from_secs(1));
        assert_eq!(liveness.state(&dead), Some(NodeState::Down));
        assert_eq!(
            liveness.sweep(down_at + NODE_DOWN_ORPHAN_AFTER).orphan,
            vec![dead.clone()],
            "the orphan clock still started when the node went down"
        );
    }

    /// The killed-leader debt: a node the new leader has never heard from gets
    /// an expectation at leadership gain, and if it never registers, the
    /// expectation expires into `DOWN` through the ordinary sweep — the same
    /// level (`mark_down`, then the orchestrator's `InvalidNode`) that already
    /// evicts a killed follower's tasks.
    #[test]
    fn an_expectation_expires_into_down_through_the_ordinary_sweep() {
        let mut liveness = Liveness::new(config());
        let dead = Id::generate();
        let elected = Instant::now();
        assert!(liveness.expect(&dead, elected));
        assert_eq!(liveness.state(&dead), Some(NodeState::Unknown));
        assert_eq!(
            liveness.session(&dead),
            None,
            "an expectation has no session"
        );

        // The grace is the doubled session TTL: 2 x 3 x 5 s = 30 s.
        assert_eq!(config().unknown_grace(), Duration::from_secs(30));
        assert!(
            liveness.sweep(elected + Duration::from_secs(29)).is_empty(),
            "the node still has time to re-register"
        );
        let sweep = liveness.sweep(elected + Duration::from_secs(30));
        assert_eq!(sweep.went_down, vec![dead.clone()]);
        assert_eq!(liveness.state(&dead), Some(NodeState::Down));
        // And the orphaning clock started at the expiry, as for any DOWN node.
        assert_eq!(
            liveness
                .sweep(elected + Duration::from_secs(30) + NODE_DOWN_ORPHAN_AFTER)
                .orphan,
            vec![dead]
        );
    }

    #[test]
    fn a_seeded_node_that_registers_in_time_becomes_ready() {
        let mut liveness = Liveness::new(config());
        let alive = Id::generate();
        let elected = Instant::now();
        liveness.expect(&alive, elected);

        // Measured on the VMs: re-registration lands 2.9-7.5 s after the
        // election. Model the worst observed case.
        let superseded = liveness.register(
            &alive,
            "s1".to_owned(),
            PERIOD,
            elected + Duration::from_secs(8),
        );
        assert_eq!(
            superseded, None,
            "replacing an expectation is not a re-registration: no streams to tear down"
        );
        assert_eq!(liveness.state(&alive), Some(NodeState::Ready));
        // The registration re-armed the clock: 3 x 5 s from the registration,
        // so the node outlives the expectation's 30 s deadline as long as it
        // beats, and expires by its own session TTL when it stops.
        assert!(
            liveness
                .sweep(elected + Duration::from_secs(8) + Duration::from_secs(14))
                .is_empty(),
            "inside the registration's own TTL"
        );
        assert_eq!(
            liveness
                .sweep(elected + Duration::from_secs(8) + Duration::from_secs(15))
                .went_down,
            vec![alive],
            "from registration on, the ordinary session TTL governs"
        );
    }

    /// No RPC may validate against an expectation — in particular not one
    /// presenting the empty session ID, which is the proto default and what a
    /// sentinel-string implementation would have compared equal.
    #[test]
    fn an_expectation_validates_no_session_not_even_an_empty_one() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        liveness.expect(&node, Instant::now());
        for presented in ["", "s1"] {
            assert!(
                matches!(
                    liveness.validate(&node, presented),
                    Err(SessionRejection::NotRegistered { .. })
                ),
                "presenting {presented:?} must read as never-registered"
            );
        }
    }

    /// Seeding is additive only: a node this manager tracks — live session,
    /// `DOWN` entry, or an earlier expectation — is left exactly alone.
    /// One `Liveness` per sub-case, so no clock leaks into another's sweep.
    #[test]
    fn seeding_never_touches_a_tracked_node() {
        let start = Instant::now();

        // A registered node keeps its session and its own TTL.
        let mut liveness = Liveness::new(config());
        let live = Id::generate();
        liveness.register(&live, "s1".to_owned(), PERIOD, start);
        assert!(!liveness.expect(&live, start + Duration::from_secs(1)));
        assert_eq!(liveness.state(&live), Some(NodeState::Ready));
        assert_eq!(liveness.session(&live), Some("s1"));

        // A DOWN node is not resurrected, and its orphaning clock is not reset.
        let mut liveness = Liveness::new(config());
        let dead = Id::generate();
        liveness.register(&dead, "d1".to_owned(), PERIOD, start);
        let down_at = start + Duration::from_secs(15);
        liveness.sweep(down_at);
        assert!(!liveness.expect(&dead, down_at + Duration::from_secs(1)));
        assert_eq!(liveness.state(&dead), Some(NodeState::Down));
        assert_eq!(
            liveness.sweep(down_at + NODE_DOWN_ORPHAN_AFTER).orphan,
            vec![dead],
            "the orphan clock still counts from the original expiry"
        );

        // Seeding twice arms one clock, at the first deadline.
        let mut liveness = Liveness::new(config());
        let expected = Id::generate();
        assert!(liveness.expect(&expected, start));
        assert!(!liveness.expect(&expected, start + Duration::from_secs(10)));
        assert_eq!(
            liveness.sweep(start + Duration::from_secs(30)).went_down,
            vec![expected],
            "the second expect neither extended nor doubled the deadline"
        );
    }

    /// The double failure: the new leader dies during the grace period, and
    /// the *next* leader seeds again from the store. Idempotent, and the clock
    /// restarts — the dead node gets a full fresh grace, never an accumulated
    /// or an already-expired one.
    #[test]
    fn re_seeding_after_a_leadership_flap_restarts_the_clock() {
        let mut liveness = Liveness::new(config());
        let dead = Id::generate();
        let first_election = Instant::now();
        liveness.expect(&dead, first_election);

        // 10 s in, this manager loses leadership (or is the next manager,
        // whose map is empty either way).
        let flapped = first_election + Duration::from_secs(10);
        liveness.leadership_lost();
        assert!(liveness.is_empty());
        assert!(liveness.expect(&dead, flapped));

        assert!(
            liveness
                .sweep(first_election + Duration::from_secs(30))
                .is_empty(),
            "the first election's deadline died with the first leadership"
        );
        assert_eq!(
            liveness.sweep(flapped + Duration::from_secs(30)).went_down,
            vec![dead],
            "one full grace from the re-seeding, no accumulation"
        );
    }

    #[test]
    fn a_node_in_unknown_state_returns_to_ready_on_a_heartbeat() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);
        liveness.leadership_gained(start);
        assert_eq!(liveness.state(&node), Some(NodeState::Unknown));
        liveness
            .heartbeat(&node, "s1", PERIOD, start + Duration::from_secs(1))
            .expect("an unknown node may still beat");
        assert_eq!(liveness.state(&node), Some(NodeState::Ready));
    }

    #[test]
    fn losing_leadership_voids_every_session() {
        let mut liveness = Liveness::new(config());
        let a = Id::generate();
        let b = Id::generate();
        let now = Instant::now();
        liveness.register(&a, "a1".to_owned(), PERIOD, now);
        liveness.register(&b, "b1".to_owned(), PERIOD, now);
        liveness.expect(&Id::generate(), now);
        let voided = liveness.leadership_lost();
        assert_eq!(
            voided.len(),
            2,
            "an expectation is dropped too, but it is no session to void"
        );
        assert!(liveness.is_empty());
        assert!(matches!(
            liveness.validate(&a, "a1"),
            Err(SessionRejection::NotRegistered { .. })
        ));
    }

    #[test]
    fn the_next_deadline_is_the_earliest_ttl_or_orphaning() {
        let mut liveness = Liveness::new(config());
        assert_eq!(liveness.next_deadline(Instant::now()), None);

        let soon = Id::generate();
        let later = Id::generate();
        let start = Instant::now();
        liveness.register(&soon, "s".to_owned(), Duration::from_secs(1), start);
        liveness.register(&later, "l".to_owned(), Duration::from_secs(10), start);
        assert_eq!(
            liveness.next_deadline(start),
            Some(Duration::from_secs(3)),
            "3 × the shortest dictated period"
        );

        liveness.sweep(start + Duration::from_secs(3));
        // `soon` is down: its orphan timer is now the horizon for it, while
        // `later` still has its TTL.
        assert_eq!(
            liveness.next_deadline(start + Duration::from_secs(3)),
            Some(Duration::from_secs(27)),
            "later's ttl is 30 s from start"
        );
    }

    /// The projection the sweep reconciles the store against: every tracked
    /// node, with the state its node object should carry.
    #[test]
    fn the_state_projection_covers_every_tracked_node() {
        let mut liveness = Liveness::new(config());
        assert!(liveness.states().is_empty());

        let ready = Id::generate();
        let down = Id::generate();
        let start = Instant::now();
        liveness.register(&ready, "r1".to_owned(), PERIOD, start);
        liveness.register(&down, "d1".to_owned(), PERIOD, start);
        liveness
            .heartbeat(&ready, "r1", PERIOD, start + Duration::from_secs(14))
            .expect("heartbeat");
        liveness.sweep(start + Duration::from_secs(15));

        let states: BTreeMap<Id, NodeState> = liveness.states().into_iter().collect();
        assert_eq!(states.get(&ready), Some(&NodeState::Ready));
        assert_eq!(
            states.get(&down),
            Some(&NodeState::Down),
            "a down node is part of the projection, not dropped from it"
        );
        assert_eq!(states.len(), 2);

        liveness.forget(&down);
        assert_eq!(liveness.states().len(), 1);
    }

    #[test]
    fn forgetting_a_node_drops_its_session_and_its_timers() {
        let mut liveness = Liveness::new(config());
        let node = Id::generate();
        let start = Instant::now();
        liveness.register(&node, "s1".to_owned(), PERIOD, start);
        liveness.sweep(start + Duration::from_secs(15));
        assert_eq!(liveness.forget(&node), Some("s1".to_owned()));
        assert!(liveness.is_empty());
        assert!(
            liveness
                .sweep(start + Duration::from_hours(48))
                .orphan
                .is_empty()
        );
        assert_eq!(liveness.forget(&node), None);
    }
}
