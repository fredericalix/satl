// SPDX-License-Identifier: BSD-2-Clause
//! The agent's session reconnect backoff (architecture §7.2, SWK §14.1).
//!
//! SwarmKit's exact shape, kept because the numbers are load-bearing for how
//! fast a cluster recovers from a leadership change:
//!
//! ```text
//! backoff = min(100 ms + 2 × backoff, 8 s)
//! delay   = uniform in [0, backoff)
//! ```
//!
//! The **jittered delay** is what matters: after a leader dies, every agent
//! in the cluster fails at the same instant, and an unjittered retry would
//! turn a leadership change into a synchronized stampede against the new
//! leader. `backoff` is reset to zero on a successful **registration** — not
//! on a successful connection, because a manager that accepts TCP and then
//! refuses the session is exactly the case the backoff exists for.

use std::time::Duration;

use rand::{Rng, RngExt as _};

use satl_core::defaults::{SESSION_BACKOFF_BASE, SESSION_BACKOFF_MAX};

/// The next backoff bound after a failure: `min(100 ms + 2 × current, 8 s)`.
#[must_use]
pub fn next_bound(current: Duration) -> Duration {
    SESSION_BACKOFF_BASE
        .saturating_add(current.saturating_mul(2))
        .min(SESSION_BACKOFF_MAX)
}

/// The delay to actually sleep: uniform in `[0, bound)`.
///
/// A zero bound means "no wait" — the state after a successful registration.
pub fn delay<R: Rng + ?Sized>(bound: Duration, rng: &mut R) -> Duration {
    if bound.is_zero() {
        return Duration::ZERO;
    }
    bound.mul_f64(rng.random_range(0.0..1.0))
}

/// The agent's reconnect backoff state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Backoff {
    bound: Duration,
}

impl Backoff {
    /// A backoff that has not failed yet: the first retry is immediate-ish
    /// (uniform in `[0, 100 ms)` after the first failure).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current bound.
    #[must_use]
    pub fn bound(self) -> Duration {
        self.bound
    }

    /// Records a failure and returns how long to wait before the next
    /// attempt.
    pub fn fail<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Duration {
        self.bound = next_bound(self.bound);
        delay(self.bound, rng)
    }

    /// Registration succeeded: the next failure starts from scratch.
    pub fn reset(&mut self) {
        self.bound = Duration::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xdead_beef)
    }

    #[test]
    fn the_bound_follows_the_swarmkit_recurrence() {
        let mut bound = Duration::ZERO;
        let expected = [100, 300, 700, 1_500, 3_100, 6_300, 8_000, 8_000];
        for millis in expected {
            bound = next_bound(bound);
            assert_eq!(bound, Duration::from_millis(millis));
        }
    }

    #[test]
    fn the_bound_is_capped_at_eight_seconds_from_any_starting_point() {
        assert_eq!(next_bound(Duration::from_mins(1)), SESSION_BACKOFF_MAX);
        assert_eq!(next_bound(Duration::MAX), SESSION_BACKOFF_MAX);
    }

    #[test]
    fn the_delay_is_jittered_below_the_bound() {
        let mut rng = rng();
        let bound = Duration::from_secs(8);
        let mut seen_below_half = false;
        for _ in 0..1_000 {
            let delay = delay(bound, &mut rng);
            assert!(delay < bound, "{delay:?} must stay under {bound:?}");
            seen_below_half |= delay < bound / 2;
        }
        assert!(
            seen_below_half,
            "an unjittered backoff would stampede the new leader"
        );
    }

    #[test]
    fn a_zero_bound_does_not_wait() {
        let mut rng = rng();
        assert_eq!(delay(Duration::ZERO, &mut rng), Duration::ZERO);
    }

    #[test]
    fn registration_resets_the_climb() {
        let mut rng = rng();
        let mut backoff = Backoff::new();
        for _ in 0..10 {
            backoff.fail(&mut rng);
        }
        assert_eq!(backoff.bound(), SESSION_BACKOFF_MAX);
        backoff.reset();
        assert_eq!(backoff.bound(), Duration::ZERO);
        backoff.fail(&mut rng);
        assert_eq!(backoff.bound(), SESSION_BACKOFF_BASE);
    }

    #[test]
    fn every_delay_stays_within_its_bound() {
        let mut rng = rng();
        let mut backoff = Backoff::new();
        for _ in 0..50 {
            let delay = backoff.fail(&mut rng);
            assert!(delay < backoff.bound() || backoff.bound().is_zero());
            assert!(delay <= SESSION_BACKOFF_MAX);
        }
    }
}
