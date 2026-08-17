// SPDX-License-Identifier: BSD-2-Clause
//! Certificate renewal scheduling (architecture §12.3, SWK §16.4).
//!
//! Pure arithmetic over an injected clock and RNG — no I/O, no timers. The
//! renewal loop in the daemon owns the sleeping; this module only answers
//! "when".
//!
//! Two behaviours, both taken from `ca/renewer.go`:
//!
//! - **Herd avoidance.** The next renewal is drawn uniformly from the
//!   50–80 % point of the certificate's validity. Every node in a cluster is
//!   issued its certificate within minutes of the others (they all join at
//!   once); renewing at a fixed fraction would send the whole cluster at the
//!   CA simultaneously 45 days later. The window is wide enough — 12 days out
//!   of a 90-day certificate — that the leader sees a trickle, and early
//!   enough that a node has 18 days of slack to keep retrying if the CA is
//!   unreachable.
//! - **Expired-certificate backoff.** Once a certificate has expired the node
//!   can no longer authenticate to the CA with it, so it retries with
//!   exponential backoff from 5 s, capped at 1 h.

use std::time::{Duration, SystemTime};

use rand::{Rng, RngExt as _};

/// Start of the renewal window, as a fraction of validity (SWK §16.4).
pub const RENEWAL_WINDOW_START: f64 = 0.5;

/// End of the renewal window, as a fraction of validity (SWK §16.4).
pub const RENEWAL_WINDOW_END: f64 = 0.8;

/// First retry delay after a failed renewal of an expired certificate.
pub const RETRY_BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Ceiling on the retry delay.
pub const RETRY_BACKOFF_CAP: Duration = Duration::from_hours(1);

/// The instant at which a certificate issued at `issued_at` and expiring at
/// `expires_at` should be renewed.
///
/// Uniform in `[issued_at + 50 % · validity, issued_at + 80 % · validity)`.
/// A certificate whose validity is empty or inverted (a clock that jumped, a
/// certificate already expired at issuance) renews immediately.
pub fn next_renewal<R: Rng + ?Sized>(
    issued_at: SystemTime,
    expires_at: SystemTime,
    rng: &mut R,
) -> SystemTime {
    let Ok(validity) = expires_at.duration_since(issued_at) else {
        return issued_at;
    };
    if validity.is_zero() {
        return issued_at;
    }
    let fraction = rng.random_range(RENEWAL_WINDOW_START..RENEWAL_WINDOW_END);
    issued_at
        .checked_add(validity.mul_f64(fraction))
        .unwrap_or(expires_at)
}

/// How long to wait before renewing, from `now`.
///
/// Zero when the renewal point has already passed — the caller should renew at
/// once rather than sleep.
pub fn renewal_delay<R: Rng + ?Sized>(
    issued_at: SystemTime,
    expires_at: SystemTime,
    now: SystemTime,
    rng: &mut R,
) -> Duration {
    next_renewal(issued_at, expires_at, rng)
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
}

/// Whether a certificate expiring at `expires_at` is expired at `now`.
#[must_use]
pub fn is_expired(expires_at: SystemTime, now: SystemTime) -> bool {
    now >= expires_at
}

/// Retry delay for attempt number `attempt` (0-based) after a renewal failure.
///
/// `5 s · 2^attempt`, capped at 1 h (SWK §16.4).
#[must_use]
pub fn retry_backoff(attempt: u32) -> Duration {
    let delay = RETRY_BACKOFF_BASE
        .checked_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX))
        .unwrap_or(RETRY_BACKOFF_CAP);
    delay.min(RETRY_BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;

    const NINETY_DAYS: Duration = Duration::from_hours(90 * 24);

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn renewal_always_falls_inside_the_window() {
        let issued = epoch_plus(1_700_000_000);
        let expires = issued + NINETY_DAYS;
        let low = issued + NINETY_DAYS.mul_f64(RENEWAL_WINDOW_START);
        let high = issued + NINETY_DAYS.mul_f64(RENEWAL_WINDOW_END);

        let mut rng = StdRng::seed_from_u64(0x5A71);
        for _ in 0..10_000 {
            let at = next_renewal(issued, expires, &mut rng);
            assert!(at >= low, "renewal before 50% of validity");
            assert!(at < high, "renewal at or after 80% of validity");
        }
    }

    #[test]
    fn the_window_is_actually_spread_over_its_whole_range() {
        let issued = epoch_plus(1_000_000);
        let expires = issued + NINETY_DAYS;
        let mut rng = StdRng::seed_from_u64(42);

        // Ten buckets over [0.5, 0.8): every one must be hit, or the draw is
        // not uniform over the window (a fixed fraction would hit one).
        let window_start = NINETY_DAYS.mul_f64(RENEWAL_WINDOW_START).as_secs();
        let window_len = NINETY_DAYS
            .mul_f64(RENEWAL_WINDOW_END - RENEWAL_WINDOW_START)
            .as_secs();
        let mut buckets = [0_u32; 10];
        for _ in 0..10_000 {
            let at = next_renewal(issued, expires, &mut rng);
            let offset = at.duration_since(issued).expect("after issuance").as_secs();
            let index = usize::try_from((offset - window_start) * 10 / window_len)
                .expect("bucket index fits");
            buckets[index.min(9)] += 1;
        }
        assert!(
            buckets.iter().all(|&count| count > 500),
            "uneven spread over the renewal window: {buckets:?}"
        );
    }

    #[test]
    fn two_nodes_issued_together_do_not_renew_together() {
        // The property the window exists for: independent draws diverge.
        let issued = epoch_plus(1_700_000_000);
        let expires = issued + NINETY_DAYS;
        let mut a = StdRng::seed_from_u64(1);
        let mut b = StdRng::seed_from_u64(2);
        let first = next_renewal(issued, expires, &mut a);
        let second = next_renewal(issued, expires, &mut b);
        assert_ne!(first, second);
    }

    #[test]
    fn a_seeded_rng_makes_the_schedule_reproducible() {
        let issued = epoch_plus(1_700_000_000);
        let expires = issued + NINETY_DAYS;
        let first = next_renewal(issued, expires, &mut StdRng::seed_from_u64(99));
        let second = next_renewal(issued, expires, &mut StdRng::seed_from_u64(99));
        assert_eq!(first, second);
    }

    #[test]
    fn degenerate_validity_renews_immediately() {
        let issued = epoch_plus(1_700_000_000);
        let mut rng = StdRng::seed_from_u64(3);
        assert_eq!(next_renewal(issued, issued, &mut rng), issued);
        assert_eq!(
            next_renewal(issued, issued - Duration::from_secs(1), &mut rng),
            issued
        );
    }

    #[test]
    fn short_validity_still_lands_in_the_window() {
        let issued = epoch_plus(1_700_000_000);
        let expires = issued + Duration::from_hours(1);
        let mut rng = StdRng::seed_from_u64(4);
        for _ in 0..1_000 {
            let at = next_renewal(issued, expires, &mut rng);
            let offset = at.duration_since(issued).expect("after issuance");
            assert!(offset >= Duration::from_mins(30), "{offset:?}");
            assert!(offset < Duration::from_mins(48), "{offset:?}");
        }
    }

    #[test]
    fn renewal_delay_is_zero_once_the_point_has_passed() {
        let issued = epoch_plus(1_700_000_000);
        let expires = issued + NINETY_DAYS;
        let mut rng = StdRng::seed_from_u64(5);

        let delay = renewal_delay(issued, expires, issued, &mut rng);
        assert!(delay >= NINETY_DAYS.mul_f64(RENEWAL_WINDOW_START));

        let late = renewal_delay(issued, expires, expires, &mut rng);
        assert_eq!(late, Duration::ZERO);
    }

    #[test]
    fn expiry_check() {
        let expires = epoch_plus(1_000);
        assert!(!is_expired(expires, epoch_plus(999)));
        assert!(is_expired(expires, expires));
        assert!(is_expired(expires, epoch_plus(1_001)));
    }

    #[test]
    fn backoff_doubles_from_five_seconds_and_caps_at_one_hour() {
        assert_eq!(retry_backoff(0), Duration::from_secs(5));
        assert_eq!(retry_backoff(1), Duration::from_secs(10));
        assert_eq!(retry_backoff(2), Duration::from_secs(20));
        assert_eq!(retry_backoff(9), Duration::from_secs(2560));
        // 5 * 2^10 = 5120s > 3600s.
        assert_eq!(retry_backoff(10), RETRY_BACKOFF_CAP);
        // Never overflows, however long the CA stays away.
        for attempt in [31_u32, 32, 64, u32::MAX] {
            assert_eq!(retry_backoff(attempt), RETRY_BACKOFF_CAP);
        }
        // Monotonic up to the cap.
        for attempt in 0..12 {
            assert!(retry_backoff(attempt) <= retry_backoff(attempt + 1));
        }
    }
}
