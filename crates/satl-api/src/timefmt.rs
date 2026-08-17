// SPDX-License-Identifier: BSD-2-Clause
//! Docker's time formats: RFC 3339 with nanosecond precision (Go's
//! `time.RFC3339Nano`, which trims trailing zeros in the fraction), unix
//! seconds, and the `Less than a second` / `About a minute` / `3 days`
//! humanization Docker prints in `docker ps`' `STATUS` column
//! (`go-units.HumanDuration`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};

/// Go's zero `time.Time` rendered as JSON — what Docker puts in
/// `State.StartedAt` / `FinishedAt` for a container that never ran.
pub const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Formats an instant the way Go's `time.RFC3339Nano` does: UTC, `Z` suffix,
/// nanosecond fraction with trailing zeros removed (and no `.` at all when
/// the fraction is zero).
pub fn rfc3339_nano(time: SystemTime) -> String {
    let stamp = DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Nanos, true);
    trim_fraction(&stamp)
}

/// [`rfc3339_nano`] for optional instants, falling back to Go's zero time.
pub fn rfc3339_nano_or_zero(time: Option<SystemTime>) -> String {
    time.map_or_else(|| ZERO_TIME.to_owned(), rfc3339_nano)
}

/// Removes trailing zeros from the fractional seconds of an RFC 3339 stamp
/// ending in `Z`, dropping the separator when nothing is left.
fn trim_fraction(stamp: &str) -> String {
    let Some((seconds, rest)) = stamp.split_once('.') else {
        return stamp.to_owned();
    };
    let fraction = rest.trim_end_matches('Z').trim_end_matches('0');
    if fraction.is_empty() {
        format!("{seconds}Z")
    } else {
        format!("{seconds}.{fraction}Z")
    }
}

/// Whole seconds since the unix epoch (negative before it).
pub fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(err) => -i64::try_from(err.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Nanoseconds since the unix epoch (Docker's `timeNano` event field).
pub fn unix_nanos(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_nanos()).unwrap_or(i64::MAX),
        Err(err) => -i64::try_from(err.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

/// Parses the `since` / `until` timestamp forms Docker accepts on `/events`
/// and `/containers/{id}/logs`: unix seconds (`1712345678`), unix seconds with
/// a nanosecond fraction (`1712345678.000000042`), or an RFC 3339 stamp.
///
/// Returns `None` for an empty value (the parameter was not really set).
pub fn parse_timestamp(value: &str) -> Result<Option<SystemTime>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if let Some(time) = parse_unix(value) {
        return Ok(Some(time));
    }
    match DateTime::parse_from_rfc3339(value) {
        Ok(parsed) => Ok(Some(SystemTime::from(parsed.with_timezone(&Utc)))),
        Err(_) => Err(format!(
            "invalid time format {value:?}: expected unix seconds \
             (optionally with a nanosecond fraction) or an RFC 3339 timestamp"
        )),
    }
}

/// Parses `<seconds>[.<nanoseconds>]`, positive or negative.
fn parse_unix(value: &str) -> Option<SystemTime> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds: i64 = seconds.parse().ok()?;
    let nanos: u32 = if fraction.is_empty() {
        0
    } else {
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Pad/truncate to exactly nine digits.
        let mut digits = fraction.to_owned();
        digits.truncate(9);
        while digits.len() < 9 {
            digits.push('0');
        }
        digits.parse().ok()?
    };
    let magnitude = Duration::new(seconds.unsigned_abs(), nanos);
    if seconds < 0 {
        UNIX_EPOCH.checked_sub(magnitude)
    } else {
        UNIX_EPOCH.checked_add(magnitude)
    }
}

/// Docker's `STATUS` column duration wording (`go-units.HumanDuration`).
// Go rounds hours through float arithmetic; the cast is bounded by the
// `seconds < 60` / `minutes < 60` branches above and can only lose precision
// far beyond the human wording's resolution.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn humanize_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 1 {
        return "Less than a second".to_owned();
    }
    if seconds == 1 {
        return "1 second".to_owned();
    }
    if seconds < 60 {
        return format!("{seconds} seconds");
    }
    let minutes = seconds / 60;
    if minutes == 1 {
        return "About a minute".to_owned();
    }
    if minutes < 60 {
        return format!("{minutes} minutes");
    }
    // Go rounds hours to nearest (`int(d.Hours() + 0.5)`).
    let hours = (duration.as_secs_f64() / 3600.0 + 0.5) as u64;
    if hours == 1 {
        return "About an hour".to_owned();
    }
    if hours < 48 {
        return format!("{hours} hours");
    }
    if hours < 24 * 7 * 2 {
        return format!("{} days", hours / 24);
    }
    if hours < 24 * 30 * 2 {
        return format!("{} weeks", hours / 24 / 7);
    }
    if hours < 24 * 365 * 2 {
        return format!("{} months", hours / 24 / 30);
    }
    format!("{} years", (duration.as_secs() / 3600) / 24 / 365)
}

/// How long ago `time` was, saturating at zero for future instants.
pub fn elapsed_since(now: SystemTime, time: SystemTime) -> Duration {
    now.duration_since(time).unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64, nanos: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(seconds, nanos)
    }

    #[test]
    fn rfc3339_nano_matches_go_formatting() {
        let cases = [
            (at(0, 0), "1970-01-01T00:00:00Z"),
            (at(1_770_000_000, 0), "2026-02-02T02:40:00Z"),
            (at(1_770_000_000, 123_000_000), "2026-02-02T02:40:00.123Z"),
            (
                at(1_770_000_000, 123_456_789),
                "2026-02-02T02:40:00.123456789Z",
            ),
            (at(1_770_000_000, 1), "2026-02-02T02:40:00.000000001Z"),
        ];
        for (time, expected) in cases {
            assert_eq!(rfc3339_nano(time), expected);
        }
        assert_eq!(rfc3339_nano_or_zero(None), ZERO_TIME);
        assert_eq!(rfc3339_nano_or_zero(Some(at(0, 0))), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn unix_conversions() {
        assert_eq!(unix_seconds(at(1_770_000_000, 500)), 1_770_000_000);
        assert_eq!(unix_nanos(at(2, 5)), 2_000_000_005);
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(3)), -3);
    }

    #[test]
    fn parses_every_docker_timestamp_form() {
        let cases: [(&str, Option<SystemTime>); 6] = [
            ("", None),
            ("1770000000", Some(at(1_770_000_000, 0))),
            ("1770000000.000000042", Some(at(1_770_000_000, 42))),
            ("1770000000.5", Some(at(1_770_000_000, 500_000_000))),
            ("2026-02-02T02:40:00Z", Some(at(1_770_000_000, 0))),
            ("2026-02-02T03:40:00+01:00", Some(at(1_770_000_000, 0))),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_timestamp(input), Ok(expected), "for {input:?}");
        }
    }

    #[test]
    fn rejects_unparsable_timestamps() {
        let err = parse_timestamp("yesterday").unwrap_err();
        assert!(err.contains("yesterday"), "{err}");
        assert!(parse_timestamp("2026-13-45").is_err());
    }

    #[test]
    fn humanize_duration_matches_go_units() {
        let days = |count: u64| Duration::from_hours(count * 24);
        let cases = [
            (Duration::from_millis(300), "Less than a second"),
            (Duration::from_secs(1), "1 second"),
            (Duration::from_secs(45), "45 seconds"),
            (Duration::from_mins(1), "About a minute"),
            (Duration::from_secs(119), "About a minute"),
            (Duration::from_mins(3), "3 minutes"),
            (Duration::from_hours(1), "About an hour"),
            (Duration::from_hours(2), "2 hours"),
            (Duration::from_hours(47), "47 hours"),
            (Duration::from_hours(48), "2 days"),
            (days(13), "13 days"),
            (days(14), "2 weeks"),
            (days(59), "8 weeks"),
            (days(60), "2 months"),
            (days(729), "24 months"),
            (days(730), "2 years"),
        ];
        for (duration, expected) in cases {
            assert_eq!(humanize_duration(duration), expected, "for {duration:?}");
        }
    }

    #[test]
    fn elapsed_never_goes_backwards() {
        let now = at(100, 0);
        assert_eq!(elapsed_since(now, at(40, 0)), Duration::from_mins(1));
        assert_eq!(elapsed_since(now, at(200, 0)), Duration::ZERO);
    }
}
