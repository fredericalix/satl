// SPDX-License-Identifier: BSD-2-Clause
//! Name validation and task naming (architecture §3, SWK §3.2).
//!
//! Implementation note: the checks are hand-rolled character logic rather
//! than a regex dependency. Both SwarmKit patterns reduce exactly to
//! "first and last character ASCII alphanumeric, interior characters from a
//! fixed ASCII set":
//!
//! - services/networks — `^[a-zA-Z0-9](?:[-_]*[A-Za-z0-9]+)*$`: every run of
//!   `-`/`_` must be followed by an alphanumeric, which is equivalent to the
//!   interior set `[A-Za-z0-9_-]` with alphanumeric first and last chars.
//! - secrets/configs — `^[a-zA-Z0-9]+(?:[a-zA-Z0-9-_.]*[a-zA-Z0-9])?$`:
//!   equivalent to the interior set `[A-Za-z0-9_.-]` with alphanumeric first
//!   and last chars.
//!
//! Non-ASCII input always fails the character-set checks, so length limits
//! can be enforced on bytes.

use crate::error::InvalidName;
use crate::id::Id;

/// Maximum length of a service or network name (DNS-label bound).
const MAX_SERVICE_NAME_LEN: usize = 63;

/// Maximum length of a secret or config name.
const MAX_SECRET_NAME_LEN: usize = 64;

const SERVICE_NAME_RULE: &str = "must match ^[a-zA-Z0-9](?:[-_]*[A-Za-z0-9]+)*$ \
     and be at most 63 characters";

const SECRET_NAME_RULE: &str = "must match ^[a-zA-Z0-9]+(?:[a-zA-Z0-9-_.]*[a-zA-Z0-9])?$ \
     and be at most 64 characters";

/// Validates a service name (architecture §3).
pub fn validate_service_name(name: &str) -> Result<(), InvalidName> {
    validate(name, MAX_SERVICE_NAME_LEN, false, SERVICE_NAME_RULE)
}

/// Validates a network name — same rule as service names (architecture §3).
pub fn validate_network_name(name: &str) -> Result<(), InvalidName> {
    validate(name, MAX_SERVICE_NAME_LEN, false, SERVICE_NAME_RULE)
}

/// Validates a secret name (architecture §3).
pub fn validate_secret_name(name: &str) -> Result<(), InvalidName> {
    validate(name, MAX_SECRET_NAME_LEN, true, SECRET_NAME_RULE)
}

/// Validates a config name — same rule as secret names (architecture §3).
pub fn validate_config_name(name: &str) -> Result<(), InvalidName> {
    validate(name, MAX_SECRET_NAME_LEN, true, SECRET_NAME_RULE)
}

/// Builds the canonical task name `<service>.<slot>.<taskID>` (SWK §3.2).
///
/// `slot` is passed as a string because global tasks use the node ID in
/// place of the slot number. Note that jail names are the bare task ID, not
/// this name — jail(8) treats `.` as a hierarchy separator (architecture §3).
#[must_use]
pub fn task_name(service_name: &str, slot: &str, task_id: &Id) -> String {
    format!("{service_name}.{slot}.{task_id}")
}

/// Shared checker: length bound, interior character set (`.` only when
/// `allow_dot`), and alphanumeric first/last characters.
fn validate(
    name: &str,
    max_len: usize,
    allow_dot: bool,
    rule: &'static str,
) -> Result<(), InvalidName> {
    let bytes = name.as_bytes();
    let interior_ok =
        |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || (allow_dot && b == b'.');
    let valid = match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => {
            bytes.len() <= max_len
                && first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && bytes.iter().copied().all(interior_ok)
        }
        _ => false, // empty
    };
    if valid {
        Ok(())
    } else {
        Err(InvalidName {
            value: name.to_owned(),
            rule,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_and_network_names() {
        let accept = [
            "a",
            "A",
            "0",
            "web",
            "Web-Frontend",
            "a-b",
            "a_b",
            "a--b",
            "a-_-b",
            "a0",
            "redis_6379",
            &"x".repeat(63),
        ];
        let reject = [
            "",
            "-a",               // leading dash
            "_a",               // leading underscore
            "a-",               // trailing dash
            "a_",               // trailing underscore
            "-",                // separator only
            "a.b",              // dot not allowed for services/networks
            "a b",              // space
            "a/b",              // slash
            "caf\u{e9}",        // unicode rejected
            "\u{4f60}\u{597d}", // unicode rejected
            &"x".repeat(64),    // too long
        ];
        for name in accept {
            assert!(
                validate_service_name(name).is_ok(),
                "expected accept: {name:?}"
            );
            assert!(
                validate_network_name(name).is_ok(),
                "expected accept: {name:?}"
            );
        }
        for name in reject {
            let err = validate_service_name(name).unwrap_err();
            assert_eq!(err.value, name);
            assert!(
                validate_network_name(name).is_err(),
                "expected reject: {name:?}"
            );
        }
    }

    #[test]
    fn secret_and_config_names() {
        let accept = [
            "a",
            "app.key",
            "app..key",
            "db-password_v2",
            "0secret9",
            "a.b-c_d",
            &"x".repeat(64),
        ];
        let reject = [
            "",
            ".a",            // leading dot
            "a.",            // trailing dot
            "-a",            // leading dash
            "a_",            // trailing underscore
            "a b",           // space
            "cl\u{e9}",      // unicode rejected
            &"x".repeat(65), // too long
        ];
        for name in accept {
            assert!(
                validate_secret_name(name).is_ok(),
                "expected accept: {name:?}"
            );
            assert!(
                validate_config_name(name).is_ok(),
                "expected accept: {name:?}"
            );
        }
        for name in reject {
            let err = validate_secret_name(name).unwrap_err();
            assert_eq!(err.value, name);
            assert!(
                validate_config_name(name).is_err(),
                "expected reject: {name:?}"
            );
        }
    }

    #[test]
    fn max_length_is_a_byte_bound_even_for_unicode() {
        // 32 two-byte characters: 64 bytes but still rejected by charset.
        let name = "\u{e9}".repeat(32);
        assert!(validate_secret_name(&name).is_err());
    }

    #[test]
    fn invalid_name_error_carries_value_and_rule() {
        let err = validate_service_name("-bad-").unwrap_err();
        assert_eq!(err.value, "-bad-");
        assert!(err.rule.contains("63"));
        let message = err.to_string();
        assert!(message.contains("-bad-"), "{message}");
    }

    #[test]
    fn task_name_formats_service_slot_and_id() {
        let id: Id = "1hvy0lj3x0b883f8e30fyp217".parse().unwrap();
        assert_eq!(
            task_name("web", "3", &id),
            "web.3.1hvy0lj3x0b883f8e30fyp217"
        );
        // Global tasks use the node ID in place of the slot.
        let node: Id = "2zrw1727u0mgg6ugs60vxe42e".parse().unwrap();
        assert_eq!(
            task_name("agent", node.as_str(), &id),
            "agent.2zrw1727u0mgg6ugs60vxe42e.1hvy0lj3x0b883f8e30fyp217"
        );
    }
}
