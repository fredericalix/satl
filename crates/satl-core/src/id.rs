// SPDX-License-Identifier: BSD-2-Clause
//! Random object identifiers (architecture §3, SWK §3.2).
//!
//! IDs follow SwarmKit's format exactly: 17 bytes from a CSPRNG with the top
//! bit of byte 0 forced to 1, interpreted as a big-endian integer, encoded in
//! lowercase base36, truncated to 25 characters (~129 bits of entropy). The
//! forced top bit guarantees the full encoding is always 27 digits, so the
//! truncated form is always exactly 25 characters. IDs are opaque strings;
//! prefix match is supported in lookups.

use std::fmt;
use std::str::FromStr;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::InvalidId;

/// Number of random bytes drawn per ID (SWK §3.2).
const ID_BYTES: usize = 17;

/// Length of the textual (base36) form of an [`Id`].
pub const ID_LENGTH: usize = 25;

/// Base36 digits, lowercase.
const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Opaque object identifier: exactly 25 lowercase base36 characters.
///
/// Serialized as a plain string; deserialization validates the format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    /// Generates a fresh random ID from the process CSPRNG.
    ///
    /// `rand::rng()` is a cryptographically secure generator periodically
    /// reseeded from the OS entropy source, matching SwarmKit's use of
    /// `crypto/rand`.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; ID_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        // Force the top bit so the big-endian value is always >= 2^135,
        // which makes the base36 encoding a fixed 27 digits (SWK §3.2).
        bytes[0] |= 0x80;
        let mut encoded = base36(&bytes);
        encoded.truncate(ID_LENGTH);
        debug_assert_eq!(encoded.len(), ID_LENGTH);
        Self(encoded)
    }

    /// The textual form of the ID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this ID starts with `prefix` (used for prefix lookups).
    ///
    /// An empty prefix matches nothing: lookups must be anchored to at least
    /// one character, as in SwarmKit's prefix resolution.
    #[must_use]
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        !prefix.is_empty() && self.0.starts_with(prefix)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Id {
    type Err = InvalidId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if is_valid_id(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidId {
                value: s.to_owned(),
            })
        }
    }
}

impl TryFrom<String> for Id {
    type Error = InvalidId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_valid_id(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidId { value })
        }
    }
}

impl From<Id> for String {
    fn from(id: Id) -> Self {
        id.0
    }
}

/// Validates the textual ID form: exactly 25 chars of `[0-9a-z]`.
fn is_valid_id(s: &str) -> bool {
    s.len() == ID_LENGTH
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

/// Encodes a big-endian byte string as lowercase base36.
///
/// Manual repeated division over the byte array (no bigint dependency): each
/// pass divides the whole number by 36, emitting one digit; leading zero
/// bytes are skipped as they accumulate. Returns `"0"` for an all-zero input.
// The cast in the division loop cannot truncate: `rem < 36`, so
// `acc = rem * 256 + byte <= 35 * 256 + 255 = 9215` and `acc / 36 <= 255`.
#[allow(clippy::cast_possible_truncation)]
fn base36(bytes: &[u8; ID_BYTES]) -> String {
    let mut scratch = *bytes;
    // 17 bytes = 136 bits; log36(2^136) < 27 digits.
    let mut digits: Vec<u8> = Vec::with_capacity(27);
    let mut start = 0;
    while start < scratch.len() {
        let mut rem: u32 = 0;
        for byte in &mut scratch[start..] {
            let acc = rem * 256 + u32::from(*byte);
            *byte = (acc / 36) as u8;
            rem = acc % 36;
        }
        digits.push(ALPHABET[rem as usize]);
        while start < scratch.len() && scratch[start] == 0 {
            start += 1;
        }
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    digits.reverse();
    digits.into_iter().map(char::from).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn generated_ids_have_the_documented_format() {
        for _ in 0..256 {
            let id = Id::generate();
            assert_eq!(id.as_str().len(), ID_LENGTH);
            assert!(
                id.as_str()
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()),
                "unexpected character in {id}"
            );
        }
    }

    #[test]
    fn generated_ids_are_unique() {
        let ids: HashSet<Id> = (0..1000).map(|_| Id::generate()).collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn base36_known_vectors() {
        // Reference values computed independently with bc(1):
        //   echo "obase=36; 2^135" | bc            (bytes 80 00 .. 00)
        //   echo "obase=36; 2^136-1" | bc          (bytes ff ff .. ff)
        //   echo "obase=36; ibase=16; 8001...0F10" | bc
        let mut lowest = [0_u8; ID_BYTES];
        lowest[0] = 0x80;
        assert_eq!(base36(&lowest), "1hvy0lj3x0b883f8e30fyp21728");

        let highest = [0xff_u8; ID_BYTES];
        assert_eq!(base36(&highest), "2zrw1727u0mgg6ugs60vxe42e4f");

        let mut mixed = [0_u8; ID_BYTES];
        for (i, byte) in mixed.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        mixed[0] = 0x80;
        assert_eq!(base36(&mixed), "1hw05xdvcpbrfi4jekqvbjy4b2o");
    }

    #[test]
    fn base36_handles_small_values() {
        let zero = [0_u8; ID_BYTES];
        assert_eq!(base36(&zero), "0");

        let mut thirty_five = [0_u8; ID_BYTES];
        thirty_five[ID_BYTES - 1] = 35;
        assert_eq!(base36(&thirty_five), "z");

        let mut thirty_six = [0_u8; ID_BYTES];
        thirty_six[ID_BYTES - 1] = 36;
        assert_eq!(base36(&thirty_six), "10");
    }

    #[test]
    fn top_bit_forces_fixed_length_encoding() {
        // The smallest and largest possible generated values both encode to
        // 27 digits, so truncation always yields exactly 25 characters.
        let mut lowest = [0_u8; ID_BYTES];
        lowest[0] = 0x80;
        assert_eq!(base36(&lowest).len(), 27);
        assert_eq!(base36(&[0xff_u8; ID_BYTES]).len(), 27);
    }

    #[test]
    fn display_from_str_roundtrip() {
        let id = Id::generate();
        let parsed: Id = id.to_string().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn from_str_rejects_bad_input() {
        let cases = [
            "",
            "short",
            "1hvy0lj3x0b883f8e30fyp21",       // 24 chars
            "1hvy0lj3x0b883f8e30fyp2172",     // 26 chars
            "1HVY0LJ3X0B883F8E30FYP217",      // uppercase
            "1hvy0lj3x0b883f8e30fyp21-",      // punctuation
            "1hvy0lj3x0b883f8e30fyp21\u{e9}", // non-ASCII
        ];
        for case in cases {
            let err = case.parse::<Id>().unwrap_err();
            assert_eq!(err.value, case, "case {case:?}");
        }
    }

    #[test]
    fn serde_roundtrips_as_plain_string() {
        let id = Id::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        let back: Id = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn serde_rejects_invalid_strings() {
        assert!(serde_json::from_str::<Id>("\"not an id\"").is_err());
    }

    #[test]
    fn prefix_matching() {
        let id: Id = "1hvy0lj3x0b883f8e30fyp217".parse().unwrap();
        assert!(id.matches_prefix("1hvy"));
        assert!(id.matches_prefix("1hvy0lj3x0b883f8e30fyp217"));
        assert!(!id.matches_prefix("hvy0"));
        assert!(!id.matches_prefix(""), "empty prefix must match nothing");
        assert!(!id.matches_prefix("1hvy0lj3x0b883f8e30fyp2172"));
    }
}
