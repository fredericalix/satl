// SPDX-License-Identifier: BSD-2-Clause
//! Lowercase base36 encoding of a big-endian byte string, zero-padded to a
//! fixed width.
//!
//! Join tokens encode a SHA-256 digest (32 bytes → 50 characters) and a
//! 16-byte secret (→ 25 characters) exactly the way SwarmKit does
//! (`ca/certificates.go`: `big.Int.Text(36)` left-padded with `0`), which is
//! also the encoding [`satl_core::Id`] uses for object IDs.
//!
//! `satl-core` keeps its encoder private and specialized to 17-byte inputs, so
//! this is an independent implementation over arbitrary-length inputs. The
//! unit tests below re-check it against the same externally computed vectors
//! `satl-core` uses (see `crates/satl-core/src/id.rs`), which is what proves
//! the two agree.

/// Base36 digits, lowercase — the alphabet shared with [`satl_core::Id`].
const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Encodes `bytes` (interpreted as a big-endian integer) in lowercase base36,
/// left-padded with `0` to at least `min_width` characters.
///
/// Repeated division by 36 over the byte array; no bigint dependency. An
/// all-zero input encodes as `"0"` (then padded).
// The cast in the division loop cannot truncate: `rem < 36`, so
// `acc = rem * 256 + byte <= 35 * 256 + 255 = 9215` and `acc / 36 <= 255`.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn encode(bytes: &[u8], min_width: usize) -> String {
    let mut scratch = bytes.to_vec();
    // log36(2^8) ≈ 1.55 digits per byte.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
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
    while digits.len() < min_width {
        digits.push(b'0');
    }
    digits.reverse();
    digits.into_iter().map(char::from).collect()
}

/// Whether every character of `s` is a base36 digit (`[0-9a-z]`).
///
/// An empty string is *not* considered valid: callers always expect a
/// fixed-width field.
#[must_use]
pub fn is_base36(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact vectors `satl-core`'s private encoder is tested against
    /// (`crates/satl-core/src/id.rs`, computed independently with `bc(1)`:
    /// `echo "obase=36; 2^135" | bc`). Agreement on these is what pins this
    /// encoder to the one behind [`satl_core::Id`].
    #[test]
    fn agrees_with_satl_core_known_vectors() {
        let mut lowest = [0_u8; 17];
        lowest[0] = 0x80;
        assert_eq!(encode(&lowest, 0), "1hvy0lj3x0b883f8e30fyp21728");

        let highest = [0xff_u8; 17];
        assert_eq!(encode(&highest, 0), "2zrw1727u0mgg6ugs60vxe42e4f");

        let mut mixed = [0_u8; 17];
        for (i, byte) in mixed.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("index < 17 fits in u8");
        }
        mixed[0] = 0x80;
        assert_eq!(encode(&mixed, 0), "1hw05xdvcpbrfi4jekqvbjy4b2o");
    }

    /// Cross-check: a fresh [`satl_core::Id`] is the first 25 characters of a
    /// 27-digit base36 string, so anything this encoder produces for a 17-byte
    /// top-bit-set input must have the same shape and alphabet.
    #[test]
    fn agrees_with_satl_core_id_shape() {
        for _ in 0..64 {
            let id = satl_core::Id::generate();
            assert_eq!(id.as_str().len(), 25);
            assert!(is_base36(id.as_str()), "{id} is not base36");
        }
        let mut widest = [0xff_u8; 17];
        widest[0] = 0x80;
        assert_eq!(encode(&widest, 0).len(), 27);
    }

    #[test]
    fn small_values() {
        assert_eq!(encode(&[], 0), "0");
        assert_eq!(encode(&[0], 0), "0");
        assert_eq!(encode(&[0, 0, 0], 0), "0");
        assert_eq!(encode(&[35], 0), "z");
        assert_eq!(encode(&[36], 0), "10");
        assert_eq!(encode(&[1, 0], 0), "74"); // 256 = 7*36 + 4
    }

    #[test]
    fn padding_is_left_aligned_and_never_truncates() {
        assert_eq!(encode(&[1], 5), "00001");
        assert_eq!(encode(&[], 3), "000");
        // min_width is a minimum, not a maximum.
        assert_eq!(encode(&[0xff_u8; 17], 3).len(), 27);
    }

    /// 2^128 - 1 is the widest 16-byte secret; 2^256 - 1 the widest digest.
    /// Both must fit the field widths the token format pins.
    #[test]
    fn token_field_widths_are_sufficient() {
        assert_eq!(encode(&[0xff_u8; 16], 25).len(), 25);
        assert_eq!(encode(&[0xff_u8; 32], 50).len(), 50);
        assert_eq!(encode(&[0_u8; 16], 25), "0".repeat(25));
        assert_eq!(encode(&[0_u8; 32], 50), "0".repeat(50));
    }

    #[test]
    fn base36_alphabet_check() {
        assert!(is_base36("0123456789abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_base36(""));
        assert!(!is_base36("ABC"));
        assert!(!is_base36("ab-cd"));
        assert!(!is_base36("ab\u{e9}"));
    }
}
