// SPDX-License-Identifier: BSD-2-Clause
//! Object metadata envelope (architecture §3, SWK §3.1).

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Object version: the Raft log index at the mutation that last wrote the
/// object. Powers optimistic concurrency — updates carry the caller's copy
/// and fail with a sequence conflict on mismatch (architecture §3).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Version(pub u64);

/// Common metadata carried by every store object (architecture §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Raft log index of the last write to this object.
    pub version: Version,
    /// Wall-clock creation time (manager clock).
    pub created_at: SystemTime,
    /// Wall-clock time of the last update (manager clock).
    pub updated_at: SystemTime,
}

impl Meta {
    /// Fresh metadata for a newly created object: version 0, both timestamps
    /// set to now. The store stamps the real version when the create commits.
    #[must_use]
    pub fn new() -> Self {
        let now = SystemTime::now();
        Self {
            version: Version(0),
            created_at: now,
            updated_at: now,
        }
    }
}

impl Default for Meta {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_meta_starts_at_version_zero() {
        let meta = Meta::new();
        assert_eq!(meta.version, Version(0));
        assert_eq!(meta.created_at, meta.updated_at);
    }

    #[test]
    fn version_orders_numerically() {
        assert!(Version(1) < Version(2));
        assert!(Version(100) > Version(99));
    }

    #[test]
    fn serde_roundtrip() {
        let meta = Meta::new();
        let json = serde_json::to_string(&meta).unwrap();
        let back: Meta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
    }

    #[test]
    fn version_serializes_as_plain_number() {
        assert_eq!(serde_json::to_string(&Version(42)).unwrap(), "42");
    }
}
