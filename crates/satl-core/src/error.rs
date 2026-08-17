// SPDX-License-Identifier: BSD-2-Clause
//! Error types shared by the domain model (see `docs/architecture.md` §3–§4).
//!
//! Library-crate errors use `thiserror` per project convention; every error
//! carries the offending input so operator-facing messages can say exactly
//! what was rejected.

use crate::state::TaskState;

/// An object ID failed validation (architecture §3: 25 chars base36).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid object id {value:?}: must be exactly 25 base36 characters [0-9a-z]")]
pub struct InvalidId {
    /// The rejected input.
    pub value: String,
}

/// An object name failed validation (architecture §3, SWK §3.2 naming rules).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid name {value:?}: {rule}")]
pub struct InvalidName {
    /// The rejected input.
    pub value: String,
    /// Human-readable description of the rule that was violated.
    pub rule: &'static str,
}

/// A CIDR string failed to parse (architecture §11.3).
///
/// Addressing reaches the daemon as text — `--subnet`, `--gateway`, the
/// cluster's address pools — and the operator needs to know which value was
/// rejected and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid CIDR {value:?}: {reason}")]
pub struct InvalidCidr {
    /// The rejected input.
    pub value: String,
    /// Human-readable description of what was wrong with it.
    pub reason: &'static str,
}

/// A MAC address string failed to parse (architecture §11.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid MAC address {value:?}: expected six colon-separated hex octets, e.g. 02:42:0a:64:04:05"
)]
pub struct InvalidMac {
    /// The rejected input.
    pub value: String,
}

/// A placement constraint expression failed to parse (SWK §8.7).
///
/// Every variant names the offending expression: constraints reach us from
/// `--constraint` on the CLI, and the operator needs to know *which* of them
/// was rejected, not just that one was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidConstraint {
    /// Neither `==` nor `!=` appears in the expression.
    #[error("invalid constraint {expression:?}: expected one operator from ==, !=")]
    Operator {
        /// The rejected expression.
        expression: String,
    },
    /// The left-hand side is not a valid constraint key.
    #[error("invalid constraint {expression:?}: key {key:?} must match ^(?i)[a-z_][a-z0-9\\-_.]+$")]
    Key {
        /// The rejected expression.
        expression: String,
        /// The key that was extracted from it.
        key: String,
    },
    /// The right-hand side uses characters the value charset excludes.
    #[error(
        "invalid constraint {expression:?}: value {value:?} may only contain alphanumerics, \
         whitespace and : - _ . * ( ) ? + [ ] \\ ^ $ | /"
    )]
    Value {
        /// The rejected expression.
        expression: String,
        /// The value that was extracted from it.
        value: String,
    },
}

/// A proposed task state transition would move backwards (architecture §4 rule 1).
///
/// Task states are a Lamport clock: observed state never decreases. SwarmKit
/// panics on regression; SatL returns this typed error instead so callers can
/// log at error level and count the occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid task state transition: {from} -> {to} would move the state backwards")]
pub struct InvalidTransition {
    /// The currently observed state.
    pub from: TaskState,
    /// The rejected, regressing proposal.
    pub to: TaskState,
}

/// A spec failed semantic validation (size limits and similar).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// Secret payload outside `1..MAX_SECRET_SIZE` bytes (architecture §12.4, SWK §3.8).
    #[error("secret data is {size} bytes: must be at least 1 and less than {max} bytes")]
    SecretDataSize {
        /// Actual payload size in bytes.
        size: usize,
        /// The exclusive upper bound ([`crate::defaults::MAX_SECRET_SIZE`]).
        max: usize,
    },
    /// Config payload outside `1..MAX_CONFIG_SIZE` bytes (architecture §12.4, SWK §3.8).
    #[error("config data is {size} bytes: must be at least 1 and less than {max} bytes")]
    ConfigDataSize {
        /// Actual payload size in bytes.
        size: usize,
        /// The exclusive upper bound ([`crate::defaults::MAX_CONFIG_SIZE`]).
        max: usize,
    },
}
