// SPDX-License-Identifier: BSD-2-Clause
//! Placement constraint expressions (SWK §8.7).
//!
//! The language is SwarmKit's, verbatim — `docker service create
//! --constraint 'node.labels.zone == a'` must behave the same here as on
//! Docker Swarm (invariant #8). It is evaluated in three places, so it lives
//! in `satl-core` rather than the scheduler (architecture §2 assigns
//! "constraint expressions" to this crate): the scheduler's constraint filter
//! (SWK §8.3), the global orchestrator's node set (SWK §7.8), and the
//! constraint enforcer (SWK §7.6).
//!
//! Grammar:
//!
//! - `key op value`, with `op` exactly `==` or `!=`. The operator is found by
//!   substring search in that order — **`==` wins whenever the expression
//!   contains one**, wherever it sits — and the expression is split once, at
//!   that first occurrence. Both sides are then trimmed.
//! - Keys match `^(?i)[a-z_][a-z0-9\-_.]+$` (so: at least two characters).
//! - Values are alphanumerics plus `: - _ . * ( ) ? + [ ] \ ^ $ | /` and
//!   whitespace. The set deliberately excludes characters that future
//!   operators might use (`< > ~`), and the metacharacters it does allow are
//!   **not** interpreted: matching is plain full-string equality, never
//!   globbing or regex.
//!
//! Matching: case-insensitive full-string equality; a node satisfies a
//! constraint set iff **every** constraint matches. Missing values (no node
//! description, absent label) compare as the empty string, so `!=` matches
//! them and `==` does not. Label *names* are case-sensitive even though keys
//! are not. An unrecognized key fails the node — a typo excludes every node
//! rather than silently placing tasks anywhere.
//!
//! Implementation note: the validators are hand-rolled character logic, like
//! [`crate::naming`], instead of pulling `regex` into the workspace root
//! crate. Both patterns reduce to "first character from set A, rest from
//! set B", and non-ASCII input fails every character check. `node.ip`
//! likewise parses addresses with `std::net` and masks CIDR prefixes by hand
//! (~30 lines) rather than adding an IP-network dependency.

use std::net::IpAddr;

use crate::error::InvalidConstraint;
use crate::objects::{Node, NodeRole};

/// Key prefix for constraints against node spec labels.
const NODE_LABEL_PREFIX: &str = "node.labels.";

/// Key prefix for constraints against engine labels.
const ENGINE_LABEL_PREFIX: &str = "engine.labels.";

/// Characters allowed in a constraint value on top of ASCII alphanumerics and
/// ASCII whitespace (SWK §8.7).
const VALUE_PUNCTUATION: &[u8] = b":-_.*()?+[]\\^$|/";

/// The two comparison operators the language accepts, in the order they are
/// searched for (SWK §8.7: the first one *present* in the expression wins).
const OPERATORS: [(&str, Operator); 2] = [("==", Operator::Equal), ("!=", Operator::NotEqual)];

/// Comparison operator of a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// `==`: the node value must equal the constraint value.
    Equal,
    /// `!=`: the node value must differ from the constraint value.
    NotEqual,
}

impl Operator {
    /// The operator's source spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
        }
    }

    /// Applies the operator to a raw "the values are equal" verdict.
    fn holds(self, equal: bool) -> bool {
        match self {
            Self::Equal => equal,
            Self::NotEqual => !equal,
        }
    }
}

/// One parsed placement constraint, e.g. `node.labels.zone == a`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    key: String,
    operator: Operator,
    value: String,
}

impl Constraint {
    /// Parses one `key op value` expression (SWK §8.7).
    pub fn parse(expression: &str) -> Result<Self, InvalidConstraint> {
        for (token, operator) in OPERATORS {
            let Some(at) = expression.find(token) else {
                continue;
            };
            let (key, value) = expression.split_at(at);
            let key = key.trim();
            let value = value[token.len()..].trim();
            if !valid_key(key) {
                return Err(InvalidConstraint::Key {
                    expression: expression.to_owned(),
                    key: key.to_owned(),
                });
            }
            if !valid_value(value) {
                return Err(InvalidConstraint::Value {
                    expression: expression.to_owned(),
                    value: value.to_owned(),
                });
            }
            return Ok(Self {
                key: key.to_owned(),
                operator,
                value: value.to_owned(),
            });
        }
        Err(InvalidConstraint::Operator {
            expression: expression.to_owned(),
        })
    }

    /// The constraint key, as written (`node.labels.Zone`, `node.role`, …).
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The comparison operator.
    #[must_use]
    pub fn operator(&self) -> Operator {
        self.operator
    }

    /// The right-hand side, as written.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether `node` satisfies this constraint (SWK §8.7).
    ///
    /// Unknown keys and malformed `node.ip` values fail the node.
    #[must_use]
    pub fn matches(&self, node: &Node) -> bool {
        let key = self.key.as_str();
        if key.eq_ignore_ascii_case("node.id") {
            return self.compare(node.id.as_str());
        }
        if key.eq_ignore_ascii_case("node.hostname") {
            return self.compare(description_str(node, |d| d.hostname.as_str()));
        }
        if key.eq_ignore_ascii_case("node.ip") {
            return self.matches_ip(&node.status.addr);
        }
        if key.eq_ignore_ascii_case("node.role") {
            return self.compare(role_name(node.spec.role));
        }
        if key.eq_ignore_ascii_case("node.platform.os") {
            return self.compare(description_str(node, |d| d.platform.os.as_str()));
        }
        if key.eq_ignore_ascii_case("node.platform.arch") {
            return self.compare(description_str(node, |d| d.platform.arch.as_str()));
        }
        // Label names are case-sensitive; only the prefix folds.
        if let Some(label) = strip_prefix_ignore_case(key, NODE_LABEL_PREFIX) {
            let value = node.spec.labels.get(label).map_or("", String::as_str);
            return self.compare(value);
        }
        if let Some(label) = strip_prefix_ignore_case(key, ENGINE_LABEL_PREFIX) {
            let value = node
                .description
                .as_ref()
                .and_then(|d| d.engine.labels.get(label))
                .map_or("", String::as_str);
            return self.compare(value);
        }
        // Key doesn't match the predefined syntax.
        false
    }

    /// Case-insensitive full-string comparison, then the operator.
    fn compare(&self, what: &str) -> bool {
        self.operator.holds(self.value.eq_ignore_ascii_case(what))
    }

    /// `node.ip`: the value is either an address (equality) or a CIDR block
    /// (containment). A malformed value fails the node under **either**
    /// operator — an unparseable constraint is never silently satisfied.
    fn matches_ip(&self, addr: &str) -> bool {
        let node_ip = addr.parse::<IpAddr>().ok().map(canonical_ip);
        if let Ok(ip) = self.value.parse::<IpAddr>() {
            return self.operator.holds(node_ip == Some(canonical_ip(ip)));
        }
        if let Some(subnet) = Cidr::parse(&self.value) {
            return self
                .operator
                .holds(node_ip.is_some_and(|ip| subnet.contains(ip)));
        }
        false
    }
}

/// A parsed set of constraints; a node matches iff it satisfies all of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraints(Vec<Constraint>);

impl Constraints {
    /// Parses every expression, failing on the first invalid one.
    pub fn parse_all(expressions: &[String]) -> Result<Self, InvalidConstraint> {
        expressions
            .iter()
            .map(|expression| Constraint::parse(expression))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Whether `node` satisfies **every** constraint in the set.
    #[must_use]
    pub fn matches(&self, node: &Node) -> bool {
        self.0.iter().all(|constraint| constraint.matches(node))
    }

    /// The parsed constraints.
    #[must_use]
    pub fn as_slice(&self) -> &[Constraint] {
        &self.0
    }

    /// Number of constraints in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty (matches every node).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `^(?i)[a-z_][a-z0-9\-_.]+$` — note the `+`: keys are at least 2 characters.
fn valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    if rest.is_empty() || !(first.is_ascii_alphabetic() || *first == b'_') {
        return false;
    }
    rest.iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Alphanumerics, [`VALUE_PUNCTUATION`] and whitespace; at least one byte.
fn valid_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b.is_ascii_whitespace() || VALUE_PUNCTUATION.contains(&b)
        })
}

/// Case-insensitive [`str::strip_prefix`]; `None` when the remainder would be
/// empty (`node.labels.` alone is not a label constraint, it is a bad key).
fn strip_prefix_ignore_case<'a>(key: &'a str, prefix: &str) -> Option<&'a str> {
    if key.len() > prefix.len() && key[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&key[prefix.len()..])
    } else {
        None
    }
}

/// The spelling `node.role` constraints compare against.
fn role_name(role: NodeRole) -> &'static str {
    match role {
        NodeRole::Worker => "worker",
        NodeRole::Manager => "manager",
    }
}

/// A field of the node description, or `""` when the node has never
/// described itself (SWK §8.7: missing values compare as empty).
fn description_str(node: &Node, pick: fn(&crate::objects::NodeDescription) -> &str) -> &str {
    node.description.as_ref().map_or("", pick)
}

/// IPv4-mapped IPv6 addresses compare equal to their IPv4 form, as they do in
/// Go's `net` package (which SwarmKit's implementation relies on).
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// An address block, e.g. `10.2.0.0/16`. Host bits are masked off at parse
/// time, as `net.ParseCIDR` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u32,
}

impl Cidr {
    /// Parses `<address>/<prefix-length>`; `None` on anything malformed.
    fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.split_once('/')?;
        let addr = canonical_ip(addr.parse::<IpAddr>().ok()?);
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u32 = prefix.parse().ok()?;
        if prefix > Self::bits(addr) {
            return None;
        }
        Some(Self { addr, prefix })
    }

    /// Whether `ip` falls inside the block. Mixed address families never
    /// match (an IPv4 block does not contain an IPv6 address).
    fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }

    /// Address width in bits.
    fn bits(addr: IpAddr) -> u32 {
        match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}

/// Whether two addresses agree on their first `prefix` bits.
fn prefix_eq(a: &[u8], b: &[u8], prefix: u32) -> bool {
    let whole = (prefix / 8) as usize;
    let bits = prefix % 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    a[whole] & mask == b[whole] & mask
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::id::Id;
    use crate::meta::Meta;
    use crate::objects::{
        Availability, CertificateStatus, EngineDescription, NodeDescription, NodeSpec, NodeState,
        NodeStatus, Platform, Resources,
    };

    use super::*;

    /// A node with everything the language can look at filled in.
    fn node() -> Node {
        Node {
            id: "1hvy0lj3x0b883f8e30fyp217".parse::<Id>().unwrap(),
            meta: Meta::new(),
            spec: NodeSpec {
                name: Some("alpha".to_owned()),
                labels: BTreeMap::from([
                    ("zone".to_owned(), "A".to_owned()),
                    ("Zone".to_owned(), "b".to_owned()),
                    ("empty".to_owned(), String::new()),
                ]),
                role: NodeRole::Manager,
                availability: Availability::Active,
            },
            description: Some(NodeDescription {
                hostname: "Alpha.example.com".to_owned(),
                platform: Platform {
                    os: "freebsd".to_owned(),
                    arch: "amd64".to_owned(),
                },
                resources: Resources::default(),
                engine: EngineDescription {
                    version: "0.1.0".to_owned(),
                    labels: BTreeMap::from([("tier".to_owned(), "ssd".to_owned())]),
                },
                linux_emulation: true,
                racct_enabled: false,
                data_addr: None,
            }),
            status: NodeStatus {
                state: NodeState::Ready,
                message: String::new(),
                addr: "10.2.0.11".to_owned(),
            },
            manager_status: None,
            certificate_status: CertificateStatus::Issued,
            certificate_issuer: None,
        }
    }

    /// The same node before its first session: no description at all.
    fn undescribed_node() -> Node {
        let mut node = node();
        node.description = None;
        node.spec.labels.clear();
        node.status.addr = String::new();
        node
    }

    fn parse(expression: &str) -> Constraint {
        Constraint::parse(expression).expect("valid constraint")
    }

    #[test]
    fn parses_key_operator_and_value() {
        let cases = [
            ("node.role==worker", "node.role", Operator::Equal, "worker"),
            (
                "  node.labels.zone   ==   a  ",
                "node.labels.zone",
                Operator::Equal,
                "a",
            ),
            (
                "engine.labels.tier != ssd",
                "engine.labels.tier",
                Operator::NotEqual,
                "ssd",
            ),
            // Dots, dashes and underscores are all legal key characters, and
            // the key may start with an underscore.
            (
                "node.labels._my-key.sub == v",
                "node.labels._my-key.sub",
                Operator::Equal,
                "v",
            ),
            // Value metacharacters are stored verbatim, never interpreted.
            (
                "node.labels.zone == a*b?[c]|d",
                "node.labels.zone",
                Operator::Equal,
                "a*b?[c]|d",
            ),
            // Interior whitespace survives trimming.
            (
                "node.labels.desc == two words",
                "node.labels.desc",
                Operator::Equal,
                "two words",
            ),
        ];
        for (expression, key, operator, value) in cases {
            let constraint = parse(expression);
            assert_eq!(constraint.key(), key, "{expression}");
            assert_eq!(constraint.operator(), operator, "{expression}");
            assert_eq!(constraint.value(), value, "{expression}");
        }
    }

    #[test]
    fn equal_wins_over_not_equal_wherever_it_appears() {
        // `==` is searched for first, so an expression containing both is
        // split on `==` — here that leaves an invalid key (SWK §8.7).
        let err = Constraint::parse("node.labels.zone != a==b").unwrap_err();
        assert!(
            matches!(&err, InvalidConstraint::Key { key, .. } if key == "node.labels.zone != a"),
            "{err:?}"
        );
    }

    #[test]
    fn not_equal_inside_a_value_is_rejected_by_the_value_charset() {
        // Split at the first `!=`, leaving `a!=b` as the value: `!` is not an
        // allowed value character, so the whole expression is invalid.
        let err = Constraint::parse("node.labels.zone != a!=b").unwrap_err();
        assert!(
            matches!(&err, InvalidConstraint::Value { value, .. } if value == "a!=b"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_malformed_expressions() {
        let missing_operator = [
            "node.labels.zone",
            "node.labels.zone = a",
            "node.labels.zone > a",
            "",
        ];
        for expression in missing_operator {
            let err = Constraint::parse(expression).unwrap_err();
            assert!(
                matches!(err, InvalidConstraint::Operator { .. }),
                "{expression:?}: {err:?}"
            );
            assert!(err.to_string().contains(expression), "{err}");
        }

        let bad_key = [
            "== a",           // empty key
            "n == a",         // one character: the regex needs two
            "1node == a",     // must start with a letter or underscore
            ".node == a",     // ditto
            "node zone == a", // space inside the key
            "node/zone == a", // slash is not a key character
            "caf\u{e9} == a", // non-ASCII
        ];
        for expression in bad_key {
            let err = Constraint::parse(expression).unwrap_err();
            assert!(
                matches!(err, InvalidConstraint::Key { .. }),
                "{expression:?}: {err:?}"
            );
            assert!(err.to_string().contains(expression), "{err}");
        }

        let bad_value = [
            "node.labels.zone ==",           // empty value
            "node.labels.zone == a>b",       // future operator characters
            "node.labels.zone == a<b",       // ditto
            "node.labels.zone == a~b",       // ditto
            "node.labels.zone == a!b",       // ditto
            "node.labels.zone == caf\u{e9}", // non-ASCII
        ];
        for expression in bad_value {
            let err = Constraint::parse(expression).unwrap_err();
            assert!(
                matches!(err, InvalidConstraint::Value { .. }),
                "{expression:?}: {err:?}"
            );
            assert!(err.to_string().contains(expression), "{err}");
        }
    }

    #[test]
    fn every_allowed_value_character_parses() {
        let value = "aZ09:-_. */()?+[]\\^$|";
        let constraint = parse(&format!("node.labels.k == {value}"));
        // Leading/trailing whitespace is trimmed, the rest is kept.
        assert_eq!(constraint.value(), value.trim());
    }

    #[test]
    fn matches_the_documented_key_matrix() {
        let node = node();
        // (expression, matches)
        let cases = [
            ("node.id == 1hvy0lj3x0b883f8e30fyp217", true),
            ("node.id == 1HVY0LJ3X0B883F8E30FYP217", true), // values fold
            ("node.id != 1hvy0lj3x0b883f8e30fyp217", false),
            ("node.id == deadbeef", false),
            ("NODE.ID == 1hvy0lj3x0b883f8e30fyp217", true), // keys fold
            ("node.hostname == alpha.example.com", true),
            ("node.hostname == alpha", false), // full string, no prefixes
            ("node.hostname != alpha.example.com", false),
            ("node.hostname == alpha.*", false), // globbing is not interpreted
            ("node.role == manager", true),
            ("node.role == worker", false),
            ("node.role != worker", true),
            ("node.platform.os == freebsd", true),
            ("node.platform.os == linux", false),
            ("node.platform.arch == amd64", true),
            ("node.platform.arch != arm64", true),
            ("node.labels.zone == A", true),
            ("node.labels.zone == a", true), // value comparison folds
            ("node.labels.Zone == b", true), // label name does not
            ("node.labels.zone == b", false),
            ("node.labels.missing == a", false),
            ("node.labels.missing != a", true), // absent label reads as ""
            ("engine.labels.tier == ssd", true),
            ("engine.labels.tier == hdd", false),
            ("engine.labels.missing != x", true),
            ("ENGINE.LABELS.tier == ssd", true), // prefix folds, name does not
            ("engine.labels.TIER == ssd", false),
            // Unknown keys fail the node under either operator.
            ("node.nonsense == whatever", false),
            ("node.nonsense != whatever", false),
            ("node.label.zone == A", false), // typo: "label", not "labels"
            ("node.labels. == A", false),    // empty label name
        ];
        for (expression, expected) in cases {
            assert_eq!(parse(expression).matches(&node), expected, "{expression}");
        }
    }

    #[test]
    fn missing_values_compare_as_empty_string() {
        let node = undescribed_node();
        let cases = [
            ("node.hostname == alpha", false),
            ("node.hostname != alpha", true),
            ("node.platform.os == freebsd", false),
            ("node.platform.os != freebsd", true),
            ("node.platform.arch != amd64", true),
            ("node.labels.zone != a", true),
            ("engine.labels.tier != ssd", true),
            // The node ID and role are always present.
            ("node.role == manager", true),
        ];
        for (expression, expected) in cases {
            assert_eq!(parse(expression).matches(&node), expected, "{expression}");
        }
    }

    #[test]
    fn node_ip_matches_addresses_and_cidr_blocks() {
        let mut node = node();
        let cases = [
            ("node.ip == 10.2.0.11", true),
            ("node.ip == 10.2.0.12", false),
            ("node.ip != 10.2.0.12", true),
            ("node.ip == 10.2.0.0/16", true),
            ("node.ip == 10.2.0.0/24", true),
            ("node.ip == 10.2.0.8/29", true), // .11 is inside .8/29
            ("node.ip == 10.2.0.0/29", false),
            ("node.ip == 10.3.0.0/16", false),
            ("node.ip != 10.3.0.0/16", true),
            ("node.ip == 0.0.0.0/0", true),
            // Host bits in the block are masked off, as net.ParseCIDR does.
            ("node.ip == 10.2.0.99/16", true),
            // Mixed families never match.
            ("node.ip == 2001:db8::/32", false),
            // Malformed values fail the node under either operator.
            ("node.ip == 10.2.0.0/33", false),
            ("node.ip != 10.2.0.0/33", false),
            ("node.ip == 10.2.0.999", false),
            ("node.ip != 10.2.0.999", false),
            ("node.ip == not-an-address", false),
            ("node.ip != not-an-address", false),
            ("node.ip == 10.2.0.0/", false),
        ];
        for (expression, expected) in cases {
            assert_eq!(parse(expression).matches(&node), expected, "{expression}");
        }

        // A node with no (or an unparseable) address matches nothing under
        // `==` and everything under `!=` — Go's net.ParseIP returns nil and
        // neither Equal nor Contains can succeed against it.
        for addr in ["", "not-an-address"] {
            node.status.addr = addr.to_owned();
            assert!(!parse("node.ip == 10.2.0.11").matches(&node), "{addr:?}");
            assert!(parse("node.ip != 10.2.0.11").matches(&node), "{addr:?}");
            assert!(parse("node.ip != 10.2.0.0/16").matches(&node), "{addr:?}");
        }
    }

    #[test]
    fn node_ip_handles_ipv6_and_v4_mapped_forms() {
        let mut node = node();
        node.status.addr = "2001:db8::2".to_owned();
        assert!(parse("node.ip == 2001:db8::2").matches(&node));
        assert!(parse("node.ip == 2001:db8::/32").matches(&node));
        assert!(!parse("node.ip == 2001:db9::/32").matches(&node));
        assert!(parse("node.ip != 2001:db9::/32").matches(&node));
        assert!(!parse("node.ip == 10.0.0.0/8").matches(&node));

        // ::ffff:10.2.0.11 and 10.2.0.11 are the same address.
        node.status.addr = "::ffff:10.2.0.11".to_owned();
        assert!(parse("node.ip == 10.2.0.11").matches(&node));
        assert!(parse("node.ip == 10.2.0.0/16").matches(&node));
    }

    #[test]
    fn a_node_must_satisfy_every_constraint() {
        let node = node();
        let all = |exprs: &[&str]| {
            let owned: Vec<String> = exprs.iter().map(|e| (*e).to_string()).collect();
            Constraints::parse_all(&owned)
                .expect("valid")
                .matches(&node)
        };
        assert!(all(&["node.role == manager", "node.labels.zone == a"]));
        assert!(!all(&["node.role == manager", "node.labels.zone == z"]));
        assert!(!all(&["node.role == worker", "node.labels.zone == a"]));
        // An empty set matches everything.
        assert!(Constraints::default().matches(&node));
        assert!(Constraints::default().is_empty());
    }

    #[test]
    fn parse_all_reports_the_offending_expression() {
        let expressions = vec![
            "node.role == manager".to_owned(),
            "node.labels.zone <> a".to_owned(),
        ];
        let err = Constraints::parse_all(&expressions).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("node.labels.zone <> a"), "{message}");
        assert!(!message.contains("node.role"), "{message}");

        let ok = Constraints::parse_all(&expressions[..1]).expect("valid");
        assert_eq!(ok.len(), 1);
        assert_eq!(ok.as_slice()[0].key(), "node.role");
    }

    #[test]
    fn operator_spellings_round_trip() {
        assert_eq!(Operator::Equal.as_str(), "==");
        assert_eq!(Operator::NotEqual.as_str(), "!=");
        assert_eq!(parse("node.role == manager").operator().as_str(), "==");
    }
}
