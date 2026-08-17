// SPDX-License-Identifier: BSD-2-Clause
//! The DNS wire format: enough of RFC 1035 to answer service-discovery
//! queries, and nothing else (architecture §11.5).
//!
//! **Why this codec is hand-rolled.** A DNS crate would bring a parser for
//! the whole record space (zones, DNSSEC, EDNS, dynamic update) plus its
//! transitive dependencies into a process that reads untrusted datagrams
//! from inside containers: a container is the least trusted thing on the
//! node, and it can reach this responder by design. The subset SatL needs is
//! small — one question, `A`/`AAAA`, class `IN`, no recursion of our own —
//! so every byte of parsing that faces a container is code we own, review,
//! and can fuzz on our own terms. The tests in this module are the
//! justification: every malformed shape has a case, and each one must yield
//! `FORMERR` or a dropped packet, never a panic and never a loop.
//!
//! What is implemented:
//!
//! - **Header** (RFC 1035 §4.1.1): `ID`, `QR`, `OPCODE`, `AA`, `TC`, `RD`,
//!   `RA`, `RCODE`, and the four section counts.
//! - **Question** (§4.1.2): exactly one, any `QTYPE`/`QCLASS` (the
//!   *responder* decides what it supports, so unsupported values can be
//!   answered honestly instead of dropped).
//! - **Answer records** (§4.1.3) for `A` (§3.4.1) and `AAAA` (RFC 3596).
//! - **Name compression** (§4.1.4) on **read** — a client may send it — and
//!   on write only as the standard pointer to the question name at offset 12.
//! - **512-byte UDP limit** (§4.2.1) with `TC` when answers do not fit.
//!
//! What is deliberately left out: TCP (§4.2.2) and therefore `AXFR`; EDNS0
//! (RFC 6891) — we never advertise a larger buffer, so 512 bytes stays the
//! contract; zone data, `NS`/`SOA`/`CNAME`/`MX`/`SRV`/`TXT`/`PTR` records;
//! recursion (queries we are not authoritative for are forwarded verbatim by
//! [`crate::server`]); `IQUERY`, `STATUS`, `NOTIFY`, `UPDATE` opcodes;
//! DNSSEC; and the `\DDD` escape syntax of master files (names are handled as
//! label bytes, not as text).

use std::fmt;
use std::net::IpAddr;

/// Largest DNS message we send over UDP (RFC 1035 §4.2.1).
pub const MAX_UDP_PAYLOAD: usize = 512;

/// Length of the fixed DNS header (RFC 1035 §4.1.1).
pub const HEADER_LEN: usize = 12;

/// Maximum wire length of a domain name, length octets and root included
/// (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;

/// Maximum length of one label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Class `IN`.
pub const CLASS_IN: u16 = 1;

/// Type `A` (RFC 1035 §3.2.2).
pub const TYPE_A: u16 = 1;

/// Type `AAAA` (RFC 3596 §2.1).
pub const TYPE_AAAA: u16 = 28;

/// Opcode `QUERY` — the only one we implement.
const OPCODE_QUERY: u8 = 0;

/// Offset of the question name in every message: right after the header. Used
/// as the compression target for answer owner names.
const QUESTION_NAME_OFFSET: u16 = 12;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

/// Label-type bits of a length octet (RFC 1035 §4.1.4).
const LABEL_MASK: u8 = 0xC0;
const LABEL_LITERAL: u8 = 0x00;
const LABEL_POINTER: u8 = 0xC0;

/// Response codes we can produce (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rcode {
    /// No error.
    NoError,
    /// The query could not be interpreted.
    FormErr,
    /// We could not complete the query (upstream unreachable, saturated).
    ServFail,
    /// The name does not exist.
    NxDomain,
    /// We do not implement what was asked (opcode, class).
    NotImp,
}

impl Rcode {
    /// The 4-bit wire value.
    #[must_use]
    pub fn value(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
        }
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::NoError => "NOERROR",
            Self::FormErr => "FORMERR",
            Self::ServFail => "SERVFAIL",
            Self::NxDomain => "NXDOMAIN",
            Self::NotImp => "NOTIMP",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// Why a name could not be decoded (or built).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// The packet ends inside the name.
    #[error("name runs past the end of the packet")]
    Truncated,
    /// Label types `01` and `10` are reserved (RFC 1035 §4.1.4).
    #[error("reserved label type in name")]
    ReservedLabelType,
    /// A label longer than 63 bytes.
    #[error("label longer than {MAX_LABEL_LEN} bytes")]
    LabelTooLong,
    /// An empty label in a name built from text (`a..b`).
    #[error("empty label in name")]
    EmptyLabel,
    /// A name whose wire form would exceed 255 bytes.
    #[error("name longer than {MAX_NAME_LEN} bytes on the wire")]
    NameTooLong,
    /// A compression pointer that does not point strictly backwards into the
    /// message body — forward pointers, self-pointers and loops all land here.
    #[error("compression pointer does not point backwards into the message")]
    BadPointer,
    /// Non-ASCII byte in a name built from text.
    #[error("non-ASCII byte in name")]
    NonAscii,
}

/// A domain name, stored in its uncompressed wire form (labels plus the root
/// octet) exactly as received.
///
/// Keeping the received bytes rather than a normalized string means the
/// question we echo is byte-identical to the one that was asked, which
/// clients that randomize the case of the name (DNS-0x20) check. Comparisons
/// against the endpoint table go through [`Name::to_key`], which lowercases.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// Validated: every label ≤ 63 bytes, total ≤ 255, terminated by a root
    /// octet, no compression pointers.
    wire: Vec<u8>,
}

impl Name {
    /// The root name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self { wire: vec![0] }
    }

    /// Builds a name from dotted ASCII text; a single trailing dot is
    /// allowed, and `""`/`"."` are the root.
    pub fn from_ascii(text: &str) -> Result<Self, NameError> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        let mut wire = Vec::with_capacity(trimmed.len() + 2);
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if bytes.len() > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong);
            }
            if !label.is_ascii() {
                return Err(NameError::NonAscii);
            }
            if wire.len() + 1 + bytes.len() + 1 > MAX_NAME_LEN {
                return Err(NameError::NameTooLong);
            }
            let len = u8::try_from(bytes.len()).map_err(|_| NameError::LabelTooLong)?;
            wire.push(len);
            wire.extend_from_slice(bytes);
        }
        wire.push(0);
        Ok(Self { wire })
    }

    /// The uncompressed wire form, root octet included.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.wire.as_slice() == [0]
    }

    /// Lookup key for the endpoint table: labels joined by `.`, ASCII
    /// lowercased, no trailing dot (the root yields an empty string).
    ///
    /// Labels are not required to be UTF-8 on the wire; bytes that are not
    /// are replaced (`from_utf8_lossy`). No service or task name can contain
    /// the replacement character, so a lossy label never matches by accident.
    #[must_use]
    pub fn to_key(&self) -> String {
        let mut key = String::with_capacity(self.wire.len());
        for label in self.labels() {
            if !key.is_empty() {
                key.push('.');
            }
            key.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        }
        key
    }

    /// Iterates the labels, root excluded.
    fn labels(&self) -> Labels<'_> {
        Labels {
            wire: &self.wire,
            pos: 0,
        }
    }
}

/// Iterator over a validated name's labels.
struct Labels<'a> {
    wire: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(*self.wire.get(self.pos)?);
        if len == 0 {
            return None;
        }
        let from = self.pos + 1;
        let label = self.wire.get(from..from + len)?;
        self.pos = from + len;
        Some(label)
    }
}

impl fmt::Display for Name {
    /// Presentation form, always with the trailing dot (`web.` / `.`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            write!(f, "{}.", String::from_utf8_lossy(label))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// The single question of a query (RFC 1035 §4.1.2).
///
/// `qtype` and `qclass` stay raw: unsupported values are answered, not
/// dropped, so the responder needs to see what was actually asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The queried name.
    pub name: Name,
    /// `QTYPE` as sent.
    pub qtype: u16,
    /// `QCLASS` as sent.
    pub qclass: u16,
}

impl Question {
    /// A question for `name` of type `qtype`, class `IN`.
    #[must_use]
    pub fn new(name: Name, qtype: u16) -> Self {
        Self {
            name,
            qtype,
            qclass: CLASS_IN,
        }
    }

    /// Wire length of the encoded question.
    fn encoded_len(&self) -> usize {
        self.name.as_wire().len() + 4
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.name.as_wire());
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

/// A query we accepted and can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction ID, echoed in the response.
    pub id: u16,
    /// `RD` as sent; echoed in the response.
    pub recursion_desired: bool,
    /// The question.
    pub question: Question,
}

/// Why a packet was not accepted as a query.
///
/// [`ParseError::reply`] is the whole point of this type: it decides, per
/// case, between a silent drop and an honest error response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Shorter than the fixed header: there is no transaction ID to answer
    /// with, so the packet can only be dropped.
    #[error("packet shorter than the {HEADER_LEN}-byte DNS header ({len} bytes)")]
    ShortHeader {
        /// Bytes received.
        len: usize,
    },
    /// `QR=1`: a *response* arrived on the responder's socket. Answering it
    /// would risk a packet loop between two resolvers, so it is dropped.
    #[error("packet is a response, not a query")]
    NotAQuery {
        /// Transaction ID (for logs only).
        id: u16,
    },
    /// An opcode other than `QUERY` (`IQUERY`, `STATUS`, `NOTIFY`, `UPDATE`).
    #[error("unsupported opcode {opcode}")]
    UnsupportedOpcode {
        /// Transaction ID.
        id: u16,
        /// `RD` as sent.
        recursion_desired: bool,
        /// The opcode we will not serve.
        opcode: u8,
    },
    /// Not exactly one question. Zero is meaningless; more than one has no
    /// unambiguous response, and no real client sends it.
    #[error("expected exactly one question, got {count}")]
    QuestionCount {
        /// Transaction ID.
        id: u16,
        /// `RD` as sent.
        recursion_desired: bool,
        /// `QDCOUNT` as sent.
        count: u16,
    },
    /// The question section is malformed.
    #[error("malformed question: {source}")]
    BadQuestion {
        /// Transaction ID.
        id: u16,
        /// `RD` as sent.
        recursion_desired: bool,
        /// What was wrong with it.
        #[source]
        source: NameError,
    },
    /// The question is truncated: the name parsed but `QTYPE`/`QCLASS` are
    /// missing.
    #[error("question truncated after the name")]
    ShortQuestion {
        /// Transaction ID.
        id: u16,
        /// `RD` as sent.
        recursion_desired: bool,
    },
    /// A class other than `IN`. `CH`/`HS` mean nothing on an overlay network.
    #[error("unsupported class {}", question.qclass)]
    UnsupportedClass {
        /// Transaction ID.
        id: u16,
        /// `RD` as sent.
        recursion_desired: bool,
        /// The question, echoed in the `NOTIMP` response.
        question: Box<Question>,
    },
}

impl ParseError {
    /// The response this rejection deserves, or `None` when the only correct
    /// reaction is to drop the packet.
    ///
    /// `recursion_available` and `authoritative` are left `false`; the server
    /// sets `recursion_available` from its upstream configuration.
    #[must_use]
    pub fn reply(&self) -> Option<StatusReply<'_>> {
        let (id, recursion_desired, rcode, question) = match self {
            // No ID to echo, and a response to a response invites a loop.
            Self::ShortHeader { .. } | Self::NotAQuery { .. } => return None,
            Self::UnsupportedOpcode {
                id,
                recursion_desired,
                ..
            } => (*id, *recursion_desired, Rcode::NotImp, None),
            Self::QuestionCount {
                id,
                recursion_desired,
                ..
            }
            | Self::BadQuestion {
                id,
                recursion_desired,
                ..
            }
            | Self::ShortQuestion {
                id,
                recursion_desired,
            } => (*id, *recursion_desired, Rcode::FormErr, None),
            Self::UnsupportedClass {
                id,
                recursion_desired,
                question,
            } => (
                *id,
                *recursion_desired,
                Rcode::NotImp,
                Some(question.as_ref()),
            ),
        };
        Some(StatusReply {
            id,
            rcode,
            question,
            recursion_desired,
            recursion_available: false,
            authoritative: false,
        })
    }
}

/// Reads a big-endian `u16` at `at`, or `None` if it does not fit.
fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let bytes = buf.get(at..at + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// The transaction ID of a message, if it is long enough to have one.
#[must_use]
pub fn peek_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    read_u16(packet, 0)
}

/// Whether a message has `QR=1`.
#[must_use]
pub fn is_response(packet: &[u8]) -> bool {
    packet.len() >= HEADER_LEN
        && read_u16(packet, 2).is_some_and(|flags| flags & FLAG_QR == FLAG_QR)
}

/// Parses a query: header, then exactly one question.
///
/// Everything after the question — authority and additional sections,
/// including an EDNS0 `OPT` record — is ignored. We never advertise EDNS, so
/// responses stay within 512 bytes and no `OPT` is echoed, which is the
/// correct behavior for a server that does not implement it (RFC 6891 §6.1.1).
pub fn parse_query(packet: &[u8]) -> Result<Query, ParseError> {
    let (Some(id), Some(flags), Some(qdcount)) =
        (peek_id(packet), read_u16(packet, 2), read_u16(packet, 4))
    else {
        return Err(ParseError::ShortHeader { len: packet.len() });
    };
    if flags & FLAG_QR == FLAG_QR {
        return Err(ParseError::NotAQuery { id });
    }
    let recursion_desired = flags & FLAG_RD == FLAG_RD;
    // Bits 11..14 of the flags word: four bits, so the conversion is exact
    // and the fallback is unreachable.
    let opcode = u8::try_from((flags >> 11) & 0x0F).unwrap_or(u8::MAX);
    if opcode != OPCODE_QUERY {
        return Err(ParseError::UnsupportedOpcode {
            id,
            recursion_desired,
            opcode,
        });
    }
    if qdcount != 1 {
        return Err(ParseError::QuestionCount {
            id,
            recursion_desired,
            count: qdcount,
        });
    }
    let (name, after_name) =
        read_name(packet, HEADER_LEN).map_err(|source| ParseError::BadQuestion {
            id,
            recursion_desired,
            source,
        })?;
    let (Some(qtype), Some(qclass)) = (
        read_u16(packet, after_name),
        read_u16(packet, after_name + 2),
    ) else {
        return Err(ParseError::ShortQuestion {
            id,
            recursion_desired,
        });
    };
    let question = Question {
        name,
        qtype,
        qclass,
    };
    if qclass != CLASS_IN {
        return Err(ParseError::UnsupportedClass {
            id,
            recursion_desired,
            question: Box::new(question),
        });
    }
    Ok(Query {
        id,
        recursion_desired,
        question,
    })
}

/// Decodes the name at `start`, following compression pointers, and returns
/// it with the offset just past the name *in the packet*.
///
/// Termination is structural, not a jump budget: a pointer must target an
/// offset strictly smaller than the smallest offset jumped to so far (and at
/// or after the header). That single rule rejects self-pointers, loops and
/// forward pointers, and bounds the number of jumps by the packet length.
fn read_name(packet: &[u8], start: usize) -> Result<(Name, usize), NameError> {
    let mut wire: Vec<u8> = Vec::new();
    let mut pos = start;
    // Offset just past the name in the packet: fixed by the *first* pointer
    // taken, since everything after it lives elsewhere in the message.
    let mut end: Option<usize> = None;
    // Pointers must point strictly before this.
    let mut jump_limit = start;
    loop {
        let octet = *packet.get(pos).ok_or(NameError::Truncated)?;
        match octet & LABEL_MASK {
            LABEL_LITERAL => {
                if octet == 0 {
                    wire.push(0);
                    return Ok((Name { wire }, end.unwrap_or(pos + 1)));
                }
                let len = usize::from(octet);
                let from = pos + 1;
                let label = packet.get(from..from + len).ok_or(NameError::Truncated)?;
                // +1 length octet, +1 for the root octet still to come.
                if wire.len() + 1 + len + 1 > MAX_NAME_LEN {
                    return Err(NameError::NameTooLong);
                }
                wire.push(octet);
                wire.extend_from_slice(label);
                pos = from + len;
            }
            LABEL_POINTER => {
                let low = *packet.get(pos + 1).ok_or(NameError::Truncated)?;
                let offset = usize::from(u16::from_be_bytes([octet & !LABEL_MASK, low]));
                if end.is_none() {
                    end = Some(pos + 2);
                }
                if offset >= jump_limit || offset < HEADER_LEN {
                    return Err(NameError::BadPointer);
                }
                jump_limit = offset;
                pos = offset;
            }
            // Label types 01 and 10 are reserved; 0x41 was the (withdrawn)
            // bit-string label. Refuse rather than guess.
            _ => return Err(NameError::ReservedLabelType),
        }
    }
}

// ---------------------------------------------------------------------------
// Response building
// ---------------------------------------------------------------------------

/// A response carrying no answer records: `NXDOMAIN`, `NODATA`, `FORMERR`,
/// `SERVFAIL`, `NOTIMP`.
#[derive(Debug, Clone)]
pub struct StatusReply<'a> {
    /// Transaction ID of the query.
    pub id: u16,
    /// Response code.
    pub rcode: Rcode,
    /// Question to echo. `None` when it could not be parsed — a `FORMERR`
    /// with `QDCOUNT=0` is what a server sends when it cannot read the
    /// question.
    pub question: Option<&'a Question>,
    /// `RD` as sent by the client, echoed.
    pub recursion_desired: bool,
    /// `RA`: whether this responder forwards what it is not authoritative for.
    pub recursion_available: bool,
    /// `AA`: set when the answer comes from the endpoint table.
    pub authoritative: bool,
}

impl StatusReply<'_> {
    /// Encodes the response.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        let flags = FLAG_QR
            | u16::from(self.rcode.value())
            | flag(FLAG_AA, self.authoritative)
            | flag(FLAG_RD, self.recursion_desired)
            | flag(FLAG_RA, self.recursion_available);
        let qdcount = u16::from(self.question.is_some());
        push_header(&mut out, self.id, flags, qdcount, 0);
        if let Some(question) = self.question {
            question.encode(&mut out);
        }
        out
    }
}

/// A response carrying address records for the question's name.
#[derive(Debug, Clone)]
pub struct AnswerReply<'a> {
    /// The query being answered; its question is echoed verbatim.
    pub query: &'a Query,
    /// Addresses to answer with, in the order they should appear. Addresses
    /// whose family does not match the question's `QTYPE` are skipped.
    pub addresses: &'a [IpAddr],
    /// TTL of the records.
    pub ttl: u32,
    /// `AA`: set when the answer comes from the endpoint table.
    pub authoritative: bool,
    /// `RA`: whether this responder forwards what it is not authoritative for.
    pub recursion_available: bool,
}

impl AnswerReply<'_> {
    /// Encodes the response, dropping records that do not fit in 512 bytes
    /// and setting `TC` when it drops any (RFC 1035 §4.2.1). TCP retry is not
    /// offered — see the module docs — so `TC` is a statement, not an
    /// invitation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let question = &self.query.question;
        let mut records = Vec::with_capacity(self.addresses.len());
        let mut truncated = false;
        // Header + question are always well under 512 bytes: 12 + 255 + 4.
        let mut used = HEADER_LEN + question.encoded_len();
        for &address in self.addresses {
            if !family_matches(question.qtype, address) {
                continue;
            }
            let mut record = Vec::with_capacity(28);
            push_address_record(&mut record, address, self.ttl);
            if used + record.len() > MAX_UDP_PAYLOAD {
                truncated = true;
                break;
            }
            used += record.len();
            records.push(record);
        }
        let mut out = Vec::with_capacity(used);
        let flags = FLAG_QR
            | u16::from(Rcode::NoError.value())
            | flag(FLAG_AA, self.authoritative)
            | flag(FLAG_TC, truncated)
            | flag(FLAG_RD, self.query.recursion_desired)
            | flag(FLAG_RA, self.recursion_available);
        let ancount = u16::try_from(records.len()).unwrap_or(u16::MAX);
        push_header(&mut out, self.query.id, flags, 1, ancount);
        question.encode(&mut out);
        for record in records {
            out.extend_from_slice(&record);
        }
        out
    }
}

/// Encodes a query — used by tests and by anything that probes a resolver;
/// the responder itself forwards client packets verbatim.
#[must_use]
pub fn encode_query(id: u16, question: &Question, recursion_desired: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + question.encoded_len());
    let flags = if recursion_desired { FLAG_RD } else { 0 };
    push_header(&mut out, id, flags, 1, 0);
    question.encode(&mut out);
    out
}

/// `bit` when `set`, nothing otherwise — used to assemble the flag word.
fn flag(bit: u16, set: bool) -> u16 {
    if set { bit } else { 0 }
}

fn push_header(out: &mut Vec<u8>, id: u16, flags: u16, qdcount: u16, ancount: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    // NSCOUNT, ARCOUNT: we never send authority or additional records.
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
}

/// Whether an address can answer this `QTYPE`.
fn family_matches(qtype: u16, address: IpAddr) -> bool {
    match qtype {
        TYPE_A => address.is_ipv4(),
        TYPE_AAAA => address.is_ipv6(),
        _ => false,
    }
}

/// One `A`/`AAAA` record whose owner name is a compression pointer to the
/// question name (RFC 1035 §4.1.4).
fn push_address_record(out: &mut Vec<u8>, address: IpAddr, ttl: u32) {
    out.extend_from_slice(&(LABEL_POINTER_WORD | QUESTION_NAME_OFFSET).to_be_bytes());
    match address {
        IpAddr::V4(v4) => push_rdata(out, TYPE_A, ttl, &v4.octets()),
        IpAddr::V6(v6) => push_rdata(out, TYPE_AAAA, ttl, &v6.octets()),
    }
}

/// Type, class, TTL, `RDLENGTH` and `RDATA` of one record.
fn push_rdata(out: &mut Vec<u8>, rtype: u16, ttl: u32, rdata: &[u8]) {
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    let rdlength = u16::try_from(rdata.len()).unwrap_or(0);
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(rdata);
}

/// The two high bits of a compression pointer, as a 16-bit word.
const LABEL_POINTER_WORD: u16 = 0xC000;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).expect("valid name")
    }

    fn query_packet(id: u16, text: &str, qtype: u16) -> Vec<u8> {
        encode_query(id, &Question::new(name(text), qtype), true)
    }

    /// A header with explicit flags and counts, and nothing after it.
    fn header(id: u16, flags: u16, qdcount: u16) -> Vec<u8> {
        let mut out = Vec::new();
        push_header(&mut out, id, flags, qdcount, 0);
        out
    }

    // -- names --------------------------------------------------------------

    #[test]
    fn names_round_trip_through_the_wire_form() {
        let cases = [
            ("web", vec![3, b'w', b'e', b'b', 0], "web", "web."),
            (
                "api.web",
                vec![3, b'a', b'p', b'i', 3, b'w', b'e', b'b', 0],
                "api.web",
                "api.web.",
            ),
            ("web.", vec![3, b'w', b'e', b'b', 0], "web", "web."),
            ("", vec![0], "", "."),
            (".", vec![0], "", "."),
        ];
        for (text, wire, key, display) in cases {
            let parsed = name(text);
            assert_eq!(parsed.as_wire(), wire.as_slice(), "{text}");
            assert_eq!(parsed.to_key(), key, "{text}");
            assert_eq!(parsed.to_string(), display, "{text}");
        }
    }

    #[test]
    fn lookup_keys_are_lowercased_but_the_wire_form_is_not() {
        let parsed = name("WeB.Example");
        assert_eq!(parsed.to_key(), "web.example");
        assert_eq!(&parsed.as_wire()[1..4], b"WeB");
    }

    #[test]
    fn from_ascii_rejects_bad_text() {
        let long_label = "x".repeat(64);
        let long_name = vec!["y".repeat(60); 5].join(".");
        let cases = [
            ("a..b", NameError::EmptyLabel),
            (long_label.as_str(), NameError::LabelTooLong),
            (long_name.as_str(), NameError::NameTooLong),
            ("caf\u{e9}", NameError::NonAscii),
        ];
        for (text, expected) in cases {
            assert_eq!(Name::from_ascii(text), Err(expected), "{text}");
        }
    }

    #[test]
    fn read_name_follows_backward_compression_pointers() {
        // 12: "web."  17: "api" -> ptr(12)   23: "db" -> ptr(17)
        let mut packet = header(1, 0, 1);
        packet.extend_from_slice(&[3, b'w', b'e', b'b', 0]);
        packet.extend_from_slice(&[3, b'a', b'p', b'i', 0xC0, 12]);
        packet.extend_from_slice(&[2, b'd', b'b', 0xC0, 17]);

        let (first, after) = read_name(&packet, 12).expect("plain name");
        assert_eq!((first.to_key().as_str(), after), ("web", 17));
        let (second, after) = read_name(&packet, 17).expect("one pointer");
        assert_eq!((second.to_key().as_str(), after), ("api.web", 23));
        let (third, after) = read_name(&packet, 23).expect("pointer chain");
        assert_eq!((third.to_key().as_str(), after), ("db.api.web", 28));
    }

    #[test]
    fn read_name_rejects_pointers_that_do_not_strictly_decrease() {
        let mut packet = header(1, 0, 1);
        // 12: ptr(20) — forward.        17: ptr(17) — itself.
        packet.extend_from_slice(&[0xC0, 20, 0, 0, 0, 0xC0, 17]);
        packet.resize(40, 0);
        assert_eq!(read_name(&packet, 12), Err(NameError::BadPointer));
        assert_eq!(read_name(&packet, 17), Err(NameError::BadPointer));

        // A two-name loop: 12 -> 18, 18 -> 12. The first hop already fails.
        let mut looped = header(1, 0, 1);
        looped.extend_from_slice(&[0xC0, 18, 0, 0, 0, 0, 0xC0, 12]);
        assert_eq!(read_name(&looped, 12), Err(NameError::BadPointer));
        assert_eq!(read_name(&looped, 18), Err(NameError::BadPointer));
    }

    // -- query parsing ------------------------------------------------------

    #[test]
    fn parse_query_reads_what_encode_query_wrote() {
        let packet = query_packet(0xBEEF, "web", TYPE_A);
        let query = parse_query(&packet).expect("valid query");
        assert_eq!(query.id, 0xBEEF);
        assert!(query.recursion_desired);
        assert_eq!(query.question.qtype, TYPE_A);
        assert_eq!(query.question.qclass, CLASS_IN);
        assert_eq!(query.question.name.to_key(), "web");
        assert!(!is_response(&packet));
        assert_eq!(peek_id(&packet), Some(0xBEEF));
    }

    #[test]
    fn parse_query_ignores_trailing_sections() {
        // An EDNS0-looking OPT record in the additional section is ignored,
        // and nothing about it changes the parse.
        let mut packet = query_packet(7, "web", TYPE_AAAA);
        packet[11] = 1; // ARCOUNT = 1
        packet.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let query = parse_query(&packet).expect("valid query");
        assert_eq!(query.question.qtype, TYPE_AAAA);
    }

    /// Every malformed shape, and what the responder owes the sender.
    #[test]
    fn malformed_packets_never_panic_and_answer_honestly() {
        let mut truncated_question = header(0x0101, 0, 1);
        truncated_question.extend_from_slice(&[3, b'w', b'e']); // label runs off

        let mut bad_label_type = header(0x0102, 0, 1);
        bad_label_type.extend_from_slice(&[0x40, b'x', 0]);

        let mut reserved_label_type = header(0x0103, 0, 1);
        reserved_label_type.extend_from_slice(&[0x80, b'x', 0]);

        let mut pointer_forward = header(0x0104, 0, 1);
        pointer_forward.extend_from_slice(&[0xC0, 30]);
        pointer_forward.resize(40, 0);

        let mut pointer_self = header(0x0105, 0, 1);
        pointer_self.extend_from_slice(&[0xC0, 12]);

        let mut pointer_into_header = header(0x0106, 0, 1);
        pointer_into_header.extend_from_slice(&[0xC0, 0]);

        let mut pointer_half = header(0x0107, 0, 1);
        pointer_half.extend_from_slice(&[0xC0]);

        // 300 bytes of labels with no root octet in sight.
        let mut name_too_long = header(0x0108, 0, 1);
        for _ in 0..6 {
            name_too_long.push(50);
            name_too_long.extend_from_slice(&[b'z'; 50]);
        }
        name_too_long.push(0);

        // Many tiny labels: still over 255 bytes total.
        let mut too_many_labels = header(0x0109, 0, 1);
        for _ in 0..200 {
            too_many_labels.extend_from_slice(&[1, b'a']);
        }
        too_many_labels.push(0);

        let mut no_qtype = header(0x010A, 0, 1);
        no_qtype.extend_from_slice(&[3, b'w', b'e', b'b', 0, 0, 1]); // one byte short

        let mut wrong_class = query_packet(0x010B, "web", TYPE_A);
        let last = wrong_class.len() - 1;
        wrong_class[last] = 3; // class CH

        let cases: Vec<(&str, Vec<u8>, Option<Rcode>)> = vec![
            ("empty packet", Vec::new(), None),
            ("header cut short", vec![0; HEADER_LEN - 1], None),
            ("a response, not a query", header(0x0100, FLAG_QR, 1), None),
            (
                "opcode UPDATE",
                header(0x0111, 5 << 11, 1),
                Some(Rcode::NotImp),
            ),
            ("no question", header(0x0112, 0, 0), Some(Rcode::FormErr)),
            ("two questions", header(0x0113, 0, 2), Some(Rcode::FormErr)),
            (
                "qdcount 65535",
                header(0x0114, 0, u16::MAX),
                Some(Rcode::FormErr),
            ),
            (
                "header only, qdcount 1",
                header(0x0115, 0, 1),
                Some(Rcode::FormErr),
            ),
            (
                "label past the end",
                truncated_question,
                Some(Rcode::FormErr),
            ),
            ("label type 01", bad_label_type, Some(Rcode::FormErr)),
            ("label type 10", reserved_label_type, Some(Rcode::FormErr)),
            ("forward pointer", pointer_forward, Some(Rcode::FormErr)),
            ("self pointer", pointer_self, Some(Rcode::FormErr)),
            (
                "pointer into header",
                pointer_into_header,
                Some(Rcode::FormErr),
            ),
            ("half a pointer", pointer_half, Some(Rcode::FormErr)),
            ("oversized name", name_too_long, Some(Rcode::FormErr)),
            ("too many labels", too_many_labels, Some(Rcode::FormErr)),
            ("question without qclass", no_qtype, Some(Rcode::FormErr)),
            ("class CH", wrong_class, Some(Rcode::NotImp)),
        ];

        for (label, packet, expected) in cases {
            let error = parse_query(&packet).expect_err(label);
            let reply = error.reply();
            assert_eq!(
                reply.as_ref().map(|reply| reply.rcode),
                expected,
                "{label}: {error}"
            );
            if let Some(reply) = reply {
                // Every error response must be encodable and well-formed.
                let bytes = reply.encode();
                assert!(bytes.len() >= HEADER_LEN, "{label}");
                assert!(is_response(&bytes), "{label}");
                assert_eq!(peek_id(&bytes), Some(reply.id), "{label}");
                assert!(bytes.len() <= MAX_UDP_PAYLOAD, "{label}");
            }
        }
    }

    #[test]
    fn every_byte_prefix_of_a_valid_query_is_handled() {
        // Truncation fuzzing: a short read must never panic, and must never
        // be mistaken for a valid query.
        let packet = query_packet(0x4242, "api.web.svc", TYPE_A);
        for len in 0..packet.len() {
            let outcome = parse_query(&packet[..len]);
            assert!(outcome.is_err(), "prefix of {len} bytes parsed");
        }
        assert!(parse_query(&packet).is_ok());
    }

    #[test]
    fn class_mismatch_echoes_the_question() {
        let mut packet = query_packet(9, "web", TYPE_A);
        let last = packet.len() - 1;
        packet[last] = 4; // class HS
        let error = parse_query(&packet).expect_err("wrong class");
        let reply = error.reply().expect("NOTIMP is answerable");
        let bytes = reply.encode();
        assert_eq!(reply.rcode, Rcode::NotImp);
        assert_eq!(read_u16(&bytes, 4), Some(1), "question echoed");
        assert!(bytes.ends_with(&[3, b'w', b'e', b'b', 0, 0, 1, 0, 4]));
    }

    // -- response building --------------------------------------------------

    #[test]
    fn answer_bytes_are_exactly_what_the_rfc_asks_for() {
        let packet = query_packet(0x1234, "web", TYPE_A);
        let query = parse_query(&packet).expect("valid");
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let bytes = AnswerReply {
            query: &query,
            addresses: &addresses,
            ttl: 30,
            authoritative: true,
            recursion_available: true,
        }
        .encode();
        let expected: Vec<u8> = [
            // id, flags QR|AA|RD|RA, qd=1, an=2, ns=0, ar=0
            &[0x12, 0x34, 0x85, 0x80, 0, 1, 0, 2, 0, 0, 0, 0][..],
            &[3, b'w', b'e', b'b', 0, 0, 1, 0, 1][..],
            &[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 1][..],
            &[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 0, 2][..],
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn aaaa_answers_carry_v6_records_and_skip_v4() {
        let packet = query_packet(1, "web", TYPE_AAAA);
        let query = parse_query(&packet).expect("valid");
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        ];
        let bytes = AnswerReply {
            query: &query,
            addresses: &addresses,
            ttl: 10,
            authoritative: true,
            recursion_available: false,
        }
        .encode();
        assert_eq!(read_u16(&bytes, 6), Some(1), "one answer");
        assert!(bytes.ends_with(&[
            0, 28, 0, 1, 0, 0, 0, 10, 0, 16, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    #[test]
    fn an_a_question_with_only_v6_addresses_answers_nothing_but_noerror() {
        let packet = query_packet(1, "web", TYPE_A);
        let query = parse_query(&packet).expect("valid");
        let addresses = [IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let bytes = AnswerReply {
            query: &query,
            addresses: &addresses,
            ttl: 10,
            authoritative: true,
            recursion_available: false,
        }
        .encode();
        assert_eq!(read_u16(&bytes, 6), Some(0), "no answers");
        assert_eq!(
            read_u16(&bytes, 2).map(|flags| flags & 0x000F),
            Some(0),
            "NOERROR, not NXDOMAIN"
        );
        assert_eq!(read_u16(&bytes, 2).map(|flags| flags & FLAG_TC), Some(0));
    }

    #[test]
    fn oversized_answers_are_truncated_with_tc_set() {
        let packet = query_packet(1, "web", TYPE_A);
        let query = parse_query(&packet).expect("valid");
        let addresses: Vec<IpAddr> = (0..40)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
            .collect();
        let bytes = AnswerReply {
            query: &query,
            addresses: &addresses,
            ttl: 30,
            authoritative: true,
            recursion_available: true,
        }
        .encode();
        // 12 header + 9 question = 21, each A record is 16 bytes.
        let fits = (MAX_UDP_PAYLOAD - 21) / 16;
        assert_eq!(read_u16(&bytes, 6), Some(u16::try_from(fits).unwrap()));
        assert_eq!(
            read_u16(&bytes, 2).map(|flags| flags & FLAG_TC),
            Some(FLAG_TC),
            "TC set"
        );
        assert!(bytes.len() <= MAX_UDP_PAYLOAD, "{} bytes", bytes.len());
    }

    #[test]
    fn a_maximal_question_still_leaves_the_response_inside_512_bytes() {
        let long = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let packet = query_packet(1, &long, TYPE_A);
        let query = parse_query(&packet).expect("valid");
        let addresses: Vec<IpAddr> = (0..40)
            .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 1, i)))
            .collect();
        let bytes = AnswerReply {
            query: &query,
            addresses: &addresses,
            ttl: 30,
            authoritative: true,
            recursion_available: true,
        }
        .encode();
        assert!(bytes.len() <= MAX_UDP_PAYLOAD, "{} bytes", bytes.len());
        assert_eq!(
            read_u16(&bytes, 2).map(|flags| flags & FLAG_TC),
            Some(FLAG_TC)
        );
    }

    #[test]
    fn status_replies_echo_flags_and_question() {
        let packet = query_packet(0x5555, "nope", TYPE_A);
        let query = parse_query(&packet).expect("valid");
        let bytes = StatusReply {
            id: query.id,
            rcode: Rcode::NxDomain,
            question: Some(&query.question),
            recursion_desired: true,
            recursion_available: true,
            authoritative: true,
        }
        .encode();
        assert_eq!(read_u16(&bytes, 0), Some(0x5555));
        assert_eq!(read_u16(&bytes, 2), Some(0x8583));
        assert_eq!(read_u16(&bytes, 4), Some(1), "question echoed");
        assert_eq!(read_u16(&bytes, 6), Some(0), "no answers");

        let bare = StatusReply {
            id: 1,
            rcode: Rcode::FormErr,
            question: None,
            recursion_desired: false,
            recursion_available: false,
            authoritative: false,
        }
        .encode();
        assert_eq!(bare.len(), HEADER_LEN);
        assert_eq!(read_u16(&bare, 2), Some(0x8001));
        assert_eq!(read_u16(&bare, 4), Some(0), "no question to echo");
    }

    #[test]
    fn rd_is_echoed_and_ra_reflects_forwarding() {
        let no_rd = encode_query(1, &Question::new(name("web"), TYPE_A), false);
        let query = parse_query(&no_rd).expect("valid");
        assert!(!query.recursion_desired);
        let bytes = AnswerReply {
            query: &query,
            addresses: &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            ttl: 1,
            authoritative: true,
            recursion_available: false,
        }
        .encode();
        let flags = read_u16(&bytes, 2).expect("flags");
        assert_eq!(flags & FLAG_RD, 0, "RD echoed as sent");
        assert_eq!(flags & FLAG_RA, 0, "no upstream, no RA");
    }

    #[test]
    fn rcode_wire_values_match_rfc_1035() {
        for (rcode, value) in [
            (Rcode::NoError, 0),
            (Rcode::FormErr, 1),
            (Rcode::ServFail, 2),
            (Rcode::NxDomain, 3),
            (Rcode::NotImp, 4),
        ] {
            assert_eq!(rcode.value(), value, "{rcode}");
        }
    }

    #[test]
    fn peek_helpers_tolerate_short_packets() {
        assert_eq!(peek_id(&[]), None);
        assert_eq!(peek_id(&[0; HEADER_LEN - 1]), None);
        assert!(!is_response(&[0; 4]));
        let mut response = header(1, FLAG_QR, 0);
        assert!(is_response(&response));
        response.truncate(3);
        assert!(!is_response(&response));
    }
}
