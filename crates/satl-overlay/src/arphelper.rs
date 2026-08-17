// SPDX-License-Identifier: BSD-2-Clause
//! Programming a task jail's ARP table by **re-executing the daemon** with a
//! hidden subcommand.
//!
//! [`crate::lltable`] can only work in a process that has already called
//! `jail_attach`(2), which is irreversible for the caller — so the work has to
//! happen in a child, and the child cannot be a `fork()` of `satld`: the daemon
//! is multi-threaded, and doing anything beyond `exec` in a forked child of a
//! multi-threaded process is unsound (a lock held by a thread that does not
//! exist in the child never unlocks).
//!
//! So: **spawn, don't fork.** And spawn *this same binary* rather than a
//! separate helper, because one artefact is one thing to build, install,
//! version and keep in step. The daemon exposes a hidden subcommand that calls
//! [`child_main`] and nothing else; this module is both sides of that boundary.
//!
//! ```text
//!   satld (async, multi-threaded)                 satld __jail-arp (sync, 1 job)
//!   ┌────────────────────────────┐  request on    ┌──────────────────────────┐
//!   │ ArpHelper::run             │──── stdin ────▶│ child_main               │
//!   │  Programmer::apply         │                │  lltable::attach_to(jid) │
//!   │                            │◀─── stdout ────│  RouteSocket add/delete  │
//!   └────────────────────────────┘  results +     │  lltable::table() (verify)│
//!                                    the table    └──────────────────────────┘
//! ```
//!
//! ## What the daemon must run
//!
//! ```text
//! <path to satld> __jail-arp        # reads a request on stdin, answers on stdout
//! ```
//!
//! [`HELPER_SUBCOMMAND`] is that argument. The subcommand takes **no** further
//! arguments and no environment: everything, the jail included, travels in the
//! request, so the contract the daemon has to honour is one hidden verb that
//! calls [`child_main`]. The path and the argv prefix are
//! [`ArpHelper::new`]'s parameters rather than a constant, so this crate never
//! hardcodes `satld` and a test can point it at anything.
//!
//! ## Why a text protocol
//!
//! One round trip carries a whole batch — every entry to add and remove for one
//! jail — so the cost is one process per jail per reconciliation pass, not one
//! per entry. The format is line-oriented text because it is the thing an
//! operator will find quoted in `/var/log/messages` when a batch fails, and
//! because both directions are then trivially testable in both directions
//! ([`parse_request`]/[`render_request`], [`parse_response`]/[`render_response`]).
//!
//! ## Never trust the exit status
//!
//! This area of the codebase has been bitten twice by tools reporting success
//! while failing (`ifconfig` on a vxlan interface the driver refused;
//! `arp -s` on an off-link address, which exits **0** —
//! `hack/experiments/jail-arp/captures/30-premise-and-mechanism.txt` §6b'). So:
//!
//! - the child **reads the table back** after applying and downgrades any
//!   "installed" it cannot find to a failure;
//! - the response ends with an explicit `end` line, and [`parse_response`]
//!   rejects a response without one — a child killed mid-run cannot look like a
//!   successful one;
//! - the parent ignores the exit status entirely and reads the response.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use satl_core::MacAddr;

use crate::arp::{ArpApplied, ArpBatch, ArpEntry, ArpError, JailArp};
use crate::lltable::{self, LinkTarget, LlEntry, LlError, RouteSocket};
use crate::runner::{PipedRunner, SystemRunner};

/// The hidden subcommand the daemon must expose, which calls [`child_main`].
///
/// Underscore-prefixed so it cannot collide with a Docker-compatible verb and
/// is obviously not for operators.
pub const HELPER_SUBCOMMAND: &str = "__jail-arp";

/// Wire-format version. Bumped only on an incompatible change; both sides refuse
/// anything else, so a half-upgraded install fails loudly instead of silently
/// programming nothing.
pub const PROTOCOL_VERSION: u32 = 1;

/// First line of a request.
const REQUEST_BANNER: &str = "satl-arp-request";
/// First line of a response.
const RESPONSE_BANNER: &str = "satl-arp-response";

/// How long the parent waits for a child before killing it.
///
/// The child does a handful of syscalls, so this is a runaway guard rather than
/// a budget: a child that hangs holds a jail attachment, and a leaked attached
/// process keeps the jail from being removed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

/// One batch of ARP work for one jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The jail to enter: a numeric jid or a jail name
    /// ([`crate::lltable::resolve_jid`]).
    pub jail: String,
    /// Entries to install, in order.
    pub add: Vec<(Ipv4Addr, MacAddr)>,
    /// Addresses to stop resolving, in order.
    pub remove: Vec<Ipv4Addr>,
}

impl Request {
    /// A request that only reads the jail's table back.
    pub fn list(jail: impl Into<String>) -> Self {
        Self {
            jail: jail.into(),
            add: Vec::new(),
            remove: Vec::new(),
        }
    }

    /// A request carrying `batch`.
    pub fn for_batch(jail: impl Into<String>, batch: &ArpBatch) -> Self {
        Self {
            jail: jail.into(),
            add: batch.add.clone(),
            remove: batch.remove.clone(),
        }
    }

    /// How many entries this request touches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.add.len() + self.remove.len()
    }

    /// Whether it only reads the table back.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Which operation a result belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// `add <ip> <mac>`.
    Add,
    /// `del <ip>`.
    Del,
}

impl OpKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Del => "del",
        }
    }
}

/// What became of one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Installed, and confirmed present in the read-back.
    Installed,
    /// Removed, and confirmed absent in the read-back.
    Removed,
    /// There was nothing to remove — the idempotent case.
    Absent,
    /// It did not work. `errno` is present when the kernel supplied one.
    Failed {
        /// Raw errno, when there was one.
        errno: Option<i32>,
        /// Single-line diagnosis, naming the operation.
        message: String,
    },
}

impl Outcome {
    /// Whether this outcome is a failure.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

/// One entry's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryResult {
    /// Which operation.
    pub op: OpKind,
    /// The address.
    pub ip: Ipv4Addr,
    /// The MAC, for an `add`.
    pub mac: Option<MacAddr>,
    /// What happened.
    pub outcome: Outcome,
}

/// A failure that stopped the child before it could touch any entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fatal {
    /// Which step: `attach`, `socket` or `table`.
    pub stage: String,
    /// Raw errno, when there was one.
    pub errno: Option<i32>,
    /// Single-line diagnosis.
    pub message: String,
}

/// What the child reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// The jid actually entered, once `jail_attach` succeeded.
    pub jid: Option<i32>,
    /// Set when the child could not get as far as programming anything.
    pub fatal: Option<Fatal>,
    /// One per requested operation, in request order.
    pub results: Vec<EntryResult>,
    /// The jail's whole link-layer table after the batch — the read-back.
    pub table: Vec<LlEntry>,
}

impl Response {
    /// Whether every requested operation succeeded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.fatal.is_none() && !self.results.iter().any(|result| result.outcome.failed())
    }

    /// The failures, rendered one per line, for [`ArpApplied::failures`].
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .fatal
            .iter()
            .map(|fatal| format!("{}: {}", fatal.stage, fatal.message))
            .collect();
        out.extend(
            self.results
                .iter()
                .filter_map(|result| match &result.outcome {
                    Outcome::Failed { message, .. } => Some(message.clone()),
                    _ => None,
                }),
        );
        out
    }
}

/// A request or response that did not have the expected shape.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The first line was not the expected banner and version.
    #[error(
        "the {side} does not start with `{expected} {PROTOCOL_VERSION}` \
         (first line was {found:?}); the parent and the child are different \
         builds of satld"
    )]
    Banner {
        /// `request` or `response`.
        side: &'static str,
        /// The banner that was expected.
        expected: &'static str,
        /// What was there instead.
        found: String,
    },

    /// A line could not be understood.
    #[error("cannot parse the {side} at line {line}: {reason}; the line was {text:?}")]
    Line {
        /// `request` or `response`.
        side: &'static str,
        /// 1-based line number.
        line: usize,
        /// Why it was rejected.
        reason: String,
        /// The offending line.
        text: String,
    },

    /// A request named no jail.
    #[error("the request carries no `jail` line, so there is nothing to attach to")]
    NoJail,

    /// The response stopped before its `end` line.
    #[error(
        "the response has no `end` line, so the child did not run to \
         completion: it was killed, or it crashed. {lines} line(s) arrived"
    )]
    Truncated {
        /// How many lines did arrive.
        lines: usize,
    },
}

/// Collapse a diagnostic to one line, so it cannot break the framing.
fn one_line(text: &str) -> String {
    let collapsed: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        "(no diagnostic)".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Render a request for the child's stdin.
#[must_use]
pub fn render_request(request: &Request) -> String {
    use std::fmt::Write as _;
    // Infallible: `fmt::Write` on a `String` never errors.
    let mut out = format!(
        "{REQUEST_BANNER} {PROTOCOL_VERSION}\njail {}\n",
        request.jail
    );
    for (ip, mac) in &request.add {
        let _ = writeln!(out, "add {ip} {mac}");
    }
    for ip in &request.remove {
        let _ = writeln!(out, "del {ip}");
    }
    out
}

/// Parse what [`render_request`] wrote.
pub fn parse_request(text: &str) -> Result<Request, ProtocolError> {
    let mut lines = text.lines().enumerate();
    let (_, banner) = lines.next().unwrap_or((0, ""));
    if banner.trim() != format!("{REQUEST_BANNER} {PROTOCOL_VERSION}") {
        return Err(ProtocolError::Banner {
            side: "request",
            expected: REQUEST_BANNER,
            found: one_line(banner),
        });
    }
    let mut jail = None;
    let mut add = Vec::new();
    let mut remove = Vec::new();
    for (index, raw) in lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let bad = |reason: &str| ProtocolError::Line {
            side: "request",
            line: number,
            reason: reason.to_owned(),
            text: one_line(raw),
        };
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("jail") => {
                let name = fields
                    .next()
                    .ok_or_else(|| bad("`jail` needs a jid or name"))?;
                if jail.is_some() {
                    return Err(bad("a request names exactly one jail"));
                }
                jail = Some(name.to_owned());
            }
            Some("add") => {
                let (Some(ip), Some(mac)) = (fields.next(), fields.next()) else {
                    return Err(bad("`add` needs an address and a MAC"));
                };
                add.push((
                    ip.parse().map_err(|_| bad("not an IPv4 address"))?,
                    mac.parse().map_err(|_| bad("not a MAC address"))?,
                ));
            }
            Some("del") => {
                let ip = fields.next().ok_or_else(|| bad("`del` needs an address"))?;
                remove.push(ip.parse().map_err(|_| bad("not an IPv4 address"))?);
            }
            _ => return Err(bad("unknown directive")),
        }
        if fields.next().is_some() {
            return Err(bad("trailing fields"));
        }
    }
    Ok(Request {
        jail: jail.ok_or(ProtocolError::NoJail)?,
        add,
        remove,
    })
}

/// Render a response for the child's stdout.
#[must_use]
pub fn render_response(response: &Response) -> String {
    use std::fmt::Write as _;
    let mut out = format!("{RESPONSE_BANNER} {PROTOCOL_VERSION}\n");
    if let Some(jid) = response.jid {
        let _ = writeln!(out, "jid {jid}");
    }
    if let Some(fatal) = &response.fatal {
        let _ = writeln!(
            out,
            "fatal {} {} {}",
            fatal.stage,
            render_errno(fatal.errno),
            one_line(&fatal.message)
        );
    }
    for result in &response.results {
        let _ = write!(out, "result {} {}", result.op.as_str(), result.ip);
        match result.mac {
            Some(mac) => {
                let _ = write!(out, " {mac}");
            }
            None => {
                let _ = write!(out, " -");
            }
        }
        match &result.outcome {
            Outcome::Installed => {
                let _ = writeln!(out, " installed");
            }
            Outcome::Removed => {
                let _ = writeln!(out, " removed");
            }
            Outcome::Absent => {
                let _ = writeln!(out, " absent");
            }
            Outcome::Failed { errno, message } => {
                let _ = writeln!(
                    out,
                    " failed {} {}",
                    render_errno(*errno),
                    one_line(message)
                );
            }
        }
    }
    for entry in &response.table {
        let _ = writeln!(
            out,
            "entry {} {} {} {} {:#x} {}",
            entry.ip,
            entry
                .mac
                .map_or_else(|| "-".to_owned(), |mac| mac.to_string()),
            entry.iface.as_deref().unwrap_or("-"),
            entry.ifindex,
            entry.flags,
            entry.expire,
        );
    }
    out.push_str("end\n");
    out
}

/// Parse what [`render_response`] wrote.
///
/// Fails with [`ProtocolError::Truncated`] when the `end` line is missing:
/// a child that was killed must not be mistaken for one that did nothing.
pub fn parse_response(text: &str) -> Result<Response, ProtocolError> {
    let mut lines = text.lines().enumerate();
    let (_, banner) = lines.next().unwrap_or((0, ""));
    if banner.trim() != format!("{RESPONSE_BANNER} {PROTOCOL_VERSION}") {
        return Err(ProtocolError::Banner {
            side: "response",
            expected: RESPONSE_BANNER,
            found: one_line(banner),
        });
    }
    let mut response = Response::default();
    let mut ended = false;
    let mut count = 1;
    for (index, raw) in lines {
        count = index + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let bad = |reason: &str| ProtocolError::Line {
            side: "response",
            line: number,
            reason: reason.to_owned(),
            text: one_line(raw),
        };
        if ended {
            return Err(bad("content after the `end` line"));
        }
        let mut fields = line.splitn(2, char::is_whitespace);
        let keyword = fields.next().unwrap_or_default();
        let rest = fields.next().unwrap_or_default().trim();
        match keyword {
            "end" => ended = true,
            "jid" => {
                response.jid = Some(rest.parse().map_err(|_| bad("`jid` needs a number"))?);
            }
            "fatal" => response.fatal = Some(parse_fatal(rest, &bad)?),
            "result" => response.results.push(parse_result(rest, &bad)?),
            "entry" => response.table.push(parse_entry(rest, &bad)?),
            _ => return Err(bad("unknown keyword")),
        }
    }
    if !ended {
        return Err(ProtocolError::Truncated { lines: count });
    }
    Ok(response)
}

/// `-` for "the kernel gave no errno", a number otherwise.
fn render_errno(errno: Option<i32>) -> String {
    errno.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// `-` means "the kernel gave no errno"; anything else must be a number.
///
/// `Err(())` rather than a nested `Option`, so "absent" and "unparseable" cannot
/// be confused at a call site.
fn parse_errno(field: &str) -> Result<Option<i32>, ()> {
    if field == "-" {
        return Ok(None);
    }
    field.parse().map(Some).map_err(|_| ())
}

fn parse_fatal(rest: &str, bad: &impl Fn(&str) -> ProtocolError) -> Result<Fatal, ProtocolError> {
    let mut fields = rest.splitn(3, char::is_whitespace);
    let (Some(stage), Some(errno), Some(message)) = (fields.next(), fields.next(), fields.next())
    else {
        return Err(bad("`fatal` needs a stage, an errno and a message"));
    };
    Ok(Fatal {
        stage: stage.to_owned(),
        errno: parse_errno(errno).map_err(|()| bad("errno must be a number or `-`"))?,
        message: message.trim().to_owned(),
    })
}

fn parse_result(
    rest: &str,
    bad: &impl Fn(&str) -> ProtocolError,
) -> Result<EntryResult, ProtocolError> {
    let mut fields = rest.splitn(4, char::is_whitespace);
    let (Some(op), Some(ip), Some(mac), Some(tail)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(bad(
            "`result` needs an operation, an address, a MAC and an outcome",
        ));
    };
    let op = match op {
        "add" => OpKind::Add,
        "del" => OpKind::Del,
        _ => return Err(bad("operation must be `add` or `del`")),
    };
    let mac = if mac == "-" {
        None
    } else {
        Some(mac.parse().map_err(|_| bad("not a MAC address"))?)
    };
    let mut outcome_fields = tail.trim().splitn(3, char::is_whitespace);
    let outcome = match outcome_fields.next() {
        Some("installed") => Outcome::Installed,
        Some("removed") => Outcome::Removed,
        Some("absent") => Outcome::Absent,
        Some("failed") => {
            let (Some(errno), Some(message)) = (outcome_fields.next(), outcome_fields.next())
            else {
                return Err(bad("`failed` needs an errno and a message"));
            };
            Outcome::Failed {
                errno: parse_errno(errno).map_err(|()| bad("errno must be a number or `-`"))?,
                message: message.trim().to_owned(),
            }
        }
        _ => return Err(bad("unknown outcome")),
    };
    Ok(EntryResult {
        op,
        ip: ip.parse().map_err(|_| bad("not an IPv4 address"))?,
        mac,
        outcome,
    })
}

fn parse_entry(rest: &str, bad: &impl Fn(&str) -> ProtocolError) -> Result<LlEntry, ProtocolError> {
    let mut fields = rest.split_whitespace();
    let (Some(ip), Some(mac), Some(iface), Some(ifindex), Some(flags), Some(expire)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(bad(
            "`entry` needs an address, a MAC, an interface, an index, flags and an expiry",
        ));
    };
    if fields.next().is_some() {
        return Err(bad("trailing fields"));
    }
    Ok(LlEntry {
        ip: ip.parse().map_err(|_| bad("not an IPv4 address"))?,
        mac: if mac == "-" {
            None
        } else {
            Some(mac.parse().map_err(|_| bad("not a MAC address"))?)
        },
        iface: (iface != "-").then(|| iface.to_owned()),
        ifindex: ifindex.parse().map_err(|_| bad("index must be a number"))?,
        flags: flags
            .strip_prefix("0x")
            .and_then(|hex| i32::from_str_radix(hex, 16).ok())
            .ok_or_else(|| bad("flags must be hexadecimal, like 0xc05"))?,
        expire: expire.parse().map_err(|_| bad("expiry must be a number"))?,
    })
}

// ---------------------------------------------------------------------------
// The child side
// ---------------------------------------------------------------------------

/// Do the work described by `request`, **in this process**.
///
/// Calls `jail_attach`(2), so the process it runs in can never leave the jail
/// again. Only [`child_main`] should call it outside tests.
///
/// Never returns `Err`: every per-entry failure is reported in the response, so
/// one bad address does not cost the whole batch. The three ways the child can
/// fail before touching an entry — attach, socket, read-back — become
/// [`Response::fatal`].
#[must_use]
pub fn execute(request: &Request) -> Response {
    let mut response = Response::default();

    let jid = match lltable::attach_to(&request.jail) {
        Ok(jid) => jid,
        Err(err) => {
            response.fatal = Some(fatal("attach", &err));
            return response;
        }
    };
    response.jid = Some(jid);

    let mut socket = match RouteSocket::open() {
        Ok(socket) => socket,
        Err(err) => {
            response.fatal = Some(fatal("socket", &err));
            return response;
        }
    };

    // Make before break, matching the reconciler's own ordering.
    for (ip, mac) in &request.add {
        response.results.push(EntryResult {
            op: OpKind::Add,
            ip: *ip,
            mac: Some(*mac),
            outcome: match socket.add(*ip, *mac) {
                Ok(()) => Outcome::Installed,
                Err(err) => failure(&err),
            },
        });
    }

    if !request.remove.is_empty() {
        // Deletions are driven off the table rather than off a route lookup:
        // `lla_rt_output()` needs an interface index even to delete, and an
        // entry can outlive the address that made its own address on-link, so
        // asking `RTM_GET` would fail exactly when teardown needs it to work.
        // An address that is not in the table needs no syscall at all.
        let current = match lltable::table() {
            Ok(table) => table,
            Err(err) => {
                response.fatal = Some(fatal("table", &err));
                return response;
            }
        };
        for ip in &request.remove {
            let outcome = match current.iter().find(|entry| entry.ip == *ip) {
                None => Outcome::Absent,
                Some(entry) => match socket.delete_on(*ip, LinkTarget::of(entry)) {
                    Ok(true) => Outcome::Removed,
                    Ok(false) => Outcome::Absent,
                    Err(err) => failure(&err),
                },
            };
            response.results.push(EntryResult {
                op: OpKind::Del,
                ip: *ip,
                mac: None,
                outcome,
            });
        }
    }

    // The read-back. Everything above only proves the kernel accepted a write.
    match lltable::table() {
        Ok(table) => {
            verify(&mut response.results, &table);
            response.table = table;
        }
        Err(err) => response.fatal = Some(fatal("table", &err)),
    }
    response
}

/// Turn a reported success into a failure when the table disagrees.
///
/// This is where "do not trust an exit status" is enforced: an `RTM_ADD` the
/// kernel accepted but whose entry is not in the table afterwards — or is there
/// with the wrong MAC, or expiring — did not do what was asked.
fn verify(results: &mut [EntryResult], table: &[LlEntry]) {
    for result in results {
        let found = table.iter().find(|entry| entry.ip == result.ip);
        let complaint = match (result.op, &result.outcome) {
            (OpKind::Add, Outcome::Installed) => match (found, result.mac) {
                (None, _) => Some(
                    "the kernel accepted RTM_ADD but the entry is absent from the \
                     link-layer table"
                        .to_owned(),
                ),
                (Some(entry), Some(wanted)) if entry.mac != Some(wanted) => Some(format!(
                    "the entry resolves to {} rather than the {wanted} that was \
                     installed",
                    entry
                        .mac
                        .map_or_else(|| "nothing".to_owned(), |mac| mac.to_string())
                )),
                (Some(entry), _) if !entry.permanent() => Some(format!(
                    "the entry is not permanent (rmx_expire = {}), so an ARP \
                     reply can replace it",
                    entry.expire
                )),
                _ => None,
            },
            (OpKind::Del, Outcome::Removed | Outcome::Absent) => found.map(|entry| {
                format!(
                    "the kernel reported the entry withdrawn but it is still in \
                     the link-layer table, resolving to {}",
                    entry
                        .mac
                        .map_or_else(|| "nothing".to_owned(), |mac| mac.to_string())
                )
            }),
            _ => None,
        };
        if let Some(reason) = complaint {
            result.outcome = Outcome::Failed {
                errno: None,
                message: format!(
                    "{} {}: read-back disagrees: {reason}",
                    result.op.as_str(),
                    result.ip
                ),
            };
        }
    }
}

fn fatal(stage: &str, err: &LlError) -> Fatal {
    Fatal {
        stage: stage.to_owned(),
        errno: errno_of(err),
        message: one_line(&format!("{err}")),
    }
}

fn failure(err: &LlError) -> Outcome {
    Outcome::Failed {
        errno: errno_of(err),
        message: one_line(&format!("{err}")),
    }
}

fn errno_of(err: &LlError) -> Option<i32> {
    let source: &dyn std::error::Error = err;
    std::iter::successors(source.source(), |err| err.source())
        .filter_map(|err| err.downcast_ref::<io::Error>())
        .find_map(io::Error::raw_os_error)
}

/// Entry point for the hidden `<satld> __jail-arp` subcommand.
///
/// Reads a request from standard input, does the work, writes the response to
/// standard output, and returns the process exit code the caller should exit
/// with:
///
/// ```ignore
/// // in satld's argument dispatch, before any runtime is started:
/// std::process::exit(i32::from(satl_overlay::child_main()));
/// ```
///
/// A raw `u8` rather than [`std::process::ExitCode`] because the daemon's `main`
/// returns `anyhow::Result<()>` and cannot forward one.
///
/// **The status is not part of the protocol.** The parent reads the response and
/// ignores the status, except that its *absence* (a signal) means the jail was
/// removed under the child. It is still set truthfully so that a human running
/// the subcommand by hand gets a useful shell status.
pub fn child_main() -> u8 {
    use std::io::{Read as _, Write as _};

    let mut request = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut request) {
        eprintln!("{HELPER_SUBCOMMAND}: cannot read the request from stdin: {err}");
        return 1;
    }
    let request = match parse_request(&request) {
        Ok(request) => request,
        Err(err) => {
            eprintln!("{HELPER_SUBCOMMAND}: {err}");
            return 1;
        }
    };
    let response = execute(&request);
    let complete = response.is_complete();
    let rendered = render_response(&response);
    let mut stdout = io::stdout();
    if stdout.write_all(rendered.as_bytes()).is_err() || stdout.flush().is_err() {
        eprintln!("{HELPER_SUBCOMMAND}: cannot write the response to stdout");
        return 1;
    }
    u8::from(!complete)
}

// ---------------------------------------------------------------------------
// The parent side
// ---------------------------------------------------------------------------

/// Spawns the helper child and reads its answer.
///
/// The **program and argv prefix are the caller's**, not a hardcoded `satld`:
/// this crate has no business knowing what binary it lives in, and a test can
/// point it at a stub.
#[derive(Debug, Clone)]
pub struct ArpHelper<R = SystemRunner> {
    program: PathBuf,
    argv: Vec<String>,
    timeout: Duration,
    runner: R,
}

impl ArpHelper<SystemRunner> {
    /// Helper that runs `program` with `argv` and then the protocol on stdin.
    ///
    /// For `satld` that is `(path_to_satld, [HELPER_SUBCOMMAND])`.
    pub fn new(
        program: impl Into<PathBuf>,
        argv: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::with_runner(program, argv, SystemRunner)
    }

    /// Helper that re-executes **this** binary with [`HELPER_SUBCOMMAND`] — the
    /// production wiring, and the reason no separate helper binary exists.
    ///
    /// # Errors
    ///
    /// Propagates [`std::env::current_exe`], which can fail if the binary was
    /// unlinked or replaced under a running daemon. That is worth reporting at
    /// start-up rather than discovering per batch.
    pub fn from_current_exe() -> io::Result<Self> {
        Ok(Self::new(std::env::current_exe()?, [HELPER_SUBCOMMAND]))
    }
}

impl<R: PipedRunner> ArpHelper<R> {
    /// Helper using `runner` to spawn the child (test injection point).
    pub fn with_runner(
        program: impl Into<PathBuf>,
        argv: impl IntoIterator<Item = impl Into<String>>,
        runner: R,
    ) -> Self {
        Self {
            program: program.into(),
            argv: argv.into_iter().map(Into::into).collect(),
            timeout: DEFAULT_TIMEOUT,
            runner,
        }
    }

    /// Override the runaway guard.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The exact command line the daemon will run, for logs and diagnostics.
    #[must_use]
    pub fn command_line(&self) -> String {
        crate::runner::render_argv(&self.program, &self.argv)
    }

    /// The binary this helper re-executes.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Run one batch in a child and return what it reported.
    ///
    /// The exit status is not consulted: [`parse_response`] requires the `end`
    /// line, so a child that died mid-run is a [`ProtocolError::Truncated`] and
    /// never a silent success.
    #[tracing::instrument(skip(self), fields(jail = %request.jail, entries = request.len()))]
    pub async fn run(&self, request: &Request) -> Result<Response, ArpError> {
        let rendered = render_request(request);
        let output = self
            .runner
            .run_piped(&self.program, &self.argv, rendered, self.timeout)
            .await
            .map_err(|source| ArpError::Spawn {
                context: format!(
                    "program {} ARP entries in jail '{}'",
                    request.len(),
                    request.jail
                ),
                argv: self.command_line(),
                source,
            })?;

        match parse_response(&output.stdout) {
            Ok(response) => {
                // A child that could not attach reports it as a fatal, and a
                // vanished jail is a race the reconciler must treat as benign.
                if let Some(fatal) = &response.fatal
                    && fatal.stage == "attach"
                    && matches!(fatal.errno, Some(libc::EINVAL | libc::ENOENT))
                {
                    return Err(ArpError::NoSuchJail {
                        context: format!("program ARP entries in jail '{}'", request.jail),
                        jail: request.jail.clone(),
                    });
                }
                Ok(response)
            }
            // No `end` line and no exit code means a signal: `jail -r` sends
            // one to every process attached to the jail, so a batch racing a
            // task teardown lands here (measured, signal 15).
            Err(ProtocolError::Truncated { .. }) if output.exit_code.is_none() => {
                Err(ArpError::NoSuchJail {
                    context: format!(
                        "program ARP entries in jail '{}' (the helper was killed by a \
                         signal before it could answer, which is what jail removal \
                         does to a process attached to the jail)",
                        request.jail
                    ),
                    jail: request.jail.clone(),
                })
            }
            Err(source) => Err(ArpError::Helper {
                jail: request.jail.clone(),
                argv: self.command_line(),
                status: crate::runner::render_exit(output.exit_code),
                stderr: crate::runner::render_raw(&output.stderr),
                source: Box::new(source),
            }),
        }
    }
}

impl<R: PipedRunner> JailArp for ArpHelper<R> {
    async fn apply(&self, jail: &str, batch: &ArpBatch) -> Result<ArpApplied, ArpError> {
        let response = self.run(&Request::for_batch(jail, batch)).await?;
        let mut applied = ArpApplied {
            failures: response.failures(),
            ..ArpApplied::default()
        };
        for result in &response.results {
            match (&result.outcome, result.mac) {
                (Outcome::Installed, Some(mac)) => applied.added.push((result.ip, mac)),
                (Outcome::Removed, _) => applied.removed.push(result.ip),
                (Outcome::Absent, _) => applied.absent.push(result.ip),
                _ => {}
            }
        }
        Ok(applied)
    }

    async fn list(&self, jail: &str) -> Result<Vec<ArpEntry>, ArpError> {
        let response = self.run(&Request::list(jail)).await?;
        if let Some(fatal) = &response.fatal {
            return Err(ArpError::Helper {
                jail: jail.to_owned(),
                argv: self.command_line(),
                status: "no child was run".to_owned(),
                stderr: "(empty)".to_owned(),
                source: Box::new(io::Error::other(format!(
                    "{}: {}",
                    fatal.stage, fatal.message
                ))),
            });
        }
        Ok(response.table.iter().map(ArpEntry::from_ll).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockRunner;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("valid MAC")
    }

    fn sample_request() -> Request {
        Request {
            jail: "satl-t1".to_owned(),
            add: vec![
                (ip("10.79.0.12"), mac("02:42:0a:4f:00:0c")),
                (ip("10.79.0.21"), mac("02:42:0a:4f:00:15")),
            ],
            remove: vec![ip("10.79.0.13")],
        }
    }

    fn sample_response() -> Response {
        Response {
            jid: Some(52),
            fatal: None,
            results: vec![
                EntryResult {
                    op: OpKind::Add,
                    ip: ip("10.79.0.12"),
                    mac: Some(mac("02:42:0a:4f:00:0c")),
                    outcome: Outcome::Installed,
                },
                EntryResult {
                    op: OpKind::Add,
                    ip: ip("10.80.0.5"),
                    mac: Some(mac("02:42:0a:50:00:05")),
                    outcome: Outcome::Failed {
                        errno: Some(libc::ESRCH),
                        message: "RTM_GET for 10.80.0.5 failed: No such process".to_owned(),
                    },
                },
                EntryResult {
                    op: OpKind::Del,
                    ip: ip("10.79.0.13"),
                    mac: None,
                    outcome: Outcome::Absent,
                },
            ],
            table: vec![
                LlEntry {
                    ip: ip("10.79.0.11"),
                    mac: Some(mac("02:42:0a:4f:00:0b")),
                    ifindex: 22,
                    iface: Some("satl-ep1b".to_owned()),
                    flags: 0x0010_0c05,
                    expire: 0,
                },
                LlEntry {
                    ip: ip("10.79.0.12"),
                    mac: Some(mac("02:42:0a:4f:00:0c")),
                    ifindex: 22,
                    iface: Some("satl-ep1b".to_owned()),
                    flags: 0xc05,
                    expire: 0,
                },
                LlEntry {
                    ip: ip("10.79.0.9"),
                    mac: None,
                    ifindex: 22,
                    iface: None,
                    flags: 0x405,
                    expire: 44_115,
                },
            ],
        }
    }

    // ---- the wire format, both directions ----------------------------------

    #[test]
    fn a_request_renders_to_the_documented_lines() {
        assert_eq!(
            render_request(&sample_request()),
            "satl-arp-request 1\n\
             jail satl-t1\n\
             add 10.79.0.12 02:42:0a:4f:00:0c\n\
             add 10.79.0.21 02:42:0a:4f:00:15\n\
             del 10.79.0.13\n"
        );
        assert_eq!(
            render_request(&Request::list("52")),
            "satl-arp-request 1\njail 52\n"
        );
    }

    #[test]
    fn a_request_round_trips() {
        let request = sample_request();
        assert_eq!(parse_request(&render_request(&request)).unwrap(), request);
        let listing = Request::list("52");
        assert_eq!(parse_request(&render_request(&listing)).unwrap(), listing);
        assert!(listing.is_empty() && sample_request().len() == 3);
    }

    #[test]
    fn a_response_renders_to_the_documented_lines() {
        assert_eq!(
            render_response(&sample_response()),
            "satl-arp-response 1\n\
             jid 52\n\
             result add 10.79.0.12 02:42:0a:4f:00:0c installed\n\
             result add 10.80.0.5 02:42:0a:50:00:05 failed 3 RTM_GET for 10.80.0.5 failed: No such process\n\
             result del 10.79.0.13 - absent\n\
             entry 10.79.0.11 02:42:0a:4f:00:0b satl-ep1b 22 0x100c05 0\n\
             entry 10.79.0.12 02:42:0a:4f:00:0c satl-ep1b 22 0xc05 0\n\
             entry 10.79.0.9 - - 22 0x405 44115\n\
             end\n"
        );
    }

    #[test]
    fn a_response_round_trips() {
        let response = sample_response();
        assert_eq!(
            parse_response(&render_response(&response)).unwrap(),
            response
        );
        assert!(!response.is_complete());
        assert_eq!(response.failures().len(), 1);
    }

    #[test]
    fn a_fatal_response_round_trips() {
        let response = Response {
            fatal: Some(Fatal {
                stage: "attach".to_owned(),
                errno: Some(libc::EINVAL),
                message: "jail_attach(99999) failed: Invalid argument (os error 22)".to_owned(),
            }),
            ..Response::default()
        };
        let text = render_response(&response);
        assert!(
            text.contains("fatal attach 22 jail_attach(99999)"),
            "{text}"
        );
        assert_eq!(parse_response(&text).unwrap(), response);
        assert!(!response.is_complete());
        assert_eq!(
            response.failures(),
            ["attach: jail_attach(99999) failed: Invalid argument (os error 22)"]
        );
    }

    #[test]
    fn an_empty_response_round_trips_and_is_complete() {
        let response = Response::default();
        assert_eq!(render_response(&response), "satl-arp-response 1\nend\n");
        assert_eq!(
            parse_response(&render_response(&response)).unwrap(),
            response
        );
        assert!(response.is_complete());
    }

    #[test]
    fn a_diagnostic_with_newlines_cannot_break_the_framing() {
        let response = Response {
            results: vec![EntryResult {
                op: OpKind::Add,
                ip: ip("10.79.0.12"),
                mac: Some(mac("02:42:0a:4f:00:0c")),
                outcome: Outcome::Failed {
                    errno: None,
                    message: "line one\nline two\r\tand a tab".to_owned(),
                },
            }],
            ..Response::default()
        };
        let text = render_response(&response);
        assert_eq!(text.lines().count(), 3, "banner, one result, end: {text}");
        let back = parse_response(&text).unwrap();
        assert_eq!(back.results.len(), 1);
        assert!(
            matches!(&back.results[0].outcome, Outcome::Failed { message, .. }
                if message == "line one line two  and a tab"),
            "{:?}",
            back.results[0]
        );
    }

    #[test]
    fn a_version_mismatch_is_refused_on_both_sides() {
        let err = parse_request("satl-arp-request 2\njail 52\n").unwrap_err();
        assert!(matches!(err, ProtocolError::Banner { .. }), "{err:?}");
        assert!(
            err.to_string().contains("different builds of satld"),
            "{err}"
        );
        let err = parse_response("satl-arp-response 99\nend\n").unwrap_err();
        assert!(matches!(err, ProtocolError::Banner { .. }), "{err:?}");
        // And so is empty input, which is what a child that never ran produces.
        assert!(matches!(
            parse_response("").unwrap_err(),
            ProtocolError::Banner { .. }
        ));
    }

    #[test]
    fn a_truncated_response_is_never_a_success() {
        // The whole point of the `end` line.
        let full = render_response(&sample_response());
        let cut = full.trim_end_matches("end\n");
        let err = parse_response(cut).unwrap_err();
        assert!(matches!(err, ProtocolError::Truncated { .. }), "{err:?}");
        assert!(
            err.to_string().contains("did not run to completion"),
            "{err}"
        );
        // ...and nothing may follow it.
        let err = parse_response(&format!("{full}entry 10.0.0.1 - - 0 0x0 0\n")).unwrap_err();
        assert!(err.to_string().contains("after the `end` line"), "{err}");
    }

    #[test]
    fn malformed_lines_name_the_line_and_the_reason() {
        for (text, needle) in [
            ("satl-arp-request 1\n", "no `jail` line"),
            ("satl-arp-request 1\njail 1\njail 2\n", "exactly one jail"),
            (
                "satl-arp-request 1\njail 1\nadd 10.0.0.1\n",
                "needs an address and a MAC",
            ),
            (
                "satl-arp-request 1\njail 1\nadd nope 02:42:00:00:00:01\n",
                "not an IPv4",
            ),
            (
                "satl-arp-request 1\njail 1\nadd 10.0.0.1 nope\n",
                "not a MAC",
            ),
            ("satl-arp-request 1\njail 1\ndel\n", "needs an address"),
            ("satl-arp-request 1\njail 1\nflush\n", "unknown directive"),
            (
                "satl-arp-request 1\njail 1\ndel 10.0.0.1 extra\n",
                "trailing fields",
            ),
        ] {
            let err = parse_request(text).unwrap_err();
            assert!(err.to_string().contains(needle), "{text:?} -> {err}");
        }
        for (text, needle) in [
            ("satl-arp-response 1\nnonsense\nend\n", "unknown keyword"),
            ("satl-arp-response 1\njid x\nend\n", "`jid` needs a number"),
            ("satl-arp-response 1\nfatal attach\nend\n", "needs a stage"),
            (
                "satl-arp-response 1\nresult add 10.0.0.1 - nope\nend\n",
                "unknown outcome",
            ),
            (
                "satl-arp-response 1\nresult sub 10.0.0.1 - absent\nend\n",
                "must be `add` or `del`",
            ),
            (
                "satl-arp-response 1\nresult add 10.0.0.1 - failed\nend\n",
                "needs an errno",
            ),
            (
                "satl-arp-response 1\nentry 10.0.0.1 - - 0\nend\n",
                "`entry` needs",
            ),
            (
                "satl-arp-response 1\nentry 10.0.0.1 - - 0 c05 0\nend\n",
                "hexadecimal",
            ),
            (
                "satl-arp-response 1\nentry 10.0.0.1 - - 0 0xc05 0 x\nend\n",
                "trailing fields",
            ),
        ] {
            let err = parse_response(text).unwrap_err();
            assert!(err.to_string().contains(needle), "{text:?} -> {err}");
        }
    }

    // ---- the read-back check -----------------------------------------------

    fn entry(ip_text: &str, mac_text: Option<&str>, expire: u64) -> LlEntry {
        LlEntry {
            ip: ip(ip_text),
            mac: mac_text.map(mac),
            ifindex: 22,
            iface: Some("satl-ep1b".to_owned()),
            flags: 0xc05,
            expire,
        }
    }

    #[test]
    fn a_reported_success_the_table_does_not_confirm_becomes_a_failure() {
        let mut results = vec![EntryResult {
            op: OpKind::Add,
            ip: ip("10.79.0.12"),
            mac: Some(mac("02:42:0a:4f:00:0c")),
            outcome: Outcome::Installed,
        }];

        // Absent from the table.
        verify(&mut results, &[]);
        let text = match &results[0].outcome {
            Outcome::Failed { message, .. } => message.clone(),
            other => panic!("expected a failure, got {other:?}"),
        };
        assert!(
            text.contains("accepted RTM_ADD but the entry is absent"),
            "{text}"
        );

        // Present with the wrong MAC.
        results[0].outcome = Outcome::Installed;
        verify(
            &mut results,
            &[entry("10.79.0.12", Some("02:42:de:ad:be:ef"), 0)],
        );
        assert!(results[0].outcome.failed(), "{:?}", results[0]);

        // Present with the right MAC but not permanent.
        results[0].outcome = Outcome::Installed;
        verify(
            &mut results,
            &[entry("10.79.0.12", Some("02:42:0a:4f:00:0c"), 1200)],
        );
        let text = match &results[0].outcome {
            Outcome::Failed { message, .. } => message.clone(),
            other => panic!("expected a failure, got {other:?}"),
        };
        assert!(text.contains("not permanent"), "{text}");

        // Present, right MAC, permanent: confirmed.
        results[0].outcome = Outcome::Installed;
        verify(
            &mut results,
            &[entry("10.79.0.12", Some("02:42:0a:4f:00:0c"), 0)],
        );
        assert_eq!(results[0].outcome, Outcome::Installed);
    }

    #[test]
    fn a_reported_removal_the_table_still_shows_becomes_a_failure() {
        let mut results = vec![EntryResult {
            op: OpKind::Del,
            ip: ip("10.79.0.13"),
            mac: None,
            outcome: Outcome::Removed,
        }];
        verify(
            &mut results,
            &[entry("10.79.0.13", Some("02:42:0a:4f:00:0d"), 0)],
        );
        let text = match &results[0].outcome {
            Outcome::Failed { message, .. } => message.clone(),
            other => panic!("expected a failure, got {other:?}"),
        };
        assert!(text.contains("still in the link-layer table"), "{text}");

        // Gone: confirmed, and `absent` is treated the same way.
        for outcome in [Outcome::Removed, Outcome::Absent] {
            results[0].outcome = outcome.clone();
            verify(&mut results, &[entry("10.79.0.99", None, 0)]);
            assert_eq!(results[0].outcome, outcome);
        }
    }

    #[test]
    fn a_failure_is_never_upgraded_by_the_read_back() {
        // An entry whose install failed must stay failed even if some *other*
        // process happens to have put the address in the table.
        let mut results = vec![EntryResult {
            op: OpKind::Add,
            ip: ip("10.79.0.12"),
            mac: Some(mac("02:42:0a:4f:00:0c")),
            outcome: Outcome::Failed {
                errno: Some(libc::ESRCH),
                message: "no route".to_owned(),
            },
        }];
        let before = results[0].outcome.clone();
        verify(
            &mut results,
            &[entry("10.79.0.12", Some("02:42:0a:4f:00:0c"), 0)],
        );
        assert_eq!(results[0].outcome, before);
    }

    // ---- the parent side ---------------------------------------------------

    #[test]
    fn the_argv_the_daemon_must_run_is_exactly_this() {
        let helper = ArpHelper::new("/usr/local/sbin/satld", [HELPER_SUBCOMMAND]);
        assert_eq!(
            helper.command_line(),
            "/usr/local/sbin/satld __jail-arp",
            "this is the contract satld's hidden subcommand has to honour"
        );
        assert_eq!(helper.program(), Path::new("/usr/local/sbin/satld"));
    }

    #[tokio::test]
    async fn run_feeds_the_request_on_stdin_and_parses_the_answer() {
        let mock = MockRunner::new();
        mock.push_output(0, &render_response(&sample_response()), "");
        let helper = ArpHelper::with_runner("/usr/local/sbin/satld", [HELPER_SUBCOMMAND], &mock);
        let response = helper.run(&sample_request()).await.unwrap();
        assert_eq!(response, sample_response());
        assert_eq!(mock.calls(), ["/usr/local/sbin/satld __jail-arp"]);
        assert_eq!(mock.stdins(), [render_request(&sample_request())]);
    }

    #[tokio::test]
    async fn a_child_that_could_not_attach_is_a_vanished_jail() {
        let response = Response {
            fatal: Some(Fatal {
                stage: "attach".to_owned(),
                errno: Some(libc::EINVAL),
                message: "jail_attach(52) failed".to_owned(),
            }),
            ..Response::default()
        };
        let mock = MockRunner::new();
        mock.push_output(1, &render_response(&response), "");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let err = helper.run(&Request::list("52")).await.unwrap_err();
        assert!(matches!(err, ArpError::NoSuchJail { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn a_child_killed_by_a_signal_is_a_vanished_jail() {
        // `jail -r` signals every process attached to the jail (measured:
        // signal 15). No exit code and no `end` line is exactly that.
        let mock = MockRunner::new();
        mock.push_signalled("satl-arp-response 1\njid 52\n", "");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let err = helper.run(&Request::list("52")).await.unwrap_err();
        assert!(matches!(err, ArpError::NoSuchJail { .. }), "{err:?}");
        assert!(err.to_string().contains("killed by a signal"), "{err}");
    }

    #[tokio::test]
    async fn a_truncated_answer_with_an_exit_code_is_a_helper_error_not_a_race() {
        let mock = MockRunner::new();
        mock.push_output(1, "satl-arp-response 1\njid 52\n", "something went wrong\n");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let err = helper.run(&Request::list("52")).await.unwrap_err();
        assert!(matches!(err, ArpError::Helper { .. }), "{err:?}");
        let text = err.to_string();
        assert!(text.contains("/satld __jail-arp"), "{text}");
        assert!(text.contains("something went wrong"), "{text}");
    }

    #[tokio::test]
    async fn a_spawn_failure_names_the_binary_the_daemon_configured() {
        let mock = MockRunner::new();
        mock.push_spawn_error(io::ErrorKind::NotFound, "no such file");
        let helper = ArpHelper::with_runner("/nonexistent/satld", [HELPER_SUBCOMMAND], &mock);
        let err = helper.run(&Request::list("52")).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("/nonexistent/satld __jail-arp"), "{text}");
        assert!(text.contains("no such file"), "{text}");
    }

    #[tokio::test]
    async fn apply_maps_outcomes_onto_the_reconcilers_accounting() {
        let mock = MockRunner::new();
        mock.push_output(1, &render_response(&sample_response()), "");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let applied = helper
            .apply(
                "satl-t1",
                &ArpBatch {
                    add: sample_request().add,
                    remove: sample_request().remove,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            applied.added,
            [(ip("10.79.0.12"), mac("02:42:0a:4f:00:0c"))]
        );
        assert!(applied.removed.is_empty());
        assert_eq!(applied.absent, [ip("10.79.0.13")]);
        assert_eq!(applied.failures.len(), 1);
        assert!(
            applied.failures[0].contains("No such process"),
            "{applied:?}"
        );
    }

    #[tokio::test]
    async fn list_returns_the_tables_entries_as_arp_entries() {
        let mock = MockRunner::new();
        mock.push_output(0, &render_response(&sample_response()), "");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let entries = helper.list("satl-t1").await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].ip, ip("10.79.0.11"));
        assert_eq!(entries[0].iface, "satl-ep1b");
        assert!(entries[0].permanent);
        assert!(
            !entries[0].is_overlay_static(),
            "the jail's own address is RTF_PINNED and is never ours"
        );
        assert!(
            entries[1].is_overlay_static(),
            "{:?} should be recognised as ours",
            entries[1]
        );
        assert_eq!(entries[2].mac, None);
    }

    #[tokio::test]
    async fn list_reports_a_fatal_rather_than_an_empty_table() {
        // The dangerous bug this rules out: a child that could not open its
        // routing socket reports an empty table, and an empty table read as
        // success would make the reconciler re-install everything, or worse,
        // conclude nothing is programmed and remove nothing.
        let response = Response {
            jid: Some(52),
            fatal: Some(Fatal {
                stage: "socket".to_owned(),
                errno: Some(libc::EPERM),
                message: "could not open a PF_ROUTE socket".to_owned(),
            }),
            ..Response::default()
        };
        let mock = MockRunner::new();
        mock.push_output(1, &render_response(&response), "");
        let helper = ArpHelper::with_runner("/satld", [HELPER_SUBCOMMAND], &mock);
        let err = helper.list("52").await.unwrap_err();
        assert!(err.to_string().contains("PF_ROUTE socket"), "{err}");
    }

    // ---- the child, against the real kernel, unprivileged ------------------

    #[test]
    fn execute_on_a_nonexistent_jail_reports_a_fatal_and_touches_nothing() {
        // Safe to run in-process: `jail_attach` fails, so this process is not
        // moved anywhere. It exercises the child's whole error path.
        let response = execute(&Request {
            jail: "satl-no-such-jail-exists".to_owned(),
            add: vec![(ip("10.79.0.12"), mac("02:42:0a:4f:00:0c"))],
            remove: vec![],
        });
        let fatal = response.fatal.as_ref().expect("must be fatal");
        assert_eq!(fatal.stage, "attach");
        assert!(response.results.is_empty(), "{response:?}");
        assert!(response.table.is_empty(), "{response:?}");
        assert!(!response.is_complete());
        // ...and it survives a round trip, which is what the parent will parse.
        assert_eq!(
            parse_response(&render_response(&response)).unwrap(),
            response
        );
    }

    #[test]
    fn errno_of_digs_the_os_error_out_of_the_error_chain() {
        let err = LlError::Socket {
            source: io::Error::from_raw_os_error(libc::EPERM),
        };
        assert_eq!(errno_of(&err), Some(libc::EPERM));
        let err = LlError::NotOnLink {
            ip: ip("10.80.0.5"),
            reason: "nothing".to_owned(),
        };
        assert_eq!(errno_of(&err), None, "not every failure has an errno");
    }
}
