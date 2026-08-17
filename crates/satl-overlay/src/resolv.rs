// SPDX-License-Identifier: BSD-2-Clause
//! `resolv.conf`: reading the host's, and generating the one SatL writes into
//! a container (architecture §11.5).
//!
//! Two directions, one file format:
//!
//! - [`HostResolvConf`] parses the node's `/etc/resolv.conf`. The responder
//!   forwards to those nameservers ([`crate::server::Upstream`]), and their
//!   `search`/`options` lines are what a container inherits.
//! - [`OverlayResolvConf`] renders the container's file: `nameserver` lines
//!   pointing at the embedded responder, plus the inherited `search`/`options`.
//!
//! [`OverlayResolvConf::render`] is pure on purpose. The M1 controller writes a
//! `resolv.conf` copied from the host's; switching it to service discovery is
//! one call to this function, and this crate does not reach into the agent to
//! do it.
//!
//! **Search domains cost a round trip.** A FreeBSD stub applies the search
//! list before the absolute name when the queried name has fewer dots than
//! `ndots` (default 1), so a container looking up `web` with `search
//! example.com` asks for `web.example.com` first. That query is not ours: it
//! is forwarded, comes back `NXDOMAIN`, and only then does the stub ask for
//! `web`, which we answer. Inheriting the host's search list is what Docker
//! does and what operators expect, so [`OverlayResolvConf::from_host`] keeps
//! it — but a deployment that wants the fastest possible service lookups
//! should pass `options ndots:0` or no search list at all.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The DNS port. The responder does not run anywhere else: a container's stub
/// resolver has no way to be told a different one.
pub const DNS_PORT: u16 = 53;

/// Nameservers a libc stub actually uses (`MAXNS`, `resolv.h` on FreeBSD 15.1).
/// Entries past the third are ignored by the resolver, so the renderer refuses
/// to pretend otherwise.
pub const MAX_NAMESERVERS: usize = 3;

/// Search domains a libc stub actually uses (`MAXDNSRCH`).
pub const MAX_SEARCH_DOMAINS: usize = 6;

/// Why a `resolv.conf` could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ResolvConfError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file we tried to read.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// The parts of a host `resolv.conf` SatL cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostResolvConf {
    /// `nameserver` addresses, in file order.
    pub nameservers: Vec<IpAddr>,
    /// `search` domains (a `domain` line counts as a one-element search list;
    /// the last of either wins, as the resolver does).
    pub search: Vec<String>,
    /// `options` tokens, accumulated across lines.
    pub options: Vec<String>,
}

impl HostResolvConf {
    /// Parses `resolv.conf` text.
    ///
    /// Lenient by design: unknown keywords (`sortlist`, `lookup`, …) and
    /// unparseable nameserver addresses are ignored rather than failing the
    /// node's DNS setup. Only whole-line comments are comments — `#` and `;`
    /// have no meaning mid-line in `resolv.conf`.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut parsed = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(keyword) = fields.next() else {
                continue;
            };
            match keyword {
                "nameserver" => {
                    if let Some(address) = fields.next() {
                        if let Ok(server) = address.parse::<IpAddr>() {
                            parsed.nameservers.push(server);
                        } else {
                            tracing::warn!(
                                %address,
                                "ignoring an unparseable nameserver in resolv.conf"
                            );
                        }
                    }
                }
                "search" => {
                    parsed.search = fields.map(str::to_owned).collect();
                }
                "domain" => {
                    parsed.search = fields.next().map(str::to_owned).into_iter().collect();
                }
                "options" => {
                    parsed.options.extend(fields.map(str::to_owned));
                }
                _ => {}
            }
        }
        parsed
    }

    /// Reads and parses a `resolv.conf`. The path is a parameter so tests (and
    /// a chrooted daemon) do not depend on the host's file.
    pub async fn read(path: impl AsRef<Path>) -> Result<Self, ResolvConfError> {
        let path = path.as_ref();
        let text =
            tokio::fs::read_to_string(path)
                .await
                .map_err(|source| ResolvConfError::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        Ok(Self::parse(&text))
    }
}

/// The `resolv.conf` SatL writes into a container.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverlayResolvConf {
    /// Embedded-responder addresses for the task's networks, in attach order.
    pub nameservers: Vec<IpAddr>,
    /// Search domains to pass through.
    pub search: Vec<String>,
    /// `options` tokens to pass through.
    pub options: Vec<String>,
}

impl OverlayResolvConf {
    /// A file pointing only at the responder addresses.
    #[must_use]
    pub fn new(nameservers: Vec<IpAddr>) -> Self {
        Self {
            nameservers,
            search: Vec::new(),
            options: Vec::new(),
        }
    }

    /// Responder addresses plus the host's `search`/`options`.
    ///
    /// The host's *nameservers* are deliberately dropped: they are the
    /// responder's upstreams, not the container's. Listing them here would
    /// give the container a resolver that knows nothing about services, used
    /// whenever the first one blinked.
    #[must_use]
    pub fn from_host(nameservers: Vec<IpAddr>, host: &HostResolvConf) -> Self {
        Self {
            nameservers,
            search: host.search.clone(),
            options: host.options.clone(),
        }
    }

    /// Overrides `search`/`options` with a task's `--dns-search`/`--dns-opt`.
    ///
    /// A task's own `--dns` nameservers are **not** written: pointing the
    /// container at them would disable service discovery. Docker's semantics
    /// are that they become the resolver's upstreams for that container;
    /// per-task upstreams are not implemented in v1 (the responder forwards to
    /// the node's resolvers), so they are reported here and dropped.
    #[must_use]
    pub fn with_task_dns(mut self, dns: &satl_core::DnsConfig) -> Self {
        if !dns.search.is_empty() {
            self.search.clone_from(&dns.search);
        }
        if !dns.options.is_empty() {
            self.options.clone_from(&dns.options);
        }
        if !dns.nameservers.is_empty() {
            tracing::info!(
                nameservers = ?dns.nameservers,
                "task-specified DNS servers are not used as the container's resolver; \
                 the embedded responder stays in place (per-task upstreams are not in v1)"
            );
        }
        self
    }

    /// Renders the file.
    ///
    /// Shape: a generated-by comment, one `nameserver` line per responder
    /// address (at most `MAX_NAMESERVERS`, with the rest listed in a comment
    /// so an operator reading the file can see what libc will ignore), one
    /// `search` line, and one `options` line with all tokens — the form
    /// `resolv.conf` documents and every stub accepts.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# generated by SatL: service names resolve through the embedded responder\n");
        for address in self.nameservers.iter().take(MAX_NAMESERVERS) {
            let _ = writeln!(out, "nameserver {address}");
        }
        if self.nameservers.len() > MAX_NAMESERVERS {
            let ignored: Vec<String> = self
                .nameservers
                .iter()
                .skip(MAX_NAMESERVERS)
                .map(ToString::to_string)
                .collect();
            let _ = writeln!(
                out,
                "# {} more responder address(es) omitted: a stub resolver reads {MAX_NAMESERVERS}: {}",
                ignored.len(),
                ignored.join(" ")
            );
        }
        if !self.search.is_empty() {
            let kept: Vec<&str> = self
                .search
                .iter()
                .take(MAX_SEARCH_DOMAINS)
                .map(String::as_str)
                .collect();
            let _ = writeln!(out, "search {}", kept.join(" "));
        }
        if !self.options.is_empty() {
            let _ = writeln!(out, "options {}", self.options.join(" "));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parses_a_realistic_host_file() {
        let text = "\
# Generated by resolvconf
; another comment style

nameserver 213.186.33.99
nameserver 2001:41d0:3:163::1
search example.com lan
options ndots:2 timeout:1
options attempts:2
sortlist 10.0.0.0/8
lookup file bind
nameserver not-an-address
";
        let parsed = HostResolvConf::parse(text);
        assert_eq!(
            parsed.nameservers,
            vec![
                v4(213, 186, 33, 99),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x41d0, 3, 0x163, 0, 0, 0, 1)),
            ]
        );
        assert_eq!(parsed.search, vec!["example.com", "lan"]);
        assert_eq!(
            parsed.options,
            vec!["ndots:2", "timeout:1", "attempts:2"],
            "options accumulate across lines"
        );
    }

    #[test]
    fn domain_and_search_are_the_same_slot_and_the_last_wins() {
        let domain_first = HostResolvConf::parse("domain corp.example\nsearch a.example b.example");
        assert_eq!(domain_first.search, vec!["a.example", "b.example"]);
        let search_first = HostResolvConf::parse("search a.example b.example\ndomain corp.example");
        assert_eq!(search_first.search, vec!["corp.example"]);
    }

    #[test]
    fn an_empty_or_useless_file_parses_to_nothing() {
        for text in ["", "\n\n", "# only comments\n", "nameserver\n", "garbage\n"] {
            assert_eq!(
                HostResolvConf::parse(text),
                HostResolvConf::default(),
                "{text:?}"
            );
        }
    }

    #[tokio::test]
    async fn read_uses_the_injected_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("resolv.conf");
        tokio::fs::write(&path, "nameserver 10.0.0.53\nsearch svc.local\n")
            .await
            .expect("write");
        let parsed = HostResolvConf::read(&path).await.expect("read");
        assert_eq!(parsed.nameservers, vec![v4(10, 0, 0, 53)]);
        assert_eq!(parsed.search, vec!["svc.local"]);

        let missing = HostResolvConf::read(dir.path().join("absent")).await;
        let error = missing.expect_err("absent file");
        assert!(error.to_string().contains("absent"), "{error}");
    }

    #[test]
    fn renders_the_container_file() {
        let host = HostResolvConf::parse("nameserver 8.8.8.8\nsearch example.com\noptions ndots:1");
        let overlay = OverlayResolvConf::from_host(vec![v4(10, 100, 0, 1)], &host);
        assert_eq!(
            overlay.render(),
            "# generated by SatL: service names resolve through the embedded responder\n\
             nameserver 10.100.0.1\n\
             search example.com\n\
             options ndots:1\n"
        );
        assert!(
            !overlay.render().contains("8.8.8.8"),
            "the host's resolvers are the responder's upstreams, not the container's"
        );
    }

    #[test]
    fn renders_without_search_or_options() {
        let overlay = OverlayResolvConf::new(vec![v4(10, 100, 0, 1), v4(10, 100, 1, 1)]);
        assert_eq!(
            overlay.render(),
            "# generated by SatL: service names resolve through the embedded responder\n\
             nameserver 10.100.0.1\n\
             nameserver 10.100.1.1\n"
        );
    }

    #[test]
    fn beyond_three_nameservers_the_extras_are_named_in_a_comment() {
        let overlay = OverlayResolvConf::new(vec![
            v4(10, 100, 0, 1),
            v4(10, 100, 1, 1),
            v4(10, 100, 2, 1),
            v4(10, 100, 3, 1),
            v4(10, 100, 4, 1),
        ]);
        let rendered = overlay.render();
        assert_eq!(
            rendered
                .lines()
                .filter(|l| l.starts_with("nameserver"))
                .count(),
            MAX_NAMESERVERS
        );
        assert!(rendered.contains("# 2 more responder address(es) omitted"));
        assert!(rendered.contains("10.100.3.1 10.100.4.1"));
    }

    #[test]
    fn search_lists_are_capped_at_what_a_stub_reads() {
        let mut overlay = OverlayResolvConf::new(vec![v4(10, 100, 0, 1)]);
        overlay.search = (0..8).map(|i| format!("d{i}.example")).collect();
        let rendered = overlay.render();
        let search_line = rendered
            .lines()
            .find(|line| line.starts_with("search "))
            .expect("search line");
        assert_eq!(
            search_line.split_whitespace().count() - 1,
            MAX_SEARCH_DOMAINS
        );
    }

    #[test]
    fn task_dns_overrides_search_and_options_but_never_the_nameserver() {
        let host = HostResolvConf::parse("search host.example\noptions ndots:1");
        let dns = satl_core::DnsConfig {
            nameservers: vec!["9.9.9.9".to_owned()],
            search: vec!["task.example".to_owned()],
            options: vec!["ndots:0".to_owned()],
        };
        let rendered = OverlayResolvConf::from_host(vec![v4(10, 100, 0, 1)], &host)
            .with_task_dns(&dns)
            .render();
        assert!(rendered.contains("nameserver 10.100.0.1\n"));
        assert!(!rendered.contains("9.9.9.9"));
        assert!(rendered.contains("search task.example\n"));
        assert!(rendered.contains("options ndots:0\n"));
    }

    #[test]
    fn an_empty_task_dns_config_changes_nothing() {
        let host = HostResolvConf::parse("search host.example\noptions ndots:1");
        let base = OverlayResolvConf::from_host(vec![v4(10, 100, 0, 1)], &host);
        let with_empty = base.clone().with_task_dns(&satl_core::DnsConfig::default());
        assert_eq!(base, with_empty);
    }

    #[test]
    fn every_rendered_file_is_parseable_again() {
        let overlay = OverlayResolvConf {
            nameservers: vec![v4(10, 100, 0, 1)],
            search: vec!["a.example".to_owned(), "b.example".to_owned()],
            options: vec!["ndots:0".to_owned(), "timeout:1".to_owned()],
        };
        let reparsed = HostResolvConf::parse(&overlay.render());
        assert_eq!(reparsed.nameservers, overlay.nameservers);
        assert_eq!(reparsed.search, overlay.search);
        assert_eq!(reparsed.options, overlay.options);
    }
}
