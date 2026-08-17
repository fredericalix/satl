// SPDX-License-Identifier: BSD-2-Clause
//! What the overlay needs to know about the underlay, measured rather than
//! assumed: the interface that carries this node's VTEP address, its **MTU**
//! and its **prefix**.
//!
//! Both values are load-bearing and neither may be a constant:
//!
//! - the **MTU** decides the overlay MTU (`underlay − 50`,
//!   [`satl_overlay::overlay_mtu_v4`]). `satl_overlay::DEFAULT_UNDERLAY_MTU`
//!   exists so the arithmetic is never a literal, not so it can be trusted:
//!   `if_vxlan(4)` computes its own default from the constant `ETHERMTU`, so on
//!   any underlay that is not exactly 1500 the driver's default is wrong and
//!   nothing says so. A forgotten −50 keeps working, fragments every full-size
//!   frame, doubles packet counts and amplifies loss, and is invisible in
//!   throughput (`docs/vxlan.md` §1, §6 case B);
//! - the **prefix** is where the blackhole default remote comes from
//!   ([`blackhole_in`]). `if_vxlan(4)` requires a default remote and sends every
//!   broadcast, multicast and unknown-unicast frame there without consulting the
//!   FDB, so an address that is a *real peer* makes a missing FDB entry work
//!   anyway — which is how an FDB bug survives a two-node test
//!   (`docs/vxlan.md` §2 point 4).
//!
//! `ifconfig(8)` is the only source for either: `satl_net::IfaceState` carries
//! the MTU but not the netmask, and `satl_net::Ifconfig` looks interfaces up by
//! name while what we have is an *address*. So this is one more typed wrapper in
//! the house style (CLAUDE.md, "External command wrappers"): one command, one
//! pure parser, fixtures captured from the real hosts
//! (`tests/fixtures/ifconfig_a_inet_*.txt`).

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use satl_core::Ipv4Cidr;
use satl_net::{CommandOutput, CommandRunner, SystemRunner};

/// Default location of the `ifconfig` binary on FreeBSD.
pub const DEFAULT_IFCONFIG_BINARY: &str = "/sbin/ifconfig";

/// The underlay facts one interface supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnderlayFacts {
    /// Interface carrying [`Self::addr`].
    pub iface: String,
    /// This node's underlay (VTEP) address.
    pub addr: Ipv4Addr,
    /// The prefix that address sits in, as `ifconfig` reports its netmask.
    pub prefix: Ipv4Cidr,
    /// The interface's MTU, from the same `ifconfig` output.
    pub mtu: u32,
}

impl UnderlayFacts {
    /// Overlay MTU on this underlay: `mtu − 50` for an IPv4 VTEP.
    #[must_use]
    pub fn overlay_mtu(&self) -> u32 {
        satl_overlay::overlay_mtu_v4(self.mtu)
    }

    /// Overlay MTU of an **encrypted** network on this underlay: `mtu − 84`
    /// (50 VXLAN + 34 ESP transport overhead, measured in
    /// `hack/experiments/esp/README.md` §4).
    #[must_use]
    pub fn overlay_mtu_encrypted(&self) -> u32 {
        satl_overlay::overlay_mtu_v4_encrypted(self.mtu)
    }
}

/// Why the underlay could not be measured.
#[derive(Debug, thiserror::Error)]
pub enum UnderlayError {
    /// `ifconfig` could not be spawned.
    #[error("underlay: cannot run '{argv}': {source}")]
    Spawn {
        /// The command line attempted.
        argv: String,
        /// The spawn failure.
        source: std::io::Error,
    },

    /// `ifconfig` ran and failed.
    #[error(
        "underlay: '{argv}' failed (exit {exit_code:?}); stderr: {stderr}. \
         Without it the overlay MTU and the blackhole default remote cannot be \
         derived, so no overlay network can be programmed on this node"
    )]
    Failed {
        /// The command line attempted.
        argv: String,
        /// Exit code, `None` when killed by a signal.
        exit_code: Option<i32>,
        /// Raw stderr.
        stderr: String,
    },

    /// No interface on the host holds the address this node advertises.
    #[error(
        "underlay: no interface on this host carries {addr}, which is the \
         address this node advertises as its VXLAN endpoint. Interfaces with an \
         IPv4 address: {seen}. Set advertise_addr in satld.toml to an address \
         this host actually holds"
    )]
    AddressNotHeld {
        /// The address that was looked for.
        addr: Ipv4Addr,
        /// What was found instead, for the operator.
        seen: String,
    },

    /// The prefix has no address that is guaranteed not to be a peer.
    #[error(
        "underlay: {prefix} (on {iface}) is too small to derive a blackhole \
         default remote from: if_vxlan requires one, and it must be an address \
         that is not a real peer, because a real one makes a missing forwarding \
         entry work anyway and hides the bug (docs/vxlan.md section 2). Set \
         overlay_blackhole in satld.toml to an address on this underlay that \
         nothing answers on"
    )]
    PrefixTooSmall {
        /// The interface the prefix came from.
        iface: String,
        /// The prefix itself.
        prefix: Ipv4Cidr,
    },

    /// The derived (or configured) blackhole is this node itself.
    #[error(
        "underlay: the blackhole default remote {blackhole} is this node's own \
         underlay address. Every broadcast and unknown-unicast frame would be \
         sent back to this node. Set overlay_blackhole in satld.toml to an \
         address on {prefix} that nothing answers on"
    )]
    BlackholeIsSelf {
        /// The offending address.
        blackhole: Ipv4Addr,
        /// The underlay prefix it was derived from.
        prefix: Ipv4Cidr,
    },

    /// A configured blackhole that is not usable as a VXLAN remote.
    #[error(
        "underlay: the configured overlay_blackhole {blackhole} is unusable: \
         {reason}"
    )]
    BlackholeRejected {
        /// The offending address.
        blackhole: Ipv4Addr,
        /// Why it was refused.
        reason: String,
    },
}

/// One interface, as much of it as `ifconfig -a inet` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedIface {
    name: String,
    mtu: u32,
    addrs: Vec<Ipv4Cidr>,
}

/// Reads the underlay facts for `addr` off this host.
///
/// Generic over the runner so the parse is exercised against captured output
/// with no privileges and no FreeBSD.
#[derive(Debug, Clone)]
pub struct Underlay<R = SystemRunner> {
    ifconfig: PathBuf,
    runner: R,
}

impl Underlay<SystemRunner> {
    /// Probe running the real `ifconfig`.
    #[must_use]
    pub fn system() -> Self {
        Self::with_runner(SystemRunner)
    }
}

impl Default for Underlay<SystemRunner> {
    fn default() -> Self {
        Self::system()
    }
}

impl<R: CommandRunner> Underlay<R> {
    /// Probe using `runner` (test seam).
    pub fn with_runner(runner: R) -> Self {
        Self {
            ifconfig: PathBuf::from(DEFAULT_IFCONFIG_BINARY),
            runner,
        }
    }

    /// The interface, prefix and MTU behind `addr`.
    #[tracing::instrument(skip(self), fields(addr = %addr))]
    pub async fn facts(&self, addr: Ipv4Addr) -> Result<UnderlayFacts, UnderlayError> {
        let params = args_show_inet();
        let argv = render_argv(&self.ifconfig, &params);
        tracing::debug!(command = %argv, "running");
        let output: CommandOutput = self
            .runner
            .run(&self.ifconfig, &params, None)
            .await
            .map_err(|source| UnderlayError::Spawn {
                argv: argv.clone(),
                source,
            })?;
        if !output.success() {
            return Err(UnderlayError::Failed {
                argv,
                exit_code: output.exit_code,
                stderr: output.stderr,
            });
        }
        facts_for(addr, &parse_inet(&output.stdout))
    }
}

/// `ifconfig -a inet`: every interface, IPv4 only.
fn args_show_inet() -> Vec<String> {
    vec!["-a".to_owned(), "inet".to_owned()]
}

/// A command line as an operator would type it.
fn render_argv(binary: &Path, args: &[String]) -> String {
    let mut out = binary.display().to_string();
    for arg in args {
        out.push(' ');
        out.push_str(arg);
    }
    out
}

/// Pick the interface holding `addr` out of a parsed listing.
fn facts_for(addr: Ipv4Addr, ifaces: &[ParsedIface]) -> Result<UnderlayFacts, UnderlayError> {
    for iface in ifaces {
        for cidr in &iface.addrs {
            if cidr.addr() == addr {
                return Ok(UnderlayFacts {
                    iface: iface.name.clone(),
                    addr,
                    prefix: *cidr,
                    mtu: iface.mtu,
                });
            }
        }
    }
    let seen: Vec<String> = ifaces
        .iter()
        .filter(|iface| !iface.addrs.is_empty())
        .map(|iface| {
            let addrs: Vec<String> = iface.addrs.iter().map(ToString::to_string).collect();
            format!("{}={}", iface.name, addrs.join(","))
        })
        .collect();
    Err(UnderlayError::AddressNotHeld {
        addr,
        seen: if seen.is_empty() {
            "(none)".to_owned()
        } else {
            seen.join(" ")
        },
    })
}

/// The blackhole default remote for an underlay prefix: its **last usable
/// host**, i.e. one below the broadcast address.
///
/// Why that address and not another:
///
/// - it is **inside the underlay prefix**, so it is on-link and needs no route.
///   `if_vxlan` rejects `INADDR_ANY` and multicast, so the remote has to be a
///   concrete unicast address somewhere, and an address off-prefix would depend
///   on a route this node may not have;
/// - it is the address at the **top** of the prefix, which is the part of a
///   cloud subnet that DHCP hands out last and that no SatL node ever configures
///   for itself. It is what the measurement scripts used
///   (`docs/vxlan.md` §2 recommends "an unused address in the underlay prefix",
///   and the captures used the `.255.254` host of the inventory's
///   `underlay_cidr`);
/// - it is **derived**, so two nodes on one underlay compute the same value and
///   an operator reading `vxlanremote 10.2.255.254` on any node knows it is not
///   a peer.
///
/// It is not *proved* unroutable — nothing in a prefix can be — so this is a
/// convention plus the checks the caller makes on top: not this node
/// ([`UnderlayError::BlackholeIsSelf`]) and not any node the store knows
/// (`crate::overlay`). An operator whose fabric really does use the top address
/// overrides it with `overlay_blackhole`.
///
/// Note the deliberate tension `docs/vxlan.md` §2 records: an address *in* the
/// prefix is on-link, so `Oerrs` stays at 0 for the first
/// `net.link.ether.inet.maxtries` frames aimed at it. That makes `Oerrs` a
/// one-way signal, and it is the price of not needing a reject route on every
/// node. The FDB entry count from the ioctl is the signal to use instead.
pub fn blackhole_in(facts: &UnderlayFacts) -> Result<Ipv4Addr, UnderlayError> {
    // /31 and /32 have no host that is neither the network nor the broadcast
    // address; /30 has exactly two, and this node holds one of them, so the
    // "other" host is a legitimate peer address. Refuse all three.
    if facts.prefix.prefix_len() > 29 {
        return Err(UnderlayError::PrefixTooSmall {
            iface: facts.iface.clone(),
            prefix: facts.prefix,
        });
    }
    let broadcast = u32::from(facts.prefix.broadcast());
    let blackhole = Ipv4Addr::from(broadcast.saturating_sub(1));
    if blackhole == facts.addr {
        return Err(UnderlayError::BlackholeIsSelf {
            blackhole,
            prefix: facts.prefix,
        });
    }
    Ok(blackhole)
}

/// Check an operator-configured blackhole against the same rules the derived
/// one satisfies by construction.
pub fn check_blackhole(facts: &UnderlayFacts, blackhole: Ipv4Addr) -> Result<(), UnderlayError> {
    let reject = |reason: String| Err(UnderlayError::BlackholeRejected { blackhole, reason });
    if blackhole == facts.addr {
        return Err(UnderlayError::BlackholeIsSelf {
            blackhole,
            prefix: facts.prefix,
        });
    }
    if blackhole.is_unspecified() || blackhole.is_multicast() || blackhole.is_broadcast() {
        return reject(
            "if_vxlan rejects INADDR_ANY and multicast as a default remote, and a \
             broadcast address would flood the underlay"
                .to_owned(),
        );
    }
    if !facts.prefix.contains(blackhole) {
        return reject(format!(
            "it is outside this node's underlay prefix {}, so reaching it depends \
             on a route that may not exist; an off-prefix remote turns every \
             broadcast frame into a routing failure rather than a discard",
            facts.prefix
        ));
    }
    if blackhole == facts.prefix.network() || blackhole == facts.prefix.broadcast() {
        return reject(format!(
            "it is the network or broadcast address of {}",
            facts.prefix
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// Parse `ifconfig -a inet`.
///
/// An interface block starts at column 0 with `name: flags=…  mtu N`; its
/// indented lines carry `inet <addr> netmask 0x<hex>`. Anything unrecognised is
/// skipped: this must never fail on an interface type it has not seen.
fn parse_inet(text: &str) -> Vec<ParsedIface> {
    let mut out: Vec<ParsedIface> = Vec::new();
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            if let (Some(current), Some(cidr)) = (out.last_mut(), parse_inet_line(line.trim())) {
                current.addrs.push(cidr);
            }
            continue;
        }
        if let Some(iface) = parse_header(line) {
            out.push(iface);
        }
    }
    out
}

/// `vtnet1: flags=1008843<...> metric 0 mtu 1500` → name + MTU.
fn parse_header(line: &str) -> Option<ParsedIface> {
    let (name, rest) = line.split_once(": flags=")?;
    if name.is_empty() || name.contains(char::is_whitespace) {
        return None;
    }
    let mut fields = rest.split_whitespace();
    let mut mtu = None;
    while let Some(field) = fields.next() {
        if field == "mtu" {
            mtu = fields.next().and_then(|value| value.parse::<u32>().ok());
            break;
        }
    }
    Some(ParsedIface {
        name: name.to_owned(),
        // An interface with no printed MTU is not usable as an underlay; 0 is
        // caught by `VtepSpec::validate` (below `ETHERMIN`) with a message that
        // names the measurement.
        mtu: mtu.unwrap_or(0),
        addrs: Vec::new(),
    })
}

/// `inet 10.2.2.47 netmask 0xffff0000 broadcast 10.2.255.255` → `10.2.2.47/16`.
fn parse_inet_line(line: &str) -> Option<Ipv4Cidr> {
    let mut fields = line.split_whitespace();
    if fields.next()? != "inet" {
        return None;
    }
    let addr: Ipv4Addr = fields.next()?.parse().ok()?;
    // The netmask is printed in hex, and `ifconfig` prints it for every inet
    // line; an address with none is not something to guess a prefix for.
    let mut prefix_len = None;
    while let Some(field) = fields.next() {
        if field == "netmask" {
            prefix_len = fields.next().and_then(parse_netmask);
            break;
        }
    }
    Ipv4Cidr::new(addr, prefix_len?).ok()
}

/// `0xffff0000` → 16. Rejects a non-contiguous mask rather than inventing a
/// length for it.
fn parse_netmask(text: &str) -> Option<u8> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    let mask = u32::from_str_radix(hex, 16).ok()?;
    let ones = mask.leading_ones();
    // A contiguous mask is exactly `ones` set bits at the top.
    (mask.count_ones() == ones).then_some(u8::try_from(ones).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;

    const FIXTURE_VM: &str = include_str!("../tests/fixtures/ifconfig_a_inet_node1.txt");

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("valid address")
    }

    fn cidr(text: &str) -> Ipv4Cidr {
        text.parse().expect("valid cidr")
    }

    /// Runner replaying one canned output and recording the argv.
    #[derive(Debug, Default)]
    struct MockRunner {
        stdout: String,
        exit_code: Option<i32>,
        calls: Mutex<Vec<String>>,
    }

    impl MockRunner {
        fn ok(stdout: &str) -> Self {
            Self {
                stdout: stdout.to_owned(),
                exit_code: Some(0),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        async fn run(
            &self,
            program: &Path,
            args: &[String],
            _stdin: Option<&str>,
        ) -> io::Result<CommandOutput> {
            self.calls
                .lock()
                .expect("no panic while holding the lock")
                .push(render_argv(program, args));
            Ok(CommandOutput {
                exit_code: self.exit_code,
                stdout: self.stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    // ---- argv --------------------------------------------------------------

    #[tokio::test]
    async fn one_command_lists_every_inet_interface() {
        let underlay = Underlay::with_runner(MockRunner::ok(FIXTURE_VM));
        underlay.facts(ip("10.2.2.47")).await.expect("facts");
        let calls = underlay
            .runner
            .calls
            .lock()
            .expect("no panic while holding the lock")
            .clone();
        assert_eq!(calls, ["/sbin/ifconfig -a inet"]);
    }

    // ---- parsing a real capture --------------------------------------------

    #[test]
    fn the_cluster_vm_capture_parses() {
        let ifaces = parse_inet(FIXTURE_VM);
        assert_eq!(
            ifaces.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
            ["vtnet0", "vtnet1", "lo0", "satl0"]
        );
        assert_eq!(ifaces[1].mtu, 1500);
        assert_eq!(ifaces[1].addrs, [cidr("10.2.2.47/16")]);
        // OVH hands the public interface a /32; the loopback keeps its /8.
        assert_eq!(ifaces[0].addrs, [cidr("152.228.230.132/32")]);
        assert_eq!(ifaces[2].addrs, [cidr("127.0.0.1/8")]);
        // The `description:` and `options=` lines are not addresses.
        assert_eq!(ifaces[3].addrs, [cidr("10.88.0.1/24")]);
        assert_eq!(ifaces[3].mtu, 1500);
    }

    #[test]
    fn facts_come_from_the_interface_holding_the_address() {
        let ifaces = parse_inet(FIXTURE_VM);
        let facts = facts_for(ip("10.2.2.47"), &ifaces).expect("held");
        assert_eq!(facts.iface, "vtnet1");
        assert_eq!(facts.prefix, cidr("10.2.2.47/16"));
        assert_eq!(facts.mtu, 1500);
        // The whole point of measuring: 1500 - 50.
        assert_eq!(facts.overlay_mtu(), 1450);
    }

    #[test]
    fn an_address_no_interface_holds_names_the_ones_that_exist() {
        let ifaces = parse_inet(FIXTURE_VM);
        let error = facts_for(ip("10.9.9.9"), &ifaces).expect_err("not held");
        let text = error.to_string();
        assert!(text.contains("10.9.9.9"), "{text}");
        assert!(text.contains("vtnet1=10.2.2.47/16"), "{text}");
        assert!(text.contains("advertise_addr"), "{text}");
    }

    #[test]
    fn netmasks_are_hex_and_must_be_contiguous() {
        assert_eq!(parse_netmask("0xffff0000"), Some(16));
        assert_eq!(parse_netmask("0xffffffff"), Some(32));
        assert_eq!(parse_netmask("0x00000000"), Some(0));
        assert_eq!(parse_netmask("ffffff00"), Some(24));
        // Non-contiguous: a length would be a lie.
        assert_eq!(parse_netmask("0xff00ff00"), None);
        assert_eq!(parse_netmask("banana"), None);
    }

    #[test]
    fn a_header_without_an_mtu_yields_zero_rather_than_a_guess() {
        let iface = parse_header("weird0: flags=8843<UP> metric 0").expect("header");
        assert_eq!(iface.mtu, 0);
        // And a spec built from it is refused rather than silently wrong.
        assert!(satl_overlay::overlay_mtu_v4(0) < satl_net::ETHERMIN);
    }

    #[test]
    fn indented_non_address_lines_are_ignored() {
        let text = "\
em0: flags=8843<UP,BROADCAST,RUNNING> metric 0 mtu 9000
\tdescription: satl:vxlan:mynet
\toptions=1<RXCSUM>
\tinet 10.5.0.7 netmask 0xffffff00 broadcast 10.5.0.255
\tinet 10.5.0.8 netmask 0xffffff00 broadcast 10.5.0.255
\tmedia: Ethernet autoselect
";
        let ifaces = parse_inet(text);
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0].mtu, 9000);
        assert_eq!(
            ifaces[0].addrs,
            [cidr("10.5.0.7/24"), cidr("10.5.0.8/24")],
            "both addresses of a multi-homed interface are kept"
        );
        // A jumbo underlay is exactly the case the driver's ETHERMTU-derived
        // default gets wrong (docs/vxlan.md §1).
        let facts = facts_for(ip("10.5.0.7"), &ifaces).expect("held");
        assert_eq!(facts.overlay_mtu(), 8950);
    }

    // ---- the blackhole -----------------------------------------------------

    fn facts_on(addr: &str, prefix: &str, mtu: u32) -> UnderlayFacts {
        UnderlayFacts {
            iface: "vtnet1".to_owned(),
            addr: ip(addr),
            prefix: cidr(prefix),
            mtu,
        }
    }

    #[test]
    fn the_blackhole_is_the_last_usable_host_of_the_underlay_prefix() {
        // The value the measurement captures used on this very fabric.
        assert_eq!(
            blackhole_in(&facts_on("10.2.2.47", "10.2.2.47/16", 1500)).expect("derived"),
            ip("10.2.255.254")
        );
        assert_eq!(
            blackhole_in(&facts_on("192.168.4.9", "192.168.4.9/24", 1500)).expect("derived"),
            ip("192.168.4.254")
        );
    }

    #[test]
    fn every_node_on_one_underlay_derives_the_same_blackhole() {
        // The three cluster VMs, as inventory.toml records them.
        let derived: Vec<Ipv4Addr> = ["10.2.2.47", "10.2.1.50", "10.2.3.124"]
            .into_iter()
            .map(|addr| {
                blackhole_in(&facts_on(addr, &format!("{addr}/16"), 1500)).expect("derived")
            })
            .collect();
        assert_eq!(
            derived,
            [ip("10.2.255.254"), ip("10.2.255.254"), ip("10.2.255.254")]
        );
    }

    #[test]
    fn a_prefix_with_no_address_that_cannot_be_a_peer_is_refused() {
        // OVH's /32 on the public interface: a node advertising that address
        // has no underlay prefix to take a blackhole out of.
        let error = blackhole_in(&facts_on("152.228.230.132", "152.228.230.132/32", 1500))
            .expect_err("refused");
        assert!(error.to_string().contains("overlay_blackhole"), "{error}");
        assert!(blackhole_in(&facts_on("10.0.0.1", "10.0.0.1/31", 1500)).is_err());
        // /30 leaves two hosts, and the one that is not us is a legal peer.
        assert!(blackhole_in(&facts_on("10.0.0.1", "10.0.0.1/30", 1500)).is_err());
        // /29 leaves six, so the top one is derivable again.
        assert_eq!(
            blackhole_in(&facts_on("10.0.0.1", "10.0.0.1/29", 1500)).expect("derived"),
            ip("10.0.0.6")
        );
    }

    #[test]
    fn a_node_sitting_on_the_top_address_refuses_to_blackhole_itself() {
        let error =
            blackhole_in(&facts_on("10.2.255.254", "10.2.255.254/16", 1500)).expect_err("refused");
        assert!(error.to_string().contains("back to this node"), "{error}");
    }

    #[test]
    fn a_configured_blackhole_is_held_to_the_same_rules() {
        let facts = facts_on("10.2.2.47", "10.2.2.47/16", 1500);
        assert!(check_blackhole(&facts, ip("10.2.99.99")).is_ok());
        // Itself.
        assert!(check_blackhole(&facts, ip("10.2.2.47")).is_err());
        // Off-prefix.
        let error = check_blackhole(&facts, ip("192.0.2.1")).expect_err("refused");
        assert!(error.to_string().contains("outside"), "{error}");
        // Multicast and the two edges of the prefix.
        assert!(check_blackhole(&facts, ip("239.1.2.3")).is_err());
        assert!(check_blackhole(&facts, ip("0.0.0.0")).is_err());
        assert!(check_blackhole(&facts, ip("10.2.0.0")).is_err());
        assert!(check_blackhole(&facts, ip("10.2.255.255")).is_err());
    }
}
