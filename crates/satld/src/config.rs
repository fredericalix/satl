// SPDX-License-Identifier: BSD-2-Clause
//! Daemon configuration: TOML file with all fields optional, defaults from
//! `docs/architecture.md` §15.
//!
//! A missing config file is fine (all defaults); a malformed file is fatal.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

/// Default config file location (architecture §15).
pub const DEFAULT_CONFIG_PATH: &str = "/usr/local/etc/satl/satld.toml";
/// Default REST API unix socket (architecture §15).
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/satl.sock";
/// Default node state directory (architecture §15).
pub const DEFAULT_STATE_DIR: &str = "/var/db/satl";
/// Default ZFS root dataset (architecture §15).
pub const DEFAULT_ZFS_ROOT: &str = "zroot/satl";
/// Default group owning the unix socket. A dedicated `satl` group replaces
/// this once packaging creates it (architecture §12.5).
pub const DEFAULT_SOCKET_GROUP: &str = "wheel";

/// Default name of the node-local bridge network (architecture §11.1). It
/// also names the bridge interface (`satl0`) and the interface group SatL
/// marks everything it owns with.
pub const DEFAULT_NETWORK_NAME: &str = "satl";

/// Default port the internal gRPC server binds (architecture §7, §15).
pub const DEFAULT_LISTEN_PORT: u16 = satl_cluster::DEFAULT_PORT;

/// Default address the internal gRPC server binds: every interface, on
/// [`DEFAULT_LISTEN_PORT`].
#[must_use]
pub fn default_listen_addr() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        DEFAULT_LISTEN_PORT,
    )
}

/// How the node-local network manager applies its pf rules
/// (`pf_mode` in `satld.toml`, architecture §11.4).
///
/// A config-file mirror of [`satl_net::PfMode`] — that type is not
/// `Deserialize`, and the TOML spelling (`check`) is friendlier than the
/// Rust variant name (`CheckOnly`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PfModeConfig {
    /// Syntax-check and load the `satl/*` anchors (production).
    Enforce,
    /// Syntax-check the generated rules, never load them. The default,
    /// because a host whose pf ruleset is managed elsewhere should not have
    /// anchors loaded under it by surprise.
    ///
    /// This used to claim it was "the only mode allowed on a shared dev host
    /// (CLAUDE.md)". That was wrong twice over: CLAUDE.md says no such thing,
    /// and the dev host has run `enforce` since M1 — its definition of done needed a live
    /// `rdr` rule to serve a remote client at all. The real constraint is not
    /// about the mode but about **exclusivity**: `satl/rdr` is one anchor per
    /// host, not one per network, so two `satld` instances both in `enforce`
    /// delete each other's rules on every reconciliation pass. That is why an
    /// integration test which measures the anchor has to stop the host's own
    /// daemon first, and why it would otherwise measure something better than
    /// the truth.
    #[default]
    Check,
    /// Generate and log rules, never invoke `pfctl` (hosts without pf).
    Disabled,
}

impl PfModeConfig {
    /// The `satl-net` mode this config value selects.
    #[must_use]
    pub fn as_pf_mode(self) -> satl_net::PfMode {
        match self {
            Self::Enforce => satl_net::PfMode::Enforce,
            Self::Check => satl_net::PfMode::CheckOnly,
            Self::Disabled => satl_net::PfMode::Disabled,
        }
    }

    /// The TOML spelling, for the startup banner.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Check => "check",
            Self::Disabled => "disabled",
        }
    }
}

/// Raw, all-optional shape of `satld.toml`. Unknown keys are rejected so a
/// typo fails loudly instead of being silently ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    socket_path: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    zfs_root: Option<String>,
    node_name: Option<String>,
    socket_group: Option<String>,
    pf_mode: Option<PfModeConfig>,
    network_name: Option<String>,
    network_pool: Option<String>,
    egress_if: Option<String>,
    listen_addr: Option<String>,
    advertise_addr: Option<String>,
    overlay_blackhole: Option<String>,
    cert_validity: Option<String>,
    metrics_addr: Option<String>,
    keyring_rotate_after_secs: Option<u64>,
    keyring_phase_settle_secs: Option<u64>,
}

/// Effective daemon configuration after defaulting.
#[derive(Debug, Clone)]
pub struct Config {
    /// Unix socket the Docker REST API is served on.
    pub socket_path: PathBuf,
    /// Node state directory (normally the mountpoint of `zfs_root`).
    pub state_dir: PathBuf,
    /// ZFS root dataset holding all SatL datasets.
    pub zfs_root: String,
    /// Node name; defaults to the hostname.
    pub node_name: String,
    /// Group owning the REST API socket.
    pub socket_group: String,
    /// How the node-local network manager applies its pf rules.
    pub pf_mode: PfModeConfig,
    /// Name of the node-local bridge network; also the interface group and,
    /// suffixed with `0`, the bridge interface name.
    pub network_name: String,
    /// Address pool node-local network subnets are carved from.
    pub network_pool: satl_net::SubnetV4,
    /// Interface container traffic is NAT-ed out of. `None` means "take it
    /// from the host default route at startup".
    pub egress_if: Option<String>,
    /// Address the internal gRPC server (Raft, Control, Dispatcher, `NodeCA`)
    /// binds — architecture §7. Every node listens: a manager needs it for
    /// peers, and a single-node cluster needs it for the joiners it will get.
    pub listen_addr: SocketAddr,
    /// `host:port` peers are told to dial. `None` means "derive it at startup
    /// from the address of the interface carrying the default route", which
    /// is what an operator would write by hand on an ordinary host.
    pub advertise_addr: Option<String>,
    /// Validity of the node certificates this daemon issues (its own on
    /// init and renewal and, when it leads, the ones `NodeCA` signs for
    /// joiners and renewers). `None` — the default, and the only production
    /// setting — means [`satl_ca::NODE_CERT_VALIDITY`] (90 days).
    ///
    /// **This knob exists for testing certificate renewal**, by making the
    /// 50-80 % renewal window arrive in minutes instead of weeks. Values
    /// below one hour ([`satl_ca::MIN_CERT_VALIDITY`]) are issued under a
    /// loud startup warning; values below one minute
    /// ([`satl_ca::HARD_MIN_CERT_VALIDITY`]) are refused at config load.
    pub cert_validity: Option<std::time::Duration>,
    /// Address the Prometheus `/metrics` endpoint binds, mirroring dockerd's
    /// `--metrics-addr`. `None` — the default — means **off**: the endpoint is
    /// unauthenticated (like dockerd's), so it is never on unless the operator
    /// chose an address, and that address should be a private one
    /// (`docs/operations.md`).
    pub metrics_addr: Option<SocketAddr>,
    /// The **blackhole default remote** every VTEP on this node is created with.
    ///
    /// `if_vxlan(4)` requires a default remote and sends every broadcast,
    /// multicast and unknown-unicast frame there without consulting the
    /// forwarding table, so it must be an address that is **not a real peer**:
    /// a real one makes a missing forwarding entry work anyway, on that one peer,
    /// which is exactly how an FDB bug survives a two-node test
    /// (`docs/vxlan.md` §2 point 4).
    ///
    /// `None` — the normal case — derives it from the measured underlay prefix:
    /// its **last usable host** (`10.2.0.0/16` gives `10.2.255.254`). Set this
    /// only on a fabric that really does use the top address of the prefix; the
    /// value is then held to the same rules the derived one satisfies by
    /// construction (`crate::underlay::check_blackhole`).
    pub overlay_blackhole: Option<std::net::Ipv4Addr>,
    /// The encrypted-overlay keyring's rotation cadence
    /// (`keyring_rotate_after_secs` in `satld.toml`). The default is the
    /// production [`satl_orchestrator::ROTATE_AFTER`] (12h).
    ///
    /// **This knob exists for testing key rotation**, by making a full
    /// rotation arrive in minutes instead of half a day; it is what the
    /// cluster rotation scenario injects through `SATL_SATLD_EXTRA`.
    pub keyring_rotate_after: std::time::Duration,
    /// Settling time between keyring rotation phases
    /// (`keyring_phase_settle_secs`). The default is the production
    /// [`satl_orchestrator::PHASE_SETTLE`] (60s) — shorten it together with
    /// the rotation interval in tests, never alone on a real cluster.
    pub keyring_phase_settle: std::time::Duration,
}

impl Config {
    /// The bridge interface backing [`Config::network_name`].
    #[must_use]
    pub fn bridge(&self) -> String {
        format!("{}0", self.network_name)
    }

    /// Address the unauthenticated `NodeCA` bootstrap endpoint binds.
    ///
    /// It is a **second** listener, one port above [`Config::listen_addr`],
    /// and it exists because the shared internal server requires a client
    /// certificate on every connection (`satl_ca::live_server_config` builds
    /// a mandatory client verifier) while a node that has never joined
    /// has no certificate to present — the chicken-and-egg exemption
    /// `proto/ca.proto` documents. `NodeCA` is registered on *both*: on the
    /// mTLS server for renewals (authenticated by the existing certificate)
    /// and here for joins.
    #[must_use]
    pub fn ca_listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_addr.ip(), self.listen_addr.port() + 1)
    }

    /// The keyring cadence this daemon's leader loop runs with:
    /// [`satl_orchestrator::Cadence::default`] unless the testing knobs said
    /// otherwise.
    #[must_use]
    pub fn keyring_cadence(&self) -> satl_orchestrator::Cadence {
        satl_orchestrator::Cadence {
            rotate_after: self.keyring_rotate_after,
            phase_settle: self.keyring_phase_settle,
        }
    }
}

/// Parses a config duration: an integer with a unit suffix — `"300s"`,
/// `"5m"`, `"12h"`, `"90d"`. The suffix is mandatory so a bare number can
/// never be read as the wrong unit.
fn parse_duration(text: &str) -> anyhow::Result<std::time::Duration> {
    let trimmed = text.trim();
    let (number, unit) = trimmed.split_at(trimmed.len().saturating_sub(1));
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => anyhow::bail!(
            "expected an integer with a unit suffix (s, m, h or d), like \"5m\" or \"90d\""
        ),
    };
    let count = number
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("{number:?} is not a whole number of {unit}"))?;
    count
        .checked_mul(scale)
        .map(std::time::Duration::from_secs)
        .ok_or_else(|| anyhow::anyhow!("{trimmed:?} overflows"))
}

impl Config {
    /// The node-certificate validity this daemon issues with:
    /// [`Config::cert_validity`] when set, [`satl_ca::NODE_CERT_VALIDITY`]
    /// otherwise.
    #[must_use]
    pub fn effective_cert_validity(&self) -> std::time::Duration {
        self.cert_validity.unwrap_or(satl_ca::NODE_CERT_VALIDITY)
    }
}

/// The `host:port` a joiner reaches this node's bootstrap `NodeCA` endpoint
/// on, derived from the manager address an operator pasted into
/// `satl swarm join` ([`Config::ca_listen_addr`]).
///
/// Pure and total: an address with no port, or one whose port is already the
/// maximum, is returned unchanged so the caller fails on the dial with the
/// address the operator actually typed rather than on a parse here.
#[must_use]
pub fn ca_endpoint_of(manager_addr: &str) -> String {
    let Some((host, port)) = manager_addr.rsplit_once(':') else {
        return manager_addr.to_owned();
    };
    match port.parse::<u16>() {
        Ok(port) if port < u16::MAX => format!("{host}:{}", port + 1),
        _ => manager_addr.to_owned(),
    }
}

/// The advertise address this node publishes to peers.
///
/// Configured value wins; otherwise the address of the interface carrying the
/// default route, with [`Config::listen_addr`]'s port. `None` means the node
/// could not determine one — the leader then substitutes the address it sees
/// the node connect from (SWK §11.3), which is why this degrades rather than
/// failing.
///
/// Pure, so the precedence is unit-tested without touching the host.
#[must_use]
pub fn resolve_advertise_addr(
    configured: Option<&str>,
    detected: Option<IpAddr>,
    listen_port: u16,
) -> Option<String> {
    if let Some(configured) = configured {
        let trimmed = configured.trim();
        if !trimmed.is_empty() {
            // A bare address gets the listen port appended, so an operator
            // can write `advertise_addr = "10.2.0.4"` and mean the obvious.
            return Some(
                if trimmed.rsplit_once(':').is_some_and(|(_, port)| {
                    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                }) {
                    trimmed.to_owned()
                } else {
                    format!("{trimmed}:{listen_port}")
                },
            );
        }
    }
    detected.map(|ip| SocketAddr::new(ip, listen_port).to_string())
}

/// Where the effective configuration came from (for the startup banner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// The config file was read and applied.
    File,
    /// No config file was present; all defaults.
    Defaults,
}

/// Longest network name that still yields a usable bridge interface name
/// (`IFNAMSIZ` is 16 on FreeBSD, minus the `0` suffix and the NUL).
const MAX_NETWORK_NAME_LEN: usize = 14;

impl Config {
    fn from_file(file: ConfigFile, default_node_name: &str) -> anyhow::Result<Self> {
        let network_name = file
            .network_name
            .unwrap_or_else(|| DEFAULT_NETWORK_NAME.to_owned());
        satl_core::naming::validate_network_name(&network_name)
            .with_context(|| format!("invalid network_name {network_name:?}"))?;
        anyhow::ensure!(
            network_name.len() <= MAX_NETWORK_NAME_LEN,
            "network_name {network_name:?} is too long: the bridge interface is named \
             \"{network_name}0\", which must fit in {} characters",
            MAX_NETWORK_NAME_LEN + 1
        );
        let network_pool = match file.network_pool {
            None => satl_net::DEFAULT_LOCAL_BRIDGE_POOL,
            Some(pool) => pool
                .parse::<satl_net::SubnetV4>()
                .with_context(|| format!("invalid network_pool {pool:?}"))?,
        };
        let listen_addr = match file.listen_addr {
            None => default_listen_addr(),
            Some(addr) => addr
                .parse::<SocketAddr>()
                .with_context(|| format!("invalid listen_addr {addr:?} (expected host:port)"))?,
        };
        let overlay_blackhole = match file.overlay_blackhole {
            None => None,
            Some(addr) => Some(addr.parse::<std::net::Ipv4Addr>().with_context(|| {
                format!(
                    "invalid overlay_blackhole {addr:?} (expected a bare IPv4 address on this \
                     node's underlay that nothing answers on)"
                )
            })?),
        };
        let metrics_addr =
            match file.metrics_addr {
                None => None,
                Some(addr) => Some(addr.parse::<SocketAddr>().with_context(|| {
                    format!("invalid metrics_addr {addr:?} (expected host:port)")
                })?),
            };
        let cert_validity = match file.cert_validity {
            None => None,
            Some(text) => {
                let validity = parse_duration(&text)
                    .with_context(|| format!("invalid cert_validity {text:?}"))?;
                anyhow::ensure!(
                    validity >= satl_ca::HARD_MIN_CERT_VALIDITY,
                    "cert_validity {text:?} is below the one-minute floor: certificates that \
                     short expire faster than the cluster can renew them",
                );
                Some(validity)
            }
        };
        let keyring_rotate_after = file.keyring_rotate_after_secs.map_or(
            satl_orchestrator::ROTATE_AFTER,
            std::time::Duration::from_secs,
        );
        anyhow::ensure!(
            !keyring_rotate_after.is_zero(),
            "keyring_rotate_after_secs must not be 0: the leader would re-rotate \
             every keyring in a hot loop"
        );
        let keyring_phase_settle = file.keyring_phase_settle_secs.map_or(
            satl_orchestrator::PHASE_SETTLE,
            std::time::Duration::from_secs,
        );
        anyhow::ensure!(
            keyring_phase_settle < keyring_rotate_after,
            "keyring_phase_settle_secs ({}s) must be below keyring_rotate_after_secs \
             ({}s): the settle pause between rotation phases has to fit inside the \
             rotation interval",
            keyring_phase_settle.as_secs(),
            keyring_rotate_after.as_secs(),
        );
        Ok(Self {
            network_name,
            network_pool,
            listen_addr,
            advertise_addr: file.advertise_addr,
            overlay_blackhole,
            cert_validity,
            metrics_addr,
            egress_if: file.egress_if,
            keyring_rotate_after,
            keyring_phase_settle,
            socket_path: file
                .socket_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
            state_dir: file
                .state_dir
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)),
            zfs_root: file.zfs_root.unwrap_or_else(|| DEFAULT_ZFS_ROOT.to_owned()),
            node_name: file
                .node_name
                .unwrap_or_else(|| default_node_name.to_owned()),
            socket_group: file
                .socket_group
                .unwrap_or_else(|| DEFAULT_SOCKET_GROUP.to_owned()),
            pf_mode: file.pf_mode.unwrap_or_default(),
        })
    }
}

/// Parse config file contents (pure; unit-tested).
fn parse(contents: &str, default_node_name: &str) -> anyhow::Result<Config> {
    let file: ConfigFile = toml::from_str(contents)?;
    Config::from_file(file, default_node_name)
}

/// Load configuration from `path`.
///
/// - File absent → all defaults, [`ConfigSource::Defaults`].
/// - File unreadable or malformed → fatal error naming the file and the
///   parse problem.
pub fn load(path: &Path, default_node_name: &str) -> anyhow::Result<(Config, ConfigSource)> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                Config::from_file(ConfigFile::default(), default_node_name)?,
                ConfigSource::Defaults,
            ));
        }
        Err(err) => {
            return Err(anyhow::Error::new(err)
                .context(format!("failed to read config file {}", path.display())));
        }
    };
    let config = parse(&contents, default_node_name).with_context(|| {
        format!(
            "malformed config file {}: fix the file or remove it to run with defaults",
            path.display()
        )
    })?;
    Ok((config, ConfigSource::File))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_all_defaults() {
        let config = parse("", "alpha").unwrap();
        assert_eq!(config.socket_path, PathBuf::from("/var/run/satl.sock"));
        assert_eq!(config.state_dir, PathBuf::from("/var/db/satl"));
        assert_eq!(config.zfs_root, "zroot/satl");
        assert_eq!(config.node_name, "alpha");
        assert_eq!(config.socket_group, "wheel");
        assert_eq!(config.pf_mode, PfModeConfig::Check);
        assert_eq!(config.network_name, "satl");
        assert_eq!(config.bridge(), "satl0");
        assert_eq!(config.network_pool, satl_net::DEFAULT_LOCAL_BRIDGE_POOL);
        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:2377");
        assert_eq!(config.advertise_addr, None);
        assert_eq!(config.ca_listen_addr().to_string(), "0.0.0.0:2378");
    }

    #[test]
    fn the_listen_address_is_parsed_and_validated() {
        let config = parse("listen_addr = \"10.2.0.4:7777\"\n", "alpha").unwrap();
        assert_eq!(config.listen_addr.to_string(), "10.2.0.4:7777");
        assert_eq!(config.ca_listen_addr().to_string(), "10.2.0.4:7778");
        let err = parse("listen_addr = \"nope\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("listen_addr"), "{err:#}");
    }

    #[test]
    fn the_ca_endpoint_is_one_port_above_the_manager_address() {
        assert_eq!(ca_endpoint_of("10.2.0.4:2377"), "10.2.0.4:2378");
        assert_eq!(ca_endpoint_of("[::1]:2377"), "[::1]:2378");
        // Unusable inputs come back untouched: the dial then fails naming
        // exactly what the operator typed.
        assert_eq!(ca_endpoint_of("10.2.0.4"), "10.2.0.4");
        assert_eq!(ca_endpoint_of("10.2.0.4:http"), "10.2.0.4:http");
        assert_eq!(ca_endpoint_of("10.2.0.4:65535"), "10.2.0.4:65535");
    }

    #[test]
    fn the_advertise_address_prefers_configuration_then_the_default_route() {
        let detected = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 4)));
        // Configured, with and without a port.
        assert_eq!(
            resolve_advertise_addr(Some("192.0.2.7:9999"), detected, 2377).as_deref(),
            Some("192.0.2.7:9999")
        );
        assert_eq!(
            resolve_advertise_addr(Some("192.0.2.7"), detected, 2377).as_deref(),
            Some("192.0.2.7:2377")
        );
        // Not configured: the egress address plus the listen port.
        assert_eq!(
            resolve_advertise_addr(None, detected, 2377).as_deref(),
            Some("10.2.0.4:2377")
        );
        // Blank configuration is treated as absent, not as an empty address.
        assert_eq!(
            resolve_advertise_addr(Some("  "), detected, 2377).as_deref(),
            Some("10.2.0.4:2377")
        );
        // Nothing configured and nothing detected: the leader substitutes the
        // address it sees us connect from.
        assert_eq!(resolve_advertise_addr(None, None, 2377), None);
    }

    #[test]
    fn cert_validity_is_parsed_bounded_and_defaulted() {
        // Absent: production validity.
        let config = parse("", "alpha").unwrap();
        assert_eq!(config.cert_validity, None);
        assert_eq!(
            config.effective_cert_validity(),
            satl_ca::NODE_CERT_VALIDITY
        );

        // Every unit parses.
        for (text, secs) in [("90s", 90), ("5m", 300), ("2h", 7200), ("90d", 7_776_000)] {
            let config = parse(&format!("cert_validity = \"{text}\"\n"), "alpha").unwrap();
            assert_eq!(
                config.cert_validity,
                Some(std::time::Duration::from_secs(secs)),
                "{text}"
            );
            assert_eq!(
                config.effective_cert_validity(),
                std::time::Duration::from_secs(secs)
            );
        }

        // Below the hard floor: refused, naming the field.
        let err = parse("cert_validity = \"30s\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("cert_validity"), "{err:#}");

        // Garbage: refused with the expected shape in the message.
        for bad in ["", "5", "5 minutes", "m5", "-3m", "5w"] {
            let err = parse(&format!("cert_validity = \"{bad}\"\n"), "alpha").unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("cert_validity"), "{bad}: {msg}");
        }
    }

    #[test]
    fn keyring_cadence_keys_default_to_production_and_are_honored() {
        // Absent: the production cadence, which is the orchestrator's named
        // constants — the keys must never change a default install.
        let config = parse("", "alpha").unwrap();
        assert_eq!(config.keyring_rotate_after, satl_orchestrator::ROTATE_AFTER);
        assert_eq!(config.keyring_phase_settle, satl_orchestrator::PHASE_SETTLE);
        assert_eq!(
            config.keyring_cadence(),
            satl_orchestrator::Cadence::default()
        );

        // Present: honored, and independently so.
        let config = parse(
            "keyring_rotate_after_secs = 120\nkeyring_phase_settle_secs = 10\n",
            "alpha",
        )
        .unwrap();
        assert_eq!(
            config.keyring_cadence(),
            satl_orchestrator::Cadence {
                rotate_after: std::time::Duration::from_mins(2),
                phase_settle: std::time::Duration::from_secs(10),
            }
        );
        let config = parse("keyring_rotate_after_secs = 300\n", "alpha").unwrap();
        assert_eq!(
            config.keyring_rotate_after,
            std::time::Duration::from_mins(5)
        );
        assert_eq!(config.keyring_phase_settle, satl_orchestrator::PHASE_SETTLE);

        // Garbage: TOML rejects a non-integer, serde rejects a negative one,
        // and the error names the file, not a default.
        let err = parse("keyring_rotate_after_secs = \"soon\"\n", "alpha").unwrap_err();
        assert!(
            format!("{err:#}").contains("keyring_rotate_after_secs"),
            "{err:#}"
        );
        let err = parse("keyring_phase_settle_secs = -1\n", "alpha").unwrap_err();
        assert!(
            format!("{err:#}").contains("keyring_phase_settle_secs"),
            "{err:#}"
        );
    }

    #[test]
    fn a_degenerate_keyring_cadence_is_refused() {
        // A zero rotation interval would spin the leader's rotation loop.
        let err = parse("keyring_rotate_after_secs = 0\n", "alpha").unwrap_err();
        assert!(
            format!("{err:#}").contains("keyring_rotate_after_secs"),
            "{err:#}"
        );

        // A settle time that does not fit inside the rotation interval leaves
        // no room for the rotation phases themselves: equal is refused, and
        // so is longer — against the configured interval and against the
        // defaulted one alike.
        for (rotate, settle) in [(120, 120), (120, 121)] {
            let err = parse(
                &format!(
                    "keyring_rotate_after_secs = {rotate}\nkeyring_phase_settle_secs = {settle}\n"
                ),
                "alpha",
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("keyring_phase_settle_secs"),
                "{rotate}/{settle}: {err:#}"
            );
        }
        let err = parse("keyring_phase_settle_secs = 99999999\n", "alpha").unwrap_err();
        assert!(
            format!("{err:#}").contains("keyring_phase_settle_secs"),
            "{err:#}"
        );

        // The boundary just below is valid.
        let config = parse(
            "keyring_rotate_after_secs = 120\nkeyring_phase_settle_secs = 119\n",
            "alpha",
        )
        .unwrap();
        assert_eq!(
            config.keyring_phase_settle,
            std::time::Duration::from_secs(119)
        );
    }

    #[test]
    fn metrics_addr_is_parsed_and_off_by_default() {
        let config = parse("", "alpha").unwrap();
        assert_eq!(config.metrics_addr, None);
        let config = parse("metrics_addr = \"10.2.0.4:9323\"\n", "alpha").unwrap();
        assert_eq!(config.metrics_addr, Some("10.2.0.4:9323".parse().unwrap()));
        let err = parse("metrics_addr = \"nope\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("metrics_addr"), "{err:#}");
    }

    #[test]
    fn the_network_name_drives_the_bridge_name() {
        let config = parse("network_name = \"wire\"\n", "alpha").unwrap();
        assert_eq!(config.network_name, "wire");
        assert_eq!(config.bridge(), "wire0");
    }

    #[test]
    fn an_unusable_network_name_is_rejected() {
        // Not a valid network name at all.
        let err = parse("network_name = \"-nope\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("network_name"), "{err:#}");
        // Valid, but the bridge interface name would not fit in IFNAMSIZ.
        let err = parse("network_name = \"averyverylongname\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("too long"), "{err:#}");
    }

    #[test]
    fn the_network_pool_is_parsed_and_validated() {
        let config = parse("network_pool = \"10.79.0.0/16\"\n", "alpha").unwrap();
        assert_eq!(config.network_pool.to_string(), "10.79.0.0/16");
        let err = parse("network_pool = \"not a subnet\"\n", "alpha").unwrap_err();
        assert!(format!("{err:#}").contains("network_pool"), "{err:#}");
    }

    #[test]
    fn pf_mode_values_map_to_the_network_manager_modes() {
        for (toml_value, expected, net_mode) in [
            ("enforce", PfModeConfig::Enforce, satl_net::PfMode::Enforce),
            ("check", PfModeConfig::Check, satl_net::PfMode::CheckOnly),
            (
                "disabled",
                PfModeConfig::Disabled,
                satl_net::PfMode::Disabled,
            ),
        ] {
            let config = parse(&format!("pf_mode = \"{toml_value}\"\n"), "alpha").unwrap();
            assert_eq!(config.pf_mode, expected, "{toml_value}");
            assert_eq!(config.pf_mode.as_pf_mode(), net_mode, "{toml_value}");
            assert_eq!(config.pf_mode.as_str(), toml_value);
        }
    }

    #[test]
    fn an_unknown_pf_mode_is_an_error() {
        let err = parse("pf_mode = \"maybe\"\n", "alpha").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("pf_mode"), "{msg}");
    }

    #[test]
    fn partial_file_keeps_defaults_for_missing_keys() {
        let config = parse(
            "zfs_root = \"tank/satl\"\nnode_name = \"node-a\"\n",
            "alpha",
        )
        .unwrap();
        assert_eq!(config.zfs_root, "tank/satl");
        assert_eq!(config.node_name, "node-a");
        // untouched keys keep their defaults
        assert_eq!(config.socket_path, PathBuf::from("/var/run/satl.sock"));
        assert_eq!(config.state_dir, PathBuf::from("/var/db/satl"));
        assert_eq!(config.socket_group, "wheel");
    }

    #[test]
    fn full_file_overrides_everything() {
        let config = parse(
            r#"
socket_path = "/tmp/test.sock"
state_dir = "/tmp/satl-state"
zfs_root = "tank/containers"
node_name = "worker-3"
socket_group = "operators"
pf_mode = "enforce"
network_name = "lab"
network_pool = "10.99.0.0/16"
listen_addr = "0.0.0.0:12377"
advertise_addr = "10.2.0.9:12377"
"#,
            "alpha",
        )
        .unwrap();
        assert_eq!(config.socket_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.state_dir, PathBuf::from("/tmp/satl-state"));
        assert_eq!(config.zfs_root, "tank/containers");
        assert_eq!(config.node_name, "worker-3");
        assert_eq!(config.socket_group, "operators");
        assert_eq!(config.pf_mode, PfModeConfig::Enforce);
        assert_eq!(config.network_name, "lab");
        assert_eq!(config.bridge(), "lab0");
        assert_eq!(config.network_pool.to_string(), "10.99.0.0/16");
        assert_eq!(config.listen_addr.to_string(), "0.0.0.0:12377");
        assert_eq!(config.advertise_addr.as_deref(), Some("10.2.0.9:12377"));
    }

    #[test]
    fn malformed_toml_is_an_error() {
        let err = parse("socket_path = [not toml", "alpha").unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.is_empty());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = parse("sokcet_path = \"/tmp/x.sock\"\n", "alpha").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("sokcet_path"), "{msg}");
    }

    #[test]
    fn wrong_value_type_is_an_error() {
        assert!(parse("socket_path = 42\n", "alpha").is_err());
    }

    #[test]
    fn missing_file_loads_defaults() {
        let (config, source) = load(Path::new("/nonexistent/satld.toml"), "alpha").unwrap();
        assert_eq!(source, ConfigSource::Defaults);
        assert_eq!(config.node_name, "alpha");
        assert_eq!(config.zfs_root, "zroot/satl");
    }

    #[test]
    fn malformed_file_error_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("satld.toml");
        std::fs::write(&path, "this is { not toml").unwrap();
        let err = load(&path, "alpha").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("satld.toml"), "{msg}");
        assert!(msg.contains("malformed config file"), "{msg}");
    }

    #[test]
    fn valid_file_loads_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("satld.toml");
        std::fs::write(&path, "node_name = \"from-file\"\n").unwrap();
        let (config, source) = load(&path, "alpha").unwrap();
        assert_eq!(source, ConfigSource::File);
        assert_eq!(config.node_name, "from-file");
    }
}
