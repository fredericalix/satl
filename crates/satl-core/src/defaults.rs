// SPDX-License-Identifier: BSD-2-Clause
//! Constants and defaults — single source of truth for the table in
//! `docs/architecture.md` §15 (adopted from SwarmKit, SWK §22, unless noted).
//! Keep that table in sync with any change here.

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::time::Duration;

/// Grace period between the stop signal and SIGKILL (architecture §8.2).
pub const STOP_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Delay before the restart supervisor starts a replacement task (§7.4 SWK).
pub const RESTART_DELAY: Duration = Duration::from_secs(5);

/// Docker's healthcheck defaults, from moby's `daemon/health.go`
/// (`defaultProbeInterval`, `defaultProbeTimeout`, `defaultProbeRetries`).
/// `satl_agent::health` re-exports these three under its own names, so there
/// is one source of truth for them.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Docker's default per-probe timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// Docker's default retry count.
pub const PROBE_RETRIES: u32 = 3;

/// Probe interval given to a healthcheck that leaves it unset **on a service
/// that publishes a port** (`crate::health`, `docs/api-compat.md` #125).
///
/// A published port is a `pf` redirect and `pf` does not probe its targets, so
/// the only thing that takes a dead backend out of the pool is the task being
/// stopped and replaced: detection latency is the exposure. 5 s x
/// [`PUBLISHED_PROBE_RETRIES`] is about 10 s of it, against about 90 s with
/// Docker's defaults.
pub const PUBLISHED_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Per-probe timeout for the same case. **Shorter than
/// [`PUBLISHED_PROBE_INTERVAL`] on purpose** — the prober runs one probe at a
/// time, so a timeout longer than the interval does not overlap probes, it
/// stretches the detection bound without saying so. 2 s of headroom under the
/// interval covers `ocijail exec` on a loaded box.
pub const PUBLISHED_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Consecutive failures needed for a verdict on the same case. Two at 5 s means
/// 10 s of *sustained* failure, which is what separates a dead backend from a
/// blip — and, because unhealthy and killed are one event here (api-compat
/// #88), also how eagerly the task is replaced.
pub const PUBLISHED_PROBE_RETRIES: u32 = 2;

/// The service label that opts a published port into the L4 PROXY-protocol
/// mode (M6e): `satl.publish.proxy_protocol=v2`. Docker's `PublishMode` has
/// only `host`/`ingress` and SatL rejects unknown spec fields with 400
/// (api-compat #50), so a label is the only Docker-compatible escape hatch.
/// With it, `satld` listens on the published port and relays with a PROXY v2
/// header — the task sees the real client address, which the pf mesh's SNAT
/// would otherwise mask. TCP only; UDP ports of a labeled service stay on the
/// pf path.
pub const PROXY_PROTOCOL_LABEL: &str = "satl.publish.proxy_protocol";

/// Whether the label set opts into the PROXY-protocol publish mode. Only the
/// exact value `v2` enables it: anything else is ignored, the way Docker
/// ignores labels it does not know.
#[must_use]
pub fn proxy_protocol_enabled(labels: &std::collections::BTreeMap<String, String>) -> bool {
    labels.get(PROXY_PROTOCOL_LABEL).is_some_and(|v| v == "v2")
}

/// Container-label prefix that passes a jail parameter through to ocijail:
/// `satl.jail.<param>=<value>` becomes the OCI bundle annotation
/// `org.freebsd.jail.<param>=<value>` (docs/ocijail.md §2.2). The use that
/// motivated it is `SysV` IPC — `PostgreSQL` wants `satl.jail.sysvshm=new`
/// and `satl.jail.sysvsem=new`, which the kernel default `disable` refuses —
/// but any parameter ocijail supports passes through, and ocijail warns and
/// ignores the ones it does not know. No privilege boundary is crossed:
/// whoever can create containers can already bind-mount the host into a
/// root-owned jail.
pub const JAIL_PARAM_LABEL_PREFIX: &str = "satl.jail.";

/// OCI annotation namespace ocijail reads jail parameters from.
pub const JAIL_ANNOTATION_PREFIX: &str = "org.freebsd.jail.";

/// Collect a container's `satl.jail.*` labels as ocijail bundle annotations.
/// A bare `satl.jail.` label (empty parameter name) is ignored.
#[must_use]
pub fn jail_annotations(
    labels: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    labels
        .iter()
        .filter_map(|(key, value)| {
            let param = key.strip_prefix(JAIL_PARAM_LABEL_PREFIX)?;
            if param.is_empty() {
                return None;
            }
            Some((format!("{JAIL_ANNOTATION_PREFIX}{param}"), value.clone()))
        })
        .collect()
}

/// SNAT source that makes a published port reachable from the publishing
/// host itself (`docs/api-compat.md` #35, measured in
/// `hack/experiments/lo0rdr`).
///
/// Locally generated traffic to `127.0.0.1:port` or to the host's own address
/// re-enters through `lo0`, where pf's `rdr` does fire — but the kernel then
/// refuses to forward a packet whose *source* is loopback. So `satl-net`
/// NATs the source on `lo0` to this dummy and `satld` keeps a host route
/// sending it back to `127.0.0.1`, which makes the reply non-local: it
/// re-traverses `lo0` and both pf states get their reverse pass in order.
///
/// Why this address: `198.18.0.0/15` is the RFC 2544 benchmarking block,
/// reserved and never routable, so the route is harmless — and it is outside
/// any container subnet, which is mandatory: an in-subnet dummy makes the
/// container ARP for it on its own link, nobody answers, and the reply never
/// leaves (measured with `10.88.0.254`). Keep every IPAM pool out of
/// `198.18.0.0/15`.
pub const LOOPBACK_PUBLISH_SNAT: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

/// Failure-observation window after a task starts during a rolling update.
pub const UPDATE_MONITOR: Duration = Duration::from_secs(5);

/// Upper bound on waiting for the predecessor task to stop before promoting
/// its replacement anyway (architecture §5).
pub const OLD_TASK_STOP_WAIT: Duration = Duration::from_mins(1);

/// Terminated tasks retained per slot (negative would mean keep forever,
/// SWK §4.6; with `max_attempts > 0` the effective limit is `max_attempts + 1`).
pub const TASK_HISTORY_LIMIT: i64 = 5;

/// Task reaper batching window (architecture §5).
pub const REAPER_BATCH: Duration = Duration::from_millis(250);

/// Scheduler intake debounce: commit a batch after this much quiet time.
pub const SCHEDULER_DEBOUNCE: Duration = Duration::from_millis(50);

/// Scheduler intake debounce: never delay a batch longer than this.
pub const SCHEDULER_DEBOUNCE_MAX: Duration = Duration::from_secs(1);

/// Dispatcher heartbeat period dictated to agents (architecture §7.1).
pub const HEARTBEAT_PERIOD: Duration = Duration::from_secs(5);

/// Session TTL as a multiple of the heartbeat period.
pub const HEARTBEAT_TTL_FACTOR: u32 = 3;

/// How long a node stays down before its tasks are marked `ORPHANED`.
pub const NODE_DOWN_ORPHAN_AFTER: Duration = Duration::from_hours(24);

/// Agent session reconnect backoff: base increment (architecture §7.2).
pub const SESSION_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Agent session reconnect backoff: cap.
pub const SESSION_BACKOFF_MAX: Duration = Duration::from_secs(8);

/// Node description refresh interval (architecture §8.3).
pub const DESCRIPTION_REFRESH: Duration = Duration::from_secs(20);

/// Exclusive upper bound on secret payload size in bytes (architecture §12.4).
pub const MAX_SECRET_SIZE: usize = 500 * 1024;

/// Exclusive upper bound on config payload size in bytes (architecture §12.4).
pub const MAX_CONFIG_SIZE: usize = 1000 * 1024;

/// Raft snapshot every this many applied entries (architecture §6.3).
pub const RAFT_SNAPSHOT_INTERVAL: u64 = 10_000;

/// Log entries kept after compaction for slow followers (architecture §6.3).
pub const RAFT_SLOW_FOLLOWER_ENTRIES: u64 = 500;

/// Maximum actions in one store transaction (architecture §6.1, SWK §10.5).
pub const MAX_TX_ACTIONS: usize = 200;

/// Maximum serialized size of one store transaction: 1.5 MiB (SWK §10.5).
pub const MAX_TX_BYTES: usize = 1_572_864;

/// Dynamic range for auto-assigned ingress published ports (architecture §11.4).
pub const INGRESS_PORT_RANGE: RangeInclusive<u16> = 30000..=32767;

/// Master range the allocator records *every* ingress published port in
/// (SWK §9.5): the authoritative "in use" space, of which
/// [`INGRESS_PORT_RANGE`] is the auto-assign pool.
pub const INGRESS_PORT_MASTER_RANGE: RangeInclusive<u16> = 1..=u16::MAX;

/// Default cluster-wide pool overlay subnets are carved from (architecture
/// §15). Read the live value from `ClusterSpec::default_address_pool`; this is
/// only the fallback for a cluster object that carries none.
pub const DEFAULT_OVERLAY_POOL: &str = "10.100.0.0/14";

/// Default prefix length of subnets carved from the overlay pool
/// (architecture §15, `ClusterSpec::subnet_size`).
pub const DEFAULT_SUBNET_SIZE: u8 = 24;

/// VXLAN network identifiers the allocator hands out (architecture §11.2).
///
/// The 24-bit VNI space starts at 0; SatL allocates from 4096 up, leaving the
/// low range to hand-configured or externally managed networks.
pub const OVERLAY_VNI_RANGE: RangeInclusive<u32> = 4096..=16_777_215;

/// UDP ports the allocator hands out as the per-network VTEP port of an
/// **encrypted** overlay network ([`crate::Network::vxlan_port`]).
///
/// FreeBSD's SPD matches neither the VNI nor a hashed source port, so
/// per-network `IPsec` keys need per-network UDP ports: both ends' VTEPs bind
/// the network's port (`vxlanlocalport`/`vxlanremoteport`). The pool sits
/// above the standard 4789 and below the ephemeral source-port range
/// (`net.inet.ip.portrange.first`, 10000), so a VTEP never collides with an
/// outbound flow's source port; 210 ports is generous against the number of
/// encrypted networks a cluster will have.
pub const OVERLAY_VXLAN_PORT_RANGE: RangeInclusive<u16> = 4790..=4999;

/// How often the allocator retries allocations that failed — typically for
/// want of address space (architecture §15 "Allocator retry", SWK §9.3). A
/// deallocation retries them immediately instead of waiting for this.
pub const ALLOCATOR_RETRY: Duration = Duration::from_mins(5);

/// Default REST API unix socket path (architecture §15).
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/satl.sock";

/// Default node state directory (architecture §15).
pub const DEFAULT_STATE_DIR: &str = "/var/db/satl";

/// Default ZFS root dataset (architecture §10).
pub const DEFAULT_ZFS_ROOT: &str = "zroot/satl";

/// Docker Engine API version SatL targets (architecture §13).
pub const API_VERSION: &str = "1.43";

/// Oldest Docker Engine API version accepted via version negotiation.
pub const API_MIN_VERSION: &str = "1.24";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spot_check_against_architecture_table() {
        assert_eq!(STOP_GRACE_PERIOD, Duration::from_secs(10));
        assert_eq!(RESTART_DELAY, Duration::from_secs(5));
        assert_eq!(NODE_DOWN_ORPHAN_AFTER.as_secs(), 86_400);
        assert_eq!(MAX_SECRET_SIZE, 512_000);
        assert_eq!(MAX_CONFIG_SIZE, 1_024_000);
        assert_eq!(MAX_TX_BYTES, 3 * 1024 * 1024 / 2);
    }

    /// The invariant the published-port defaults exist to hold: a probe can
    /// never outlive the cycle it runs on. The prober is sequential, so a
    /// timeout above the interval would not overlap probes — it would stretch
    /// the detection bound (retries x (interval + timeout)) with nothing in the
    /// configuration looking wrong.
    #[test]
    fn a_published_probe_timeout_is_shorter_than_its_interval() {
        assert!(
            PUBLISHED_PROBE_TIMEOUT < PUBLISHED_PROBE_INTERVAL,
            "timeout {PUBLISHED_PROBE_TIMEOUT:?} must be shorter than interval \
             {PUBLISHED_PROBE_INTERVAL:?}"
        );
        // Docker's own pairing is what this fixes: 30 s against 30 s, which
        // becomes 30 s against 5 s the moment the interval is tightened.
        assert_eq!(PROBE_TIMEOUT, PROBE_INTERVAL);
        const { assert!(PUBLISHED_PROBE_RETRIES < PROBE_RETRIES) };
        // The whole point, in numbers: worst-case detection, probes included.
        let tightened = PUBLISHED_PROBE_RETRIES
            * u32::try_from((PUBLISHED_PROBE_INTERVAL + PUBLISHED_PROBE_TIMEOUT).as_secs())
                .unwrap();
        let dockers =
            PROBE_RETRIES * u32::try_from((PROBE_INTERVAL + PROBE_TIMEOUT).as_secs()).unwrap();
        assert_eq!((tightened, dockers), (16, 180));
    }

    #[test]
    fn overlay_defaults_match_architecture_table() {
        assert_eq!(DEFAULT_OVERLAY_POOL, "10.100.0.0/14");
        assert_eq!(DEFAULT_SUBNET_SIZE, 24);
        assert_eq!(ALLOCATOR_RETRY.as_secs(), 300);
        // 24-bit VNI space, low 4096 left to hand-configured networks.
        assert_eq!(*OVERLAY_VNI_RANGE.start(), 4096);
        assert_eq!(*OVERLAY_VNI_RANGE.end(), (1 << 24) - 1);
        assert_eq!(*INGRESS_PORT_MASTER_RANGE.start(), 1);
        assert_eq!(*INGRESS_PORT_MASTER_RANGE.end(), 65535);
        // The encrypted-overlay VTEP port pool: 210 ports, above the standard
        // 4789 and below the ephemeral source-port range.
        assert_eq!(*OVERLAY_VXLAN_PORT_RANGE.start(), 4790);
        assert_eq!(*OVERLAY_VXLAN_PORT_RANGE.end(), 4999);
        assert_eq!(OVERLAY_VXLAN_PORT_RANGE.count(), 210);
    }

    /// The loopback-publish SNAT source must stay inside the RFC 2544
    /// benchmark block (never routable) and outside both default container
    /// pools — an in-subnet dummy dies on unanswered ARP in the container
    /// (measured, `hack/experiments/lo0rdr`).
    #[test]
    fn loopback_publish_snat_is_in_the_benchmark_block() {
        assert_eq!(LOOPBACK_PUBLISH_SNAT, Ipv4Addr::new(198, 18, 0, 1));
        // 198.18.0.0/15: first octet 198, second octet 18 or 19.
        let [a, b, _, _] = LOOPBACK_PUBLISH_SNAT.octets();
        assert_eq!(a, 198);
        assert!(b == 18 || b == 19);
        // Outside 10.0.0.0/8, which holds the default local bridge pool
        // (10.88.0.0/16) and the default overlay pool (10.100.0.0/14).
        assert_ne!(a, 10);
    }

    #[test]
    fn ingress_port_range_bounds() {
        assert_eq!(*INGRESS_PORT_RANGE.start(), 30000);
        assert_eq!(*INGRESS_PORT_RANGE.end(), 32767);
        assert!(INGRESS_PORT_RANGE.contains(&30000));
        assert!(INGRESS_PORT_RANGE.contains(&32767));
        assert!(!INGRESS_PORT_RANGE.contains(&29999));
        assert!(!INGRESS_PORT_RANGE.contains(&32768));
    }

    #[test]
    fn jail_labels_become_ocijail_annotations() {
        let labels = std::collections::BTreeMap::from([
            ("satl.jail.sysvshm".to_owned(), "new".to_owned()),
            ("satl.jail.".to_owned(), "ignored".to_owned()),
            ("other".to_owned(), "ignored".to_owned()),
        ]);
        assert_eq!(
            jail_annotations(&labels),
            std::collections::BTreeMap::from([(
                "org.freebsd.jail.sysvshm".to_owned(),
                "new".to_owned()
            )])
        );
        assert!(jail_annotations(&std::collections::BTreeMap::new()).is_empty());
    }
}
