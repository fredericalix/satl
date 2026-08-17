// SPDX-License-Identifier: BSD-2-Clause
//! Probe defaults for a service whose port is published, and the rule that
//! decides when they apply (`docs/api-compat.md` #125-#128).
//!
//! # Why a published service gets different defaults
//!
//! A published port is a `pf` `rdr` rule, and `pf` never probes what it
//! redirects to (`docs/operations.md`, "Published ports"). What takes a dead
//! backend out of the pool is one layer up: an unhealthy task is stopped and
//! `FAILED` (#88), so it leaves the live set and the node's port reconciler
//! rewrites the whole anchor without it. Detection latency is therefore the
//! whole of the exposure, and with Docker's defaults — `interval` 30 s,
//! `retries` 3 — it is about 90 s of traffic into a container that stopped
//! answering.
//!
//! Docker's defaults are not wrong for Docker: there, health only annotates a
//! container, and the load balancer in front of a swarm service is IPVS, which
//! the orchestrator reprograms. They are wrong *here* for the one shape where
//! the `pf` pool is the only thing between a client and the task. So the
//! tighter values are applied where they are earned and nowhere else: the
//! service publishes a port, it has a healthcheck, and the healthcheck left the
//! field unset.
//!
//! # The timeout, which is the field that could not stay as it was
//!
//! Docker's `timeout` default is 30 s — six times a 5 s interval. The prober
//! runs one probe at a time (`satl_agent::health::run_prober`: wait, probe,
//! fold, repeat), so an overlong timeout neither overlaps nor queues probes;
//! what it does is stretch the cycle, silently. A probe that hangs for 30 s on
//! a 5 s interval turns a 2-retry verdict from 10 s into 70 s, and nothing in
//! the configuration looks wrong. The bound only holds if the timeout is part
//! of it, hence the invariant this module enforces and tests:
//!
//! > the effective `timeout` is never longer than the effective `interval`.
//!
//! Two branches, because "the operator chose the cadence" and "SatL chose it"
//! deserve different answers:
//!
//! - `interval` unset too: SatL owns the whole cadence and picks
//!   [`PUBLISHED_PROBE_TIMEOUT`] (3 s against a 5 s interval), leaving 2 s of
//!   headroom for `ocijail exec` and a loaded box.
//! - `interval` set explicitly: the operator has chosen the detection latency,
//!   and tightening their timeout could only fail a slow probe that Docker
//!   would have passed. The timeout becomes `min(30 s, interval)` — Docker's
//!   value, capped so one probe cannot outlive its own cycle.
//!
//! # What is deliberately *not* here
//!
//! Nothing in this module decouples "unhealthy" from "killed". In SatL they are
//! the same event (#88), so tightening detection also makes replacement more
//! eager; that trade is documented in `docs/operations.md` under "Published
//! ports and healthchecks", and decoupling them is M6 work.

use std::time::Duration;

use crate::defaults::{
    PROBE_TIMEOUT, PUBLISHED_PROBE_INTERVAL, PUBLISHED_PROBE_RETRIES, PUBLISHED_PROBE_TIMEOUT,
};
use crate::objects::{HealthConfig, PortConfig, ServiceSpec};

impl HealthConfig {
    /// Whether this healthcheck actually makes a probe run.
    ///
    /// The same rule as `satl_agent::health::ProbeSettings::resolve`, which
    /// owns the argv and is the authority: an empty `test`, `NONE`, `""`
    /// (Docker's "inherit from the image", which SatL does not do, #91), a bare
    /// `CMD`/`CMD-SHELL` with nothing to run, and an unrecognized `test[0]`
    /// (Docker warns and runs nothing) all mean no probe.
    ///
    /// The two are kept in step by
    /// `satl-agent/src/health.rs::probes_agrees_with_the_resolver`, which runs
    /// this predicate and the resolver over the same table.
    #[must_use]
    pub fn probes(&self) -> bool {
        match self.test.split_first() {
            Some((kind, rest)) => matches!(kind.as_str(), "CMD" | "CMD-SHELL") && !rest.is_empty(),
            None => false,
        }
    }
}

impl ServiceSpec {
    /// The ports this service asks to publish, in either publish mode.
    ///
    /// Both modes, because both end up as a `rdr` rule in the same `satl/rdr`
    /// anchor on whichever node runs a task (#75, #76): what a client reaches
    /// is a port on a node either way. A `published_port` of 0 counts — it is
    /// an ingress port the allocator has not assigned yet, not the absence of
    /// one.
    #[must_use]
    pub fn published_ports(&self) -> &[PortConfig] {
        match &self.endpoint {
            Some(endpoint) => &endpoint.ports,
            None => &[],
        }
    }
}

/// Which fields [`harden_published_probe`] filled in, with the values it used.
///
/// `None` means the healthcheck already said something and was left alone — an
/// explicit value always wins.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AppliedProbeDefaults {
    /// The interval that was applied.
    pub interval: Option<Duration>,
    /// The per-probe timeout that was applied.
    pub timeout: Option<Duration>,
    /// The retry count that was applied.
    pub retries: Option<u32>,
}

impl AppliedProbeDefaults {
    /// Whether anything was applied at all.
    #[must_use]
    pub fn any(&self) -> bool {
        self.interval.is_some() || self.timeout.is_some() || self.retries.is_some()
    }

    /// The applied fields as one greppable ASCII list, e.g.
    /// `interval=5s timeout=3s retries=2`. Empty when nothing was applied.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(3);
        if let Some(interval) = self.interval {
            parts.push(format!("interval={}s", interval.as_secs()));
        }
        if let Some(timeout) = self.timeout {
            parts.push(format!("timeout={}s", timeout.as_secs()));
        }
        if let Some(retries) = self.retries {
            parts.push(format!("retries={retries}"));
        }
        parts.join(" ")
    }
}

/// What [`harden_published_probe`] found, so the caller can log it and warn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedProbe {
    /// The service publishes nothing: Docker's defaults stand untouched.
    NotPublished,
    /// It publishes `ports` and has no probe at all. Nothing was changed and
    /// the caller must warn: `RUNNING` then means only "the jail started".
    Unprobed {
        /// The published ports, as `<published>-><target>/<proto>`.
        ports: String,
    },
    /// It publishes a port and has a probe; `applied` says what was filled in
    /// (possibly nothing, when the healthcheck set everything itself).
    Probed {
        /// The published ports, as `<published>-><target>/<proto>`.
        ports: String,
        /// The defaults this call applied.
        applied: AppliedProbeDefaults,
    },
}

/// Apply the published-service probe defaults to `spec`, in place.
///
/// Called on every service create and update before the spec is stored, so the
/// values an operator reads back with `satl service inspect` are the ones the
/// prober will use — the deviation is that the stored spec is not byte-for-byte
/// what was posted (#125), and the reason is that magic defaults nobody can
/// read are worse than a visible edit.
///
/// Idempotent: a second call sees explicit values and changes nothing, which is
/// what makes `satl service update` (which reposts the stored spec) safe.
pub fn harden_published_probe(spec: &mut ServiceSpec) -> PublishedProbe {
    let ports = describe_ports(spec.published_ports());
    if ports.is_empty() {
        return PublishedProbe::NotPublished;
    }
    let Some(health) = spec.task.container.healthcheck.as_mut() else {
        return PublishedProbe::Unprobed { ports };
    };
    if !health.probes() {
        return PublishedProbe::Unprobed { ports };
    }

    let mut applied = AppliedProbeDefaults::default();
    let interval_was_set = positive(health.interval).is_some();
    if !interval_was_set {
        health.interval = Some(PUBLISHED_PROBE_INTERVAL);
        applied.interval = Some(PUBLISHED_PROBE_INTERVAL);
    }
    if positive(health.timeout).is_none() {
        // The invariant: never longer than the interval this probe will run on.
        let interval = positive(health.interval).unwrap_or(PUBLISHED_PROBE_INTERVAL);
        let timeout = if interval_was_set {
            PROBE_TIMEOUT.min(interval)
        } else {
            PUBLISHED_PROBE_TIMEOUT
        };
        health.timeout = Some(timeout);
        applied.timeout = Some(timeout);
    }
    if health.retries == 0 {
        health.retries = PUBLISHED_PROBE_RETRIES;
        applied.retries = Some(PUBLISHED_PROBE_RETRIES);
    }
    PublishedProbe::Probed { ports, applied }
}

/// Docker's `timeoutWithDefault` rule: zero or absent means "unset".
fn positive(value: Option<Duration>) -> Option<Duration> {
    value.filter(|value| *value > Duration::ZERO)
}

/// Worst-case time from a probe starting to fail to the verdict, for one
/// healthcheck: `retries` cycles, each at most an interval plus a probe that
/// runs to its timeout.
///
/// The bound an operator needs is one interval longer — a container that stops
/// serving does so between two probes — and the anchor rewrite that follows it
/// is a stop plus at most one port sweep (`docs/operations.md`).
#[must_use]
pub fn detection_bound(config: &HealthConfig) -> Duration {
    if !config.probes() {
        return Duration::ZERO;
    }
    let interval = positive(config.interval).unwrap_or(crate::defaults::PROBE_INTERVAL);
    let timeout = positive(config.timeout).unwrap_or(PROBE_TIMEOUT);
    let retries = if config.retries == 0 {
        crate::defaults::PROBE_RETRIES
    } else {
        config.retries
    };
    (interval + timeout) * retries
}

/// The published ports as one ASCII list: `8080->80/tcp`, with `auto` for an
/// ingress port the allocator has not assigned yet.
fn describe_ports(ports: &[PortConfig]) -> String {
    ports
        .iter()
        .map(|port| {
            let published = if port.published_port == 0 {
                "auto".to_owned()
            } else {
                port.published_port.to_string()
            };
            format!("{published}->{}/{}", port.target_port, port.protocol)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::defaults::{PROBE_INTERVAL, PROBE_RETRIES};
    use crate::objects::{
        Annotations, ContainerSpec, EndpointMode, EndpointSpec, Placement, PortProtocol,
        PublishMode, ResourceRequirements, RestartPolicy, ServiceMode, TaskSpec,
    };

    /// A healthcheck that runs a probe and sets nothing else.
    fn check(test: &[&str]) -> HealthConfig {
        HealthConfig {
            test: test.iter().map(|word| (*word).to_owned()).collect(),
            interval: None,
            timeout: None,
            retries: 0,
            start_period: None,
        }
    }

    fn container(healthcheck: Option<HealthConfig>) -> ContainerSpec {
        ContainerSpec {
            image: "registry.example.com/web:1".to_owned(),
            labels: BTreeMap::new(),
            command: Vec::new(),
            args: Vec::new(),
            hostname: None,
            env: Vec::new(),
            dir: None,
            user: None,
            groups: Vec::new(),
            tty: false,
            open_stdin: false,
            read_only: false,
            stop_signal: None,
            stop_grace_period: None,
            healthcheck,
            hosts: Vec::new(),
            dns_config: None,
            mounts: Vec::new(),
            secrets: Vec::new(),
            configs: Vec::new(),
            pull_options: None,
            platform: None,
        }
    }

    /// A service spec publishing `ports` (as `(published, target)` pairs, in
    /// ingress mode) with `healthcheck`.
    fn spec(ports: &[(u16, u16)], healthcheck: Option<HealthConfig>) -> ServiceSpec {
        ServiceSpec {
            annotations: Annotations {
                name: "web".to_owned(),
                labels: BTreeMap::new(),
            },
            task: TaskSpec {
                container: container(healthcheck),
                resources: ResourceRequirements::default(),
                restart: RestartPolicy::default(),
                placement: Placement::default(),
                networks: Vec::new(),
                force_update: 0,
            },
            mode: ServiceMode::Replicated { replicas: 1 },
            update: None,
            rollback: None,
            endpoint: (!ports.is_empty()).then(|| EndpointSpec {
                mode: EndpointMode::DnsRR,
                ports: ports
                    .iter()
                    .map(|(published, target)| PortConfig {
                        name: String::new(),
                        protocol: PortProtocol::Tcp,
                        target_port: *target,
                        published_port: *published,
                        publish_mode: PublishMode::Ingress,
                    })
                    .collect(),
            }),
        }
    }

    fn health_of(spec: &ServiceSpec) -> HealthConfig {
        spec.task
            .container
            .healthcheck
            .clone()
            .expect("the spec has a healthcheck")
    }

    // ---- which service shape gets what ----------------------------------

    /// The earned case: publishes a port, has a probe, set nothing.
    #[test]
    fn a_published_service_with_an_untuned_probe_gets_the_tighter_defaults() {
        let mut spec = spec(&[(8080, 80)], Some(check(&["CMD", "/bin/true"])));
        let outcome = harden_published_probe(&mut spec);
        let health = health_of(&spec);
        assert_eq!(health.interval, Some(PUBLISHED_PROBE_INTERVAL));
        assert_eq!(health.timeout, Some(PUBLISHED_PROBE_TIMEOUT));
        assert_eq!(health.retries, PUBLISHED_PROBE_RETRIES);
        // start_period is never touched: it is a property of the workload's
        // boot time, not of the pool.
        assert_eq!(health.start_period, None);
        let PublishedProbe::Probed { ports, applied } = outcome else {
            panic!("expected Probed, got {outcome:?}");
        };
        assert_eq!(ports, "8080->80/tcp");
        assert_eq!(applied.describe(), "interval=5s timeout=3s retries=2");
        // 2 x (5 + 3) rather than 3 x (30 + 30).
        assert_eq!(detection_bound(&health), Duration::from_secs(16));
    }

    /// A host-mode published port is the same exposure: a port on a node.
    #[test]
    fn host_mode_publishing_counts_too() {
        let mut spec = spec(&[(9090, 80)], Some(check(&["CMD", "/bin/true"])));
        if let Some(endpoint) = spec.endpoint.as_mut() {
            endpoint.ports[0].publish_mode = PublishMode::Host;
        }
        assert!(matches!(
            harden_published_probe(&mut spec),
            PublishedProbe::Probed { .. }
        ));
        assert_eq!(health_of(&spec).interval, Some(PUBLISHED_PROBE_INTERVAL));
    }

    /// An ingress port the allocator has not assigned yet is still a published
    /// port: `0` means "waiting for a number", not "no port".
    #[test]
    fn an_unallocated_ingress_port_still_counts() {
        let mut spec = spec(&[(0, 80)], Some(check(&["CMD", "/bin/true"])));
        let outcome = harden_published_probe(&mut spec);
        let PublishedProbe::Probed { ports, .. } = outcome else {
            panic!("expected Probed, got {outcome:?}");
        };
        assert_eq!(ports, "auto->80/tcp");
    }

    /// A service that publishes nothing keeps Docker's defaults, which is the
    /// whole point of applying these only where they are earned.
    #[test]
    fn an_unpublished_service_is_left_alone() {
        let mut spec = spec(&[], Some(check(&["CMD", "/bin/true"])));
        assert_eq!(
            harden_published_probe(&mut spec),
            PublishedProbe::NotPublished
        );
        let health = health_of(&spec);
        assert_eq!(health.interval, None);
        assert_eq!(health.timeout, None);
        assert_eq!(health.retries, 0);
        // Unset still resolves to Docker's 30s/30s/3 in the prober.
        assert_eq!(detection_bound(&health), Duration::from_mins(3));
    }

    /// An empty endpoint (`EndpointSpec` with no ports) is not publishing.
    #[test]
    fn an_endpoint_with_no_ports_is_not_publishing() {
        let mut spec = spec(&[(8080, 80)], Some(check(&["CMD", "/bin/true"])));
        if let Some(endpoint) = spec.endpoint.as_mut() {
            endpoint.ports.clear();
        }
        assert_eq!(
            harden_published_probe(&mut spec),
            PublishedProbe::NotPublished
        );
    }

    // ---- an explicit value always wins ------------------------------------

    #[test]
    fn explicit_values_are_never_overridden() {
        let mut health = check(&["CMD", "/bin/true"]);
        health.interval = Some(Duration::from_mins(1));
        health.timeout = Some(Duration::from_secs(45));
        health.retries = 7;
        let mut spec = spec(&[(8080, 80)], Some(health));
        let outcome = harden_published_probe(&mut spec);
        let health = health_of(&spec);
        assert_eq!(health.interval, Some(Duration::from_mins(1)));
        assert_eq!(health.timeout, Some(Duration::from_secs(45)));
        assert_eq!(health.retries, 7);
        let PublishedProbe::Probed { applied, .. } = outcome else {
            panic!("expected Probed, got {outcome:?}");
        };
        assert!(!applied.any(), "{applied:?}");
        assert_eq!(applied.describe(), "");
    }

    /// Docker's defaults, asked for explicitly, are honoured: this is how an
    /// operator opts back out of the tighter pool.
    #[test]
    fn dockers_defaults_can_be_asked_for_explicitly() {
        let mut health = check(&["CMD", "/bin/true"]);
        health.interval = Some(PROBE_INTERVAL);
        health.timeout = Some(PROBE_TIMEOUT);
        health.retries = PROBE_RETRIES;
        let mut spec = spec(&[(8080, 80)], Some(health));
        harden_published_probe(&mut spec);
        let health = health_of(&spec);
        assert_eq!(health.interval, Some(PROBE_INTERVAL));
        assert_eq!(health.timeout, Some(PROBE_TIMEOUT));
        assert_eq!(health.retries, PROBE_RETRIES);
        assert_eq!(detection_bound(&health), Duration::from_mins(3));
    }

    /// Zero is "unset" on the wire (Docker's `timeoutWithDefault`), so it takes
    /// the default rather than meaning "no timeout".
    #[test]
    fn zero_durations_count_as_unset() {
        let mut health = check(&["CMD", "/bin/true"]);
        health.interval = Some(Duration::ZERO);
        health.timeout = Some(Duration::ZERO);
        let mut spec = spec(&[(8080, 80)], Some(health));
        harden_published_probe(&mut spec);
        let health = health_of(&spec);
        assert_eq!(health.interval, Some(PUBLISHED_PROBE_INTERVAL));
        assert_eq!(health.timeout, Some(PUBLISHED_PROBE_TIMEOUT));
    }

    /// Applying twice must be a no-op: `satl service update` reposts the stored
    /// spec, which already carries what the first pass wrote.
    #[test]
    fn hardening_is_idempotent() {
        let mut spec = spec(&[(8080, 80)], Some(check(&["CMD", "/bin/true"])));
        harden_published_probe(&mut spec);
        let once = spec.clone();
        let outcome = harden_published_probe(&mut spec);
        assert_eq!(spec, once);
        let PublishedProbe::Probed { applied, .. } = outcome else {
            panic!("expected Probed, got {outcome:?}");
        };
        assert!(!applied.any(), "a second pass must change nothing");
    }

    // ---- the timeout invariant --------------------------------------------

    /// The invariant, over every combination the rule can produce: a probe
    /// never gets longer than the cycle it runs on.
    #[test]
    fn the_timeout_never_exceeds_the_interval() {
        for interval in [
            None,
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(20)),
            Some(Duration::from_secs(30)),
            Some(Duration::from_mins(2)),
        ] {
            let mut health = check(&["CMD", "/bin/true"]);
            health.interval = interval;
            let mut spec = spec(&[(8080, 80)], Some(health));
            harden_published_probe(&mut spec);
            let health = health_of(&spec);
            let (Some(applied_interval), Some(applied_timeout)) = (health.interval, health.timeout)
            else {
                panic!("both fields must be set after hardening: {health:?}");
            };
            assert!(
                applied_timeout <= applied_interval,
                "interval {interval:?}: timeout {applied_timeout:?} exceeds interval \
                 {applied_interval:?}"
            );
        }
    }

    /// When the operator chose the interval, the timeout is Docker's 30 s
    /// capped at that interval — tightening it further could only fail a slow
    /// probe that Docker would have passed.
    #[test]
    fn an_explicit_interval_keeps_dockers_timeout_capped_at_the_cycle() {
        let mut health = check(&["CMD", "/bin/true"]);
        health.interval = Some(Duration::from_mins(2));
        let mut long = spec(&[(8080, 80)], Some(health));
        harden_published_probe(&mut long);
        assert_eq!(health_of(&long).timeout, Some(PROBE_TIMEOUT));

        let mut health = check(&["CMD", "/bin/true"]);
        health.interval = Some(Duration::from_secs(2));
        let mut short = spec(&[(8080, 80)], Some(health));
        harden_published_probe(&mut short);
        assert_eq!(health_of(&short).timeout, Some(Duration::from_secs(2)));
    }

    // ---- the warning fires exactly when there is no probe ------------------

    #[test]
    fn a_published_service_with_no_healthcheck_at_all_is_unprobed() {
        let mut spec = spec(&[(8080, 80), (0, 443)], None);
        assert_eq!(
            harden_published_probe(&mut spec),
            PublishedProbe::Unprobed {
                ports: "8080->80/tcp auto->443/tcp".to_owned()
            }
        );
    }

    /// A healthcheck that runs nothing is no healthcheck: the same warning,
    /// because the exposure is identical.
    #[test]
    fn a_healthcheck_that_runs_nothing_is_unprobed_too() {
        for test in [
            vec![],
            vec!["NONE"],
            vec![""],
            vec!["CMD"],
            vec!["CMD-SHELL"],
            vec!["HTTP-GET", "/healthz"],
        ] {
            let mut spec = spec(&[(8080, 80)], Some(check(&test)));
            assert_eq!(
                harden_published_probe(&mut spec),
                PublishedProbe::Unprobed {
                    ports: "8080->80/tcp".to_owned()
                },
                "{test:?}"
            );
            // And nothing was written into a healthcheck that will not run.
            let health = health_of(&spec);
            assert_eq!(health.interval, None, "{test:?}");
            assert_eq!(health.retries, 0, "{test:?}");
        }
    }

    /// An unprobed service that publishes nothing is nobody's problem: no
    /// warning, no defaults.
    #[test]
    fn an_unpublished_service_with_no_healthcheck_is_not_warned_about() {
        let mut spec = spec(&[], None);
        assert_eq!(
            harden_published_probe(&mut spec),
            PublishedProbe::NotPublished
        );
    }

    #[test]
    fn probes_recognizes_exactly_the_forms_that_run_something() {
        assert!(check(&["CMD", "/bin/true"]).probes());
        assert!(check(&["CMD-SHELL", "test -f /tmp/ready"]).probes());
        for test in [
            vec![],
            vec!["NONE"],
            vec![""],
            vec!["CMD"],
            vec!["CMD-SHELL"],
            vec!["cmd", "/bin/true"],
            vec!["HTTP-GET", "/healthz"],
        ] {
            assert!(!check(&test).probes(), "{test:?}");
        }
    }
}
