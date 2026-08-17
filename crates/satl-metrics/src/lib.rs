// SPDX-License-Identifier: BSD-2-Clause
//! Prometheus metrics for SatL: the registry, the typed metric families, the
//! text encoder, and the standalone `/metrics` HTTP listener.
//!
//! Two naming regimes share one registry, deliberately (see
//! `docs/api-compat.md`):
//!
//! - where dockerd itself defines a metric SatL has an equivalent of, SatL
//!   uses **Docker's exact name** (`engine_daemon_*`, `http_requests_total`)
//!   so off-the-shelf Docker dashboards render unchanged;
//! - everything else is `satl_*`. One name per fact, no duplicate series.
//!
//! Two ways in, on purpose:
//!
//! - long-lived components (satld's collectors) hold a [`Metrics`] clone and
//!   set gauges directly — that is the injected dependency;
//! - leaf code that cannot plausibly be threaded a handle (the external
//!   command runners, the health prober, the API middleware) calls the
//!   process-global helpers ([`record_command_failure`], [`record_health_check`],
//!   [`observe_http_request`]), which no-op until satld installs the instance
//!   with [`Metrics::install_global`]. Counters and histograms only: concurrent
//!   unit tests sharing the process cannot corrupt anything.

mod server;

pub use server::serve;

use std::sync::{Arc, OnceLock, RwLock};

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Default histogram buckets: the prometheus `client_golang` defaults dockerd's
/// own timers use, so a `http_requests_total` panel keeps the same shape.
const LATENCY_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// `state=` on `engine_daemon_container_states_containers` — Docker's three
/// values, emitted even at zero so a dashboard panel never goes missing.
pub const CONTAINER_STATES: [&str; 3] = ["running", "paused", "stopped"];

/// `role=` on `satl_raft_role`: openraft's states plus `none` for a worker
/// (no raft on this node).
pub const RAFT_ROLES: [&str; 5] = ["leader", "follower", "candidate", "learner", "none"];

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct StateLabels {
    pub state: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RoleLabels {
    pub role: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HttpLabels {
    pub method: String,
    pub code: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ToolLabels {
    pub tool: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SweepLabels {
    pub sweep: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SweepOutcomeLabels {
    pub sweep: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TaskLabels {
    pub task_id: String,
}

/// Labels of `engine_daemon_engine_info`, set once at daemon startup to 1 —
/// Docker's info-metric shape.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EngineInfoLabels {
    pub version: String,
    pub commit: String,
    pub architecture: String,
    pub graphdriver: String,
    pub kernel: String,
    pub os: String,
    pub os_type: String,
    pub os_version: String,
    pub daemon_id: String,
}

/// The registry and every family registered in it. Cheap to clone; all
/// families are internally shared, so a clone writes to the same series.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<RwLock<Registry>>,

    // Docker's names (docs/api-compat.md): keep byte-exact.
    container_states: Family<StateLabels, Gauge>,
    health_checks: Counter,
    health_checks_failed: Counter,
    engine_info: Family<EngineInfoLabels, Gauge>,
    engine_cpus: Gauge,
    engine_memory_bytes: Gauge,
    http_requests: Family<HttpLabels, Histogram>,

    // SatL's own.
    raft_role: Family<RoleLabels, Gauge>,
    raft_leader_id: Gauge,
    raft_term: Gauge,
    raft_last_applied_index: Gauge,
    tasks: Family<StateLabels, Gauge>,
    services: Gauge,
    reconcile_pass_seconds: Family<SweepLabels, Histogram>,
    reconcile_passes: Family<SweepOutcomeLabels, Counter>,
    command_failures: Family<ToolLabels, Counter>,
    dispatcher_sessions: Gauge,
    node_certificate_not_after: Gauge,
    container_memory_usage_bytes: Family<TaskLabels, Gauge>,
    container_cpu_time_seconds: Family<TaskLabels, Gauge>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A registry with every series registered (families start empty, plain
    /// gauges/counters at zero).
    ///
    /// Registration names carry the suffixes dockerd's go-metrics unit system
    /// would append (`_info`, `_cpus`, `_bytes`), because the text encoder
    /// here renders the registered name verbatim for gauges and histograms —
    /// only counters get a `_total` from the encoder itself.
    #[must_use]
    pub fn new() -> Self {
        let metrics = Self {
            registry: Arc::new(RwLock::new(Registry::default())),
            container_states: Family::default(),
            health_checks: Counter::default(),
            health_checks_failed: Counter::default(),
            engine_info: Family::default(),
            engine_cpus: Gauge::default(),
            engine_memory_bytes: Gauge::default(),
            http_requests: Family::new_with_constructor(|| Histogram::new(LATENCY_BUCKETS)),
            raft_role: Family::default(),
            raft_leader_id: Gauge::default(),
            raft_term: Gauge::default(),
            raft_last_applied_index: Gauge::default(),
            tasks: Family::default(),
            services: Gauge::default(),
            reconcile_pass_seconds: Family::new_with_constructor(|| {
                Histogram::new(LATENCY_BUCKETS)
            }),
            reconcile_passes: Family::default(),
            command_failures: Family::default(),
            dispatcher_sessions: Gauge::default(),
            node_certificate_not_after: Gauge::default(),
            container_memory_usage_bytes: Family::default(),
            container_cpu_time_seconds: Family::default(),
        };
        let mut registry = Registry::default();
        metrics.register_docker_series(&mut registry);
        metrics.register_satl_series(&mut registry);
        *metrics.registry.write().expect("fresh registry") = registry;
        // Fixed-shape families are seeded at zero so a dashboard panel never
        // goes missing between daemon start and the first collector pass.
        metrics.set_container_states(0, 0, 0);
        metrics.set_raft("none", 0, 0, 0);
        metrics
    }

    /// Docker's names (docs/api-compat.md): keep byte-exact, suffixes included.
    fn register_docker_series(&self, registry: &mut Registry) {
        registry.register(
            "engine_daemon_container_states_containers",
            "The count of containers in various states",
            self.container_states.clone(),
        );
        registry.register(
            "engine_daemon_health_checks",
            "The total number of health checks",
            self.health_checks.clone(),
        );
        registry.register(
            "engine_daemon_health_checks_failed",
            "The total number of failed health checks",
            self.health_checks_failed.clone(),
        );
        registry.register(
            "engine_daemon_engine_info",
            "The information related to the engine and the OS it is running on",
            self.engine_info.clone(),
        );
        registry.register(
            "engine_daemon_engine_cpus_cpus",
            "The number of cpus that the host system of the engine has",
            self.engine_cpus.clone(),
        );
        registry.register(
            "engine_daemon_engine_memory_bytes",
            "The number of bytes of memory that the host system of the engine has",
            self.engine_memory_bytes.clone(),
        );
        registry.register(
            "http_requests_total",
            "The number of HTTP requests on the Docker API, by method and response code",
            self.http_requests.clone(),
        );
    }

    /// SatL's own series: the `satl_*` prefix the project committed to at M0.
    fn register_satl_series(&self, registry: &mut Registry) {
        registry.register(
            "satl_raft_role",
            "The raft state of this node, 1 on the current role (none on a worker)",
            self.raft_role.clone(),
        );
        registry.register(
            "satl_raft_leader_id",
            "Raft id of the current known leader (0: unknown or no raft on this node)",
            self.raft_leader_id.clone(),
        );
        registry.register(
            "satl_raft_term",
            "Current raft term (0 on a worker)",
            self.raft_term.clone(),
        );
        registry.register(
            "satl_raft_last_applied_index",
            "Highest raft log index applied to the state machine (0 on a worker)",
            self.raft_last_applied_index.clone(),
        );
        registry.register(
            "satl_tasks",
            "Cluster tasks by state, as this manager's store sees them",
            self.tasks.clone(),
        );
        registry.register(
            "satl_services",
            "Services in the cluster store (0 on a worker)",
            self.services.clone(),
        );
        registry.register(
            "satl_reconcile_pass_seconds",
            "Duration of one reconciliation pass, by sweep",
            self.reconcile_pass_seconds.clone(),
        );
        registry.register(
            "satl_reconcile_passes",
            "Reconciliation passes, by sweep and outcome",
            self.reconcile_passes.clone(),
        );
        registry.register(
            "satl_external_command_failures",
            "Failed external command invocations (zfs, ifconfig, pfctl, ocijail, rctl), by tool",
            self.command_failures.clone(),
        );
        registry.register(
            "satl_dispatcher_sessions",
            "Agent dispatcher sessions currently established with this manager",
            self.dispatcher_sessions.clone(),
        );
        registry.register(
            "satl_node_certificate_not_after_timestamp_seconds",
            "Expiry of this node's certificate, seconds since the epoch",
            self.node_certificate_not_after.clone(),
        );
        registry.register(
            "satl_container_memory_usage_bytes",
            "Current memory usage (rctl memoryuse) of a running task's jail",
            self.container_memory_usage_bytes.clone(),
        );
        registry.register(
            "satl_container_cpu_time_seconds",
            "Accumulated CPU time (rctl cputime) of a running task's jail",
            self.container_cpu_time_seconds.clone(),
        );
    }

    /// Install this instance as the process-global sink the leaf helpers
    /// below write to, returning the instance actually installed. Called once
    /// by satld after construction.
    ///
    /// A second install (only possible in tests) keeps the first: counters
    /// already handed out would otherwise silently split across instances.
    /// Tests should assert against the *returned* handle, never against a
    /// fresh instance they tried to install — which test installed first is
    /// not defined.
    #[must_use]
    pub fn install_global(&self) -> Metrics {
        GLOBAL.get_or_init(|| self.clone()).clone()
    }

    /// Prometheus text exposition format (`text/plain; version=0.0.4`).
    ///
    /// The encoder writes `# HELP`/`# TYPE` with the registered name but
    /// appends `_total` to counter *samples*; promtool and dockerd's own
    /// exposition reconcile the two the other way, with the full sample name
    /// in the headers. Rewrite the counter headers, so `promtool check
    /// metrics` is clean and a diff against dockerd's output is minimal.
    #[must_use]
    pub fn encode(&self) -> String {
        let registry = self.registry.read().expect("registry lock poisoned");
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry)
            .expect("encoding to a String cannot fail");
        for base in COUNTER_BASES {
            for kind in ["# HELP ", "# TYPE "] {
                out = out.replace(&format!("{kind}{base} "), &format!("{kind}{base}_total "));
            }
        }
        out
    }

    /// `engine_daemon_engine_info{...} 1` plus host cpu/memory, once at startup.
    pub fn set_engine_info(&self, labels: &EngineInfoLabels, cpus: i64, memory_bytes: i64) {
        self.engine_info.get_or_create(labels).set(1);
        self.engine_cpus.set(cpus);
        self.engine_memory_bytes.set(memory_bytes);
    }

    /// Container counts by Docker state, from the node's local task view.
    pub fn set_container_states(&self, running: i64, paused: i64, stopped: i64) {
        for (state, count) in [
            ("running", running),
            ("paused", paused),
            ("stopped", stopped),
        ] {
            self.container_states
                .get_or_create(&StateLabels {
                    state: state.to_owned(),
                })
                .set(count);
        }
    }

    /// Raft snapshot; `leader_id` 0 means "none known". `role` is one of
    /// [`RAFT_ROLES`]; anything else is coerced to `none` so a bad value
    /// cannot invent a new label. A worker reports `none` and zeros.
    pub fn set_raft(&self, role: &str, leader_id: i64, term: i64, last_applied: i64) {
        let role = if RAFT_ROLES.contains(&role) {
            role
        } else {
            "none"
        };
        for candidate in RAFT_ROLES {
            self.raft_role
                .get_or_create(&RoleLabels {
                    role: candidate.to_owned(),
                })
                .set(i64::from(candidate == role));
        }
        self.raft_leader_id.set(leader_id);
        self.raft_term.set(term);
        self.raft_last_applied_index.set(last_applied);
    }

    /// Replace the whole task-state view with this pass's counts, from
    /// `satl_core::TaskState`'s lowercase Display. The collector clears and
    /// re-sets the store view each pass, so states at zero simply vanish.
    pub fn set_tasks(&self, counts: &[(String, i64)]) {
        self.tasks.clear();
        for (state, count) in counts {
            self.tasks
                .get_or_create(&StateLabels {
                    state: state.clone(),
                })
                .set(*count);
        }
    }

    /// Service count (manager view; 0 on a worker).
    pub fn set_services(&self, count: i64) {
        self.services.set(count);
    }

    /// One reconciliation pass done: duration and outcome.
    pub fn observe_reconcile_pass(&self, sweep: &str, outcome: &str, seconds: f64) {
        self.reconcile_pass_seconds
            .get_or_create(&SweepLabels {
                sweep: sweep.to_owned(),
            })
            .observe(seconds);
        self.reconcile_passes
            .get_or_create(&SweepOutcomeLabels {
                sweep: sweep.to_owned(),
                outcome: outcome.to_owned(),
            })
            .inc();
    }

    /// Agent dispatcher sessions currently established (manager view).
    pub fn set_dispatcher_sessions(&self, count: i64) {
        self.dispatcher_sessions.set(count);
    }

    /// Node certificate expiry, seconds since the epoch.
    pub fn set_node_certificate_not_after(&self, epoch_seconds: i64) {
        self.node_certificate_not_after.set(epoch_seconds);
    }

    /// Replace the whole per-task usage view with this pass's live set.
    ///
    /// `Family` has no removal, and per-task cardinality must follow the live
    /// set (one series set per task): the collector clears and re-sets every
    /// cadence, which costs nothing at these sizes and never leaks a dead
    /// task's series.
    pub fn set_container_usages(&self, usages: &[(String, i64, i64)]) {
        self.container_memory_usage_bytes.clear();
        self.container_cpu_time_seconds.clear();
        for (task_id, memory_bytes, cpu_seconds) in usages {
            let labels = TaskLabels {
                task_id: task_id.clone(),
            };
            self.container_memory_usage_bytes
                .get_or_create(&labels)
                .set(*memory_bytes);
            self.container_cpu_time_seconds
                .get_or_create(&labels)
                .set(*cpu_seconds);
        }
    }
}

/// Registered counter base names (without the `_total` the encoder appends
/// to samples) — [`Metrics::encode`] rewrites their `# HELP`/`# TYPE` headers.
const COUNTER_BASES: [&str; 4] = [
    "engine_daemon_health_checks",
    "engine_daemon_health_checks_failed",
    "satl_reconcile_passes",
    "satl_external_command_failures",
];

static GLOBAL: OnceLock<Metrics> = OnceLock::new();

/// One external command invocation failed. Called from the typed command
/// runners (`satl-storage`'s zfs, `satl-net`'s ifconfig/pfctl, `satl-overlay`'s
/// ifconfig, `satl-runtime`'s ocijail, `satl-agent`'s rctl) — no-op until
/// [`Metrics::install_global`].
pub fn record_command_failure(tool: &'static str) {
    if let Some(metrics) = GLOBAL.get() {
        metrics
            .command_failures
            .get_or_create(&ToolLabels {
                tool: tool.to_owned(),
            })
            .inc();
    }
}

/// [`record_command_failure`] for a call site that only has the binary path:
/// reduced to the tool name (`/sbin/pfctl` -> `pfctl`), so the `tool=` label
/// cardinality is the handful of wrapped binaries, never argv shapes.
pub fn record_command_failure_for(program: &std::path::Path) {
    let tool = program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    if let Some(metrics) = GLOBAL.get() {
        metrics
            .command_failures
            .get_or_create(&ToolLabels {
                tool: tool.to_owned(),
            })
            .inc();
    }
}

/// One container health check ran. Docker counts both the total and the
/// failures, so SatL does the same under Docker's names.
pub fn record_health_check(failed: bool) {
    if let Some(metrics) = GLOBAL.get() {
        metrics.health_checks.inc();
        if failed {
            metrics.health_checks_failed.inc();
        }
    }
}

/// One reconciliation pass completed, with its duration. Called from satld's
/// two node sweeps (`reconcile.rs`) — no-op until [`Metrics::install_global`].
pub fn observe_reconcile_pass(sweep: &'static str, outcome: &'static str, seconds: f64) {
    if let Some(metrics) = GLOBAL.get() {
        metrics.observe_reconcile_pass(sweep, outcome, seconds);
    }
}

/// One Docker API request completed. Method is lowercased to match Docker's
/// label values (`method="get"`).
pub fn observe_http_request(method: &str, code: u16, seconds: f64) {
    if let Some(metrics) = GLOBAL.get() {
        metrics
            .http_requests
            .get_or_create(&HttpLabels {
                method: method.to_ascii_lowercase(),
                code: code.to_string(),
            })
            .observe(seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_registry_exposes_the_fixed_series() {
        let metrics = Metrics::new();
        let out = metrics.encode();
        // Plain gauges/counters and the seeded families render at zero; the
        // on-demand families (http_requests, tasks, reconcile, per-task usage)
        // appear with their first observation, like any label family.
        for name in [
            "engine_daemon_container_states_containers{state=\"running\"} 0",
            "engine_daemon_container_states_containers{state=\"paused\"} 0",
            "engine_daemon_container_states_containers{state=\"stopped\"} 0",
            "engine_daemon_health_checks_total 0",
            "engine_daemon_health_checks_failed_total 0",
            "engine_daemon_engine_cpus_cpus 0",
            "engine_daemon_engine_memory_bytes 0",
            "satl_raft_role{role=\"leader\"} 0",
            "satl_raft_role{role=\"none\"} 1",
            "satl_raft_leader_id 0",
            "satl_raft_term 0",
            "satl_raft_last_applied_index 0",
            "satl_services 0",
            "satl_dispatcher_sessions 0",
            "satl_node_certificate_not_after_timestamp_seconds 0",
        ] {
            assert!(out.contains(name), "missing {name} in:\n{out}");
        }
    }

    #[test]
    fn docker_named_series_take_dockers_shape() {
        let metrics = Metrics::new();
        metrics.set_container_states(3, 0, 2);
        metrics.set_engine_info(
            &EngineInfoLabels {
                version: "0.1.0".to_owned(),
                commit: "abc".to_owned(),
                architecture: "amd64".to_owned(),
                graphdriver: "zfs".to_owned(),
                kernel: "15.1-RELEASE-p2".to_owned(),
                os: "FreeBSD".to_owned(),
                os_type: "freebsd".to_owned(),
                os_version: "15.1".to_owned(),
                daemon_id: "node-1".to_owned(),
            },
            4,
            8_589_934_592,
        );
        let out = metrics.encode();
        assert!(
            out.contains("engine_daemon_container_states_containers{state=\"running\"} 3"),
            "{out}"
        );
        assert!(
            out.contains("engine_daemon_container_states_containers{state=\"paused\"} 0"),
            "{out}"
        );
        assert!(
            out.contains("engine_daemon_container_states_containers{state=\"stopped\"} 2"),
            "{out}"
        );
        assert!(out.contains("engine_daemon_engine_cpus_cpus 4"), "{out}");
        assert!(
            out.contains("engine_daemon_engine_memory_bytes 8589934592"),
            "{out}"
        );
        assert!(out.contains("engine_daemon_engine_info{"), "{out}");
        assert!(out.contains("graphdriver=\"zfs\""), "{out}");
    }

    #[test]
    fn raft_role_marks_exactly_one_role() {
        let metrics = Metrics::new();
        metrics.set_raft("leader", 7, 12, 340);
        let out = metrics.encode();
        assert!(out.contains("satl_raft_role{role=\"leader\"} 1"), "{out}");
        assert!(out.contains("satl_raft_role{role=\"follower\"} 0"), "{out}");
        assert!(out.contains("satl_raft_leader_id 7"), "{out}");
        assert!(out.contains("satl_raft_term 12"), "{out}");
        assert!(out.contains("satl_raft_last_applied_index 340"), "{out}");
    }

    #[test]
    fn container_and_task_series_follow_the_live_set() {
        let metrics = Metrics::new();
        metrics
            .set_container_usages(&[("task-a".to_owned(), 100, 5), ("task-b".to_owned(), 200, 9)]);
        // Next pass: task-a is gone, task-c appeared.
        metrics
            .set_container_usages(&[("task-b".to_owned(), 210, 11), ("task-c".to_owned(), 50, 1)]);
        metrics.set_tasks(&[("running".to_owned(), 2)]);
        metrics.set_tasks(&[("complete".to_owned(), 1)]);
        let out = metrics.encode();
        assert!(!out.contains("task-a"), "{out}");
        assert!(
            out.contains("satl_container_memory_usage_bytes{task_id=\"task-b\"} 210"),
            "{out}"
        );
        assert!(
            out.contains("satl_container_cpu_time_seconds{task_id=\"task-c\"} 1"),
            "{out}"
        );
        assert!(!out.contains("satl_tasks{state=\"running\"}"), "{out}");
        assert!(out.contains("satl_tasks{state=\"complete\"} 1"), "{out}");
    }

    #[test]
    fn counter_headers_carry_the_total_suffix_promtool_expects() {
        // Assert on the instance that actually got installed (see
        // install_global): the headers exist regardless of which test
        // installed first, and no exact count is ever checked against a
        // shared global.
        let installed = Metrics::new().install_global();
        record_health_check(true);
        let out = installed.encode();
        assert!(
            out.contains("# HELP engine_daemon_health_checks_total "),
            "{out}"
        );
        assert!(
            out.contains("# TYPE engine_daemon_health_checks_total counter"),
            "{out}"
        );
        assert!(
            out.contains("# HELP engine_daemon_health_checks_failed_total "),
            "{out}"
        );
    }

    #[test]
    fn reconcile_and_http_histograms_render_as_histograms() {
        let metrics = Metrics::new();
        // The reconcile pass goes through the instance method, no global.
        metrics.observe_reconcile_pass("port", "ok", 0.012);
        let out = metrics.encode();
        assert!(
            out.contains("satl_reconcile_pass_seconds_bucket{le=\"0.025\",sweep=\"port\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("satl_reconcile_passes_total{sweep=\"port\",outcome=\"ok\"} 1"),
            "{out}"
        );

        // The http/command-failure helpers only exist as globals; assert the
        // label shape appears on the installed instance, never an exact value
        // (other tests share it).
        let installed = Metrics::new().install_global();
        observe_http_request("GET", 200, 0.004);
        record_command_failure("pfctl");
        let out = installed.encode();
        assert!(
            out.contains("http_requests_total_bucket{le=\"0.005\",method=\"get\",code=\"200\"}"),
            "{out}"
        );
        assert!(
            out.contains("satl_external_command_failures_total{tool=\"pfctl\"}"),
            "{out}"
        );
    }
}
