// SPDX-License-Identifier: BSD-2-Clause
//! A `tracing` span must never leak from one task into another.
//!
//! The background loops here are long-lived futures that want a span over
//! everything they log. The tempting way to write that -- build the span, hold
//! an `Entered` guard for the body -- is wrong for an `async fn`: `Entered`
//! un-enters the span when it is *dropped*, and a parked future drops nothing.
//! The span therefore stays on the worker thread's span stack while the future
//! is suspended, and the next task the runtime polls on that same thread picks
//! it up as its contextual parent.
//!
//! The damage is not cosmetic. `CLAUDE.md` tells operators that spans carry the
//! identifiers to correlate by and to grep by id rather than read
//! chronologically; a wrong parent attributes one subsystem's events to
//! another, which is how someone ends up debugging the wrong component. The
//! symptom seen on the cluster was `dispatcher.sweep{...}:agent.session{...}`
//! and even three-deep chains mixing both dispatcher loops.
//!
//! These tests drive the real production loops on a **current-thread** runtime,
//! which is what forces every task onto one thread and makes the leak
//! deterministic, and assert the exact span ancestry of recorded events. They
//! fail against a `span.enter()` implementation and pass against
//! `tracing::Instrument`.
//!
//! Each test also asserts the loop's *own* events still carry its span, so that
//! deleting the instrumentation is not a way to make them pass.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use satl_core::Id;
use satl_dispatcher::agent::{Agent, AgentConfig, ChannelFactory, ConnectError, SessionReporter};
use satl_dispatcher::manager::{Dispatcher, DispatcherConfig};
use satl_dispatcher::peer::Endpoint;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

#[path = "../src/testing.rs"]
mod testing;

use testing::{RecordingSink, TestCluster};

// ---------------------------------------------------------------------------
// Recording layer
// ---------------------------------------------------------------------------

/// One recorded event: what emitted it, and the span names above it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventRecord {
    /// The event's `message` field, which is how the loops identify themselves.
    message: String,
    /// Span names from the root down to the innermost, i.e. exactly the chain
    /// the log formatter prints as `a{..}:b{..}:`.
    ancestry: Vec<String>,
}

/// A `Layer` that records `(message, span ancestry)` for every event.
#[derive(Clone, Default)]
struct SpanRecorder {
    events: Arc<Mutex<Vec<EventRecord>>>,
}

impl SpanRecorder {
    fn new() -> Self {
        Self::default()
    }

    fn events(&self) -> Vec<EventRecord> {
        self.events.lock().expect("recorder lock").clone()
    }

    /// The ancestry of the one event whose message is `message`.
    ///
    /// Panics when the event is missing or ambiguous: both mean the test is no
    /// longer observing what it claims to.
    fn ancestry_of(&self, message: &str) -> Vec<String> {
        let matching: Vec<EventRecord> = self
            .events()
            .into_iter()
            .filter(|record| record.message == message)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one {message:?} event, got {matching:#?}"
        );
        matching[0].ancestry.clone()
    }
}

/// Pulls the `message` field out of an event; other fields are not needed here.
#[derive(Default)]
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.0);
        }
    }
}

impl<S> Layer<S> for SpanRecorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let mut ancestry = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                ancestry.push(span.name().to_owned());
            }
        }
        self.events
            .lock()
            .expect("recorder lock")
            .push(EventRecord {
                message: visitor.0,
                ancestry,
            });
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Runs `body` on a **current-thread** runtime with `recorder` installed for
/// this thread only.
///
/// Both halves matter. The single thread is what puts every task on one span
/// stack, so a leaked `Entered` is guaranteed to be observed rather than merely
/// likely. Installing the subscriber thread-locally (rather than globally) is
/// what lets several of these tests share one test binary.
fn with_recorder<F: std::future::Future<Output = ()>>(recorder: &SpanRecorder, body: F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let subscriber = tracing_subscriber::registry().with(recorder.clone());
    tracing::subscriber::with_default(subscriber, || runtime.block_on(body));
}

/// Emits one event under a fresh `probe` span, standing in for any unrelated
/// task the runtime happens to poll next.
///
/// A span's parent is resolved from `Span::current()` when it is *built*, which
/// is precisely the thread-local state a leaked guard corrupts -- so building
/// the span here, after the loops have parked, is the whole measurement.
fn probe() {
    let span = tracing::info_span!("probe");
    // A guard in a synchronous scope, dropped before this function returns and
    // never held across an await: the shape that is always correct.
    let _guard = span.enter();
    tracing::info!("probe event");
}

/// Yields enough times for every spawned task to be polled and reach its first
/// await, which is the moment a guard-based loop leaks its span.
async fn let_the_loops_park() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// The loop spans are the roots of their own tasks; none may ever appear nested
/// under anything. This is the reported symptom stated directly:
/// `dispatcher.sweep{..}:agent.session{..}` and the three-deep chains.
fn assert_no_loop_span_is_nested(recorder: &SpanRecorder) {
    const TASK_ROOTS: [&str; 3] = ["dispatcher.sweep", "dispatcher.status", "agent.session"];
    for record in recorder.events() {
        for (depth, name) in record.ancestry.iter().enumerate() {
            assert!(
                !(TASK_ROOTS.contains(&name.as_str()) && depth > 0),
                "{name} is a task-root span but appears at depth {depth} in {:?} \
                 (event {:?}); a span leaked across tasks",
                record.ancestry,
                record.message
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Manager side: sweep_loop and status_loop
// ---------------------------------------------------------------------------

/// Both dispatcher loops park on their first await while a third piece of work
/// runs on the same thread. That work must be parented by its own span only.
#[test]
fn the_manager_loops_do_not_leak_their_spans_into_other_tasks() {
    let recorder = SpanRecorder::new();
    with_recorder(&recorder, async {
        let cluster = TestCluster::start().await;
        let manager_id = cluster.node_id().clone();
        let shutdown = CancellationToken::new();

        let dispatcher = Dispatcher::new(
            cluster.store().clone(),
            manager_id,
            DispatcherConfig::default(),
        );
        let loops = dispatcher.spawn(shutdown.clone());
        let_the_loops_park().await;

        probe();

        shutdown.cancel();
        for handle in loops {
            let _ = handle.await;
        }
        cluster.shutdown().await;
    });

    // The loops still own their own events: this is an instrumentation fix, not
    // a deletion, and removing the spans must not be a way to pass.
    assert_eq!(
        recorder.ancestry_of("dispatcher sweep loop started"),
        vec!["dispatcher.sweep"],
    );
    assert_eq!(
        recorder.ancestry_of("dispatcher status loop started"),
        vec!["dispatcher.status"],
    );
    // ... and nothing else is dragged under them.
    assert_eq!(recorder.ancestry_of("probe event"), vec!["probe"]);
    assert_no_loop_span_is_nested(&recorder);
}

// ---------------------------------------------------------------------------
// Worker side: Agent::run
// ---------------------------------------------------------------------------

/// A connector that never yields a channel.
///
/// The agent under test is configured with no managers at all, so `connect` is
/// never reached; it exists only to satisfy the type.
struct NeverConnects;

impl ChannelFactory for NeverConnects {
    async fn connect(&self, _endpoint: &Endpoint) -> Result<Channel, ConnectError> {
        Err(ConnectError::new(std::io::Error::other(
            "this test never dials",
        )))
    }
}

/// The agent session loop parks in its back-off sleep while other work runs on
/// the same thread. That work must not inherit `agent.session`.
#[test]
fn the_agent_session_loop_does_not_leak_its_span_into_other_tasks() {
    let recorder = SpanRecorder::new();
    with_recorder(&recorder, async {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = satl_agent::TaskDb::open(dir.path()).expect("task db");
        let shutdown = CancellationToken::new();

        // No bootstrap managers and no local socket: the loop finds nothing to
        // dial, reports `NoManager`, and parks in its back-off sleep -- one
        // full iteration of the real loop, with no transport needed.
        let mut config = AgentConfig::new(Id::generate());
        config.description_refresh = Duration::from_hours(1);
        let agent = Agent::new(
            config,
            RecordingSink::new(),
            NeverConnects,
            db,
            SessionReporter::new(),
            Arc::new(|| testing::description("worker-1")),
        );
        let handle = agent.spawn(shutdown.clone());
        let_the_loops_park().await;

        probe();

        shutdown.cancel();
        let _ = handle.await;
    });

    assert_eq!(
        recorder.ancestry_of("agent session loop started"),
        vec!["agent.session"],
    );
    assert_eq!(recorder.ancestry_of("probe event"), vec!["probe"]);
    assert_no_loop_span_is_nested(&recorder);
}
