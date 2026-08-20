// SPDX-License-Identifier: BSD-2-Clause
//! `satl events` -- follow the daemon's event stream.
//!
//! The daemon's `GET /events` is an unbounded NDJSON stream of the store's
//! watch feed mapped onto Docker's event vocabulary (task created ->
//! `container create`, observed state `RUNNING` -> `container start`, and so
//! on), merged with the node-local image events. It ends when the daemon
//! stops or the operator interrupts.
//!
//! Three of Docker's four flags need an honest disposition, because the
//! daemon's shape is not Docker's:
//!
//! - **`--since` is sent, and warned about.** The daemon parses it and then
//!   discards it: SatL keeps no event history, so a stream can only start
//!   now. Faking it client-side would be worse -- there is nothing to replay.
//!   A one-line warning on stderr says so and names `docs/api-compat.md` #37.
//! - **`--until` is sent, and the daemon answers `501`.** The route refuses
//!   it explicitly; that refusal is the honest answer, so it is surfaced
//!   verbatim rather than emulated by a client-side stopwatch.
//! - **`--filter` is applied here, client-side**, because the daemon never
//!   reads `filters` at all. An unsupported key is refused *before* the
//!   connection is opened -- the same discipline the prune endpoints apply to
//!   their filters (api-compat #134): a filter accepted and ignored shows an
//!   operator more than they asked to see, which is the failure mode a filter
//!   exists to prevent.
//! - **`--format` accepts `json` only.** There is no Go template engine in
//!   this CLI, and pretending otherwise would mean silently ignoring the
//!   template.

use std::collections::BTreeMap;

use hyper::Method;

use crate::api::EventMessage;
use crate::client::{self, Host};
use crate::ndjson::LineSplitter;
use crate::output::Streams;

/// The filter keys `satl events` understands, matched against what the daemon
/// actually emits (`crates/satld/src/backend/events.rs`).
const FILTER_KEYS: [&str; 6] = ["type", "event", "container", "image", "label", "scope"];

/// Flags of `satl events`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct EventsArgs {
    /// Show all events created since timestamp (sent to the daemon, which
    /// keeps no history -- see docs/api-compat.md #37).
    #[arg(long, value_name = "TIMESTAMP")]
    pub since: Option<String>,

    /// Stream events until this timestamp (not supported by the daemon yet).
    #[arg(long, value_name = "TIMESTAMP")]
    pub until: Option<String>,

    /// Filter output based on conditions provided; repeatable. Supported
    /// keys: type, event, container, image, label, scope.
    #[arg(short, long, value_name = "KEY=VALUE")]
    pub filter: Vec<String>,

    /// Format the output. Only `json` is supported: the raw event line is
    /// printed verbatim.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
}

/// How each event is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Docker's human line.
    Human,
    /// The daemon's own NDJSON line, verbatim.
    Json,
}

/// The stderr line `--since` earns: the daemon takes the parameter and drops
/// it, so a stream that looks like a replay is really starting now.
const SINCE_WARNING: &str = "--since is accepted and ignored by the daemon: SatL keeps no event \
                             history, so this stream starts now (docs/api-compat.md #37).";

/// Run `satl events`: stream `GET /events` and print what passes the filters.
pub async fn execute(host: &Host, args: &EventsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    // Both client-side rejections happen before the socket is touched.
    let filters = parse_filters(&args.filter)?;
    let format = parse_format(args.format.as_deref())?;

    if args.since.is_some() {
        streams.warn(SINCE_WARNING).await;
    }

    let path = events_path(args.since.as_deref(), args.until.as_deref());
    let mut body = client::stream(host, &Method::GET, &path, None).await?;
    let mut lines = LineSplitter::default();
    while let Some(chunk) = body.next_chunk().await? {
        for line in lines.push(&chunk) {
            emit(&line, &filters, format, streams).await?;
        }
    }
    if let Some(line) = lines.finish() {
        emit(&line, &filters, format, streams).await?;
    }
    Ok(0)
}

/// Decode one NDJSON line, drop it if the filters reject it, print the rest.
async fn emit(
    line: &str,
    filters: &[(String, String)],
    format: Format,
    streams: &mut Streams,
) -> anyhow::Result<()> {
    let event: EventMessage = serde_json::from_str(line)
        .map_err(|err| anyhow::anyhow!("unreadable event line from the daemon: {err}"))?;
    if !matches(&event, filters) {
        return Ok(());
    }
    match format {
        Format::Human => streams.outln(&render_event(&event)).await,
        // Verbatim: whatever the daemon sent, byte for byte, so that piping
        // `satl events --format json` into a parser sees the wire document.
        Format::Json => streams.outln(line).await,
    }
    Ok(())
}

/// Build the `GET /events` URL. Both timestamps go up untouched: the daemon
/// owns the parsing, and its error message is the one worth showing.
#[must_use]
pub fn events_path(since: Option<&str>, until: Option<&str>) -> String {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(since) = since {
        pairs.push(("since", since));
    }
    if let Some(until) = until {
        pairs.push(("until", until));
    }
    format!("/events{}", client::query(&pairs))
}

/// Parse `--format`. Anything but `json` is refused rather than ignored.
fn parse_format(value: Option<&str>) -> anyhow::Result<Format> {
    match value {
        None => Ok(Format::Human),
        Some("json") => Ok(Format::Json),
        Some(other) => anyhow::bail!(
            "invalid format {other:?}: satl events supports --format json only \
             (there is no Go template engine in this CLI)"
        ),
    }
}

/// Parse `-f/--filter KEY=VALUE` pairs, refusing an unsupported key.
///
/// Pure, and deliberately called before the connection is opened: a filter
/// silently dropped would show the operator events they asked to hide.
pub fn parse_filters(raw: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut parsed = Vec::with_capacity(raw.len());
    for filter in raw {
        let Some((key, value)) = filter.split_once('=') else {
            anyhow::bail!("invalid filter {filter:?}: expected KEY=VALUE");
        };
        let key = key.trim().to_ascii_lowercase();
        if !FILTER_KEYS.contains(&key.as_str()) {
            anyhow::bail!(
                "invalid filter {key:?}: satl events supports {}",
                FILTER_KEYS.join(", ")
            );
        }
        parsed.push((key, value.to_owned()));
    }
    Ok(parsed)
}

/// Whether an event passes the filters: values of one key are OR-ed, keys are
/// AND-ed together, exactly as Docker's `filters.Args` matches.
#[must_use]
pub fn matches(event: &EventMessage, filters: &[(String, String)]) -> bool {
    let mut by_key: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (key, value) in filters {
        by_key.entry(key.as_str()).or_default().push(value.as_str());
    }
    by_key
        .iter()
        .all(|(key, values)| values.iter().any(|value| matches_one(event, key, value)))
}

/// One `key=value` against one event.
fn matches_one(event: &EventMessage, key: &str, value: &str) -> bool {
    let attribute = |name: &str| event.actor.attributes.get(name).map(String::as_str);
    match key {
        "type" => event.kind == value,
        "event" => event.action == value,
        // A container is named by its task ID or by its container name; the
        // daemon puts both on the event.
        "container" => {
            event.kind == "container"
                && (event.actor.id == value || attribute("name") == Some(value))
        }
        // On an image event the actor *is* the reference; on a container
        // event the image the task runs is an attribute.
        "image" => match event.kind.as_str() {
            "image" => event.actor.id == value || attribute("name") == Some(value),
            "container" => attribute("image") == Some(value),
            _ => false,
        },
        // `label=key` tests presence, `label=key=value` tests the value --
        // Docker's rule, and the one `satl run -l` writes into the task spec.
        "label" => match value.split_once('=') {
            Some((name, expected)) => attribute(name) == Some(expected),
            None => event.actor.attributes.contains_key(value),
        },
        "scope" => event.scope == value,
        // Unreachable: `parse_filters` refuses unknown keys before this runs.
        _ => false,
    }
}

/// Docker's human event line (pure, for goldens):
/// `<timestamp> <type> <action> <actor id> (k=v, k=v)`.
///
/// The timestamp is UTC with a fixed nine-digit fraction (Go's
/// `RFC3339NanoFixed`, which is what `docker events` prints). Docker renders
/// it in the *local* zone; this CLI has no timezone database and refuses to
/// guess an offset, so it says `Z` and means it.
#[must_use]
pub fn render_event(event: &EventMessage) -> String {
    let mut line = format!(
        "{} {} {} {}",
        timestamp(event),
        event.kind,
        event.action,
        event.actor.id
    );
    if !event.actor.attributes.is_empty() {
        use std::fmt::Write as _;
        let attributes: Vec<String> = event
            .actor
            .attributes
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        // Writing into a `String` is infallible.
        let _ = write!(line, " ({})", attributes.join(", "));
    }
    line
}

/// The event's instant, preferring the nanosecond field the daemon always
/// sends and falling back to whole seconds.
fn timestamp(event: &EventMessage) -> String {
    let nanos = if event.time_nano == 0 {
        event.time.saturating_mul(1_000_000_000)
    } else {
        event.time_nano
    };
    rfc3339_nano_fixed(nanos)
}

/// Unix nanoseconds -> `YYYY-MM-DDTHH:MM:SS.fffffffffZ`.
///
/// The inverse of [`crate::format::parse_rfc3339_seconds`]: Howard Hinnant's
/// civil-from-days, so no calendar crate is needed for the one place the CLI
/// prints an absolute date.
fn rfc3339_nano_fixed(unix_nanos: i64) -> String {
    let seconds = unix_nanos.div_euclid(1_000_000_000);
    let fraction = unix_nanos.rem_euclid(1_000_000_000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{fraction:09}Z",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    )
}

/// Days since the unix epoch -> `(year, month, day)`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    /// One container event, exactly as `render::event` serializes it.
    const START: &str = r#"{"Type":"container","Action":"start","Actor":{"ID":"2ju54ic19pyb","Attributes":{"image":"nginx:1.27","name":"web"}},"scope":"local","time":1755613351,"timeNano":1755613351114882000}"#;
    /// One image event, with a label-free actor.
    const PULL: &str = r#"{"Type":"image","Action":"pull","Actor":{"ID":"nginx:1.27","Attributes":{"name":"nginx:1.27"}},"scope":"local","time":1755613300,"timeNano":1755613300000000000}"#;

    fn event(raw: &str) -> EventMessage {
        serde_json::from_str(raw).expect("fixture parses")
    }

    fn filters(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn path_carries_only_the_timestamps_that_were_given() {
        assert_eq!(events_path(None, None), "/events");
        assert_eq!(
            events_path(Some("1755613351"), None),
            "/events?since=1755613351"
        );
        assert_eq!(
            events_path(Some("2026-08-19T14:00:00Z"), Some("2026-08-19T15:00:00Z")),
            "/events?since=2026-08-19T14%3A00%3A00Z&until=2026-08-19T15%3A00%3A00Z"
        );
    }

    #[test]
    fn human_line_golden() {
        assert_eq!(
            render_event(&event(START)),
            "2025-08-19T14:22:31.114882000Z container start 2ju54ic19pyb \
             (image=nginx:1.27, name=web)"
        );
    }

    #[test]
    fn an_actor_without_attributes_prints_no_parentheses() {
        let destroy = r#"{"Type":"container","Action":"destroy","Actor":{"ID":"2ju54ic19pyb","Attributes":{}},"scope":"local","time":0,"timeNano":0}"#;
        assert_eq!(
            render_event(&event(destroy)),
            "1970-01-01T00:00:00.000000000Z container destroy 2ju54ic19pyb"
        );
    }

    /// `timeNano` is what the line is built from; `time` is the fallback for
    /// a daemon that only sent seconds.
    #[test]
    fn seconds_are_used_when_the_nanosecond_field_is_absent() {
        let seconds_only = r#"{"Type":"image","Action":"tag","Actor":{"ID":"web:1"},"scope":"local","time":1755613351}"#;
        assert_eq!(
            render_event(&event(seconds_only)),
            "2025-08-19T14:22:31.000000000Z image tag web:1"
        );
    }

    #[test]
    fn calendar_conversion_round_trips_against_the_parser() {
        for stamp in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T12:34:56Z",
            "2024-12-31T23:59:59Z",
            "2026-08-19T14:22:31Z",
        ] {
            let seconds = crate::format::parse_rfc3339_seconds(stamp).expect("parses");
            assert_eq!(
                rfc3339_nano_fixed(seconds * 1_000_000_000),
                format!("{}.000000000Z", stamp.trim_end_matches('Z')),
            );
        }
    }

    #[test]
    fn filters_parse_into_lowercase_pairs() {
        let parsed = parse_filters(&filters(&["Type=container", "label=role=web"])).unwrap();
        assert_eq!(
            parsed,
            vec![
                ("type".to_owned(), "container".to_owned()),
                ("label".to_owned(), "role=web".to_owned()),
            ]
        );
    }

    #[test]
    fn an_unsupported_filter_key_is_refused_with_the_supported_list() {
        let err = parse_filters(&filters(&["daemon=alpha"])).unwrap_err();
        assert!(
            err.to_string().contains("invalid filter \"daemon\""),
            "{err}"
        );
        assert!(err.to_string().contains("type, event, container"), "{err}");

        let err = parse_filters(&filters(&["container"])).unwrap_err();
        assert!(err.to_string().contains("expected KEY=VALUE"), "{err}");
    }

    #[test]
    fn format_accepts_json_and_refuses_a_template() {
        assert_eq!(parse_format(None).unwrap(), Format::Human);
        assert_eq!(parse_format(Some("json")).unwrap(), Format::Json);
        let err = parse_format(Some("{{.Actor.ID}}")).unwrap_err();
        assert!(err.to_string().contains("--format json only"), "{err}");
        assert!(err.to_string().contains("Go template engine"), "{err}");
    }

    #[test]
    fn no_filters_match_everything() {
        assert!(matches(&event(START), &[]));
        assert!(matches(&event(PULL), &[]));
    }

    #[test]
    fn keys_are_anded_and_values_of_one_key_are_ored() {
        let start = event(START);
        let both = parse_filters(&filters(&["type=container", "event=start"])).unwrap();
        assert!(matches(&start, &both));
        let conflicting = parse_filters(&filters(&["type=container", "event=die"])).unwrap();
        assert!(!matches(&start, &conflicting));
        let either = parse_filters(&filters(&["event=die", "event=start"])).unwrap();
        assert!(matches(&start, &either));
    }

    #[test]
    fn container_matches_the_task_id_and_the_name() {
        let start = event(START);
        for value in ["container=2ju54ic19pyb", "container=web"] {
            assert!(
                matches(&start, &parse_filters(&filters(&[value])).unwrap()),
                "{value}"
            );
        }
        assert!(!matches(
            &start,
            &parse_filters(&filters(&["container=db"])).unwrap()
        ));
        // An image event is never a container.
        assert!(!matches(
            &event(PULL),
            &parse_filters(&filters(&["container=nginx:1.27"])).unwrap()
        ));
    }

    #[test]
    fn image_matches_the_reference_on_both_event_kinds() {
        let filter = parse_filters(&filters(&["image=nginx:1.27"])).unwrap();
        assert!(matches(&event(START), &filter), "the image a task runs");
        assert!(
            matches(&event(PULL), &filter),
            "the actor of an image event"
        );
    }

    #[test]
    fn label_tests_presence_or_value() {
        let labelled = r#"{"Type":"container","Action":"create","Actor":{"ID":"x","Attributes":{"name":"web","role":"front"}},"scope":"local","time":1,"timeNano":1000000000}"#;
        let event = event(labelled);
        assert!(matches(
            &event,
            &parse_filters(&filters(&["label=role"])).unwrap()
        ));
        assert!(matches(
            &event,
            &parse_filters(&filters(&["label=role=front"])).unwrap()
        ));
        assert!(!matches(
            &event,
            &parse_filters(&filters(&["label=role=back"])).unwrap()
        ));
        assert!(!matches(
            &event,
            &parse_filters(&filters(&["label=zone"])).unwrap()
        ));
    }

    #[test]
    fn scope_matches_the_daemons_scope() {
        assert!(matches(
            &event(START),
            &parse_filters(&filters(&["scope=local"])).unwrap()
        ));
        assert!(!matches(
            &event(START),
            &parse_filters(&filters(&["scope=swarm"])).unwrap()
        ));
    }

    fn stream_body() -> Vec<u8> {
        format!("{START}\n{PULL}\n").into_bytes()
    }

    #[tokio::test]
    async fn events_streams_the_human_lines() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, out, err) = testing::streams();
        let code = execute(&stub.host(), &EventsArgs::default(), &mut streams)
            .await
            .expect("events streams");
        assert_eq!(code, 0);
        assert_eq!(
            out.contents(),
            "2025-08-19T14:22:31.114882000Z container start 2ju54ic19pyb \
             (image=nginx:1.27, name=web)\n\
             2025-08-19T14:21:40.000000000Z image pull nginx:1.27 (name=nginx:1.27)\n"
        );
        assert!(err.contents().is_empty(), "{}", err.contents());
        assert_eq!(stub.first_call("GET /events").unwrap().query, "");
    }

    #[tokio::test]
    async fn json_format_prints_the_daemons_line_verbatim() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, out, _err) = testing::streams();
        let args = EventsArgs {
            format: Some("json".to_owned()),
            ..EventsArgs::default()
        };
        execute(&stub.host(), &args, &mut streams)
            .await
            .expect("events streams");
        assert_eq!(out.contents(), format!("{START}\n{PULL}\n"));
    }

    #[tokio::test]
    async fn filters_are_applied_client_side_and_never_reach_the_daemon() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, out, _err) = testing::streams();
        let args = EventsArgs {
            filter: filters(&["type=image"]),
            ..EventsArgs::default()
        };
        execute(&stub.host(), &args, &mut streams)
            .await
            .expect("events streams");
        assert!(
            out.contents().starts_with("2025-08-19T14:21:40"),
            "{}",
            out.contents()
        );
        assert!(
            !out.contents().contains("container start"),
            "{}",
            out.contents()
        );
        // The daemon reads no `filters` parameter, so sending one would be a
        // lie about where the filtering happened.
        assert_eq!(stub.first_call("GET /events").unwrap().query, "");
    }

    #[tokio::test]
    async fn since_is_sent_and_warned_about() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, _out, err) = testing::streams();
        let args = EventsArgs {
            since: Some("1755613351".to_owned()),
            ..EventsArgs::default()
        };
        execute(&stub.host(), &args, &mut streams)
            .await
            .expect("events streams");
        assert_eq!(
            stub.first_call("GET /events").unwrap().query,
            "since=1755613351"
        );
        let warning = err.contents();
        assert!(
            warning.starts_with("WARNING: --since is accepted and ignored"),
            "{warning}"
        );
        assert!(warning.contains("docs/api-compat.md #37"), "{warning}");
        assert!(warning.is_ascii(), "operator text must be ASCII: {warning}");
    }

    /// The route answers `501`; the CLI must show that, not emulate `until`.
    #[tokio::test]
    async fn until_surfaces_the_daemons_refusal() {
        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/events",
            Reply::json(
                501,
                r#"{"message":"the until parameter of /events is not supported yet"}"#,
            ),
        );

        let (mut streams, _out, _err) = testing::streams();
        let args = EventsArgs {
            until: Some("1755613400".to_owned()),
            ..EventsArgs::default()
        };
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .expect_err("501 is an error");
        assert_eq!(
            err.to_string(),
            "Error response from daemon: the until parameter of /events is not supported yet"
        );
        assert_eq!(
            stub.first_call("GET /events").unwrap().query,
            "until=1755613400"
        );
    }

    #[tokio::test]
    async fn an_unsupported_filter_key_opens_no_connection() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, out, _err) = testing::streams();
        let args = EventsArgs {
            filter: filters(&["daemon=alpha"]),
            ..EventsArgs::default()
        };
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .expect_err("an unknown filter key is refused");
        assert!(
            err.to_string().contains("invalid filter \"daemon\""),
            "{err}"
        );
        assert!(out.contents().is_empty());
        assert!(
            stub.calls().is_empty(),
            "a client-side rejection must not reach the daemon"
        );
    }

    #[tokio::test]
    async fn a_go_template_opens_no_connection() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, stream_body()));

        let (mut streams, _out, _err) = testing::streams();
        let args = EventsArgs {
            format: Some("{{json .}}".to_owned()),
            ..EventsArgs::default()
        };
        let err = execute(&stub.host(), &args, &mut streams)
            .await
            .expect_err("a template is refused");
        assert!(err.to_string().contains("--format json only"), "{err}");
        assert!(stub.calls().is_empty());
    }

    #[tokio::test]
    async fn a_corrupt_line_names_the_stream() {
        let stub = Stub::start().await;
        stub.on("GET", "/events", Reply::raw(200, b"not json\n".to_vec()));

        let (mut streams, _out, _err) = testing::streams();
        let err = execute(&stub.host(), &EventsArgs::default(), &mut streams)
            .await
            .expect_err("a corrupt line is an error");
        assert!(err.to_string().contains("unreadable event line"), "{err}");
    }
}
