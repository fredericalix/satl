// SPDX-License-Identifier: BSD-2-Clause
//! `satl ps` — list containers.
//!
//! Columns are docker's, plus the SatL `PLATFORM` extension between `PORTS`
//! and `NAMES` (architecture §10: the resolved image platform decides whether
//! a task runs as a native or a linuxulator jail, so it is operator-visible).

use crate::api::ContainerSummary;
use crate::client::{self, Host};
use crate::format::{self, Table};

/// Flags of `satl ps`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PsArgs {
    /// Show all containers (default shows just running).
    #[arg(short, long)]
    pub all: bool,

    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display container IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Fetch the container list and render it.
pub async fn execute(host: &Host, args: &PsArgs) -> anyhow::Result<String> {
    let path = format!(
        "/containers/json{}",
        client::query(&[("all", if args.all { "true" } else { "false" })])
    );
    let containers: Vec<ContainerSummary> = client::get_json(host, &path).await?;
    Ok(render(&containers, args, format::now_unix()))
}

/// Render the table (pure: the clock is injected so goldens are stable).
pub fn render(containers: &[ContainerSummary], args: &PsArgs, now_unix: i64) -> String {
    if args.quiet {
        let mut out = String::new();
        for container in containers {
            out.push_str(&id_cell(&container.id, args.no_trunc));
            out.push('\n');
        }
        return out;
    }

    let mut table = Table::new(&[
        "CONTAINER ID",
        "IMAGE",
        "COMMAND",
        "CREATED",
        "STATUS",
        "PORTS",
        "PLATFORM",
        "NAMES",
    ]);
    for container in containers {
        table.push(vec![
            id_cell(&container.id, args.no_trunc),
            container.image.clone(),
            format::command_cell(&container.command, args.no_trunc),
            format::created_ago(container.created, now_unix),
            status_cell(container),
            format::display_ports(&container.ports),
            container.platform.clone(),
            format::display_names(&container.names),
        ]);
    }
    table.render()
}

fn id_cell(id: &str, no_trunc: bool) -> String {
    if no_trunc {
        id.to_owned()
    } else {
        format::truncate_id(id)
    }
}

/// The daemon computes `Status` (`Up 2 minutes`); fall back to the coarse
/// state if it did not, so the column is never blank.
fn status_cell(container: &ContainerSummary) -> String {
    if !container.status.is_empty() {
        return container.status.clone();
    }
    let mut chars = container.state.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::PortSummary;

    const NOW: i64 = 1_800_000_000;

    fn sample() -> Vec<ContainerSummary> {
        vec![
            ContainerSummary {
                id: "b7c1d3e5f6a7b8c9d0e1f2a3b4c5d6e7".to_owned(),
                names: vec!["/web".to_owned()],
                image: "127.0.0.1:5000/freebsd-nginx:v1".to_owned(),
                command: "/docker-entrypoint.sh nginx -g daemon off;".to_owned(),
                created: NOW - 180,
                ports: vec![PortSummary {
                    ip: "0.0.0.0".to_owned(),
                    private_port: 80,
                    public_port: Some(8080),
                    typ: "tcp".to_owned(),
                }],
                state: "running".to_owned(),
                status: "Up 3 minutes".to_owned(),
                platform: "freebsd/amd64".to_owned(),
            },
            ContainerSummary {
                id: "0f0f0f0f0f0f11112222333344445555".to_owned(),
                names: vec!["/busy_moore".to_owned()],
                image: "alpine".to_owned(),
                command: "sh".to_owned(),
                created: NOW - 7200,
                ports: Vec::new(),
                state: "exited".to_owned(),
                status: "Exited (0) 2 hours ago".to_owned(),
                platform: "linux/amd64".to_owned(),
            },
        ]
    }

    #[test]
    fn column_golden() {
        let rendered = render(&sample(), &PsArgs::default(), NOW);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("CONTAINER ID   IMAGE"), "{}", lines[0]);
        assert!(lines[0].contains("PORTS"));
        // PLATFORM sits between PORTS and NAMES.
        let ports = lines[0].find("PORTS").unwrap();
        let platform = lines[0].find("PLATFORM").unwrap();
        let names = lines[0].find("NAMES").unwrap();
        assert!(ports < platform && platform < names, "{}", lines[0]);
        assert!(lines[1].starts_with("b7c1d3e5f6a7   127.0.0.1:5000/freebsd-nginx:v1   "));
        assert!(lines[1].contains("\"/docker-entrypoint.…\""));
        assert!(lines[1].contains("3 minutes ago"));
        assert!(lines[1].contains("0.0.0.0:8080->80/tcp"));
        assert!(lines[1].contains("freebsd/amd64"));
        assert!(lines[1].ends_with("web"));
        assert!(lines[2].contains("2 hours ago"));
        assert!(lines[2].ends_with("busy_moore"));
    }

    #[test]
    fn exact_layout_golden() {
        let rendered = render(&sample()[1..], &PsArgs::default(), NOW);
        let expected = "\
CONTAINER ID   IMAGE    COMMAND   CREATED       STATUS                   PORTS   PLATFORM      NAMES
0f0f0f0f0f0f   alpine   \"sh\"      2 hours ago   Exited (0) 2 hours ago           linux/amd64   busy_moore
";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn quiet_prints_truncated_ids_only() {
        let args = PsArgs {
            quiet: true,
            ..PsArgs::default()
        };
        assert_eq!(
            render(&sample(), &args, NOW),
            "b7c1d3e5f6a7\n0f0f0f0f0f0f\n"
        );
    }

    #[test]
    fn no_trunc_keeps_full_ids_and_commands() {
        let args = PsArgs {
            no_trunc: true,
            ..PsArgs::default()
        };
        let rendered = render(&sample(), &args, NOW);
        assert!(rendered.contains("b7c1d3e5f6a7b8c9d0e1f2a3b4c5d6e7"));
        assert!(rendered.contains("\"/docker-entrypoint.sh nginx -g daemon off;\""));
    }

    #[test]
    fn empty_list_still_prints_headers() {
        let rendered = render(&[], &PsArgs::default(), NOW);
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.starts_with("CONTAINER ID"));
        assert!(rendered.ends_with("NAMES\n"));
    }

    #[tokio::test]
    async fn fetches_all_when_asked_and_renders_the_daemon_list() {
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/containers/json",
            Reply::json(
                200,
                r#"[{"Id":"0f0f0f0f0f0f11112222","Names":["/web"],"Image":"nginx",
                     "Command":"nginx","Created":1,"State":"running","Status":"Up 1 second",
                     "Platform":"freebsd/amd64","Ports":[]}]"#,
            ),
        );
        let args = PsArgs {
            all: true,
            ..PsArgs::default()
        };
        let table = execute(&stub.host(), &args).await.unwrap();
        assert!(table.contains("0f0f0f0f0f0f   nginx"), "{table}");
        assert!(table.contains("freebsd/amd64"), "{table}");
        assert_eq!(
            stub.first_call("GET /containers/json").unwrap().query,
            "all=true"
        );
    }

    #[test]
    fn status_falls_back_to_the_state() {
        let container = ContainerSummary {
            state: "created".to_owned(),
            ..ContainerSummary::default()
        };
        assert_eq!(status_cell(&container), "Created");
    }
}
