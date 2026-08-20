// SPDX-License-Identifier: BSD-2-Clause
//! `satl network ls|create|inspect|rm`.
//!
//! The `SCOPE` column is the one worth reading: `local` is a node-local
//! bridge(4) network, `swarm` is a VXLAN overlay that spans the cluster
//! (architecture §11.1, §11.2). It is the driver's consequence, not a separate
//! choice — `-d overlay` implies `swarm`.

use std::collections::BTreeMap;

use crate::api::{
    CreateNetworkBody, CreateNetworkResponse, Ipam, IpamConfig, Network, NetworksPruneResponse,
};
use crate::client::{self, Host};
use crate::cmd::{FAILURE, system};
use crate::format::{self, Table};
use crate::output::Streams;
use crate::parse;

/// Subcommands of `satl network`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum NetworkCommand {
    /// List networks.
    Ls(LsArgs),
    /// Create a network.
    Create(CreateArgs),
    /// Display detailed information on one or more networks.
    Inspect(InspectArgs),
    /// Remove one or more networks.
    Rm(RmArgs),
    /// Remove all unused networks.
    Prune(PruneArgs),
}

/// Flags of `satl network ls`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LsArgs {
    /// Do not truncate the output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display network IDs.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl network create`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CreateArgs {
    /// Driver to manage the network (`bridge`, `overlay`).
    #[arg(short, long, value_name = "DRIVER")]
    pub driver: Option<String>,

    /// Subnet in CIDR format representing a network segment.
    #[arg(long, value_name = "CIDR")]
    pub subnet: Option<String>,

    /// IPv4 gateway for the master subnet.
    #[arg(long, value_name = "IP")]
    pub gateway: Option<String>,

    /// Set metadata on a network.
    #[arg(long, value_name = "KEY=VALUE")]
    pub label: Vec<String>,

    /// Driver options (`encrypted` is the only one SatL reads, overlay only).
    #[arg(long, value_name = "KEY=VALUE")]
    pub opt: Vec<String>,

    /// Network name.
    #[arg(value_name = "NETWORK")]
    pub name: String,
}

/// Flags of `satl network inspect`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InspectArgs {
    /// Networks to inspect.
    #[arg(required = true, value_name = "NETWORK")]
    pub networks: Vec<String>,
}

/// Flags of `satl network rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// Networks to remove.
    #[arg(required = true, value_name = "NETWORK")]
    pub networks: Vec<String>,
}

/// Flags of `satl network prune`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct PruneArgs {
    /// Do not prompt for confirmation.
    #[arg(short, long)]
    pub force: bool,
}

/// Dispatch a `satl network` subcommand.
pub async fn execute(
    host: &Host,
    command: &NetworkCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        NetworkCommand::Ls(args) => {
            let networks: Vec<Network> = client::get_json(host, "/networks").await?;
            streams.out(render(&networks, args).as_bytes()).await;
            Ok(0)
        }
        NetworkCommand::Create(args) => {
            let body = create_body(args)?;
            let created: CreateNetworkResponse =
                client::post_json(host, "/networks/create", Some(&body)).await?;
            if !created.warning.is_empty() {
                streams.error(&created.warning).await;
            }
            // Docker prints the full ID of the network it created.
            let id = if created.id.is_empty() {
                body.name.clone()
            } else {
                created.id
            };
            streams.outln(&id).await;
            Ok(0)
        }
        NetworkCommand::Inspect(args) => inspect(host, args, streams).await,
        NetworkCommand::Rm(args) => remove(host, args, streams).await,
        NetworkCommand::Prune(args) => prune(host, args, streams).await,
    }
}

/// `satl network prune [-f]`.
///
/// The one verb of the prune family that reports no space at all: a network
/// is a store object and a handful of interfaces, not a dataset, so there is
/// nothing on disk to reclaim and a `Total reclaimed space: 0B` line would
/// only invite the question of why it is always zero. Networks are cluster
/// objects, so this removes them cluster-wide (api-compat #130's other half).
async fn prune(host: &Host, args: &PruneArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    if !args.force {
        streams.out(PRUNE_WARNING.as_bytes()).await;
        if !system::confirmed().await {
            return Ok(0);
        }
    }
    let pruned: NetworksPruneResponse = client::post_empty_json(host, "/networks/prune").await?;
    streams.out(render_prune(&pruned).as_bytes()).await;
    Ok(0)
}

/// The confirmation text of `satl network prune`.
const PRUNE_WARNING: &str = "WARNING! This will remove all networks not used by at least one \
                             container.\nNetworks are cluster objects, so this acts on the whole \
                             cluster.\nAre you sure you want to continue? [y/N] ";

/// Docker's `network prune` summary (pure, for goldens).
#[must_use]
pub fn render_prune(pruned: &NetworksPruneResponse) -> String {
    if pruned.networks_deleted.is_empty() {
        return String::new();
    }
    let mut text = String::from("Deleted Networks:\n");
    for name in &pruned.networks_deleted {
        text.push_str(name);
        text.push('\n');
    }
    text
}

fn create_body(args: &CreateArgs) -> anyhow::Result<CreateNetworkBody> {
    let mut labels = BTreeMap::new();
    for label in &args.label {
        let (key, value) = parse::parse_label(label)?;
        labels.insert(key, value);
    }
    let mut options = BTreeMap::new();
    for opt in &args.opt {
        let (key, value) = parse::parse_label(opt)?;
        // The daemon would 400 any other key; failing here saves the round
        // trip and keeps the wording in the operator's own vocabulary.
        if key != "encrypted" {
            anyhow::bail!(
                "invalid driver option {key:?}: encrypted is the only driver option SatL reads"
            );
        }
        // Docker muscle memory types a bare `--opt encrypted`; the daemon's
        // contract is that an empty value is a 400, so the bare spelling is
        // normalized to `true` here, client-side.
        let value = if value.is_empty() {
            "true".to_owned()
        } else {
            value
        };
        options.insert(key, value);
    }
    let subnet = args.subnet.clone().unwrap_or_default();
    let gateway = args.gateway.clone().unwrap_or_default();
    // The daemon rejects a gateway without a subnet; send the pair as Docker
    // does — one `IPAM.Config` entry — and only when something was asked for.
    let ipam = (!subnet.is_empty() || !gateway.is_empty()).then(|| Ipam {
        config: vec![IpamConfig { subnet, gateway }],
    });
    Ok(CreateNetworkBody {
        name: args.name.clone(),
        driver: args.driver.clone().unwrap_or_default(),
        ipam,
        options,
        labels,
    })
}

async fn inspect(host: &Host, args: &InspectArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut found: Vec<serde_json::Value> = Vec::new();
    let mut failed = false;
    for network in &args.networks {
        let path = format!("/networks/{network}");
        match client::get_json::<serde_json::Value>(host, &path).await {
            Ok(value) => found.push(value),
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    streams.outln(&crate::cmd::inspect::render(&found)).await;
    Ok(if failed { FAILURE } else { 0 })
}

async fn remove(host: &Host, args: &RmArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let mut failed = false;
    for network in &args.networks {
        let path = format!("/networks/{network}");
        match client::delete_ok(host, &path).await {
            Ok(()) => streams.outln(network).await,
            Err(err) => {
                streams.error(&format!("{err:#}")).await;
                failed = true;
            }
        }
    }
    Ok(if failed { FAILURE } else { 0 })
}

/// Render `network ls` (pure, for goldens).
#[must_use]
pub fn render(networks: &[Network], args: &LsArgs) -> String {
    if args.quiet {
        let mut out = String::new();
        for network in networks {
            out.push_str(&id_cell(&network.id, args.no_trunc));
            out.push('\n');
        }
        return out;
    }
    let mut table = Table::new(&["NETWORK ID", "NAME", "DRIVER", "SCOPE"]);
    for network in networks {
        table.push(vec![
            id_cell(&network.id, args.no_trunc),
            network.name.clone(),
            network.driver.clone(),
            network.scope.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Network> {
        vec![
            Network {
                id: "1hvy0lj3x0b883f8e30fyp217".to_owned(),
                name: "satl0".to_owned(),
                driver: "bridge".to_owned(),
                scope: "local".to_owned(),
                ..Network::default()
            },
            Network {
                id: "2r1h539fesw6ri0hn141a994y".to_owned(),
                name: "blue".to_owned(),
                driver: "overlay".to_owned(),
                scope: "swarm".to_owned(),
                ..Network::default()
            },
        ]
    }

    #[test]
    fn ls_golden() {
        let expected = "\
NETWORK ID     NAME    DRIVER    SCOPE
1hvy0lj3x0b8   satl0   bridge    local
2r1h539fesw6   blue    overlay   swarm
";
        assert_eq!(render(&sample(), &LsArgs::default()), expected);
    }

    #[test]
    fn ls_quiet_prints_ids_and_no_trunc_keeps_them_whole() {
        let quiet = LsArgs {
            quiet: true,
            no_trunc: false,
        };
        assert_eq!(render(&sample(), &quiet), "1hvy0lj3x0b8\n2r1h539fesw6\n");
        let full = LsArgs {
            quiet: true,
            no_trunc: true,
        };
        assert_eq!(
            render(&sample(), &full),
            "1hvy0lj3x0b883f8e30fyp217\n2r1h539fesw6ri0hn141a994y\n"
        );
    }

    #[test]
    fn create_body_carries_the_driver_subnet_gateway_and_labels() {
        let args = CreateArgs {
            driver: Some("overlay".to_owned()),
            subnet: Some("10.100.4.0/24".to_owned()),
            gateway: Some("10.100.4.1".to_owned()),
            label: vec!["role=web".to_owned(), "marker".to_owned()],
            opt: Vec::new(),
            name: "blue".to_owned(),
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue","Driver":"overlay","IPAM":{"Config":[{"Subnet":"10.100.4.0/24","Gateway":"10.100.4.1"}]},"Labels":{"marker":"","role":"web"}}"#
        );
    }

    #[test]
    fn create_body_without_options_asks_the_daemon_to_choose() {
        let args = CreateArgs {
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue"}"#,
            "no IPAM member at all: the allocator picks the subnet"
        );
    }

    #[test]
    fn a_subnet_without_a_gateway_still_ships_one_config_entry() {
        let args = CreateArgs {
            subnet: Some("10.100.4.0/24".to_owned()),
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue","IPAM":{"Config":[{"Subnet":"10.100.4.0/24"}]}}"#
        );
    }

    #[test]
    fn opt_encrypted_is_forwarded_as_a_driver_option() {
        let args = CreateArgs {
            driver: Some("overlay".to_owned()),
            opt: vec!["encrypted=true".to_owned()],
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue","Driver":"overlay","Options":{"encrypted":"true"}}"#
        );
    }

    /// Docker muscle memory is a bare `--opt encrypted` with no `=value`;
    /// the daemon's contract is that an empty value is a 400, so the CLI
    /// normalizes the bare spelling to `encrypted=true` before the request
    /// leaves.
    #[test]
    fn a_bare_opt_encrypted_means_true() {
        let args = CreateArgs {
            driver: Some("overlay".to_owned()),
            opt: vec!["encrypted".to_owned()],
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue","Driver":"overlay","Options":{"encrypted":"true"}}"#
        );

        // An explicit value is forwarded as typed, including `false`.
        let args = CreateArgs {
            driver: Some("overlay".to_owned()),
            opt: vec!["encrypted=false".to_owned()],
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let body = create_body(&args).unwrap();
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"Name":"blue","Driver":"overlay","Options":{"encrypted":"false"}}"#
        );
    }

    /// `encrypted` is the only driver option SatL reads; anything else would
    /// be a 400 from the daemon, so fail before the request leaves.
    #[test]
    fn an_unknown_opt_key_fails_client_side() {
        let args = CreateArgs {
            opt: vec!["com.docker.network.driver.mtu=1450".to_owned()],
            name: "blue".to_owned(),
            ..CreateArgs::default()
        };
        let error = create_body(&args).expect_err("only encrypted is a valid key");
        assert!(
            format!("{error:#}").contains("com.docker.network.driver.mtu"),
            "names the rejected key: {error:#}"
        );
    }

    #[tokio::test]
    async fn ls_create_inspect_and_rm_over_the_socket() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "GET",
            "/networks",
            Reply::json(
                200,
                r#"[{"Id":"1hvy0lj3x0b883f8e30fyp217","Name":"blue","Driver":"overlay","Scope":"swarm","Vni":4096}]"#,
            ),
        )
        .on(
            "POST",
            "/networks/create",
            Reply::json(201, r#"{"Id":"1hvy0lj3x0b883f8e30fyp217","Warning":""}"#),
        )
        .on(
            "GET",
            "/networks/blue",
            Reply::json(
                200,
                r#"{"Id":"1hvy0lj3x0b883f8e30fyp217","Name":"blue","Driver":"overlay","Vni":4096}"#,
            ),
        )
        .on("DELETE", "/networks/blue", Reply::empty(204));

        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &NetworkCommand::Ls(LsArgs::default()),
            &mut streams,
        )
        .await
        .unwrap();
        assert_eq!(
            out.contents(),
            "NETWORK ID     NAME   DRIVER    SCOPE\n1hvy0lj3x0b8   blue   overlay   swarm\n"
        );

        let (mut streams, out, _err) = testing::streams();
        let create = NetworkCommand::Create(CreateArgs {
            driver: Some("overlay".to_owned()),
            name: "blue".to_owned(),
            ..CreateArgs::default()
        });
        execute(&stub.host(), &create, &mut streams).await.unwrap();
        assert_eq!(out.contents(), "1hvy0lj3x0b883f8e30fyp217\n");
        assert_eq!(
            stub.first_call("POST /networks/create").unwrap().body,
            r#"{"Name":"blue","Driver":"overlay"}"#
        );

        let (mut streams, out, _err) = testing::streams();
        let inspect = NetworkCommand::Inspect(InspectArgs {
            networks: vec!["blue".to_owned()],
        });
        execute(&stub.host(), &inspect, &mut streams).await.unwrap();
        assert!(
            out.contents().starts_with("[\n    {\n"),
            "docker prints the raw document in an array: {:?}",
            out.contents()
        );
        assert!(out.contents().contains("\"Vni\": 4096"));

        let (mut streams, out, _err) = testing::streams();
        let remove = NetworkCommand::Rm(RmArgs {
            networks: vec!["blue".to_owned()],
        });
        assert_eq!(
            execute(&stub.host(), &remove, &mut streams).await.unwrap(),
            0
        );
        assert_eq!(out.contents(), "blue\n");
    }

    #[tokio::test]
    async fn rm_reports_a_network_in_use_and_exits_1() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "DELETE",
            "/networks/blue",
            Reply::json(409, r#"{"message":"network blue has active endpoints"}"#),
        );
        let (mut streams, out, err) = testing::streams();
        let remove = NetworkCommand::Rm(RmArgs {
            networks: vec!["blue".to_owned()],
        });
        let code = execute(&stub.host(), &remove, &mut streams).await.unwrap();
        assert_eq!(code, FAILURE);
        assert!(out.contents().is_empty());
        assert_eq!(
            err.contents(),
            "Error response from daemon: network blue has active endpoints\n"
        );
    }

    #[tokio::test]
    async fn create_rejected_by_the_daemon_surfaces_the_reason() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/networks/create",
            Reply::json(
                400,
                r#"{"message":"Attachable is not supported by SatL: standalone containers cannot attach"}"#,
            ),
        );
        let (mut streams, _out, _err) = testing::streams();
        let create = NetworkCommand::Create(CreateArgs {
            name: "blue".to_owned(),
            ..CreateArgs::default()
        });
        let error = execute(&stub.host(), &create, &mut streams)
            .await
            .expect_err("the daemon refused");
        assert!(
            format!("{error:#}").contains("Attachable is not supported"),
            "{error:#}"
        );
    }

    fn pruned(raw: &str) -> NetworksPruneResponse {
        serde_json::from_str(raw).expect("fixture parses")
    }

    #[test]
    fn prune_summary_golden() {
        assert_eq!(
            render_prune(&pruned(r#"{"NetworksDeleted":["scratch","blue"]}"#)),
            "Deleted Networks:\nscratch\nblue\n"
        );
    }

    /// A network is not disk: there is nothing to report reclaiming.
    #[test]
    fn prune_never_reports_space() {
        for raw in ["{}", r#"{"NetworksDeleted":["scratch"]}"#] {
            let rendered = render_prune(&pruned(raw));
            assert!(!rendered.contains("reclaimed"), "{rendered}");
        }
        assert!(render_prune(&pruned("{}")).is_empty());
    }

    #[test]
    fn the_prune_prompt_says_what_goes_and_how_far_it_reaches() {
        assert!(PRUNE_WARNING.contains("all networks not used by at least one container"));
        assert!(PRUNE_WARNING.contains("whole cluster"));
        assert!(PRUNE_WARNING.ends_with("Are you sure you want to continue? [y/N] "));
        assert!(PRUNE_WARNING.is_ascii(), "operator text must be ASCII");
    }

    #[tokio::test]
    async fn prune_with_force_posts_once_and_never_reads_info() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/networks/prune",
            Reply::json(200, r#"{"NetworksDeleted":["scratch"]}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let command = NetworkCommand::Prune(PruneArgs { force: true });
        let code = execute(&stub.host(), &command, &mut streams)
            .await
            .expect("prune succeeds");
        assert_eq!(code, 0);
        // No `/info`: nothing node-local is being claimed here.
        assert_eq!(stub.routes(), vec!["POST /networks/prune"]);
        assert_eq!(out.contents(), "Deleted Networks:\nscratch\n");
    }

    #[tokio::test]
    async fn prune_surfaces_a_daemon_error() {
        use crate::output::testing;
        use crate::stub::{Reply, Stub};

        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/networks/prune",
            Reply::json(503, r#"{"message":"this node is not a swarm manager"}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let command = NetworkCommand::Prune(PruneArgs { force: true });
        let error = execute(&stub.host(), &command, &mut streams)
            .await
            .expect_err("a 503 is an error");
        assert_eq!(
            error.to_string(),
            "Error response from daemon: this node is not a swarm manager"
        );
        assert!(out.contents().is_empty());
    }
}
