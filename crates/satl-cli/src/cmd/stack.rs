// SPDX-License-Identifier: BSD-2-Clause
//! `satl stack` — Docker's `docker stack` verbs (M7c), on SatL's compose
//! machinery. A stack is the set of services and networks one compose file
//! created, labelled with the project name.
//!
//! `deploy`/`rm`/`config` delegate to [`compose`] with
//! [`compose::World::Cluster`], which is what makes them the cluster half of
//! the split: free placement, overlay networks and ingress publishing, where
//! `satl compose` pins to one node and publishes on it (M11a, api-compat 169).
//! Only the read side (`ls`/`services`/`ps`) is code of its own.

use std::collections::BTreeMap;

use clap::Subcommand;

use crate::api::cluster::{Node, Service, Task};
use crate::client::{self, Host};
use crate::format::Table;
use crate::output::Streams;
use crate::{cmd::compose, cmd::service, format};

/// The label every compose-created object carries (compose/plan.rs).
const PROJECT_LABEL: &str = "com.docker.compose.project";

/// Subcommands of `satl stack`.
#[derive(Debug, Clone, Subcommand)]
pub enum StackCommand {
    /// Deploy a Compose file as a stack (or update the one running).
    Deploy(DeployArgs),
    /// List the stacks running on the cluster.
    Ls,
    /// List the services of a stack.
    Services(StackArgs),
    /// List the tasks of a stack.
    Ps(StackPsArgs),
    /// Remove one or more stacks.
    Rm(RmArgs),
    /// Print what `deploy` would create, without creating it.
    Config(ConfigArgs),
}

/// Flags of `satl stack deploy`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct DeployArgs {
    /// Compose file to deploy (default: discovered walking up from the
    /// working directory).
    #[arg(short = 'c', long = "compose-file", value_name = "FILE")]
    pub compose_file: Vec<std::path::PathBuf>,

    /// Prune services that are no longer in the file. Default true, as
    /// Docker's stack deploy — unlike `satl compose up`, where pruning is the
    /// explicit `--remove-orphans`.
    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = true)]
    pub prune: bool,

    /// The stack name.
    #[arg(value_name = "STACK")]
    pub stack: String,
}

/// A stack name for the read verbs.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct StackArgs {
    /// The stack name.
    #[arg(value_name = "STACK")]
    pub stack: String,
}

/// Flags of `satl stack ps`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct StackPsArgs {
    /// Don't truncate output.
    #[arg(long = "no-trunc")]
    pub no_trunc: bool,

    /// Only display task IDs.
    #[arg(short, long)]
    pub quiet: bool,

    /// The stack name.
    #[arg(value_name = "STACK")]
    pub stack: String,
}

/// Flags of `satl stack rm`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct RmArgs {
    /// The stacks to remove.
    #[arg(required = true, value_name = "STACK")]
    pub stacks: Vec<String>,
}

/// Flags of `satl stack config`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct ConfigArgs {
    /// Compose file to read (default: discovered walking up).
    #[arg(short = 'c', long = "compose-file", value_name = "FILE")]
    pub compose_file: Vec<std::path::PathBuf>,
}

/// Dispatch a `satl stack` subcommand.
pub async fn execute(
    host: &Host,
    command: &StackCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        StackCommand::Deploy(args) => deploy(host, args, streams).await,
        StackCommand::Ls => ls(host, streams).await,
        StackCommand::Services(args) => services(host, &args.stack, streams).await,
        StackCommand::Ps(args) => ps(host, args, streams).await,
        StackCommand::Rm(args) => rm(host, &args.stacks, streams).await,
        StackCommand::Config(args) => config(host, args, streams).await,
    }
}

/// `stack deploy` is `compose up` with the stack as the project name.
async fn deploy(host: &Host, args: &DeployArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let args = compose::ComposeArgs {
        file: args.compose_file.clone(),
        project_name: Some(args.stack.clone()),
        project_directory: None,
        command: compose::ComposeCommand::Up(compose::UpArgs {
            detach: true,
            remove_orphans: args.prune,
            scale: Vec::new(),
            build: false,
        }),
    };
    compose::execute(host, &args, compose::World::Cluster, streams).await
}

/// `stack rm` is `compose down` per stack; down needs no file.
async fn rm(host: &Host, stacks: &[String], streams: &mut Streams) -> anyhow::Result<u8> {
    let mut code = 0;
    for stack in stacks {
        let args = compose::ComposeArgs {
            file: Vec::new(),
            project_name: Some(stack.clone()),
            project_directory: None,
            command: compose::ComposeCommand::Down(compose::DownArgs {
                volumes: false,
                remove_orphans: true,
            }),
        };
        if compose::execute(host, &args, compose::World::Cluster, streams).await? != 0 {
            code = 1;
        }
    }
    Ok(code)
}

/// `stack config` is `compose config` (validation and the resolved plan).
async fn config(host: &Host, args: &ConfigArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let args = compose::ComposeArgs {
        file: args.compose_file.clone(),
        project_name: None,
        project_directory: None,
        command: compose::ComposeCommand::Config(compose::ConfigArgs { quiet: false }),
    };
    compose::execute(host, &args, compose::World::Cluster, streams).await
}

/// The services of one stack, by project label.
async fn stack_services(host: &Host, stack: &str) -> anyhow::Result<Vec<Service>> {
    let services: Vec<Service> = client::get_json(host, "/services?status=true").await?;
    Ok(services
        .into_iter()
        .filter(|service| service.spec.labels.get(PROJECT_LABEL).map(String::as_str) == Some(stack))
        .collect())
}

/// Every stack known to the cluster, with its service count.
async fn ls(host: &Host, streams: &mut Streams) -> anyhow::Result<u8> {
    let services: Vec<Service> = client::get_json(host, "/services").await?;
    let mut stacks: BTreeMap<String, usize> = BTreeMap::new();
    for service in &services {
        if let Some(project) = service.spec.labels.get(PROJECT_LABEL) {
            *stacks.entry(project.clone()).or_default() += 1;
        }
    }
    let mut table = Table::new(&["NAME", "SERVICES"]);
    for (name, count) in &stacks {
        table.push(vec![name.clone(), count.to_string()]);
    }
    streams.out(table.render().as_bytes()).await;
    Ok(0)
}

/// `docker stack services`: the service table, filtered to the stack.
async fn services(host: &Host, stack: &str, streams: &mut Streams) -> anyhow::Result<u8> {
    let services = stack_services(host, stack).await?;
    if services.is_empty() {
        anyhow::bail!("nothing found in stack {stack}");
    }
    streams
        .out(service::render_ls(&services, &service::LsArgs { quiet: false }).as_bytes())
        .await;
    Ok(0)
}

/// `docker stack ps`: the task table of every service in the stack.
async fn ps(host: &Host, args: &StackPsArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let services = stack_services(host, &args.stack).await?;
    if services.is_empty() {
        anyhow::bail!("nothing found in stack {}", args.stack);
    }
    let mut tasks = Vec::new();
    for service in &services {
        let filters = serde_json::json!({"service": {&service.spec.name: true}}).to_string();
        let path = format!("/tasks{}", client::query(&[("filters", filters.as_str())]));
        let found: Vec<Task> = client::get_json(host, &path).await?;
        tasks.extend(found);
    }
    // Docker shows hostnames in the NODE column; the node list is the only
    // place that maps a node ID to one.
    let nodes: Vec<Node> = client::get_json(host, "/nodes").await.unwrap_or_default();
    let hostnames: BTreeMap<String, String> = nodes
        .iter()
        .map(|node| (node.id.clone(), node.display_name().to_owned()))
        .collect();
    let render_args = service::PsArgs {
        no_trunc: args.no_trunc,
        quiet: args.quiet,
        services: Vec::new(),
    };
    streams
        .out(service::render_ps(&tasks, &hostnames, &render_args, format::now_unix()).as_bytes())
        .await;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    fn services_json() -> String {
        r#"[
          {"ID":"1hvy0lj3x0b883f8e30fyp217","Version":{"Index":7},
           "Spec":{"Name":"shop_web","Labels":{"com.docker.compose.project":"shop"},
             "TaskTemplate":{"ContainerSpec":{"Image":"nginx:1.27"}},
             "Mode":{"Replicated":{"Replicas":2}}}},
          {"ID":"2hvy0lj3x0b883f8e30fyp218","Version":{"Index":8},
           "Spec":{"Name":"shop_db","Labels":{"com.docker.compose.project":"shop"},
             "TaskTemplate":{"ContainerSpec":{"Image":"mariadb:11"}},
             "Mode":{"Replicated":{"Replicas":1}}}},
          {"ID":"3hvy0lj3x0b883f8e30fyp219","Version":{"Index":9},
           "Spec":{"Name":"lonely",
             "TaskTemplate":{"ContainerSpec":{"Image":"redis:7"}},
             "Mode":{"Replicated":{"Replicas":1}}}}
        ]"#
        .to_owned()
    }

    #[tokio::test]
    async fn ls_groups_services_by_stack_label() {
        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, &services_json()));
        let (mut streams, out, _err) = testing::streams();
        execute(&stub.host(), &StackCommand::Ls, &mut streams)
            .await
            .expect("ls succeeds");
        let printed = out.contents();
        assert!(printed.contains("shop"), "{printed}");
        assert!(printed.contains('2'), "{printed}");
        assert!(!printed.contains("lonely"), "{printed}");
    }

    #[tokio::test]
    async fn services_filters_to_the_stack_and_unknown_is_an_error() {
        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, &services_json()));
        let (mut streams, out, _err) = testing::streams();
        let args = StackArgs {
            stack: "shop".to_owned(),
        };
        execute(&stub.host(), &StackCommand::Services(args), &mut streams)
            .await
            .expect("services succeeds");
        let printed = out.contents();
        assert!(printed.contains("shop_web"), "{printed}");
        assert!(printed.contains("shop_db"), "{printed}");
        assert!(!printed.contains("lonely"), "{printed}");

        let (mut streams, _out, _err) = testing::streams();
        let args = StackArgs {
            stack: "ghost".to_owned(),
        };
        let err = execute(&stub.host(), &StackCommand::Services(args), &mut streams)
            .await
            .expect_err("an unknown stack is an error");
        assert!(
            err.to_string().contains("nothing found in stack ghost"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn ps_fetches_the_tasks_of_each_service_of_the_stack() {
        let stub = Stub::start().await;
        stub.on("GET", "/services", Reply::json(200, &services_json()))
            .on("GET", "/tasks", Reply::json(200, "[]"))
            .on(
                "GET",
                "/nodes",
                Reply::json(
                    200,
                    r#"[{"ID":"1hvy0lj3x0b883f8e30fyp217","Description":{"Hostname":"alpha"}}]"#,
                ),
            );
        let (mut streams, _out, _err) = testing::streams();
        let args = StackPsArgs {
            stack: "shop".to_owned(),
            ..StackPsArgs::default()
        };
        execute(&stub.host(), &StackCommand::Ps(args), &mut streams)
            .await
            .expect("ps succeeds");
        let task_calls: Vec<_> = stub
            .calls()
            .into_iter()
            .filter(|call| call.route() == "GET /tasks")
            .collect();
        assert_eq!(task_calls.len(), 2, "one query per service of the stack");
        assert!(
            task_calls[0].query.contains("shop_"),
            "{:?}",
            task_calls[0].query
        );
    }
}
