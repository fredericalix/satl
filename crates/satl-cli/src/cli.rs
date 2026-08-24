// SPDX-License-Identifier: BSD-2-Clause
//! Command-line surface: docker's verbs, flags and exit codes.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::client::{self, Host};
use crate::cmd::{self, FAILURE};
use crate::output::Streams;
use crate::version;

/// SatL: docker-compatible container engine for FreeBSD.
#[derive(Debug, Parser)]
#[command(name = "satl", version, disable_help_subcommand = true)]
pub struct Cli {
    /// Daemon socket to connect to (docker-style URL).
    #[arg(
        long,
        global = true,
        value_name = "URL",
        env = "DOCKER_HOST",
        default_value = client::DEFAULT_HOST
    )]
    pub host: String,

    /// The verb to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Every verb `satl` implements.
// `run` carries far more flags than the other verbs; the enum is built once
// per process, so the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the SatL version information (client and server).
    Version,

    /// Create and run a new container from an image.
    Run(cmd::run::RunArgs),

    /// List containers.
    Ps(cmd::ps::PsArgs),

    /// Stop one or more running containers.
    Stop(cmd::containers::StopArgs),

    /// Kill one or more running containers.
    Kill(cmd::containers::KillArgs),

    /// Remove one or more containers.
    Rm(cmd::containers::RmArgs),

    /// Block until one or more containers stop, then print their exit codes.
    Wait(cmd::containers::WaitArgs),

    /// Fetch the logs of a container.
    Logs(cmd::logs::LogsArgs),

    /// Execute a command in a running container.
    Exec(cmd::exec::ExecArgs),

    /// Return low-level information on containers.
    Inspect(cmd::inspect::InspectArgs),

    /// Get real-time events from the daemon.
    ///
    /// The stream starts now and runs until interrupted. `--since` is sent
    /// but has no effect -- SatL keeps no event history (docs/api-compat.md
    /// #37) -- and `--until` is refused by the daemon. `--filter` is applied
    /// by this client, on the keys type, event, container, image, label and
    /// scope; any other key is refused rather than ignored.
    #[command(verbatim_doc_comment)]
    Events(cmd::events::EventsArgs),

    /// Display system-wide information about this node's daemon.
    Info(cmd::info::InfoArgs),

    /// Download an image from a registry.
    Pull(cmd::pull::PullArgs),

    /// Push an image from this node's store to a registry (client-side, like
    /// `satl build`).
    Push(cmd::push::PushArgs),

    /// Create a tag `TARGET_IMAGE` that refers to `SOURCE_IMAGE`.
    Tag(cmd::tag::TagArgs),

    /// Build a FreeBSD image from a Satlfile into this node's store.
    Build(cmd::build::BuildArgs),

    /// List images, or manage them (`ls`, `rm`, `prune`, `inspect`).
    ///
    /// Bare `satl images` is docker's `docker images`. The subcommands are
    /// SatL's own spelling -- docker has `docker image rm`, never
    /// `docker images rm` (docs/api-compat.md 154).
    #[command(verbatim_doc_comment)]
    Images(cmd::images::ImagesArgs),

    /// Remove one or more images. Alias of `satl images rm`, which is the
    /// canonical spelling; docker keeps `rmi` for the same reason.
    Rmi(cmd::images::RmArgs),

    /// Manage containers -- the verbs that have no top-level spelling.
    ///
    /// The lifecycle verbs stay at the top level, where docker puts them and
    /// where muscle memory reaches for them: `satl ps`, `satl rm`, `satl
    /// stop`, `satl kill`, `satl logs`, `satl inspect`. Docker's container
    /// surface is flat, and a second spelling of a verb that already has one
    /// would only be a second thing to keep in sync. This noun exists for the
    /// verbs with no flat spelling at all -- today, `prune`.
    #[command(verbatim_doc_comment)]
    Container {
        /// The container subcommand.
        #[command(subcommand)]
        command: cmd::container::ContainerCommand,
    },

    /// Manage volumes.
    Volume {
        /// The volume subcommand.
        #[command(subcommand)]
        command: cmd::volume::VolumeCommand,
    },

    /// Manage networks.
    Network {
        /// The network subcommand.
        #[command(subcommand)]
        command: cmd::network::NetworkCommand,
    },

    /// Manage SatL itself.
    System {
        /// The system subcommand.
        #[command(subcommand)]
        command: cmd::system::SystemCommand,
    },

    /// Manage the swarm. `satl cluster` is an accepted alias: the docker verb
    /// is kept for compatibility, the alias reads better in SatL's own docs.
    #[command(visible_alias = "cluster")]
    Swarm {
        /// The swarm subcommand.
        #[command(subcommand)]
        command: cmd::swarm::SwarmCommand,
    },

    /// View and rotate the cluster root CA (docker's `swarm ca`, as its own
    /// verb: certificate operations deserve better than a flag pile).
    Ca(cmd::ca::CaArgs),

    /// Manage swarm nodes.
    Node {
        /// The node subcommand.
        #[command(subcommand)]
        command: cmd::node::NodeCommand,
    },

    /// Deploy a Compose file on this node (use `satl stack` for the cluster).
    ///
    /// `satl compose up` runs the whole file on the node you are talking to:
    /// every service is pinned there with a node.id== constraint, ports are
    /// published on that node rather than on the cluster's routing mesh, and a
    /// relative bind or an `env_file` means a path on that node -- which is the
    /// same machine as this client, since satl speaks a unix socket only. That
    /// is `docker compose`'s scope. For `docker stack deploy`'s, spreading the
    /// same file over the cluster on an overlay, use `satl stack deploy`.
    ///
    /// What does not change between the two: every container is a task of a
    /// service either way (there is no standalone container), so `up` creates
    /// one service per compose service and `deploy:` is honoured rather than
    /// ignored. Services are named <project>-<service> here and
    /// <project>_<service> under `satl stack`, docker's own split; both answer
    /// to the bare compose service name as a DNS alias, so the hostnames
    /// inside the file keep working.
    ///
    /// The project name comes from -p, else `COMPOSE_PROJECT_NAME`, else the
    /// file's `name:`, else the directory; `down` removes exactly the objects
    /// `up` labelled with it, and nothing else.
    ///
    /// Anything outside the supported subset is refused with the file, the
    /// service and the key named, never silently ignored. The subset and every
    /// deviation are in docs/api-compat.md (entries 110-124, 169-174).
    #[command(verbatim_doc_comment)]
    Compose(cmd::compose::ComposeArgs),

    /// Manage services.
    Service {
        /// The service subcommand.
        #[command(subcommand)]
        command: cmd::service::ServiceCommand,
    },

    /// Manage stacks -- deploy a Compose file across the cluster (use
    /// `satl compose` for this node alone). A stack is one compose file's
    /// services and networks, on a shared overlay, placed by the scheduler.
    #[command(subcommand)]
    Stack(cmd::stack::StackCommand),

    /// Manage secrets.
    Secret {
        /// The secret subcommand.
        #[command(subcommand)]
        command: cmd::secret::SecretCommand,
    },

    /// Manage configs.
    Config {
        /// The config subcommand.
        #[command(subcommand)]
        command: cmd::config::ConfigCommand,
    },
}

/// Parse the command line, run the verb, and map the result to an exit code:
/// 0 or 1 for the CLI's own outcome, or the container's/exec's exit code for
/// `run`, `exec` and `wait`.
pub async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut streams = Streams::stdio();
    match dispatch(&cli, &mut streams).await {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            // Docker-style: bare message on stderr, exit code 1.
            streams.error(&format!("{err:#}")).await;
            ExitCode::from(FAILURE)
        }
    }
}

/// Run one verb, returning the process exit code.
pub async fn dispatch(cli: &Cli, streams: &mut Streams) -> anyhow::Result<u8> {
    let host = Host::parse(&cli.host)?;
    match &cli.command {
        Command::Version => {
            version::run(&host).await?;
            Ok(0)
        }
        Command::Run(args) => cmd::run::execute(&host, args, streams).await,
        Command::Ps(args) => {
            let table = cmd::ps::execute(&host, args).await?;
            streams.out(table.as_bytes()).await;
            Ok(0)
        }
        Command::Stop(args) => cmd::containers::stop(&host, args, streams).await,
        Command::Kill(args) => cmd::containers::kill(&host, args, streams).await,
        Command::Rm(args) => cmd::containers::rm(&host, args, streams).await,
        Command::Wait(args) => cmd::containers::wait(&host, args, streams).await,
        Command::Logs(args) => cmd::logs::execute(&host, args, streams).await,
        Command::Exec(args) => cmd::exec::execute(&host, args, streams).await,
        Command::Inspect(args) => cmd::inspect::execute(&host, args, streams).await,
        Command::Events(args) => cmd::events::execute(&host, args, streams).await,
        Command::Info(args) => cmd::info::execute(&host, args, streams).await,
        Command::Pull(args) => cmd::pull::execute(&host, args, streams).await,
        Command::Push(args) => cmd::push::execute(&host, args, streams).await,
        Command::Tag(args) => cmd::tag::execute(&host, args, streams).await,
        Command::Build(args) => cmd::build::execute(&host, args, streams).await,
        Command::Images(args) => cmd::images::execute(&host, args, streams).await,
        Command::Rmi(args) => cmd::images::remove(&host, args, streams).await,
        Command::Container { command } => cmd::container::execute(&host, command, streams).await,
        Command::Volume { command } => cmd::volume::execute(&host, command, streams).await,
        Command::Network { command } => cmd::network::execute(&host, command, streams).await,
        Command::System { command } => cmd::system::execute(&host, command, streams).await,
        Command::Swarm { command } => cmd::swarm::execute(&host, command, streams).await,
        Command::Ca(args) => cmd::ca::execute(&host, args, streams).await,
        Command::Node { command } => cmd::node::execute(&host, command, streams).await,
        Command::Compose(args) => {
            cmd::compose::execute(&host, args, cmd::compose::World::Local, streams).await
        }
        Command::Service { command } => cmd::service::execute(&host, command, streams).await,
        Command::Stack(command) => cmd::stack::execute(&host, command, streams).await,
        Command::Secret { command } => cmd::secret::execute(&host, command, streams).await,
        Command::Config { command } => cmd::config::execute(&host, command, streams).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::run::PullPolicy;

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    #[test]
    fn host_defaults_to_the_satl_socket() {
        let cli = Cli::parse_from(["satl", "version"]);
        assert_eq!(cli.host, "unix:///var/run/satl.sock");
    }

    #[test]
    fn host_flag_overrides_default() {
        let cli = Cli::parse_from(["satl", "--host", "unix:///tmp/x.sock", "version"]);
        assert_eq!(cli.host, "unix:///tmp/x.sock");
    }

    fn run_args(command_line: &[&str]) -> cmd::run::RunArgs {
        let cli = Cli::parse_from(command_line);
        match cli.command {
            Command::Run(args) => args,
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn run_flags_mirror_docker() {
        let args = run_args(&[
            "satl",
            "run",
            "-d",
            "--name",
            "web",
            "-p",
            "8080:80",
            "-p",
            "53:53/udp",
            "-v",
            "data:/data:ro",
            "--tmpfs",
            "/run",
            "-e",
            "A=1",
            "--env-file",
            "/tmp/env",
            "-w",
            "/srv",
            "-u",
            "www",
            "--hostname",
            "web1",
            "-m",
            "512m",
            "--cpus",
            "1.5",
            "--restart",
            "on-failure:3",
            "--platform",
            "freebsd/amd64",
            "--rm",
            "-l",
            "role=web",
            "--entrypoint",
            "/bin/tini",
            "--pull",
            "always",
            "-i",
            "nginx:1.25",
            "nginx",
            "-g",
            "daemon off;",
        ]);
        assert!(args.detach && args.rm && args.interactive && !args.tty);
        assert_eq!(args.name.as_deref(), Some("web"));
        assert_eq!(args.publish, vec!["8080:80", "53:53/udp"]);
        assert_eq!(args.volume, vec!["data:/data:ro"]);
        assert_eq!(args.tmpfs, vec!["/run"]);
        assert_eq!(args.env, vec!["A=1"]);
        assert_eq!(args.env_file, vec!["/tmp/env"]);
        assert_eq!(args.workdir.as_deref(), Some("/srv"));
        assert_eq!(args.user.as_deref(), Some("www"));
        assert_eq!(args.hostname.as_deref(), Some("web1"));
        assert_eq!(args.memory.as_deref(), Some("512m"));
        assert_eq!(args.cpus.as_deref(), Some("1.5"));
        assert_eq!(args.restart.as_deref(), Some("on-failure:3"));
        assert_eq!(args.platform.as_deref(), Some("freebsd/amd64"));
        assert_eq!(args.label, vec!["role=web"]);
        assert_eq!(args.entrypoint.as_deref(), Some("/bin/tini"));
        assert_eq!(args.pull, PullPolicy::Always);
        assert_eq!(args.image, "nginx:1.25");
        // Everything after the image belongs to the container, flags included.
        assert_eq!(args.command, vec!["nginx", "-g", "daemon off;"]);
    }

    #[test]
    fn run_defaults_to_pull_missing() {
        let args = run_args(&["satl", "run", "nginx"]);
        assert_eq!(args.pull, PullPolicy::Missing);
        assert!(!args.detach);
        assert!(args.command.is_empty());
    }

    #[test]
    fn run_rejects_an_unknown_pull_policy() {
        assert!(Cli::try_parse_from(["satl", "run", "--pull", "sometimes", "nginx"]).is_err());
    }

    #[test]
    fn lifecycle_verbs_take_several_containers() {
        let cli = Cli::parse_from(["satl", "stop", "-t", "5", "web", "db"]);
        match cli.command {
            Command::Stop(args) => {
                assert_eq!(args.time, Some(5));
                assert_eq!(args.containers, vec!["web", "db"]);
            }
            other => panic!("expected stop, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "kill", "-s", "SIGHUP", "web"]);
        match cli.command {
            Command::Kill(args) => assert_eq!(args.signal.as_deref(), Some("SIGHUP")),
            other => panic!("expected kill, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "rm", "-f", "-v", "web"]);
        match cli.command {
            Command::Rm(args) => assert!(args.force && args.volumes),
            other => panic!("expected rm, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["satl", "stop"]).is_err());
    }

    #[test]
    fn logs_and_exec_flags() {
        let cli = Cli::parse_from(["satl", "logs", "-f", "--tail", "20", "-t", "web"]);
        match cli.command {
            Command::Logs(args) => {
                assert!(args.follow && args.timestamps);
                assert_eq!(args.tail, "20");
                assert_eq!(args.container, "web");
            }
            other => panic!("expected logs, got {other:?}"),
        }
        let cli = Cli::parse_from([
            "satl", "exec", "-i", "-w", "/srv", "-u", "www", "-e", "A=1", "web", "sh", "-c",
            "echo hi",
        ]);
        match cli.command {
            Command::Exec(args) => {
                assert!(args.interactive && !args.tty);
                assert_eq!(args.workdir.as_deref(), Some("/srv"));
                assert_eq!(args.user.as_deref(), Some("www"));
                assert_eq!(args.env, vec!["A=1"]);
                assert_eq!(args.container, "web");
                assert_eq!(args.command, vec!["sh", "-c", "echo hi"]);
            }
            other => panic!("expected exec, got {other:?}"),
        }
    }

    #[test]
    fn logs_tail_defaults_to_all() {
        let cli = Cli::parse_from(["satl", "logs", "web"]);
        match cli.command {
            Command::Logs(args) => assert_eq!(args.tail, "all"),
            other => panic!("expected logs, got {other:?}"),
        }
    }

    fn events_args(command_line: &[&str]) -> cmd::events::EventsArgs {
        let cli = Cli::parse_from(command_line);
        match cli.command {
            Command::Events(args) => args,
            other => panic!("expected events, got {other:?}"),
        }
    }

    #[test]
    fn events_flags_mirror_docker() {
        let args = events_args(&[
            "satl",
            "events",
            "--since",
            "1755613351",
            "--until",
            "2026-08-19T15:00:00Z",
            "-f",
            "type=container",
            "--filter",
            "event=start",
            "--format",
            "json",
        ]);
        assert_eq!(args.since.as_deref(), Some("1755613351"));
        assert_eq!(args.until.as_deref(), Some("2026-08-19T15:00:00Z"));
        assert_eq!(args.filter, vec!["type=container", "event=start"]);
        assert_eq!(args.format.as_deref(), Some("json"));
    }

    #[test]
    fn events_takes_no_arguments_and_defaults_to_everything() {
        let args = events_args(&["satl", "events"]);
        assert!(args.since.is_none() && args.until.is_none() && args.format.is_none());
        assert!(args.filter.is_empty());
        assert!(Cli::try_parse_from(["satl", "events", "web"]).is_err());
    }

    #[test]
    fn info_takes_no_arguments() {
        assert!(matches!(
            Cli::parse_from(["satl", "info"]).command,
            Command::Info(_)
        ));
        assert!(Cli::try_parse_from(["satl", "info", "--format", "json"]).is_err());
    }

    /// The lifecycle verbs stay top-level; `container` holds only `prune`.
    #[test]
    fn container_subcommands() {
        let cli = Cli::parse_from(["satl", "container", "prune", "-f"]);
        match cli.command {
            Command::Container {
                command: cmd::container::ContainerCommand::Prune(args),
            } => assert!(args.force),
            other => panic!("expected container prune, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "container", "prune"]);
        match cli.command {
            Command::Container {
                command: cmd::container::ContainerCommand::Prune(args),
            } => assert!(!args.force),
            other => panic!("expected container prune, got {other:?}"),
        }
        for absent in ["ls", "rm", "stop", "logs", "inspect"] {
            assert!(
                Cli::try_parse_from(["satl", "container", absent, "web"]).is_err(),
                "satl container {absent} must not exist: the flat spelling is the only one"
            );
        }
    }

    #[test]
    fn node_ps_defaults_to_self() {
        let cli = Cli::parse_from(["satl", "node", "ps"]);
        match cli.command {
            Command::Node {
                command: cmd::node::NodeCommand::Ps(args),
            } => {
                assert_eq!(args.nodes, vec!["self"]);
                assert!(!args.quiet && !args.no_trunc);
            }
            other => panic!("expected node ps, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "node", "ps", "--no-trunc", "-q", "alpha", "beta"]);
        match cli.command {
            Command::Node {
                command: cmd::node::NodeCommand::Ps(args),
            } => {
                assert!(args.no_trunc && args.quiet);
                assert_eq!(args.nodes, vec!["alpha", "beta"]);
            }
            other => panic!("expected node ps, got {other:?}"),
        }
    }

    #[test]
    fn network_prune_takes_only_force() {
        let cli = Cli::parse_from(["satl", "network", "prune", "-f"]);
        match cli.command {
            Command::Network {
                command: cmd::network::NetworkCommand::Prune(args),
            } => assert!(args.force),
            other => panic!("expected network prune, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["satl", "network", "prune", "blue"]).is_err());
    }

    #[test]
    fn images_is_a_noun_that_still_lists_bare() {
        // Bare `satl images` keeps docker's listing, flags and all: this is
        // the backwards-compatibility assertion for the noun change.
        let cli = Cli::parse_from(["satl", "images", "-q", "--no-trunc"]);
        match cli.command {
            Command::Images(args) => {
                assert!(args.command.is_none(), "no subcommand means list");
                assert!(args.ls.quiet && args.ls.no_trunc);
            }
            other => panic!("expected images, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "images", "rm", "-f", "--no-prune", "a", "b"]);
        match cli.command {
            Command::Images(args) => match args.command {
                Some(cmd::images::ImagesCommand::Rm(rm)) => {
                    assert!(rm.force && rm.no_prune);
                    assert_eq!(rm.images, ["a", "b"]);
                }
                other => panic!("expected images rm, got {other:?}"),
            },
            other => panic!("expected images, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "images", "prune", "-a", "-f"]);
        match cli.command {
            Command::Images(args) => match args.command {
                Some(cmd::images::ImagesCommand::Prune(prune)) => {
                    assert!(prune.all && prune.force);
                }
                other => panic!("expected images prune, got {other:?}"),
            },
            other => panic!("expected images, got {other:?}"),
        }

        // `args_conflicts_with_subcommands`: a listing flag and a subcommand
        // in one invocation is an error, not a silently ignored flag.
        assert!(Cli::try_parse_from(["satl", "images", "-q", "rm", "a"]).is_err());
        // rm takes at least one image.
        assert!(Cli::try_parse_from(["satl", "images", "rm"]).is_err());
    }

    #[test]
    fn rmi_parses_the_same_arguments_as_images_rm() {
        let flat = Cli::parse_from(["satl", "rmi", "-f", "nginx:1.25"]);
        let noun = Cli::parse_from(["satl", "images", "rm", "-f", "nginx:1.25"]);
        let (Command::Rmi(flat), Command::Images(noun)) = (flat.command, noun.command) else {
            panic!("expected rmi and images rm");
        };
        let Some(cmd::images::ImagesCommand::Rm(noun)) = noun.command else {
            panic!("expected images rm");
        };
        assert_eq!(flat.force, noun.force);
        assert_eq!(flat.no_prune, noun.no_prune);
        assert_eq!(flat.images, noun.images);
    }

    #[test]
    fn volume_subcommands() {
        let cli = Cli::parse_from(["satl", "volume", "create", "--driver", "local", "web-data"]);
        match cli.command {
            Command::Volume {
                command: cmd::volume::VolumeCommand::Create(args),
            } => {
                assert_eq!(args.name.as_deref(), Some("web-data"));
                assert_eq!(args.driver.as_deref(), Some("local"));
            }
            other => panic!("expected volume create, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "volume", "rm", "-f", "a", "b"]);
        match cli.command {
            Command::Volume {
                command: cmd::volume::VolumeCommand::Rm(args),
            } => {
                assert!(args.force);
                assert_eq!(args.volumes, vec!["a", "b"]);
            }
            other => panic!("expected volume rm, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "volume", "inspect", "a", "b"]);
        match cli.command {
            Command::Volume {
                command: cmd::volume::VolumeCommand::Inspect(args),
            } => assert_eq!(args.volumes, vec!["a", "b"]),
            other => panic!("expected volume inspect, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["satl", "volume", "inspect"]).is_err());
        let cli = Cli::parse_from(["satl", "volume", "prune", "--force"]);
        match cli.command {
            Command::Volume {
                command: cmd::volume::VolumeCommand::Prune(args),
            } => assert!(args.force),
            other => panic!("expected volume prune, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["satl", "volume", "prune", "web-data"]).is_err());
        assert!(Cli::try_parse_from(["satl", "volume", "ls"]).is_ok());
    }

    #[test]
    fn network_subcommands() {
        let cli = Cli::parse_from([
            "satl",
            "network",
            "create",
            "-d",
            "overlay",
            "--subnet",
            "10.100.4.0/24",
            "--gateway",
            "10.100.4.1",
            "--label",
            "role=web",
            "--opt",
            "encrypted=true",
            "blue",
        ]);
        match cli.command {
            Command::Network {
                command: cmd::network::NetworkCommand::Create(args),
            } => {
                assert_eq!(args.name, "blue");
                assert_eq!(args.driver.as_deref(), Some("overlay"));
                assert_eq!(args.subnet.as_deref(), Some("10.100.4.0/24"));
                assert_eq!(args.gateway.as_deref(), Some("10.100.4.1"));
                assert_eq!(args.label, vec!["role=web"]);
                assert_eq!(args.opt, vec!["encrypted=true"]);
            }
            other => panic!("expected network create, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "network", "ls", "-q", "--no-trunc"]);
        match cli.command {
            Command::Network {
                command: cmd::network::NetworkCommand::Ls(args),
            } => assert!(args.quiet && args.no_trunc),
            other => panic!("expected network ls, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "network", "rm", "blue", "green"]);
        match cli.command {
            Command::Network {
                command: cmd::network::NetworkCommand::Rm(args),
            } => assert_eq!(args.networks, vec!["blue", "green"]),
            other => panic!("expected network rm, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "network", "inspect", "blue"]);
        match cli.command {
            Command::Network {
                command: cmd::network::NetworkCommand::Inspect(args),
            } => assert_eq!(args.networks, vec!["blue"]),
            other => panic!("expected network inspect, got {other:?}"),
        }

        // A name is required, and so is at least one argument to rm/inspect.
        assert!(Cli::try_parse_from(["satl", "network", "create"]).is_err());
        assert!(Cli::try_parse_from(["satl", "network", "rm"]).is_err());
        assert!(Cli::try_parse_from(["satl", "network", "inspect"]).is_err());
    }

    #[test]
    fn pull_and_images_flags() {
        let cli = Cli::parse_from(["satl", "pull", "--platform", "linux/amd64", "nginx:1.25"]);
        match cli.command {
            Command::Pull(args) => {
                assert_eq!(args.platform.as_deref(), Some("linux/amd64"));
                assert_eq!(args.image, "nginx:1.25");
            }
            other => panic!("expected pull, got {other:?}"),
        }
        let cli = Cli::parse_from(["satl", "images", "--no-trunc", "-q"]);
        match cli.command {
            Command::Images(args) => assert!(args.ls.no_trunc && args.ls.quiet),
            other => panic!("expected images, got {other:?}"),
        }
    }

    #[test]
    fn tag_takes_a_source_and_a_target() {
        let cli = Cli::parse_from([
            "satl",
            "tag",
            "alpine:3.20",
            "registry.example.com/mirror/alpine:3.20",
        ]);
        match cli.command {
            Command::Tag(args) => {
                assert_eq!(args.source, "alpine:3.20");
                assert_eq!(args.target, "registry.example.com/mirror/alpine:3.20");
            }
            other => panic!("expected tag, got {other:?}"),
        }
        assert!(Cli::try_parse_from(["satl", "tag", "only-one"]).is_err());
        assert!(Cli::try_parse_from(["satl", "tag"]).is_err());
    }

    #[test]
    fn swarm_verbs_mirror_docker() {
        let cli = Cli::parse_from([
            "satl",
            "swarm",
            "init",
            "--advertise-addr",
            "10.2.0.11:2377",
            "--listen-addr",
            "0.0.0.0:2377",
            "--force-new-cluster",
        ]);
        match cli.command {
            Command::Swarm {
                command: cmd::swarm::SwarmCommand::Init(args),
            } => {
                assert_eq!(args.advertise_addr.as_deref(), Some("10.2.0.11:2377"));
                assert_eq!(args.listen_addr.as_deref(), Some("0.0.0.0:2377"));
                assert!(args.force_new_cluster);
            }
            other => panic!("expected swarm init, got {other:?}"),
        }

        let cli = Cli::parse_from([
            "satl",
            "swarm",
            "join",
            "--token",
            "SATL-1-worker",
            "--advertise-addr",
            "10.2.0.12",
            "10.2.0.11:2377",
        ]);
        match cli.command {
            Command::Swarm {
                command: cmd::swarm::SwarmCommand::Join(args),
            } => {
                assert_eq!(args.token, "SATL-1-worker");
                assert_eq!(args.manager, "10.2.0.11:2377");
                assert_eq!(args.advertise_addr.as_deref(), Some("10.2.0.12"));
            }
            other => panic!("expected swarm join, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "swarm", "join-token", "--rotate", "-q", "manager"]);
        match cli.command {
            Command::Swarm {
                command: cmd::swarm::SwarmCommand::JoinToken(args),
            } => {
                assert!(args.rotate && args.quiet);
                assert_eq!(args.role, "manager");
            }
            other => panic!("expected swarm join-token, got {other:?}"),
        }

        // A join without a token, or a token for an unknown role, is refused
        // before any request is made.
        assert!(Cli::try_parse_from(["satl", "swarm", "join", "10.2.0.11:2377"]).is_err());
        assert!(Cli::try_parse_from(["satl", "swarm", "join-token", "leader"]).is_err());
        assert!(Cli::try_parse_from(["satl", "swarm", "leave", "--force"]).is_ok());
    }

    #[test]
    fn cluster_is_an_alias_of_swarm() {
        let cli = Cli::parse_from(["satl", "cluster", "leave", "--force"]);
        match cli.command {
            Command::Swarm {
                command: cmd::swarm::SwarmCommand::Leave(args),
            } => assert!(args.force),
            other => panic!("expected swarm leave, got {other:?}"),
        }
    }

    #[test]
    fn node_verbs_mirror_docker() {
        let cli = Cli::parse_from([
            "satl",
            "node",
            "update",
            "--label-add",
            "zone=a",
            "--label-rm",
            "old",
            "--availability",
            "drain",
            "--role",
            "manager",
            "alpha",
        ]);
        match cli.command {
            Command::Node {
                command: cmd::node::NodeCommand::Update(args),
            } => {
                assert_eq!(args.label_add, ["zone=a"]);
                assert_eq!(args.label_rm, ["old"]);
                assert_eq!(args.availability.as_deref(), Some("drain"));
                assert_eq!(args.role.as_deref(), Some("manager"));
                assert_eq!(args.node, "alpha");
            }
            other => panic!("expected node update, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "node", "inspect", "--pretty", "self"]);
        match cli.command {
            Command::Node {
                command: cmd::node::NodeCommand::Inspect(args),
            } => {
                assert!(args.pretty);
                assert_eq!(args.nodes, ["self"]);
            }
            other => panic!("expected node inspect, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "node", "rm", "-f", "alpha", "beta"]);
        match cli.command {
            Command::Node {
                command: cmd::node::NodeCommand::Rm(args),
            } => {
                assert!(args.force);
                assert_eq!(args.nodes, ["alpha", "beta"]);
            }
            other => panic!("expected node rm, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["satl", "node", "promote", "alpha"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "node", "demote", "alpha"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "node", "ls", "-q"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "node", "update", "--role", "boss", "a"]).is_err());
        assert!(Cli::try_parse_from(["satl", "node", "rm"]).is_err());
    }

    #[test]
    fn service_create_flags_mirror_docker() {
        let cli = Cli::parse_from([
            "satl",
            "service",
            "create",
            "--name",
            "web",
            "--replicas",
            "3",
            "--mode",
            "replicated",
            "-p",
            "8080:80",
            "-e",
            "A=1",
            "-l",
            "tier=front",
            "--constraint",
            "node.labels.zone == a",
            "--limit-cpu",
            "1.5",
            "--limit-memory",
            "512m",
            "--restart-condition",
            "on-failure",
            "--network",
            "backend",
            "--update-parallelism",
            "2",
            "--update-delay",
            "10s",
            "--update-failure-action",
            "rollback",
            "--update-monitor",
            "8s",
            "--update-max-failure-ratio",
            "0.25",
            "--update-order",
            "start-first",
            "--rollback-parallelism",
            "2",
            "--rollback-failure-action",
            "continue",
            "nginx:1.27",
            "nginx",
            "-g",
            "daemon off;",
        ]);
        match cli.command {
            Command::Service {
                command: cmd::service::ServiceCommand::Create(args),
            } => {
                assert_eq!(args.name.as_deref(), Some("web"));
                assert_eq!(args.replicas, Some(3));
                assert_eq!(args.mode.as_deref(), Some("replicated"));
                assert_eq!(args.publish, ["8080:80"]);
                assert_eq!(args.env, ["A=1"]);
                assert_eq!(args.label, ["tier=front"]);
                assert_eq!(args.constraint, ["node.labels.zone == a"]);
                assert_eq!(args.limit_cpu.as_deref(), Some("1.5"));
                assert_eq!(args.limit_memory.as_deref(), Some("512m"));
                assert_eq!(args.restart_condition.as_deref(), Some("on-failure"));
                assert_eq!(args.network, ["backend"]);
                assert_eq!(args.policy.update_parallelism, Some(2));
                assert_eq!(args.policy.update_delay.as_deref(), Some("10s"));
                assert_eq!(
                    args.policy.update_failure_action.as_deref(),
                    Some("rollback")
                );
                assert_eq!(args.policy.update_monitor.as_deref(), Some("8s"));
                assert_eq!(args.policy.update_max_failure_ratio, Some(0.25));
                assert_eq!(args.policy.update_order.as_deref(), Some("start-first"));
                assert_eq!(args.policy.rollback_parallelism, Some(2));
                assert_eq!(
                    args.policy.rollback_failure_action.as_deref(),
                    Some("continue")
                );
                assert_eq!(args.image, "nginx:1.27");
                // Everything after the image belongs to the task, flags included.
                assert_eq!(args.command, ["nginx", "-g", "daemon off;"]);
            }
            other => panic!("expected service create, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["satl", "service", "create"]).is_err());
        assert!(
            Cli::try_parse_from(["satl", "service", "create", "--mode", "job", "nginx"]).is_err()
        );
    }

    #[test]
    fn service_other_verbs_mirror_docker() {
        let cli = Cli::parse_from(["satl", "service", "ps", "--no-trunc", "web"]);
        match cli.command {
            Command::Service {
                command: cmd::service::ServiceCommand::Ps(args),
            } => {
                assert!(args.no_trunc);
                assert_eq!(args.services, ["web"]);
            }
            other => panic!("expected service ps, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "service", "scale", "web=3", "db=1"]);
        match cli.command {
            Command::Service {
                command: cmd::service::ServiceCommand::Scale(args),
            } => assert_eq!(args.scales, ["web=3", "db=1"]),
            other => panic!("expected service scale, got {other:?}"),
        }

        let cli = Cli::parse_from([
            "satl",
            "service",
            "update",
            "--image",
            "nginx:1.28",
            "--replicas",
            "5",
            "--constraint-add",
            "node.role == worker",
            "--constraint-rm",
            "node.labels.zone == a",
            "--label-add",
            "owner=sre",
            "--label-rm",
            "tier",
            "web",
        ]);
        match cli.command {
            Command::Service {
                command: cmd::service::ServiceCommand::Update(args),
            } => {
                assert_eq!(args.image.as_deref(), Some("nginx:1.28"));
                assert_eq!(args.replicas, Some(5));
                assert_eq!(args.constraint_add, ["node.role == worker"]);
                assert_eq!(args.constraint_rm, ["node.labels.zone == a"]);
                assert_eq!(args.label_add, ["owner=sre"]);
                assert_eq!(args.label_rm, ["tier"]);
                assert_eq!(args.service, "web");
            }
            other => panic!("expected service update, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["satl", "service", "ls", "-q"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "service", "inspect", "--pretty", "web"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "service", "rm", "web", "db"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "service", "rm"]).is_err());
        assert!(Cli::try_parse_from(["satl", "service", "ps"]).is_err());
    }

    #[test]
    fn secret_subcommands() {
        let cli = Cli::parse_from([
            "satl",
            "secret",
            "create",
            "-l",
            "env=prod",
            "--label",
            "owner=sre",
            "site-cert",
            "/tmp/site.pem",
        ]);
        match cli.command {
            Command::Secret {
                command: cmd::secret::SecretCommand::Create(args),
            } => {
                assert_eq!(args.name, "site-cert");
                assert_eq!(args.file, "/tmp/site.pem");
                assert_eq!(args.label, ["env=prod", "owner=sre"]);
            }
            other => panic!("expected secret create, got {other:?}"),
        }

        // `-` is the file argument: the payload comes from stdin.
        let cli = Cli::parse_from(["satl", "secret", "create", "site-cert", "-"]);
        match cli.command {
            Command::Secret {
                command: cmd::secret::SecretCommand::Create(args),
            } => assert_eq!(args.file, "-"),
            other => panic!("expected secret create, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "secret", "ls", "-q"]);
        match cli.command {
            Command::Secret {
                command: cmd::secret::SecretCommand::Ls(args),
            } => assert!(args.quiet),
            other => panic!("expected secret ls, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "secret", "rm", "site-cert", "old-cert"]);
        match cli.command {
            Command::Secret {
                command: cmd::secret::SecretCommand::Rm(args),
            } => assert_eq!(args.secrets, ["site-cert", "old-cert"]),
            other => panic!("expected secret rm, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "secret", "inspect", "site-cert"]);
        match cli.command {
            Command::Secret {
                command: cmd::secret::SecretCommand::Inspect(args),
            } => assert_eq!(args.secrets, ["site-cert"]),
            other => panic!("expected secret inspect, got {other:?}"),
        }

        // Both positionals are required, and so is one argument to rm/inspect.
        assert!(Cli::try_parse_from(["satl", "secret", "create"]).is_err());
        assert!(Cli::try_parse_from(["satl", "secret", "create", "site-cert"]).is_err());
        assert!(Cli::try_parse_from(["satl", "secret", "rm"]).is_err());
        assert!(Cli::try_parse_from(["satl", "secret", "inspect"]).is_err());
    }

    #[test]
    fn config_subcommands() {
        let cli = Cli::parse_from([
            "satl",
            "config",
            "create",
            "-l",
            "role=web",
            "nginx-conf",
            "/tmp/nginx.conf",
        ]);
        match cli.command {
            Command::Config {
                command: cmd::config::ConfigCommand::Create(args),
            } => {
                assert_eq!(args.name, "nginx-conf");
                assert_eq!(args.file, "/tmp/nginx.conf");
                assert_eq!(args.label, ["role=web"]);
            }
            other => panic!("expected config create, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "config", "ls", "-q"]);
        match cli.command {
            Command::Config {
                command: cmd::config::ConfigCommand::Ls(args),
            } => assert!(args.quiet),
            other => panic!("expected config ls, got {other:?}"),
        }

        let cli = Cli::parse_from(["satl", "config", "rm", "nginx-conf"]);
        match cli.command {
            Command::Config {
                command: cmd::config::ConfigCommand::Rm(args),
            } => assert_eq!(args.configs, ["nginx-conf"]),
            other => panic!("expected config rm, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["satl", "config", "create"]).is_err());
        assert!(Cli::try_parse_from(["satl", "config", "create", "nginx-conf"]).is_err());
        assert!(Cli::try_parse_from(["satl", "config", "rm"]).is_err());
        assert!(Cli::try_parse_from(["satl", "config", "inspect"]).is_err());
    }

    /// The compound `--secret`/`--config` values reach the verb untouched; the
    /// parser in `crate::parse` is what interprets them.
    #[test]
    fn service_create_takes_secret_and_config_references() {
        let cli = Cli::parse_from([
            "satl",
            "service",
            "create",
            "--secret",
            "site-cert",
            "--secret",
            "source=other,target=other.pem,uid=80,gid=80,mode=0400",
            "--config",
            "src=nginx-conf,target=/etc/nginx/nginx.conf",
            "nginx:1.27",
        ]);
        match cli.command {
            Command::Service {
                command: cmd::service::ServiceCommand::Create(args),
            } => {
                assert_eq!(
                    args.secret,
                    [
                        "site-cert",
                        "source=other,target=other.pem,uid=80,gid=80,mode=0400"
                    ]
                );
                assert_eq!(args.config, ["src=nginx-conf,target=/etc/nginx/nginx.conf"]);
            }
            other => panic!("expected service create, got {other:?}"),
        }
    }

    #[test]
    fn compose_flags_are_global_on_either_side_of_the_verb() {
        for line in [
            [
                "satl",
                "compose",
                "-f",
                "stack.yaml",
                "-p",
                "shop",
                "up",
                "-d",
            ],
            [
                "satl",
                "compose",
                "up",
                "-d",
                "-f",
                "stack.yaml",
                "-p",
                "shop",
            ],
        ] {
            let cli = Cli::parse_from(line);
            match cli.command {
                Command::Compose(args) => {
                    assert_eq!(args.file, [std::path::PathBuf::from("stack.yaml")]);
                    assert_eq!(args.project_name.as_deref(), Some("shop"));
                    match args.command {
                        cmd::compose::ComposeCommand::Up(up) => {
                            assert!(up.detach && !up.remove_orphans);
                        }
                        other => panic!("expected up, got {other:?}"),
                    }
                }
                other => panic!("expected compose, got {other:?}"),
            }
        }
    }

    #[test]
    fn compose_subcommands() {
        let cli = Cli::parse_from(["satl", "compose", "down", "-v", "--remove-orphans"]);
        match cli.command {
            Command::Compose(args) => match args.command {
                cmd::compose::ComposeCommand::Down(down) => {
                    assert!(down.volumes && down.remove_orphans);
                }
                other => panic!("expected down, got {other:?}"),
            },
            other => panic!("expected compose, got {other:?}"),
        }

        let cli = Cli::parse_from([
            "satl",
            "compose",
            "--project-directory",
            "/srv/shop",
            "ps",
            "--no-trunc",
        ]);
        match cli.command {
            Command::Compose(args) => {
                assert_eq!(
                    args.project_directory,
                    Some(std::path::PathBuf::from("/srv/shop"))
                );
                match args.command {
                    cmd::compose::ComposeCommand::Ps(ps) => assert!(ps.no_trunc && !ps.quiet),
                    other => panic!("expected ps, got {other:?}"),
                }
            }
            other => panic!("expected compose, got {other:?}"),
        }

        assert!(Cli::try_parse_from(["satl", "compose", "config", "-q"]).is_ok());
        // A verb is required.
        assert!(Cli::try_parse_from(["satl", "compose"]).is_err());

        // `logs` exists since M11d, because a node-local project's tasks are
        // all on the node this CLI talks to. `--follow` is long-only: `-f` is
        // the compose file at this level (api-compat 179).
        assert!(Cli::try_parse_from(["satl", "compose", "logs"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "compose", "logs", "--follow", "web"]).is_ok());
        assert!(Cli::try_parse_from(["satl", "compose", "logs", "-f"]).is_err());
        for verb in ["stop", "start", "restart"] {
            assert!(
                Cli::try_parse_from(["satl", "compose", verb]).is_ok(),
                "compose {verb} should parse"
            );
        }
        assert!(Cli::try_parse_from(["satl", "compose", "up", "--scale", "web=3"]).is_ok());
    }

    #[test]
    fn ps_flags() {
        let cli = Cli::parse_from(["satl", "ps", "-a", "--no-trunc", "-q"]);
        match cli.command {
            Command::Ps(args) => assert!(args.all && args.no_trunc && args.quiet),
            other => panic!("expected ps, got {other:?}"),
        }
    }
}
