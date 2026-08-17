// SPDX-License-Identifier: BSD-2-Clause
//! `satl swarm init|join|leave|update|join-token|unlock|unlock-key` (aliased
//! as `satl cluster …`).
//!
//! The flow mirrors the docker CLI's: `init` posts to `/swarm/init`, then
//! reads `/swarm` and the new manager's node object to print the ready-made
//! `satl swarm join` invitation an operator can paste on the next node.
//! `--autolock` (init or `update --autolock=…`) is Docker's manager-key
//! locking: the daemon answers with the unlock key via `/swarm/unlockkey`,
//! shown once, here.

use crate::api::cluster::{
    Node, Swarm, SwarmInitBody, SwarmJoinBody, SystemInfo, UnlockKeyBody, UnlockKeyResponse,
};
use crate::client::{self, Host};
use crate::output::Streams;

/// Subcommands of `satl swarm`.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum SwarmCommand {
    /// Initialize a swarm.
    Init(InitArgs),
    /// Join a swarm as a node and/or manager.
    Join(JoinArgs),
    /// Leave the swarm.
    Leave(LeaveArgs),
    /// Update swarm settings.
    Update(UpdateArgs),
    /// Manage join tokens.
    JoinToken(JoinTokenArgs),
    /// Unlock a locked manager.
    Unlock(UnlockArgs),
    /// Display or rotate the manager unlock key.
    UnlockKey(UnlockKeyArgs),
}

/// Flags of `satl swarm init`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct InitArgs {
    /// Advertised address (format: `<ip|interface>[:port]`).
    #[arg(long, value_name = "ADDR")]
    pub advertise_addr: Option<String>,

    /// Listen address (format: `<ip|interface>[:port]`).
    #[arg(long, value_name = "ADDR")]
    pub listen_addr: Option<String>,

    /// Force create a new cluster from the current state.
    #[arg(long)]
    pub force_new_cluster: bool,

    /// Lock the managers' keys behind an unlock key, shown once.
    #[arg(long)]
    pub autolock: bool,
}

/// Flags of `satl swarm update`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UpdateArgs {
    /// Turn manager autolock on or off (`--autolock=true|false`).
    #[arg(long, value_name = "true|false")]
    pub autolock: Option<bool>,
}

/// Flags of `satl swarm unlock`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UnlockArgs {
    /// The unlock key, base64. Without the flag, one line is read from
    /// stdin (pipe it, or type it in).
    #[arg(long, value_name = "KEY")]
    pub key: Option<String>,
}

/// Flags of `satl swarm unlock-key`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct UnlockKeyArgs {
    /// Rotate the unlock key; every manager reseals.
    #[arg(long)]
    pub rotate: bool,

    /// Only display the key.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Flags of `satl swarm join`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct JoinArgs {
    /// Token for entry into the swarm.
    #[arg(long, required = true, value_name = "TOKEN")]
    pub token: String,

    /// Advertised address (format: `<ip|interface>[:port]`).
    #[arg(long, value_name = "ADDR")]
    pub advertise_addr: Option<String>,

    /// Listen address (format: `<ip|interface>[:port]`).
    #[arg(long, value_name = "ADDR")]
    pub listen_addr: Option<String>,

    /// Address of an existing manager (`<ip>:<port>`).
    #[arg(value_name = "HOST:PORT")]
    pub manager: String,
}

/// Flags of `satl swarm leave`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct LeaveArgs {
    /// Force this node to leave the swarm, ignoring warnings.
    #[arg(short, long)]
    pub force: bool,
}

/// Flags of `satl swarm join-token`.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct JoinTokenArgs {
    /// Rotate the join token.
    #[arg(long)]
    pub rotate: bool,

    /// Only display the token.
    #[arg(short, long)]
    pub quiet: bool,

    /// Which token to show.
    #[arg(value_name = "worker|manager", value_parser = ["worker", "manager"])]
    pub role: String,
}

/// Dispatch a `satl swarm` subcommand.
pub async fn execute(
    host: &Host,
    command: &SwarmCommand,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    match command {
        SwarmCommand::Init(args) => init(host, args, streams).await,
        SwarmCommand::Join(args) => join(host, args, streams).await,
        SwarmCommand::Leave(args) => leave(host, args, streams).await,
        SwarmCommand::Update(args) => update(host, args, streams).await,
        SwarmCommand::JoinToken(args) => join_token(host, args, streams).await,
        SwarmCommand::Unlock(args) => unlock(host, args, streams).await,
        SwarmCommand::UnlockKey(args) => unlock_key(host, args, streams).await,
    }
}

async fn init(host: &Host, args: &InitArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let body = SwarmInitBody {
        listen_addr: args.listen_addr.clone().unwrap_or_default(),
        advertise_addr: args.advertise_addr.clone().unwrap_or_default(),
        force_new_cluster: args.force_new_cluster,
        auto_lock_managers: args.autolock,
    };
    let node_id: String = client::post_json(host, "/swarm/init", Some(&body)).await?;
    let swarm: Swarm = client::get_json(host, "/swarm").await?;
    let addr = manager_addr(host, &node_id).await;
    streams
        .out(init_message(&node_id, &swarm.join_tokens.worker, &addr).as_bytes())
        .await;
    if args.autolock {
        let key = current_unlock_key(host).await?;
        streams.out(unlock_key_message(&key).as_bytes()).await;
    }
    Ok(0)
}

async fn update(host: &Host, args: &UpdateArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let Some(autolock) = args.autolock else {
        anyhow::bail!("nothing to update: pass --autolock=true|false");
    };
    // Docker's read-modify-write: inspect for the version and the spec,
    // change the one flag, post it back.
    let swarm: Swarm = client::get_json(host, "/swarm").await?;
    let mut spec = swarm.spec.clone();
    spec["EncryptionConfig"] = serde_json::json!({"AutoLockManagers": autolock});
    let path = format!(
        "/swarm/update{}",
        client::query(&[("version", swarm.version.index.to_string().as_str())])
    );
    client::post_ok(host, &path, Some(&spec)).await?;
    if autolock {
        let key = current_unlock_key(host).await?;
        streams.out(unlock_key_message(&key).as_bytes()).await;
    }
    Ok(0)
}

/// The current unlock key, straight from the daemon.
async fn current_unlock_key(host: &Host) -> anyhow::Result<String> {
    let response: UnlockKeyResponse = client::get_json(host, "/swarm/unlockkey").await?;
    Ok(response.unlock_key)
}

async fn unlock(host: &Host, args: &UnlockArgs, _streams: &mut Streams) -> anyhow::Result<u8> {
    let key = match &args.key {
        Some(key) => key.clone(),
        None => read_key_line().await?,
    };
    let body = UnlockKeyBody { unlock_key: key };
    client::post_ok(host, "/swarm/unlock", Some(&body)).await?;
    Ok(0)
}

/// One line of stdin, trimmed — how the key arrives without `--key`
/// (Docker prompts interactively; a line from a pipe or a terminal is the
/// same thing here).
async fn read_key_line() -> anyhow::Result<String> {
    use tokio::io::AsyncBufReadExt as _;
    let mut line = String::new();
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|err| anyhow::anyhow!("could not read the unlock key from stdin: {err}"))?;
    let key = line.trim().to_owned();
    if read == 0 || key.is_empty() {
        anyhow::bail!("no unlock key given: pass --key, or pipe one line of stdin");
    }
    Ok(key)
}

async fn unlock_key(
    host: &Host,
    args: &UnlockKeyArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    if args.rotate {
        let swarm: Swarm = client::get_json(host, "/swarm").await?;
        let path = format!(
            "/swarm/update{}",
            client::query(&[
                ("version", swarm.version.index.to_string().as_str()),
                ("rotateManagerUnlockKey", "true"),
            ])
        );
        client::post_ok(host, &path, Some(&swarm.spec)).await?;
        if !args.quiet {
            streams
                .outln("Successfully rotated manager unlock key.\n")
                .await;
        }
    }
    let key = current_unlock_key(host).await?;
    if args.quiet {
        streams.outln(&key).await;
    } else {
        streams.out(unlock_key_message(&key).as_bytes()).await;
    }
    Ok(0)
}

/// The block docker prints when an unlock key is (re)issued (pure, for
/// goldens).
pub fn unlock_key_message(key: &str) -> String {
    format!(
        "To unlock a swarm manager after it restarts, run the following command:\n\n    \
         satl swarm unlock\n\n\
         Please remember the following key, as it will not be shown again:\n\n    {key}\n\n"
    )
}

async fn join(host: &Host, args: &JoinArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let body = SwarmJoinBody {
        listen_addr: args.listen_addr.clone().unwrap_or_default(),
        advertise_addr: args.advertise_addr.clone().unwrap_or_default(),
        remote_addrs: vec![args.manager.clone()],
        join_token: args.token.clone(),
    };
    client::post_ok(host, "/swarm/join", Some(&body)).await?;
    // Docker decides the wording from the role the daemon ended up with.
    let manager = client::get_json::<SystemInfo>(host, "/info")
        .await
        .is_ok_and(|info| info.swarm.control_available);
    let role = if manager { "manager" } else { "worker" };
    streams
        .outln(&format!("This node joined a swarm as a {role}."))
        .await;
    Ok(0)
}

async fn leave(host: &Host, args: &LeaveArgs, streams: &mut Streams) -> anyhow::Result<u8> {
    let path = format!(
        "/swarm/leave{}",
        client::query(&[("force", if args.force { "true" } else { "false" })])
    );
    client::post_empty_ok(host, &path).await?;
    streams.outln("Node left the swarm.").await;
    Ok(0)
}

async fn join_token(
    host: &Host,
    args: &JoinTokenArgs,
    streams: &mut Streams,
) -> anyhow::Result<u8> {
    if args.rotate {
        // Docker's read-modify-write: inspect for the version, resend the
        // spec, ask for the rotation in the query string.
        let swarm: Swarm = client::get_json(host, "/swarm").await?;
        let version = swarm.version.index.to_string();
        let path = format!(
            "/swarm/update{}",
            client::query(&[
                ("version", version.as_str()),
                (rotate_flag(&args.role), "true"),
            ])
        );
        client::post_ok(host, &path, Some(&swarm.spec)).await?;
        if !args.quiet {
            streams
                .out(format!("Successfully rotated {} join token.\n\n", args.role).as_bytes())
                .await;
        }
    }

    let swarm: Swarm = client::get_json(host, "/swarm").await?;
    let token = match args.role.as_str() {
        "manager" => swarm.join_tokens.manager,
        _ => swarm.join_tokens.worker,
    };
    if args.quiet {
        streams.outln(&token).await;
        return Ok(0);
    }

    let info: SystemInfo = client::get_json(host, "/info").await?;
    let addr = manager_addr(host, &info.swarm.node_id).await;
    streams
        .out(join_hint(&args.role, &token, &addr).as_bytes())
        .await;
    Ok(0)
}

/// The `POST /swarm/update` query flag that rotates `role`'s token.
fn rotate_flag(role: &str) -> &'static str {
    if role == "manager" {
        "rotateManagerToken"
    } else {
        "rotateWorkerToken"
    }
}

/// The address to paste into a `satl swarm join` command: the manager's Raft
/// address, falling back to the address the dispatcher observed. Failures are
/// not fatal — docker prints `<manager-ip>:2377` as a placeholder rather than
/// failing a successful `init`.
async fn manager_addr(host: &Host, node_id: &str) -> String {
    const PLACEHOLDER: &str = "<manager-ip>:2377";
    if node_id.is_empty() {
        return PLACEHOLDER.to_owned();
    }
    let path = format!("/nodes/{node_id}");
    let Ok(node) = client::get_json::<Node>(host, &path).await else {
        return PLACEHOLDER.to_owned();
    };
    node.manager_status
        .map(|status| status.addr)
        .filter(|addr| !addr.is_empty())
        .or_else(|| Some(node.status.addr).filter(|addr| !addr.is_empty()))
        .unwrap_or_else(|| PLACEHOLDER.to_owned())
}

/// What `satl swarm init` prints (pure, for goldens).
pub fn init_message(node_id: &str, worker_token: &str, addr: &str) -> String {
    format!(
        "Swarm initialized: current node ({node_id}) is now a manager.\n\n{}\
         To add a manager to this swarm, run 'satl swarm join-token manager' \
         and follow the instructions.\n\n",
        join_hint("worker", worker_token, addr)
    )
}

/// The ready-to-paste join invitation docker prints (pure, for goldens).
pub fn join_hint(role: &str, token: &str, addr: &str) -> String {
    format!(
        "To add a {role} to this swarm, run the following command:\n\n    \
         satl swarm join --token {token} {addr}\n\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing;
    use crate::stub::{Reply, Stub};

    const NODE_ID: &str = "1hvy0lj3x0b883f8e30fyp217";

    fn swarm_reply() -> Reply {
        Reply::json(
            200,
            r#"{"ID":"cluster1","Version":{"Index":11},
                "JoinTokens":{"Worker":"SATL-1-worker","Manager":"SATL-1-manager"},
                "Spec":{"Name":"default"}}"#,
        )
    }

    fn node_reply() -> Reply {
        Reply::json(
            200,
            r#"{"ID":"1hvy0lj3x0b883f8e30fyp217","ManagerStatus":{"Addr":"10.2.0.11:2377"}}"#,
        )
    }

    #[test]
    fn join_hint_golden() {
        assert_eq!(
            join_hint("worker", "SATL-1-worker", "10.2.0.11:2377"),
            "To add a worker to this swarm, run the following command:\n\n    \
             satl swarm join --token SATL-1-worker 10.2.0.11:2377\n\n"
        );
    }

    #[test]
    fn init_message_golden() {
        let expected = "\
Swarm initialized: current node (1hvy0lj3x0b883f8e30fyp217) is now a manager.

To add a worker to this swarm, run the following command:

    satl swarm join --token SATL-1-worker 10.2.0.11:2377

To add a manager to this swarm, run 'satl swarm join-token manager' and follow the instructions.

";
        assert_eq!(
            init_message(NODE_ID, "SATL-1-worker", "10.2.0.11:2377"),
            expected
        );
    }

    #[tokio::test]
    async fn init_posts_the_options_and_prints_the_join_hint() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/swarm/init",
            Reply::json(200, &format!("\"{NODE_ID}\"")),
        )
        .on("GET", "/swarm", swarm_reply())
        .on("GET", &format!("/nodes/{NODE_ID}"), node_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = InitArgs {
            advertise_addr: Some("10.2.0.11:2377".to_owned()),
            listen_addr: Some("0.0.0.0:2377".to_owned()),
            force_new_cluster: true,
            autolock: false,
        };
        let code = execute(&stub.host(), &SwarmCommand::Init(args), &mut streams)
            .await
            .expect("init succeeds");

        assert_eq!(code, 0);
        assert_eq!(
            out.contents(),
            init_message(NODE_ID, "SATL-1-worker", "10.2.0.11:2377")
        );
        let call = stub.first_call("POST /swarm/init").expect("init call");
        assert_eq!(
            call.body,
            r#"{"ListenAddr":"0.0.0.0:2377","AdvertiseAddr":"10.2.0.11:2377","ForceNewCluster":true}"#
        );
    }

    #[tokio::test]
    async fn init_reports_a_daemon_failure() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/swarm/init",
            Reply::json(503, r#"{"message":"this node is already part of a swarm"}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let err = execute(
            &stub.host(),
            &SwarmCommand::Init(InitArgs::default()),
            &mut streams,
        )
        .await
        .expect_err("a failed init must not print a join hint");
        assert!(err.to_string().contains("already part of a swarm"), "{err}");
        assert!(out.contents().is_empty());
    }

    #[tokio::test]
    async fn join_sends_the_token_and_manager_address() {
        let stub = Stub::start().await;
        stub.on("POST", "/swarm/join", Reply::empty(200)).on(
            "GET",
            "/info",
            Reply::json(200, r#"{"Swarm":{"ControlAvailable":false}}"#),
        );

        let (mut streams, out, _err) = testing::streams();
        let args = JoinArgs {
            token: "SATL-1-worker".to_owned(),
            advertise_addr: Some("10.2.0.12".to_owned()),
            listen_addr: None,
            manager: "10.2.0.11:2377".to_owned(),
        };
        execute(&stub.host(), &SwarmCommand::Join(args), &mut streams)
            .await
            .expect("join succeeds");

        assert_eq!(out.contents(), "This node joined a swarm as a worker.\n");
        let call = stub.first_call("POST /swarm/join").expect("join call");
        assert_eq!(
            call.body,
            r#"{"AdvertiseAddr":"10.2.0.12","RemoteAddrs":["10.2.0.11:2377"],"JoinToken":"SATL-1-worker"}"#
        );
    }

    #[tokio::test]
    async fn join_as_a_manager_says_so() {
        let stub = Stub::start().await;
        stub.on("POST", "/swarm/join", Reply::empty(200)).on(
            "GET",
            "/info",
            Reply::json(200, r#"{"Swarm":{"ControlAvailable":true}}"#),
        );
        let (mut streams, out, _err) = testing::streams();
        let args = JoinArgs {
            token: "SATL-1-manager".to_owned(),
            manager: "10.2.0.11:2377".to_owned(),
            ..JoinArgs::default()
        };
        execute(&stub.host(), &SwarmCommand::Join(args), &mut streams)
            .await
            .expect("join succeeds");
        assert_eq!(out.contents(), "This node joined a swarm as a manager.\n");
    }

    #[tokio::test]
    async fn leave_forwards_force() {
        let stub = Stub::start().await;
        stub.on("POST", "/swarm/leave", Reply::empty(200));
        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &SwarmCommand::Leave(LeaveArgs { force: true }),
            &mut streams,
        )
        .await
        .expect("leave succeeds");
        assert_eq!(out.contents(), "Node left the swarm.\n");
        assert_eq!(
            stub.first_call("POST /swarm/leave").expect("leave").query,
            "force=true"
        );
    }

    #[tokio::test]
    async fn join_token_prints_the_invitation() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", swarm_reply())
            .on(
                "GET",
                "/info",
                Reply::json(200, &format!(r#"{{"Swarm":{{"NodeID":"{NODE_ID}"}}}}"#)),
            )
            .on("GET", &format!("/nodes/{NODE_ID}"), node_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = JoinTokenArgs {
            role: "manager".to_owned(),
            ..JoinTokenArgs::default()
        };
        execute(&stub.host(), &SwarmCommand::JoinToken(args), &mut streams)
            .await
            .expect("join-token succeeds");
        assert_eq!(
            out.contents(),
            join_hint("manager", "SATL-1-manager", "10.2.0.11:2377")
        );
    }

    #[tokio::test]
    async fn join_token_quiet_prints_only_the_token() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", swarm_reply());
        let (mut streams, out, _err) = testing::streams();
        let args = JoinTokenArgs {
            quiet: true,
            role: "worker".to_owned(),
            rotate: false,
        };
        execute(&stub.host(), &SwarmCommand::JoinToken(args), &mut streams)
            .await
            .expect("join-token succeeds");
        assert_eq!(out.contents(), "SATL-1-worker\n");
        assert_eq!(stub.routes(), vec!["GET /swarm"]);
    }

    #[tokio::test]
    async fn join_token_rotate_updates_with_the_current_version() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", swarm_reply())
            .on("POST", "/swarm/update", Reply::empty(200))
            .on(
                "GET",
                "/info",
                Reply::json(200, &format!(r#"{{"Swarm":{{"NodeID":"{NODE_ID}"}}}}"#)),
            )
            .on("GET", &format!("/nodes/{NODE_ID}"), node_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = JoinTokenArgs {
            rotate: true,
            quiet: false,
            role: "worker".to_owned(),
        };
        execute(&stub.host(), &SwarmCommand::JoinToken(args), &mut streams)
            .await
            .expect("rotation succeeds");

        let call = stub.first_call("POST /swarm/update").expect("update call");
        assert_eq!(call.query, "version=11&rotateWorkerToken=true");
        assert_eq!(call.body, r#"{"Name":"default"}"#);
        assert_eq!(
            out.contents(),
            format!(
                "Successfully rotated worker join token.\n\n{}",
                join_hint("worker", "SATL-1-worker", "10.2.0.11:2377")
            )
        );
    }

    #[tokio::test]
    async fn init_falls_back_to_a_placeholder_address() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/swarm/init",
            Reply::json(200, &format!("\"{NODE_ID}\"")),
        )
        .on("GET", "/swarm", swarm_reply());
        // No /nodes/{id} reply: the node lookup fails, init still succeeds.
        let (mut streams, out, _err) = testing::streams();
        execute(
            &stub.host(),
            &SwarmCommand::Init(InitArgs::default()),
            &mut streams,
        )
        .await
        .expect("init succeeds");
        assert!(
            out.contents().contains("<manager-ip>:2377"),
            "{}",
            out.contents()
        );
    }

    fn unlock_key_reply() -> Reply {
        Reply::json(200, r#"{"UnlockKey":"dGhlLWtleQ=="}"#)
    }

    #[tokio::test]
    async fn init_with_autolock_prints_the_unlock_key_once() {
        let stub = Stub::start().await;
        stub.on(
            "POST",
            "/swarm/init",
            Reply::json(200, &format!("\"{NODE_ID}\"")),
        )
        .on("GET", "/swarm", swarm_reply())
        .on("GET", &format!("/nodes/{NODE_ID}"), node_reply())
        .on("GET", "/swarm/unlockkey", unlock_key_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = InitArgs {
            autolock: true,
            ..InitArgs::default()
        };
        execute(&stub.host(), &SwarmCommand::Init(args), &mut streams)
            .await
            .expect("init succeeds");

        let call = stub.first_call("POST /swarm/init").expect("init call");
        assert_eq!(
            call.body,
            r#"{"ForceNewCluster":false,"AutoLockManagers":true}"#
        );
        assert!(
            out.contents().contains(&unlock_key_message("dGhlLWtleQ==")),
            "{}",
            out.contents()
        );
    }

    #[tokio::test]
    async fn update_autolock_posts_the_spec_with_the_flag_set() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", swarm_reply())
            .on("POST", "/swarm/update", Reply::empty(200))
            .on("GET", "/swarm/unlockkey", unlock_key_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = UpdateArgs {
            autolock: Some(true),
        };
        execute(&stub.host(), &SwarmCommand::Update(args), &mut streams)
            .await
            .expect("update succeeds");

        let call = stub.first_call("POST /swarm/update").expect("update call");
        assert_eq!(call.query, "version=11");
        let body: serde_json::Value = serde_json::from_str(&call.body).expect("json body");
        assert_eq!(
            body["EncryptionConfig"]["AutoLockManagers"],
            serde_json::json!(true)
        );
        assert_eq!(body["Name"], "default");
        assert!(
            out.contents().contains("dGhlLWtleQ=="),
            "{}",
            out.contents()
        );
    }

    #[tokio::test]
    async fn update_without_a_flag_is_an_error() {
        let stub = Stub::start().await;
        let (mut streams, _out, _err) = testing::streams();
        let err = execute(
            &stub.host(),
            &SwarmCommand::Update(UpdateArgs::default()),
            &mut streams,
        )
        .await
        .expect_err("nothing to do is an error");
        assert!(err.to_string().contains("--autolock"), "{err}");
    }

    #[tokio::test]
    async fn unlock_posts_the_key_and_nothing_more() {
        let stub = Stub::start().await;
        stub.on("POST", "/swarm/unlock", Reply::empty(200));
        let (mut streams, out, _err) = testing::streams();
        let args = UnlockArgs {
            key: Some("dGhlLWtleQ==".to_owned()),
        };
        execute(&stub.host(), &SwarmCommand::Unlock(args), &mut streams)
            .await
            .expect("unlock succeeds");
        assert_eq!(
            stub.first_call("POST /swarm/unlock")
                .expect("unlock call")
                .body,
            r#"{"UnlockKey":"dGhlLWtleQ=="}"#
        );
        assert!(out.contents().is_empty(), "{}", out.contents());
    }

    #[tokio::test]
    async fn unlock_key_rotate_then_prints() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm", swarm_reply())
            .on("POST", "/swarm/update", Reply::empty(200))
            .on("GET", "/swarm/unlockkey", unlock_key_reply());

        let (mut streams, out, _err) = testing::streams();
        let args = UnlockKeyArgs {
            rotate: true,
            quiet: false,
        };
        execute(&stub.host(), &SwarmCommand::UnlockKey(args), &mut streams)
            .await
            .expect("unlock-key succeeds");

        let call = stub.first_call("POST /swarm/update").expect("rotate call");
        assert_eq!(call.query, "version=11&rotateManagerUnlockKey=true");
        assert!(
            out.contents()
                .contains("Successfully rotated manager unlock key."),
            "{}",
            out.contents()
        );
        assert!(
            out.contents().contains("dGhlLWtleQ=="),
            "{}",
            out.contents()
        );
    }

    #[tokio::test]
    async fn unlock_key_quiet_prints_only_the_key() {
        let stub = Stub::start().await;
        stub.on("GET", "/swarm/unlockkey", unlock_key_reply());
        let (mut streams, out, _err) = testing::streams();
        let args = UnlockKeyArgs {
            rotate: false,
            quiet: true,
        };
        execute(&stub.host(), &SwarmCommand::UnlockKey(args), &mut streams)
            .await
            .expect("unlock-key succeeds");
        assert_eq!(out.contents(), "dGhlLWtleQ==\n");
        assert_eq!(stub.routes(), vec!["GET /swarm/unlockkey"]);
    }
}
