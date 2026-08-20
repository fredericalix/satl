// SPDX-License-Identifier: BSD-2-Clause
//! Swarm endpoints: init, join, leave, inspect and token rotation.
//!
//! SatL nodes bootstrap a single-node cluster at first start (architecture
//! §1.2), so `GET /swarm` answers on a fresh daemon and `POST /swarm/init`
//! re-initializes rather than creating from nothing.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{Params, flag, json_body};
use crate::backend::model::{BackendError, SwarmDetail, TokenRole};
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;
use crate::types::{SwarmInitBody, SwarmJoinBody, SwarmSpecBody, UnlockKeyBody, UnlockKeyResponse};

/// `GET /swarm`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/swarm",
    operation_id = "SwarmInspect",
    tag = "Swarm",
    description = "Answers on a fresh daemon: a SatL node bootstraps a \
        single-node cluster at first start (architecture section 1.2). \
        `TLSInfo` carries `TrustRoot` only, and `RootRotationInProgress` is \
        always false (api-compat #45).",
    responses(
        (status = 200, description = "The cluster document.", body = crate::types::SwarmResponse),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let detail = state.backend().swarm_inspect().await?;
    Ok(Json(render::swarm(&detail)).into_response())
}

/// `POST /swarm/init`.
///
/// Docker answers `200` with the new manager's node ID as a bare JSON string.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/swarm/init",
    operation_id = "SwarmInit",
    tag = "Swarm",
    description = "**Idempotent**: a SatL node self-initializes a single-node \
        cluster on first boot, so `init` re-initializes an existing one \
        rather than creating from nothing (api-compat #42). \
        `ForceNewCluster` is a 501 permanently (api-compat #137); changing \
        the advertise or listen address is a 400 pointing at `satld.toml`; \
        `Spec`, `DataPathAddr`, `DataPathPort`, `DefaultAddrPool` and \
        `SubnetSize` are accepted and ignored. The 200 body is the new \
        manager's node ID as a bare JSON string, exactly as Docker sends it.",
    request_body = crate::types::SwarmInitBody,
    responses(
        (status = 200, description = "The manager's node ID, as a bare JSON string.", body = String),
        (status = 400, description = "Invalid body, or an address change that belongs in `satld.toml`.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`ForceNewCluster` was set (api-compat #137), or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn init(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: SwarmInitBody = json_body(&body)?;
    let options = convert::swarm_init_options(&body)?;
    let result = state.backend().swarm_init(options).await?;
    tracing::info!(node = %result.node_id, "swarm initialized");
    Ok(Json(result.node_id).into_response())
}

/// `POST /swarm/join`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/swarm/join",
    operation_id = "SwarmJoin",
    tag = "Swarm",
    description = "Both token roles are accepted, and the token decides the \
        role as in Docker (api-compat #43). The token format is \
        `SATL-1-<digest>-<secret>`: the digest pins the CA bundle so a first \
        contact over an untrusted channel cannot be MITM'd, and tooling that \
        pattern-matches `SWMTKN` will not recognize it (api-compat #55).",
    request_body = crate::types::SwarmJoinBody,
    responses(
        (status = 200, description = "Joined."),
        (status = 400, description = "Invalid body or token.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "No manager was reachable at the given addresses.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn join(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<StatusCode, BackendError> {
    let body: SwarmJoinBody = json_body(&body)?;
    let options = convert::swarm_join_options(body)?;
    let managers = options.remote_addrs.join(", ");
    state.backend().swarm_join(options).await?;
    tracing::info!(managers = %managers, "joined the swarm");
    Ok(StatusCode::OK)
}

/// `POST /swarm/leave?force=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/swarm/leave",
    operation_id = "SwarmLeave",
    tag = "Swarm",
    description = "Leaves the cluster.",
    params(("force" = Option<String>, Query, description = "Leave even when this node is the last manager. Docker `BoolValue` semantics.")),
    responses(
        (status = 200, description = "Left."),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "Refused: this node is the last manager and `?force=` was not set.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn leave(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<StatusCode, BackendError> {
    let force = flag(&params, "force");
    state.backend().swarm_leave(force).await?;
    tracing::info!(force, "left the swarm");
    Ok(StatusCode::OK)
}

/// `POST /swarm/update?rotateWorkerToken=&rotateManagerToken=`.
///
/// What an update can do, besides rotating the join tokens (the query flags)
/// and the root CA (a `CAConfig.ForceRotate` above the stored counter —
/// exactly what `docker swarm ca --rotate` sends, SWK §6.6):
///
/// - `EncryptionConfig.AutoLockManagers` toggles manager autolock
///   ([`Backend::swarm_set_autolock`]), and
/// - `?rotateManagerUnlockKey` rotates the unlock key
///   ([`Backend::swarm_rotate_unlock_key`]).
///
/// `?version=` is accepted and the rest of the body's spec is accepted and
/// ignored, because Docker's clients read-modify-write the whole spec. The
/// response carries the updated `Swarm` document where Docker sends an empty
/// body — a superset Docker clients ignore (deviation recorded in
/// `docs/api-compat.md`).
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/swarm/update",
    operation_id = "SwarmUpdate",
    tag = "Swarm",
    description = "Applies exactly four kinds of update and refuses the rest \
        with a 501 (api-compat #44): join-token rotation (the query flags), \
        root CA rotation (a `CAConfig.ForceRotate` above the stored counter, \
        api-compat #97), the manager autolock toggle \
        (`EncryptionConfig.AutoLockManagers`) and unlock-key rotation \
        (`?rotateManagerUnlockKey`, api-compat #151). The rest of the body's \
        spec is accepted and ignored, because Docker's clients \
        read-modify-write the whole spec. The response carries the updated \
        `Swarm` document where Docker sends an empty body -- a superset \
        clients discard (api-compat #44).",
    params(
        ("version" = Option<String>, Query, description = "Accepted but not enforced (api-compat #44)."),
        ("rotateWorkerToken" = Option<String>, Query, description = "Rotate the worker join token. Docker `BoolValue` semantics."),
        ("rotateManagerToken" = Option<String>, Query, description = "Rotate the manager join token. Docker `BoolValue` semantics."),
        ("rotateManagerUnlockKey" = Option<String>, Query, description = "Rotate the manager unlock key (api-compat #151). Docker `BoolValue` semantics.")
    ),
    request_body = crate::types::SwarmSpecBody,
    responses(
        (status = 200, description = "The updated cluster document.", body = crate::types::SwarmResponse),
        (status = 400, description = "Invalid body.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "The request asked for a spec change SatL does not apply (api-compat #44).", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn update(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let spec: SwarmSpecBody = json_body(&body)?;
    let mut detail: Option<SwarmDetail> = None;
    if flag(&params, "rotateManagerUnlockKey") {
        detail = Some(state.backend().swarm_rotate_unlock_key().await?);
        tracing::info!("manager unlock key rotated");
    }

    // An autolock toggle, from a read-modify-write client sending the whole
    // spec back: only a *changed* flag is an update.
    if let Some(encryption) = spec.encryption_config {
        let current = state.backend().swarm_inspect().await?;
        if encryption.auto_lock_managers != current.spec.autolock {
            detail = Some(
                state
                    .backend()
                    .swarm_set_autolock(encryption.auto_lock_managers)
                    .await?,
            );
            tracing::info!(
                autolock = encryption.auto_lock_managers,
                "manager autolock toggled"
            );
        }
    }

    let mut roles = Vec::new();
    if flag(&params, "rotateWorkerToken") {
        roles.push(TokenRole::Worker);
    }
    if flag(&params, "rotateManagerToken") {
        roles.push(TokenRole::Manager);
    }

    // A ForceRotate above the stored counter starts a root CA rotation; a
    // spec resent verbatim by a token-rotation client carries the stored
    // value and triggers nothing.
    if let Some(force_rotate) = spec.ca_config.map(|ca| ca.force_rotate) {
        let current = state.backend().swarm_inspect().await?;
        if force_rotate > current.spec.ca.force_rotate {
            detail = Some(state.backend().swarm_rotate_ca(force_rotate).await?);
            tracing::info!(force_rotate, "root CA rotation started");
        }
    }
    for role in roles {
        detail = Some(state.backend().swarm_rotate_token(role).await?);
        tracing::info!(%role, "join token rotated");
    }
    let Some(detail) = detail else {
        return Err(BackendError::not_implemented(
            "updating the cluster spec is not supported by SatL: \
             POST /swarm/update rotates join tokens (?rotateWorkerToken / \
             ?rotateManagerToken), the manager unlock key \
             (?rotateManagerUnlockKey), autolock (EncryptionConfig) and the \
             root CA (a CAConfig.ForceRotate above the stored counter)",
        ));
    };
    Ok(Json(render::swarm(&detail)).into_response())
}

/// `POST /swarm/unlock` on a *running* daemon: always a refusal. A daemon
/// that actually is locked serves only this route (satld's locked listener);
/// reaching it through the full router means the store is already open.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/swarm/unlock",
    operation_id = "SwarmUnlock",
    tag = "Swarm",
    description = "The second of the two routes a **locked** manager serves \
        (api-compat #151): it takes the operator's unlock key and tries it \
        against the sealed raft DEK, answering 200 on success and 401 on a \
        wrong key. Reaching this operation through the full router means the \
        store is already open, so a running daemon always answers 503 here.",
    request_body = crate::types::UnlockKeyBody,
    responses(
        (status = 200, description = "The key opened the sealed store (locked daemon only)."),
        (status = 400, description = "`UnlockKey` is missing or empty.", body = crate::types::ErrorBody),
        (status = 401, description = "The key does not open this manager's sealed store (locked daemon only).", body = crate::types::ErrorBody),
        (status = 503, description = "This swarm is not locked: the store is already open.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn unlock(body: Bytes) -> Result<StatusCode, BackendError> {
    let _: UnlockKeyBody = json_body(&body)?;
    Err(BackendError::unavailable(
        "this swarm is not locked: the store is already open",
    ))
}

/// `GET /swarm/unlockkey`: the current unlock key, from the open store —
/// manager-only, and meaningful only while autolock is on.
#[utoipa::path(
    get,
    path = "/swarm/unlockkey",
    operation_id = "SwarmUnlockkey",
    tag = "Swarm",
    description = "The current unlock key, read from the open store. \
        Manager-only, and meaningful only while autolock is on (api-compat \
        #151).",
    responses(
        (status = 200, description = "The current unlock key.", body = crate::types::UnlockKeyResponse),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn unlock_key(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let key = state.backend().swarm_unlock_key().await?;
    Ok(Json(UnlockKeyResponse { unlock_key: key }).into_response())
}
