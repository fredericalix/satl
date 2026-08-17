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
pub(super) async fn inspect(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let detail = state.backend().swarm_inspect().await?;
    Ok(Json(render::swarm(&detail)).into_response())
}

/// `POST /swarm/init`.
///
/// Docker answers `200` with the new manager's node ID as a bare JSON string.
#[allow(clippy::needless_pass_by_value)]
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
pub(super) async fn unlock(body: Bytes) -> Result<StatusCode, BackendError> {
    let _: UnlockKeyBody = json_body(&body)?;
    Err(BackendError::unavailable(
        "this swarm is not locked: the store is already open",
    ))
}

/// `GET /swarm/unlockkey`: the current unlock key, from the open store —
/// manager-only, and meaningful only while autolock is on.
pub(super) async fn unlock_key(State(state): State<ApiState>) -> Result<Response, BackendError> {
    let key = state.backend().swarm_unlock_key().await?;
    Ok(Json(UnlockKeyResponse { unlock_key: key }).into_response())
}
