// SPDX-License-Identifier: BSD-2-Clause
//! Network endpoints: list, inspect, create, remove, connect and disconnect
//! (architecture §11, `docs/api-compat.md`).
//!
//! Two SatL facts shape these handlers:
//!
//! - **`Scope` follows the driver.** An `overlay` network is cluster-wide
//!   (`swarm`), a `bridge` network is node-local (`local`); there is no third
//!   option to negotiate.
//! - **The gateway a document reports is this node's.** An overlay has one
//!   gateway address per participating node, so a cluster-wide gateway does not
//!   exist to report (`docs/vxlan.md` §8). The backend fills in the local one.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{Params, json_body, reject_filters};
use crate::backend::model::BackendError;
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;
use crate::types::{
    NetworkConnectBody, NetworkCreateBody, NetworkCreateResponse, NetworkDisconnectBody,
};

/// `GET /networks`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, "networks")?;
    let networks = state.backend().list_networks().await?;
    let body: Vec<_> = networks.iter().map(render::network_summary).collect();
    Ok(Json(body).into_response())
}

/// `GET /networks/{id}`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let network = state.backend().inspect_network(&id).await?;
    Ok(Json(render::network_detail(&network)).into_response())
}

/// `POST /networks/create`.
///
/// The ingress check is here rather than in the converter because it is the one
/// rejection that needs to see the other networks: a cluster has exactly one
/// ingress network (SWK §9.5), and the second request for one has to say so
/// instead of creating a network that the allocator will then fight over. The
/// backend re-checks it under the store lock — this is the 400 the operator
/// sees, not the guarantee.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn create(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: NetworkCreateBody = json_body(&body)?;
    let spec = convert::network_spec(body)?;
    if spec.ingress {
        let existing = state.backend().list_networks().await?;
        if let Some(other) = existing.iter().find(|summary| summary.network.spec.ingress) {
            return Err(BackendError::invalid(format!(
                "network {:?} is already the cluster's ingress network: there can be only one",
                other.network.spec.annotations.name
            )));
        }
    }
    let name = spec.annotations.name.clone();
    let created = state
        .backend()
        .create_network(crate::backend::model::CreateNetworkOptions { spec })
        .await?;
    tracing::info!(network = %created.id, name = %name, "network created");
    Ok((
        StatusCode::CREATED,
        Json(NetworkCreateResponse {
            id: created.id,
            warning: created.warning,
        }),
    )
        .into_response())
}

/// `DELETE /networks/{id}`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    state.backend().remove_network(&id).await?;
    tracing::info!(network = %id, "network removed");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /networks/{id}/connect`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn connect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, BackendError> {
    let body: NetworkConnectBody = json_body(&body)?;
    let options = convert::network_connect(body)?;
    tracing::info!(
        network = %id,
        container = %options.container,
        aliases = options.aliases.len(),
        "attaching a container to a network"
    );
    state.backend().connect_network(&id, options).await?;
    Ok(StatusCode::OK)
}

/// `POST /networks/{id}/disconnect`.
#[allow(clippy::needless_pass_by_value)]
pub(super) async fn disconnect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, BackendError> {
    let body: NetworkDisconnectBody = json_body(&body)?;
    let options = convert::network_disconnect(&body)?;
    tracing::info!(
        network = %id,
        container = %options.container,
        force = options.force,
        "detaching a container from a network"
    );
    state.backend().disconnect_network(&id, options).await?;
    Ok(StatusCode::OK)
}
