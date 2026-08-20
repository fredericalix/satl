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
#[utoipa::path(
    get,
    path = "/networks",
    operation_id = "NetworkList",
    tag = "Network",
    description = "`Scope` follows the driver, always: `overlay` is `swarm`, \
        `bridge` is `local` (api-compat #60). An overlay row carries an extra \
        `Vni`, the VXLAN network identifier the allocator assigned \
        (api-compat #62).",
    params(("filters" = Option<String>, Query, description = "A non-empty value is rejected with 501 rather than silently listing everything (api-compat #47).")),
    responses(
        (status = 200, description = "One row per network.", body = Vec<crate::types::NetworkResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?filters=` was non-empty, or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    get,
    path = "/networks/{id}",
    operation_id = "NetworkInspect",
    tag = "Network",
    description = "`IPAM.Config[0].Gateway` is **this node's** gateway on the \
        network, never a cluster-wide one: an overlay has one gateway per \
        participating node, so a shared address on one L2 segment would be a \
        duplicate address (api-compat #61, `docs/vxlan.md` section 8).",
    params(("id" = String, Path, description = "Network ID or name.")),
    responses(
        (status = 200, description = "The network document.", body = crate::types::NetworkResponse),
        (status = 404, description = "No such network.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/networks/create",
    operation_id = "NetworkCreate",
    tag = "Network",
    description = "A create whose `Scope` contradicts its `Driver` is a 400, \
        not a network with the other scope (api-compat #60). A cluster has \
        exactly one ingress network: the second request for one is a 400 \
        naming the existing one.",
    request_body = crate::types::NetworkCreateBody,
    responses(
        (status = 201, description = "Created.", body = crate::types::NetworkCreateResponse),
        (status = 400, description = "Invalid spec, contradictory scope, or a second ingress network.", body = crate::types::ErrorBody),
        (status = 409, description = "A network of that name already exists.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    delete,
    path = "/networks/{id}",
    operation_id = "NetworkDelete",
    tag = "Network",
    description = "Removes a network from the cluster store. A network is a \
        store object, so this is cluster-wide (api-compat #130).",
    params(("id" = String, Path, description = "Network ID or name.")),
    responses(
        (status = 204, description = "Removed."),
        (status = 404, description = "No such network.", body = crate::types::ErrorBody),
        (status = 409, description = "The network still has endpoints attached.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/networks/{id}/connect",
    operation_id = "NetworkConnect",
    tag = "Network",
    description = "Attaches a container to a network. Only \
        `EndpointConfig.Aliases` is honoured; static addressing is rejected \
        because the cluster allocator owns addresses.",
    params(("id" = String, Path, description = "Network ID or name.")),
    request_body = crate::types::NetworkConnectBody,
    responses(
        (status = 200, description = "Attached."),
        (status = 400, description = "Invalid body, or a field SatL refuses to ignore.", body = crate::types::ErrorBody),
        (status = 404, description = "No such network or container.", body = crate::types::ErrorBody),
        (status = 409, description = "The container is already attached.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
#[utoipa::path(
    post,
    path = "/networks/{id}/disconnect",
    operation_id = "NetworkDisconnect",
    tag = "Network",
    description = "Detaches a container from a network.",
    params(("id" = String, Path, description = "Network ID or name.")),
    request_body = crate::types::NetworkDisconnectBody,
    responses(
        (status = 200, description = "Detached."),
        (status = 400, description = "Invalid body.", body = crate::types::ErrorBody),
        (status = 404, description = "No such network or container.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
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
