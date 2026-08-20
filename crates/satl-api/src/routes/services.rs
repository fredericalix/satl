// SPDX-License-Identifier: BSD-2-Clause
//! Service endpoints: create, list, inspect, update and remove.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;

use super::{Params, flag, json_body, param, registry_auth, reject_filters};
use crate::backend::model::{
    BackendError, ServiceCreateOptions, ServiceTaskCounts, ServiceUpdateOptions,
};
use crate::convert::cluster as convert;
use crate::render::cluster as render;
use crate::state::ApiState;
use crate::types::{ServiceCreateResponse, ServiceSpecWire, ServiceUpdateResponse};

/// `POST /services/create`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/services/create",
    operation_id = "ServiceCreate",
    tag = "Service",
    description = "An empty `Spec.Name` is accepted and a name generated, \
        mirroring `POST /containers/create` without `?name=` (api-compat \
        #49). Spec fields SatL cannot honour are rejected with 400 rather \
        than silently dropped (api-compat #50), and `EndpointSpec.Mode: \
        \"vip\"` is one of them: service discovery is DNS round-robin, there \
        is no IPVS on FreeBSD (api-compat #52). Publishing a port without a \
        healthcheck is a warning in the response, not an error (api-compat \
        #128).",
    params(("X-Registry-Auth" = Option<String>, Header, description = "base64url or standard-base64 `AuthConfig` document, used when the tasks pull the image (api-compat #16).")),
    request_body = crate::types::ServiceSpecWire,
    responses(
        (status = 201, description = "Created, with any admission warnings.", body = crate::types::ServiceCreateResponse),
        (status = 400, description = "Invalid spec, or a field SatL refuses to drop silently (api-compat #50).", body = crate::types::ErrorBody),
        (status = 409, description = "A service of that name already exists.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn create(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BackendError> {
    let body: ServiceSpecWire = json_body(&body)?;
    let spec = convert::service_spec(body)?;
    let name = spec.annotations.name.clone();
    let created = state
        .backend()
        .create_service(ServiceCreateOptions {
            spec,
            registry_auth: registry_auth(&headers)?,
        })
        .await?;
    tracing::info!(service = %created.id, name = %name, "service created");
    Ok((
        StatusCode::CREATED,
        Json(ServiceCreateResponse {
            id: created.id,
            warnings: (!created.warnings.is_empty()).then_some(created.warnings),
        }),
    )
        .into_response())
}

/// `GET /services?status=`.
///
/// `ServiceStatus` (the replica counts) is only attached when the client asks
/// for it, exactly as Docker does since v1.41.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/services",
    operation_id = "ServiceList",
    tag = "Service",
    description = "`ServiceStatus` (the replica counts) is attached only when \
        the client asks for it, exactly as Docker does since v1.41. \
        `Endpoint.VirtualIPs` is always empty: DNS round-robin only \
        (api-compat #52).",
    params(
        ("filters" = Option<String>, Query, description = "A non-empty value is rejected with 501 rather than silently listing everything (api-compat #47)."),
        ("status" = Option<String>, Query, description = "Attach `ServiceStatus` to each row. Docker `BoolValue` semantics.")
    ),
    responses(
        (status = 200, description = "One row per service.", body = Vec<crate::types::ServiceResponse>),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "`?filters=` was non-empty, or the daemon has no store wired.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn list(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, "services")?;
    let with_status = flag(&params, "status");
    let services = state.backend().list_services().await?;
    let body: Vec<_> = services
        .iter()
        .map(|summary| {
            let counts: Option<ServiceTaskCounts> = with_status.then_some(summary.tasks);
            render::service(&summary.service, counts)
        })
        .collect();
    Ok(Json(body).into_response())
}

/// `GET /services/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    get,
    path = "/services/{id}",
    operation_id = "ServiceInspect",
    tag = "Service",
    description = "One service, without the replica counts (`GET /services` \
        with `?status=1` is where those live).",
    params(("id" = String, Path, description = "Service ID or name.")),
    responses(
        (status = 200, description = "The service document.", body = crate::types::ServiceResponse),
        (status = 404, description = "No such service.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let service = state.backend().inspect_service(&id).await?;
    Ok(Json(render::service(&service.service, None)).into_response())
}

/// `POST /services/{id}/update?version=&rollback=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/services/{id}/update",
    operation_id = "ServiceUpdate",
    tag = "Service",
    description = "A missing or unparsable `?version=` is a 400 before the \
        backend is called, and `?rollback=` accepts only `previous` \
        (api-compat #54). A resources-only update is a hot resize rather than \
        a roll: the tasks are not replaced (api-compat #147).",
    params(
        ("id" = String, Path, description = "Service ID or name."),
        ("version" = Option<String>, Query, description = "The object version being updated. Required: a missing or unparsable value is a 400 (api-compat #54)."),
        ("rollback" = Option<String>, Query, description = "`previous` is the only supported value; anything else is a 400 (api-compat #54)."),
        ("X-Registry-Auth" = Option<String>, Header, description = "base64url or standard-base64 `AuthConfig` document, used when the tasks pull the image (api-compat #16).")
    ),
    request_body = crate::types::ServiceSpecWire,
    responses(
        (status = 200, description = "Updated, with any admission warnings.", body = crate::types::ServiceUpdateResponse),
        (status = 400, description = "Missing or unparsable `?version=`, an unsupported `?rollback=`, or an invalid spec.", body = crate::types::ErrorBody),
        (status = 404, description = "No such service.", body = crate::types::ErrorBody),
        (status = 409, description = "The stored object version has moved on.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn update(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<Params>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, BackendError> {
    let version = convert::object_version(param(&params, "version"))?;
    let rollback = match param(&params, "rollback") {
        None | Some("") => false,
        Some("previous") => true,
        Some(other) => {
            return Err(BackendError::invalid(format!(
                "invalid rollback {other:?}: the only supported value is \"previous\""
            )));
        }
    };
    let body: ServiceSpecWire = json_body(&body)?;
    let spec = convert::service_spec(body)?;
    let warnings = state
        .backend()
        .update_service(
            &id,
            version,
            ServiceUpdateOptions {
                spec,
                rollback,
                registry_auth: registry_auth(&headers)?,
            },
        )
        .await?;
    tracing::info!(service = %id, rollback, "service updated");
    Ok(Json(ServiceUpdateResponse {
        warnings: (!warnings.is_empty()).then_some(warnings),
    })
    .into_response())
}

/// `DELETE /services/{id}`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    delete,
    path = "/services/{id}",
    operation_id = "ServiceDelete",
    tag = "Service",
    description = "Removes a service and, with it, its tasks.",
    params(("id" = String, Path, description = "Service ID or name.")),
    responses(
        (status = 200, description = "Removed."),
        (status = 404, description = "No such service.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    state.backend().remove_service(&id).await?;
    tracing::info!(service = %id, "service removed");
    Ok(StatusCode::OK)
}
