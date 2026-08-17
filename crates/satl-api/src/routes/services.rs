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
pub(super) async fn inspect(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, BackendError> {
    let service = state.backend().inspect_service(&id).await?;
    Ok(Json(render::service(&service.service, None)).into_response())
}

/// `POST /services/{id}/update?version=&rollback=`.
#[allow(clippy::needless_pass_by_value)]
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
pub(super) async fn remove(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, BackendError> {
    state.backend().remove_service(&id).await?;
    tracing::info!(service = %id, "service removed");
    Ok(StatusCode::OK)
}
