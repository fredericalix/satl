// SPDX-License-Identifier: BSD-2-Clause
//! Prune endpoints: `POST /containers/prune`, `/images/prune`,
//! `/networks/prune`, `/volumes/prune`.
//!
//! Four endpoints because that is what Docker has and what `docker system
//! prune` drives, in this order; `satl system prune` drives the same four.
//! Deviations are recorded in `docs/api-compat.md` 129-136. The two that matter
//! most here:
//!
//! - **Only `dangling` is understood as a filter**, and only on
//!   `/images/prune`, because it is how `-a` reaches the daemon
//!   (`filters={"dangling":["false"]}`). Any other filter is a `400` rather
//!   than a silent no-op: `until=` or `label=` accepted-and-ignored would
//!   delete more than the operator asked for.
//! - **Images, layers and volumes are node-local.** These endpoints reclaim
//!   what *this* daemon holds. Containers and networks are cluster objects and
//!   are pruned cluster-wide, the same asymmetry `satl rm` and `satl volume rm`
//!   already have.

use axum::Json;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};

use super::{Params, param};
use crate::backend::model::BackendError;
use crate::render;
use crate::state::ApiState;

/// `POST /containers/prune?filters=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/containers/prune",
    operation_id = "ContainerPrune",
    tag = "Container",
    description = "Removes stopped containers **cluster-wide**, and with each \
        one the service backing it, exactly as `DELETE /containers/{id}` does \
        (api-compat #33, #129). `SpaceReclaimed` is measured before removal \
        and can be short of the truth: a rootfs cannot be destroyed while its \
        jail is still dying (api-compat #136). Any filter at all is a 400 \
        rather than a silent no-op (api-compat #134).",
    params(("filters" = Option<String>, Query, description = "No filter is supported here; a non-empty value is a 400 (api-compat #134).")),
    responses(
        (status = 200, description = "What was removed and how much was reclaimed.", body = crate::types::ContainersPruneResponse),
        (status = 400, description = "A filter was supplied.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn containers(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, &[])?;
    let pruned = state.backend().prune_containers().await?;
    tracing::info!(
        containers = pruned.deleted.len(),
        space_reclaimed = pruned.space_reclaimed,
        "stopped containers pruned"
    );
    Ok(Json(render::pruned_containers(&pruned)).into_response())
}

/// `POST /images/prune?filters=`.
///
/// `filters={"dangling":["false"]}` is Docker's wire form of `-a`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/images/prune",
    operation_id = "ImagePrune",
    tag = "Image",
    description = "Reclaims images, layers and blobs on **this node only** \
        (api-compat #130). A layer dataset is destroyed only when two \
        consecutive passes 1.5 s apart agree it is unreferenced; what the \
        sweep deferred comes back in a `Deferred` array Docker has no \
        equivalent for (api-compat #131). A pull in flight stops content \
        reclamation for that pass and says so (api-compat #133).",
    params(("filters" = Option<String>, Query, description = "Only `dangling` is understood -- `filters={\"dangling\":[\"false\"]}` is how `-a` reaches the daemon, in either of Docker's two encodings. Any other key is a 400 (api-compat #134).")),
    responses(
        (status = 200, description = "What was deleted, what was deferred and how much was reclaimed.", body = crate::types::ImagesPruneResponse),
        (status = 400, description = "An unsupported filter, or a nonsense `dangling` value.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn images(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    let all = !dangling_only(&params)?;
    let pruned = state.backend().prune_images(all).await?;
    tracing::info!(
        all,
        items = pruned.deleted.len(),
        deferred = pruned.deferred.len(),
        space_reclaimed = pruned.space_reclaimed,
        "images and layers pruned on this node"
    );
    Ok(Json(render::pruned_images(&pruned)).into_response())
}

/// `POST /networks/prune?filters=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/networks/prune",
    operation_id = "NetworkPrune",
    tag = "Network",
    description = "Removes unused networks **cluster-wide**: a network is a \
        store object (api-compat #130). Any filter at all is a 400 rather \
        than a silent no-op (api-compat #134).",
    params(("filters" = Option<String>, Query, description = "No filter is supported here; a non-empty value is a 400 (api-compat #134).")),
    responses(
        (status = 200, description = "What was removed.", body = crate::types::NetworksPruneResponse),
        (status = 400, description = "A filter was supplied.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn networks(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, &[])?;
    let pruned = state.backend().prune_networks().await?;
    tracing::info!(networks = pruned.deleted.len(), "unused networks pruned");
    Ok(Json(render::pruned_networks(&pruned)).into_response())
}

/// `POST /volumes/prune?filters=`.
#[allow(clippy::needless_pass_by_value)]
#[utoipa::path(
    post,
    path = "/volumes/prune",
    operation_id = "VolumePrune",
    tag = "Volume",
    description = "Removes unused volumes on **this node only**: a volume is \
        a ZFS dataset on whichever node holds it (api-compat #130). Any \
        filter at all is a 400 rather than a silent no-op (api-compat #134).",
    params(("filters" = Option<String>, Query, description = "No filter is supported here; a non-empty value is a 400 (api-compat #134).")),
    responses(
        (status = 200, description = "What was removed and how much was reclaimed.", body = crate::types::VolumesPruneResponse),
        (status = 400, description = "A filter was supplied.", body = crate::types::ErrorBody),
        (status = 500, description = "Daemon error.", body = crate::types::ErrorBody),
        (status = 501, description = "Not implemented by this daemon.", body = crate::types::ErrorBody),
        (status = 503, description = "This node is not a swarm manager, or no manager is reachable.", body = crate::types::ErrorBody)
    )
)]
pub(super) async fn volumes(
    State(state): State<ApiState>,
    Query(params): Query<Params>,
) -> Result<Response, BackendError> {
    reject_filters(&params, &[])?;
    let pruned = state.backend().prune_volumes().await?;
    tracing::info!(
        volumes = pruned.deleted.len(),
        space_reclaimed = pruned.space_reclaimed,
        "unused volumes pruned on this node"
    );
    Ok(Json(render::pruned_volumes(&pruned)).into_response())
}

/// Whether the caller wants dangling content only (no `-a`).
///
/// Docker's `-a` is `filters={"dangling":["false"]}`; no filter at all means
/// dangling only. Both of Docker's encodings of a filter map are accepted
/// (`{"k":["v"]}` and `{"k":{"v":true}}`) because both are on the wire.
fn dangling_only(params: &Params) -> Result<bool, BackendError> {
    let values = reject_filters(params, &["dangling"])?;
    match values.first().map(String::as_str) {
        // No filter at all and an explicit `dangling=true` mean the same thing.
        None | Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(other) => Err(BackendError::invalid(format!(
            "invalid filter 'dangling={other}': expected true or false"
        ))),
    }
}

/// Parse `filters` and refuse every key not in `allowed`, returning the values
/// of the (single) allowed key.
///
/// Refusing is the point. Docker's `until=` and `label=` change *what gets
/// deleted*, so accepting them and ignoring them would delete more than the
/// caller asked for — the one class of compatibility shortcut that cannot be
/// taken with a command whose whole job is destroying things.
fn reject_filters(params: &Params, allowed: &[&str]) -> Result<Vec<String>, BackendError> {
    let Some(raw) = param(params, "filters") else {
        return Ok(Vec::new());
    };
    let parsed: serde_json::Value = serde_json::from_str(raw)
        .map_err(|source| BackendError::invalid(format!("invalid filters JSON: {source}")))?;
    let Some(map) = parsed.as_object() else {
        return Err(BackendError::invalid(
            "invalid filters: expected a JSON object",
        ));
    };
    let mut values = Vec::new();
    for (key, value) in map {
        if !allowed.contains(&key.as_str()) {
            return Err(BackendError::invalid(format!(
                "prune filter {key:?} is not supported by SatL (see docs/api-compat.md); \
                 supported here: {}",
                if allowed.is_empty() {
                    "none".to_owned()
                } else {
                    allowed.join(", ")
                }
            )));
        }
        values.extend(filter_values(value));
    }
    Ok(values)
}

/// The values of one filter entry, in either Docker encoding.
fn filter_values(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        // `{"true": true}` — the map encoding; only the enabled keys count.
        serde_json::Value::Object(map) => map
            .iter()
            .filter(|(_, on)| on.as_bool().unwrap_or(false))
            .map(|(key, _)| key.clone())
            .collect(),
        serde_json::Value::String(text) => vec![text.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(filters: &str) -> Params {
        let mut map = Params::new();
        map.insert("filters".to_owned(), filters.to_owned());
        map
    }

    #[test]
    fn no_filter_means_dangling_only() {
        assert!(dangling_only(&Params::new()).expect("no filters"));
    }

    /// The two encodings the docker CLI actually puts on the wire for `-a`.
    #[test]
    fn dangling_false_in_either_encoding_means_all() {
        assert!(!dangling_only(&params(r#"{"dangling":["false"]}"#)).expect("array form"));
        assert!(!dangling_only(&params(r#"{"dangling":{"false":true}}"#)).expect("map form"));
    }

    #[test]
    fn dangling_true_means_dangling_only() {
        assert!(dangling_only(&params(r#"{"dangling":["true"]}"#)).expect("array form"));
    }

    /// A filter that would change what gets deleted must be refused, not
    /// ignored.
    #[test]
    fn an_unsupported_filter_is_a_400_rather_than_a_silent_no_op() {
        for filters in [
            r#"{"until":["24h"]}"#,
            r#"{"label":["keep=yes"]}"#,
            r#"{"dangling":["false"],"until":["24h"]}"#,
        ] {
            let err = dangling_only(&params(filters)).expect_err(filters);
            assert!(
                matches!(err, BackendError::InvalidParameter(_)),
                "{filters}: {err}"
            );
        }
    }

    #[test]
    fn container_and_network_prune_take_no_filters_at_all() {
        assert!(reject_filters(&Params::new(), &[]).is_ok());
        let err = reject_filters(&params(r#"{"until":["1h"]}"#), &[]).expect_err("until");
        assert!(err.to_string().contains("none"), "{err}");
    }

    #[test]
    fn malformed_filters_json_is_rejected_with_its_reason() {
        let err = reject_filters(&params("not json"), &[]).expect_err("garbage");
        assert!(err.to_string().contains("invalid filters JSON"), "{err}");
        let err = reject_filters(&params("[1,2]"), &[]).expect_err("not an object");
        assert!(err.to_string().contains("expected a JSON object"), "{err}");
    }

    #[test]
    fn a_nonsense_dangling_value_is_rejected() {
        let err = dangling_only(&params(r#"{"dangling":["maybe"]}"#)).expect_err("maybe");
        assert!(err.to_string().contains("expected true or false"), "{err}");
    }
}
