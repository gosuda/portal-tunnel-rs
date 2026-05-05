//! Admin trust-boundary endpoint handlers.
//!
//! `POST /v1/admin/config/reload` is the operator HTTP trigger for
//! hot-reload of [`crate::config::RuntimeConfig`]. Complements the
//! `cfg(feature = "config_file_watch")` filesystem-write trigger
//! (`reload::file_watch::watch_runtime_config`, iter-126) —
//! operators may use either.
//!
//! ## Trust boundary
//!
//! The admin router is a trust boundary at the LISTENER level (mTLS
//! / unix socket / loopback-only per the threat model); handlers
//! here do NOT enforce per-request authentication. Mounting the
//! router on a network-exposed listener without listener-level
//! gating is a deployment misconfiguration.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use serde::Serialize;

use crate::api::envelope::{ApiError, ApiErrorCode, ApiResult, ok};
use crate::api::state::AdminState;
use crate::config::RuntimeConfig;

/// Response body for a successful reload.
///
/// `accepted: true` is the only contract today; future fields may
/// surface diff'd field names or validation warnings.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ReloadAcceptedBody {
    /// Always `true` on a 200 response.
    pub accepted: bool,
}

/// `POST /v1/admin/config/reload` handler.
///
/// Accepts a JSON [`RuntimeConfig`] body (per iter-124's
/// `default + deny_unknown_fields` policy: missing fields default-
/// fill, unknown fields reject). Calls
/// [`crate::reload::ReloadHandle::reload`] with the new runtime AND
/// the handle's existing bootstrap. Returns `200 OK` with
/// [`ReloadAcceptedBody`] on success.
///
/// ## Hoare invariant — trust-boundary mutation cannot fire here
///
/// The handler always passes `handle.bootstrap()` as the
/// `bootstrap_candidate`, so the bootstrap diff inside
/// [`crate::reload::ReloadHandle::reload`] is always empty —
/// [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`]
/// is unreachable through this endpoint. Trust-boundary key
/// rotation remains a process-restart-only operation per R-S5-4.
///
/// # Errors
///
/// - [`ApiErrorCode::FeatureUnavailable`] (503) — `AdminState.reload`
///   is `None` (operator built without an attached reload handle).
/// - [`ApiErrorCode::InvalidRequest`] (400) — JSON deserialize
///   failed (bad shape, unknown field, malformed JSON).
/// - [`ApiErrorCode::Internal`] (500) — the underlying reload
///   returned an error. Unreachable in practice given the Hoare
///   invariant above; the path exists for completeness.
pub async fn reload_handler(
    State(state): State<AdminState>,
    body: Result<Json<RuntimeConfig>, JsonRejection>,
) -> ApiResult<ReloadAcceptedBody> {
    let Json(new_runtime) = body.map_err(|err| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            format!("config reload body: {err}"),
        )
    })?;

    let handle = state.reload.as_ref().ok_or_else(|| {
        ApiError::new(
            ApiErrorCode::FeatureUnavailable,
            "hot-reload not configured (no ReloadHandle attached)",
        )
    })?;

    let bootstrap = handle.bootstrap();
    handle
        .reload(&bootstrap, new_runtime)
        .map_err(|err| ApiError::new(ApiErrorCode::Internal, format!("reload rejected: {err}")))?;

    Ok(ok(ReloadAcceptedBody { accepted: true }))
}

/// `GET /v1/admin/config/current` — return the live [`RuntimeConfig`]
/// snapshot from the attached [`crate::reload::ReloadHandle`].
///
/// Reads `handle.current()` (cheap `Arc<RuntimeConfig>` load via
/// `arc_swap`); the clone copies a small struct, kept inside the
/// handler so the wire shape is owned [`RuntimeConfig`] rather than
/// `Arc<RuntimeConfig>` for serde simplicity. [`RuntimeConfig`] is
/// `#[non_exhaustive]`, so returning it directly via the envelope is
/// forward-compat — no wrapper body type needed.
///
/// # Errors
///
/// - [`ApiErrorCode::FeatureUnavailable`] (503) — `AdminState.reload`
///   is `None` (operator built without an attached reload handle).
pub async fn get_current_config_handler(
    State(state): State<AdminState>,
) -> ApiResult<RuntimeConfig> {
    let handle = state.reload.as_ref().ok_or_else(|| {
        ApiError::new(
            ApiErrorCode::FeatureUnavailable,
            "reload handle not attached; bootstrap.json + runtime.json not loaded",
        )
    })?;
    Ok(ok((*handle.current()).clone()))
}
