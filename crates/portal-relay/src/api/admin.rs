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
#[tracing::instrument(name = "admin.reload", skip_all)]
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
#[tracing::instrument(name = "admin.config_current", skip_all)]
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

/// Wire body for `GET /v1/admin/health`. Carries the portal-relay
/// crate version so an operator can verify which build a given
/// listener is running.
///
/// Marked `#[non_exhaustive]` so future fields (commit SHA, build
/// timestamp, server lifecycle phase) can land without a breaking
/// change to the on-the-wire envelope shape.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct HealthBody {
    /// `CARGO_PKG_VERSION` of the running `portal-relay` crate —
    /// captured at compile time via `env!`. Operators use this to
    /// confirm a listener is on the version they intend.
    pub version: &'static str,
}

/// `GET /v1/admin/health` — stateless liveness endpoint.
///
/// Returns 200 OK whenever the router is mounted; carries the crate
/// version. Has no state dependency (does NOT require the
/// `AdminState.reload` handle), so a brand-new dev relay
/// (`Server::new()` with no bundle) is observable as alive
/// immediately. Trust boundary inherits from the module rustdoc.
///
/// # Errors
///
/// Infallible. Signature returns [`ApiResult`] for envelope
/// uniformity with the rest of the admin surface.
#[tracing::instrument(name = "admin.health")]
pub async fn health_handler() -> ApiResult<HealthBody> {
    Ok(ok(HealthBody {
        version: env!("CARGO_PKG_VERSION"),
    }))
}

/// Wire body for `GET /v1/admin/policy/snapshot`.
///
/// Carries the effective policy state derived from the attached
/// [`crate::policy::PolicyRuntime`]: the configured per-identity
/// BPS cap (`None` if open / no cap) and the operator-managed IP
/// ban-list size.
///
/// Marked `#[non_exhaustive]` so future fields (rate-limit hit
/// counts, dynamic-ban count, reputation-engine snapshot
/// counters) can land without breaking the wire shape.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct PolicySnapshotBody {
    /// Configured per-identity bytes-per-second cap from the
    /// reload-snapshot. `None` means no cap is configured (the
    /// runtime value is `0`, the documented sentinel for "open"),
    /// or no [`crate::reload::ReloadHandle`] is attached.
    pub bps_cap_per_identity: Option<u64>,
    /// Number of operator-managed IP bans in the most recent
    /// reload snapshot. Counts ONLY
    /// [`crate::config::RuntimeConfig::ip_ban_list`]; dynamic
    /// in-memory bans set via
    /// [`crate::policy::ip_filter::IpFilter::ban`] are NOT
    /// included (they have a separate observability path).
    pub ip_ban_count: usize,
}

/// `GET /v1/admin/policy/snapshot` — derived-policy observability.
///
/// Reads from the [`crate::policy::PolicyRuntime`] held by
/// [`AdminState`] (which itself reads from the optionally-attached
/// reload snapshot). Returns 200 OK with sentinel values
/// (`bps_cap_per_identity: None`, `ip_ban_count: 0`) when no
/// reload handle is attached — same surface contract as a brand-
/// new dev relay. Trust boundary inherits from the module rustdoc.
///
/// # Errors
///
/// Infallible. Signature returns [`ApiResult`] for envelope
/// uniformity with the rest of the admin surface.
#[tracing::instrument(name = "admin.policy_snapshot", skip_all)]
pub async fn policy_snapshot_handler(
    State(state): State<AdminState>,
) -> ApiResult<PolicySnapshotBody> {
    Ok(ok(PolicySnapshotBody {
        bps_cap_per_identity: state.policy.bps_cap_per_identity(),
        ip_ban_count: state.policy.ip_ban_count(),
    }))
}
