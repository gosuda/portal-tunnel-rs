//! Admin trust-boundary endpoint handlers.
//!
//! ## Endpoints
//!
//! - `POST /v1/admin/config/reload` — hot-reload trigger for
//!   [`crate::config::RuntimeConfig`]; complements the
//!   `cfg(feature = "config_file_watch")` filesystem-write trigger
//!   (`reload::file_watch::watch_runtime_config`).
//! - `GET /v1/admin/config/current` — read the current runtime
//!   snapshot (file + env overlay) from the attached
//!   [`crate::reload::ReloadHandle`]; 503 when no handle attached.
//! - `GET /v1/admin/health` — stateless liveness; returns 200 with
//!   the crate version regardless of handle attachment.
//! - `GET /v1/admin/policy/snapshot` — derived effective policy
//!   state from [`crate::policy::PolicyRuntime`] (BPS cap +
//!   operator-managed IP ban count); 200 always, sentinel values
//!   when no handle attached.
//! - `GET /v1/admin/lease/count` — active-lease count from
//!   [`AdminState::leases`]; 200 always, count from a lock-free
//!   read of the registry.
//!
//! Each handler carries a `#[tracing::instrument(name = "admin.…")]`
//! span so operators can correlate admin requests with relay log
//! entries when debugging 503/400 paths.
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
use crate::tui::{Lifecycle, StatusSnapshot};

/// Response body for a successful reload. `accepted: true` is the
/// only field on a 200 response.
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ReloadAcceptedBody {
    /// Always `true` on a 200 response.
    pub accepted: bool,
}

/// `POST /v1/admin/config/reload` handler.
///
/// Accepts a JSON [`RuntimeConfig`] body (per the
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
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
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
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
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

/// Wire body for `GET /v1/admin/lease/count`.
///
/// Carries the active-lease count from the [`AdminState`]'s lease
/// registry. Operator value: monitor lease accumulation (potential
/// leak) or zero (operator misconfiguration).
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates so a future field addition does not
/// break the Rust API. It does NOT guarantee JSON-wire
/// compatibility for strict clients — adding a field still
/// surfaces a new key on the wire, which a `deny_unknown_fields`-
/// equivalent strict-decoder client would reject.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct LeaseCountBody {
    /// Active lease count from the registry's lock-free read.
    pub count: usize,
}

/// `GET /v1/admin/lease/count` — operator-facing lease count.
///
/// Reads from the [`AdminState`]'s lease registry via
/// [`crate::state::LeaseRegistry::lease_count`] (lock-free read).
/// Returns 200 OK with the current count regardless of reload-handle
/// attachment — the lease registry is independent of the runtime
/// config surface. Trust boundary inherits from the module rustdoc.
///
/// # Errors
///
/// Infallible. Signature returns [`ApiResult`] for envelope
/// uniformity with the rest of the admin surface.
#[tracing::instrument(name = "admin.lease_count", skip_all)]
pub async fn lease_count_handler(State(state): State<AdminState>) -> ApiResult<LeaseCountBody> {
    Ok(ok(LeaseCountBody {
        count: state.leases.lease_count(),
    }))
}

/// Wire body for `GET /v1/admin/status`. Mirrors
/// [`crate::tui::StatusSnapshot`] for serde.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct StatusBody {
    /// Lifecycle state.
    pub lifecycle: LifecycleBody,
    /// Recent events.
    pub recent_events: Vec<String>,
    /// Active lease count.
    pub lease_count: usize,
    /// Identity health summary.
    pub identity_health: IdentityHealthBody,
    /// Aggregate BPS.
    pub bps: BpsBody,
}

/// Tagged lifecycle body preserving structured fields.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct LifecycleBody {
    /// Discriminant label: `Stopped`, `Running`, `Stopping`, `Errored`.
    pub phase: String,
    /// Uptime when `phase == "Running"`, else `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Error message when `phase == "Errored"`, else `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Identity health summary for the status wire body.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct IdentityHealthBody {
    /// Approved identities.
    pub approved: usize,
    /// Identities awaiting approval.
    pub pending: usize,
    /// Denied identities.
    pub denied: usize,
    /// Banned identities.
    pub banned: usize,
}

/// Aggregate BPS for the status wire body.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct BpsBody {
    /// Inbound bytes per second.
    pub inbound: u64,
    /// Outbound bytes per second.
    pub outbound: u64,
}

impl From<StatusSnapshot> for StatusBody {
    fn from(snapshot: StatusSnapshot) -> Self {
        let (phase, uptime_secs, error) = match snapshot.lifecycle {
            Lifecycle::Stopped => ("Stopped".to_owned(), None, None),
            Lifecycle::Running { uptime } => ("Running".to_owned(), Some(uptime.as_secs()), None),
            Lifecycle::Stopping => ("Stopping".to_owned(), None, None),
            Lifecycle::Errored(ref msg) => ("Errored".to_owned(), None, Some(msg.clone())),
        };
        Self {
            lifecycle: LifecycleBody {
                phase,
                uptime_secs,
                error,
            },
            recent_events: snapshot
                .recent_events
                .iter()
                .map(|event| match event {
                    crate::tui::RecentEvent::Error(msg) => format!("error: {msg}"),
                    crate::tui::RecentEvent::Denial(msg) => format!("denial: {msg}"),
                    crate::tui::RecentEvent::Throttle(msg) => format!("throttle: {msg}"),
                })
                .collect(),
            lease_count: snapshot.lease_count,
            identity_health: IdentityHealthBody {
                approved: snapshot.identity_health.approved,
                pending: snapshot.identity_health.pending,
                denied: snapshot.identity_health.denied,
                banned: snapshot.identity_health.banned,
            },
            bps: BpsBody {
                inbound: snapshot.bps.inbound,
                outbound: snapshot.bps.outbound,
            },
        }
    }
}

/// `GET /v1/admin/status` — live status snapshot.
///
/// Reads from the [`AdminState`]'s optional status receiver.
/// Returns 200 OK with the current [`StatusSnapshot`] values,
/// or the default snapshot when no status publisher is active.
///
/// # Errors
///
/// Infallible. Signature returns [`ApiResult`] for envelope
/// uniformity with the rest of the admin surface.
#[tracing::instrument(name = "admin.status", skip_all)]
pub async fn status_handler(State(state): State<AdminState>) -> ApiResult<StatusBody> {
    let snapshot = state
        .status
        .as_ref()
        .map(|rx| rx.borrow().clone())
        .unwrap_or_default();
    Ok(ok(snapshot.into()))
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use crate::api::state::AdminState;
    use crate::policy::PolicyRuntime;
    use crate::state::LeaseRegistry;
    use crate::tui::StatusSnapshot;
    use axum::extract::State;
    use std::sync::Arc;

    #[tokio::test]
    async fn status_returns_snapshot() {
        let server = crate::server::Server::new();
        let state = server.admin_state();
        let resp = status_handler(State(state)).await;
        assert!(resp.is_ok());
        let body = resp.unwrap().data.clone();
        assert_eq!(body.lease_count, 0);
    }

    #[tokio::test]
    async fn status_running_includes_uptime() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let (tx, rx) = tokio::sync::watch::channel(StatusSnapshot {
            lifecycle: crate::tui::Lifecycle::Running {
                uptime: std::time::Duration::from_secs(42),
            },
            recent_events: Vec::new(),
            lease_count: 3,
            identity_health: crate::tui::IdentityHealth {
                approved: 1,
                pending: 2,
                denied: 3,
                banned: 4,
            },
            bps: crate::tui::BpsAggregate {
                inbound: 100,
                outbound: 200,
            },
        });
        // Keep tx alive so rx can borrow.
        let _tx = tx;
        let state = AdminState {
            leases,
            policy,
            reload: None,
            status: Some(rx),
        };
        let resp = status_handler(State(state)).await;
        assert!(resp.is_ok());
        let body = resp.unwrap().data.clone();
        assert_eq!(body.lifecycle.phase, "Running");
        assert_eq!(body.lifecycle.uptime_secs, Some(42));
        assert_eq!(body.lease_count, 3);
        assert_eq!(body.identity_health.approved, 1);
        assert_eq!(body.identity_health.pending, 2);
        assert_eq!(body.identity_health.denied, 3);
        assert_eq!(body.identity_health.banned, 4);
        assert_eq!(body.bps.inbound, 100);
        assert_eq!(body.bps.outbound, 200);
    }

    #[tokio::test]
    async fn status_errored_includes_message() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let (tx, rx) = tokio::sync::watch::channel(StatusSnapshot {
            lifecycle: crate::tui::Lifecycle::Errored("disk full".to_owned()),
            recent_events: Vec::new(),
            lease_count: 0,
            identity_health: crate::tui::IdentityHealth::default(),
            bps: crate::tui::BpsAggregate::default(),
        });
        let _tx = tx;
        let state = AdminState {
            leases,
            policy,
            reload: None,
            status: Some(rx),
        };
        let resp = status_handler(State(state)).await;
        assert!(resp.is_ok());
        let body = resp.unwrap().data.clone();
        assert_eq!(body.lifecycle.phase, "Errored");
        assert_eq!(body.lifecycle.error, Some("disk full".to_owned()));
        assert_eq!(body.lifecycle.uptime_secs, None);
    }

    #[tokio::test]
    async fn status_no_receiver_returns_default() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let state = AdminState {
            leases,
            policy,
            reload: None,
            status: None,
        };
        let resp = status_handler(State(state)).await;
        assert!(resp.is_ok());
        let body = resp.unwrap().data.clone();
        assert_eq!(body.lifecycle.phase, "Stopped");
        assert_eq!(body.lease_count, 0);
    }
}
