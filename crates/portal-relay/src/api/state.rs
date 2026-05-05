//! Per-surface state structs.
//!
//! Each axum router carries the minimum state it legitimately needs.
//! Cross-surface state escape is type-rejected: a handler on the
//! discovery router cannot accidentally reach the admin policy
//! mutators because its state struct doesn't carry the handle.
//!
//! Phase 5 B6 landed the initial type plumbing; subsequent batches
//! extend each struct alongside its consuming handlers — e.g.
//! [`AdminState::reload`] landed with the
//! `POST /v1/admin/config/reload` handler.

use std::sync::Arc;

use crate::policy::PolicyRuntime;
use crate::reload::ReloadHandle;
use crate::state::LeaseRegistry;

/// State carried by the SDK trust-boundary router. SDK handlers see
/// the lease registry (read + write) and the policy runtime (read).
#[derive(Clone)]
pub struct SdkState {
    /// Lease registry (read + write).
    pub leases: LeaseRegistry,
    /// Policy runtime (read-only from the SDK surface).
    pub policy: Arc<PolicyRuntime>,
}

/// State carried by the admin trust-boundary router.
///
/// Admin handlers see the lease registry (read-only), the policy
/// runtime (read + write — admin can ban/unban IPs, set BPS, etc),
/// and an optional [`ReloadHandle`] consumed by the config-surface
/// endpoints (per the field rustdoc on [`Self::reload`]).
#[derive(Clone)]
pub struct AdminState {
    /// Lease registry (read-only from the admin surface).
    pub leases: LeaseRegistry,
    /// Policy runtime (read + write).
    pub policy: Arc<PolicyRuntime>,
    /// Optional handle to the workspace's hot-reload primitive. Three
    /// admin handlers consume this field today; their behavior on the
    /// `None` path differs by intent:
    ///
    /// - `POST /v1/admin/config/reload` — `Some`: accept new
    ///   [`crate::config::RuntimeConfig`] JSON and swap via the
    ///   handle. `None`: return
    ///   [`crate::api::envelope::ApiErrorCode::FeatureUnavailable`]
    ///   (503).
    /// - `GET /v1/admin/config/current` — `Some`: return the live
    ///   runtime snapshot. `None`: 503 `FeatureUnavailable`.
    /// - `GET /v1/admin/policy/snapshot` — reads through
    ///   [`crate::policy::PolicyRuntime`] (which itself carries an
    ///   `Option<Arc<ReloadHandle>>`). `None`: returns 200 with
    ///   sentinel values rather than 503, because the policy
    ///   surface is observability-oriented.
    ///
    /// `GET /v1/admin/health` and `GET /v1/admin/lease/count` do
    /// NOT consult this field — health is stateless liveness and
    /// lease count reads from `AdminState.leases`, both
    /// independent of bundle load.
    pub reload: Option<Arc<ReloadHandle>>,
}

/// State carried by the discovery trust-boundary router. Discovery
/// handlers see only the lease registry's hostname index — no policy
/// mutation surface, no admin state.
#[derive(Clone)]
pub struct DiscoveryState {
    /// Lease registry (read-only, hostname-index queries only).
    pub leases: LeaseRegistry,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_are_cheaply_cloneable() {
        // Smoke test that the state types compile and clone without
        // owning anything heavy directly. This is the type-level
        // contract that subsequent handlers rely on.
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let _sdk = SdkState {
            leases: leases.clone(),
            policy: Arc::clone(&policy),
        };
        let _admin = AdminState {
            leases: leases.clone(),
            policy,
            reload: None,
        };
        let _disc = DiscoveryState { leases };
    }
}
