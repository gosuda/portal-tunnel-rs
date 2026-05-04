//! HTTPS API surfaces — admin / sdk / discovery axum routers.
//!
//! Phase 5 B6 lands the envelope shape, the typed `ApiError` enum,
//! and per-surface state types (`AdminState`, `SdkState`,
//! `DiscoveryState`). Three empty router constructors are exported
//! so the eventual server orchestrator (Phase 5 B9) can mount them
//! before the actual handlers land in subsequent batches.

pub mod envelope;
pub mod state;

pub use envelope::{
    ApiDataEnvelope, ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, ApiResult, ok,
};
pub use state::{AdminState, DiscoveryState, SdkState};

/// Build the SDK trust-boundary router. Phase 5 B6 returns an empty
/// router; Phase 5 B7 registers handlers under `/v1/sdk/*`.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
pub fn build_sdk_router(state: SdkState) -> axum::Router {
    axum::Router::new().with_state(state)
}

/// Build the admin trust-boundary router. Phase 5 B6 returns an
/// empty router; Phase 5 B8 registers handlers under `/v1/admin/*`
/// + `/metrics`.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
pub fn build_admin_router(state: AdminState) -> axum::Router {
    axum::Router::new().with_state(state)
}

/// Build the discovery trust-boundary router. Phase 5 B6 returns an
/// empty router; Phase 5 B8 registers handlers under `/v1/discovery`.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
pub fn build_discovery_router(state: DiscoveryState) -> axum::Router {
    axum::Router::new().with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyRuntime;
    use crate::state::LeaseRegistry;
    use std::sync::Arc;

    #[test]
    fn build_sdk_router_returns_router() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let _r = build_sdk_router(SdkState { leases, policy });
    }

    #[test]
    fn build_admin_router_returns_router() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let _r = build_admin_router(AdminState { leases, policy });
    }

    #[test]
    fn build_discovery_router_returns_router() {
        let leases = LeaseRegistry::new();
        let _r = build_discovery_router(DiscoveryState { leases });
    }
}
