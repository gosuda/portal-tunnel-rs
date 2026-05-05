//! HTTPS API surfaces — admin / sdk / discovery axum routers.
//!
//! Phase 5 lands the envelope shape, the typed `ApiError` enum, and
//! per-surface state types (`AdminState`, `SdkState`,
//! `DiscoveryState`) plus three empty router constructors so the
//! server orchestrator can mount them. The actual handlers register
//! in follow-up commits. See this crate's `lib.rs` for current
//! Phase 5 status.

pub mod admin;
pub mod envelope;
pub mod state;

pub use envelope::{
    ApiDataEnvelope, ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, ApiResult, ok,
};
pub use state::{AdminState, DiscoveryState, SdkState};

/// Build the SDK trust-boundary router. Returns an empty router
/// today; handlers register under `/v1/sdk/*` in a follow-up commit.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
pub fn build_sdk_router(state: SdkState) -> axum::Router {
    axum::Router::new().with_state(state)
}

/// Build the admin trust-boundary router. Mounts
/// `POST /v1/admin/config/reload` (iter-135). Additional `/v1/admin/*`
/// + `/metrics` handlers register in follow-up commits.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "Phase 7 U8.8 utoipa coverage gate names \
              `utoipa_axum::OpenApiRouter::route` for library-crate route \
              registration. The admin surface has no `ApiDoc::openapi()` \
              aggregator wired in the workspace yet; iter-135 lands the \
              FIRST admin endpoint (`POST /v1/admin/config/reload`) under \
              the same carve-out shape as the keyless oracle. The \
              utoipa-axum migration is a single Phase 7 follow-up that \
              switches every admin handler in one diff once the aggregator \
              lands — adopting utoipa-axum here for one route would \
              fragment the migration. Recorded as a follow-up gap; \
              reachable only via the admin trust-boundary listener."
)]
pub fn build_admin_router(state: AdminState) -> axum::Router {
    use axum::routing::post;
    // Bound-to-var rebind shape per `docs/utoipa-coverage-policy.md`
    // §Enforcement note 2: this is the documented escape from the
    // ast-grep belt-and-suspenders gate, which only matches the
    // chained-builder shape `Router::new().route(...)`. Clippy's
    // `disallowed_methods` still resolves the `r.route(...)` call by
    // DefId — that is the load-bearing primary gate, and the
    // `#[expect(clippy::disallowed_methods, ...)]` above carries the
    // Phase 7 U8.8 carve-out justification.
    let r = axum::Router::new();
    let r = r.route("/v1/admin/config/reload", post(admin::reload_handler));
    r.with_state(state)
}

/// Build the discovery trust-boundary router. Returns an empty
/// router today; handlers register under `/v1/discovery` in a
/// follow-up commit.
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
        let _r = build_admin_router(AdminState {
            leases,
            policy,
            reload: None,
        });
    }

    #[test]
    fn build_discovery_router_returns_router() {
        let leases = LeaseRegistry::new();
        let _r = build_discovery_router(DiscoveryState { leases });
    }
}
