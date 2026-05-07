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
pub mod sdk;
pub mod state;

pub use envelope::{
    ApiDataEnvelope, ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope, ApiResult, ok,
};
pub use state::{AdminState, DiscoveryState, SdkState};

/// Build the SDK trust-boundary router.
///
/// Mounts the [`sdk`] handlers landed so far — `GET /v1/sdk/domain`,
/// `POST /v1/sdk/register-challenge`, `POST /v1/sdk/register`,
/// `POST /v1/sdk/renew`, `POST /v1/sdk/unregister`, and
/// `POST /v1/sdk/connect`. See the [`sdk`] module rustdoc for the
/// per-endpoint contracts (auth posture, CORS, etc.).
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
              registration. The SDK surface has no `ApiDoc::openapi()` \
              aggregator wired in the workspace yet; the SDK handlers \
              register through `axum::Router::route` under the same \
              carve-out shape as the admin router and the keyless \
              oracle. The utoipa-axum migration is a single Phase 7 \
              follow-up that switches every handler in one diff once \
              the aggregator lands — adopting utoipa-axum here per \
              route would fragment the migration. Recorded as a \
              follow-up gap."
)]
pub fn build_sdk_router(state: SdkState) -> axum::Router {
    use axum::routing::{get, post};
    // Bound-to-var rebind shape per `docs/utoipa-coverage-policy.md`
    // §Enforcement note 2: this is the documented escape from the
    // ast-grep belt-and-suspenders gate, which only matches the
    // chained-builder shape `Router::new().route(...)`. Clippy's
    // `disallowed_methods` still resolves the `r.route(...)` call by
    // DefId — that is the load-bearing primary gate, and the
    // `#[expect(clippy::disallowed_methods, ...)]` above carries the
    // Phase 7 U8.8 carve-out justification.
    let r = axum::Router::new();
    let r = r.route("/v1/sdk/domain", get(sdk::domain_handler));
    let r = r.route(
        "/v1/sdk/register-challenge",
        post(sdk::register_challenge_handler),
    );
    let r = r.route("/v1/sdk/register", post(sdk::register_handler));
    let r = r.route("/v1/sdk/renew", post(sdk::renew_handler));
    let r = r.route("/v1/sdk/unregister", post(sdk::unregister_handler));
    let r = r.route("/v1/sdk/connect", post(sdk::connect_handler));
    r.with_state(state)
}

/// Build the admin trust-boundary router.
///
/// Mounts the five [`admin`] handlers — `POST /v1/admin/config/reload`,
/// `GET /v1/admin/config/current`, `GET /v1/admin/health`,
/// `GET /v1/admin/policy/snapshot`, and `GET /v1/admin/lease/count`.
/// See the [`admin`] module rustdoc for the per-endpoint contracts
/// (handle-required vs stateless vs sentinel-on-no-handle).
/// Additional `/v1/admin/*` + `/metrics` handlers register in
/// follow-up commits.
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
              aggregator wired in the workspace yet; the five admin \
              handlers register through `axum::Router::route` under the \
              same carve-out shape as the keyless oracle. The utoipa-axum \
              migration is a single Phase 7 follow-up that switches every \
              admin handler in one diff once the aggregator lands — \
              adopting utoipa-axum here per route would fragment the \
              migration. Recorded as a follow-up gap; the admin router is \
              reachable only via the admin trust-boundary listener."
)]
pub fn build_admin_router(state: AdminState) -> axum::Router {
    use axum::routing::{get, post};
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
    let r = r.route(
        "/v1/admin/config/current",
        get(admin::get_current_config_handler),
    );
    let r = r.route("/v1/admin/health", get(admin::health_handler));
    let r = r.route(
        "/v1/admin/policy/snapshot",
        get(admin::policy_snapshot_handler),
    );
    let r = r.route("/v1/admin/lease/count", get(admin::lease_count_handler));
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
    use crate::policy::{PolicyRuntime, ReputationEngine};
    use crate::state::LeaseRegistry;
    use std::sync::Arc;

    #[test]
    fn build_sdk_router_returns_router() {
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let engine = ReputationEngine::new();
        let signing_key = Arc::new(portal_crypto::ed25519_from_seed_for_test([0x11u8; 32]));
        let verifier = Arc::new(portal_crypto::Ed25519Verifier::new(
            portal_crypto::verifying_key(&signing_key),
        ));
        let _r = build_sdk_router(SdkState {
            leases,
            policy,
            engine,
            ens_resolver: None,
            lease_token_signing_key: signing_key,
            lease_token_verifier: verifier,
        });
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
