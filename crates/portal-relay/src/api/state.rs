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

use portal_crypto::{BoxedEnsResolver, Ed25519Verifier, RelayEd25519Key};
use secrecy::SecretBox;

use crate::policy::{PolicyRuntime, ReputationEngine};
use crate::reload::ReloadHandle;
use crate::state::LeaseRegistry;

/// State carried by the SDK trust-boundary router.
///
/// SDK handlers see the lease registry (read + write), the policy
/// runtime (read), the reputation engine (the future
/// `/v1/sdk/register` handler calls [`ReputationEngine::mark_ens_named`]
/// on it after a successful SIWE+ENS gating check), and an optional
/// [`BoxedEnsResolver`] used to drive the `address → ENS name`
/// lookup that backs the marking.
#[derive(Clone)]
pub struct SdkState {
    /// Lease registry (read + write).
    pub leases: LeaseRegistry,
    /// Policy runtime (read-only from the SDK surface).
    pub policy: Arc<PolicyRuntime>,
    /// Reputation engine handle (cheap `Arc`-clone internally).
    ///
    /// The (future) `POST /v1/sdk/register` handler consumes this
    /// field exclusively: after a successful SIWE signature check
    /// and an `EnsResolver` round-trip that confirms the SIWE
    /// address has a primary ENS name, the handler calls
    /// [`ReputationEngine::mark_ens_named`] on this engine so the
    /// reputation pipeline's [`ReputationEngine::decide`] step 4
    /// bypass applies on subsequent traffic for that identity.
    ///
    /// MUST be the same `ReputationEngine` instance the
    /// reputation-persist cadence loop (started by
    /// [`crate::server::Server::with_reputation_persistence`])
    /// flushes — the bin crate threads one engine clone through
    /// both call sites. The Server's plumbing does NOT enforce
    /// this in v0.1; it is the operator's contract.
    pub engine: ReputationEngine,
    /// Optional ENS resolver. `None` is the v0.1 default for demo
    /// or no-ENS-configured deployments. The (future)
    /// `POST /v1/sdk/register` handler consumes this field as
    /// follows:
    ///
    /// - `Some`: after SIWE signature verification, the handler
    ///   calls [`BoxedEnsResolver::resolve_reverse`] on the SIWE
    ///   address; on `Ok(Some(name))` it forward-verifies via
    ///   [`BoxedEnsResolver::resolve`] and, on round-trip match,
    ///   marks the identity via [`ReputationEngine::mark_ens_named`].
    /// - `None`: the registration is still accepted (SIWE alone is
    ///   sufficient), but the ENS-bypass-marking step is skipped —
    ///   the identity is not added to the engine's ENS-named cache,
    ///   so [`ReputationEngine::decide`] step 4 does not apply.
    pub ens_resolver: Option<BoxedEnsResolver>,
    /// Shared lease-token signing-key handle.
    ///
    /// Handlers reach for a borrowed [`portal_crypto::Ed25519Signer`]
    /// at call time (`Ed25519Signer::new(&state.lease_token_signing_key)`).
    /// Held as `Arc<SecretBox<…>>` because [`portal_crypto::Ed25519Signer`]
    /// is borrowed (lifetime `'k` over the key) and therefore cannot
    /// itself be `Arc`-wrapped.
    ///
    /// # Invariant (verifier/signer pairing)
    ///
    /// [`Self::lease_token_verifier`] MUST be derived from this same
    /// key (via [`portal_crypto::verifying_key`]). The pairing is
    /// enforced by construction inside
    /// [`crate::server::Server::sdk_state`] — direct callers (test
    /// fixtures only) MUST mirror that derivation; a mismatched pair
    /// silently breaks verification.
    pub lease_token_signing_key: Arc<SecretBox<RelayEd25519Key>>,
    /// Shared lease-token verifier. Owned (no lifetime),
    /// `Arc`-cloned across handlers.
    ///
    /// MUST be derived from [`Self::lease_token_signing_key`]; see
    /// that field's invariant note for the pairing contract.
    pub lease_token_verifier: Arc<Ed25519Verifier>,
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
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use core::future::Future;

    use portal_crypto::{EnsError, EnsResolver, EthAddress};

    use super::*;
    use crate::policy::IdentityKey;

    /// Minimal in-test [`EnsResolver`] used to wrap a
    /// [`BoxedEnsResolver`] for `SdkState` plumbing tests. Always
    /// returns `NameNotFound` / `Ok(None)` — handler-level
    /// behavioral coverage lives in the future `/v1/sdk/register`
    /// commit.
    struct StubEnsResolver;

    impl EnsResolver for StubEnsResolver {
        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
            async move { Err(EnsError::NameNotFound("stub".to_owned())) }
        }

        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve_reverse(
            &self,
            _addr: EthAddress,
        ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
            async move { Ok(None) }
        }
    }

    /// Build a paired `(Arc<SecretBox<RelayEd25519Key>>, Arc<Ed25519Verifier>)`
    /// from a deterministic seed. Used by every fixture below to
    /// satisfy the `SdkState` verifier/signer pairing invariant
    /// without ad-hoc per-test duplication.
    fn fixture_lease_token_keys(
        seed: [u8; 32],
    ) -> (
        Arc<SecretBox<portal_crypto::RelayEd25519Key>>,
        Arc<portal_crypto::Ed25519Verifier>,
    ) {
        let key = Arc::new(portal_crypto::ed25519_from_seed_for_test(seed));
        let vk = portal_crypto::verifying_key(&key);
        let verifier = Arc::new(portal_crypto::Ed25519Verifier::new(vk));
        (key, verifier)
    }

    #[test]
    fn states_are_cheaply_cloneable() {
        // Smoke test that the state types compile and clone without
        // owning anything heavy directly. This is the type-level
        // contract that subsequent handlers rely on.
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let (signing_key, verifier) = fixture_lease_token_keys([0xAAu8; 32]);
        let _sdk = SdkState {
            leases: leases.clone(),
            policy: Arc::clone(&policy),
            engine: ReputationEngine::new(),
            ens_resolver: None,
            lease_token_signing_key: signing_key,
            lease_token_verifier: verifier,
        };
        let _admin = AdminState {
            leases: leases.clone(),
            policy,
            reload: None,
        };
        let _disc = DiscoveryState { leases };
    }

    #[tokio::test]
    async fn sdk_state_carries_engine_and_resolver() {
        // Type-level: SdkState is Send + Sync. If any field type ever
        // regresses to a non-Send shape this assertion stops compiling.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SdkState>();

        // Construct an `SdkState` carrying the new fields and verify
        // (a) Clone is cheap (every field is Arc-shaped or `Option`
        // around an Arc-shaped value), (b) the engine reference
        // round-trips: marking via the original handle is observable
        // via the state-carried clone, proving the Arc share-graph
        // is intact rather than a sneaky deep clone, and (c) the
        // boxed ENS resolver is actually invokable through the
        // state-carried clone (not just held as a phantom shape).
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let engine = ReputationEngine::new();
        let resolver = BoxedEnsResolver::new(StubEnsResolver);
        let (signing_key, verifier) = fixture_lease_token_keys([0xBBu8; 32]);
        let state = SdkState {
            leases,
            policy,
            engine: engine.clone(),
            ens_resolver: Some(resolver),
            lease_token_signing_key: signing_key,
            lease_token_verifier: verifier,
        };
        let cloned = state.clone();

        let id = IdentityKey([0x42; 32]);
        assert!(!engine.is_ens_named(id), "fresh engine: not marked");
        cloned.engine.mark_ens_named(id);
        assert!(
            engine.is_ens_named(id),
            "mark on state-carried engine clone is visible through the source engine \
             — the engine reference is truly shared, not duplicated",
        );
        assert!(
            state.ens_resolver.is_some(),
            "ens_resolver carried through Some-construction",
        );
        assert!(cloned.ens_resolver.is_some(), "ens_resolver survives Clone");

        // Round-trip the resolver through the state-carried handle to
        // verify the boxed resolver remains usable end-to-end. Stub
        // returns `Ok(None)` for any reverse lookup; a regression that
        // breaks the dyn-dispatch routing through `SdkState` would
        // show up here as a panic or compile error.
        let reverse = cloned
            .ens_resolver
            .as_ref()
            .unwrap()
            .resolve_reverse(EthAddress::new([0u8; 20]))
            .await;
        assert!(
            matches!(reverse, Ok(None)),
            "stub resolver routed through SdkState: expected Ok(None), got {reverse:?}",
        );
    }
}
