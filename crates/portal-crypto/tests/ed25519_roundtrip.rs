//! Proptest round-trip integration tests for ed25519 domain-separated signing.
//!
//! These tests exercise [`portal_crypto::Ed25519Signer`] and
//! [`portal_crypto::Ed25519Verifier`] end-to-end through the public crate API,
//! using proptest to generate random seeds and payloads.
//!
//! Two properties are verified:
//!
//! - **`same_role_round_trip`** — signing with role X and verifying with role X
//!   always succeeds (correctness invariant).
//! - **`cross_role_fails`** — signing with role X and verifying with a
//!   *different* role Y always fails (SEC-007 domain-separation invariant).
//!
//! Phase 2 B8 / U12.

use portal_crypto::{
    Ed25519Signer, Ed25519Verifier, HopRoute, LeaseToken, RelayDescriptor,
    ed25519_from_seed_for_test, verifying_key,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

// ---------------------------------------------------------------------------
// Role-pair table
// ---------------------------------------------------------------------------

/// A discriminant for the three ed25519 signing roles under proptest coverage.
///
/// `KeylessRequest`, `ReputationDelta`, and `BindingAttestation` are excluded:
/// `BindingAttestation` is signed via secp256k1 (SIWE flow), not ed25519;
/// `KeylessRequest` and `ReputationDelta` are exercised in their owner
/// crates (portal-relay Phase 6b/A and Phase 5 U12 respectively).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleId {
    RelayDescriptor,
    HopRoute,
    LeaseToken,
}

/// Sign `payload` with the key under the role indicated by `role_id`.
fn sign_with_role(
    signer: &Ed25519Signer<'_>,
    role_id: RoleId,
    payload: &[u8],
) -> Result<ed25519_dalek::Signature, portal_crypto::PortalCryptoError> {
    match role_id {
        RoleId::RelayDescriptor => signer.sign_with_separator::<RelayDescriptor>(payload),
        RoleId::HopRoute => signer.sign_with_separator::<HopRoute>(payload),
        RoleId::LeaseToken => signer.sign_with_separator::<LeaseToken>(payload),
    }
}

/// Verify `sig` over `payload` with the verifier under the role indicated by `role_id`.
fn verify_with_role(
    verifier: &Ed25519Verifier,
    role_id: RoleId,
    payload: &[u8],
    sig: &ed25519_dalek::Signature,
) -> Result<(), portal_crypto::PortalCryptoError> {
    match role_id {
        RoleId::RelayDescriptor => verifier.verify_with_separator::<RelayDescriptor>(payload, sig),
        RoleId::HopRoute => verifier.verify_with_separator::<HopRoute>(payload, sig),
        RoleId::LeaseToken => verifier.verify_with_separator::<LeaseToken>(payload, sig),
    }
}

/// Proptest strategy: pick any `RoleId`.
fn arb_role() -> impl Strategy<Value = RoleId> {
    prop_oneof![
        Just(RoleId::RelayDescriptor),
        Just(RoleId::HopRoute),
        Just(RoleId::LeaseToken),
    ]
}

/// Proptest strategy: produce a `(sign_role, verify_role)` pair that is
/// guaranteed to differ.  Uses `prop_flat_map` so the second element depends
/// on the first, giving proptest clean shrink paths.
fn arb_cross_role_pair() -> impl Strategy<Value = (RoleId, RoleId)> {
    arb_role().prop_flat_map(|sign| {
        let others: Vec<RoleId> = [
            RoleId::RelayDescriptor,
            RoleId::HopRoute,
            RoleId::LeaseToken,
        ]
        .into_iter()
        .filter(|r| *r != sign)
        .collect();
        // `prop_oneof!` requires a fixed list; use `proptest::sample::select`
        // over the filtered vec instead.
        proptest::sample::select(others).prop_map(move |verify| (sign, verify))
    })
}

// ---------------------------------------------------------------------------
// Property 1: same-role round-trip always succeeds
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Signing and verifying with the SAME role always succeeds.
    #[test]
    fn same_role_round_trip(
        seed in any::<[u8; 32]>(),
        payload in proptest::collection::vec(any::<u8>(), 1..=4096),
        role_id in arb_role(),
    ) {
        let key = ed25519_from_seed_for_test(seed);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let sig = sign_with_role(&signer, role_id, &payload)
            .map_err(|e| TestCaseError::fail(format!("sign failed: {e}")))?;

        verify_with_role(&verifier, role_id, &payload, &sig)
            .map_err(|e| TestCaseError::fail(format!("verify failed: {e}")))?;
    }
}

// ---------------------------------------------------------------------------
// Property 2: cross-role verification always fails
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Signing with role X and verifying with a DIFFERENT role Y always fails.
    ///
    /// The `(sign_role, verify_role)` pair is generated by
    /// [`arb_cross_role_pair`], which guarantees the two roles differ without
    /// needing `prop_assume!`.
    #[test]
    fn cross_role_fails(
        seed in any::<[u8; 32]>(),
        payload in proptest::collection::vec(any::<u8>(), 1..=4096),
        (sign_role, verify_role) in arb_cross_role_pair(),
    ) {
        let key = ed25519_from_seed_for_test(seed);
        let vk = verifying_key(&key);
        let signer = Ed25519Signer::new(&key);
        let verifier = Ed25519Verifier::new(vk);

        let sig = sign_with_role(&signer, sign_role, &payload)
            .map_err(|e| TestCaseError::fail(format!("sign failed: {e}")))?;

        let result = verify_with_role(&verifier, verify_role, &payload, &sig);
        prop_assert!(
            result.is_err(),
            "cross-role verification must fail: sign={sign_role:?} verify={verify_role:?}"
        );
    }
}
