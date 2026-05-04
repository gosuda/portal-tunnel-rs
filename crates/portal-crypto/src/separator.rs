//! Domain separator newtype and Role typestate markers (SEC-007).
//!
//! Every signing operation in `portal-crypto` prefixes its input with a
//! [`DomainSeparator`] selected by the [`Role`] typestate trait, preventing
//! cross-protocol confusion attacks.

use portal_wire::domain_separators;

/// A validated, non-empty byte-string used to domain-separate signing inputs.
///
/// Construction is const-only via [`DomainSeparator::new`], which enforces
/// the length invariant (1 – 255 bytes inclusive) at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSeparator(&'static [u8]);

impl DomainSeparator {
    /// Construct a [`DomainSeparator`] from a static byte slice.
    ///
    /// # Panics
    ///
    /// Panics in const evaluation if `bytes` is empty or longer than 255 bytes.
    #[must_use]
    pub const fn new(bytes: &'static [u8]) -> Self {
        assert!(
            !bytes.is_empty() && bytes.len() <= u8::MAX as usize,
            "DomainSeparator must be 1–255 bytes"
        );
        Self(bytes)
    }

    /// Return the raw bytes of this separator.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}

/// Typestate marker trait binding a struct to its SEC-007 domain separator.
///
/// This trait is intentionally object-unsafe (associated const) so it can only
/// be used as a zero-cost compile-time tag, never as a trait object.
pub trait Role {
    /// The domain separator for this role.
    const SEPARATOR: DomainSeparator;
}

/// Typestate marker for [`portal_wire::descriptor::RelayDescriptor`] signing.
pub struct RelayDescriptor;

/// Typestate marker for [`portal_wire::hop::HopRoute`] signing.
pub struct HopRoute;

/// Typestate marker for [`portal_wire::lease::LeaseToken`] signing.
pub struct LeaseToken;

/// Typestate marker for keyless signing requests (Phase 6b).
pub struct KeylessRequest;

/// Typestate marker for [`portal_wire::reputation::ReputationDelta`] signing.
pub struct ReputationDelta;

/// Typestate marker for binding attestation payloads (SEC-002).
pub struct BindingAttestation;

impl Role for RelayDescriptor {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::RELAY_DESCRIPTOR);
}

impl Role for HopRoute {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::HOP_ROUTE);
}

impl Role for LeaseToken {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::LEASE_TOKEN);
}

impl Role for KeylessRequest {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::KEYLESS_REQUEST);
}

impl Role for ReputationDelta {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::REPUTATION_DELTA);
}

impl Role for BindingAttestation {
    const SEPARATOR: DomainSeparator = DomainSeparator::new(domain_separators::BINDING_ATTESTATION);
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        BindingAttestation, HopRoute, KeylessRequest, LeaseToken, RelayDescriptor, ReputationDelta,
        Role,
    };

    #[test]
    fn each_role_separator_matches_sec007() {
        assert_eq!(
            <RelayDescriptor as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/relay-descriptor/v1"
        );
        assert_eq!(
            <HopRoute as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/hop-route/v1"
        );
        assert_eq!(
            <LeaseToken as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/lease-token/v1"
        );
        assert_eq!(
            <KeylessRequest as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/keyless-request/v1"
        );
        assert_eq!(
            <ReputationDelta as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/reputation-delta/v1"
        );
        assert_eq!(
            <BindingAttestation as Role>::SEPARATOR.as_bytes(),
            b"portal-tunnel/binding-attestation/v1"
        );
    }

    #[test]
    fn separators_are_pairwise_distinct() {
        let separators: HashSet<&[u8]> = [
            <RelayDescriptor as Role>::SEPARATOR.as_bytes(),
            <HopRoute as Role>::SEPARATOR.as_bytes(),
            <LeaseToken as Role>::SEPARATOR.as_bytes(),
            <KeylessRequest as Role>::SEPARATOR.as_bytes(),
            <ReputationDelta as Role>::SEPARATOR.as_bytes(),
            <BindingAttestation as Role>::SEPARATOR.as_bytes(),
        ]
        .into_iter()
        .collect();
        assert_eq!(separators.len(), 6);
    }
}
