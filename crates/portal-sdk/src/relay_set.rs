//! Relay descriptor set validation.
//!
//! The wire-owned [`portal_wire::descriptor::RelayDescriptor`] carries
//! relay identity + dual-stack addresses only. SDK-side relay picking
//! needs optional operator/discovery metadata (for example ASN bins),
//! but that metadata is **not** part of the Phase 1 descriptor wire
//! shape. This module therefore wraps each descriptor in a
//! [`RelayCandidate`] with explicit [`RelayMetadata`] provenance.
//!
//! Provenance is load-bearing: the eclipse picker only treats ASN
//! metadata as enforceable when it came from operator config or a
//! future authenticated discovery document. Untrusted hints are
//! retained for diagnostics but do not satisfy diversity checks.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

#[cfg(test)]
use std::net::{SocketAddrV4, SocketAddrV6};

use portal_wire::descriptor::RelayDescriptor;

use crate::error::{SdkError, SdkResult};

/// ASN diversity bin used by the eclipse-resistant picker.
///
/// ASN 0 is reserved and rejected so `AsnBin(0)` cannot become a
/// silent sentinel value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AsnBin(u32);

impl AsnBin {
    /// Construct an ASN bin.
    ///
    /// # Errors
    /// Returns [`SdkError::Config`] when `value == 0`.
    pub fn new(value: u32) -> SdkResult<Self> {
        if value == 0 {
            return Err(SdkError::Config("ASN bin 0 is reserved".to_owned()));
        }
        Ok(Self(value))
    }

    /// Return the raw ASN/bin identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Provenance of sidecar relay metadata.
///
/// The picker treats only [`MetadataProvenance::OperatorConfig`] and
/// [`MetadataProvenance::AuthenticatedDiscovery`] as enforceable.
/// [`MetadataProvenance::UntrustedHint`] is intentionally ignored for
/// diversity policy because a poisoned discovery source could label
/// colluding relays as distinct ASNs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetadataProvenance {
    /// Static operator-provided config (`--relays`, local config file,
    /// or test fixture). Trust is delegated to the operator.
    OperatorConfig,
    /// Future signed discovery/enrichment document after signature,
    /// freshness, and identity binding checks have completed.
    AuthenticatedDiscovery,
    /// Diagnostic-only metadata from an unauthenticated source. Never
    /// counts toward enforced ASN diversity.
    UntrustedHint,
}

/// Optional sidecar metadata for a relay descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayMetadata {
    /// Optional ASN diversity bin.
    pub asn_bin: Option<AsnBin>,
    /// Metadata source and trust boundary.
    pub provenance: MetadataProvenance,
}

impl RelayMetadata {
    /// No metadata available.
    #[must_use]
    pub const fn missing() -> Self {
        Self {
            asn_bin: None,
            provenance: MetadataProvenance::UntrustedHint,
        }
    }

    /// Metadata from static operator config.
    #[must_use]
    pub const fn operator_config(asn_bin: AsnBin) -> Self {
        Self {
            asn_bin: Some(asn_bin),
            provenance: MetadataProvenance::OperatorConfig,
        }
    }

    /// Metadata from a future authenticated discovery/enrichment
    /// source after signature and freshness checks.
    #[must_use]
    pub const fn authenticated_discovery(asn_bin: AsnBin) -> Self {
        Self {
            asn_bin: Some(asn_bin),
            provenance: MetadataProvenance::AuthenticatedDiscovery,
        }
    }

    /// Metadata from an unauthenticated source. Retained for logs and
    /// diagnostics, ignored for enforced diversity.
    #[must_use]
    pub const fn untrusted_hint(asn_bin: AsnBin) -> Self {
        Self {
            asn_bin: Some(asn_bin),
            provenance: MetadataProvenance::UntrustedHint,
        }
    }

    /// ASN bin that may be used for policy enforcement.
    #[must_use]
    pub const fn enforceable_asn_bin(self) -> Option<AsnBin> {
        match self.provenance {
            MetadataProvenance::OperatorConfig | MetadataProvenance::AuthenticatedDiscovery => {
                self.asn_bin
            }
            MetadataProvenance::UntrustedHint => None,
        }
    }
}

impl Default for RelayMetadata {
    fn default() -> Self {
        Self::missing()
    }
}

/// A relay descriptor plus SDK-local metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidate {
    /// Wire descriptor owned by `portal-wire`.
    pub descriptor: RelayDescriptor,
    /// SDK-local metadata with explicit provenance.
    pub metadata: RelayMetadata,
}

impl RelayCandidate {
    /// Construct a candidate without metadata.
    #[must_use]
    pub const fn without_metadata(descriptor: RelayDescriptor) -> Self {
        Self {
            descriptor,
            metadata: RelayMetadata::missing(),
        }
    }

    /// Construct a candidate with metadata.
    #[must_use]
    pub const fn with_metadata(descriptor: RelayDescriptor, metadata: RelayMetadata) -> Self {
        Self {
            descriptor,
            metadata,
        }
    }

    /// Whether the descriptor has at least one reachable address.
    #[must_use]
    pub const fn is_reachable(&self) -> bool {
        !self.descriptor.addresses_v4.is_empty() || !self.descriptor.addresses_v6.is_empty()
    }

    /// All advertised addresses as generic [`SocketAddr`] values.
    #[must_use]
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::with_capacity(
            self.descriptor.addresses_v4.len() + self.descriptor.addresses_v6.len(),
        );
        addrs.extend(
            self.descriptor
                .addresses_v4
                .iter()
                .copied()
                .map(SocketAddr::V4),
        );
        addrs.extend(
            self.descriptor
                .addresses_v6
                .iter()
                .copied()
                .map(SocketAddr::V6),
        );
        addrs
    }
}

/// Validated relay set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySet {
    candidates: Vec<RelayCandidate>,
}

impl RelaySet {
    /// Validate and construct a relay set.
    ///
    /// # Errors
    /// Returns [`SdkError::Config`] for empty sets, duplicate relay
    /// identities, unreachable descriptors, or IPv4-mapped IPv6
    /// addresses in the descriptor's v6 list.
    pub fn new(candidates: Vec<RelayCandidate>) -> SdkResult<Self> {
        if candidates.is_empty() {
            return Err(SdkError::Config("relay set is empty".to_owned()));
        }
        let mut identities = HashSet::with_capacity(candidates.len());
        for candidate in &candidates {
            validate_descriptor(&candidate.descriptor)?;
            if !identities.insert(candidate.descriptor.identity_key) {
                return Err(SdkError::Config("duplicate relay identity".to_owned()));
            }
        }
        Ok(Self { candidates })
    }

    /// Construct from raw descriptors without sidecar metadata.
    ///
    /// This is useful for parsing legacy/manual inputs, but the
    /// eclipse picker will reject these candidates unless degraded
    /// mode is explicitly allowed.
    ///
    /// # Errors
    /// Returns [`SdkError::Config`] for the same validation failures as
    /// [`Self::new`].
    pub fn from_descriptors(descriptors: Vec<RelayDescriptor>) -> SdkResult<Self> {
        Self::new(
            descriptors
                .into_iter()
                .map(RelayCandidate::without_metadata)
                .collect(),
        )
    }

    /// Borrow all candidates.
    #[must_use]
    pub fn candidates(&self) -> &[RelayCandidate] {
        &self.candidates
    }

    /// Number of candidates.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether the set is empty. Always false for a constructed set,
    /// but useful for generic callers.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
}

fn validate_descriptor(descriptor: &RelayDescriptor) -> SdkResult<()> {
    if descriptor.addresses_v4.is_empty() && descriptor.addresses_v6.is_empty() {
        return Err(SdkError::Config(
            "relay descriptor has no addresses".to_owned(),
        ));
    }
    for addr in &descriptor.addresses_v6 {
        if matches!(addr.ip().to_canonical(), IpAddr::V4(_)) {
            return Err(SdkError::Config(
                "relay descriptor v6 list contains IPv4-mapped IPv6 address".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Test helper for constructing a v4 address.
#[cfg(test)]
pub(crate) const fn v4(a: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(std::net::Ipv4Addr::new(192, 0, 2, a), port)
}

/// Test helper for constructing a v6 address.
#[cfg(test)]
pub(crate) const fn v6(a: u16, port: u16) -> SocketAddrV6 {
    SocketAddrV6::new(
        std::net::Ipv6Addr::new(0x2001, 0xdb8, a, 0, 0, 0, 0, 1),
        port,
        0,
        0,
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only constructors")]
mod tests {
    use super::*;

    fn descriptor(id: u8) -> RelayDescriptor {
        RelayDescriptor {
            identity_key: [id; 32],
            addresses_v4: vec![v4(id, 443)],
            addresses_v6: Vec::new(),
        }
    }

    #[test]
    fn rejects_empty_set() {
        assert!(RelaySet::new(Vec::new()).is_err());
    }

    #[test]
    fn rejects_unreachable_descriptor() {
        let descriptor = RelayDescriptor {
            identity_key: [1; 32],
            addresses_v4: Vec::new(),
            addresses_v6: Vec::new(),
        };
        let err = RelaySet::from_descriptors(vec![descriptor]).unwrap_err();
        assert!(matches!(err, SdkError::Config(_)));
    }

    #[test]
    fn rejects_duplicate_identity() {
        let err = RelaySet::from_descriptors(vec![descriptor(1), descriptor(1)]).unwrap_err();
        assert!(matches!(err, SdkError::Config(_)));
    }

    #[test]
    fn rejects_v4_mapped_v6_in_v6_list() {
        let descriptor = RelayDescriptor {
            identity_key: [1; 32],
            addresses_v4: Vec::new(),
            addresses_v6: vec!["[::ffff:192.0.2.1]:443".parse().unwrap()],
        };
        let err = RelaySet::from_descriptors(vec![descriptor]).unwrap_err();
        assert!(matches!(err, SdkError::Config(_)));
    }

    #[test]
    fn accepts_ipv6_only_descriptor() {
        let descriptor = RelayDescriptor {
            identity_key: [1; 32],
            addresses_v4: Vec::new(),
            addresses_v6: vec![v6(1, 443)],
        };
        let set = RelaySet::from_descriptors(vec![descriptor]).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn untrusted_hint_is_not_enforceable() {
        let metadata = RelayMetadata::untrusted_hint(AsnBin::new(64512).unwrap());
        assert_eq!(metadata.enforceable_asn_bin(), None);
    }
}
