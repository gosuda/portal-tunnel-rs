//! Eclipse-resistant relay picker.
//!
//! The picker is deterministic and conservative:
//!
//! - ASN metadata must be enforceable (`OperatorConfig` or future
//!   `AuthenticatedDiscovery`) unless degraded mode is explicitly
//!   allowed.
//! - Untrusted ASN hints never satisfy diversity policy.
//! - When enforceable metadata is present, fewer than the configured
//!   minimum distinct ASN bins rejects the set unless degraded mode is
//!   enabled.
//!
//! This module does not fetch, authenticate, or enrich relay metadata.
//! It only consumes [`crate::relay_set::RelayCandidate`] values after
//! a discovery/config layer has attached provenance-aware metadata.

use std::collections::BTreeSet;

use crate::error::{SdkError, SdkResult};
use crate::relay_set::{AsnBin, RelayCandidate, RelaySet};

/// Picker constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PickerConstraints {
    /// Minimum relays to return.
    pub min_relays: usize,
    /// Minimum distinct enforceable ASN bins required when metadata
    /// is available.
    pub min_asn_bins: usize,
    /// Permit deterministic selection even when trusted metadata is
    /// absent or diversity is below the floor. This never relaxes
    /// [`Self::min_relays`]; callers that want best-effort single-relay
    /// behavior must set an explicitly lower relay floor.
    pub allow_degraded: bool,
}

impl PickerConstraints {
    /// v0.1 default: three relays from at least three distinct ASN
    /// bins; no degraded selection unless the operator asks for it.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            min_relays: 3,
            min_asn_bins: 3,
            allow_degraded: false,
        }
    }

    /// Same floor as strict mode, but allows deterministic fallback
    /// when trusted diversity metadata is missing or insufficient.
    #[must_use]
    pub const fn degraded() -> Self {
        Self {
            min_relays: 3,
            min_asn_bins: 3,
            allow_degraded: true,
        }
    }
}

impl Default for PickerConstraints {
    fn default() -> Self {
        Self::strict()
    }
}

/// Pick relays from a validated set.
///
/// # Errors
/// Returns [`SdkError::Eclipse`] if the set cannot satisfy the
/// requested minimum relays / ASN diversity and degraded selection is
/// not allowed.
pub fn pick_relays(
    set: &RelaySet,
    constraints: PickerConstraints,
) -> SdkResult<Vec<RelayCandidate>> {
    if constraints.min_relays == 0 {
        return Err(SdkError::Eclipse("min_relays must be > 0".to_owned()));
    }
    if constraints.min_asn_bins == 0 {
        return Err(SdkError::Eclipse("min_asn_bins must be > 0".to_owned()));
    }
    if constraints.min_asn_bins > constraints.min_relays {
        return Err(SdkError::Eclipse(
            "min_asn_bins cannot exceed min_relays".to_owned(),
        ));
    }
    if set.len() < constraints.min_relays {
        return Err(SdkError::Eclipse(format!(
            "relay set has {} candidates; {} required",
            set.len(),
            constraints.min_relays,
        )));
    }

    let sorted = sorted_candidates(set);
    let enforceable_bins = enforceable_bins(&sorted);
    let missing_trusted_metadata = sorted
        .iter()
        .any(|candidate| candidate.metadata.enforceable_asn_bin().is_none());

    if missing_trusted_metadata && !constraints.allow_degraded {
        return Err(SdkError::Eclipse(
            "trusted ASN metadata missing; refusing to claim eclipse resistance".to_owned(),
        ));
    }

    if !missing_trusted_metadata && enforceable_bins.len() < constraints.min_asn_bins {
        if !constraints.allow_degraded {
            return Err(SdkError::Eclipse(format!(
                "insufficient ASN diversity: {} bins present; {} required",
                enforceable_bins.len(),
                constraints.min_asn_bins,
            )));
        }
        tracing::warn!(
            bins = enforceable_bins.len(),
            required = constraints.min_asn_bins,
            "relay picker running in degraded mode with insufficient ASN diversity",
        );
    } else if missing_trusted_metadata && constraints.allow_degraded {
        tracing::warn!(
            relay_count = sorted.len(),
            "relay picker running in degraded mode without trusted ASN metadata",
        );
    }

    Ok(select_deterministically(&sorted, constraints.min_relays))
}

fn sorted_candidates(set: &RelaySet) -> Vec<RelayCandidate> {
    let mut candidates = set.candidates().to_vec();
    candidates.sort_by_key(|candidate| {
        (
            candidate
                .metadata
                .enforceable_asn_bin()
                .map_or(u32::MAX, AsnBin::get),
            candidate.descriptor.identity_key,
        )
    });
    candidates
}

fn enforceable_bins(candidates: &[RelayCandidate]) -> BTreeSet<AsnBin> {
    candidates
        .iter()
        .filter_map(|candidate| candidate.metadata.enforceable_asn_bin())
        .collect()
}

fn select_deterministically(
    candidates: &[RelayCandidate],
    min_relays: usize,
) -> Vec<RelayCandidate> {
    let mut selected = Vec::new();
    let mut used_bins = BTreeSet::new();

    for candidate in candidates {
        if let Some(bin) = candidate.metadata.enforceable_asn_bin()
            && used_bins.insert(bin)
        {
            selected.push(candidate.clone());
        }
        if selected.len() == min_relays {
            return selected;
        }
    }

    for candidate in candidates {
        if selected.iter().all(|picked: &RelayCandidate| {
            picked.descriptor.identity_key != candidate.descriptor.identity_key
        }) {
            selected.push(candidate.clone());
        }
        if selected.len() == min_relays || selected.len() == candidates.len() {
            return selected;
        }
    }

    selected
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only constructors")]
mod tests {
    use std::net::SocketAddrV6;

    use portal_wire::descriptor::RelayDescriptor;

    use super::*;
    use crate::relay_set::{RelayMetadata, v4, v6};

    fn descriptor(id: u8) -> RelayDescriptor {
        RelayDescriptor {
            identity_key: [id; 32],
            addresses_v4: vec![v4(id, 443)],
            addresses_v6: Vec::new(),
        }
    }

    fn candidate(id: u8, asn: u32) -> RelayCandidate {
        RelayCandidate::with_metadata(
            descriptor(id),
            RelayMetadata::operator_config(AsnBin::new(asn).unwrap()),
        )
    }

    #[test]
    fn rejects_missing_trusted_metadata_in_strict_mode() {
        let set =
            RelaySet::from_descriptors(vec![descriptor(1), descriptor(2), descriptor(3)]).unwrap();
        let err = pick_relays(&set, PickerConstraints::strict()).unwrap_err();
        assert!(matches!(err, SdkError::Eclipse(_)));
    }

    #[test]
    fn rejects_single_asn_dominance_in_strict_mode() {
        let set = RelaySet::new(vec![
            candidate(1, 64512),
            candidate(2, 64512),
            candidate(3, 64512),
        ])
        .unwrap();
        let err = pick_relays(&set, PickerConstraints::strict()).unwrap_err();
        assert!(matches!(err, SdkError::Eclipse(_)));
    }

    #[test]
    fn selects_three_distinct_asn_bins() {
        let set = RelaySet::new(vec![
            candidate(3, 64514),
            candidate(1, 64512),
            candidate(2, 64513),
        ])
        .unwrap();
        let picked = pick_relays(&set, PickerConstraints::strict()).unwrap();
        let bins: BTreeSet<AsnBin> = picked
            .iter()
            .map(|candidate| candidate.metadata.enforceable_asn_bin().unwrap())
            .collect();
        assert_eq!(picked.len(), 3);
        assert_eq!(bins.len(), 3);
    }

    #[test]
    fn degraded_mode_allows_missing_metadata_when_relay_floor_is_met() {
        let set =
            RelaySet::from_descriptors(vec![descriptor(1), descriptor(2), descriptor(3)]).unwrap();
        let picked = pick_relays(&set, PickerConstraints::degraded()).unwrap();
        assert_eq!(picked.len(), 3);
    }

    #[test]
    fn degraded_mode_does_not_relax_min_relay_floor() {
        let set = RelaySet::from_descriptors(vec![descriptor(1), descriptor(2)]).unwrap();
        let err = pick_relays(&set, PickerConstraints::degraded()).unwrap_err();
        assert!(matches!(err, SdkError::Eclipse(_)));
    }

    #[test]
    fn rejects_asn_floor_above_relay_floor() {
        let set = RelaySet::new(vec![
            candidate(1, 64512),
            candidate(2, 64513),
            candidate(3, 64514),
        ])
        .unwrap();
        let err = pick_relays(
            &set,
            PickerConstraints {
                min_relays: 2,
                min_asn_bins: 3,
                allow_degraded: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, SdkError::Eclipse(_)));
    }

    #[test]
    fn untrusted_hints_do_not_satisfy_strict_diversity() {
        let candidates: Vec<RelayCandidate> = [1_u8, 2, 3]
            .into_iter()
            .map(|id| {
                RelayCandidate::with_metadata(
                    descriptor(id),
                    RelayMetadata::untrusted_hint(AsnBin::new(64_511 + u32::from(id)).unwrap()),
                )
            })
            .collect();
        let set = RelaySet::new(candidates).unwrap();
        let err = pick_relays(&set, PickerConstraints::strict()).unwrap_err();
        assert!(matches!(err, SdkError::Eclipse(_)));
    }

    #[test]
    fn ipv6_only_relay_can_be_selected() {
        let descriptor = RelayDescriptor {
            identity_key: [1; 32],
            addresses_v4: Vec::new(),
            addresses_v6: vec![v6(1, 443)],
        };
        let set = RelaySet::new(vec![RelayCandidate::with_metadata(
            descriptor,
            RelayMetadata::operator_config(AsnBin::new(64512).unwrap()),
        )])
        .unwrap();
        let picked = pick_relays(
            &set,
            PickerConstraints {
                min_relays: 1,
                min_asn_bins: 1,
                allow_degraded: false,
            },
        )
        .unwrap();
        assert_eq!(picked.len(), 1);
        assert!(matches!(
            picked[0].socket_addrs()[0],
            std::net::SocketAddr::V6(_)
        ));
    }

    #[test]
    fn v4_mapped_v6_descriptor_is_rejected_before_pick() {
        let descriptor = RelayDescriptor {
            identity_key: [1; 32],
            addresses_v4: Vec::new(),
            addresses_v6: vec!["[::ffff:192.0.2.1]:443".parse::<SocketAddrV6>().unwrap()],
        };
        assert!(RelaySet::from_descriptors(vec![descriptor]).is_err());
    }
}
