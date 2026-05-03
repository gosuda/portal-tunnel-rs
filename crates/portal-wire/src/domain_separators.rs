//! SEC-007 domain separator constants for signing inputs.

/// Prefix for [`crate::descriptor::RelayDescriptor`] canonical bytes.
pub const RELAY_DESCRIPTOR: &[u8] = b"portal-tunnel/relay-descriptor/v1";
/// Prefix for [`crate::hop::HopRoute`] canonical bytes.
pub const HOP_ROUTE: &[u8] = b"portal-tunnel/hop-route/v1";
/// Prefix for [`crate::lease::LeaseToken`] canonical bytes.
pub const LEASE_TOKEN: &[u8] = b"portal-tunnel/lease-token/v1";
/// Prefix for keyless signing requests (Phase 6b).
pub const KEYLESS_REQUEST: &[u8] = b"portal-tunnel/keyless-request/v1";
/// Prefix for [`crate::reputation::ReputationDelta`] canonical bytes (v0.2 wire).
pub const REPUTATION_DELTA: &[u8] = b"portal-tunnel/reputation-delta/v1";

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    #[test]
    fn separators_are_unique() {
        let all = [
            super::RELAY_DESCRIPTOR,
            super::HOP_ROUTE,
            super::LEASE_TOKEN,
            super::KEYLESS_REQUEST,
            super::REPUTATION_DELTA,
        ];
        let uniq: HashSet<&[u8]> = all.iter().copied().collect();
        assert_eq!(uniq.len(), 5);
    }

    #[test]
    fn mitm_label_differs_from_go_v1_literal() {
        let go = b"Portal-MITM-Probe-v1";
        assert_ne!(crate::mitm::MITM_PROBE_LABEL, go);
    }
}
