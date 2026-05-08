//! [`HopRoute`] — multi-hop attestation payload (Phase 6b consumes).

use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::domain_separators;
use crate::error::Error;

/// Attested next-hop routing decision (wire reservation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopRoute {
    /// Opaque route id for logging / correlation.
    pub route_id: u64,
    /// Next relay identity (raw pubkey).
    pub next_hop: [u8; 32],
    /// Public hostname advertised for this route.
    pub public_hostname: CompactString,
    /// Route-specific hostname (may differ from public).
    pub route_hostname: CompactString,
    /// Hash of the hostname for deterministic lookup.
    pub hostname_hash: String,
    /// ECH config list bytes derived from the relay's ECH seed.
    pub ech_config_list: Vec<u8>,
    /// Token used to match incoming requests against this route.
    pub match_token: String,
    /// When the route was first observed (epoch millis).
    pub first_seen_at: Option<Timestamp>,
}

impl HopRoute {
    /// Canonical signing input for hop attestations.
    ///
    /// # Errors
    /// Returns [`Error::PostcardEncode`] on serialization failure.
    pub fn canonical_signing_input(&self) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(&(domain_separators::HOP_ROUTE, self)).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test-only assertions")]

    use super::*;

    #[test]
    fn canonical_signing_input_is_stable() {
        let hop = HopRoute {
            route_id: 42,
            next_hop: [0u8; 32],
            public_hostname: CompactString::from("example.com"),
            route_hostname: CompactString::from("route.example.com"),
            hostname_hash: "abc123".to_owned(),
            ech_config_list: vec![0x01, 0x02],
            match_token: "token_xyz".to_owned(),
            first_seen_at: None,
        };
        let input1 = hop.canonical_signing_input().expect("serialize");
        let input2 = hop.canonical_signing_input().expect("serialize");
        assert_eq!(
            input1, input2,
            "canonical signing input must be deterministic"
        );

        // Verify the tuple encoding includes the domain separator as the first element.
        let (sep, decoded_hop): (&[u8], HopRoute) =
            postcard::from_bytes(&input1).expect("decode tuple");
        assert_eq!(sep, domain_separators::HOP_ROUTE);
        assert_eq!(decoded_hop, hop);
    }
}
