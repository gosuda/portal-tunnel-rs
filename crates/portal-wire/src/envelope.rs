//! Signed postcard [`Envelope`](Envelope) and [`Claims`](Claims) (SEC-001).

use bytes::Bytes;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::error::Error;

/// Outer signed container: opaque payload + ed25519 signature + claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Opaque bytes for the operation (lease token, control body, …).
    pub payload: Bytes,
    /// Ed25519 signature over [`Envelope::signing_input`].
    #[serde(with = "BigArray")]
    pub sig: [u8; 64],
    /// Time-bounded, audience-bound metadata.
    pub claims: Claims,
}

/// Claim set bound to a surface and purpose (replay-resistant when verified).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// 128-bit nonce for replay windows.
    pub nonce: [u8; 16],
    /// Lower bound on validity (inclusive).
    pub not_before: Timestamp,
    /// Upper bound on validity (exclusive or inclusive per verifier policy).
    pub not_after: Timestamp,
    /// Receiving trust surface.
    pub audience: Audience,
    /// Operation binding.
    pub purpose: Purpose,
}

/// Receiving API surface for an [`Envelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Audience {
    /// Relay admin HTTPS router (`/v1/admin/*`).
    RelayApiAdmin,
    /// Public SDK router (`/v1/sdk/*`).
    RelayApiSdk,
    /// Discovery announce/refresh (`/discovery`).
    RelayApiDiscovery,
    /// Keyless signing oracle (Phase 6b).
    Keyless,
    /// Hop-forward attestation (overlay).
    HopForward,
    /// QUIC backhaul control channel (relay-server-side handshake).
    QuicBackhaul,
}

/// Operation the [`Envelope`] is allowed to perform once verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Purpose {
    /// New lease registration.
    Register,
    /// Renew an existing lease.
    Renew,
    /// Drop a lease.
    Unregister,
    /// Attest a hop for overlay paths.
    HopAttest,
    /// Keyless oracle signing request.
    KeylessSign,
    /// Discovery pool mutation.
    DiscoveryAnnounce,
    /// Access an existing lease (QUIC backhaul, etc.).
    LeaseAccess,
}

impl Envelope {
    /// Deterministic signing input for `domain_separator` (SEC-007 layout).
    ///
    /// Phase 2 feeds this to ed25519 signing after choosing the correct separator.
    ///
    /// # Errors
    /// Returns [`Error::PostcardEncode`] when serialization fails.
    pub fn signing_input(&self, domain_separator: &[u8]) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(&(domain_separator, &self.payload, &self.claims)).map_err(Into::into)
    }

    /// Round-trip encode for tests / disk.
    ///
    /// # Errors
    /// Returns [`Error::PostcardEncode`] when serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        postcard::to_stdvec(self).map_err(Into::into)
    }

    /// Decode from postcard bytes.
    ///
    /// # Errors
    /// Returns [`Error::PostcardDecode`] when bytes are malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        postcard::from_bytes(bytes).map_err(Error::PostcardDecode)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "signing_input determinism uses fixed claims"
    )]

    use super::*;

    #[test]
    fn signing_input_deterministic() {
        let env = Envelope {
            payload: Bytes::from_static(b"hi"),
            sig: [0u8; 64],
            claims: Claims {
                nonce: [7u8; 16],
                not_before: Timestamp::UNIX_EPOCH,
                not_after: Timestamp::UNIX_EPOCH,
                audience: Audience::RelayApiSdk,
                purpose: Purpose::LeaseAccess,
            },
        };
        let a = env.signing_input(b"sep-a").unwrap();
        let b = env.signing_input(b"sep-a").unwrap();
        assert_eq!(a, b);
        let c = env.signing_input(b"sep-b").unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn quic_backhaul_audience_postcard_round_trips() {
        let env = Envelope {
            payload: Bytes::from_static(b"backhaul-payload"),
            sig: [0u8; 64],
            claims: Claims {
                nonce: [9u8; 16],
                not_before: Timestamp::UNIX_EPOCH,
                not_after: Timestamp::UNIX_EPOCH,
                audience: Audience::QuicBackhaul,
                purpose: Purpose::LeaseAccess,
            },
        };
        let bytes = env.to_bytes().unwrap();
        let decoded = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.claims.audience, Audience::QuicBackhaul);
        assert_eq!(decoded, env);
    }
}
