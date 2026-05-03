//! JSON DTOs for HTTP API bodies (utoipa-friendly).

use serde::{Deserialize, Serialize};

/// SIWE binding attestation field (SEC-002) — verification in `portal-crypto`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiweAttestation {
    /// Bound ed25519 protocol key (raw).
    pub ed25519_pubkey: [u8; 32],
    /// EIP-4361 message bytes (UTF-8).
    pub siwe_message: String,
    /// secp256k1 / EIP-191 signature hex or raw (Phase 2 normalizes).
    pub siwe_signature: String,
}

/// Tenant registration (subset for Phase 1 wire reservation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Human-readable name.
    pub name: String,
    /// Optional SIWE attestation for binding (SEC-002).
    pub siwe_attestation: Option<SiweAttestation>,
}
