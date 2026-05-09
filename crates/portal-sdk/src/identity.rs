//! Tenant and protocol identity key surfaces for the SDK.
//!
//! Thin wrappers over [`portal-crypto`] constructors so callers do not
//! need to depend on `portal-crypto` directly for routine key loading.

use std::path::Path;

use portal_crypto::{
    generate_relay_ed25519_key, load_relay_ed25519_key, load_tenant_secp256k1_key,
    tenant_public_key as tenant_public_key_inner, verifying_key as protocol_verifying_key_inner,
};
use secrecy::SecretBox;

use crate::error::{SdkError, SdkResult};

// ---------------------------------------------------------------------------
// Tenant identity (secp256k1)
// ---------------------------------------------------------------------------

/// Re-export: the tenant's secp256k1 signing key type.
pub use portal_crypto::TenantSecp256k1Key;

/// Load the tenant secp256k1 identity key from disk.
///
/// # Errors
/// Returns [`SdkError::Crypto`] on load failure.
pub fn load_tenant_key(path: &Path) -> SdkResult<SecretBox<TenantSecp256k1Key>> {
    load_tenant_secp256k1_key(path).map_err(|e| SdkError::Crypto(e.to_string()))
}

/// Derive the [`k256::PublicKey`] from a loaded tenant key.
///
/// # Errors
/// Returns [`SdkError::Crypto`] on internal key derivation failure.
pub fn tenant_public_key(key: &SecretBox<TenantSecp256k1Key>) -> SdkResult<k256::PublicKey> {
    tenant_public_key_inner(key).map_err(|e| SdkError::Crypto(e.to_string()))
}

// ---------------------------------------------------------------------------
// Protocol identity (ed25519)
// ---------------------------------------------------------------------------

/// Re-export: the ed25519 protocol-identity key type.
pub use portal_crypto::RelayEd25519Key as ProtocolKey;

/// Generate a fresh ephemeral ed25519 protocol-identity key.
///
/// # Errors
/// Returns [`SdkError::Crypto`] on RNG failure.
pub fn generate_protocol_key() -> SdkResult<SecretBox<ProtocolKey>> {
    generate_relay_ed25519_key().map_err(|e| SdkError::Crypto(e.to_string()))
}

/// Load a persisted ed25519 protocol-identity key from disk.
///
/// # Errors
/// Returns [`SdkError::Crypto`] on load failure.
pub fn load_protocol_key(path: &Path) -> SdkResult<SecretBox<ProtocolKey>> {
    load_relay_ed25519_key(path).map_err(|e| SdkError::Crypto(e.to_string()))
}

/// Extract the 32-byte ed25519 public key from a loaded protocol key.
#[must_use]
pub fn protocol_pubkey(key: &SecretBox<ProtocolKey>) -> [u8; 32] {
    protocol_verifying_key_inner(key).to_bytes()
}
