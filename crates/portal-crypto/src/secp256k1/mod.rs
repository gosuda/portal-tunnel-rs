//! secp256k1 tenant-identity primitives.
//!
//! This module owns the three concerns that together form the tenant's
//! Ethereum / SIWE identity:
//!
//! - **[`key`]** — the [`TenantSecp256k1Key`] newtype and its sole constructor
//!   [`load_tenant_secp256k1_key`].  Key material is held behind
//!   `secrecy::SecretBox<TenantSecp256k1Key>` so secrets are zeroized on drop.
//!
//! - **[`address`]** — [`EthAddress`] newtype with EIP-55 mixed-case checksum
//!   `Display` impl, and [`evm_address_from_pubkey`] which derives the EVM
//!   address from a secp256k1 public key via Keccak-256.
//!
//! - **[`eip191`]** — [`sign_eip191_personal`] which produces a 65-byte
//!   Ethereum personal-message signature (`r || s || v`, `v ∈ {27, 28}`).

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `secp256k1` itself is declared `pub(crate)` in `lib.rs`, making an
// inner `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod address;
pub mod eip191;
pub mod key;
