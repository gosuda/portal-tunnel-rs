//! Keyless signing oracle types.
//!
//! This module exposes the [`trait_def::KeylessSigningKey`] sync trait and the
//! [`newtype::KeylessSigningKeyHandle`] newtype that wraps it behind a
//! [`secrecy::SecretBox`].
//!
//! Public items are re-exported at the crate root by `lib.rs`.

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `keyless` itself is declared `pub(crate)` in `lib.rs`, making an
// inner `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod newtype;
pub mod trait_def;

pub use newtype::{KeylessSigningKeyHandle, load_keyless_signing_key};
pub use trait_def::{KeylessError, KeylessSigningKey, SignatureScheme, SigningInput};
