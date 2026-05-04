//! Keyless signing oracle types.
//!
//! This module exposes the [`trait_def::KeylessSigningKey`] sync trait and the
//! [`newtype::KeylessSigningKeyHandle`] newtype that wraps it behind a
//! [`secrecy::SecretBox`].
//!
//! Public items are re-exported at the crate root by `lib.rs`.

pub mod newtype;
pub mod trait_def;

pub use newtype::{KeylessSigningKeyHandle, load_keyless_signing_key};
pub use trait_def::{KeylessError, KeylessSigningKey, SignatureScheme, SigningInput};
