//! API HTTPS key types for the relay's API HTTPS surface.
//!
//! This module exposes [`key::ApiHttpsKey`] and its file-backed constructor
//! [`key::load_api_https_key`].  The signing-key accessor
//! [`key::signing_key`] is re-exported at the crate root as
//! [`api_https_signing_key`][crate::api_https_signing_key] to avoid ambiguity.
//!
//! Public items are re-exported at the crate root by `lib.rs`.

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `api_https` itself is declared `pub(crate)` in `lib.rs`, making an
// inner `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod key;

pub use key::{ApiHttpsKey, load_api_https_key, signing_key};
