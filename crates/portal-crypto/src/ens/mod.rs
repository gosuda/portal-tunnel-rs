//! ENS (Ethereum Name Service) resolution primitives.
//!
//! This module provides the [`EnsResolver`] trait and the production
//! [`AlloyEnsResolver`] implementation backed by `alloy-ens`.
//!
//! # Usage
//!
//! ```rust,no_run
//! use portal_crypto::{AlloyEnsResolver, EnsResolver};
//!
//! # async fn run() -> Result<(), portal_crypto::EnsError> {
//! let resolver = AlloyEnsResolver::from_rpc_url("https://mainnet.infura.io/v3/KEY").await?;
//! let addr = resolver.resolve("vitalik.eth").await?;
//! # Ok(())
//! # }
//! ```

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `ens` itself is declared `pub(crate)` in `lib.rs`, making an inner
// `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod alloy_resolver;
pub mod cache;

pub use alloy_resolver::{AlloyEnsResolver, BoxedEnsResolver, EnsError, EnsResolver};
pub use cache::{CachedEnsResolver, DEFAULT_ENS_CACHE_TTL};
