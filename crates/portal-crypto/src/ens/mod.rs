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

pub mod alloy_resolver;

pub use alloy_resolver::{AlloyEnsResolver, EnsError, EnsResolver};
