//! ACME (RFC 8555) issuance + DNS-01 providers for portal-tunnel-rs.
//!
//! See `crates/portal-acme/README.md` for the public-API summary and the
//! feature-flag matrix. Phase 5 (`portal-relay`) consumes the issued
//! `fullchain.pem` + `privatekey.pem` via on-disk handoff: this crate
//! atomically writes the files into the configured [`KeyDir`] and the
//! relay re-reads them on its own cadence. There is no in-process
//! handoff API across the phase boundary.
//!
//! ## Implementation status
//!
//! Phase 4 is landing in batches per
//! `docs/plans/2026-05-04-004-feat-portal-acme-plan.md`. Phase 4 Batch
//! 1 ships the trait surface ([`provider::DnsProvider`]), configuration
//! ([`config::AcmeConfig`]), and filesystem helpers
//! ([`persist::write_atomic_with_mode`]). Phase 4 Batch 2 ships the
//! local self-signed provider ([`providers::local::LocalProvider`]).
//! Phase 4 Batch 6 (U8) ships the [`Manager`] lifecycle façade with
//! the local-self-signed path fully wired; the ACME (Cloudflare,
//! Route53, Google Cloud) dispatch arms return
//! [`error::AcmeError::Config`] until B3-B5 + the `instant-acme`
//! client wrapper land. Phase 5 (`portal-relay`) consumes the
//! `Manager` directly — local-mode boot is unblocked as of B6.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod manager;
pub mod persist;
pub mod provider;

pub mod providers {
    //! DNS-01 provider implementations gated by per-provider features.

    #[cfg(feature = "cloudflare")]
    pub mod cloudflare;
    #[cfg(feature = "gcloud")]
    pub mod gcloud;
    #[cfg(feature = "local")]
    pub mod local;
    #[cfg(feature = "route53")]
    pub mod route53;
}

pub use config::{
    AcmeConfig, CloudflareToken, DirectoryUrl, GcloudServiceAccount, KeyDir, Route53Credentials,
};
pub use error::{AcmeError, AcmeResult};
pub use manager::{CertificateHandoff, Manager, Mode, ProviderSelector};
pub use provider::{DnsProvider, DnsRecord};
