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
//! `docs/plans/2026-05-04-004-feat-portal-acme-plan.md`. **The `Manager`
//! lifecycle façade and the `instant-acme` client wrapper do NOT yet
//! exist in this crate** — they are scheduled for unit U8 (Batch 6).
//! Phase 4 Batch 1 ships the trait surface
//! ([`provider::DnsProvider`]), configuration ([`config::AcmeConfig`]),
//! and filesystem helpers ([`persist::write_atomic_with_mode`]). Phase
//! 4 Batch 2 ships the local self-signed provider
//! ([`providers::local::LocalProvider`]). Subsequent batches add the
//! cloud-DNS providers and the `Manager` driver. Until U8 lands, callers
//! invoke the Local provider directly — there is no top-level façade
//! to consume.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod error;
pub mod persist;
pub mod provider;

pub mod providers {
    //! DNS-01 provider implementations gated by per-provider features.

    #[cfg(feature = "local")]
    pub mod local;
    #[cfg(feature = "cloudflare")]
    pub mod cloudflare;
    #[cfg(feature = "route53")]
    pub mod route53;
    #[cfg(feature = "gcloud")]
    pub mod gcloud;
}

pub use config::{
    AcmeConfig, CloudflareToken, DirectoryUrl, GcloudServiceAccount, KeyDir,
    Route53Credentials,
};
pub use error::{AcmeError, AcmeResult};
pub use provider::{DnsProvider, DnsRecord};
