//! ACME (RFC 8555) issuance + DNS-01 providers for portal-tunnel-rs.
//!
//! See `crates/portal-acme/README.md` for the public-API summary and the
//! feature-flag matrix. Phase 5 (`portal-relay`) consumes the issued
//! `fullchain.pem` + `privatekey.pem` via on-disk handoff: this crate
//! atomically writes the files into the configured [`KeyDir`] and the
//! relay re-reads them on its own cadence. There is no in-process
//! handoff API across the phase boundary.
//!
//! Batch 1 of Phase 4 ships only the trait surface, configuration, and
//! filesystem helpers; the `Manager` lifecycle façade and the
//! `instant-acme` client wrapper land in subsequent batches per
//! `docs/plans/2026-05-04-004-feat-portal-acme-plan.md` (units U3–U8).

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
