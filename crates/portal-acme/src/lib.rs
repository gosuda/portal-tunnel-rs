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
//! Phase 4 lands in batches per
//! `docs/plans/2026-05-04-004-feat-portal-acme-plan.md`. Per-batch
//! state lives in `PLAN.md` "Current implementation status" — Phase 4
//! is **partial-landed**:
//!
//! - **Landed**: B1 [`provider::DnsProvider`] trait + `SecretBox` cred
//!   newtypes + filesystem helpers ([`persist::write_atomic_with_mode`]);
//!   B2 [`providers::local::LocalProvider`] (rcgen self-signed dev
//!   path); B3 [`providers::cloudflare`]; B4 [`providers::route53`];
//!   B5 [`providers::gcloud`]; B6 (U8) [`Manager`] lifecycle façade
//!   with the local-self-signed path fully wired end-to-end.
//! - **Pending**: the `instant-acme` client wrapper that integrates
//!   the four DNS providers under [`Manager::ensure_certificate`] for
//!   the three ACME modes (`AcmeCloudflare`, `AcmeRoute53`,
//!   `AcmeGcloud`). Until that wrapper lands those dispatch arms
//!   return [`error::AcmeError::Config`] with the message
//!   `"<Mode> not implemented; waits on the instant-acme client wrapper"`.
//!
//! Phase 5/`portal-relay` consumes [`Manager`] directly. Local-mode
//! boot is unblocked as of B6 — the local-self-signed cert flow is
//! production-shape (atomic-rename, 0o600 mode, 10y validity); ACME
//! issuance against Let's Encrypt waits on the wrapper.

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

mod acme;
pub use acme::AcmeClient;
