//! Cloudflare DNS-01 provider stub.
//!
//! Phase 4 Batch 3 will land the `cloudflare = 0.14` REST-client
//! implementation per `docs/plans/2026-05-04-004-feat-portal-acme-plan.md`
//! U5. This module declares the public type so feature-gated callers
//! can compile against the eventual surface; every method returns
//! `AcmeError::Config("cloudflare provider not implemented in B1")`.

use crate::config::CloudflareToken;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Cloudflare DNS-01 provider.
pub struct CloudflareProvider {
    #[expect(dead_code, reason = "consumed by B3 implementation")]
    token: CloudflareToken,
}

impl CloudflareProvider {
    /// Construct a stub Cloudflare provider with the supplied token.
    #[must_use]
    pub const fn new(token: CloudflareToken) -> Self {
        Self { token }
    }
}

impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn upsert(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "cloudflare provider not implemented in B1 (Phase 4 B3)".to_owned(),
        ))
    }

    async fn delete(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "cloudflare provider not implemented in B1 (Phase 4 B3)".to_owned(),
        ))
    }

    async fn ensure_a_records(&self, _hostname: &str, _ipv4: std::net::Ipv4Addr) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "cloudflare provider not implemented in B1 (Phase 4 B3)".to_owned(),
        ))
    }
}
