//! AWS Route53 DNS-01 provider stub.
//!
//! Phase 4 Batch 4 will land the `aws-sdk-route53` wrapper per
//! `docs/plans/2026-05-04-004-feat-portal-acme-plan.md` U6. This module
//! declares the public type so feature-gated callers can compile
//! against the eventual surface.

use crate::config::Route53Credentials;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// AWS Route53 DNS-01 provider.
pub struct Route53Provider {
    #[expect(dead_code, reason = "consumed by B4 implementation")]
    credentials: Route53Credentials,
}

impl Route53Provider {
    /// Construct a stub Route53 provider with the supplied credentials.
    #[must_use]
    pub const fn new(credentials: Route53Credentials) -> Self {
        Self { credentials }
    }
}

impl DnsProvider for Route53Provider {
    fn name(&self) -> &'static str {
        "route53"
    }

    async fn upsert(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "route53 provider not implemented in B1 (Phase 4 B4)".to_owned(),
        ))
    }

    async fn delete(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "route53 provider not implemented in B1 (Phase 4 B4)".to_owned(),
        ))
    }

    async fn ensure_a_records(
        &self,
        _hostname: &str,
        _ipv4: std::net::Ipv4Addr,
    ) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "route53 provider not implemented in B1 (Phase 4 B4)".to_owned(),
        ))
    }
}
