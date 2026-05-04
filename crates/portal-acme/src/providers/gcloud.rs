//! Google Cloud DNS DNS-01 provider stub.
//!
//! Phase 4 Batch 5 will land the `google-cloud-dns-v1` native-SDK
//! wrapper per `docs/plans/2026-05-04-004-feat-portal-acme-plan.md` U7.
//! This module declares the public type so feature-gated callers can
//! compile against the eventual surface.

use crate::config::GcloudServiceAccount;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Google Cloud DNS provider.
pub struct GcloudProvider {
    #[expect(dead_code, reason = "consumed by B5 implementation")]
    service_account: GcloudServiceAccount,
}

impl GcloudProvider {
    /// Construct a stub Cloud DNS provider with the supplied service
    /// account JSON.
    #[must_use]
    pub const fn new(service_account: GcloudServiceAccount) -> Self {
        Self { service_account }
    }
}

impl DnsProvider for GcloudProvider {
    fn name(&self) -> &'static str {
        "gcloud"
    }

    async fn upsert(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "gcloud provider not implemented in B1 (Phase 4 B5)".to_owned(),
        ))
    }

    async fn delete(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "gcloud provider not implemented in B1 (Phase 4 B5)".to_owned(),
        ))
    }

    async fn ensure_a_records(
        &self,
        _hostname: &str,
        _ipv4: std::net::Ipv4Addr,
    ) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "gcloud provider not implemented in B1 (Phase 4 B5)".to_owned(),
        ))
    }
}
