//! Local self-signed provider stub.
//!
//! Phase 4 Batch 2 will land the rcgen-based ECDSA-P256 self-signed CA
//! per `docs/plans/2026-05-04-004-feat-portal-acme-plan.md` U3. This
//! module declares the public type so feature-gated callers can compile
//! against the eventual surface; every method returns
//! `AcmeError::Config("local provider not implemented in B1")`.

use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Local self-signed DNS-01-bypass provider.
///
/// Does not actually use DNS — the local provider is the
/// `--no-acme` shortcut for development that emits a self-signed cert
/// without contacting any CA. Phase 4 B1 ships only the type stub.
pub struct LocalProvider;

impl LocalProvider {
    /// Construct a stub local provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for LocalProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn upsert(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider not implemented in B1 (Phase 4 B2)".to_owned(),
        ))
    }

    async fn delete(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider not implemented in B1 (Phase 4 B2)".to_owned(),
        ))
    }

    async fn ensure_a_records(
        &self,
        _hostname: &str,
        _ipv4: std::net::Ipv4Addr,
    ) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider not implemented in B1 (Phase 4 B2)".to_owned(),
        ))
    }
}
