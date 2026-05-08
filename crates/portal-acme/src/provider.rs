//! `DnsProvider` async trait + `DnsRecord` value type.
//!
//! The trait is used by all four provider impls (Local, Cloudflare,
//! Route53, Gcloud) so the ACME flow can dispatch DNS-01 challenge
//! create/delete/sync calls without knowing the underlying API.

use compact_str::CompactString;

use crate::error::AcmeResult;

/// One DNS record. The provider is responsible for translating this
/// into the cloud-API-specific shape (Route53 `ChangeBatch`, Cloudflare
/// `dns_record`, Cloud DNS `Change`, etc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Fully-qualified domain name (no trailing dot).
    pub name: CompactString,
    /// Record type — `"TXT"` and `"A"` are the v0.1 set; future
    /// `"AAAA"` is reserved for v0.2.
    pub record_type: CompactString,
    /// Record value (TXT body, A IPv4 string, etc.).
    pub value: CompactString,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// DNS provider interface for ACME DNS-01 challenges.
///
/// All methods are async because the underlying cloud APIs are HTTP
/// REST clients. The trait uses explicit `impl Future` return types
/// (Rust 2024 RPIT in traits) rather than `async fn` so impls can
/// name the return type when needed.
pub trait DnsProvider: Send + Sync + 'static {
    /// Provider name for tracing / metrics (`"local"`, `"cloudflare"`,
    /// `"route53"`, `"gcloud"`).
    fn name(&self) -> &'static str;

    /// Create or update a DNS record. Idempotent — calling twice with
    /// the same input is a no-op or upsert.
    fn upsert<'a>(
        &'a self,
        record: &'a DnsRecord,
    ) -> impl core::future::Future<Output = AcmeResult<()>> + Send + 'a;

    /// Delete a DNS record. Returns `Ok(())` if the record does not
    /// exist (idempotent delete).
    fn delete<'a>(
        &'a self,
        record: &'a DnsRecord,
    ) -> impl core::future::Future<Output = AcmeResult<()>> + Send + 'a;

    /// Ensure the apex `A` records (and v0.1-not `AAAA`) for the given
    /// hostname point at the relay's public IP. The provider may
    /// upsert multiple records (e.g. a wildcard + apex).
    fn ensure_a_records<'a>(
        &'a self,
        hostname: &'a str,
        ipv4: std::net::Ipv4Addr,
    ) -> impl core::future::Future<Output = AcmeResult<()>> + Send + 'a;
}
