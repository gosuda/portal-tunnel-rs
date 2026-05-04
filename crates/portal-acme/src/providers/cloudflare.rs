//! Cloudflare DNS-01 provider — drives the Cloudflare REST API via the
//! official `cloudflare = 0.14` async client.
//!
//! # Method semantics
//!
//! - [`CloudflareProvider::upsert`]: zone lookup → list-by-name →
//!   noop / update / create.
//! - [`CloudflareProvider::delete`]: zone lookup → list-by-name →
//!   delete each match (idempotent: empty list ⇒ `Ok(())`).
//! - [`CloudflareProvider::ensure_a_records`]: upserts a single apex
//!   `A` record. The wildcard variant mentioned in the [`DnsProvider`]
//!   trait doc is reserved for v0.2; matches the local provider's
//!   v0.1 surface.
//!
//! # Zone resolution (v0.1 limitation)
//!
//! [`parent_zone`] takes the **last two labels** of the FQDN as the
//! zone name (e.g. `_acme-challenge.foo.bar.example.com` →
//! `example.com`). This is sufficient for the common
//! `<sub>.<apex>.<tld>` shape but **fails for Public-Suffix-List
//! ccTLDs** like `co.uk`, `com.au`, `org.uk`, etc. — `foo.example.co.uk`
//! would resolve to `co.uk`, which the operator does not own.
//! PSL-aware zone resolution is a v0.2 concern; production callers in
//! the meantime should use a generic-TLD apex or accept the limit.

use std::net::Ipv4Addr;

use cloudflare::endpoints::dns::dns::{
    CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, ListDnsRecords,
    ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
};
use cloudflare::endpoints::zones::zone::{ListZones, ListZonesParams};
pub use cloudflare::framework::Environment;
use cloudflare::framework::auth::Credentials;
use cloudflare::framework::client::ClientConfig;
use cloudflare::framework::client::async_api::Client;
use cloudflare::framework::response::ApiFailure;

use crate::config::CloudflareToken;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Cloudflare DNS-01 provider.
///
/// Wraps a [`cloudflare::framework::client::async_api::Client`] and
/// exposes the [`DnsProvider`] surface. Construct via
/// [`CloudflareProvider::new`] for production or
/// [`CloudflareProvider::with_environment`] when tests need to point
/// the underlying HTTP client at a wiremock instance.
pub struct CloudflareProvider {
    client: Client,
}

impl CloudflareProvider {
    /// Construct a Cloudflare provider against the production endpoint
    /// (`https://api.cloudflare.com/client/v4/`).
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the underlying `reqwest` client
    /// builder rejects the default configuration (essentially never in
    /// practice, but the cloudflare crate's constructor is fallible).
    pub fn new(token: CloudflareToken) -> AcmeResult<Self> {
        Self::with_environment(token, Environment::Production)
    }

    /// Construct a Cloudflare provider against an explicit
    /// [`Environment`]. Tests pass [`Environment::Custom(uri)`] with a
    /// wiremock URL; production uses [`Environment::Production`].
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the underlying `reqwest` client
    /// builder rejects the default configuration.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value transfers ownership of the SecretBox-wrapped token; \
                  the inner String is consumed into Credentials and zeroized on drop"
    )]
    pub fn with_environment(token: CloudflareToken, environment: Environment) -> AcmeResult<Self> {
        let credentials = Credentials::UserAuthToken {
            token: token.expose().to_owned(),
        };
        let client = Client::new(credentials, ClientConfig::default(), environment)
            .map_err(|e| AcmeError::Config(format!("cloudflare client init: {e}")))?;
        Ok(Self { client })
    }
}

impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn upsert(&self, record: &DnsRecord) -> AcmeResult<()> {
        let content = dns_content_from_record(record)?;
        let zone_id = self.resolve_zone_id(record.name.as_str()).await?;
        let existing = self
            .list_records_by_name(&zone_id, record.name.as_str())
            .await?;

        // Multi-valued vs singleton record-type semantics.
        //
        // TXT is **multi-valued**: DNS-01 issuance for a multi-domain
        // order legitimately produces several TXT records on the same
        // `_acme-challenge.<host>` (one key authorization per SAN).
        // Updating an existing peer's TXT would destroy a concurrent
        // challenge mid-flight. So for TXT we only ever (a) noop on
        // exact-content match, or (b) create a new record. Cleanup is
        // the responsibility of `delete`, which is content-scoped.
        //
        // A is **singleton** for our use case (one apex IP per host),
        // so update-on-mismatch is the correct upsert semantic.
        // AAAA / CNAME / etc. are not synthesized by `dns_content_from_record`
        // in v0.1 so we don't reach the singleton arm for them.
        let exact_match = existing
            .iter()
            .any(|r| dns_content_eq(&r.content, &content));
        if exact_match {
            return Ok(());
        }

        let is_singleton = matches!(&content, DnsContent::A { .. });
        let same_type_existing = if is_singleton {
            existing
                .iter()
                .find(|r| dns_content_kind(&r.content) == dns_content_kind(&content))
        } else {
            None
        };

        if let Some(found) = same_type_existing {
            let params = UpdateDnsRecordParams {
                ttl: Some(record.ttl),
                proxied: Some(false),
                name: record.name.as_str(),
                content,
            };
            let endpoint = UpdateDnsRecord {
                zone_identifier: &zone_id,
                identifier: &found.id,
                params,
            };
            self.client
                .request(&endpoint)
                .await
                .map_err(|e| map_api_failure(&e))?;
        } else {
            let params = CreateDnsRecordParams {
                ttl: Some(record.ttl),
                priority: None,
                proxied: Some(false),
                name: record.name.as_str(),
                content,
            };
            let endpoint = CreateDnsRecord {
                zone_identifier: &zone_id,
                params,
            };
            self.client
                .request(&endpoint)
                .await
                .map_err(|e| map_api_failure(&e))?;
        }
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> AcmeResult<()> {
        let content = dns_content_from_record(record)?;
        let zone_id = self.resolve_zone_id(record.name.as_str()).await?;
        let existing = self
            .list_records_by_name(&zone_id, record.name.as_str())
            .await?;

        for found in existing
            .iter()
            .filter(|r| dns_content_eq(&r.content, &content))
        {
            let endpoint = DeleteDnsRecord {
                zone_identifier: &zone_id,
                identifier: &found.id,
            };
            self.client
                .request(&endpoint)
                .await
                .map_err(|e| map_api_failure(&e))?;
        }

        Ok(())
    }

    async fn ensure_a_records(&self, hostname: &str, ipv4: Ipv4Addr) -> AcmeResult<()> {
        let record = DnsRecord {
            name: compact_str::CompactString::from(hostname),
            record_type: compact_str::CompactString::from("A"),
            value: compact_str::CompactString::from(ipv4.to_string()),
            ttl: 300,
        };
        self.upsert(&record).await
    }
}

impl CloudflareProvider {
    /// Resolve the parent zone of `fqdn` to a Cloudflare zone id by
    /// listing zones filtered on the parent name.
    async fn resolve_zone_id(&self, fqdn: &str) -> AcmeResult<String> {
        let parent = parent_zone(fqdn).ok_or_else(|| {
            AcmeError::Config(format!("cannot derive parent zone from name `{fqdn}`"))
        })?;
        let endpoint = ListZones {
            params: ListZonesParams {
                name: Some(parent.clone()),
                ..ListZonesParams::default()
            },
        };
        let response = self
            .client
            .request(&endpoint)
            .await
            .map_err(|e| map_api_failure(&e))?;
        let first =
            response.result.into_iter().next().ok_or_else(|| {
                AcmeError::Config(format!("no Cloudflare zone matches `{parent}`"))
            })?;
        Ok(first.id)
    }

    /// List DNS records for `zone_id` filtered by `name`. We do not
    /// pre-filter by `type` because the cloudflare crate's
    /// [`ListDnsRecordsParams::record_type`] requires a fully
    /// constructed [`DnsContent`] (which also carries the `content`
    /// value), defeating the purpose of a type-only filter. Callers
    /// post-filter on the returned slice.
    async fn list_records_by_name(
        &self,
        zone_id: &str,
        name: &str,
    ) -> AcmeResult<Vec<cloudflare::endpoints::dns::dns::DnsRecord>> {
        let endpoint = ListDnsRecords {
            zone_identifier: zone_id,
            params: ListDnsRecordsParams {
                name: Some(name.to_owned()),
                ..ListDnsRecordsParams::default()
            },
        };
        let response = self
            .client
            .request(&endpoint)
            .await
            .map_err(|e| map_api_failure(&e))?;
        Ok(response.result)
    }
}

/// Translate a [`DnsRecord`] into the cloudflare-crate's [`DnsContent`]
/// enum. Only `A` and `TXT` are supported in v0.1 (matches the trait
/// doc); `AAAA` is reserved for v0.2.
fn dns_content_from_record(record: &DnsRecord) -> AcmeResult<DnsContent> {
    match record.record_type.as_str() {
        "TXT" => Ok(DnsContent::TXT {
            content: record.value.to_string(),
        }),
        "A" => {
            let ip: Ipv4Addr = record.value.parse().map_err(|e| {
                AcmeError::Config(format!(
                    "cloudflare upsert: invalid IPv4 `{}`: {e}",
                    record.value
                ))
            })?;
            Ok(DnsContent::A { content: ip })
        }
        other => Err(AcmeError::Config(format!(
            "cloudflare provider does not support record type `{other}` in v0.1 \
             (supported: TXT, A)"
        ))),
    }
}

/// Coarse "kind" of a [`DnsContent`] — used to match an existing record
/// against an incoming request without comparing the value payload.
const fn dns_content_kind(content: &DnsContent) -> &'static str {
    match content {
        DnsContent::A { .. } => "A",
        DnsContent::AAAA { .. } => "AAAA",
        DnsContent::CNAME { .. } => "CNAME",
        DnsContent::NS { .. } => "NS",
        DnsContent::MX { .. } => "MX",
        DnsContent::TXT { .. } => "TXT",
        DnsContent::SRV { .. } => "SRV",
    }
}

/// Structural equality on [`DnsContent`]. The cloudflare crate does
/// not derive `PartialEq` on `DnsContent`, so we hand-roll the
/// per-variant comparison. v0.1 only inspects `A` and `TXT`; other
/// variants compare false against any incoming request because we
/// never construct them.
fn dns_content_eq(left: &DnsContent, right: &DnsContent) -> bool {
    match (left, right) {
        (DnsContent::A { content: l }, DnsContent::A { content: r }) => l == r,
        (DnsContent::TXT { content: l }, DnsContent::TXT { content: r }) => l == r,
        _ => false,
    }
}

/// Map a cloudflare-crate [`ApiFailure`] into [`AcmeError::Dns`]. The
/// cloudflare error `Display` is already redaction-safe (no token /
/// header echo), so direct stringification is acceptable.
fn map_api_failure(err: &ApiFailure) -> AcmeError {
    AcmeError::Dns(format!("cloudflare API: {err}"))
}

/// Take the **last two labels** of `fqdn` as the parent zone name.
///
/// Returns `None` when `fqdn` has fewer than two labels.
///
/// # Limitations
///
/// This is a deliberate v0.1 simplification — see the module-level
/// rustdoc. Public Suffix List zones (`co.uk`, `com.au`, etc.) are
/// resolved incorrectly to the suffix itself rather than the operator-
/// owned apex. PSL-aware resolution is deferred to v0.2.
pub(crate) fn parent_zone(fqdn: &str) -> Option<String> {
    let trimmed = fqdn.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let zone_labels = &labels[labels.len() - 2..];
    Some(zone_labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_zone_strips_subdomain_labels() {
        assert_eq!(
            parent_zone("_acme-challenge.example.com"),
            Some("example.com".to_owned())
        );
        assert_eq!(
            parent_zone("foo.bar.baz.example.com"),
            Some("example.com".to_owned())
        );
        assert_eq!(parent_zone("example.com"), Some("example.com".to_owned()));
    }

    #[test]
    fn parent_zone_returns_none_for_single_label() {
        assert_eq!(parent_zone("localhost"), None);
        assert_eq!(parent_zone(""), None);
    }

    #[test]
    fn parent_zone_strips_trailing_dot() {
        assert_eq!(
            parent_zone("foo.example.com."),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn dns_content_eq_matches_only_same_variant() {
        let txt_a = DnsContent::TXT {
            content: "hello".to_owned(),
        };
        let txt_b = DnsContent::TXT {
            content: "hello".to_owned(),
        };
        let txt_c = DnsContent::TXT {
            content: "world".to_owned(),
        };
        let a = DnsContent::A {
            content: Ipv4Addr::LOCALHOST,
        };
        assert!(dns_content_eq(&txt_a, &txt_b));
        assert!(!dns_content_eq(&txt_a, &txt_c));
        assert!(!dns_content_eq(&txt_a, &a));
    }
}
