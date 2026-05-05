//! AWS Route53 DNS-01 provider — drives the Route53 v2013-04-01 API via
//! the `aws-sdk-route53 = 1` SDK with `SigV4` request signing.
//!
//! # Method semantics
//!
//! - [`Route53Provider::upsert`]: hosted-zone lookup → single-shot
//!   `ChangeResourceRecordSets` with `Action::Upsert` (the
//!   `aws-sdk-route53` change-action enum). Route53's UPSERT
//!   primitive is atomically create-or-replace, so no list-first
//!   round trip is required (unlike Cloudflare). The trade-off is
//!   that UPSERT replaces all values for the (name, type) tuple,
//!   which is correct for singleton A records but **clobbers
//!   concurrent peer TXTs** — see the multi-valued caveat below.
//! - [`Route53Provider::delete`]: hosted-zone lookup → list existing
//!   record sets via `ListResourceRecordSets` → if a matching record
//!   exists, send `Action::Delete` with the **exact** resource record
//!   set (Route53 requires the existing values to match byte-for-byte
//!   on delete). If the list returns nothing, no-op. This makes
//!   delete idempotent without leaning on the AWS error-code surface.
//!   The same multi-valued-RRset caveat that applies to upsert applies
//!   here: deleting the matched `RRset` removes **all** of its values,
//!   so a concurrent peer TXT under the same name is collateral damage.
//!   Acceptable for v0.1 single-domain issuance; revisit alongside the
//!   merge-existing-values upsert path if multi-domain orders return.
//! - [`Route53Provider::ensure_a_records`]: upserts a single apex `A`
//!   record. Wildcard-A is reserved for v0.2; matches the local and
//!   Cloudflare provider surface.
//!
//! # Multi-valued TXT caveat (v0.1 limitation)
//!
//! Cloudflare's provider preserves concurrent peer TXT values for
//! multi-domain ACME issuance — UPSERT against a singleton-typed
//! resource record set in Route53 does not. For the v0.1 single-domain
//! issuance flow this is fine because the relay only ever publishes
//! one challenge token at a time. If multi-domain orders return to the
//! roadmap, the upsert path needs to fetch + merge existing values
//! before submitting the change. Tracked as a v0.2 concern alongside
//! Public Suffix List handling; not blocking Phase 4.
//!
//! # Hosted-zone lookup (v0.1 simplification)
//!
//! The private `Route53Provider::resolve_zone_id` method fetches
//! **only the first page** of `ListHostedZones` (1-100 zones) and
//! returns the zone whose `Name` equals `<parent_zone>.` (Route53
//! names are FQDNs with a trailing dot). Operators with ≥100 hosted
//! zones whose target zone lives on page 2+ will see an
//! `AcmeError::Config` "no Route53 zone for ..." error; pagination
//! is the v0.2 trigger.
//!
//! # Parent-zone resolution
//!
//! The private `parent_zone` helper takes the **last two labels**
//! of the FQDN, same posture as `cloudflare.rs`. PSL ccTLDs
//! (`co.uk`, `com.au`, ...) resolve incorrectly to the suffix;
//! deferred to v0.2.
//!
//! # Wiremock / `SigV4`
//!
//! Construct via [`Route53Provider::with_endpoint`] for tests; the
//! AWS SDK still signs requests with `SigV4`, but wiremock matchers
//! ignore the `Authorization` and `X-Amz-Date` headers since we
//! are not asserting signature shape — only the request body.

use std::net::Ipv4Addr;

use aws_sdk_route53::Client;
use aws_sdk_route53::config::{BehaviorVersion, Builder as ConfigBuilder, Credentials, Region};
use aws_sdk_route53::error::SdkError;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};

use crate::config::Route53Credentials;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Static identifier passed through to AWS SDK telemetry as the
/// "credential provider" name. Not a credential — just a label.
const PROVIDER_NAME: &str = "portal-acme";

/// Route53 region for the SDK request. Route53 is a global service
/// but the SDK requires a region in `Config`; `us-east-1` is the
/// canonical home region for control-plane operations.
const ROUTE53_HOME_REGION: &str = "us-east-1";

/// AWS Route53 DNS-01 provider.
///
/// Wraps an [`aws_sdk_route53::Client`] and exposes the
/// [`DnsProvider`] surface. Construct via [`Route53Provider::new`] for
/// production (default Route53 endpoint) or
/// [`Route53Provider::with_endpoint`] when tests need to point the
/// underlying HTTP client at a wiremock instance.
pub struct Route53Provider {
    client: Client,
}

impl Route53Provider {
    /// Construct a Route53 provider against the production Route53
    /// endpoint (`https://route53.amazonaws.com`).
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the SDK rejects the
    /// configuration (essentially never in practice with the supplied
    /// constants, but `Builder::build` is fallible).
    pub fn new(credentials: Route53Credentials) -> AcmeResult<Self> {
        Self::build(credentials, None)
    }

    /// Construct a Route53 provider with an explicit `endpoint_url`
    /// override. Tests pass a wiremock URL; production uses
    /// [`Route53Provider::new`] which lets the default endpoint
    /// resolver pick the global Route53 endpoint.
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the SDK rejects the
    /// configuration.
    pub fn with_endpoint(
        credentials: Route53Credentials,
        endpoint_url: String,
    ) -> AcmeResult<Self> {
        Self::build(credentials, Some(endpoint_url))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "constructors return `AcmeResult<Self>` for symmetry with the \
                  Cloudflare provider (whose underlying client constructor IS \
                  fallible), so callers can `?`-chain across providers"
    )]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value transfers ownership of the SecretBox-wrapped credentials; \
                  the inner Strings are consumed into AWS SDK Credentials and \
                  zeroized when their Arc<Inner> drops"
    )]
    fn build(credentials: Route53Credentials, endpoint_url: Option<String>) -> AcmeResult<Self> {
        let creds = Credentials::new(
            credentials.access_key_id().to_owned(),
            credentials.secret_access_key().to_owned(),
            None,
            None,
            PROVIDER_NAME,
        );
        let mut builder: ConfigBuilder = aws_sdk_route53::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(ROUTE53_HOME_REGION))
            .credentials_provider(creds);
        if let Some(url) = endpoint_url {
            builder = builder.endpoint_url(url);
        }
        let cfg = builder.build();
        Ok(Self {
            client: Client::from_conf(cfg),
        })
    }
}

impl DnsProvider for Route53Provider {
    fn name(&self) -> &'static str {
        "route53"
    }

    async fn upsert(&self, record: &DnsRecord) -> AcmeResult<()> {
        let rr_type = rr_type_from_record(record)?;
        let zone_id = self.resolve_zone_id(record.name.as_str()).await?;
        let rrset = build_resource_record_set(record, rr_type)?;
        let change = build_change(ChangeAction::Upsert, rrset)?;
        self.submit_change(&zone_id, change).await
    }

    async fn delete(&self, record: &DnsRecord) -> AcmeResult<()> {
        let rr_type = rr_type_from_record(record)?;
        let zone_id = self.resolve_zone_id(record.name.as_str()).await?;
        // Route53 requires the EXACT existing record set on delete, so
        // list-then-match before issuing the DELETE change. Idempotent:
        // an empty list is `Ok(())`.
        let Some(existing) = self
            .find_existing_record_set(
                &zone_id,
                record.name.as_str(),
                &rr_type,
                record.value.as_str(),
            )
            .await?
        else {
            return Ok(());
        };
        let change = build_change(ChangeAction::Delete, existing)?;
        self.submit_change(&zone_id, change).await
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

impl Route53Provider {
    /// Resolve the parent zone of `fqdn` to a Route53 hosted-zone id by
    /// listing zones and matching on `Name == "<parent>."`.
    async fn resolve_zone_id(&self, fqdn: &str) -> AcmeResult<String> {
        let parent = parent_zone(fqdn).ok_or_else(|| {
            AcmeError::Config(format!("cannot derive parent zone from name `{fqdn}`"))
        })?;
        let expected = format!("{parent}.");
        let response = self
            .client
            .list_hosted_zones()
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        let matched = response
            .hosted_zones()
            .iter()
            .find(|zone| zone.name() == expected);
        let zone = matched.ok_or_else(|| {
            AcmeError::Config(format!("no Route53 zone for `{parent}` (first page)"))
        })?;
        Ok(zone.id().to_owned())
    }

    /// Fetch the first page of resource record sets for the
    /// `(name, type)` tuple and return the one whose values include
    /// `value`. Returns `None` when nothing matches — caller treats
    /// that as a no-op (idempotent delete).
    async fn find_existing_record_set(
        &self,
        zone_id: &str,
        name: &str,
        rr_type: &RrType,
        value: &str,
    ) -> AcmeResult<Option<ResourceRecordSet>> {
        let response = self
            .client
            .list_resource_record_sets()
            .hosted_zone_id(zone_id)
            .start_record_name(name)
            .start_record_type(rr_type.clone())
            .max_items(1)
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        // Route53's start_record_name + start_record_type seek to a
        // lexicographic position; the returned page may include records
        // beyond the requested name. We post-filter to the exact tuple
        // and require the value to be present in the record set's
        // resource_records vector.
        let normalized_name = normalize_name(name);
        let owned = response.resource_record_sets().iter().find(|rrs| {
            normalize_name(rrs.name()) == normalized_name
                && rrs.r#type() == rr_type
                && rrs
                    .resource_records()
                    .iter()
                    .any(|rr| record_value_eq(rr.value(), value, rr_type))
        });
        Ok(owned.cloned())
    }

    async fn submit_change(&self, zone_id: &str, change: Change) -> AcmeResult<()> {
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| AcmeError::Dns(format!("route53 ChangeBatch build: {e}")))?;
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        Ok(())
    }
}

/// Translate a [`DnsRecord`] into a Route53 [`RrType`]. Only `A` and
/// `TXT` are supported in v0.1; matches the trait doc.
fn rr_type_from_record(record: &DnsRecord) -> AcmeResult<RrType> {
    match record.record_type.as_str() {
        "TXT" => Ok(RrType::Txt),
        "A" => Ok(RrType::A),
        other => Err(AcmeError::Config(format!(
            "route53 provider does not support record type `{other}` in v0.1 \
             (supported: TXT, A)"
        ))),
    }
}

/// Build a [`ResourceRecordSet`] for upsert/delete.
///
/// Route53 wraps TXT values in `"..."` quotes per RFC 1464 — the SDK
/// ships this through the wire literally, so the caller-supplied
/// `value` is wrapped here only for TXT and passed through verbatim
/// for A.
fn build_resource_record_set(record: &DnsRecord, rr_type: RrType) -> AcmeResult<ResourceRecordSet> {
    let value = match rr_type {
        RrType::Txt => quote_txt_value(record.value.as_str()),
        _ => record.value.to_string(),
    };
    let rr = ResourceRecord::builder()
        .value(value)
        .build()
        .map_err(|e| AcmeError::Dns(format!("route53 ResourceRecord build: {e}")))?;
    ResourceRecordSet::builder()
        .name(record.name.to_string())
        .r#type(rr_type)
        .ttl(i64::from(record.ttl))
        .resource_records(rr)
        .build()
        .map_err(|e| AcmeError::Dns(format!("route53 ResourceRecordSet build: {e}")))
}

fn build_change(action: ChangeAction, rrset: ResourceRecordSet) -> AcmeResult<Change> {
    Change::builder()
        .action(action)
        .resource_record_set(rrset)
        .build()
        .map_err(|e| AcmeError::Dns(format!("route53 Change build: {e}")))
}

/// Quote a TXT value per Route53's wire format. Idempotent — already-
/// quoted values pass through unchanged.
fn quote_txt_value(value: &str) -> String {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value.to_owned()
    } else {
        format!("\"{value}\"")
    }
}

/// Compare a stored TXT/A record value against the caller's
/// unquoted/quoted value, accounting for Route53's TXT quoting.
fn record_value_eq(stored: &str, caller: &str, rr_type: &RrType) -> bool {
    if matches!(rr_type, RrType::Txt) {
        stored == quote_txt_value(caller) || stored == caller
    } else {
        stored == caller
    }
}

/// Strip a trailing dot for case-insensitive Route53 name comparison.
/// Route53 returns names with a trailing `.`; callers pass either form.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Map an AWS SDK error into [`AcmeError::Dns`]. The SDK's `Display`
/// impl is documented as redaction-safe (no key material echoed); the
/// access-key-id is public-ish anyway and the secret never appears.
fn map_sdk_error<E, R>(err: &SdkError<E, R>) -> AcmeError
where
    E: std::fmt::Display,
{
    AcmeError::Dns(format!("route53 API: {err}"))
}

/// Take the **last two labels** of `fqdn` as the parent zone name.
///
/// Returns `None` when `fqdn` has fewer than two labels.
///
/// # Limitations
///
/// PSL-aware resolution deferred to v0.2; see module-level rustdoc
/// and the matching note in `cloudflare.rs`.
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
    fn quote_txt_value_wraps_unquoted() {
        assert_eq!(quote_txt_value("abc"), "\"abc\"");
    }

    #[test]
    fn quote_txt_value_passes_through_already_quoted() {
        assert_eq!(quote_txt_value("\"abc\""), "\"abc\"");
    }

    #[test]
    fn record_value_eq_matches_quoted_or_unquoted_txt() {
        let txt = RrType::Txt;
        assert!(record_value_eq("\"foo\"", "foo", &txt));
        assert!(record_value_eq("foo", "foo", &txt));
        assert!(!record_value_eq("\"foo\"", "bar", &txt));
    }

    #[test]
    fn normalize_name_strips_trailing_dot_and_lowers() {
        assert_eq!(normalize_name("Foo.Example.com."), "foo.example.com");
        assert_eq!(normalize_name("foo.example.com"), "foo.example.com");
    }
}
