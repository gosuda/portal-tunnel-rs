//! Google Cloud DNS DNS-01 provider — drives the Cloud DNS v1 API via the
//! native `google-cloud-dns-v1 = 1.3` SDK with OAuth 2.0 service-account
//! authentication.
//!
//! # Method semantics
//!
//! - [`GcloudProvider::upsert`]: managed-zone lookup via [`ManagedZones::list`]
//!   on the FQDN's parent → list existing rrset at `(name, type)` via
//!   [`ResourceRecordSets::list`] → submit a single atomic [`Change`] via
//!   [`Changes::create`] containing both `additions` (the new record) and
//!   `deletions` (the prior record, if any). Cloud DNS's `Change` API is the
//!   atomic create-or-replace primitive. For TXT we apply the same
//!   multi-valued caveat as `route53.rs`: the rrset replace consolidates all
//!   values for the (name, type) tuple, so concurrent peer TXTs would be
//!   collateral damage. Acceptable for v0.1 single-domain issuance.
//! - [`GcloudProvider::delete`]: zone lookup → list rrset → if a matching
//!   record exists, submit a `Change` with that rrset in `deletions`. Empty
//!   list ⇒ `Ok(())` (idempotent delete).
//! - [`GcloudProvider::ensure_a_records`]: upserts a single apex `A` record;
//!   wildcard-A is reserved for v0.2 (matches the local / Cloudflare / Route53
//!   provider surface).
//!
//! # Authentication
//!
//! Production callers pass a [`GcloudServiceAccount`] (the
//! `SecretBox`-wrapped service-account JSON bytes per SEC-012). The
//! `project_id` is parsed out of the JSON at construction time — service
//! accounts are project-scoped, so the project id is implicit in the
//! credential. The JSON is fed verbatim into
//! [`google_cloud_auth::credentials::service_account::Builder`], which
//! handles the OAuth 2.0 token exchange transparently for every SDK call.
//!
//! # Wiremock / [`GcloudProvider::with_endpoint`]
//!
//! The test path uses [`google_cloud_auth::credentials::anonymous::Builder`]
//! to skip the OAuth handshake entirely (anonymous credentials inject empty
//! request headers). Combined with `with_endpoint`, this lets the wiremock
//! fixture stand in for the real Cloud DNS API without round-tripping
//! through Google's OAuth endpoint. The service-account JSON is still
//! parsed for `project_id` (it is not exercised at runtime in tests).
//!
//! # Parent-zone resolution
//!
//! [`parent_zone`] takes the **last two labels** of the FQDN, same posture
//! as `cloudflare.rs` and `route53.rs`. PSL ccTLDs (`co.uk`, `com.au`, ...)
//! resolve incorrectly to the suffix; deferred to v0.2.
//!
//! # Hosted-zone (managed-zone) lookup (v0.1 simplification)
//!
//! [`GcloudProvider::resolve_zone_name`] requests one page of managed zones
//! filtered by `dnsName == "<parent>."` (Cloud DNS uses FQDN-with-trailing-
//! dot for the `dns_name` field). Operators with multiple zones at the same
//! `dns_name` (rare; usually a public + private split) get the first match.
//! Public/private discrimination is a v0.2 concern alongside PSL.

use std::net::Ipv4Addr;

use google_cloud_auth::credentials::Credentials;
use google_cloud_auth::credentials::anonymous::Builder as AnonymousBuilder;
use google_cloud_auth::credentials::service_account::Builder as ServiceAccountBuilder;
use google_cloud_dns_v1::Error as GcpError;
use google_cloud_dns_v1::client::{Changes, ManagedZones, ResourceRecordSets};
use google_cloud_dns_v1::model::{Change, ResourceRecordSet};

use crate::config::GcloudServiceAccount;
use crate::error::{AcmeError, AcmeResult};
use crate::provider::{DnsProvider, DnsRecord};

/// Google Cloud DNS DNS-01 provider.
///
/// Wraps the three native-SDK clients required by the [`DnsProvider`]
/// surface: [`ManagedZones`] for zone resolution, [`ResourceRecordSets`]
/// for read, and [`Changes`] for atomic rrset add/remove. Each holds an
/// internal `Arc` so the struct itself is cheap to clone (we do not — the
/// trait object is `Box<dyn DnsProvider>`).
pub struct GcloudProvider {
    managed_zones: ManagedZones,
    resource_record_sets: ResourceRecordSets,
    changes: Changes,
    project_id: String,
}

impl GcloudProvider {
    /// Construct a Cloud DNS provider against the production endpoint
    /// (`https://dns.googleapis.com/`) using the supplied service-account
    /// JSON. The JSON's `project_id` field is parsed at construction time
    /// and consumed in every subsequent API call.
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the service-account JSON is
    /// malformed, missing `project_id`, rejected by the Google auth
    /// builder, or the SDK's transport client fails to build.
    pub async fn new(service_account: GcloudServiceAccount) -> AcmeResult<Self> {
        let (project_id, credentials) = parse_service_account(&service_account)?;
        let managed_zones = ManagedZones::builder()
            .with_credentials(credentials.clone())
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        let resource_record_sets = ResourceRecordSets::builder()
            .with_credentials(credentials.clone())
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        let changes = Changes::builder()
            .with_credentials(credentials)
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        Ok(Self {
            managed_zones,
            resource_record_sets,
            changes,
            project_id,
        })
    }

    /// Construct a Cloud DNS provider with an explicit `endpoint_url`
    /// override and **anonymous** credentials (skips the OAuth token
    /// fetch). Tests pass a wiremock URL; production uses
    /// [`GcloudProvider::new`].
    ///
    /// The supplied service-account JSON is parsed for `project_id` only;
    /// its private key is not exercised because the anonymous credentials
    /// short-circuit the auth flow entirely. This matches the Route53
    /// `with_endpoint` shape (real credentials + wiremock URL) without
    /// requiring a syntactically-valid PKCS#8 PEM in tests.
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the service-account JSON is
    /// malformed or missing `project_id`, or the SDK's transport client
    /// fails to build against the given endpoint.
    pub async fn with_endpoint(
        service_account: GcloudServiceAccount,
        endpoint_url: String,
    ) -> AcmeResult<Self> {
        let project_id = parse_project_id(&service_account)?;
        let credentials: Credentials = AnonymousBuilder::new().build();
        let managed_zones = ManagedZones::builder()
            .with_endpoint(endpoint_url.clone())
            .with_credentials(credentials.clone())
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        let resource_record_sets = ResourceRecordSets::builder()
            .with_endpoint(endpoint_url.clone())
            .with_credentials(credentials.clone())
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        let changes = Changes::builder()
            .with_endpoint(endpoint_url)
            .with_credentials(credentials)
            .build()
            .await
            .map_err(|e| map_builder_error(&e))?;
        Ok(Self {
            managed_zones,
            resource_record_sets,
            changes,
            project_id,
        })
    }
}

impl DnsProvider for GcloudProvider {
    fn name(&self) -> &'static str {
        "gcloud"
    }

    async fn upsert(&self, record: &DnsRecord) -> AcmeResult<()> {
        let rr_type = rr_type_from_record(record)?;
        let zone_name = self.resolve_zone_name(record.name.as_str()).await?;
        let fqdn = fqdn_with_trailing_dot(record.name.as_str());
        let new_set = build_resource_record_set(record, rr_type)?;

        let existing = self
            .find_existing_record_set(&zone_name, &fqdn, rr_type)
            .await?;

        // No-op if the existing set already carries exactly the value we
        // want; the SDK rejects a Change whose additions match the wire
        // state, so short-circuiting here also avoids an unnecessary
        // round-trip.
        if let Some(ref existing_set) = existing
            && existing_set.rrdatas == new_set.rrdatas
            && existing_set.ttl == new_set.ttl
            && existing_set.r#type == new_set.r#type
        {
            return Ok(());
        }

        let mut change = Change::new().set_additions([new_set]);
        if let Some(prior) = existing {
            change = change.set_deletions([prior]);
        }
        self.submit_change(&zone_name, change).await
    }

    async fn delete(&self, record: &DnsRecord) -> AcmeResult<()> {
        let rr_type = rr_type_from_record(record)?;
        let zone_name = self.resolve_zone_name(record.name.as_str()).await?;
        let fqdn = fqdn_with_trailing_dot(record.name.as_str());
        let Some(existing) = self
            .find_existing_record_set(&zone_name, &fqdn, rr_type)
            .await?
        else {
            return Ok(());
        };
        let change = Change::new().set_deletions([existing]);
        self.submit_change(&zone_name, change).await
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

impl GcloudProvider {
    /// Resolve the parent zone of `fqdn` to a Cloud DNS managed-zone name
    /// by listing zones filtered on `dnsName == "<parent>."`.
    async fn resolve_zone_name(&self, fqdn: &str) -> AcmeResult<String> {
        let parent = parent_zone(fqdn).ok_or_else(|| {
            AcmeError::Config(format!("cannot derive parent zone from name `{fqdn}`"))
        })?;
        let dns_name = format!("{parent}.");
        let response = self
            .managed_zones
            .list()
            .set_project(self.project_id.clone())
            .set_dns_name(&dns_name)
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        let zone = response.managed_zones.into_iter().find(|z| {
            z.dns_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(&dns_name))
        });
        let name = zone
            .ok_or_else(|| AcmeError::Config(format!("no Cloud DNS zone for `{parent}`")))?
            .name
            .ok_or_else(|| AcmeError::Dns("Cloud DNS zone missing `name` field".to_owned()))?;
        Ok(name)
    }

    /// Fetch the rrset at `(fqdn, rr_type)` in `zone_name` and return it
    /// if present. Returns `None` when the API responds with an empty
    /// `rrsets` list — caller treats that as a no-op for delete and as
    /// "create" for upsert.
    async fn find_existing_record_set(
        &self,
        zone_name: &str,
        fqdn: &str,
        rr_type: RrType,
    ) -> AcmeResult<Option<ResourceRecordSet>> {
        let response = self
            .resource_record_sets
            .list()
            .set_project(self.project_id.clone())
            .set_managed_zone(zone_name.to_owned())
            .set_name(fqdn.to_owned())
            .set_type(rr_type.as_str())
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        Ok(response.rrsets.into_iter().next())
    }

    async fn submit_change(&self, zone_name: &str, change: Change) -> AcmeResult<()> {
        self.changes
            .create()
            .set_project(self.project_id.clone())
            .set_managed_zone(zone_name.to_owned())
            .set_body(change)
            .send()
            .await
            .map_err(|e| map_sdk_error(&e))?;
        Ok(())
    }
}

/// Coarse record-type discriminator. Mirrors the Cloud DNS REST `type`
/// field, which is a free-form string but constrained at the API layer
/// to the canonical DNS type names.
#[derive(Clone, Copy)]
enum RrType {
    Txt,
    A,
}

impl RrType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "TXT",
            Self::A => "A",
        }
    }
}

/// Translate a [`DnsRecord`] into an [`RrType`]. Only `A` and `TXT` are
/// supported in v0.1; matches the trait doc.
fn rr_type_from_record(record: &DnsRecord) -> AcmeResult<RrType> {
    match record.record_type.as_str() {
        "TXT" => Ok(RrType::Txt),
        "A" => Ok(RrType::A),
        other => Err(AcmeError::Config(format!(
            "gcloud provider does not support record type `{other}` in v0.1 \
             (supported: TXT, A)"
        ))),
    }
}

/// Build a Cloud DNS [`ResourceRecordSet`] for the supplied record.
///
/// Cloud DNS wraps TXT values in `"..."` quotes per RFC 1464 — same as
/// Route53. The wrap is idempotent so already-quoted values pass
/// through unchanged.
fn build_resource_record_set(record: &DnsRecord, rr_type: RrType) -> AcmeResult<ResourceRecordSet> {
    let value = match rr_type {
        RrType::Txt => quote_txt_value(record.value.as_str()),
        RrType::A => record.value.to_string(),
    };
    let ttl = i32::try_from(record.ttl).map_err(|e| {
        AcmeError::Config(format!(
            "gcloud upsert: ttl `{}` does not fit in i32: {e}",
            record.ttl
        ))
    })?;
    Ok(ResourceRecordSet::new()
        .set_name(fqdn_with_trailing_dot(record.name.as_str()))
        .set_type(rr_type.as_str())
        .set_ttl(ttl)
        .set_rrdatas([value]))
}

/// Quote a TXT value per Cloud DNS's wire format. Idempotent —
/// already-quoted values pass through unchanged. Same shape as
/// `route53.rs::quote_txt_value`.
fn quote_txt_value(value: &str) -> String {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value.to_owned()
    } else {
        format!("\"{value}\"")
    }
}

/// Cloud DNS uses fully-qualified domain names with a trailing dot for
/// rrset names (`example.com.` not `example.com`). Idempotent — input
/// already terminated in a dot is returned unchanged.
fn fqdn_with_trailing_dot(name: &str) -> String {
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

/// Parse the supplied JSON for a `project_id` string and a Google
/// `Credentials` instance built from the service-account body.
fn parse_service_account(
    service_account: &GcloudServiceAccount,
) -> AcmeResult<(String, Credentials)> {
    let value: serde_json::Value = serde_json::from_slice(service_account.json_bytes())
        .map_err(|e| AcmeError::Config(format!("gcloud service-account JSON: {e}")))?;
    let project_id = value
        .get("project_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            AcmeError::Config(
                "gcloud service-account JSON missing string field `project_id`".to_owned(),
            )
        })?
        .to_owned();
    let credentials = ServiceAccountBuilder::new(value)
        .build()
        .map_err(|e| AcmeError::Config(format!("gcloud credentials: {e}")))?;
    Ok((project_id, credentials))
}

/// Parse the supplied JSON for the `project_id` string only — used by
/// [`GcloudProvider::with_endpoint`] which constructs anonymous
/// credentials and therefore does not need the rest of the JSON body.
fn parse_project_id(service_account: &GcloudServiceAccount) -> AcmeResult<String> {
    let value: serde_json::Value = serde_json::from_slice(service_account.json_bytes())
        .map_err(|e| AcmeError::Config(format!("gcloud service-account JSON: {e}")))?;
    value
        .get("project_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            AcmeError::Config(
                "gcloud service-account JSON missing string field `project_id`".to_owned(),
            )
        })
}

/// Map a Google client-builder error into [`AcmeError::Config`]. The
/// builder error's `Display` impl is documented as redaction-safe.
fn map_builder_error(err: &google_cloud_gax::client_builder::Error) -> AcmeError {
    AcmeError::Config(format!("gcloud client builder: {err}"))
}

/// Map an SDK runtime error into [`AcmeError::Dns`]. The SDK's `Display`
/// impl is redaction-safe; service-account JSON content never appears
/// because credentials live in the auth layer, not in error context.
fn map_sdk_error(err: &GcpError) -> AcmeError {
    AcmeError::Dns(format!("gcloud API: {err}"))
}

/// Take the **last two labels** of `fqdn` as the parent zone name.
///
/// Returns `None` when `fqdn` has fewer than two labels.
///
/// # Limitations
///
/// PSL-aware resolution deferred to v0.2; see module-level rustdoc.
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
    fn fqdn_with_trailing_dot_appends_when_missing() {
        assert_eq!(fqdn_with_trailing_dot("example.com"), "example.com.");
        assert_eq!(fqdn_with_trailing_dot("example.com."), "example.com.");
    }
}
