//! Wiremock contract test for [`Route53Provider`].
//!
//! Drives the provider against a fake Route53 v2013-04-01 API stood
//! up via `wiremock = 0.6`, exercising the three
//! [`portal_acme::DnsProvider`] methods (`upsert`, `delete`,
//! `ensure_a_records`) plus the hosted-zone lookup that all three
//! share.
//!
//! # Why only the provider, not the full ACME flow?
//!
//! Per the deferred-shared-fixture posture documented in
//! `tests/cloudflare_provider.rs`: the full RFC 8555 order-flow test
//! shares a wiremock CA fixture across U5/U6/U7. Landing that fixture
//! before all three provider contracts are independently validated
//! would fix its shape prematurely. The provider-only contract here
//! covers the three trait methods that `Manager` consumes — sufficient
//! for B4 acceptance.
//!
//! # Wiremock + AWS SDK `SigV4`
//!
//! The AWS SDK signs every Route53 request with `SigV4`. Wiremock
//! matchers ignore the `Authorization` and `X-Amz-Date` headers
//! (we do not assert signature shape — only the request path, method,
//! and body). The mock responses must still be valid Route53 XML or
//! the SDK's XML deserializer will fail before the provider code sees
//! any data.
//!
//! # XML response shapes
//!
//! Route53 v2013-04-01 returns XML with element names that the SDK's
//! deserializer matches on — see the SDK's `protocol_serde/`
//! generated code for the canonical shape. The fixtures below match
//! those element names exactly (`ListHostedZonesResponse` with
//! `HostedZones > HostedZone > {Id, Name, CallerReference, Config}`,
//! `ChangeResourceRecordSetsResponse > ChangeInfo > {Id, Status,
//! SubmittedAt}`, etc.).

#![cfg(feature = "route53")]
#![expect(clippy::expect_used, reason = "test-only setup")]

use std::net::Ipv4Addr;

use compact_str::CompactString;
use portal_acme::config::Route53Credentials;
use portal_acme::provider::{DnsProvider, DnsRecord};
use portal_acme::providers::route53::Route53Provider;
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const HOSTED_ZONE_ID: &str = "Z1234567890ABC";
const ZONE_NAME_DOTTED: &str = "example.com.";
const RRSET_PATH_PREFIX: &str = "/2013-04-01/hostedzone/Z1234567890ABC/rrset";
const LIST_HOSTED_ZONES_PATH: &str = "/2013-04-01/hostedzone";

/// Build a `ListHostedZonesResponse` XML body containing exactly one
/// public hosted zone matching `zone_name`.
fn list_hosted_zones_xml(zone_name: &str, zone_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones>
    <HostedZone>
      <Id>/hostedzone/{zone_id}</Id>
      <Name>{zone_name}</Name>
      <CallerReference>portal-acme-test</CallerReference>
      <Config><PrivateZone>false</PrivateZone></Config>
      <ResourceRecordSetCount>2</ResourceRecordSetCount>
    </HostedZone>
  </HostedZones>
  <Marker></Marker>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListHostedZonesResponse>"#
    )
}

/// Build an empty `ListHostedZonesResponse` XML body.
fn empty_hosted_zones_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <HostedZones></HostedZones>
  <Marker></Marker>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListHostedZonesResponse>"#
        .to_owned()
}

/// Build a `ChangeResourceRecordSetsResponse` XML body — used as the
/// stub for both UPSERT and DELETE submissions.
fn change_resource_record_sets_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeInfo>
    <Id>/change/C1111111111111</Id>
    <Status>INSYNC</Status>
    <SubmittedAt>2026-05-04T00:00:00Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>"#
        .to_owned()
}

/// Build a `ListResourceRecordSetsResponse` XML body containing a
/// single TXT record. Used to stub the list-then-delete read.
fn list_rrset_with_txt_xml(name: &str, value: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>{name}</Name>
      <Type>TXT</Type>
      <TTL>60</TTL>
      <ResourceRecords>
        <ResourceRecord>
          <Value>"{value}"</Value>
        </ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>"#
    )
}

/// Build an empty `ListResourceRecordSetsResponse` — no record exists
/// at the queried (name, type) tuple.
fn list_rrset_empty_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets></ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>"#
        .to_owned()
}

fn xml_response(body: String) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Content-Type", "text/xml")
        .set_body_string(body)
}

/// Build a [`Route53Provider`] pointed at the wiremock instance.
fn provider_for(server: &MockServer) -> Route53Provider {
    let creds = Route53Credentials::new("AKIAEXAMPLE".to_owned(), "SECRETKEY".to_owned());
    Route53Provider::with_endpoint(creds, server.uri()).expect("provider construct")
}

// ---------------------------------------------------------------------------
// upsert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upsert_creates_txt_record() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_HOSTED_ZONES_PATH))
        .respond_with(xml_response(list_hosted_zones_xml(
            ZONE_NAME_DOTTED,
            HOSTED_ZONE_ID,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RRSET_PATH_PREFIX))
        .and(body_string_contains("<Action>UPSERT</Action>"))
        .and(body_string_contains(
            "<Name>_acme-challenge.example.com</Name>",
        ))
        .and(body_string_contains("<Type>TXT</Type>"))
        .and(body_string_contains("&quot;challenge-value-123&quot;"))
        .respond_with(xml_response(change_resource_record_sets_xml()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("challenge-value-123"),
        ttl: 60,
    };

    provider.upsert(&record).await.expect("upsert succeeds");
}

#[tokio::test]
async fn ensure_a_records_upserts_apex_a() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_HOSTED_ZONES_PATH))
        .respond_with(xml_response(list_hosted_zones_xml(
            ZONE_NAME_DOTTED,
            HOSTED_ZONE_ID,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RRSET_PATH_PREFIX))
        .and(body_string_contains("<Action>UPSERT</Action>"))
        .and(body_string_contains("<Name>relay.example.com</Name>"))
        .and(body_string_contains("<Type>A</Type>"))
        .and(body_string_contains("<Value>203.0.113.7</Value>"))
        .respond_with(xml_response(change_resource_record_sets_xml()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    provider
        .ensure_a_records("relay.example.com", Ipv4Addr::new(203, 0, 113, 7))
        .await
        .expect("ensure_a_records succeeds");
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_removes_existing_record() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_HOSTED_ZONES_PATH))
        .respond_with(xml_response(list_hosted_zones_xml(
            ZONE_NAME_DOTTED,
            HOSTED_ZONE_ID,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH_PREFIX))
        .and(query_param("name", "_acme-challenge.example.com"))
        .and(query_param("type", "TXT"))
        .respond_with(xml_response(list_rrset_with_txt_xml(
            "_acme-challenge.example.com.",
            "challenge-value-123",
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(RRSET_PATH_PREFIX))
        .and(body_string_contains("<Action>DELETE</Action>"))
        .and(body_string_contains(
            "<Name>_acme-challenge.example.com.</Name>",
        ))
        .and(body_string_contains("<Type>TXT</Type>"))
        .and(body_string_contains("&quot;challenge-value-123&quot;"))
        .respond_with(xml_response(change_resource_record_sets_xml()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("challenge-value-123"),
        ttl: 60,
    };

    provider.delete(&record).await.expect("delete succeeds");
}

#[tokio::test]
async fn delete_idempotent_when_record_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_HOSTED_ZONES_PATH))
        .respond_with(xml_response(list_hosted_zones_xml(
            ZONE_NAME_DOTTED,
            HOSTED_ZONE_ID,
        )))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(RRSET_PATH_PREFIX))
        .and(query_param("name", "_acme-challenge.example.com"))
        .and(query_param("type", "TXT"))
        .respond_with(xml_response(list_rrset_empty_xml()))
        .expect(1)
        .mount(&server)
        .await;

    // No POST mock — the provider must short-circuit because nothing
    // matches. Any unintended POST hits wiremock's 404 default and
    // bubbles up as an SDK error.
    let provider = provider_for(&server);
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("anything"),
        ttl: 60,
    };

    provider.delete(&record).await.expect("delete idempotent");
}

// ---------------------------------------------------------------------------
// zone resolution failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upsert_fails_when_zone_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_HOSTED_ZONES_PATH))
        .respond_with(xml_response(empty_hosted_zones_xml()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("v"),
        ttl: 60,
    };

    let err = provider.upsert(&record).await.expect_err("zone missing");
    let msg = err.to_string();
    assert!(
        msg.contains("no Route53 zone for"),
        "unexpected error message: {msg}"
    );
}
