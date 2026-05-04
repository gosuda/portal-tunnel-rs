//! Wiremock contract test for [`GcloudProvider`].
//!
//! Drives the provider against a fake Cloud DNS v1 API stood up via
//! `wiremock = 0.6`, exercising the three [`portal_acme::DnsProvider`]
//! methods (`upsert`, `delete`, `ensure_a_records`) plus the managed-zone
//! lookup that all three share.
//!
//! # Why only the provider, not the full ACME flow?
//!
//! Per the deferred-shared-fixture posture documented in
//! `tests/cloudflare_provider.rs` and `tests/route53_provider.rs`: the
//! full RFC 8555 order-flow test shares a wiremock CA fixture across
//! U5/U6/U7. Landing that fixture before all three provider contracts
//! are independently validated would fix its shape prematurely. The
//! provider-only contract here covers the three trait methods that
//! `Manager` consumes — sufficient for B5 acceptance.
//!
//! # Authentication path
//!
//! [`GcloudProvider::with_endpoint`] uses anonymous credentials (see the
//! module rustdoc on `providers::gcloud`), so no OAuth token endpoint
//! mock is required — the SDK injects empty auth headers. The
//! service-account JSON is parsed only for `project_id`. The
//! private-key field is a syntactically-valid PEM placeholder; it is
//! not exercised because the anonymous credential builder bypasses
//! token issuance entirely.
//!
//! # Cloud DNS REST endpoints touched
//!
//! - `GET  /dns/v1/projects/{project}/managedZones?dnsName=...`
//! - `GET  /dns/v1/projects/{project}/managedZones/{zone}/rrsets?name=...&type=...`
//! - `POST /dns/v1/projects/{project}/managedZones/{zone}/changes`
//!
//! Wiremock matchers ignore the SDK-injected `$alt=json`,
//! `x-goog-api-client`, `Host`, and other meta headers — only path,
//! method, query parameters, and request body shape are asserted.

#![cfg(feature = "gcloud")]
#![expect(clippy::expect_used, reason = "test-only setup")]

use std::net::Ipv4Addr;

use compact_str::CompactString;
use portal_acme::config::GcloudServiceAccount;
use portal_acme::provider::{DnsProvider, DnsRecord};
use portal_acme::providers::gcloud::GcloudProvider;
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PROJECT_ID: &str = "test-project-12345";
const ZONE_NAME: &str = "example-com-zone";
const ZONE_DNS_NAME: &str = "example.com.";

/// Service-account JSON skeleton. The `private_key` field carries a
/// syntactically-valid PKCS#8 placeholder so the JSON parses; the
/// anonymous-credentials path used by `with_endpoint` never reads it.
const FAKE_SERVICE_ACCOUNT_JSON: &str = r#"{
    "type": "service_account",
    "project_id": "test-project-12345",
    "private_key_id": "fake-key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+placeholder=\n-----END PRIVATE KEY-----\n",
    "client_email": "test@test-project-12345.iam.gserviceaccount.com",
    "client_id": "12345",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project-12345.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}"#;

/// Build a `ManagedZonesListResponse`-shaped JSON body containing
/// exactly one zone matching `dns_name`. Field names match the SDK's
/// JSON wire format (`dnsName`, `managedZones`, etc.).
fn managed_zones_list_response(zone_name: &str, dns_name: &str) -> Value {
    json!({
        "kind": "dns#managedZonesListResponse",
        "managedZones": [
            {
                "kind": "dns#managedZone",
                "name": zone_name,
                "dnsName": dns_name,
                "id": "1",
                "creationTime": "2024-01-01T00:00:00Z",
                "visibility": "public",
            }
        ]
    })
}

/// Build an empty `ManagedZonesListResponse`.
fn empty_managed_zones_list_response() -> Value {
    json!({
        "kind": "dns#managedZonesListResponse",
        "managedZones": []
    })
}

/// Build a `ResourceRecordSetsListResponse` with one rrset.
fn rrsets_list_response(name: &str, rr_type: &str, value: &str, ttl: i64) -> Value {
    json!({
        "kind": "dns#resourceRecordSetsListResponse",
        "rrsets": [
            {
                "kind": "dns#resourceRecordSet",
                "name": name,
                "type": rr_type,
                "ttl": ttl,
                "rrdatas": [value],
            }
        ]
    })
}

/// Build an empty `ResourceRecordSetsListResponse`.
fn empty_rrsets_list_response() -> Value {
    json!({
        "kind": "dns#resourceRecordSetsListResponse",
        "rrsets": []
    })
}

/// Stub `Change` response — wire shape returned by `Changes::create`.
fn change_response() -> Value {
    json!({
        "kind": "dns#change",
        "id": "1",
        "status": "done",
        "startTime": "2026-05-04T00:00:00Z",
    })
}

async fn provider_for(server: &MockServer) -> GcloudProvider {
    let svc = GcloudServiceAccount::new(FAKE_SERVICE_ACCOUNT_JSON.as_bytes().to_vec());
    GcloudProvider::with_endpoint(svc, server.uri())
        .await
        .expect("provider construct")
}

// ---------------------------------------------------------------------------
// upsert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upsert_creates_when_record_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "_acme-challenge.example.com."))
        .and(query_param("type", "TXT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_rrsets_list_response()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/changes"
        )))
        .and(body_partial_json(json!({
            "additions": [{
                "name": "_acme-challenge.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": ["\"challenge-value-123\""],
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(change_response()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("challenge-value-123"),
        ttl: 60,
    };

    provider.upsert(&record).await.expect("upsert succeeds");
}

#[tokio::test]
async fn upsert_replaces_when_record_value_differs() {
    // Cloud DNS Change semantics: an existing rrset is replaced
    // atomically by submitting `deletions: [old]` + `additions: [new]`
    // in the same Change. Exercises the upsert-replace path directly
    // via `provider.upsert(&record)` rather than going through
    // `ensure_a_records`, so the replace contract is asserted on the
    // method named in the failure case.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "_acme-challenge.example.com."))
        .and(query_param("type", "TXT"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(rrsets_list_response(
                "_acme-challenge.example.com.",
                "TXT",
                "\"old-challenge-value\"",
                60,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/changes"
        )))
        .and(body_partial_json(json!({
            "additions": [{
                "name": "_acme-challenge.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": ["\"new-challenge-value\""],
            }],
            "deletions": [{
                "name": "_acme-challenge.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": ["\"old-challenge-value\""],
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(change_response()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("new-challenge-value"),
        ttl: 60,
    };
    provider.upsert(&record).await.expect("upsert replaces");
}

// ---------------------------------------------------------------------------
// ensure_a_records
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ensure_a_records_upserts_apex_a() {
    // `ensure_a_records` is the apex-A convenience wrapper around
    // `upsert(record_type="A")`. Exercise it explicitly so the wiring
    // is asserted independently of the TXT upsert path covered above.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "relay.example.com."))
        .and(query_param("type", "A"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_rrsets_list_response()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/changes"
        )))
        .and(body_partial_json(json!({
            "additions": [{
                "name": "relay.example.com.",
                "type": "A",
                "ttl": 300,
                "rrdatas": ["203.0.113.7"],
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(change_response()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
    provider
        .ensure_a_records("relay.example.com", Ipv4Addr::new(203, 0, 113, 7))
        .await
        .expect("ensure_a_records succeeds");
}

#[tokio::test]
async fn upsert_noop_when_record_already_matches() {
    // Existing rrset already carries the desired value: short-circuit
    // before submitting a Change. No POST mock — wiremock's 404
    // default would surface any unintended write as an SDK error.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "_acme-challenge.example.com."))
        .and(query_param("type", "TXT"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(rrsets_list_response(
                "_acme-challenge.example.com.",
                "TXT",
                "\"challenge-value-123\"",
                60,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("challenge-value-123"),
        ttl: 60,
    };

    provider
        .upsert(&record)
        .await
        .expect("upsert noop succeeds");
}

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_removes_existing_record() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "_acme-challenge.example.com."))
        .and(query_param("type", "TXT"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(rrsets_list_response(
                "_acme-challenge.example.com.",
                "TXT",
                "\"challenge-value-123\"",
                60,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/changes"
        )))
        .and(body_partial_json(json!({
            "deletions": [{
                "name": "_acme-challenge.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": ["\"challenge-value-123\""],
            }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(change_response()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
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
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(managed_zones_list_response(ZONE_NAME, ZONE_DNS_NAME)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/dns/v1/projects/{PROJECT_ID}/managedZones/{ZONE_NAME}/rrsets"
        )))
        .and(query_param("name", "_acme-challenge.example.com."))
        .and(query_param("type", "TXT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_rrsets_list_response()))
        .expect(1)
        .mount(&server)
        .await;

    // No POST mock — the provider must short-circuit because nothing
    // matches. Any unintended POST hits wiremock's 404 default and
    // bubbles up as an SDK error.
    let provider = provider_for(&server).await;
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
        .and(path(format!("/dns/v1/projects/{PROJECT_ID}/managedZones")))
        .and(query_param("dnsName", ZONE_DNS_NAME))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_managed_zones_list_response()))
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server).await;
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("v"),
        ttl: 60,
    };

    let err = provider.upsert(&record).await.expect_err("zone missing");
    let msg = err.to_string();
    assert!(
        msg.contains("no Cloud DNS zone for"),
        "unexpected error message: {msg}"
    );
}
