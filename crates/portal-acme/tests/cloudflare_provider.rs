//! Wiremock contract test for [`CloudflareProvider`].
//!
//! Drives the provider against a fake Cloudflare REST API stood up via
//! `wiremock = 0.6`, exercising the three [`portal_acme::DnsProvider`]
//! methods (`upsert`, `delete`, `ensure_a_records`) plus the zone-lookup
//! step that all three share.
//!
//! # Why only the provider, not the full ACME flow?
//!
//! The plan's U5 also describes a full RFC 8555 order-flow test
//! (`tests/cloudflare_acme.rs` + a shared `tests/common/mod.rs` ACME
//! directory fixture). Landing that fixture now would prematurely fix
//! its shape before U6 (Route53) and U7 (Cloud DNS) get to share it,
//! so the order-flow fixture is deferred to whichever batch lands
//! second among the three providers. The provider-only contract test
//! here covers exactly the surface that `Manager` consumes — the
//! three trait methods — which is what matters for B3 acceptance.
//!
//! # Wiremock URL → cloudflare crate path resolution
//!
//! The cloudflare 0.14 crate joins endpoint paths via
//! `Url::parse(env_url).join(path)` where each endpoint's `path()` is
//! relative (`"zones"`, `"zones/{}/dns_records"`, etc — no leading
//! slash). That means with `Environment::Custom("http://127.0.0.1:N/")`
//! the request URLs become `http://127.0.0.1:N/zones[...]` — i.e. the
//! `/client/v4/` prefix the production environment adds is **not**
//! present when we override the environment. Wiremock matchers in this
//! file therefore match `/zones`, not `/client/v4/zones`.

#![cfg(feature = "cloudflare")]
#![expect(clippy::expect_used, reason = "test-only setup")]

use std::net::Ipv4Addr;

use compact_str::CompactString;
use portal_acme::config::CloudflareToken;
use portal_acme::provider::{DnsProvider, DnsRecord};
use portal_acme::providers::cloudflare::{CloudflareProvider, Environment};
use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ZONE_ID: &str = "ZONEID123456";
const RECORD_ID_TXT: &str = "TXTRECID000001";
const RECORD_ID_A: &str = "ARECID0000001";

/// Build a `Vec<Zone>`-shaped success body for `GET /zones?name=...`
/// containing exactly one zone matching `zone_name`.
fn zones_response(zone_name: &str, zone_id: &str) -> Value {
    let zone = json!({
        "id": zone_id,
        "name": zone_name,
        "account": { "id": "ACCT1", "name": "test-account" },
        "activated_on": "2024-01-01T00:00:00Z",
        "betas": null,
        "created_on": "2024-01-01T00:00:00Z",
        "deactivation_reason": null,
        "development_mode": 0,
        "host": null,
        "meta": {
            "custom_certificate_quota": 0,
            "page_rule_quota": 0,
            "phishing_detected": false
        },
        "modified_on": "2024-01-01T00:00:00Z",
        "name_servers": ["ns1.test", "ns2.test"],
        "original_dnshost": null,
        "original_name_servers": null,
        "original_registrar": null,
        "owner": { "type": "user", "id": "U1", "email": "user@test" },
        "paused": false,
        "permissions": [],
        "plan": null,
        "plan_pending": null,
        "status": "active",
        "vanity_name_servers": null,
        "type": "full",
    });
    api_success(json!([zone]))
}

/// Build an empty zones response (`result: []`).
fn empty_zones_response() -> Value {
    api_success(json!([]))
}

/// Build a `Vec<DnsRecord>`-shaped success body for
/// `GET /zones/{id}/dns_records?name=...`. `records` is a `Vec` of
/// per-record JSON objects already shaped to the cloudflare crate's
/// `DnsRecord` deserialize type (see [`txt_record`] and [`a_record`]).
fn dns_records_response(records: Value) -> Value {
    api_success(records)
}

/// Build a single TXT-typed `DnsRecord`-shaped JSON object.
fn txt_record(record_id: &str, name: &str, value: &str) -> Value {
    json!({
        "id": record_id,
        "meta": {},
        "name": name,
        "ttl": 60,
        "modified_on": "2024-01-01T00:00:00Z",
        "created_on": "2024-01-01T00:00:00Z",
        "proxiable": false,
        "type": "TXT",
        "content": value,
        "proxied": false,
    })
}

/// Build a single A-typed `DnsRecord`-shaped JSON object.
fn a_record(record_id: &str, name: &str, ip: &str) -> Value {
    json!({
        "id": record_id,
        "meta": {},
        "name": name,
        "ttl": 300,
        "modified_on": "2024-01-01T00:00:00Z",
        "created_on": "2024-01-01T00:00:00Z",
        "proxiable": false,
        "type": "A",
        "content": ip,
        "proxied": false,
    })
}

/// Wrap a `result` value in the cloudflare `ApiSuccess` envelope.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the `serde_json::json!` macro moves `result` into the constructed \
              object; clippy's heuristic does not see the move through the macro"
)]
fn api_success(result: Value) -> Value {
    json!({
        "result": result,
        "result_info": null,
        "success": true,
        "errors": [],
        "messages": [],
    })
}

/// Build a `CloudflareProvider` pointed at the wiremock instance.
fn provider_for(server: &MockServer) -> CloudflareProvider {
    let token = CloudflareToken::new("test-token".to_owned());
    // wiremock's `uri()` returns e.g. "http://127.0.0.1:54321" (no
    // trailing slash). The cloudflare crate parses this with
    // `url::Url::parse` so either form works; we pass-through.
    let env = Environment::Custom(server.uri());
    CloudflareProvider::with_environment(token, env).expect("provider construct")
}

// ---------------------------------------------------------------------------
// upsert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upsert_creates_when_record_absent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "_acme-challenge.example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_response(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(body_json(json!({
            "ttl": 60,
            "proxied": false,
            "name": "_acme-challenge.example.com",
            "type": "TXT",
            "content": "challenge-value-123",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(api_success(txt_record(
                RECORD_ID_TXT,
                "_acme-challenge.example.com",
                "challenge-value-123",
            ))),
        )
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
async fn upsert_noop_when_txt_value_already_present() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "_acme-challenge.example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(dns_records_response(json!([txt_record(
                RECORD_ID_TXT,
                "_acme-challenge.example.com",
                "challenge-value-123"
            )]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    // No POST/PUT/DELETE mocks — the provider must short-circuit
    // because the existing record matches exactly. Wiremock returns
    // 404 for any request not matching a mounted mock; an unintended
    // create/update would surface as an ApiFailure and fail the test.
    let provider = provider_for(&server);
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

#[tokio::test]
async fn upsert_creates_additional_txt_when_peer_value_present() {
    // Critical multi-valued-TXT semantic: a different challenge value
    // for the same `_acme-challenge.<host>` must NOT overwrite the
    // existing TXT — DNS-01 issuance for multi-domain orders pushes
    // multiple TXTs to the same name, one per SAN identifier. The
    // provider must POST (create) instead of PUT (update).
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "_acme-challenge.example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(dns_records_response(json!([txt_record(
                RECORD_ID_TXT,
                "_acme-challenge.example.com",
                "peer-value-AAA"
            )]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(body_json(json!({
            "ttl": 60,
            "proxied": false,
            "name": "_acme-challenge.example.com",
            "type": "TXT",
            "content": "new-value-BBB",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(api_success(txt_record(
                "TXTRECID000002",
                "_acme-challenge.example.com",
                "new-value-BBB",
            ))),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider = provider_for(&server);
    let record = DnsRecord {
        name: CompactString::from("_acme-challenge.example.com"),
        record_type: CompactString::from("TXT"),
        value: CompactString::from("new-value-BBB"),
        ttl: 60,
    };

    provider.upsert(&record).await.expect("upsert succeeds");
}

#[tokio::test]
async fn upsert_updates_a_record_when_value_differs() {
    // A records are singleton-per-host; an upsert with a different IP
    // must PUT (update) the existing record, not create a peer.
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "relay.example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(dns_records_response(json!([a_record(
                RECORD_ID_A,
                "relay.example.com",
                "10.0.0.1"
            )]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records/{RECORD_ID_A}")))
        .and(body_json(json!({
            "ttl": 300,
            "proxied": false,
            "name": "relay.example.com",
            "type": "A",
            "content": "203.0.113.7",
        })))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(api_success(a_record(
                RECORD_ID_A,
                "relay.example.com",
                "203.0.113.7",
            ))),
        )
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
async fn delete_removes_matching_record() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "_acme-challenge.example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(dns_records_response(json!([
                txt_record(
                    RECORD_ID_TXT,
                    "_acme-challenge.example.com",
                    "challenge-value-123"
                ),
                txt_record(
                    "UNRELATED",
                    "_acme-challenge.example.com",
                    "different-peer-value"
                ),
            ]))),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!(
            "/zones/{ZONE_ID}/dns_records/{RECORD_ID_TXT}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(api_success(json!({
            "id": RECORD_ID_TXT
        }))))
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
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(zones_response("example.com", ZONE_ID)),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/zones/{ZONE_ID}/dns_records")))
        .and(query_param("name", "_acme-challenge.example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dns_records_response(json!([]))))
        .expect(1)
        .mount(&server)
        .await;

    // No DELETE mock — the provider must not issue any DELETE because
    // there is nothing to delete. Any unintended request hits the
    // wiremock 404 default and bubbles up as an ApiFailure.
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
        .and(path("/zones"))
        .and(query_param("name", "example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(empty_zones_response()))
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
        msg.contains("no Cloudflare zone matches"),
        "unexpected error message: {msg}"
    );
}
