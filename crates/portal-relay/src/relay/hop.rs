use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(test)]
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use k256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::identity::{address_from_verifying_key, normalize_hostname};
use crate::config::normalize_relay_url;
use crate::relay::discovery::{canonical_descriptor_bytes, RelayDescriptor};
use crate::relay::leases::LeaseMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopRoute {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_public_key: String,
    pub relay_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub match_hostname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub match_token: String,
    #[serde(default, skip_serializing_if = "LeaseMetadata::is_empty")]
    pub metadata: LeaseMetadata,
    pub forward_relay: RelayDescriptor,
    pub forward_token: String,
    #[serde(default = "default_hop_route_first_seen_at")]
    pub first_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

fn default_hop_route_first_seen_at() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).expect("unix epoch timestamp is valid")
}

#[derive(Debug, thiserror::Error)]
pub enum HopRouteError {
    #[error("hop route signature is invalid")]
    SignatureInvalid,
    #[error("{0}")]
    Invalid(String),
}

pub fn verify_hop_route(method: &str, mut route: HopRoute) -> Result<HopRoute, HopRouteError> {
    let signature = route.signature.trim().to_string();
    route.signature.clear();
    let mut route = normalize_hop_route(route, true)?;
    let payload = canonical_hop_route_bytes(method, &route)?;
    verify_sha256_secp256k1_der(&payload, &route.owner_public_key, &signature)
        .map_err(|_| HopRouteError::SignatureInvalid)?;
    route.signature = signature;
    Ok(route)
}

#[cfg(test)]
fn sign_hop_route(
    method: &str,
    mut route: HopRoute,
    signing_key: &SigningKey,
    expires_at: DateTime<Utc>,
) -> anyhow::Result<HopRoute> {
    route.expires_at = expires_at;
    route.signature.clear();
    route.owner_public_key.clear();
    let mut route = normalize_hop_route(route, false).map_err(anyhow::Error::msg)?;
    route.owner_public_key = hex::encode(signing_key.verifying_key().to_encoded_point(true));
    let payload = canonical_hop_route_bytes(method, &route).map_err(anyhow::Error::msg)?;
    let digest = Sha256::digest(&payload);
    let signature: Signature = signing_key
        .sign_prehash(&digest)
        .context("sign hop route")?;
    route.signature = hex::encode(signature.to_der().as_bytes());
    Ok(route)
}

pub fn canonical_hop_route_bytes(method: &str, route: &HopRoute) -> Result<Vec<u8>, HopRouteError> {
    let forward_relay = canonical_descriptor_bytes(&route.forward_relay)
        .map_err(|err| HopRouteError::Invalid(err.to_string()))?;
    let forward_relay = std::str::from_utf8(&forward_relay)
        .map_err(|err| HopRouteError::Invalid(err.to_string()))?;
    let first_seen_at_unix_nano = go_unix_nano(route.first_seen_at);
    let expires_at_unix_nano = go_unix_nano(route.expires_at);
    let json = format!(
        concat!(
            "{{",
            "\"purpose\":{},",
            "\"method\":{},",
            "\"owner_public_key\":{},",
            "\"relay_url\":{},",
            "\"match_hostname\":{},",
            "\"match_token\":{},",
            "\"forward_relay\":{},",
            "\"forward_token\":{},",
            "\"first_seen_at_unix_nano\":{},",
            "\"expires_at_unix_nano\":{}",
            "}}"
        ),
        json_string("portal hop route v1"),
        json_string(&method.trim().to_ascii_uppercase()),
        json_string(route.owner_public_key.trim()),
        json_string(route.relay_url.trim()),
        json_string(route.match_hostname.trim()),
        json_string(route.match_token.trim()),
        forward_relay,
        json_string(route.forward_token.trim()),
        first_seen_at_unix_nano,
        expires_at_unix_nano,
    );
    Ok(json.into_bytes())
}

pub fn normalize_hop_route(
    mut route: HopRoute,
    require_owner: bool,
) -> Result<HopRoute, HopRouteError> {
    let owner_public_key = route
        .owner_public_key
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if owner_public_key.is_empty() {
        if require_owner {
            return Err(HopRouteError::Invalid(
                "hop route owner public key is required".to_string(),
            ));
        }
    } else {
        parse_secp256k1_public_key_hex(&owner_public_key)
            .map_err(|err| HopRouteError::Invalid(format!("hop route owner public key: {err}")))?;
    }

    route.owner_public_key = owner_public_key;
    route.relay_url = normalize_relay_url(&route.relay_url)
        .map_err(|err| HopRouteError::Invalid(format!("hop relay url: {err}")))?;
    route.match_hostname = normalize_hostname(&route.match_hostname);
    route.match_token = route.match_token.trim().to_string();
    route.forward_token = route.forward_token.trim().to_string();
    route.first_seen_at = route.first_seen_at.with_timezone(&Utc);
    route.expires_at = route.expires_at.with_timezone(&Utc);
    route.signature = route.signature.trim().to_string();
    Ok(route)
}

pub fn owner_address_from_hop_route(route: &HopRoute) -> anyhow::Result<String> {
    let key = parse_secp256k1_public_key_hex(&route.owner_public_key)?;
    Ok(address_from_verifying_key(&key))
}

fn verify_sha256_secp256k1_der(
    payload: &[u8],
    public_key_hex: &str,
    signature_hex: &str,
) -> anyhow::Result<()> {
    let public_key = parse_secp256k1_public_key_hex(public_key_hex)?;
    let signature_hex = signature_hex.trim().trim_start_matches("0x");
    if signature_hex.is_empty() {
        bail!("signature is required");
    }
    let signature = hex::decode(signature_hex).context("signature must be hex encoded")?;
    let signature = Signature::from_der(&signature).context("parse signature")?;
    let digest = Sha256::digest(payload);
    public_key
        .verify_prehash(&digest, &signature)
        .context("verify signature")
}

fn parse_secp256k1_public_key_hex(raw: &str) -> anyhow::Result<VerifyingKey> {
    let key = raw.trim().trim_start_matches("0x");
    if key.is_empty() {
        bail!("public key is required");
    }
    let decoded = hex::decode(key).context("public key must be hex encoded")?;
    VerifyingKey::from_sec1_bytes(&decoded).context("invalid secp256k1 public key")
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("json string serialization cannot fail")
}

fn go_unix_nano(time: DateTime<Utc>) -> i64 {
    time.timestamp()
        .wrapping_mul(1_000_000_000)
        .wrapping_add(i64::from(time.timestamp_subsec_nanos()))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::*;
    use crate::auth::identity::address_from_signing_key;
    use crate::relay::discovery::{sign_relay_descriptor, DISCOVERY_VERSION};

    fn signed_overlay_descriptor(now: DateTime<Utc>) -> (RelayDescriptor, SigningKey) {
        let key = SigningKey::random(&mut OsRng);
        let desc = RelayDescriptor {
            address: address_from_signing_key(&key),
            version: DISCOVERY_VERSION.to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            api_https_addr: "https://forward.example".to_string(),
            wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
            wireguard_port: 51820,
            supports_overlay: true,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
        };
        (
            sign_relay_descriptor(desc, &hex::encode(key.to_bytes())).unwrap(),
            key,
        )
    }

    #[test]
    fn canonical_hop_route_matches_go_field_order() {
        let now = Utc.timestamp_opt(10, 20).unwrap();
        let forward_relay = RelayDescriptor {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            version: DISCOVERY_VERSION.to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            api_https_addr: "https://forward.example".to_string(),
            wireguard_public_key: "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=".to_string(),
            wireguard_port: 51820,
            supports_overlay: true,
            supports_udp: false,
            supports_tcp: true,
            active_connections: 0,
            tcp_bps: 0.0,
            signature: String::new(),
        };
        let route = HopRoute {
            owner_public_key: "02abcdef".to_string(),
            relay_url: "https://relay.example".to_string(),
            match_hostname: "demo.localhost".to_string(),
            match_token: String::new(),
            metadata: LeaseMetadata::default(),
            forward_relay,
            forward_token: "hpt_token".to_string(),
            first_seen_at: now,
            expires_at: now + Duration::seconds(30),
            signature: String::new(),
        };
        let payload =
            String::from_utf8(canonical_hop_route_bytes("post", &route).unwrap()).unwrap();
        assert_eq!(
            payload,
            concat!(
                "{\"purpose\":\"portal hop route v1\",",
                "\"method\":\"POST\",",
                "\"owner_public_key\":\"02abcdef\",",
                "\"relay_url\":\"https://relay.example\",",
                "\"match_hostname\":\"demo.localhost\",",
                "\"match_token\":\"\",",
                "\"forward_relay\":{",
                "\"address\":\"0x0000000000000000000000000000000000000001\",",
                "\"version\":\"7\",",
                "\"issued_at_unix_nano\":10000000020,",
                "\"expires_at_unix_nano\":310000000020,",
                "\"api_https_addr\":\"https://forward.example\",",
                "\"wireguard_public_key\":\"L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=\",",
                "\"wireguard_port\":51820,",
                "\"supports_overlay\":true,",
                "\"supports_udp\":false,",
                "\"supports_tcp\":true,",
                "\"active_connections\":0,",
                "\"tcp_bps\":0",
                "},",
                "\"forward_token\":\"hpt_token\",",
                "\"first_seen_at_unix_nano\":10000000020,",
                "\"expires_at_unix_nano\":40000000020",
                "}"
            )
        );
    }

    #[test]
    fn verifies_signed_hop_route() {
        let now = Utc::now();
        let owner = SigningKey::random(&mut OsRng);
        let (forward_relay, _) = signed_overlay_descriptor(now);
        let route = HopRoute {
            owner_public_key: String::new(),
            relay_url: "https://relay.example/path".to_string(),
            match_hostname: "Demo.Localhost".to_string(),
            match_token: String::new(),
            metadata: LeaseMetadata::default(),
            forward_relay,
            forward_token: " hpt_token ".to_string(),
            first_seen_at: now,
            expires_at: now + Duration::seconds(30),
            signature: String::new(),
        };
        let signed = sign_hop_route("POST", route, &owner, now + Duration::seconds(30)).unwrap();
        let verified = verify_hop_route("post", signed).unwrap();
        assert_eq!(verified.relay_url, "https://relay.example");
        assert_eq!(verified.match_hostname, "demo.localhost");
        assert_eq!(verified.forward_token, "hpt_token");
        assert_eq!(
            owner_address_from_hop_route(&verified).unwrap(),
            address_from_signing_key(&owner)
        );
    }

    #[test]
    fn canonical_hop_route_uses_go_zero_time_unix_nano_wrapping() {
        let zero = chrono::NaiveDate::from_ymd_opt(1, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();

        assert_eq!(go_unix_nano(zero), -6795364578871345152);
        assert_eq!(
            go_unix_nano(zero - Duration::seconds(30)),
            -6795364608871345152
        );
    }

    #[test]
    fn verifies_delete_hop_route_with_go_zero_expiry() {
        let now = Utc::now();
        let zero = chrono::NaiveDate::from_ymd_opt(1, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        let owner = SigningKey::random(&mut OsRng);
        let (forward_relay, _) = signed_overlay_descriptor(now);
        let route = HopRoute {
            owner_public_key: String::new(),
            relay_url: "https://relay.example".to_string(),
            match_hostname: String::new(),
            match_token: "hpt_previous".to_string(),
            metadata: LeaseMetadata::default(),
            forward_relay,
            forward_token: "hpt_next".to_string(),
            first_seen_at: zero - Duration::seconds(30),
            expires_at: zero,
            signature: String::new(),
        };

        let signed = sign_hop_route("DELETE", route, &owner, zero).unwrap();
        let wire = serde_json::to_vec(&signed).unwrap();
        assert!(std::str::from_utf8(&wire)
            .unwrap()
            .contains("\"expires_at\":\"0001-01-01T00:00:00Z\""));
        assert!(std::str::from_utf8(&wire)
            .unwrap()
            .contains("\"first_seen_at\":\"0000-12-31T23:59:30Z\""));

        let decoded: HopRoute = serde_json::from_slice(&wire).unwrap();
        let verified = verify_hop_route("DELETE", decoded).unwrap();
        assert_eq!(verified.expires_at, zero);
        assert_eq!(verified.first_seen_at, zero - Duration::seconds(30));
        assert_eq!(verified.match_token, "hpt_previous");
    }

    #[test]
    fn verifies_go_signed_hop_route_fixture() {
        let route: HopRoute = serde_json::from_str(r#"{"owner_public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","relay_url":"https://rly.best","match_token":"hpt_prev_synthetic","metadata":{},"forward_relay":{"address":"0x1111111111111111111111111111111111111111","version":"6","issued_at":"2023-11-14T22:13:20.123456789Z","expires_at":"2023-11-14T22:18:20.123457776Z","api_https_addr":"https://s-h.day","wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","wireguard_port":51820,"supports_overlay":true,"supports_udp":true,"supports_tcp":true,"active_connections":3,"tcp_bps":12.5,"signature":"descriptor-signature-is-not-canonicalized"},"forward_token":"hpt_forward_synthetic","first_seen_at":"2023-11-14T22:17:50.222333444Z","expires_at":"2023-11-14T22:18:20.222333444Z","signature":"304402205088376396f1005075c6c9d0ae707187a25d2d0bd1c5ab33b92eb60dd9d98e3002204e4e97c01af14fb441a906f2ed9deabcb57fc1da37f653d48ccae92c81ca8849"}"#).unwrap();

        verify_hop_route("POST", route).unwrap();
    }

    #[test]
    fn verifies_go_signed_hop_route_with_go_json_float_fixture() {
        let route: HopRoute = serde_json::from_str(r#"{"owner_public_key":"0240b894395b95163678d6999458063196c488b31bda0fae30577a5c7a2eab605f","relay_url":"https://rly.best","match_token":"hpt_NPfWRDJVJ9QeYSFLWLUSNJuCaL2Uw5awhPxZ3M7GbGw","metadata":{},"forward_relay":{"address":"0x9DfAD4dEdaAe5A083e0025546572689E589528B7","version":"7","issued_at":"2026-05-02T04:44:35.854025467Z","expires_at":"2026-05-02T04:49:35.854025467Z","api_https_addr":"https://s-h.day","wireguard_public_key":"SNQ2hEOy+DERc//XvWNT/+nj2HbleFXuZMdecIZRRhM=","wireguard_port":51820,"supports_overlay":true,"supports_udp":true,"supports_tcp":true,"active_connections":472,"tcp_bps":45270.148289023724,"signature":"H5CQNoPzdzxJvGnBABK2NaK83LxJ0JernAoFPc/1N1wXOQoskv71d/aFuoaIAM9Z22ITnMIURjPHf0J6eV8CPfk="},"forward_token":"hpt_uxyk1J9SJeK2RzPsx4SKvnF3ZK3pm-WYnM3OogY5Pwk","first_seen_at":"2026-05-02T04:44:53.273277152Z","expires_at":"2026-05-02T04:45:23.273277152Z","signature":"304402206da725356c71c4a845028b5043c38254934cf7ef031ac60ea1ca50c114cb058702207822238fcf969d1d3f20bd01ce8c8f7ff347ec2a0efb4752b0e2483157542e7f"}"#).unwrap();

        verify_hop_route("POST", route).unwrap();
    }

    #[test]
    fn verifies_go_signed_delete_hop_route_fixture() {
        let route: HopRoute = serde_json::from_str(r#"{"owner_public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","relay_url":"https://rly.best","match_token":"hpt_prev_synthetic","metadata":{},"forward_relay":{"address":"0x1111111111111111111111111111111111111111","version":"6","issued_at":"2023-11-14T22:13:20.123456789Z","expires_at":"2023-11-14T22:18:20.123457776Z","api_https_addr":"https://s-h.day","wireguard_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","wireguard_port":51820,"supports_overlay":true,"supports_udp":true,"supports_tcp":true,"active_connections":3,"tcp_bps":12.5,"signature":"descriptor-signature-is-not-canonicalized"},"forward_token":"hpt_forward_synthetic","first_seen_at":"0000-12-31T23:59:30Z","expires_at":"0001-01-01T00:00:00Z","signature":"304402204b60cd53c71335cb1bb3b8ef74632314bd13760caf35006abd7a105dca3098d8022008d8de2e6a7aa5f74ce40d6435574e2da11350ee68ce7e847ef241235ae2629e"}"#).unwrap();

        verify_hop_route("DELETE", route).unwrap();
    }
}
