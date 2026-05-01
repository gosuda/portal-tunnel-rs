pub mod admin;
pub mod envelope;
pub mod frontend;
pub mod installer;
pub mod keyless;
pub mod paths;
pub mod sdk;

use std::sync::Arc;

use chrono::Utc;
use hyper::StatusCode;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::api::envelope::{api_error, api_ok};
use crate::api::keyless::{ErrorResponse, SignRequest};
use crate::api::paths::{
    PATH_ADMIN_PREFIX, PATH_APP, PATH_DISCOVERY, PATH_DISCOVERY_ANNOUNCE, PATH_HEALTHZ,
    PATH_INSTALL_BIN_PREFIX, PATH_INSTALL_POWERSHELL, PATH_INSTALL_SHELL, PATH_SDK_DOMAIN,
    PATH_SDK_HOP, PATH_SDK_REGISTER, PATH_SDK_REGISTER_CHALLENGE, PATH_SDK_RENEW,
    PATH_SDK_UNREGISTER, PATH_TUNNEL_STATUS, PATH_V1_SIGN,
};
use crate::api::sdk::DomainResponse;
use crate::relay::discovery::{
    verify_relay_descriptor, DiscoveryAnnounceRequest, DiscoveryAnnounceResponse, DISCOVERY_VERSION,
};
use crate::relay::hop::{verify_hop_route, HopRoute, HopRouteError};
use crate::relay::leases::{
    LeaseError, RegisterChallengeRequest, RegisterRequest, RenewRequest, UnregisterRequest,
};
use crate::relay::AppState;

pub struct ApiReply {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub async fn handle_request(
    state: Arc<AppState>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    client_ip: String,
    body: Vec<u8>,
) -> ApiReply {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let host = header_value(headers, "host").unwrap_or_else(|| state.portal_host.clone());
    if path == "/admin" || path.starts_with(PATH_ADMIN_PREFIX) {
        return admin::handle_admin_request(state, method, path, headers, &body).await;
    }

    match (method, path) {
        ("GET", PATH_HEALTHZ) => json_ok(StatusCode::OK, &HealthzResponse { status: "ok" }),
        (_, PATH_HEALTHZ) => method_not_allowed(),

        ("GET", PATH_SDK_DOMAIN) => {
            let mut response = json_ok(
                StatusCode::OK,
                &DomainResponse {
                    protocol_version: sdk::SDK_VERSION,
                    release_version: sdk::RELEASE_VERSION,
                },
            );
            response
                .headers
                .push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
            response
        }
        (_, PATH_SDK_DOMAIN) => method_not_allowed(),

        ("GET" | "HEAD", path)
            if state.frontend.is_none()
                && (path == "/" || path == PATH_APP || path == PATH_TUNNEL_STATUS) =>
        {
            if let Some(reply) =
                frontend::handle_builtin_request(state.as_ref(), method, path, query).await
            {
                return reply;
            }
            if method == "GET" && path == "/" {
                return json_ok(
                    StatusCode::OK,
                    &RootResponse {
                        service: "portal-relay",
                        root: &state.root_host,
                    },
                );
            }
            api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found")
        }

        ("GET" | "HEAD", PATH_INSTALL_SHELL) => {
            installer::install_script(&state.portal_url, method, false)
        }
        (_, PATH_INSTALL_SHELL) => method_not_allowed(),

        ("GET" | "HEAD", PATH_INSTALL_POWERSHELL) => {
            installer::install_script(&state.portal_url, method, true)
        }
        (_, PATH_INSTALL_POWERSHELL) => method_not_allowed(),

        ("GET" | "HEAD", path) if path.starts_with(PATH_INSTALL_BIN_PREFIX) => {
            installer::install_binary(path, method)
        }
        (_, path) if path.starts_with(PATH_INSTALL_BIN_PREFIX) => method_not_allowed(),

        ("GET", PATH_DISCOVERY) => match &state.discovery {
            Some(discovery) => match discovery.response(Utc::now()) {
                Ok(resp) => json_ok(StatusCode::OK, &resp),
                Err(err) => api_error_reply(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    &err.to_string(),
                ),
            },
            None => api_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "feature_unavailable",
                "relay discovery disabled",
            ),
        },
        (_, PATH_DISCOVERY) => method_not_allowed(),

        ("POST", PATH_DISCOVERY_ANNOUNCE) => match &state.discovery {
            Some(discovery) => match decode_json::<DiscoveryAnnounceRequest>(&body) {
                Ok(payload) => match discovery.announce(payload, Utc::now()) {
                    Ok(()) => json_ok(
                        StatusCode::ACCEPTED,
                        &DiscoveryAnnounceResponse {
                            protocol_version: DISCOVERY_VERSION.to_string(),
                            accepted: true,
                        },
                    ),
                    Err(err) => api_error_reply(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        &err.to_string(),
                    ),
                },
                Err(err) => invalid_json(err),
            },
            None => api_error_reply(
                StatusCode::SERVICE_UNAVAILABLE,
                "feature_unavailable",
                "relay discovery disabled",
            ),
        },
        (_, PATH_DISCOVERY_ANNOUNCE) => method_not_allowed(),

        ("POST", PATH_V1_SIGN) => match decode_json::<SignRequest>(&body) {
            Ok(payload) => match keyless::sign(payload, &state.keyless_signer) {
                Ok(resp) => raw_json(StatusCode::OK, &resp),
                Err(err) => raw_json(
                    StatusCode::BAD_REQUEST,
                    &ErrorResponse {
                        error: err.to_string(),
                    },
                ),
            },
            Err(_) => raw_json(
                StatusCode::BAD_REQUEST,
                &ErrorResponse {
                    error: "invalid json body".to_string(),
                },
            ),
        },
        (_, PATH_V1_SIGN) => raw_json(
            StatusCode::METHOD_NOT_ALLOWED,
            &ErrorResponse {
                error: "method not allowed".to_string(),
            },
        ),

        ("POST", PATH_SDK_REGISTER_CHALLENGE) => {
            match decode_json::<RegisterChallengeRequest>(&body) {
                Ok(payload) => {
                    if !payload.hop_token.trim().is_empty() && state.hop_mux.is_none() {
                        return api_error_reply(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "feature_unavailable",
                            "feature unavailable",
                        );
                    }
                    let register_uri = format!("https://{host}{PATH_SDK_REGISTER}");
                    match state.leases.issue_register_challenge(
                        payload,
                        &host,
                        &register_uri,
                        client_ip,
                    ) {
                        Ok(resp) => json_ok(StatusCode::CREATED, &resp),
                        Err(err) => lease_error(err),
                    }
                }
                Err(err) => invalid_json(err),
            }
        }
        (_, PATH_SDK_REGISTER_CHALLENGE) => method_not_allowed(),

        ("POST", PATH_SDK_REGISTER) => match decode_json::<RegisterRequest>(&body) {
            Ok(payload) => match state.leases.register(payload, client_ip) {
                Ok(resp) => json_ok(StatusCode::CREATED, &resp),
                Err(err) => lease_error(err),
            },
            Err(err) => invalid_json(err),
        },
        (_, PATH_SDK_REGISTER) => method_not_allowed(),

        ("POST", PATH_SDK_RENEW) => match decode_json::<RenewRequest>(&body) {
            Ok(payload) => match state.leases.renew(payload, client_ip) {
                Ok(resp) => json_ok(StatusCode::OK, &resp),
                Err(err) => lease_error(err),
            },
            Err(err) => invalid_json(err),
        },
        (_, PATH_SDK_RENEW) => method_not_allowed(),

        ("POST", PATH_SDK_UNREGISTER) => match decode_json::<UnregisterRequest>(&body) {
            Ok(payload) => match state.leases.unregister(payload) {
                Ok(()) => json_ok(StatusCode::OK, &serde_json::json!({})),
                Err(err) => lease_error(err),
            },
            Err(err) => invalid_json(err),
        },
        (_, PATH_SDK_UNREGISTER) => method_not_allowed(),

        ("POST", PATH_SDK_HOP) | ("DELETE", PATH_SDK_HOP) => {
            if state.hop_mux.is_none() {
                return api_error_reply(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "feature_unavailable",
                    "feature unavailable",
                );
            }
            match decode_json::<HopRoute>(&body) {
                Ok(payload) => match verify_hop_route(method, payload) {
                    Ok(mut route) => {
                        if route.relay_url != state.portal_url {
                            return api_error_reply(
                                StatusCode::FORBIDDEN,
                                "unauthorized",
                                "hop route relay url does not match receiving relay",
                            );
                        }
                        if method == "DELETE" {
                            match state.leases.delete_hop_route(&route) {
                                Ok(()) => json_ok(StatusCode::OK, &serde_json::json!({})),
                                Err(err) => lease_error(err),
                            }
                        } else {
                            match verify_relay_descriptor(route.forward_relay) {
                                Ok(forward_relay) => {
                                    route.forward_relay = forward_relay;
                                    match state.leases.register_hop_route(route, Utc::now()) {
                                        Ok(()) => json_ok(StatusCode::OK, &serde_json::json!({})),
                                        Err(err) => lease_error(err),
                                    }
                                }
                                Err(err) => api_error_reply(
                                    StatusCode::BAD_REQUEST,
                                    "invalid_request",
                                    &format!("forward relay: {err}"),
                                ),
                            }
                        }
                    }
                    Err(HopRouteError::SignatureInvalid) => api_error_reply(
                        StatusCode::FORBIDDEN,
                        "unauthorized",
                        "hop route signature is invalid",
                    ),
                    Err(HopRouteError::Invalid(message)) => {
                        api_error_reply(StatusCode::BAD_REQUEST, "invalid_request", &message)
                    }
                },
                Err(err) => invalid_json(err),
            }
        }
        (_, PATH_SDK_HOP) => method_not_allowed(),

        _ => {
            if let Some(frontend) = &state.frontend {
                if let Some(reply) = frontend
                    .handle_request(state.as_ref(), method, path, query)
                    .await
                {
                    return reply;
                }
            }
            api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found")
        }
    }
}

pub(crate) fn decode_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|err| err.to_string())
}

pub(crate) fn method_not_allowed() -> ApiReply {
    api_error_reply(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed",
    )
}

fn invalid_json(err: String) -> ApiReply {
    api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err)
}

fn lease_error(err: LeaseError) -> ApiReply {
    api_error_reply(err.status_code(), err.api_code(), &err.to_string())
}

pub(crate) fn json_ok<T: Serialize>(status: StatusCode, data: &T) -> ApiReply {
    json_reply(status, &api_ok(data))
}

pub fn api_error_reply(status: StatusCode, code: &str, message: &str) -> ApiReply {
    json_reply(status, &api_error(code, message))
}

fn json_reply<T: Serialize>(status: StatusCode, payload: &T) -> ApiReply {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    ApiReply {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
    }
}

fn raw_json<T: Serialize>(status: StatusCode, payload: &T) -> ApiReply {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{\"error\":\"internal\"}".to_vec());
    ApiReply {
        status,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
    }
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

#[derive(Debug, Serialize)]
struct HealthzResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct RootResponse<'a> {
    service: &'static str,
    root: &'a str,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use serde_json::json;

    use super::*;
    use crate::api::paths::{PATH_APP, PATH_SDK_HOP, PATH_SDK_REGISTER_CHALLENGE};
    use crate::auth::identity::{address_from_signing_key, compressed_public_key_hex};
    use crate::policy::PolicyRuntime;
    use crate::relay::leases::{LeaseRegistry, LeaseRegistryConfig};
    use crate::relay::AppState;
    use crate::state::identity::RelayIdentity;
    use crate::state::tls_material::load_or_create_tls_material;

    #[test]
    fn healthz_response_is_enveloped() {
        let response = json_ok(StatusCode::OK, &HealthzResponse { status: "ok" });
        assert_eq!(response.status, StatusCode::OK);
    }

    #[test]
    fn api_error_response_is_enveloped() {
        let payload = api_error("invalid_request", "bad input");
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            json!({
                "ok": false,
                "error": {
                    "code": "invalid_request",
                    "message": "bad input"
                }
            })
        );
    }

    #[test]
    fn healthz_response_matches_fixture() {
        let payload = api_ok(&HealthzResponse { status: "ok" });
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            read_fixture("api/healthz_success.json")
        );
    }

    #[test]
    fn sdk_domain_response_matches_fixture() {
        let payload = api_ok(&DomainResponse {
            protocol_version: sdk::SDK_VERSION,
            release_version: sdk::RELEASE_VERSION,
        });
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            read_fixture("api/sdk_domain_success.json")
        );
    }

    #[test]
    fn method_not_allowed_response_matches_fixture() {
        let payload = api_error("method_not_allowed", "method not allowed");
        assert_eq!(
            serde_json::to_value(payload).unwrap(),
            read_fixture("api/method_not_allowed.json")
        );
    }

    #[tokio::test]
    async fn sdk_hop_requires_hop_mux_runtime_before_decode() {
        let state = test_state();
        let response = handle_request(
            state,
            "POST",
            PATH_SDK_HOP,
            &[],
            "127.0.0.1".to_string(),
            b"not json".to_vec(),
        )
        .await;

        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["error"]["code"],
            "feature_unavailable"
        );
    }

    #[tokio::test]
    async fn hop_token_register_challenge_requires_hop_mux_runtime() {
        let state = test_state();
        let body = serde_json::to_vec(&json!({
            "identity": {
                "name": "demo",
                "address": "0x0000000000000000000000000000000000000001"
            },
            "hop_token": "hpt_exit"
        }))
        .unwrap();
        let response = handle_request(
            state,
            "POST",
            PATH_SDK_REGISTER_CHALLENGE,
            &[],
            "127.0.0.1".to_string(),
            body,
        )
        .await;

        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["error"]["code"],
            "feature_unavailable"
        );
    }

    #[tokio::test]
    async fn root_returns_json_when_builtin_landing_is_disabled() {
        let response = handle_request(
            test_state(),
            "GET",
            "/",
            &[],
            "127.0.0.1".to_string(),
            Vec::new(),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header_value(&response.headers, "Content-Type").as_deref(),
            Some("application/json")
        );
        let payload: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(payload["data"]["service"], "portal-relay");
        assert_eq!(payload["data"]["root"], "localhost");
    }

    #[tokio::test]
    async fn builtin_landing_serves_html_without_frontend_dist() {
        let state = test_state();
        state.admin.policy.set_landing_page_enabled(true);

        let response = handle_request(
            Arc::clone(&state),
            "GET",
            "/",
            &[],
            "127.0.0.1".to_string(),
            Vec::new(),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header_value(&response.headers, "Content-Type").as_deref(),
            Some("text/html; charset=utf-8")
        );
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("<!doctype html>"));
        assert!(body.contains("Portal Tunnel Relay"));
        assert!(body.contains("localhost"));
        assert!(body.contains(sdk::RELEASE_VERSION));
        assert!(body.contains("No public tunnels are listed"));

        let app = handle_request(
            state,
            "GET",
            PATH_APP,
            &[],
            "127.0.0.1".to_string(),
            Vec::new(),
        )
        .await;
        assert_eq!(app.status, StatusCode::OK);
        assert!(String::from_utf8(app.body)
            .unwrap()
            .contains("Portal Tunnel Relay"));
    }

    #[tokio::test]
    async fn builtin_landing_head_has_no_body() {
        let state = test_state();
        state.admin.policy.set_landing_page_enabled(true);

        let response =
            handle_request(state, "HEAD", "/", &[], "127.0.0.1".to_string(), Vec::new()).await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header_value(&response.headers, "Content-Type").as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert!(response.body.is_empty());
    }

    #[tokio::test]
    async fn frontend_serves_portal_html_when_dist_is_configured() {
        let dist = write_frontend_dist();
        let frontend = Arc::new(frontend::FrontendState::new(&dist).unwrap());
        let state = test_state_with_frontend(Some(frontend));
        state.admin.policy.set_landing_page_enabled(true);

        let response =
            handle_request(state, "GET", "/", &[], "127.0.0.1".to_string(), Vec::new()).await;

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("__SSR_DATA__"));
        assert!(body.contains("landing=true"));
        assert!(body.contains(sdk::RELEASE_VERSION));
    }

    #[tokio::test]
    async fn frontend_serves_assets_and_tunnel_status() {
        let dist = write_frontend_dist();
        let frontend = Arc::new(frontend::FrontendState::new(&dist).unwrap());
        let state = test_state_with_frontend(Some(frontend));

        let asset = handle_request(
            Arc::clone(&state),
            "GET",
            "/assets/app.js",
            &[],
            "127.0.0.1".to_string(),
            Vec::new(),
        )
        .await;
        assert_eq!(asset.status, StatusCode::OK);
        assert_eq!(asset.body, b"console.log('portal');");

        let status = handle_request(
            state,
            "GET",
            "/tunnel/status?hostname=demo.localhost",
            &[],
            "127.0.0.1".to_string(),
            Vec::new(),
        )
        .await;
        assert_eq!(status.status, StatusCode::OK);
        let payload: serde_json::Value = serde_json::from_slice(&status.body).unwrap();
        assert_eq!(payload["data"]["hostname"], "demo.localhost");
        assert_eq!(payload["data"]["registered"], false);
    }

    fn test_state() -> Arc<AppState> {
        test_state_with_frontend(None)
    }

    fn test_state_with_frontend(frontend: Option<Arc<frontend::FrontendState>>) -> Arc<AppState> {
        let signing_key = SigningKey::random(&mut OsRng);
        let relay = RelayIdentity {
            name: "localhost".to_string(),
            address: address_from_signing_key(&signing_key),
            public_key: compressed_public_key_hex(&signing_key),
            private_key: hex::encode(signing_key.to_bytes()),
            admin_secret_key: "admin".to_string(),
            wireguard_public_key: String::new(),
            wireguard_private_key: String::new(),
        };
        let unique = format!(
            "portal-api-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        );
        let identity_path = std::env::temp_dir().join(unique);
        let tls_material = load_or_create_tls_material(&identity_path, "localhost").unwrap();
        let policy = Arc::new(PolicyRuntime::load(&identity_path, false, false).unwrap());
        let leases = Arc::new(LeaseRegistry::new(LeaseRegistryConfig {
            root_host: "localhost".to_string(),
            relay,
            issuer: "https://localhost:4017".to_string(),
            sni_port: 443,
            udp_enabled: false,
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            policy: Arc::clone(&policy),
            metrics: Arc::new(crate::relay::bridge::RelayMetrics::default()),
        }));
        Arc::new(AppState {
            root_host: "localhost".to_string(),
            portal_host: "localhost".to_string(),
            portal_url: "https://localhost:4017".to_string(),
            leases,
            keyless_signer: tls_material.keyless_signer,
            admin: Arc::new(
                crate::api::admin::AdminState::new("admin".to_string(), policy).unwrap(),
            ),
            frontend,
            discovery: None,
            overlay: None,
            hop_mux: None,
            metrics: Arc::new(crate::relay::bridge::RelayMetrics::default()),
        })
    }

    fn write_frontend_dist() -> PathBuf {
        let unique = format!(
            "portal-frontend-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        );
        let dist = std::env::temp_dir().join(unique);
        let app = dist.join("app");
        fs::create_dir_all(app.join("assets")).unwrap();
        fs::write(
            app.join("portal.html"),
            "<html><head><title>[%RELEASE_VERSION%]</title></head><body>landing=[%LANDING_PAGE_ENABLED%]</body></html>",
        )
        .unwrap();
        fs::write(app.join("assets/app.js"), "console.log('portal');").unwrap();
        dist
    }

    fn read_fixture(path: &str) -> serde_json::Value {
        let fixture_path = workspace_fixture_path(path);
        let raw = fs::read_to_string(&fixture_path)
            .unwrap_or_else(|err| panic!("read fixture {}: {err}", fixture_path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("decode fixture {}: {err}", fixture_path.display()))
    }

    fn workspace_fixture_path(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/go")
            .join(path)
    }
}
