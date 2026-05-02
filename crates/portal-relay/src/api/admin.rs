use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration as ChronoDuration;
use hyper::StatusCode;
use rand_core_06::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::api::{ApiReply, api_error_reply, decode_json, json_ok, method_not_allowed};
use crate::auth::identity::{Identity, normalize_identity};
use crate::auth::voucher::{ReservationVoucher, sign_reservation_voucher};
use crate::policy::{ApprovalMode, PolicyRuntime};
use crate::relay::AppState;
use crate::wire::paths::{
    PATH_ADMIN, PATH_ADMIN_APPROVAL, PATH_ADMIN_AUTH_STATUS, PATH_ADMIN_IPS_PREFIX,
    PATH_ADMIN_LANDING_PAGE, PATH_ADMIN_LEASES_PREFIX, PATH_ADMIN_LOGIN, PATH_ADMIN_LOGOUT,
    PATH_ADMIN_RESERVE, PATH_ADMIN_SNAPSHOT, PATH_ADMIN_TCP_PORT, PATH_ADMIN_UDP,
};

const ADMIN_COOKIE_NAME: &str = "portal_admin";
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub struct AdminState {
    auth: AdminAuth,
    pub policy: Arc<PolicyRuntime>,
}

impl AdminState {
    pub fn new(secret_key: String, policy: Arc<PolicyRuntime>) -> anyhow::Result<Self> {
        Ok(Self {
            auth: AdminAuth::new(secret_key)?,
            policy,
        })
    }

    fn is_authenticated(&self, headers: &[(String, String)]) -> bool {
        cookie_value(headers, ADMIN_COOKIE_NAME)
            .as_deref()
            .is_some_and(|token| self.auth.validate_session(token))
    }
}

struct AdminAuth {
    secret_key: String,
    sessions: Mutex<HashMap<String, Instant>>,
}

impl AdminAuth {
    fn new(secret_key: String) -> anyhow::Result<Self> {
        let secret_key = secret_key.trim().to_string();
        if secret_key.is_empty() {
            anyhow::bail!("admin secret key is required");
        }
        Ok(Self {
            secret_key,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn validate_key(&self, key: &str) -> bool {
        constant_time_eq(self.secret_key.as_bytes(), key.trim().as_bytes())
    }

    fn create_session(&self) -> String {
        let token = random_token();
        let mut sessions = self.sessions.lock().expect("admin sessions lock poisoned");
        let now = Instant::now();
        sessions.retain(|_, expires_at| *expires_at > now);
        sessions.insert(token.clone(), now + SESSION_TTL);
        token
    }

    fn validate_session(&self, token: &str) -> bool {
        let token = token.trim();
        if token.is_empty() {
            return false;
        }
        self.sessions
            .lock()
            .expect("admin sessions lock poisoned")
            .get(token)
            .is_some_and(|expires_at| *expires_at > Instant::now())
    }

    fn delete_session(&self, token: &str) {
        self.sessions
            .lock()
            .expect("admin sessions lock poisoned")
            .remove(token.trim());
    }
}

pub async fn handle_admin_request(
    state: Arc<AppState>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> ApiReply {
    match (method, path) {
        ("GET", PATH_ADMIN_AUTH_STATUS) => {
            return json_ok(
                StatusCode::OK,
                &AdminAuthStatusResponse {
                    authenticated: state.admin.is_authenticated(headers),
                    auth_enabled: true,
                },
            );
        }
        (_, PATH_ADMIN_AUTH_STATUS) => return method_not_allowed(),
        ("POST", PATH_ADMIN_LOGIN) => return handle_login(&state, body),
        (_, PATH_ADMIN_LOGIN) => return method_not_allowed(),
        ("POST", PATH_ADMIN_LOGOUT) => return handle_logout(&state, headers),
        (_, PATH_ADMIN_LOGOUT) => return method_not_allowed(),
        ("GET", PATH_ADMIN) => {
            return json_ok(
                StatusCode::OK,
                &serde_json::json!({"service": "portal-relay-admin"}),
            );
        }
        (_, PATH_ADMIN) => return method_not_allowed(),
        _ => {}
    }

    if !state.admin.is_authenticated(headers) {
        return api_error_reply(StatusCode::UNAUTHORIZED, "unauthorized", "unauthorized");
    }

    match (method, path) {
        ("GET", PATH_ADMIN_SNAPSHOT) => {
            let udp = state.admin.policy.udp_policy();
            let tcp_port = state.admin.policy.tcp_port_policy();
            json_ok(
                StatusCode::OK,
                &AdminSnapshotResponse {
                    approval_mode: state.admin.policy.approval_mode().as_str().to_string(),
                    landing_page_enabled: state.admin.policy.landing_page_enabled(),
                    leases: state.leases.admin_leases().await,
                    udp: PortSettingsResponse {
                        enabled: udp.enabled,
                        max_leases: udp.max_leases,
                    },
                    tcp_port: PortSettingsResponse {
                        enabled: tcp_port.enabled,
                        max_leases: tcp_port.max_leases,
                    },
                },
            )
        }
        (_, PATH_ADMIN_SNAPSHOT) => method_not_allowed(),
        ("POST", PATH_ADMIN_APPROVAL) => handle_approval_mode(&state, body),
        (_, PATH_ADMIN_APPROVAL) => method_not_allowed(),
        ("POST", PATH_ADMIN_LANDING_PAGE) => handle_landing_page(&state, body),
        (_, PATH_ADMIN_LANDING_PAGE) => method_not_allowed(),
        ("POST", PATH_ADMIN_UDP) => handle_port_settings(&state, body, PortKind::Udp),
        (_, PATH_ADMIN_UDP) => method_not_allowed(),
        ("POST", PATH_ADMIN_TCP_PORT) => handle_port_settings(&state, body, PortKind::Tcp),
        (_, PATH_ADMIN_TCP_PORT) => method_not_allowed(),
        ("POST", PATH_ADMIN_RESERVE) => handle_reserve(&state, body),
        (_, PATH_ADMIN_RESERVE) => method_not_allowed(),
        _ if path.starts_with(PATH_ADMIN_LEASES_PREFIX) => {
            handle_identity_action(&state, method, path, body)
        }
        _ if path.starts_with(PATH_ADMIN_IPS_PREFIX) => handle_ip_action(&state, method, path),
        _ => api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found"),
    }
}

fn handle_login(state: &AppState, body: &[u8]) -> ApiReply {
    let req = match decode_json::<AdminLoginRequest>(body) {
        Ok(req) => req,
        Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err),
    };
    if !state.admin.auth.validate_key(&req.key) {
        return api_error_reply(StatusCode::UNAUTHORIZED, "invalid_key", "Invalid key");
    }
    let token = state.admin.auth.create_session();
    let mut reply = json_ok(StatusCode::OK, &AdminLoginResponse { success: true });
    reply.headers.push((
        "Set-Cookie".to_string(),
        format!(
            "{ADMIN_COOKIE_NAME}={token}; Path=/admin; Max-Age=86400; HttpOnly; Secure; SameSite=Strict"
        ),
    ));
    reply
}

fn handle_logout(state: &AppState, headers: &[(String, String)]) -> ApiReply {
    if let Some(token) = cookie_value(headers, ADMIN_COOKIE_NAME) {
        state.admin.auth.delete_session(&token);
    }
    let mut reply = json_ok(StatusCode::OK, &serde_json::json!({}));
    reply.headers.push((
        "Set-Cookie".to_string(),
        format!("{ADMIN_COOKIE_NAME}=; Path=/admin; Max-Age=-1; HttpOnly; Secure; SameSite=Strict"),
    ));
    reply
}

fn handle_approval_mode(state: &AppState, body: &[u8]) -> ApiReply {
    let req = match decode_json::<AdminApprovalModeRequest>(body) {
        Ok(req) => req,
        Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err),
    };
    let Some(mode) = ApprovalMode::parse(&req.mode) else {
        return api_error_reply(
            StatusCode::BAD_REQUEST,
            "invalid_mode",
            "invalid mode (must be 'auto' or 'manual')",
        );
    };
    state.admin.policy.set_approval_mode(mode);
    save_policy_or_error(state).unwrap_or_else(|| {
        json_ok(
            StatusCode::OK,
            &AdminApprovalModeResponse {
                approval_mode: mode.as_str().to_string(),
            },
        )
    })
}

fn handle_landing_page(state: &AppState, body: &[u8]) -> ApiReply {
    let req = match decode_json::<LandingPageSettingsRequest>(body) {
        Ok(req) => req,
        Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err),
    };
    state.admin.policy.set_landing_page_enabled(req.enabled);
    save_policy_or_error(state).unwrap_or_else(|| {
        json_ok(
            StatusCode::OK,
            &LandingPageSettingsResponse {
                enabled: req.enabled,
            },
        )
    })
}

fn handle_port_settings(state: &AppState, body: &[u8], kind: PortKind) -> ApiReply {
    let req = match decode_json::<PortSettingsRequest>(body) {
        Ok(req) => req,
        Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err),
    };
    if req.max_leases < 0 {
        return api_error_reply(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "max_leases must be non-negative",
        );
    }
    let max_leases = req.max_leases as usize;
    match kind {
        PortKind::Udp => state.admin.policy.set_udp_policy(req.enabled, max_leases),
        PortKind::Tcp => state
            .admin
            .policy
            .set_tcp_port_policy(req.enabled, max_leases),
    }
    save_policy_or_error(state).unwrap_or_else(|| {
        json_ok(
            StatusCode::OK,
            &PortSettingsResponse {
                enabled: req.enabled,
                max_leases,
            },
        )
    })
}

/// EXPERIMENTAL: Issues a signed `ReservationVoucher` for a given client address.
/// Mirrors Go's `POST /admin/reserve`.
///
/// Issuance is capped by a process-lifetime budget
/// (see [`MAX_VOUCHER_BUDGET`](crate::relay::server::MAX_VOUCHER_BUDGET)): each *successful*
/// issuance permanently consumes one slot for the lifetime of the process. Failed attempts
/// (validation errors, signing errors) do NOT consume a slot — the acquired permit is
/// released so callers cannot exhaust the budget by replaying invalid requests.
fn handle_reserve(state: &AppState, body: &[u8]) -> ApiReply {
    let req = match decode_json::<AdminReserveRequest>(body) {
        Ok(req) => req,
        Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_request", &err),
    };
    if req.client_address.trim().is_empty() {
        return api_error_reply(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_address is required",
        );
    }
    // Normalize duration: clamp to [60s, 24h], default to 60s if unset or non-positive.
    let duration_secs = if req.requested_duration_seconds <= 0 {
        60_i64
    } else {
        req.requested_duration_seconds.clamp(60, 86_400)
    };
    // Acquire one slot from the process-lifetime issuance budget. The guard will release the
    // slot on drop; on success we explicitly forget it so the slot stays consumed for the
    // remainder of the process.
    let Some(guard) = state.voucher_budget.acquire() else {
        return api_error_reply(
            StatusCode::SERVICE_UNAVAILABLE,
            "capacity_exhausted",
            "reservation budget exhausted",
        );
    };
    let now = chrono::Utc::now();
    let voucher = ReservationVoucher {
        client_address: req.client_address.trim().to_string(),
        relay_url: state.portal_url.clone(),
        issued_at: now,
        expires_at: now + ChronoDuration::seconds(duration_secs),
        signature: Vec::new(),
    };
    match sign_reservation_voucher(voucher, &state.relay_identity.private_key) {
        Ok(signed) => {
            // Permanently consume the slot for this successful issuance.
            guard.consume();
            json_ok(StatusCode::OK, &signed)
        }
        Err(err) => {
            // Failed issuance: drop releases the slot so the budget is not depleted by errors.
            drop(guard);
            api_error_reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                &err.to_string(),
            )
        }
    }
}

fn handle_identity_action(state: &AppState, method: &str, path: &str, body: &[u8]) -> ApiReply {
    let rest = path.trim_start_matches(PATH_ADMIN_LEASES_PREFIX);
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 {
        return api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found");
    }
    let identity = match decode_identity_path(parts[0], parts[1]) {
        Ok(identity) => identity,
        Err((code, message)) => return api_error_reply(StatusCode::BAD_REQUEST, code, message),
    };
    let identity_key = identity.key();

    match (method, parts[2]) {
        ("POST", "ban") => state.admin.policy.ban_identity(&identity_key),
        ("DELETE", "ban") => state.admin.policy.unban_identity(&identity_key),
        ("POST", "approve") => state.admin.policy.approve_identity(&identity_key),
        ("DELETE", "approve") => state.admin.policy.revoke_identity(&identity_key),
        ("POST", "deny") => state.admin.policy.deny_identity(&identity_key),
        ("DELETE", "deny") => state.admin.policy.undeny_identity(&identity_key),
        ("POST", "bps") => {
            let req = match decode_json::<AdminBpsRequest>(body) {
                Ok(req) => req,
                Err(err) => return api_error_reply(StatusCode::BAD_REQUEST, "invalid_json", &err),
            };
            if req.bps <= 0 {
                return api_error_reply(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "bps must be greater than zero",
                );
            }
            state.admin.policy.set_identity_bps(&identity_key, req.bps);
        }
        ("DELETE", "bps") => state.admin.policy.delete_identity_bps(&identity_key),
        (_, "ban" | "approve" | "deny" | "bps") => return method_not_allowed(),
        _ => return api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found"),
    }

    save_policy_or_error(state).unwrap_or_else(|| json_ok(StatusCode::OK, &serde_json::json!({})))
}

fn handle_ip_action(state: &AppState, method: &str, path: &str) -> ApiReply {
    if !path.ends_with("/ban") {
        return api_error_reply(StatusCode::NOT_FOUND, "not_found", "not found");
    }
    let raw_ip = path
        .trim_start_matches(PATH_ADMIN_IPS_PREFIX)
        .trim_end_matches("/ban")
        .trim_matches('/');
    let ok = match method {
        "POST" => state.admin.policy.ban_ip(raw_ip),
        "DELETE" => state.admin.policy.unban_ip(raw_ip),
        _ => return method_not_allowed(),
    };
    if !ok {
        return api_error_reply(StatusCode::BAD_REQUEST, "invalid_ip", "invalid IP address");
    }
    save_policy_or_error(state).unwrap_or_else(|| json_ok(StatusCode::OK, &serde_json::json!({})))
}

fn save_policy_or_error(state: &AppState) -> Option<ApiReply> {
    state.admin.policy.save().err().map(|err| {
        api_error_reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            &err.to_string(),
        )
    })
}

fn decode_identity_path(
    name: &str,
    address: &str,
) -> Result<Identity, (&'static str, &'static str)> {
    let name = decode_base64_url(name).map_err(|_| ("invalid_request", "invalid identity"))?;
    let address = decode_base64_url(address).map_err(|_| ("invalid_address", "invalid address"))?;
    normalize_identity(&Identity {
        name,
        address,
        public_key: String::new(),
        private_key: String::new(),
    })
    .map_err(|_| ("invalid_request", "invalid identity"))
}

fn decode_base64_url(raw: &str) -> anyhow::Result<String> {
    let bytes = URL_SAFE_NO_PAD.decode(raw)?;
    Ok(String::from_utf8(bytes)?)
}

fn cookie_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let cookie = headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value.as_str())?;
    cookie.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name).then(|| value.to_string())
    })
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    key: String,
}

#[derive(Debug, Serialize)]
struct AdminLoginResponse {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    success: bool,
}

#[derive(Debug, Serialize)]
struct AdminAuthStatusResponse {
    authenticated: bool,
    auth_enabled: bool,
}

#[derive(Debug, Serialize)]
struct AdminSnapshotResponse {
    approval_mode: String,
    landing_page_enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    leases: Vec<crate::relay::leases::AdminLeaseView>,
    udp: PortSettingsResponse,
    tcp_port: PortSettingsResponse,
}

#[derive(Debug, Deserialize)]
struct AdminApprovalModeRequest {
    mode: String,
}

#[derive(Debug, Serialize)]
struct AdminApprovalModeResponse {
    approval_mode: String,
}

#[derive(Debug, Deserialize)]
struct LandingPageSettingsRequest {
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct LandingPageSettingsResponse {
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct PortSettingsRequest {
    enabled: bool,
    max_leases: i64,
}

#[derive(Debug, Serialize)]
struct PortSettingsResponse {
    enabled: bool,
    max_leases: usize,
}

#[derive(Debug, Deserialize)]
struct AdminBpsRequest {
    bps: i64,
}

#[derive(Debug, Deserialize)]
struct AdminReserveRequest {
    client_address: String,
    #[serde(default)]
    requested_duration_seconds: i64,
}

#[derive(Clone, Copy)]
enum PortKind {
    Udp,
    Tcp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_portal_admin_cookie() {
        let headers = vec![(
            "cookie".to_string(),
            "foo=bar; portal_admin=session; theme=dark".to_string(),
        )];
        assert_eq!(
            cookie_value(&headers, ADMIN_COOKIE_NAME),
            Some("session".to_string())
        );
    }
}
