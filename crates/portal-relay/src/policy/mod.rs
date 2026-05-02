use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    Auto,
    Manual,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "auto" => Some(Self::Auto),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PortPolicy {
    pub enabled: bool,
    pub max_leases: usize,
}

pub struct PolicyRuntime {
    path: PathBuf,
    inner: Mutex<PolicyState>,
}

#[derive(Debug, Clone)]
struct PolicyState {
    approval_mode: ApprovalMode,
    approved_identity_keys: HashSet<String>,
    denied_identity_keys: HashSet<String>,
    banned_identity_keys: HashSet<String>,
    banned_ips: HashSet<String>,
    identity_ips: HashMap<String, String>,
    identity_bps: HashMap<String, i64>,
    identity_bps_limiters: HashMap<String, BpsLimiter>,
    udp: PortPolicy,
    tcp_port: PortPolicy,
    landing_page_enabled: bool,
    trust_proxy_headers: bool,
    trusted_proxy_cidrs: Vec<IpNet>,
}

impl PolicyRuntime {
    #[cfg(test)]
    pub fn load(
        identity_path: &Path,
        udp_enabled: bool,
        tcp_port_enabled: bool,
    ) -> anyhow::Result<Self> {
        Self::load_with_landing_default(identity_path, udp_enabled, tcp_port_enabled, false)
    }

    pub fn load_with_landing_default(
        identity_path: &Path,
        udp_enabled: bool,
        tcp_port_enabled: bool,
        landing_page_enabled: bool,
    ) -> anyhow::Result<Self> {
        let path = admin_settings_path(identity_path);
        let mut state = PolicyState {
            approval_mode: ApprovalMode::Auto,
            approved_identity_keys: HashSet::new(),
            denied_identity_keys: HashSet::new(),
            banned_identity_keys: HashSet::new(),
            banned_ips: HashSet::new(),
            identity_ips: HashMap::new(),
            identity_bps: HashMap::new(),
            identity_bps_limiters: HashMap::new(),
            udp: PortPolicy {
                enabled: udp_enabled,
                max_leases: 0,
            },
            tcp_port: PortPolicy {
                enabled: tcp_port_enabled,
                max_leases: 0,
            },
            landing_page_enabled,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
        };

        if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("read admin settings {}", path.display()))?;
            let persisted: PersistedAdminState = serde_json::from_str(&raw)
                .with_context(|| format!("decode admin settings {}", path.display()))?;
            persisted.apply(&mut state)?;
        }

        Ok(Self {
            path,
            inner: Mutex::new(state),
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let payload = {
            let state = self.inner.lock().expect("policy runtime lock poisoned");
            PersistedAdminState::from_state(&state)
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create admin settings directory {}", parent.display()))?;
        }
        let raw = serde_json::to_vec_pretty(&payload).context("encode admin settings")?;
        fs::write(&self.path, raw)
            .with_context(|| format!("write admin settings {}", self.path.display()))?;
        Ok(())
    }

    pub fn approval_mode(&self) -> ApprovalMode {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .approval_mode
    }

    pub fn set_approval_mode(&self, mode: ApprovalMode) {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .approval_mode = mode;
    }

    pub fn landing_page_enabled(&self) -> bool {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .landing_page_enabled
    }

    pub fn set_landing_page_enabled(&self, enabled: bool) {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .landing_page_enabled = enabled;
    }

    pub fn udp_policy(&self) -> PortPolicy {
        self.inner.lock().expect("policy runtime lock poisoned").udp
    }

    pub fn set_udp_policy(&self, enabled: bool, max_leases: usize) {
        self.inner.lock().expect("policy runtime lock poisoned").udp = PortPolicy {
            enabled,
            max_leases,
        };
    }

    pub fn tcp_port_policy(&self) -> PortPolicy {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .tcp_port
    }

    pub fn set_tcp_port_policy(&self, enabled: bool, max_leases: usize) {
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .tcp_port = PortPolicy {
            enabled,
            max_leases,
        };
    }

    pub fn approve_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        if key.is_empty() {
            return;
        }
        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        state.approved_identity_keys.insert(key.clone());
        state.denied_identity_keys.remove(&key);
    }

    pub fn revoke_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .approved_identity_keys
            .remove(&key);
    }

    pub fn deny_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        if key.is_empty() {
            return;
        }
        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        state.denied_identity_keys.insert(key.clone());
        state.approved_identity_keys.remove(&key);
    }

    pub fn undeny_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .denied_identity_keys
            .remove(&key);
    }

    pub fn ban_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        if key.is_empty() {
            return;
        }
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .banned_identity_keys
            .insert(key);
    }

    pub fn unban_identity(&self, key: &str) {
        let key = normalize_identity_key(key);
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .banned_identity_keys
            .remove(&key);
    }

    pub fn ban_ip(&self, ip: &str) -> bool {
        let normalized = normalize_ip(ip);
        let Some(ip) = normalized else {
            return false;
        };
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .banned_ips
            .insert(ip);
        true
    }

    pub fn unban_ip(&self, ip: &str) -> bool {
        let normalized = normalize_ip(ip);
        let Some(ip) = normalized else {
            return false;
        };
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .banned_ips
            .remove(&ip);
        true
    }

    pub fn set_identity_bps(&self, key: &str, bps: i64) {
        let key = normalize_identity_key(key);
        if key.is_empty() {
            return;
        }
        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        if bps <= 0 {
            state.identity_bps.remove(&key);
            state.identity_bps_limiters.remove(&key);
            return;
        }
        state.identity_bps.insert(key.clone(), bps);
        state.identity_bps_limiters.remove(&key);
    }

    pub fn delete_identity_bps(&self, key: &str) {
        let key = normalize_identity_key(key);
        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        state.identity_bps.remove(&key);
        state.identity_bps_limiters.remove(&key);
    }

    pub fn reserve_identity_bps(&self, key: &str, max_bytes: usize) -> BpsReservation {
        let key = normalize_identity_key(key);
        if key.is_empty() || max_bytes == 0 {
            return BpsReservation::ready(max_bytes);
        }

        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        let bps = state.identity_bps.get(&key).copied().unwrap_or_default();
        if bps <= 0 {
            return BpsReservation::ready(max_bytes);
        }

        let chunk_size = bps_chunk_size(max_bytes, bps);
        let limiter = state.identity_bps_limiters.entry(key).or_default();
        BpsReservation {
            chunk_size,
            wait: limiter.reserve(chunk_size as f64, bps as f64),
        }
    }

    pub fn register_identity_ip(&self, key: &str, ip: &str) {
        let key = normalize_identity_key(key);
        let ip = ip.trim();
        if key.is_empty() || ip.is_empty() {
            return;
        }
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .identity_ips
            .insert(key, ip.to_string());
    }

    pub fn remove_identity_ip(&self, key: &str) {
        let key = normalize_identity_key(key);
        self.inner
            .lock()
            .expect("policy runtime lock poisoned")
            .identity_ips
            .remove(&key);
    }

    pub fn is_ip_banned(&self, ip: &str) -> bool {
        let ip = ip.trim();
        !ip.is_empty()
            && self
                .inner
                .lock()
                .expect("policy runtime lock poisoned")
                .banned_ips
                .contains(ip)
    }

    pub fn identity_status(&self, key: &str, client_ip: &str) -> IdentityPolicyStatus {
        let key = normalize_identity_key(key);
        let state = self.inner.lock().expect("policy runtime lock poisoned");
        let is_approved = state.approval_mode == ApprovalMode::Auto
            || state.approved_identity_keys.contains(&key);
        IdentityPolicyStatus {
            is_approved,
            is_banned: state.banned_identity_keys.contains(&key),
            is_denied: state.denied_identity_keys.contains(&key),
            is_ip_banned: !client_ip.trim().is_empty() && state.banned_ips.contains(client_ip),
            bps: state.identity_bps.get(&key).copied().unwrap_or_default(),
        }
    }

    pub fn is_identity_routable(&self, key: &str, client_ip: &str) -> bool {
        let status = self.identity_status(key, client_ip);
        status.is_approved && !status.is_banned && !status.is_denied && !status.is_ip_banned
    }

    pub fn set_proxy_trust(
        &self,
        trust_proxy_headers: bool,
        raw_trusted_proxy_cidrs: &str,
    ) -> anyhow::Result<()> {
        let trusted_proxy_cidrs =
            parse_cidrs(raw_trusted_proxy_cidrs).context("parse trusted proxy cidrs")?;
        let mut state = self.inner.lock().expect("policy runtime lock poisoned");
        state.trust_proxy_headers = trust_proxy_headers;
        state.trusted_proxy_cidrs = trusted_proxy_cidrs;
        Ok(())
    }

    pub fn extract_client_ip(
        &self,
        remote_addr: SocketAddr,
        headers: &[(String, String)],
    ) -> String {
        let (trust_proxy_headers, trusted_proxy_cidrs) = {
            let state = self.inner.lock().expect("policy runtime lock poisoned");
            (state.trust_proxy_headers, state.trusted_proxy_cidrs.clone())
        };

        if trust_proxy_headers && is_trusted_proxy(remote_addr.ip(), &trusted_proxy_cidrs) {
            if let Some(xff) = header_value(headers, "x-forwarded-for") {
                let first = xff.split_once(',').map(|(first, _)| first).unwrap_or(&xff);
                if let Some(ip) = normalize_client_ip_candidate(first) {
                    return ip;
                }
            }
            if let Some(xri) = header_value(headers, "x-real-ip")
                && let Some(ip) = normalize_client_ip_candidate(&xri) {
                    return ip;
                }
        }

        remote_addr.ip().to_string()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IdentityPolicyStatus {
    pub is_approved: bool,
    pub is_banned: bool,
    pub is_denied: bool,
    pub is_ip_banned: bool,
    pub bps: i64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedAdminState {
    #[serde(default)]
    approval_mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    approved_identity_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    denied_identity_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    banned_identity_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    banned_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    identity_bps: HashMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_max_leases: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_port_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_port_max_leases: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    landing_page_enabled: Option<bool>,
}

impl PersistedAdminState {
    fn apply(self, state: &mut PolicyState) -> anyhow::Result<()> {
        if !self.approval_mode.trim().is_empty() {
            state.approval_mode =
                ApprovalMode::parse(&self.approval_mode).context("invalid admin approval mode")?;
        }
        state.approved_identity_keys = normalized_key_set(self.approved_identity_keys);
        state.denied_identity_keys = normalized_key_set(self.denied_identity_keys);
        for key in &state.denied_identity_keys {
            state.approved_identity_keys.remove(key);
        }
        state.banned_identity_keys = normalized_key_set(self.banned_identity_keys);
        state.banned_ips = self
            .banned_ips
            .into_iter()
            .filter_map(|ip| normalize_ip(&ip))
            .collect();
        state.identity_bps = self
            .identity_bps
            .into_iter()
            .map(|(key, bps)| (normalize_identity_key(&key), bps))
            .filter(|(key, bps)| !key.is_empty() && *bps > 0)
            .collect();
        state.identity_bps_limiters.clear();
        if let Some(enabled) = self.udp_enabled {
            state.udp.enabled = enabled;
        }
        if let Some(max_leases) = self.udp_max_leases {
            state.udp.max_leases = max_leases;
        }
        if let Some(enabled) = self.tcp_port_enabled {
            state.tcp_port.enabled = enabled;
        }
        if let Some(max_leases) = self.tcp_port_max_leases {
            state.tcp_port.max_leases = max_leases;
        }
        if let Some(enabled) = self.landing_page_enabled {
            state.landing_page_enabled = enabled;
        }
        Ok(())
    }

    fn from_state(state: &PolicyState) -> Self {
        Self {
            approval_mode: state.approval_mode.as_str().to_string(),
            approved_identity_keys: sorted_strings(&state.approved_identity_keys),
            denied_identity_keys: sorted_strings(&state.denied_identity_keys),
            banned_identity_keys: sorted_strings(&state.banned_identity_keys),
            banned_ips: sorted_strings(&state.banned_ips),
            identity_bps: state.identity_bps.clone(),
            udp_enabled: Some(state.udp.enabled),
            udp_max_leases: Some(state.udp.max_leases),
            tcp_port_enabled: Some(state.tcp_port.enabled),
            tcp_port_max_leases: Some(state.tcp_port.max_leases),
            landing_page_enabled: Some(state.landing_page_enabled),
        }
    }
}

fn admin_settings_path(identity_path: &Path) -> PathBuf {
    match identity_path.file_name().and_then(|name| name.to_str()) {
        Some("identity.json") => identity_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("admin_settings.json"),
        _ => identity_path.join("admin_settings.json"),
    }
}

fn normalize_identity_key(key: &str) -> String {
    key.trim().to_ascii_lowercase()
}

fn normalized_key_set(keys: Vec<String>) -> HashSet<String> {
    keys.into_iter()
        .map(|key| normalize_identity_key(&key))
        .filter(|key| !key.is_empty())
        .collect()
}

fn normalize_ip(ip: &str) -> Option<String> {
    let ip = ip.trim();
    ip.parse::<IpAddr>().ok().map(|parsed| parsed.to_string())
}

fn parse_cidrs(raw: &str) -> anyhow::Result<Vec<IpNet>> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| IpNet::from_str(item).with_context(|| format!("parse cidr {item:?}")))
        .collect()
}

fn is_trusted_proxy(remote_ip: IpAddr, configured: &[IpNet]) -> bool {
    let defaults;
    let networks = if configured.is_empty() {
        defaults = default_trusted_proxy_cidrs();
        defaults.as_slice()
    } else {
        configured
    };
    networks.iter().any(|cidr| cidr.contains(&remote_ip))
}

fn default_trusted_proxy_cidrs() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .map(|cidr| IpNet::from_str(cidr).expect("default trusted proxy cidr must parse"))
    .collect()
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn normalize_client_ip_candidate(raw: &str) -> Option<String> {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return None;
    }
    if let Ok(ip) = candidate.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let (host, _) = candidate.rsplit_once(':')?;
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

fn sorted_strings(values: &HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = values.iter().cloned().collect();
    out.sort();
    out
}

#[derive(Debug, Clone, Copy)]
pub struct BpsReservation {
    pub chunk_size: usize,
    pub wait: Duration,
}

impl BpsReservation {
    fn ready(chunk_size: usize) -> Self {
        Self {
            chunk_size,
            wait: Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
struct BpsLimiter {
    tokens: f64,
    updated_at: Option<Instant>,
}

impl Default for BpsLimiter {
    fn default() -> Self {
        Self {
            tokens: 0.0,
            updated_at: None,
        }
    }
}

impl BpsLimiter {
    fn reserve(&mut self, bytes: f64, bps: f64) -> Duration {
        let now = Instant::now();
        if let Some(updated_at) = self.updated_at {
            let elapsed = now.saturating_duration_since(updated_at).as_secs_f64();
            if elapsed > 0.0 {
                self.tokens += elapsed * bps;
                self.updated_at = Some(now);
            }
        } else {
            self.updated_at = Some(now);
        }
        if self.tokens > bps {
            self.tokens = bps;
        }

        if self.tokens >= bytes {
            self.tokens -= bytes;
            return Duration::ZERO;
        }

        let missing = bytes - self.tokens;
        self.tokens = 0.0;
        self.updated_at = Some(now);
        Duration::from_secs_f64(missing / bps)
    }
}

fn bps_chunk_size(length: usize, bps: i64) -> usize {
    if bps <= 0 {
        return length;
    }
    let chunk = (bps / 10).max(1) as usize;
    chunk.min(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_mode_parses_go_values() {
        assert_eq!(ApprovalMode::parse("auto"), Some(ApprovalMode::Auto));
        assert_eq!(ApprovalMode::parse("manual"), Some(ApprovalMode::Manual));
        assert_eq!(ApprovalMode::parse("other"), None);
    }

    #[test]
    fn persisted_state_normalizes_identity_keys() {
        let mut state = PolicyState {
            approval_mode: ApprovalMode::Auto,
            approved_identity_keys: HashSet::new(),
            denied_identity_keys: HashSet::new(),
            banned_identity_keys: HashSet::new(),
            banned_ips: HashSet::new(),
            identity_ips: HashMap::new(),
            identity_bps: HashMap::new(),
            identity_bps_limiters: HashMap::new(),
            udp: PortPolicy::default(),
            tcp_port: PortPolicy::default(),
            landing_page_enabled: false,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
        };
        PersistedAdminState {
            approval_mode: "manual".to_string(),
            approved_identity_keys: vec!["Demo:0xABC".to_string()],
            denied_identity_keys: vec!["Demo:0xABC".to_string()],
            ..PersistedAdminState::default()
        }
        .apply(&mut state)
        .unwrap();

        assert_eq!(state.approval_mode, ApprovalMode::Manual);
        assert!(state.approved_identity_keys.is_empty());
        assert!(state.denied_identity_keys.contains("demo:0xabc"));
    }

    #[test]
    fn proxy_trust_uses_forwarded_headers_only_from_trusted_remotes() {
        let temp_path = std::env::temp_dir().join("portal-policy-proxy-test");
        let _ = fs::remove_file(temp_path.join("admin-settings.json"));
        let runtime = PolicyRuntime::load(&temp_path, false, false).unwrap();
        runtime.set_proxy_trust(true, "").unwrap();
        let headers = vec![(
            "x-forwarded-for".to_string(),
            "203.0.113.10, 10.0.0.10".to_string(),
        )];

        assert_eq!(
            runtime.extract_client_ip("127.0.0.1:443".parse().unwrap(), &headers),
            "203.0.113.10"
        );
        assert_eq!(
            runtime.extract_client_ip("198.51.100.1:443".parse().unwrap(), &headers),
            "198.51.100.1"
        );
    }

    #[test]
    fn proxy_trust_accepts_custom_cidr_and_real_ip_fallback() {
        let temp_path = std::env::temp_dir().join("portal-policy-proxy-custom-test");
        let _ = fs::remove_file(temp_path.join("admin-settings.json"));
        let runtime = PolicyRuntime::load(&temp_path, false, false).unwrap();
        runtime.set_proxy_trust(true, "198.51.100.0/24").unwrap();
        let headers = vec![("x-real-ip".to_string(), "2001:db8::1".to_string())];

        assert_eq!(
            runtime.extract_client_ip("198.51.100.9:443".parse().unwrap(), &headers),
            "2001:db8::1"
        );
        assert!(runtime.set_proxy_trust(true, "not-a-cidr").is_err());
    }
}
