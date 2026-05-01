use std::path::{Path, PathBuf};

use anyhow::bail;
use chrono::SecondsFormat;
use hyper::StatusCode;
use serde::Serialize;
use url::form_urlencoded;

use crate::api::paths::{PATH_APP, PATH_APP_PREFIX, PATH_ASSETS_PREFIX, PATH_TUNNEL_STATUS};
use crate::api::{api_error_reply, json_ok, method_not_allowed, ApiReply};
use crate::auth::identity::normalize_hostname;
use crate::relay::leases::LeaseView;
use crate::relay::AppState;

const FAVICON_PATHS: &[&str] = &[
    "/favicon.ico",
    "/favicon.svg",
    "/favicon-96x96.png",
    "/apple-touch-icon.png",
    "/web-app-manifest-192x192.png",
    "/web-app-manifest-512x512.png",
];

#[derive(Debug)]
pub struct FrontendState {
    app_root: PathBuf,
}

impl FrontendState {
    pub fn new(dist_root: &Path) -> anyhow::Result<Self> {
        let dist_root = dist_root.to_path_buf();
        let app_root = if dist_root.join("portal.html").is_file() {
            dist_root
        } else {
            dist_root.join("app")
        };
        if !app_root.join("portal.html").is_file() {
            bail!(
                "frontend dist must contain portal.html or app/portal.html: {}",
                app_root.display()
            );
        }
        Ok(Self { app_root })
    }

    pub async fn handle_request(
        &self,
        state: &AppState,
        method: &str,
        path: &str,
        query: &str,
    ) -> Option<ApiReply> {
        match path {
            "/" | PATH_APP => Some(self.serve_app_static(state, method, "").await),
            PATH_TUNNEL_STATUS => Some(handle_tunnel_status(state, method, query).await),
            path if path.starts_with(PATH_APP_PREFIX) => {
                let app_path = path.trim_start_matches(PATH_APP_PREFIX);
                Some(self.serve_app_static(state, method, app_path).await)
            }
            path if path.starts_with(PATH_ASSETS_PREFIX) => {
                let asset_path = path.trim_start_matches('/');
                Some(self.serve_asset(method, asset_path))
            }
            path if FAVICON_PATHS.contains(&path) => {
                Some(self.serve_asset(method, path.trim_start_matches('/')))
            }
            _ => None,
        }
    }

    async fn serve_app_static(&self, state: &AppState, method: &str, app_path: &str) -> ApiReply {
        if !is_get_or_head(method) {
            return method_not_allowed();
        }
        let Some(app_path) = clean_frontend_path(app_path) else {
            return not_found();
        };
        if app_path.is_empty() {
            return self.serve_portal_html(state, method).await;
        }

        let file_path = self.app_root.join(&app_path);
        match std::fs::read(&file_path) {
            Ok(data) => file_reply(method, &app_path, data, true),
            Err(_) if Path::new(&app_path).extension().is_none() => {
                self.serve_portal_html(state, method).await
            }
            Err(_) => not_found(),
        }
    }

    fn serve_asset(&self, method: &str, asset_path: &str) -> ApiReply {
        if !is_get_or_head(method) {
            return method_not_allowed();
        }
        let Some(asset_path) = clean_frontend_path(asset_path) else {
            return not_found();
        };
        if asset_path.is_empty() {
            return not_found();
        }
        match std::fs::read(self.app_root.join(&asset_path)) {
            Ok(data) => file_reply(method, &asset_path, data, true),
            Err(_) => not_found(),
        }
    }

    async fn serve_portal_html(&self, state: &AppState, method: &str) -> ApiReply {
        let raw = match std::fs::read_to_string(self.app_root.join("portal.html")) {
            Ok(raw) => raw,
            Err(_) => return not_found(),
        };
        let leases = state.leases.public_leases().await;
        let leases = serde_json::to_string(&leases).unwrap_or_else(|_| "[]".to_string());
        let ssr_script =
            format!("<script id=\"__SSR_DATA__\" type=\"application/json\">{leases}</script>");
        let mut html = if raw.contains("</head>") {
            raw.replacen("</head>", &format!("{ssr_script}\n</head>"), 1)
        } else {
            format!("{ssr_script}\n{raw}")
        };
        html = inject_og_metadata(
            &html,
            state.admin.policy.landing_page_enabled(),
            crate::api::sdk::RELEASE_VERSION,
        );

        ApiReply {
            status: StatusCode::OK,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                (
                    "Cache-Control".to_string(),
                    "no-cache, must-revalidate".to_string(),
                ),
            ],
            body: body_for_method(method, html.into_bytes()),
        }
    }
}

pub async fn handle_builtin_request(
    state: &AppState,
    method: &str,
    path: &str,
    query: &str,
) -> Option<ApiReply> {
    if !state.admin.policy.landing_page_enabled() {
        return None;
    }
    match path {
        "/" | PATH_APP => Some(serve_builtin_landing_page(state, method).await),
        PATH_TUNNEL_STATUS => Some(handle_tunnel_status(state, method, query).await),
        _ => None,
    }
}

async fn serve_builtin_landing_page(state: &AppState, method: &str) -> ApiReply {
    if !is_get_or_head(method) {
        return method_not_allowed();
    }
    let mut leases = state.leases.public_leases().await;
    leases.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    let mut cards = String::new();
    for lease in &leases {
        cards.push_str(&lease_card(lease));
    }
    if cards.is_empty() {
        cards.push_str(
            "<section class=\"empty\"><h2>No public tunnels are listed</h2><p>Registered public tunnels will appear here when they are online.</p></section>",
        );
    }

    let html = format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head>",
            "<meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>{root} - Portal Tunnel Relay</title>",
            "<style>{style}</style>",
            "</head><body>",
            "<main>",
            "<header class=\"hero\">",
            "<p class=\"eyebrow\">Portal Tunnel Relay</p>",
            "<h1>{root}</h1>",
            "<p class=\"summary\">Public tunnels currently routed through this relay.</p>",
            "<div class=\"stats\"><span>{count} tunnel{plural}</span><span>{version}</span></div>",
            "</header>",
            "<section class=\"grid\">{cards}</section>",
            "</main>",
            "</body></html>"
        ),
        root = escape_html(&state.root_host),
        style = BUILTIN_LANDING_CSS,
        count = leases.len(),
        plural = if leases.len() == 1 { "" } else { "s" },
        version = escape_html(crate::api::sdk::RELEASE_VERSION),
        cards = cards,
    );

    ApiReply {
        status: StatusCode::OK,
        headers: vec![
            (
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            (
                "Cache-Control".to_string(),
                "no-cache, must-revalidate".to_string(),
            ),
        ],
        body: body_for_method(method, html.into_bytes()),
    }
}

fn lease_card(lease: &LeaseView) -> String {
    let title = if lease.metadata.description.trim().is_empty() {
        lease.hostname.as_str()
    } else {
        lease.metadata.description.as_str()
    };
    let owner = if lease.metadata.owner.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<span class=\"owner\">{}</span>",
            escape_html(&lease.metadata.owner)
        )
    };
    let mut tags = String::new();
    for tag in &lease.metadata.tags {
        tags.push_str("<span>");
        tags.push_str(&escape_html(tag));
        tags.push_str("</span>");
    }
    if lease.udp_enabled {
        tags.push_str("<span>UDP</span>");
    }
    if lease.tcp_enabled {
        tags.push_str("<span>TCP</span>");
    }
    if lease.ready > 0 {
        tags.push_str("<span>online</span>");
    }
    if tags.is_empty() {
        tags.push_str("<span>HTTPS</span>");
    }
    let first_seen = lease
        .first_seen_at
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    format!(
        concat!(
            "<article class=\"card\">",
            "<a class=\"host\" href=\"https://{hostname}/\">{title}</a>",
            "<p class=\"url\">{hostname}</p>",
            "<div class=\"meta\">{owner}<time datetime=\"{first_seen}\">{first_seen}</time></div>",
            "<div class=\"tags\">{tags}</div>",
            "</article>"
        ),
        hostname = escape_html(&lease.hostname),
        title = escape_html(title),
        owner = owner,
        first_seen = escape_html(&first_seen),
        tags = tags,
    )
}

async fn handle_tunnel_status(state: &AppState, method: &str, query: &str) -> ApiReply {
    if method != "GET" {
        return method_not_allowed();
    }
    let hostname = form_urlencoded::parse(query.as_bytes())
        .find_map(|(key, value)| (key == "hostname").then(|| normalize_hostname(&value)))
        .unwrap_or_default();
    if hostname.is_empty() {
        return api_error_reply(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "hostname is required",
        );
    }

    let mut response = TunnelStatusResponse {
        hostname: hostname.clone(),
        registered: false,
        service_alive: false,
    };
    for lease in state.leases.public_leases().await {
        if hostname_matches_pattern(&lease.hostname, &hostname) {
            response.hostname = lease.hostname;
            response.registered = true;
            response.service_alive = lease.ready > 0;
            break;
        }
    }
    json_ok(StatusCode::OK, &response)
}

fn clean_frontend_path(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_start_matches('/');
    if raw.is_empty() {
        return Some(String::new());
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

fn file_reply(method: &str, path: &str, data: Vec<u8>, cache: bool) -> ApiReply {
    let mut headers = Vec::new();
    if let Some(content_type) = content_type(path) {
        headers.push(("Content-Type".to_string(), content_type.to_string()));
    }
    if cache {
        headers.push((
            "Cache-Control".to_string(),
            "public, max-age=3600".to_string(),
        ));
    }
    ApiReply {
        status: StatusCode::OK,
        headers,
        body: body_for_method(method, data),
    }
}

fn body_for_method(method: &str, body: Vec<u8>) -> Vec<u8> {
    if method == "HEAD" {
        Vec::new()
    } else {
        body
    }
}

fn not_found() -> ApiReply {
    ApiReply {
        status: StatusCode::NOT_FOUND,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: b"404 page not found\n".to_vec(),
    }
}

fn is_get_or_head(method: &str) -> bool {
    matches!(method, "GET" | "HEAD")
}

fn content_type(path: &str) -> Option<&'static str> {
    match Path::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("css") => Some("text/css; charset=utf-8"),
        Some("html") => Some("text/html; charset=utf-8"),
        Some("ico") => Some("image/x-icon"),
        Some("jpg" | "jpeg") => Some("image/jpeg"),
        Some("js" | "mjs") => Some("text/javascript; charset=utf-8"),
        Some("json" | "webmanifest") => Some("application/json; charset=utf-8"),
        Some("png") => Some("image/png"),
        Some("svg") => Some("image/svg+xml"),
        Some("txt") => Some("text/plain; charset=utf-8"),
        Some("wasm") => Some("application/wasm"),
        Some("webp") => Some("image/webp"),
        _ => None,
    }
}

const BUILTIN_LANDING_CSS: &str = r#"
:root{color-scheme:light;--bg:#f6f7f9;--ink:#14171f;--muted:#5d6675;--line:#d8dde5;--panel:#fff;--accent:#0b6bcb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.5}
main{width:min(1120px,calc(100% - 32px));margin:0 auto;padding:56px 0}
.hero{padding:0 0 28px;border-bottom:1px solid var(--line)}
.eyebrow{margin:0 0 10px;color:var(--accent);font-weight:700;text-transform:uppercase;font-size:12px;letter-spacing:0}
h1{margin:0;font-size:clamp(38px,8vw,88px);line-height:.95;letter-spacing:0;overflow-wrap:anywhere}
.summary{max-width:640px;margin:18px 0 0;color:var(--muted);font-size:18px}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin-top:24px}
.stats span,.tags span{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:6px 10px;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:24px}
.card,.empty{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:18px;min-width:0}
.host{display:block;color:var(--ink);font-weight:760;font-size:18px;text-decoration:none;overflow-wrap:anywhere}
.host:hover{color:var(--accent)}
.url{margin:6px 0 0;color:var(--muted);font-size:14px;overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px;color:var(--muted);font-size:12px}
.owner{font-weight:700;color:var(--ink)}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.empty{grid-column:1/-1}
.empty h2{margin:0;font-size:22px;letter-spacing:0}
.empty p{margin:8px 0 0;color:var(--muted)}
"#;

fn inject_og_metadata(html: &str, landing_page_enabled: bool, release_version: &str) -> String {
    html.replace("[%OG_TITLE%]", &escape_html("Portal Proxy Gateway"))
        .replace(
            "[%OG_DESCRIPTION%]",
            &escape_html(
                "Transform your local services into web-accessible endpoints. Instant access from anywhere.",
            ),
        )
        .replace(
            "[%LANDING_PAGE_ENABLED%]",
            if landing_page_enabled { "true" } else { "false" },
        )
        .replace("[%RELEASE_VERSION%]", &escape_html(release_version))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn hostname_matches_pattern(pattern: &str, hostname: &str) -> bool {
    let pattern = normalize_hostname(pattern);
    let hostname = normalize_hostname(hostname);
    if pattern == hostname {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some((_, rest)) = hostname.split_once('.') else {
        return false;
    };
    rest == suffix
}

#[derive(Debug, Serialize)]
struct TunnelStatusResponse {
    hostname: String,
    registered: bool,
    service_alive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_frontend_path_rejects_parent_segments() {
        assert_eq!(
            clean_frontend_path("/assets/./app.js").as_deref(),
            Some("assets/app.js")
        );
        assert!(clean_frontend_path("../secret").is_none());
        assert!(clean_frontend_path("assets/../secret").is_none());
    }

    #[test]
    fn wildcard_hostname_match_is_one_level() {
        assert!(hostname_matches_pattern("*.example.com", "app.example.com"));
        assert!(!hostname_matches_pattern(
            "*.example.com",
            "deep.app.example.com"
        ));
    }
}
