use hyper::StatusCode;

use crate::api::ApiReply;
use crate::api::paths::PATH_INSTALL_BIN_PREFIX;

const INSTALL_SH: &str = include_str!("install.sh");
const INSTALL_PS1: &str = include_str!("install.ps1");
const OFFICIAL_RELEASE_BASE_URL: &str = "https://github.com/gosuda/portal-tunnel/releases";

pub fn install_script(portal_url: &str, method: &str, is_windows: bool) -> ApiReply {
    let (script, filename, content_type) = if is_windows {
        (
            relay_powershell_script(portal_url, INSTALL_PS1),
            "install.ps1",
            "text/plain; charset=utf-8",
        )
    } else {
        (
            relay_shell_script(portal_url, INSTALL_SH),
            "install.sh",
            "text/x-shellscript",
        )
    };
    ApiReply {
        status: StatusCode::OK,
        headers: vec![
            ("Content-Type".to_string(), content_type.to_string()),
            (
                "Content-Disposition".to_string(),
                format!("inline; filename=\"{filename}\""),
            ),
        ],
        body: body_for_method(method, script.into_bytes()),
    }
}

pub fn install_binary(path: &str, method: &str) -> ApiReply {
    let slug = path
        .trim_start_matches(PATH_INSTALL_BIN_PREFIX)
        .trim_matches('/');
    let checksum_request = slug.ends_with(".sha256");
    let slug = slug.strip_suffix(".sha256").unwrap_or(slug);
    let Some(filename) = asset_filename(slug) else {
        return not_found(method);
    };

    let mut location = format!("{OFFICIAL_RELEASE_BASE_URL}/latest/download/{filename}");
    if checksum_request {
        location.push_str(".sha256");
    }
    ApiReply {
        status: StatusCode::TEMPORARY_REDIRECT,
        headers: vec![("Location".to_string(), location)],
        body: Vec::new(),
    }
}

fn relay_shell_script(portal_url: &str, script: &str) -> String {
    let overrides = format!(
        "BASE_URL={}\nRELAY_URL={}\nBIN_PATH_PREFIX='install/bin'\n\n",
        quote_shell_value(portal_url),
        quote_shell_value(portal_url)
    );
    insert_after_shebang(script, &overrides)
}

fn relay_powershell_script(portal_url: &str, script: &str) -> String {
    format!(
        "$env:BASE_URL = {}\n$env:RELAY_URL = {}\n$env:BIN_PATH_PREFIX = 'install/bin'\n\n{}",
        quote_powershell_value(portal_url),
        quote_powershell_value(portal_url),
        script
    )
}

fn insert_after_shebang(script: &str, prefix: &str) -> String {
    if script.starts_with("#!")
        && let Some(newline) = script.find('\n')
    {
        return format!(
            "{}{}{}",
            &script[..=newline],
            prefix,
            &script[newline + 1..]
        );
    }
    format!("{prefix}{script}")
}

fn quote_shell_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn quote_powershell_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn asset_filename(slug: &str) -> Option<String> {
    match slug.trim() {
        "linux-amd64" | "linux-arm64" | "darwin-amd64" | "darwin-arm64" => {
            Some(format!("portal-{slug}"))
        }
        "windows-amd64" | "windows-arm64" => Some(format!("portal-{slug}.exe")),
        _ => None,
    }
}

fn not_found(method: &str) -> ApiReply {
    ApiReply {
        status: StatusCode::NOT_FOUND,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: body_for_method(method, b"404 page not found\n".to_vec()),
    }
}

fn body_for_method(method: &str, body: Vec<u8>) -> Vec<u8> {
    if method == "HEAD" { Vec::new() } else { body }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_script_injects_relay_overrides_after_shebang() {
        let reply = install_script("https://relay.example", "GET", false);
        assert_eq!(reply.status, StatusCode::OK);
        let body = String::from_utf8(reply.body).unwrap();
        assert!(body.starts_with("#!/usr/bin/env sh\nBASE_URL='https://relay.example'\n"));
        assert!(body.contains("BIN_PATH_PREFIX='install/bin'"));
        assert!(body.contains("portal expose 3000 --relays $RELAY_URL"));
    }

    #[test]
    fn install_binary_redirects_to_official_release_asset() {
        let reply = install_binary("/install/bin/linux-arm64.sha256", "GET");
        assert_eq!(reply.status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            reply.headers,
            vec![(
                "Location".to_string(),
                "https://github.com/gosuda/portal-tunnel/releases/latest/download/portal-linux-arm64.sha256"
                    .to_string()
            )]
        );
    }
}
