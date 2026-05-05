//! Phase 7 U8.11 — relay-served install-script render API.
//!
//! Go parity with `portal-tunnel/cmd/portal-tunnel/installer/installer.go`'s
//! `RelayScript`: when a tenant runs `curl <relay>/__install.sh | sh`,
//! the served script carries per-relay overrides for `BASE_URL`,
//! `RELAY_URL`, and `BIN_PATH_PREFIX` so the resulting `portal`
//! binary is configured to talk to *this* relay.
//!
//! The bytes for `install.sh` and `install.ps1` are embedded at
//! compile time from the workspace-root copies committed in `364a420`.
//! `rust-embed` is the workspace-default embed mechanism for the
//! frontend bundle (per plan U8.1) — for the install-script pair the
//! `include_str!` macro is sufficient and simpler (no derive, no
//! folder filter, no runtime asset enumeration), so this module
//! deviates from the plan's literal "`#[derive(RustEmbed)]`" wording
//! while preserving the compile-time-embed semantic. The module-level
//! comment in commit message names the deviation.
//!
//! ## Override insertion rules (Go-parity)
//!
//! - **Shell**: insert overrides AFTER the shebang line. The
//!   resulting script preserves the `#!/usr/bin/env sh` first line,
//!   followed by the override block, followed by the rest of the
//!   upstream script body.
//! - **PowerShell**: prepend overrides (no shebang). PowerShell
//!   ignores leading whitespace before the script body.
//!
//! ## Out of scope (this module)
//!
//! Axum handler wiring for `/__install.sh` and `/__install.ps1`
//! routes lands when the public-facing relay router has its admin
//! surface plumbed; this module ships the pure render API + tests
//! so the handler integration is a thin wrapper later.

const INSTALL_SH: &str = include_str!("../../../install.sh");
const INSTALL_PS1: &str = include_str!("../../../install.ps1");

/// MIME type to serve for the rendered shell script.
pub const SHELL_CONTENT_TYPE: &str = "text/x-shellscript";

/// MIME type to serve for the rendered PowerShell script.
pub const POWERSHELL_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// Render the shell-flavoured install script with per-relay overrides.
///
/// `portal_url` is the public-facing URL of the relay (e.g.
/// `https://example.relay.portal-tunnel.com`).  Overrides are inserted
/// after the shebang line; the rest of the upstream script body
/// follows verbatim.
///
/// Empty / whitespace-only `portal_url` is rejected (returns `None`)
/// because a script with `BASE_URL=''` would download from
/// `https:////portal-linux-amd64` and fail at runtime in a
/// confusing way.
#[must_use]
pub fn relay_shell_script(portal_url: &str) -> Option<String> {
    let portal_url = portal_url.trim();
    if portal_url.is_empty() {
        return None;
    }
    let overrides = format!(
        "BASE_URL={}\nRELAY_URL={}\nBIN_PATH_PREFIX='install/bin'\n",
        quote_shell_value(portal_url),
        quote_shell_value(portal_url),
    );
    Some(insert_after_shebang(INSTALL_SH, &overrides))
}

/// Render the PowerShell-flavoured install script with per-relay
/// overrides. Same `portal_url` empty-rejection rule as
/// [`relay_shell_script`]; overrides are prepended (PowerShell has no
/// shebang).
#[must_use]
pub fn relay_powershell_script(portal_url: &str) -> Option<String> {
    let portal_url = portal_url.trim();
    if portal_url.is_empty() {
        return None;
    }
    let overrides = format!(
        "$env:BASE_URL = {}\n$env:RELAY_URL = {}\n$env:BIN_PATH_PREFIX = 'install/bin'\n",
        quote_powershell_value(portal_url),
        quote_powershell_value(portal_url),
    );
    Some(format!("{overrides}{INSTALL_PS1}"))
}

/// Single-quote a value for POSIX shell, escaping embedded
/// single-quotes via the `'\''` (close, escaped quote, open) idiom.
/// Matches `quoteShellValue` in the Go reference.
fn quote_shell_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Single-quote a value for PowerShell, escaping embedded
/// single-quotes via the doubled-quote (`''`) idiom. Matches
/// `quotePowerShellValue` in the Go reference.
fn quote_powershell_value(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Insert `prefix` after the shebang line of `script`.
///
/// Three cases:
///   1. `script` starts with `#!` AND contains a newline — `prefix`
///      lands after the first newline.
///   2. `script` starts with `#!` but has NO newline (shebang-only,
///      pathological): preserve the shebang first, append `\n`, then
///      `prefix`. The shebang-on-line-one invariant matters more
///      than the prefix's exact position; an interpreter handed a
///      script with the override block before the shebang would
///      reject it as a non-script.
///   3. `script` has no shebang at all: prepend `prefix` verbatim.
fn insert_after_shebang(script: &str, prefix: &str) -> String {
    if !script.starts_with("#!") {
        return format!("{prefix}{script}");
    }
    if let Some(nl) = script.find('\n') {
        let (head_with_newline, body) = script.split_at(nl + 1);
        return format!("{head_with_newline}{prefix}{body}");
    }
    // Shebang-only script (no newline). Preserve the shebang first;
    // emit a newline before the prefix so the override block lands
    // on its own line.
    format!("{script}\n{prefix}")
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn shell_script_rejects_empty_portal_url() {
        assert!(relay_shell_script("").is_none());
        assert!(relay_shell_script("   ").is_none());
        assert!(relay_shell_script("\n\t").is_none());
    }

    #[test]
    fn powershell_script_rejects_empty_portal_url() {
        assert!(relay_powershell_script("").is_none());
        assert!(relay_powershell_script("   ").is_none());
    }

    #[test]
    fn shell_script_inserts_overrides_after_shebang() {
        let rendered =
            relay_shell_script("https://relay.example.com").expect("non-empty url renders");
        // First line stays the shebang; the overrides line follows.
        let mut lines = rendered.lines();
        assert!(
            lines.next().expect("shebang").starts_with("#!"),
            "first line must remain the shebang",
        );
        let overrides_block: Vec<&str> = lines.by_ref().take(3).collect();
        assert_eq!(overrides_block[0], "BASE_URL='https://relay.example.com'");
        assert_eq!(overrides_block[1], "RELAY_URL='https://relay.example.com'");
        assert_eq!(overrides_block[2], "BIN_PATH_PREFIX='install/bin'");
    }

    #[test]
    fn powershell_script_prepends_overrides() {
        let rendered =
            relay_powershell_script("https://relay.example.com").expect("non-empty url renders");
        let mut lines = rendered.lines();
        assert_eq!(
            lines.next().expect("first override line"),
            "$env:BASE_URL = 'https://relay.example.com'"
        );
        assert_eq!(
            lines.next().expect("second override line"),
            "$env:RELAY_URL = 'https://relay.example.com'"
        );
        assert_eq!(
            lines.next().expect("third override line"),
            "$env:BIN_PATH_PREFIX = 'install/bin'"
        );
    }

    #[test]
    fn shell_script_preserves_upstream_body_verbatim() {
        let rendered = relay_shell_script("https://r.example").expect("renders");
        // The override block ends at "BIN_PATH_PREFIX='install/bin'\n";
        // everything after must match the embedded INSTALL_SH minus
        // its shebang line.
        let upstream_body_after_shebang = INSTALL_SH
            .split_once('\n')
            .map(|(_, body)| body)
            .expect("install.sh has at least 2 lines");
        assert!(
            rendered.contains(upstream_body_after_shebang),
            "rendered script must include the upstream body verbatim"
        );
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quote() {
        // Go reference: `'\''` (close, escaped quote, open).
        assert_eq!(quote_shell_value("ab'cd"), r"'ab'\''cd'");
        assert_eq!(quote_shell_value("a''b"), r"'a'\'''\''b'");
        assert_eq!(quote_shell_value("plain"), "'plain'");
    }

    #[test]
    fn powershell_quote_escapes_embedded_single_quote() {
        // Go reference: doubled-quote.
        assert_eq!(quote_powershell_value("ab'cd"), "'ab''cd'");
        assert_eq!(quote_powershell_value("a''b"), "'a''''b'");
        assert_eq!(quote_powershell_value("plain"), "'plain'");
    }

    #[test]
    fn insert_after_shebang_handles_no_shebang() {
        let result = insert_after_shebang("body line\n", "OVERRIDE\n");
        assert_eq!(result, "OVERRIDE\nbody line\n");
    }

    #[test]
    fn insert_after_shebang_handles_shebang_only() {
        // Script that's literally just a shebang with no newline.
        // The shebang MUST stay on line 1 so the OS recognises the
        // interpreter; overrides go on the new line below.
        let result = insert_after_shebang("#!/bin/sh", "OVERRIDE\n");
        assert_eq!(result, "#!/bin/sh\nOVERRIDE\n");
    }

    #[test]
    fn shell_overrides_use_correct_url_after_trim() {
        // Whitespace around the URL is trimmed before quoting.
        let rendered = relay_shell_script("  https://r.example  ").expect("renders");
        assert!(rendered.contains("BASE_URL='https://r.example'"));
        assert!(!rendered.contains("BASE_URL='  https://r.example"));
    }

    #[test]
    fn shell_overrides_quote_url_with_apostrophe() {
        // Defensive: a malicious operator config carrying a literal
        // single-quote in the URL must produce a syntactically valid
        // shell-quoted string (Go-parity escape).
        let rendered =
            relay_shell_script("https://r.exa'mple").expect("renders even with apostrophe");
        assert!(rendered.contains(r"BASE_URL='https://r.exa'\''mple'"));
    }
}
