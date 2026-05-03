//! Phase 1 U16 — compare `docs/wire-protocol.md` drift marker to `git log -1` for `crates/portal-wire`.

use std::fs;
use std::path::Path;
use std::process::Command;

const SPEC_REL_PATH: &str = "docs/wire-protocol.md";
const MARKER_START: &str = "<!-- Last verified against crates/portal-wire commit: ";
const MARKER_END: &str = " -->";

/// Fail when the spec HTML comment lags the tree for `crates/portal-wire`.
pub fn run(repo_root: &Path) -> Result<(), String> {
    let spec_path = repo_root.join(SPEC_REL_PATH);
    let spec =
        fs::read_to_string(&spec_path).map_err(|e| format!("read {}: {e}", spec_path.display()))?;

    let recorded = parse_recorded_sha(&spec).ok_or_else(|| {
        format!(
            "{SPEC_REL_PATH}: missing `{MARKER_START}<40-hex>{MARKER_END}` (Phase 1 U16 drift gate)."
        )
    })?;

    if recorded.len() != 40 {
        return Err(format!(
            "{SPEC_REL_PATH}: recorded id must be 40 hex chars, got {} (`{recorded}`)",
            recorded.len()
        ));
    }
    if !recorded.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{SPEC_REL_PATH}: recorded commit `{recorded}` is not 40 hexadecimal digits"
        ));
    }

    let actual = git_last_portal_wire_commit(repo_root)?;
    if !actual.eq_ignore_ascii_case(&recorded) {
        return Err(format!(
            "wire-protocol drift: spec records `{recorded}` but \
             `git log -1 --format=%H -- crates/portal-wire` is `{actual}`. \
             Update the HTML comment in {SPEC_REL_PATH} to match the latest \
             commit touching `crates/portal-wire`."
        ));
    }

    Ok(())
}

fn parse_recorded_sha(spec: &str) -> Option<String> {
    let idx = spec.find(MARKER_START)?;
    let start = idx + MARKER_START.len();
    let tail = spec.get(start..)?;
    let end_rel = tail.find(MARKER_END)?;
    let inner = tail.get(..end_rel)?;
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

fn git_last_portal_wire_commit(repo_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["log", "-1", "--format=%H", "--", "crates/portal-wire"])
        .output()
        .map_err(|e| format!("spawn `git log`: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "`git log` failed (status {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| format!("git stdout: {e}"))?;
    let sha = stdout.trim();
    if sha.is_empty() {
        return Err(
            "`git log -1 -- crates/portal-wire` returned empty output — is this a shallow clone missing history?"
                .to_string(),
        );
    }
    if sha.len() != 40 {
        return Err(format!(
            "`git log -1 --format=%H` expected 40-char hash, got len {} (`{sha}`)",
            sha.len()
        ));
    }
    Ok(sha.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip_marker() {
        let spec = format!(
            "# Title\n\n{MARKER_START}abcdef0123456789abcdef0123456789abcdef01{MARKER_END}\n"
        );
        assert_eq!(
            parse_recorded_sha(&spec).as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef01")
        );
    }
}
