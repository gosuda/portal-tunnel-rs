//! Phase 7 U8.7 — dep-spawning-audit gate.
//!
//! Validates that `docs/dep-spawning-audit.md` is present, non-empty, and
//! carries every required section header. The audit document itself is
//! hand-authored (it captures per-dep contracts that are not derivable from
//! Rust source); this xtask only enforces structural completeness so a
//! future contributor adding or upgrading a dep cannot silently bypass the
//! audit.
//!
//! Required sections: `## Per-dep contracts`, `### quinn`, `### axum + hyper`,
//! `### instant-acme`, `### defguard_boringtun`, `## R9 honest-claim`.
//!
//! Failure modes:
//! - File missing → exit 1.
//! - File empty → exit 1.
//! - One or more required section headers missing → exit 1, listing each
//!   missing header so the contributor knows exactly what to add.

use std::fs;
use std::path::Path;

const AUDIT_PATH: &str = "docs/dep-spawning-audit.md";

const REQUIRED_HEADERS: &[&str] = &[
    "## Per-dep contracts",
    "### `quinn`",
    "### `axum` + `hyper`",
    "### `instant-acme`",
    "### `defguard_boringtun`",
    "## R9 honest-claim",
];

pub fn run(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = repo_root.join(AUDIT_PATH);
    let body = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            return Err(format!(
                "{AUDIT_PATH} not readable ({e}). Phase 7 U8.7 requires a \
                 hand-authored dep-spawning audit; see the matching plan unit."
            )
            .into());
        }
    };

    if body.trim().is_empty() {
        return Err(format!(
            "{AUDIT_PATH} is empty. Phase 7 U8.7 requires non-empty contract \
             content per dep."
        )
        .into());
    }

    // Header detection must reject substring matches inside fenced code
    // blocks or blockquotes, which would otherwise let a contributor satisfy
    // the gate by quoting the required headers in a code-fenced example.
    let real_headers = collect_real_headers(&body);
    let mut missing: Vec<&'static str> = Vec::new();
    for header in REQUIRED_HEADERS {
        if !real_headers.iter().any(|h| h == header) {
            missing.push(header);
        }
    }

    if !missing.is_empty() {
        let list = missing
            .iter()
            .map(|h| format!("  - {h}"))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!(
            "{AUDIT_PATH} is missing required section header(s):\n{list}\n\
             Phase 7 U8.7: every listed dep must have its contract documented \
             before CI accepts the change."
        )
        .into());
    }

    println!(
        "xtask dep-audit: {AUDIT_PATH} carries all {n} required section \
         header(s).",
        n = REQUIRED_HEADERS.len()
    );
    Ok(())
}

/// Walk the markdown body and return every line that is a real ATX heading
/// (`#`, `##`, `###`, ...) — skipping any line inside a fenced code block
/// (` ``` ` or `~~~` fence) or inside a blockquote (`>` prefix). Indented
/// (4-space) code blocks are not detected; they are uncommon in this audit
/// and their bypass risk is acknowledged.
///
/// Per `CommonMark` 4.5: a fenced code block opened with N fence characters
/// (N >= 3) is closed only by a fence line of N or more matching characters.
/// We therefore track the opener char AND the opener length so a 4-backtick
/// block containing 3-backtick lines is not falsely closed mid-block.
fn collect_real_headers(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if let Some((open_char, open_len)) = fence {
            // Closing fence: same char AND length >= opener length.
            if let Some(close_len) = fence_run_len(trimmed, open_char)
                && close_len >= open_len
            {
                fence = None;
            }
            continue;
        }
        if let Some(open_len) = fence_run_len(trimmed, '`')
            && open_len >= 3
        {
            fence = Some(('`', open_len));
            continue;
        }
        if let Some(open_len) = fence_run_len(trimmed, '~')
            && open_len >= 3
        {
            fence = Some(('~', open_len));
            continue;
        }
        // Blockquote line — skip; markdown treats `> ### foo` as quoted text,
        // not a heading inside the document's outline.
        if trimmed.starts_with('>') {
            continue;
        }
        // ATX heading: starts with 1-6 `#` followed by a space, then content.
        if trimmed.starts_with('#') {
            let hash_len = trimmed.chars().take_while(|c| *c == '#').count();
            if (1..=6).contains(&hash_len) && trimmed.as_bytes().get(hash_len) == Some(&b' ') {
                out.push(trimmed.to_owned());
            }
        }
    }
    out
}

/// Return `Some(n)` if `line` starts with `n >= 1` consecutive `fence_char`
/// characters; `None` otherwise.
fn fence_run_len(line: &str, fence_char: char) -> Option<usize> {
    let count = line.chars().take_while(|c| *c == fence_char).count();
    if count >= 1 { Some(count) } else { None }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test-only setup; failure aborts the test, which is the desired signal"
)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn write_audit(root: &Path, body: &str) {
        let docs = root.join("docs");
        fs::create_dir_all(&docs).expect("mkdir docs");
        let mut f = fs::File::create(docs.join("dep-spawning-audit.md")).expect("create");
        f.write_all(body.as_bytes()).expect("write");
    }

    #[test]
    fn missing_file_fails() {
        let dir = temp_root();
        let err = run(dir.path()).expect_err("missing file must fail");
        assert!(err.to_string().contains("not readable"), "got: {err}");
    }

    #[test]
    fn empty_file_fails() {
        let dir = temp_root();
        write_audit(dir.path(), "   \n\t");
        let err = run(dir.path()).expect_err("empty must fail");
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn missing_section_fails() {
        let dir = temp_root();
        // Has Per-dep contracts header but missing every dep section.
        write_audit(dir.path(), "## Per-dep contracts\n\nbody\n");
        let err = run(dir.path()).expect_err("missing dep sections must fail");
        let msg = err.to_string();
        assert!(msg.contains("### `quinn`"), "got: {msg}");
        assert!(msg.contains("### `defguard_boringtun`"), "got: {msg}");
    }

    #[test]
    fn complete_file_passes() {
        let dir = temp_root();
        let body = "## Per-dep contracts\n\
                    ### `quinn`\n\
                    ### `axum` + `hyper`\n\
                    ### `instant-acme`\n\
                    ### `defguard_boringtun`\n\
                    ## R9 honest-claim\n\
                    body\n";
        write_audit(dir.path(), body);
        run(dir.path()).expect("complete file must pass");
    }

    #[test]
    fn fenced_code_block_does_not_satisfy_required_headers() {
        // Required headers appear ONLY inside a triple-backtick fence —
        // collect_real_headers must skip them and the gate must fail.
        let dir = temp_root();
        let body = "# Top\n\
                    ```text\n\
                    ## Per-dep contracts\n\
                    ### `quinn`\n\
                    ### `axum` + `hyper`\n\
                    ### `instant-acme`\n\
                    ### `defguard_boringtun`\n\
                    ## R9 honest-claim\n\
                    ```\n\
                    real body\n";
        write_audit(dir.path(), body);
        let err = run(dir.path()).expect_err("fenced fakes must fail");
        let msg = err.to_string();
        assert!(msg.contains("missing required section"), "got: {msg}");
        assert!(msg.contains("### `quinn`"), "got: {msg}");
    }

    #[test]
    fn four_backtick_block_with_three_backtick_inner_does_not_close_early() {
        // CommonMark §4.5: a fence opened with N backticks (N>=3) closes
        // only on N+ backticks. A 4-backtick block containing a 3-backtick
        // line stays open; required headers placed AFTER that 3-backtick
        // line but BEFORE the 4-backtick closer must NOT be detected.
        let dir = temp_root();
        let body = "# Top\n\
                    ````text\n\
                    inner content\n\
                    ```\n\
                    ## Per-dep contracts\n\
                    ### `quinn`\n\
                    ### `axum` + `hyper`\n\
                    ### `instant-acme`\n\
                    ### `defguard_boringtun`\n\
                    ## R9 honest-claim\n\
                    ````\n\
                    real body\n";
        write_audit(dir.path(), body);
        let err = run(dir.path()).expect_err("4-backtick fence must keep enclosed headers hidden");
        let msg = err.to_string();
        assert!(msg.contains("missing required section"), "got: {msg}");
    }

    #[test]
    fn blockquoted_required_headers_do_not_satisfy_gate() {
        let dir = temp_root();
        let body = "# Top\n\
                    > ## Per-dep contracts\n\
                    > ### `quinn`\n\
                    > ### `axum` + `hyper`\n\
                    > ### `instant-acme`\n\
                    > ### `defguard_boringtun`\n\
                    > ## R9 honest-claim\n\
                    real body\n";
        write_audit(dir.path(), body);
        let err = run(dir.path()).expect_err("blockquoted fakes must fail");
        let msg = err.to_string();
        assert!(msg.contains("missing required section"), "got: {msg}");
    }
}
