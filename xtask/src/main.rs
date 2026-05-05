//! Workspace task runner — landed subcommands: `wire-drift-check` (Phase 1
//! U16 commit-bound marker gate), `ci` (mirrors every CI workflow gate
//! locally for `cargo xtask ci`), `openapi-export` (Phase 7 U8.8 v0.2-
//! backlog stub), `dep-audit` (Phase 7 U8.7 dep-spawning-audit validator).
//! Future subcommands (not landed): `codegen`, `release`,
//! `refresh-frontend-bundle`.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};

mod dep_audit;
mod openapi_export;
mod wire_drift_check;

/// Workspace member crates verified individually by `cargo msrv verify
/// --path crates/<member>`.
///
/// Each member's effective MSRV depends on its own dependency graph and
/// feature set — verifying a single anchor crate is insufficient because
/// crates with a smaller dep graph (e.g., portal-wire) miss MSRV-ratcheting
/// deps that only enter the resolved tree via heavier crates (rustls in
/// portal-relay, alloy in portal-crypto, `defguard_boringtun` in
/// portal-relay, etc.). `cargo-msrv --workspace` semantics vary across
/// versions and were observed to silently skip iteration in 0.19.3 when
/// anchored on the workspace root, so this gate iterates explicitly.
///
/// Mirrors `[workspace] members` in the root `Cargo.toml`, minus `xtask`
/// itself (xtask's MSRV tracks the workspace pin and is not separately
/// gated). Drift between this list and `Cargo.toml` is caught by
/// [`assert_msrv_members_match_workspace`] before the iteration runs.
const MSRV_MEMBERS: &[&str] = &[
    "portal-wire",
    "portal-crypto",
    "portal-net",
    "portal-acme",
    "portal-relay",
    "portal-sdk",
    "portal-relay-bin",
    "portal-cli",
    "portal-demo",
];

/// Workspace maintenance tasks (`cargo xtask …`).
#[derive(Parser)]
#[command(name = "xtask", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fail when `docs/wire-protocol.md` drift comment lags `git log -1 -- crates/portal-wire`.
    WireDriftCheck,
    /// Run every CI workflow gate locally (fmt, taplo, clippy, nextest at
    /// `PROPTEST_CASES=4096`, deny, vet warn-only, cargo-machete, msrv per
    /// member, wire-drift, multi-key-return, dep-spawning-audit,
    /// rustls-mandatory, utoipa-coverage). Source of truth:
    /// `.github/workflows/ci.yml`; `run_ci` mirrors it gate-by-gate.
    Ci,
    /// Phase 7 U8.8 v0.2-backlog stub. Prints the deferral note pointing
    /// at the v0.1 mechanism — clippy `disallowed_methods` on bare
    /// `axum::Router::route` plus the ast-grep `utoipa-coverage-gate`
    /// step in `.github/workflows/ci.yml`, both already mirrored in
    /// `Ci`. The v0.2 follow-up (serializing `ApiDoc::openapi()` to
    /// `docs/openapi.yaml` for a snapshot test) lands when the
    /// trigger criterion in `PLAN.md` §v0.2 Backlog fires.
    OpenapiExport,
    /// Validate `docs/dep-spawning-audit.md` carries every required dep contract section (Phase 7 U8.7).
    DepAudit,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let repo_root = workspace_root()?;

    match cli.command {
        Commands::WireDriftCheck => wire_drift_check::run(&repo_root).map_err(Into::into),
        Commands::Ci => run_ci(&repo_root),
        Commands::OpenapiExport => {
            openapi_export::run();
            Ok(())
        }
        Commands::DepAudit => dep_audit::run(&repo_root),
    }
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .ok_or("xtask manifest has no parent (expected workspace root)")?
        .to_path_buf())
}

fn run_ci(repo_root: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut failures: Vec<&'static str> = Vec::new();

    if !cmd_ok(repo_root, "cargo", &["fmt", "--all", "--check"]) {
        failures.push("cargo fmt --check");
    }
    // taplo fmt --check — mirrors the `taplo` CI job. Config + file
    // list live in `.taplo.toml`. Spawn failure (taplo not installed)
    // is a gate failure, not a warning: CI runs taplo unconditionally,
    // so the local mirror must too.
    if !cmd_ok(repo_root, "taplo", &["fmt", "--check"]) {
        failures.push("taplo fmt --check");
    }
    if !cmd_ok(
        repo_root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ) {
        failures.push("cargo clippy");
    }
    // Second clippy pass with `--all-features` to surface compile/lint
    // errors in feature-gated modules. The default-features pass above
    // doesn't compile modules behind off-by-default features (e.g.
    // `portal-crypto::api_https` behind `rustls-integration`), so a
    // missing import or stale type reference inside a gated module can
    // slip through the default-features gate and only surface when a
    // downstream caller enables the feature. The 2026-05-04 iter-100
    // build-regression incident — where iter-96 dropped two `use`
    // imports inside the rustls-integration-gated `api_https/key.rs`
    // and the default-features gate missed it — is the canonical
    // example.
    if !cmd_ok(
        repo_root,
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-features",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ) {
        failures.push("cargo clippy --all-features");
    }
    if !cmd_ok_with_env(
        repo_root,
        "cargo",
        &["nextest", "run", "--workspace", "--no-fail-fast"],
        &[("PROPTEST_CASES", "4096")],
    ) {
        failures.push("cargo nextest");
    }
    if !cmd_ok(repo_root, "cargo", &["deny", "check"]) {
        failures.push("cargo deny check");
    }
    // Phase 5 U1: cargo-vet supply-chain audit. Warn-only during Phase 5
    // per the Mozilla cargo-vet book's incremental-adoption posture; the
    // workspace promotes this to a hard gate in Phase 7 release work.
    // Failure modes covered: cargo-vet not installed, no network for
    // imported audit sets, missing audits on first run. None of these
    // should fail `xtask ci` until the workspace has bootstrapped its
    // own audit corpus.
    if !cmd_ok(repo_root, "cargo", &["vet", "check"]) {
        eprintln!("xtask ci: cargo vet check failed (warn-only, Phase 5)");
    }
    // cargo-machete: invoke the binary directly (not via `cargo machete`).
    // When invoked through cargo's subcommand dispatch, cargo-machete
    // receives argv `["cargo-machete", "machete"]` and its skip-subcommand-
    // arg heuristic is gated on the `CARGO` env var being set in a way
    // that subprocess inheritance does not reliably preserve under the
    // xtask → cargo → cargo-machete chain (observed locally on
    // cargo-machete 0.9.2 / cargo 1.95). Direct binary invocation makes
    // argv `["cargo-machete"]` with no positional path, eliminating the
    // skip ambiguity.
    if !cmd_ok(repo_root, "cargo-machete", &[]) {
        failures.push("cargo-machete");
    }
    // cargo-msrv: iterate every workspace member. The workspace root
    // `Cargo.toml` has no `[package]` section so `cargo msrv verify
    // --path .` errors with "Unable to find key 'package.rust-version'".
    // Single-anchor checks (`--path crates/portal-wire`) are insufficient
    // because each member's dep graph + feature set can ratchet the
    // effective MSRV above the workspace pin. `--workspace` semantics
    // are unstable across cargo-msrv versions — observed silent
    // skip-iteration in 0.19.3 — so explicit per-member iteration is the
    // correctness contract. The MSRV_MEMBERS list is validated against
    // workspace Cargo.toml on every run; drift fails fast with a
    // diagnostic rather than silently dropping coverage.
    if let Err(e) = assert_msrv_members_match_workspace(repo_root) {
        eprintln!("xtask ci: MSRV_MEMBERS drift: {e}");
        failures.push("MSRV_MEMBERS / Cargo.toml drift");
    } else {
        for member in MSRV_MEMBERS {
            let path = format!("crates/{member}");
            if !cmd_ok(repo_root, "cargo", &["msrv", "verify", "--path", &path]) {
                failures.push("cargo msrv verify");
                // Stop on first failure: cargo-msrv already prints which
                // crate broke; running the remaining members would only
                // add noise to the failure list.
                break;
            }
        }
    }
    if wire_drift_check::run(repo_root).is_err() {
        failures.push("wire-drift-check");
    }
    // multi-key-return-gate (R2): mirrors the CI job of the same name.
    // Extracted to keep `run_ci` under clippy's `too_many_lines` threshold.
    multi_key_return_gate(repo_root, &mut failures);
    // dep-spawning-audit-gate (Phase 7 U8.7): mirrors the CI job. The
    // helper is already exposed as `cargo xtask dep-audit`; calling it
    // here ensures local CI parity. The gate validates that
    // `docs/dep-spawning-audit.md` carries every required ATX section
    // header (Per-dep contracts, quinn, axum + hyper, instant-acme,
    // defguard_boringtun, R9 honest-claim) — see `xtask/src/dep_audit.rs`.
    if dep_audit::run(repo_root).is_err() {
        failures.push("dep-spawning-audit");
    }
    // rustls-mandatory (R13 / ADR-0002): mirrors the CI job. Asserts no
    // transitive openssl in the resolved tree — `cargo tree --workspace
    // --no-default-features -i openssl` must produce empty stdout. The
    // CI job's bash form (`if cargo tree ... | grep -q .; then exit 1`)
    // collapses non-empty stdout = violation; the structured form below
    // captures stdout explicitly so a tool error (cargo not installed,
    // metadata I/O failure) is reported separately from a real R13
    // violation. `-i openssl` exits non-zero with empty stdout when the
    // package is absent — that is the success case we want.
    rustls_mandatory_gate(repo_root, &mut failures);
    // utoipa-coverage-gate (Phase 7 U8.8): mirrors the CI job's
    // ast-grep belt-and-suspenders. Clippy's `disallowed_methods`
    // rule (workspace `clippy.toml`) is the primary R7 gate;
    // ast-grep catches macro-expanded chained-builder shapes that
    // do not surface to the lint pass. See
    // `docs/utoipa-coverage-policy.md` for the full coverage split.
    utoipa_coverage_gate(repo_root, &mut failures);

    if failures.is_empty() {
        println!("xtask ci: all gates passed.");
        Ok(())
    } else {
        eprintln!("xtask ci: failed: {}", failures.join(", "));
        Err("ci gate(s) failed".into())
    }
}

/// Run the R2 multi-key-return-gate: two regex checks against return-type
/// shapes that clippy's `disallowed_methods` cannot express (no
/// return-type predicate). Mirrors the `multi-key-return-gate` job in
/// `.github/workflows/ci.yml`. The two patterns reject any function
/// signature returning `(SecretBox<A>, SecretBox<B>)` or
/// `(SigningKey, SigningKey)` shapes — bundled multi-key loaders that
/// would defeat per-role isolation.
///
/// rg exit codes (per ripgrep manual):
/// * 0  = at least one match found → R2 VIOLATION, fail the gate.
/// * 1  = no matches → success, what we want.
/// * 2+ = rg error (bad pattern, IO error, missing dir, etc.) →
///   tool-level failure, also fail the gate so a broken pattern cannot
///   silently pass.
///
/// `cmd_ok` collapses 0-vs-non-zero, which would treat rg-error (2)
/// as success. Capture the exit status explicitly and gate on exactly
/// code 1.
fn multi_key_return_gate(repo_root: &Path, failures: &mut Vec<&'static str>) {
    // The patterns must match a tuple return type that contains the
    // forbidden ident twice — including the rustfmt-broken multiline
    // shape `fn foo() -> (\n  SecretBox<A>,\n  SecretBox<B>,\n)`.
    // Line-only regexes (e.g., `-> .*SecretBox.*SecretBox`) miss the
    // multiline form: a contributor running `cargo fmt` after writing
    // a one-line tuple return would silently bypass the gate. The
    // `-U` flag enables ripgrep multi-line mode; `[^)]` then spans
    // newlines, so the regex matches the entire content between
    // `->` and the closing tuple paren regardless of formatting.
    for (label, pattern) in [
        (
            "multi-key-return-gate (SecretBox<A>, SecretBox<B>)",
            r"-> \([^)]*SecretBox[^)]*SecretBox",
        ),
        (
            "multi-key-return-gate (SigningKey, SigningKey)",
            r"-> \([^)]*SigningKey[^)]*SigningKey",
        ),
    ] {
        let st = Command::new("rg")
            .args([
                "-U",
                "--type",
                "rust",
                "--quiet",
                "-e",
                pattern,
                "crates/portal-crypto",
                "crates/portal-relay",
                "crates/portal-sdk",
                "crates/portal-net",
            ])
            .current_dir(repo_root)
            .status();
        match st {
            Ok(s) => match s.code() {
                Some(1) => {} // no match → success
                Some(0) => {
                    eprintln!("xtask ci: {label} matched a forbidden return-type shape");
                    failures.push(label);
                }
                Some(other) => {
                    eprintln!("xtask ci: {label} rg exited {other} (tool error, not a no-match)");
                    failures.push(label);
                }
                None => {
                    eprintln!("xtask ci: {label} rg terminated without exit code");
                    failures.push(label);
                }
            },
            Err(e) => {
                eprintln!("xtask ci: failed to run rg for {label}: {e}");
                failures.push(label);
            }
        }
    }
}

/// Run the Phase 7 U8.8 utoipa-coverage ast-grep belt-and-suspenders.
/// Mirrors the four `ast-grep run --pattern …` invocations in the
/// `utoipa-coverage-gate` CI job (`.github/workflows/ci.yml`).
///
/// ast-grep exits 0 always (per its CLI contract); match output goes
/// to stdout. Any non-empty stdout from any of the four patterns is a
/// gate failure. Spawn errors (ast-grep not installed, etc.) are
/// reported as gate failures rather than warnings so the local
/// mirror does not silently pass when a tool is missing — matches
/// the iteration-38 taplo / iteration-40 rustls-mandatory contract.
///
/// Bound-to-var rebinds (`let r = Router::new(); r.route(...)`) are
/// the policy-documented escape from this gate; clippy's
/// `disallowed_methods` is the primary gate that catches them by
/// `DefId`. See `docs/utoipa-coverage-policy.md` §Enforcement note 2.
fn utoipa_coverage_gate(repo_root: &Path, failures: &mut Vec<&'static str>) {
    const PATTERNS: &[&str] = &[
        "Router::new().route($$$ARGS)",
        "Router::new().nest($$$ARGS)",
        "axum::Router::new().route($$$ARGS)",
        "axum::Router::new().nest($$$ARGS)",
    ];
    const SCAN_PATHS: &[&str] = &["crates/portal-relay/src", "crates/portal-sdk/src"];
    // ast-grep exit codes (0.39 series, observed locally):
    //   0  = matches found (output on stdout) OR pattern-parse warning
    //        path with no matches.
    //   1  = no matches OR run-level error (e.g., path not found —
    //        emits `ERROR: <path>: ...` on stderr).
    //   2+ = catastrophic failure.
    // Because exit 1 covers BOTH "no match" (success) and "bad path"
    // (failure), the discriminator is stderr: ast-grep emits an
    // `ERROR:` line on stderr when the run itself failed, and is
    // silent on stderr when the run was clean (pattern just did not
    // match). The CI workflow's bash form collapses non-empty stdout
    // to violation and silently passes on stderr-only failures
    // (`matches="$(... )"` captures stdout only); the local mirror
    // is stricter — stderr containing `ERROR:` is reported as a probe
    // failure rather than collapsed into success.
    const RUN_ERROR_MARKER: &str = "ERROR:";
    let mut violation = false;
    for pattern in PATTERNS {
        let mut args: Vec<&str> = vec!["run", "--pattern", pattern, "--lang", "rust"];
        args.extend_from_slice(SCAN_PATHS);
        let output = Command::new("ast-grep")
            .args(&args)
            .current_dir(repo_root)
            .output();
        match output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let exit_code = out.status.code();
                let benign_no_match =
                    matches!(exit_code, Some(0 | 1)) && !stderr.contains(RUN_ERROR_MARKER);
                if !benign_no_match && out.stdout.is_empty() {
                    eprintln!(
                        "xtask ci: utoipa-coverage-gate ast-grep error for pattern `{pattern}` \
                         (exit {exit_code:?}):\nstderr: {stderr}"
                    );
                    violation = true;
                } else if !out.stdout.is_empty() {
                    eprintln!(
                        "xtask ci: utoipa-coverage-gate matched `{pattern}`:\n{}",
                        String::from_utf8_lossy(&out.stdout)
                    );
                    violation = true;
                }
                // benign no-match (clean stderr, exit 0/1, empty stdout) →
                // implicit success: nothing to report.
            }
            Err(e) => {
                eprintln!(
                    "xtask ci: utoipa-coverage-gate failed to spawn ast-grep \
                     (install: cargo install ast-grep --locked): {e}"
                );
                violation = true;
                break;
            }
        }
    }
    if violation {
        failures.push("utoipa-coverage-gate");
    }
}

/// Run the R13 rustls-mandatory gate: assert `cargo tree --workspace
/// --no-default-features -i openssl` proves openssl is not in the
/// resolved tree. Mirrors the `rustls-mandatory` job in
/// `.github/workflows/ci.yml`.
///
/// Three distinct outcomes, each handled explicitly so cargo errors
/// cannot silently pass the gate:
///
/// * Non-empty stdout → openssl IS in the tree → R13 violation, fail.
/// * Empty stdout + stderr contains the canonical
///   `did not match any packages` (cargo's "package not in graph"
///   message) → success: openssl is absent from the resolved tree.
/// * Empty stdout + any other stderr (or no stderr at all) → cargo
///   itself failed (network, manifest parse, OS error) → probe
///   failure, fail. Treating these as success would let R13
///   silently regress when cargo is broken.
/// * Spawn error (cargo not installed) → also a probe failure;
///   matches the "mirrors CI" contract since CI runs cargo
///   unconditionally.
fn rustls_mandatory_gate(repo_root: &Path, failures: &mut Vec<&'static str>) {
    const NOT_IN_GRAPH_MARKER: &str = "did not match any packages";
    let output = Command::new("cargo")
        .args([
            "tree",
            "--workspace",
            "--no-default-features",
            "-i",
            "openssl",
        ])
        .current_dir(repo_root)
        .output();
    match output {
        Ok(out) if !out.stdout.is_empty() => {
            eprintln!(
                "xtask ci: rustls-mandatory (R13) violated — openssl in resolved tree:\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
            failures.push("rustls-mandatory (transitive openssl)");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains(NOT_IN_GRAPH_MARKER) {
                // Canonical "package not in graph" — the success case.
            } else {
                eprintln!(
                    "xtask ci: rustls-mandatory probe — cargo tree exited without the expected \
                     '{NOT_IN_GRAPH_MARKER}' message:\nstdout: <empty>\nstderr: {stderr}"
                );
                failures.push("rustls-mandatory (probe error)");
            }
        }
        Err(e) => {
            eprintln!("xtask ci: rustls-mandatory probe failed to spawn cargo: {e}");
            failures.push("rustls-mandatory (probe error)");
        }
    }
}

/// Verify [`MSRV_MEMBERS`] matches the `[workspace] members` list in the
/// root `Cargo.toml`, ignoring `xtask` (which is not separately gated).
///
/// Drift between the two would silently drop MSRV coverage on whichever
/// member was added without updating the constant; this check turns that
/// silent gap into a noisy failure.
fn assert_msrv_members_match_workspace(repo_root: &Path) -> Result<(), String> {
    let toml_path = repo_root.join("Cargo.toml");
    let body = std::fs::read_to_string(&toml_path)
        .map_err(|e| format!("read {}: {e}", toml_path.display()))?;
    // The `[workspace] members = [ ... ]` array is intentionally extracted
    // by string scanning rather than full TOML parsing — xtask has no toml
    // dependency and adding one for a 10-line scan is overkill. The
    // workspace root's members block is single-line-per-entry by
    // convention; if a future contributor reformats it, this scan
    // continues to work as long as each entry is "crates/<name>" or
    // "xtask" inside the array literal.
    let members_section = body
        .split_once("\nmembers = [")
        .ok_or("workspace Cargo.toml missing `members = [` block")?
        .1;
    let members_end = members_section
        .find(']')
        .ok_or("workspace Cargo.toml `members = [` block has no closing `]`")?;
    let block = &members_section[..members_end];
    let mut found: Vec<String> = Vec::new();
    for line in block.lines() {
        let trimmed = line.trim().trim_end_matches(',').trim_matches('"');
        if trimmed.is_empty() || trimmed == "xtask" {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("crates/") {
            found.push(rest.to_owned());
        }
    }
    let mut declared: Vec<String> = MSRV_MEMBERS.iter().map(|s| (*s).to_owned()).collect();
    found.sort();
    declared.sort();
    if found == declared {
        Ok(())
    } else {
        Err(format!(
            "MSRV_MEMBERS = {declared:?} but workspace Cargo.toml has \
             crates/ members = {found:?}; update MSRV_MEMBERS in xtask/src/main.rs"
        ))
    }
}

fn cmd_ok(repo_root: &PathBuf, program: &str, args: &[&str]) -> bool {
    cmd_ok_with_env(repo_root, program, args, &[])
}

fn cmd_ok_with_env(
    repo_root: &PathBuf,
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> bool {
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(repo_root);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let st = cmd.status();
    match st {
        Ok(s) if s.success() => true,
        Ok(_) => false,
        Err(e) => {
            eprintln!("xtask ci: failed to run {program} {}: {e}", args.join(" "));
            false
        }
    }
}
