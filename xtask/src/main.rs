//! Workspace task runner — codegen, release, openapi-export, dep-audit,
//! refresh-frontend-bundle, and wire-protocol drift gate (Phase 1 U16).

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
    /// Run fmt, clippy, nextest, deny, machete, coverage (mirrors CI intent; best-effort locally).
    Ci,
    /// v0.2-backlog stub for the utoipa coverage CI gate (Phase 7 U8.8).
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

    if failures.is_empty() {
        println!("xtask ci: all gates passed.");
        Ok(())
    } else {
        eprintln!("xtask ci: failed: {}", failures.join(", "));
        Err("ci gate(s) failed".into())
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
