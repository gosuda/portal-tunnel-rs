//! Workspace task runner — codegen, release, openapi-export, dep-audit,
//! refresh-frontend-bundle, and wire-protocol drift gate (Phase 1 U16).

use std::path::PathBuf;
use std::process::Command;

use clap::{Parser, Subcommand};

mod openapi_export;
mod wire_drift_check;

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
    if !cmd_ok(repo_root, "cargo", &["machete"]) {
        failures.push("cargo machete");
    }
    if !cmd_ok(repo_root, "cargo", &["msrv", "verify", "--path", "."]) {
        failures.push("cargo msrv verify");
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
