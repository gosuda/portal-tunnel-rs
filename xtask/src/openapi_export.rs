//! Phase 7 U8.8 v0.2-backlog stub: `xtask openapi-export`.
//!
//! v0.1 ships the clippy + ast-grep utoipa coverage gate (see
//! `docs/utoipa-coverage-policy.md` and the `utoipa-coverage-gate` CI job).
//! The snapshot test that diffs `ApiDoc::openapi()` against a committed
//! `docs/openapi.yaml` is a v0.2 backlog item.
//!
//! This stub prints the deferral note so contributors who reach for
//! `cargo xtask openapi-export` see a clear pointer to the v0.1 mechanism
//! and the v0.2 follow-up rather than a missing-subcommand error.

pub fn run() {
    println!("xtask openapi-export — v0.2 backlog stub.");
    println!();
    println!("v0.1 coverage gate: clippy `disallowed-methods` (workspace-root");
    println!("`clippy.toml`) + `ast-grep` belt-and-suspenders (CI job");
    println!("`utoipa-coverage-gate` in `.github/workflows/ci.yml`).");
    println!();
    println!("v0.2 follow-up: serialize `ApiDoc::openapi()` to");
    println!("`docs/openapi.yaml`; CI snapshot test asserts the committed");
    println!("file matches the generated output. Trigger criterion: v0.1 ships.");
    println!();
    println!("Policy: docs/utoipa-coverage-policy.md");
    println!("Roadmap: §v0.2 Backlog (utoipa coverage CI gate full implementation).");
}
