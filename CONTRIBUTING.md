# Contributing to portal-tunnel-rs

Thank you for considering a contribution. This document captures the
non-negotiables; the why-we-chose-X rationale lives in `docs/adr/`.

## Toolchain

| Tool | Version | Install |
|---|---|---|
| Rust | `1.91` (workspace MSRV) | `rust-toolchain.toml` auto-installs via rustup |
| `prek` | latest | `cargo install prek` (Rust-native) or `pip install prek` (the pip distribution ships the prebuilt Rust binary; no Python runtime needed at hook invocation) |
| `taplo-cli` | latest | `cargo install taplo-cli --locked` |
| `cargo-deny` | latest | `cargo install cargo-deny --locked` |
| `cargo-machete` | latest | `cargo install cargo-machete --locked` |
| `cargo-msrv` | latest | `cargo install cargo-msrv --locked` |
| `cargo-llvm-cov` | latest | `cargo install cargo-llvm-cov --locked` |
| `cargo-nextest` | latest | `cargo install cargo-nextest --locked` |

## Git hooks

After cloning, run `prek install` once. This wires the `prek.toml` hooks into
`.git/hooks/`. Pre-commit runs cargo fmt --check, clippy -D warnings, taplo
fmt --check, and cargo machete; pre-push runs the full nextest suite.

`cargo xtask ci` (alias `cargo ci`) runs the same gate set CI runs.

## Atomic commits

One concern per commit. ≤200 LoC substantive diff (file moves and generated
files do not count). When a change set has more than one concern, split it
before committing — `git add -p` and `git commit --interactive` help. Commit
messages follow Conventional Commits:

```
<type>(<scope>): <imperative subject>

<body explaining the why, not the what>
```

Types: feat, fix, docs, style, refactor, perf, test, chore, build, ci.

## ADR amendment procedure (Engineering Defaults deviations)

R7-R9 Engineering Defaults, the cargo-deny ban list, and any "Resolved During
Planning" decision in the roadmap may be reopened **only via ADR amendment**.

To deviate (example: add `chrono` to the workspace):

1. Open a PR that includes the dep change AND the ADR amendment in the same
   commit.
2. The ADR amendment cites the original ADR (typically ADR-0002 for register
   bans), names the rationale that no longer holds, lists the considered
   alternatives, and documents the impact on phase plans.
3. cargo-deny `bans` table is updated in the same commit (the ban removal is
   part of the amendment).
4. Pass `ce-doc-review` (or the equivalent reviewer for cross-cutting
   amendments) before merging.

Mid-flight reversals via TODO are out of process — see the Decision Stability
clause in `AGENTS.md`.

## Code style

- Edition 2024 native idioms only: native async-fn-in-trait, `let-else`,
  `let-chains`, `use<>` lifetime captures.
- `forbid(unsafe_code)` workspace-wide.
- `clippy::pedantic + cargo + nursery` warn at priority -1; `unwrap_used` +
  `expect_used` deny.
- Per-lint silence uses `#[expect(lint_name, reason = "…")]`, never
  `#[allow]`.
- Errors: `thiserror` per crate with `#[non_exhaustive]`; `eyre` only at
  `main` boundaries with `color-eyre::install()`.
- Secrets: every key/token wrapped in `secrecy::SecretBox<T>` newtype.
- Async traits that need Send bounds: `trait_variant::make` (see
  `docs/architecture.md`).

## Phase posture

The roadmap [`PLAN.md`](PLAN.md) sequences work into 8 phases (0-7).
Phases 1-7 each have a downstream phase plan in
[`docs/plans/`](docs/plans/) (`...-001-feat-portal-wire-plan.md` through
`...-008-feat-binaries-and-e2e-plan.md`), spawned ahead of code via
`/ce-plan` runs. Phase 0 has no standalone plan — its scope is the
workspace bootstrap that the eight phase plans consume; Phase 0 state
lives in `PLAN.md` under "Current implementation status" alongside
per-phase landed/partial/pending state.

## Certifying dependencies (`cargo-vet`)

When `cargo vet check` flags a missing audit during local
verification, do **not** run `cargo vet certify` reflexively to
silence the gate. A certification is an attestation that the
contributor has read the dep's source at the named version and
satisfied themselves it meets the cargo-vet criteria (no malicious
behavior, no unsafe-without-justification, no shell-out, etc. for
`safe-to-deploy`; the relaxed `safe-to-run` set for dev-only deps).
See the [cargo-vet book](https://mozilla.github.io/cargo-vet/) for
the full criteria reference.

After completing that review, record the attestation:

```sh
cargo vet certify <crate-name> <version> --criteria safe-to-deploy
# or for dev-only deps:
cargo vet certify <crate-name> <version> --criteria safe-to-run
```

The entry is appended to `supply-chain/audits.toml`. If a review
isn't feasible (large crate, time-boxed contribution), open an issue
requesting an exemption rather than certifying without review;
imported audit sets and policy live in `supply-chain/config.toml`.

## Reporting bugs / security issues

Bugs: open a GitHub issue with reproduction steps and `cargo --version` /
`rustc --version` / OS info.

Security issues: see `SECURITY.md`. Do not file public issues for
vulnerabilities.
