# ADR-0002: Aggressive 2026 Rust register; banned-crates list

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0001 (greenfield-wire decision that this register supports), the
  cargo-deny `bans` table this ADR authorizes

## Context and problem statement

The Rust port positions itself as a 2026 reference implementation of Portal.
Crate selection is a load-bearing constraint: every dependency we accept costs
attention surface, supply-chain audit budget, and a long-tail upgrade path. The
Rust ecosystem has bifurcated by 2026 into a "modern" register (sans-I/O typed
crates with deterministic codecs and structured concurrency) and a "legacy"
register (the pre-edition-2024 incumbents whose APIs predate `async fn` in
traits, `let-else`, `let-chains`, and the `std::sync::OnceLock` that obviates
the singleton-cell crates).

Without a hard register pinned at workspace bootstrap, downstream phase plans
will reach for whichever crate Stack Overflow surfaces first — typically the
incumbent — and the modern picks become advisory rather than enforced.

## Decision

R7-R9 are codified as **Engineering Defaults** in `AGENTS.md`. Deviation from
any default requires an ADR amendment in the same commit as the dep change. The
ban list ships in `deny.toml`; the amendment procedure is documented in
`docs/adr/README.md`.

### Modern picks (mandatory; ban list enforces the inverse)

| Concern | Pick | Replaces | Tier 1 source |
|---|---|---|---|
| TLS | `rustls 0.23` + `aws-lc-rs` (R13 MANDATORY) | `openssl`, `native-tls` | [rustls docs](https://docs.rs/rustls/) + cargo-deny canonical `deny.toml` |
| Time | `jiff 0.2` | `chrono`, `time` | [jiff README](https://docs.rs/jiff/) |
| Parser | `winnow 1` | `nom` | [winnow README](https://docs.rs/winnow/) |
| Builder | `bon 3` | `derive_builder`, `typed-builder`, hand-rolled | [bon docs](https://docs.rs/bon/) |
| Async-fn-in-trait | edition-2024 native + explicit `impl Future<Output = ...> + Send + 'a` RPIT for Send-bound shapes (per Amendment 2026-05-04 below; supersedes the original `trait_variant` pick) | `async-trait` macro, `trait_variant::make` | rustc 1.75+ stabilization notes; canonical pattern in [`crates/portal-crypto/src/ens/alloy_resolver.rs`](../../crates/portal-crypto/src/ens/alloy_resolver.rs) |
| Singleton cell | `std::sync::OnceLock` | `lazy_static`, `once_cell` | rustc 1.70+ stabilization |
| Coverage | `cargo-llvm-cov` | `tarpaulin` | [cargo-llvm-cov README](https://github.com/taiki-e/cargo-llvm-cov) |
| Bench | `divan` (iterative) + `criterion` permitted (CI regression detection) | none | [divan README](https://docs.rs/divan/) |
| Concurrent map | `papaya 0.2` (read-heavy with `pin_owned()` for await-crossing) | `dashmap` (write-heavy fallback only) | [papaya docs](https://docs.rs/papaya/) |
| Hot-reload config | `arc-swap` | `RwLock<Arc<Config>>` | [arc-swap docs](https://docs.rs/arc-swap/) |
| Rate limit | `governor 0.10` | hand-rolled token buckets | [governor docs](https://docs.rs/governor/) |
| Secrets | `secrecy::SecretBox<T>` | bare `String` | [secrecy docs](https://docs.rs/secrecy/) |
| Short identifiers | `compact_str` | `String` (where applicable) | [compact_str docs](https://docs.rs/compact_str/) |
| HTTP server | `axum 0.8` + `hyper 1` + `tower` | `actix-web`, `warp` | [axum docs](https://docs.rs/axum/) |
| Inner binary codec | `postcard` | JSON for binary envelopes | [postcard docs](https://docs.rs/postcard/) |
| OpenAPI | `utoipa 5` + `utoipa-axum` | hand-written specs | [utoipa README](https://docs.rs/utoipa/) |
| Git hooks | `prek` (Rust-native) | `lefthook` (Go), `pre-commit` (Python) | [prek README](https://github.com/j178/prek); used by CPython/Airflow/FastAPI 2026 |
| QUIC | `quinn 0.11` | `quic-go` (port) | [quinn docs](https://docs.rs/quinn/) |
| ACME | `instant-acme 0.8` | `lego` (port) | [instant-acme docs](https://docs.rs/instant-acme/) |
| Eth ecosystem | `alloy` | `ethers-rs` (deprecated) | [alloy docs](https://docs.rs/alloy/) |
| TUI | `ratatui 0.30` + `ratatui-crossterm` | none in upstream | [ratatui README](https://ratatui.rs/) |
| AWS Route53 | `aws-sdk-route53 1` (rt-tokio + default-https-client; FEAS-R2-4) | port via lego | [aws-sdk-route53 docs](https://docs.rs/aws-sdk-route53/) |

### Banned direct dependencies

`deny.toml` enforces these direct-dep bans. Transitive occurrences are accepted
via `bans.skip` / `bans.skip-tree` with explicit `reason` strings — pattern
matches cargo-deny's own canonical config.

#### TLS competitors (rustls-MANDATORY per R13)

- `openssl`, `openssl-sys` — collapses the FIPS-able + supply-chain-audit story
- `libssh2-sys` — pulls openssl transitively
- `cmake` — use `cc` instead; cmake-build-system in dep tree pulls a C
  toolchain footprint we do not need

CI gate: `cargo tree --workspace -i openssl` reports nothing. A PR that
introduces a transitive openssl pull fails CI; resolution requires an ADR
amendment with documented sunset criterion.

#### Legacy crates (Engineering-Defaults inverse picks)

- `chrono` — use `jiff`
- `nom` — use `winnow`
- `async-trait` — use native async-fn-in-trait + explicit `impl Future + Send + 'a` RPIT for Send-bound shapes (per Amendment 2026-05-04 below; the original `trait_variant` pick was superseded)
- `derive_builder`, `typed-builder` — use `bon`
- `lazy_static`, `once_cell` — use `std::sync::OnceLock` for singletons
- `tarpaulin` — use `cargo-llvm-cov`

`criterion` is **NOT banned**: R8 escape-hatch for CI regression-detection
workflows alongside `divan` for iterative dev. Both are listed in 2026 community
guidance and complement each other.

## Identity tradeoff weighing (per product-lens P2#7)

The aggressive register costs us less Stack Overflow / blog precedent than the
legacy register. The trade is intentional:

- Each modern pick was selected because the legacy alternative either (a)
  predates an edition-2024 capability we want, (b) requires a C-FFI dependency
  that conflicts with our supply-chain story (rustls-MANDATORY), or (c) carries
  a maintenance pattern the project-lifetime cost of which we declined.
- Documentation gap is mitigated by ADR amendments per dep that explain the
  decision, by `cargo vet` audit chains as crates land in Phase 5+, and by
  `docs/architecture.md` documenting the few migration shapes (notably
  `trait_variant` for Send-bound async-trait migration) where the modern pick
  diverges from common Rust tutorials.
- The cost is concentrated in onboarding — once a contributor has internalized
  the register, the daily friction is lower than the legacy register because
  the modern crates have smaller surface area, fewer foot-guns, and unified
  error/secret/concurrency stories.

If a downstream phase plan finds the documentation gap genuinely blocking, the
amendment procedure permits whitelisting an alternative — but the default is
the modern pick, and the burden of evidence sits on the deviation.

## MSRV bump (FEAS-1)

`rust-toolchain.toml` pins **1.91** (bumped from the original 1.87 sketch in
old-`AGENTS.md`). Rationale: `aws-sdk-route53@1.110` declares MSRV 1.91 floor.
Bumping the workspace MSRV to match the toughest dep avoids per-crate MSRV
fragmentation and aligns with the Rust ecosystem's typical 6-month MSRV-bump
cadence.

### Amendment 2026-05-04 — bump 1.91 → 1.95

Per user directive ("Rust latest version is 1.95!!!"), `rust-toolchain.toml`
and `[workspace.package].rust-version` bump from **1.91** → **1.95** to
align with the current latest stable Rust. Rationale: consume current
ecosystem features (edition 2024 polish, async-fn-in-trait stability, const-
fn assertions used in `portal-crypto::DomainSeparator::new`). 1.91 → 1.95 is
a 4-release bump within the Rust ecosystem's typical 6-month MSRV cadence;
existing dep floors (`aws-sdk-route53@1.110` MSRV 1.91) remain satisfied.
The CI matrix `cargo msrv verify` job and the per-toolchain build matrix in
`.github/workflows/ci.yml` were updated in the same commit. The original
1.91-pin prose above is preserved as the historical decision record.

### Amendment 2026-05-04 — async-fn-in-trait Send-bound shape: `trait_variant` → explicit `impl Future + Send` RPIT

The original pick (L39 picks table; L79 banned-deps follow-on) was
"edition-2024 native async-fn-in-trait + `trait_variant` for Send-bound
shapes". During Phase 2 Batch 7 (ENS resolver,
[`crates/portal-crypto/src/ens/alloy_resolver.rs`](../../crates/portal-crypto/src/ens/alloy_resolver.rs)),
`trait_variant::make` was found to expand into proc-macro spans where
`clippy::future_not_send` fires at the macro's internal token positions;
`#[expect(clippy::future_not_send, reason = "...")]` applied at the
trait/item level cannot suppress lint events scoped to the macro's
expansion site, so the workspace `-D warnings` CI gate fails. The
rationale is captured at `alloy_resolver.rs:60-77`'s rustdoc.

**Replacement pick.** Async traits that need Send-bounded futures use
explicit return-position `impl Future<Output = ...> + Send + 'a` syntax in
the trait declaration. The trait body uses non-`async fn` shape so the
`Send` bound on the returned `impl Future` is express, not inferred:

```rust
pub trait EnsResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> impl core::future::Future<Output = Result<EthAddress, EnsError>> + Send + 'a;
}
```

This is the pattern landed in `alloy_resolver.rs` (canonical) and
[`crates/portal-acme/src/provider.rs`](../../crates/portal-acme/src/provider.rs).
The macro-free shape keeps every clippy event at suppressible item-level
spans, preserves the type-level `Send` guarantee, and removes the
`trait_variant` workspace dep (zero member crates currently consume it).

**Impact.** Same-commit changes alongside this amendment:

- `Cargo.toml`: remove the `trait_variant = { package = "trait-variant", version = "0.1" }` workspace dep entry (no member crate consumes it; removal is dead-code cleanup, not a behavior change).
- [`docs/architecture.md`](../architecture.md) §`trait_variant` Send-bound migration shape: rewritten to show the explicit-RPIT pattern.
- [`AGENTS.md`](../../AGENTS.md) §Async traits with Send bounds (L88-93) already prescribes the explicit-RPIT shape and is the constitution; this amendment + architecture.md update brings the ADR + architecture overview into alignment with AGENTS.md and the code.

The L39 picks-table cell and the L79 banned-deps line are updated in the
same commit to name the explicit-RPIT pattern as the current rule, with
inline parenthetical pointers back to this amendment; the historical
`trait_variant` pick is preserved in each row's "Replaces" / rationale
column. The `async-trait` macro ban remains in force.

## Consequences

### Positive

- The Rust port has a single, audit-able crate register. Future contributors
  (human or agent) have one place to look when a "what crate should I use for
  X?" question arises.
- `deny.toml` operationally enforces the register at CI time. A PR that adds
  `chrono` fails CI; remediation is either to use `jiff` or to amend the ADR.
- Type-level R2 trust-boundary enforcement becomes feasible because every
  secret newtype is `secrecy::SecretBox<T>` — no escape hatch via bare `String`.

### Negative — accepted

- Less Stack Overflow precedent per modern pick. Mitigated as above.
- Some crates (`jiff` 0.2, `winnow` 1, `bon` 3, `divan`, `papaya` 0.2, `prek`,
  `instant-acme` 0.8) are pre-1.0 or recently 1.0. Mitigated by `cargo-vet`
  audit chains landing in Phase 5 (deferred from Phase 0 per scope-guardian
  #2 — the supply chain to gate has zero crates at Phase 0 bootstrap).

## Considered alternatives

### A. No register; let downstream pick

Status quo of an unscoped Rust workspace. Every phase plan re-litigates dep
choice. Inconsistent register across crates. Type-level R2 enforcement
degrades because secret-handling policy is per-crate. Rejected on consistency
grounds.

### B. Conservative register — pick incumbents (`chrono`, `nom`, `async-trait`)

Maximizes Stack Overflow precedent. Pulls a heavier C-FFI footprint
(`openssl` is the typical TLS pick alongside `chrono`). Conflicts with the
rustls-MANDATORY R13 commitment. Forecloses the modern Rust idiom story the
port is trying to demonstrate. Rejected.

### C. Aggressive 2026 register — selected

Costs documented above; benefits documented above. The amendment procedure
keeps the choice reversible at per-crate granularity without re-opening the
whole register.

## References

- Roadmap plan: §`Engineering Defaults` (R7-R9), §`Aggressive 2026 register`,
  §`Resolved During Planning` for the per-pick decision trail
- `deny.toml` (Phase 0 commit 7) — ban-list enforcement
- `docs/adr/README.md` — amendment procedure
