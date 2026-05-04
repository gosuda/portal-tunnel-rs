# ADR-0005: siwe-rs stewardship and v0.2 fork-trigger criterion

## Status

Accepted. 2026-05-04.

## Context

`siwe = "=0.6.1"` (last release Feb 2024) is the canonical Rust port of EIP-4361 Sign-In With Ethereum, written by spruceid. The crate has not received an upstream release in over a year. Notable open issues include alloy 2.x compatibility (PR pending since March 2025).

Phase 2's SIWE wrapper (`crates/portal-crypto/src/siwe/`) and the SEC-002 SIWE→ed25519 binding code consume the upstream crate at the exact 0.6.1 version pin. FEAS-4 in `PLAN.md` flagged the question of whether to fork or pin.

## Decision

**v0.1: pin upstream `siwe = "=0.6.1"` exactly.** No fork. Document v0.2 fork-trigger criteria below.

The exact-version pin (`=0.6.1` not `^0.6.1` or `0.6`) prevents accidental feature regressions if upstream cuts an unannounced patch.

### v0.2 fork-trigger criteria

Fork to a `vendor/siwe-rs` workspace member with `[patch.crates-io] siwe = { path = "vendor/siwe-rs" }` IF AND ONLY IF one of the following fires:

1. **Bug:** A v0.1-shipping bug attributable to `siwe = "=0.6.1"` is reported (issue filed upstream, reproducer in our repo) AND upstream has not published a crates.io release containing the fix within 30 days of the report date.
2. **Compat break:** Alloy 3.x ships and `siwe = "=0.6.1"` cannot satisfy the alloy-types compatibility surface (siwe currently uses alloy 2.x types in its public API).
3. **Maintenance signal:** Upstream archives the repository OR explicitly marks the crate unmaintained on crates.io.

Any other reason to fork (perceived staleness, subjective code smell, "we should own our deps") is **not** sufficient.

## Consequences

- We do not pay the upkeep cost of a vendored fork in v0.1.
- A reported bug becomes a hard 30-day deadline at v0.1 ship; CI tests against the pinned version catch regressions.
- The fork-trigger criteria are unambiguous and date-bound, so the fork-or-don't decision is observable rather than discretionary.
- Phase 2's `verify_binding` and `canonical_statement` are layered on top of the upstream crate — the binding logic itself does NOT depend on upstream-only features, so a v0.2 fork would replace only the parsing/verification layer below the binding.

## Sources

- siwe-rs upstream: <https://github.com/spruceid/siwe-rs>
- Alloy compat PR: see siwe-rs upstream pull-request list for the alloy-2.x integration PR (open since March 2025 as of 2026-05).
- FEAS-4 in `/home/alpha/toys/portal-tunnel-rs/PLAN.md` and Phase 2 plan U6 + U7.

## Related ADRs

- ADR-0002 (aggressive 2026 register): pinning policy and dep-amendment procedure.
- This ADR is the third ADR amendment to ADR-0002's register-pinning rules (after the 1.91→1.95 MSRV amendment).
