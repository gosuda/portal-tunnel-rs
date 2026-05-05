# portal-tunnel-rs

Modern Rust 2024 reference implementation of the Portal relay-tunnel system.
Greenfield port of [`gosuda/portal-tunnel`](https://github.com/gosuda/portal-tunnel)
v2.1.8 — the Go upstream is the behavioral specification; the Rust port owns
the wire (see [ADR-0001](docs/adr/0001-greenfield-wire.md)).

> **Status**: Active development on `refact/rework`. Per-phase
> landed/partial/pending state and per-commit gate state (U16 wire-drift
> marker, U17 `PROPTEST_CASES=4096` proptest suites, plus the workspace
> CI matrix) live in [`PLAN.md`](PLAN.md) under "Current implementation
> status"; CI runs the same gates on every PR. v0.1 ships when Phases
> 1-5 + 6a + 7-minus-overlay land; v0.2 backlog is enumerated in the
> roadmap plan.

## Quick links

- Architecture overview — [`docs/architecture.md`](docs/architecture.md)
- Architecture decision records — [`docs/adr/README.md`](docs/adr/README.md)
- Constitution / agent operating rules — [`AGENTS.md`](AGENTS.md)
- Contribution guide — [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy — [`SECURITY.md`](SECURITY.md)

## Compatibility / Supported clients

> Reserved section. Populated in Phase 7 release prep (see
> [ADR-0004](docs/adr/0004-supported-clients-and-upgrade-encouragement.md))
> with the user-visible upgrade-encouragement matrix:

- TLS 1.2 acceptance posture + sunset criterion
- RSA signature acceptance posture
- ML-KEM hybrid KEX rollout schedule
- ECH-aware tenant TLS routing + plaintext-SNI fallback sunset
- IPv4-only listener operator opt-in
- Server-side ECH on relay HTTPS deferral (rustls#1980 pending)

## License

MIT. See `LICENSE` (Phase 7 deliverable; until then, refer to the workspace
manifest's `[workspace.package].license`).
