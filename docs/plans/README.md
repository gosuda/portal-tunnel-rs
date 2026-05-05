# Per-phase implementation plans

Each phase of the portal-tunnel-rs port has a downstream plan committed
here, spawned ahead of code via `/ce-plan` runs and reviewed by
`ce-feasibility-reviewer` + `ce-adversarial-document-reviewer` before
implementation begins. PLAN.md (workspace root) is the roadmap that
sequences phases; this directory holds the per-phase contract.

## Naming convention

`YYYY-MM-DD-NNN-feat-<crate-or-feature>-plan.md`

- `YYYY-MM-DD` — date the plan was first committed.
- `NNN` — sequential plan ordinal (001 = Phase 1, 002 = Phase 2, …).
- `feat` — conventional-commits prefix; every plan ships a feature
  surface (no separate `chore-plan` or `fix-plan` shape).
- `<crate-or-feature>` — short slug naming what the plan owns.

## Index

| ID  | Plan | Phase | Owns |
|---|---|---|---|
| 001 | [`feat-portal-wire-plan.md`](2026-05-04-001-feat-portal-wire-plan.md) | 1 | Wire protocol types, codecs, U16 drift gate, U17 proptest suites |
| 002 | [`feat-portal-crypto-plan.md`](2026-05-04-002-feat-portal-crypto-plan.md) | 2 | ed25519 + secp256k1 + SIWE + envelope sign/verify + ENS resolver |
| 003 | [`feat-portal-net-plan.md`](2026-05-04-003-feat-portal-net-plan.md) | 3 | quinn QUIC backhaul + dual-stack listeners + TCP/UDP relay |
| 004 | [`feat-portal-acme-plan.md`](2026-05-04-004-feat-portal-acme-plan.md) | 4 | ACME (instant-acme) + Local/Cloudflare/Route53/Cloud DNS providers |
| 005 | [`feat-portal-relay-plan.md`](2026-05-04-005-feat-portal-relay-plan.md) | 5 | Lease registry + admin/sdk/discovery API + R10 reputation engine |
| 006 | [`feat-portal-sdk-plan.md`](2026-05-04-006-feat-portal-sdk-plan.md) | 6a | Client expose + listener + RFC-5705 MITM probe + eclipse-resistant picker |
| 007 | [`feat-portal-relay-overlay-keyless-plan.md`](2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md) | 6b | Keyless mTLS endpoint + sealed `WgDevice` overlay + smoltcp |
| 008 | [`feat-binaries-and-e2e-plan.md`](2026-05-04-008-feat-binaries-and-e2e-plan.md) | 7 | Three binaries + e2e harness + behavioral-trace + release pipeline |

## No Phase 0 plan

Phase 0 has no standalone plan because its scope is the workspace
bootstrap that the eight phase plans consume — the workspace
`Cargo.toml`, `rust-toolchain.toml`, ADRs 0001-0005, the rewritten
`AGENTS.md`, `deny.toml`, `prek.toml`, `.cargo/config.toml`,
`.github/workflows/ci.yml`, the xtask skeleton, `docs/architecture.md`,
and the nine member-crate stubs. Phase 0 status lives in `PLAN.md`
under "Current implementation status" alongside the per-phase
landed/partial/pending state.

## Frontmatter shapes

Plans use one of two YAML frontmatter shapes (committed-as-is from
their original `/ce-plan` runs):

- **Shape A** (`title` / `type` / `status` / `date` / `origin`):
  used by 001 portal-wire, 003 portal-net, 004 portal-acme, 005
  portal-relay, 006 portal-sdk, 007 overlay+keyless. The `status`
  field is `active` for in-flight plans.
- **Shape B** (`name` / `overview` / `todos`): used by 002
  portal-crypto and 008 binaries-and-e2e. The `todos` array carries
  per-unit `id` + `content` + `status` (`status: pending|in_progress
  |completed` per unit).

Plan-level "is this phase landed?" status does NOT live in the
frontmatter under either shape. The canonical per-phase
landed/partial/pending state lives in `PLAN.md` "Current
implementation status"; per-unit / per-batch state lives in the plan
body's implementation-units section (Shape A) or the `todos` array
(Shape B). Frontmatter `status: active` means "this plan is the
contract; do not reopen without ADR amendment", not "phase is
incomplete" — `active` is preserved even after the phase fully lands.

Reopening an active plan requires the ADR-amendment procedure
([`docs/adr/README.md`](../adr/README.md) §Amendment procedure); ad-hoc
plan rewrites mid-phase are out of process.
