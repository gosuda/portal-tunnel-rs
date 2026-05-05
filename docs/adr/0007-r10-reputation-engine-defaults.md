# ADR-0007: R10 v0.1 reputation engine defaults

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: Phase 5 plan §"R10 v0.1 reputation engine flow"; commit `6f298be` (`crates/portal-relay/src/policy/reputation.rs`); roadmap R10 (v0.1 leg); `docs/threat-model.md` §"R10 threat classes (a-h)"; `docs/release-notes/v0.1-r10-threat-mapping.md`

## Context and problem statement

Phase 5 lands the per-relay R10 v0.1 reputation engine: a governor-keyed
`(identity, ip, lease)` adaptive rate limiter plus a per-identity exponential-
decay reputation scalar. The engine's `decide()` function returns
`Allow` / `Backpressure(Duration)` / `Block(Reason)` based on the score;
`record_signal()` accumulates weighted signals (rate-limit hits, honeypot
matches, blocked-request observations).

Five numeric defaults govern the engine's behaviour:

1. **Decay half-life** — how long does a reputation signal persist?
2. **Block threshold** — what score forces a `Block` decision?
3. **Backpressure threshold** — what score forces a yield-before-forward?
4. **Backpressure yield duration** — how long does the handler sleep?
5. **Governor quota** — what's the per-triple rate-limit shape?

Plus per-signal weights for `record_signal`:
- Rate-limit hit weight.
- Honeypot match weight (per plan U12 §Approach: 25.0).
- Blocked-request weight.

Without an ADR, these constants are ambient choices. With an ADR, future
amendments are tracked, downstream operators see the rationale for each
default, and the per-relay defense posture is auditable.

## Decision

The engine ships with the constants below as workspace defaults. Each is a
`pub const` in `crates/portal-relay/src/policy/reputation.rs` so call sites
import the same source of truth. Operator overrides land via
`ReputationConfig` (consumed at engine construction time; hot-reload via
`arc-swap<ReputationConfig>` is a separate U13 follow-up).

### Decay parameters

| Constant | Value | Rationale |
|---|---|---|
| `REPUTATION_DECAY_HALF_LIFE_SECS` | `86_400.0` (24 h) | A tenant that earns reputation points and then goes quiet sees the score halve every 24 h. Long enough that a single bad actor cannot wash out by waiting overnight; short enough that a now-reformed identity is not blocked forever. |
| `REPUTATION_DECAY_CONSTANT` | `ln(2) / 86_400.0` | Derived from the half-life. Pinned as a `f64` constant (not recomputed) — `f64::ln` is not `const fn` yet, so the canonical value is inlined and unit-tested for the round-trip. |

### Decision thresholds

| Constant | Value | Rationale |
|---|---|---|
| `REPUTATION_BLOCK_THRESHOLD` | `100.0` | Round-number ceiling. With the per-signal weights below, a tenant that produces 4 honeypot hits in a 24 h window crosses the threshold; a tenant generating only rate-limit pressure takes ~20 separate hits. Both shapes name plausible adversarial behaviour, not legitimate traffic. |
| `REPUTATION_BACKPRESSURE_THRESHOLD` | `50.0` | Half the block threshold. Tenants in the 50-100 band experience yield-before-forward — a soft signal that protects relay capacity without an explicit refusal. |
| `REPUTATION_BACKPRESSURE_YIELD_MS` | `50` ms | Conservative — enough to feel adversarial-noticeable jitter without stalling a single legitimate burst behind a rate-limit hit. The 50 ms upper bound keeps p99 request latency for cooperating tenants well under typical TLS handshake budgets. |

### Per-triple rate-limit quota

| Constant | Value | Rationale |
|---|---|---|
| `REPUTATION_GOVERNOR_BURST` | `100` req | Matches the per-tenant keyless-policy burst (`KEYLESS_TENANT_BURST` in `crates/portal-relay/src/keyless/policy.rs`). A CDN-style tenant doing pipelined TLS handshakes during a traffic ramp can comfortably handle 100 in-flight requests. |
| `REPUTATION_GOVERNOR_SUSTAINED_RPS` | `50` req/s | Matches `KEYLESS_TENANT_SUSTAINED`. The 2:1 burst-to-sustained ratio is governor's recommended starting shape and well above the ~1 req/s/handshake/min observed at healthy CDN nodes. |

The governor key is the `(IdentityKey, IpAddr, LeaseId)` triple — a single
identity issuing multiple leases is rate-limited per-lease, and a single
identity reused across multiple IPs is rate-limited per-IP. This makes
identity-rotation by an attacker more costly than just the SIWE
re-signing step.

### Per-signal weights

| Signal kind | Weight | Rationale |
|---|---|---|
| `SignalKind::RateLimited` | `5.0` | A rate-limit hit is signal but not strong proof of abuse — legitimate bursty tenants can trip it. ~20 hits in a 24 h window are needed to cross the block threshold. |
| `SignalKind::HoneypotHit` | `25.0` | A honeypot path match is high-signal — production tenants do not request `/.env` or `/.git/config`. The plan U12 explicit value of 25.0 is preserved here (4 hits across a 24 h decay window cross the block threshold). |
| `SignalKind::BlockedRequest` | `10.0` | A previously-blocked request retried is moderate signal — the tenant has already seen one refusal and is re-trying. ~10 retries in a 24 h window cross the threshold. |

These weights interact with the decay constant: any individual signal halves
in 24 h, so an attacker accumulating exactly the threshold-equivalent each
day stays at or just above the block line indefinitely. Lower-volume
attackers wash out within 1-3 half-life windows; this is by design — v0.1's
goal is to make sustained attacks unprofitable, not to permanently brand
identities on a single misstep.

## Consequences

### Positive

- **Auditable defaults.** Each constant has a one-paragraph rationale; downstream operators amending via `ReputationConfig` understand the trade-off they are flipping.
- **Symmetric with keyless quotas.** The governor burst/sustained values match `KEYLESS_TENANT_BURST` / `KEYLESS_TENANT_SUSTAINED` so a tenant hitting both surfaces sees coherent rate-limit behaviour.
- **Cross-relay propagation deferred but reachable.** The engine emits `record_signal` at every decision point; v0.2 cross-relay propagation (`ReputationDelta` envelope per `docs/wire-protocol.md` reservation) reads from the same store without re-shaping the per-relay defense.
- **R10 a-h class coverage** is documented in [`docs/release-notes/v0.1-r10-threat-mapping.md`](../release-notes/v0.1-r10-threat-mapping.md) — each class names its v0.1 mitigation status against these defaults.

### Negative — accepted

- **Per-relay scope only.** Cross-relay coordination (b — coordinated cross-relay abuse; e — hop-mux laundering) defers to v0.2. The defaults above are tuned for single-relay traffic; an attacker splitting load across N relays sees `N × block_threshold` headroom before any defense fires. v0.2 trigger criterion: ≥1 operator with >2 relays reports false-positive rate-limiting at single-relay scope (see `PLAN.md` §"v0.2 Backlog freeze trigger").
- **Honeypot path matcher not yet wired.** The `HoneypotHit` signal weight is set; the matcher lives behind a TODO(R10-followup) marker in `reputation.rs`. Until the matcher lands, this signal is recorded only by code paths that explicitly identify a honeypot match.
- **No ENS Sybil-gating bypass yet.** The plan U12's "ENS-named identity bypasses block_threshold" carve-out is a TODO(R10-followup) marker. Without ENS gating, a high-reputation cooperating tenant who issues many leases under one identity is treated identically to a low-reputation attacker — a known v0.1 false-positive shape that the bypass is designed to address.
- **Persistence to `reputation.json` is a TODO.** Engine state is in-memory until U5 atomic-write integration lands (separate Phase 5/U12 follow-up commit). Process restart loses accumulated reputation; an attacker can wash by triggering a relay restart. Operators who care can pin restart cadence as part of the deployment posture.

## Considered alternatives

### A. Larger half-life (7-day or 30-day decay)

Pros: a single bad actor cannot quickly recover from a block. Cons: forgiving cooperating tenants who hit a transient signal misfires for a week or a month — operationally bad. **Rejected** in favour of the 24 h shape.

### B. Lower block threshold (10.0 — single-honeypot-hit blocks)

Pros: aggressive defense; one honeypot hit ends the conversation. Cons: false-positive rate too high — a misconfigured legitimate tenant accidentally requesting `/.env` (e.g., a Kubernetes liveness probe checking a path it shouldn't) is permanently blocked. **Rejected** in favour of the 4-hit threshold (100.0 / 25.0).

### C. Hard-bake the constants into the type system (no `ReputationConfig`)

Pros: simpler engine; one less knob. Cons: operators tuning the workspace defaults at deployment time have no path; every default change requires a code patch + redeploy. **Rejected** — `ReputationConfig` is the operator-tuneable surface; this ADR pins the workspace defaults that the config defaults to.

### D. Move the defense to v0.2 in full (skip R10 v0.1)

Pros: zero false-positive surface in v0.1; no defense to misconfigure. Cons: leaves v0.1 with no per-relay anti-abuse defense whatsoever — every tenant has unbounded rate-limit-only protection. R10 a-h enumerates eight threat classes; classes a, c, d, f, g, h are all addressable at the per-relay scope. **Rejected** — v0.1 ships with the defaults above; v0.2 adds cross-relay coordination.

## Amendment procedure

Per [`docs/adr/README.md`](README.md), this ADR's defaults can be reopened
only via ADR amendment. An amendment names this ADR, cites the rationale
that no longer holds (e.g., "operator data shows 24 h half-life produces a
1% false-positive rate; recommend 12 h"), and ships in the same commit as
the constant change.

Operator tuning via `ReputationConfig` does NOT require an amendment — that
surface is the per-deployment escape hatch. The amendment requirement
applies only to changes to the WORKSPACE DEFAULT values (the `pub const`s
in `reputation.rs`).

## References

- `crates/portal-relay/src/policy/reputation.rs` — workspace-default
  constants + `ReputationConfig` consumer surface.
- Phase 5 plan: [`docs/plans/2026-05-04-005-feat-portal-relay-plan.md`](../plans/2026-05-04-005-feat-portal-relay-plan.md) §"R10 v0.1 reputation engine flow" + U12.
- Roadmap R10 (v0.1 leg) — per-relay defense scope statement.
- [`docs/threat-model.md`](../threat-model.md) §"R10 threat classes (a-h)" — adversary catalog.
- [`docs/release-notes/v0.1-r10-threat-mapping.md`](../release-notes/v0.1-r10-threat-mapping.md) — per-class v0.1 mitigation status against these defaults.
- ADR-0002 — modern register that selects `governor 0.10` + `papaya 0.2` (the engine's load-bearing crates).
