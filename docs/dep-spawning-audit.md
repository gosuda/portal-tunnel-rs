# Dependency task-spawning audit (Phase 7 U8.7 / F4)

This document enumerates the per-dependency tokio-task-spawning contract for
every dependency that drives async I/O in `portal-tunnel-rs`. The audit
underwrites portal-tunnel-rs's R9 (structured concurrency) invariant
**without overclaiming**: our code holds R9; transitive deps follow each
dep's own documented contract.

The xtask `dep-audit` subcommand validates that this file is present and
contains every required section. CI fails the build if this file is missing,
empty, or missing any required section. Updating a dep's contract — or
adopting a new dep that spawns tokio tasks — must update the matching
section in the same commit.

## Per-dep contracts

| Dep | Spawns Tasks? | Honors `CancellationToken`? | Shutdown Contract | Risk |
|---|---|---|---|---|
| `quinn` | Yes (per-connection driver) | No | drop the `Endpoint`; connection drivers exit on close | tasks not under our `JoinSet` |
| `axum` + `hyper` | Yes (connection/service drivers; handler futures driven by them) | No | `axum::serve` cancellation OR `.with_graceful_shutdown(...)` PLUS an app-owned timeout/cancellation layer | connection-driving tasks not enclosed by our `JoinSet`; graceful shutdown alone does not bound handler runtime |
| `instant-acme` | No | Yes (drop the future) | drop the order future | none — clean R9 composition |
| `defguard_boringtun` | No (synchronous state machine) | Yes (drop the `Tunn`) | drop `Tunn`; consumer-driven `update_timers()` polling is in our task tree | none — fork's contract; verified at U6 land time |

### `quinn`

`quinn::Endpoint::accept()` is a streaming future the consumer wraps inside
its own `JoinSet`. **Internally, quinn spawns one driver task per inbound
connection** via `tokio::spawn`. These per-connection drivers are NOT
enclosed by any `CancellationToken` we hand to quinn — quinn's connection
lifecycle is anchored to connection-state events (close-frame, idle-timeout,
peer abort), not to caller-controlled cancellation.

**Shutdown contract.** Drop the `Endpoint` (or call `Endpoint::close(...)`).
quinn closes every active connection; per-connection driver tasks observe
the close and exit. No leak in well-behaved teardown; an inflight connection
closing slowly may hold a driver task past our `JoinSet` join.

**Implication for R9 honest-claim.** We do NOT claim end-to-end `JoinSet`
enclosure for the tokio tasks quinn spawns. Our code's `JoinSet` enclosure
covers the surface we own (the accept loop and per-connection consumer
tasks); quinn's internal drivers are scoped to connection lifecycle.

### `axum` + `hyper`

`axum::serve(listener, app)` returns a future the consumer wraps inside its
own `JoinSet`. **Internally, hyper drives the accepted connections via its
own task structure** (connection/service driver tasks owning the per-
connection HTTP state machine; handler futures driven by those connection
tasks for each in-flight request). The exact internal spawn shape is not a
public hyper contract and may shift between hyper releases — this audit
intentionally does not pin to a specific spawn count or task topology, only
to the observable lifecycle boundary: hyper owns connection-level drivers
that are not enclosed by any caller `CancellationToken`.

**Shutdown contract.** Both of the following are required for bounded
shutdown — `axum::serve` cancellation alone, or `with_graceful_shutdown`
alone, leaves handler runtime unbounded:

1. **Stop accepting**: cancel the `axum::serve` future, OR use
   `axum::serve(listener, app).with_graceful_shutdown(signal_future)` —
   hyper stops accepting new connections; in-flight handlers continue to
   run on their connection driver tasks.
2. **Bound handler runtime**: an app-owned timeout/cancellation layer is
   required. `with_graceful_shutdown` does NOT impose an inherent handler
   timeout — a handler that never returns will hold its connection task
   indefinitely. The bounded-shutdown options are:
   - Wrap the entire `axum::serve(...)` future in `tokio::time::timeout`
     so the await drops the future after a deadline.
   - Use a `tower::timeout::TimeoutLayer` (or middleware) that imposes a
     per-request deadline on handler futures.
   - Plumb a `CancellationToken` through `Extension`/`State` and have
     handlers observe it explicitly at await points.

   At least one of these MUST be wired by the consumer. The portal-relay
   binary's shutdown path documents which option it uses; reviewers
   verify at code review time that bounded shutdown holds.

**Implication for R9 honest-claim.** Same shape as quinn: hyper's
connection-driving spawn surface is not under our `JoinSet`, and graceful
shutdown does not by itself terminate handlers. R9 binds the surface we
own; bounded shutdown is the consumer's responsibility, achieved via the
explicit timeout/cancellation layer above.

### `instant-acme`

`instant_acme::Order` polling is a single future the consumer drives. **No
internal task spawning.** The order's I/O lives entirely under the caller's
async context.

**Shutdown contract.** Drop the future. No transitive task tree.

**Implication for R9 honest-claim.** Clean composition; no carve-out.

### `defguard_boringtun`

Per ADR-0015 (primary fork pick), `defguard_boringtun = "0.6.5"` exposes a
**synchronous state machine** (`Tunn`). **No internal tokio spawning.** The
consumer:
- Drives encapsulation/decapsulation calls from its own tasks (read TUN →
  `Tunn::encapsulate()` → write socket; read socket →
  `Tunn::decapsulate_packet()` → write TUN).
- Calls `Tunn::update_timers()` on a periodic interval the consumer owns.

Both the I/O loops and the timer loop are tasks WE spawn — they live inside
our `JoinSet`, are cancellable via our `CancellationToken`, and observe our
shutdown contract directly.

**Shutdown contract.** Drop the `Tunn` instance after our async wrappers
exit. Cancellation: cancel our wrapping tasks; the `Tunn` state machine
itself has no async surface to cancel.

**Implication for R9 honest-claim.** Clean composition. The fork's contract
is verified at the U6 land-time when `crates/portal-relay/src/overlay/wg_device.rs`
first imports the dep; if the verification surfaces a deviation from this
preliminary contract, this section MUST be updated in the same commit and
the audit re-validated.

## R9 honest-claim

> portal-tunnel-rs's R9 structured-concurrency invariant binds **our** code;
> transitive dependencies follow each dependency's documented shutdown
> contract — see per-dep entries above. We do NOT claim end-to-end
> `JoinSet` enclosure for tokio tasks spawned inside `quinn` or
> `axum`/`hyper`. The surfaces we own are enclosed; the surfaces we
> consume are bounded by their dep's published lifecycle (connection close,
> graceful shutdown, future drop).

This is the load-bearing claim: where our code spawns, R9 holds; where deps
spawn, the dep's contract holds. The combined system terminates cleanly when
every owner of a spawn-source observes its contract.

## Update procedure

Adding a new dep that spawns tokio tasks (or upgrading an existing dep across
a major version where its spawning contract changes) requires a same-commit
update to:

1. The Per-dep contracts table above.
2. The matching named subsection.
3. The R9 honest-claim if the new dep changes the bounded set (e.g., a new
   surface that internally spawns under a `CancellationToken` we hand it
   would extend, not narrow, our R9 claim).

CI gate (`xtask dep-audit`) fails if any required section header is missing
from this file. The list of required sections is the union of:
`## Per-dep contracts`, `### quinn`, `### axum + hyper`, `### instant-acme`,
`### defguard_boringtun`, `## R9 honest-claim`.

## References

- Phase 7 plan: [`docs/plans/2026-05-04-008-feat-binaries-and-e2e-plan.md`](plans/2026-05-04-008-feat-binaries-and-e2e-plan.md) § U8.7 (this audit)
- ADR-0015 — WG fork pick (primary: `defguard_boringtun 0.6.5`)
- AGENTS.md — R9 (structured concurrency invariant)
- `xtask/src/dep_audit.rs` — the validator
- `.github/workflows/ci.yml` — `dep-spawning-audit-gate` job
