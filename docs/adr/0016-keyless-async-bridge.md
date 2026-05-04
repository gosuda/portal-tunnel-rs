# ADR-0016: Keyless async bridge — bounded mpsc + spawn_blocking dispatch

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0001 (greenfield wire — drops `keyless_tls` line protocol),
  ADR-0002 (modern register that rules out hand-rolled crypto primitives),
  ADR-0014 (overlay architecture; "use rustls's own provider, don't roll our
  own" precedent), Phase 6b/A plan §U2

## Context and problem statement

Phase 6b/A ships a keyless tenant-TLS oracle: an mTLS-protected HTTP signing
endpoint served by axum, where each signing call ultimately calls
[`rustls::sign::Signer::sign`]. The trait surface poses an immediate
mismatch:

```rust
pub trait Signer: Debug + Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn scheme(&self) -> SignatureScheme;
}
```

[`Signer::sign`] is **synchronous**. The axum handler is **async**. The signing
operation is CPU-bound (RSA-2048: ~1 ms; RSA-3072: ~3-4 ms; ECDSA-P256:
sub-millisecond) — short relative to network latency, but long enough that a
naive call site has visible operational consequences. Three constraints bind:

1. **Reactor preservation.** Calling a sync 1-ms primitive directly inside a
   tokio task occupies one runtime worker thread per concurrent sign. At even
   moderate parallelism this starves the reactor — every request the relay
   serves on the same runtime is delayed for as long as the signing thread
   holds the worker.
2. **Backpressure visibility.** SEC-004 mandates per-tenant rate limiting and
   an observable saturation surface. Whatever shape the bridge takes, queue
   saturation must surface at the HTTP wire (mapped to `503 Service
   Unavailable` with a `Retry-After` header) rather than silently buffering
   inside the runtime.
3. **Structured concurrency (R9).** Worker-pool spawns must live inside a
   caller-supplied `JoinSet<()>` so the relay top-level `main` can drain
   every signing task on shutdown. Free `tokio::spawn` is forbidden by
   workspace lints (clippy `disallowed_methods` enforcement is a Phase 7
   deliverable; the discipline is enforced today by the `JoinSet`-owner
   pattern at code review).

The Go upstream sidesteps this entirely — Go's runtime is preemptive and the
`keyless_tls` reference uses goroutines per request. The Rust port owns the
async-to-sync bridging cost explicitly because the runtime is cooperative.

## Decision

The keyless module ships a `Bridge` type in
`crates/portal-relay/src/keyless/bridge.rs` with the following shape:

1. **Bounded `tokio::sync::mpsc` queue** between the axum handler and a pool
   of supervisor tasks. Default `queue_depth = 256`; operator-tunable. The
   handler uses [`mpsc::Sender::try_send`] (never the blocking `send`); a
   full queue immediately returns `KeylessError::QueueFull`, which the U3
   handler maps to HTTP `503 Service Unavailable`. This is the
   backpressure-visibility contract.

2. **Caller-supplied `JoinSet<()>`** holds the supervisor tasks. The
   `Bridge::spawn` constructor takes the `JoinSet` by `&mut`; the relay
   top-level `main` is the canonical owner. All supervisors live inside the
   caller's structured-concurrency scope (R9), so a graceful shutdown drains
   every task before exit.

3. **`spawn_blocking` dispatch** is the load-bearing concurrency choice.
   Each supervisor pulls a `SignJob` from the mpsc, then dispatches the sync
   `Signer::sign` call onto tokio's blocking pool via
   [`tokio::task::spawn_blocking`] and awaits the resulting `JoinHandle`
   before taking the next job. This is what keeps CPU-heavy signing off
   the runtime worker threads: the supervisor task remains async (cheap,
   parked across the await), and the actual signing runs on a dedicated
   OS thread from tokio's blocking pool (`max_blocking_threads`, default
   512). Bounding on dispatch is already enforced upstream by the mpsc
   `queue_depth` plus the supervisor count, so this is **not** the
   unbounded per-request `spawn_blocking` antipattern (see §Considered
   alternatives below) — every dispatch passes through the bounded mpsc
   first.

   Because each supervisor awaits its in-flight `spawn_blocking` handle
   before reading the next job from the mpsc, **`worker_count` IS the
   keyless signing concurrency cap**. At any instant, at most
   `worker_count` blocking-pool threads are running `Signer::sign` on
   behalf of the keyless surface. tokio's `max_blocking_threads`
   (default 512) is the *outer* envelope shared across the rest of the
   process; the keyless surface lives strictly under `worker_count` of
   that budget.

4. **Cooperative shutdown** via `tokio_util::sync::CancellationToken`. The
   token is passed to `Bridge::spawn` by the JoinSet owner. Each supervisor
   races `mpsc::Receiver::recv()` against `cancellation.cancelled()` in a
   `tokio::select!` block; a fired token causes the supervisor to exit
   without taking new work, but any already-dispatched `spawn_blocking`
   handle is awaited to completion before the supervisor returns.

5. **Single-Receiver fan-out** is handled by wrapping the
   `mpsc::Receiver<SignJob>` in `Arc<tokio::sync::Mutex<…>>` so multiple
   supervisors can contend on `recv()`. The mutex is held only across the
   short `recv()` await; the actual signing runs off the mutex on a blocking
   thread. tokio's `mpsc` is single-receiver by design (the type system says
   one consumer); adding `async-channel` for one mpmc primitive would expand
   the dep tree without ergonomic benefit at this workload size.

Default sizing:

- `worker_count = max(2, available_parallelism / 4)` — this is the
  **keyless signing concurrency cap** (see point 3 above). Each
  supervisor task processes one in-flight sign at a time; at most
  `worker_count` blocking-pool threads run `Signer::sign` for the
  keyless surface concurrently. The floor protects small hosts; the
  divisor leaves headroom for the rest of the runtime. Operators who
  expect higher steady-state keyless throughput raise `worker_count`
  alongside the runtime's `max_blocking_threads` budget.
- `queue_depth = 256` — large enough to absorb a burst without artificial
  503s, small enough that a saturated queue is a visible operational signal
  (256 jobs at 1 ms each is ~256 ms of latent work).

## Consequences

### Positive

- **Reactor stays responsive** under signing load. CPU-heavy work runs on
  blocking pool threads; the runtime worker count is the right resource for
  network I/O and request handling, not crypto.
- **Backpressure is visible at the HTTP wire.** Queue saturation maps to
  `503` deterministically; operators see saturation in their HTTP error
  rate without having to instrument internal queue depth.
- **Structured shutdown.** The relay top-level `main` drains every signing
  task on graceful shutdown via the JoinSet; cancellation propagates
  cleanly through `CancellationToken`.
- **No bespoke crypto.** `KeylessSignerAdapter` delegates to
  `rustls::crypto::aws_lc_rs::sign::any_supported_type`; the bridge never
  touches signing primitives directly.

### Negative — accepted

- **Per-sign overhead from `spawn_blocking`.** Each dispatch incurs a
  channel send into the blocking pool plus a `JoinHandle::await` round-trip.
  At the keyless workload (sub-ms to ~ms per sign) this overhead is a
  small constant; it would matter for sub-microsecond primitives, but
  signing is not in that regime.
- **Mutex contention on the mpsc receiver.** The supervisor pool contends
  on a shared `Arc<Mutex<Receiver>>` per `recv()`. The lock is held for
  microseconds; under the keyless workload (low rate, signing dominates)
  contention is negligible. If a future workload demonstrates contention,
  the mitigation is to swap in an mpmc channel (e.g. `async-channel`) — the
  swap is local to `Bridge::spawn`.
- **Blocking-pool tuning becomes operationally relevant.** The bridge
  inherits its OS-thread budget from tokio's `max_blocking_threads`. An
  operator who reduces this below the keyless bridge's `worker_count` will
  see signing latency degrade. Phase 7 release docs name the runtime build
  invariants the keyless bridge depends on.

## Considered alternatives

### A. `block_on` inside the async handler

Pros: zero bridge code; the handler calls `Signer::sign` directly.

Cons: `tokio::runtime::Handle::block_on` cannot be called from inside the
multi-thread runtime context (it panics); even if it could, it would block
the calling worker thread for the full sign duration, which is the failure
mode this ADR exists to prevent. **Rejected** — obvious anti-pattern,
listed for completeness.

### B. Per-request `tokio::task::spawn_blocking` directly from the handler

Pros: no shared queue; conceptually simple — the handler `await`s a
`spawn_blocking` per request and returns the result.

Cons:

- **Unbounded.** An adversarial client (or a misconfigured peer) can spam
  signing requests faster than the blocking pool can drain them; tokio's
  blocking pool grows up to `max_blocking_threads` (default 512) and any
  excess work queues internally with no operator-visible saturation
  signal. This violates the SEC-004 backpressure-visibility requirement.
- **No per-tenant rate-limit hook.** SEC-004 calls for a per-tenant
  governor keyed by client-cert subject; that lives in U3's `policy.rs`
  and is wired in front of `Bridge::sign`. Direct `spawn_blocking` per
  request bypasses the policy layer — not a place we want to make easy to
  defeat.
- **No shutdown drain.** The blocking pool tasks are not tracked in a
  caller-owned `JoinSet`, so a graceful shutdown either races signing
  tasks (they keep running while the rest of the relay tears down) or
  pulls in tokio's `shutdown_timeout` which is coarse-grained and not
  per-subsystem.

**Rejected** as the primary path. Note that the *internal* dispatch step
inside `Bridge::supervisor_loop` does use `spawn_blocking` — the
distinction is that the bridge bounds entry through the mpsc and tracks
shutdown through the JoinSet, so the cited cons do not apply.

### C. Dedicated OS-thread pool spawned at `Bridge::spawn` time

Pros: the bridge owns its threads end-to-end; no dependency on tokio's
blocking-pool config; dispatch overhead reduces to a `std::sync::mpsc` send.

Cons:

- **Two kinds of workers in one struct.** The supervisors are tokio tasks
  (so they can `await` the cancellation token via `select!`); the signing
  workers would be OS threads (so they can run sync code without a
  spawn_blocking dispatch). The bridge would have to maintain both in
  parallel, including a separate handshake to wake the OS threads on
  cancellation. Twice the moving parts for marginal throughput gain.
- **Resource accounting splits.** Operators tune one knob today
  (`max_blocking_threads`); the dedicated-pool design adds a second.
  Phase 7 ops docs would name both.
- **Workload size doesn't justify it.** The keyless oracle is a low-rate
  signing surface (per-tenant). The throughput floor of `spawn_blocking`
  is far above the SLO.

**Rejected** as v0.1. If Phase 7 traces show `spawn_blocking` overhead is
material to keyless latency, the dedicated-pool variant is reachable
without touching `Bridge`'s public surface — the swap is local to
`supervisor_loop`'s dispatch step.

### D. Free `tokio::spawn` per supervisor (no `JoinSet`)

Pros: simpler constructor signature.

Cons: violates R9 structured-concurrency discipline. The relay shutdown
path cannot drain orphan tasks; supervisors keep running for the lifetime
of the runtime. This is the precise antipattern the workspace's planned
clippy `disallowed_methods` rule on `tokio::spawn` will refuse. **Rejected**.

### E. `async-channel` mpmc instead of `Arc<Mutex<mpsc::Receiver>>`

Pros: cloneable receiver; no mutex contention on `recv()`.

Cons: adds a workspace dep for one primitive. Plan §U2 (line 268) locks
`mpsc::Sender<SignJob>` shape; the mutex is held for microseconds and
contention is not material at the keyless rate. **Rejected** as v0.1; the
swap is local to one constructor call if a future workload demonstrates
contention.

## References

- Roadmap plan: [`port_go_to_rust_greenfield_383a2dc9.plan.md`](../../) §
  Phase 6b/A (keyless tenant-TLS oracle)
- Phase 6b plan: [`docs/plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md`](../plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md)
  §§ U2 (this ADR's owning unit), U3 (axum handler that maps `QueueFull`
  → HTTP 503)
- ADR-0001 — greenfield wire commitment that retired the Go `keyless_tls`
  line protocol the Rust port replaces
- ADR-0002 — modern register that rules out hand-rolled crypto primitives
- ADR-0014 — overlay architecture; "use rustls's own provider, don't roll
  our own" precedent applied here
- rustls 0.23 `crypto::signer` module: `Signer::sign` sync trait surface
- tokio docs: `task::spawn_blocking` semantics; runtime
  `max_blocking_threads` knob
