# Behavioral-trace curation criteria (Phase 7 U8.6)

This document defines the criteria for selecting scenarios from the Go
reference implementation (`gosuda/portal-tunnel` v2.1.8) for capture
and replay against the Rust port.

## Curation principle

A scenario is included only if it exercises a state-transition or
wire-format contract that the Rust port has committed to preserving.
Scenarios that test Go-specific implementation details (goroutine
scheduling, `net/http` internal behavior, `quic-go` version-specific
frame layout) are excluded.

## Inclusion criteria (whitelist)

1. **Lease lifecycle** — register, renew, unregister, lease janitor eviction.
2. **Policy decisions** — IP ban, honeypot hit, reputation score decay.
3. **SDK surface** — domain query, connect admission, token validation.
4. **Admin surface** — config reload, health, policy snapshot.
5. **Wire format** — envelope serialization, descriptor canonicalization,
   hop-route encoding.  For wire-format scenarios the replay harness asserts
   canonical-form equivalence (postcard round-trip matches canonical signing
   input), not just high-level state equivalence.

## Exclusion criteria

1. Go-runtime-specific timing tests.
2. Tests that depend on `pprof` endpoints (not ported).
3. Tests that exercise deferred v0.2 features (cross-relay propagation,
   R11 dashboard, R15 admin TUI views).

## Fixture format

Each captured fixture is a JSON file containing:

- `scenario`: human-readable name
- `input`: serialized request/state
- `expected_output`: serialized response/state
- `go_sha`: commit SHA of the Go reference that produced the fixture

## Replay harness

The `behavioral-trace` test crate boots an in-process Rust `Server`
with the same initial state as the Go fixture, replays the input,
and asserts state-equivalence (not byte-equivalence) on the output.

## CI gating

Behavioral-trace tests are gated behind `BEHAVIORAL_TRACE=1`.
Linux CI runners enable the gate; macOS local dev skips it.
