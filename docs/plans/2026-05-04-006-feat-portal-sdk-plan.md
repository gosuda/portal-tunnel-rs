---
title: "feat: portal-sdk (expose, listener, MITM probe, eclipse picker, TUI bus)"
type: feat
status: active
date: 2026-05-04
origin: docs/plans/port_go_to_rust_greenfield_383a2dc9.plan.md (U7a)
---

# feat: portal-sdk (client orchestration)

## Summary

Stand up `crates/portal-sdk` as the **only** owner of client-side orchestration: `expose` session lifecycle, lease listener loop, RFC 5705 MITM probe via `rustls` TLS exporter labels, eclipse-resistant relay-set selection (R10 v0.1 — per-relay defense without cross-relay propagation), and a structured event bus consumed by `portal-cli` for the R15 v0.1 Tunnel TUI default mode. The crate wires `portal-wire` types, `portal-net` transport (`Endpoint`, `TcpPortRelay`, `DatagramClient` per Phase 3), and `portal-crypto` tenant identity (`SecretBox<TenantSecp256k1Key>` load + SIWE surfaces per Phase 2) — it does **not** duplicate wire codecs or QUIC trust-boundary key material.

---

## Problem Frame

Go upstream (`portal-tunnel/sdk/`, `cmd/portal-tunnel/`) interleaves CLI concerns with transport. Greenfield separates: `portal-sdk` owns reusable client library code; `portal-cli` (Phase 7) stays thin (`clap` + TUI glue). The roadmap mandates **MITM detection** (`--ban-mitm`) using exporter labels and **eclipse resistance** when `--relays` / discovery returns a biased relay set. v0.1 implements picker rules that require **≥3 ASN-bin-independent** operators *when ASN metadata is available*; when descriptors lack ASN, the plan documents honest degradation (warn + operator override), not a fake security guarantee.

---

## Requirements

- R1. Rust 2024 workspace style per `AGENTS.md` — `forbid(unsafe_code)`, deps only via `[workspace.dependencies]`, `thiserror` errors, structured concurrency (`JoinSet` + `CancellationToken`) for every long-lived task.
- R3 (client slice). Behavioral parity at **CLI-visible flags** for `expose` / `list` shapes is Phase 7; `portal-sdk` exposes APIs those binaries call — not byte-compat with Go wire.
- R10 v0.1. Per-relay abuse signals consumed from discovery descriptors; **no** `ReputationDelta` wire emission or cross-relay propagation (v0.2). Picker MUST reject single-descriptor / single-ASN dominance when metadata suffices.
- R12. Dual-stack: every outbound dial uses `portal_net::dual_stack::canonicalize_ip` before cache keys; relay lists honor split `addresses_v4` / `addresses_v6` from `portal_wire::RelayDescriptor`.
- R13 / SEC-013. MITM probe uses **exact** `portal_wire::mitm::PROBE_LABEL` (`b"portal-tunnel/mitm-probe/v2"`); exporter access goes through `rustls 0.23` EKM / `TlsExporter` APIs with the label pinned in one `const`.
- R15 v0.1. Publish `TunnelEvent` / `TunnelState` types for `ratatui` front-end; no `ratatui` dependency inside `portal-sdk` (keep TUI crate boundary in `portal-cli`) — use `tokio::sync::broadcast` or `watch` channels + plain structs.

---

## Scope Boundaries

- **In scope:** expose orchestration, listener accept loop, MITM probe helper, eclipse picker, event bus types, integration tests for probe + picker.
- **Out of scope:** relay policy engine, ACME, keyless server, WireGuard overlay (Phase 6b), admin TUI views (v0.2), auto-update binary, `agent` subcommands.
- **HTTP/3 client** to relay API: use `hyper` + `rustls` (workspace pins) — not `reqwest` unless ADR-0002 amended (default: **no** new dep; prefer `hyper-rustls` / manual connector already used elsewhere — *confirm at U4 execution against workspace tree*).

### Deferred to Follow-Up Work

- Live RIPEStat / Maxmind ASN enrichment for descriptors without embedded ASN — v0.2 or operator plug-in.
- Full multi-hop depth >2 combinatorics — v0.1 ships depth=1–2 consistent with Go default exposure paths.

---

## Key Technical Decisions

- **MITM probe:** One public async fn `probe_mitm(conn: &mut ClientConnection, expected_spki: &[u8]) -> Result<(), MitmError>` wrapping `rustls` exporter API after handshake completes; compares derived MS to expected relay SPKI fingerprint policy from Phase 3 verifier story. On label mismatch / exporter failure → `MitmError::ExporterMismatch`. Exporter label bytes MUST match `portal_wire::mitm::MITM_PROBE_LABEL` (alias `portal_wire::mitm::PROBE_LABEL`).
- **Eclipse picker:** `fn pick_relays(descriptors: &[RelayDescriptor], constraints: PickerConstraints) -> Result<Vec<RelayDescriptor>, PickerError>` — deterministic sort by `(asn_bin, identity_key)` then greedy coverage for v4+v6 reachability; **if** `<3` distinct ASN bins after filtering stale / self-referential entries → `PickerError::InsufficientAsnDiversity` unless `PickerConstraints::allow_degraded = true` (CLI maps `--relays` manual mode).
- **Expose session:** `ExposeHandle` owns `CancellationToken`, holds `portal_net` clients, subscribes to lease renewal timers using `jiff` + `tokio::time::sleep` aligned to half TTL (exact factor from Phase 5 lease plan).
- **Listener:** `listen_for_ports(...)` async stream of `ListenEvent` — wraps TCP accept + QUIC stream dispatch from `portal-net` without re-implementing codecs (uses `Framed` + `portal_wire::ChannelCodec` from Phase 1).

---

## Implementation Units (atomic commits, ≤200 LoC substantive each)

| U-ID | Concern |
|------|---------|
| U1 | Crate scaffold + `SdkError` + `lib.rs` exports |
| U2 | `events.rs` — `TunnelState`, `TunnelEvent`, `broadcast` channel factory |
| U3 | `relay_set.rs` — parse / validate `RelayDescriptor` list + time skew checks (`jiff`) |
| U4 | `picker.rs` — eclipse-resistant selection + ASN bin extraction (descriptor field + tests use injected ASN) |
| U5 | `mitm.rs` — RFC5705 exporter probe + `MitmError` |
| U6 | `expose.rs` — `ExposeSession` builder (`bon`) + start/stop + wire-up `portal_net` |
| U7 | `listener.rs` — accept loop + channel dispatch delegation |
| U8 | `identity.rs` — thin re-export surface for loading tenant key via `portal_crypto` (no new loaders — call Phase 2 entrypoints) |
| U9 | `tests/mitm_probe.rs` — behavioral gate (local rustls server + exporter) |
| U10 | `tests/eclipse_picker.rs` — behavioral gate (synthetic descriptors, diversity pass/fail) |

---

## Behavioral Gates

1. **`tests/mitm_probe.rs`** — handshake against `tokio::net::TcpStream` + in-memory rustls server; assert exporter label path succeeds; tampered label fails.
2. **`tests/eclipse_picker.rs`** — feed 5 descriptors with 1 ASN → expect `InsufficientAsnDiversity`; feed 3+ distinct bins → success; IPv6-only relay in set still passes when v6 addr present.

---

## Dependencies (execution order)

- **Hard:** Phase 1 (`portal-wire` — `RelayDescriptor`, `ChannelCodec`, `PROBE_LABEL`, limits), Phase 2 (`portal-crypto` — tenant key types), Phase 3 (`portal-net` — QUIC/TCP/UDP helpers + `canonicalize_ip`).
- **Soft:** Phase 5 only for *integration tests* that hit a live relay — optional `#[ignore]`; library unit tests use mocks / in-process stacks.

---

## Coordination Notes

- Phase 7 `portal-cli` imports `portal_sdk::ExposeSession` + `TunnelEvent` receiver; no circular dep (`portal-sdk` must not depend on `portal-cli`).
- Phase 6b overlay may add optional `HopRoute` consumer APIs later — reserve `portal_sdk::hop` module name in U1 skeleton as `pub mod hop { /* TODO Phase 6b */ }` **only if** empty modules are forbidden by clippy; otherwise omit until 6b.

---

## Risks

| Risk | Mitigation |
|------|------------|
| `rustls` exporter API drift across 0.23.x patches | Pin exact patch in workspace; probe test catches semver breakage |
| ASN metadata sparse in the wild | Degraded mode + loud `tracing::warn` + docs in `expose` rustdoc |

---

## Open Questions

### Resolved During Planning

- *MITM label source of truth?* — `portal_wire::mitm::PROBE_LABEL` only; `portal-sdk` imports, does not redefine.
- *TUI crate boundary?* — Events only in `portal-sdk`; `ratatui` stays in `portal-cli`.

### Deferred

- *reqwest vs hyper for SDK HTTP to relay API?* — pick at U6 based on smallest dep delta vs Phase 5 server stack alignment.

---

## Output Structure (post-implementation)

```
crates/portal-sdk/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── events.rs
│   ├── relay_set.rs
│   ├── picker.rs
│   ├── mitm.rs
│   ├── expose.rs
│   ├── listener.rs
│   └── identity.rs
└── tests/
    ├── mitm_probe.rs
    └── eclipse_picker.rs
```

---

## Verification

- `cargo test -p portal-sdk`
- `cargo clippy -p portal-sdk -- -D warnings`
- No `openssl` in `cargo tree -p portal-sdk -i openssl`
