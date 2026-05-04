# ADR-0014: Overlay architecture — sealed `WgDevice` + smoltcp + QUIC-on-smoltcp-UDP hop-mux

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0001 (greenfield wire — yamux removal), ADR-0015 (WG fork pick), ADR-0002 (modern register that constrains fork-adapter dep choices)

## Context and problem statement

Portal's overlay subsystem provides multi-hop relay routing on top of a userspace
WireGuard data plane. The Go upstream (`portal-tunnel/portal/overlay/`) achieves
this with three coupled mechanics:

1. A kernel-mode WireGuard device (Linux `wg` interface or `wireguard-go`) for
   the cryptographic data plane.
2. A custom hop-multiplexer riding `hashicorp/yamux` over TCP for hop-to-hop
   stream framing.
3. Direct kernel-network-stack participation — packets enter the host's TCP/IP
   stack via the WG `tun` interface.

Each Go-shape primitive is a poor fit for the Rust port:

- **Kernel WireGuard requires root + Linux-only.** Portal-relay must run
  unprivileged on macOS, Windows, BSD, and inside Docker layers without
  `--cap-add=NET_ADMIN`. v0.1 cannot ship a kernel-WG dependency.
- **`wireguard-go` invocation requires CGO + a Go toolchain at build time.**
  Vendoring `wireguard-go` semantics into pure Rust is a 3-6 month rewrite
  (per F11), not a v0.1 dependency.
- **`yamux` was retired in ADR-0001.** The greenfield wire commits to QUIC-only
  backhaul; reintroducing yamux for hop-mux specifically would re-establish a
  TCP-multiplexer dependency the rest of the wire eliminated.
- **Kernel-stack participation pulls in OS-specific TUN driver code** and forces
  the relay binary to negotiate per-platform interface lifecycle (route table,
  MTU, IPv6 RA). The greenfield port owns the byte-level surface (R1) and
  benefits from a portable in-process net stack.

The roadmap's overlay deliverable (R12: IPv6 dual-stack carriage; F11:
multi-hop) needs an architecture that:

- Decouples the cryptographic data plane (a userspace WG fork) from the rest
  of `portal-relay` so swapping forks is one file.
- Carries IPv4 + IPv6 packets without depending on the host's network stack.
- Carries hop-mux frames without reintroducing yamux.

## Decision

The overlay subsystem ships in `crates/portal-relay/src/overlay/` with three
co-equal architectural commitments:

### 1. Sealed `WgDevice` trait isolates fork choice

`crates/portal-relay/src/overlay/wg_device.rs` exposes a sealed trait:

```rust
mod sealed { pub trait Sealed {} }

pub trait WgDevice: sealed::Sealed + Send + Sync {
    fn apply_peers(&self, peers: &[PeerConfig]) -> Result<(), OverlayError>;
    fn read_packet(&self, buf: &mut [u8]) -> Result<usize, OverlayError>;
    fn write_packet(&self, packet: &[u8]) -> Result<(), OverlayError>;
    fn close(self) -> Result<(), OverlayError>;
}
```

Only the in-crate adapter for the chosen fork (per ADR-0015) implements
`sealed::Sealed`. Switching to the secondary fork — or to the
MVP-without-overlay fallback — requires editing this single adapter file plus
the `[workspace.dependencies]` entry. No ripple into `overlay::Overlay`,
`overlay::netstack`, or `overlay::HopMux`.

The sealed-trait pattern follows the workspace convention used in `portal-wire`
for marker types.

### 2. `smoltcp` provides the in-process TCP/IP + UDP stack

The chosen fork's TUN-equivalent packet I/O feeds a `smoltcp::Interface` running
inside `portal-relay`'s tokio runtime. `smoltcp` carries v4 + v6 (R12 first-class)
without participating in the host's kernel network stack, eliminating the
root-permission and platform-specific TUN-driver requirements that block kernel-
WireGuard adoption.

`overlay::netstack` owns the `smoltcp::Interface`, the `SocketSet`, and the
poll loop. It is the only module that calls `smoltcp` types directly; the rest
of `portal-relay` interacts via the typed sockets `netstack` exposes.

### 3. Hop-mux is QUIC streams over a `quinn::AsyncUdpSocket` adapter that wraps a smoltcp UDP socket

Inside the overlay, hop-to-hop frame multiplexing is QUIC streams (`quinn 0.11`)
running through a **named transport adapter** that bridges quinn's
`AsyncUdpSocket` trait to a `smoltcp::iface::SocketSet`-managed UDP socket.
The adapter lives at `crates/portal-relay/src/overlay/netstack/quinn_smoltcp.rs`
and is U7's responsibility (`overlay::netstack` integration). It is not a
free composition: quinn's `Endpoint::new` requires an `AsyncUdpSocket` impl,
and a smoltcp UDP socket is not one. The adapter:

- Implements `quinn::AsyncUdpSocket` (`poll_send`, `poll_recv`,
  `local_addr`, `may_fragment`).
- Forwards send/recv to the smoltcp `UdpSocket::send_slice` / `recv_slice`
  inside the `SocketSet` poll cycle.
- Registers tokio wakers that fire when smoltcp's `Interface::poll` advances
  socket state, so the quinn endpoint task is woken when smoltcp completes
  an I/O step.

This adapter is the only piece of `quinn` integration outside the public
backhaul path; it is intentionally scoped to one file so the overlay's QUIC
choice can be reconsidered later (e.g., switch to `s2n-quic` with a
narrower transport surface) without touching `overlay::HopMux` callers.

ADR-0001 retired yamux from the Rust port. The overlay subsystem honors that
decision: QUIC-streams-over-the-`quinn::AsyncUdpSocket`-adapter is the
operational form of "QUIC streams" inside the overlay. The only semantic
difference between the public wire and the overlay wire is the carrier —
public uses tokio's UDP socket directly; overlay uses the smoltcp-bridging
adapter. Hop-mux frame layout (`Channel::HopRoute` typed prefix, Phase 1
framing) is identical across both.

## Consequences

### Positive

- **Fork swap is one file.** ADR-0015 records a primary + secondary pick with a
  documented go/no-go cliff; this ADR ensures the swap cost is bounded.
- **Greenfield wire is intact end-to-end.** The overlay does not reintroduce
  yamux, ES256K JWTs, or any v2.1.8 wire shape ADR-0001 retired.
- **Unprivileged + portable.** No kernel WG, no root, no platform-specific TUN
  driver. The same binary runs on Linux, macOS, Windows, and inside Docker.
- **R12 IPv6 carriage is enforced at the architecture layer.** `smoltcp::Interface`
  carries v4 + v6 by construction; ADR-0015's evaluation matrix scores fork
  IPv6-carriage maturity as a first-class column.
- **Workspace `unsafe_code = "forbid"` is preserved as a hard gate.**
  `Cargo.toml` line 162 sets the lint to `forbid`, and each `portal-*` crate
  carries `#![forbid(unsafe_code)]` at the crate root. `forbid` cannot be
  locally relaxed by `#[expect]` or `#[allow]` (Rust lint semantics); any
  fork whose public API requires the adapter to call `unsafe` is therefore
  disqualified at the architecture layer. ADR-0015 records the per-fork
  `unsafe`-surface column as a **hard disqualifier** rather than a tracked-
  but-allowed state. If a future fork's API regresses to require `unsafe`,
  the resolution paths are: (a) request a safe-API upstream change, (b) fork
  the fork into a separate vetted crate that opts out of `forbid` via an
  ADR-0002 amendment with sunset criterion, or (c) reject the fork.

### Negative — accepted

- **Userspace WG is slower than kernel WG.** v0.1 accepts the throughput cost;
  Phase 7 release docs name the operational characteristics. Kernel-WG support
  is a v0.2 candidate iff a portable kernel-binding crate emerges that does
  not regress the unprivileged-deployment story.
- **smoltcp adds a runtime layer with its own buffer pool, poll cadence, and
  timer wheel.** Operational tuning (poll interval, socket buffer sizes) is
  documented in Phase 7; defaults follow `smoltcp` upstream guidance.
- **Multi-hop deferral is real.** If both forks evaluated in ADR-0015 are
  integration-blocked by 2026-08-04, the overlay/ module ships empty in v0.1
  and multi-hop defers to v0.2. ADR-0015 names "MVP-without-overlay" as the
  honest fallback. Vendoring `wireguard-go` semantics into pure Rust is **not**
  a v0.1 fallback (3-6 month rewrite, not a recovery path).

## Considered alternatives

### A. Kernel WireGuard via `wireguard-rs` or per-OS shims

Pros: native throughput, mature stack, IPv6 carriage already proven on Linux
since 2020. Cons: requires root or `CAP_NET_ADMIN`; macOS support is via
`wireguard-go` userspace anyway; Windows requires `wintun.dll`; Docker images
need elevated privileges. **Rejected** because portal-relay's deployment story
explicitly targets unprivileged operators in containerized environments.

### B. Vendor `wireguard-go` semantics into pure Rust

Pros: deterministic upstream, well-tested IPv6 path, one-time cost. Cons:
3-6 month effort (per F11) to port the cookie reply, handshake, AEAD-rotation,
and roaming logic to Rust safely; the ROI does not clear v0.1; the work is
better spent on overlay-consumer code once a fork lands. **Rejected as
v0.1 work** — recorded as a possible v0.2 path if all userspace forks
integration-block; ADR-0015 explicitly names this as NOT a fallback for the
2026-08-04 cliff.

### C. Userspace WireGuard fork behind a sealed adapter — selected

Pros: greenfield wire intact; unprivileged; portable; fork swap is one file;
v0.2 candidates (kernel WG, vendored `wireguard-go`) remain reachable from the
same `WgDevice` interface. Cons: throughput cost, smoltcp runtime layer, and
deferral risk if all forks block — all accepted above.

### D. Reintroduce yamux for hop-mux only (not full wire)

Pros: behavioral parity with Go's hop-mux frame layout. Cons: ADR-0001 is the
greenfield-wire commitment; reintroducing yamux specifically for hop-mux would
require an ADR-0001 amendment with a sunset criterion. The QUIC-on-smoltcp-UDP
shape carries the same stream semantics without that cost. **Rejected**
because ADR-0001 already paid for QUIC-only and the overlay should not relitigate.

## References

- Roadmap plan: [`port_go_to_rust_greenfield_383a2dc9.plan.md`](../../) §
  R12 (IPv6 dual-stack); F11 (multi-hop deferral path)
- Phase 6b/B plan: [`docs/plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md`](../plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md)
  §§ U5 (this ADR), U6 (`WgDevice` adapter), U7 (`netstack` + `Overlay` orchestrator)
- ADR-0001 — greenfield wire commitment that retired yamux from the public wire
- ADR-0002 — register that constrains adapter-internal dep choices (no openssl,
  no chrono, etc.)
- ADR-0015 — fork pick + evaluation matrix + 2026-08-04 go/no-go date
- Go reference: `portal-tunnel/portal/overlay/stack.go` — kernel-WG + yamux
  shape that this ADR replaces
