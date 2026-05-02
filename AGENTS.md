# portal-tunnel-rs — AGENTS.md

Port pin: `gosuda/portal-tunnel` Go, tag `v2.1.8` is the upstream source of truth for relay-server wire and API behavior.

Wire-compat rule: Rust matches Go v2.1.8 wire/API surface. Any deliberate break lands in the same commit with a new entry in `docs/wire-compat-deltas.md`. Two distinct documents exist for two distinct failure modes — do not merge them:
- `docs/wire-compat-deltas.md` — "ported but intentionally diverged"

## Wire-invariant table

All constants below are normative. Their single owner is `crates/portal-relay/src/wire/`. Changing a value here changes the protocol.

| Constant | Value | Owner |
|---|---|---|
| `KEEPALIVE` | `0x00` | `wire/markers.rs` |
| `RAW_TCP` | `0x01` | `wire/markers.rs` |
| `TLS_ACTIVATE` | `0x02` | `wire/markers.rs` |
| ALPN identifier | `b"portal-tunnel"` | `wire/alpn.rs` |
| JWT algorithm | `"ES256K"` | `wire/jwt.rs` |
| API envelope shape | `{ ok, data?, error? }` | `wire/envelope.rs` |
| HTTP path constants | `/healthz`, `/sdk/*`, `/admin/*`, `/discovery` | `wire/paths.rs` |

## Trust-boundary table

Three TLS surfaces exist with distinct trust roots. They MUST remain as separate `rustls::ServerConfig` instances — merging any two collapses trust boundaries.

| Surface | Trust root | Config location |
|---|---|---|
| Relay API HTTPS | ACME / public CAs | `state/tls_material.rs` |
| Tenant TLS | Per-lease keyless RSA / public CAs | `api/keyless.rs` |
| QUIC datagram | Self-signed ES256K / pinned identity | `state/identity.rs` |

## Atomic commits / tidy-first

One concern per commit. ≤200 LoC substantive diff (file moves and generated files do not count toward this limit).

Rules:
- Minimize concepts, duplication, and ceremony
- One real owner per contract — no mirroring
- Remove dead code in the same commit where you touch nearby code
- No behavior change bundled with restructure — split them

## 2026 Rust house style

| Setting | Value |
|---|---|
| Edition | 2024 |
| Resolver | 3 |
| MSRV | declared in `[workspace.package]` (`rust-version = "1.87"`) |
| `unsafe_code` | `forbid` (zero unsafe blocks in crate) |
| Clippy lints | `pedantic` + `cargo` at `warn`, `priority = -1` |
| Per-lint silence | `#[expect(lint_name, reason = "...")]` — NOT `#[allow]` |
| Dep declarations | `[workspace.dependencies]` only |