# Known Gaps Resolution Plan

Last updated: 2026-05-02

## Scope

This plan closes the gaps listed in `docs/porting-status.md` for the Rust relay
server. The Rust project does not need to implement a tunnel client or SDK. The
existing Go SDK/CLI remains the compatibility client used to prove that the Rust
relay behaves like the Go relay on the public wire/API surface.

Direct relay parity is the first target:

- `/sdk/*` lifecycle and lease token behavior
- `/sdk/connect` reverse-session admission and marker bytes
- SNI passthrough routing
- `/v1/sign` keyless signing
- raw TCP and UDP relay transports when enabled
- admin policy effects on registration and routing
- deployment/runtime behavior for the relay process

Relay mesh parity is separate:

- discovery polling/refresh
- `/sdk/hop`
- WireGuard overlay and multi-hop forwarding

The current `/sdk/hop` `feature_unavailable` response is acceptable for a
direct-relay release, but not for full multi-hop parity.

## Gap Mapping

| Current gap | Relay-only interpretation | Resolution track |
| --- | --- | --- |
| Full Go SDK end-to-end compatibility not proven | Use the existing Go CLI/SDK as a black-box client against the Rust relay | Track 1 and 2 |
| SIWE/JWT fixture tests missing | Capture Go-generated crypto/API fixtures and verify them in Rust | Track 1 |
| SNI wildcard/root fallback incomplete | Implement Go lookup order on the Rust SNI listener | Track 3 |
| UDP framing not exercised with Go SDK | Run the Go CLI UDP path against the Rust relay and fix relay-side mismatches | Track 4 |
| BPS stored but not enforced | Completed: relay-side bridge throttling is wired into SNI/raw TCP paths | Track 5 |
| Multi-hop/WireGuard missing | In progress: WireGuard identity prep, `/sdk/hop` route verification/registry, HopMux framing, next-hop bridge wiring, and experimental `tokio-wireguard` runtime wiring are implemented; end-to-end mesh validation remains | Track 6 |
| Managed ACME and operational frontend gaps | Frontend static serving and install endpoints are implemented; managed ACME, thumbnails, and embedded asset packaging remain | Track 7 |

## Track 0: Docker And Runtime Checkpoint

Purpose: verify that the current relay can be built and run from the documented
container packaging before deeper compatibility work starts.

Tasks:

- Build `portal-relay-rs:local` from the repository Dockerfile.
- Run the container with local ports mapped to non-privileged host ports.
- Check `GET /healthz` and `GET /sdk/domain` over HTTPS.
- Confirm persistent `IDENTITY_PATH` writes `identity.json`, `fullchain.pem`,
  and `privatekey.pem`.

Done when:

- Docker build succeeds with `--locked`.
- Container starts without root-only host port assumptions.
- API health checks pass from the host.

## Track 1: Go Contract Fixture Gate

Purpose: lock the Go relay/SDK contract into fixtures so future Rust changes
can be checked without manually reading Go behavior each time.

Tasks:

- Add a fixture generator under `fixtures/go/` that is run from
  `../portal-tunnel`.
- Capture JSON request/response fixtures for:
  - `/sdk/domain`
  - `/sdk/register/challenge`
  - `/sdk/register`
  - `/sdk/renew`
  - `/sdk/unregister`
  - `/v1/sign`
  - `/discovery`
  - `/discovery/announce`
- Capture crypto fixtures for:
  - relay identity public/private key encoding
  - SIWE challenge message text and signature verification
  - Go-issued ES256K lease JWT verified by Rust
  - Rust-issued ES256K lease JWT verified by Go
  - relay descriptor canonical bytes and signature
  - UDP datagram frame encoding
- Add Rust tests that load these fixtures and compare exact field names, omitted
  fields, status codes, error codes, and signature encodings.

Done when:

- `cargo test` fails on meaningful wire-contract drift.
- At least one Go-issued JWT and one Rust-issued JWT are verified across
  language boundaries.
- SIWE message construction is fixture-backed.

## Track 2: Direct Relay End-To-End Gate

Purpose: prove the Rust relay works with the existing Go client, without
porting client-side code.

Tasks:

- Build the Go CLI from `../portal-tunnel/cmd/portal-tunnel`.
- Start a local HTTP echo service.
- Start the Rust relay with:
  - local/generated TLS material
  - API port on a non-privileged host port
  - SNI port on a non-privileged host port for local testing
  - discovery disabled
- Run `portal expose ... --relays https://localhost:<api-port> --discovery=false`
  against the Rust relay.
- Make a public HTTPS request to the lease hostname through the Rust SNI port
  using DNS override tooling such as `curl --resolve`.
- Keep the Go client's MITM self-probe enabled unless a local certificate trust
  issue makes the test invalid; any relay-side TLS termination failure must be
  treated as a blocker.
- Exercise renew and unregister by keeping the session alive long enough to
  cross at least one lease TTL.

Done when:

- Unmodified Go CLI registers, connects, renews, and unregisters through the
  Rust relay.
- Public HTTPS traffic reaches the local service through SNI passthrough.
- The Rust relay never sees tenant TLS plaintext.
- The test can be repeated by a script or documented command sequence.

## Track 3: SNI Wildcard And Root-Host Fallback

Purpose: match the Go relay's ingress lookup order.

Tasks:

- Implement lookup order:
  1. exact lease hostname
  2. one-level wildcard lease hostname
  3. exact root-host fallback to the API listener
  4. close when no route exists
- Add SNI parser tests for exact, wildcard, deep wildcard miss, root-host, and
  no-SNI/no-route cases.
- Add an integration test that connects to the SNI port with root-host SNI and
  receives the API server response.
- Confirm wildcard routes never match the root host and never match deeper
  labels.

Done when:

- Routing behavior matches the Go analysis in `docs/existing-system-analysis.md`.
- Root-host SNI can reach the relay API/admin surface.
- Existing exact-host behavior remains unchanged.

## Track 4: TCP/UDP Transport Interop Gate

Purpose: prove the optional direct transports against the existing Go client.

Tasks:

- Run the Go CLI with `--tcp` against the Rust relay and a local TCP echo
  service.
- Run the Go CLI with `--udp --udp-addr ...` against the Rust relay and a local
  UDP echo service.
- Verify register responses include `tcp_addr`, `udp_addr`, and `sni_port`
  exactly as the Go client expects.
- Verify the raw TCP marker `0x01` and TLS marker `0x02` are not conflated.
- Verify QUIC ALPN, control-stream JSON, DATAGRAM frame encoding, and 30-second
  UDP flow expiry with fixture-backed tests.

Done when:

- Existing Go CLI TCP mode passes through the Rust relay.
- Existing Go CLI UDP mode passes through the Rust relay.
- Transport-specific failures return compatible error codes.

## Track 5: Admin Policy And BPS Enforcement

Status: implemented for SNI and raw TCP stream paths.

Evidence:

- `./scripts/dev-rust-ci.sh` passes bridge BPS throttling tests.
- `PolicyRuntime` exposes per-identity shared BPS limiters.
- SNI and raw TCP bridge paths reserve identity limiters before copy.

Remaining follow-up:

- Add broader live admin-policy smoke coverage for approval/deny/ban/IP-ban transitions.
- Decide whether UDP admission needs a byte-rate limiter equivalent or remains policy/admission-only.

## Track 6: Discovery And Multi-Hop Decision

Purpose: separate direct relay completion from relay mesh parity.

Decision:

- If direct relay parity is enough for the first Rust release, keep `/sdk/hop`
  as explicit `feature_unavailable` and document multi-hop unsupported.
- If full Go relay parity is required, implement this track after Tracks 1-5.

Full parity tasks:

- Implement discovery bootstrap polling, public registry bootstrap merge, and
  relay-set refresh, not only `/discovery` and `/discovery/announce`.
  **Done for direct HTTPS discovery refresh; overlay discovery still depends on
  WireGuard.**
- Add WireGuard key persistence to `identity.json`.
- Implement WireGuard overlay listener and peer management. **Done for peer
  descriptor normalization, endpoint resolution/fallback, IPC config change
  detection, experimental `tokio-wireguard` interface creation, peer sync, and
  overlay HopMux listener wiring.**
- Implement HopMux-compatible stream open/accept behavior. **Done for token framing/yamux runtime, boxed async I/O hooks, and overlay connector wiring.**
- Implement hop route canonical bytes and signature verification. **Done for first-pass Rust verification, including v2.1.8 `first_seen_at_unix_nano`.**
- Implement `POST` and `DELETE /sdk/hop`. **Done for route validation and registry storage/deletion when HopMux is available; runtime API is enabled when discovery starts the overlay runtime.**
- Route public ingress to next-hop overlay streams when a lease record has a
  next hop. **Done for SNI ingress when HopMux is available.**

Done when:

- Go SDK multi-hop route sync succeeds against the Rust relay.
- A Rust relay can participate as entry, middle, or exit relay with Go relays.
- Discovery descriptors truthfully advertise overlay support only when overlay
  is operational.
- `tokio-wireguard` data-path smoke covers at least two local Rust relay
  instances before Go mesh interop is treated as supported.

## Track 7: ACME And Frontend Serving

Purpose: close operational gaps that matter for replacing the Go relay in
production.

Tasks:

- Keep manual certificate loading as the default production path.
- Decide whether managed ACME is required for the first deployment target.
- If managed ACME is required:
  - port Cloudflare DNS-01 first
  - then Route53
  - then Google Cloud DNS
  - sync root and wildcard DNS A records
  - preserve certificate/account state files under `IDENTITY_PATH`
- Serve existing built frontend assets as static files when `FRONTEND_DIST` is
  configured. **Done.**
- Add fallback routing after fixed API paths and before generic 404 responses.
  **Done for `/`, `/app`, `/assets/*`, favicon assets, and `/tunnel/status`.**
- Implement relay install script and binary endpoints. **Done with GitHub
  latest-release redirects for binaries.**
- Decide whether thumbnail generation is required for the first deployment
  target.

Done when:

- The chosen certificate path can issue/load a root plus wildcard certificate.
- The relay can be deployed without the Go binary for the selected production
  mode.
- Unsupported operational features are explicit in docs and API behavior.

## Recommended Execution Order

1. Track 0: Docker/runtime checkpoint.
2. Track 1: fixtures and contract tests.
3. Track 2: direct HTTPS relay end-to-end gate.
4. Track 3: SNI wildcard/root fallback.
5. Track 5: BPS enforcement.
6. Track 4: TCP/UDP interop gate.
7. Track 7: production ACME/frontend decision and selected implementation.
8. Track 6: multi-hop/WireGuard only if full relay mesh parity is required.

## Needed From The User

- For local direct-relay tests: no extra input is required if `../portal-tunnel`
  remains available and Docker is running.
- For public production validation: provide the target relay domain and whether
  manual certificates are acceptable.
- For managed ACME validation: provide a test domain plus one provider credential
  set, starting with Cloudflare if there is no preference.
- For frontend parity: decide whether the Rust relay must serve the existing
  web frontend, or whether headless JSON/admin API behavior is enough.
- For multi-hop parity: decide whether it is required for the first Rust release.
  If yes, we need at least two or three relay instances with UDP/WireGuard
  reachability for an integration test.
