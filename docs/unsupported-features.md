# Unsupported Features Compared To Upstream v2.1.8

Comparison baseline:

- Upstream: `gosuda/portal-tunnel` release `v2.1.8`, tag commit `3bb510c356e74268f1b3aa89b742c6661ff2ac4f`.
- Current Rust scope: this repository currently builds `portal-relay`. It is a relay-server port, not a full port of the upstream monorepo.
- Upstream surface includes the Go relay, Go client/SDK, frontend app, docs site, VS Code extension, demo app, release workflows, and installers.

## Implemented Relay Surface

The current Rust relay implements the main relay-server compatibility surface:

- API TLS listener and public SNI ingress listener.
- `/healthz`, `/sdk/domain`, `/sdk/register/challenge`, `/sdk/register`, `/sdk/renew`, `/sdk/unregister`, `/sdk/connect`, and `/v1/sign`.
- Registration challenge verification, lease tokens, renew/unregister lifecycle, SNI stream forwarding, UDP relay transport, and raw TCP port transport.
- Admin JSON API for login/logout/status, snapshot, approval mode, landing-page setting, UDP/TCP policy, identity approval/deny/ban/BPS, and IP ban.
- Discovery endpoints and signed relay descriptors.
- Experimental `tokio-wireguard` overlay and HopMux wiring.
- ECDSA P-256/P-384 and RSA keyless signing for the upstream signrpc algorithm set.
- Cloudflare, Google Cloud DNS, and Route53 managed ACME DNS-01 certificate provisioning, DNS A/TXT sync, and on-disk renewal.
- Installer script endpoints, with binary downloads redirected to upstream release assets.
- Static frontend serving when `FRONTEND_DIST` points at a built upstream frontend dist.
- Built-in minimal landing page that lists public tunnels and discovered public relays when `FRONTEND_DIST` is absent and `LANDING_PAGE_ENABLED=true`.
- Distroless non-root container runtime image and tag-triggered Forgejo container image publishing.

## Unsupported Or Partial Features

| Upstream v2.1.8 feature | Current Rust status | Operational impact |
| --- | --- | --- |
| `portal` CLI binary | Not implemented | There is no Rust equivalent for `portal expose`, `portal list`, or `portal update`. Smoke scripts use the official Go release client against the Rust relay. |
| Go SDK/client library | Not implemented as Rust SDK | The relay protocol is implemented server-side, but this repo does not provide a Rust client SDK package. |
| CLI HTTP route aggregation | Not implemented | Upstream `--http-route PATH=UPSTREAM` aggregation, route-prefix mounting, upstream `Location` rewrite, and cookie-domain/path rewrite are unavailable in Rust because the client is absent. |
| CLI MITM self-probe and relay ban flow | Not implemented | Upstream `--ban-mitm` behavior is client-side and is not present in this repo. |
| CLI relay discovery, MOLS relay selection, and automatic multi-hop selection | Not implemented | Upstream client-side discovery expansion, RTT-aware relay selection, `--multi-hop`, and `--multi-hop-depth` are unavailable in Rust. |
| CLI local UDP and raw TCP proxy flows | Not implemented | The Rust relay can accept UDP/TCP lease transports, but the Rust client-side proxy that forwards local UDP/TCP services is absent. |
| CLI self-update and background update notice | Not implemented | Upstream `portal update` and periodic update checks are not available. |
| Full frontend source and embedded frontend artifact packaging | Not included | The Rust relay can serve an externally supplied `FRONTEND_DIST`, but this repo does not include the upstream React app source, Vite build, or embedded dist packaging. |
| Full admin UI | Not included by default | Admin JSON APIs exist, but `/admin` is not a built-in browser UI unless an external upstream frontend dist is provided. |
| Full public landing/listing UI | Partially implemented | The built-in Rust page is a minimal server-rendered tunnel and public relay list. It is not the upstream React landing/list/detail/search/filter command-generator UI. |
| `/thumbnail/<hostname>` endpoint | Not implemented | Thumbnail URLs can be accepted as metadata, but relay-generated thumbnails are unavailable. |
| `HEADLESS_SHELL_URL` thumbnail capture | Explicitly rejected | Setting `HEADLESS_SHELL_URL` fails startup because headless Chrome/CDP screenshot capture and cache are not ported. |
| Managed ACME DNS-01 automation | Implemented for supported providers | `ACME_DNS_PROVIDER=cloudflare`, `ACME_DNS_PROVIDER=gcloud`, and `ACME_DNS_PROVIDER=route53` are supported. Unknown non-empty providers still fail startup; an empty value keeps the manual certificate opt-out behavior. |
| DNS A/TXT sync for managed zones | Implemented for supported providers | Cloudflare, Google Cloud DNS, and Route53 root/wildcard A records and ACME TXT records are managed. Route53 DNSSEC KMS automation remains unsupported. |
| ENS gasless DNSSEC/TXT automation | Explicitly rejected | `ENS_GASLESS_ENABLED=true` and related ENS gasless DNSSEC settings fail startup. Route53 DNSSEC/KMS (`AWS_DNSSEC_KMS_KEY_ARN`) also remains unsupported and is rejected. |
| Production-grade relay mesh/multi-hop parity | Experimental only | Overlay identity, discovery metadata, peer config, `tokio-wireguard`, and HopMux are wired, but multi-hop mesh mode still lacks relay-pair smoke coverage, NAT/keepalive validation, MTU validation, peer churn testing, and Go v2.1.8 mesh interop validation. Treat it as not production-supported. |
| Upstream docs site | Not ported | The SvelteKit docs site, static examples, package manifests, and docs build workflow are not included. |
| VS Code extension | Not ported | Upstream `extensions/vscode` is absent. |
| Demo app | Not ported | Upstream `cmd/demo-app` is absent. |
| Release asset build matrix | Partially implemented | Tag pushes publish a relay container image to the Forgejo registry. There is still no upstream-equivalent GitHub release workflow or Rust `portal` client assets. |
| Relay-hosted binary assets | Redirect-only | `/install/bin/*` redirects to the official upstream GitHub release assets, so a relay-hosted install script installs the upstream Go client, not a Rust client. |

## Known Compatibility Notes

- Managed ACME certificates are written to `fullchain.pem` and `privatekey.pem`; manually provisioned PEM files are still supported and are treated as an override when they cover the root and wildcard relay domains.
- ACME renewal updates certificate files on disk. The current running TLS acceptor and QUIC config load renewed material after relay restart.
- The keyless signer supports ECDSA P-256/P-384 and RSA private keys.
- `LANDING_PAGE_ENABLED=true` only provides the built-in minimal HTML page when no persisted admin setting overrides it.
- Existing Go v2.1.8 compatibility coverage focuses on relay basics: HTTP SNI passthrough, lifecycle, JWT verification, raw TCP, UDP, and selected API/discovery response shapes.
