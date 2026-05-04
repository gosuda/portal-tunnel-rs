# portal-acme

ACME (RFC 8555) issuance + DNS-01 providers for the portal-tunnel-rs
relay. Stand-alone crate consumed by `portal-relay`'s
`state/tls_material.rs` in Phase 5; Phase 4 produces only on-disk
`(fullchain.pem, privatekey.pem)` material — no in-process handoff.

## Feature flags

| Feature      | Default | Pulls                  | Notes                                 |
| ------------ | ------- | ---------------------- | ------------------------------------- |
| `local`      | yes     | `rcgen`                | rcgen-backed self-signed CA for dev   |
| `cloudflare` | yes     | `cloudflare 0.14`      | Official Cloudflare client (rustls-tls) |
| `route53`    | yes     | `aws-sdk-route53`      | AWS SDK for Rust                      |
| `gcloud`     | yes     | `google-cloud-dns-v1`  | Native Google client (rustls/aws-lc-rs) |

Build with `--no-default-features` and selectively re-enable features
for minimal-deploy targets (e.g. WASM CLIs that only need `local`).

## Scope (v0.1)

- Issuance via DNS-01 against Let's Encrypt or any RFC 8555-compliant CA.
- Four DNS providers: Local (no DNS, self-signed), Cloudflare, AWS
  Route53, Google Cloud DNS.
- On-disk persistence with atomic-rename + `0o600` private-key mode.
- 24h renewal-check interval; 10m DNS-record resync interval.

## Out of scope (v0.1)

- HTTP-01 / TLS-ALPN-01 challenges (use HTTP-01 only when v0.2 demand
  surfaces; relays typically live behind NAT).
- ENS gasless surfaces (FEAS-7-related; rejected as v0.1 scope).
- Route53 KSK creation (operator pre-provisions KSK in v0.1).
- AAAA record support (v0.2).
- At-rest encryption of credential material (SEC-005, Phase 5 wave).
