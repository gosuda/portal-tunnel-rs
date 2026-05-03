# Threat model — portal-tunnel-rs (greenfield)

**Status:** draft SEC-006 companion.  
**Scope:** v0.1 single-relay deployment; v0.2 cross-relay items called out explicitly.

## Adversary capabilities

| Class | Capability |
|-------|--------------|
| A1 | Passive network observer (metadata, timing, ciphertext sizes). |
| A2 | Active MITM on paths not covered by pinned identities / TLS. |
| A3 | Malicious or compromised relay operator. |
| A4 | Malicious tenant (illegal content, abuse of leased ports). |
| A5 | Registry / discovery pool poisoner (false descriptors). |
| A6 | Botnet source (DDoS, scanning via leased tunnels). |

## Multi-hop privacy (claim)

Each relay in a chain SHOULD see only its hop slice: inner routing keys and next-hop addresses are not globally revealed to all prior hops. **v0.1:** up to 2-hop paths aligned with SDK plans; **v0.2:** overlay + accounting hardening.

## R10 threat classes (a–h)

| ID | Description | v0.1 mitigation | v0.2 mitigation |
|----|-------------|-----------------|-----------------|
| a | Single-relay rate-limit bypass | `governor` + backpressure (Phase 5) | Cross-relay reputation merge |
| b | Coordinated cross-relay abuse | Per-relay only | `ReputationDelta` propagation |
| c | Sybil identities | SIWE + ENS gate (Phase 5) | Stronger cross-relay identity graph |
| d | Eclipse on relay set | SDK picker ≥3 ASN bins when data exists (Phase 6a) | Enriched ASN / graph metrics |
| e | Hop-mux laundering | Not applicable v0.1 | Phase 6b accounting |
| f | Discovery descriptor poisoning | Rollback defense + takeover guards (Phase 5) | Registry quorum |
| g | Scan / probe amplification | Policy + honeypot signals (Phase 5) | Shared blocklists |
| h | DDoS on relay surfaces | Listener limits + load shed | Operator mesh |

## SEC evaluation map

| ID | Claim | Proving phase |
|----|--------|----------------|
| SEC-001 | Envelope replay / audience binding | Phase 1 wire + Phase 2 crypto tests |
| SEC-002 | SIWE ↔ ed25519 binding | Phase 2 crypto |
| SEC-003 | Lease token relay binding | Phase 1 `LeaseToken` + Phase 5 verifier |
| SEC-004 | Keyless input validation | Phase 5 + Phase 6b |
| SEC-005 | At-rest credential protection | Phase 5 (strategy); v0.1 plaintext noted in SECURITY.md until enabled |

## Deployment surface (v0.1)

- Relay HTTPS API (public CA or ACME), **rustls** + `aws-lc-rs`.
- Tenant TLS keyless (**separate** `ServerConfig`).
- QUIC datagram / stream backhaul (**separate** identity).
- IPv4 + IPv6 listeners; IPv4-mapped IPv6 canonicalized before ACL lookup (portal-net helper).

## Out of scope (v0.1)

- Server-side ECH on relay HTTPS (rustls limitation — GREASE only).
- `tokio-console` / admin dashboard as operational HTTP routes.
- Cross-relay reputation wire emission.
