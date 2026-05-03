# ADR-0003: Registry-fork strategy and v2.1.8 user-base migration posture

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0001 (greenfield wire decision that creates the migration
  discontinuity); ADR-0004 (per-surface upgrade-encouragement matrix)

## Context and problem statement

ADR-0001 dropped the v2.1.8 wire-compat pin. The Rust port speaks an
incompatible wire by design, and that incompatibility is a *user-facing*
discontinuity — not just an internal refactor — because:

1. **Public registry**: deployed v2.1.8 relays publish themselves to a public
   registry under a known shape (`Address: String`, `Identity: secp256k1
   pubkey`, ES256K-signed `RelayDescriptor`). Rust-port relays publish a
   different shape (`addresses_v4 + addresses_v6` per R12, `identity: ed25519
   pubkey`, ed25519-signed `RelayDescriptor` with a domain separator per
   SEC-007). A naive shared registry path produces silent client/server
   protocol mismatch — a v2.1.8 client picks a Rust-port relay from the
   registry and fails the handshake with no actionable error.
2. **Existing user base**: `gosuda/portal-tunnel` v2.1.8 is a deployed
   product. Users who run their own relays under the v2.1.8 binary expect to
   either (a) see a deprecation timeline that lets them plan an upgrade, or
   (b) see an explicit "we will continue to maintain v2.1.8 in parallel"
   commitment. Silence on this question is the worst outcome — they discover
   the discontinuity by hitting a registry mismatch in production.

## Decision

### 1. Registry-fork posture

The Rust port runs on a **versioned registry path**. The discovery announce /
refresh endpoints carry the protocol version in the URL: `/v1/discovery` for
the Rust port (greenfield wire), `/v2.1.8/discovery` for the legacy Go port.
A relay announces under exactly one version path. A client queries the path
that matches its protocol version and never sees descriptors of the wrong
shape.

We considered a per-entry `protocol: "v0.1" | "v2.1.8"` discriminator field
inside a unified registry path. Rejected because (a) it requires every legacy
v2.1.8 client to add field-aware filtering before it can safely consume the
shared registry — i.e., it requires a coordinated v2.1.8 client update which
the migration narrative explicitly cannot rely on, and (b) silently-ignored
unknown field values are a known footgun (legacy clients connect to a Rust
relay because they didn't recognize the discriminator and defaulted to
"accept"). Versioned registry paths fail closed by design — a v2.1.8 client
asking `/v1/discovery` gets a 404, not a malformed descriptor.

### 2. Cryptographic separation

Even with versioned registry paths, the protocol identity-key roots MUST be
cryptographically separable so a confused or malicious intermediary cannot
present a v0.1-shaped envelope on the v2.1.8 path or vice versa. Concretely:

- v2.1.8 ES256K JWTs are verified by a JWS-shaped verifier with `alg: ES256K`
  fixed. Verifier rejects every other `alg` value.
- v0.1 ed25519 signed envelopes carry a domain separator per SEC-007
  (`b"portal-tunnel/relay-descriptor/v1"`, `b"portal-tunnel/lease-token/v1"`,
  ...). The first byte of every payload is the domain separator; ed25519
  verification is computed over `separator || payload`.
- The two verifiers share no key root and no input encoding. A v2.1.8
  ES256K JWT, presented to a v0.1 verifier, fails because `postcard`
  parsing fails on the first JOSE header byte. A v0.1 envelope, presented to
  a v2.1.8 verifier, fails because the JWS parser rejects raw bytes that do
  not start with a base64url-encoded JOSE header.

Clients consuming both protocol versions MUST pick the verifier by registry
path / protocol version, never by content sniffing. Out-of-band acceptance of
a v0.1-shaped envelope on the v2.1.8 path is treated as a security incident
and rejected.

### 3. v2.1.8 user-base migration posture

We commit to **explicit indefinite parallel maintenance** of the Go v2.1.8
binary, NOT a deprecation timeline. Rationale:

- A deprecation timeline forces a forced-march upgrade for users whose
  deployment cadence does not match ours. We do not have the operational
  visibility into their environments to set a credible date.
- Indefinite parallel maintenance on the Go side has a small marginal cost
  (the Go code is feature-complete and only receives security fixes); the
  cost is bounded.
- ADR-0004 captures the upgrade-encouragement matrix that nudges users
  toward the Rust port without forcing the move.

Maintenance budget for the Go v2.1.8 branch: security fixes only, no new
features. Any feature added to the Rust port stays in the Rust port. Users
who want the new features upgrade; users who want the old wire keep the old
binary.

The Rust port's release notes for v0.1 ship with a "Migrating from
gosuda/portal-tunnel v2.1.8" section that names the wire discontinuity, the
versioned registry-path strategy, the cryptographic-separation guarantee, and
the parallel-maintenance commitment in user-visible terms.

## Consequences

### Positive

- v2.1.8 deployments keep working. They publish to and consume from
  `/v2.1.8/discovery`. They never see a Rust-port descriptor.
- Rust-port deployments keep working. They publish to and consume from
  `/v1/discovery`. They never see a v2.1.8 descriptor.
- A confused intermediary cannot present a wrong-version envelope to a
  verifier — cryptographic separation enforces failure-by-construction.
- The migration discontinuity is named in release notes; users can plan.

### Negative — accepted

- The public registry operator runs two distinct paths. Operationally trivial
  but worth naming.
- Rust port and Go port cannot share a single registry deployment without two
  path mounts. Acceptable.
- We carry indefinite Go maintenance burden. Bounded; security-fixes-only.

## Considered alternatives

### A. Unified registry path with per-entry `protocol` discriminator

Rejected per §1 above (silently-ignored unknown field values; requires a
coordinated v2.1.8 client update).

### B. Hard cutover — drop Go v2.1.8 once Rust v0.1 ships

Rejected as user-hostile. Forces a forced-march upgrade with no operational
visibility into deployment cadence.

### C. Versioned registry paths + indefinite parallel maintenance — selected

Per §1-§3 above.

## References

- ADR-0001 (greenfield-wire posture)
- ADR-0004 (per-surface upgrade encouragement matrix)
- Roadmap plan: §`Resolved During Planning` → "Wire compat scope?"; §`Risks &
  Dependencies` → row "v2.1.8 user base has no migration path"
