# Security policy

## Reporting a vulnerability

Email security reports to **`security@portal-tunnel-rs.invalid`** (placeholder
— update before v0.1 ship). Use PGP key fingerprint published on
`https://portal-tunnel-rs.example` (placeholder, same caveat). We acknowledge
within 72 hours and aim for a fix or workaround within 14 days for high-
severity issues, 30 days for medium, 90 days for low.

Please do **not** file public GitHub issues for vulnerabilities until a fix
ships.

## Scope

In scope: code under `crates/` (per-crate `tests/` directories are inside
their owning crate), `xtask/`, build configuration (`Cargo.toml`,
`deny.toml`, `rust-toolchain.toml`, `.cargo/`, `.github/`).

Out of scope:

- The Go upstream (`portal-tunnel/`) — file upstream at
  https://github.com/gosuda/portal-tunnel
- Third-party deployments running modified copies of the codebase
- Social engineering, physical access, or denial-of-service that requires
  unbounded resources

## Threat model

The full threat model lives at [`docs/threat-model.md`](docs/threat-model.md)
(Phase 1 deliverable per SEC-006, landed). It enumerates adversary
capabilities, multi-hop privacy claims, the eight R10 anti-abuse threat
classes (a-h), and the SEC-001..005 evaluation context.

In summary, the working assumptions are:

- **Adversary classes**: passive on-path observer, active MITM proxy, hostile
  relay operator, hostile registry operator, hostile tenant.
- **Trust boundaries** are key-material isolated per R2 — three distinct
  `SecretBox<KeyType>` newtypes (`ApiHttpsKey`, `KeylessSigningKey`,
  `QuicIdentityKey`); see `AGENTS.md` and `docs/architecture.md`.
- **Cryptographic primitives**: ed25519 (`ed25519-dalek`) for protocol
  identity, k256 for SIWE, X25519+ML-KEM-768 hybrid KEX for transport (when
  the peer offers it; see ADR-0004), `aws-lc-rs` rustls provider.
- **Wire posture**: greenfield per ADR-0001. Cryptographic separation from
  Go v2.1.8 per ADR-0003 (ES256K JWT and ed25519 envelopes share no key
  root and no input encoding; verifier picked by registry path, never by
  content sniffing).
- **At-rest encryption** for `identity.json`, ACME private keys, and DNS-
  provider credentials is a Phase 5 deliverable (SEC-005). v0.1 plaintext-
  on-disk is an acknowledged limitation; deployments that require at-rest
  protection should run on encrypted-at-rest storage (LUKS, FileVault, ZFS
  encryption) until SEC-005 lands.

## Supply-chain posture

- TLS implementation is **rustls only** (R13 / ADR-0002). `openssl`,
  `openssl-sys`, `libssh2-sys`, `native-tls`, `tokio-native-tls`, `hyper-tls`
  are banned by `deny.toml` direct + transitive. The actual direct +
  transitive ban enforcement runs via `cargo deny check bans`
  (`bans.deny` array in `deny.toml`). A separate belt-and-suspenders
  CI gate (`rustls-mandatory` workflow in `.github/workflows/ci.yml`)
  asserts `cargo tree --workspace --no-default-features -i openssl`
  returns nothing — this only inspects the no-default-features
  feature subgraph; openssl pulled in by an optional feature would
  not appear here, and is caught by the cargo-deny ban list instead.
- License allowlist in `deny.toml` rejects copyleft licenses incompatible
  with the workspace MIT license.
- Advisory database checked on every CI run (`cargo deny check advisories`,
  `version = 2`); RUSTSEC vulnerabilities deny by default; yanked deny.
- `cargo vet` supply-chain audit harness landed in Phase 5 Batch 1 under
  [`supply-chain/`](supply-chain/); see
  [`CONTRIBUTING.md`](CONTRIBUTING.md) §`Certifying dependencies` for the
  per-PR `cargo vet certify` workflow and gate timeline.

## Coordinated disclosure

We follow [Coordinated Vulnerability Disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)
practice. Reports are not disclosed publicly until a fix ships and affected
operators have a reasonable upgrade window (typically 14 days for high-
severity).

This template draws from the [OpenZeppelin rust-project-template baseline
SECURITY.md](https://github.com/OpenZeppelin/rust-contracts-stylus). Update
the contact + key fingerprint placeholders before v0.1 ship.
