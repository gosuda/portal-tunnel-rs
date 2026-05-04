# ADR-0015: WireGuard userspace fork — defguard_boringtun primary, NepTUN secondary (pending license review)

- Status: accepted
- Date: 2026-05-04
- Deciders: portal-tunnel-rs maintainers
- Related: ADR-0014 (overlay architecture; sealed `WgDevice` adapter), ADR-0001 (greenfield wire), ADR-0002 (modern register that constrains adapter dep choices), ADR-0003 (parallel-maintenance posture for v2.1.8 deployments)

## Context and problem statement

ADR-0014 commits `portal-relay`'s overlay subsystem to a sealed `WgDevice`
trait wrapping a userspace WireGuard fork. The trait isolates fork choice;
this ADR pins the fork.

The 2026 userspace-WireGuard-fork landscape, evaluated as of 2026-05-04 against
the requirements ADR-0014 imposes:

| Fork | Repo | Last commit | Server-side validation | IPv6 carriage | License | Distribution | Public API stability | `unsafe` in public API |
|---|---|---|---|---|---|---|---|---|
| **defguard_boringtun** | github.com/DefGuard/wireguard-rs (crate `defguard_boringtun = 0.6.5`) | actively released (0.6.5 on crates.io 2025-Q4) | defguard commercial VPN gateway (server-side, multi-tenant production load) | tracked; v6 carriage exercised in defguard test suite | Apache-2.0 OR MIT | crates.io published | Stable since 0.6.x; pre-1.0 with semver caveats | none in public API |
| **NepTUN** | github.com/NordSecurity/neptun | active (NordSecurity primary maintainer; forked from boringtun) | NordSecurity production VPN gateway | mature; v6 carried alongside v4 in `tun` packet path | **license-pending verification** (upstream boringtun is BSD-3-Clause; NepTUN's effective licensing has not been confirmed compatible with workspace MIT distribution) | not on crates.io as of 2026-05-04 — git source only | Drop-in `boringtun`-API surface; minor renames | none in public API |
| GotaTun | github.com/zaneschepke/gotatun (Android-validated fork) | active | Android-only validation; no documented server-side use | unknown | GPL-2.0 | git source | Android-NDK-shaped API | unknown — never evaluated for server use |
| wiresock/boringtun | github.com/wiresock/boringtun | sporadic | Windows-leaning fork; WinTun integration | minimal | BSD-3-Clause | git source | unstable | reportedly `unsafe` blocks for WinTun FFI |
| Cloudflare upstream `boringtun` | github.com/cloudflare/boringtun | upstream advisory: not for server-side use; archived for greenfield | none — Cloudflare's notice deprecates it for new server adoption | n/a | BSD-3-Clause | crates.io published | last 0.6 release deprecated | n/a |

The roadmap's Phase 6b plan (R12) requires IPv6 carriage as a first-class
feature. ADR-0014 requires the chosen fork to expose a fully safe public API
— workspace-wide `unsafe_code = "forbid"` cannot be locally relaxed by
`#[expect]` or `#[allow]` (Rust lint semantics). A fork whose public surface
forces `unsafe` calls in the adapter is **disqualified** at the architecture
layer, not "tracked-but-allowed".

A second hard gate emerged at this ADR's review: **Cargo dependencies are
statically linked into Rust binaries by default.** A copyleft-licensed fork
(GPL-2.0 / LGPL with a static-linking obligation) creates a license obligation
on the combined work that the workspace's MIT licensing does not currently
contemplate. Therefore: **license compatibility with workspace MIT distribution
is a hard gate**; any fork whose effective licensing has not been verified
compatible cannot be the primary v0.1 dep without an explicit legal-review
sign-off ahead of consumption.

## Decision

### Primary: **defguard_boringtun 0.6.5**

- **Why primary:**
  - **Permissive license (Apache-2.0 OR MIT).** No static-linking-into-MIT-binary
    concern; the workspace's MIT distribution stays clean without a legal
    review gate.
  - **crates.io published.** cargo-vet audits a published version with normal
    supply-chain ergonomics. No git-source-pinning complications.
  - **Server-side validation.** defguard ships a commercial VPN gateway product
    using this crate at multi-tenant production load. The "must run in a
    server multi-tenant context" requirement is satisfied.
  - **IPv6 carriage tracked.** v6 is exercised in defguard's test suite (per
    repo); R12 first-class requirement is satisfied.
  - **Safe public API.** No `unsafe` in the consuming surface — workspace
    `forbid(unsafe_code)` policy holds without architecture exception.
  - **Stable across 0.6.x.** Pre-1.0 with semver caveats acknowledged; the
    Phase 6b/B U6 adapter pins to a specific 0.6.x patch.
- **Consumption:**

  ```toml
  [workspace.dependencies]
  defguard_boringtun = "0.6.5"
  ```

  Pinned at U6 implementation time alongside the first consuming code in
  `crates/portal-relay/src/overlay/wg_device.rs`. Workspace-dep declaration is
  deferred to U6 (no orphan dep declared in the interval).

### Secondary: **NepTUN** (NordSecurity) — pending license review before promotion

- **Why secondary, not disqualified:** NepTUN has demonstrably strong
  server-side validation under NordSecurity's production VPN load and a more
  drop-in boringtun-API surface than defguard_boringtun. If defguard_boringtun's
  integration becomes blocked at the 2026-07-04 re-score (IPv6 regression,
  semver break, audit-blocked supply chain), NepTUN is the documented
  secondary candidate.
- **Pre-promotion gate:** Before NepTUN is consumed in workspace `Cargo.toml`,
  the maintainer who promotes it runs an explicit **license-compatibility
  review** against the workspace's MIT distribution model. The review covers:
  - Effective NepTUN license (text in `LICENSE` of the pinned sha — boringtun
    upstream is BSD-3-Clause, but NepTUN may have re-licensed at fork time).
  - Static-linking obligations under that license.
  - Compatibility with workspace MIT publication and downstream binary
    distribution (Phase 7 release pipeline).
  - Any compliance steps required (`THIRDPARTY-LICENSES.md` updates, source
    redistribution, etc.).
  - The review result lands as an **ADR-0015 amendment** in the same commit
    as the promotion. If the review concludes incompatibility, NepTUN is
    moved to "Disqualified" and the amendment records the legal rationale.
- **Promotion path is sealed-trait swap.** Per ADR-0014, the swap is one
  adapter file plus the workspace dep entry; this ADR's secondary→primary
  swap therefore costs:
  1. The license-compatibility review above.
  2. Updating `crates/portal-relay/src/overlay/wg_device.rs` to wrap NepTUN's
     handle type instead of `boringtun::noise::Tunn`.
  3. Updating `[workspace.dependencies]` to remove `defguard_boringtun` and
     add `neptun = { git = "https://github.com/NordSecurity/neptun", rev = "<sha>" }`.
  4. Adding the cargo-vet audit for the NepTUN sha (Phase 5/U6 vet setup
     supports git-rev audits).
- **Why `<sha>` is deferred:** NepTUN is not on crates.io as of 2026-05-04; a
  git source needs a pinned revision. This ADR deliberately does not pin a
  placeholder sha — pinning a sha that has not been cargo-vet-audited is a
  worse failure mode than recording the deferral. The pinned sha lands in the
  promotion amendment.

### Disqualified

- **GotaTun** — Android-NDK-shaped API; no documented server-side validation;
  porting to a server runtime is rewrite work, not adapter work. Disqualified
  for v0.1.
- **wiresock/boringtun** — Windows-leaning; reportedly carries `unsafe` blocks
  for WinTun FFI in its public surface. Disqualified by ADR-0014's safe-API
  requirement.
- **Cloudflare upstream `boringtun`** — upstream advisory deprecates it for
  new server-side use; the maintained forks (defguard_boringtun, NepTUN) exist
  precisely because the upstream stalled. Disqualified.

### Go/no-go cliff

**2026-08-04** is the integration go/no-go date. If both
defguard_boringtun (primary) and NepTUN (secondary, post-license-review)
integration are blocked at that date — fork landscape regression, audit
failure, IPv6 carriage breakage, sealed-trait integration proves intractable —
the **fallback is MVP-without-overlay** per F11:

- `crates/portal-relay/src/overlay/` ships as an empty module shell (or is
  deleted entirely) for v0.1.
- Multi-hop defers to v0.2.
- Single-hop relay backhaul (Phase 3 + Phase 5 minus overlay) ships as the
  v0.1 surface.

**Vendoring `wireguard-go` semantics into pure Rust is not a v0.1 fallback.**
The work is 3-6 months of careful Rust port (handshake, AEAD-rotation, cookie
reply, roaming) — not recovery work. F11 records this as a possible v0.2 path
if all userspace forks integration-block; it is captured in the v0.2 backlog
narrative.

### Re-score: 2026-07-04 (30 days before go/no-go)

The fork-landscape evaluation is re-run on **2026-07-04**. If the primary
regresses on any matrix column — particularly IPv6 carriage (R12 first-class)
or `unsafe`-in-public-API (hard disqualifier) — the swap to the secondary
happens BEFORE the 2026-08-04 cliff, not at it. The re-score is a calendar
event owned by the implementer holding Phase 6b/B at that date; it is not a
code constant.

## Consequences

### Positive

- **License compatibility is preserved at the architecture layer.** The v0.1
  primary (defguard_boringtun) is Apache-2.0 OR MIT — a permissive pair that
  composes cleanly with the workspace's MIT distribution. No legal-review
  gate sits in the v0.1 critical path.
- **Sealed-trait swap cost is bounded** (per ADR-0014): the primary→secondary
  swap remains one adapter file plus the workspace dep edit + the license
  review.
- **Supply-chain ergonomics are conventional.** Primary is a published
  crates.io version; cargo-vet audits the published version directly without
  a git-rev workflow.
- **R12 IPv6 carriage is a first-class evaluation column.** The 2026-07-04
  re-score guards against silent IPv6 regression in either the primary or
  the secondary.
- **`unsafe_code = "forbid"` is preserved as a hard gate** — enforced by
  ADR-0014 at the architecture layer, ratified here at the fork-pick layer.
- **MVP-without-overlay is a credible fallback.** If both forks block, v0.1
  ships with single-hop relay backhaul; the architecture acknowledges
  multi-hop is not unconditionally guaranteed.

### Negative — accepted

- **defguard_boringtun is pre-1.0.** Semver caveats apply across 0.6.x; a
  0.7 release with API changes forces an adapter update. Mitigation: the
  sealed-trait pattern keeps the blast radius to one file; release cadence
  is monitored as part of the 2026-07-04 re-score.
- **NepTUN's stronger validation story is forfeited at v0.1.** The
  primary→secondary swap path keeps NepTUN reachable, but only after the
  pre-promotion license review. If NordSecurity's server-side validation
  proves load-bearing for portal-relay's v0.1 deployment story, this ADR
  is amended to expedite the license review.
- **`<sha>` for NepTUN is deferred to promotion-amendment time.** No
  workspace dep is declared for NepTUN until the license review and the
  cargo-vet audit land together.
- **2026-08-04 cliff is a real risk.** If defguard_boringtun blocks AND
  NepTUN's license review concludes incompatibility, v0.1 ships single-hop
  only. Multi-hop delivery moves to v0.2. The risk is named here so the
  project does not silently slip the cliff.

## Considered alternatives

### A. NepTUN primary, defguard_boringtun secondary

Pros: NordSecurity's server-side validation is stronger; drop-in boringtun
API surface. Cons: NepTUN's effective licensing is unverified as of
2026-05-04; Cargo statically links deps into the consuming binary, so a
copyleft NepTUN fork (or any incompatible-with-MIT-distribution license)
creates a workspace-distribution obligation that has not been legal-reviewed.
Pinning a v0.1 hard dep on a license-unverified fork puts the project's
distribution model at risk. **Rejected** for v0.1 — adopted as the secondary
behind a license-review gate.

### B. Pin a placeholder `<sha>` for NepTUN now, audit later

Pros: ADR-0014's "Cargo.toml builds with the new dep present" verification
fires now. Cons: a placeholder sha that has not been cargo-vet-audited and a
license that has not been compatibility-reviewed is worse than a deferred
dep — it invites accidental adoption by a future implementer without
re-checking either gate. **Rejected** in favor of deferring both NepTUN's
sha and its consumption to the promotion-amendment commit.

### C. Vendor `wireguard-go` into pure Rust now

Pros: deterministic upstream, mature IPv6, no fork-pick anxiety. Cons: 3-6
month rewrite (per F11); does not clear v0.1; pulls Phase 6b/B's land date out
by a quarter. **Rejected as v0.1 work.** Recorded in the v0.2 backlog
narrative.

### D. Skip overlay entirely; ship single-hop only

Pros: no fork dependency; predictable v0.1 ship date. Cons: multi-hop is a
named v0.1 deliverable in the roadmap; explicitly cutting it forecloses
Phase 6b/B work that has otherwise viable paths. **Rejected as a default**;
it is the **fallback** if the 2026-08-04 cliff fires (MVP-without-overlay).

## References

- Roadmap plan: [`port_go_to_rust_greenfield_383a2dc9.plan.md`](../../) §
  R12 (IPv6 first-class), F11 (multi-hop deferral path), v0.2 backlog
  narrative (vendoring path)
- Phase 6b/B plan: [`docs/plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md`](../plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md)
  §§ U5 (this ADR), U6 (`WgDevice` adapter — consumes the chosen fork),
  Risks table (cliff + IPv6-regression + unsafe-surface mitigations)
- ADR-0014 — overlay architecture; sealed `WgDevice` trait that this ADR's
  fork pick implements
- ADR-0002 — register that bans certain crates at workspace level; the
  `unsafe_code = "forbid"` workspace lint and the MIT distribution model are
  the policies this ADR upholds
- defguard_boringtun crate — crates.io/crates/defguard_boringtun
- NepTUN repo — github.com/NordSecurity/neptun (consumed only after promotion-
  amendment lands)
