# Release engineering

Phase 7 U8.10 / U8.11 follow-on document. Captures the runtime-link
contract for the `gcr.io/distroless/cc-debian12:nonroot` runtime image,
the cross-compile matrix shape pending Phase 6b/B U7's WG-fork
selection, and the operator-facing artifact surface (binaries,
checksums, install scripts).

This file is referenced from the Phase 7 plan
([`docs/plans/2026-05-04-008-feat-binaries-and-e2e-plan.md`](plans/2026-05-04-008-feat-binaries-and-e2e-plan.md))
§Risks ("Distroless cc runtime missing dynamic dep that aws-lc-rs
needs") and is the canonical place for the ldd smoke-and-debug
narrative the release pipeline produces.

## Distroless `cc` runtime — required dynamic dependencies

The Dockerfile (`ac6cff7`) ships `gcr.io/distroless/cc-debian12:nonroot`
as the runtime base. **NOT** `static` because the `aws-lc-rs` rustls
provider links libc through the `cc` crate (per Phase 7 U8.7
dep-spawning-audit, `af3ae66`). The static variant would fail to link
at runtime.

The actually-linked dynamic dependencies vary by toolchain glibc
version. On bookworm (glibc 2.36) most threading / dynamic-loader /
realtime entry points are merged into `libc.so.6` via compat stubs,
so the DT_NEEDED list of a release-built binary may be just two or
three entries. Operators should NOT pin a specific library list as
the contract — the contract is "no unresolved entries".

Libraries that the release binary may or may not have as separate
DT_NEEDED entries (presence depends on the build toolchain):

- `libc.so.6` — glibc; `cc`-crate linkage + tokio syscall wrappers.
- `libgcc_s.so.1` — gcc runtime; stack unwinding for panic propagation.
- `libm.so.6` — f64 math used by the reputation engine's `apply_decay`.
- `libpthread.so.0` / `libdl.so.2` / `librt.so.1` — on glibc 2.34+ these
  are compat stubs merged into `libc.so.6`; older toolchains may
  emit them as separate DT_NEEDED entries.

**Smoke (release pipeline ldd verification):**

```sh
docker run --rm --entrypoint=/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    gosuda/portal-tunnel-rs:dev --list /app/portal-relay
```

The contract is **no unresolved entries** — every line in the output
must resolve to a path inside the runtime image (typically under
`/lib/x86_64-linux-gnu/`). Any line ending in `=> not found` is a
release-blocking failure regardless of which library is missing —
either the runtime image must extend distroless `cc` with the missing
library, the rust port must drop the dep, or the build toolchain must
be updated to consolidate the dep into `libc.so.6`.

## Cross-compile matrix

**Status: pending Phase 6b/B U7 (smoltcp + Overlay orchestrator).**

The plan ([`docs/plans/2026-05-04-008-feat-binaries-and-e2e-plan.md`](plans/2026-05-04-008-feat-binaries-and-e2e-plan.md))
U8.10 names the matrix shape:

```
[
  { os: ubuntu-latest,  target: x86_64-unknown-linux-gnu },
  { os: ubuntu-latest,  target: aarch64-unknown-linux-gnu },
  { os: macos-latest,   target: x86_64-apple-darwin },
  { os: macos-latest,   target: aarch64-apple-darwin },
  { os: windows-latest, target: x86_64-pc-windows-msvc }
]
```

Per Phase 6b/B (ADR-0014 + ADR-0015), the WG userspace fork choice
informs whether the matrix carries per-cell `--features` flags:

- If Phase 6b/B U6 lands `defguard_boringtun` symmetrically across all
  five cells → the matrix is symmetric (no per-cell `--features`).
- If Phase 6b/B U6 surfaces a per-OS fork variance (e.g., NepTUN on
  Linux only after license review, defguard_boringtun on macOS,
  wiresock-derived on Windows) → the matrix carries per-cell
  `--features` flags.

The current state (commit `f91b323`, Phase 6b/B U6 first half) ships
the `WgDevice` adapter via `defguard_boringtun = 0.6.5` and is
**symmetric** under the assumption that the same fork compiles on all
five targets. The 2026-08-04 fork-pick cliff (per ADR-0015) is when
this assumption locks; until then, `release.yml` is held back so the
matrix shape settles cleanly with U7.

## Artifact surface (per release tag)

Each released tag (e.g., `v0.1.0-rc1`) produces:

- One binary per matrix cell — named `portal-{os}-{arch}` (Linux/macOS)
  or `portal-{os}-{arch}.exe` (Windows). Asset slugs match the
  `install.sh`/`install.ps1` expectations (committed at workspace root
  in `364a420`); no slug renaming.
- One SHA256 sidecar per binary: `<binary>.sha256`. The install
  scripts verify this checksum fail-closed (per `install.sh:75-93`,
  `install.ps1:33-49`). The ldd smoke output above is captured into
  the release notes for operator review.
- One Docker image per architecture pushed to
  `ghcr.io/gosuda/portal-tunnel-rs:<tag>`.

## Release-notes posting

Two markdown templates are committed in tree as canonical release-body
content:

- [`docs/release-notes/v0.1-r10-threat-mapping.md`](release-notes/v0.1-r10-threat-mapping.md)
  — per-class R10 mitigation status, landed in `620495e`.
- [`docs/release-notes/v0.1-mvp-scope.md`](release-notes/v0.1-mvp-scope.md)
  — Ship candidates / Conditional / Deferred to point release or v0.2,
  landed in `317fb04`.

### Pre-v1.0 (current state — manual)

`cargo release` is gated off (`publish = false`, `push = false`,
`tag = false` in `release.toml`, landed in `c44fa73`). Pre-v1.0
release tags are created **manually** by the maintainer who runs the
release; that maintainer also **manually** copies / edits the two
release-notes templates into the GitHub release body via the GitHub
UI or `gh release create` flow. The cargo-release post-tag hook is
NOT used at this stage — it is configured but unreachable until the
disable flags flip.

### v1.0+ (future — automated)

When the v1.0 ADR flips the cargo-release disable flags to `true`,
the post-tag hook becomes reachable and will be wired to inject the
two committed templates into the GitHub release body automatically
(plus the git-cliff-generated changelog section for the tag's commit
range). Until that ADR lands, the automation does NOT fire — the
templates are operator-copied content, not auto-injected content.

## References

- Phase 7 plan: [`docs/plans/2026-05-04-008-feat-binaries-and-e2e-plan.md`](plans/2026-05-04-008-feat-binaries-and-e2e-plan.md)
  §§ U8.7 (dep-spawning audit), U8.10 (release pipeline), U8.11
  (Dockerfile + install scripts)
- Phase 7 U8.7 audit: [`docs/dep-spawning-audit.md`](dep-spawning-audit.md)
- ADR-0014 — overlay architecture (drives matrix shape via fork pick)
- ADR-0015 — WG userspace fork pick (defguard_boringtun primary)
- `Dockerfile` (workspace root) — multi-stage Rust 1.95 + distroless cc
- `cliff.toml` + `release.toml` (workspace root) — changelog +
  cargo-release config
- `install.sh` + `install.ps1` (workspace root) — Go-parity installer
  scripts
