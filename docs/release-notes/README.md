# Release-notes templates

Markdown templates committed in tree as the canonical release-body
content for portal-tunnel-rs tags. Each template is a structured
checklist that the release maintainer reviews against the actual tag
commit at release time, then injects into the GitHub release body.

## Templates

| File | Purpose |
|---|---|
| [`v0.1-mvp-scope.md`](v0.1-mvp-scope.md) | What's in / out of v0.1 — Ship candidates / Conditional / Deferred to point release or v0.2. Pre-tag every "Ships in v0.1" entry is a candidate verified against the tag commit before the release fires. |
| [`v0.1-r10-threat-mapping.md`](v0.1-r10-threat-mapping.md) | Per-class R10 mitigation status (a-h). Maps each threat class from [`docs/threat-model.md`](../threat-model.md) §"R10 threat classes (a-h)" to its v0.1 mitigation posture and the trigger criterion that promotes the matching v0.2 backlog work to active. |

## Posting flow

Pre-v1.0 (current state — manual): release tags are created manually
by the maintainer who runs the release. That maintainer manually
copies / edits each template into the GitHub release body via the
GitHub UI or `gh release create` flow. The `cargo release` post-tag
hook is configured but unreachable while `release.toml` carries
`publish = false`, `push = false`, `tag = false` (committed at
`c44fa73`).

v1.0+ (future — automated): a v1.0 ADR will flip those three flags
from `false` to `true`. When that lands, the post-tag hook becomes
reachable and is wired to inject the templates into the GitHub
release body automatically (plus the git-cliff-generated changelog
section for the tag's commit range).

The full release-engineering flow (cross-compile matrix, ldd smoke
contract, install-script SHA256 verification, Docker image push) is
documented in [`docs/release-engineering.md`](../release-engineering.md).

## Authoring conventions

- **Forecasts belong in [`PLAN.md`](../../PLAN.md), not here.** These
  templates record facts at tag time. Pre-tag prose should be
  candidate-shaped ("Ships in v0.1 IF …") and reviewers move
  candidates between sections to match the actual tag commit's state
  before the release fires.
- **Trigger criteria are required for every v0.2-deferred item.**
  Each "deferred to v0.2" row names the explicit promotion trigger
  (date / evidence threshold / ship-event) per the Decision Stability
  clause in PLAN.md. Enforcement is reviewer-discipline only — there
  is no dedicated CI gate; reviewers reject a deferral without a
  trigger by citing the PLAN.md clause directly.
- **Cross-references are absolute paths from this directory** (e.g.,
  `../threat-model.md`, `../../PLAN.md`) so the rendered GitHub
  release body links back to the canonical source-of-truth docs.
