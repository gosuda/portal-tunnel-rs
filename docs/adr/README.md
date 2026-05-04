# Architecture Decision Records

ADRs use the [MADR 4.0](https://adr.github.io/madr/) template. One ADR per
non-trivial decision per phase. Status lifecycle: `proposed` → `accepted` →
`superseded by NNNN`.

| ID | Title | Status |
|---|---|---|
| [0001](0001-greenfield-wire.md) | Greenfield wire — drop Go v2.1.8 byte-compat | accepted |
| [0002](0002-aggressive-2026-register.md) | Aggressive 2026 Rust register; banned-crates | accepted |
| [0003](0003-registry-fork-and-v2-1-8-migration.md) | Registry-fork strategy and v2.1.8 user-base migration posture | accepted |
| [0004](0004-supported-clients-and-upgrade-encouragement.md) | Supported clients and upgrade-encouragement matrix (R13) | accepted |
| [0005](0005-siwe-rs-stewardship.md) | siwe-rs stewardship and v0.2 fork-trigger criterion | accepted |

## Amendment procedure

R7-R9 Engineering Defaults, the cargo-deny ban list, and any "Resolved During
Planning" decision in the roadmap may be reopened **only via ADR amendment**.
The amendment names the original ADR, cites the rationale that no longer holds,
and ships in the same commit as the cargo-deny / lint / config change it
authorizes. Mid-flight reversals via TODO are out of process — see the Decision
Stability clause in the roadmap plan.
