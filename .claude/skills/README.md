# Skills Provenance & Curation Ledger

Every skill in this directory was deliberately curated for the xUSDC-on-Miden build (2026-06-11). Skills are **mandatory checklist material** per `docs/governing/BUILDER-GATES.md` (G-MASM / G-RUST); they do **not** override the frozen Phase 4 spec, the canonical ownership map, or the human NS-1/NS-2/DC-7 decisions — conflicts are findings to report, not guidance to apply.

## Sources

Sync policy (since 2026-08-03): each skill tracks whichever upstream (`0xMiden/protocol` `.claude/skills/` or `0xMiden/agent-tools` `skills/`) has the newest commit touching that skill; copies are verbatim unless an amendment is noted below.

| Set | Skills | Source (pinned) |
|---|---|---|
| **Protocol `next`** — 4 skills, re-synced 2026-08-03 | `cheap-masm-equivalents`, `masm-doc-comments`, `masm-inline-comments`, `masm-locals-over-globals` | `0xMiden/protocol` branch `next` @ `b414de2d15b4fcd5dfd1abaf30d50a54b21302d0` (2026-08-03). Copied verbatim from `.claude/skills/` at that commit. |
| **Protocol (#2927, still current)** — 16 skills | `assert-specific-error-in-tests`, `checked-arithmetic`, `conversion-method-naming`, `domain-newtypes-over-primitives`, `intra-doc-links`, `lowercase-error-messages`, `masm-named-literals`, `non-exhaustive-public-types`, `parametrize-related-tests`, `preserve-error-source`, `private-fields-with-accessors`, `return-error-not-panic`, `use-bon-builder`, `use-test-fixtures`, `validate-in-constructor`, `workspace-shared-dependencies` | `0xMiden/protocol` PR **#2927**, merge commit `5bc1655d51011e3c1eb3830564fc0cd23bb35e0e` (2026-06-08). Verified byte-identical to protocol `next` @ `b414de2d` on 2026-08-03 — unchanged upstream, no re-copy needed. |
| **agent-tools** — 15 skills, re-synced 2026-08-03 | `advice-provider-hygiene`, `decouple-component-from-storage`, `felt-construction`, `local-node-validation`, `masm-constants`*, `masm-error-constants`, `masm-explicit-stack-inputs`, `masm-file-structure`, `masm-formatting`, `masm-padding`, `masm-rust-constant-parity`, `miden-concepts`, `rust-sdk-source-guide`, `rust-sdk-testing-patterns`, `u32-assert-before-u32-ops` | `0xMiden/agent-tools` `main` @ `1283946cdee0f436f78c8b5c4c40657e2544558e` (2026-07-06, the v0.15 skills migration — newer for these skills than protocol's last touch). Copied verbatim from `skills/` at that commit, except `masm-constants` (see note). |
| **No upstream counterpart** — 1 skill | `miden-client-cli` | `agentic-template/project-template/.claude/skills/` (0xMiden agentic-template submodule), copied 2026-06-11. No same-named skill in protocol or agent-tools; left as pinned. |

\* `masm-constants` carries two amendments on top of the agent-tools copy: (1) the Local Memory Offsets section notes the uppercase rule is assembler-enforced (`miden-assembly-syntax` 0.25.x, `ident.rs`, rejects lowercase in constant identifiers); (2) the `=`-spacing guidance is strengthened to the spaced form, with counts measured at protocol `next` @ `b414de2d` (975 spaced vs 111 no-space in `.masm` sources).

Agents (`.claude/agents/`): `code-reviewer.md`, `security-reviewer.md` — also from protocol #2927 @ `5bc1655d`.
Commands (`.claude/commands/`): `review-plan`, `review-security`, `deps-audit`, `pr-enhance` — from `0xMiden/agent-tools` @ `origin/main` (2026-06-11).

## Deliberate exclusions (do NOT re-add without a reason)

- **`rust-sdk-patterns`, `rust-sdk-pitfalls`** (project-template) — they teach the **Rust-contract → `cargo miden build`** path. This repo is **MASM-first**: on-chain code is hand-written MASM; Rust is mirror/harness only. Including them would mis-route builders. (They remain in `project-template` if ever needed for off-path work.)
- **`agent-tools` MASM-6** (`masm-formatting`, `masm-file-structure`, `masm-constants`, `masm-padding`, `masm-inline-comments`, `masm-doc-comments`) — originally excluded in favor of the #2927 protocol-local copies. Superseded by the 2026-08-03 per-skill newest-upstream sync: `masm-constants`, `masm-file-structure`, `masm-formatting`, and `masm-padding` now come from agent-tools; `masm-inline-comments` and `masm-doc-comments` from protocol `next` (see Sources). The agent-tools *commands* were always taken.
- **frontend-template skills** (all 8) — frontend is DEFERRED in this program; nothing relevant to the on-chain/off-chain build.
- **`changelog-manager` agent** (#2927) — protocol-release tooling, not applicable here.

## Pinned obligations (from BUILDER-GATES)

- `checked-arithmetic` + `u32-assert-before-u32-ops`: **mandatory for the uint256→AssetAmount reducer.**
- `advice-provider-hygiene`: **mandatory + security-critical** on any attestation/advice-input path (later units).
- `masm-rust-constant-parity`: DC-1 offsets/magic/cap must be parity-checked or code-generated — never hand-copied.
- `assert-specific-error-in-tests` + `parametrize-related-tests`: negative tests assert the named `ERR_*`, reject families parametrized.
