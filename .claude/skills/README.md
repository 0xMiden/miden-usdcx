# Skills Provenance & Curation Ledger

Every skill in this directory was deliberately curated for the xUSDC-on-Miden build (2026-06-11). Skills are **mandatory checklist material**; they do **not** override a frozen decision or a wire format — conflicts are findings to report, not guidance to apply.

## Sources

| Set | Skills | Source (pinned) |
|---|---|---|
| **Protocol-local (#2927)** — 31 skills | `advice-provider-hygiene`, `assert-specific-error-in-tests`, `cheap-masm-equivalents`, `checked-arithmetic`, `conversion-method-naming`, `decouple-component-from-storage`, `domain-newtypes-over-primitives`, `felt-construction`, `intra-doc-links`, `lowercase-error-messages`, `masm-constants`, `masm-doc-comments`, `masm-error-constants`, `masm-explicit-stack-inputs`, `masm-file-structure`, `masm-formatting`, `masm-inline-comments`, `masm-locals-over-globals`, `masm-named-literals`, `masm-padding`, `masm-rust-constant-parity`, `non-exhaustive-public-types`, `parametrize-related-tests`, `preserve-error-source`, `private-fields-with-accessors`, `return-error-not-panic`, `u32-assert-before-u32-ops`, `use-bon-builder`, `use-test-fixtures`, `validate-in-constructor`, `workspace-shared-dependencies` | `0xMiden/protocol` PR **#2927**, merge commit `5bc1655d51011e3c1eb3830564fc0cd23bb35e0e` (2026-06-08) — "aggregated skills from 1y of PRs". Copied verbatim from `.claude/skills/` at that commit. |
| **Miden app-developer (project-template)** — 5 skills | `miden-concepts`, `rust-sdk-testing-patterns`, `rust-sdk-source-guide`, `local-node-validation`, `miden-client-cli` | `agentic-template/project-template/.claude/skills/` (0xMiden agentic-template submodule), copied 2026-06-11. |

Agents (`.claude/agents/`): `code-reviewer.md`, `security-reviewer.md` — also from protocol #2927 @ `5bc1655d`.
Commands (`.claude/commands/`): `review-plan`, `review-security`, `deps-audit`, `pr-enhance` — from `0xMiden/agent-tools` @ `origin/main` (2026-06-11).

## Deliberate exclusions (do NOT re-add without a reason)

- **`rust-sdk-patterns`, `rust-sdk-pitfalls`** (project-template) — they teach the **Rust-contract → `cargo miden build`** path. This repo is **MASM-first**: on-chain code is hand-written MASM; Rust is mirror/harness only. Including them would mis-route builders. (They remain in `project-template` if ever needed for off-path work.)
- **`agent-tools` MASM-6** (`masm-formatting`, `masm-file-structure`, `masm-constants`, `masm-padding`, `masm-inline-comments`, `masm-doc-comments`) — same names ship in the pinned #2927 set; the protocol-local versions take precedence and are the audited mandate. Only the agent-tools *commands* were taken.
- **frontend-template skills** (all 8) — frontend is DEFERRED in this program; nothing relevant to the on-chain/off-chain build.
- **`changelog-manager` agent** (#2927) — protocol-release tooling, not applicable here.

## Pinned obligations (from BUILDER-GATES)

- `checked-arithmetic` + `u32-assert-before-u32-ops`: **mandatory for the uint256→AssetAmount reducer.**
- `advice-provider-hygiene`: **mandatory + security-critical** on any attestation/advice-input path (later units).
- `masm-rust-constant-parity`: DC-1 offsets/magic/cap must be parity-checked or code-generated — never hand-copied.
- `assert-specific-error-in-tests` + `parametrize-related-tests`: negative tests assert the named `ERR_*`, reject families parametrized.
