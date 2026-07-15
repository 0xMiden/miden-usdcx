# Documentation inventory

Every Markdown document in this repository, with its disposition from the self-containment cleanup.
Dispositions: **KEEP** (documents the code / proves a real fact, well-placed), **REWRITE**
(planning-voice → repo-voice), **REPLACE** (removed and superseded by a self-authored doc),
**REMOVE** (build-process cruft that doesn't serve a repo reader). All dispositions below are
**done** — no document retained here cites a path or task outside this repository.

The `.claude/` skills and the git-ignored anneal runtime files (`.orchestration/`, `.anneal-gates/`, …)
are out of scope and are not listed.

## Specification (`docs/spec/`)

| Doc | Disposition | Notes |
|---|---|---|
| `GLOSSARY.md` | KEEP (new) | Defines **every** internal identifier that survives anywhere in the repo (requirements, invariants, `CMP-*`, `DC-*`, `DEV-*`/`Q-*`, `IMPL-DEV-*`, findings, LNV rows, and each `TV-*` vector). The resolve-target for all surviving anchors. |
| `FAUCET-COMPONENT-SPEC.md` | KEEP (new) | Self-authored spec for the on-chain faucet, matched to the shipped MASM. |
| `ENCODING-COMPONENT-SPEC.md` | KEEP (new) | Self-authored spec for the shared encoding layer (`DC-1`..`DC-7`, the codec routines, the dual Rust/MASM structure). |
| (removed) shared-encoding component-spec mirror | REPLACE (removed) | The planning-era mirror was dense with citations to an absent program tree; its content is now in `ENCODING-COMPONENT-SPEC.md`, the glossary (`DC-*`, `TV-*`), and the code. |
| (removed) shared-encoding test-and-verification-harness mirror | REPLACE (removed) | The test plan it described is realized by the actual crate tests; the `TV-*` catalog is in the glossary. |
| (removed) shared-encoding claim-evidence-matrix mirror | REMOVE | A planning-QA claim→evidence matrix; build-process artifact with no standalone reader value. |

## Migration & reconciliation (`docs/`)

| Doc | Disposition | Notes |
|---|---|---|
| `MIGRATION-V16-ALPHA2.md` | KEEP (new) | The v0.16.0-alpha.2 migration map: pin ledger, mechanical + semantic inventories (the S-rows), re-pin ledger, gate decisions, count parity. The historical record of the migration — not edited after the fact. |
| `reconciliation/CDR-1-CONFORMANCE-REWALK.md` | KEEP (new) | Post-migration conformance re-walk: every load-bearing `CIR-*`/Miden-family/`DEV-*`/`Q-*`/`INV-*`/`IMPL-DEV-*` id with a v16 verdict + evidence. |
| `reconciliation/V16-DOC-DELTA.md` | KEEP (new) | The doc/comment reconciliation record: per-S-row greps, every corrected prose site, every verified-current adjudication. |
| `reconciliation/CDR-RECONCILIATION-REPORT.md` | KEEP (new) | The consolidated CDR verdict (CDR-1/2/3 roll-up, NEEDS-HUMAN items, residual risk). |

## Governing (`docs/governing/`)

These are the conventions, pins, and grounding the code is built against; several are referenced by
code and tests (e.g. `MASM-STRUCTURE-RESEARCH-REPORT.md` drives `tests/masm_structure.rs`). Each was
mirrored from an internal spec program: the mirror banner (which cited an absolute path on the
author's machine) was replaced with a plain provenance note, and **all planning-tree path citations
in their bodies were cleaned** — references to docs that also live here (`V15-DEVNET-BASELINE.md`,
`CANONICAL-OWNERSHIP-MAP.md`, `GROUNDING-REPORT.md`, …) were repointed to their in-repo names, and
references to docs that are *not* in this repo were rewritten into plain prose.

| Doc | Disposition | Notes |
|---|---|---|
| `V15-DEVNET-BASELINE.md` | KEEP / REWRITE (citations cleaned) | The Miden v0.15 / devnet pin matrix. |
| `CANONICAL-OWNERSHIP-MAP.md` | KEEP / REWRITE (citations cleaned) | Module/ownership layout; referenced by MASM comments. |
| `MASM-STRUCTURE-RESEARCH-REPORT.md` | KEEP / REWRITE (citations cleaned) | The MASM source conventions the structure-conformance test enforces. |
| `BUILDER-GATES.md` | KEEP / REWRITE (citations cleaned) | The build/audit gates. |
| `GROUNDING-REPORT.md` | KEEP / REWRITE (citations cleaned) | The toolchain grounding spike. |

## Grounding canaries (`canary/`)

Each report proves that a specific Miden primitive the faucet relies on actually **executes** on the
pinned toolchain — real toolchain facts, KEEP.

| Doc | Disposition |
|---|---|
| `precompile-execution-grounding/PRECOMPILE-EXECUTION-GROUNDING-REPORT.md` | KEEP (keccak + ECDSA precompile execution) |
| `storage-map-grounding/STORAGE-MAP-GROUNDING-REPORT.md` | KEEP (storage-map read/write) |
| `mint-effects-grounding/MINT-EFFECTS-GROUNDING-REPORT.md` | KEEP (mint write primitives) |
| `mint-note-transport-grounding/MINT-NOTE-TRANSPORT-GROUNDING-REPORT.md` | KEEP (mint-note transport) |
| `burn-lifecycle-grounding/BURN-MECHANICS-GROUNDING-REPORT.md` | KEEP (burn mechanics) |

## `crates/xusdc-encoding/`

| Doc | Disposition | Notes |
|---|---|---|
| (removed) shared-encoding test ledger | REMOVE (done) | Per-slice build-loop record; no lasting reader value. |
| (removed) mint-shell test ledger | REMOVE (done) | Same — a build-loop ledger for the mint-shell slice. |
| `tests/fixtures/pinned-standards/PROVENANCE.md` | KEEP | Documents the vendored, read-only pinned-standards test fixtures. |
| `tests/vectors/circle-extraction/README.md` | KEEP | Provenance of a locally-generated test vector (explicitly not shipped by Circle). |

## `crates/xreserve-deposit-relayer/`

| Doc | Disposition | Notes |
|---|---|---|
| `DEFERRED-DEPENDENCIES.md` | KEEP | The relayer's deferred-dependency record (reqwest declaration discharged at the Circle-facing slice; cross-referenced by `deferred_dependencies_doc.rs` tests). |
| `PERSISTENCE-CHOICE.md` | KEEP (new, relayer R4) | The idempotency-store persistence decision record (SQLite; durable-path rules); cross-referenced by the `persistence_choice_doc.rs` tests. |
| `RIV-ADVICE-KEY.md` | KEEP (new, relayer R5) | The advice-key reconciliation record (the mint-note attachment advice-map key); carries an explicit up-front v16 disclaimer over its v15-era shape figures (adjudicated in `docs/reconciliation/V16-DOC-DELTA.md` §3). |

## `crates/xusdc-validation/`

Real-local-node validation evidence. The records prove the faucet works against a real node. Each
per-slice record's "Authoritative spec: `TASK-…`" line (an absent planning task) was rewritten to a
plain in-repo scope reference (`crates/xusdc-validation/README.md`).

| Doc | Disposition | Notes |
|---|---|---|
| `README.md` | KEEP | Crate orientation. |
| `PARKED-V15.md` | KEEP (new, v16 migration R1) | Why the crate is parked (no v16 `miden-client` yet), what still works, the re-enable trigger + steps. |
| `VALIDATION-RECORD.md` (LNV-1) | KEEP / REWRITE (citation cleaned) | Harness + rows A/B. |
| `VALIDATION-RECORD-LNV2.md` | KEEP / REWRITE (citation cleaned) | Admin suite (rows C) + auth boundary (row F). |
| `VALIDATION-RECORD-LNV3.md` | KEEP / REWRITE (citation cleaned) | Mint rows D/E. |
| `VALIDATION-RECORD-LNV4.md` | KEEP / REWRITE (citation cleaned) | Burn rows G/H/I/J. |
| `VALIDATION-RECORD-LNV5.md` | KEEP | The consolidated full-matrix (rows A–L) gate run — the durable evidence record. |
| `LNV5-F7-EVIDENCE-PACKET.md` | KEEP | Same-block-burn-erasure (F7) evidence for the OPEN DEV-7 decision. |
| `LNV5-NTX-LIVENESS-VERDICT.md` | KEEP | Row K (network-transaction-builder liveness) verdict. |
| `LNV5-ROW-L-FINDING.md` | KEEP | Row L operational finding + its disposition. |

## Root

| Doc | Disposition | Notes |
|---|---|---|
| `README.md` | REWRITE (done) | Now orients a fresh reader (what this is, how to build/test, where the spec + glossary are). Previously claimed "pre-implementation, no source yet". |
| `CLAUDE.md` | KEEP / REWRITE (citations cleaned) | The repo's authoring ground rules; the two references to the internal program tree were removed. |
| `AGENTS.md` | KEEP (canonical copy) | Byte-identical mirror of `CLAUDE.md` (kept in sync by rule — CLAUDE.md is canonical, edited first, then copied over AGENTS.md) so a local agent gets the same onboarding whichever file its tooling reads. |
| `docs/DOCS-INVENTORY.md` | KEEP (new) | This file. |
