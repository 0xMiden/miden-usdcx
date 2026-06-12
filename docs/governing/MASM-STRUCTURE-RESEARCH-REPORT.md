> **MIRROR — READ-ONLY (mirrored 2026-06-11).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/07-implementation-readiness/MASM-STRUCTURE-RESEARCH-REPORT.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# MASM Structure & Tooling Research Report (Phase 4.3)

## Scope, Premise, and Sources

> **BASELINE SUPERSESSION (rev-3, 2026-06-10 — Miden v0.15 + devnet; read this first).** The implementation/validation target is now **Miden v0.15 on devnet** (devnet runs v0.15; **testnet is v0.14 and is NOT the validation network**), per the human-authoritative correction and the verified pin matrix `07-implementation-readiness/V15-DEVNET-BASELINE.md`. This **reframes — it does not invalidate** the version narrative below. The mapping:
> - **`protocol@0b662adfb` (labeled "v0.16.0" throughout this report) is actually on the v0.15 line:** `git describe` = **`v0.15.0-21-g0b662adfb27d`** (21 commits after the `v0.15.0` tag). Wherever this report says `protocol@0b662adfb` / "v0.16.0", read it as a **v0.15-line commit**, superseded as the canonical pin by the released tag **`protocol v0.15.3`** (`681fc9058`), which locks the `miden-assembly`/`miden-core-lib` **0.23.3** stack (the historical `v0.15.1` (`625b66dc4`) locked the **0.23.1** stack the spike's resolution was verified against; the spike verified Q1–Q4 identical on both 0.23.1 and 0.23.3) — so every component/note/`CodeBuilder`/MockChain convention cited below holds under v0.15.3.
> - **The `0.23` assembler / core-lib versions are the v0.15 stack's DEPENDENCY**, not a stale top-level target. `protocol v0.15.3` locks `miden-assembly`/`miden-core`/`miden-core-lib`/`miden-processor` = **0.23.3** and `miden-crypto`/`miden-field` = **0.25.1** (the historical v0.15.1 locked 0.23.1) (`V15-DEVNET-BASELINE.md` §1). KEEP these internal versions; frame the top-level target as "Miden v0.15 + devnet."
> - **The "0.23-vs-0.24 retarget" / "HUMAN RETARGET DECISION REQUIRED" thread below is MOOT under v0.15.** `miden-vm@328071990` (the "0.24" pin) was a separate VM-track reference, not the v0.15 target; v0.15 simply resolves the 0.23.x family (0.23.3 at v0.15.3; 0.23.1 historically at v0.15.1), and the spike (§8) + `V15-DEVNET-BASELINE.md` §3 re-confirmed the Keccak/ECDSA precompiles ARE present on **BOTH `miden-core-lib` 0.23.1 AND 0.23.3**. There is no 0.24 retarget to decide for v0.15. The §3.1/§3.3–§3.6/§5.1 "retarget" labels are retained for provenance but should be read as **resolved-on-v0.15** (0.23.3 is the current dependency, precompiles present on both).
> - **The `0.23` line citations in §2–§5 (the spike-resolved facts) carry to the current v0.15.3-locked 0.23.3 stack** (spike Q1–Q4 verified identical on 0.23.1 and 0.23.3). Local-node validation (§3.9) now targets the **v0.15 devnet** node (`miden-node bundled start`).
> - **Status under v0.15:** the gate (A)/(B) verdicts and this report's `READY FOR RE-AUDIT` status predate the retarget; an independent Codex re-audit under v0.15/devnet is required before finalization (`READINESS-STATUS.md`).

> **Revision note (rev-1, post-`AUDIT-MASM-STRUCTURE-RESEARCH.md` REVISE).** Re-grounds all version-sensitive guidance against the **Phase 4 archive-pinned** Miden baselines (not the originally-inspected heads), adjudicates the MASM convention conflicts into explicit project rules, corrects the shim-header overclaim, fixes the evidence counts (151/150/1), adds a Commands-run section, and downgrades the status from `RESEARCH COMPLETE` (§7). See the finding-by-finding closure map in §6.
>
> **Revision note (rev-2, post-`AUDIT-MASM-STRUCTURE-RESEARCH-RECHECK.md` REVISE).** Two narrow repairs: (1) §3.3–§3.6 split into a labeled **safe builder path** vs **target-dependent raw assembler/package APIs**, every raw row carrying a `PINNED BASELINE`/`HUMAN RETARGET DECISION REQUIRED` label, plus a **0.24 retarget-reference box** (`Box<Package>`/`with_package`/`.masp` from `miden-vm@328071990`); (2) the invalid bare-`core::` example citation moved off the wrong core-lib-README range (that file ends at L43) to `assembly/README.md:L88-L97` in §2.3 and §5.4. Status now `REVISION-2 COMPLETE — READY FOR RE-AUDIT`.

This report establishes the MASM monorepo layout and the Rust assemble/test harness pipeline for the xUSDC-on-Miden faucet, so a builder can lay out the repo and stand up a harness. The premise is **MASM-first**: the xUSDC custom contracts (faucet account components, mint/burn note scripts) are hand-written `.masm` assembled by a Rust harness via `miden-assembly`, NOT generated through `cargo miden build`. Rust exists only for the off-chain assemble/load/package/execute harness, storage construction, and tests.

Every convention below is carried with its exact source citation `repo/relpath:Lstart-Lend`. Conventions whose verification verdict was MISMATCH or whose statement could not be confirmed are NOT presented as fact; they are surfaced in Section 5.

### Baselines — three distinct things (do not conflate)

Phase 4 **pins** Miden baselines (`06-phase4-component-specs/00-foundation/PHASE4-SOURCE-MAP.md:64`; `06-phase4-component-specs/04-shared-encoding/COMPONENT-SPEC.md:3`). The original research was done against *different, separately-checked-out* local heads. Both are recorded below, and the **pinned baseline is the builder target** unless a human approves a retarget.

| Role | Repo | Commit | Version | Used for |
|---|---|---|---|---|
| **v0.15 BUILDER TARGET (released tag)** | `protocol` (= renamed `miden-base`) | **`v0.15.3` (`681fc9058`)** — supersedes the spike pin `0b662adfb` (= `git describe` `v0.15.0-21`, on the v0.15 line); the historical `v0.15.1` (`625b66dc4`) is the spike-verification pin | **Miden v0.15.3**, locks deps `miden-assembly`/`miden-core-lib` **0.23.3** + `miden-crypto` **0.25.1** (the v0.15 stack's deps; v0.15.1 historically locked 0.23.1) | Authoritative for component/note/build.rs/CodeBuilder/MockChain conventions. Conventions cited at `0b662adfb` carry to the v0.15.3-locked 0.23.3 stack (spike Q1–Q4 verified identical on 0.23.1 and 0.23.3). See `V15-DEVNET-BASELINE.md`. |
| ~~ARCHIVE-PINNED (builder target)~~ **SUPERSEDED reference (not the v0.15 target)** | `miden-vm` | `328071990` | "v0.24" (`miden-core-lib` 0.24) — a separate VM-track pin, **NOT the v0.15 target** | Read-only retarget reference only. Under v0.15 there is no 0.24 retarget: v0.15 resolves the 0.23.x family (0.23.3 at v0.15.3; 0.23.1 historically at v0.15.1). Rows citing it below are provenance, not a builder target. |
| originally-inspected | `protocol` | `2ef8056323` | v0.16.0, deps 0.23 | rev-0 research head. **Same v0.16.0 / assembly-0.23 family as the pinned `0b662adfb`** — its miden-standards conventions match the pin (re-verified below). |
| originally-inspected | `miden-vm` | `f84b0fff83` (branch `next`) | ~v0.22.x | rev-0 research head. **Older (2026-04-24) than the pinned VM (2026-06-03)**; some raw-assembler APIs differ from the pin (see §3.1). |
| skills (style only) | `agent-tools` | `e082708` | — | The 6 MASM skill files; one MISMATCH quarantined (STD-2). |
| secondary | `miden-tutorials` | `54bdcb96` | — | Corroborative only; never a builder gate. |

**CORRECTED version fact (was wrong in rev-0).** rev-0 claimed the older pinned VM "likely still uses `std::*` / `miden-stdlib` / `StdLibrary`". **That is false.** The pinned `miden-vm@328071990` *already* uses the `miden::core::*` module roots, the `miden-core-lib` crate, and the `CoreLibrary` type, and already ships the Keccak/ECDSA precompiles (`miden-vm@328071990:crates/lib/core/README.md:L15-L37`; `:Cargo.toml:L68`; `:crates/lib/core/src/lib.rs:L142-L147`). The `std::*→miden::core::*` rename predates *both* baselines, so it is **not** a pinned-vs-current difference. The genuine pinned-vs-inspected delta is narrower — the **raw assembler-linking call** (§3.1) — and is encapsulated by `CodeBuilder`/`TransactionKernel::assembler()`, which a builder should use instead of a hand-built `Assembler`.

**Version-alignment caveat — RESOLVED under Miden v0.15 (was "HUMAN RETARGET DECISION REQUIRED").** Under the v0.15 baseline this fork is **moot**: the builder target is `protocol v0.15.3`, which locks `miden-assembly`/`miden-core-lib` **0.23.3** (the historical v0.15.1 locked 0.23.1) — and the 0.23.x family IS the v0.15 stack's assembler dependency (not a fork to choose). The "0.24 VM `328071990`" was a separate VM-track reference, never the v0.15 target, so there is no 0.23-vs-0.24 retarget for v0.15. The safe `CodeBuilder` / `TransactionKernel::assembler()` path (whose link call at the 0.23.x stack is `with_dynamic_library`, verified at 0.23.1) is the entry point; the spike (§8) + `V15-DEVNET-BASELINE.md` §3 re-confirmed the precompiles are present on both the `0.23.1` and `0.23.3` dependency (spike Q1–Q4 identical on both). *(The original wording, retained for provenance: "The two Phase 4 pins are not mutually version-aligned at the assembler layer — `protocol@0b662adfb` depends on 0.23 while the separately-pinned `miden-vm@328071990` is 0.24." This was an artifact of pinning a VM-track commit alongside the protocol; v0.15 simply uses the 0.23.x it resolves — 0.23.1 historically, 0.23.3 at v0.15.3.)* A hand-built raw `Assembler` / precompile-host *execution* wiring remains a later, human-gated step.

### Baseline status labels (applied throughout §1–§4)

Every builder-facing command / API / import is tagged with one of:

- **`PINNED BASELINE`** — verified at the archive-pinned `protocol@0b662adfb` (v0.16.0 / assembly 0.23) and/or `miden-vm@328071990` (0.24); safe for the pinned builder target.
- **`CURRENT/NEXT ONLY`** — observed only at the originally-inspected heads (`protocol@2ef8056323` / `miden-vm@f84b0fff83`); must not gate a pinned build without re-check.
- **`HUMAN RETARGET DECISION REQUIRED`** — *(MOOT under Miden v0.15 — see the rev-3 baseline supersession note above)* originally tagged rows depending on the 0.23-vs-0.24 assembler-version choice; under v0.15 the target is `protocol v0.15.3`, which locks `0.23.3` as its dependency (no fork; v0.15.1 historically locked 0.23.1). Retained on rows below for provenance.
- **`UNVERIFIED`** — not confirmed against any baseline in this pass; kept in §5 as `PENDING MASM STRUCTURE RESEARCH`.

Unlabeled prose in §1–§2 that describes MASM *source conventions* (file layout, comments, naming) is **`PINNED BASELINE`**: the conventions were re-confirmed identical at `protocol@0b662adfb` and the inspected `2ef8056323` (both v0.16.0); only the items explicitly tagged otherwise are version-sensitive.

---

## 1. Recommended MASM monorepo folder structure (one folder per component)

### 1.1 How miden-standards actually organizes `asm/`

The faucet COMPONENT-SPEC sketched a single flat `asm/standards/xreserve/` tree. The **real** `miden-standards` source uses a **two-root architecture** that the xUSDC monorepo should mirror conceptually, because it cleanly separates canonical implementation from the thin component surface:

- **Canonical implementation root** `asm/standards/**` — contains the real procedure bodies. `build.rs` assembles this whole directory into ONE shared `.masl` library under namespace `miden::standards` (`protocol/crates/miden-standards/build.rs:18-19`, `:74-79`). Note scripts live inside this same library (`protocol/crates/miden-standards/build.rs:46-49`).
- **Component-shim root** `asm/account_components/**` — each `.masm` is a THIN RE-EXPORT SHIM (`pub use ::miden::standards::...::<proc>`), assembled INDIVIDUALLY into its own `.masl` under `miden::standards::components` (`protocol/crates/miden-standards/asm/account_components/faucets/fungible_faucet.masm:7-9`; `protocol/crates/miden-standards/build.rs:18-19`).

A component's `.masl` library path maps directly from its `.masm` path under `account_components`: e.g. `faucets/fungible_faucet.masm` → `miden::standards::components::faucets::fungible_faucet`, derived by walking the relative path components (`protocol/crates/miden-standards/build.rs:109-120`). **The Rust component's `NAME` constant must equal this MASM-derived library path** (`protocol/crates/miden-standards/src/account/mod.rs:80-85`).

### 1.2 Recommended xUSDC tree

This tree follows the real two-root organization and the **canonical ownership** boundary (faucet(01) vs shared-encoding(04)). Directory→module-path mapping is the assembler's documented behavior: `assemble_library_from_dir(dir, namespace)` recursively maps the directory structure to module paths and ignores non-`.masm` files (`miden-vm/crates/assembly/src/assembler.rs:463-478`).

```
xusdc-masm/
  asm/
    standards/                         # canonical implementation root → ONE .masl @ namespace root
      xreserve/                        # FAUCET(01)-owned logic
        constants.masm                 # shared slot/error/memory consts (see §2 const rules)
        xreserve_mint.masm             # mint_and_send-equivalent (faucet-binding assert)
        xreserve_receive_and_burn.masm # receive_and_burn-equivalent
        mint_deny_guard.masm           # mint-deny guard
        nonce_registry.masm            # nonce registry
        attester_admin.masm            # attester admin gate
        min_burn_admin.masm
        burn_policy.masm
        domain_config.masm
        deposit_intent_parser.masm     # RESOLVED (ownership): faucet(01)-owned at xreserve/, consumes 04's encoding/layout.masm consts — see §1.3 note
        attestation_verify.masm        # RESOLVED (ownership): faucet(01)-owned at xreserve/, over 04's encoding/attestation.masm staging — see §1.3 note
      encoding/                        # SHARED-ENCODING(04)-owned — single owner. ⚠️ SIBLING placement SUPERSEDED: the governing CANONICAL-OWNERSHIP-MAP nests encoding/ under xreserve/ (frozen `xreserve::encoding::*` product root) and adds attestation.masm + burn_items.masm — follow the map, not this sketch
        layout.masm
        uint256.masm                   # uint256 → AssetAmount reducer
        bytes32.masm                   # bytes32 → Word
        account_id.masm                # AccountId <-> bytes32
      notes/                           # note-script implementations (live in the standards lib)
        xreserve_mint_note.masm        # @note_script pub proc main
        xreserve_burn_note.masm        # @note_script pub proc main
    account_components/                # component-shim root → each assembled to its own .masl
      faucets/
        xreserve_faucet.masm           # thin pub use re-exports of the xreserve procs
  src/                                 # Rust harness only (constructors, storage, tests)
    account/xreserve/...
    note/xreserve_*.rs
  build.rs                             # mirrors miden-standards build.rs (see §3)
```

**Rationale (cited):**
- One library per directory root, multi-file split under one namespace, is the canonical multi-file MASM project shape — the faucet's helpers can be split across files under one namespace root (`miden-vm/crates/assembly/src/assembler.rs:463-478`; `protocol/crates/miden-standards/build.rs:74-79`).
- The shim/standards split lets the component's public surface (`pub use`) re-export canonical procs that the statically-linked standards library resolves (`protocol/crates/miden-standards/build.rs:46-49`; `asm/account_components/faucets/fungible_faucet.masm:7-9`).
- Pick the component dir/filename so the resulting `miden::standards::components::...` name is exactly what the Rust harness expects, since the Rust `NAME` must match (`protocol/crates/miden-standards/build.rs:109-120`; `src/account/mod.rs:80-85`).

### 1.3 Divergence from the faucet spec's sketched tree (prefer the real source)

The spec sketched everything flat under `asm/standards/xreserve/...` plus `asm/standards/notes/...`. The real `miden-standards` separates **canonical implementation** (`asm/standards/**`) from **component shims** (`asm/account_components/**`), which the spec's sketch collapsed. **Prefer the two-root organization** shown in §1.2: keep faucet logic in `asm/standards/xreserve/`, keep the component's public surface in a separate `asm/account_components/faucets/xreserve_faucet.masm` shim. This is grounded in `build.rs:18-19` (two namespaces) and the shim form at `fungible_faucet.masm:7-9`.

> **OPEN QUESTION (layout):** Whether the xUSDC harness should replicate the shim+standards-library split (re-export facade over a separately-assembled logic library) OR assemble a single self-contained `.masm` with proc bodies directly in the component file. Both assemble via `assemble_library` (`protocol/crates/miden-standards/build.rs:121-126`; component-with-bodies-or-facade choice at `src/account/mod.rs` macro / `fungible_faucet.masm:8-9`). This depends on the harness's `assemble_library` call shape and is a design decision, not dictated by source.

> **RESOLVED (2026-06-09 — supersedes the former parser/attestation ownership question):** Reconciled against the frozen archive; **no longer an open decision — builders must NOT re-litigate the home.** The DepositIntent layout constants and the depositAttestation felt-packing are **shared-encoding(04)-owned** (`asm/standards/xreserve/encoding/layout.masm`, `…/encoding/attestation.masm`), while the **on-chain parse/verify ASSERTION logic is faucet(01)-owned at `asm/standards/xreserve/`** (`deposit_intent_parser.masm`, `attestation_verify.masm`), which **consumes** the 04 constants/staging — per the frozen faucet spec `01-onchain-xusdc-faucet/COMPONENT-SPEC.md:278`,`:294`. This split preserves ≤1 MASM impl per routine (04 owns the constants/staging; 01 owns the assertions). Canonical source of truth: `07-implementation-readiness/CANONICAL-OWNERSHIP-MAP.md` (§Resolved layout + owner table) and `08-masm-grounding-spike/GROUNDING-REPORT.md` (decisions table). *(The separate layout OPEN QUESTION above — shim vs self-contained — remains the human's open decision.)*

---

## 2. .masm module naming/layout & conventions

Every row below is verified against the real `miden-standards` source and the agent-tools MASM skills. The xUSDC faucet is **protocol-style** code, so where the skills offer a protocol-vs-miden-vm choice, the protocol variant is selected.

### 2.1 File & section ordering — ADJUDICATED (the skill default and live `miden-standards` conflict)

The audit (Finding 3) correctly flagged that rev-0 presented two *contradictory* orderings as if both were fact. They are separated and adjudicated here. All three are `PINNED BASELINE` source-checked.

**(a) `agent-tools` skill default** — a strict five-section order, **public interface before helpers**:
1 Imports (`use` only, no header) → 2 Type aliases → 3 Constants (non-error first, then errors) → **4 Public interface (`pub proc`)** → **5 Helper procedures (non-`pub` `proc`)** (`agent-tools/skills/masm-file-structure/SKILL.md:L17-L21`). Empty sections omitted; "no helpers → public interface is last" (`:L90-L100`). Section headers = a `# SECTION NAME` line + a long `# ===…` separator (`:L8-L13`).

**(b) Live `miden-standards` style** — **feature-grouped, NOT a single public-then-helpers split.** `fungible.masm` is organized into feature banners (`TOKEN CONFIG` → `SET MAX SUPPLY` → `MINT AND SEND` → `RECEIVE AND BURN`), and within the first block the two internal `proc *_internal` helpers (`:64`, `:75`) appear **before** the public getters (`pub proc get_token_config` `:93`+). So the live order is neither the skill's public-before-helpers nor a clean helpers-before-public — it is **helpers grouped next to the public procs they serve** (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:50-93`). Re-verified identical at the pinned `protocol@0b662adfb`.

**(c) PROJECT RULE for new xUSDC MASM (chosen, with basis):**
- **New standalone xUSDC files** (the common case — `xreserve_mint.masm`, `nonce_registry.masm`, the `encoding/` files have no single neighbor to mirror): **follow the skill default (a)** — imports → constants (non-error, then `ERR_*`) → `pub proc` public interface → non-`pub` `proc` helpers last — because it is the documented standard and yields predictable file shape. *Basis: `agent-tools` skill default.*
- **When extending or sitting directly beside an existing `miden-standards` file** (e.g. a faucet variant that mirrors `fungible.masm`): **match that file's feature-grouped style (b)** for local consistency. *Basis: live `miden-standards` style.*
- This is a **project-level choice** made because the skill and the live source genuinely disagree; it is not claimed as a universal Miden rule. Either way, use `# SECTION NAME` + long `# ===` banner section headers (skill (a) + live source agree on this).

### 2.2 Module header

| Convention | Citation |
|---|---|
| **Implementation modules** open with a `#` (single-hash, NOT `#!`) block whose line 1 is the fully-qualified module namespace (`# miden::standards::faucets::fungible`), then a blank `#` line, then a prose description. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:1-8` |
| **CORRECTION (rev-0 overclaim, Finding 3):** component **shim** files do NOT use a namespace header line — the real shim opens with a plain prose `#` comment (`# The MASM code of the Basic Fungible Faucet Account Component.`), then `pub use ...` lines; there is no `# miden::standards::components::...` header. Re-verified at the pinned baseline. So: namespace-first header = implementation modules; prose-only `#` header = shims. | `protocol/crates/miden-standards/asm/account_components/faucets/fungible_faucet.masm:1-9` (and pinned `protocol@0b662adfb:` same path `:1-9`) |
| **Note scripts** open with neither — the `mint.masm`/`burn.masm` files begin with bare `use` lines, then the `#!` entry doc block above `pub proc main`; there is no module `#` header at all. | `protocol/crates/miden-standards/asm/standards/notes/burn.masm:1-21` |
| PROJECT RULE for new xUSDC MASM: implementation modules → namespace-first `#` header; component shims → prose `#` header + `pub use`; note scripts → `use` + `#!` entry doc. | (project choice; basis: the three live shapes above) |

### 2.3 Imports / use paths

| Convention | Citation |
|---|---|
| Bare `use <path>` lines (no `.masm`, no header) immediately after the header, one per line, grouped by module, no blank lines between. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:10-21`; `agent-tools/skills/masm-file-structure/SKILL.md:L90-L99` |
| Three import families: protocol kernel `miden::protocol::*` (active_account, native_account, faucet, output_note, asset, active_note), the crate's own `miden::standards::*`, and core lib `miden::core::*`. **`PINNED BASELINE`** — the `miden::core::*` root is present at the pinned `miden-vm@328071990`, not a `next`-only feature. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:10-21` |
| A single named const can be imported via its full path, e.g. `use miden::protocol::asset::FUNGIBLE_ASSET_MAX_AMOUNT`. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:10-21` |
| Note-script imports: same bare `use`, with alias via `->`, e.g. `use miden::standards::faucets::fungible->faucet` then `call.faucet::receive_and_burn`. | `protocol/crates/miden-standards/asm/standards/notes/mint.masm:L1-L3` |
| Note-type constants are imported, not hard-coded: `use miden::protocol::note::NOTE_TYPE_PUBLIC` / `NOTE_TYPE_PRIVATE`, then `push.NOTE_TYPE_PUBLIC`. | `protocol/crates/miden-standards/asm/standards/notes/mint.masm:L11-L12` |
| Core-library module roots at the **pinned** VM: `miden::core::math::u64`, `miden::core::crypto::hashes::keccak256`, `miden::core::crypto::dsa::ecdsa_k256_keccak`, etc. **`PINNED BASELINE`** (the full module index is in the pinned **core-lib** README). **Namespace-root ambiguity (`UNVERIFIED`, §5):** the pinned **assembly** README writes the MASM `use` example as bare `use core::math::u64` — confirm whether the linked `CoreLibrary` exposes the `use` root as `miden::core::…` or `core::…` before fixing import lines. | `miden-vm@328071990:crates/lib/core/README.md:L15-L37` (module index); `miden-vm@328071990:crates/assembly/README.md:L88-L97` (bare `core::` example, `use core::math::u64` at `:L91`) |

### 2.4 Export vs proc, visibility

| Convention | Citation |
|---|---|
| No separate `export.` keyword. Public procedures are `pub proc <name>`; internal helpers are plain `proc <name>`. `pub use …` re-exports another module's proc. Only `pub proc` (and `pub use`) form the callable surface. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:64-67` |
| Components do NOT use `syscall` directly; they reach the kernel via `exec.miden::protocol::*` and reach other accounts via `call`. | `protocol/crates/miden-standards/asm/account_components/access/authority.masm:22-25` |
| `exec`-only helpers (e.g. `execute_*_policy`) are intentionally NOT re-exported by the shim; only `call`-invocation procs form the component public API. Mirror this internal-vs-external split. | `protocol/crates/miden-standards/asm/account_components/faucets/policies/policy_manager.masm:13-18` |

### 2.5 Doc-comment block format

| Convention | Citation |
|---|---|
| Every `pub proc` carries a `#!` block with sections in fixed order: 1 Description, 2 Inputs/Outputs, 3 Where, 4 Panics if (when applicable), 5 Invocation (exec/call). | `agent-tools/skills/masm-doc-comments/SKILL.md:L10-L17`; confirmed in real code at `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:217-247` |
| Description starts with a capitalized present-tense verb, first sentence ends with a period. Canonical verbs: Returns, Creates, Increments, Computes, Copies, Asserts, Verifies, Hashes, Adds, Removes; Burns/Mints fit the same rule for a faucet (the skill checklist literally lists "Burns"). | `agent-tools/skills/masm-formatting/SKILL.md:L116-L116`; `agent-tools/skills/masm-doc-comments/SKILL.md:L183-L190` |
| Stack notation: single felt = lowercase_with_underscores; Word = UPPERCASE_WITH_UNDERSCORES; multi-felt (2-3) = lowercase with `{parts}` suffix. Items listed left-to-right, top-of-stack first; empty stack `[]`. | `agent-tools/skills/masm-doc-comments/SKILL.md:L47-L62` |
| `Where:` defines every Inputs/Outputs item; use "is" for single, "are" for multi-part; descriptions start lowercase (continue the sentence) and end with a period; group related items. | `agent-tools/skills/masm-doc-comments/SKILL.md:L82-L97` |
| `Panics if:` lists direct conditions from `assert*`. <4 conditions → list them; 4+ propagated → reference the subprocedure with "if <procedure> fails to verify". Omit the section if the proc cannot panic. Bullets describe the CONDITION, not the error identifier. | `agent-tools/skills/masm-doc-comments/SKILL.md:L99-L162` |
| `Invocation:` always specified. Rule of thumb: `call` if invoked via `call.<name>`, `exec` if via `exec.<name>`. For `call`, show padding in Inputs/Outputs. | `agent-tools/skills/masm-doc-comments/SKILL.md:L164-L179` |
| Use the protocol uniform doc style for NEW protocol-style code: plural `Inputs:`/`Outputs:`, `Panics if:` bullet list, `Invocation:` line (NOT the miden-vm mixed variants). | `agent-tools/skills/masm-formatting/SKILL.md:L62-L62` |
| Note-entry doc block also carries a `Requires that the account exposes:` list naming the exact proc the note calls, and a `Note storage is assumed to be as follows:` section (the latter only when the note carries storage). | `protocol/crates/miden-standards/asm/standards/notes/burn.masm:L3-L20` |

### 2.6 Inline `# => [...]` stack comments

| Convention | Citation |
|---|---|
| Inline `# => [...]` trackers record the operand stack after an operation, top-of-stack first, using the **exact same** item names/capitalization/`(N)` span notation as the `#!` doc block. Composite names decompose into their felts in inline trackers. | `agent-tools/skills/masm-formatting/SKILL.md:L122-L122`, `:L7-L7` (FMT-7) |
| Inline comments (single `#`) begin with a lowercase letter (descriptive comments and `# =>` alike). | `agent-tools/skills/masm-inline-comments/SKILL.md:L10-L21` |
| Do not over-comment obvious ops (simple arithmetic, basic stack ops, standard control flow). DO comment: stack state after complex ops, block purpose, non-obvious business rules, TODO/spec refs. Apply skip-rule only to NEW code; never strip existing comments. | `agent-tools/skills/masm-inline-comments/SKILL.md:L23-L38` |
| Insert a blank line after a `# => [...]` tracker EXCEPT when the next non-blank line is `end`, a control-flow keyword (`else`/`else.true`/`else.false`), another `# =>`, or a `#` continuation comment. | `agent-tools/skills/masm-inline-comments/SKILL.md:L41-L48` |
| Pervasive in real procs; the primary readability mechanism — place after every non-trivial stack manipulation. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:264-270`; `asm/standards/notes/p2id.masm:L53-L59` |

### 2.7 Constants & error-code naming

| Convention | Citation |
|---|---|
| Constants at the top of the file, before any procedure, after imports/type aliases. The ERRORS section is dedicated and placed AFTER the non-error constants section. | `agent-tools/skills/masm-constants/SKILL.md:L9-L27` |
| Group non-error constants by topic (Slot names, Memory pointer offsets, Magic numbers, Event ids) with blank lines between; most widely used first. | `agent-tools/skills/masm-constants/SKILL.md:L14-L24` |
| Spaces around `=` (skill rule). **Caveat:** the live standards note files are not uniform — `swap.masm` and ERR consts use NO spaces while `p2id`/`mint` arithmetic-derived consts use spaces. Match the specific file/section you extend. (See Section 5.) | `agent-tools/skills/masm-constants/SKILL.md:L65-L84`; `protocol/crates/miden-standards/asm/standards/notes/swap.masm:L9-L15` |
| Storage-slot constants: `pub const <NAME>_SLOT = word("<full::namespaced::label>")` — the slot id is a hash of a human-readable namespaced string, NOT a numeric index. `pub` makes it importable. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:26-26`; `agent-tools/skills/masm-constants/SKILL.md:L65-L84` |
| Error consts: `const ERR_<CATEGORY>_<DETAIL> = "<message>"` (string literal, no numeric codes). Category = first `_`-segment after `ERR_`. **Messages must NOT end with a period.** | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:40-48`; `asm/standards/notes/p2id.masm:L8-L13` |
| Errors are used at the assertion site via `assert.err=ERR_NAME`, `assert_eqw.err=ERR_NAME`, or after a comparison op (`lte assert.err=ERR_…`). For protocol-style code, prefer the named-constant `ERR_*` form over inline strings. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:198-199`; `agent-tools/skills/masm-formatting/SKILL.md:L97-L100` |
| Chained u32 guards on one line followed by a single `assert.err=`, e.g. `u32assert2 u32lte.MAX_LEAF_SIZE assert.err="…"` (works with `u32lt`/`u32gte` too). | `agent-tools/skills/masm-formatting/SKILL.md:L102-L108` |

### 2.8 Memory-pointer & locals naming

| Convention | Citation |
|---|---|
| Memory pointer constants (shared/global offsets, not scoped to one proc) use descriptive names WITHOUT a procedure prefix, e.g. `ASSET_OFF = 0`, `AMOUNT_OFF = 1`, `NOTE_DATA_LEN = 16`. | `agent-tools/skills/masm-constants/SKILL.md:L32-L44` |
| Memory **locals** offsets are procedure-scoped and MUST be prefixed with the owning proc name, e.g. `validate_note_NOTE_IDX_LOC = 0`. Generic unprefixed names are wrong (the prefix avoids collisions). | `agent-tools/skills/masm-constants/SKILL.md:L47-L62` |
| Real-source local-memory consts are plain integer consts (`const TOKEN_CONFIG_SLOT_LOCAL = 0`, `const MINT_ASSET_KEY_LOCAL = 4`), distinct from `word(...)` slot consts; they are offsets, not field elements with arithmetic meaning. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:32-38` |
| Local memory is declared via a `@locals(N)` attribute on the line directly above `pub proc`, accessed via `loc_storew_le.<CONST>` / `loc_loadw_le.<CONST>`; `mint_and_send` uses `@locals(8)`. | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:247-251` |
| Note-script base pointers: read note storage to memory from a base `STORAGE_PTR = 0`, derive word-aligned (4-apart) field pointers arithmetically, e.g. `const PRIVATE_ASSET_KEY_PTR = STORAGE_PTR + 4`. | `protocol/crates/miden-standards/asm/standards/notes/mint.masm:L14-L19` |
| Memory address space: first 2^31 addresses are global program memory; ≥2^31 are reserved for procedure locals (use `loc_*`/`locaddr`, never write directly ≥2^31); the top address 2^32-1 is VM-reserved for the frame pointer. | `miden-vm/docs/src/user_docs/assembly/execution_contexts.md:L58-L61` |

### 2.9 Padding (call vs exec) & the depth-16 floor

| Convention | Citation |
|---|---|
| `call` procedures: EXPLICIT `pad(N)` in doc and inline comments, with EXACTLY 16 input/output elements. `exec` procedures: NO explicit padding, no fixed-16 requirement. | `agent-tools/skills/masm-padding/SKILL.md:L12-L16` |
| VM minimum operand-stack depth is 16 (`MIN_STACK_DEPTH = 16`). Ops that would shrink the stack below 16 are auto-filled with zeros via the overflow table — actual depth stays 16, only visible content shrinks. Applies at entry of `call` procs and note/tx scripts (entered via `dyncall` at depth 16); NOT to mid-chain `exec`. | `agent-tools/skills/masm-padding/SKILL.md:L18-L26`; `miden-vm/docs/src/user_docs/assembly/execution_contexts.md:L24-L31` |
| At a floor-enforcing boundary, the `# =>` tracker must reflect the actual auto-padded depth, not the naive count: after `dropw` on entry `[VALUE, pad(12)]` write `# => [pad(16)]` (NOT `pad(12)`). Common at the start of note scripts that drop unused ARGS. | `agent-tools/skills/masm-padding/SKILL.md:L30-L42` |
| `call` doc comments show exactly 16 elements via `pad(N)` (e.g. `Inputs: [ASSET, pad(12)]`, `Outputs: [pad(16)]`); inline `# =>` tracks `pad(N)` through the proc. | `agent-tools/skills/masm-padding/SKILL.md:L62-L82`; real `Invocation: call` proc at `asm/standards/faucets/fungible.masm:217-247` |
| `exec` procs must NOT have explicit padding (they share the caller's stack); if an `exec` proc's stack falls below the specified elements it consumes caller items — a bug to fix, not pad over. | `agent-tools/skills/masm-padding/SKILL.md:L86-L111` |
| When MASM itself issues a `call`, pad BEFORE and clean AFTER: `padw padw swapdw` → `call.<proc>` → `dropw dropw`. Adapt the exact pad/movup sequence to the callee's documented input layout. | `protocol/crates/miden-standards/asm/standards/wallets/basic.masm:107-116` |
| Debug aids (`debug.stack`, `debug.stack.N`, `sdepth`) cost zero cycles and are stripped unless run with `--debug`; remove or comment out all `debug.*` lines before committing production MASM. | `agent-tools/skills/masm-padding/SKILL.md:L126-L143` |

### 2.10 Capitalization (three-tier)

| Convention | Citation |
|---|---|
| Word (4 felts) / Word-shaped commitment/root/constant → `UPPER_SNAKE_CASE` (`ASSET_KEY`, `EMPTY_WORD`). Single felt → `lower_snake_case` (`final_nonce`, `amount`). Multi-felt composite under one name → `lower_snake_case` with brace parts (`account_id_{suffix,prefix}`). | `agent-tools/skills/masm-formatting/SKILL.md:L26-L30` |
| `EMPTY_WORD` denotes the all-zero Word `[0,0,0,0]` in trackers/Where/prose — a naming convention to convey absence of data, NOT a declared source constant. | `agent-tools/skills/masm-formatting/SKILL.md:L34-L34` |
| The `(N)` span family: `pad(N)`, known-size felt-array params (`foreign_procedure_inputs(16)`), and a trailing `, ...` remainder. Words stay UPPERCASE without `(N)`; spans stay lowercase. | `agent-tools/skills/masm-formatting/SKILL.md:L40-L48` |

---

## 3. Rust-harness assemble / load / package / execute pipeline

The contract-build path is **pure `miden-assembly`**, NOT `cargo miden`: there is no `cargo miden build`, no Rust component crate in the build flow. The harness builds an `Assembler`, links dependencies, and feeds it hand-written `.masm` (`protocol/crates/miden-standards/build.rs:45-56`).

### 3.1 Construct the assembler

**Builder rule: use the `miden-standards` entry points (`TransactionKernel::assembler()` / `CodeBuilder`), NOT a hand-built `Assembler`.** Those entry points encapsulate the version-sensitive raw-link call, so the builder is insulated from the raw-assembler API difference below. *(Under Miden v0.15 the safe path resolves the v0.15 stack's `0.23.3` assembler dependency (v0.15.3-locked; 0.23.1 historically at v0.15.1); the "0.24" rows below are a superseded VM-track reference, not a v0.15 target — rev-3 supersession note.)*

| Step | Label | Citation |
|---|---|---|
| Start from `TransactionKernel::assembler()` (or `assembler_with_source_manager`). At the pinned baseline it is pre-loaded with the kernel plus the **core** library (`CoreLibrary::default()`) and the protocol library (`ProtocolLib::default()`), both linked via `.with_dynamic_library(…)`. Do NOT build a bare `Assembler::default()` — `use miden::core::…` / `use miden::protocol::…` would not resolve. | **`PINNED BASELINE`** | `protocol@0b662adfb:crates/miden-protocol/src/transaction/kernel/mod.rs:135-148` |
| `.with_warnings_as_errors(true)` is applied by `build.rs`. | **`PINNED BASELINE`** | `protocol@0b662adfb:crates/miden-standards/build.rs:45` |
| **Raw-assembler linking call — VERSION-SENSITIVE.** At the **0.23** assembler that `miden-standards@0b662adfb` pulls in, the form is `.with_dynamic_library(&CoreLibrary::default())` (the protocol kernel assembler uses exactly this). At the separately-pinned **`miden-vm@328071990` (0.24)** the README form is `Assembler::new(Arc::clone(&sm)).with_package(CoreLibrary::default().package(), Linkage::Dynamic)` — `with_dynamic_library` is replaced by `with_package(.., Linkage::Dynamic)`. A builder who hand-builds an `Assembler` must use the form matching the resolved assembler version. | **`HUMAN RETARGET DECISION REQUIRED`** (0.23 `with_dynamic_library` vs 0.24 `with_package`) | 0.23: `protocol@0b662adfb:crates/miden-protocol/src/transaction/kernel/mod.rs:146-148`; 0.24: `miden-vm@328071990:crates/assembly/README.md:L83-L85` |
| `CoreLibrary` carries off-chain precompile machinery: `.package() -> Arc<Package>` and `.handlers() -> Vec<(EventName, Arc<dyn EventHandler>)>` (Keccak, SHA512, **ECDSA**, EdDSA, SMT-peek, u64/u128-div). The executor Host MUST register these or programs calling the precompile procs fail at runtime. | **`PINNED BASELINE`** (pinned VM 0.24) | `miden-vm@328071990:crates/lib/core/src/lib.rs:L130-L150` |
| Whether the **0.23** `miden-core-lib` that `miden-standards@0b662adfb` resolves contains the same Keccak/ECDSA precompiles as the 0.24 pinned VM was not confirmed in this pass. | **`UNVERIFIED`** (§5) | — |

### 3.2 Static vs dynamic linking (a real decision)

| Decision | Citation |
|---|---|
| **Static** (`link_static_library`) COPIES the lib code into the artifact → self-contained, larger; use for code not on-chain. **Dynamic** only references it → use for FPI / code already on-chain (kernel, core, miden, foreign accounts). `build.rs` statically links the standards lib into each component so components are self-contained. The static/dynamic *decision* is stable across versions; the *method names* are version-sensitive (0.23 `with_dynamic_library`/`link_dynamic_library` vs 0.24 `with_package(.., Linkage::Dynamic)` — see §3.1). | **`PINNED BASELINE`** (semantics); method names per §3.1 | `protocol@0b662adfb:crates/miden-standards/build.rs:46-49`, `:49` (`link_static_library`) |

> **Read first — §3.3–§3.6 split into two paths (Finding 1, recheck).** **(A) SAFE BUILDER PATH (`PINNED BASELINE` — protocol 0.23 stack):** assemble via `miden-standards`' `CodeBuilder` / `TransactionKernel::assembler()`, NOT a hand-built `Assembler`. These are stable at `protocol@0b662adfb` and insulate the harness from the version-sensitive raw-assembler difference (§3.1). **(B) RAW assembler / package / artifact APIs** are target-dependent: the `Arc<Library>` / `.masl` shape below is the **protocol 0.23 stack** that `protocol@0b662adfb` actually pulls in (`protocol@0b662adfb:Cargo.toml:L48-L54`) and is labeled `PINNED BASELINE (protocol 0.23 stack)`; the **`miden-vm@328071990` 0.24** raw shape differs (`Box<Package>` + explicit name + `with_package`) and is captured in the **0.24 RETARGET REFERENCE** box after §3.6, labeled `HUMAN RETARGET DECISION REQUIRED`. The human retarget question (§3.1, §5.1) is NOT decided here.

**(A) Safe builder path — `CodeBuilder` / `TransactionKernel::assembler()`:**

| Step | Label | Citation |
|---|---|---|
| **Prefer `CodeBuilder`** (default/new/with_source_manager): pre-links kernel + core + `miden` AND dynamically links `StandardsLib::default()`, exposing `compile_component_code(path, code) -> AccountComponentCode`, `compile_note_script(source) -> NoteScript`, `compile_tx_script(code) -> TransactionScript`. This is the recommended harness entry point AGAINST the standards lib. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/code_builder/mod.rs:103-112`, `:334-405` |
| `compile_component_code(self, component_path: impl AsRef<str>, component_code: impl Parse) -> Result<AccountComponentCode, CodeBuilderError>` parses with `ParseOptions::for_library()` + the explicit module path, assembles, wraps `AccountComponentCode::from(library)`. Single-call string→component entry point. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/code_builder/mod.rs:334-358` |

**(B) Raw `Assembler` terminal methods — VERSION-SENSITIVE (only if hand-building an `Assembler`):**

| Step | Label | Citation |
|---|---|---|
| At the **0.23 protocol stack**, the terminal methods consume the `Assembler` by value and return a `Library`: `assemble_library(modules) -> Arc<Library>` (no name arg), demonstrated by `build.rs` assembling a component string `assembler.clone().assemble_library([NamedSource::new(library_path, source)])` after `link_static_library(standards_lib)`. **At 0.24 the signature differs — see the retarget box.** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/build.rs:121-126`, `:49` (`link_static_library`) |
| Pre-assemble a whole dir tree into ONE library: `assemble_library_from_dir(dir, namespace)` — directory structure maps to module paths, non-`.masm` ignored, recursion automatic; at 0.23 it returns `Arc<Library>`, written to `.masl` (`Library::LIBRARY_EXTENSION`). **At 0.24 it returns `Box<Package>` and derives the package name from the namespace — see the retarget box.** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/build.rs:73-81` |
| A single component `.masm` string assembles to its own library under the full namespace (`miden::standards::components::faucets::xreserve_faucet`); the standards lib must be statically linked first so `pub use` re-exports resolve. | **`PINNED BASELINE`** (protocol 0.23 stack) | `protocol@0b662adfb:crates/miden-standards/build.rs:98-126` |

### 3.4 Note-script assembly

All rows are protocol-side (`miden-standards` / `miden-protocol`) and re-confirmed at the pinned `protocol@0b662adfb`.

| Step | Label | Citation |
|---|---|---|
| A note `.masm` is NOT a `begin/end` program. Its entrypoint is a single `pub proc main` carrying the `@note_script` attribute on the line directly above it. Exactly one such entrypoint per file. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/asm/standards/notes/p2id.masm:L43-L44`; `:asm/standards/notes/burn.masm:20-21` |
| `compile_note_script(source)`: assemble into a Library then `NoteScript::from_library(&lib)`. `from_library` scans `library.exports()` for the single proc with the `@note_script` attribute; zero → `NoteScriptNoProcedureWithAttribute`, multiple → error. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/code_builder/mod.rs:395-405`; `:crates/miden-protocol/src/note/script.rs:119-134` |
| **Extract one script from a multi-script library:** `NoteScript::from_library_reference(library, path)` finds the export at the FQ path (e.g. `::miden::standards::notes::burn::main`), checks `@note_script`, and builds a MINIMAL MastForest (external node only) — it does NOT copy the whole library. This is how p2id/burn Rust wrappers pull their script from `standards.masl`. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-protocol/src/note/script.rs:159-182`; `:crates/miden-standards/src/note/burn.rs:L26-L33` |

### 3.5 Package, load, and bind to a component

The artifact-format rows (`.masl` / `Library`) are the **protocol 0.23 stack**; **at the 0.24 pinned VM the artifact is a `Package` (`.masp`)** — see the retarget box after §3.6. The `AccountComponentCode` / `AccountComponent::new` / `StorageSlot` rows are protocol-side, re-confirmed at `protocol@0b662adfb`.

| Step | Label | Citation |
|---|---|---|
| Pre-assembled `.masl` is written with `write_to_file(...with_extension(Library::LIBRARY_EXTENSION))`. **(0.24: `Package` written as `.masp`.)** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/build.rs:74-79` |
| Loaded at runtime by `include_bytes!(concat!(env!("OUT_DIR"), "/assets/…masl"))` then `Library::read_from_bytes(BYTES)`, wrapped in a `LazyLock` for one-time init. **(0.24: load a `Package`.)** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/src/standards_lib.rs:11-12`; `:crates/miden-standards/src/account/mod.rs:85-87` |
| A loaded component `.masl` Library → `AccountComponentCode::from(library)` (a `From<Library>`; `account_component_code!` macro does `read_from_bytes` then `::from`). | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/account/mod.rs:85-87` |
| **Final binding:** `AccountComponent::new(code: impl Into<AccountComponentCode>, storage_slots: Vec<StorageSlot>, metadata: AccountComponentMetadata) -> Result<Self, AccountError>`. Only error is >255 storage slots. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-protocol/src/account/component/mod.rs:60-64` |
| Worked example: `AccountComponent::new(FungibleFaucet::code().clone(), storage_slots, component_metadata)`. Copy this shape: assemble → `AccountComponentCode` → `AccountComponent::new(code, slots, metadata)`. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/account/faucets/fungible/mod.rs:514-517` |
| Schema-driven alternative: `AccountComponent::from_library(library, metadata, init_storage_data)` derives slots from `metadata.storage_schema().build_storage_slots(init_storage_data)` instead of an explicit Vec. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-protocol/src/account/component/mod.rs:126-138` |
| **StorageSlots are built in plain Rust:** `StorageSlot::with_value(StorageSlotName, Word)`; the faucet packs `[token_supply, max_supply, decimals, token_symbol]` into one `Word::new([...])` of 4 Felts. Slot names are namespaced strings. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/account/faucets/fungible/mod.rs:403-409` |
| Procedure roots (MAST digests) obtained POST-assembly via `code.get_procedure_root_by_path("{component}::{proc}") -> Option<AccountProcedureRoot>` (wrapped by `procedure_root!` in a LazyLock). Needed to wire auth gating / allowlists. | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/account/mod.rs:51-54` |

### 3.6 build.rs vs runtime assembly

| Decision | Label | Citation |
|---|---|---|
| build.rs sets `cargo::rerun-if-changed=asm/`, reads sources from `$CARGO_MANIFEST_DIR/asm`, writes `.masl` artifacts to `$OUT_DIR/assets` (no source copy). The harness's build.rs should mirror this and emit `.masl` for `include_bytes!`. **(0.24: emit `.masp` `Package`.)** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/build.rs:32-43` |
| Either (a) assemble at runtime via `CodeBuilder::compile_component_code` on a `.masm` string, or (b) pre-assemble to `.masl` at build time and load via `include_bytes!` + `read_from_bytes`. Both are demonstrated in-source; the runtime path is simplest for hand-written MASM (no build-time codegen step). | **`PINNED BASELINE`** (protocol 0.23) | `protocol@0b662adfb:crates/miden-standards/src/standards_lib.rs:11-12`; `:crates/miden-standards/src/code_builder/mod.rs:334-359` |
| Types to import in the harness: `Assembler`, `Library` (`miden_assembly`, re-exported as `miden_protocol::assembly::{Assembler, Library}`), `MastForest`, `Library::LIBRARY_EXTENSION`, `Library::read_from_bytes` / `write_to_file`. **(0.24: the artifact type is `Package`, not `Library`.)** | **`PINNED BASELINE`** (protocol 0.23 stack); 0.24 differs → `HUMAN RETARGET DECISION REQUIRED` | `protocol@0b662adfb:crates/miden-standards/build.rs:6-8` |

> **0.24 RETARGET REFERENCE — raw assembler/package API at the pinned `miden-vm@328071990` (`HUMAN RETARGET DECISION REQUIRED`).** Only relevant if the human retargets off the protocol 0.23 stack (§3.1, §5.1); the safe builder path (A) avoids all of this. At the 0.24 pin the raw `Assembler` API and artifact shape differ from the 0.23 rows above:
> - **Linking:** `Assembler::with_package(self, package: Arc<Package>, linkage: Linkage) -> Result<Self, Report>` (and `link_package(&mut self, Arc<Package>, Linkage)`) — replaces 0.23's `with_dynamic_library` / `link_dynamic_library` (`miden-vm@328071990:crates/assembly/src/assembler.rs:L298-L305`).
> - **Terminal methods return `Box<Package>` and take an explicit package name:** `assemble_library(self, name: impl Into<PackageId>, modules) -> Result<Box<Package>, Report>` (`:L365-L369`); `assemble_program(self, name: impl Into<PackageId>, source) -> Result<Box<Package>, Report>` (`:L723-L727`); `assemble_library_from_dir(self, dir, namespace) -> Result<Box<Package>, Report>`, deriving the name as `namespace.replace("::","-")` (`:L422-L437`).
> - **Artifact:** a `Package` (serialized `.masp`), not a `Library`/`.masl` (cf. the core lib ships as `miden-core.masp`, `miden-vm@328071990:crates/lib/core/src/lib.rs:L121-L122`).
> - **Implication:** if retargeted, the `.masl`/`Arc<Library>`/`write_to_file`/`read_from_bytes`/`AccountComponentCode::from(library)` rows in §3.3/§3.5/§3.6 must be re-derived against the 0.24 `Package` API, AND the `miden-standards`/`miden-protocol` crates would have to move to a 0.24-compatible release (they pin 0.23 at `0b662adfb`). This is exactly the unresolved §5.1 decision.

### 3.7 Shared Rust↔MASM error constants (codegen)

| Step | Citation |
|---|---|
| Error codes are SHARED by codegen, not hand-duplication: build.rs greps every `.masm` for `const ERR_<NAME> = "<message>"`, dedups/validates (no period-terminated messages, no conflicting duplicates), and writes `$OUT_DIR/standards_errors.rs` containing `pub const ERR_<NAME>: MasmError = MasmError::from_static_str("<message>")`. | `protocol/crates/miden-standards/build.rs:374-378` |
| MASM source syntax the codegen expects: `const ERR_<CATEGORY>_<NAME> = "<message>"` (category = first token after `ERR_`; no trailing period). | `protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:40-41` |
| Rust-side hookup: `pub mod standards { include!(concat!(env!("OUT_DIR"), "/standards_errors.rs")); }` (here gated behind testing). Mirror to expose MASM errors as typed `MasmError` constants. | `protocol/crates/miden-standards/src/errors/mod.rs:3-5` |

### 3.8 Execution semantics the harness depends on

| Semantics | Citation |
|---|---|
| `exec` = in-context call: callee runs on the SAME context and operand stack (conceptually inlined). Use for internal helpers. | `miden-vm/docs/src/user_docs/assembly/execution_contexts.md:L44-L44` |
| `call`/`dyncall` create a NEW isolated user context (own 2^32 memory space); items beyond the top 16 are hidden; callee MUST return at depth exactly 16 or the VM traps. Top 16 are the param/return channel. | `miden-vm/docs/src/user_docs/assembly/execution_contexts.md:L24-L31` |
| `syscall` = same context-switch + depth-16, but moves back into the root context; callee must be a kernel-exported proc. Default (empty) kernel → no `syscall`. | `miden-vm/docs/src/user_docs/assembly/execution_contexts.md:L12-L12` |
| `procref.NAME` pushes the 4-element MAST root of NAME (compiles to `push.HASH`); used to obtain a proc hash for dynexec/dyncall. | `miden-vm/docs/src/user_docs/assembly/code_organization.md:L77-L77` |
| `sys::truncate_stack()` drops deep elements until depth is exactly 16 (preserving top 16) — call at the end of a `call`/`syscall` callee to satisfy the depth-16-on-return rule. | `miden-vm/crates/lib/core/asm/sys/mod.masm:L12-L15` |

### 3.9 (Reference) The test harness — assemble→component→MockChain→execute→assert

The MockChain harness path (Phase 4 testing) is fully grounded:

| Step | Citation |
|---|---|
| Stand up: `MockChain::builder()`; add the faucet via `builder.add_existing_account_from_components(auth, components)` (genesis) or `add_account_from_builder(auth, AccountBuilder, AccountState::Exists)`; `builder.build()?`. Auth component appended and authenticator registered automatically. | `protocol/crates/miden-testing/src/mock_chain/chain_builder.rs:L624-L637`, `:L598-L622` |
| Genesis/input notes: `add_output_note(impl Into<RawOutputNote>)` (or `add_p2id_note` etc.). | `protocol/crates/miden-testing/src/mock_chain/chain_builder.rs:L658-L661` |
| Build a tx: `mock_chain.build_tx_context(input, note_ids, unauthenticated_notes) -> TransactionContextBuilder`; attach `.tx_script(compile_tx_script(...))`; `.build()?`. Component MAST auto-registered via `TransactionMastStore::load_account_code`. | `protocol/crates/miden-testing/src/mock_chain/chain.rs:L651-L659`; `tests/scripts/faucet.rs:L120-L127`; `tx_context/builder.rs:L322-L331` |
| Execute: `tx_context.execute().await -> ExecutedTransaction` (wraps `miden_tx::TransactionExecutor::execute_transaction`). For unit-probing one proc: `TransactionContext::execute_code(masm_str).await -> ExecutionOutput`. | `protocol/crates/miden-testing/src/tx_context/context.rs:L178-L197`, `:L85-L86`; `miden-tx/src/executor/mod.rs:L223-L229` |
| Custom-note flow: `NoteBuilder::new(sender, &mut rng).note_type(...).script(note_script).build()?` then pass as `unauthenticated_notes` to `build_tx_context`. | `protocol/crates/miden-testing/tests/scripts/faucet.rs:L172-L182` |
| Assert: `executed_transaction.account_delta().nonce_delta() == Felt::ONE`, `.input_notes()`/`.output_notes()`; `assert_note_created!` macro; multi-tx via `add_pending_executed_transaction` + `prove_next_block` + `apply_delta` + `vault().get`; typed faucet metadata via `FungibleFaucet::try_from(storage).max_supply()/token_supply()`. | `protocol/crates/miden-testing/tests/scripts/faucet.rs:L425-L428`, `:L765-L783`, `:L405-L413`; `src/asserts.rs:L71-L87` |
| **AVOID** modeling xUSDC on `MockFaucetComponent`/`MockAccountComponent` — they wrap a fixed `mock_faucet_library()` with empty storage and no real logic. | `protocol/crates/miden-standards/src/testing/account_component/mock_faucet_component.rs:L17-L25` |
| Local-node path (gated, after MockChain): same assembly half, then `TransactionRequestBuilder::new().custom_script(tx_script).build()` + `client.submit_new_transaction(account_id, request)`. | `miden-tutorials/rust-client/src/bin/counter_contract_deploy.rs:L110-L118` |

---

## 4. Copy / avoid / adapt patterns for the xUSDC faucet

### 4.1 Faucet account component — mint procedure (`xreserve_mint`)

**COPY:**
- Storage read via `push.<SLOT_CONST>[0..2] exec.active_account::get_item`; storage WRITE via `push.<SLOT_CONST>[0..2] exec.native_account::set_item dropw`. Reads use `active_account`, writes use `native_account` (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:64-67`, `:443-444`).
- token_supply mechanics: `token_supply` is word[0] of `TOKEN_CONFIG_SLOT` `[token_supply, max_supply, decimals, token_symbol]`. Mint asserts `token_supply<=max_supply`, `max_supply<=FUNGIBLE_ASSET_MAX_AMOUNT`, `amount<=max_supply-token_supply`, then writes `token_supply+amount` (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:55-57`).
- Asset mint via the protocol faucet kernel: `exec.faucet::create_fungible_asset` → `exec.faucet::mint`; add to output note via `exec.output_note::add_asset` (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:340-356`).
- **Self-faucet binding (security check):** store the note's `ASSET_KEY` in a local, derive the active faucet's own fungible asset key, and `assert_eqw.err=ERR_..._NOT_FROM_THIS_FAUCET` so a mint note created for faucet A cannot mint against faucet B (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:347-350`).
- `@locals(8)` on the line above `pub proc mint_and_send`; locals via `loc_storew_le`/`loc_loadw_le` (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:247-251`).

### 4.2 Mint-deny guard & admin gates (deny guard, attester admin, min-burn admin)

**ADAPT:**
- Admin/owner gating: gate a state-mutating proc with `exec.authority::assert_authorized` (consults a single `AUTHORITY_SLOT`: 0=AuthControlled no-op, 1=OwnerControlled→ownable2step, 2=RbacControlled→rbac) and `exec.pausable::assert_not_paused`, both `exec`'d inline in the active-account context. For an owner-only xUSDC admin proc (attester admin, min-burn admin), reuse this `assert_authorized` gate (`protocol/crates/miden-standards/asm/standards/access/authority.masm:46-49`; `asm/standards/faucets/fungible.masm:186-190`).
- **Internal-vs-external split for the deny guard / policy helpers:** keep `exec`-only helpers (mint-deny logic, burn-policy execution) NOT re-exported by the component shim; expose only the `call`-invocation procs (set/get policy) as the public API (`protocol/crates/miden-standards/asm/account_components/faucets/policies/policy_manager.masm:13-18`).

### 4.3 Nonce registry

**ADAPT:** Use the storage-slot + `get_item`/`set_item` read/write pattern (§4.1) for the nonce registry slot(s). `Panics if:` bullets describe the CONDITION (e.g. "the nonce has already been incremented.") not the error identifier (`agent-tools/skills/masm-doc-comments/SKILL.md:L99-L162`). Concrete nonce-registry slot names are NOT covered by source — see Section 5.

### 4.4 Burn note (`xreserve_burn_note`) and burn flow

**COPY (thin-note design):** The BURN note is the minimal model — import only the faucet, ignore ARGS (`dropw` → `# => [pad(16)]`), and do the entire burn with a single `call.faucet::receive_and_burn`. It carries NO storage (`NUM_STORAGE_ITEMS = 0`), so it does NOT call `get_storage` and does NOT assert a storage count. All validation (exactly one asset, asset belongs to this faucet, amount ≤ supply, burn-policy) lives in the faucet's `receive_and_burn`, not the note (`protocol/crates/miden-standards/asm/standards/notes/burn.masm:L21-L30`).

**REFERENCE (burn vs p2id):** p2id consumes a note that DELIVERS assets INTO the consuming account (`add_assets_to_account` credits the vault). burn does the opposite: `receive_and_burn` pulls the single asset from the active note (`get_assets` + `asset::load`), runs burn policy, then `exec.faucet::burn` removes it from circulation and DECREMENTS token_supply. The xUSDC burn-note maps onto the faucet-side `receive_and_burn`, NOT onto p2id's add_assets path (`protocol/crates/miden-standards/asm/standards/faucets/fungible.masm:L399-L421`).

**COPY (tag set in Rust):** the note tag is NOT computed in the note script — it is chosen on the Rust harness side: `tag = NoteTag::with_account_target(faucet_id)` so the network routes the burn note to the faucet; the MASM just forwards/loads the tag felt (`protocol/crates/miden-standards/src/note/burn.rs:L99-L101`).

**COPY (script load):** the Rust harness loads a note script by library path to `main`: `NoteScript::from_library_reference(lib, Path::new("::…::burn::main"))` — assemble the standards-style lib then reference `<lib>::…::main` (`protocol/crates/miden-standards/src/note/burn.rs:L26-L33`).

### 4.5 Mint note (`xreserve_mint_note`)

**ADAPT:** The MINT note is the model. It reads its storage (`push.<ptr> exec.active_note::get_storage` → `num_storage_items`), asserts the count (`u32assert2.err=… u32gte.MIN_NUM_STORAGE_ITEMS_PUBLIC`), branches on public (20+ items) vs private (13 items) with `if.true … else … end` to assemble `[ASSET_KEY, ASSET_VALUE, tag, note_type, RECIPIENT, pad(12)]`, then does ALL minting + supply checks + output-note creation in one `call.faucet::mint_and_send`. The note itself never mints (`protocol/crates/miden-standards/asm/standards/notes/mint.masm:L80-L84`, `:L14-L19`).

**COPY (call/drop discipline):** after a `call` that returns more elements than wanted, restore the floor: `call.faucet::mint_and_send` → `# => [note_idx, pad(25)]` → `dropw dropw drop drop` → `# => [pad(16)]` (`protocol/crates/miden-standards/asm/standards/notes/mint.masm:L146-L150`).

**REFERENCE (output-note creation contract):** `exec.output_note::create` input is exactly `[tag, note_type, RECIPIENT]`, output `[note_idx]` (`protocol/crates/miden-protocol/asm/protocol/output_note.masm:L15-L18`). Recipient built in-MASM with `exec.note::compute_and_store_recipient` (input `[storage_ptr, num_storage_items, SERIAL_NUM, SCRIPT_ROOT]` → `[RECIPIENT]`); the own script root via `procref.main` (`protocol/crates/miden-protocol/asm/protocol/note.masm:L239-L244`).

> **PRODUCT DECISION (not in source):** whether the xUSDC mint-note supports BOTH public and private branches or only one mode. Flagged in Section 5.

### 4.6 Shared-encoding MASM module (`encoding/`)

**ADAPT:** Treat the encoding module as a separate set of `.masm` files under one namespace (`bytes32`, `uint256`, `account_id`, `layout`), assembled into the same library and `use`d by the faucet procs. There is no shared-encoding-specific MASM in the inspected miden-standards source, so the patterns to copy are the generic ones: storage/memory pointer conventions (§2.8), the `# => [...]` tracker discipline (§2.6), and the Rust↔MASM test-vector parity discipline below. **Anti-duplication:** ≤1 MASM impl AND ≤1 Rust impl of each owned routine (ownership invariant from the spec).

### 4.7 Rust↔MASM layout sync (cross-cutting)

**ADAPT:** The Rust component module documents that its storage layout must stay in sync with the MASM source, citing the exact `.masm` path: `//! Layout sync: the same layout is defined in MASM at asm/standards/faucets/mod.masm`. For xUSDC, keep the MASM slot consts and the Rust harness's slot definitions in lockstep and reference the `.masm` path in a comment (`protocol/crates/miden-standards/src/account/faucets/token_metadata.rs:24-24`).

### 4.8 Core-library precompiles for the xUSDC signature/encoding path (REFERENCE)

**`PINNED BASELINE` at the pinned VM `miden-vm@328071990` (0.24)** — the Keccak/ECDSA precompiles are present there (correcting rev-0's open question that doubted it). If xUSDC's attestation/encoding needs hashing or ECDSA:
- Keccak256: `miden::core::crypto::hashes::keccak256` — `pub proc hash_bytes`/`hash`/`merge`; implemented as a PRECOMPILE that `emit`s `KECCAK_HASH_BYTES_EVENT`; the Host MUST register the Keccak event handler (`miden-vm@328071990:crates/lib/core/asm/crypto/hashes/keccak256.masm:L17`, `:L32-L33`).
- ECDSA secp256k1: `miden::core::crypto::dsa::ecdsa_k256_keccak::verify` (`@locals(48) pub proc verify`; PK 9 felts loaded to locals, Poseidon2 commitment checked via `assert_eqw "invalid public key commitment"`; traps on bad commitment/signature); `EcdsaPrecompile` handler must be registered (`miden-vm@328071990:crates/lib/core/asm/crypto/dsa/ecdsa_k256_keccak.masm:L56-L67`; handler set at `:crates/lib/core/src/lib.rs:L142-L147`).
- 64/256-bit math for balances: `miden::core::math::u64` (`wrapping_add`, `widening_mul -> u128`, comparators, div/mod) and `math::u256`.
- u32 ops are NATIVE VM instructions (`u32assert2`, `u32overflowing_add`, etc.), `[b, a, ...]` operand order, "Undefined if max(a,b) ≥ 2^32" unless a `u32assert` guard precedes.
- **`UNVERIFIED` (§5):** whether the **0.23** `miden-core-lib` that `miden-standards@0b662adfb` actually resolves contains these same precompiles. If the builder targets the 0.23 stack (via `miden-standards`) and 0.23 lacks the ECDSA/Keccak precompile, that forces the 0.24-VM retarget decision (§3.1) or a hand-written fallback. The u64/u256/u32 line citations in this section are from the inspected head and should be re-confirmed at the resolved core-lib version.

---

## 5. Open questions / undecided items

Do NOT resolve these by guessing into conventions.

**Version-targeting — RESOLVED under Miden v0.15 (rev-3; was "highest priority — `HUMAN RETARGET DECISION REQUIRED`"):**
1. **No 0.23-vs-0.24 fork under v0.15.** ~~The two Phase 4 pins are not version-aligned at the assembler layer.~~ Under the Miden v0.15 + devnet baseline the builder target is `protocol v0.15.3` (the spike pin `0b662adfb` = `git describe` `v0.15.0-21` is a v0.15-line commit; the historical v0.15.1 locked the 0.23.1 the spike verified against), which locks `miden-assembly`/`miden-core-lib` **0.23.3** — the v0.15 stack's assembler dependency, NOT a fork (spike Q1–Q4 + the precompile gate verified identical on 0.23.1 and 0.23.3; Q5/Q6 on the 0.23.1-seeded stack, carrying per `V15-DEVNET-BASELINE.md` §4). `miden-vm@328071990` ("0.24") was a separate VM-track reference, never the v0.15 target. The harness uses the safe `CodeBuilder`/`TransactionKernel::assembler()` path (link call `with_dynamic_library`, verified at 0.23.1). **No raw-assembler retarget decision is pending for v0.15.** (rev-0 wrongly framed this as "current `next` is ahead of an older pinned VM that still uses `std::*`/`StdLibrary`" — corrected: both baselines use `miden::core`/`CoreLibrary`.) See `V15-DEVNET-BASELINE.md` §1, §3 and §8 below.
2. **`UNVERIFIED`:** whether the **0.23** `miden-core-lib` resolved by `miden-standards@0b662adfb` contains the `ecdsa_k256_keccak` / `keccak256` precompiles. They ARE present at the 0.24 pinned VM `328071990` (`:crates/lib/core/asm/crypto/dsa/ecdsa_k256_keccak.masm:L56-L67`, `:crates/lib/core/asm/crypto/hashes/keccak256.masm:L32`), but the 0.23 line was not resolved/inspected. If xUSDC needs secp256k1/keccak and the resolved 0.23 lacks it, that forces the §1 retarget decision or a hand-written fallback. → keep readiness item `PENDING MASM STRUCTURE RESEARCH` (owner: builder + human; trigger: choosing the assembler/VM target).

**Verification MISMATCH (do NOT cite as fact):**
3. **STD-2 (MISMATCH):** The extractor's verbatim quote for the core-library module index at `miden-vm/crates/lib/core/README.md:L15-L37` does NOT match — the README bullets are alphabetical and keccak256/poseidon2 are non-adjacent (poseidon2 at L20, keccak256 at L22), not the consecutive pair quoted. The *substantive* module index (which modules exist) was independently confirmed against the actual `asm/` tree, but the specific quoted line pair must NOT be presented as a verbatim citation. Use the module names only with the verified file-tree backing, not the README line-range quote.

**Namespace / attribute grammar (unconfirmed):**
4. **Core-lib namespace root ambiguity (`UNVERIFIED`):** the pinned **core-lib** README lists modules as `miden::core::…` (`miden-vm@328071990:crates/lib/core/README.md:L15-L37`, which ends at L43) while the pinned **assembly** README's MASM example uses the bare `use core::math::u64` (`miden-vm@328071990:crates/assembly/README.md:L90-L97`, the `use` line at `:L91`). Confirm which root the linked `CoreLibrary` exposes for `use` lines — getting it wrong is an unresolved-symbol error.
5. The assembler-level definition/semantics of `@note_script` and `@locals(N)` (where parsed, what they compile to, max locals/alignment, `le`-suffix meaning) were NOT found in the files read; confirm in the assembly/compiler crate before relying on exact attribute spelling/casing for a hand-rolled lib.
6. The `word("...")` slot-id syntax and the `[0..2]` slice operator are used as language features but their exact semantics (string→slot hashing, what `[0..2]` selects) were not defined in the inspected `.masm`; verify in miden-vm assembly docs / the compiler.
7. Whether a hand-written account-component `.masm` needs any export-marking attribute analogous to `@note_script` (e.g. `@auth_script` referenced at `component/mod.rs:189`) vs all `pub proc`s being auto-exported. `mint_and_send` carries only `@locals(8)` with no export attribute, suggesting `pub proc` alone exports — but the full attribute set was not enumerated.

**Constants-style inconsistency (file-dependent, not a global rule):**
8. The masm-constants skill mandates spaces around `=`, but live standards note files are NOT uniform: `swap.masm` and ERR consts use NO spaces; `p2id`/`mint` arithmetic-derived consts use spaces. There is no codebase-uniform rule — match the specific file/section you extend, and pick a project-level convention explicitly for new files.

**Composite-name ordering (no canonical default for new files):**
9. Brace spacing and part order in composite names are inconsistent in source: both `{suffix,prefix}` and `{suffix, prefix}`, and both suffix-first and prefix-first, appear. The two skills even disagree on the default order (`account_id_{suffix,prefix}` in masm-formatting vs `account_id_{prefix,suffix}` in masm-doc-comments). For a brand-new faucet there is no surrounding-file default; pick one ordering convention explicitly (protocol procs more commonly use suffix-first).

**Section-header & Cycles width (not mandated):**
10. The section-header separator length (a long run of `=`, 49 in the example) has no mandated exact column count.
11. Whether the faucet's pub procs carry a `Cycles:` section is left to "match the local file or repo style"; for new protocol-style code there is no firm rule. Decide whether to include cycle accounting.

**Faucet-specific storage slot names (not covered):**
12. The skills do NOT specify faucet-specific storage slot names (total supply, max supply, metadata, nonce registry, attester admin) beyond the generic Slots topic and `word("path::to::slot")` format. Concrete xUSDC slot names must be derived from the spec / `protocol/crates/miden-protocol/asm/protocol/faucet.masm` (referenced but not read in this task).

**Harness / metadata API surface (observed, not read from defining modules):**
13. The exact `StorageSlotName`/`StorageSlot` and `AccountComponentMetadata`/`StorageSchema` API (map slots, `StorageSchema::new`, what metadata is needed for slot names to resolve at MASM assembly time) was observed only via faucet usage. For non-trivial storage (maps, multi-slot), read `protocol/crates/miden-protocol/src/account/component/{metadata,storage}.*` directly.
14. Whether the harness must link `link_static_library(standards_lib)` to resolve `exec.miden::protocol::*` / `exec.miden::standards::*`, or whether `TransactionKernel::assembler()` / `CodeBuilder` already provides them dynamically, for a downstream (non-protocol) harness crate — and whether `CoreLibrary::default()` / `ProtocolLib::default()` are publicly re-exported for external use.
15. Whether `miden-protocol` (with the `std` feature for `assemble_library_from_dir`, which is `#[cfg(feature = "std")]`) is wired as a BUILD dependency vs a normal dependency — not verified which `Cargo.toml` section.
16. The protocol kernel proc signatures/stack contracts the faucet calls (`active_account::get_item`, `native_account::set_item`, `faucet::mint/burn/create_fungible_asset`, `output_note::create/add_asset`, `active_note::get_assets`, `asset::load/fungible_to_amount`) were `use`d but defined in miden-protocol/miden-vm; confirm signatures before xUSDC calls them.

**Product / design decisions (not source facts):**
17. Whether the xUSDC mint-note supports BOTH public (20+ items) and private (13 items) branches or only one mode.
18. The exact felt/u32-limb encoding xUSDC should use for balances (whether amounts fit in a single felt < p ≈ 2^64, or need u64/u128/u256) — a contract-design decision.
19. Prebuilt `.masl` (`account_component_code!` macro, build-time codegen) vs runtime `compile_component_code` for the monorepo's perf/startup budget — both compile; a design decision.

---

## 6. Sources inspected

### Repos & commits

| Repo | Role | Commit | Version | Local-clone check |
|---|---|---|---|---|
| `protocol` (= `miden-base`) | ~~ARCHIVE-PINNED (builder target)~~ **SUPERSEDED — v0.15-line dev commit (rev-3: builder target = released `v0.15.3`)** | `0b662adfb` (retrieval ref `2c423249d`; `git describe` = `v0.15.0-21`) | recorded "v0.16.0" pre-tag; deps `miden-assembly`/`miden-core-lib` 0.23 | `cat-file -t` → `commit` (present) |
| `miden-vm` | ~~ARCHIVE-PINNED (builder target)~~ **SUPERSEDED — separate VM-track reference, never the v0.15 target (rev-3)** | `328071990` | 0.24 (VM track) | `cat-file -t` → `commit` (present) |
| `protocol` | originally-inspected (rev-0) | `2ef8056323` | v0.16.0, deps 0.23 | local HEAD; same v0.16.0/0.23 family as the pin |
| `miden-vm` | originally-inspected (rev-0) | `f84b0fff83` (branch `next`) | ~v0.22.x | local HEAD; **older (2026-04-24)** than the pinned VM (2026-06-03) |
| `agent-tools` | skills (style only) | `e082708` | — | local HEAD |
| `miden-tutorials` | secondary/corroborative | `54bdcb96` | — | local HEAD |

All component/note/build.rs/CodeBuilder/MockChain conventions in §1–§4 were re-confirmed at the **pinned `protocol@0b662adfb`** (identical to the inspected `2ef8056323`). miden-vm assembler/core-lib line citations from the inspected `f84b0fff83` that are version-sensitive are re-grounded to the **pinned `miden-vm@328071990`** in §2.3/§3.1/§4.8 and labeled.

### Concrete paths read

**agent-tools MASM skills:** `skills/masm-formatting/SKILL.md`, `skills/masm-file-structure/SKILL.md`, `skills/masm-constants/SKILL.md`, `skills/masm-padding/SKILL.md`, `skills/masm-inline-comments/SKILL.md`, `skills/masm-doc-comments/SKILL.md`.

**protocol — miden-standards (build & Rust):** `build.rs`, `src/standards_lib.rs`, `src/code_builder/mod.rs`, `src/lib.rs`, `src/errors/mod.rs`, `src/account/mod.rs`, `src/account/components/mod.rs`, `src/account/faucets/fungible/mod.rs`, `src/account/faucets/fungible/tests.rs`, `src/account/faucets/token_metadata.rs`, `src/note/p2id.rs`, `src/note/burn.rs`, `src/testing/account_component/mock_account_component.rs`, `src/testing/account_component/mock_faucet_component.rs`.

**protocol — miden-standards (MASM):** `asm/account_components/faucets/fungible_faucet.masm`, `asm/account_components/faucets/policies/policy_manager.masm`, `asm/account_components/faucets/policies/mint/owner_controlled/owner_only.masm`, `asm/account_components/wallets/basic_wallet.masm`, `asm/account_components/access/authority.masm`, `asm/standards/faucets/fungible.masm`, `asm/standards/faucets/mod.masm`, `asm/standards/wallets/basic.masm`, `asm/standards/access/authority.masm`, `asm/standards/notes/{p2id,burn,mint,p2ide,swap}.masm`, `asm/standards/data_structures/array.masm`.

**protocol — miden-protocol:** `asm/protocol/{note,active_note,output_note}.masm`, `src/account/component/mod.rs`, `src/account/component/code.rs`, `src/note/script.rs`, `src/transaction/kernel/mod.rs`, `src/transaction/TransactionKernel`.

**protocol — miden-testing:** `src/lib.rs`, `src/mock_chain/{mod,chain,chain_builder}.rs`, `src/tx_context/{builder,context}.rs`, `src/executor.rs`, `src/asserts.rs`, `tests/scripts/faucet.rs`.

**protocol — miden-tx:** `src/executor/mod.rs`.

**miden-vm:** `crates/assembly/src/{lib.rs,assembler.rs}`, `crates/assembly/README.md`, `crates/lib/core/README.md`, `crates/lib/core/src/lib.rs`, `crates/lib/core/asm/{mod.masm, crypto/hashes/keccak256.masm, crypto/hashes/poseidon2.masm, crypto/dsa/ecdsa_k256_keccak.masm, math/u64.masm, math/u256.masm, mem.masm, sys/mod.masm, word.masm}`, `docs/src/user_docs/assembly/{execution_contexts,code_organization,instruction_reference}.md`, `CHANGELOG.md`.

**miden-tutorials:** `rust-client/src/bin/counter_contract_deploy.rs`.

### Verification summary

**Counts corrected (rev-1, Finding 4).** rev-0 reported `153/152/1`; the authoritative figure is the **actual row count of `MASM-STRUCTURE-RESEARCH-EVIDENCE-LEDGER.md` = 151 claims, 150 CONFIRMED, 1 MISMATCH**, which the per-area table below now matches exactly (the rev-0 per-area numbers were inflated by 2). Verified by the row-count commands in "Commands run" below.

| Area (ledger section) | Claims | CONFIRMED | MISMATCH |
|---|---|---|---|
| A. masm-skills | 32 | 32 | 0 |
| B. account-component-masm | 27 | 27 | 0 |
| C. note-script-masm | 23 | 23 | 0 |
| D. rust-assembly-pipeline | 27 | 27 | 0 |
| E. miden-vm-assembler-stdlib | 20 | 19 | **1 (STD-2)** |
| F. test-harness | 22 | 22 | 0 |
| **Total** | **151** | **150** | **1 (STD-2)** |

The single MISMATCH (STD-2) is a verbatim-quote defect on the core-library README index, NOT a content defect; it remains **quarantined** (not used as a factual citation in the report body — the module names are backed by the `asm/` file tree). Other flagged items are trivial line-offsets plus the file-dependent constants-spacing and composite-name-ordering inconsistencies surfaced in §5.

### Commands run (source acquisition + verification)

The rev-0 research used **pre-existing local clones** under `/Users/philipp/Documents/Work/Miden-Coding/` (no fetch/install/symlink; MASM skills read from the local `agent-tools/skills/` clone). The exact per-command provenance was **not recorded in rev-0**; the rev-1 revision re-ran the checks below (all read-only):

```bash
# Baseline existence + relationships
for C in 0b662adfb 2c423249d; do git -C .../protocol cat-file -t $C; done      # -> commit, commit
git -C .../miden-vm cat-file -t 328071990                                      # -> commit
git -C .../protocol show -s --format='%ci %h %s' 0b662adfb 2c423249d 2ef8056323
git -C .../miden-vm  show -s --format='%ci %h %s' 328071990 f84b0fff83
git -C .../protocol merge-base --is-ancestor 0b662adfb HEAD; echo $?           # -> 1 (not ancestor)

# Pinned-baseline API re-grounding
git -C .../miden-vm  show 328071990:crates/lib/core/README.md          | sed -n '12,40p'   # miden::core::* roots
git -C .../miden-vm  show 328071990:Cargo.toml                         | sed -n '64,72p'   # miden-core-lib 0.24
git -C .../miden-vm  show 328071990:crates/assembly/README.md          | sed -n '78,98p'   # with_package(.., Linkage::Dynamic)
git -C .../miden-vm  show f84b0fff83:crates/assembly/README.md         | sed -n '78,95p'   # with_dynamic_library (inspected)
git -C .../miden-vm  show 328071990:crates/lib/core/src/lib.rs         | sed -n '119,150p' # handlers(): Keccak/ECDSA/...
git -C .../miden-vm  show 328071990:crates/lib/core/asm/crypto/dsa/ecdsa_k256_keccak.masm | sed -n '56,67p'
git -C .../protocol  show 0b662adfb:Cargo.toml                         | rg 'miden-assembly|miden-core-lib'  # 0.23
git -C .../protocol  show 0b662adfb:crates/miden-standards/build.rs    | sed -n '14,57p'   # two-root + namespaces (identical)
git -C .../protocol  show 0b662adfb:crates/miden-standards/src/code_builder/mod.rs | rg 'with_dynamic_library|compile_(component_code|note_script)'
git -C .../protocol  show 0b662adfb:crates/miden-protocol/src/transaction/kernel/mod.rs | rg 'assembler|with_dynamic_library|CoreLibrary|ProtocolLib'
git -C .../protocol  show 0b662adfb:crates/miden-protocol/src/account/component/mod.rs   | sed -n '60,64p'  # AccountComponent::new (identical)
git -C .../protocol  show 0b662adfb:crates/miden-protocol/src/note/script.rs | rg 'from_library(_reference)?'  # identical
git -C .../protocol  show 0b662adfb:crates/miden-standards/asm/account_components/faucets/fungible_faucet.masm | sed -n '1,12p'  # shim = prose header

# Ledger count verification (Finding 4)
rg '^\s*\| `[^`]+` \|' MASM-STRUCTURE-RESEARCH-EVIDENCE-LEDGER.md | wc -l                       # -> 151
rg '^\s*\| `[^`]+` \|' MASM-STRUCTURE-RESEARCH-EVIDENCE-LEDGER.md | rg '\| CONFIRMED \|' | wc -l # -> 150
rg '^\s*\| `[^`]+` \|' MASM-STRUCTURE-RESEARCH-EVIDENCE-LEDGER.md | rg '\| MISMATCH \|'  | wc -l # -> 1

# Scope guard (no frozen-archive edits)
find ai-tasks/circle-integration/06-phase4-component-specs -type f \
  -newer ai-tasks/circle-integration/07-implementation-readiness/TASK-P4-3-MASM-STRUCTURE-RESEARCH.md -print   # -> (no output)
git status --short
```

### Finding-by-finding closure map (audit `REVISE` → rev-1)

| Audit finding | Closure |
|---|---|
| **1 (HIGH) version handling** | Re-grounded to the pinned baselines; added the three-way baseline table + status-label legend + the 0.23-vs-0.24 alignment caveat; corrected the false `std::*`/`StdLibrary` claim; corrected `with_dynamic_library` vs `with_package(.., Linkage::Dynamic)` (§Baselines, §2.3, §3.1, §3.2, §4.8, §5.1). |
| **2 (HIGH) `RESEARCH COMPLETE` overstates readiness** | Status downgraded to `REVISION COMPLETE — READY FOR RE-AUDIT` (§7); builder-facing facts either re-grounded with pinned citations or explicitly kept `UNVERIFIED`/`PENDING MASM STRUCTURE RESEARCH` with owner+trigger (§5). |
| **3 (MEDIUM) convention conflicts** | §2.1 split into skill-default / live-`miden-standards` / project-rule; §2.2 shim-header overclaim corrected (shim = prose header, not namespace line). |
| **4 (MEDIUM) evidence accounting + provenance** | Report counts fixed to ledger truth `151/150/1`; STD-2 quarantine preserved; this "Commands run" section added. |

---

## 7. Final status

**REVISION-2 COMPLETE — READY FOR RE-AUDIT**

rev-2 (post-`AUDIT-MASM-STRUCTURE-RESEARCH-RECHECK.md`) closed the two narrow recheck findings: (1) §3.3–§3.6 raw assembler/package/load/artifact rows are now split into a **safe builder path** (`CodeBuilder`/`TransactionKernel::assembler()`, `PINNED BASELINE` protocol 0.23) and **target-dependent raw APIs** (every row labeled; `.masl`/`Arc<Library>` grounded in the 0.23 stack, with a `HUMAN RETARGET DECISION REQUIRED` **0.24 retarget-reference box** giving the `Box<Package>`/`with_package`/`.masp` shapes from `miden-vm@328071990`); (2) the invalid `core::` example citation was moved off the wrong core-lib-README range (that file ends at L43) to `assembly/README.md:L88-L97` (`use core::math::u64` at L91) in both §2.3 and §5.4. The rev-1 fixes (status downgrade, style adjudication, shim-header correction, ledger count `151/150/1`) are preserved.

Still downgraded from rev-0's `RESEARCH COMPLETE` (original audit Finding 2). The report is repaired against the four audit findings and re-grounded on the Phase 4 pinned baselines, but it is **not** `RESEARCH COMPLETE` because builder-facing decisions remain open and must not be de-PENDING-ed yet:

**No longer blocking under Miden v0.15 (rev-3; was `HUMAN RETARGET DECISION REQUIRED`):**
- ~~The 0.23-vs-0.24 assembler-version target.~~ **Moot under v0.15** — the target is `protocol v0.15.3`, which locks `0.23.3` as its assembler dependency (no fork; §5.1; v0.15.1 historically locked 0.23.1). The remaining human-gated step is only the later raw-`Assembler` / precompile-host *execution* wiring, not a version-target choice. Precompiles confirmed present on both `miden-core-lib` 0.23.1 and 0.23.3 (`V15-DEVNET-BASELINE.md` §3, spike §8).

**Keep `PENDING MASM STRUCTURE RESEARCH` (owner: builder; trigger: when writing the harness):**
- Core-lib `use` root (`miden::core::…` vs bare `core::…`) at the resolved version (§5.4).
- `@note_script` / `@locals(N)` attribute grammar; `word("…")` slot-id hashing and `[0..2]` slice semantics; whether `pub proc`/`pub use` alone exports an account component or another attribute is required (§5.5–§5.7).
- Concrete faucet/nonce/attester storage-slot names; the `StorageSlotName`/`StorageSlot`/`AccountComponentMetadata`/`StorageSchema` (map-slot) API; downstream-harness linking of `miden::protocol::*`/`miden::standards::*`/core procs; `[build-dependencies]` surface for any `build.rs` path; the exact protocol-kernel proc stack contracts the faucet calls (§5.12–§5.16).
- Whether the resolved 0.23 `miden-core-lib` carries the Keccak/ECDSA precompiles (§5.2).

**Resolved at the pinned baseline and safe to carry into the readiness drafts (`PINNED BASELINE`):** the MASM-first premise; the two-root `asm/standards` + `asm/account_components` structure with per-component shim libraries; the `.masm` source conventions (§2, with the §2.1/§2.2 adjudications); the `CodeBuilder`/`TransactionKernel::assembler()` → `AccountComponentCode` → `AccountComponent::new` pipeline; `NoteScript::from_library_reference`; the `miden-testing` MockChain harness path. The human still owns de-PENDING-ing the draft docs and must factor in the open items above.

---

## 8. Post-research spike addendum (2026-06-08 — supersedes the relevant §5 OPEN/UNVERIFIED rows)

The grounding spike (`../08-masm-grounding-spike/`, status `GROUNDED`, Codex audit PASS) resolved several §5 items with running code. The body above is left intact (audited); these rows are now **RESOLVED on the v0.15 stack's assembler dependency (`miden-core-lib` — verified on 0.23.1, what the historical `v0.15.1` locked, AND on the current v0.15.3-locked 0.23.3)**, cited to the spike (the spike pin `0b662adfb` = `git describe` `v0.15.0-21`, on the v0.15 line — facts carry to the v0.15.3-locked 0.23.3 stack; spike Q1–Q4 verified identical on both):
- **§5.1 / §5.2 (the old retarget thread / precompiles UNVERIFIED on 0.23):** the resolved `miden-core-lib` **does** carry the `keccak256` + `ecdsa_k256_keccak::verify` precompiles — confirmed on BOTH 0.23.1 and the current v0.15.3-locked 0.23.3 (present + assembly-time linkable; execution-with-handlers is a later step). **Under v0.15 there is no 0.24 retarget — the 0.23.x dependency (0.23.3 at v0.15.3) is sufficient** (re-confirmed in `V15-DEVNET-BASELINE.md` §3).
- **§5.4 (use-root ambiguity):** the linked `CoreLibrary` exposes `use miden::core::…` (bare `core::…` fails) on the safe `CodeBuilder` path.
- **§5.5–§5.7 (attribute grammar / `word()` / `[0..2]` / export):** `@note_script` + `@locals(N)` lowercase line-above attrs with `loc_*_le` access; `word("ns::label")` + `[0..2]` slot-id; **`pub proc` alone exports** (no attribute).
- Still genuinely PENDING (later units): map/schema storage, precompile **execution** with host handlers, faucet kernel proc stack contracts, local-node. Build hygiene: seed `Cargo.lock` to the v0.15.3-locked 0.23.3 (the spike verified **Q1–Q4 + the precompile gate** identical on 0.23.1 and 0.23.3; Q5/Q6 were verified on the 0.23.1-seeded stack and carry per `V15-DEVNET-BASELINE.md` §4; precompiles on both).