> **MIRROR — READ-ONLY (mirrored 2026-06-11).** Canonical source: `/Users/philipp/Documents/Work/Miden-Coding/agentic-template/ai-tasks/circle-integration/08-masm-grounding-spike/GROUNDING-REPORT.md`. Do NOT edit this copy; if it diverges from the canonical source, the canonical source wins. Re-sync via `tools/sync-mirrors.sh`.

# Phase 4.3 MASM Toolchain Grounding Spike — Report

> **BASELINE SUPERSESSION (rev-2, 2026-06-10 — Miden v0.15 + devnet; read first).** This spike was
> built against a worktree of `protocol@0b662adfb` (recorded below as "v0.16.0"). That pin is on the
> **v0.15 line**: `git describe 0b662adfb` = **`v0.15.0-21-g0b662adfb27d`** (21 commits after
> `v0.15.0`). The implementation/validation target is **Miden v0.15 + devnet** (devnet runs v0.15;
> **testnet is v0.14 and is NOT the validation network**), and the canonical pin is now the released
> tag **`protocol v0.15.3`** (`681fc9058`) — the latest v0.15 patch — which locks
> **`miden-assembly`/`miden-core`/`miden-core-lib`/`miden-processor` = 0.23.3** (published from
> `miden-vm@v0.23.3`) and `miden-crypto`/field = `0.25.1`
> (`../07-implementation-readiness/V15-DEVNET-BASELINE.md` §1, §4). The earlier tag **`v0.15.1`**
> (`625b66dc4`) is **historical**: it locked the `0.23.1` stack — the resolution this spike's
> evidence was originally verified against. **The toolchain evidence in this report carries forward
> to the current v0.15.3/0.23.3 stack**: the spike itself verified Q1–Q4 + the Q2 gate IDENTICAL on
> both `0.23.1` and `0.23.3` (§0, §3), and the **precompile presence was RE-CONFIRMED on BOTH
> `miden-core-lib 0.23.1` AND `0.23.3`** (`V15-DEVNET-BASELINE.md` §3) — so the Q2 gate is RESOLVED
> under v0.15, not re-opened. **Carry-forward obligation:** if this spike is re-run, **re-pin the
> worktree to `protocol v0.15.3`** (or its `next` line), not `0b662adfb`. The `0.23.x`/`0.25.1` crate
> versions are the **v0.15 stack's dependencies**, not stale targets (miden-vm follows its own 0.23.x
> cadence — there is never a "miden-vm v0.15" tag); the "0.24 retarget" thread is moot under v0.15.
> The §0 table and body below are the **completed proof record at the historical pin** and stay as
> written (v0.15.1/0.23.1 mentions there are historical). Local-node validation (a later unit)
> targets the **v0.15 devnet** node.

**Final status: `GROUNDED`** (carried to the Miden v0.15 baseline — see the supersession note above).
The smallest end-to-end hand-written-MASM toolchain on the safe
`CodeBuilder` builder path is green through MockChain, and all six builder-empirical questions are
resolved with running code. **The v0.15 stack's assembler dependency (`miden-core-lib 0.23.1`) carries
the Keccak/ECDSA precompiles, so under v0.15 there is NO 0.24 retarget to force** (the
precompile-absence trigger from report §3.1/§5.1 is false; re-confirmed on the v0.15 core-lib in
`V15-DEVNET-BASELINE.md` §3). No real component logic was written; no raw `Assembler` was hand-built;
no precompile-host wiring, layout/ownership, or version decision was made (all reserved for the human).

---

## 0. Baseline, environment, fidelity

| Item | Value |
|---|---|
| v0.15 builder target (released tag) | **`protocol v0.15.3` (`681fc9058`)** — current canonical pin (rev-2); supersedes the spike build pin `0b662adfb` (= `git describe` `v0.15.0-21`, on the v0.15 line) and the rev-1 `v0.15.1` (`625b66dc4`, historical — locked the `0.23.1` stack the spike verified; `v0.15.3` locks `0.23.3`, precompiles confirmed on both) |
| Spike build pin (historical) | `protocol@0b662adfb27deecb6b6ede88d45ef0d0d4eb9068` (recorded "v0.16.0"; actually `v0.15.0-21`) — the worktree this spike was built against |
| Reference (NOT the v0.15 target) | `miden-vm@328071990a6de3487c3189f08c7d8ad545c9d408` ("0.24") — read-only VM-track reference; not built against; not the v0.15 target (no 0.24 retarget under v0.15) |
| Build source | a git **worktree** of `protocol` at the historical pin: `/Users/philipp/Documents/Work/Miden-Coding/protocol-pin-0b662adfb` (the user's working tree stays at `2ef805632`, untouched). Re-run against `v0.15.3` (the current canonical pin). |
| Resolved Miden stack (pinned) | `miden-protocol`/`miden-standards`/`miden-testing` **0.15.x** (recorded "0.16.0" at the v0.15-line build pin; = **0.15.1** at the historical `v0.15.1` tag — canonical tag now `v0.15.3` → `0.15.3`); `miden-assembly`/`miden-core`/`miden-core-lib` **0.23.1** — the historical v0.15.1-locked deps the spike built on, verified equal to the pin's own `Cargo.lock` (seeded into the scaffold) and to `v0.15.1`'s lockfile (the current `v0.15.3` locks **0.23.3**; precompiles confirmed on both — `V15-DEVNET-BASELINE.md` §1, §3) |
| Resolved Miden stack (fresh, no seeded lock) | same crates at **0.23.3** (a newer 0.23 patch shipped since the pin's lock). **Q1–Q4 + the Q2 gate were verified IDENTICAL on both 0.23.1 and 0.23.3.** |
| Safe path used | `CodeBuilder::new()` → `compile_component_code` / `compile_note_script` / `compile_tx_script` (`code_builder/mod.rs:103-112` pre-links kernel + core + protocol + `StandardsLib`). **No hand-built `Assembler`.** |

**Builder caveat (lock vs fresh resolve).** A downstream harness that does not pin its lockfile
resolves `miden-core-lib` to the latest 0.23 patch (0.23.3 today), not the 0.23.1 the pin's lock
holds. To reproduce the baseline exactly, seed the pin's `Cargo.lock` (this spike does). Either way
the precompiles are present.

---

## 1. Files created (scaffold tree)

Untracked scratch at `ai-tasks/circle-integration/08-masm-grounding-spike/` (the permanent monorepo
home on disk is a deferred **human decision** — this path is deliberately non-committal):

```
08-masm-grounding-spike/
  GROUNDING-REPORT.md                 # this file
  README.md                           # how to recreate the worktree + run
  xusdc-masm/
    Cargo.toml                        # path-deps into the pinned worktree; runtime-compile path (NO build.rs)
    Cargo.lock                        # seeded from the v0.15-line pin -> miden 0.15.x / assembly+core-lib 0.23.1 (v0.15 deps)
    src/
      lib.rs                          # loads the .masm via include_str!, exposes consts
      bin/probe.rs                    # Q1-Q4 + Q2 assembly probes
    tests/
      happy_path.rs                   # MockChain gate: assemble -> bind -> execute -> assert (Q5, Q6)
    asm/
      standards/
        xreserve/counter.masm         # trivial slot read/write component (get_count/set_count)
        encoding/scaffold_encoding.masm# trivial encoding-root placeholder
        notes/xreserve_noop_note.masm # trivial @note_script note
      account_components/
        faucets/xreserve_faucet.masm  # shim SKELETON (pub use) — NOT assembled (self-contained path used)
    target/                           # build artifacts (~5.7 GB) — `cargo clean` to reclaim
```

The two-root layout (`asm/standards/{xreserve,encoding,notes}` + `asm/account_components/faucets`)
mirrors report §1.2. The shim file is a documented skeleton only; the spike proves the
**self-contained** component path (`compile_component_code` on a single `.masm`), since
shim-vs-self-contained is a deferred human decision (report §1.2).

---

## 2. Questions resolved (running-code evidence)

All evidence is from `cargo run --bin probe` and `cargo test --test happy_path` against the pinned
**0.23.1** stack (Q1–Q4 + the Q2 gate re-confirmed on 0.23.3; Q5/Q6 ran on the 0.23.1-seeded stack only). Exact commands/outputs in §3.

### Q1 — CoreLibrary `use` root → **`miden::core::…`** (NOT bare `core::…`)
The `CoreLibrary` linked by `CodeBuilder`/`TransactionKernel::assembler()` exposes its modules under
the `miden::core` root.
- `use miden::core::math::u64` + `procref.u64::wrapping_add` → **assembles** (`[Q1a] OK`).
- `use core::math::u64` (bare) → **`undefined symbol reference … this symbol path could not be
  resolved`** (`[Q1b] ERR`).

Resolves report §5.4. The bare-`core::` example in `miden-vm@328071990:crates/assembly/README.md`
is the *standalone-CoreLibrary* form; when the core lib is linked via the kernel/standards entry
points (the safe path), the root is `miden::core`.

### Q2 — Keccak/ECDSA precompiles on the resolved 0.23.1 core-lib → **PRESENT & LINKABLE** *(the GATE)*
- `use miden::core::crypto::hashes::keccak256` + `procref.keccak256::hash` → **OK**; `…::hash_bytes`
  → **OK**.
- `use miden::core::crypto::dsa::ecdsa_k256_keccak` + `procref.ecdsa_k256_keccak::verify` → **OK**.
- Same probes under bare `core::…` → ERR (consistent with Q1).

**Conclusion:** the `miden-core-lib` that the v0.15 stack resolves (`0.23.1` at `protocol v0.15.1`
and at the v0.15-line build pin `0b662adfb`; `0.23.3` on a fresh resolve) **does** expose the
secp256k1-keccak ECDSA and Keccak256 precompile procedures. The report §3.1/§5.1 retarget trigger —
*"if 0.23 lacks the precompile → forces the 0.24 retarget"* — is therefore **FALSE**, and under the
Miden v0.15 baseline there is no 0.24 retarget at all (`0.23.1` is simply the v0.15 dependency). The
v0.15 stack's `0.23.1` assembler dependency is sufficient for the xUSDC attestation/encoding path at
the assembly/linking level. Re-confirmed on the v0.15 core-lib in `V15-DEVNET-BASELINE.md` §3.

**Honest scope of this evidence.** `procref` proves the precompile procedures **resolve at assembly
time** (the symbol and its MAST root are available through the dynamically-linked core lib). It does
**not** execute them. Executing a precompile additionally requires the executor `Host` to register
the precompile event handlers (`CoreLibrary::handlers()`, report §3.1/§4.8) — wiring that is an
explicit **STOP condition** (it touches the version-sensitive host layer). So the proven claim is
"present and linkable on 0.23," which is exactly what is needed to retire the retarget trigger;
end-to-end precompile *execution* with handlers is a later, human-gated step.

### Q3 — Attribute grammar + export rules → resolved
- **`@note_script`** (lowercase, on the line directly above `pub proc main`): parses, and
  `compile_note_script` finds the single attributed proc (`[Q3 @note_script] OK`).
- **`@locals(N)`** (lowercase, on the line directly above `pub proc`): parses (`[Q3 @locals(4)
  attribute parses] OK`); local access via **`loc_storew_le.<N>` / `loc_loadw_le.<N>`** assembles
  (`[Q3 @locals(4) + loc_storew_le/loc_loadw_le] OK`).
- **Export rule:** a module with one `pub proc` and one plain `proc` yields **exactly 1 export**
  (`[Q3 pub-proc-exports-without-attribute] OK (1 export)`). So **`pub proc` alone exports** an
  account-component procedure; plain `proc` does not; **no export attribute** (no `@auth_script`-style
  marker) is required for a normal component proc.

Resolves report §5.5 and §5.7.

### Q4 — `word("…")` slot-id + `[0..2]` slice → resolved
`pub const COUNTER_SLOT = word("xusdc::scaffold::xreserve::counter_slot")` is a Word-valued const;
`push.COUNTER_SLOT[0..2]` slices its first two felts (the slot id), consumed by
`exec.miden::protocol::active_account::get_item`; `native_account::set_item` writes. The
`counter.masm` component **assembles** (`[Q4] OK (2 exports)`) **and executes** in the happy path
(get returns the initialized word; set writes the sentinel; both `assert_eqw` pass).

The **cross-language linkage** is proven concretely: the MASM `word("xusdc::scaffold::xreserve::
counter_slot")` and the Rust `StorageSlotName::new("xusdc::scaffold::xreserve::counter_slot")` use
the *same namespaced string*; the test initialises the slot in Rust to `[1,2,3,4]` and the MASM
`get_count` reads back exactly that word. Resolves report §5.6.

### Q5 — Minimal component-binding API → resolved
The smallest binding that the executed test uses:
```rust
let code = CodeBuilder::new().compile_component_code(path, masm)?;            // -> AccountComponentCode
let slot = StorageSlot::with_value(StorageSlotName::new(label)?, Word::from([1u32,2,3,4]));
let metadata = AccountComponentMetadata::new("xusdc-scaffold-counter");       // empty StorageSchema by default
let component = AccountComponent::new(code, vec![slot], metadata)?;           // binds; only error = >255 slots
```
- `StorageSlotName::new(impl Into<Arc<str>>) -> Result` ; `StorageSlot::with_value(name, Word)`.
- `AccountComponentMetadata::new(name)` is the minimal metadata (no schema needed for a value slot).
- `AccountComponent::new(code: impl Into<AccountComponentCode>, Vec<StorageSlot>, metadata)`.

Resolves report §5.12–§5.13. **Not exercised (noted):** the schema-driven path
`AccountComponent::from_library(code, metadata, init_storage_data)` + `StorageSchema` and **map
slots** — needed only for non-trivial/typed storage; the faucet build should ground those when it
introduces maps (registries/allowlists).

### Q6 — Harness linking + Cargo surface → resolved
- **Dynamic provision:** `CodeBuilder::new()` already provides `miden::protocol::*`,
  `miden::standards::*`, and `miden::core::*` to the assembler (it links kernel + core + protocol +
  `StandardsLib` internally). A bare `CodeBuilder` assembled the component (`miden::protocol::*`) and
  the core probes (`miden::core::*`) with **no manual `link_static_library`**.
- **Calling a custom component from a script:** the script's own assembler does not know a custom
  (non-standards) component's procs, so link the component library into the script builder:
  `CodeBuilder::new().with_dynamically_linked_library(&account_component_code)?.compile_tx_script(…)`
  (`AccountComponentCode: AsRef<Library>`, so `&code` is accepted directly). The happy-path
  `call.counter::get_count` resolves and executes via this.
- **Cargo surface (the §5.14–§5.15 answer):** **no `[build-dependencies]` are required** for the
  runtime-compile path (there is no `build.rs`; `assemble_library_from_dir`, the `#[cfg(feature =
  "std")]` build-time API of §5.15, is unnecessary when assembling a `.masm` string at runtime). The
  working surface is:
  - `[dependencies]`: `miden-protocol`, `miden-standards` (default features).
  - `[dev-dependencies]` (MockChain): `miden-testing`, `tokio { features=["macros","rt"] }`,
    `anyhow`, and `miden-protocol`/`miden-standards` with `features=["testing"]`.
  - `miden-assembly`/`miden-core-lib` are **build-deps of `miden-standards` itself**, not of the
    harness; the harness reaches `Assembler`/`Library`/`Parse` types via `miden_protocol::assembly::*`
    re-exports.

Resolves report §5.14–§5.15.

---

## 3. Exact commands run + outputs

All `cargo` commands run with the sandbox disabled (cargo must write its package cache under
`~/.cargo`, which the default sandbox blocks — `Operation not permitted`). Source reads were
sandboxed/read-only.

**Pinned worktree (build source):**
```
git -C .../protocol worktree add --detach .../protocol-pin-0b662adfb 0b662adfb27deecb6b6ede88d45ef0d0d4eb9068
git -C .../protocol-pin-0b662adfb rev-parse HEAD   # 0b662adfb27...   (user's tree stays at 2ef805632)
cp .../protocol-pin-0b662adfb/Cargo.lock .../xusdc-masm/Cargo.lock   # seed pin versions (0.23.1)
```

**Probe build + run (light dep set; `miden-testing` is a dev-dep, not compiled here):**
```
$ cargo build --bin probe
    Finished `dev` profile [unoptimized + debuginfo] target(s)        # EXIT=0
$ cargo run --bin probe
================ Q1: core-lib `use` root ================
  [Q1a miden::core::math::u64] OK  (1 export(s))
  [Q1b bare core::math::u64] ERR: ... undefined symbol reference / this symbol path could not be resolved
================ Q2: precompile presence on resolved 0.23.1 (GATE) ================
  [Q2 keccak256 (miden::core)] OK  (1 export(s))
  [Q2 keccak256 hash_bytes (miden::core)] OK  (1 export(s))
  [Q2 ecdsa_k256_keccak::verify (miden::core)] OK  (1 export(s))
  [Q2 keccak256 (bare core)] ERR: ... undefined symbol reference
  [Q2 ecdsa_k256_keccak::verify (bare core)] ERR: ... undefined symbol reference
================ Q3: attribute grammar + export rules ================
  [Q3 @note_script (noop note)] OK
  [Q3 @locals(4) attribute parses] OK  (1 export(s))
  [Q3 @locals(4) + loc_storew_le/loc_loadw_le] OK  (1 export(s))
  [Q3 pub-proc-exports-without-attribute (expect 1 export)] OK  (1 export(s))
================ Q4: word("...") slot-id + [0..2] slice ================
  [Q4 counter.masm (word()+[0..2]+get_item/set_item)] OK  (2 export(s))
  [Q4b encoding placeholder] OK  (1 export(s))
```

**MockChain happy-path gate (G4) — compiles miden-testing/miden-tx/provers/tokio:**
```
$ cargo test --test happy_path -- --nocapture
    Finished `test` profile [unoptimized + debuginfo] target(s) in 42.52s    # EXIT=0
running 1 test
test counter_component_assembles_binds_and_executes ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
```

**Verification gates (task `<verification>`):**
```
find 06-phase4-component-specs -type f -newer TASK-P4-3-MASM-GROUNDING-SPIKE.md   # empty -> PASS (no frozen edits)
git status --porcelain | grep project-template                                   # empty -> PASS
git status --porcelain | grep -v '^??'                                           # empty -> PASS (no tracked file changed)
git -C .../protocol rev-parse --short HEAD                                        # 2ef805632 -> user's tree untouched
```

---

## 4. Gates / OPEN items this spike moved

### `BUILDER-GATES` G-MASM "Still PENDING (owner: builder)" list — RESOLVED:
| PENDING item | Result |
|---|---|
| core-lib `use` root (`miden::core::` vs `core::`) | **`miden::core::`** (Q1) |
| `@note_script` / `@locals(N)` grammar | lowercase attrs; `loc_*_le` access (Q3) |
| `word("…")` slot-id + `[0..2]` slice | Word const sliced to 2-felt slot id (Q4) |
| `pub proc`/`pub use` export vs export-attribute | **`pub proc` alone exports**; no attribute (Q3) |
| concrete slot names + `StorageSlot`/`AccountComponentMetadata`/`StorageSchema` API | value-slot path resolved (Q5); map/schema path noted as not-yet-exercised |
| downstream-harness linking + Cargo/`[build-dependencies]` surface | **no build-deps** (runtime compile); surface in Q6/§1 |
| **whether 0.23 `miden-core-lib` carries the Keccak/ECDSA precompiles** | **YES — present & linkable** (Q2 GATE) |

**Partially resolved — kernel proc stack contracts (report §5.16):** `active_account::get_item` /
`native_account::set_item` are exercised (a value-slot read/write executes). The faucet kernel procs
(`faucet::mint`/`burn`/`create_fungible_asset`, `output_note::*`, `active_note::*`, `asset::*`) are
**not** exercised — they belong to the real faucet build, not this trivial spike.

### Human-owned decisions — status after the spike:
| Item | Status |
|---|---|
| ✅ 0.23-vs-0.24 assembler retarget | **Moot under Miden v0.15.** `0.23.1` is the v0.15 stack's assembler dependency (what `protocol v0.15.1` resolves), not a target fork; the precompile-absence trigger is false (re-confirmed on the v0.15 core-lib, `V15-DEVNET-BASELINE.md` §3). There is no 0.24 retarget to choose for v0.15; the safe-path deferral is validated. |
| 🟡 shim vs self-contained component layout | **OPEN** — spike used self-contained; shim is a skeleton placeholder. |
| ✅ `deposit_intent_parser` / `attestation_verify` home (`encoding/` vs `xreserve/`) | **RESOLVED** (the spike did not adjudicate this) — conformed to the frozen faucet spec: at `asm/standards/xreserve/`, faucet(01)-owned assertion over 04's `encoding/layout.masm` (`01:278`,`:294`). See `07-implementation-readiness/CANONICAL-OWNERSHIP-MAP.md` §Resolved layout (consortium N5 cross-doc reconcile, 2026-06-09). |
| 🟡 permanent monorepo home on disk | **OPEN** — scaffold is scratch at `08-…`. |
| 🟡 product decisions (mint-note modes; balance felt/u32; prebuilt `.masl` vs runtime compile) | **OPEN** — runtime compile demonstrated; prebuilt `.masl` not needed for the spike. |

> **⚠️ This spike is throwaway PROOF code, NOT a style template (consortium N9/N10).** The `.masm` files here (`counter.masm`, `scaffold_encoding.masm`, `xreserve_noop_note.masm`) and their inline `assert.err="..."` strings intentionally skip the §2 / PR #2927 MASM conventions — **no `#!` doc blocks, no named `ERR_*` constants, magic-literal words**. They prove the toolchain works, not the house style. **Real xUSDC MASM units MUST follow `MASM-STRUCTURE-RESEARCH-REPORT.md §2` + `BUILDER-GATES` G-MASM** (doc blocks, named `ERR_*` per `masm-error-constants`, named literals per `masm-named-literals`). Do NOT copy this scaffold's file shape or inline error strings into a real component.

---

## 5. Contradictions found (G5 — code wins over spec)

**None that contradict the frozen archive or the report.** The safe-path predictions in
`MASM-STRUCTURE-RESEARCH-REPORT.md` (§3.1–§3.3, §3.9) all held: `CodeBuilder` is the correct insulated
entry point; `AccountComponent::new` / `StorageSlot` / `AccountComponentMetadata` have the shapes the
report cited; the MockChain path works as in §3.9. Two refinements (not contradictions) for the human
to fold into the drafts when finalizing:
1. **§5.4 ambiguity is now decided:** the linked-CoreLibrary `use` root is **`miden::core`**, not bare
   `core` (the bare form is the standalone-lib README example only).
2. **Lock-vs-fresh-resolve nuance:** the pin's `Cargo.lock` holds `miden-core-lib 0.23.1`, but a fresh
   downstream resolve picks the latest 0.23 patch (0.23.3 today). Builders should seed/pin the lock to
   reproduce the baseline exactly. The precompile finding holds on both.

---

## 6. STOP conditions honored

No real faucet/encoding/component business logic (trivial pipeline-exercising procs only); no
hand-built raw `Assembler` (only `CodeBuilder`); no precompile event-handler / host wiring (only
assembly-time `procref` resolution probed); no shim-vs-self-contained, ownership-home, or permanent-
disk-home decision; no 0.23-vs-0.24 retarget decision (only its precompile trigger evaluated); no
edits to the frozen Phase 4 archive or `project-template/`; no Circle-owned items touched; no
commits, pushes, or publishing.

---

## 7. Final status: `GROUNDED` (carried to Miden v0.15 + devnet)

Pipeline green on the safe path at the v0.15 stack's `0.23.1` assembler dependency; Q1, Q3, Q4, Q5,
Q6 resolved; **Q2 resolved in the affirmative — the precompiles are present on `miden-core-lib 0.23.1`
(the version `protocol v0.15.1` resolves; re-confirmed in `V15-DEVNET-BASELINE.md` §3), so the v0.15
assembler dependency is sufficient and there is no 0.24 retarget under v0.15.** Recommended next steps
(human-gated, per `READINESS-STATUS.md`): **first an independent Codex re-audit of the v0.15/devnet
retarget** (the gate verdicts predate it), then drop `.draft` on the two governing docs (folding in
§5's two refinements + re-pinning the build source to `protocol v0.15.3`), confirm the layout/ownership
OPEN questions, then build the first real component (shared-encoding(04) MASM module) under
`BUILDER-GATES` with shared Rust↔MASM test vectors against the **v0.15 devnet** node.
