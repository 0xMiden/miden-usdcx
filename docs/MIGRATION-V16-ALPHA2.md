# MIGRATION-V16-ALPHA2 — protocol v0.15.3 → crates.io `=0.16.0-alpha.2`

> **[AMENDMENT 2026-07-14 — S21 DISPOSITION FLIP (post-migration, human-ratified).]** This
> historical record repeatedly pins the note-script allowlist at **13 roots** and treats the
> runtime `set_role_admin` note as a kept-with-changed-gate member of the note set. That was true
> at migration close (2026-07-13). It is **SUPERSEDED**: on 2026-07-14 the runtime
> `set_role_admin` note was **REMOVED from the allowlist (13 → 12 roots)** and its note
> script/factory deleted — the same disposition as `renounce_role` and S12 `freeze`/`unfreeze`
> (present-but-unreachable account proc; the role-admin graph is frozen at the build seed;
> rotation is `grant_role`/`revoke_role`, CIR-ADMIN-3). Every "13-root" count and every
> "`set_role_admin` note kept" statement below reads through this amendment. See
> `docs/spec/GLOSSARY.md` IMPL-DEV-24 and `DECISION-SETROLEADMIN-NOTE-REMOVAL.md`
> (implementation-readiness tree); enforcement: `tests/account_callable_surface.rs` +
> `tests/f5_admin_notes.rs`.

**Status: PHASES 0-5 COMPLETE — ALL DECISIONS RATIFIED. The three gate decisions were approved
2026-07-13 (ADJUDICATION block, §10), and the one consequence that surfaced during Phase 3 —
**S21** (upstream #3215 gives the DOM_MANAGER holder `set_role_admin` over DOM_PAUSER and removes
the owner's direct use of it; the owner retains authority via owner→ADMIN→DOM_MANAGER→DOM_PAUSER)
— was HUMAN-RATIFIED 2026-07-13 as CIR-ADMIN-3-conformant. No open decisions remain. The code
phases are implemented, the gates run green (§11), and every hunk traces to a row here.**

**Original Phase-0/1 status: PHASE 0 + PHASE 1 COMPLETE — discovery CLOSED (every inventory row source-verified
against the alpha.2 registry crates; zero unresolved ⏳ items). Revised per the round-2 audit
(S16 decision carries the DC-2/DC-3 governed-contract supersession + the field-complete vector
scope incl. `packed_felts`; S18 pins THE single-install algorithm; S19's proof closes the
filtered-vs-unfiltered enumeration gap) and the round-3 audit (S18 additionally pins the
builder's PUBLIC policy-override API replacement — fields, method signatures, clone/fallible
resolution, unchanged root-first reject semantics, and the exact call-site updates).
Round 4 completed the S18 call-site inventory with the two TEST-ORACLE manager constructions
(`oracle_components`/`oracle_burn_components`) and closed S5's slot-conditionality question
from source. This map sits at its HARD GATE: the audit reviews it BEFORE any code phase
(Phases 2-5) runs, and the map is reconciled against the shipped diff again at the end
(Phase 5). Three decisions are requested at this gate — §10 items 1-3.**

This map is the migration's pin ledger and change contract. For the duration of the migration it
supersedes the `CLAUDE.md`/`AGENTS.md` ground-rule-5 pin (protocol v0.15.3 `681fc9058` →
assembler 0.23.3) and the `docs/governing/V15-DEVNET-BASELINE.md` framing (human decision,
2026-07-13); those files themselves stay UNEDITED. Every hunk of the migration diff must trace to
a row here (mechanical, semantic, re-pin, restructure, or comment-fix). An unmapped hunk is a
defect — regardless of test results.

Authority for "what changed upstream": the published crates at `=0.16.0-alpha.2` (present in the
local pinned cargo cache under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`) and the
protocol CHANGELOG at the `v0.16.0-alpha.2` tag (fetched 2026-07-13 from
`https://raw.githubusercontent.com/0xMiden/protocol/v0.16.0-alpha.2/CHANGELOG.md`). The in-repo
test suite is the behavioral oracle. PR numbers below cite `0xMiden/protocol` pull requests.

---

## 1. Pin ledger (old → new)

### 1.1 Direct dependency pins

| Manifest site | v15 (current) | v16 (target) |
|---|---|---|
| `crates/xusdc-encoding/Cargo.toml` deps: `miden-protocol` (features `testing`), `miden-standards` | git `0xMiden/protocol` rev `681fc90584131560b87db8f7487685f4fa8420a8` (= v0.15.3 tag) | crates.io `=0.16.0-alpha.2` |
| `crates/xusdc-encoding/Cargo.toml` dev-deps: `miden-standards` (features `testing`), `miden-testing`, `miden-tx` | git rev `681fc905…` | crates.io `=0.16.0-alpha.2` |
| `crates/xusdc-encoding/Cargo.toml` dev-dep `miden-processor` | `=0.23.3` (crates.io) | `=0.25.3` (the version alpha.2 resolves; required for exact-error downcasts to unify) |
| `crates/xusdc-encoding/Cargo.toml` optional dep `miden-crypto` (vectors feature) | `0.25` | `0.28` (alpha.2 family requires ^0.28) |
| `crates/xusdc-encoding/Cargo.toml` dev-dep `miden-crypto` | `0.25` | `0.28` |
| `crates/xreserve-deposit-relayer/Cargo.toml` dev-dep `miden-protocol` | git rev `681fc905…` | crates.io `=0.16.0-alpha.2` |
| root `Cargo.toml` `[patch.crates-io]` block (5 entries, all rev `681fc905…`) | present | **REMOVED** (see restructure row R2) |
| `crates/xusdc-validation/Cargo.toml` (all pins) | git rev `681fc905…` + `miden-client =0.15.3` | **UNCHANGED — crate PARKED** (row R1); manifest left byte-intact |

### 1.2 Resolved-family record (the `cargo tree` evidence)

v15 workspace (`cargo tree --locked`, captured 2026-07-13, pre-migration):

| family | v15 resolved | alpha.2 resolves (verified via offline throwaway-crate lock of the five `=0.16.0-alpha.2` crates) |
|---|---|---|
| protocol family (`miden-protocol`, `miden-standards`, `miden-tx`, `miden-testing`, `miden-agglayer`) | 0.15.3 (git) | 0.16.0-alpha.2 (crates.io) |
| batch/block provers | `miden-tx-batch-prover` 0.15.3 (git), `miden-block-prover` 0.15.3 (git) | **renamed** `miden-tx-batch` 0.16.0-alpha.2 (#3035) + `miden-block-prover` 0.16.0-alpha.2 |
| assembler/VM (`miden-assembly`, `miden-processor`, `miden-core`, `miden-air`, `miden-prover`, `miden-verifier`, `miden-core-lib`, `miden-mast-package`, `miden-debug-types`) | 0.23.3 | **0.25.3** (#3278: "Updated miden-vm dependencies to v0.25") |
| crypto (`miden-crypto`, `miden-field`, lifted-air/stark, stark-transcript, stateful-hasher, serde-utils) | miden-crypto 0.25.1, miden-field 0.25.1 | miden-crypto **0.28.0**, miden-field 0.28.0 (#3278) |
| assembler syntax split | `miden-assembly-syntax` 0.23.3 | `miden-assembly-syntax` 0.25.3 + NEW `miden-assembly-syntax-cst` 0.25.3, `miden-rowan` 0.16.4 |
| client | `miden-client`/`miden-client-sqlite-store` 0.15.3, `miden-remote-prover-client` 0.15.1 | **NO v16 release exists** (newest 0.15.3) — the client consumer (`xusdc-validation`) parks (R1) |
| MSRV | 1.87-ish (v15) | **1.96.1** (#3278); box toolchain is 1.97.0 ✓ |

NOT published at alpha.2 (verified against the local registry index while resolving the throwaway
crate): `miden-tx-batch-prover` (superseded by the rename), `miden-client`,
`miden-client-sqlite-store`. Nothing in the post-migration graph requires them (evidence in R2).

---

## 2. Phase 0 record — environment pre-flight + v15 baseline (the count-parity anchor)

### 2.1 Cache check (Phase 0a) — PASS

Throwaway crate outside the repo depending on the five `=0.16.0-alpha.2` crates
(`miden-protocol`, `miden-standards`, `miden-tx`, `miden-testing`, `miden-agglayer`):
`cargo generate-lockfile --offline` → "Locking 318 packages", exit 0; `cargo fetch --offline` →
exit 0. The full alpha.2 closure (including assembly/processor 0.25.3, miden-crypto 0.28.0,
miden-tx-batch + miden-block-prover 0.16.0-alpha.2) resolves and fetches from the pinned local
cache with no network. The offline gate stands.

### 2.2 v15 baseline (Phase 0b) — all suites green on the unmodified base

| gate | result |
|---|---|
| `cargo test --locked -p xusdc-encoding --release` | **416 passed / 0 failed / 0 ignored** (16 test binaries + unit tests) |
| `cargo test --locked -p xreserve-deposit-relayer` | **197 passed / 0 failed / 0 ignored** |
| `cargo test --locked -p xusdc-validation` (non-ignored portion; parks in Phase 2) | **159 passed / 0 failed / 5 ignored** (the 5 ignored are the per-file real-node rows) |
| `cargo fmt --all -- --check` | clean (exit 0) |
| `cargo clippy --workspace --locked -- -D warnings` | clean (exit 0) |

No-weakening sweep baselines (v15): `#[ignore` attribute lines = **10**, all in
`crates/xusdc-validation/tests/rows_*.rs` (2 per file × 5 files); `todo!|unimplemented!` = **0**.

### 2.3 Environment notes (documented so the auditor can reproduce)

- The shared `target/` at the repo root is owned by the auditor user with group read-only ACLs;
  this session builds with `CARGO_TARGET_DIR=$HOME/.cache/usdcx-target` and `CARGO_INCREMENTAL=0`.
  Neither changes build semantics (same `--locked` lock, same profiles).
- Disk ceiling ~13 GB free: suites are built/run sequentially with target wipes in between where
  needed. The `xusdc-validation` BASELINE run (only) used `CARGO_PROFILE_DEV_DEBUG=0
  CARGO_PROFILE_TEST_DEBUG=0` to fit on disk — debuginfo volume only; pass/fail/ignored counts
  are unaffected. The v16 verification gates (encoding release, relayer debug, clippy) run with
  stock profiles.

---

## 3. Workspace restructure plan (Phase 2 rows)

| row | action | justification |
|---|---|---|
| **R1** | Park `xusdc-validation`: remove `"crates/xusdc-validation"` from `workspace.members`, add it to `workspace.exclude`, add `crates/xusdc-validation/PARKED-V15.md`. Crate directory otherwise byte-intact. | `miden-client` has no v16 release (protocol team, 2026-07-13: node+client alpha releases pending). Without the `exclude`, any cargo invocation inside the parked dir errors ("believes it's in a workspace"). The parked crate is INTENTIONALLY NON-BUILDING standalone (manifest keeps `workspace = true` deps). |
| **R2** | Delete the root `[patch.crates-io]` block (5 git entries). | Its documented purpose (root `Cargo.toml:52-61`) is to unify `miden-client 0.15.3`'s crates.io `^0.15.3` family requirements onto the one git-pinned protocol copy. Reverse-dep evidence (v15 `cargo tree -i`): `miden-client` is consumed ONLY by `xusdc-validation` (parked, R1); `miden-tx-batch-prover` is consumed only by `miden-client` (parks) and `miden-testing` 0.15.3 (which at alpha.2 depends on the RENAMED, published `miden-tx-batch` — in the verified offline closure). Post-park, every miden dep comes uniformly from crates.io at `=0.16.0-alpha.2`; nothing needs patching and nothing needs `miden-tx-batch-prover`. |
| **R3** | Re-pin `xusdc-encoding` per pin-ledger §1.1 (deps + dev-deps + `miden-processor =0.25.3` + `miden-crypto 0.28` at both sites). | §1.1 / §1.2. The processor pin must move in lockstep or the `OperationError`/`U32AssertionFailed` exact-error downcasts in ≥5 test files silently mismatch (two processor copies in the graph). |
| **R4** | Re-pin the relayer dev-dep `miden-protocol` to `=0.16.0-alpha.2`. | §1.1 (the `681fc905` grep-proof covers it). |
| **R5** | Regenerate `Cargo.lock` ONCE (`cargo update`/`generate-lockfile`) after the manifest edits. | The authorized, mapped lockfile row per the task. Every verification gate thereafter runs `--locked` against the regenerated lock. No hand-edits. |
| **R6** | Factual comment updates in the two migrated crates' manifests + root manifest (e.g. the encoding crate's "v0.15.3-locked 0.23.3 assembler family" header; the root's patch-block comment removal travels with R2). | Comments must not lie post-bump. Mechanical comment-fix rows; zero code meaning. |

Grep-proofs at the end of Phase 2: no `681fc905` remains in any WORKSPACE MEMBER manifest
(the parked `xusdc-validation` and the out-of-scope `canary/` crates keep theirs by design); no
workspace member references `miden-client`.

Out of scope, untouched: `canary/` (five standalone non-member grounding crates with `path` deps
onto a `../../../protocol-pin-v0.15.3/` sibling checkout; no gate builds them; they cannot
migrate without a v16 sibling checkout), the v15 LNV records/evidence, `main`,
`.claude/skills/`, `docs/governing/` (including `V15-DEVNET-BASELINE.md` and
`CANONICAL-OWNERSHIP-MAP.md` — the S16 DC-2/DC-3 supersession is recorded in THIS map, never as
a governing-doc edit), and the golden vectors (`crates/xusdc-encoding/tests/vectors/*.json` —
Circle-frozen wire formats, byte-identical across the migration) with EXACTLY ONE carve-out:
the `att`-family fields named in §10 decision item 1(b), which change ONLY under that approved
decision. The end-state vector check becomes: `git diff implementation --
'**/vectors/*.json'` shows NO change outside the decision-1(b) fields (and is entirely EMPTY
for `circle-depositintent-groundtruth.json`).

---

## 4a. Stock-surface discipline (process fix — the third time a "mechanical" bucket nearly carried a capability change: S16-routing, S12-freeze)

**Rule:** a change to any STOCK component's CALLABLE surface — a procedure that a v0.16
dependency newly exports (or stops exporting) and that lands on the composed account's callable
interface — is NEVER "mechanical conformance". It is a capability delta (a new root a transaction
could `call`, or a lost one the faucet relied on) and it MUST be:
1. DETECTED, not assumed. `tests/account_callable_surface.rs` freezes the entire composed-account
   callable set (xreserve 17 + the stock 45) as a literal list, at both the source and on-chain
   layers, so any stock bump that adds/removes a callable proc fails LOUDLY rather than being
   silently inherited.
2. SURFACED for ratification in ITS OWN map row (never folded into another root's ratification)
   and, for shipped deviations, the GLOSSARY IMPL-DEV register. Each v16 surface addition took
   this path under a SEPARATE row: `freeze`/`unfreeze` → **S12** (GLOSSARY IMPL-DEV-21);
   `has_procedure` → **S13**; `get_authority` + `invoke_send_policy` + `invoke_receive_policy` →
   **S24** (GLOSSARY IMPL-DEV-22). The three S24 roots were NOT ratified under S12 — attributing
   them to S12 would be the exact self-sanctioning this discipline forbids.
3. NEVER waved through under STOP-condition-5's "mechanical" reading. STOP-condition 5 is tightened
   accordingly (§10): a stock callable-surface change is itself a STOP-and-surface trigger.

This closes the pattern where a capability arrives inside a bucket labelled mechanical — it bit at
S16 (the note-creation routing move, #3204), again at S12 (the freeze/unfreeze bundle), and again
at S24 (the three roots the full-account pin exposed, initially mislabelled "already ratified under
S12" until the audit caught it). The frozen full-account surface test is the mechanical backstop
that makes "we didn't notice" no longer possible.

## 4. Mechanical inventory (Rust API renames/moves the compiler forces)

> Every row below is source-verified against the alpha.2 registry crates (✅); cites are to
> files inside `~/.cargo/registry/src/index.crates.io-…/<crate>-0.16.0-alpha.2/` and the v15 git
> checkout. Rows M10/S18 and the S2/S16 decisions carry their design questions to the gate.

| id | v15 usage (repo sites) | upstream change | repo-side action |
|---|---|---|---|
| M1 ✅ | `ExecutedTransaction::account_delta()` — **~111 call sites**; `Account::apply_delta` — ~90 evolve-pattern sites | #3109/#3089: renamed `account_patch() -> &AccountPatch` (alpha.2 `miden-protocol src/transaction/executed_tx.rs:133`); #3110: `Account::apply_delta` → **`Account::apply_patch(&AccountPatch) -> Result<(), AccountError>`** (`account/mod.rs:315`) — signature-shape-identical drop-in (repo evolves only pre-existing accounts, so the full-state-patch reject path is not hit) | `evolved.apply_patch(x.account_patch())?` — mechanical double rename |
| M2 ✅ | `StorageSlotDelta::{Value,Map}` matches — 30+ sites across ~10 files; `nonce_delta()` — ~7 sites | `StorageSlotPatch` (`patch/storage/slot_patch.rs:27`): same variant NAMES, payloads changed — `Value(StorageValuePatch)` → read via `.value() -> Option<Word>` (`value_patch.rs:42`); `Map(StorageMapPatch)` → `.entries() -> Option<&StorageMapPatchEntries>` + `.as_map() -> &BTreeMap<StorageMapKey, Word>` (`map_patch.rs:48,205`). **`nonce_delta()` has NO patch equivalent — `AccountPatch::final_nonce()` is ABSOLUTE** (`patch/mod.rs:274`) | migrate match arms per the recipes; nonce assertions become `final_account().nonce() - initial_account().nonce() == ONE` (`executed_tx.rs:97,102`) or the absolute `final_nonce()` — same strictness (S8) |
| M3 ✅ | Stock-note factories: **`BurnNote::create` — exactly ONE site** (tests/support/mod.rs:2802); `P2idNote` is consumed ONLY via `script_root()`/`script()` (7 files); `MintNote` unused (all `*MintNote` hits are the repo's own `XReserveMintNote`) | #2283: `::create` → bon `::builder()`; `script()`/`script_root()` statics UNCHANGED (`standards note/burn.rs:100,105`, `p2id.rs:108,113`) | one rewrite: `BurnNote::builder().sender(user).asset(asset).generate_serial_number(rng).build()?.into()` (no `faucet_id` param — derived from the asset; explicit `.into()` to `Note`) |
| M4 ✅ | `Asset::vault_key()` → `get_balance` (xreserve_burn.rs:343) | #3186: `Asset::id() -> AssetId` (`asset/mod.rs:160`); `AssetVault::get_balance(AssetId)` (`asset/vault/mod.rs:124`); `AssetVaultKey` gone | `get_balance(h.asset.id())?` |
| M5 ✅ | `AuthScheme::Falcon512Poseidon2` inside `Auth::BasicAuth { auth_scheme }` (xreserve_burn.rs:66-68) | **NO CHANGE** — miden-testing's `Auth::BasicAuth`/`Auth::IncrNonce`/`Auth::NetworkAccount` variants are structurally identical at alpha.2 (`mock_chain/auth.rs:41,71,86`); #3098's `Approver` reshaping is internal to `build_component()` | none |
| M6 ✅ | `miden_processor::{ExecutionError, operation::OperationError, advice::AdviceInputs, crypto::random::RandomCoin}` (10+ RandomCoin sites; exact-error matches in masm_dual.rs:223, masm_mint_shell.rs:309, mint_recipient_account_id.rs:226 etc.) | processor 0.23.3 → 0.25.3: **all re-export paths identical**; `OperationError::U32AssertionFailed { err_code, err_msg, invalid_values }` and `::FailedAssertion`, `ExecutionError::OperationError{err,..}`/`::AdviceError{err,..}` **byte-identical shapes** (0.25.3 errors.rs:311,300,92,38); `RandomCoin` still a concrete struct with `new(Word)` + `FeltRng` impl (crypto-0.28 rand/coin.rs:35,42,134) | none beyond the R3 pin bump (`=0.23.3` → `=0.25.3`, required for downcast type-unification) |
| M7 ✅ | `LocalTransactionProver::default().prove_dummy(tx)` (xreserve_burn.rs:403,412) | `prove_dummy` was ALREADY sync at v15 and stays sync (`miden-tx prover/mod.rs:175`); #3281 changed only `prove` (unused by repo). `TransactionContext::execute` STAYS async (`tx_context/context.rs:165`) — tokio stays | none |
| M8 ✅ | `AccountBuilderSchemaCommitmentExt` | used ONLY by the parked `xusdc-validation` (deploy.rs, actors.rs) | none in this migration (recorded in the parked ledger; #3222 moved it to `account::inspection` for the future re-enable) |
| M9 ✅ | wholesale-verified stable surface: `bytes_to_packed_u32_elements` + `packed_u32_elements_to_bytes` (`miden-core utils/mod.rs:136,167` via unchanged glob re-export), `MasmError::from_static_str` (`errors/masm_error.rs:15`), `NoteScriptRoot::from_raw`, `Note*` family exports, `TransactionKernel::assembler()` (`transaction/kernel/mod.rs:202`), `StorageMapKey`/`StorageSlotName`/`RoleSymbol`, `AccountIdBuilder` (testing feature, `testing/account_id.rs:141`), `RawOutputNote::Full`, `Word`/`Felt`/`Hasher`/`ONE`/`ZERO`/`word!` re-exports (`lib.rs:31-35`), `errors::standards::{ERR_NOTE_SCRIPT_ALLOWLIST_NOTE_NOT_ALLOWED, ERR_TX_SCRIPT_ALLOWLIST_TX_SCRIPT_NOT_ALLOWED}` (behind the already-enabled `testing` feature), `NoteBuilder` (testing), `assert_transaction_executor_error!` (byte-identical macro, 126 invocations all in MasmError form) | — | none |
| M10 ✅→S18 | `TokenPolicyManager::new().with_mint_policy(_, PolicyRegistration::Active)?…` + `MintPolicyConfig`/`BurnPolicyConfig`/`TokenPolicyManagerError` (builder.rs:42-44,451,498,505-507; builder_api.rs:203,228) | #2974/#3047: **manager API fully rewritten** — bon `TokenPolicyManager::builder().active_mint_policy(MintPolicy).active_burn_policy(BurnPolicy).build()` (returns `Self`, no Result); `MintPolicy::custom(root, components)` / `BurnPolicy::custom(root, components)` (`policies/mint/mod.rs:69`, `burn/mod.rs:84`); `PolicyRegistration` + `TokenPolicyManagerError` DELETED | the rewrite is semantic-adjacent (component-install mechanics changed) — full design in **S18** |
| M11 ✅ | `AssetCallbacks::on_before_asset_added_to_{note,account}_slot()` (basic_asset_tripwire.rs:90,97) | accessors SURVIVE unchanged (`asset/asset_callbacks.rs:66,72`); #3167 additionally introduces `AssetCallbackFlag` on the AccountId | tripwire's component-level absence-proof still compiles; S6 covers the new ID-flag dimension |
| M13 ✅ | **Post-migration comment truth-up** (operator-approved in the round-7 resume note; map-consistent cleanup, not scope expansion). TWO clusters of comments that became FALSE the moment this patch landed: (a) the v15 "owner-only `set_role_admin`" authority labels — `src/note/xreserve_admin.rs` (the `XReserveSetRoleAdminNote` module + `create` docs), `tests/support/mod.rs` (`set_role_admin_note` / `grant_role_note` / `revoke_role_note` gate labels), `tests/role_admin.rs` + `tests/f5_admin_notes.rs` headers, `tests/pause_admin.rs`'s owner-rotation aside, and the three admin-note `.masm` headers (grant / revoke / set_role_admin) — all now state the v16 effective-admin gate (S2/S21); (b) the pause-slot provenance claiming `is_paused` is `FungibleFaucet`-installed "at the pinned v0.15.3" and framing the #2944 move as FUTURE work — `tests/builder_api.rs` (the `production_components_carry_is_paused_slot` tripwire doc + its assertion text), `tests/pause_admin.rs`, `tests/burn_policy.rs`, `tests/f5_admin_notes.rs`, `tests/support/mod.rs` — all now name the base `Pausable` component this patch installs (S1), and the `is_paused` tripwire doc additionally records WHY it is now load-bearing: #3047 made `assert_not_paused` a silent NO-OP on a missing slot instead of a trap, so a dropped `Pausable` would disable the pause halt-gates QUIETLY. (c) comments still naming the SUPERSEDED PIN as current — every remaining "pinned v0.15.3" cite in migrated code (`builder.rs`'s two `token_metadata.rs` references, `role_admin.rs`'s two stock-`rbac.masm` cites, `set_min_burn.rs`'s seed-model comment, and the transport shim's canary-provenance header) now names `=0.16.0-alpha.2`, or (for the canary, a v15 artifact that is deliberately NOT re-run — `canary/` is out of scope) says so explicitly. Verified by grep: ZERO `pinned v0.15` claims remain in `asm/`, `crates/xusdc-encoding/src`, or `crates/xusdc-encoding/tests`. The still-accurate `mutability_config` provenance (that slot did NOT move out of `FungibleFaucet`) is deliberately left as-is, and now says so. Comments only — zero behavior change. |
| M12 ✅ | `account.storage().get_map_item(&slot, word)` — ~8 sites (set_attester.rs:62, set_min_burn.rs:234-295, support/mod.rs:3575,3594) | #3080: `get_map_item(&StorageSlotName, StorageMapKey)` (`account/storage/mod.rs:192`) — no implicit Word coercion | wrap each key: `get_map_item(&slot, StorageMapKey::new(word))` |

MASM mechanical/semantic edits are inventoried in §7 (every `.masm` edit is a semantic-class row
per the task rules).

---

## 5. Semantic inventory (each lands as its own commit-equivalent map row in Phase 3)

> Every row: upstream cite → repo-side action → proof obligation. All rows source-verified;
> S2/S16/S18 additionally carry a DECISION to this map's gate (§10 items 1-3). Row IDs are
> stable labels (S14-S15 sit after S16-S17 in file order; numbering is not positional).

### S1 — #2944: `is_paused` moves out of `FungibleFaucet`; composition adds base `Pausable`

- Upstream: "`FungibleFaucet` no longer installs the `is_paused` storage slot itself. Faucet
  factories now bundle the `Pausable` component (slot + `is_paused()` view procedure) alongside
  `PausableManager`. Callers using `AccountBuilder` directly must also install `Pausable` or the
  faucet's mint/burn/transfer/metadata-setter procedures will panic at runtime" (CHANGELOG,
  #2944).
- Repo-side: `XReserveStablecoinBuilder::assemble_components`
  (`crates/xusdc-encoding/src/account/xreserve/builder.rs`) adds `Pausable::unpaused()`
  (NOT `PausableManager` — the Domain-Pauser-only model, IMPL-DEV-1, keeps the stock owner-gated
  pause surface OFF this faucet). This is exactly the action the in-code PIN-BUMP HAZARD block
  (builder.rs ~L586-590) prescribes. Position in the component list: immediately after the
  faucet component (the slot lived inside the faucet's slot block at v15; slots are
  name-addressed so position is non-semantic — pinned in S18 step 5 for auditability).
- Slot identity proof (source-verified): the new base component is `Pausable` —
  `Pausable::unpaused()` installs the slot (standards `account/access/pausable/mod.rs:105-107,
  :175`); the slot NAME is byte-identical across versions
  (`"miden::standards::access::pausable::is_paused"`, alpha.2 pausable/mod.rs:28 + MASM
  pausable/mod.masm:22 = v15 :20); the Rust accessor is `PausableStorage::is_paused_slot()`
  (pausable/mod.rs:79). `PausableManager` still installs ZERO storage (manager.rs:76) and stays
  OUT of the composition (Domain-Pauser-only model preserved; builder_api's
  pause-root-absence assertions remain valid). Every reader — `xreserve_mint.masm`'s halt-gate,
  the stock `execute_mint_policy`/`execute_burn_policy` pause reads, `pause_admin.masm`'s
  `pausable::pause/unpause` — resolves the SAME unchanged slot name.
- Proof: `production_components_carry_is_paused_slot` (expected RED at the bump, GREEN after);
  `dom_pauser_pause_halts_mint`; the burn-paused reject; owner setters commit while paused (F6).
- ⚠ Related failure-mode change (#3047): `pausable::assert_not_paused` now NO-OPS (instead of
  panicking) when the slot is absent — i.e. if the composition FORGOT `Pausable` at v16, pause
  enforcement would silently disappear rather than trap. The tripwire test is therefore
  load-bearing in a way it was not at v15; it must stay set-equality-strict.

### S2 — #3215: RBAC role administration is fully role-based (owner super-admin REMOVED) — **DESIGN DECISION REQUIRED AT THIS MAP'S GATE** (source-verified)

- Upstream, source-verified in alpha.2 `asm/standards/access/rbac.masm`: `grant_role` (:232),
  `revoke_role` (:271) and `set_role_admin` (:196) all gate on `assert_sender_is_role_admin`
  (:453), whose effective admin = the role's configured `admin_role_symbol`, else the built-in
  `ADMIN` role (`get_effective_role_admin`, :427-438; `ADMIN` = `"ADMIN"`, element 1836707,
  rbac.rs:139/:308). **There is NO owner path** (no ownable2step import at all). v15 by contrast:
  `set_role_admin` = owner-only (`assert_sender_is_owner_internal`, v15 rbac.masm:164);
  `grant/revoke` = owner OR role-admin (:201/:232). Error renamed
  `ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN` → `ERR_SENDER_NOT_ROLE_ADMIN` ("note sender does not hold
  the role's admin role", alpha.2 rbac.masm:66). Stack ABIs of all three procs UNCHANGED, and
  `assert_sender_has_role` (#3116, now exec `[role_symbol]→[]`) matches the repo's existing
  `exec.` call sites — pause gating is unaffected.
- Rust side: `RoleBasedAccessControl::{code, role_config_slot, role_membership_slot,
  component_metadata}` all survive unchanged (rbac.rs:152,178,183,212), and the seed
  key/value encodings the repo hand-builds still match the stock readers — so
  `seeded_dom_roles_rbac` still COMPILES; what changed is WHO the seeded words authorize.
- Repo impact on the ratified Circle model (owner → DOM_MANAGER → DOM_PAUSER chain):
  - `DOM_PAUSER` (admin_role = DOM_MANAGER): **survives unchanged** — a DOM_MANAGER holder still
    grants/revokes the pauser.
  - `DOM_MANAGER` (admin_role = 0 → resolves to `ADMIN`) and every `set_role_admin` call: at
    alpha.2 these need an `ADMIN`-role member. The repo seeds NO `ADMIN` member, and the OWNER
    qua owner has no standing → owner-driven manager rotation and admin re-pointing (the
    "owner-only" F5 flows) are DEAD without a seed change.
- **PROPOSED resolution (decision at gate):** extend `seeded_dom_roles_rbac` (builder.rs:620)
  AND its harness twin `seeded_dom_roles_rbac_component` (tests/support/mod.rs:2562 — the copy
  the oracle/burn harness accounts install; it gains an `owner: AccountId` parameter, which its
  caller `oracle_burn_components` already holds; both seeds move in lockstep, and the existing
  replica-fidelity pair `support_replica_carries_delegation_seed` ↔
  `shipped_delegation_reads_back` extends to the new ADMIN entries) to seed the `ADMIN`
  role with the OWNER's account as its single member (`role_config[{0,0,0,ADMIN}] = [1,0,0,0]`
  self/default-administered; `role_membership[{0,ADMIN,owner.suffix,owner.prefix}] = [1,0,0,0]`),
  preserving the operational chain: the owner-held account still administers `DOM_MANAGER` and
  still re-points role admins — now via its `ADMIN` membership rather than owner status. KNOWN
  DIVERGENCE to document and test: after `transfer_ownership`/`accept_ownership`, `ADMIN`
  membership does NOT auto-follow the new owner (role membership is account-bound); the rotation
  runbook gains an explicit `grant_role(ADMIN, new_owner)` + `revoke_role(ADMIN, old_owner)` leg
  (executable via the existing grant/revoke admin notes, sender = an ADMIN member). The F5
  owner-only tests are updated to ADMIN-member-only per this row (upstream cite #3215) — same
  strictness, new authority anchor. ALTERNATIVE if this divergence is unacceptable to the Circle
  model: STOP and escalate (§10 item 7).
- Proof: the F5 admin-note suite (grant/revoke/set_role_admin flows, rotation-seam tests,
  `shipped_delegation_reads_back`), updated ONLY as this row documents; negative proof that a
  non-ADMIN owner-lookalike cannot administer (the new error constant asserted exactly).

### S21 — #3215 CONSEQUENCE FOUND DURING PHASE 3: `set_role_admin` is gated on the ROLE's effective admin — **HUMAN-RATIFIED 2026-07-13** (operator, via the approval bridge)

- Source-verified (alpha.2 `standards/access/rbac.masm:196-210` + `assert_sender_is_role_admin`
  :453 + `get_effective_role_admin` :427-438): `set_role_admin(role, new_admin)` gates on the
  **role's own effective admin** — the role's configured delegated admin, else the built-in
  `ADMIN`. At v15 `set_role_admin` was **owner-only** (`assert_sender_is_owner_internal`,
  v15 rbac.masm:164).
- Consequence for the ratified Circle model, GIVEN the CMP-F5 delegation
  (`DOM_PAUSER.admin_role = DOM_MANAGER`) that the faucet seeds:
  1. **A DOM_MANAGER holder GAINS `set_role_admin(DOM_PAUSER, …)`** — it can re-point (or clear)
     the Pauser's administration. At v15 only the owner could. NEW capability for the manager.
  2. **The OWNER LOSES direct `set_role_admin(DOM_PAUSER, …)`** — as an `ADMIN` member it is not
     a DOM_MANAGER holder. It retains the authority only by first granting itself DOM_MANAGER
     (which it may do as the `ADMIN` member, DOM_MANAGER's effective admin) — a two-hop path.
  This is UPSTREAM-FORCED: it follows from #3215 plus the CMP-F5 delegation itself. The only way
  to eliminate it is to DROP the CMP-F5 delegation (seed `DOM_PAUSER.admin_role = ADMIN`), which
  would break the ratified Circle requirement that the Domain Manager rotates the Pauser — NOT a
  change this migration may make unilaterally.
- The operator's S2 condition ("ADMIN resolves to the owner (NO new capability)") holds for the
  ADMIN SEED itself: the seed grants the owner nothing it did not have. The new capability above
  belongs to DOM_MANAGER and arises from upstream's role-admin model, not from the seed. Because
  it was NOT enumerated at the gate, it is surfaced here for explicit ratification.
- Implemented + pinned (no silent drift): `role_admin.rs` asserts the v16 reality EXACTLY —
  `set_role_admin_dom_manager_can_redelegate_pauser` (POSITIVE: the manager may re-delegate),
  `set_role_admin_owner_direct_rejects` (the owner's direct attempt traps
  `ERR_SENDER_NOT_ROLE_ADMIN`), `owner_reaches_set_role_admin_through_dom_manager` (the surviving
  two-hop owner authority), plus the unchanged stranger/pauser rejects. The owner-backstop
  capability proofs are re-expressed through the v16 chain (owner→ADMIN→DOM_MANAGER→DOM_PAUSER)
  and still traverse it END TO END: `owner_can_still_grant_pauser` (owner grants DOM_MANAGER → the
  new manager grants DOM_PAUSER → that member's pause REALLY halts the faucet) and
  `owner_can_still_revoke_pauser` (owner takes DOM_MANAGER → REVOKES the seeded pauser's
  DOM_PAUSER → that pauser's pause is REJECTED with the exact `ERR_SENDER_LACKS_ROLE` and
  `is_paused` never flips). A round-6 audit fix restored the second one, which had degenerated
  into "revoke the manager, then deny a future grant" without ever stripping a live pauser; the
  chain-cut variant it had become is KEPT as the additive
  `owner_can_revoke_dom_manager_cutting_the_delegation_chain`. Same strictness as v15, new
  authority anchor.
- **RATIFICATION (operator, 2026-07-13):** APPROVED as pinned. Grounded on CIR-ADMIN-3 ("Domain
  Manager rotates the Pauser + owner backstop"), which this model PRESERVES: the owner backstop is
  intact and unbreakable because `DOM_MANAGER.admin_role` is unset → resolves to `ADMIN` → the
  owner, so a rogue Manager cannot escape — the owner revokes it and two-hop reclaims the Pauser
  subtree. Rejecting would mean dropping CMP-F5 and thereby violating CIR-ADMIN-3, so ratify is the
  Circle-conformant choice. The pinned tests are kept exactly as listed
  (`set_role_admin_dom_manager_can_redelegate_pauser`, `set_role_admin_owner_direct_rejects`,
  `owner_reaches_set_role_admin_through_dom_manager`, `owner_can_still_grant_pauser`,
  `owner_can_still_revoke_pauser` — the last REALLY strips a live pauser, asserts
  `ERR_SENDER_LACKS_ROLE`, and proves `is_paused` never flips). Circle disclosure is handled
  operator-side (it folds into the already-open `Q-ADMIN-RBAC-EQUIV`, which already names
  `set_role_admin`) — an FYI, NOT a sign-off gate. Supply / F1 `{mint}`-only surface untouched;
  the 13-root allowlist count is unchanged (S21 changes the on-chain GATE of the existing
  `set_role_admin` note, not the note set). [SUPERSEDED 2026-07-14 → S21 flip (top amendment):
  the runtime `set_role_admin` note was subsequently REMOVED — the allowlist is now 12 roots.]

### S3 — #3255: `protocol::faucet::create_fungible_asset` REMOVED (MASM edit) — recipe verified

- Upstream: fungible-asset procs moved to NEW `miden::standards::assets::fungible_asset`; the
  faucet-relative `protocol::faucet::create_fungible_asset` is REMOVED (alpha.2
  `protocol/asm .../faucet.masm` exports only `mint`, `burn`; v15 had it at faucet.masm:21).
- Repo-side (`asm/standards/xreserve/xreserve_mint.masm:342`), the exact stock-parallel recipe
  (alpha.2 stock `mint_and_send` does the same at fungible.masm:357-360):
  `exec.active_account::get_id` (already imported) then `exec.fungible_asset::create` —
  signature `[faucet_id_suffix, faucet_id_prefix, amount] → [ASSET_ID, ASSET_VALUE]`
  (alpha.2 `standards/assets/fungible_asset.masm:65`). Downstream `dupw.1 dupw.1
  exec.faucet::mint` (`[ASSET_ID, ASSET_VALUE]→[]`, faucet.masm:21) and
  `exec.output_note::add_asset` (`[ASSET_ID, ASSET_VALUE, note_idx]→[]`, output_note.masm:171)
  are ABI-unchanged (v15's `ASSET_KEY` word0 is a naming-only rename to `ASSET_ID`).
  `exec.faucet::mint` STAYS. Doc-comment refs to `fungible_to_amount` (burn_policy.masm:48)
  re-point to the new home (`fungible_asset::to_amount`).
- Proof: the whole mint suite (masm_mint_shell, f5 mint paths, e2e) green with byte-identical
  minted-asset semantics; goldens untouched.

### S4 — #3106: mint-policy dispatch ABI takes the full `ASSET_VALUE` word — resolved, low impact

- Source-verified dispatch ABIs (policy proc's view at `dynexec`):
  mint — v15 `[amount, tag, note_type, RECIPIENT]` → alpha.2 `[ASSET_VALUE(word), tag,
  note_type, RECIPIENT]` (policy_manager.masm:268-297 vs v15 :270-298);
  burn — `[ASSET_KEY, ASSET_VALUE]` → `[ASSET_ID, ASSET_VALUE]`, **same 8-felt shape,
  rename-only** (:347-375 vs v15 :343-368).
- Repo impact: `burn_policy::check_policy` (reads amount at `dup.4`) is **ABI-compatible
  unchanged**; `mint_deny_guard::check_policy` is `push.0 assert` (never reads the stack) —
  functionally unaffected, its documented `Inputs:` line updates to the new shape. Both procs
  need `@account_procedure` (S19). #3121 adds named zero-root guards upstream
  (`ERR_ACTIVE_MINT_POLICY_NOT_SET` :287 / `ERR_ACTIVE_BURN_POLICY_NOT_SET` :365) — new
  upstream error paths, no repo action. #3114 fixed the policy getters' 16-felt call ABI
  (`swapw dropw` added) — no repo caller affected.
- Proof: mint-deny suite (stock `mint_and_send` still traps), burn accept/reject matrix
  unchanged, min-burn-size behavior unchanged.

### S5 — #3047/#3021: TokenPolicyManager storage growth — resolved

- alpha.2 manager schema (source-CLOSED, `manager_storage_slots`, manager.rs:596-660): the 8
  named slots install UNCONDITIONALLY — 4 active-root value slots
  (`active_{mint,burn,send,receive}_policy_proc_root`; send/receive hold the EMPTY word when no
  transfer policy is configured) + 4 allowed-roots map slots (send/receive maps empty likewise);
  the allowed maps are built from the UNIFIED policies map (actives included, `build_allowed_map`
  :653-660). The RESERVED asset-callback slots (holding the `invoke_send_policy`/
  `invoke_receive_policy` WRAPPER roots, policy_manager.masm:497/:574) install ONLY when
  `has_transfer_policy()` (:639-645) — the repo registers NO transfer policy, so NO callback
  slots appear (the basic-asset decision stands).
- #3021's STOCK `min_burn_amount` policy: slot
  `"miden::standards::faucets::policies::burn::min_burn_amount::min_burn_amount"` — disjoint
  from the repo's `"xusdc::xreserve::attester_admin::min_burn_size"`; the repo keeps its custom
  pair; NO collision (verified).
- The manager MASM now calls `active_account::has_procedure` in its set-policy validation paths
  (policy_manager.masm:94,148) — satisfied because the stock faucet component exposes
  `has_procedure` (S13).
- Proof: `basic_asset_tripwire` green (NO transfer policy / callback slots appear), policy
  dispatch tests green, storage-shape assertions updated only per this row.

### S6 — #3167: asset-callback flag moved into the AccountId — resolved, low impact

- alpha.2: `AssetCallbackFlag` derives from `TokenPolicyManager::has_transfer_policy()` at the
  stock factory (`fungible/mod.rs:651`); the repo's production account is assembled by the
  miden-testing fixture path (`add_existing_account_from_components`), and the repo registers no
  transfer policy → flag Disabled. `AssetCallbacks::on_before_asset_added_to_{note,account}_slot()`
  accessors survive unchanged (asset_callbacks.rs:66,72) so `basic_asset_tripwire`'s
  component-level absence-proof compiles as-is; AccountId accessor surface used by the repo
  (`prefix().as_felt()/as_u64()`, `suffix()`) is unchanged (AccountId is internally a versioned
  enum now — no repo impact).
- Proof: `basic_asset_tripwire` + the mint/burn e2e (P2ID consumption by a basic wallet without
  FPI attachment).

### S7 — #2283: P2ID notes must now carry ≥1 asset

- Upstream: `P2idNote::builder()` (bon); "P2ID notes must now carry at least one asset".
- Repo exposure: every P2ID the repo builds carries the minted/burn-change asset already (mint
  emits a P2ID with the minted asset; tests construct P2IDs with assets), so the constraint is
  expected satisfiable everywhere — any site that built an asset-LESS P2ID would be a semantic
  break to escalate, not to paper over. (The repo's own mint/admin notes are custom scripts, not
  P2IDs, and are asset-less by design — unaffected by this constraint.)
- Proof: compile + suite green; no assertion weakening.

### S8 — #3109/#3110: the delta→patch test-infrastructure migration

- The M1/M2 mechanical rewrite is behavior-relevant in ONE way: tests that asserted exact
  delta CONTENTS (e.g. `set_attester.rs` map-delta assertions, f5 slot-delta reads) must assert
  the equivalent PATCH contents — same slots, same values, same strictness (no
  equality→containment weakening; #3144 requires full-state patches to be Create-only, which the
  assertions may need to name explicitly).
- Proof: the rewritten assertions pin the SAME observable state transitions.

### S9 — pinned-standards vendored fixtures: REQUIRED re-vendor (the carve-out row)

- The fixtures `crates/xusdc-encoding/tests/fixtures/pinned-standards/{fungible,policy_manager}.masm`
  are VERSION-TRACKING artifacts (NOT golden vectors); their own failure messages command a
  re-vendor at a pin bump.
- Actions: (a) re-vendor both from the alpha.2 REGISTRY source
  (`~/.cargo/registry/src/index.crates.io-…/miden-standards-0.16.0-alpha.2/asm/…`), byte-identical
  copies; (b) recompute `FUNGIBLE_FNV1A` / `POLICY_MANAGER_FNV1A`
  (xreserve_receive_and_burn.rs:176-177); (c) REWRITE the rev-anchor
  (`pinned_standards_rev_matches_cargo`, xreserve_receive_and_burn.rs:224 — currently parses
  `rev = "…"` out of git dep entries) to anchor a REGISTRY pin (`=0.16.0-alpha.2` version
  extraction) with the same specificity guarantees (`rev_pin_binds_to_miden_standards_specifically`
  companion updated in kind); (d) update `PROVENANCE.md`'s source paths + re-derivation recipe to
  the registry layout (`~/.cargo/registry/src/…`, not `~/.cargo/git/checkouts`); (e) RE-VERIFY
  N1D on the alpha.2 stock source: `exec.faucet::burn` has exactly ONE standards caller
  (`receive_and_burn`) and exactly ONE sub-fed `TOKEN_CONFIG_SLOT` supply-decrement write
  (`pinned_standards_single_faucet_burn_caller`, `pinned_standards_single_supply_decrement_write`);
  (e-EVIDENCE, Phase 4): N1D RE-VERIFIED on the alpha.2 stock source — `exec.faucet::burn` appears
  EXACTLY ONCE across both re-vendored fixtures (`fungible.masm:441`), inside `receive_and_burn`
  (`pub proc` @ :411), and the sole sub-fed `TOKEN_CONFIG_SLOT` supply-decrement write-back sits in
  that same proc (get_item → sub → set_item, :447/:461/:465). The sole-supply-decrement property
  therefore HOLDS at alpha.2; both fixture tests are green with the new checksums.
  (f) WHICH COPY (source-verified): alpha.2 ships each source twice — the LOGIC libraries
  `asm/standards/faucets/fungible.masm` + `asm/standards/faucets/policies/policy_manager.masm`
  (where `receive_and_burn`, `faucet::burn`, the supply write-back, and the policy dispatchers
  actually live — the N1D anchors), and thin component RE-EXPORT WRAPPERS under
  `asm/components/faucets/…` (the fungible wrapper adds the `has_procedure` re-export). The
  vendored fixtures are and remain the LOGIC copies — the wrappers contain no burn/supply code
  and are NOT vendored (recorded here as the copy-choice rationale).
- Proof: fixture tests green with the new checksums; the N1D sweep result unchanged in MEANING
  (sole-burn-caller holds at alpha.2 — if it does NOT, STOP per §10).

### S10 — #3281: sync proving (alpha.2)

- Mechanical at the call sites (M7), semantic only in that no execution/proving behavior may
  change; the prove-dummy paths in xreserve_burn.rs stay proofs of the same transactions.

### S11 — #3204: `output_note::create` context restriction — resolved: NOT NEW, repo complies

- Source-verified: the enforcing check (`authenticate_account_origin` → `caller` root must be a
  procedure of the active account, `ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE`) exists
  IDENTICALLY at v15 (kernel api.masm:63) and alpha.2 (api.masm:70,90). An account-component
  procedure invoked via `call` from a note script IS account context. The repo's chain — note
  `main` → `call.note_entry::receive_and_mint` (account-installed) → `exec.xreserve_mint::mint`
  → `exec.output_note::create/add_asset` — passes at both versions. CAVEAT: this holds only
  while `receive_and_mint` remains an account-INTERFACE procedure, which at alpha.2 requires
  `@account_procedure` (S19).
- Proof: the mint e2e emits the P2ID output note exactly as at v15.

### S12 — #3102/#3209: `Authority` gains freeze/unfreeze — **HUMAN-RATIFIED 2026-07-13** (present-but-unreachable; the ratified `renounce_role` disposition)

- **DECISION NOTE (operator, 2026-07-13, RATIFY):** the v16 stock `Authority::OwnerControlled`
  bundles owner-gated `freeze`/`unfreeze` account procedures (upstream #3102/#3209). Disposition:
  they are callable PROCEDURES but OPERATIONALLY UNREACHABLE on this faucet — the immutable
  13-root note-script allowlist contains NO freeze note and the tx-script allowlist is EMPTY (F5,
  preserved at v16), so `freeze` can never be invoked, `is_frozen` is never set, and
  `ERR_AUTHORITY_FROZEN` never fires. The mechanism is INERT — the SAME disposition as the
  ratified `renounce_role`. Unreachability is the load-bearing guarantee; owner-gated
  account-self-freeze (NOT holder/on-token control) is a secondary comfort. No F4 contradiction,
  no Circle no-freeze conflict. EXCLUDE was NOT chosen (would need an upstream/custom `Authority`,
  out of migration scope, and buys nothing over unreachable-inert). Recorded as GLOSSARY
  **IMPL-DEV-21** (the CDR mirror). Circle disclosure folds into the already-open
  `Q-ADMIN-RBAC-EQUIV` — an FYI, not a gate.
- Source-verified: alpha.2 `authority.masm` exports `freeze` (:124) and `unfreeze` (:142) as
  account procedures (v15 exported ONLY `assert_authorized`); under `OwnerControlled` both are
  owner-gated and bypass the frozen flag. `assert_authorized` now `dup.1
  assertz.err=ERR_AUTHORITY_FROZEN` before dispatch (:79-80) — the config word is
  `[authority, is_frozen, 0, 0]`; `Authority::OwnerControlled.into()` produces the correct
  unfrozen word, so the repo's composition is insulated. The config SLOT NAME changed
  (`"miden::standards::access::authority"` → `"…::authority_config"`, + a new RBAC-only
  `procedure_roles` map slot) — the repo pins neither string.
- PIN + PROOF (`tests/account_callable_surface.rs`, the S12 deliverable):
  `production_account_callable_surface_is_frozen` freezes the WHOLE composed-account callable set
  (the xreserve 17 + the **45** stock procs) as a LITERAL list at both the source layer
  (component exports) and the on-chain layer (the committed account's procedure roots), so ANY
  future stock bump that adds/drops a callable proc fails LOUDLY.
  `authority_freeze_and_unfreeze_are_present_on_the_account` asserts they ARE callable roots;
  `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note` scans the MAST of all 13
  allowlisted note scripts (exhaustive over the allowlist) and shows none references the roots;
  `freeze_and_unfreeze_are_not_admissible_via_either_allowlist` asserts the roots are not among
  the 13 note-script roots; and `the_auth_component_rejects_a_non_allowlisted_note` /
  `the_auth_component_rejects_any_tx_script_via_the_empty_allowlist` EXECUTE the two entry vectors
  and watch the auth component reject them (the allowlist is an epilogue `@auth_script`, so a
  freeze-CALLING note would trap on freeze's own owner-gate before the check — the allowlist's
  decision on such a note is the root-membership one, asserted directly).
- SCOPE OF THIS ROW: S12 ratifies `freeze`/`unfreeze` ONLY. Building the full-account pin ALSO
  exposed THREE further v0.16 stock callable roots no v0.15 composition had —
  `authority::get_authority` and `policy_manager::invoke_send_policy`/`invoke_receive_policy`.
  Those are NOT dispositioned here and were NOT ratified under S12; declaring them "already
  ratified" would be exactly the self-sanctioning §4a forbids. They carry their OWN
  human-ratified disposition — see **S24** — reached by an explicit round-9 operator ratification.
- INVARIANTS (unchanged shape, Phase 4): note-script allowlist EXACTLY 13 roots (set-equality at
  source + on-chain layers); supply-raising callable-root set EXACTLY `{mint}` by enumeration;
  tx-script allowlist EMPTY. The freeze/unfreeze addition changes the on-chain GATE surface, NOT
  the note set — the 13-root count is unchanged. [SUPERSEDED 2026-07-14 → S21 flip (top
  amendment): the standing invariant is now EXACTLY 12 roots.]

### S13 — #3222: unified stock BURN note reflects via `has_procedure` — resolved

- Source-verified: the alpha.2 stock burn note (`standards/notes/burn.masm:42-45`) does
  `procref.fungible::receive_and_burn` + `call.code_inspection::has_procedure` to pick the
  faucet kind, and PANICS (`ERR_BURN_UNSUPPORTED_FAUCET`, :33) on accounts not exposing
  `has_procedure`. The stock `FungibleFaucet` COMPONENT now re-exports `has_procedure` itself
  (`components/faucets/fungible_faucet/fungible_faucet.masm:21` — same MAST root as
  `CodeInspection::has_procedure_root()`), so composing stock `FungibleFaucet` SUFFICES — the
  repo does NOT add `CodeInspection`. Net: +1 callable root on the faucet (counted in S12).
- Proof: xreserve_receive_and_burn suite + f5 burn-note row green with the re-pinned (one of 13)
  stock BurnNote root.

### S16 — vm#3342 (VM 0.25.0): ECDSA K256 Keccak PUBKEY COMMITMENT FORMAT CHANGED — the deepest delta of this migration (⚠ contains the one golden-vector conflict → §10 decision item 1)

- Upstream (miden-vm CHANGELOG v0.25.0, PR #3342): "[BREAKING] Changed the ECDSA K256 Keccak
  public key commitment format to use affine public key coordinates (`qx_le_u32[8] ||
  qy_le_u32[8]`) instead of compressed SEC1 public key bytes … Existing public key commitments
  must be regenerated with `PublicKey::to_commitment()`."
- Source-verified (registry): core-lib 0.23.3 `asm/crypto/dsa/ecdsa_k256_keccak.masm:20`
  `PK_LEN_FELTS = 9` (33-byte compressed SEC1 as 9 felts) → core-lib 0.25.3 same file `:20`
  `PK_LEN_FELTS = 16` (affine `qx_le_u32[8] || qy_le_u32[8]`); PK staging and PK_COMM =
  Poseidon2(PK felts) structure otherwise unchanged. miden-crypto 0.28's
  `PublicKey::to_commitment` matches the new format (the PR aligns wrapper ↔ crypto).
- Repo exposure (the D5d attestation seam, R-MINT-13/14):
  1. `asm/standards/xreserve/encoding/mod.masm::pubkey_commitment` hashes the **9** staged pubkey
     felts (locals 0..9, `PUBKEY_FELTS`; sponge domain tag `9 % 8 = 1`) — must become **16**
     affine felts (domain tag `16 % 8 = 0`), staying byte-identical to the new precompile-wrapper
     PK_COMM staging (the mirrored-staging invariant the proc documents).
  2. `asm/standards/xreserve/attestation_verify.masm` — the advice materialization (`[PK(9),
     SIG(17)]` → `[PK(16), SIG(17)]`), the word-aligned locals plan (`@locals(40)`, pubkey
     loc[0..9] / digest loc[12..20] / sig loc[20..37] → re-laid-out for a 16-felt pubkey region),
     and the doc comments. The load-bearing seam (ONE pubkey region feeds BOTH the allowlist
     commitment AND `verify_prehash`) is preserved by construction.
  3. The mint-note scheme-1 attestation ATTACHMENT layout (DC-2/DC-3 boundary):
     `[feeAmount(8), pubkey(9), signature(17), pad(2)] = 36 felts = 9 words`
     (`XRESERVE_MINT_ATTACHMENT_NUM_WORDS = 9`, parity-pinned in
     `xreserve_mint_note_entry.masm`) → `[feeAmount(8), pubkey(16), signature(17), pad(3)] = 44
     felts = 11 words`. Both parity sides move together (Rust const + MASM const + the shim's
     word-count checks).
  4. Rust codec: `compressed_pubkey_felts` (packs 33 compressed bytes → 9 felts) is replaced by
     an affine-coordinate packing. The Circle-facing ingress format stays the 33-byte compressed
     SEC1 pubkey (what the attestation service returns; Q-API stays OPEN) — unit-04 owns the
     SEC1→affine decompression at the codec boundary, which makes `k256` a REGULAR (non-optional)
     dependency of `xusdc-encoding` (version from the workspace table; already in the pinned
     cache — no new version enters the graph). `MintAttestation` keeps its `[u8; 33]` pubkey.
  5. Consumers by reference (no re-derivation): the relayer fixture's allowlist key (computed at
     test runtime via unit-04's `pubkey_commitment`) and the set_attester path (commitment keys
     into `xReserveAttesters`) follow automatically; D5d in-test vectors regenerate their
     commitments in-test via the same primitives.
- **GOVERNED-CONTRACT SUPERSESSION (part of decision item 1):** this delta changes shapes that
  `docs/governing/CANONICAL-OWNERSHIP-MAP.md` PINS as shared boundaries — the DC-2 row pins the
  attestation wire as "65B `r‖s‖v`=17 felts; **33B pubkey=9 felts**" and the DC-3 row pins the
  allowlist key as "**`Poseidon2(33B)` → `Word`**" (ownership map, Canonical-owners table), and
  its anti-duplication rule ends: "A new shared concept/boundary must be added to this map first
  (**human re-approves**) — no silent new shared shapes." This migration's supersession banner
  (§ header) covers only the ground-rule-5 PIN framing — NOT these data contracts. Therefore
  decision item 1 explicitly requests approval of a **DC-2/DC-3 v16 supersession**: DC-2 on-chain
  staging becomes 16 affine-coordinate felts (`qx_le_u32[8] || qy_le_u32[8]`; attachment grows
  9→11 words) and DC-3 becomes `Poseidon2(affine qx‖qy, 16 felts) → Word`, both FORCED by
  vm#3342, while the **Circle ingress format stays the 33-byte compressed SEC1 pubkey**
  (`MintAttestation` keeps `[u8; 33]`; unit-04 owns the SEC1→affine decompression, so the
  boundary OWNERSHIP is unchanged — owner 04 staging + faucet 01 verify, exactly as the map
  assigns). Per the task scope, `docs/governing/` stays UNEDITED: **APPROVED 2026-07-13
  (operator, MAP-ROW-AS-RECORD) — THIS row IS the binding DC-2/DC-3 v16 supersession record.**
  Operator-mandated statement, verbatim: "Circle-wire inputs byte-identical; only the 3 derived
  att fields (packed_felts, expected_commitment, derivation) regenerate; commitment preimage
  33B to affine-16 is internal."
- **Golden-vector conflict (decision item 1, field-complete scope):** the canonical artifact's
  `att` family (`tests/vectors/xreserve-encoding-vectors.json`, 3 vectors) is EXPLICITLY
  VERSION-DERIVED (its own `derivation` field: "commitment = miden-crypto
  PublicKey::to_commitment @ 0.25.1 (Poseidon2 over the 9 pubkey felts)"), unlike the
  Circle-wire families (`aid`/`amt`/`b32`/`bn`/`di` — byte-identical across the migration, no
  exception exists for them). The regeneration approval covers EXACTLY these `att`-vector
  fields, via the committed generator (`cargo run --bin gen_vectors --features vectors`):
  - **`packed_felts`** — the load-bearing staging oracle (AttVector, src/vectors.rs:155;
    emitted as `packed(&pk)` = the 9 compressed-SEC1 felts, gen_vectors.rs:698-703; consumed
    felt-by-felt by TV-DUAL-5's MASM staging, tests/masm_dual.rs:426-451): becomes the **16
    affine-coordinate felts**;
  - **`expected_commitment`** — recomputed by crypto-0.28 `to_commitment` over the affine form;
  - **`cite` + `derivation`** — updated to name the 0.28/affine derivation;
  - the `AttVector` struct DOC (src/vectors.rs:146-149) and the generator's att helpers
    (`packed(&pk)` → affine packing) and TV-DUAL-5's staging (9-felt `[PK_W0, PK_W1, pk8]` →
    16-felt `[PK_W0..PK_W3]`) move in the same mapped change;
  - **byte-identical, NO exception granted:** `id`, `tv`, `pubkey_hex` (the 33-byte compressed
    Circle ingress), `payload_hex`, `digest_hex`, `digest_felts`, `sig_hex`, `sig_felts`,
    `v_byte` — every Circle-authentic input/digest/signature field. Old→new values of the
    changed fields are recorded in §6 at re-pin time.
  REJECTED alternative: leaving the artifact untouched would require the suite to re-derive
  commitments outside the oracle (weakening the dual-derivation design).
- Proof: TV-DUAL-5 (MASM `pubkey_commitment` ≡ Rust mirror ≡ `PublicKey::to_commitment`@0.28)
  green; the full D5d attestation matrix green; allowlist reject tests green; the e2e mint green.

### S17 — vm#3220 (VM 0.24.0): MASM import-syntax + module-structure overhaul (assembler-forced source edits across ALL repo `.masm`)

- Upstream (miden-vm CHANGELOG v0.24.0, PR #3220): (a) "[BREAKING] Import syntax … Module
  imports are of the form `use some::module` or `use some::module as alias`" (the `->` alias
  form is gone), "item imports are of the form `use {item} from some::module`"; (b) imports
  resolve in the GLOBAL namespace (submodule-relative needs `self::`); (c) "[BREAKING] Miden
  Assembly module structure must now be explicitly declared via `mod name`/`pub mod name`; only
  modules declared this way are included in an artifact"; (d) `pub use` may no longer re-export
  modules; (e) `Assembler::compile_and_statically_link_from_dir` → `…_from_root`. Also vm#3201/
  #3208 removed `debug.*`/`trace` decorators (repo MASM has none — verified by grep), and
  v0.24.0 added `do … while … end` (additive).
- Repo exposure (verified against the 0.25.3 parser's own tests): **27 offending import lines**.
  The `->` alias is a HARD PARSE ERROR ("import aliases use `as`; `->` is no longer supported",
  miden-assembly-syntax-0.25.3 parser/tests.rs:388-394) — one site
  (`xreserve_mint_note.masm:17`). Bare no-brace ITEM/const imports are silently treated as
  module imports and the symbol becomes UNDEFINED (sema/tests.rs:847-859) — ~26 sites
  (`use miden::protocol::note::NOTE_TYPE_PUBLIC`, `use miden::protocol::asset::
  FUNGIBLE_ASSET_MAX_AMOUNT` ×2, `use miden::standards::attachments::network_account_target::
  NETWORK_ACCOUNT_TARGET_ATTACHMENT_SCHEME`, ~15 `use xreserve::encoding::layout::*` const
  lines, the `deposit_intent_parser::{USED_NONCES_SLOT, IDENTIFIER_CONFIG_SLOT,
  DOMAIN_CONFIG_SLOT}` lines, …). Bare MODULE imports (`use miden::protocol::active_note` etc.)
  remain VALID (parser/tests.rs:303-304). Zero `debug.*`/`trace.*` decorators in repo MASM.
  Confirmed still-valid forms the repo keeps: `pub const N = word("…")`, `push.N[0..2]`
  const-word indexing, `@locals(N)`; typed signatures (#3234) are OPTIONAL (typed and untyped
  procs coexist in alpha.2 stock).
- Repo-side actions: (i) rewrite the 27 lines to `use {ITEM, …} from module` / `use module as
  alias`; (ii) satisfy the 0.25 module-structure requirement for the `xreserve` namespace
  (explicit `mod`/`pub mod` declarations — exact shape set by whichever library-assembly API the
  harness lands on); (iii) **Rust harness break (assembly 0.25.3, source-verified):**
  `Assembler::with_dynamic_library` is GONE → `with_package(Arc<Package>, Linkage)` /
  `link_package(…)` (assembler.rs:349,355; `StandardsLib` has `impl From<StandardsLib> for
  Package`); `assemble_library_from_dir` is REMOVED → `assemble_library(…)` (:415) or
  `assemble_library_from_root(…)` (:436). Affected call sites: src/note/xreserve_mint.rs:76-84
  (the production mint-note factory), src/note/xreserve_admin.rs (same recipe),
  tests/support/mod.rs `assemble_xreserve_lib` (:308) + `assemble_xreserve_lib_effects_public`
  (:338), tests/masm_dual.rs:46-53. `CodeBuilder` itself SURVIVES compatibly
  (`with_dynamically_linked_library(impl CodeBuilderLibrary)` accepts `&Library` unchanged;
  `compile_note_script`/`compile_component_code` intact — code_builder/mod.rs:260,395,491,576).
  Each touched `.masm` file lands under this row (+ §7); the MASM skills checklist applies to
  every edit.
- Proof: the whole 416-test encoding gate re-assembles and EXECUTES every `.masm`;
  `masm_structure` conventions suite green (52 tests).

### S22 — #3204 note-creation context restriction: the TEST HARNESS's emit paths move into account context (harness-only; production MASM already complied — S11)

- Source-verified: at alpha.2 the kernel rejects `output_note::create` / `add_attachment` unless
  the syscall's `caller` root is a procedure of the ACTIVE account (api.masm:70,90 →
  `ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE`). Upstream's own wallets therefore expose
  `create_note` (`standards/note/note_creator.masm:27`, re-exported by the BasicWallet component)
  — a tx script may no longer `exec` the kernel API directly.
- Repo production MASM already complies (S11: `apply_mint_effects` is an account procedure).
  The TEST harness's note-emitting tx scripts did NOT: `emit_note_with_attachments` (the mint
  note's F5 two-attachment emit) and `send_burn_note_script` (the burn note's emit) exec'd
  `output_note::create`/`add_attachment` from the script.
- Repo-side (tests/support/mod.rs): a zero-storage `emit_helper` account component
  (`xusdc::test_fixtures::emit_helper`) exposes two `@account_procedure` wrappers —
  `emit_note_with_two_attachments` (the mint shape) and `emit_note_with_attachment` (the
  single-attachment burn shape) — and the note-emitting wallets (`producer`, the burn `user`, the
  assembled-faucet recipients) are built with it installed (`add_emitting_wallet`). The
  attachment-less stock `BurnNote` path uses the STOCK `create_note` — which lives in
  `miden::standards::note::note_creator` (the `wallets::basic` MODULE does not carry it; the
  BasicWallet COMPONENT re-exports it, so the account exposes its root and the script calls
  `note_creator::create_note`). EXACTLY TWO helper wrappers exist — no third procedure. The emitted note's identity is unchanged (same recipient,
  metadata, attachments → same `NoteId`; the id-parity assertions in both emit paths still hold).

### S23 — #3188/#3216: `account_id::validate` checks the VERSION before the structure

- Source-verified: alpha.2 `validate` = version check (`ERR_ACCOUNT_ID_UNKNOWN_VERSION`) then
  `validate_structure` (account_id.masm:141-152); v15 surfaced the suffix-low-byte error first
  for the same input.
- Repo exposure: the Circle-frozen `aid-rej-non-canonical` golden vector (`prefix = suffix = 7`)
  now trips the VERSION constant instead of the low-byte constant. The vector is NOT regenerated
  (it stays byte-identical — Circle-frozen); the test asserts the exact v16 error, and a NEW
  crafted case (`aid_low_byte_traps_protocol_low_byte`, valid version + non-zero suffix low byte)
  keeps the low-byte assertion alive. Net: same strictness, +1 test.

### S24 — three FURTHER v0.16 stock callable roots (#3102 `get_authority`, #3047 `invoke_send_policy` / `invoke_receive_policy`) — HUMAN-RATIFIED 2026-07-13 (round 9), NOT under S12

- **PROVENANCE (why a separate row):** the full-account surface pin (S12 deliverable 1) exposed
  these three as v0.16 stock callable additions beyond freeze/unfreeze. The round-8 operator
  ratification covered freeze/unfreeze ONLY; round 8's map text calling these "already ratified"
  was self-sanctioning — exactly what §4a forbids — and the audit correctly caught it. They are
  dispositioned HERE by an EXPLICIT round-9 operator ratification, with the AUDITOR's corrected
  semantics (the round-8 "#3121 zero-root trap" claim was wrong and is deleted).
- **DISPOSITION (operator, RATIFY):**
  - `authority::get_authority` (#3102): a pure read-only VIEW accessor — no state, no capability,
    not supply-raising. Benign.
  - `policy_manager::invoke_send_policy` / `invoke_receive_policy` (#3047): INERT NO-OPs on this
    faucet. Source-verified corrected semantics
    (`standards/faucets/policies/policy_manager.masm::invoke_transfer_policy:447-471`): the proc
    reads the active send/receive policy root, and on the EMPTY-root branch (`word::testz` →
    `if.true`) it DROPS the empty root and asset id and returns `ASSET_VALUE` UNCHANGED — and
    that branch SKIPS the pause check (`assert_not_paused` lives only in the non-empty `else`
    branch). There is NO zero-root assertion/trap (the round-8 claim was wrong). F4 installs NO
    transfer policy → `AssetCallbackFlag::Disabled` → the kernel never invokes these on a
    transfer; and they are unreachable via the immutable 13-root note allowlist (tx-allowlist
    EMPTY). F4 (unpoliced transfers / no policy registered) and F1 (`{mint}`-only) both INTACT;
    the "skips pause" behavior is CONSISTENT with F4 — transfers are unpoliced by design.
  - EXCLUDE was NOT chosen (would need an upstream/custom `Authority`/`TokenPolicyManager`, out
    of migration scope, and buys nothing over inert-unreachable).
- **RECORDED** like S12/`renounce_role`: GLOSSARY **IMPL-DEV-22** (the CDR mirror). Circle
  disclosure folds into the register (stock bundles them; we ship inert/unreachable, no
  on-token/holder control) — an FYI, not a gate.
- **PIN + CONFIRMATION (`tests/account_callable_surface.rs`):** all three roots are part of the
  frozen 62-root literal surface (`production_account_callable_surface_is_frozen`), so any future
  drift fails loudly. The inert/F4-intact guarantee is re-confirmed at v16 by
  `invoke_wrappers_are_inert_and_the_asset_stays_basic` (asserts NO transfer policy / callback
  slots on the composition and `AssetCallbackFlag::Disabled` on the minted asset), and the
  standing `basic_asset_tripwire` (F4) + `production_supply_raising_root_set_is_exactly_mint`
  (F1) stay green — the `invoke_*` presence did NOT flip the callback flag or register a policy.

### S14 — behavioral guardrails that may surface as new error paths (no repo code change expected)

- #3118 `set_max_supply` rejects caps above `FUNGIBLE_ASSET_MAX_AMOUNT` (DEV-5 stays OPEN; the
  repo's set_max_supply admin note passes through to the stock setter).
- #3121 zero-root policy dispatch check (descriptive error instead of silent fail).
- #3182 note/tx allowlists read INITIAL storage state (`get_initial_map_item`) — allowlist is
  immutable on this faucet, so no observable change.
- #3216 zero account ID fails structural validation.
- Proof: the negative-path tests' expected errors stay exact; any error-constant re-key gets a
  map row.

### S15 — #3272/#3060: input-note assets became stateful; attachments retained — resolved NO-OP

- Source-verified: every `active_note` procedure the repo calls SURVIVES with identical
  signatures — `get_storage` (`[dest_ptr]→[num_storage_items]`, active_note.masm:252),
  `find_attachment` (`[attachment_scheme]→[is_found, attachment_idx]`, :585),
  `write_attachment_to_memory` (:553), `write_attachment_commitments_to_memory` (:526);
  `NETWORK_ACCOUNT_TARGET_ATTACHMENT_SCHEME` still = 2. The #3272 assets-API replacement touches
  procs the repo never calls (`get_assets` → zero repo sites). The stock burn path's own asset
  handling is stock-internal.

### S18 — #2974/#3047: TokenPolicyManager Rust construction rewritten — **DESIGN DECISION REQUIRED AT THIS MAP'S GATE** (custom-policy component install mechanics)

- Source-verified alpha.2 API: `TokenPolicyManager::builder().active_mint_policy(MintPolicy)
  .active_burn_policy(BurnPolicy).build()` (bon builder, manager.rs:254; `build()` returns
  `Self`, NOT `Result`); `MintPolicy::custom(root, components) -> Result<_, MintPolicyError>`
  (mint/mod.rs:69), `BurnPolicy::custom(root, components)` (burn/mod.rs:84) — each VALIDATES
  `root` against the supplied components (`has_procedure`, else `RootNotInComponents`) and the
  manager's `IntoIterator` INSTALLS those components. `PolicyRegistration`,
  `MintPolicyConfig`/`BurnPolicyConfig` (enums), and `TokenPolicyManagerError` are DELETED —
  builder.rs's imports (:42-44), its `XReserveStablecoinBuilderError::PolicyManager` variant,
  and both `with_*_policy` call sites (:505-507) must be rewritten; `IntoIterator for
  TokenPolicyManager` survives so `components.extend(manager)` keeps working.
- **The hazard (source-proven):** the repo's mint-deny root AND burn-policy root live in ONE
  shared `xreserve` component that the builder installs exactly once (assemble_components,
  builder.rs:597-598). At alpha.2 the manager's `policies` map is keyed BY ROOT
  (`register_policy`, manager.rs:680-695), the two roots are DISTINCT, and
  `IntoIterator for TokenPolicyManager` (manager.rs:697-712) yields "the manager itself first,
  then the companion components contributed by EVERY registered policy" — its implicit
  deduplication is per-root only ("a policy installed under both send and receive only
  contributes its companion components once" — not across different roots). So passing the
  xreserve component to both `custom()` calls makes the iterator emit it TWICE →
  `AccountError::DuplicateStorageSlotName` at account build. `to_manager_component` is private:
  the manager component is reachable ONLY through this iterator.
- **THE pinned algorithm (this is the design; Phase 3 implements it verbatim):**
  1. Validation unchanged and FIRST: the existing `MissingMintDenyGuard`/
     `MissingBurnPolicyGuard` root-first rejects (builder.rs:453-455, :502-504) keep running
     before manager construction, with their existing precedence (account-type → mint-root
     check → mutability/slots/token-config → burn-root check) intact.
  2. Build `MintPolicy::custom(deny_root, [xreserve_component.clone()])` and
     `BurnPolicy::custom(burn_root, [xreserve_component.clone()])` — satisfying `custom()`'s
     `has_procedure` validation with the REAL installed component (mint/mod.rs:69-80,
     burn/mod.rs:84; CMP-A10 preserved by construction: the registered root is resolved FROM
     that same component).
  3. `TokenPolicyManager::builder().active_mint_policy(mp).active_burn_policy(bp).build()`.
  4. At the composition seam, consume the manager's iterator ONCE with an exact-shape
     assertion (order-insensitive beyond the documented head): the FIRST item is the manager
     component (per the IntoIterator doc, manager.rs:701-703); the REMAINDER must be EXACTLY
     TWO components, EACH code-commitment-equal to the installed `xreserve_component`
     (`component_code()` equality — the same identity the builder already uses to resolve
     roots). The two duplicates are DROPPED — the xreserve component is already in the list
     once (step 5). ANY deviation (count ≠ 2, or an unrecognized companion) is a loud build
     error via the NEW builder variant `PolicyCompanionMismatch` — never a silent drop.
  5. Final component order (storage slots are NAME-addressed, so order is non-semantic; pinned
     for auditability, v15-adjacent): `[FungibleFaucet, Pausable::unpaused() (S1 — adjacent to
     the faucet whose slot block carried is_paused at v15), xreserve(+min_burn slot),
     manager_component, Ownable2Step, seeded-RBAC(+ADMIN seed per S2), Authority::OwnerControlled]`
     + the `Auth::NetworkAccount` auth component via the fixture, as at v15.
  6. Error-variant mapping in `XReserveStablecoinBuilderError`: the deleted
     `PolicyManager(TokenPolicyManagerError)` variant is REPLACED by
     `MintPolicy(MintPolicyError)` + `BurnPolicy(BurnPolicyError)` (source-preserving, matching
     the file's existing wrapping style) + the new
     `PolicyCompanionMismatch { expected, found, recognized }`. `found` is the FULL companion
     remainder the manager emitted and `recognized` how many of those were the already-installed
     xreserve component, so a SMUGGLED foreign companion is visible as `found > recognized`
     instead of hiding behind a matching recognized count (round-6 audit fix).
- **THE pinned public policy-override API replacement (the deleted-config-types successor;
  Phase 3 implements verbatim):** the builder keeps its override capability with the SAME method
  names and the SAME root-first rejection semantics, re-typed onto the upstream alpha.2
  descriptors (the minimal, upstream-idiomatic replacement — a repo-owned selector enum or raw
  `AccountProcedureRoot` parameters would lose the `allow_all()` expressiveness the negative
  tests exercise and invent a second policy vocabulary):
  - Fields (builder.rs:277,280): `requested_active_mint_policy: Option<MintPolicyConfig>` →
    `Option<MintPolicy>`; `requested_active_burn_policy: Option<BurnPolicyConfig>` →
    `Option<BurnPolicy>` (the alpha.2 descriptors — `#[derive(Debug, Clone)]`, NON-Copy since
    they own their companion `Vec<AccountComponent>`).
  - Public methods (builder.rs:323,333): `with_active_mint_policy(mut self, policy:
    MintPolicy) -> Self` and `with_active_burn_policy(mut self, policy: BurnPolicy) -> Self` —
    signatures unchanged except the parameter type; doc comments re-point their examples
    (`BurnPolicyConfig::AllowAll` → `BurnPolicy::allow_all()`).
  - Resolution sites (builder.rs:449-451, :496-498): the v15 code moves the config out of
    `&self` (`self.requested_active_mint_policy.unwrap_or(…)`), which compiled only because the
    v15 enums were `Copy`; the alpha.2 form clones the override and constructs the default
    descriptor fallibly:
    `let active = match &self.requested_active_mint_policy { Some(p) => p.clone(), None =>
    MintPolicy::custom(deny_root, [self.xreserve_component.clone()])
    .map_err(XReserveStablecoinBuilderError::MintPolicy)? };` (burn twin identical with
    `BurnPolicy`/`BurnPolicyError`). The default path cannot actually fail (`deny_root`/
    `burn_root` are resolved FROM that same component at :448/:495), so the documented
    rejection precedence is UNCHANGED; no `expect`/`unwrap` on the fallible constructor.
  - Root checks (builder.rs:453,:502): unchanged in place and meaning —
    `active.root() != deny_root` → `MissingMintDenyGuard`; `active_burn.root() != burn_root` →
    `MissingBurnPolicyGuard` (`MintPolicy::root()`/`BurnPolicy::root()` survive,
    mint/mod.rs:82). Root comparisons live in the `AccountProcedureRoot` domain (the type
    `custom()` takes and `get_procedure_root_by_path` yields; any residual `Word`-typed
    plumbing converts once at the resolution site).
  - Override flow-through: an override that PASSES the root check contributes its OWN companion
    vector to the manager; the step-4 seam assertion then requires every companion to be
    code-commitment-equal to the installed xreserve component — a passing-root override
    carrying any foreign companion trips `PolicyCompanionMismatch` (loud, by design: no
    smuggled components).
  - Call-site updates in the PRODUCTION-API consumers: `tests/builder_api.rs:203`
    `with_active_mint_policy(MintPolicyConfig::AllowAll)` → `…(MintPolicy::allow_all())` and
    `:228` `with_active_burn_policy(BurnPolicyConfig::AllowAll)` → `…(BurnPolicy::allow_all())`
    — both tests keep asserting EXACTLY `MissingMintDenyGuard` / `MissingBurnPolicyGuard` (no
    weakening); the builder.rs struct/method docs at :278-279, :320-322, :328-332 re-word to
    the descriptor defaults.
- **THE pinned TEST-ORACLE manager migrations (the remaining two constructors of the deleted
  types — tests/support/mod.rs:40 imports them; these complete the call-site inventory):**
  the harness builds two CODE-IDENTICAL account pairs whose members differ ONLY in the active
  policy root — `oracle_components` (support/mod.rs:2440-2464, the R-MINT-16 deny/allow mint
  pair) and `oracle_burn_components` (:2646-2687, the CMP-A10 real/allow burn pair). The
  code-identity invariant SURVIVES at alpha.2 because `build_allowed_map` filters the UNIFIED
  policies map — ACTIVE policies are in the on-chain `allowed_*_policy_proc_roots` maps too
  (manager.rs:596-660), so registering the same policy SET with the active/reserved choice
  swapped yields identical components + identical allowed maps + differing active slot, exactly
  the v15 shape. Pinned rewrites:
  1. `oracle_components(faucet, xreserve_component, deny_root: Word, deny_active: bool)`:
     `let deny = MintPolicy::custom(AccountProcedureRoot::from_raw(deny_root),
     [xreserve_component.clone()]).map_err(anyhow)?;` (`from_raw` is the manager's own
     Word→`AccountProcedureRoot` idiom, manager.rs:270); `let allow = MintPolicy::allow_all();`
     `(active, reserved)` per `deny_active`; then `TokenPolicyManager::builder()
     .active_mint_policy(active).allowed_mint_policy(reserved)
     .active_burn_policy(BurnPolicy::allow_all()).build()` — **`active_burn_policy` is a
     REQUIRED builder param at alpha.2** (manager.rs:255-263; v15's mint-only manager is no
     longer expressible). `BurnPolicy::allow_all()` is the pinned choice for this MINT oracle:
     burn is out of scope for its tests, the `BurnAllowAll` companion lands IDENTICALLY in both
     pair variants (code-identity preserved), and production remains untouched by
     harness-only shapes. Mapped composition delta vs v15: each mint-oracle account gains the
     `BurnAllowAll` component + a non-zero active-burn slot (both variants identically).
  2. `oracle_burn_components(…, mint_deny_root: Word, burn_root: Word, burn_real_active, …)`:
     `active_mint_policy(MintPolicy::custom(from_raw(mint_deny_root),
     [xreserve_component.clone()])?)`; `real_burn = BurnPolicy::custom(from_raw(burn_root),
     [xreserve_component.clone()])?`; `allow_burn = BurnPolicy::allow_all()`;
     `(active_burn, reserved_burn)` per the flag; `.active_burn_policy(active_burn)
     .allowed_burn_policy(reserved_burn).build()`.
  3. Both helpers apply the SAME seam rule as production step 4, with oracle-specific expected
     shapes (anyhow-asserted, harness-style): consume the iterator head (manager component);
     from the remainder DROP every component code-commitment-equal to the separately-installed
     xreserve component, ASSERTING the dropped count (mint oracle: 1 — the deny custom; burn
     oracle: 2 — the mint-deny + real-burn customs); KEEP the stock policy companions the
     code-identity invariant REQUIRES (mint oracle keeps `{MintAllowAll, BurnAllowAll}`; burn
     oracle keeps `{BurnAllowAll}`), and REJECT anything else.
  4. Both helpers add `Pausable::unpaused()` immediately after the faucet component (S1 applies
     to the oracle accounts too — their policy-dispatch paths read the pause slot, and at
     alpha.2 a missing slot silently NO-OPS the check per #3047 instead of trapping; both pair
     variants gain it identically) and update their stale "is_paused is
     FungibleFaucet-installed (pinned v0.15.3)" comments.
- Proof: builder_api composition-shape tests green, EXTENDED per this row with: (i) the final
  component list contains exactly ONE component whose code commitment equals the xreserve
  component's and exactly ONE policy-manager component; (ii) the built account still resolves
  deny/burn roots to the installed component's MAST roots (CMP-A10); (iii) every account-build
  e2e passes (no `DuplicateStorageSlotName`); (iv) a negative unit test drives
  `PolicyCompanionMismatch` (an unexpected companion trips the seam assertion); (v) the ORACLE
  pairs stay sound — for each pair, both variants' component sets are EQUAL (code-identity) and
  the existing non-vacuity behaviors hold unchanged (deny-active traps `mint_and_send` /
  allow-active mints; real-burn-active enforces R-BURN-1/2 / allow-burn-active accepts), with
  each oracle account carrying exactly one xreserve-code component. The seam obligations are
  discharged by NAMED tests (round-6 audit fix — they were missing):
  `production_composition_installs_one_xreserve_and_one_manager` (POSITIVE: exactly one
  xreserve-code component + exactly one policy-manager component in the shipped composition) and
  `seam_rejects_a_smuggled_foreign_policy_companion` (NEGATIVE: an override whose ROOT is the deny
  guard — so it passes the `MissingMintDenyGuard` check — but whose companion vector smuggles a
  foreign component is rejected with the exact
  `PolicyCompanionMismatch { expected: 2, found: 3, recognized: 2 }`).

### S19 — vm/#3171 + protocol #3171: `@account_procedure` is now REQUIRED for account-interface membership — annotate the xreserve library (MASM edits, every component file)

- Source-verified: alpha.2 `AccountComponentCode::exports()` FILTERS to procedures carrying the
  `account_procedure` (or `auth_script`) attribute (miden-protocol
  src/account/component/code.rs:48-57); `procedure_roots()` derives from `exports()`. At v15
  exports() = every `pub proc`. The repo's MASM carries ZERO `@account_procedure` annotations →
  unannotated, the entire xreserve interface silently vanishes from the built account (every
  `call.*`, the policy dynexec roots, and the note-entry shim would fail
  `ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE`).
- Repo-side action: annotate `@account_procedure` on EXACTLY the 17 procs of the ratified
  callable set (`FROZEN_CALLABLE_ROOTS`, mint_root_surface.rs:50-68) — the F1-demotion surface
  is thereby preserved BYTE-EQUAL in membership to v15 (at v15 all 17 pub procs were interface
  members by default; the two demoted procs stay unannotated/private). Any alternative (e.g.
  annotating only the ~9 directly-called procs) would CHANGE the ratified F1 surface = a
  different semantic decision, deliberately NOT taken here.
- Stock components the repo `call`s (fungible::set_max_supply, ownable2step transfer/accept,
  rbac grant/revoke/set_role_admin, pausable, authority) already carry the attribute at alpha.2.
- The TEST HARNESS's string-generated driver components (the `pub proc drive`/`check`/
  `read_slots` templates in tests/support/mod.rs ×12 + mint_root_surface.rs ×1 — all
  account-installed `call`-targets) gain the same `@account_procedure` annotation; the inline
  note/tx-script templates already carried `@note_script` at v15 and are unchanged. The harness's
  string-generated tx/note scripts also converted their `->` import aliases to ` as ` (9 embedded
  sites — the same vm#3220 rewrite as the repo `.masm` files, S17).
- **Known verification gap this row must CLOSE (the existing tests would NOT catch a missed
  annotation):** in `production_supply_raising_root_set_is_exactly_mint`
  (tests/mint_root_surface.rs:217-273), only the three membership spot-checks (:240-252) read
  the FILTERED interface (`xreserve.procedures()`, :227-230 — which at alpha.2 derives from
  `AccountComponentCode::exports()`'s `@account_procedure` filter, miden-protocol
  code.rs:42-58); the "frozen tripwire" exact-17 comparison (:254-271) walks the RAW
  `Library::exports()` (:255-260), which still lists every `pub proc` REGARDLESS of the
  attribute. A missing annotation on any of the 16 non-mint paths would therefore leave the
  exact-17 test GREEN while the proc silently vanished from the account interface.
- Proof (hardened): UPGRADE the test under this row to assert, IN ADDITION to the existing
  path-level `Library::exports()` equality (kept as the source-layer no-new-pub-procs leg),
  **root-level set-equality between the FILTERED interface and the frozen set**: resolve each of
  the 17 `FROZEN_CALLABLE_ROOTS` paths to its MAST root via
  `get_procedure_root_by_path` and assert the resolved 17-root set `==` the
  `xreserve.procedures()` root set EXACTLY (the `callable` set the test already computes at
  :227-230). This fails on ANY missing/extra annotation. Plus: the mint e2e (S11 chain) green;
  the two demoted procs (`apply_mint_effects`, `extract_recipient_account_id`) still ABSENT
  from the filtered interface.

---

## 6. Re-pin ledger (Phase 4; derivation-mandatory)

Derivation procedure (every row): (1) recompute the value FROM SOURCE via the test's own
enumeration/build path; (2) where two independent layers exist they must AGREE with each other
before the constant moves; (3) only then update, recording old → new + the derivation command
here. Copying hexes out of failure messages without the derivation is forbidden.

| constant (site) | v15 value | v16 value | derivation |
|---|---|---|---|
| `XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX` (src/note/xreserve_mint.rs:67) | `0xb4a510d89ef62eac1dd645fadeca1b00db000dddae8103e0220296ab208328c5` | **`0x85c8cfd61de921bd272d7e39766447b52ad04febd868e2c64f1ab442bf0c37b8`** ✅ (final; derived TWICE — the second derivation follows the `P2ID_SCRIPT_ROOT` re-pin, which changes the xreserve library MAST the note script binds transitively) | derived FROM SOURCE by the factory's own build path (`XReserveMintNote::script().root()`, printed by the parity test itself); at each step the OLD value in the failure was mechanically verified to equal the in-tree constant before the swap (binding proof) |
| the ELEVEN admin-note root constants (`xreserve_admin.rs`): `XRESERVE_{SET_ATTESTER, DOMAIN_INIT, SET_MIN_BURN_SIZE, PAUSE, UNPAUSE, GRANT_ROLE, SET_ROLE_ADMIN, TRANSFER_OWNERSHIP, ACCEPT_OWNERSHIP, SET_MAX_SUPPLY, REVOKE_ROLE}_NOTE_SCRIPT_ROOT_HEX` | (in-tree v15 hexes) | **all 11 RE-PINNED** ✅ | derived FROM SOURCE by each factory's own build path (each `…_root_is_pinned` parity test recompiles the script and prints computed-vs-pinned). Derivation script: for every failing pair, the OLD (right) hex was mechanically matched against the in-tree constant — each matched EXACTLY ONE constant (unique binding, asserted), and only then was the NEW (left) hex written. No hex was copied without that binding proof. |
| `P2ID_SCRIPT_ROOT` (**MASM felt-array const**, `asm/standards/xreserve/xreserve_mint.masm:61`) | `[12857783041667862256, 16051201080474444825, 5045064883019570010, 12450335876814921250]` | **`[7131697192369665042, 13614976149584716721, 15020972229364874097, 1084006998777425639]`** ✅ | the stock `P2idNote::script_root()` at alpha.2 (the tests' own canonical source — support/mod.rs:1149 stages exactly this root); cross-proof: the e2e mint emits a P2ID consumable by a stock wallet. NOTE: this root moves for TWO upstream reasons — the 0.25 assembler AND #3204's rewrite of `p2id.masm` itself (note creation now routes through `basic_wallet::create_note`) |
| `FUNGIBLE_FNV1A` (xreserve_receive_and_burn.rs:176) | `17252926805552427287` | **`13171367163648116355`** ✅ | fnv1a over the re-vendored alpha.2 fixture bytes (byte-identical `cp` from the registry source, `diff` empty; N1D re-verified on the new fixture: sole `exec.faucet::burn` caller = `receive_and_burn` @:411/:441, sole sub-fed TOKEN_CONFIG write-back inside it) |
| `POLICY_MANAGER_FNV1A` (:177) | `12570707895715501309` | **`17561546685770092653`** ✅ | same |
| `PINNED_STANDARDS_REV` anchor (:205) | git rev string | **REWRITTEN** ✅ → `PINNED_STANDARDS_VERSION = "=0.16.0-alpha.2"` (`miden_standards_versions` manifest parse; specificity companion updated in kind; PROVENANCE.md re-derivation path now names the registry layout + the LOGIC-copy choice) | manifest parse of the `=0.16.0-alpha.2` pin |
| `FROZEN_CALLABLE_ROOTS` path FORMAT (mint_root_surface.rs:50) | absolute `::xreserve::…` renders at assembler 0.23.3 | format re-checked at 0.25.3 | the enumeration test's own printout; membership (17 paths) is IMMUTABLE — only the string FORMAT may adapt |
| `att` family fields `packed_felts` / `expected_commitment` / `derivation` (×3 vectors, `xreserve-encoding-vectors.json`) | 9 compressed-SEC1 felts / 0.25.1 commitments | **REGENERATED** ✅ per decision 1(b) via `cargo run --bin gen_vectors --features vectors`; field-level diff verified: EXACTLY 18 changed leaves, all inside the 3 approved fields (`packed_felts` 9→16 felts ×3, `expected_commitment` ×3, `derivation` ×3); `cite`, `pubkey_hex`, `sig_hex`, `payload_hex`, `digest_hex`, `digest_felts`, `sig_felts`, `v_byte`, `id`, `tv` and EVERY other family byte-identical. Old→new commitments: att-1 `0xd697e679e5c9caad,0xcc5014ce6e6e0cfe,0x7a3a3f4fc7cb83c0,0xd8bd0bf11ad869b1` → `0xf5b91758da8d358e,0x7b725b8e11924cfd,0x2e1c72d1df5aed81,0x12ab5a3e8ea9d1b0`; att-2 `0x30383c2f…,0x1e573757…,0x7eecaf93…,0x241a5874…` → `0x23d8cdc9…,0xf0c442c8…,0xcc1e5af9…,0xd9040e50…`; att-3 `0x25b8b532…,0xf9543bfd…,0xd2deb953…,0x12523f29…` → `0xf3d46528…,0x50fa3e91…,0x2c0110a2…,0x044373b6…` | the committed generator; the commitment oracle (`PublicKey::read_from_bytes(pk33).to_commitment()`) auto-follows crypto 0.28 |

Set-shaped invariants that must survive Phase 4 UNCHANGED: 13-root note allowlist (set-equality,
both layers, factory-derived — the 13 identities may only re-key); supply-raising set exactly
`{mint}`; tx-script allowlist EMPTY. Membership changes = STOP. [SUPERSEDED 2026-07-14 → S21
flip (top amendment): the allowlist invariant is now the 12-root set — the one ratified
membership change was the `set_role_admin` note removal.]

NOT re-pin sites (protocol-independent, must NOT change): the relayer's Circle wire fixtures
(`PARTNER_PUBKEY_HEX`, `TEST_VECTOR_MESSAGE_HASH_HEX`, `TEST_VECTOR_ATTESTATION_HEX` — pure
secp256k1/keccak vectors), the entire `circle-depositintent-groundtruth.json`, and every
non-`att` family of `xreserve-encoding-vectors.json` (`aid`/`amt`/`b32`/`bn`/`di`); within the
`att` family, every field OUTSIDE the decision-1(b) list stays byte-identical.

---

## 7. MASM-level changes (every touched `.masm` = a semantic-class row; MASM skills loaded first)

| file | change | driver |
|---|---|---|
| ALL 24 repo `.masm` files | import-form rewrites where present (the 27 lines: bare item imports → `use {…} from …`; the one `->` alias → `as`); module-structure declarations as required by the 0.25 assembler | S17 (vm#3220) |
| the 17 `FROZEN_CALLABLE_ROOTS` procs across the xreserve component files (`xreserve_mint`, `xreserve_mint_note_entry`, `attestation_verify`, `attester_admin`, `burn_policy`, `deposit_intent_parser` ×3, `domain_config`, `encoding` ×4, `min_burn_admin`, `mint_deny_guard`, `pause_admin` ×2) | add `@account_procedure` to exactly these 17 | S19 (#3171) |
| `asm/standards/xreserve/xreserve_mint.masm` | `exec.faucet::create_fungible_asset` → `exec.active_account::get_id` + `exec.fungible_asset::create` (+ the new import; doc comments follow) | S3 (#3255) |
| `asm/standards/xreserve/xreserve_mint.masm:63` | re-pin the hardcoded `P2ID_SCRIPT_ROOT` felt-array const (§6 row) | Phase 4 re-pin (assembler 0.25 + #3204 p2id rewrite) |
| `asm/standards/xreserve/encoding/mod.masm` (`pubkey_commitment`) | 9-felt SEC1 staging → 16-felt affine staging (PUBKEY_FELTS const, locals plan, doc comments) | S16 (vm#3342) |
| `asm/standards/xreserve/attestation_verify.masm` | advice materialization `[PK(9),SIG(17)]` → `[PK(16),SIG(17)]`; locals re-layout; doc comments | S16 |
| `asm/standards/xreserve/xreserve_mint_note_entry.masm` | attachment word-count consts/checks 9→11 words (parity twin of the Rust consts) | S16 |
| `asm/standards/notes/xreserve_mint_note.masm` | the `->` alias import → `as` | S17 |
| `asm/standards/xreserve/mint_deny_guard.masm` | doc-comment `Inputs:` update to the ASSET_VALUE-word dispatch shape (body unchanged — `push.0 assert` never reads the stack) | S4 (#3106) |
| `asm/standards/xreserve/burn_policy.masm` | NO ABI change (burn dispatch shape identical, rename-only); comment ref `fungible_to_amount`→`fungible_asset::to_amount` | S4 / S3 |
| `asm/standards/xreserve/mod.masm` (**NEW**) | the namespace-root module declaring the library tree (`pub mod …` ×11) — the v0.25 assembler includes only modules declared this way (vm#3220); it replaces the v0.15 directory-walk assembly. Carries no procedures. | S17 |
| `asm/standards/xreserve/encoding/mod.masm` | `pub mod layout` declaration (same requirement) | S17 |
| `asm/standards/xreserve/attester_admin.masm`, `min_burn_admin.masm`, `domain_config.masm`, `deposit_intent_parser.masm`, `pause_admin.masm` | `@account_procedure` annotations + braced item-imports; `pause_admin`'s stale "is_paused is FungibleFaucet-installed" comment | S19 / S17 / S1 |
| `asm/standards/xreserve/xreserve_mint.masm:61` | `P2ID_SCRIPT_ROOT` re-pinned (the stock P2ID script changed at v16: #3204 routes note creation through `basic_wallet::create_note`) — derived from `P2idNote::script_root()` at alpha.2, old `[12857783041667862256, …]` → new `[7131697192369665042, 13614976149584716721, 15020972229364874097, 1084006998777425639]`; the failing symptom was the kernel's `before_created` event rejecting the emitted recipient note ("note script … not found in data store") | §6 re-pin |
| others | any additional forced edit gets its own row before it lands | — |

Assembler-level residual to confirm during Phase 2 (self-surfacing, mapped here in advance):
the `FROZEN_CALLABLE_ROOTS` leading-`::` path-format under the 0.25 path renderer
(mint_root_surface.rs:49 documents the 0.23.3 rendering; the enumeration test's own printout is
the derivation source if the format moved).

---

## 8. MockChain sufficiency at alpha.2 — VERIFIED (the only verification harness for this task)

Source-verified against `miden-testing-0.16.0-alpha.2` (all consumed symbols):

- `Auth::{IncrNonce, BasicAuth{auth_scheme}, NetworkAccount{allowed_script_roots,
  allowed_tx_script_roots}}` — the ONLY three variants the repo uses — structurally IDENTICAL
  (mock_chain/auth.rs:41,71,86); `Auth::NetworkAccount` still routes through
  `AuthNetworkAccount::with_allowed_notes(…).with_allowed_tx_scripts(…)` (auth.rs:173-183).
- `MockChain::builder()`, `add_existing_account_from_components` (chain_builder.rs:650-659),
  `add_existing_wallet` (:326), `add_existing_basic_faucet` (:391), `build()` (:191),
  `build_tx_context` (chain.rs:704-712), `add_pending_executed_transaction` (:946 — still takes
  `&ExecutedTransaction`), `prove_next_block` (:880) — ALL byte-compatible.
- `TransactionContextBuilder::{tx_script, extend_advice_inputs, extend_expected_output_notes,
  extend_note_args, build}` unchanged; `TransactionContext::execute` STAYS async
  (tx_context/context.rs:165) → the 23 `#[tokio::test]` files keep their shape (alpha.2's own
  kernel tests: 262 tokio vs 22 sync).
- `assert_transaction_executor_error!` — byte-identical macro (utils.rs:66-105); all 126 repo
  invocations use the MasmError form; `MasmError::matches_execution_error` unchanged.
- Precompiles: the execute path runs through miden-tx's `TransactionBaseHost`, which registers
  `CoreLibrary::default().handlers()` — including the keccak256 (`KECCAK_HASH_BYTES_EVENT_NAME`,
  core-lib 0.25.3 lib.rs:146) and ECDSA (`ECDSA_VERIFY_EVENT_NAME`, lib.rs:26) handlers —
  exactly as v15 (miden-tx host/mod.rs:123-133).
- Determinism: `TIMESTAMP_START_SECS`/`TIMESTAMP_STEP_SECS` unchanged; `verification_base_fee`
  defaults to 0 in BOTH versions, so #3108's kernel-fee removal shifts NO balance any test
  asserts.

The v15 local-node record (LNV-1..5, 12/12) stands as the v15 evidence and is not touched;
there is NO v16 node/client, so no LNV leg runs in this task.

---

## 9. Parked-items ledger

| item | why parked | what still works | re-enable trigger | re-enable steps |
|---|---|---|---|---|
| `crates/xusdc-validation` (LNV harness, rows A–L) | `miden-client` has no v16 release (only 0.15.3; protocol team 2026-07-13: node+client alpha pending) | the v15 LNV record (VALIDATION-RECORD.md, LNV-1..5, 12/12 rows) as v15 evidence; the crate builds/tests on the v15 lock outside this workspace state | the protocol team announces the v16-alpha `miden-client` (+ node) | restore `workspace.members` entry, drop the `workspace.exclude` entry, bump its manifest pins to the v16 family + client, re-run the LNV row gates |
| Client-dependent legs anywhere (submit legs, node E2E) | same | MockChain coverage (416-test encoding gate) | same | same |
| `canary/` grounding crates | non-members pinned by `path` to a v0.15.3 sibling checkout that has no v16 twin | their committed v15 grounding reports | a v16 sibling checkout decision (out of this task's scope) | separate task |

`crates/xusdc-validation/PARKED-V15.md` (Phase 2, R1) carries this ledger into the crate dir.

---

## 10. STOP items / decision items (escalate, do not improvise)

**GATE ADJUDICATION (2026-07-13, human operator via the approval bridge): ALL THREE decisions
APPROVED — none require Circle sign-off; Phase 2 authorized ("implement the map verbatim").**
Conditions attached by the operator (Round-F enforces these alongside the standing STOPs):
- S16: MAP-ROW-AS-RECORD (no `docs/governing` edit). "Circle-wire inputs byte-identical; only
  the 3 derived att fields (packed_felts, expected_commitment, derivation) regenerate;
  commitment preimage 33B to affine-16 is internal." The 9→11-word attachment cascade MUST NOT
  change the 13-root allowlist count or the `{mint}`-only supply surface; the mint-note root
  re-pins as expected. `pubkey_hex`, `sig_hex`, `payload_hex`, `digest_hex` and every other
  family stay byte-identical. (Scope note: the operator's regenerate list names EXACTLY
  `packed_felts`/`expected_commitment`/`derivation` — the `cite` field therefore stays
  byte-identical too; the 0.28/affine provenance lives in the regenerated `derivation` string.)
- S2: ADMIN resolves to the owner (NO new capability); owner-only-setter + role-gating tests
  green; NO new allowlisted note.
- S18: approved as-is, revise nothing; Round-F confirms (1) production still rejects AllowAll
  (`MissingBurnPolicyGuard` + the unchanged builder_api reject test), (2) production still
  registers the real `burn_policy::check_policy` (`BURN_POLICY_PROC_PATH` unchanged), (3)
  deny-guard `{mint}`-only semantics unchanged.
- An informational FYI to Circle about the internal attestation-repr change is handled by the
  operator OUTSIDE this loop; it is not a gate.

**The three decisions as put to the gate (retained for the record; all APPROVED above):**

1. **S16 — one decision, two inseparable halves (vm#3342):**
   (a) **DC-2/DC-3 governed-contract supersession:** approve the v16 supersession of the
   ownership map's pinned shapes — DC-2 staging 33B/9-felt → 16 affine felts (attachment 9→11
   words), DC-3 `Poseidon2(33B)` → `Poseidon2(affine 16 felts)` — with the Circle ingress
   format staying 33-byte compressed SEC1 and boundary OWNERSHIP unchanged (04 staging / 01
   verify). `docs/governing/` stays UNEDITED; on approval this map row is the binding
   supersession record (or direct a governing addendum — human's choice).
   (b) **att-vector regeneration, field-complete scope:** regenerate ONLY `packed_felts`
   (9 compressed felts → 16 affine felts), `expected_commitment`, and `cite`/`derivation` of
   the 3 `att` vectors via the committed generator — together with the `AttVector` doc, the
   generator's att packing, and TV-DUAL-5's staging — while `id`, `tv`, `pubkey_hex`,
   `payload_hex`, `digest_hex`, `digest_felts`, `sig_hex`, `sig_felts`, `v_byte` and ALL other
   families stay byte-identical (no exception exists for them). Without (a)+(b) the migration
   CANNOT reach green without violating the golden-vector/governing rules → hard STOP.
2. **S2 / RBAC ADMIN seed:** approve the proposed `ADMIN`={owner-held account} seed + the
   documented ownership-rotation runbook divergence (or STOP for Circle guidance).
3. **S18 / policy-manager single-install algorithm + override API + test oracles:** approve
   the PINNED design (S18 steps 1-6 — companion-drop with exact-shape assertion
   `PolicyCompanionMismatch`, error-variant mapping, v15-adjacent component order — PLUS the
   pinned public policy-override API replacement: `Option<MintPolicy>`/`Option<BurnPolicy>`
   fields, the re-typed `with_active_mint_policy(MintPolicy)`/`with_active_burn_policy(BurnPolicy)`
   methods, clone-based resolution with fallible default construction, unchanged root-first
   `MissingMintDenyGuard`/`MissingBurnPolicyGuard` semantics, the two builder_api call-site
   updates — PLUS the pinned oracle-helper migrations: `oracle_components` /
   `oracle_burn_components` rebuilt on `MintPolicy::custom`/`allow_all` +
   `allowed_{mint,burn}_policy` with code-identity preserved, the now-REQUIRED
   `active_burn_policy(BurnPolicy::allow_all())` on the mint oracle as a mapped harness-only
   delta, oracle-shaped seam assertions, and `Pausable::unpaused()` in both helpers). Fully
   specified against the alpha.2 source; Phase 3 implements it verbatim.

**4. S21 (surfaced in Phase 3, not at the original gate) — RATIFIED 2026-07-13 (operator):** the
   v16 `set_role_admin` authority model is approved as pinned — DOM_MANAGER holds Pauser-admin and
   may re-delegate; the owner's DIRECT call is correctly rejected (`ERR_SENDER_NOT_ROLE_ADMIN`);
   the owner retains authority via owner→ADMIN→DOM_MANAGER→DOM_PAUSER, and its backstop is
   unbreakable (DOM_MANAGER's admin resolves to ADMIN = the owner). See the S21 row for the full
   ratification text and the pinned test list.

**Standing STOP conditions (unchanged):**

4. Any test passable only by an assertion change NOT covered by a row here.
5. **The 13-root allowlist count [SUPERSEDED 2026-07-14 → S21 flip (top amendment): now the
   12-root count], the `{mint}`-only supply surface, or the empty tx-allowlist
   cannot be preserved exactly as shaped — OR ANY STOCK-COMPONENT CALLABLE-SURFACE CHANGE
   (a new/removed exported-and-callable procedure from any stock component) is observed.**
   The full-account callable surface is FROZEN as a literal set in
   `tests/account_callable_surface.rs`; a stock bump that grows or shrinks it fails that test.
   Such a delta is a CAPABILITY change (a new callable root the account did not have) and MUST be
   SURFACED FOR RATIFICATION — it may NOT be self-sanctioned under "mechanical conformance" or
   waved through as "just a stock re-export". This is the **stock-surface discipline** (§4a).
   The v16 additions surfaced and human-ratified this way, EACH under its OWN row (not folded
   into another's): `freeze`/`unfreeze` (**S12**); `has_procedure` (**S13**, #3222);
   `get_authority` + `invoke_send_policy` + `invoke_receive_policy` (**S24**, #3102/#3047). Any
   FURTHER change re-opens the ratification.
6. A consumed API with NO alpha.2 equivalent — discovery CLOSED with none found: every ⏳ row
   resolved to a verified equivalent (§4, §5, §8).
7. Anything besides `miden-client`'s graph needing `miden-tx-batch-prover` — disproven by the
   R2 reverse-dep evidence (miden-testing moves to the renamed, published `miden-tx-batch`).
8. Any OTHER golden-vector test (the Circle-wire families `aid`/`amt`/`b32`/`bn`/`di`, or the
   DepositIntent ground-truth file) failing byte-identically = Circle-compat break, hard STOP
   (unlike item 1, no regeneration is proposable for these).
9. N1D sole-burn-caller failing on the alpha.2 stock source at re-vendor time (S9e).

---

## 11. Count parity (Phase 5)

| suite | v15 (this map §2.2) | v16 | delta explanation |
|---|---|---|---|
| xusdc-encoding --release | 416 / 0 / 0 | **430 / 0 / 0** ✅ (exit 0) | v16 total = **430** = 416 + 14 NET NEW tests (4 in rounds 1-5, 3 in the round-6 audit, 6 in the round-8 S12 deliverable, 1 in the round-9 S24 ratification) — all mapped, all ADDITIVE (no test removed, no assertion weakened; the deleted-test sweep is EMPTY): `invalid_pubkey_rejects` (S16 — the SEC1→affine decompression seam fail-closes on an off-curve key), `aid_low_byte_traps_protocol_low_byte` (S23 — keeps the protocol low-byte assertion alive after the upstream check re-ordering), `grant_role_owner_on_delegated_role_traps` (S2/S21 — the owner's direct grant on the delegated role now traps), `set_role_admin_dom_manager_can_redelegate_pauser` (S21 — pins the upstream capability change as a POSITIVE), plus THREE added by the round-6 audit: `production_composition_installs_one_xreserve_and_one_manager` + `seam_rejects_a_smuggled_foreign_policy_companion` (S18 — the composition-shape and anti-smuggling proofs the row mandated but the round-5 implementation had not written) and `owner_can_revoke_dom_manager_cutting_the_delegation_chain` (S21 — kept as an additive proof when the full-chain `owner_can_still_revoke_pauser` was restored). PLUS SIX added by the round-8 S12 deliverable — the new `tests/account_callable_surface.rs`: `production_account_callable_surface_is_frozen`, `authority_freeze_and_unfreeze_are_present_on_the_account`, `freeze_and_unfreeze_are_unreachable_from_every_allowlisted_note`, `freeze_and_unfreeze_are_not_admissible_via_either_allowlist`, `the_auth_component_rejects_a_non_allowlisted_note`, `the_auth_component_rejects_any_tx_script_via_the_empty_allowlist` (S12 — the full-account callable-surface pin + the freeze/unfreeze present-but-unreachable proof); AND ONE added by the round-9 S24 ratification in the same file — `invoke_wrappers_are_inert_and_the_asset_stays_basic` (S24 — confirms the #3047 invoke_* wrappers' presence did NOT register a transfer policy or flip `AssetCallbackFlag::Disabled`; F4 intact). Renames (not count deltas): `aid_rej_non_canonical_traps_protocol_low_byte`→`…_protocol_version` (S23), `set_role_admin_dom_manager_rejects`→`set_role_admin_owner_direct_rejects` (S21), `owner_set_role_admin_controls_delegation`→`owner_reaches_set_role_admin_through_dom_manager` (S21). |
| xreserve-deposit-relayer | 197 / 0 / 0 | **197 / 0 / 0** ✅ | EXACT parity (the relayer's only migration surface is the S16 fallible `pubkey_commitment` at two fixture sites) |
| xusdc-validation | 159 / 0 / 5 | (parked; not run) | R1 — the whole suite leaves the workspace gate |
| fmt / clippy | clean / clean | **clean / clean (both exit 0)** ✅ | clippy surfaced two real findings in NEW migration code (a `vec_init_then_push` in the S18 composition seam and a now-`useless_conversion` `Word::from` in the S16 commitment — crypto 0.28's `hash_elements` already yields a `Word`); both were FIXED at the source, never `allow`-silenced |

### Verification transcript (Phase 5, all gates run `--locked --offline` against the regenerated lock)

```
cargo build  --locked --workspace                         → exit 0
cargo test   --locked -p xusdc-encoding --release         → exit 0   430 passed / 0 failed / 0 ignored
cargo test   --locked -p xreserve-deposit-relayer         → exit 0   197 passed / 0 failed / 0 ignored
cargo fmt    --all -- --check                             → exit 0   (clean)
cargo clippy --workspace --locked -- -D warnings          → exit 0   (clean)
```

> **Gate-harness correction (round 6).** The round-5 transcript reported `cargo fmt` GREEN when it
> was in fact RED: the gate script piped `cargo fmt --all -- --check` into `head`, and the exit
> code that reached `PIPESTATUS` was not rustfmt's. The audit caught it. Every gate above is now
> captured by running the command to a file and reading `$?` DIRECTLY — no pipes in the exit path.
> The tree is genuinely rustfmt-clean (verified against the v15 base, which is itself clean under
> rustfmt 1.97, so every reformatted line was migration-introduced).

No-weakening sweep (the exact commands from the task's verification section):

```
git diff implementation -- 'crates/**/tests/**' 'crates/**/src/**' | grep -E '^\-.*#\[(tokio::)?test\]'
    → EMPTY (no test deleted)                                        ✅
grep -rn "#\[ignore" crates/ --include="*.rs" | wc -l  → 10 (baseline 10; ALL in the parked
    crates/xusdc-validation/tests/rows_*.rs — none added elsewhere)  ✅
grep -rn "todo!\|unimplemented!" crates/ --include="*.rs" | wc -l → 0 (baseline 0)  ✅
grep -rn '681fc905' <member manifests>  → the only hits are PROSE inside the R2 removal-rationale
    comment in the root Cargo.toml; ZERO git-source dependency lines remain                    ✅
grep -rn 'miden-client' <member manifests> → likewise prose-only (the R1/R2 rationale)         ✅
```

Golden-vector byte-stability (mechanically diffed field-by-field, not eyeballed):
`circle-depositintent-groundtruth.json` → **0-line diff**. `xreserve-encoding-vectors.json` →
changed FAMILIES = `{att}` only; changed FIELDS = `{packed_felts, expected_commitment,
derivation}` only — EXACTLY the §10 decision-1(b) scope. `pubkey_hex`, `sig_hex`, `payload_hex`,
`digest_hex`, `digest_felts`, `sig_felts`, `v_byte`, `id`, `tv`, `cite` and every other family:
byte-identical.

Tripwire spot-proofs (all green in the 430): `production_components_carry_is_paused_slot` (S1),
the 13-root allowlist set-equality at BOTH layers with the new roots,
`production_supply_raising_root_set_is_exactly_mint` (now ALSO asserting root-level set-equality
against the FILTERED `@account_procedure` interface — S19), the FULL-ACCOUNT
`production_account_callable_surface_is_frozen` + the five freeze/unfreeze unreachability proofs
(S12 — the composed account's 17 + 45 callable procs frozen at both layers; freeze/unfreeze
present but inadmissible via either entry vector; `invoke_wrappers_are_inert_and_the_asset_stays_basic` — S24, the #3047 invoke_* wrappers left F4 and the callback flag untouched), `basic_asset_tripwire` (no transfer
policy appeared), `pinned_standards_single_faucet_burn_caller` + `…_single_supply_decrement_write`
(N1D re-verified on the re-vendored alpha.2 fixtures), `dom_pauser_pause_halts_mint` + the
burn-paused reject + the F6 owner-setters-while-paused semantics, the mint-deny suite (production
still rejects `AllowAll` with `MissingBurnPolicyGuard`; `BURN_POLICY_PROC_PATH` unchanged; the
deny-guard `{mint}`-only surface intact — the operator's three S18 conditions).

---

## 12. ALPHA CAVEAT

`0.16.0-alpha.2` is a PRE-RELEASE: APIs may still move before v0.16.0 final. This map is a LIVING
document — a later alpha.3/final bump re-runs a lighter pass of this task (pin ledger refresh,
re-pin re-derivation, delta review), reconciling against this map rather than restarting
discovery. The `DEV-*`/`Q-*` Circle-owned items remain OPEN throughout (nothing in this migration
resolves or approves any of them); `docs/governing/V15-DEVNET-BASELINE.md` remains the v15
ledger of record and is superseded FOR THIS BRANCH by §1 only.
