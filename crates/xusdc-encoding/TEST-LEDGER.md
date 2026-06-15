# 04 Shared-Encoding TEST LEDGER

Loop records per the approved plan §10/§11. Phase: **R4 COMPLETE — FULL SLICE GREEN (37/37)** — red-suite + R1 + R2 + R3 audited/accepted; R4 implemented; every in-scope TV row passes; awaiting final audit.

## R5 — DEV-10 AccountId→bytes32 layout revision to R-B / Agglayer-mirroring (2026-06-15; human-authorized; GREEN)

Post-acceptance layout supersession (`P5-04-SHARED-ENCODING-ACCEPTANCE-RECORD.md §1b`): the human selected the **R-B / Agglayer-mirroring** AccountId→bytes32 packaging, replacing the accepted left-aligned draft. This is the separate builder-gated **code+vector** revision that §1b deferred.

**Before → after (`account_id_to_bytes32`):** left-aligned `out[..15] = id.to_bytes()` (8 BE prefix + 7 BE suffix), `[15..32]=0` → **R-B** `out[16..24] = prefix().as_u64() BE`, `out[24..32] = suffix().as_canonical_u64() BE`, `[0..16]=0` (full 8-byte suffix). Inverse now validates a zero leading-16 pad (`AccountIdOutOfRange`) then `Felt::try_from` + `AccountId::try_from_elements(suffix, prefix)` (`NonCanonicalAccountId`) — mirrors `miden-agglayer/.../eth_embedded_account_id.rs:86-96,:117-122`. `account_id_to_felts` unchanged (layout-independent).

**Scope:** `account_id.rs` (impl + docs), `gen_vectors.rs` (R-B inline derivation `r_b_bytes32`, kept independent of the crate mirror; aid round-trip + both rejects regenerated; `recipient_b32` for the di family), regenerated `xreserve-encoding-vectors.json`. NO MASM AccountId proc (D-5 in force). Faucet MASM untouched. `remoteToken` di field is a synthetic pattern (unaffected); only `remoteRecipient` (AccountId-encoded) regenerated, so the di preimages change.

**Vector deltas:** aid valid ids now occupy bytes 16..31 (zero pad 0..15; suffix LSB at 31 = 0 per the always-zero suffix byte); `aid-rej-out-of-range` = byte[0] set in the leading pad; `aid-rej-non-canonical` = zero pad + prefix=suffix=7 (in-field, rejected by `try_from_elements`, generator-asserted). Artifact 77296 bytes.

| Command | Result |
|---|---|
| `cargo run --bin gen_vectors` | wrote artifact; R-B invariant asserts passed (`try_from_elements(7,7)` rejects) |
| `cargo build --locked` | clean |
| `cargo test --locked --test constant_parity` | 4 passed |
| `cargo test --locked --test masm_dual` | 7 passed |
| `cargo test --locked --test masm_mint_shell` | 11 passed (faucet alignment-agnostic — green against R-B vectors) |
| `cargo test --locked --no-fail-fast` | **50/50** (lib 28, parity 4, masm_dual 7, masm_mint_shell 11) |

**DEV-10 / Q-CRY-3 / Q-CRY-4 remain OPEN** — R-B is a revised proposal to Circle (`REQUIRES CIRCLE CONFIRMATION`, `NO EVIDENCE OF CIRCLE APPROVAL`), not an approval. Awaiting independent audit; faucet Phase B re-verification remains separately gated.

## R4 — DepositIntent layout + parser (2026-06-12, approved start; GREEN)

Pre-change baselines: 11 DI tests RED (`unimplemented!()` + sentinel offsets), parity ×2
RED, `tv_dual_3` RED via the named parser placeholder — all expected reasons.

**Pinned-source facts driving the implementation:** word memory ops trap on unaligned
addresses (`UnalignedWordAccess`, processor errors.rs:228-232) and the DC-1 felt offsets
are mostly odd ⇒ the parser AND the driver layout-asserts use single-felt `mem_load`s.
`push.{Word}` leaves element 0 on top (proven by the staging round-trip + the one
word-order failure below) ⇒ the parser pushes each output word highest-index felt first.
Packed compare constants: magic `0xcd0a2e5a` = u32-LE reinterpretation of BE `5a2e0acd`;
version `0x01000000` (both already pinned by the artifact's preimage felts).

| # | Step | Result / classification | Action |
|---|---|---|---|
| 1 | Rust: real DC-1 constants + offsets table + `parse_deposit_intent_header` (order: truncation guard → magic → version → amount/localToken/localDepositor nonzero → u64 length relation) + `deposit_intent_to_packed_felts` (validate, pack via `bytes_to_packed_u32_elements`, 1024-felt bound → `HookDataTooLarge`) | **PROCESS SLIP, caught immediately and disclosed:** the full-file rewrite momentarily dropped the `tests` module; detected by grep before any test run, restored BYTE-FOR-BYTE (same names, cases, assertions — verified `11 passed`) | tests restored verbatim; net diff to tests = none |
| 2 | focused Rust run | **11/11 green first pass** | — |
| 3 | `layout.masm` real values + `mod.masm`: ERR_DI_* consts (string-identical to Rust), placeholder const/body removed, parser body + `field8_is_nonzero` helper; driver layout-asserts switched to single-felt loads (alignment); `probe_p3` DELETED (mandated — last placeholder gone) | parity: **2/2 green** | — |
| 4 | `tv_dual_3` first run | accepts reached the OUTPUT asserts: structural checks + `remote_domain` correct; `remote_token_1` mismatch = word-orientation (push.{Word} = element-0-on-top, my pushes were reversed). Class: R4 implementation bug | RT words now pushed highest-index-first (element-0-on-top orientation) |
| 5 | `tv_dual_3` re-run | **1 passed** — 2 accepts (D-4A stack contract + all 12 fields' per-felt layout asserts post-exec ⇒ staged memory unmutated) + 8 MASM rejects with exact `ERR_DI_*` (incl. the MASM-only `di-rej-felt-len`; truncation hits the len-guard branch — the byte-level TruncatedHeader analogue — sharing the frozen `ERR_DI_LENGTH`) | — |
| 6 | full dual + full suite | masm_dual **7/7**; workspace **37/37 green** (lib 28, parity 2, masm_dual 7; doc-tests 0) | — |

Final sweeps: exactly ONE proc definition per canonical home (`mod.masm:64/96/189`);
zero `bytes32_to_storage_map_key` in MASM (NS-1); one Rust impl per routine; no
`#[ignore]`; exactly 1 vector artifact. Containment: this phase wrote `mod.masm`,
`layout.masm`, `deposit_intent.rs`, `masm_dual.rs`, `lib.rs` (+ this ledger); the
artifact (Jun 11 20:14), `constant_parity.rs`, unit-test modules, and `Cargo.lock`
untouched. Deferred families (burn-note, attestation, Circle JSON/binary) untouched.

## R3 — AccountId ↔ bytes32 (2026-06-12, approved start; GREEN; D-5 in force — no MASM)

Pre-change filtered run confirmed the placeholder RED (4 × `unimplemented!()` at
`account_id.rs:26` + the sentinel `0 ≠ 232`).

**Semantics pinned from source before implementing:** 15-byte layout =
`[..8] = prefix.as_u64().to_be_bytes()`, `[8..15] = suffix.as_canonical_u64().to_be_bytes()[..7]`
(the suffix's always-zero last byte omitted) — `v1/mod.rs:300-308` (E-10 confirmed);
deserialization validates canonicity (`v1/mod.rs:388-394` → `AccountIdError`, prefix
rules at `:400`); `AddressType::AccountId = 232 = 0b1110_1000` (`address/type.rs:19,:24`,
E-11). `AccountId::SERIALIZED_SIZE = 15` (`mod.rs:101`).

| # | Step | Result |
|---|---|---|
| 1 | focused RED baseline | placeholder/sentinel reasons confirmed |
| 2 | implement `account_id.rs` only: const 232; `to_bytes()` into zero-padded `[u8;32]`; padding-region check → `AccountIdOutOfRange`, then `read_from_bytes(&b[..15])` → `NonCanonicalAccountId` (frozen unit variant cannot carry `AccountIdError` — recorded conflict); `[prefix().as_felt(), suffix()]` | `cargo build --locked` clean; focused: **5/5 green first pass** |
| 3 | `cargo test --locked --no-fail-fast` | lib `17 passed; 11 failed` (green = B32×4 + AMT×7 + AID×5 + artifact_guard; ALL 11 red = TV-DI-*) · parity `0 passed; 2 failed` (R4 sentinels/missing `ERR_DI_*`) · masm_dual `7 passed; 1 failed` (only `tv_dual_3`, R4 placeholder) — exactly the task's expected shape; R1/R2 stayed green |

Containment (mtimes): ONLY `account_id.rs` written this phase (2026-06-12 13:40); MASM
files, vectors, all test files, `deposit_intent.rs`, and `Cargo.lock` carry prior-phase
timestamps. No MASM `account_id.masm` created (D-5).

## R2 — uint256 → AssetAmount (2026-06-11, approved start; GREEN)

Pre-change filtered runs confirmed the placeholder RED (TV-AMT tests panicking at the
`unimplemented!()` lines; `tv_dual_2` trapping with the named uint256 placeholder).

**Semantics resolved from pinned source before implementing:** the E-16 model proc ships
in the pin — `crates/miden-agglayer/asm/agglayer/common/asset_conversion.masm`
(`verify_u256_to_native_amount_conversion`): it is a VERIFIER (caller supplies the
quotient), which our frozen contract (`[U1, U0, scale_exp] → [y]`, computational, 04:311-316)
cannot adopt; its byte-swap (`swap_u32_bytes`), `pow10` (u32-guarded, ≤18), limb
conventions, and `FUNGIBLE_ASSET_MAX_AMOUNT` import were adapted. Division: core-lib
`miden::core::math::u128::divmod` (u128.masm:1516; advice-backed `U128_DIV_EVENT`,
self-verifying q·b + r = a with r < b) — its host handler is registered by default by the
transaction executor (`miden-tx/src/host/mod.rs:117-126` registers all
`CoreLibrary::handlers()`), so it executes under MockChain with no wiring.
`FUNGIBLE_ASSET_MAX_AMOUNT = 0x7fffffff80000000 = 2^63 − 2^31 = AssetAmount::MAX`
(`shared_utils/util/asset.masm:16`; `asset_amount.rs:30`) — imported as the SINGLE cap
source (no local cap constant; constant parity by construction). Cap compared in u64
limb space BEFORE composing the output felt (a quotient in [p, 2^64) would wrap a felt
compose). `u64::lte` stack contract `[b_lo, b_hi, a_lo, a_hi] → a ≤ b` (u64.masm:244).

| # | Step | Result / classification | Action |
|---|---|---|---|
| 1 | focused RED baselines | placeholder reasons confirmed | — |
| 2 | implement Rust (`amount.rs`: shared `reduce` core + 3 public fns, checked arithmetic) + MASM (guards → high-zero `word::eqz` → byte-swap ×4 → `word::reverse` → `pow10`+`u32split` divisor word → `u128::divmod` → drop remainder → q2/q3 `assertz` + `u64::lte` cap vs imported MAX → compose felt) | `cargo test --locked -p xusdc-encoding amount`: **7/7 R2 tests green first pass** (one FAILED in the filter = `tv_di_…zero_amount`, an R4 placeholder string-matched by the loose filter — planned red) | — |
| 3 | `tv_dual_2` first run | all accepts + 3 rejects passed; LAST vector `amt-guard-limb-not-u32` failed the ASSERTION MECHANICS: `u32assertw` traps surface as `OperationError::U32AssertionFailed` (processor errors.rs:310-324), not `FailedAssertion`, so `MasmError::matches_execution_error` (masm_error.rs:41-58) returns false BY DESIGN. The MASM behavior itself was correct (named message + offending limb in the output). Class (c) harness mechanics | guard-vector arm now pins the SAME named error on the CORRECT variant: `matches ExecutionError::OperationError { err: U32AssertionFailed { err_code, err_msg, .. }, .. } if code+message == ERR_FELT_OUT_OF_FIELD` — full strength, no broadening. Added `miden-processor = "=0.23.3"` dev-dep (same version the lock already resolves) ⇒ one-time `cargo build --offline` lock update (new direct edge only; pins re-verified 0.23.3/0.25.1) |
| 4 | `tv_dual_2` re-run | **`1 passed; 0 failed`** — 5 accepts (incl. cap boundary == MAX exactly), `ERR_X_TOO_LARGE`/`ERR_AMOUNT_OVER_CAP`/`ERR_SCALE_EXP_TOO_LARGE` exact, u32-guard pinned | — |
| 5 | `cargo test --locked --no-fail-fast` | lib `12 passed; 16 failed` · parity `0 passed; 2 failed` · masm_dual `7 passed; 1 failed` — **green delta vs R1 state = exactly the 8 R2 tests**; R1 stayed green; every red re-classified: TV-AID ×5 = R3 placeholders/sentinel, TV-DI ×11 + `tv_dual_3` = R4 placeholders/sentinels, parity ×2 = R4 reasons (offset-relation sentinel `3604 ≠ 800`; first missing ERR const now `ERR_DI_BAD_MAGIC` — the four R2 ERR consts present and string-identical) | — |

**Harness retarget (disclosed for audit):** `probe_p3_placeholder_trap_surfaces` was
pinned to the uint256 placeholder that R2 legitimately removes; it now targets the LAST
remaining placeholder (`parse_deposit_intent`) with the identical exact-error assertion.
When R4 removes the final placeholder, this probe's red-suite purpose is fully served and
it should be DELETED in the R4 change (pre-flagged here for that audit). No TV test or
vector was touched (mtime evidence: artifact 20:14, unit-test modules/`constant_parity.rs`
/`layout.masm` 19:2x–19:33 — all pre-R2; this turn wrote only `mod.masm`, `amount.rs`,
`masm_dual.rs` (probe + guard arm), `Cargo.toml`, `Cargo.lock`).

## R1 — bytes32 → Word (2026-06-11, approved start; GREEN)

Pre-change filtered runs confirmed the placeholder RED (4 lib tests panicking at the
`unimplemented!()` lines; `tv_dual_1` trapping with "red-suite placeholder: bytes32_to_key
is not implemented").

**Semantics resolved from pinned source before implementing** (no ambiguity remained):
`miden-crypto-0.25.1/src/hash/algebraic_sponge/mod.rs` — `hash_elements` over exactly 8
felts sets capacity[0] = `8 % 8 = 0` (all-zero capacity), absorbs the 8 felts as
rate[0..8], applies ONE permutation, digest = rate word 0 ⇒ **identical to
`merge([w0, w1])`**; `miden-core-lib-0.23.3/asm/crypto/hashes/poseidon2.masm:500-512` —
`pub proc merge`: `Inputs: [A, B]`, `C = Poseidon2(A || B)`, body = native `hmerge` (top
word = first rate word). Frozen contract (`04:263-268`): Inputs `[B1, B0]`,
`KEY = hash_elements(B0 || B1)` ⇒ body = `swapw hmerge`.

| Change | Content |
|---|---|
| `asm/.../encoding/mod.masm` | `bytes32_to_key` body: placeholder trap → `swapw` (`# => [B0, B1]`) + `hmerge` (`# => [KEY]`); removed the now-unused `ERR_UNIMPLEMENTED_BYTES32_TO_KEY`; header BUILD STATE updated. Doc block UNCHANGED (the approved contract). |
| `src/.../encoding/bytes32.rs` | `bytes32_to_packed_felts` = `bytes_to_packed_u32_elements(b).try_into()` (length type-guaranteed); `bytes32_to_storage_map_key` = `StorageMapKey::new(Hasher::hash_elements(&felts))`; `bytes32_to_word_lossless` = `Word::try_from(*b).map_err(|_| LimbOutOfField)` (frozen unit variant cannot carry the `WordError` source — preserve-error-source conflict recorded, frozen wins). |

| Command | Result |
|---|---|
| `cargo build --locked` | `Finished` (exit 0) |
| `cargo test --locked -p xusdc-encoding bytes32 -- --nocapture` | lib: `4 passed; 0 failed` (TV-B32-1..4); masm_dual name-match: `tv_dual_1` `1 passed` |
| `cargo test --locked -p xusdc-encoding --test masm_dual tv_dual_1_bytes32_to_key -- --nocapture` | `1 passed; 0 failed` — MASM executed against all 4 `b32-*` vectors, keys equal |
| `cargo test --locked --no-fail-fast` | lib `5 passed; 23 failed` · parity `0 passed; 2 failed` · masm_dual `6 passed; 2 failed` — **green delta vs red-suite baseline = exactly the 5 R1 tests**; every remaining RED re-classified: TV-AMT-* + `tv_dual_2` = R2 placeholders (`unimplemented!()` / `ERR_UNIMPLEMENTED_UINT256…` trap), TV-AID-* = R3 placeholders + sentinel (0 vs 232), TV-DI-* + `tv_dual_3` = R4 placeholders + sentinel offsets, parity ×2 = R4/R2 sentinels + ERR consts missing. No unexpected failures; no test/vector touched. |

`harness_detects_wrong_vector` now exercises the REAL mismatch path (wrong expected vs
computed key → in-script `assert_eqw` trap) and stays green.

---
Human decisions in force: **D-1: A** (proc bodies in `encoding/mod.masm`; `layout.masm` separate) ·
**D-2: yes** (string `MasmError` constants) · **D-4: A** (bounded parser output contract) ·
**D-5: yes** (no `account_id.masm`; AccountId Rust-primary).

## Red-suite loop iterations (run → classify → fix → re-run)

| # | Command | Result | Classification | Fix (phase-local only) |
|---|---|---|---|---|
| 1 | `cargo build` (sandboxed) | registry-cache writes blocked (`Operation not permitted` under `~/.cargo`) | (b) infrastructure | re-run unsandboxed (the documented grounding-spike condition) |
| 2 | `cargo build` | 5 errors in `gen_vectors` | (b) infrastructure | `Serializable` → `miden_protocol::utils::serde::Serializable`; `Felt::as_int()` → `as_canonical_u64()` (inherent at miden-field 0.25.1) |
| 3 | `cargo build` | `Finished`, exit 0 (1 unused-import warning) | green | removed the unused import |
| 4 | `cargo run --bin gen_vectors` | `wrote …/xreserve-encoding-vectors.json (77232 bytes)`; all generator invariants held (cap arithmetic, 15-byte AccountId serialization, non-canonical candidate verified rejected) | green | — |
| 5 | `cargo test --no-fail-fast` | masm_dual test target: 10 compile errors | (b) infrastructure | `Felt::new` is FALLIBLE at miden-field 0.25.1 → use `miden_protocol::{ZERO, ONE}`; `LibraryExport` is an enum → `e.as_procedure()` + `e.path().to_string()` |
| 6 | `cargo test --no-fail-fast` | 38 tests discovered; lib 1/28 pass, parity 0/2, masm_dual 3/8 (P1+P3 unexpectedly red) | P1/P3 = (c) wrong-reason | P1: exports render as ABSOLUTE paths (`::xreserve::…`) — expected form fixed. P3: **identical placeholder bodies dedupe to ONE MAST root**, mis-attributing trap messages → each stub got a distinct discriminant (`push.N drop`) so every proc owns its root |
| 7 | `cargo test --test masm_dual` | tv_dual_3 driver fails to COMPILE: `mem_storew` REMOVED at assembler 0.23.3 | (b) infrastructure | driver staging → `mem_storew_le` / `mem_loadw_le` (the 0.23 endian-suffixed forms; felt-order of the asymmetric storew→mem_load mapping is mechanically verified by the TV-DUAL-3 layout asserts when R4 goes green — flagged for R4) |
| 8 | `cargo test --test masm_dual` | tv_dual_3 driver: `push.layout::CONST` invalid syntax | (b) infrastructure | constants are imported INDIVIDUALLY (`use xreserve::encoding::layout::MAGIC_FELT_OFF`; protocol single-const import style, report §2.3) and pushed unqualified |
| 9 | `cargo test --locked --no-fail-fast` | **exit state = the red-suite target** (table below) | all (a) expected RED + allowed scaffolds | — |

## Final red-suite state (iteration 9, `cargo test --locked --no-fail-fast`)

| Binary | Result | Breakdown |
|---|---|---|
| `--lib` (unit tests) | `1 passed; 27 failed` | 27 × expected RED: 25 via `unimplemented!()` placeholder panics; `tv_di_9_offsets_table` via sentinel mismatch (`left: 800, right: 0`); `tv_aid_3` via sentinel (`left: 0, right: 232`). Green: `vectors::tests::artifact_guard` (allowed scaffold) |
| `--test constant_parity` | `0 passed; 2 failed` | `masm_rust_constant_parity`: sentinel relation failure; `masm_rust_error_string_parity`: "encoding/mod.masm must define const ERR_X_TOO_LARGE" (missing implementation behind the test boundary) — both expected RED |
| `--test masm_dual` | `5 passed; 3 failed` | RED (connected, per-routine named traps surfaced through REAL VM execution): `tv_dual_1` → "assertion failed with error message: red-suite placeholder: bytes32_to_key is not implemented"; `tv_dual_2` → "…uint256_to_asset_amount is not implemented"; `tv_dual_3` → "…parse_deposit_intent is not implemented". Green (allowed scaffolds): `probe_p1_exports` (canonical flat paths exported — **D-1A empirically validated**), `probe_p2_script_executes`, `probe_p3_placeholder_trap_surfaces` (exact-error macro matches the named placeholder), `probe_p4_packing_util`, `harness_detects_wrong_vector` (a wrong expected value FAILS execution) |
| doc-tests (×2) | `0 passed; 0 failed` | none |

No dependency-resolution, syntax, missing-file, missing-vector, skipped-test, or test-discovery failures remain. No `#[ignore]`. Zero real routine logic implemented.

## Pin + containment evidence (this phase)

- `grep -A1 'name = "miden-core-lib"' Cargo.lock` → `0.23.3`; `miden-assembly` → `0.23.3`; `miden-crypto` → `0.25.1`. `cargo build --locked` → `Finished` (exit 0). Worktree `protocol-pin-v0.15.3` @ `681fc9058`; the user's protocol checkout untouched (`2ef805632`).
- `find … -name '*vector*.json' -not -path '*/target/*'` → exactly **1** (the canonical artifact). (Bare `find` also matches 3 cargo fingerprint files under gitignored `target/` named after the `gen_vectors` bin — the final-gate sweep must exclude `target/`.)
- `git status --short --untracked-files=all -- ai-tasks/circle-integration/09-implementation project-template frontend-template` (agentic-template) → empty.
- `find 06-…specs 07-…readiness -newer <builder task>` listed `READINESS-STATUS.md` + `HUMAN-FINALIZATION-PACKET.md` — **not touched this phase**: their mtimes are byte-identical to the builder task file's own (`Jun 11 18:07:01`, the pre-session sync batch), >1 h before this phase's first write (`19:18`). This phase wrote only under `xusdc-miden/` (+ the plan file and this ledger).

## Notes for routine phases (R1/R2/R4)

- MAST dedup: keep placeholder/real bodies structurally distinct while any placeholder remains.
- `mem_storew_le`/`mem_loadw_le` felt-order vs per-felt `mem_load` addressing: confirmed mechanically by the TV-DUAL-3 layout asserts the moment R4 implements the parser — if the order is reversed, fix the DRIVER staging direction (vector semantics are canonical per C-10 and do not move).
- Library exports render absolute (leading `::`) — relevant for any future export checks.
