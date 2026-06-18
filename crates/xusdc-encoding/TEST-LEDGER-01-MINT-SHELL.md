# 01 Faucet Slice 1 — Mint-Precondition Shell TEST LEDGER

Loop records per the approved P5-01 plan. Phase: **IMPLEMENTATION COMPLETE — FULL SLICE
GREEN (50/50)** — red-suite (C3+C4) audited PASS, then staged behavior-by-behavior
implementation (C5a→C5b→C5c), each stage canary-first + focused + full suite. Awaiting
final Codex audit.

## Implementation loop (C5a → C5b → C5c, 2026-06-12; approved staged plan)

Every stage ran, in order: (1) `cargo test --locked --test masm_mint_shell -- --exact
probe_slot_binding --nocapture` (canary) → `1 passed`; (2) the focused shell suite;
(3) `cargo test --locked --no-fail-fast` (04's 37 + parity 4 stayed green throughout).

| Stage | Change (MASM + same-commit parity rows) | Focused result | RED remainder (named trap) |
|---|---|---|---|
| C5a `e329c6b` | placeholder → `exec.encoding::parse_deposit_intent` route + `ERR_UNIMPLEMENTED_DOMAIN_COMPARE` trap (distinct discriminant 502) | **`7 passed; 4 failed`** — r_mint_1..5 GREEN with exact `ERR_DI_*` THROUGH the shell call path (ratified seam mapping executed) | happy ×2 + r6 + r7 on "domain compare is not implemented" — the happy failure point advanced past parsing |
| C5b `41eebc7` | + `DOMAIN_CONFIG_SLOT` word-const + `get_item` + element-0 `assert_eq.err=ERR_XRESERVE_WRONG_DOMAIN`; trap → `ERR_UNIMPLEMENTED_IDENTIFIER_COMPARE` (503); parity: `SHELL_ERRORS_DECLARED += WRONG_DOMAIN`, `EXPECTED_SHELL_WORD_CONSTS += DOMAIN_CONFIG_SLOT` | **`8 passed; 3 failed`** — r_mint_6 GREEN on the frozen error; parity 4/4 incl. the new rows | happy ×2 + r7 on "identifier compare is not implemented" |
| C5c (this commit) | + `IDENTIFIER_CONFIG_SLOT` word-const + `exec.encoding::bytes32_to_key` (parser output orientation = `[B1, B0]` input orientation) + `assert_eqw.err=ERR_XRESERVE_WRONG_IDENTIFIER` + final `[hook_data_len]` output contract + final doc block; last placeholder REMOVED; parity lists completed; the red-phase `ERR_UNIMPLEMENTED_*` exemption REMOVED from the bidirectional sweep | **`11 passed; 0 failed`** first pass — happy ×2 (in-driver `hook_data_len` assert + nonce_delta==1 + empty storage delta) + all 7 rejects exact + 2 probes | none — full suite **50/50** (lib 28, gen_vectors 0, parity 4, masm_dual 7, masm_mint_shell 11) |

No test was edited in any C5 stage beyond the pre-declared additive parity-list
extensions (plan §7, ratified); no behavior test body changed since the audited red
commit `4298fca`.

Ratified human decisions in force (plan §0): **D-A** module home
`asm/standards/xreserve/deposit_intent_parser.masm`, nested canonical path
`xreserve::deposit_intent_parser::assert_deposit_intent` (D-1A rule-3 adjudication) ·
**D-B** seam (a)-extended: R-MINT-1..5 satisfied by the 04 parser's `ERR_DI_*` traps
through the shell call path (R-MINT-3/4/5 share `ERR_DI_ZERO_FIELD`) · **D-C**
identifier slot = `bytes32_to_key` key-Word, R-MINT-7 as key equality.

## Red-suite phase (C3, 2026-06-12)

**Pinned-source facts driving the harness shape:**
- `active_account::get_item` syscalls into kernel `account_get_item`, which runs
  `authenticate_account_origin` — slot reads MUST originate from account-context code
  (kernel `api.masm`). A tx script cannot `exec` the shell directly ⇒ the driver is a
  CALL-entered account component proc (the production `xreserve_mint` calling shape)
  that stages the preimage in its own call context and `exec`s the shell.
- Root-dir `mod.masm` is banned by `assemble_library_from_dir`
  (`miden-assembly-syntax-0.23.3/src/parser/mod.rs:207-210`) — the task's flat
  `xreserve::<name>` premise is unrealizable; per-file nested module per D-A.
- Spike Q4/Q5/Q6 (`word("label")[0..2]` + `StorageSlotName::new(label)` +
  `AccountComponent::new(code, slots, metadata)` + dynamic linking + `call` from a tx
  script) had only run on the 0.23.1-era stack ⇒ `probe_slot_binding` is the 0.23.3
  canary, run FIRST via its own `--exact` invocation before any other suite command.

**New surfaces (test/verification infrastructure only):**
- `asm/standards/xreserve/deposit_intent_parser.masm` — placeholder
  `pub proc assert_deposit_intent` with distinct body + named trap
  `ERR_UNIMPLEMENTED_ASSERT_DEPOSIT_INTENT = "red-suite placeholder:
  assert_deposit_intent is not implemented"` (no other consts: assembles clean under
  warnings-as-errors; distinct discriminant per the 04 MAST-dedup lesson).
- `tests/support/mod.rs` — 01-owned TEST-SIDE mirrors (`SHELL_ERR_TABLE` with the two
  frozen error names + D-2 strings; slot labels
  `xusdc::xreserve::domain_config::{domain,identifier}`; Q-DOM-1/DEV-10 disclaimers);
  harness (assemble lift of `masm_dual.rs:41-47`, two named value slots via
  `StorageSlot::with_value(StorageSlotName::new(label))`, per-case driver component
  compiled with the xreserve library dynamically linked, `call.driver::<proc>` runner);
  generated driver/probe sources (staging at `INTENT_PTR = 1024` inside the driver's own
  call context — recorded `masm-locals-over-globals` deviation: test-fixture-only, the
  driver owns the entire fresh context; the shell itself uses no memory).
- `tests/masm_mint_shell.rs` — happy path FIRST (rstest ×2 accept vectors), rejects as
  ONE rstest ×7 (`r_mint_1..r_mint_7`, exact-error pinned via
  `assert_transaction_executor_error!` + `shell_error_by_name`), probes P1
  (`probe_shell_exports`, D-1A/D-A path check) and P2 (`probe_slot_binding`, canary).
  Canonical 04 vectors loaded by reference (`load().families.di`); ZERO new vectors —
  R-MINT-6/7 reuse `di-pos-hookdata` against mismatched CONFIG (fixture data), with
  per-case isolation (6: wrong domain + matching identifier; 7: matching domain +
  one-byte-flipped identifier key).

| # | Command | Result | Classification |
|---|---|---|---|
| 1 | `cargo test --locked --test masm_mint_shell -- --exact probe_slot_binding --nocapture` (first run, sandboxed) | registry-cache write blocked (`Operation not permitted` under `~/.cargo`) | (b) infrastructure — the documented grounding-spike/04 condition; re-run unsandboxed |
| 2 | same, unsandboxed (one run mis-CWD'd into the protocol worktree: "no test target" error; worktree verified clean via `git status --porcelain`, re-run from the repo) | **`1 passed` — `probe_slot_binding ... ok` (0.30s)**; the whole new suite compiled first pass | green — the 0.23.3 canary holds: `word("…")[0..2]` + `StorageSlotName` + call-entered `get_item` execute on the pinned stack |
| 3 | `cargo test --locked --test masm_mint_shell -- --nocapture` | **`2 passed; 9 failed`** — green: `probe_shell_exports`, `probe_slot_binding`; RED ×9: `happy_path_mint_preconditions::{case_1_hookdata,case_2_empty_hookdata}` + `r_mint_rejects::case_{1..7}_*` — EVERY failure surfaced through real MockChain execution as `assertion failed with error message: red-suite placeholder: assert_deposit_intent is not implemented` | all (a) expected RED — the planned named missing-behavior trap; no compile error, no fixture bug, no non-MASM shortcut |
| 4 | `cargo test --locked --no-fail-fast` | lib `28 passed` · gen_vectors `0` · constant_parity `2 passed` · masm_dual `7 passed` · masm_mint_shell `2 passed; 9 failed` | 04's 37 stay green; suite total 48 discovered (39 green + 9 expected RED) |

**Why no test can pass without executing the target MASM:** every behavior case's only
signal is `execute().await` over a transaction whose driver component cannot compile
unless the shell symbol exists in the assembled `xreserve` library, and cannot succeed
unless the shell body runs (the placeholder traps; the implementation must satisfy the
in-driver `hook_data_len` assert / produce the exact named per-row trap). No Rust mirror
of the shell exists.

Containment: this phase wrote `asm/standards/xreserve/deposit_intent_parser.masm`,
`tests/support/mod.rs`, `tests/masm_mint_shell.rs`, and this ledger. `encoding/{mod,
layout}.masm` procs, mirror routine bodies, the vector artifact, and all prior tests
untouched (C1 doc-comment edits and the C2 pin migration are their own audited commits).

## CS-5 hardening (C4, 2026-06-12)

- `constant_parity.rs` rebuilt: `word("…")` constants parsed as a third category; NEW
  rows `SCALE_EXP_MAX == MAX_SCALE_EXP` (= 18; cross-language names differ by frozen
  decision) and `POW2_32 == 2^32`; NEW `masm_constants_bidirectional` sweep — every
  numeric/string/word constant parsed from `layout.masm`, `encoding/mod.masm`, AND the
  shell module must be covered by a parity row or a documented exemption (a new
  MASM-only constant now FAILS); NEW staged `masm_shell_error_string_parity` (the
  `SHELL_ERRORS_DECLARED` / `EXPECTED_SHELL_WORD_CONSTS` lists grow with the C5 commits
  that declare the MASM consts, pinned against `tests/support`'s single Rust source).
  Exemption: `ERR_UNIMPLEMENTED_*` prefix, red/implementation-phase-only — the final C5
  stage removes the last placeholder and the hand-off sweep `rg ERR_UNIMPLEMENTED asm/`
  must be empty.
- **Enabling visibility edit (disclosed):** `amount.rs` `MAX_SCALE_EXP` `const` →
  `pub const` (one token + doc note; zero behavior) — the CS-5-mandated parity row is
  impossible from an integration test against a private constant.
- `vectors.rs` `artifact_guard`: every vector requires non-empty `tv` tags; explicit
  allowlist exactly `["amt-guard-limb-not-u32"]` (the only guard-only vector).

| # | Command | Result |
|---|---|---|
| 1 | `cargo test --locked --test masm_mint_shell -- --exact probe_slot_binding --nocapture` (canary first) | `1 passed` |
| 2 | `cargo test --locked --no-fail-fast` | lib `28 passed` (incl. the extended `artifact_guard`) · constant_parity **`4 passed`** · masm_dual `7 passed` · masm_mint_shell `2 passed; 9 failed` (unchanged expected RED on the named placeholder) — 50 discovered: 41 green + 9 expected RED |

# 01 Faucet Slice 2 — D5b amount/fee Preconditions TEST LEDGER

Loop records per the approved revised P5-01 D5b plan (Codex Round-P REVISE → revised →
human-ratified Option C for `feeAmount`; Round-R red-suite audit PASS). Phase:
**IMPLEMENTATION COMPLETE — FULL SLICE GREEN** (red `303b8e6` → green-1 `ed5ae31` →
green-2 `1db91b6`). Awaiting final Codex audit (Round F).

NEW sibling proc `xreserve::deposit_intent_parser::assert_mint_amounts` (D-1A/D-A home;
`assert_deposit_intent` + its 9 tests untouched). Consumes the 04-owned
`xreserve::encoding::uint256_to_asset_amount` BY REFERENCE for `amount` (felt[2..9]),
`maxFee` (felt[43..50]), and the operator `feeAmount` (advice stack); asserts reduced
`amount >= maxFee` (R-MINT-10) and `feeAmount <= maxFee` (R-MINT-11); R-MINT-9
(`ERR_X_TOO_LARGE`) PROPAGATES from the reducer. `scale_exp` is a proc parameter — DEV-5 /
Q-CRY-6 (cap/scale) stays OPEN, never presented as Circle-approved. `feeAmount` advice =
human-ratified **Option C** (operator-chosen free parameter; hygiene rules 1/2 N/A — no
in-scope commitment, bound is R-MINT-11 over the Circle-signed maxFee; rule 3 enforced:
missing advice traps, malformed/non-u32 limb traps `ERR_FELT_OUT_OF_FIELD`, `feeAmount==0`
is eight explicit zero limbs).

Vectors reused BY REFERENCE from the canonical 04 `amt-*` family (zero new vectors):
`amt-ge-gt/eq/lt` (the reduced-compare `reduced_ge` vectors, TV-AMT-5), `amt-pos-1/2`,
`amt-cap-accept`, `amt-rej-limb-overflow`. `amount`/`maxFee` are spliced into a base
`di-pos-empty-hookdata` preimage; `feeAmount` is staged on the advice stack.

| Stage | Change (MASM + same-commit parity rows) | Full-suite result | RED remainder (named trap) |
|---|---|---|---|
| RED `303b8e6` | named placeholder `assert_mint_amounts` (`ERR_UNIMPLEMENTED_MINT_AMOUNTS`) + 11 D5b tests (happy ×4, rejects ×5, missing/malformed advice ×2) + 3 helpers (`splice_amounts`, `mint_amounts_driver_src`, `run_call_driver_with_advice`) + 2 proposed errors in `SHELL_ERR_TABLE` + temp CS-5 exemption + `probe_mint_amounts_exports` | masm_mint_shell **`12 passed; 11 failed`** (lib 28, parity 4, masm_dual 8 green) | all 11 D5b on the placeholder trap, via real MockChain execution (exact-error mismatch / expected-accept) |
| GREEN-1 `ed5ae31` | reduce amount + maxFee via `reduce_uint256_field` (parser-mirrored non-word-aligned single-felt load) + R-MINT-10 (`ERR_XRESERVE_AMOUNT_BELOW_FEE`) via `u64::lte`; placeholder + exemption REMOVED; `SHELL_ERRORS_DECLARED += AMOUNT_BELOW_FEE` | masm_mint_shell **`19 passed; 4 failed`** | R-MINT-9 fee, R-MINT-11, missing, malformed (feeAmount path) |
| GREEN-2 `1db91b6` | feeAmount via `adv_pushw`×2 (→ `[U1, U0]`) + reducer + R-MINT-11 (`ERR_XRESERVE_FEE_OVER_MAX`) via `u64::lte`; `SHELL_ERRORS_DECLARED += FEE_OVER_MAX` | **`23 passed; 0 failed`** — full suite GREEN: lib 28, gen_vectors 0, constant_parity 4, masm_dual 8, masm_mint_shell 23 | none |

Every stage: `cargo test --locked --no-fail-fast`; 04 (masm_dual 8) + D5a (the 12 prior
masm_mint_shell tests) stayed green throughout; no test body weakened. Exact-error asserts
per case: R-MINT-9/10/11 via `assert_transaction_executor_error!` + `shell_error_by_name`;
missing advice via `matches ExecutionError::AdviceError` ("advice stack read failed");
malformed limb via `OperationError::U32AssertionFailed` pinned to `ERR_FELT_OUT_OF_FIELD`.
G1 anti-duplication: the shell CALLS the reducer (two `exec.encoding::uint256_to_asset_amount`
— one in the helper for amount/maxFee, one direct for feeAmount); `rg` shows NO copied
`pow10`/`u128::divmod`/byte-swap/cap/`AssetAmount::MAX` logic in the shell. No
storage-map/nonce/attestation/`token_supply`/note/mint-effect code; no R-B/account_id,
Cargo, or pin change.

# 01 Faucet Slice 3 — D5c Nonce Replay Guard TEST LEDGER

Loop records per the approved P5-01 D5c plan (Codex Round-P REVISE → revised → PASS;
Round-R red-suite audit PASS; Round-F final audit PASS). Phase: **IMPLEMENTATION COMPLETE
— FULL SLICE GREEN** (red `7da46d2` → green `6bf980c`).

NEW sibling proc `xreserve::deposit_intent_parser::assert_nonce_unused` (D-1A/D-A home;
`assert_deposit_intent`/`assert_mint_amounts` + their 23 tests untouched). This is the
**first REAL `StorageMap` slot on the faucet** (`USED_NONCES_SLOT`, frozen §5.6 nonce
registry), built on the storage-map grounding canary. Derives the nonce key by CONSUMING the
04-owned `xreserve::encoding::bytes32_to_key` BY REFERENCE over the parsed nonce
(`felt[51..58]`, loaded as `[B1, B0]` — the parser's remoteToken orientation), reads
`usedNonces[key]` via the canary-proven `active_account::get_map_item`, and asserts
`== EMPTY_WORD` else traps `ERR_XRESERVE_NONCE_REPLAY` (R-MINT-12). **assert-zero ONLY** —
the nonce mark is the first atomic write in D5e, so a failed mint never consumes a nonce
(no `set_map_item` in D5c). DEV-9 / Q-CRY-5 (nonce-commitment keying) stays OPEN, never
presented as Circle-approved.

Fixture: NEW `setup_shell_account_with_nonce_seed` binds the `usedNonces` map slot
(`StorageSlot::with_map`, canary-proven) — empty by default; `setup_shell_account` delegates
with `None`, so the D5a/D5b accounts now carry the (unwritten) map slot (additive,
behavior-preserving — slots are name-addressed; no storage delta). The replay fixture seeds
`usedNonces[bytes32_to_storage_map_key(nonce)] = marker` via `StorageMap::with_entries`; the
seed key is derived by the 04-owned Rust routine (by reference), parity with the MASM
`bytes32_to_key(felt[51..58])` guaranteed by TV-DUAL-1. NEW `nonce_driver_src` helper.

Vectors reused BY REFERENCE from the canonical 04 `di-*` accept family (zero new vectors):
`di-pos-hookdata`, `di-pos-empty-hookdata`. Finding (non-defect): both accept vectors share
the same nonce, so the key-scoping case derives a distinct "other" key by flipping one nonce
byte (the `config_for` identifier-flip idiom), guaranteed distinct.

| Stage | Change (MASM + same-commit parity rows) | Full-suite result | RED remainder (named trap) |
|---|---|---|---|
| RED `7da46d2` | named placeholder `assert_nonce_unused` (inline `.err` trap — no new `const`, so constant-parity stays green) + the `usedNonces` map-slot fixture (`setup_shell_account_with_nonce_seed` + empty slot bound in `setup_shell_account`) + `nonce_driver_src` + 5 D5c tests (happy ×2, replay ×2, key-scoping) + `probe_nonce_unused_exports` + `ERR_XRESERVE_NONCE_REPLAY` in `SHELL_ERR_TABLE` (red-suite carrier) | masm_mint_shell **`24 passed; 5 failed`** (lib 28, constant_parity 4, masm_dual 8, canary 1 green) | all 5 D5c on the placeholder trap, via real MockChain execution (exact-error mismatch / expected-accept) |
| GREEN `6bf980c` | real proc: load nonce `felt[51..58]` as `[B1, B0]` → `exec.encoding::bytes32_to_key` → `push.USED_NONCES_SLOT[0..2]` → `active_account::get_map_item` → `padw assert_eqw.err=ERR_XRESERVE_NONCE_REPLAY`; declared `USED_NONCES_SLOT` word-const + `ERR_XRESERVE_NONCE_REPLAY` string-const + `NONCE_FELT_OFF` import; parity: `SHELL_ERRORS_DECLARED += NONCE_REPLAY`, `EXPECTED_SHELL_WORD_CONSTS += USED_NONCES_SLOT` | **`29 passed; 0 failed`** — full suite GREEN: lib 28, gen_vectors 0, constant_parity 4, masm_dual 8, masm_mint_shell 29; canary 1 | none |

Every stage: `cargo test -p xusdc-encoding --locked --no-fail-fast` + the canary
(`cargo test --manifest-path canary/storage-map-grounding/Cargo.toml --locked`); 04
(masm_dual 8) + D5a/D5b (the 24 prior masm_mint_shell tests) + canary stayed green
throughout; no test body weakened. Exact-error: replay via `assert_transaction_executor_error!`
+ `shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY")`; happy + key-scoping assert success +
`nonce_delta == 1` + empty storage delta (proves D5c writes NO nonce). G1 anti-duplication:
the shell CALLS `bytes32_to_key` (a 2nd `exec.encoding::bytes32_to_key` call site after D5a)
+ `get_map_item`; `rg "bytes32_to_key|hash_elements|Poseidon2" asm/standards/xreserve/` shows
NO re-implemented hash in the shell; `rg "bytes32_to_storage_map_key" asm/` = zero (NS-1);
`rg -ni "set_map_item|marker|usedNonces.*:=|nonce.*set" asm/standards/xreserve/` = zero (no
nonce SET in D5c). `usedNonces` is the faucet's frozen §5.6 slot (not a new boundary, G2). No
attestation/supply/note/mint-effect code; no R-B/account_id, Cargo, or pin change.

Ratified decisions in force: **D-A** module home `deposit_intent_parser.masm`, nested path
`xreserve::deposit_intent_parser::assert_nonce_unused` (human-confirmed at plan time) · the
nonce SET deferred to **D5e** (assert-zero only here).

# 01 Faucet Slice 4 — D5d Attestation Verify TEST LEDGER

Loop records per the approved P5-01 D5d plan (Codex Round-P REVISE → recheck REVISE →
addressed; plan approved). Phase: **IMPLEMENTATION COMPLETE — FULL SLICE GREEN** (red
`9d5874c` → green this commit). Awaiting Codex Round-R / Round-F audits.

NEW file `asm/standards/xreserve/attestation_verify.masm` (the first NEW shell file; D-1A
nested home `xreserve::attestation_verify::verify_attestation` — NOT in
`deposit_intent_parser.masm`, NOT a flat `xreserve::verify_attestation`). The mint-time
deposit-attestation gate, built as ONE slice because of a single binding invariant: **the
candidate pubkey is materialized ONCE into one word-aligned local region (loc[0..9]) that
feeds BOTH `xreserve::encoding::pubkey_commitment` (→ the `xReserveAttesters` allowlist key)
AND `ecdsa_k256_keccak::verify_prehash` (`pk_ptr`)** — so an allowlisted commitment can only
pass with its own signature (ECDSA soundness closes the seam by construction). Consumes the
built/proven primitives BY REFERENCE: `pubkey_commitment` (04 ATT), `keccak256::hash_bytes`
+ `verify_prehash` (precompiles, EXECUTION-proven by the precompile canary), and
`active_account::get_map_item` (kernel, storage-map canary). Flow (§5.4): keccak the full
payload → store the 8-limb digest to loc[12..20]; materialize pubkey(9)+sig(17) from advice
(seam region + sig at loc[20..37]; missing/short advice traps fail-closed); allowlist gate
R-MINT-13 (`exec.word::eqz` → `assertz.err=ERR_XRESERVE_BAD_PK_COMMITMENT` — the value is a
non-empty enabled marker, absent/`EMPTY_WORD` = not allowlisted); verify R-MINT-14
(`verify_prehash` over the SAME pubkey region → `assert.err=ERR_XRESERVE_SIG_INVALID`).
NEW slot `XRESERVE_ATTESTERS_SLOT = word("xusdc::xreserve::attester_admin::xreserve_attesters")`
(frozen §5.5 `XReserveAttesterAdmin`; the later `set_attester` admin slice co-owns the SAME
slot). DEV-1 / Q-CRY-1 / Q-DA-QUORUM / DEV-6 (hookData extent) stay OPEN, never presented as
Circle-approved.

Vectors: **in-test deterministic secp256k1 generation** (`gen_attester` in `tests/support`,
mirroring the precompile canary + `gen_vectors` `att_*`: k256 `SigningKey::random(seeded
StdRng)` + `sign_prehash_recoverable`, sha3 `Keccak256`, miden-crypto
`PublicKey::to_commitment` oracle, `bytes_to_packed_u32_elements` advice felts) — **zero
touch to the 04 canonical artifact / `gen_vectors.rs` / the att-1..3 vectors**. Additive
`[dev-dependencies]`: `k256 0.13` (ecdsa), `sha3 0.10`, `rand 0.8`, `miden-crypto 0.25` (std)
— the canary-established set. Key A (seed 1) and key B (seed 2) sign keccak256 of the SAME
payload (`di-pos-empty-hookdata`, the 240-byte / 60-felt accept DepositIntent, consumed BY
REFERENCE) so the seam test can pair an allowlisted commitment with a foreign valid signature.
NEW fixture `setup_attestation_account` (binds the `xReserveAttesters` map slot via
`StorageSlot::with_map`; `Some((commitment, marker))` enables an attester directly — NOT via
the out-of-scope `set_attester`) + `attestation_driver_src`.

| Stage | Change (MASM + same-commit parity rows) | Full-suite result | RED remainder (named trap) |
|---|---|---|---|
| RED `9d5874c` | **executing-red** placeholder `verify_attestation` — runs the FULL real sequence (hash_bytes + pubkey_commitment + get_map_item + verify_prehash) then traps `ERR_XRESERVE_D5D_RED_PLACEHOLDER` (the last instruction, so the primitives genuinely execute) + the slot const + the two R-MINT-13/14 error consts + `setup_attestation_account` + `gen_attester` + dev-deps + 6 tests (happy, forged-sig, non-allowlisted, seam-both-arrangements, missing-advice, export probe) + constant-parity wiring (`ATTESTATION_VERIFY_MASM` parsed; `SHELL_ERRORS_DECLARED`/`SHELL_ERR_TABLE` += 3; `EXPECTED_ATTESTATION_WORD_CONSTS`; the bidirectional `sources` += the new file) | masm_mint_shell **`31 passed; 4 failed`** (lib 31, constant_parity 4, masm_dual 9 green) | the 4 behavior cases on the placeholder trap, via REAL primitive execution (exact-error mismatch / expected-accept); the missing-advice hygiene case + the export probe are declared green scaffolds |
| GREEN (this commit) | wire the gate: `exec.word::eqz` + `assertz.err=ERR_XRESERVE_BAD_PK_COMMITMENT` (R-MINT-13) + `assert.err=ERR_XRESERVE_SIG_INVALID` (R-MINT-14) + accept (Outputs `[]`); `use miden::core::word` added; the placeholder const + its `SHELL_ERR_TABLE` / `SHELL_ERRORS_DECLARED` rows REMOVED | **`35 passed; 0 failed`** — full suite GREEN: lib 31, gen_vectors 0, constant_parity 4, masm_dual 9, masm_mint_shell 35 (= **79 total**, the 73 baseline + 6 D5d) | none |

Every stage: `cargo test --locked --no-fail-fast`; the 73 baseline (lib 31, parity 4,
masm_dual 9, the 29 prior masm_mint_shell tests) stayed green throughout — D5d is purely
additive. Exact-error per case: R-MINT-13 / R-MINT-14 via `assert_transaction_executor_error!`
+ `shell_error_by_name`; happy asserts success + `nonce_delta == 1` + empty storage delta
(read-only gate, reaches the supply-write boundary); missing advice via
`matches ExecutionError::AdviceError` ("advice stack read failed"). The seam test drives BOTH
attacker arrangements through real execution: (1) allowlisted pubkey A + B's valid-for-B
signature → R-MINT-14; (2) B's pubkey + B's valid signature, B not allowlisted → R-MINT-13.
G1 anti-duplication: `rg "pubkey_commitment|hash_bytes|verify_prehash|get_map_item"
attestation_verify.masm` shows CALLS only; `rg -ni "hash_elements|poseidon|secp|ecdsa.*proc|
keccak.*proc"` shows no re-implemented crypto (only descriptive comments). No
`set_attester`/Authority/`token_supply`/note/mint-effect/nonce-set code (D5e + the admin
slice + the composition stay out of scope); no 04 / D5a-c / canary / vector / pin change
(`git status` clean of those); `rg RED_PLACEHOLDER` empty post-implementation.

Ratified decisions in force: **D-1A** new-file nested home (the spec's flat
`xreserve::verify_attestation` superseded) · the single-pubkey-region seam (one
materialization feeds both consumers) · in-test vector generation (no edit to the 04
artifact) · error strings proposed-and-user-selected (`ERR_XRESERVE_BAD_PK_COMMITMENT` =
"deposit attester pubkey commitment is not allowlisted"; `ERR_XRESERVE_SIG_INVALID` =
"deposit attestation signature verification failed"). Remaining before `verify_attestation`
is wired into the composite `xreserve_mint`: **D5e** (supply-guard + the atomic mint effects
— supply write / notes / nonce SET) + the `xreserve_mint` composition slice; DEV-1 /
Q-CRY-1 / Q-DA-QUORUM / DEV-6 stay OPEN.

## D5e — mint write-phase (`xreserve::xreserve_mint::apply_mint_effects`, P5-01 slice 5)

The mint WRITE-phase (CMP-A9, §5.1): the supply-cap guard (R-MINT-15) + the atomic mint
effects (nonce SET, P2ID recipient note carrying `amount − feeAmount`, `token_supply += amount`).
NEW file `asm/standards/xreserve/xreserve_mint.masm` (module `xreserve::xreserve_mint`, D-1A
home, CMP-A9). A CUSTOM proc that does NOT route through `execute_mint_policy` / stock
`mint_and_send` (ASG-1 / C-7) — the supply math mirrors `mint_and_send`'s NON-WRAPPING assert
chain (`fungible.masm:288-308`): `token_supply <= max_supply` (no-wrap guard before the `sub`),
`max_supply <= FUNGIBLE_ASSET_MAX_AMOUNT`, `amount <= max_supply − token_supply`, all trapping
the single `ERR_XRESERVE_SUPPLY_CAP`; the guard is FIRST so an over-cap mint rejects before any
effect. The recipient note is built ON-CHAIN from the `[prefix, suffix]` AccountId felts (D-5)
via `miden::protocol::note::compute_and_store_recipient` + `output_note::create` (the P2ID script
root passed in, the `faucet.rs` pattern) — so the xreserve library stays **core+protocol only**
(no standards link needed by the harness assembler; `masm_dual.rs` untouched). The write-side
kernel primitives (`active_account::get_item` / `native_account::set_item` on the faucet
`token_config` slot, `native_account::set_map_item`, `note::compute_and_store_recipient` +
`output_note::*`, `faucet::create_fungible_asset` + `faucet::mint`) are consumed BY REFERENCE and
grounded by a NEW grounding canary (`canary/mint-effects-grounding/`, commit `b1e107a`) that
proves they EXECUTE AND COMMIT on a `FungibleFaucet` account carrying a custom component under
MockChain. `USED_NONCES_SLOT` is IMPORTED from `deposit_intent_parser` (no duplication, G1);
`TOKEN_CONFIG_SLOT` is hard-coded byte-identical to the standard faucet slot
(`CANONICAL-OWNERSHIP-MAP:41`; `fungible.masm:26`). NEW fixture `setup_mint_faucet_account` (a
`FungibleFaucet` + the xreserve component + the mint driver + a no-effects readback probe;
`add_existing_account_from_components([faucet.into(), …])`, the canary-proven construction) +
`mint_effects_driver_src` + `mint_noeffect_probe_src`.

| Stage | Change (MASM + same-commit parity rows) | Full-suite result | RED remainder (named trap) |
|---|---|---|---|
| RED `5e0bcc8` | **executing-red** `apply_mint_effects` — runs the FULL real primitive sequence (token_config read + `set_map_item` nonce SET + `compute_and_store_recipient`/`output_note::*` note emission + `create_fungible_asset`/`faucet::mint` + token_supply write-back) then traps `ERR_XRESERVE_D5E_RED_PLACEHOLDER` (the last instruction, so the primitives genuinely execute; the trap rolls the tx back, no commit) + the slot/marker consts + `ERR_XRESERVE_SUPPLY_CAP` + `setup_mint_faucet_account`/`mint_effects_driver_src` + 4 tests (happy/conservation, cap-boundary accept, over-cap reject, export probe) + constant-parity wiring (`XRESERVE_MINT_MASM` parsed; `SHELL_ERRORS_DECLARED`/`SHELL_ERR_TABLE` += 2; `EXPECTED_XRESERVE_MINT_WORD_CONSTS`/`XRESERVE_MINT_COVERED_NUMS`; the `sources` += the new file) | mint_effects **`1 passed; 3 failed`** (lib 31, constant_parity 4, masm_dual 9, masm_mint_shell 35 green) | the 3 behavior cases on the placeholder trap, via REAL primitive execution (happy/cap-boundary fail because the terminal trap reverts; over-cap fails the exact-error match — confirming the kernel mint does NOT catch the component-level over-cap); the export probe is a declared green scaffold |
| GREEN `8395b7c` | wire the guard: the three ordered non-wrap asserts at the supply-guard marker (R-MINT-15, single `ERR_XRESERVE_SUPPLY_CAP`) + `use …asset::FUNGIBLE_ASSET_MAX_AMOUNT`; the placeholder const + its `SHELL_ERR_TABLE`/`SHELL_ERRORS_DECLARED` rows REMOVED; add the same-account no-effects readback (`run_noeffect_probe`) to the over-cap test + the near-`FUNGIBLE_ASSET_MAX_AMOUNT` boundary test | **`84 passed; 0 failed`** — full suite GREEN: lib 31, constant_parity 4, masm_dual 9, masm_mint_shell 35, mint_effects 5 | none |

Every stage: `cargo test --locked --no-fail-fast`; the 79 baseline (lib 31, parity 4, masm_dual
9, masm_mint_shell 35) stayed green throughout — D5e is purely additive. Exact-error per case:
R-MINT-15 via `assert_transaction_executor_error!` + `shell_error_by_name`; happy/conservation
reads back the post-tx `OutputNote` asset (`output_notes().get_note(0).assets().iter_fungible()`
== `amount − feeAmount`), the `token_config` value-slot delta (`StorageSlotDelta::Value` word[0]
== `amount`), and `usedNonces[KEY]` (`StorageSlotDelta::Map` == the marker). Over-cap: traps
`ERR_XRESERVE_SUPPLY_CAP` (guard before any effect) + a follow-up readback tx on the SAME account
proves `token_config`/`usedNonces[KEY]` unchanged (no committed effect). G1 anti-duplication:
`rg "set_map_item|get_item|set_item|output_note|create_fungible_asset|faucet::mint" xreserve_mint.masm`
shows CALLS only; `rg -ni "execute_mint_policy|mint_and_send"` shows descriptive comments only (no
route); `rg -ni "hash_elements|poseidon|asset::create_fungible_asset_unchecked"` empty; no live
MASM/parity/support execution path contains `ERR_XRESERVE_D5E_RED_PLACEHOLDER` post-green
(`rg` over `xreserve_mint.masm`, `constant_parity.rs`, `support/mod.rs` is empty — remaining hits
are historical/prose ledger + test-doc evidence). No 04 / D5a-d / canary-dir / vector / pin change.

**ATOMIC ORDER (static trace — finding #3a):** post-tx state proves final conservation, not
temporal order within one atomic tx. The order is the documented instruction sequence in
`apply_mint_effects` (`# =>` stack comments): supply guard (read + assert) → nonce SET (FIRST
write) → recipient note → `token_supply += amount` (last) — the FINAL-round auditor inspects this
static trace against §5.1 CIR-MINT-STATE-1..4.

Ratified decisions in force: **D-1A** new-file `xreserve_mint.masm` home (module `xreserve::xreserve_mint`);
custom proc, no `mint_and_send`/`execute_mint_policy` (ASG-1); on-chain P2ID recipient build from
`[prefix, suffix]` (D-5; library stays core+protocol only, P2ID script root passed in); supply
math mirrors `mint_and_send`'s ordered non-wrap pattern (the catastrophic-case guard); `feeAmount`
computed into the note value (`amount − feeAmount`), full `amount` into supply. Remaining before
this is a complete mint: the **`xreserve_mint` COMPOSITION** slice (chain D5a→D5e + the fail-closed
"any verify trap ⇒ no writes" property + the audit-level "only `xreserve_mint` raises
`token_supply`" check) + the mint-deny guard (R-MINT-16, §5.2). **DEV-8** (`feeAmount > 0` two-note
relayer split), **DEV-9 / Q-CRY-5** (nonce keying / marker), **DEV-10** (recipient bytes32→felts
encoding), and **IMPL-MINT-SPLIT** stay OPEN — implemented per the frozen spec, never marked
Circle-approved.

## Recipient AccountId helper (`xreserve::xreserve_mint::extract_recipient_account_id`, P5-01, 2026-06-18)

The helper-first slice (human re-sequencing: build + audit the recipient extractor BEFORE chaining the
full mint). Extracts and canonically validates the `remoteRecipient` bytes32 (felt offset 19, R-B
layout: a 16-byte zero pad, then `prefix`/`suffix` u64 big-endian) into the `[suffix, prefix]`
AccountId felts `apply_mint_effects` consumes. ADDED to `asm/standards/xreserve/xreserve_mint.masm`
(faucet/01-owned; the 04 `encoding` stays untouched). The kernel does NOT validate the target
AccountId at note creation (fail-OPEN; verified in `miden-protocol` note.masm / output_note.masm), so
the check is explicit: a LOCAL byte-swap + a `build_felt` no-reduction round-trip (the `miden-agglayer`
`eth_address.masm::build_felt` precedent; the 04 `encoding::swap_u32_bytes` is private, and exporting
it / adding `account_id.masm` to 04 is out of scope) does the zero-pad assert and the `prefix < p`
felt-construction guard, then canonical validation is DELEGATED to the pinned protocol
`account_id::validate` BY REFERENCE (suffix low byte == 0, suffix MSB == 0, version == `VERSION_1` =
**1**, not 0 — a Round-2 audit fix). NEW errors `ERR_XRESERVE_RECIPIENT_{OUT_OF_RANGE, BAD_LIMB,
NONCANONICAL}` (the suffix-shape / version rejects surface the protocol `ERR_ACCOUNT_ID_*` directly —
no xUSDC copy, no version const to drift). NEW test file
`crates/xusdc-encoding/tests/mint_recipient_account_id.rs` + `splice_recipient` / `recipient_driver_src`
(support). **D-5 human approval RECORDED** (2026-06-17 helper-first decision; CANONICAL-OWNERSHIP-MAP
L29/L58) for the first MASM AccountId↔bytes32 conversion.

| Stage | Change (MASM + same-commit parity rows) | Suite result | RED remainder (named trap) |
|---|---|---|---|
| RED (audited) | named placeholder `extract_recipient_account_id` (terminal `assert` trap) + 12 tests (export probe, 3 `aid-rt` happy, the pad/prefix-modulus/suffix-modulus/suffix-MSB/bad-version/malformed-limb rejects, no-effects) + `SHELL_ERR_TABLE` += the 3 recipient errors | `mint_recipient_account_id` **`1 passed; 11 failed`** (rest of crate green) | the 11 behavior tests on the placeholder, via REAL execution; the export probe is a declared green scaffold |
| GREEN (audited) | the real extractor (local byte-swap + `build_felt` + `exec.account_id::validate`) + `SHELL_ERRORS_DECLARED` += the 3 errors (`constant_parity`) | **`12 passed; 0 failed`** first pass; full crate green | none |

Committed as `6f52d5a` (`feat(faucet): add recipient AccountId extraction helper`) — red-suite + green
together, after both passed independent Codex audits (the version-1 fix + the consume-by-reference
validator landed in the Round-2 plan/impl revisions). **DEV-10 / Q-CRY-3/4** (the R-B layout) stay OPEN.

## xreserve_mint composition (`xreserve::xreserve_mint::mint`, P5-01, 2026-06-18)

The complete supply-gating mint: chains the accepted stages **verify-once → write-once** —
`assert_deposit_intent` (D5a) → `assert_mint_amounts` (D5b) → `assert_nonce_unused` (D5c) →
`verify_attestation` (D5d) → `extract_recipient_account_id` → `apply_mint_effects` (D5e), all consumed
BY REFERENCE. **Fail-closed:** any verify / extraction trap aborts the whole tx with NO writes (no
nonce SET, no recipient note, no `token_supply` change), so a failed mint never burns the nonce. The
operand stack is kept logically empty between stages via `@locals` (D5d's keccak restores the depth-16
floor, so nothing may sit above it when it runs). `len_bytes = DEPOSIT_INTENT_HEADER_FELTS * 4 +
hook_data_len` (the hookData happy test pins the exact `240 + hook_data_len` keccak extent). MARSHAL of
the D5e inputs (deterministic recompute from the UNMUTATED preimage): `amount` re-reduced via
`encoding::uint256_to_asset_amount`, `KEY` via `encoding::bytes32_to_key` (== D5c's key, reused as
`SERIAL_NUM`), recipient via the audited extractor, `tag` via `NoteTag::with_account_target` (the top
14 bits of the prefix's HIGH u32), `P2ID_SCRIPT_ROOT` an array-literal const (functionally pinned by
the happy tests), `feeAmount = 0` (MVP single recipient note). NEW local helper `load_field_words`
(replicates the private `deposit_intent_parser` staging; the reductions / key-hash are the 04 `pub`
procs by reference). NEW test file `crates/xusdc-encoding/tests/xreserve_mint.rs` +
`setup_mint_composition_account` (a `FungibleFaucet` carrying ALL composition slots: domain_config,
identifier_config, usedNonces, xReserveAttesters) + `mint_composition_driver_src` + the readback probes
(support).

| Stage | Change | Composition-suite result | RED remainder (named trap) |
|---|---|---|---|
| RED (audited; +3 rows on re-audit) | bare terminal-trap placeholder `mint` + 11 tests: export probe, 2 happy (empty + hookData), 8 fail-closed rejects (wrong-domain D5a, amount-below-fee D5b, nonce-replay D5c, non-allowlisted + forged-sig D5d, bad-recipient, fee-over-max, supply-cap) | `xreserve_mint` **`1 passed; 10 failed`** (rest of crate green) | the 10 behavior tests on the placeholder, via REAL execution (the chain inputs are staged + reached, then the terminal trap reverts); the export probe is a declared green scaffold |
| GREEN (audited; +tag fix on re-audit) | the full chain + marshal + write. The green re-audit found `tag` kept the LOW u32 (`u32split swap drop`) — fixed to keep the HIGH u32 (`u32split drop`), matching `with_account_target`, + a regression tag assertion added to both happy paths | **`11 passed; 0 failed`**; full crate green | none |

Committed as `6445dbb` (`feat(faucet): implement xreserve_mint mint composition (chains D5a-D5e,
fail-closed)`) — red-suite + green together, after both passed independent Codex audits. Exact-error
per reject via `assert_transaction_executor_error!` + `shell_error_by_name`; no-effects via a
same-account readback probe (token_supply unchanged; usedNonces[KEY] empty, except the replay reject
where the nonce is seeded by fixture so only supply is checked). Happy paths read back the committed
`ExecutedTransaction`: one P2ID note carrying the reduced `amount` from this faucet, the canonical P2ID
script root + `[suffix, prefix]` storage, the `with_account_target` tag, `token_supply += amount`, and
`usedNonces[KEY] == MARKER`. No 04 / D5a-e / canary / vector / pin change.

**Remaining for the faucet:** **R-MINT-16** mint-deny guard (§5.2, `ERR_XRESERVE_MINT_DENIED`) — the
only-`xreserve_mint`-raises-`token_supply` exclusivity is proven HALF here (the assembled xreserve
library has a single supply-raising surface, `apply_mint_effects`; static grep + supply-conservation);
the NEGATIVE half (the stock `mint_and_send` is deny-guarded) is the next slice. Then admin /
`set_attester` / domain-config, burn produce + consume, local-node validation, then the off-chain
relayer/listener. **DEV-8** (`feeAmount > 0` relayer split), **DEV-9 / Q-CRY-5** (nonce keying /
marker), **DEV-10 / Q-CRY-3/4** (recipient bytes32→felts encoding) stay OPEN — implemented per the
frozen spec, never marked Circle-approved.
