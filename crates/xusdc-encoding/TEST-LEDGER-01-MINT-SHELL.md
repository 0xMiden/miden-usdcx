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
