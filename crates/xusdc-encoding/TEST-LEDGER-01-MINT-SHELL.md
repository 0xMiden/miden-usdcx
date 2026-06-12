# 01 Faucet Slice 1 — Mint-Precondition Shell TEST LEDGER

Loop records per the approved P5-01 plan. Phase: **RED-SUITE COMMITTED (C3)** — test
infrastructure, fixtures, and the named placeholder only; zero assertion behavior.

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
