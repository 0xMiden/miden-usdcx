# Mint-Note Transport Grounding Report (P5-01 CMP-B1 canary)

Status: **ALL GREEN** — 3/3 MockChain tests pass on the pinned Miden v0.15.3 / assembler 0.23.3
stack (`cargo test` in this crate, isolated workspace, path-deps on `protocol-pin-v0.15.3`).

## What is now PROVEN by running code

1. **`active_note::get_storage` from a CALL-entered account proc stages into the ACCOUNT call
   frame.** The probe proc (entered via `call` from a note script) staged the 6 sentinel storage
   felts at absolute `STORAGE_PTR = 1024` and read them back with `mem_load` in the same frame
   (count + first/last content asserts). The stock precedent (`receive_and_burn`,
   `fungible.masm:370-403`) proves this for `get_assets`; this canary closes the gap for
   `get_storage`. (T1)
2. **`find_attachment` by scheme** works from the same context — found path returns the index
   (T1); the not-found path fail-closes through a named wrapper-style assert,
   `ERR_CANARY_ATTACHMENT_MISSING` (T2).
3. **`write_attachment_commitments_to_memory`** returns the attachment count (asserted `== 1`)
   and lands the per-attachment commitment word in wrapper-chosen memory, loadable via
   `padw loc_loadw_le` exactly as `note.masm:198-201` does. (T1)
4. **`write_attachment_to_memory` is the hash-verified content read**: 9 words (36 felts) landed
   in locals with `num_words == 9` and exact first/last content — content bound to the
   note-committed attachment commitment. NOTE: 9 words (ODD) is fine —
   `pipe_preimage_to_memory` explicitly supports odd word counts (core-lib `mem.masm`, cycle
   formula for odd `num_words`). (T1)
5. **`adv.push_mapval` pop order is element-0-FIRST.** After verification, pushing the same
   commitment key re-surfaced the 36 felts on the advice stack and `adv_push` popped element 0,
   then element 1, …, element 35 last (distinct sentinels per position; a reversal would have
   tripped `ERR_CANARY_ADVICE_POP_ORDER`). The real attachment layout
   `[feeAmount(8), pubkey(9), signature(17), pad(2)]` therefore reads in declaration order — no
   constructor-side reversal needed. (T1)
6. **Create-side emit with attachments works and round-trips NoteId.** A producer tx-script
   using `output_note::create` + `output_note::add_attachment` (elements in the producer tx's
   advice map — the upstream `note_script_that_creates_notes` pattern,
   `miden-testing/src/utils.rs:245-315`) emitted a note whose id equals the Rust-side
   `Note::with_attachments` construction; committed at block N, consumed by id at block ≥ N+1
   with **zero consume-side advice staging** (executor auto-injection,
   `advice_inputs.rs:329-362`). (T1)
7. **The hostile-advice override IS expressible at the tx-context level and fail-closes.**
   `extend_advice_inputs(AdviceInputs::default().with_map([(commitment, wrong)]))` on the consume
   context OVERRIDES the auto-injected entry, and the transaction traps inside
   `write_attachment_to_memory`'s hash check — the bare `assert_eqw` in
   `pipe_preimage_to_memory` (core-lib 0.23.x has no named error there). Pinned trap shape:
   `TransactionProgramExecutionFailed(OperationError { .., err: FailedAssertion { err_code: 0,
   err_msg: None } })`. (T3)

## Consequences for the real slice (red-suite + wrapper)

- The `receive_and_mint` wrapper can follow the probe's exact sequence (stage → find → count →
  verified read → `num_words == 9` → `adv.push_mapval` → `exec.xreserve_mint::mint`).
- The red-suite tamper test (`mint_note_tampered_attachment_advice_rejects_no_writes`) IS
  expressible at the tx-context level. Its "exact error" is the pinned anonymous
  `FailedAssertion { err_code: 0 }` from `pipe_preimage_to_memory`'s `assert_eqw` — a named
  MasmError would require modifying pinned protocol code (out of scope). The test asserts the
  failure + zero writes and documents the anonymous-assert caveat.
- `adv_push` (bare, no immediate) is the 0.23.3 advice-pop syntax (`adv_push.1` does not parse).

## Boundary (NOT proven here)

The real DepositIntent schema, the D5a–D5e gate chain, the wrapper's `exec.xreserve_mint::mint`
hand-off, fee/pubkey/sig semantics, the P2ID output, and any Circle value. Sentinels only.
