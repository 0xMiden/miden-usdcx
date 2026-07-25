# Burn-Mechanics Grounding Canary Report (P5-01)

**Gate:** MockChain (NOT local-node). **Pins:** protocol v0.15.3 (`681fc9058`) → assembler 0.23.3, seeded `Cargo.lock` (isolated workspace). **Status:** PASS — `cargo test --locked --no-fail-fast` green (4 tests). **GO** for the burn slices on these primitives.

| | |
|---|---|
| Pin (API ground truth) | `protocol v0.15.3` (`681fc9058`) → assembler family `0.23.3` |
| Safe path | `CodeBuilder::new()` → `compile_tx_script` / `compile_note_script`; `MockChain` execute; `LocalTransactionProver::prove_dummy` (same-block batch) |
| Gate | MockChain (NOT local-node) |
| Placeholder policy | stock `BurnAllowAll` (active), wired by `add_existing_basic_faucet` (`chain_builder.rs:402`) — NO real burn policy |
| Result | `test result: ok. 4 passed; 0 failed` (`c1_next_block_user_create_retrieve_consume`, `c2_same_block_erasure_unauthenticated_consume`, `b_zero_asset_note_traps_wrong_number_of_assets`, `b_exceeds_supply_traps_amount_exceeds_token_supply`) |

## Purpose

The burn (redemption) half introduces FOUR primitives unproven in *our* harness at once: stock `receive_and_burn` (consume + burn), a **user-created asset-bearing note consumed by the faucet**, `token_supply -= amount` (the decrement direction), and the **2-block burn lifecycle** (same-block create+consume erased; next-block retrievable). Mirroring the storage-map / precompile / mint-effects canaries, this scratch crate proves — with **running code under MockChain**, not assembly — that those primitives EXECUTE, using the stock allow-all `BurnAllowAll` **placeholder** policy. It decides nothing about the real burn policy/schema; it is fully isolated (own `[workspace]`), depends only on `protocol-pin-v0.15.3`, and touches no xUSDC source.

## What was proven (running code)

**C1 — next-block lifecycle (`c1_next_block_user_create_retrieve_consume`).**
- A funded **user** `BasicWallet` (`add_existing_wallet_with_assets`) creates the canonical `BurnNote` (`BurnNote::create(user.id(), faucet.id(), fungible_asset, …)`) **in-block** via a send tx-script (`output_note::create` + `call.wallet::move_asset_to_note`) — NOT genesis seeding. The asset moves user-vault → `NoteAssets` (asserted: committed user vault balance == 0 after the block).
- **NoteId identity (details AND metadata).** The emitted note matches `burn_note` on metadata parity FIRST — `metadata().sender() == user.id()`, `note_type() == Public`, `tag() == NoteTag::with_account_target(faucet.id())` — and details (`recipient_digest()`, one fungible asset of `faucet.id()` × `AMOUNT`), THEN `id() == burn_note.id()`. (Registering the note via `extend_expected_output_notes` supplies its details to the kernel's `before_created` event.)
- **Retrieval at block N:** `is_note_committed(id)` true; `get_public_note(id)` returns the full public note whose **id, assets, recipient digest, and metadata (sender/type/tag) all match `burn_note`** (asserted via `InputNote::note()`); `is_note_unspent(nullifier)` true.
- **Burn at block N+1 (authenticated consume):** `build_tx_context(faucet.id(), &[burn_note.id()], &[])` runs the note script → stock `receive_and_burn`. **Supply decrement:** committed `token_supply` 100_000 → 95_000 (`-= AMOUNT`), and the tx-level `StorageSlotDelta::Value` for `token_config` has word[0] == 95_000. `is_note_consumed(nullifier)` true.
- **Public-note discoverability post-consume:** `get_public_note(id)` still returns the note after the burn, and the **same full details (id, assets, recipient digest, metadata) are re-asserted**. **CAVEAT:** this holds because MockChain marks the nullifier spent but does not yet prune `committed_notes` (`chain.rs:920-928`, an explicit unimplemented-removal TODO) — a harness behavior, NOT a protocol guarantee. The durable burn-event observability the withdrawal attester needs is a local-node concern (see Residual).

**C2 — same-block erasure (`c2_same_block_erasure_unauthenticated_consume`), the headline de-risk (R-BURN-4).**
- tx0 (user send-tx, emits `burn_note`) is executed then dummy-proven (`LocalTransactionProver::default().prove_dummy`); tx1 is the faucet consuming `burn_note` **UNAUTHENTICATED** — `build_tx_context(faucet.id(), &[], slice::from_ref(&burn_note))` (`&[]` authenticated ids, `&[burn_note]` unauthenticated values). Pushed create-before-consume into ONE block via `add_pending_proven_transaction` + `prove_next_block`.
- **Erasure proven:** `burn_note.id()` absent from `block.body().output_notes()`; `get_public_note(id).is_none()`; `!is_note_committed(id)`; **no nullifier** (`!is_note_consumed`). tx0 really ran (user vault depleted), and tx1 really burned — yet the note is gone: that is same-block erasure, not a no-op.
- **Account-delta survives erasure (asserted empirically, not assumed):** committed `token_supply` still `-= AMOUNT` (95_000) even though the consumed note was erased — erasure removes the *note*, not tx1's account-state delta.

**B — burn panics (named-error negatives).**
- **Exactly-one-asset (`b_zero_asset_note_traps_wrong_number_of_assets`):** a 0-asset note bearing the stock burn script traps with the stock `ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS`.
- **Exceeds-supply (`b_exceeds_supply_traps_amount_exceeds_token_supply`):** a note carrying a fungible amount > the faucet's `token_supply` (100_001 > 100_000) traps with the stock `ERR_FAUCET_BURN_AMOUNT_EXCEEDS_TOKEN_SUPPLY` (`fungible.masm:432-433`), mirroring the stock protocol negative test.
- Both asserted by the named error via `assert_transaction_executor_error!`, not `is_err()`.

## Post-tx assertion APIs confirmed (reused by the real burn slices)

- Output note: `tx.output_notes().num_notes()/.get_note(i)`; `.metadata().{sender,note_type,tag}()`, `.recipient_digest()`, `.id()`, `.assets().iter_fungible()`.
- Supply: `FungibleFaucet::try_from(chain.committed_account(id)?.storage())?.token_supply()`; tx-level `tx.account_delta().storage().get(&StorageSlotName::new("…token_config")?)` → `StorageSlotDelta::Value`.
- Notes/nullifiers: `is_note_committed`, `get_public_note`, `is_note_unspent`, `is_note_consumed`; block erasure via `block.body().output_notes()`.
- Vault: `chain.committed_account(id)?.vault().get_balance(asset.vault_key())`.
- Multi-block: `add_pending_executed_transaction` + `prove_next_block` (C1); `add_pending_proven_transaction` + `prove_next_block` (C2 batch).

## MASM grounding (consumed, not re-implemented)

Stock `receive_and_burn` (`fungible.masm:390-446`: `active_note::get_assets` → exactly-one-asset assert → `policy_manager::execute_burn_policy` → `faucet::burn` → `token_supply -= amount` via `sub` + `native_account::set_item`) and the stock burn note script (`call.::miden::standards::faucets::fungible::receive_and_burn`). The only hand-authored MASM is the user send tx-script (`output_note::create` + `call.wallet::move_asset_to_note`) and the inline burn note-script shared by the negative tests — both stock-proc compositions, no faucet/policy MASM authored.

## What this canary does NOT prove (the real-slice boundary)

The real burn policy (amount>0 / ≥minBurnSize / pause — R-BURN-1/2/3, CMP-A10); the real `XReserveBurnNote` schema/tag/payload (DC-7, CMP-B2); `set_min_burn_size` (CMP-F2); holder-balance-at-create enforcement (R-BURN-5); `xreserve_receive_and_burn` composition (CMP-B3); **DEV-2 (public note as burn event) — stays OPEN**. Stock `BurnAllowAll` placeholder only; no security/policy behavior asserted.

## Burn-slice GO/NO-GO

**GO.** All four new primitives execute under MockChain: stock `receive_and_burn` + the policy dispatch, the user-created asset-bearing note consumed by the faucet, `token_supply -= amount`, the 2-block lifecycle (both halves), and `NoteType::Public` discoverability. The burn slices may be built on these primitives. The only carried-forward item is the durable post-consume public-note observability (DEV-2-adjacent), which defers to the local-node gate / withdrawal attester.

## Residual / out of scope

Local-node validation is deferred (MockChain is the gate here). This canary does not prove proving-time security, devnet node execution, the real burn policy/schema math, or the durable observability of a consumed public note (the MockChain retention is a TODO artifact — see C1 caveat). It touches nothing in 04 / the faucet mint+admin slices / the other canaries / vectors.

## Reproduce

```
cargo test --manifest-path canary/burn-lifecycle-grounding/Cargo.toml --locked --no-fail-fast -- --nocapture
```
`cargo` runs with the sandbox disabled (it writes its package cache under `~/.cargo`, the crate `target/`, and reads the SSH signing key), as the precedent canaries document. Expect `test result: ok. 4 passed; 0 failed`.
