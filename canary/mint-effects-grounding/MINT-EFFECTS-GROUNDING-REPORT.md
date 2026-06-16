# Mint-Effects Grounding Canary Report (P5-01 D5e)

**Gate:** MockChain (NOT local-node). **Pins:** protocol v0.15.3 (`681fc9058`) → assembler 0.23.3, seeded `Cargo.lock` (isolated workspace). **Status:** PASS — `cargo test --locked --no-fail-fast` green (1 test).

## Purpose

D5e (`apply_mint_effects`) introduces the faucet's **write-side kernel primitives**, which `BUILDER-GATES.md` G-MASM lists as still-PENDING grounding ("the real kernel proc stack contracts: `faucet::mint`/`create_fungible_asset`, `output_note::*`, …; map-storage execution"). The current xusdc harness has never built a faucet-typed MockChain account, nor minted, nor emitted a note. This canary proves — with **running code under MockChain**, not assembly — that those primitives EXECUTE AND COMMIT on a `FungibleFaucet` account that also carries a custom component, and that the post-tx assertion APIs D5e's tests need actually work. It is scratch: it decides nothing about the real mint proc; it hard-codes amounts/keys and decomposes the write phase into independent procs so each primitive's stack contract is provable in isolation.

## What was proven (running code)

Account construction (the central unknown):
- A `FungibleFaucet` component (`miden_standards::account::faucets::FungibleFaucet::builder()…build()`) **coexists with a custom `AccountComponent`** on one MockChain account via `builder.add_existing_account_from_components(Auth::IncrNonce, [faucet.into(), canary_component])` — no storage-slot collision, no extra `AccessControl`/`TokenPolicyManager` needed for the kernel mint path. The resulting account IS recognized as a fungible faucet (faucet-ness derives from the component, not from `AccountType`, which is only `{Private, Public}`).

The write-side primitives (each committed and asserted on post-tx state):
- **token_config value-slot read/modify/write** — `push.TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item` then the saved-slot-copy + `exec.native_account::set_item` write-back (mirrors `fungible.masm:264-324`). The faucet's `token_config` slot label is `miden::standards::faucets::fungible::token_config`; reading/writing it from a custom component proc works (slots are account-global by hashed-label id). Post-tx: `StorageSlotDelta::Value` with word[0] = the bumped supply.
- **nonce SET** — `exec.native_account::set_map_item` on a custom map slot (mirrors the storage-map canary / D5e's `usedNonces`). Post-tx: `StorageSlotDelta::Map`, key → marker.
- **mint + P2ID note emission** — `exec.p2id::new` ([suffix, prefix, tag, note_type, SERIAL_NUM] → [note_idx]) + `exec.faucet::create_fungible_asset` ([amount] → [ASSET_KEY, ASSET_VALUE]) + `exec.faucet::mint` + `exec.output_note::add_asset` (mirrors `fungible.masm:330-363` + `p2id.masm:90`). A single **public** P2ID output note committed, carrying 1000 of the faucet's fungible asset.

## Post-tx assertion APIs confirmed (the ones D5e tests will use)

- Output note: `executed.output_notes().num_notes()`, `.get_note(0)`, `.assets().iter_fungible().next()` → `FungibleAsset`; `Felt::from(asset.amount())`, `asset.faucet_id()`.
- Value slot: `executed.account_delta().storage().get(&StorageSlotName::new(label)?)` → `StorageSlotDelta::Value(Word)`; word[0] is the new `token_supply`.
- Map slot: same path → `StorageSlotDelta::Map(d)`; `d.entries().get(&StorageMapKey::new(Word::from(key)))`.

## MASM grounding (consumed, not re-implemented)

`active_account::get_item`, `native_account::set_item`, `native_account::set_map_item`, `faucet::create_fungible_asset`, `faucet::mint`, `output_note::add_asset`, `p2id::new` — all called via `exec`/`use` from the pinned protocol. Import paths confirmed: `use miden::standards::notes::p2id` (mirrors `pswap.masm:11`), `use miden::protocol::{active_account, native_account, faucet, output_note}`.

## Implications for D5e

- The real `setup_mint_faucet_account(...)` harness helper uses `add_existing_account_from_components([FungibleFaucet…into(), xreserve_component, driver_component])` (or `add_account_from_builder` if a richer faucet is later needed). token_supply is seeded via `FungibleFaucet::builder().token_supply(…).max_supply(…)`.
- `apply_mint_effects` combines these primitives in the spec atomic order (supply guard → nonce SET → recipient note → `token_supply += amount`). The supply-cap asserts (the security core) are NOT exercised here — they are the D5e green work, mirrored from `fungible.masm:288-309`.
- Assertion APIs above are reused verbatim in the D5e happy/conservation tests; the over-cap no-effects readback uses `get_item`/`get_map_item` (proven by the slot probe + storage-map canary).

## Residual / out of scope

Local-node validation is deferred (MockChain is the gate for D5e). This canary does not prove proving-time behavior, devnet node execution, or the supply-cap math (that is D5e's own tests-first work). It touches nothing in 04 / D5a-d / the other canaries / vectors.
