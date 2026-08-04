//! Burn-mechanics grounding canary (P5-01) — exposes shared constants for the MockChain burn
//! suite. Scratch: this crate is an isolated workspace, depends only on the pinned
//! `protocol-pin-v0.15.3`, and decides nothing about the faucet's real burn policy or note schema.
//!
//! It proves, with RUNNING code (not assembly), the STOCK fungible-faucet BURN primitives that the
//! later real burn slices (CMP-A10 burn policy, CMP-B2 public burn note, CMP-B3
//! `xreserve_receive_and_burn`, CMP-F2 `set_min_burn`) will build on:
//!   - a user-created asset-bearing `BurnNote` (asset moves user-vault -> NoteAssets) consumed BY
//!     the faucet via stock `receive_and_burn` (dispatched through the stock allow-all
//!     `BurnAllowAll` placeholder policy that `add_existing_basic_faucet` wires),
//!   - the `token_supply -= amount` decrement (read back from `token_config`),
//!   - the exactly-one-asset trap (`ERR_FUNGIBLE_BURN_WRONG_NUMBER_OF_ASSETS`),
//!   - the 2-block lifecycle: next-block retrieval (`get_public_note`) + same-block erasure
//!     (create+consume in one block -> note erased from block output notes, no nullifier),
//!   - `NoteType::Public` discoverability.
//!
//! It uses STOCK components only (no hand-authored faucet/policy MASM); the sole hand-written MASM
//! is two inline tx-/note-script strings.

/// The `token_config` value slot installed by the standard `FungibleFaucet` component — index 0 of
/// the word holds `token_supply`. The burn path decrements it (`fungible.masm:444`); the canary
/// reads it back after the burn to assert `-= amount`.
pub const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";

/// The inline BURN note-script used by the exactly-one-asset negative test: drop the note args,
/// then `call` the stock faucet wrapper. Identical to the stock protocol burn test's inline script
/// (`miden-testing/tests/scripts/faucet.rs`) and the canonical `BurnNote` script
/// (`miden-standards/asm/standards/notes/burn.masm`).
pub const BURN_NOTE_SCRIPT: &str = r#"
# burn the note's single asset via the faucet wrapper (runs the active burn policy, then burns).
@note_script
pub proc main
    dropw
    # => [pad(16)]

    call.::miden::standards::faucets::fungible::receive_and_burn
    # => [pad(16)]
end
"#;
