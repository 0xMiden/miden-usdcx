//! P5-01 `set_max_supply` admin slice: the supply-cap setter. This is STOCK reuse — the standard
//! `FungibleFaucet` already exposes `set_max_supply`, gated (in this order) mutability ->
//! `authority::assert_authorized` (RbacControlled{ATTEST_ADMIN} on our account) ->
//! `assert_not_paused` -> below-current-supply. No new MASM. This file covers the role gate, write
//! integrity, the below-supply guard, the pause gate, and the immutable control. The cap-enforcement
//! seam (that `set_max_supply` actually changes what R-MINT-15 enforces) lives in `xreserve_mint.rs`,
//! alongside the shared mint-composition fixtures it reuses.
//!
//! The slice's net-new surface is the build-time mutability flag. The gate fixtures are built MUTABLE
//! (`is_max_supply_mutable = true`), so each gate test exercises its intended gate: the holder's
//! `set_max_supply` succeeds (write integrity), a non-holder traps ERR_SENDER_LACKS_ROLE, a paused
//! faucet traps ERR_PAUSABLE_IS_PAUSED, and a below-current-supply value traps
//! ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY. `set_max_supply_immutable_traps` keeps an IMMUTABLE faucet as
//! the control, pinning that the mutability gate fires FIRST (the EXACT ERR_MAX_SUPPLY_NOT_MUTABLE,
//! even for the holder). Stock `set_max_supply` is reused verbatim — no new MASM.

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageSlotDelta, StorageSlotName};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// The seeded admin_holder / owner the production builder installs (admin_holder = id(2) into
// ATTEST_ADMIN; owner = id(1)). A non-holder is any other id.
fn holder() -> AccountId {
    test_account_id(2)
}
fn non_holder() -> AccountId {
    test_account_id(99)
}

/// The exact stock error `rbac::assert_sender_has_role` traps (rbac.masm:50). Constructed inline (a
/// stock error, not an xusdc shell error, so it is not in `SHELL_ERR_TABLE`).
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

/// Config words the builder does not read (these tests invoke `set_max_supply` via a note, never the
/// mint driver).
fn dummy_config() -> (Word, Word) {
    (Word::from([7u32, 0, 0, 0]), Word::from([11u32, 12, 13, 14]))
}

/// An RBAC-equipped production faucet (admin_holder = id(2), deny active) with cap 1_000_000 and a
/// trivial unused driver/probe — the base for the gate tests. `token_supply` seeds the initial
/// `token_config[token_supply]` (for the below-supply guard); `is_max_supply_mutable` is the slice's
/// net-new flag (RED commits `false`; GREEN flips the gate tests to `true`).
fn guarded_faucet(token_supply: u64, is_max_supply_mutable: bool) -> Result<GuardedMint> {
    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    let (domain, identifier) = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        token_supply,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        is_max_supply_mutable,
    )
}

// IMMUTABLE CONTROL (declared GREEN from the start) — the mutability gate is real and fires first
// ================================================================================================

/// On an IMMUTABLE faucet, even the ATTEST_ADMIN holder's `set_max_supply` traps the EXACT
/// ERR_MAX_SUPPLY_NOT_MUTABLE — the mutability gate fires before auth/pause/below-supply. The immutable
/// control (forbidden #4 — the immutable half): it pins that the mutability gate is real and fires
/// first, independent of the role/pause/below-supply gates the mutable tests exercise.
#[tokio::test]
async fn set_max_supply_immutable_traps() -> Result<()> {
    let gm = guarded_faucet(0, false)?;
    let account = faucet_account(&gm.harness);
    let result = run_set_max_supply_tx(&gm.harness, &account, holder(), 500_000, 7).await;
    assert_transaction_executor_error!(result, err_max_supply_not_mutable());
    Ok(())
}

// ROLE GATE + WRITE INTEGRITY — RED until the gate faucet is built mutable (green)
// ================================================================================================

/// An ATTEST_ADMIN-holder-sent `set_max_supply(X)` succeeds and writes ONLY word[1] (max_supply),
/// preserving token_supply/decimals/symbol (forbidden #3 — full-word read-back).
#[tokio::test]
async fn set_max_supply_role_holder_succeeds() -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);
    let before = read_token_config(&account)?; // [token_supply=0, max_supply=1_000_000, decimals=6, "XUSDC"]

    let executed = run_set_max_supply_tx(&gm.harness, &account, holder(), 500_000, 7)
        .await
        .expect("an ATTEST_ADMIN holder's set_max_supply must succeed on a mutable faucet");

    // write integrity: the token_config delta carries the FULL word with ONLY word[1] changed.
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(after) =
        executed.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    let expected = Word::from([before[0], Felt::from(500_000u32), before[2], before[3]]);
    assert_eq!(*after, expected, "set_max_supply writes word[1] only; token_supply/decimals/symbol preserved");
    assert_eq!(after[1], Felt::from(500_000u32), "max_supply updated to 500_000");
    Ok(())
}

/// A NON-holder-sent `set_max_supply` note traps the EXACT ERR_SENDER_LACKS_ROLE (the auth gate fires
/// after mutability passes; the trap commits nothing, so token_config is untouched).
#[tokio::test]
async fn set_max_supply_non_holder_rejects() -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);
    let result = run_set_max_supply_tx(&gm.harness, &account, non_holder(), 500_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

// BELOW-SUPPLY GUARD — set_max_supply below current token_supply is rejected (forbidden #5)
// ================================================================================================

/// With token_supply seeded at 400_000, `set_max_supply(300_000)` (< token_supply) traps the EXACT
/// ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY (the below-supply guard, after mutability/auth/pause pass).
#[tokio::test]
async fn set_max_supply_below_supply_rejects() -> Result<()> {
    let gm = guarded_faucet(400_000, true)?;
    let account = faucet_account(&gm.harness);
    let result = run_set_max_supply_tx(&gm.harness, &account, holder(), 300_000, 7).await;
    assert_transaction_executor_error!(result, err_new_max_supply_below_token_supply());
    Ok(())
}

// PAUSE GATE — set_max_supply traps the EXACT pause error when paused (forbidden #8)
// ================================================================================================

/// After the ATTEST_ADMIN holder pauses the faucet (stock `PausableManager::pause`, gated on the same
/// ATTEST_ADMIN Authority), a holder-sent `set_max_supply` passes mutability + auth but traps the
/// EXACT ERR_PAUSABLE_IS_PAUSED — proving the pause guard is real (the `is_paused` slot is installed by
/// the faucet, so this is never a missing-slot artifact).
#[tokio::test]
async fn set_max_supply_paused_rejects() -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);

    // tx1: the holder pauses the faucet (is_paused := true).
    let paused = run_pause_tx(&gm.harness, &account, holder(), 5)
        .await
        .expect("the ATTEST_ADMIN holder can pause the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;

    // tx2: set_max_supply by the holder now traps the EXACT pause error (mutability + auth pass).
    let result = run_set_max_supply_tx(&gm.harness, &evolved, holder(), 500_000, 7).await;
    assert_transaction_executor_error!(result, MasmError::from_static_str("the contract is paused"));
    Ok(())
}
