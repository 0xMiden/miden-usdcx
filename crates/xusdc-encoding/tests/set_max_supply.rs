//! `set_max_supply` admin surface, reconciled to the Circle-faithful OWNER-gated model.
//! This is STOCK reuse — the standard `FungibleFaucet` already exposes
//! `set_max_supply`, gated (in this order) mutability -> `authority::assert_authorized` ->
//! `assert_not_paused` -> below-current-supply. No new MASM. The reconciliation is a pure Authority
//! config change: the account installs `Authority::OwnerControlled` (was `RbacControlled{ATTEST_ADMIN}`),
//! so `authority::assert_authorized` now resolves to the Ownable2Step owner. This file covers the owner
//! gate, write integrity, the below-supply guard, the pause gate, and the immutable control. The
//! cap-enforcement seam — that changing the maximum actually changes which mints are refused for
//! exceeding it — lives in `xreserve_mint.rs`, alongside the shared mint-composition fixtures it
//! reuses.
//!
//! The net-new surface is the build-time mutability flag. The gate fixtures are built MUTABLE
//! (`is_max_supply_mutable = true`), so each gate test exercises its intended gate: the owner's
//! `set_max_supply` succeeds (write integrity), a non-owner (incl. a seeded DOM role-holder) traps
//! ERR_SENDER_NOT_OWNER with no state change, a paused faucet traps ERR_PAUSABLE_IS_PAUSED, and a
//! below-current-supply value traps ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY. `set_max_supply_immutable_traps`
//! keeps an IMMUTABLE faucet as the control, pinning that the mutability gate fires FIRST (the EXACT
//! ERR_MAX_SUPPLY_NOT_MUTABLE, even for the owner). Stock `set_max_supply` is reused verbatim — no new MASM.

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageSlotName, StorageSlotPatch};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// The seeded principals the reconciled builder installs: owner = id(1) (Ownable2Step); the two seeded
// DOM role-holders DOM_PAUSER = id(2) / DOM_MANAGER = id(3) — privileged non-owners the owner-ONLY proof
// rejects.
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}

/// Config words the builder does not read (these tests invoke `set_max_supply` via a note, never the
/// mint driver).
fn dummy_config() -> (Word, Word) {
    (Word::from([7u32, 0, 0, 0]), Word::from([11u32, 12, 13, 14]))
}

/// An owner-gated production faucet (attestation policy active) with cap 1_000_000 and a trivial
/// unused driver/probe — the base for the gate tests. `token_supply` seeds the initial
/// `token_config[token_supply]` (for the below-supply guard); `is_max_supply_mutable` is the
/// net-new flag.
fn guarded_faucet(token_supply: u64, is_max_supply_mutable: bool) -> Result<GuardedMint> {
    // a no-op placeholder driver: these tests invoke set_max_supply via a note, never a driver.
    let driver = "#! No-op placeholder driver (unused by the set_max_supply gate tests).\n\
                  #!\n\
                  #! Inputs:  [pad(16)]\n\
                  #! Outputs: [pad(16)]\n\
                  #!\n\
                  #! Invocation: call\n\
                  @account_procedure\n\
                  pub proc drive\n\
                  \x20\x20\x20\x20push.0 drop\n\
                  end\n";
    let probe = composition_supply_probe_src(0);
    let (domain, identifier) = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        1_000_000,
        token_supply,
        domain,
        identifier,
        None,
        None,
        driver,
        &probe,
        is_max_supply_mutable,
    )
}

// IMMUTABLE CONTROL (declared GREEN from the start) — the mutability gate is real and fires first
// ================================================================================================

/// On an IMMUTABLE faucet, even the owner's `set_max_supply` traps the EXACT ERR_MAX_SUPPLY_NOT_MUTABLE —
/// the mutability gate fires before auth/pause/below-supply. The immutable control: it pins that the
/// mutability gate is real and fires first, independent of the auth/pause/below-supply gates the mutable
/// tests exercise. GREEN throughout (the mutability gate precedes auth, so the sender identity is moot).
#[tokio::test]
async fn set_max_supply_immutable_traps() -> Result<()> {
    // Builder-BYPASS fixture: the production `XReserveStablecoinBuilder` now rejects an immutable
    // max_supply at build time, so this control assembles a bare immutable faucet directly. What it
    // proves is the stock RUNTIME mutability gate, which fires FIRST (before auth/pause/below-supply),
    // so a bare faucet (no Authority) traps ERR_MAX_SUPPLY_NOT_MUTABLE identically to a full production one.
    let harness = setup_bare_immutable_faucet(0, 1_000_000)?;
    let account = faucet_account(&harness);
    let result = run_set_max_supply_tx(&harness, &account, owner(), 500_000, 7).await;
    assert_transaction_executor_error!(result, err_max_supply_not_mutable());
    Ok(())
}

// OWNER GATE + WRITE INTEGRITY — RED until the Authority is flipped to OwnerControlled (green)
// ================================================================================================

/// An OWNER-sent `set_max_supply(X)` succeeds and writes ONLY word[1] (max_supply), preserving
/// token_supply/decimals/symbol (full-word read-back).
#[tokio::test]
async fn set_max_supply_owner_succeeds() -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);
    let before = read_token_config(&account)?; // [token_supply=0, max_supply=1_000_000, decimals=6, "USDCX"]

    let executed = run_set_max_supply_tx(&gm.harness, &account, owner(), 500_000, 7)
        .await
        .expect("the owner's set_max_supply must succeed on a mutable faucet");

    // write integrity: the token_config delta carries the FULL word with ONLY word[1] changed.
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotPatch::Value(after) = executed
        .account_patch()
        .storage()
        .get(&cfg_slot)
        .expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    let after = after.value().expect("value patch carries a value");
    let expected = Word::from([before[0], Felt::from(500_000u32), before[2], before[3]]);
    assert_eq!(
        after, expected,
        "set_max_supply writes word[1] only; token_supply/decimals/symbol preserved"
    );
    assert_eq!(
        after[1],
        Felt::from(500_000u32),
        "max_supply updated to 500_000"
    );
    Ok(())
}

/// Shared owner-ONLY assertion for `set_max_supply`: a NON-owner `sender` (a seeded DOM role-holder)
/// traps the EXACT ERR_SENDER_NOT_OWNER and leaves `token_config` byte-identical (the auth gate fires
/// after mutability passes; the trap commits nothing).
async fn assert_set_max_supply_non_owner_rejected(sender: AccountId) -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);
    let before = read_token_config(&account)?;

    let result = run_set_max_supply_tx(&gm.harness, &account, sender, 500_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // no state change: token_config (esp. word[1] max_supply) is byte-identical to before the reject.
    assert_eq!(
        read_token_config(&account)?,
        before,
        "a rejected non-owner set_max_supply leaves token_config unchanged"
    );
    Ok(())
}

/// Owner-ONLY: the seeded DOM_PAUSER holder id(2) is rejected from `set_max_supply`.
#[tokio::test]
async fn set_max_supply_dom_pauser_non_owner_rejects() -> Result<()> {
    assert_set_max_supply_non_owner_rejected(dom_pauser()).await
}

/// Owner-ONLY: the seeded DOM_MANAGER holder id(3) is rejected from `set_max_supply` (completing the
/// owner-ONLY cross-product for this setter).
#[tokio::test]
async fn set_max_supply_dom_manager_non_owner_rejects() -> Result<()> {
    assert_set_max_supply_non_owner_rejected(dom_manager()).await
}

// BELOW-SUPPLY GUARD — set_max_supply below current token_supply is rejected
// ================================================================================================

/// With token_supply seeded at 400_000, an OWNER-sent `set_max_supply(300_000)` (< token_supply) traps
/// the EXACT ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY (the below-supply guard, after mutability/auth/pause pass).
#[tokio::test]
async fn set_max_supply_below_supply_rejects() -> Result<()> {
    let gm = guarded_faucet(400_000, true)?;
    let account = faucet_account(&gm.harness);
    let result = run_set_max_supply_tx(&gm.harness, &account, owner(), 300_000, 7).await;
    assert_transaction_executor_error!(result, err_new_max_supply_below_token_supply());
    Ok(())
}

// PAUSE GATE — set_max_supply traps the EXACT pause error when paused
// ================================================================================================

/// After the DOM_PAUSER pauses the faucet (custom `xreserve::pause_admin::pause` — the ONLY pause
/// surface in the Domain-Pauser-only model), an owner-sent `set_max_supply` passes mutability + auth
/// but traps the EXACT
/// ERR_PAUSABLE_IS_PAUSED — proving the pause guard is real (the `is_paused` slot is installed by the
/// faucet, so this is never a missing-slot artifact).
#[tokio::test]
async fn set_max_supply_paused_rejects() -> Result<()> {
    let gm = guarded_faucet(0, true)?;
    let account = faucet_account(&gm.harness);

    // tx1: the DOM_PAUSER pauses the faucet (is_paused := true).
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // tx2: set_max_supply by the owner now traps the EXACT pause error (mutability + auth pass).
    let result = run_set_max_supply_tx(&gm.harness, &evolved, owner(), 500_000, 7).await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("the contract is paused")
    );
    Ok(())
}
