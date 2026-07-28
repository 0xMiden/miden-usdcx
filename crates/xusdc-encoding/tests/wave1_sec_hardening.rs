//! WAVE-1 SECURITY HARDENING — the two admin-path guards (partylikeits1983 review, PA2 + PA3).
//!
//! Written RED-FIRST (anneal test-first protocol): every negative below FAILS against the
//! un-guarded build (the guard does not exist yet, so the operation SUCCEEDS instead of trapping)
//! and flips GREEN once the guard lands. Each guard has its EXACT-error negative plus the positive
//! that proves the guard is not over-broad (a legitimate block / a legitimate in-range set_min_burn
//! still succeeds), and the floor boundary is re-proven so FIX 2 cannot silently weaken the
//! pre-existing lower guard.
//!
//! FIX 1 (PA2) — `xreserve::blocklist_admin::block_account` must reject blocking the faucet's OWN
//! account id (blocking the faucet freezes it as a transfer party: mint-and-send and burn/redeem
//! both trap). FIX 2 (PA3) — the runtime `set_min_burn_size` note must reject
//! `new_min > FUNGIBLE_ASSET_MAX_AMOUNT` (an out-of-range floor makes the stock
//! `check_policy` (`min_burn_amount <= amount`) unsatisfiable for every real burn, halting all
//! redemptions).
//!
//! Both are security tripwires driven through the PRODUCTION note factories on the REAL production
//! faucet composition, so they hold the tripwire serial guard (they share the mint-transport
//! machinery that flakes under parallel `cargo test`).

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::errors::MasmError;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::MinBurnAmount;
use miden_testing::assert_transaction_executor_error;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{XReserveBlockAccountNote, XReserveSetMinBurnSizeNote};

// The maximum representable fungible-asset amount = 2^63 - 2^31 (miden::protocol::asset
// FUNGIBLE_ASSET_MAX_AMOUNT = 0x7fffffff80000000). Inlined here (not the MASM const) so the
// red-suite compiles + executes against the un-guarded build; parity with the MASM guard's imported
// constant is what FIX 2 asserts end-to-end.
const FUNGIBLE_ASSET_MAX_AMOUNT: u64 = 0x7fffffff_80000000;

// The production builder seeds owner = id(1) and BLK_MANAGER = id(4). A distinct block TARGET for
// the not-over-broad positive is any other id.
fn blk_manager() -> AccountId {
    test_account_id(4)
}
fn other_account() -> AccountId {
    test_account_id(50)
}

// EXACT expected guard errors (assert-specific-error-in-tests). Inlined as the literal strings the
// MASM `ERR_*` constants carry — never `is_err()`.
fn err_cannot_block_self() -> MasmError {
    MasmError::from_static_str("cannot block the faucet's own account")
}
fn err_min_burn_above_max() -> MasmError {
    MasmError::from_static_str("min burn size exceeds the maximum asset amount")
}

/// The stock `blocked_accounts` map slot (installed by the `BasicBlocklist` companion); key is
/// `[0, 0, suffix, prefix]`, value `[1,0,0,0]` when blocked.
const BLOCKED_ACCOUNTS_SLOT: &str =
    "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts";

fn blocked_word() -> Word {
    Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

fn read_blocked(faucet: &Account, account: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        account.suffix(),
        account.prefix().as_felt(),
    ]);
    read_map_word(faucet, BLOCKED_ACCOUNTS_SLOT, key)
}

/// The stock `MinBurnAmount` floor-slot word for a floor `v` (`[v,0,0,0]`), read-back oracle.
fn min_word(v: u64) -> Word {
    Word::from([
        Felt::try_from(v).expect("floor fits the field"),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ])
}

// FIX 1 (PA2) — the blocklist self-block guard
// ================================================================================================

/// A `BLK_MANAGER`-sent `block_account` targeting the faucet's OWN account id is REJECTED with the
/// EXACT `ERR_XRESERVE_CANNOT_BLOCK_SELF`. Without the guard this SUCCEEDS (freezing the faucet as a
/// transfer party) — the red-suite proof this tests something real.
#[tokio::test]
async fn block_account_targeting_the_faucet_itself_is_rejected() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![XReserveBlockAccountNote::create(
            blk_manager(),
            faucet_id,
            faucet_id,
            &mut note_rng(710),
        )
        .expect("building the self-targeting block_account note")]
    })?;
    let self_block_note = pf.seeded_notes[0].clone();

    let result = consume_note(&pf.mock_chain, pf.faucet_id, self_block_note.id()).await;
    assert_transaction_executor_error!(result, err_cannot_block_self());

    // no state change: the faucet was never added to its own blocklist (the trap precedes the write).
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    assert_eq!(
        read_blocked(&faucet, pf.faucet_id)?,
        Word::from([Felt::ZERO; 4]),
        "a rejected self-block leaves blocked_accounts[faucet] empty (no partial write)"
    );
    Ok(())
}

/// The guard is NOT over-broad: a `BLK_MANAGER`-sent `block_account` targeting a DIFFERENT account
/// still SUCCEEDS and writes the blocked marker (a non-vacuous success — the map write really
/// happened). Proves FIX 1 rejects ONLY the faucet's own id.
#[tokio::test]
async fn block_account_targeting_a_different_account_still_succeeds() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![XReserveBlockAccountNote::create(
            blk_manager(),
            faucet_id,
            other_account(),
            &mut note_rng(711),
        )
        .expect("building the other-account block_account note")]
    })?;
    let block_note = pf.seeded_notes[0].clone();

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, block_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("blocking a DIFFERENT account must still succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    assert_eq!(
        read_blocked(&faucet, other_account())?,
        blocked_word(),
        "after a BLK_MANAGER block of a different account, blocked_accounts[other] == [1,0,0,0]"
    );
    Ok(())
}

// FIX 2 (PA3) — the min-burn upper-range guard
// ================================================================================================

/// A `set_min_burn_size` note with `new_min = FUNGIBLE_ASSET_MAX_AMOUNT + 1` is REJECTED with the
/// EXACT `ERR_XRESERVE_MIN_BURN_ABOVE_MAX`. Without the guard this SUCCEEDS, wedging the burn floor
/// above every representable amount so `check_policy` (`min <= amount`) can never pass — all
/// redemptions halt.
#[tokio::test]
async fn set_min_burn_above_the_asset_max_is_rejected() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let above_max = FUNGIBLE_ASSET_MAX_AMOUNT + 1;
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![
            XReserveSetMinBurnSizeNote::create(owner(), faucet_id, above_max, &mut note_rng(720))
                .expect("building the above-max min-burn note"),
        ]
    })?;
    let above_max_note = pf.seeded_notes[0].clone();

    let result = consume_note(&pf.mock_chain, pf.faucet_id, above_max_note.id()).await;
    assert_transaction_executor_error!(result, &err_min_burn_above_max());

    // no state change: the floor slot is untouched by the rejected write.
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_ne!(
        floor,
        min_word(above_max),
        "a rejected above-max set_min_burn_size must NOT have written the out-of-range floor"
    );
    Ok(())
}

/// The upper bound is INCLUSIVE: `new_min = FUNGIBLE_ASSET_MAX_AMOUNT` (the boundary) is ACCEPTED and
/// the full word `[MAX,0,0,0]` lands in the stock `MinBurnAmount` slot. Proves FIX 2 rejects only
/// STRICTLY-above-max, not the max itself.
#[tokio::test]
async fn set_min_burn_at_exactly_the_asset_max_is_accepted() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![XReserveSetMinBurnSizeNote::create(
            owner(),
            faucet_id,
            FUNGIBLE_ASSET_MAX_AMOUNT,
            &mut note_rng(721),
        )
        .expect("building the at-max min-burn note")]
    })?;
    let at_max_note = pf.seeded_notes[0].clone();

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, at_max_note.id())
        .await
        .map_err(|e| {
            anyhow::anyhow!("set_min_burn_size(MAX) must succeed (inclusive bound): {e}")
        })?;
    commit(&mut pf.mock_chain, &tx)?;

    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_eq!(
        floor,
        min_word(FUNGIBLE_ASSET_MAX_AMOUNT),
        "set_min_burn_size(MAX) writes [MAX,0,0,0] to the stock MinBurnAmount slot"
    );
    Ok(())
}

/// A floor-respecting in-range write (`new_min = 1`, the floor boundary) still SUCCEEDS — FIX 2 does
/// not disturb the low end. Guards against an accidental sign/order flip that would reject the whole
/// legitimate range.
#[tokio::test]
async fn set_min_burn_at_the_floor_still_succeeds() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![
            XReserveSetMinBurnSizeNote::create(owner(), faucet_id, 1, &mut note_rng(722))
                .expect("building the floor min-burn note"),
        ]
    })?;
    let floor_note = pf.seeded_notes[0].clone();

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, floor_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("set_min_burn_size(1) must still succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_eq!(
        floor,
        min_word(1),
        "set_min_burn_size(1) writes [1,0,0,0] to the stock MinBurnAmount slot"
    );
    Ok(())
}

/// The pre-existing LOWER guard is intact after FIX 2: `new_min = 0` is STILL rejected with the EXACT
/// `ERR_XRESERVE_MIN_BURN_BELOW_FLOOR` (FIX 2 adds an upper bound WITHOUT weakening the floor).
#[tokio::test]
async fn set_min_burn_zero_still_rejected_by_the_floor() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![
            XReserveSetMinBurnSizeNote::create(owner(), faucet_id, 0, &mut note_rng(723))
                .expect("building the zero min-burn note"),
        ]
    })?;
    let zero_note = pf.seeded_notes[0].clone();

    let result = consume_note(&pf.mock_chain, pf.faucet_id, zero_note.id()).await;
    assert_transaction_executor_error!(result, &err_min_burn_below_floor());
    Ok(())
}
