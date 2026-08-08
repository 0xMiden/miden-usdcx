//! SECURITY HARDENING — the two admin-path guards adopted from external security review.
//!
//! Without each guard the operation below would SUCCEED instead of trapping.
//! Each guard has its EXACT-error negative plus the positive
//! that proves the guard is not over-broad (a legitimate block / a legitimate in-range set_min_burn
//! still succeeds), and the floor boundary is re-proven so FIX 2 cannot silently weaken the
//! pre-existing lower guard.
//!
//! FIX 1 — blocking the faucet's OWN account id must be refused (blocking the faucet freezes it as
//! a transfer party: mint-and-send and burn/redeem both trap). The guard used to live on-chain, in
//! the faucet's own `block_account` wrapper; adopting the standard blocklist manager retired that
//! wrapper, and the standard procedure validates nothing about its target, so the refusal now lives
//! in the note factory instead. That is a construction-time guard against operator error, not an
//! authorization boundary — what the chain does when someone hand-rolls the standard note past it,
//! and why that state is recoverable, is covered in `w2admin_production_admin_effects.rs`.
//! FIX 2 — the runtime `set_min_burn_size` note must reject
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
use xusdc_encoding::note::xreserve_admin::{
    XReserveBlocklistNote, XReserveBlocklistNoteError, XReserveSetMinBurnSizeNote,
};

// The maximum representable fungible-asset amount = 2^63 - 2^31 (miden::protocol::asset
// FUNGIBLE_ASSET_MAX_AMOUNT = 0x7fffffff80000000). Inlined here (not the MASM const) so the
// test stands independent of the guard's own constant; parity with the MASM guard's imported
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

// FIX 1 — the blocklist self-block guard
// ================================================================================================

/// A block note targeting the faucet's OWN account id cannot be built: the factory refuses it, so
/// the note never reaches a chain. Without the refusal the note builds and the block lands, freezing
/// the faucet as a transfer party — which is what makes this test non-vacuous.
#[test]
fn a_block_note_targeting_the_faucet_itself_cannot_be_built() {
    let faucet_id = test_faucet_id(1);
    let err = XReserveBlocklistNote::block(blk_manager(), faucet_id, faucet_id, &mut note_rng(710))
        .expect_err("the factory must refuse a self-targeting block note");
    assert!(
        matches!(err, XReserveBlocklistNoteError::SelfBlockRejected { .. }),
        "the refusal must be the specific self-block rejection, not some other note error: {err:?}"
    );
}

/// The refusal is NOT over-broad: a `BLK_MANAGER`-sent block targeting a DIFFERENT account still
/// builds, SUCCEEDS on chain, and writes the blocked marker (a non-vacuous success — the map write
/// really happened). Proves FIX 1 refuses ONLY the faucet's own id.
#[tokio::test]
async fn block_account_targeting_a_different_account_still_succeeds() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![
            stock_block_note(blk_manager(), faucet_id, other_account(), 711)
                .expect("building the other-account block note"),
        ]
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

// FIX 2 — the min-burn upper-range guard
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
        vec![XReserveSetMinBurnSizeNote::create(
            administrator(),
            faucet_id,
            above_max,
            &mut note_rng(720),
        )
        .expect("building the above-max min-burn note")]
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
            administrator(),
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
            XReserveSetMinBurnSizeNote::create(administrator(), faucet_id, 1, &mut note_rng(722))
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
            XReserveSetMinBurnSizeNote::create(administrator(), faucet_id, 0, &mut note_rng(723))
                .expect("building the zero min-burn note"),
        ]
    })?;
    let zero_note = pf.seeded_notes[0].clone();

    let result = consume_note(&pf.mock_chain, pf.faucet_id, zero_note.id()).await;
    assert_transaction_executor_error!(result, &err_min_burn_below_floor());
    Ok(())
}
