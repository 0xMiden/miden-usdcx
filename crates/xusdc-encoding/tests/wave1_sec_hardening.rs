//! SECURITY HARDENING — the construction-time guards the note factories carry.
//!
//! The standard admin procedures validate nothing about the values they write, so each guard lives
//! in the factory that builds the note: it refuses the harmful value before a note exists. Each
//! refusal has its exact-error negative plus a positive that proves it is not over-broad (a
//! legitimate block / a legitimate in-range min-burn write still succeeds). A refusal is a guard
//! against operator error, not an authorization boundary — what the chain does when someone
//! hand-rolls the standard note past it, and why that state is recoverable, is covered in
//! `w2admin_production_admin_effects.rs`.
//!
//! GUARD 1 — blocking the faucet's OWN account id is refused (blocking the faucet freezes it as a
//! transfer party: mint-and-send and burn/redeem both trap).
//! GUARD 2 — a min-burn floor below `MIN_BURN_SIZE_FLOOR` is refused (a zero floor admits
//! zero-amount burn notes). Above-range floors are unrepresentable: the factory takes an
//! [`AssetAmount`], whose constructor rejects values over the fungible-asset maximum.
//!
//! The on-chain positives run through the PRODUCTION note factories on the REAL production faucet
//! composition, so they hold the tripwire serial guard (they share the mint-transport machinery
//! that flakes under parallel `cargo test`).

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::{BlocklistStorage, MinBurnAmount};
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveBlocklistNote, XReserveBlocklistNoteError, XReserveMinBurnAmountNote,
    XReserveMinBurnAmountNoteError,
};

// The production builder seeds owner = id(1) and BLK_MANAGER = id(4). A distinct block TARGET for
// the not-over-broad positive is any other id.
fn blk_manager() -> AccountId {
    test_account_id(4)
}
fn other_account() -> AccountId {
    test_account_id(50)
}

fn blocked_word() -> Word {
    Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

/// The stock `blocked_accounts` entry for `account` (installed by the `BasicBlocklist` companion);
/// the key is `[0, 0, suffix, prefix]` and the value `[1,0,0,0]` when blocked.
fn read_blocked(faucet: &Account, account: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        account.suffix(),
        account.prefix().as_felt(),
    ]);
    read_map_word(faucet, BlocklistStorage::blocked_accounts_slot(), key)
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

// GUARD 1 — the blocklist self-block refusal
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
/// really happened). Proves the refusal targets ONLY the faucet's own id.
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

// GUARD 2 — the min-burn zero-floor refusal
// ================================================================================================

/// A min-burn note carrying a floor of 0 cannot be built: the factory refuses it, so the note never
/// reaches a chain. The stock `set_min_burn_amount` accepts 0, and a zero floor admits zero-amount
/// burn notes — which is what makes this refusal non-vacuous.
#[test]
fn a_min_burn_note_carrying_a_zero_floor_cannot_be_built() {
    let faucet_id = test_faucet_id(1);
    let err = XReserveMinBurnAmountNote::create(
        administrator(),
        faucet_id,
        AssetAmount::ZERO,
        &mut note_rng(720),
    )
    .expect_err("the factory must refuse a zero-floor min-burn note");
    assert!(
        matches!(
            err,
            XReserveMinBurnAmountNoteError::BelowFloorRejected { min_burn_amount: 0 }
        ),
        "the refusal must be the specific below-floor rejection, not some other note error: {err:?}"
    );
}

/// The refusal is NOT over-broad: an ADMIN-sent write at the floor boundary (`new_min = 1`) still
/// builds, SUCCEEDS on chain, and writes `[1,0,0,0]` into the stock `MinBurnAmount` slot.
#[tokio::test]
async fn set_min_burn_at_the_floor_still_succeeds() -> Result<()> {
    let _serial = tripwire_serial_guard().await;
    let mut pf = setup_production_faucet(MAX_SUPPLY, 0, |_recipient, faucet_id| {
        vec![stock_min_burn_note(administrator(), faucet_id, 1, 722)
            .expect("building the floor min-burn note")]
    })?;
    let floor_note = pf.seeded_notes[0].clone();

    let tx = consume_note(&pf.mock_chain, pf.faucet_id, floor_note.id())
        .await
        .map_err(|e| anyhow::anyhow!("a min-burn write of 1 must still succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)?;

    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    let floor = faucet
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount slot: {e}"))?;
    assert_eq!(
        floor,
        min_word(1),
        "a min-burn write of 1 lands [1,0,0,0] in the stock MinBurnAmount slot"
    );
    Ok(())
}
