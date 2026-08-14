//! Security tests for the xReserve blocklist note factory.
//!
//! Blocking the faucet's own account id would prevent it from transferring assets. The xReserve
//! blocklist note factory rejects that target as a construction-time guard against operator error.
//!
//! These tests use the production note factory and faucet composition. They share a serial guard
//! because the mint-transport test machinery does not support parallel execution.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::{Felt, Word};
use miden_standards::account::policies::BlocklistStorage;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{XReserveBlocklistNote, XReserveBlocklistNoteError};

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

// THE BLOCKLIST SELF-BLOCK GUARD
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
