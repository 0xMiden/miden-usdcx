//! The one behaviour the standard blocklist manager gives up, and what bounds it.
//!
//! The retired custom `block_account` refused to block the faucet's own id: the blocklist is the
//! faucet's active send AND receive transfer policy, so blocking the faucet freezes it as a transfer
//! party and halts minting and redeeming alike. The standard procedure validates nothing about its
//! target, and it has no equivalent guard.
//!
//! Accepting that was a ratified decision, taken against evidence rather than argument, so the
//! evidence lives here. The state is genuinely reachable on chain — demonstrated, not asserted. Two
//! things bound it: the faucet's note factory refuses to build such a note, so operator error alone
//! cannot produce one; and the unblock note carries no assets, so consuming it dispatches no
//! transfer policy and it lands even while the faucet is blocked against itself. Recovery is always
//! available.

mod support;

use anyhow::{Context, Result};
use miden_protocol::Word;
use miden_standards::note::BlocklistConfig;
use support::w2admin::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveBlocklistConfigNote, XReserveBlocklistNoteError,
};

// THE FACTORY REFUSAL — off-chain belt-and-braces, not an authorization boundary
// ================================================================================================

/// The faucet's note factory refuses to build a note that would block the faucet itself. This is
/// off-chain belt-and-braces, not a gate — the role holder can hand-roll the standard note past it
/// — but it stops the operator error the deleted MASM guard used to stop.
#[test]
fn the_note_factory_refuses_to_build_a_self_block_note() -> Result<()> {
    let faucet_id = test_faucet_id(7);
    let err = XReserveBlocklistConfigNote::block(
        blocklist_holder(),
        faucet_id,
        faucet_id,
        &mut note_rng(18),
    )
    .expect_err("the factory must refuse to build a self-block note");

    assert!(
        matches!(err, XReserveBlocklistNoteError::SelfBlockRejected { .. }),
        "the refusal must be the specific self-block rejection, not some other note error: {err:?}"
    );
    Ok(())
}

/// Unblocking the faucet is harmless, so the factory allows it — that is the recovery path for a
/// self-block that got past the factory.
#[test]
fn the_note_factory_allows_unblocking_the_faucet() -> Result<()> {
    let faucet_id = test_faucet_id(7);
    XReserveBlocklistConfigNote::unblock(
        blocklist_holder(),
        faucet_id,
        faucet_id,
        &mut note_rng(19),
    )
    .context("unblocking the faucet must remain constructible — it is the recovery path")?;
    Ok(())
}

// THE REACHABLE STATE, ON THE PRODUCTION FAUCET
// ================================================================================================

/// The accepted regression itself: the standard block procedure validates nothing about its target,
/// so a hand-rolled note blocks the faucet against itself and the write lands. The deleted MASM
/// guard has no standard equivalent; this documents the state that is now reachable.
#[tokio::test]
async fn a_hand_rolled_note_can_block_the_faucet_against_itself() -> Result<()> {
    let mut pf = admin_faucet(|id| {
        vec![raw_blocklist_note(
            blocklist_holder(),
            id,
            BlocklistConfig::BlockAccount { account: id },
            20,
        )
        .expect("self-block note")]
    })?;
    let note = pf.seeded_notes[0].clone();

    let after = consume_and_commit(&mut pf, &note, "a hand-rolled self-block").await?;
    assert_eq!(
        read_blocked(&after, pf.faucet_id)?,
        set_word(),
        "the standard block procedure performs no target validation, so a self-block lands — the \
         accepted regression of adopting it"
    );
    Ok(())
}

/// What bounds that regression: the unblock note carries no assets, so consuming it dispatches no
/// transfer policy and it lands even while the faucet is blocked against itself. Recovery is always
/// available.
#[tokio::test]
async fn a_self_block_is_recoverable_through_the_unblock_note() -> Result<()> {
    let mut pf = admin_faucet(|id| {
        vec![
            raw_blocklist_note(
                blocklist_holder(),
                id,
                BlocklistConfig::BlockAccount { account: id },
                21,
            )
            .expect("self-block note"),
            XReserveBlocklistConfigNote::unblock(blocklist_holder(), id, id, &mut note_rng(22))
                .expect("self-unblock note"),
        ]
    })?;
    let (block, unblock) = (pf.seeded_notes[0].clone(), pf.seeded_notes[1].clone());

    let blocked = consume_and_commit(&mut pf, &block, "a hand-rolled self-block").await?;
    assert_eq!(
        read_blocked(&blocked, pf.faucet_id)?,
        set_word(),
        "the self-block must land"
    );

    let recovered = consume_and_commit(&mut pf, &unblock, "a self-unblock").await?;
    assert_eq!(
        read_blocked(&recovered, pf.faucet_id)?,
        Word::empty(),
        "an asset-less unblock note must land even while the faucet is blocked against itself, so \
         a self-block is always recoverable"
    );
    Ok(())
}

// THE SAME TWO FACTS ON THE ISOLATED ADMIN MODEL
// ================================================================================================
// The production tests above prove it for the shipped faucet. These prove the cause is the standard
// procedure itself and not something about the faucet's composition: on an account carrying only
// the standard admin pieces, a self-block still lands and still recovers.

/// The custom block procedure refuses to block the faucet's own id, because the blocklist is the
/// active send and receive transfer policy and blocking the faucet freezes it as a transfer party.
/// The stock block procedure has no such guard: the role holder can block the account itself and
/// the write lands.
///
/// This is the plan's one genuine behaviour regression, and it is demonstrated here rather than
/// argued, so the decision to accept it is taken against evidence.
#[tokio::test]
async fn the_standard_block_procedure_accepts_the_accounts_own_id_on_a_bare_model() -> Result<()> {
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![raw_blocklist_note(
            blocklist_holder(),
            id,
            BlocklistConfig::BlockAccount { account: id },
            13,
        )
        .expect("self-block note")]
    })?;

    let evolved =
        consume_and_commit_against(&mut chain, &account, &notes[0], "a self-block").await?;
    assert_eq!(
        read_blocked(&evolved, account.id())?,
        set_word(),
        "the stock block procedure performs no target validation, so blocking the account's own \
         id succeeds — the guard the custom wrapper carries has no stock equivalent"
    );
    Ok(())
}

/// What bounds that regression: recovery. The unblock note carries no assets, so consuming it
/// dispatches no transfer policy and it lands even while the account is blocked against itself.
#[tokio::test]
async fn a_self_block_is_recoverable_on_a_bare_model() -> Result<()> {
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![
            raw_blocklist_note(
                blocklist_holder(),
                id,
                BlocklistConfig::BlockAccount { account: id },
                14,
            )
            .expect("self-block note"),
            raw_blocklist_note(
                blocklist_holder(),
                id,
                BlocklistConfig::UnblockAccount { account: id },
                15,
            )
            .expect("self-unblock note"),
        ]
    })?;

    let blocked =
        consume_and_commit_against(&mut chain, &account, &notes[0], "a self-block").await?;
    assert_eq!(
        read_blocked(&blocked, account.id())?,
        set_word(),
        "the self-block must land"
    );

    let recovered =
        consume_and_commit_against(&mut chain, &blocked, &notes[1], "a self-unblock").await?;
    assert_eq!(
        read_blocked(&recovered, account.id())?,
        Word::empty(),
        "an asset-less unblock note must land even while the account is blocked against itself, \
         so a self-block is always recoverable"
    );
    Ok(())
}
