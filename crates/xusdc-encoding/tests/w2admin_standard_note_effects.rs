//! What the standard config notes actually do, driven on an account carrying only the standard
//! admin pieces.
//!
//! The production suite proves the same effects on the shipped faucet. This one isolates the model:
//! with nothing but the pause flag, the blocklist storage, their two managers, a role-seeded RBAC
//! component and the authority, a failure here can only be the admin model itself rather than some
//! interaction with the faucet's mint or burn path.
//!
//! Both directions of every gate are covered, because a role that opens too much is as wrong as one
//! that opens too little — and the last test covers the case neither direction reaches: a procedure
//! with no role at all, which must fall back to the administrator.

mod support;

use anyhow::Result;
use miden_protocol::Word;
use miden_standards::account::access::Authority;
use miden_standards::note::{BlocklistConfig, PauseAction};
use support::w2admin::*;
use support::*;

/// The pause-role holder pauses the account through the stock note, and the flag the halt gates
/// read is set. This is the effect today's custom pause note produces, reached through stock code.
#[tokio::test]
async fn the_pause_role_holder_pauses_through_the_stock_note() -> Result<()> {
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![pause_action_note(pauser_holder(), id, PauseAction::Pause, 1).expect("pause note")]
    })?;
    let evolved = consume_and_commit_against(
        &mut chain,
        &account,
        &notes[0],
        "a pause from the role holder",
    )
    .await?;

    assert_eq!(
        read_paused(&account)?,
        Word::empty(),
        "the account starts unpaused"
    );
    assert_eq!(
        read_paused(&evolved)?,
        set_word(),
        "after a pause from the role holder the pause flag must be set"
    );
    Ok(())
}

/// And the same holder clears it again. Pausing that could not be undone would be a very different
/// capability from the one the faucet ships.
#[tokio::test]
async fn the_pause_role_holder_unpauses_through_the_stock_note() -> Result<()> {
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![
            pause_action_note(pauser_holder(), id, PauseAction::Pause, 2).expect("pause note"),
            pause_action_note(pauser_holder(), id, PauseAction::Unpause, 3).expect("unpause note"),
        ]
    })?;

    let paused = consume_and_commit_against(&mut chain, &account, &notes[0], "a pause").await?;
    assert_eq!(read_paused(&paused)?, set_word(), "the pause must land");

    let unpaused = consume_and_commit_against(&mut chain, &paused, &notes[1], "an unpause").await?;
    assert_eq!(
        read_paused(&unpaused)?,
        Word::empty(),
        "after an unpause from the role holder the pause flag must be cleared"
    );
    Ok(())
}

/// The blocklist-role holder blocks a target through the stock note, and the entry the transfer
/// policy reads is written. Same storage effect as today's custom block note.
#[tokio::test]
async fn the_blocklist_role_holder_blocks_through_the_stock_note() -> Result<()> {
    let target = stranger();
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![raw_blocklist_note(
            blocklist_holder(),
            id,
            BlocklistConfig::BlockAccount { account: target },
            4,
        )
        .expect("block note")]
    })?;

    assert_eq!(
        read_blocked(&account, target)?,
        Word::empty(),
        "the target starts unblocked"
    );
    let evolved = consume_and_commit_against(
        &mut chain,
        &account,
        &notes[0],
        "a block from the role holder",
    )
    .await?;
    assert_eq!(
        read_blocked(&evolved, target)?,
        set_word(),
        "after a block from the role holder the target's blocklist entry must be set"
    );
    Ok(())
}

/// And unblocks it again, clearing the entry.
#[tokio::test]
async fn the_blocklist_role_holder_unblocks_through_the_stock_note() -> Result<()> {
    let target = stranger();
    let (mut chain, account, notes) = setup_grounding(|id| {
        vec![
            raw_blocklist_note(
                blocklist_holder(),
                id,
                BlocklistConfig::BlockAccount { account: target },
                5,
            )
            .expect("block note"),
            raw_blocklist_note(
                blocklist_holder(),
                id,
                BlocklistConfig::UnblockAccount { account: target },
                6,
            )
            .expect("unblock note"),
        ]
    })?;

    let blocked = consume_and_commit_against(&mut chain, &account, &notes[0], "a block").await?;
    assert_eq!(
        read_blocked(&blocked, target)?,
        set_word(),
        "the block must land"
    );

    let unblocked =
        consume_and_commit_against(&mut chain, &blocked, &notes[1], "an unblock").await?;
    assert_eq!(
        read_blocked(&unblocked, target)?,
        Word::empty(),
        "after an unblock the target's blocklist entry must be cleared"
    );
    Ok(())
}

/// The bootstrap administrator cannot pause. Today the administrator has no pause path at all, and a map
/// entry has to take precedence over the administrator fallback for that to stay true.
#[tokio::test]
async fn the_administrator_cannot_pause() -> Result<()> {
    let (chain, account, notes) = setup_grounding(|id| {
        vec![pause_action_note(admin_holder(), id, PauseAction::Pause, 7).expect("pause note")]
    })?;

    let result = consume_against(&chain, &account, &notes[0]).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// The bootstrap administrator cannot block either — the blocklist is owned by an external role
/// holder, and that isolation is the point of the dedicated role.
#[tokio::test]
async fn the_administrator_cannot_block() -> Result<()> {
    let (chain, account, notes) = setup_grounding(|id| {
        vec![raw_blocklist_note(
            admin_holder(),
            id,
            BlocklistConfig::BlockAccount {
                account: stranger(),
            },
            8,
        )
        .expect("block note")]
    })?;

    let result = consume_against(&chain, &account, &notes[0]).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// Holding the pause role does not grant the blocklist role.
#[tokio::test]
async fn the_pause_role_holder_cannot_block() -> Result<()> {
    let (chain, account, notes) = setup_grounding(|id| {
        vec![raw_blocklist_note(
            pauser_holder(),
            id,
            BlocklistConfig::BlockAccount {
                account: stranger(),
            },
            9,
        )
        .expect("block note")]
    })?;

    let result = consume_against(&chain, &account, &notes[0]).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// And holding the blocklist role does not grant the pause role.
#[tokio::test]
async fn the_blocklist_role_holder_cannot_pause() -> Result<()> {
    let (chain, account, notes) = setup_grounding(|id| {
        vec![pause_action_note(blocklist_holder(), id, PauseAction::Pause, 10).expect("pause note")]
    })?;

    let result = consume_against(&chain, &account, &notes[0]).await;
    miden_testing::assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

/// An account holding nothing can do neither.
#[tokio::test]
async fn an_account_holding_no_role_can_neither_pause_nor_block() -> Result<()> {
    let (chain, account, notes) = setup_grounding(|id| {
        vec![
            pause_action_note(stranger(), id, PauseAction::Pause, 11).expect("pause note"),
            raw_blocklist_note(
                stranger(),
                id,
                BlocklistConfig::BlockAccount {
                    account: admin_holder(),
                },
                12,
            )
            .expect("block note"),
        ]
    })?;

    let paused = consume_against(&chain, &account, &notes[0]).await;
    miden_testing::assert_transaction_executor_error!(paused, err_sender_lacks_role());

    let blocked = consume_against(&chain, &account, &notes[1]).await;
    miden_testing::assert_transaction_executor_error!(blocked, err_sender_lacks_role());
    Ok(())
}

/// A procedure with no map entry resolves to the administrator role: the administrator can freeze,
/// and a role holder — who is not an administrator — cannot. Every one of the administrator-gated
/// setters relies on exactly this, since none of them is mapped and all of them must stay with the
/// account that holds them now.
#[tokio::test]
async fn an_unmapped_procedure_falls_back_to_the_administrator_role() -> Result<()> {
    let (mut chain, account, notes) = setup_grounding(|_| {
        vec![
            freeze_note(admin_holder(), 21).expect("administrator freeze note"),
            freeze_note(pauser_holder(), 22).expect("role-holder freeze note"),
        ]
    })?;

    let frozen = consume_and_commit_against(
        &mut chain,
        &account,
        &notes[0],
        "a freeze by the administrator",
    )
    .await?;
    assert!(
        Authority::try_read_frozen(frozen.storage())
            .map_err(|e| anyhow::anyhow!("reading the frozen flag: {e}"))?,
        "the administrator must be able to reach an unmapped authority-gated procedure"
    );

    let rejected = consume_against(&chain, &account, &notes[1]).await;
    miden_testing::assert_transaction_executor_error!(rejected, err_sender_lacks_role());
    Ok(())
}
