//! F4-REVERSAL transfer-blocklist SEMANTICS suite (MockChain) — the §1.5 flow matrix (split out of
//! `transfer_blocklist_e2e.rs` for the G3 file-size ceiling; the role-gating delegation contract lives
//! there). With the asset POLICED (callback-Enabled faucet + active `BasicBlocklist`): a BLOCKED holder
//! cannot SEND (incl. a burn note — full freeze incl. redemption); a BLOCKED recipient cannot CONSUME
//! (the note strands, supply/vaults unmoved); a mint/transfer TO a blocked recipient strands at consume;
//! UNBLOCK restores both directions; PAUSE halts holder transfers (send + a real holder→holder P2ID);
//! the faucet-side burn consume is callback-unaffected; and every policed transfer by a non-faucet
//! account requires the faucet attached as a FOREIGN account (the client-side coupling).

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_processor::ExecutionError;
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteId, NoteType, Nullifier};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::note::P2idNote;
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};
use miden_tx::{TransactionExecutorError, TransactionKernelError};
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveBlockAccountNote, XReservePauseNote, XReserveUnblockAccountNote,
};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

const MAX_SUPPLY: u64 = 1_000_000;
const HOLDER_BALANCE: u64 = 10_000;
const SEND_AMOUNT: u64 = 5_000;

// The production builder seeds DOM_PAUSER = id(2) and BLK_MANAGER = id(4).
fn blk_manager() -> AccountId {
    test_account_id(4)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}

fn err_blocked() -> MasmError {
    MasmError::from_static_str("account is blocked")
}
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(5u32),
        Felt::from(9u32),
    ]))
}

/// The stock `blocked_accounts` map slot (installed by the `BasicBlocklist` companion).
const BLOCKED_ACCOUNTS_SLOT: &str =
    "miden::standards::faucets::policies::transfer::blocklist::blocked_accounts";

/// Reads `blocked_accounts[account]` from a committed/evolved faucet (`[1,0,0,0]` blocked).
fn read_blocked(faucet: &Account, account: AccountId) -> Result<Word> {
    let slot =
        StorageSlotName::new(BLOCKED_ACCOUNTS_SLOT).context("blocked_accounts slot label")?;
    let key = Word::from([
        Felt::ZERO,
        Felt::ZERO,
        account.suffix(),
        account.prefix().as_felt(),
    ]);
    faucet
        .storage()
        .get_map_item(&slot, StorageMapKey::new(key))
        .map_err(|e| anyhow::anyhow!("reading blocked_accounts[{account}]: {e}"))
}

fn blocked_word() -> Word {
    Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

// PART B — the blocklist semantics (the flow matrix, foreign-account coupling)
// ================================================================================================

/// A committed policed faucet + a holder wallet pre-funded with `HOLDER_BALANCE` policed xUSDC, plus
/// COMMITTED (genesis) `block_account` / `unblock_account` admin notes targeting the holder — seeded so
/// the faucet can consume them in a proper block (an inline unauthenticated note cannot be committed
/// via `prove_next_block`).
struct SemanticsFixture {
    chain: MockChain,
    faucet_id: AccountId,
    holder_id: AccountId,
    block_note_id: NoteId,
    unblock_note_id: NoteId,
    /// A committed P2ID note carrying `SEND_AMOUNT` policed xUSDC TO the holder — a policed incoming
    /// transfer whose consume fires the RECEIVE callback (native = the holder/consumer).
    incoming_p2id_id: NoteId,
    incoming_p2id_nullifier: Nullifier,
    /// A committed DOM_PAUSER pause admin note (to exercise the pause-halts-transfer semantic).
    pause_note_id: NoteId,
    /// A committed BLK_MANAGER block note targeting the FAUCET ITSELF — the callback-only sentinel for
    /// the faucet-side burn consume (a receive callback would trap on the blocked faucet).
    block_faucet_note_id: NoteId,
}

/// Builds a policed (callback-Enabled) production faucet from the shipped composition and a holder
/// wallet holding `HOLDER_BALANCE` of its asset. `add_faucet_account` derives `AssetCallbackFlag`
/// from the composition (Enabled here — the blocklist is wired), so the asset is genuinely policed.
/// Seeds (as COMMITTED genesis notes) the block/unblock admin notes targeting the holder, a DOM_PAUSER
/// pause note, and an incoming P2ID carrying `SEND_AMOUNT` policed xUSDC to the holder.
fn semantics_fixture() -> Result<SemanticsFixture> {
    // token_supply seeded at HOLDER_BALANCE so the faucet-side burn-consume test can decrement it
    // without underflow (a holder consume never touches token_supply, so this is neutral elsewhere).
    let components = production_component_set(MAX_SUPPLY, HOLDER_BALANCE)?;
    let mut builder = MockChain::builder();
    let faucet = add_faucet_account(&mut builder, Auth::IncrNonce, components)?;
    let faucet_id = faucet.id();
    assert_eq!(
        faucet_id.asset_callback_flag(),
        miden_protocol::account::AssetCallbackFlag::Enabled,
        "the semantics fixture faucet must be callback-Enabled (policed asset)"
    );
    let asset = FungibleAsset::new(faucet_id, HOLDER_BALANCE).context("holder asset")?;
    let holder = add_emitting_wallet(&mut builder, Auth::IncrNonce, [asset.into()])?;
    let holder_id = holder.id();

    // Seed the BLK_MANAGER block/unblock admin notes (targeting the holder) as COMMITTED genesis notes.
    let block_note =
        XReserveBlockAccountNote::create(blk_manager(), faucet_id, holder_id, &mut note_rng(100))?;
    let unblock_note = XReserveUnblockAccountNote::create(
        blk_manager(),
        faucet_id,
        holder_id,
        &mut note_rng(101),
    )?;
    // A DOM_PAUSER pause admin note (DOM_PAUSER = id(2), seeded by the production builder).
    let pause_note = XReservePauseNote::create(dom_pauser(), faucet_id, &mut note_rng(102))?;
    // A BLK_MANAGER block note targeting the FAUCET ITSELF (the burn-callback sentinel).
    let block_faucet_note =
        XReserveBlockAccountNote::create(blk_manager(), faucet_id, faucet_id, &mut note_rng(104))?;
    // A policed P2ID carrying SEND_AMOUNT xUSDC TO the holder (an incoming transfer to consume).
    let incoming_p2id: Note = P2idNote::builder()
        .sender(test_account_id(77))
        .target(holder_id)
        .asset(FungibleAsset::new(faucet_id, SEND_AMOUNT).context("incoming p2id asset")?)
        .generate_serial_number(&mut note_rng(103))
        .note_type(NoteType::Public)
        .build()
        .context("building the incoming P2ID")?
        .into();

    let block_note_id = block_note.id();
    let unblock_note_id = unblock_note.id();
    let pause_note_id = pause_note.id();
    let block_faucet_note_id = block_faucet_note.id();
    let incoming_p2id_id = incoming_p2id.id();
    let incoming_p2id_nullifier = incoming_p2id.nullifier();
    builder.add_output_note(RawOutputNote::Full(block_note));
    builder.add_output_note(RawOutputNote::Full(unblock_note));
    builder.add_output_note(RawOutputNote::Full(pause_note));
    builder.add_output_note(RawOutputNote::Full(block_faucet_note));
    builder.add_output_note(RawOutputNote::Full(incoming_p2id));

    let chain = builder
        .build()
        .context("building the semantics MockChain")?;
    Ok(SemanticsFixture {
        chain,
        faucet_id,
        holder_id,
        block_note_id,
        unblock_note_id,
        incoming_p2id_id,
        incoming_p2id_nullifier,
        pause_note_id,
        block_faucet_note_id,
    })
}

/// The holder's total vault balance of the faucet's fungible asset (vault iteration).
fn holder_balance(chain: &MockChain, holder_id: AccountId, faucet_id: AccountId) -> Result<u64> {
    Ok(chain
        .committed_account(holder_id)?
        .vault()
        .assets()
        .filter_map(|a| match a {
            Asset::Fungible(f) if f.faucet_id() == faucet_id => Some(u64::from(f.amount())),
            _ => None,
        })
        .sum())
}

/// The faucet's committed `token_supply` (mint/burn ledger; a holder consume must NOT move it).
fn faucet_supply(chain: &MockChain, faucet_id: AccountId) -> Result<u64> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(u64::from(
        miden_standards::account::faucets::FungibleFaucet::try_from(storage)?.token_supply(),
    ))
}

/// Consumes the incoming P2ID with `holder` as the consumer, attaching the faucet as a foreign
/// account (the receive callback runs `basic_blocklist::check_policy` on the holder).
async fn consume_incoming_p2id(
    chain: &MockChain,
    holder: &Account,
    note_id: NoteId,
    faucet_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let foreign = chain
        .get_foreign_account_inputs(faucet_id)
        .expect("faucet foreign-account inputs (committed)");
    chain
        .build_tx_context(holder.clone(), &[note_id], &[])
        .expect("building the recipient consume tx context")
        .foreign_accounts([foreign])
        .build()
        .expect("building the recipient consume tx")
        .execute()
        .await
}

/// Consumes a COMMITTED admin note (block or unblock) against the faucet and commits the resulting
/// block, so the committed faucet state (the foreign-account view the send callback loads) reflects
/// the map change.
async fn commit_faucet_consume(
    chain: &mut MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
) -> Result<()> {
    let faucet = chain.committed_account(faucet_id)?.clone();
    let tx = chain
        .build_tx_context(faucet, &[note_id], &[])
        .context("building the faucet admin-note consume tx context")?
        .build()
        .context("building the faucet admin-note consume tx")?
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("the faucet admin-note consume must execute: {e}"))?;
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;
    Ok(())
}

/// A burn note (a holder→note SEND of `SEND_AMOUNT` policed xUSDC) that fires the send callback.
fn holder_burn_note(
    holder_id: AccountId,
    faucet_id: AccountId,
    seed: u64,
) -> XReserveBurnNoteBundle {
    let items = XReserveBurnItems {
        amount: miden_protocol::asset::AssetAmount::new(SEND_AMOUNT).expect("valid amount"),
        dest_domain: 9,
        dest_recipient: [0xAB; 32],
        salt: [0xCD; 32],
    };
    let note = XReserveBurnNote::create(holder_id, faucet_id, items, &mut note_rng(seed))
        .expect("building the holder burn note");
    let asset = FungibleAsset::new(faucet_id, SEND_AMOUNT).expect("valid burn asset");
    XReserveBurnNoteBundle { note, asset }
}

struct XReserveBurnNoteBundle {
    note: miden_protocol::note::Note,
    asset: FungibleAsset,
}

/// Emits `bundle` (a holder SEND of policed xUSDC) WITHOUT attaching the faucet as a foreign account —
/// the client-side coupling probe. Mirrors `support::try_emit_burn_note` minus the foreign attachment.
async fn emit_without_faucet_foreign(
    chain: &MockChain,
    bundle: &XReserveBurnNoteBundle,
    faucet_id: AccountId,
    holder_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx_script = miden_standards::code_builder::CodeBuilder::new()
        .with_dynamically_linked_library(
            emit_helper_component()
                .expect("emit helper compiles")
                .component_code()
                .clone(),
        )
        .expect("linking the emit helper")
        .compile_tx_script(send_burn_note_script(
            &bundle.note,
            &bundle.asset,
            faucet_id,
        ))
        .expect("the holder send script compiles");
    chain
        .build_tx_context(holder_id, &[], &[])
        .expect("building the holder emit tx context")
        .tx_script(tx_script)
        .extend_advice_inputs(attachment_advice(&bundle.note))
        .extend_expected_output_notes(vec![RawOutputNote::Full(bundle.note.clone())])
        .build()
        .expect("building the holder emit tx")
        .execute()
        .await
}

/// A NON-blocked holder CAN send policed xUSDC WHEN the faucet is attached as a foreign account (the
/// send callback runs `basic_blocklist::check_policy` on the holder — not blocked — and passes). This
/// is the GREEN baseline for the blocked/coupling negatives below.
#[tokio::test]
async fn unblocked_holder_can_send_with_faucet_foreign() -> Result<()> {
    let f = semantics_fixture()?;
    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 20);
    try_emit_burn_note(
        &f.chain,
        &bundle.note,
        &bundle.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await
    .expect("a non-blocked holder can send policed xUSDC with the faucet attached as foreign");
    Ok(())
}

/// A BLOCKED holder CANNOT send policed xUSDC: after the BLK_MANAGER blocks the holder, the holder's
/// emit of a burn note (a SEND) fires the send callback, which traps the EXACT stock
/// `"account is blocked"` — blocking is a FULL freeze, incl. burn/redemption (§1.5).
#[tokio::test]
async fn blocked_holder_cannot_send_or_redeem() -> Result<()> {
    let mut f = semantics_fixture()?;
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_note_id).await?;

    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 22);
    let result = try_emit_burn_note(
        &f.chain,
        &bundle.note,
        &bundle.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await;
    assert_transaction_executor_error!(result, err_blocked());
    Ok(())
}

/// UNBLOCK restores the ability to send: block → send rejected, unblock → the SAME send succeeds.
#[tokio::test]
async fn unblock_restores_the_holder_send() -> Result<()> {
    let mut f = semantics_fixture()?;

    // block → the send is rejected.
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_note_id).await?;
    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 24);
    let rejected = try_emit_burn_note(
        &f.chain,
        &bundle.note,
        &bundle.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await;
    assert_transaction_executor_error!(rejected, err_blocked());

    // unblock (BLK_MANAGER) + commit.
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.unblock_note_id).await?;

    // the SAME send now succeeds (a fresh note; the previous one was never created).
    let bundle2 = holder_burn_note(f.holder_id, f.faucet_id, 26);
    try_emit_burn_note(
        &f.chain,
        &bundle2.note,
        &bundle2.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await
    .expect("after unblock the holder can send again");
    Ok(())
}

/// CLIENT-SIDE COUPLING (pinned executable): a policed-asset SEND by a non-faucet account FAILS when
/// the faucet is NOT attached as a foreign account — the kernel cannot dyncall the faucet's policy, so
/// `before_foreign_load` fails. This documents, as an executable test, that every wallet/tool moving
/// policed xUSDC must load the faucet as a foreign account.
#[tokio::test]
async fn send_without_faucet_foreign_account_fails() -> Result<()> {
    let f = semantics_fixture()?;
    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 27);
    let result = emit_without_faucet_foreign(&f.chain, &bundle, f.faucet_id, f.holder_id).await;
    let err = result.expect_err(
        "a policed-asset send WITHOUT the faucet foreign account must fail (the kernel cannot load \
         the faucet to run the transfer policy)",
    );
    // G4: DESTRUCTURE the typed error chain (no Debug-substring matching). The kernel fires the
    // `before_foreign_load` host event and fails to obtain the (undeclared) faucet foreign account,
    // surfaced as
    //   TransactionExecutorError::TransactionProgramExecutionFailed(
    //     ExecutionError::EventError { event_name, error, .. })
    // where the boxed `error` downcasts to
    //   TransactionKernelError::GetForeignAccountInputs { foreign_account_id, .. }.
    // Each typed field is asserted: the event is before_foreign_load and the missing foreign account
    // is THIS faucet. A different (non-foreign) failure cannot satisfy this.
    let ExecutionError::EventError {
        event_name, error, ..
    } = (match err {
        TransactionExecutorError::TransactionProgramExecutionFailed(exec_err) => exec_err,
        other => panic!("expected TransactionProgramExecutionFailed, got: {other:?}"),
    })
    else {
        panic!("expected ExecutionError::EventError (a failing host event)");
    };
    assert_eq!(
        event_name.as_ref().map(|n| n.as_str()),
        Some("miden::protocol::account::before_foreign_load"),
        "the failing host event must be `before_foreign_load`"
    );
    let kernel_err = error
        .downcast_ref::<TransactionKernelError>()
        .expect("the event error must be a TransactionKernelError");
    match kernel_err {
        TransactionKernelError::GetForeignAccountInputs {
            foreign_account_id, ..
        } => {
            assert_eq!(
                *foreign_account_id, f.faucet_id,
                "the missing foreign account must be THIS faucet"
            );
        }
        other => panic!("expected GetForeignAccountInputs, got: {other:?}"),
    }
    Ok(())
}

// PART C — the RECEIVE side + pause + faucet-side burn (the rest of the §1.5 flow matrix)
// ================================================================================================

/// A BLOCKED recipient CANNOT consume an incoming policed-xUSDC note: the receive callback (native =
/// the consumer) traps the EXACT stock `"account is blocked"`. The note STRANDS — it stays committed
/// (its nullifier unspent — the stock P2ID has NO sender reclaim, so recovery is by unblocking the
/// recipient), the recipient's vault is unchanged, and the
/// faucet's token_supply is unchanged (a consume never moves supply). §1.5 receive row.
#[tokio::test]
async fn blocked_recipient_cannot_consume_and_the_note_strands() -> Result<()> {
    let mut f = semantics_fixture()?;
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_note_id).await?;

    let supply_before = faucet_supply(&f.chain, f.faucet_id)?;
    let balance_before = holder_balance(&f.chain, f.holder_id, f.faucet_id)?;
    assert!(
        f.chain.is_note_committed(&f.incoming_p2id_id),
        "precondition: the incoming P2ID is committed before the consume attempt"
    );

    let holder = f.chain.committed_account(f.holder_id)?.clone();
    let result = consume_incoming_p2id(&f.chain, &holder, f.incoming_p2id_id, f.faucet_id).await;
    assert_transaction_executor_error!(result, err_blocked());

    // STRANDED: the rejected consume nullifies nothing — the note is still committed + unspent.
    assert!(
        f.chain.is_note_committed(&f.incoming_p2id_id),
        "the rejected consume leaves the note stranded (still committed)"
    );
    assert!(
        f.chain.is_note_unspent(&f.incoming_p2id_nullifier),
        "the stranded note's nullifier is unspent (recoverable by unblocking the recipient — the \
         stock P2ID has no sender reclaim)"
    );
    assert_eq!(
        holder_balance(&f.chain, f.holder_id, f.faucet_id)?,
        balance_before,
        "the blocked recipient's vault is unchanged (it received nothing)"
    );
    assert_eq!(
        faucet_supply(&f.chain, f.faucet_id)?,
        supply_before,
        "the faucet token_supply is unchanged (a stranded consume moves no supply)"
    );
    Ok(())
}

/// MINT/transfer TO a blocked recipient SUCCEEDS at creation, then STRANDS at consume. The incoming
/// P2ID carrying policed xUSDC to the (later-blocked) recipient was created and committed regardless
/// of the recipient's state (the send/mint side checks the SENDER, never the target); once the
/// recipient is blocked, its consume traps and the funds strand — the §1.5 "mint to a blocked
/// recipient strands" row. (The faucet's own mint is the special case where the send-side native is
/// the faucet, which is never blocked, so a mint to a blocked recipient always creates the note.)
#[tokio::test]
async fn transfer_to_a_blocked_recipient_strands_at_consume() -> Result<()> {
    let mut f = semantics_fixture()?;

    // The note carrying xUSDC to the recipient exists (committed) — creation to the (soon-blocked)
    // recipient succeeded; the target is never inspected at send/mint time.
    assert!(
        f.chain.is_note_committed(&f.incoming_p2id_id),
        "the transfer TO the recipient was created (the target is not checked at send/mint time)"
    );

    // Now block the recipient; the pre-existing incoming transfer strands at the recipient's consume.
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_note_id).await?;
    let holder = f.chain.committed_account(f.holder_id)?.clone();
    let result = consume_incoming_p2id(&f.chain, &holder, f.incoming_p2id_id, f.faucet_id).await;
    assert_transaction_executor_error!(result, err_blocked());
    assert!(
        f.chain.is_note_unspent(&f.incoming_p2id_nullifier),
        "the funds strand at consume (the note is unspent; recovery is by unblocking the recipient, \
         not a sender reclaim — the stock P2ID has none)"
    );
    Ok(())
}

/// UNBLOCK restores the RECEIVE side (not just SEND): a blocked recipient's consume is rejected, then
/// after unblock the SAME incoming note consumes and credits the recipient's vault.
#[tokio::test]
async fn unblock_restores_the_recipient_consume() -> Result<()> {
    let mut f = semantics_fixture()?;

    // block → the recipient consume is rejected.
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_note_id).await?;
    let holder = f.chain.committed_account(f.holder_id)?.clone();
    let rejected = consume_incoming_p2id(&f.chain, &holder, f.incoming_p2id_id, f.faucet_id).await;
    assert_transaction_executor_error!(rejected, err_blocked());

    // unblock (BLK_MANAGER) + commit → the SAME committed note now consumes, crediting the vault.
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.unblock_note_id).await?;
    let balance_before = holder_balance(&f.chain, f.holder_id, f.faucet_id)?;
    let holder = f.chain.committed_account(f.holder_id)?.clone();
    let consume = consume_incoming_p2id(&f.chain, &holder, f.incoming_p2id_id, f.faucet_id)
        .await
        .expect("after unblock the recipient can consume the incoming P2ID");
    f.chain.add_pending_executed_transaction(&consume)?;
    f.chain.prove_next_block()?;
    assert_eq!(
        holder_balance(&f.chain, f.holder_id, f.faucet_id)?,
        balance_before + SEND_AMOUNT,
        "after unblock the recipient's vault is credited the incoming amount"
    );
    Ok(())
}

/// PAUSE halts a holder's policed transfer even for a NON-blocked holder: with an active transfer
/// policy the send callback runs `pausable::assert_not_paused` BEFORE the blocklist check, so while
/// paused a holder→note SEND traps the EXACT stock `"the contract is paused"` — pause is a chain-wide
/// freeze on xUSDC movement, not just mint/burn (§1.5 pause row).
#[tokio::test]
async fn pause_halts_a_holder_policed_transfer() -> Result<()> {
    let mut f = semantics_fixture()?;
    // DOM_PAUSER pauses the faucet + commit (so the foreign faucet the send callback loads is paused).
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.pause_note_id).await?;

    // The holder is NOT blocked, yet the SEND is halted by the pause check inside the send callback.
    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 30);
    let result = try_emit_burn_note(
        &f.chain,
        &bundle.note,
        &bundle.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// The FAUCET-SIDE burn consume is callback-UNAFFECTED — proven with a CALLBACK-ONLY SENTINEL: the
/// FAUCET IS BLOCKED (blocked_accounts[faucet] = 1) before it consumes the burn note. The stock
/// `receive_and_burn` flow (`remove_all_assets` → `faucet::burn`) adds the asset to neither a vault nor
/// an output note, so NO receive callback fires on the faucet side — and the consume SUCCEEDS despite
/// the faucet being blocked. This distinguishes the intended absence of a receive callback from an
/// erroneous receive callback that runs and (mis)permits: had a receive callback dispatched with
/// native = the blocked faucet, it would trap `"account is blocked"` and this test would FAIL. (Not
/// attaching a foreign account is irrelevant — the faucet is the native consuming account.) §1.5 burn row.
#[tokio::test]
async fn faucet_side_burn_consume_is_callback_unaffected() -> Result<()> {
    let mut f = semantics_fixture()?;

    // A non-blocked holder emits a burn note (the holder-side SEND callback fires + needs the faucet
    // foreign — handled by try_emit_burn_note). Committed before the faucet is blocked.
    let bundle = holder_burn_note(f.holder_id, f.faucet_id, 31);
    let emit = try_emit_burn_note(
        &f.chain,
        &bundle.note,
        &bundle.asset,
        f.faucet_id,
        f.holder_id,
    )
    .await
    .expect("the non-blocked holder emits the burn note");
    f.chain.add_pending_executed_transaction(&emit)?;
    f.chain.prove_next_block()?;

    // SENTINEL: block the FAUCET ITSELF. `check_policy` checks the native account; if a receive
    // callback dispatched on the burn consume (native = faucet), it would now trap "account is blocked".
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.block_faucet_note_id).await?;
    let faucet = f.chain.committed_account(f.faucet_id)?.clone();
    assert_eq!(
        read_blocked(&faucet, f.faucet_id)?,
        blocked_word(),
        "sentinel precondition: the faucet is blocked on itself before the burn consume"
    );

    // The FAUCET consumes the committed burn note: burning fires no receive callback, so despite the
    // faucet being blocked the consume must SUCCEED and decrement token_supply. A receive-callback
    // dispatch here would trap on the blocked faucet.
    let supply_before = faucet_supply(&f.chain, f.faucet_id)?;
    let burned = f
        .chain
        .build_tx_context(faucet, &[bundle.note.id()], &[])
        .context("faucet burn-consume tx context")?
        .build()
        .context("faucet burn-consume tx")?
        .execute()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "the faucet-side burn consume must SUCCEED even with the faucet BLOCKED — burning \
                 fires no receive callback (a dispatched receive callback would trap here): {e}"
            )
        })?;
    f.chain.add_pending_executed_transaction(&burned)?;
    f.chain.prove_next_block()?;
    assert_eq!(
        faucet_supply(&f.chain, f.faucet_id)?,
        supply_before - SEND_AMOUNT,
        "the faucet-side burn decremented token_supply by the burned amount"
    );
    Ok(())
}

/// PAUSE halts an actual HOLDER-TO-HOLDER P2ID transfer (not merely a burn-note send): while paused,
/// a holder sending `SEND_AMOUNT` policed xUSDC to ANOTHER holder via the stock P2ID note traps the
/// EXACT `"the contract is paused"` — the send callback's pause check fires before the blocklist check
/// for a wallet→wallet transfer (§1.5 pause row, the explicit holder-to-holder case).
#[tokio::test]
async fn pause_halts_a_holder_to_holder_p2id_transfer() -> Result<()> {
    let mut f = semantics_fixture()?;
    commit_faucet_consume(&mut f.chain, f.faucet_id, f.pause_note_id).await?;

    // A genuine wallet→wallet P2ID transfer: the holder sends to a DIFFERENT holder id.
    let other_holder = test_account_id(78);
    let asset = FungibleAsset::new(f.faucet_id, SEND_AMOUNT).context("p2id transfer asset")?;
    let p2id: Note = P2idNote::builder()
        .sender(f.holder_id)
        .target(other_holder)
        .asset(asset)
        .generate_serial_number(&mut note_rng(40))
        .note_type(NoteType::Public)
        .build()
        .context("building the holder-to-holder P2ID")?
        .into();

    // The holder emits the P2ID (send callback → pause check FIRST → traps while paused).
    let result = try_emit_burn_note(&f.chain, &p2id, &asset, f.faucet_id, f.holder_id).await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}
