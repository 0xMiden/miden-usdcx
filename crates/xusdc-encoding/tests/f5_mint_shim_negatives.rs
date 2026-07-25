//! F5 — scheme-aware mint-shim negatives.
//!
//! The reconciled `xreserve_mint_note_entry.masm` accepts a mint note with EXACTLY one scheme-1
//! attestation + EXACTLY one scheme-2 NetworkAccountTarget (routing-only), and rejects every other
//! attachment shape. These negatives construct a malformed mint note and consume it **directly** as
//! an unauthenticated input against the production network-auth faucet (no bring-up: the mint note is
//! allowlisted row 1, so it reaches the shim and traps THERE, before any mint/domain/attester logic;
//! no block commit, so no inclusion-proof requirement). Each pins the EXACT `ERR_*`.
//!
//! Against the reconciled shim: (a)/(d) → `TARGET_MISSING` (scheme-2 presence), (b)/(c0) →
//! `ATTACHMENT_MISSING` (scheme-1 presence), (c3) → the `ATTACHMENT_COUNT` "exactly two". History:
//! authored executing-red against the pre-fix `eq.1` shim. Non-vacuity: neutralizing the scheme-2
//! presence assert re-reds (a)+(d) (a bare `eq.2`→`eq.1` does not, since the scheme-2 assert fires
//! first).

mod support;

use core::slice;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::note::xreserve_mint::{XReserveMintNote, XRESERVE_MINT_ATTACHMENT_SCHEME};
use xusdc_encoding::xreserve::encoding::deposit_intent_to_packed_felts;

const MAX_SUPPLY: u64 = 1_000_000;

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

fn accept_payload() -> Vec<u8> {
    let v = xusdc_encoding::vectors::load();
    v.families
        .di
        .iter()
        .find(|d| d.kind == "accept")
        .expect("an accepted deposit-intent vector")
        .bytes()
}

/// A scheme-1 attestation-shaped attachment (9 zero words — deliberately NOT the v16 11-word
/// attestation shape; immaterial here: the shim traps on count/scheme selection before any
/// size/hash check runs in these negatives).
fn scheme1_attestation() -> NoteAttachment {
    NoteAttachment::with_words(
        NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME).expect("scheme 1 valid"),
        vec![Word::from([0u32, 0, 0, 0]); 9],
    )
    .expect("scheme-1 attachment builds")
}

/// The scheme-2 NetworkAccountTarget routing attachment for `faucet_id`.
fn scheme2_target(faucet_id: AccountId) -> NoteAttachment {
    NoteAttachment::from(
        NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).expect("public faucet id"),
    )
}

/// A distinct extra attachment (scheme 7) to exercise the wrong-total-count path.
fn scheme7_extra() -> NoteAttachment {
    NoteAttachment::with_words(
        NoteAttachmentScheme::new(7).expect("scheme 7 valid"),
        vec![Word::from([9u32, 0, 0, 0])],
    )
    .expect("scheme-7 attachment builds")
}

/// Builds a mint note (the pinned mint script + a valid DepositIntent storage) carrying `attachments`
/// verbatim. The note script/root is unchanged, so the note stays allowlisted (row 1) and reaches the
/// shim on consume.
fn mint_note_with_attachments(
    sender: AccountId,
    faucet_id: AccountId,
    attachments: Vec<NoteAttachment>,
    seed: u64,
) -> Result<Note> {
    let items = deposit_intent_to_packed_felts(&accept_payload())
        .map_err(|e| anyhow::anyhow!("packing the deposit intent: {e}"))?;
    let storage = NoteStorage::new(items)?;
    let recipient = NoteRecipient::new(
        note_rng(seed).draw_word(),
        XReserveMintNote::script(),
        storage,
    );
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::with_account_target(faucet_id));
    let vault = NoteAssets::new(vec![])?;
    if attachments.is_empty() {
        Ok(Note::new(vault, metadata, recipient))
    } else {
        Ok(Note::with_attachments(
            vault,
            metadata,
            recipient,
            NoteAttachments::new(attachments)?,
        ))
    }
}

/// Builds a fresh production network-auth faucet, constructs a malformed mint note whose attachment
/// set is `attachments_for(faucet_id)`, and consumes it directly (unauthenticated input, no commit),
/// returning the raw executor result for `assert_transaction_executor_error!`.
async fn consume_with_attachments(
    seed: u64,
    attachments_for: impl FnOnce(AccountId) -> Vec<NoteAttachment>,
) -> std::result::Result<
    miden_protocol::transaction::ExecutedTransaction,
    miden_tx::TransactionExecutorError,
> {
    let pf = setup_production_faucet(MAX_SUPPLY, 0, |_| Vec::new())
        .expect("production network-auth faucet");
    let attachments = attachments_for(pf.faucet_id);
    let note = mint_note_with_attachments(test_account_id(3), pf.faucet_id, attachments, seed)
        .expect("building the malformed mint note");
    pf.mock_chain
        .build_tx_context(pf.faucet_id, &[], slice::from_ref(&note))
        .expect("consume tx context")
        .build()
        .expect("consume tx build")
        .execute()
        .await
}

// (a) scheme-1 attestation but NO scheme-2 target → TARGET_MISSING.
#[tokio::test]
async fn mint_note_missing_scheme2_target_rejected() -> Result<()> {
    let result = consume_with_attachments(1, |_| vec![scheme1_attestation()]).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TARGET_MISSING")
    );
    Ok(())
}

// (b) scheme-2 target but NO scheme-1 attestation → ATTACHMENT_MISSING (regression guard).
#[tokio::test]
async fn mint_note_missing_scheme1_attestation_rejected() -> Result<()> {
    let result = consume_with_attachments(2, |f| vec![scheme2_target(f)]).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTACHMENT_MISSING")
    );
    Ok(())
}

// (c0) zero attachments → ATTACHMENT_MISSING (regression guard).
#[tokio::test]
async fn mint_note_zero_attachments_rejected() -> Result<()> {
    let result = consume_with_attachments(3, |_| vec![]).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTACHMENT_MISSING")
    );
    Ok(())
}

// (c3) three attachments → ATTACHMENT_COUNT (the reworded "exactly two"): RED vs the current
// "exactly one" MASM.
#[tokio::test]
async fn mint_note_three_attachments_rejected() -> Result<()> {
    let result = consume_with_attachments(4, |f| {
        vec![scheme1_attestation(), scheme2_target(f), scheme7_extra()]
    })
    .await;
    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("mint note must carry exactly two attachments")
    );
    Ok(())
}

// (d) two scheme-1 attestations (no scheme-2) → TARGET_MISSING.
#[tokio::test]
async fn mint_note_two_scheme1_rejected() -> Result<()> {
    let result =
        consume_with_attachments(5, |_| vec![scheme1_attestation(), scheme1_attestation()]).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TARGET_MISSING")
    );
    Ok(())
}
