//! P5-01 CMP-B1 mint-note transport grounding canary — MockChain gate.
//!
//! Proves, with RUNNING code (not assembly), the note-transport primitive chain the real
//! `XReserveMintNote` + `receive_and_mint` wrapper build on, using SENTINEL data only:
//!
//!   - T1 (happy path, two-block): a producer tx emits a real Note carrying sentinel
//!     `NoteStorage` + ONE sentinel attachment via `output_note::create` +
//!     `output_note::add_attachment` (block N); the account consumes it by id (block N+1) with NO
//!     consume-side advice staging — the note script `call`s the probe proc, which internally
//!     asserts: `get_storage` staged the storage into the ACCOUNT call frame; `find_attachment`
//!     located the scheme; the commitments-list count is 1; `write_attachment_to_memory`
//!     hash-verified the content (num_words == 9, first/last felts); and the post-verification
//!     `adv.push_mapval` pops element-0-FIRST (the pop-order pin).
//!   - T2 (missing attachment): the same script consuming a note WITHOUT the attachment traps the
//!     canary's named `ERR_CANARY_ATTACHMENT_MISSING`.
//!   - T3 (tampered advice map): consuming a valid note with a hostile consume-side advice-map
//!     override under the attachment commitment must trap the commitment-mismatch assert inside
//!     `write_attachment_to_memory` (`pipe_preimage_to_memory`'s bare `assert_eqw` — no named
//!     error in the pinned core-lib). This also pins the AdviceInputs merge/override mechanics
//!     the real red-suite tamper test depends on.
//!
//! What this canary does NOT prove (the real-slice boundary): the real DepositIntent schema, the
//! D5a-D5e gate chain, the real wrapper's `exec.xreserve_mint::mint` hand-off, fee/pubkey/sig
//! semantics, or any Circle value. Sentinels only.

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountId};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteAttachments, NoteRecipient,
    NoteScript, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{assert_transaction_executor_error, Auth, MockChain};

use xusdc_canary_mint_note_transport::{
    attachment_sentinel_words, storage_sentinel_felts, ATTACHMENT_SCHEME, CANARY_MASM, CANARY_PATH,
    NOTE_SCRIPT_SRC,
};

const MAX_SUPPLY: u64 = 1_000_000;

// HARNESS
// ================================================================================================

/// Assembles the canary component and compiles the note script with the component library linked
/// (so `call.canary::receive_and_probe` resolves to the proc installed on the account).
fn build_component_and_script() -> anyhow::Result<(AccountComponent, NoteScript)> {
    let code = CodeBuilder::new().compile_component_code(CANARY_PATH, CANARY_MASM)?;
    let component = AccountComponent::new(
        code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-canary-mint-note-transport"),
    )?;
    let script = CodeBuilder::new()
        .with_dynamically_linked_library(&code)?
        .compile_note_script(NOTE_SCRIPT_SRC)?;
    Ok((component, script))
}

/// A fresh MockChain BUILDER carrying the producer wallet + the canary-component faucet account.
/// Returned un-built so tests can seed genesis notes once the ids are known.
fn builder_with_accounts(
    component: AccountComponent,
) -> anyhow::Result<(miden_testing::MockChainBuilder, AccountId, AccountId)> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(MAX_SUPPLY)?)
        .token_supply(AssetAmount::new(0)?)
        .build()?;
    let mut builder = MockChain::builder();
    let producer = builder.add_existing_wallet(Auth::IncrNonce)?;
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [faucet.into(), component])?;
    Ok((builder, producer.id(), account.id()))
}

/// The sentinel attachment (scheme 7, 9 words, felts 2001..=2036).
fn sentinel_attachment() -> anyhow::Result<NoteAttachment> {
    Ok(NoteAttachment::with_words(
        NoteAttachmentScheme::new(ATTACHMENT_SCHEME)?,
        attachment_sentinel_words(),
    )?)
}

/// Builds the canary note: sentinel storage, optional sentinel attachment, Public, account-target
/// tag, no assets (the mint-note shape).
fn build_canary_note(
    sender: AccountId,
    target: AccountId,
    script: NoteScript,
    serial: [u32; 4],
    with_attachment: bool,
) -> anyhow::Result<Note> {
    let storage = NoteStorage::new(storage_sentinel_felts())?;
    let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
        .with_tag(NoteTag::with_account_target(target));
    let recipient = NoteRecipient::new(Word::from(serial), script, storage);
    let assets = NoteAssets::new(vec![])?;
    let note = if with_attachment {
        let attachments = NoteAttachments::new(vec![sentinel_attachment()?])?;
        Note::with_attachments(assets, metadata, recipient, attachments)
    } else {
        Note::new(assets, metadata, recipient)
    };
    Ok(note)
}

/// The producer tx script emitting `note` exactly: `output_note::create` from the recipient
/// digest + metadata, then `output_note::add_attachment` for each attachment (the upstream
/// `note_script_that_creates_notes` pattern, miden-testing/src/utils.rs:245-315). The attachment
/// elements are supplied via the CREATE tx's advice map (producer-side, legitimate).
fn create_note_tx_script(note: &Note) -> (String, AdviceInputs) {
    let recipient = note.recipient().digest();
    let note_type = Felt::from(note.metadata().note_type());
    let tag = Felt::from(note.metadata().tag());

    let mut src = format!(
        "use miden::protocol::output_note\n\
         \n\
         begin\n\
         \x20\x20\x20\x20push.{recipient}\n\
         \x20\x20\x20\x20push.{note_type}\n\
         \x20\x20\x20\x20push.{tag}\n\
         \x20\x20\x20\x20exec.output_note::create\n"
    );
    let mut advice = AdviceInputs::default();
    for attachment in note.attachments().iter() {
        let scheme = attachment.attachment_scheme().as_u16();
        let commitment = attachment.content().to_commitment();
        src.push_str(&format!(
            "\x20\x20\x20\x20dup\n\
             \x20\x20\x20\x20push.{commitment}\n\
             \x20\x20\x20\x20push.{scheme}\n\
             \x20\x20\x20\x20exec.output_note::add_attachment\n"
        ));
        advice = advice.with_map([(commitment, attachment.content().to_elements())]);
    }
    src.push_str(
        "\x20\x20\x20\x20drop\n\
         \x20\x20\x20\x20exec.::miden::core::sys::truncate_stack\n\
         end\n",
    );
    (src, advice)
}

// T1 — HAPPY PATH (two-block create -> consume; all probe asserts pass; no consume-side advice)
// ================================================================================================

#[tokio::test]
async fn t1_two_block_create_consume_transport_probe() -> anyhow::Result<()> {
    let (component, script) = build_component_and_script()?;
    let (builder, producer_id, account_id) = builder_with_accounts(component)?;
    let note = build_canary_note(producer_id, account_id, script, [1, 2, 3, 4], true)?;
    let mut chain = builder.build()?;

    // tx0: the producer emits the note in-block (create seam WITH an attachment).
    let (src, advice) = create_note_tx_script(&note);
    let tx_script = CodeBuilder::new().compile_tx_script(src)?;
    let tx0 = chain
        .build_tx_context(producer_id, &[], &[])?
        .tx_script(tx_script)
        .extend_advice_inputs(advice)
        .extend_expected_output_notes(vec![RawOutputNote::Full(note.clone())])
        .build()?
        .execute()
        .await?;

    // NoteId parity: the emitted note (details + metadata + attachments) matches the Rust-side
    // construction — the create-seam proof for attachment-bearing notes.
    assert_eq!(tx0.output_notes().num_notes(), 1, "tx0 emits exactly one note");
    assert_eq!(
        tx0.output_notes().get_note(0).id(),
        note.id(),
        "emitted note id == Rust-side Note::with_attachments id"
    );

    // Commit block N; the note must be committed and retrievable.
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;
    assert!(chain.is_note_committed(&note.id()), "note committed at block N");

    // Block N+1: consume by id. NO tx script, NO consume-side advice staging — the executor
    // auto-injects note storage + attachment payloads into the advice map from the committed
    // note; every content assert lives inside receive_and_probe.
    let tx1 = chain
        .build_tx_context(account_id, &[note.id()], &[])?
        .build()?
        .execute()
        .await?;
    chain.add_pending_executed_transaction(&tx1)?;
    chain.prove_next_block()?;
    assert!(
        chain.is_note_consumed(&note.nullifier()),
        "canary note consumed at block N+1"
    );

    println!("[transport-canary][T1] two-block create->consume passed all probe asserts:");
    println!("[transport-canary][T1]   get_storage staged into the account call frame (count + content);");
    println!("[transport-canary][T1]   find_attachment located scheme {ATTACHMENT_SCHEME}; commitments count == 1;");
    println!("[transport-canary][T1]   write_attachment_to_memory hash-verified 9 words (first/last content);");
    println!("[transport-canary][T1]   adv.push_mapval pop order == element-0-FIRST.");
    Ok(())
}

// T2 — MISSING ATTACHMENT (find_attachment not-found path traps the named canary error)
// ================================================================================================

#[tokio::test]
async fn t2_missing_attachment_traps_named_error() -> anyhow::Result<()> {
    let (component, script) = build_component_and_script()?;
    let (mut builder, producer_id, account_id) = builder_with_accounts(component)?;
    // The attachment-LESS note, seeded at genesis (negative case; a committed note is fine).
    let note = build_canary_note(producer_id, account_id, script, [5, 6, 7, 8], false)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let chain = builder.build()?;

    let result = chain
        .build_tx_context(account_id, &[note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("canary: attachment with the expected scheme is missing")
    );
    println!("[transport-canary][T2] attachment-less note trapped ERR_CANARY_ATTACHMENT_MISSING.");
    Ok(())
}

// T3 — TAMPERED ADVICE MAP (hostile consume-side override must trap the commitment mismatch)
// ================================================================================================

#[tokio::test]
async fn t3_tampered_attachment_advice_traps_commitment_mismatch() -> anyhow::Result<()> {
    let (component, script) = build_component_and_script()?;
    let (mut builder, producer_id, account_id) = builder_with_accounts(component)?;
    // A VALID attachment-bearing note, seeded at genesis (the tamper is consume-side).
    let note = build_canary_note(producer_id, account_id, script, [9, 10, 11, 12], true)?;
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let chain = builder.build()?;

    let commitment = note
        .attachments()
        .iter()
        .next()
        .expect("note carries the sentinel attachment")
        .content()
        .to_commitment();
    // Hostile override: same key, WRONG 36 elements.
    let wrong: Vec<Felt> = (0..36u32).map(|_| Felt::from(9999u32)).collect();
    let hostile = AdviceInputs::default().with_map([(commitment, wrong)]);

    let result = chain
        .build_tx_context(account_id, &[note.id()], &[])?
        .extend_advice_inputs(hostile)
        .build()?
        .execute()
        .await;

    // The pinned core-lib's pipe_preimage_to_memory ends in a BARE `assert_eqw` (no named
    // MasmError). Pin the trap empirically: the tx must fail, and it must NOT be any canary
    // named error (i.e. the mismatch fires inside write_attachment_to_memory, before any
    // canary content assert could run).
    let err = match result {
        Ok(_) => panic!("tampered attachment advice must not execute"),
        Err(e) => format!("{e:?}"),
    };
    println!("[transport-canary][T3] tampered advice trap: {err}");
    assert!(
        !err.contains("canary:"),
        "the trap must fire inside the protocol's hash check, not a canary assert: {err}"
    );
    Ok(())
}
