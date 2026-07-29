//! ATTESTATION MINT POLICY E2E — the BINDING + TRANSPORT-SHAPE half of the recomposed
//! mint-semantics matrix (Wave-1 S1), the sibling of `mint_policy_e2e.rs` (one G3-sized module
//! per concern; the shared production-transport harness is `support::mint_transport`).
//!
//! This file carries the ratified ASSERT-MATCH binding negatives (amount / tag / note-type — the
//! recipient leg lives with the replay/fee legs in `wave1_recomposition_e2e.rs`), the
//! attested-recipient extraction guards (the DEV-10 pad guard + the >= modulus canonicality
//! reject table), the transport-shape negatives (the consciously re-materialized F5 posture:
//! missing/extra attachments, word counts, length binding, truncation), the pause halt, the F1
//! restatement (a policy-less mint path cannot mint — asserted on the EXACT kernel input-note
//! bound error), and the MockChain half of the network-routing proof. Every negative asserts its
//! EXACT error (never `is_err()`) and the payload-based rejects prove fail-closure.

mod support;

use anyhow::{Context, Result};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteTag, NoteType};
use miden_standards::note::{NetworkAccountTarget, P2idNote, P2idNoteStorage};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_admin::XReservePauseNote;

use miden_protocol::{Felt, Word};

// ASSERT-MATCH — the note-supplied values must EQUAL their attested derivations
// ================================================================================================

/// A note claiming MORE than the attested amount rejects with the amount-mismatch binding error.
#[tokio::test]
async fn mint_rejects_an_amount_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 17);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT + 1, // claims one unit more than attested
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        86,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_AMOUNT_MISMATCH"),
    )
    .await
}

/// A note whose output tag does not target the attested recipient rejects with the tag binding
/// error (A13: the policy derives the expected tag with the standards helper).
#[tokio::test]
async fn mint_rejects_a_tag_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 18);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: Some(NoteTag::with_account_target(pf.producer_id)), // mis-targeted
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        87,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_TAG_MISMATCH"),
    )
    .await
}

/// A PRIVATE-mode mint note (opaque recipient digest, private output note) rejects: the attested
/// output note is always public.
#[tokio::test]
async fn mint_rejects_a_private_output_note() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 19);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: false, // the 13-item private layout — note_type PRIVATE
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        88,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC"),
    )
    .await
}

// THE ATTESTED-RECIPIENT EXTRACTION (DEV-10 layout guards, through the policy)
// ================================================================================================

/// An attested payload whose remoteRecipient carries a NON-ZERO leading pad rejects in the
/// policy's recipient extraction (the DEV-10 AccountId-in-bytes32 layout guard).
#[tokio::test]
async fn mint_rejects_a_malformed_attested_recipient() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 20);
    payload[REMOTE_RECIPIENT_BYTE_OFF] = 0xaa; // the 16-byte pad must be zero
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id, // the STORAGE recipe stays honest — the PAYLOAD is bad
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        89,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE"),
    )
    .await
}

/// The NONCANONICAL reject family (one `#[rstest]` case table per G4): an attested
/// `remoteRecipient` whose prefix or suffix u64 region (bytes 16..24 / 24..32 of the bytes32)
/// holds `u64::MAX` — a value `>= p` that would REDUCE mod the field — rejects in the policy's
/// no-reduction `build_felt` round-trip (`ERR_XRESERVE_RECIPIENT_NONCANONICAL`, mirroring Rust
/// `Felt::try_from`; one case per `build_felt` call site). The storage recipe stays honest — the
/// PAYLOAD limb is what is bad, so the trap is attributable to the extraction guard alone.
#[rstest]
#[case::prefix(REMOTE_RECIPIENT_BYTE_OFF + 16, 38, 107)]
#[case::suffix(REMOTE_RECIPIENT_BYTE_OFF + 24, 39, 108)]
#[tokio::test]
async fn mint_rejects_a_noncanonical_recipient(
    #[case] limb_byte_off: usize,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    payload[limb_byte_off..limb_byte_off + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        rng_seed,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_RECIPIENT_NONCANONICAL"),
    )
    .await
}

// TRANSPORT SHAPE — the attachment negatives (consciously re-materialized F5 posture)
// ================================================================================================

/// Dropping the scheme-4 intent attachment rejects.
#[tokio::test]
async fn mint_rejects_a_missing_intent_attachment() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 21);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            intent: false,
            ..AttachmentPlan::default()
        },
        90,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_INTENT_MISSING"),
    )
    .await
}

/// Dropping the scheme-5 attestation attachment rejects.
#[tokio::test]
async fn mint_rejects_a_missing_attestation_attachment() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 22);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            attestation: false,
            ..AttachmentPlan::default()
        },
        91,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTESTATION_MISSING"),
    )
    .await
}

/// Dropping the scheme-2 routing target rejects (the routing bind stays part of the shape).
#[tokio::test]
async fn mint_rejects_a_missing_routing_target() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 23);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            target: false,
            ..AttachmentPlan::default()
        },
        92,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TARGET_MISSING"),
    )
    .await
}

/// A FOURTH attachment rejects (exactly three).
#[tokio::test]
async fn mint_rejects_a_fourth_attachment() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 24);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            extra_scheme: Some(6),
            ..AttachmentPlan::default()
        },
        93,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT"),
    )
    .await
}

/// A wrong-sized attestation attachment (10 words instead of 11) rejects.
#[tokio::test]
async fn mint_rejects_a_wrong_attestation_word_count() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 25);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            attestation_words_override: Some(10),
            ..AttachmentPlan::default()
        },
        94,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTESTATION_NUM_WORDS"),
    )
    .await
}

/// An intent attachment with a TRAILING EXTRA word (word count above the embedded length claim)
/// rejects — the hash-committed transport length is bound to the intent's own hookDataLen.
#[tokio::test]
async fn mint_rejects_an_intent_length_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 26);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            intent_extra_words: 1,
            ..AttachmentPlan::default()
        },
        95,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_INTENT_WORDS"),
    )
    .await
}

/// An intent attachment SHORTER than the 60-felt header rejects at the transport floor.
#[tokio::test]
async fn mint_rejects_a_truncated_intent() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 27);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT,
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            intent_truncate_words: Some(14), // below the 15-word header floor
            ..AttachmentPlan::default()
        },
        96,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_INTENT_TOO_SHORT"),
    )
    .await
}

// PAUSE HALT — the dispatcher gate (execute_mint_policy runs assert_not_paused FIRST)
// ================================================================================================

/// A DOM_PAUSER pause halts the attested mint at the policy dispatcher's stock pause gate.
#[tokio::test]
async fn mint_halts_while_paused() -> Result<()> {
    let mut pf = fixture_with(MAX_SUPPLY, |_, faucet_id| {
        vec![
            XReservePauseNote::create(dom_pauser(), faucet_id, &mut note_rng(953))
                .expect("building the DOM_PAUSER pause note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // identifier_init + set_attester + pause
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 28);
    let note = honest_note(&pf, &payload, 97)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        &MasmError::from_static_str("the contract is paused"),
    )
    .await
}

// F1 RESTATED — without the attested transport there is no acceptable mint
// ================================================================================================

/// A tx-script `mint_and_send` (no active note, no attachments) CANNOT mint: the attestation
/// policy's first transport read (`active_note::find_attachment`) runs outside note processing,
/// so it traps the EXACT kernel input-note bound assert — there is no input note to read — and
/// the former deny-guard posture is preserved structurally: every supply increase must ride the
/// attested note transport. Asserts the exact kernel error + zero supply.
#[tokio::test]
async fn tx_script_mint_and_send_cannot_mint() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let recipient_recipe =
        P2idNoteStorage::new(pf.recipient_id).into_recipient(Word::from([9u32, 9, 9, 9]));
    let src = format!(
        "
            @transaction_script
            pub proc main
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                exec.::miden::standards::assets::fungible_asset::create
                call.::miden::standards::faucets::fungible::mint_and_send
                dropw dropw dropw dropw
            end
            ",
        recipient = recipient_recipe.digest(),
        note_type = Felt::from(NoteType::Public),
        tag = u32::from(NoteTag::with_account_target(pf.recipient_id)),
        amount = MINT_AMOUNT,
        faucet_id_prefix = pf.faucet_id.prefix().as_felt(),
        faucet_id_suffix = pf.faucet_id.suffix(),
    );
    let tx_script = miden_standards::code_builder::CodeBuilder::new()
        .compile_tx_script(&src)
        .map_err(|e| anyhow::anyhow!("mint_and_send tx script: {e}"))?;
    let result = pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .tx_script(tx_script)
        .build()
        .context("tx build")?
        .execute()
        .await;
    // the EXACT trap: the kernel's input-note index bound (the policy asks for the active note's
    // attachments; the tx has zero input notes) — a stable pinned-kernel assertion, so the
    // fail-closure is attributable, not a generic `is_err()`
    assert_transaction_executor_error!(
        result,
        &MasmError::from_static_str(
            "requested input note index should be less than the total number of input notes"
        )
    );
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "no supply may be created outside the attested transport"
    );
    Ok(())
}

// ROUTING — the MockChain-expressible half of the network-routing proof
// ================================================================================================

/// The constructed mint note is addressed for network execution at the faucet — the note's own
/// tag is the faucet account target, the scheme-2 attachment binds the faucet id — and the
/// faucet (a network account under the stock `AuthNetworkAccount` allowlist) consumes it through
/// the STOCK script end to end. The tag-based DISCOVERY itself is ntx-builder (node service)
/// behavior outside MockChain's model — recorded as a live-validation caveat for the deploy
/// task.
#[tokio::test]
async fn mint_note_routes_to_the_faucet_network_account() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 29);
    let note = honest_note(&pf, &payload, 98)?;

    // the network-routing identity: the note itself targets the FAUCET (the output-note tag
    // inside the storage targets the recipient — two different tags, both asserted).
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(pf.faucet_id),
        "the mint note's own tag is the faucet account target (stock MintNote conversion)"
    );
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "network notes are public"
    );
    let target = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == NetworkAccountTarget::ATTACHMENT_SCHEME)
        .context("the scheme-2 routing attachment is present")?;
    let bound = NetworkAccountTarget::try_from(target)
        .map_err(|e| anyhow::anyhow!("decoding the routing attachment: {e}"))?;
    assert_eq!(
        bound.target_id(),
        pf.faucet_id,
        "the routing attachment binds THIS faucet's network account"
    );

    // the consumption proof: the network faucet consumes the committed note via the STOCK script.
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the routed mint must succeed: {e}"))?;
    assert_eq!(tx.output_notes().num_notes(), 1);
    let out = tx.output_notes().get_note(0);
    assert_eq!(
        out.recipient().map(|r| r.script().root()),
        Some(P2idNote::script_root()),
        "the attested output note is the canonical P2ID"
    );
    let mut chain = pf.mock_chain;
    commit(&mut chain, &tx)?;
    let faucet = committed(&chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "the consumed nonce is marked"
    );
    Ok(())
}
