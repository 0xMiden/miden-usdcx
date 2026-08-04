//! End-to-end mint binding: what the attestation says must be what actually gets minted.
//!
//! The companion to `mint_policy_e2e.rs`, sharing the same production transport harness. Where
//! that file asks whether a deposit is allowed at all, this one asks whether the note the faucet
//! acts on is faithfully bound to the attested deposit — a mint that passed every check but paid
//! out a different amount, or to a different account, would be just as much a loss of funds.
//!
//! It covers:
//!
//! - The binding checks themselves: a mint note whose amount, tag, or note type does not match
//!   what the attestation committed to is rejected. (The recipient binding is tested alongside the
//!   replay and fee cases in the recomposition end-to-end suite.)
//! - Recipient extraction: the attested `remoteRecipient` is a 32-byte field carrying a Miden
//!   account id in its low bytes, so the leading pad must be zero and each id half must be below
//!   the field modulus. Both guards get their own reject cases — a non-canonical value must fail,
//!   never be silently reduced into a different, valid account id.
//! - Transport shape: the merged scheme-4 attachment's layout (attestation section, deposit
//!   intent) and every way it can be wrong — an attachment missing, doubled or extra, a truncated
//!   attachment, a length that disagrees with the payload, and each sub-region tampered with
//!   independently.
//! - The pause halt, the routing proof on a MockChain, and the restatement that a mint path with
//!   no policy installed cannot mint at all.
//!
//! Every negative asserts its exact error rather than merely failing, and the payload-driven
//! rejects also assert fail-closure — nothing minted, no nonce consumed.

mod support;

use anyhow::{Context, Result};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteAttachmentScheme, NoteTag, NoteType};
use miden_standards::note::{NetworkAccountTarget, P2idNote, P2idNoteStorage};
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::mint_transport::*;
use support::*;
use xusdc_encoding::note::xreserve_mint::{MintAttestation, XUsdcMintNote};

use miden_protocol::{Felt, Word};

// ASSERT-MATCH — the note-supplied values must EQUAL their attested derivations
// ================================================================================================

/// A note amount diverging from the attested one rejects inside the amounts stage: the note
/// amount is the witness, so an over-claim trips the verifier's no-underflow subtract and an
/// under-claim its remainder bound. (`ERR_XRESERVE_MINT_AMOUNT_MISMATCH` guards the asset
/// word's upper elements, which no note-shaped transport can set nonzero.)
#[rstest]
#[case::over_claim(1i64, 17, 86, "ERR_UNDERFLOW")]
#[case::under_claim(-1i64, 40, 109, "ERR_REMAINDER_TOO_LARGE")]
#[tokio::test]
async fn mint_rejects_an_amount_mismatch(
    #[case] delta: i64,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
    #[case] expected_err: &str,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &StoragePlan {
            recipient: pf.recipient_id,
            amount: MINT_AMOUNT.checked_add_signed(delta).expect("in range"),
            tag: None,
            public: true,
        },
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan::default(),
        rng_seed,
    )?;
    expect_reject(&mut pf, note, &payload, shell_error_by_name(expected_err)).await
}

/// A note whose output tag does not target the attested recipient rejects with the tag binding
/// error — the policy derives the expected tag with the standards helper and compares.
#[tokio::test]
async fn mint_rejects_a_tag_mismatch() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
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
    bring_up(&mut pf, 1).await?;
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

// EXTRACTING THE RECIPIENT FROM THE ATTESTED PAYLOAD — the layout guards, run through the policy
// ================================================================================================

/// A recipient field with a non-zero leading pad is rejected rather than truncated.
///
/// A Miden account id occupies only the low 16 bytes of the 32-byte `remoteRecipient`; the high
/// bytes must be zero. If the policy ignored them instead of asserting, two different attested
/// payloads would extract to the same account, and the attestation would no longer pin who gets
/// paid.
///
/// The decode delegates to the standards `eth::bytes32_to_account_id`, which splits the pad check
/// in two — bytes 0..12 in the bytes32 entry point, bytes 12..16 in the `to_account_id` it calls.
/// Both halves get a case, so neither can go unasserted: a pass that only covered bytes 0..12
/// would still let a recipient with four dirty bytes at offset 12 through.
#[rstest]
#[case::leading_twelve(REMOTE_RECIPIENT_BYTE_OFF, 20, 89, "ERR_BYTES32_PADDING_NONZERO")]
#[case::bytes_twelve_to_sixteen(REMOTE_RECIPIENT_BYTE_OFF + 12, 40, 109, "ERR_MSB_NONZERO")]
#[tokio::test]
async fn mint_rejects_a_malformed_attested_recipient(
    #[case] dirty_byte_off: usize,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
    #[case] expected_err: &str,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    payload[dirty_byte_off] = 0xaa; // the 16-byte pad must be zero
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
        rng_seed,
    )?;
    expect_reject(&mut pf, note, &payload, shell_error_by_name(expected_err)).await
}

/// The NONCANONICAL reject family, parametrized into one case table: an attested
/// `remoteRecipient` whose prefix or suffix u64 region (bytes 16..24 / 24..32 of the bytes32)
/// holds `u64::MAX` — a value `>= p` that would REDUCE mod the field — rejects in the standards
/// `eth::build_felt` no-reduction round-trip (the standards `ERR_MERGE_OVERFLOW`, mirroring Rust
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
    bring_up(&mut pf, 1).await?;
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
        shell_error_by_name("ERR_MERGE_OVERFLOW"),
    )
    .await
}

// TRANSPORT SHAPE — what happens when the note's two attachments are wrong
// ================================================================================================
//
// The mint note carries ONE merged transport attachment (scheme 4: the 11-word attestation
// section, then the packed deposit intent) plus the scheme-2 routing target. Every case below
// corrupts exactly one thing and names the EXACT error it must produce — which is also how the
// merged offsets get proven: a sub-region read at the wrong offset would surface a different
// error, or none.

/// The honest note's attachment SHAPE: exactly two, one scheme-4 merged transport and one
/// scheme-2 routing target, and the transport's felts are the documented
/// `attestation(44) ‖ intent(word-padded)` concatenation.
#[tokio::test]
async fn the_honest_note_carries_the_merged_transport_and_the_routing_target() -> Result<()> {
    let pf = fixture()?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 21);
    let note = honest_note(&pf, &payload, 90)?;

    let transport_scheme =
        NoteAttachmentScheme::new(TRANSPORT_SCHEME).expect("scheme 4 is a valid attachment scheme");
    let schemes: Vec<NoteAttachmentScheme> = note
        .attachments()
        .iter()
        .map(|a| a.attachment_scheme())
        .collect();
    assert_eq!(
        schemes.len(),
        2,
        "the mint note carries exactly two attachments: the merged transport + the routing target"
    );
    assert!(
        schemes.contains(&transport_scheme),
        "one of them is the scheme-{TRANSPORT_SCHEME} merged transport (schemes = {schemes:?})"
    );
    assert!(
        schemes.contains(&NetworkAccountTarget::ATTACHMENT_SCHEME),
        "the other is the stock scheme-2 routing target (schemes = {schemes:?})"
    );

    let transport = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == transport_scheme)
        .context("the merged transport attachment is present")?
        .content()
        .to_elements();

    // the attestation section sits FIRST (fixed width), which is what makes every offset below a
    // constant rather than a function of hookDataLen
    let attester = gen_attester(1, &payload);
    let attestation = &transport[..TRANSPORT_INTENT_WORD_OFF * 4];
    assert_eq!(
        attestation.len(),
        ATTESTATION_FELTS,
        "the attestation section is {ATTESTATION_WORDS} words"
    );
    assert_eq!(
        &attestation[ATTESTATION_FEE_FELT_OFF..ATTESTATION_FEE_FELT_OFF + 8],
        &[Felt::from(0u32); 8],
        "the feeAmount limbs are zero while relayer fees stay open"
    );
    assert_eq!(
        &attestation[ATTESTATION_PUBKEY_FELT_OFF..ATTESTATION_PUBKEY_FELT_OFF + 16],
        attester.pubkey_felts.as_slice(),
        "the 16 affine pubkey felts sit at the documented offset"
    );
    assert_eq!(
        &attestation[ATTESTATION_SIGNATURE_FELT_OFF..ATTESTATION_SIGNATURE_FELT_OFF + 17],
        attester.sig_felts.as_slice(),
        "the 17 signature felts sit at the documented offset"
    );

    // the Circle-signed byte extent stays 1:1 identifiable: the intent starts at a FIXED felt
    // offset and is the packed payload verbatim, zero-padded to the word boundary
    let mut expected_intent =
        xusdc_encoding::xreserve::encoding::deposit_intent_to_packed_felts(&payload)
            .map_err(|e| anyhow::anyhow!("the payload packs: {e}"))?;
    let signed_felts = expected_intent.len();
    while !expected_intent.len().is_multiple_of(4) {
        expected_intent.push(Felt::from(0u32));
    }
    assert_eq!(
        &transport[TRANSPORT_INTENT_WORD_OFF * 4..],
        expected_intent.as_slice(),
        "the intent sub-region is the packed Circle-signed payload, verbatim"
    );
    assert_eq!(
        transport.len(),
        TRANSPORT_INTENT_WORD_OFF * 4 + expected_intent.len(),
        "the merged attachment is exactly attestation + padded intent"
    );
    assert_eq!(
        signed_felts,
        payload.len().div_ceil(4),
        "the Circle-signed byte extent is exactly the unpadded intent felts, starting at the fixed \
         intent offset — the trailing word padding carries none of it"
    );

    // and the harness builds the PRODUCTION wire, not a look-alike: the same transport the
    // `XUsdcMintNote` factory emits for the same payload and attestation. Without this, every
    // tamper case below would only be proving things about the harness.
    let factory_note = XUsdcMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &MintAttestation::new(attester.sig_bytes, attester.pubkey_bytes),
        &mut note_rng(90),
    )
    .map_err(|e| anyhow::anyhow!("the production factory must build the note: {e}"))?;
    let factory_transport = factory_note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == transport_scheme)
        .context("the factory note carries the merged transport attachment")?
        .content()
        .to_elements();
    assert_eq!(
        transport, factory_transport,
        "the harness's transport attachment is byte-for-byte the production factory's"
    );
    Ok(())
}

/// Dropping the scheme-4 merged transport attachment rejects.
#[tokio::test]
async fn mint_rejects_a_missing_transport_attachment() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 22);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            transport: false,
            ..AttachmentPlan::default()
        },
        91,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TRANSPORT_MISSING"),
    )
    .await
}

/// Dropping the scheme-2 routing target rejects (the routing bind stays part of the shape, and its
/// reject identity is unchanged by the merge).
#[tokio::test]
async fn mint_rejects_a_missing_routing_target() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 23);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
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

/// A THIRD attachment rejects — either a foreign scheme riding along, or the merged transport
/// attached twice (which `find_attachment` would happily resolve to the first copy).
#[rstest]
#[case::foreign_scheme(AttachmentPlan { extra_scheme: Some(6), ..AttachmentPlan::default() }, 24, 93)]
#[case::doubled_transport(AttachmentPlan { duplicate_transport: true, ..AttachmentPlan::default() }, 25, 94)]
#[tokio::test]
async fn mint_rejects_a_third_attachment(
    #[case] plan: AttachmentPlan,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &plan,
        rng_seed,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT"),
    )
    .await
}

/// A merged attachment shorter than the attestation + the 15-word intent header rejects at the
/// transport floor — below it, no sub-region offset can be trusted.
#[tokio::test]
async fn mint_rejects_a_truncated_transport() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 30);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            transport_truncate_words: Some(TRANSPORT_FLOOR_WORDS - 1),
            ..AttachmentPlan::default()
        },
        97,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_TRANSPORT_TOO_SHORT"),
    )
    .await
}

/// The committed word count must equal attestation + ⌈len_felts/4⌉, and the equality is EXACT, so
/// it closes three things at once: a trailing padding word makes the attachment longer than the
/// embedded `hookDataLen` claims; a whole extra attestation section smuggled in behind the intent
/// does the same at eleven words, with every constant sub-offset still reading the right bytes, so
/// this binding — nothing else — is what refuses it; and a `hookDataLen` claiming extra hookData
/// makes the claim longer than the attachment. None is admissible: the padding must not be able to
/// hide data, no second section may ride along, and the length claim must not be able to reach
/// past the committed bytes.
#[rstest]
#[case::an_extra_padding_word(
    AttachmentPlan { transport_extra_words: 1, ..AttachmentPlan::default() },
    31,
    98
)]
#[case::a_smuggled_second_attestation_section(
    AttachmentPlan { trailing_attestation_section: true, ..AttachmentPlan::default() },
    26,
    95
)]
#[case::a_hook_data_len_lie(
    AttachmentPlan {
        intent_hook_data_len_felt: Some(packed_hook_data_len(4)),
        ..AttachmentPlan::default()
    },
    32,
    99
)]
#[tokio::test]
async fn mint_rejects_a_transport_length_mismatch(
    #[case] plan: AttachmentPlan,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &plan,
        rng_seed,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_INTENT_WORDS"),
    )
    .await
}

/// A `hookDataLen` limb above the u32 range rejects BEFORE the byte-swap that derives the length —
/// the guard that keeps a hash-committed but out-of-range limb out of the length arithmetic.
#[tokio::test]
async fn mint_rejects_a_non_u32_hook_data_len_limb() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 33);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            intent_hook_data_len_felt: Some(
                Felt::new(1u64 << 32).expect("2^32 is inside the field"),
            ),
            ..AttachmentPlan::default()
        },
        100,
    )?;
    expect_reject_u32_assert(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB"),
    )
    .await
}

/// SUB-REGION ISOLATION: corrupting one region of the merged attachment surfaces THAT region's
/// reject, never another's. The pubkey sub-region is read by the allowlist gate, the signature
/// sub-region by the ECDSA verify, and the intent sub-region by the keccak — so a merge that
/// mis-derived any offset would either mis-attribute the failure or, worse, verify the wrong
/// bytes. Each case's error identity is exactly the one it had when these were separate
/// attachments.
#[rstest]
#[case::pubkey(
    ATTESTATION_PUBKEY_FELT_OFF,
    "ERR_XRESERVE_DISALLOWED_PUB_KEY",
    34,
    101
)]
#[case::signature(ATTESTATION_SIGNATURE_FELT_OFF, "ERR_XRESERVE_SIG_INVALID", 35, 102)]
#[tokio::test]
async fn mint_rejects_a_tampered_attestation_sub_region(
    #[case] felt_off: usize,
    #[case] expected_err: &str,
    #[case] nonce_variant: u8,
    #[case] rng_seed: u64,
) -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, nonce_variant);
    let note = tampered_mint_note(
        &pf,
        &payload,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        None,
        &AttachmentPlan {
            attestation_felt_tamper: Some((felt_off, Felt::from(0xdead_beefu32))),
            ..AttachmentPlan::default()
        },
        rng_seed,
    )?;
    expect_reject(&mut pf, note, &payload, shell_error_by_name(expected_err)).await
}

/// The other half of the isolation proof: a tampered INTENT byte — the attestation section left
/// untouched and the signature still over the original payload — rejects at the signature check,
/// because the keccak'd extent is the intent sub-region and nothing else. A merge that hashed the
/// attestation along with the intent would not reproduce this identity.
#[tokio::test]
async fn mint_rejects_a_tampered_intent_byte() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let signed = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 36);
    // the last maxFee byte: 1 -> 2, which every structural and amount check still admits (the
    // attested amount stays far above the fee), so the ONLY thing that changes is the digest.
    let mut carried = signed.clone();
    carried[MAX_FEE_BYTE_OFF + 31] = 2;
    let note = tampered_mint_note(
        &pf,
        &carried,
        &honest_storage(&pf),
        [Felt::from(0u32); 8],
        1,
        Some(&signed),
        &AttachmentPlan::default(),
        103,
    )?;
    expect_reject(
        &mut pf,
        note,
        &carried,
        shell_error_by_name("ERR_XRESERVE_SIG_INVALID"),
    )
    .await
}

// PAUSE HALT — the dispatcher gate (execute_mint_policy runs assert_not_paused FIRST)
// ================================================================================================

/// A DOM_PAUSER pause halts the attested mint at the policy dispatcher's stock pause gate.
#[tokio::test]
async fn mint_halts_while_paused() -> Result<()> {
    let mut pf = fixture_with(MAX_SUPPLY, |_, faucet_id| {
        vec![stock_pause_note(dom_pauser(), faucet_id, 953)
            .expect("building the DOM_PAUSER pause note")]
    })?;
    bring_up(&mut pf, 2).await?; // set_attester + pause
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

// WITHOUT THE ATTESTED TRANSPORT THERE IS NO ACCEPTABLE MINT
// ================================================================================================

/// A tx-script `mint_and_send` (no active note, no attachments) CANNOT mint: the attestation
/// policy's first transport read (`active_note::find_attachment`) runs outside note processing,
/// so it traps the EXACT kernel input-note bound assert — there is no input note to read — and
/// the former deny-guard posture is preserved structurally: every supply increase must ride the
/// attested note transport. Asserts the exact kernel error + zero supply.
#[tokio::test]
async fn tx_script_mint_and_send_cannot_mint() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
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
    bring_up(&mut pf, 1).await?;
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

// ADVICE INDEPENDENCE — the host cannot influence a mint
// ================================================================================================

/// A mint runs identically whether or not the prover seeds an advice stack.
///
/// Every operand the policy verifies — the deposit intent, the operator fee, the attester pubkey,
/// the signature — is read out of memory the policy hash-verified against the note's own
/// attachment commitments. The advice provider is host-controlled, so if any stage still popped
/// from it, a prover could hand the verify a different payload than the one the note committed to.
///
/// The behavioral half of that guarantee is what this test covers: a hostile stack changes
/// nothing. It cannot cover the whole of it, because the divergence a real attacker exploits is a
/// prover serving different bytes on a second read of the same advice-map key, and MockChain's
/// advice provider is a static map that cannot model it. What closes the gap is a source fact
/// rather than a behavior: no `.masm` under `asm/` contains an advice-read instruction at all.
#[tokio::test]
async fn mint_ignores_a_hostile_advice_stack() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 1).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 23);
    let note = honest_note(&pf, &payload, 83)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    // enough junk to satisfy every read the pre-hardening pipeline made (8 fee limbs + 16 pubkey
    // felts + 17 signature felts), so a surviving advice read would consume it and diverge rather
    // than trap on an empty stack
    let hostile: Vec<Felt> = (1u32..=41).map(Felt::from).collect();
    let tx = consume_note_with_advice(&pf.mock_chain, pf.faucet_id, note.id(), Some(hostile))
        .await
        .map_err(|e| anyhow::anyhow!("a hostile advice stack must not affect the mint: {e}"))?;

    assert_eq!(
        tx.output_notes().num_notes(),
        1,
        "the mint still emits exactly one recipient note"
    );
    let out = tx.output_notes().get_note(0);
    let asset = out
        .assets()
        .iter_fungible()
        .next()
        .ok_or_else(|| anyhow::anyhow!("the recipient note carries a fungible asset"))?;
    assert_eq!(
        u64::from(asset.amount()),
        MINT_AMOUNT,
        "the minted amount is the attested one, not anything the advice stack suggested"
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
        "the attested nonce is marked used"
    );
    Ok(())
}
