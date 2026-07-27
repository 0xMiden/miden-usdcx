//! ATTESTATION MINT POLICY E2E MATRIX (Wave-1 S1): the full mint-semantics matrix RE-PROVEN
//! through the recomposed transport — a REAL stock `MintNote` (DepositIntent scheme-4 +
//! attestation scheme-5 + `NetworkAccountTarget` scheme-2 attachments) consumed by the
//! PRODUCTION-composed faucet, whose stock `mint_and_send` dispatches
//! `xreserve::mint_policy::check_policy` as the ACTIVE mint policy.
//!
//! Every negative asserts its EXACT error (never `is_err()`), and the security-critical rejects
//! prove fail-closure (no nonce burned, no supply raised). The matrix mirrors — through the new
//! transport — the coverage the deleted custom-transport suites carried
//! (`xreserve_mint.rs` / `xreserve_mint_note.rs` / `f5_mint_shim_negatives.rs` /
//! `mint_recipient_account_id.rs`; see the Wave-1 S1 deletion ledger): wrong-attester,
//! forged-signature, wrong-domain, wrong-identifier, over-cap, malformed attested recipient,
//! fee != 0 + replay + recipient-mismatch (in `wave1_recomposition.rs`), the transport-shape
//! negatives, the pause halt, the F1 restatement (a policy-less mint path cannot mint), and the
//! MockChain half of the routing proof.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteId, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNote, P2idNoteStorage,
};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveIdentifierInitNote, XReservePauseNote, XReserveSetAttesterNote,
};
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{account_id_to_bytes32, bytes32_to_storage_map_key};

// FIXTURE VALUES
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const MAX_SUPPLY: u64 = 1_000_000_000_000;
const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the u32 `remoteDomain` field (felt 10 x 4 bytes; DC-1).
const REMOTE_DOMAIN_BYTE_OFF: usize = 10 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes; DC-1).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes; DC-1).
const NONCE_BYTE_OFF: usize = 51 * 4;

/// The ratified attachment schemes (rider A8) — test-side literals, parity-pinned in
/// `constant_parity.rs` against both the Rust factory and the MASM policy.
const INTENT_SCHEME: u16 = 4;
const ATTESTATION_SCHEME: u16 = 5;

fn owner() -> AccountId {
    test_account_id(1)
}

fn dom_pauser() -> AccountId {
    test_account_id(2)
}

fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

fn payload_for(
    recipient: AccountId,
    faucet_id: AccountId,
    amount: u64,
    nonce_variant: u8,
) -> Vec<u8> {
    let mut payload = di(BASE_VECTOR).bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    payload[REMOTE_TOKEN_BYTE_OFF..REMOTE_TOKEN_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(faucet_id));
    payload[NONCE_BYTE_OFF] ^= nonce_variant;
    payload
}

fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// THE TAMPER ENGINE — a parameterized stock-MintNote builder over an attested payload
// ================================================================================================

/// The attachment plan: which of the three attachments ride the note (the shape negatives drop /
/// duplicate entries; `extra_scheme` appends a foreign-scheme attachment for the count negative).
struct AttachmentPlan {
    intent: bool,
    attestation: bool,
    target: bool,
    extra_scheme: Option<u16>,
    /// Overrides the attestation attachment's word count (padding words appended / truncated).
    attestation_words_override: Option<usize>,
    /// Appends N EXTRA zero words to the intent attachment (the length-binding negative).
    intent_extra_words: usize,
    /// Truncates the intent attachment to N words (the header-floor negative).
    intent_truncate_words: Option<usize>,
}

impl Default for AttachmentPlan {
    fn default() -> Self {
        Self {
            intent: true,
            attestation: true,
            target: true,
            extra_scheme: None,
            attestation_words_override: None,
            intent_extra_words: 0,
            intent_truncate_words: None,
        }
    }
}

/// The storage plan: the values embedded in the stock `MintNoteStorage` (the binding negatives
/// diverge them from the attested derivations).
struct StoragePlan {
    recipient: AccountId,
    amount: u64,
    tag: Option<NoteTag>,
    public: bool,
}

fn intent_words(payload: &[u8]) -> Vec<Word> {
    let mut felts = xusdc_encoding::xreserve::encoding::deposit_intent_to_packed_felts(payload)
        .expect("the tamper payload packs");
    while felts.len() % 4 != 0 {
        felts.push(Felt::from(0u32));
    }
    felts
        .chunks_exact(4)
        .map(|c| Word::from([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn words_of(felts: &[Felt]) -> Vec<Word> {
    felts
        .chunks_exact(4)
        .map(|c| Word::from([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Builds the (possibly tampered) stock mint note. `sig_over` lets the forged-signature case sign
/// a DIFFERENT byte string than the carried payload; `attester_seed` selects the keypair (seed 1
/// is the allowlisted attester).
#[allow(clippy::too_many_arguments)]
fn tampered_mint_note(
    pf: &ProductionFaucet,
    payload: &[u8],
    storage: &StoragePlan,
    fee_limbs: [Felt; 8],
    attester_seed: u64,
    sig_over: Option<&[u8]>,
    plan: &AttachmentPlan,
    rng_seed: u64,
) -> Result<Note> {
    let key_source = gen_attester(attester_seed, sig_over.unwrap_or(payload));
    let serial = nonce_key_of_payload(payload);
    let recipient_recipe = P2idNoteStorage::new(storage.recipient).into_recipient(serial);
    let asset = FungibleAsset::new(pf.faucet_id, storage.amount)
        .map_err(|e| anyhow::anyhow!("storage asset: {e}"))?;
    let tag = storage
        .tag
        .unwrap_or_else(|| NoteTag::with_account_target(storage.recipient));
    let mint_storage = if storage.public {
        MintNoteStorage::new_fungible_public(recipient_recipe, asset, tag)
            .map_err(|e| anyhow::anyhow!("public mint storage: {e}"))?
    } else {
        MintNoteStorage::new_fungible_private(recipient_recipe.digest(), asset, tag)
    };
    let mut builder = MintNote::builder()
        .sender(pf.producer_id)
        .mint_storage(mint_storage)
        .serial_number(note_rng(rng_seed).draw_word());
    if plan.intent {
        let mut words = intent_words(payload);
        if let Some(truncate) = plan.intent_truncate_words {
            words.truncate(truncate);
        }
        for _ in 0..plan.intent_extra_words {
            words.push(Word::empty());
        }
        builder = builder.attachment(
            NoteAttachment::with_words(
                NoteAttachmentScheme::new(INTENT_SCHEME).expect("scheme 4 is valid"),
                words,
            )
            .map_err(|e| anyhow::anyhow!("intent attachment: {e}"))?,
        );
    }
    if plan.attestation {
        let mut felts: Vec<Felt> = fee_limbs.to_vec();
        felts.extend(key_source.pubkey_felts.iter().copied());
        felts.extend(key_source.sig_felts.iter().copied());
        felts.extend([Felt::from(0u32); 3]);
        let mut words = words_of(&felts);
        if let Some(override_words) = plan.attestation_words_override {
            words.resize(override_words, Word::empty());
        }
        builder = builder.attachment(
            NoteAttachment::with_words(
                NoteAttachmentScheme::new(ATTESTATION_SCHEME).expect("scheme 5 is valid"),
                words,
            )
            .map_err(|e| anyhow::anyhow!("attestation attachment: {e}"))?,
        );
    }
    if plan.target {
        builder = builder.attachment(NoteAttachment::from(
            NetworkAccountTarget::new(pf.faucet_id, NoteExecutionHint::Always)
                .map_err(|e| anyhow::anyhow!("routing attachment: {e}"))?,
        ));
    }
    if let Some(scheme) = plan.extra_scheme {
        builder = builder.attachment(NoteAttachment::with_word(
            NoteAttachmentScheme::new(scheme).expect("extra scheme is valid"),
            Word::empty(),
        ));
    }
    let mint_note = builder
        .build()
        .map_err(|e| anyhow::anyhow!("building the tampered mint note: {e}"))?;
    Ok(Note::from(mint_note))
}

/// The honest note over an attested payload (the baseline the tamper cases diverge from).
fn honest_note(pf: &ProductionFaucet, payload: &[u8], rng_seed: u64) -> Result<Note> {
    tampered_mint_note(
        pf,
        payload,
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
    )
}

// FIXTURE + DRIVERS
// ================================================================================================

/// The production faucet brought up for minting: identifier seeded (the DEC-4 minimized init),
/// attester 1 allowlisted. `extra_notes` seeds additional admin notes (e.g. the pause note).
fn fixture_with(
    max_supply: u64,
    extra_notes: impl Fn(AccountId, AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    setup_production_faucet(max_supply, 0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, faucet_id, MINT_AMOUNT, 0)).commitment;
        let mut notes = vec![
            XReserveIdentifierInitNote::create(owner(), faucet_id, &mut note_rng(951))
                .expect("building the owner identifier_init note"),
            XReserveSetAttesterNote::create(owner(), faucet_id, commitment, 1, &mut note_rng(952))
                .expect("building the owner set_attester note"),
        ];
        notes.extend(extra_notes(recipient, faucet_id));
        notes
    })
}

fn fixture() -> Result<ProductionFaucet> {
    fixture_with(MAX_SUPPLY, |_, _| vec![])
}

/// Consumes the seeded bring-up notes `0..count`, committing a block each.
async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().take(count).enumerate() {
        let tx = pf
            .mock_chain
            .build_tx_context(pf.faucet_id, &[note.id()], &[])
            .with_context(|| format!("bring-up note {i}: tx context"))?
            .build()
            .with_context(|| format!("bring-up note {i}: tx build"))?
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("bring-up note {i} must succeed: {e}"))?;
        pf.mock_chain.add_pending_executed_transaction(&tx)?;
        pf.mock_chain.prove_next_block()?;
    }
    Ok(())
}

async fn consume_note(
    chain: &MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_tx_context(faucet_id, &[note_id], &[])
        .expect("building the consume tx context")
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain.add_pending_executed_transaction(tx)?;
    chain.prove_next_block()?;
    Ok(())
}

fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain.committed_account(id)?.clone())
}

fn read_map_word(account: &Account, slot_label: &str, key: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            &StorageSlotName::new(slot_label)
                .with_context(|| format!("slot label {slot_label}"))?,
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading map slot {slot_label}: {e}"))
}

/// Asserts fail-closure after a rejected mint: the nonce unburned, the supply unraised.
fn assert_no_effects(pf: &ProductionFaucet, payload: &[u8]) -> Result<()> {
    let faucet = committed(&pf.mock_chain, pf.faucet_id)?;
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(payload)
        )?,
        Word::empty(),
        "a rejected mint must not consume the nonce"
    );
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "a rejected mint must not raise supply"
    );
    Ok(())
}

/// Emits the note and consumes it, expecting the exact `expected` trap, then (payload-based
/// cases) proves fail-closure.
async fn expect_reject(
    pf: &mut ProductionFaucet,
    note: Note,
    payload: &[u8],
    expected: &MasmError,
) -> Result<()> {
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let result = consume_note(&pf.mock_chain, pf.faucet_id, note.id()).await;
    assert_transaction_executor_error!(result, expected);
    assert_no_effects(pf, payload)
}

// D5d — ATTESTER ALLOWLIST + SIGNATURE (through the new transport)
// ================================================================================================

/// A NON-allowlisted attester's (valid) attestation rejects: R-MINT-13 through the policy.
#[tokio::test]
async fn mint_rejects_a_non_allowlisted_attester() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 11);
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
        2, // a DIFFERENT keypair — its commitment is not allowlisted
        None,
        &AttachmentPlan::default(),
        81,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"),
    )
    .await
}

/// The ALLOWLISTED attester's key with a signature over DIFFERENT bytes rejects: R-MINT-14.
#[tokio::test]
async fn mint_rejects_a_forged_signature() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 12);
    let other = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 13);
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
        Some(&other), // allowlisted key, signature over the WRONG payload
        &AttachmentPlan::default(),
        82,
    )?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_SIG_INVALID"),
    )
    .await
}

// D5a — DOMAIN / IDENTIFIER COMPARES (build-seeded domain; note-seeded identifier)
// ================================================================================================

/// A deposit intent addressed to a DIFFERENT remote domain rejects: R-MINT-6 against the
/// BUILD-SEEDED domain config (DEC-4).
#[tokio::test]
async fn mint_rejects_a_wrong_domain() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 14);
    payload[REMOTE_DOMAIN_BYTE_OFF..REMOTE_DOMAIN_BYTE_OFF + 4]
        .copy_from_slice(&TEST_WRONG_DOMAIN.to_be_bytes());
    let note = honest_note(&pf, &payload, 83)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_WRONG_DOMAIN"),
    )
    .await
}

/// A deposit intent whose remoteToken is not THIS faucet's identifier rejects: R-MINT-7 against
/// the identifier the minimized init note seeded.
#[tokio::test]
async fn mint_rejects_a_wrong_identifier() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf, 2).await?;
    let mut payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 15);
    payload[REMOTE_TOKEN_BYTE_OFF] ^= 0xff;
    let note = honest_note(&pf, &payload, 84)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        shell_error_by_name("ERR_XRESERVE_WRONG_IDENTIFIER"),
    )
    .await
}

// SUPPLY CAP — the STOCK mint_and_send discipline (the policy carries no supply arithmetic)
// ================================================================================================

/// An attested amount above the remaining supply headroom rejects in the STOCK `mint_and_send`
/// cap discipline (the R-MINT-15 semantics, now stock-owned), fail-closed.
#[tokio::test]
async fn mint_rejects_an_over_cap_amount() -> Result<()> {
    let mut pf = fixture_with(MINT_AMOUNT - 1, |_, _| vec![])?;
    bring_up(&mut pf, 2).await?;
    let payload = payload_for(pf.recipient_id, pf.faucet_id, MINT_AMOUNT, 16);
    let note = honest_note(&pf, &payload, 85)?;
    expect_reject(
        &mut pf,
        note,
        &payload,
        &MasmError::from_static_str(
            "token_supply plus the amount passed to distribute would exceed the maximum supply",
        ),
    )
    .await
}

// ASSERT-MATCH — the remaining binding legs (recipient/fee/replay live in wave1_recomposition)
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
/// policy's transport reads trap in the kernel (there is no active note to read), so the former
/// deny-guard posture is preserved structurally — every supply increase must ride the attested
/// note transport. Asserts failure + zero supply (the kernel error is a host event, not a MASM
/// assert, so no exact-string assert exists for it).
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
        .build_tx_context(pf.faucet_id, &[], &[])
        .context("tx context")?
        .tx_script(tx_script)
        .build()
        .context("tx build")?
        .execute()
        .await;
    assert!(
        result.is_err(),
        "a tx-script mint_and_send must NOT mint on the attestation-gated faucet"
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
