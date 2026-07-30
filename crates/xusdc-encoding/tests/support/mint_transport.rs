//! Shared harness for driving real mints against a production faucet.
//!
//! It builds genuine standard mint notes — carrying the deposit intent, the attestation, and the
//! routing target as their three attachments — and runs them to completion against an account
//! composed by the production builder under the standard network-account auth. Nothing is
//! substituted, so a test's accept or reject is the account's real behavior.
//!
//! Everything the mint suites share lives here exactly once: the honest baseline note
//! ([`honest_note`]), the tampering engine ([`tampered_mint_note`], with [`AttachmentPlan`] and
//! [`StoragePlan`] describing what to corrupt), the bring-up drivers that seed a faucet to the
//! point where it can mint, and the fail-closure assertions. Keeping one tamper engine matters:
//! the suites must differ in what they tamper with, not in how a tampered note is built.

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteId, NoteTag};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::note::xreserve_admin::{XReserveIdentifierInitNote, XReserveSetAttesterNote};
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::{account_id_to_bytes32, bytes32_to_storage_map_key};

use super::*;

// FIXTURE VALUES (shared across the split e2e suites)
// ================================================================================================

pub const BASE_VECTOR: &str = "di-pos-empty-hookdata";
pub const MAX_SUPPLY: u64 = 1_000_000_000_000;
pub const MINT_AMOUNT: u64 = 250_000_000;
pub const MAX_FEE_RAW: u64 = 1;

// NOTE: the `remoteRecipient` byte offset is NOT redeclared here — the split suites read
// `support::REMOTE_RECIPIENT_BYTE_OFF` (the single test-side source, `REMOTE_RECIPIENT_FELT_OFF
// * 4`); a duplicate would make the two glob imports ambiguous.

/// First byte of the u32 `remoteDomain` field (felt 10 x 4 bytes of the fixed header).
pub const REMOTE_DOMAIN_BYTE_OFF: usize = 10 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes of the fixed header).
pub const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes of the fixed header).
pub const NONCE_BYTE_OFF: usize = 51 * 4;

/// The ratified attachment schemes — test-side literals, parity-pinned in
/// `constant_parity.rs` against both the Rust factory and the MASM policy.
pub const INTENT_SCHEME: u16 = 4;
pub const ATTESTATION_SCHEME: u16 = 5;

/// The production builder's Ownable2Step owner (`test_account_id(1)` across every fixture).
pub fn owner() -> AccountId {
    test_account_id(1)
}

/// The production builder's DOM_PAUSER holder (`test_account_id(2)`).
pub fn dom_pauser() -> AccountId {
    test_account_id(2)
}

/// Looks up a DepositIntent vector by id in the canonical artifact — the same file the Rust codec
/// tests read, so both sides exercise identical bytes.
pub fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

/// The canonical accept payload with the wire amount / maxFee spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` bound to the faucet's own-id identifier
/// fixpoint (what the identifier compare checks against), and one nonce byte perturbed per variant
/// so each mint consumes a nonce the replay guard has not seen.
pub fn payload_for(
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

/// The usedNonces key (== the attested output-note serial) for a payload's nonce bytes.
pub fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

/// Deterministic note rng (serial only; never affects a gate).
pub fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

/// The non-empty `usedNonces` marker the policy writes on accept.
pub fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

/// The exact STOCK `mint_and_send` cap-discipline error (`fungible.masm` distribute) — the
/// supply-cap reject, stock-owned.
pub fn err_stock_over_cap() -> MasmError {
    MasmError::from_static_str(
        "token_supply plus the amount passed to distribute would exceed the maximum supply",
    )
}

/// The packed limbs of a NONZERO uint256 feeAmount (the fee != 0 negative).
pub fn fee_limbs_of(fee: u64) -> [Felt; 8] {
    bytes_to_packed_u32_elements(&uint256_be(fee))
        .try_into()
        .expect("a uint256 packs to exactly 8 limbs")
}

// THE TAMPER ENGINE — a parameterized stock-MintNote builder over an attested payload
// ================================================================================================

/// The attachment plan: which of the three attachments ride the note (the shape negatives drop /
/// duplicate entries; `extra_scheme` appends a foreign-scheme attachment for the count negative).
pub struct AttachmentPlan {
    pub intent: bool,
    pub attestation: bool,
    pub target: bool,
    pub extra_scheme: Option<u16>,
    /// Overrides the attestation attachment's word count (padding words appended / truncated).
    pub attestation_words_override: Option<usize>,
    /// Appends N EXTRA zero words to the intent attachment (the length-binding negative).
    pub intent_extra_words: usize,
    /// Truncates the intent attachment to N words (the header-floor negative).
    pub intent_truncate_words: Option<usize>,
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
pub struct StoragePlan {
    pub recipient: AccountId,
    pub amount: u64,
    pub tag: Option<NoteTag>,
    pub public: bool,
}

fn intent_words(payload: &[u8]) -> Vec<Word> {
    let mut felts = xusdc_encoding::xreserve::encoding::deposit_intent_to_packed_felts(payload)
        .expect("the tamper payload packs");
    while !felts.len().is_multiple_of(4) {
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
pub fn tampered_mint_note(
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
pub fn honest_note(pf: &ProductionFaucet, payload: &[u8], rng_seed: u64) -> Result<Note> {
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

/// The production faucet brought up for minting: identifier seeded (the minimized
/// identifier-only init),
/// attester 1 allowlisted. `extra_notes` seeds additional admin notes (e.g. the pause note).
pub fn fixture_with(
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

/// [`fixture_with`] at the default cap with no extra admin notes.
pub fn fixture() -> Result<ProductionFaucet> {
    fixture_with(MAX_SUPPLY, |_, _| vec![])
}

/// Consumes the seeded bring-up notes `0..count`, committing a block each.
pub async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().take(count).enumerate() {
        let tx = pf
            .mock_chain
            .build_transaction(pf.faucet_id)
            .authenticated_input_note(note.id())
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

/// Consumes ONE seeded bring-up note by index and commits it — for the admin-interplay legs
/// that interleave admin notes with mint attempts (`bring_up` consumes a PREFIX; this consumes a
/// chosen later note).
pub async fn consume_seeded_admin_note(pf: &mut ProductionFaucet, index: usize) -> Result<()> {
    let note = pf.seeded_notes[index].clone();
    let tx = consume_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("seeded admin note {index} must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &tx)
}

/// Consumes a committed note on the faucet with NO tx script and NO consume-side advice — the
/// stock `MintNote` script -> `mint_and_send` -> attestation-policy transport (admin notes ride
/// the same shape).
pub async fn consume_note(
    chain: &MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_transaction(faucet_id)
        .authenticated_input_note(note_id)
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Commits an executed transaction and proves the next block.
pub fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain.add_pending_executed_transaction(tx)?;
    chain.prove_next_block()?;
    Ok(())
}

/// The committed state of `id` on `chain`.
pub fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain.committed_account(id)?.clone())
}

/// Reads one map-slot word from a committed/evolved account.
pub fn read_map_word(account: &Account, slot_label: &str, key: Word) -> Result<Word> {
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
pub fn assert_no_effects(pf: &ProductionFaucet, payload: &[u8]) -> Result<()> {
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
pub async fn expect_reject(
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
