//! Shared harness for driving real mints against a production faucet.
//!
//! It builds genuine standard mint notes — carrying the merged transport attachment (the
//! attestation followed by the deposit intent) and the routing target as their two attachments —
//! and runs them to completion against an account
//! composed by the production builder under the standard network-account auth. Nothing is
//! substituted, so a test's accept or reject is the account's real behavior.
//!
//! Everything the mint suites share lives here exactly once: the honest baseline note
//! ([`honest_note`]), the tampering engine ([`tampered_mint_note`], with [`AttachmentPlan`] and
//! [`StoragePlan`] describing what to corrupt), the bring-up drivers that seed a faucet to the
//! point where it can mint, and the fail-closure assertions. Keeping one tamper engine matters:
//! the suites must differ in what they tamper with, not in how a tampered note is built.

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, StorageMapKey, StorageSlotName};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteId, NoteTag};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::note::{
    MintNote, MintNoteStorage, NetworkAccountTarget, NoteExecutionHint, P2idNoteStorage,
};
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_account_id, bytes32_to_storage_map_key, DepositIntent,
    MintIntent, PublicKey, MINT_INTENT_HOOK_DATA_LEN_FELT_OFF,
};

use super::*;

// FIXTURE VALUES (shared across the split e2e suites)
// ================================================================================================

pub const BASE_VECTOR: &str = "mi-pos-empty-hookdata";
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

/// The ratified merged transport attachment scheme — a test-side literal, parity-pinned in
/// `constant_parity.rs` against both the Rust factory and the MASM policy.
pub const TRANSPORT_SCHEME: u16 = 4;

/// The transport layout, test-side: the fixed-width attestation section, then the carried mint
/// payload, then the packed hookData. Every offset below is parity-pinned in `constant_parity.rs`
/// against both the Rust factory and the MASM policy, so the harness cannot drift from the wire.
pub const ATTESTATION_WORDS: usize = 5;
pub const TRANSPORT_PAYLOAD_WORD_OFF: usize = ATTESTATION_WORDS;
pub const ATTESTATION_FELTS: usize = ATTESTATION_WORDS * 4;

/// Felt offsets INSIDE the attestation section. The signature leads it so it stays word-aligned
/// for the ECDSA precompile. The attester's public key is not on the wire at all — the index
/// selects it out of the faucet's own array — and the operator `feeAmount` went with `DC-14`,
/// since the faucet writes a zero fee into the preimage.
pub const ATTESTATION_SIGNATURE_FELT_OFF: usize = 0;
pub const ATTESTATION_ATTESTER_IDX_FELT_OFF: usize = 17;

/// The word floor the policy enforces: the attestation plus the six-word carried payload.
pub const TRANSPORT_FLOOR_WORDS: usize = TRANSPORT_PAYLOAD_WORD_OFF + 6;

/// The production builder's administrator (`test_account_id(1)` across every fixture): the sole
/// seeded `ADMIN` member.
pub fn administrator() -> AccountId {
    test_account_id(1)
}

/// The production builder's DOM_PAUSER holder (`test_account_id(2)`).
pub fn dom_pauser() -> AccountId {
    test_account_id(2)
}

/// Looks up a mint-payload vector by id in the canonical artifact — the same file the Rust codec
/// tests read, so both sides exercise identical bytes. The `DC-14` rows are the ones whose
/// `localToken` / `localDepositor` are address-shaped, which the transport requires.
pub fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
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
    let mut payload = mi(BASE_VECTOR).payload();
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

// THE TAMPER ENGINE — a parameterized stock-MintNote builder over an attested payload
// ================================================================================================

/// The attachment plan: which of the two attachments ride the note, and how the merged transport
/// attachment is corrupted. Each sub-region of the merged attachment — the attestation section and
/// the deposit intent — is independently tamperable, which is what lets the negatives prove that
/// corrupting one cannot be mistaken for corrupting another.
pub struct AttachmentPlan {
    /// The merged scheme-4 transport attachment rides the note.
    pub transport: bool,
    /// The scheme-2 routing target rides the note.
    pub target: bool,
    /// Appends a foreign-scheme attachment (the count negative).
    pub extra_scheme: Option<u16>,
    /// Attaches the merged transport TWICE (the doubled-scheme negative).
    pub duplicate_transport: bool,
    /// Appends a SECOND attestation section AFTER the intent — a smuggled extra section that
    /// leaves every constant sub-offset (and so every verify stage) reading the right bytes, so
    /// the word-count binding is the only thing standing between it and an accept.
    pub trailing_attestation_section: bool,
    /// Appends N EXTRA zero words to the merged attachment (the length-binding negative).
    pub transport_extra_words: usize,
    /// Truncates the merged attachment to N words (the floor negative).
    pub transport_truncate_words: Option<usize>,
    /// Overwrites one felt of the attestation section, by its offset within that section.
    pub attestation_felt_tamper: Option<(usize, Felt)>,
    /// Overwrites one felt of the carried payload, by its offset within that section. Every
    /// carried field is reachable this way, which is what the per-field negatives use.
    pub payload_felt_tamper: Option<(usize, Felt)>,
    /// Overwrites the carried `hookDataLen` felt — a length claim that disagrees with the
    /// committed word count, or an outright non-u32 limb.
    pub payload_hook_data_len_felt: Option<Felt>,
}

impl Default for AttachmentPlan {
    fn default() -> Self {
        Self {
            transport: true,
            target: true,
            extra_scheme: None,
            duplicate_transport: false,
            trailing_attestation_section: false,
            transport_extra_words: 0,
            transport_truncate_words: None,
            attestation_felt_tamper: None,
            payload_felt_tamper: None,
            payload_hook_data_len_felt: None,
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

/// The carried mint payload for a signed intent, zero-padded to the word boundary.
///
/// Compression is done against the payload's OWN claimed domain and token, not the executing
/// faucet's, so a note addressed elsewhere still builds a well-formed transport — it has to, or
/// the wrong-domain and wrong-faucet negatives could not reach the chain to fail there.
fn carried_payload_felts(payload: &[u8]) -> Vec<Felt> {
    let intent = DepositIntent::new(payload);
    let header = intent.parse_header().expect("the tamper payload parses");
    let claimed_faucet = bytes32_to_account_id(&header.remote_token)
        .expect("the tamper payload names a well-formed faucet");
    let carried = MintIntent::from_deposit_intent(&intent, claimed_faucet)
        .expect("the tamper payload is DC-14 shaped");
    let mut felts = carried.to_felts();
    while !felts.len().is_multiple_of(4) {
        felts.push(Felt::from(0u32));
    }
    felts
}

/// The 20-felt attestation section: `[signature(17), attester_idx(1), pad(2)]`.
fn attestation_felts(key_source: &AttesterVector, attester_index: u32) -> Vec<Felt> {
    let mut felts: Vec<Felt> = Vec::new();
    felts.extend(key_source.sig_felts.iter().copied());
    felts.push(Felt::from(attester_index));
    felts.extend([Felt::from(0u32); 2]);
    debug_assert_eq!(felts.len(), ATTESTATION_FELTS);
    felts
}

/// Assembles the merged transport attachment's felts under `plan`: the attestation section
/// (optionally duplicated / tampered), then the packed intent.
fn transport_felts(
    payload: &[u8],
    key_source: &AttesterVector,
    attester_index: u32,
    plan: &AttachmentPlan,
) -> Vec<Felt> {
    let mut felts: Vec<Felt> = Vec::new();

    let mut attestation = attestation_felts(key_source, attester_index);
    if let Some((off, value)) = plan.attestation_felt_tamper {
        attestation[off] = value;
    }
    felts.extend(attestation.iter().copied());

    let mut carried = carried_payload_felts(payload);
    if let Some((off, value)) = plan.payload_felt_tamper {
        carried[off] = value;
    }
    if let Some(limb) = plan.payload_hook_data_len_felt {
        carried[MINT_INTENT_HOOK_DATA_LEN_FELT_OFF] = limb;
    }
    felts.extend(carried);

    if plan.trailing_attestation_section {
        felts.extend(attestation.iter().copied());
    }
    felts
}

fn words_of(felts: &[Felt]) -> Vec<Word> {
    felts
        .chunks_exact(4)
        .map(|c| Word::from([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// The merged transport attachment under `plan` (word truncation / padding applied last, so the
/// committed word count is exactly what the negatives intend).
fn transport_attachment(
    payload: &[u8],
    key_source: &AttesterVector,
    attester_index: u32,
    plan: &AttachmentPlan,
) -> Result<NoteAttachment> {
    let mut words = words_of(&transport_felts(payload, key_source, attester_index, plan));
    if let Some(truncate) = plan.transport_truncate_words {
        words.truncate(truncate);
    }
    for _ in 0..plan.transport_extra_words {
        words.push(Word::empty());
    }
    NoteAttachment::with_words(
        NoteAttachmentScheme::new(TRANSPORT_SCHEME).expect("scheme 4 is valid"),
        words,
    )
    .map_err(|e| anyhow::anyhow!("transport attachment: {e}"))
}

/// Builds the (possibly tampered) stock mint note. `sig_over` lets the forged-signature case sign
/// a DIFFERENT byte string than the carried payload; `attester_seed` selects the keypair (seed 1
/// is the installed attester) and `attester_index` the array index the note names (which need not
/// be where that keypair actually lives — that is how the anti-splice cases are built).
#[allow(clippy::too_many_arguments)]
pub fn tampered_mint_note(
    pf: &ProductionFaucet,
    payload: &[u8],
    storage: &StoragePlan,
    attester_seed: u64,
    attester_index: u32,
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
    if plan.transport {
        builder = builder.attachment(transport_attachment(
            payload,
            &key_source,
            attester_index,
            plan,
        )?);
        if plan.duplicate_transport {
            builder = builder.attachment(transport_attachment(
                payload,
                &key_source,
                attester_index,
                plan,
            )?);
        }
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

/// The honest storage plan: the attested recipient, the attested amount, the derived tag, public.
/// The attachment negatives all pair with it, so an unexpected trap cannot be a storage divergence.
pub fn honest_storage(pf: &ProductionFaucet) -> StoragePlan {
    StoragePlan {
        recipient: pf.recipient_id,
        amount: MINT_AMOUNT,
        tag: None,
        public: true,
    }
}

/// The honest note over an attested payload (the baseline the tamper cases diverge from).
pub fn honest_note(pf: &ProductionFaucet, payload: &[u8], rng_seed: u64) -> Result<Note> {
    tampered_mint_note(
        pf,
        payload,
        &honest_storage(pf),
        1,
        TEST_ATTESTER_INDEX,
        None,
        &AttachmentPlan::default(),
        rng_seed,
    )
}

// FIXTURE + DRIVERS
// ================================================================================================

/// The administrator's `set_attester` note that installs `gen_attester(seed, ..)`'s public key at
/// `index`. The key does not depend on what that attester signed, so this needs only the seed.
pub fn enable_attester_note(
    faucet_id: AccountId,
    index: u32,
    seed: u64,
    rng_seed: u64,
) -> Result<Note> {
    XReserveSetAttesterNote::enable(
        administrator(),
        faucet_id,
        index,
        &PublicKey::new(gen_attester_pubkey(seed)),
        &mut note_rng(rng_seed),
    )
    .context("building the administrator set_attester note")
}

/// The production faucet brought up for minting: attester 1 installed at `TEST_ATTESTER_INDEX`,
/// and nothing else — the identifier needs no seeding, because the mint path derives it from the
/// faucet's own account id. `extra_notes` seeds additional admin notes (e.g. the pause note).
pub fn fixture_with(
    max_supply: u64,
    extra_notes: impl Fn(AccountId, AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    setup_production_faucet(max_supply, 0, |recipient, faucet_id| {
        let mut notes = vec![enable_attester_note(faucet_id, TEST_ATTESTER_INDEX, 1, 952)
            .expect("the administrator set_attester note builds")];
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
    consume_note_with_advice(chain, faucet_id, note_id, None).await
}

/// Like `consume_note`, but seeds an advice stack the consuming transaction did not ask for.
///
/// The advice provider is host-controlled, so this is what a malicious prover gets to choose. A
/// mint that behaves identically with and without it is a mint that reads none of it.
pub async fn consume_note_with_advice(
    chain: &MockChain,
    faucet_id: AccountId,
    note_id: NoteId,
    advice_stack: Option<Vec<Felt>>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let mut ctx = chain
        .build_transaction(faucet_id)
        .authenticated_input_note(note_id);
    if let Some(stack) = advice_stack {
        ctx = ctx.extend_advice_inputs(AdviceInputs::default().with_stack(stack));
    }
    ctx.build()
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

/// Emits the note and consumes it, expecting a trap that carries EXACTLY `expected`'s message,
/// then proves fail-closure.
///
/// [`expect_reject`] cannot serve for a `u32assert.err=` guard: `assert_transaction_executor_error!`
/// matches only the VM's plain `FailedAssertion`, while a failed `u32assert` is a different
/// operation error that carries the declared message inside its own rendering. The assertion is
/// still exact — it names the `ERR_*` string byte for byte — it is only located differently.
pub async fn expect_reject_u32_assert(
    pf: &mut ProductionFaucet,
    note: Note,
    payload: &[u8],
    expected: &MasmError,
) -> Result<()> {
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let result = consume_note(&pf.mock_chain, pf.faucet_id, note.id()).await;
    let TransactionExecutorError::TransactionProgramExecutionFailed(execution_error) = result
        .err()
        .context("the u32 guard must trap the consuming transaction")?
    else {
        anyhow::bail!("the trap must be a transaction program execution failure");
    };
    let rendered = execution_error.to_string();
    anyhow::ensure!(
        rendered.contains(expected.message()),
        "expected a u32-assertion trap carrying {:?}, got: {rendered}",
        expected.message()
    );
    assert_no_effects(pf, payload)
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
