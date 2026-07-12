//! CMP-B1 `XReserveMintNote` — the executing-red suite (committed BEFORE implementation).
//!
//! The load-bearing proof: a REAL `XReserveMintNote` — constructed by the production
//! Rust factory, committed in block N by a producer tx, consumed by the PRODUCTION-component-set
//! faucet in block ≥ N+1 with NO tx script and NO consume-side advice staging — drives the
//! F1-fixed `xreserve_mint::mint` through ALL of D5a→D5e. This replaces the driver/advice
//! transport (`run_mint_composition` + `extend_advice_inputs`) that constituted the transport gap.
//!
//! Fail-closed non-vacuity rides the SAME real-note path: a replayed nonce (D5c), a
//! non-allowlisted signature (D5d), and a tampered attachment advice map (the transport's own
//! commitment binding) each trap their EXACT error with ZERO writes.
//!
//! RED-FOR-THE-RIGHT-REASON: at the red commit, `XReserveMintNote::create` is an executing stub
//! returning `Err("xreserve mint note constructor unimplemented")` and the pinned script root is
//! an all-zero placeholder — every test RUNS and fails behaviorally; nothing here is a compile
//! error. The green loop implements against these tests.

mod support;

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{NoteId, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::note::P2idNote;
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::note::xreserve_admin::{XReserveDomainInitNote, XReserveSetAttesterNote};
use xusdc_encoding::note::xreserve_mint::{
    MintAttestation, XReserveMintNote, XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
    XRESERVE_MINT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_storage_map_key, deposit_intent_to_packed_felts,
};

// FIXTURE VALUES (mirroring `assembled_faucet_e2e.rs`; all Circle-owned values are OPEN test
// parameters — Q-DOM-1 / DEV-10 / DEV-1)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";

/// uint256 mint amount 100_000_000, reduced on-chain by the wrapper's scale_exp=6 -> 100 units.
const MINT_AMOUNT_RAW: u64 = 100_000_000;
const MINT_REDUCED: u64 = 100;
/// maxFee 1_000_000 (amount >= maxFee holds); feeAmount stays 0 (DEV-8 MVP).
const MAX_FEE_RAW: u64 = 1_000_000;

const MAX_SUPPLY: u64 = 1_000_000;

/// Test `source_domain` (config-only; nonzero so read-backs are distinguishable).
const TEST_SOURCE_DOMAIN: u32 = 3;

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes; DC-1).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn owner() -> AccountId {
    test_account_id(1)
}

fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

fn fields_of(id: &str) -> &'static DiFields {
    di(id)
        .fields
        .as_ref()
        .expect("accept vector carries fields")
}

/// The canonical accept payload with amount/maxFee spliced and `remoteRecipient` REPLACED by the
/// bytes32 encoding of the actual recipient wallet.
fn payload_for(recipient: AccountId) -> Vec<u8> {
    let mut payload = di(BASE_VECTOR).bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT_RAW));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    payload
}

/// The identifier config word = the canonical key-Word of the payload's remoteToken (what D5a's
/// `assert_eqw` compares against).
fn identifier_word() -> Word {
    Word::from(bytes32_to_storage_map_key(&parse_hex32(
        &fields_of(BASE_VECTOR).remote_token_hex,
    )))
}

/// The usedNonces key for a payload's nonce bytes.
fn nonce_key_of_payload(payload: &[u8]) -> Word {
    let nonce: [u8; 32] = payload[NONCE_BYTE_OFF..NONCE_BYTE_OFF + 32]
        .try_into()
        .expect("32 nonce bytes");
    Word::from(bytes32_to_storage_map_key(&nonce))
}

/// The expected P2ID tag for the recipient (the HIGH u32 of the AccountId prefix,
/// masked `0xfffc0000` — `NoteTag::with_account_target`).
fn expected_p2id_tag(recipient: AccountId) -> u32 {
    let prefix = recipient.prefix().as_felt().as_canonical_u64();
    ((prefix >> 32) as u32) & 0xfffc0000
}

/// Test `xreserve_contract` bytes32: sequential distinct bytes.
fn test_xreserve_contract() -> [u8; 32] {
    core::array::from_fn(|i| 0x10 + i as u8)
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(1u32),
        Felt::from(2u32),
    ]))
}

fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// HARNESS
// ================================================================================================

/// The production-faucet fixture with the two admin bring-up notes seeded (owner domain_init +
/// owner set_attester allowlisting `gen_attester(1, ..)`'s key).
fn fixture() -> Result<ProductionFaucet> {
    setup_production_faucet(MAX_SUPPLY, 0, |recipient| {
        let commitment = gen_attester(1, &payload_for(recipient)).commitment;
        // The ALLOWLISTED PRODUCTION admin notes (F5): the routing target is a placeholder PUBLIC id
        // (routing-only, not consume-gated; the script root — hence the allowlist entry — is
        // attachment-independent, so bring_up's consume-by-id passes network auth). This replaces the
        // pre-F5 inline-stub notes whose roots were NOT allowlisted, which is why bring-up note 0 died.
        let route = test_faucet_id(1);
        vec![
            XReserveDomainInitNote::create(
                owner(),
                route,
                TEST_DOMAIN,
                TEST_SOURCE_DOMAIN,
                &test_xreserve_contract(),
                identifier_word(),
                &mut note_rng(941),
            )
            .expect("building the owner domain_init note"),
            XReserveSetAttesterNote::create(owner(), route, commitment, 1, &mut note_rng(942))
                .expect("building the owner set_attester note"),
        ]
    })
}

/// Consumes the two seeded admin notes (domain_init, set_attester), committing a block each —
/// the PRODUCTION bring-up path (no direct slot seeding).
async fn bring_up(pf: &mut ProductionFaucet) -> Result<()> {
    for (i, note) in pf.seeded_notes.clone().iter().enumerate() {
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

/// The REAL attestation for a payload from the deterministic attester `seed` (raw bytes, as the
/// relayer would hand the constructor).
fn attestation_for(seed: u64, payload: &[u8]) -> MintAttestation {
    let attester = gen_attester(seed, payload);
    MintAttestation::new(attester.sig_bytes, attester.pubkey_bytes)
}

/// Consumes a committed note on the faucet with NO tx script and NO consume-side advice staging —
/// the real-note transport under test (the executor auto-injects storage + attachment advice from
/// the committed note itself).
async fn consume_mint_note(
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
    Ok(chain
        .committed_account(id)
        .context("fetching the committed account")?
        .clone())
}

fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> Result<AssetAmount> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(FungibleFaucet::try_from(storage)?.token_supply())
}

fn assert_supply(chain: &MockChain, faucet_id: AccountId, expected: u64, what: &str) -> Result<()> {
    assert_eq!(
        committed_token_supply(chain, faucet_id)?,
        AssetAmount::new(expected).context("expected supply is a valid AssetAmount")?,
        "token_supply ledger mismatch: {what}",
    );
    Ok(())
}

/// Reads a map-slot entry word from an account (attester-allowlist / usedNonces read-backs).
fn read_map_word(account: &Account, slot_label: &str, key: Word) -> Result<Word> {
    account
        .storage()
        .get_map_item(
            &miden_protocol::account::StorageSlotName::new(slot_label)
                .with_context(|| format!("slot label {slot_label}"))?,
            key,
        )
        .map_err(|e| anyhow::anyhow!("reading map slot {slot_label}: {e}"))
}

// 1 — THE REAL-NOTE END-TO-END MINT (the must-have)
// ================================================================================================

#[tokio::test]
async fn mint_note_drives_attested_mint_end_to_end() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;

    let payload = payload_for(pf.recipient_id);
    let note = XReserveMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &attestation_for(1, &payload),
        &mut note_rng(42),
    )
    .map_err(|e| anyhow::anyhow!("constructing the real mint note: {e}"))?;

    // Block N: the producer emits the real note in a REAL tx (id parity asserted inside).
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    // Block N+1: the faucet consumes it — no tx script, no consume-side advice.
    let minted = consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id())
        .await
        .map_err(|e| anyhow::anyhow!("the real-note attested mint must succeed: {e}"))?;

    // Observability non-vacuity: the recipient P2ID note's FULL observable surface.
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "exactly one recipient note"
    );
    let p2id = minted.output_notes().get_note(0);
    let asset = p2id
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note carries a fungible asset");
    assert_eq!(
        u64::from(asset.amount()),
        MINT_REDUCED,
        "note asset == reduced amount"
    );
    assert_eq!(
        asset.faucet_id(),
        pf.faucet_id,
        "asset minted by this faucet"
    );
    let recipient_digest = p2id
        .recipient()
        .expect("public output note carries its recipient");
    assert_eq!(
        recipient_digest.serial_num(),
        nonce_key_of_payload(&payload),
        "recipient-note serial == the nonce-derived KEY"
    );
    assert_eq!(
        recipient_digest.script().root(),
        P2idNote::script_root(),
        "canonical P2ID script root"
    );
    assert_eq!(
        recipient_digest.storage().items(),
        [pf.recipient_id.suffix(), pf.recipient_id.prefix().as_felt()].as_slice(),
        "P2ID storage == [recipient_suffix, recipient_prefix]"
    );
    assert_eq!(
        p2id.metadata().tag().as_u32(),
        expected_p2id_tag(pf.recipient_id),
        "Case-001 tag (recipient account-target, prefix HIGH u32) asserted directly"
    );
    assert_eq!(
        p2id.metadata().note_type(),
        NoteType::Public,
        "recipient note is Public"
    );

    // Committed post-state: supply += amount EXACTLY; usedNonces[key] set; note consumed.
    commit(&mut pf.mock_chain, &minted)?;
    assert_supply(
        &pf.mock_chain,
        pf.faucet_id,
        MINT_REDUCED,
        "after the real-note mint",
    )?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, pf.faucet_id)?,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "usedNonces[key] marker set"
    );
    assert!(
        pf.mock_chain.is_note_consumed(&note.nullifier()),
        "the mint note's nullifier is spent"
    );
    Ok(())
}

// 2 — D5c THROUGH THE REAL NOTE (replayed nonce; exact error; zero writes)
// ================================================================================================

#[tokio::test]
async fn mint_note_replayed_nonce_rejects_no_writes() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id);
    let attestation = attestation_for(1, &payload);

    // First mint (green) — consumes nonce N.
    let note_a = XReserveMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &attestation,
        &mut note_rng(43),
    )
    .map_err(|e| anyhow::anyhow!("constructing mint note A: {e}"))?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note_a).await?;
    let minted = consume_mint_note(&pf.mock_chain, pf.faucet_id, note_a.id())
        .await
        .map_err(|e| anyhow::anyhow!("the first real-note mint must succeed: {e}"))?;
    commit(&mut pf.mock_chain, &minted)?;
    assert_supply(
        &pf.mock_chain,
        pf.faucet_id,
        MINT_REDUCED,
        "after the first mint",
    )?;

    // Replay: a SECOND real note (fresh serial), SAME payload/nonce -> the EXACT D5c error.
    let note_b = XReserveMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &attestation,
        &mut note_rng(44),
    )
    .map_err(|e| anyhow::anyhow!("constructing mint note B: {e}"))?;
    assert_ne!(note_b.id(), note_a.id(), "fresh serial -> distinct note id");
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note_b).await?;
    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, note_b.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));

    // Zero writes: supply unchanged; the nonce marker is exactly the first mint's.
    assert_supply(
        &pf.mock_chain,
        pf.faucet_id,
        MINT_REDUCED,
        "after the replay reject",
    )?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, pf.faucet_id)?,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        marker(),
        "usedNonces[key] still the first mint's marker (no second write)"
    );
    Ok(())
}

// 3 — D5d THROUGH THE REAL NOTE (non-allowlisted signature; exact error; zero writes)
// ================================================================================================

#[tokio::test]
async fn mint_note_forged_signature_rejects_no_writes() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id);

    // A VALID ECDSA signature from a key that is NOT allowlisted (attester seed 2; only seed 1
    // is in xReserveAttesters) -> the EXACT D5d allowlist error, through the real note.
    let note = XReserveMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &attestation_for(2, &payload),
        &mut note_rng(45),
    )
    .map_err(|e| anyhow::anyhow!("constructing the forged-attester mint note: {e}"))?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    let result = consume_mint_note(&pf.mock_chain, pf.faucet_id, note.id()).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT")
    );

    // Zero writes: no supply, no nonce marker.
    assert_supply(
        &pf.mock_chain,
        pf.faucet_id,
        0,
        "after the forged-signature reject",
    )?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, pf.faucet_id)?,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        Word::from([0u32, 0, 0, 0]),
        "usedNonces[key] untouched by the reject"
    );
    Ok(())
}

// 4 — PUBLIC + FIXED SCRIPT_ROOT (observability; constructor-level, asserted directly)
// ================================================================================================

#[test]
fn mint_note_is_public_with_fixed_script_root() -> Result<()> {
    let recipient = test_account_id(5);
    let faucet_id = test_faucet_id(7);
    let payload = payload_for(recipient);
    let note = XReserveMintNote::create(
        test_account_id(6),
        faucet_id,
        &payload,
        &attestation_for(1, &payload),
        &mut note_rng(46),
    )
    .map_err(|e| anyhow::anyhow!("constructing the mint note: {e}"))?;

    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "NoteType::Public is FORCED (network-tx observability mandate)"
    );
    assert_eq!(
        note.recipient().script().root(),
        XReserveMintNote::pinned_script_root(),
        "the note's script root == the PINNED XRESERVE_MINT_NOTE_SCRIPT_ROOT constant"
    );
    assert_eq!(
        XReserveMintNote::script_root(),
        XReserveMintNote::pinned_script_root(),
        "masm-rust-constant-parity: the compiled script root == the pinned constant"
    );
    assert_eq!(
        note.metadata().tag(),
        NoteTag::with_account_target(faucet_id),
        "the mint note carries the faucet account-target tag (TAG-1)"
    );
    assert_eq!(
        note.assets().num_assets(),
        0,
        "the mint note carries NO assets"
    );
    assert_eq!(
        note.attachments().num_attachments(),
        2,
        "two attachments: the scheme-1 attestation + the scheme-2 NetworkAccountTarget routing bind (F5)"
    );
    let scheme_one =
        miden_protocol::note::NoteAttachmentScheme::new(XRESERVE_MINT_ATTACHMENT_SCHEME)
            .expect("scheme 1 is a valid attachment scheme");
    let attestation = note
        .attachments()
        .iter()
        .find(|a| a.attachment_scheme() == scheme_one)
        .expect("the scheme-1 attestation attachment");
    assert_eq!(
        attestation.content().as_words().len(),
        XRESERVE_MINT_ATTACHMENT_NUM_WORDS,
        "the attestation is exactly 9 words: [fee(8), pubkey(9), sig(17), pad(2)]"
    );
    Ok(())
}

// 5 — NoteStorage.items == THE SHARED-ENCODING CODEC OUTPUT (consumed by reference, felt-exact)
// ================================================================================================

#[test]
fn mint_note_items_are_04_packed_preimage() -> Result<()> {
    let recipient = test_account_id(5);
    let payload = payload_for(recipient);
    let note = XReserveMintNote::create(
        test_account_id(6),
        test_faucet_id(7),
        &payload,
        &attestation_for(1, &payload),
        &mut note_rng(47),
    )
    .map_err(|e| anyhow::anyhow!("constructing the mint note: {e}"))?;

    let expected = deposit_intent_to_packed_felts(&payload)
        .map_err(|e| anyhow::anyhow!("packing the payload via the 04 codec: {e}"))?;
    assert_eq!(
        note.recipient().storage().items(),
        expected.as_slice(),
        "NoteStorage.items == deposit_intent_to_packed_felts(payload), felt-exact"
    );
    Ok(())
}

// 6 — TAMPERED ATTACHMENT ADVICE (the transport's commitment binding fail-closes; zero writes)
// ================================================================================================

#[tokio::test]
async fn mint_note_tampered_attachment_advice_rejects_no_writes() -> Result<()> {
    let mut pf = fixture()?;
    bring_up(&mut pf).await?;
    let payload = payload_for(pf.recipient_id);

    // A fully VALID note...
    let note = XReserveMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        &payload,
        &attestation_for(1, &payload),
        &mut note_rng(48),
    )
    .map_err(|e| anyhow::anyhow!("constructing the mint note: {e}"))?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;

    // ...consumed with a HOSTILE advice-map override under the attachment commitment (the ONE
    // sanctioned consume-side `extend_advice_inputs` use: it injects hostile advice — the
    // opposite of transport-replacement).
    let commitment = note
        .attachments()
        .iter()
        .next()
        .expect("the mint note carries its attachment")
        .content()
        .to_commitment();
    let wrong: Vec<Felt> = (0..36u32).map(|_| Felt::from(9999u32)).collect();
    let result = pf
        .mock_chain
        .build_tx_context(pf.faucet_id, &[note.id()], &[])
        .context("building the tampered consume tx context")?
        .extend_advice_inputs(AdviceInputs::default().with_map([(commitment, wrong)]))
        .build()
        .context("building the tampered consume tx")?
        .execute()
        .await;

    // The EXACT trap (canary-pinned): the bare `assert_eqw` inside
    // `mem::pipe_preimage_to_memory` -> `FailedAssertion { err_code: 0, err_msg: None }`. The
    // pinned core-lib carries NO named error at that assert; naming it would require modifying
    // pinned protocol code (out of scope) — pinned here as the anonymous assertion, and it must
    // fire BEFORE any D5 gate (no shell error string).
    let err = match result {
        Ok(_) => panic!("a tampered attachment advice map must not execute"),
        Err(e) => format!("{e:?}"),
    };
    assert!(
        err.contains("FailedAssertion { err_code: 0"),
        "the tamper must trap pipe_preimage_to_memory's bare assert_eqw, got: {err}"
    );

    // Zero writes: no supply, no nonce marker.
    assert_supply(
        &pf.mock_chain,
        pf.faucet_id,
        0,
        "after the tampered-advice reject",
    )?;
    assert_eq!(
        read_map_word(
            &committed(&pf.mock_chain, pf.faucet_id)?,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload)
        )?,
        Word::from([0u32, 0, 0, 0]),
        "usedNonces[key] untouched by the tamper reject"
    );
    Ok(())
}
