//! FULL FAUCET ASSEMBLY E2E: the single-instance, sequential,
//! full-lifecycle dress rehearsal for local-node validation. ONE faucet composed by the PRODUCTION
//! `XReserveStablecoinBuilder` (empty domain config, empty allowlist) is driven through the whole
//! lifecycle IN ORDER on ONE evolving MockChain — init (4-field domain config) → re-init trap →
//! admin bring-up (attester / max_supply / min_burn, each with its non-owner reject) → a REAL
//! attested mint (D5d in-test vectors) → nonce replay trap → stock mint_and_send deny → the
//! recipient wallet consumes the minted P2ID note (custody-traced funds) → a below-min
//! burn reject → a real burn (two-block consume, DC-7 schema asserted) → DOM_PAUSER pause halts
//! BOTH mint and burn (and the owner has NO pause path) → unpause resumes BOTH → CMP-F5 rotation
//! (DOM_MANAGER grant → new pauser pauses; revoke → rejected). Every tx is COMMITTED
//! (`add_pending_executed_transaction` + `prove_next_block`) so all stages run on one chain — no
//! stitched fixtures. Every reject pins its EXACT error; every state change is read back;
//! the final ledger asserts the exact whole-arc supply equation.
//!
//! MECHANICS: the admin notes are deterministic and pre-seeded ON-CHAIN at build
//! (`setup_assembled_faucet` seeded_notes), so every admin step consumes its note BY ID as an
//! authenticated input — block-provable, which commit-each-step requires (an unauthenticated note
//! cannot be committed: no inclusion proof). Reject-path notes stay unconsumed after their tx
//! traps.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId, RoleSymbol};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteId, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::note::P2idNote;
use miden_testing::{assert_transaction_executor_error, MockChain};
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::{DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};
use xusdc_encoding::vectors::{load, parse_hex32, DiFields, DiVector};
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_packed_felts, bytes32_to_storage_map_key,
    decode_burn_note_items, XReserveBurnItems,
};

// ACTORS (the builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3))
// ================================================================================================

fn owner() -> AccountId {
    test_account_id(1)
}
fn pauser() -> AccountId {
    test_account_id(2)
}
fn manager() -> AccountId {
    test_account_id(3)
}
fn new_pauser() -> AccountId {
    test_account_id(4)
}
fn stranger() -> AccountId {
    test_account_id(99)
}

// FIXTURE VALUES (all Circle-owned values are test parameters — Q-DOM-1 / DEV-10 / DEV-1 OPEN)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const LEN_FELTS: u64 = 60;
const SCALE_EXP: u32 = 6;

/// uint256 mint amount 100_000_000, reduced by scale_exp=6 -> 100 asset units.
const MINT_AMOUNT_RAW: u64 = 100_000_000;
const MINT_REDUCED: u64 = 100;
/// maxFee 1_000_000 -> 1 (amount >= maxFee holds); feeAmount stays 0 (DEV-8 MVP).
const MAX_FEE_RAW: u64 = 1_000_000;

const MAX_SUPPLY: u64 = 1_000_000;
const NEW_MAX_SUPPLY: u64 = 500_000;
const MIN_BURN: u64 = 10;
const BURN_LOW: u64 = 5; // < MIN_BURN -> R-BURN-2 reject
const BURN_OK: u64 = 20;
const BURN_PAUSED: u64 = 10; // emitted while paused; consumed after unpause (S11b)

/// Test `source_domain` (nonzero so the read-back is distinguishable from an unwritten slot).
const TEST_SOURCE_DOMAIN: u32 = 3;

/// Test `xreserve_contract` bytes32: sequential distinct bytes (all 8 packed limbs distinct).
fn test_xreserve_contract() -> [u8; 32] {
    core::array::from_fn(|i| 0x10 + i as u8)
}

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `nonce` field (felt 51 x 4 bytes; DC-1).
const NONCE_BYTE_OFF: usize = 51 * 4;

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
/// REAL recipient wallet's right-aligned bytes32 (so the emitted P2ID note targets an account that
/// exists on this chain and can consume it).
fn payload_for(recipient: AccountId) -> Vec<u8> {
    let mut payload = di(BASE_VECTOR).bytes();
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(MINT_AMOUNT_RAW));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(MAX_FEE_RAW));
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&account_id_to_bytes32(recipient));
    payload
}

/// The distinct-nonce second-mint payload (S11a): XOR-perturbs one nonce byte.
fn payload2_for(recipient: AccountId) -> Vec<u8> {
    let mut payload = payload_for(recipient);
    payload[NONCE_BYTE_OFF] ^= 0x5A;
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

/// The expected P2ID tag for the recipient (the HIGH u32 of the AccountId prefix, masked
/// `0xfffc0000` — `NoteTag::with_account_target`).
fn expected_p2id_tag(recipient: AccountId) -> u32 {
    let prefix = recipient.prefix().as_felt().as_canonical_u64();
    ((prefix >> 32) as u32) & 0xfffc0000
}

fn pack(bytes: &[u8]) -> Vec<Felt> {
    miden_protocol::utils::bytes_to_packed_u32_elements(bytes)
}

fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(31u32),
        Felt::from(32u32),
    ]))
}

// CHAIN MECHANICS — commit-each-step (the run_burn_consume pattern), committed-state re-fetch
// ================================================================================================

fn commit(chain: &mut MockChain, tx: &ExecutedTransaction) -> Result<()> {
    chain
        .add_pending_executed_transaction(tx)
        .context("queuing the executed tx into the block")?;
    chain.prove_next_block().context("proving the block")?;
    Ok(())
}

fn committed(chain: &MockChain, id: AccountId) -> Result<Account> {
    Ok(chain
        .committed_account(id)
        .context("fetching the committed account")?
        .clone())
}

/// Consumes a COMMITTED note (by id) with `account` as the executing/consuming account — the
/// recipient's P2ID consume and the faucet's `receive_and_burn` consume both ride this.
async fn consume_committed_note(
    chain: &MockChain,
    account: &Account,
    note_id: NoteId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_tx_context(account.clone(), &[note_id], &[])
        .expect("building the consume tx context")
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Asserts the committed faucet supply equals `expected` (the whole-arc ledger read).
fn assert_supply(chain: &MockChain, faucet_id: AccountId, expected: u64, what: &str) -> Result<()> {
    assert_eq!(
        committed_token_supply(chain, faucet_id)?,
        AssetAmount::new(expected).context("expected supply is a valid AssetAmount")?,
        "token_supply ledger mismatch: {what}",
    );
    Ok(())
}

/// Reads a map-slot entry word from an account (the attester-allowlist / usedNonces read-backs).
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

/// The recipient wallet's total balance of the faucet's fungible asset (vault iteration — the
/// custody read-back for S7).
fn wallet_balance(account: &Account, faucet_id: AccountId) -> u64 {
    account
        .vault()
        .assets()
        .filter_map(|asset| match asset {
            miden_protocol::asset::Asset::Fungible(f) if f.faucet_id() == faucet_id => {
                Some(u64::from(f.amount()))
            }
            _ => None,
        })
        .sum()
}

/// The map marker word `[1, 0, 0, 0]` (attester enabled / nonce used / role member).
fn marker() -> Word {
    Word::from([1u32, 0, 0, 0])
}

// THE FULL LIFECYCLE
// ================================================================================================

/// The single-instance, sequential, full-lifecycle E2E on ONE production-assembled faucet.
#[tokio::test]
async fn assembled_faucet_full_lifecycle() -> Result<()> {
    // ── S0 — ASSEMBLY: the production builder composes the faucet; domain config + allowlist EMPTY.
    // All admin notes are DETERMINISTIC and pre-seeded ON-CHAIN at build (indices below), so every
    // admin step consumes its note BY ID as an authenticated input — block-provable, which the
    // commit-each-step design requires (an unauthenticated note cannot be committed: "no inclusion
    // proof"). Reject-path notes simply stay unconsumed after their tx traps.
    let mut af = setup_assembled_faucet(MAX_SUPPLY, 0, |recipient| {
        let drivers = vec![
            mint_composition_driver_src(&pack(&payload_for(recipient)), LEN_FELTS, SCALE_EXP),
            mint_composition_driver_src(&pack(&payload2_for(recipient)), LEN_FELTS, SCALE_EXP),
        ];
        let commitment = gen_attester(1, &payload_for(recipient)).commitment;
        let psym = RoleSymbol::new(DOM_PAUSER_ROLE).expect("valid role symbol");
        let xrc = test_xreserve_contract();
        let identifier = identifier_word();
        let build = |what: &str, r: anyhow::Result<miden_protocol::note::Note>| {
            r.unwrap_or_else(|e| panic!("building the seeded {what} note: {e}"))
        };
        let notes = vec![
            // 0: S1a stranger domain_init (reject)
            build(
                "init-stranger",
                domain_init_note(
                    stranger(),
                    TEST_DOMAIN,
                    TEST_SOURCE_DOMAIN,
                    &xrc,
                    identifier,
                    910,
                ),
            ),
            // 1: S1b owner domain_init
            build(
                "init-owner",
                domain_init_note(
                    owner(),
                    TEST_DOMAIN,
                    TEST_SOURCE_DOMAIN,
                    &xrc,
                    identifier,
                    911,
                ),
            ),
            // 2: S2 owner re-init with different values (reject)
            build(
                "re-init",
                domain_init_note(
                    owner(),
                    TEST_WRONG_DOMAIN,
                    TEST_SOURCE_DOMAIN + 1,
                    &[0xEEu8; 32],
                    Word::from([91u32, 92, 93, 94]),
                    912,
                ),
            ),
            // 3: S3a stranger set_attester (reject)
            build(
                "attester-stranger",
                set_attester_note(stranger(), commitment, 1, 913),
            ),
            // 4: S3a owner set_attester
            build(
                "attester-owner",
                set_attester_note(owner(), commitment, 1, 914),
            ),
            // 5: S3b stranger set_max_supply (reject)
            build(
                "max-stranger",
                set_max_supply_note(stranger(), NEW_MAX_SUPPLY, 915),
            ),
            // 6: S3b owner set_max_supply
            build(
                "max-owner",
                set_max_supply_note(owner(), NEW_MAX_SUPPLY, 916),
            ),
            // 7: S3c stranger set_min_burn_size (reject)
            build(
                "min-stranger",
                set_min_burn_size_note(stranger(), MIN_BURN, 917),
            ),
            // 8: S3c owner set_min_burn_size
            build("min-owner", set_min_burn_size_note(owner(), MIN_BURN, 918)),
            // 9: S10 DOM_PAUSER pause
            build("pause-pauser", dom_pauser_pause_note(pauser(), 919)),
            // 10: S10c owner STOCK pause probe (traps UnknownAccountProcedure)
            build("pause-stock-owner", pause_note(owner(), 920)),
            // 11: S10d stranger custom pause (reject)
            build("pause-stranger", dom_pauser_pause_note(stranger(), 921)),
            // 12: S11 DOM_PAUSER unpause
            build("unpause-pauser", dom_pauser_unpause_note(pauser(), 922)),
            // 13: S12 DOM_MANAGER grant_role(DOM_PAUSER, new_pauser)
            build(
                "grant",
                grant_role_note(manager(), &psym, new_pauser(), 923),
            ),
            // 14: S12 new pauser pause
            build("pause-new", dom_pauser_pause_note(new_pauser(), 924)),
            // 15: S12 new pauser unpause
            build("unpause-new", dom_pauser_unpause_note(new_pauser(), 925)),
            // 16: S12 DOM_MANAGER revoke_role(DOM_PAUSER, new_pauser)
            build(
                "revoke",
                revoke_role_note(manager(), &psym, new_pauser(), 926),
            ),
            // 17: S12 revoked pauser pause attempt (reject)
            build("pause-revoked", dom_pauser_pause_note(new_pauser(), 927)),
        ];
        (drivers, notes)
    })?;
    let note_id = |i: usize| af.seeded_notes[i].id();
    let faucet_id = af.harness.account_id;
    let recipient_id = af.recipient_id;
    let payload1 = payload_for(recipient_id);
    let payload2 = payload2_for(recipient_id);
    let attester1 = gen_attester(1, &payload1);
    let attester2 = gen_attester(1, &payload2);
    assert_eq!(
        attester1.commitment, attester2.commitment,
        "one deterministic attester key signs both payloads (single allowlist entry)"
    );
    let identifier = identifier_word();
    let xrc = test_xreserve_contract();
    let pauser_sym = RoleSymbol::new(DOM_PAUSER_ROLE).expect("valid role symbol");
    let manager_sym = RoleSymbol::new(DOM_MANAGER_ROLE).expect("valid role symbol");

    // S0 read-backs: empty domain config; supply 0; the CMP-F5 delegation seeded at build.
    let faucet0 = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_domain_config_words(&faucet0)?,
        [Word::from([0u32, 0, 0, 0]); 5],
        "S0: all five domain-config slots ship EMPTY (domain_init is the production writer)"
    );
    assert_supply(&af.harness.mock_chain, faucet_id, 0, "S0 assembly")?;
    assert_eq!(
        read_role_config(&faucet0, &pauser_sym)?,
        Word::new([
            Felt::from(1u32),
            Felt::from(&manager_sym),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        "S0: role_config[DOM_PAUSER] carries the CMP-F5 delegation (admin_role = DOM_MANAGER)"
    );
    assert_eq!(
        read_role_config(&faucet0, &manager_sym)?,
        marker(),
        "S0: role_config[DOM_MANAGER] is owner-administered ([1,0,0,0])"
    );
    assert_eq!(
        read_map_word(
            &faucet0,
            XRESERVE_ATTESTERS_SLOT_LABEL,
            attester1.commitment
        )?,
        Word::from([0u32, 0, 0, 0]),
        "S0: the attester allowlist ships EMPTY (set_attester is the bring-up writer)"
    );

    // ── S1a — INIT REJECT: a stranger's domain_init traps the EXACT owner error; nothing written.
    let result = consume_committed_note(&af.harness.mock_chain, &faucet0, note_id(0)).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    assert_eq!(
        read_domain_config_words(&committed(&af.harness.mock_chain, faucet_id)?)?,
        [Word::from([0u32, 0, 0, 0]); 5],
        "S1a: the rejected init left every slot empty"
    );

    // ── S1b — INIT: the owner writes ALL FOUR domain-config fields; each reads back exactly.
    let init_tx = consume_committed_note(&af.harness.mock_chain, &faucet0, note_id(1))
        .await
        .expect("S1b: the owner's 4-field domain_init must succeed");
    let mut faucet1 = faucet0.clone();
    faucet1.apply_delta(init_tx.account_delta())?;
    let words = read_domain_config_words(&faucet1)?;
    let xrc_felts = bytes32_to_packed_felts(&xrc);
    assert_eq!(
        words[0],
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        "S1b: domain read-back"
    );
    assert_eq!(
        words[1],
        Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
        "S1b: source_domain read-back"
    );
    assert_eq!(
        words[2],
        Word::new([xrc_felts[0], xrc_felts[1], xrc_felts[2], xrc_felts[3]]),
        "S1b: xreserve_contract_hi read-back"
    );
    assert_eq!(
        words[3],
        Word::new([xrc_felts[4], xrc_felts[5], xrc_felts[6], xrc_felts[7]]),
        "S1b: xreserve_contract_lo read-back"
    );
    assert_eq!(words[4], identifier, "S1b: identifier read-back (verbatim)");
    // lossless round-trip: the stored bytes32 round-trips through the FAIL-CLOSED
    // inverse back to the input — the GetAccount-readable public identity.
    let stored_xrc: [Felt; 8] = [
        words[2][0],
        words[2][1],
        words[2][2],
        words[2][3],
        words[3][0],
        words[3][1],
        words[3][2],
        words[3][3],
    ];
    assert_eq!(
        xusdc_encoding::xreserve::encoding::packed_felts_to_bytes32(&stored_xrc)
            .expect("S1b: stored xreserve_contract limbs are valid u32s (fail-closed inverse)"),
        xrc,
        "S1b: fail-closed bytes32 round-trip == the input xreserve_contract"
    );
    commit(&mut af.harness.mock_chain, &init_tx)?;

    // ── S2 — RE-INIT: a second owner init traps the EXACT R-ADMIN-4 error; every field unchanged.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(2)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    assert_eq!(
        read_domain_config_words(&faucet)?,
        words,
        "S2: the trapped re-init left all five domain-config words unchanged (immutable)"
    );

    // ── S3a — ADMIN: owner allowlists the attester; a stranger's attempt is rejected and leaves
    // the map unchanged.
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(3)).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    assert_eq!(
        read_map_word(&faucet, XRESERVE_ATTESTERS_SLOT_LABEL, attester1.commitment)?,
        Word::from([0u32, 0, 0, 0]),
        "S3a: the rejected set_attester left the allowlist unchanged"
    );
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(4))
        .await
        .expect("S3a: the owner's set_attester must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    assert_eq!(
        read_map_word(
            &committed(&af.harness.mock_chain, faucet_id)?,
            XRESERVE_ATTESTERS_SLOT_LABEL,
            attester1.commitment
        )?,
        marker(),
        "S3a: the allowlist marker [1,0,0,0] reads back for the commitment"
    );

    // ── S3b — ADMIN: owner sets max_supply; a stranger's attempt is rejected.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(5)).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(6))
        .await
        .expect("S3b: the owner's set_max_supply must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_token_config(&faucet)?[1],
        Felt::from(AssetAmount::new(NEW_MAX_SUPPLY)?),
        "S3b: token_config[max_supply] read-back"
    );

    // ── S3c — ADMIN: owner sets min_burn_size; a stranger's attempt is rejected.
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(7)).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(8))
        .await
        .expect("S3c: the owner's set_min_burn_size must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_min_burn_size(&faucet)?,
        Word::from([
            Felt::from(AssetAmount::new(MIN_BURN)?),
            Felt::from(0u32),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        "S3c: min_burn_size read-back"
    );

    // ── S4 — ATTESTED MINT: the real D5d-vector mint drives the FULL xreserve_mint chain.
    let minted = run_rotation_mint(
        &af.harness,
        &af.drivers[0],
        &faucet,
        composition_advice([0u32; 8], &attester1),
    )
    .await
    .expect("S4: a fully valid deposit intent + attestation must mint on the assembled faucet");
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "S4: exactly one recipient note"
    );
    let note = minted.output_notes().get_note(0);
    let mint_note_id = note.id();
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("S4: the recipient note carries a fungible asset");
    assert_eq!(
        u64::from(asset.amount()),
        MINT_REDUCED,
        "S4: note asset == reduced amount"
    );
    assert_eq!(
        asset.faucet_id(),
        faucet_id,
        "S4: asset minted by this faucet"
    );
    let recipient_digest = note
        .recipient()
        .expect("S4: public output note carries its recipient");
    assert_eq!(
        recipient_digest.serial_num(),
        nonce_key_of_payload(&payload1),
        "S4: note serial == the nonce-derived KEY"
    );
    assert_eq!(
        recipient_digest.script().root(),
        P2idNote::script_root(),
        "S4: canonical P2ID script root"
    );
    assert_eq!(
        note.metadata().tag().as_u32(),
        expected_p2id_tag(recipient_id),
        "S4: Case-001 tag (recipient account-target, prefix HIGH u32)"
    );
    assert_eq!(
        note.metadata().note_type(),
        NoteType::Public,
        "S4: recipient note is Public"
    );
    commit(&mut af.harness.mock_chain, &minted)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        MINT_REDUCED,
        "S4 after mint",
    )?;
    assert_eq!(
        read_map_word(
            &committed(&af.harness.mock_chain, faucet_id)?,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload1)
        )?,
        marker(),
        "S4: usedNonces[key] marker set (the first atomic state write)"
    );

    // ── S5 — REPLAY: the same nonce traps the EXACT R-MINT-12 error; supply unchanged.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = run_rotation_mint(
        &af.harness,
        &af.drivers[0],
        &faucet,
        composition_advice([0u32; 8], &attester1),
    )
    .await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        MINT_REDUCED,
        "S5 after replay reject",
    )?;

    // ── S6 — DENY: stock mint_and_send traps the EXACT R-MINT-16 error; supply unchanged.
    let result = run_mint_and_send(&af.harness, Word::from([0u32, 1, 2, 3]), 0, 4, 100, 0).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_MINT_DENIED"));
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        MINT_REDUCED,
        "S6 after deny",
    )?;

    // ── S7 — P2ID CONSUME: the recipient wallet consumes the minted note (custody-traced funds).
    let recipient = committed(&af.harness.mock_chain, recipient_id)?;
    assert_eq!(
        wallet_balance(&recipient, faucet_id),
        0,
        "S7: the recipient holds nothing before consuming the mint note"
    );
    let consume = consume_committed_note(&af.harness.mock_chain, &recipient, mint_note_id)
        .await
        .expect("S7: the recipient consumes its P2ID mint note");
    commit(&mut af.harness.mock_chain, &consume)?;
    assert_eq!(
        wallet_balance(&committed(&af.harness.mock_chain, recipient_id)?, faucet_id),
        MINT_REDUCED,
        "S7: the recipient's vault holds the full minted amount (custody-traced)"
    );

    // ── S8 — BURN BELOW MIN: a real XReserveBurnNote below min_burn_size is rejected at consume
    // with the EXACT R-BURN-2 error (CMP-A10 live on the assembled instance).
    let low_items = XReserveBurnItems {
        amount: AssetAmount::new(BURN_LOW)?,
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: [0xABu8; 32],
        salt: [0x01u8; 32],
    };
    let low_note = XReserveBurnNote::create(recipient_id, faucet_id, low_items, &mut note_rng(41))?;
    let low_asset = FungibleAsset::new(faucet_id, BURN_LOW)?;
    let emit = try_emit_burn_note(
        &af.harness.mock_chain,
        &low_note,
        &low_asset,
        faucet_id,
        recipient_id,
    )
    .await
    .expect("S8: emitting the below-min burn note succeeds (the reject is at consume)");
    commit(&mut af.harness.mock_chain, &emit)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, low_note.id()).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BURN_BELOW_MIN"));
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        MINT_REDUCED,
        "S8 after below-min reject",
    )?;

    // ── S9 — BURN: a real burn of the minted funds; DC-7 schema asserted; two-block consume;
    // supply -= amount exactly (whole-arc conservation).
    let items = XReserveBurnItems {
        amount: AssetAmount::new(BURN_OK)?,
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: [0xCDu8; 32],
        salt: [0x02u8; 32],
    };
    let burn_note =
        XReserveBurnNote::create(recipient_id, faucet_id, items.clone(), &mut note_rng(42))?;
    assert_eq!(
        burn_note.metadata().note_type(),
        NoteType::Public,
        "S9: burn note is Public"
    );
    assert_eq!(
        burn_note.metadata().tag().as_u32(),
        FIXED_XUSDC_BURN_TAG,
        "S9: the fixed full-32-bit xUSDC burn tag"
    );
    assert_eq!(
        burn_note.metadata().sender(),
        recipient_id,
        "S9: metadata.sender == depositor"
    );
    assert_eq!(
        decode_burn_note_items(burn_note.recipient().storage().items())
            .expect("S9: DC-7 items decode"),
        items,
        "S9: NoteStorage.items carries the exact DC-7 payload"
    );
    let burn_asset = FungibleAsset::new(faucet_id, BURN_OK)?;
    let emit = try_emit_burn_note(
        &af.harness.mock_chain,
        &burn_note,
        &burn_asset,
        faucet_id,
        recipient_id,
    )
    .await
    .expect("S9: emitting the burn note (block N)");
    commit(&mut af.harness.mock_chain, &emit)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let consume = consume_committed_note(&af.harness.mock_chain, &faucet, burn_note.id())
        .await
        .expect(
            "S9: the faucet consumes the burn note at block >= N+1 (receive_and_burn -> CMP-A10)",
        );
    commit(&mut af.harness.mock_chain, &consume)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        MINT_REDUCED - BURN_OK,
        "S9: supply == amount_minted - amount_burned (arc conservation)",
    )?;

    // ── S10 — PAUSE: DOM_PAUSER pauses; the halt is real on BOTH paths; the owner has NO path.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(9))
        .await
        .expect("S10: the DOM_PAUSER pause must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([1u32, 0, 0, 0]),
        "S10: is_paused publicly readable == paused"
    );
    // S10a: a further mint (the second driver — its FIRST line is the pause gate) traps.
    let result = run_rotation_mint(
        &af.harness,
        &af.drivers[1],
        &faucet,
        composition_advice([0u32; 8], &attester2),
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    // S10b: a further burn consume traps (emit first — the recipient-side emit has no pause gate).
    let paused_items = XReserveBurnItems {
        amount: AssetAmount::new(BURN_PAUSED)?,
        dest_domain: TEST_SOURCE_DOMAIN,
        dest_recipient: [0xEFu8; 32],
        salt: [0x03u8; 32],
    };
    let paused_note =
        XReserveBurnNote::create(recipient_id, faucet_id, paused_items, &mut note_rng(43))?;
    let paused_asset = FungibleAsset::new(faucet_id, BURN_PAUSED)?;
    let emit = try_emit_burn_note(
        &af.harness.mock_chain,
        &paused_note,
        &paused_asset,
        faucet_id,
        recipient_id,
    )
    .await
    .expect("S10b: emitting while paused succeeds (the halt is at the faucet consume)");
    commit(&mut af.harness.mock_chain, &emit)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, paused_note.id()).await;
    assert_transaction_executor_error!(result, err_paused());
    // S10c: the owner has NO direct pause path (Domain-Pauser-only model — the stock PausableManager is absent).
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(10)).await;
    let err = result.expect_err("S10c: the stock owner pause path must not exist");
    assert_unknown_account_procedure(&err);
    // S10d: a non-DOM_PAUSER custom pause attempt is rejected with the EXACT role error.
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(11)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());

    // ── S11 — UNPAUSE: DOM_PAUSER unpauses; BOTH paths resume.
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(12))
        .await
        .expect("S11: the DOM_PAUSER unpause must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([0u32, 0, 0, 0]),
        "S11: is_paused == unpaused"
    );
    // S11a: the second attested mint (fresh nonce) succeeds — the mint path resumed.
    let minted2 = run_rotation_mint(
        &af.harness,
        &af.drivers[1],
        &faucet,
        composition_advice([0u32; 8], &attester2),
    )
    .await
    .expect("S11a: after unpause the second attested mint must succeed");
    assert_eq!(
        minted2.output_notes().num_notes(),
        1,
        "S11a: one recipient note"
    );
    commit(&mut af.harness.mock_chain, &minted2)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        2 * MINT_REDUCED - BURN_OK,
        "S11a after the second mint",
    )?;
    // S11b: the burn note emitted during the pause is now consumable — the burn path resumed.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let consume = consume_committed_note(&af.harness.mock_chain, &faucet, paused_note.id())
        .await
        .expect("S11b: after unpause the paused-era burn note consumes");
    commit(&mut af.harness.mock_chain, &consume)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        2 * MINT_REDUCED - BURN_OK - BURN_PAUSED,
        "S11b after the resumed burn",
    )?;

    // ── S12 — ROTATION (CMP-F5): DOM_MANAGER grants a new pauser -> the new member can pause
    // (capability-proven against a REAL mint); revoke -> they cannot.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(13))
        .await
        .expect("S12: the DOM_MANAGER grant must succeed (delegated admin)");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([1u32, 0, 0, 0]),
        "S12: the new pauser's membership reads back"
    );
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(14))
        .await
        .expect("S12: the NEW pauser can pause");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let result = run_rotation_mint(
        &af.harness,
        &af.drivers[0],
        &faucet,
        composition_advice([0u32; 8], &attester1),
    )
    .await;
    assert_transaction_executor_error!(result, err_paused());
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(15))
        .await
        .expect("S12: the new pauser unpauses");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let tx = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(16))
        .await
        .expect("S12: the DOM_MANAGER revoke must succeed");
    commit(&mut af.harness.mock_chain, &tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([0u32, 0, 0, 0]),
        "S12: the revoked member's membership is cleared"
    );
    let result = consume_committed_note(&af.harness.mock_chain, &faucet, note_id(17)).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&faucet)?,
        Word::from([0u32, 0, 0, 0]),
        "S12: the revoked pause attempt left is_paused unchanged"
    );

    // ── S13 — FINAL LEDGER: the exact whole-arc equation + config read-backs on the ONE instance.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        2 * MINT_REDUCED - BURN_OK - BURN_PAUSED,
        "S13 final: 100 + 100 - 20 - 10 = 170",
    )?;
    assert_eq!(
        read_domain_config_words(&faucet)?,
        words,
        "S13: the domain config is byte-identical to its S1b init"
    );
    assert_eq!(
        read_token_config(&faucet)?[1],
        Felt::from(AssetAmount::new(NEW_MAX_SUPPLY)?),
        "S13: max_supply still the S3b value"
    );
    assert_eq!(
        read_min_burn_size(&faucet)?[0],
        Felt::from(AssetAmount::new(MIN_BURN)?),
        "S13: min_burn_size still the S3c value"
    );
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload1)
        )?,
        marker(),
        "S13: nonce 1 still marked"
    );
    assert_eq!(
        read_map_word(
            &faucet,
            USED_NONCES_SLOT_LABEL,
            nonce_key_of_payload(&payload2)
        )?,
        marker(),
        "S13: nonce 2 still marked"
    );
    assert_eq!(
        read_map_word(&faucet, XRESERVE_ATTESTERS_SLOT_LABEL, attester1.commitment)?,
        marker(),
        "S13: the attester allowlist marker survives the whole arc"
    );
    assert_eq!(
        read_role_config(&faucet, &pauser_sym)?,
        Word::new([
            Felt::from(1u32),
            Felt::from(&manager_sym),
            Felt::from(0u32),
            Felt::from(0u32)
        ]),
        "S13: the CMP-F5 delegation word survives the whole arc"
    );
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, pauser())?,
        marker(),
        "S13: the original DOM_PAUSER member is intact"
    );
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym, new_pauser())?,
        Word::from([0u32, 0, 0, 0]),
        "S13: the rotated-out member stays revoked"
    );
    Ok(())
}

// SECOND-RECIPIENT ROUTING — a second attested mint targets a DIFFERENT wallet
// ================================================================================================

/// Full-path RECIPIENT ROUTING: the lifecycle E2E's two mints target the SAME wallet (`payload2_for`
/// only XORs a nonce byte), so recipient-encoding variety existed only at the extraction-helper
/// level. Here ONE assembled instance mints twice — mint #1 to recipient1, mint #2 (distinct
/// nonce) whose `remoteRecipient` encodes a DIFFERENT wallet — and EACH wallet consumes ITS P2ID
/// note and holds exactly its minted amount: the intent's recipient bytes genuinely steer the
/// funds end-to-end, not just at the helper level.
#[tokio::test]
async fn second_mint_to_distinct_recipient() -> Result<()> {
    let (mut af, recipient2_id) =
        setup_assembled_faucet_two_recipients(MAX_SUPPLY, 0, |recipient1, recipient2| {
            let drivers = vec![
                mint_composition_driver_src(&pack(&payload_for(recipient1)), LEN_FELTS, SCALE_EXP),
                mint_composition_driver_src(&pack(&payload2_for(recipient2)), LEN_FELTS, SCALE_EXP),
            ];
            let commitment = gen_attester(1, &payload_for(recipient1)).commitment;
            let xrc = test_xreserve_contract();
            let identifier = identifier_word();
            let build = |what: &str, r: anyhow::Result<miden_protocol::note::Note>| {
                r.unwrap_or_else(|e| panic!("building the seeded {what} note: {e}"))
            };
            let notes = vec![
                // 0: owner domain_init (bring-up)
                build(
                    "init-owner",
                    domain_init_note(
                        owner(),
                        TEST_DOMAIN,
                        TEST_SOURCE_DOMAIN,
                        &xrc,
                        identifier,
                        930,
                    ),
                ),
                // 1: owner set_attester (bring-up)
                build(
                    "attester-owner",
                    set_attester_note(owner(), commitment, 1, 931),
                ),
            ];
            (drivers, notes)
        })?;
    let faucet_id = af.harness.account_id;
    let recipient1_id = af.recipient_id;
    let payload1 = payload_for(recipient1_id);
    let payload2 = payload2_for(recipient2_id);
    let attester1 = gen_attester(1, &payload1);
    let attester2 = gen_attester(1, &payload2);
    assert_eq!(
        attester1.commitment, attester2.commitment,
        "one deterministic attester key signs both payloads (single allowlist entry)"
    );

    // Bring-up: domain_init + set_attester (the production path).
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let init_tx = consume_committed_note(&af.harness.mock_chain, &faucet, af.seeded_notes[0].id())
        .await
        .expect("the owner's domain_init must succeed");
    commit(&mut af.harness.mock_chain, &init_tx)?;
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let att_tx = consume_committed_note(&af.harness.mock_chain, &faucet, af.seeded_notes[1].id())
        .await
        .expect("the owner's set_attester must succeed");
    commit(&mut af.harness.mock_chain, &att_tx)?;

    // Mint #1 → recipient1's P2ID note.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let mint1 = run_rotation_mint(
        &af.harness,
        &af.drivers[0],
        &faucet,
        composition_advice([0u32; 8], &attester1),
    )
    .await
    .expect("mint #1 (recipient1) must pass");
    assert_eq!(
        mint1.output_notes().num_notes(),
        1,
        "mint #1: exactly one recipient note"
    );
    let note1_id = mint1.output_notes().get_note(0).id();
    assert_eq!(
        mint1.output_notes().get_note(0).metadata().tag().as_u32(),
        expected_p2id_tag(recipient1_id),
        "mint #1's note targets recipient1"
    );
    commit(&mut af.harness.mock_chain, &mint1)?;

    // Mint #2 (distinct nonce) → the DIFFERENT wallet's P2ID note.
    let faucet = committed(&af.harness.mock_chain, faucet_id)?;
    let mint2 = run_rotation_mint(
        &af.harness,
        &af.drivers[1],
        &faucet,
        composition_advice([0u32; 8], &attester2),
    )
    .await
    .expect("mint #2 (the DISTINCT recipient2) must pass");
    assert_eq!(
        mint2.output_notes().num_notes(),
        1,
        "mint #2: exactly one recipient note"
    );
    let note2_id = mint2.output_notes().get_note(0).id();
    assert_eq!(
        mint2.output_notes().get_note(0).metadata().tag().as_u32(),
        expected_p2id_tag(recipient2_id),
        "mint #2's note targets the DISTINCT recipient2"
    );
    commit(&mut af.harness.mock_chain, &mint2)?;
    assert_supply(
        &af.harness.mock_chain,
        faucet_id,
        2 * MINT_REDUCED,
        "after both mints",
    )?;

    // Each recipient consumes ITS note; each holds exactly its own minted amount.
    let r1 = committed(&af.harness.mock_chain, recipient1_id)?;
    let c1 = consume_committed_note(&af.harness.mock_chain, &r1, note1_id)
        .await
        .expect("recipient1 consumes its P2ID note");
    commit(&mut af.harness.mock_chain, &c1)?;
    let r2 = committed(&af.harness.mock_chain, recipient2_id)?;
    let c2 = consume_committed_note(&af.harness.mock_chain, &r2, note2_id)
        .await
        .expect("recipient2 consumes ITS P2ID note");
    commit(&mut af.harness.mock_chain, &c2)?;
    assert_eq!(
        wallet_balance(
            &committed(&af.harness.mock_chain, recipient1_id)?,
            faucet_id
        ),
        MINT_REDUCED,
        "recipient1 holds exactly its minted amount"
    );
    assert_eq!(
        wallet_balance(
            &committed(&af.harness.mock_chain, recipient2_id)?,
            faucet_id
        ),
        MINT_REDUCED,
        "recipient2 holds exactly ITS minted amount — the intent's recipient bytes steer the funds"
    );
    Ok(())
}
