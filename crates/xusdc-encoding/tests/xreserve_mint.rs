//! 01 faucet `xreserve_mint` COMPOSITION suite (P5-01 Slice 2): drives the FAUCET(01)-owned
//! `xreserve::xreserve_mint::mint` entry through MockChain `execute().await` via a CALL-entered
//! driver on a `FungibleFaucet` account bound with ALL composition slots. `mint` chains the accepted
//! stages verify-once -> write-once: assert_deposit_intent (D5a) -> assert_mint_amounts (D5b) ->
//! assert_nonce_unused (D5c) -> verify_attestation (D5d) -> extract_recipient_account_id ->
//! apply_mint_effects (D5e). The happy path proves it mints exactly once (one P2ID note carrying the
//! reduced amount, nonce SET, token_supply += amount); each reject proves fail-closed (the exact
//! stage error + a readback probe showing no supply / nonce effect — and a trapped tx commits no
//! note).
//!
//! Fixtures are built BY REFERENCE from the canonical `di-pos-empty-hookdata` payload (its
//! `remoteRecipient` is already the valid `aid-rt-1` AccountId). amount/maxFee are spliced in BYTES
//! (so the keccak'd attestation payload stays consistent) and the attester signs the spliced bytes
//! in-test (`gen_attester`), exactly as the D5d suite does.
//!
//! RED-SUITE (executing-red): `xreserve_mint.masm` holds only the NAMED placeholder trap
//! ("red-suite placeholder: xreserve_mint::mint is not implemented"). Each behavior test asserts its
//! FINAL (green) expectation and is therefore RED here — the inputs are staged + reached, then the
//! terminal placeholder reverts the tx (happy: no effects; rejects: wrong error). The Slice-2 green
//! commit wires the chain and removes the trap. `probe_mint_composition_exports` is a declared green
//! scaffold (the placeholder makes the `mint` path resolve).

mod support;

use anyhow::Result;
use miden_protocol::account::{StorageMapKey, StorageSlotDelta, StorageSlotName};
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::note::P2idNote;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::vectors::{DiFields, DiVector, load, parse_hex32};
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

// The canonical accept payload every fixture starts from (240 bytes, empty hookData, 60 felts; its
// remoteRecipient is the valid aid-rt-1 AccountId).
const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const LEN_FELTS: u64 = 60;
const SCALE_EXP: u32 = 6;

// Valid mint amounts (uint256), reduced by scale_exp=6: amount 2_000_000 -> 2, maxFee 1_000_000 -> 1
// (amount >= maxFee). The base vector ships amount(1M) < maxFee(2M) — used as-is for the D5b reject.
const HAPPY_AMOUNT_RAW: u64 = 2_000_000;
const HAPPY_MAX_FEE_RAW: u64 = 1_000_000;
const REDUCED_AMOUNT: u32 = 2;

const MARKER: [u32; 4] = [1, 0, 0, 0];

fn di(id: &str) -> &'static DiVector {
    load()
        .families
        .di
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing di vector {id}"))
}

fn fields_of(id: &str) -> &'static DiFields {
    di(id).fields.as_ref().expect("accept vector carries fields")
}

/// The expected P2ID note tag for a vector's recipient: protocol `NoteTag::with_account_target`
/// (top 14 bits of the AccountId prefix's HIGH u32, masked with `0xfffc0000`). Computed from the
/// recipient bytes, mirroring `recipient_storage_of`.
fn expected_account_target_tag(id: &str) -> u32 {
    let rr = parse_hex32(&fields_of(id).remote_recipient_hex);
    let prefix = u64::from_be_bytes(rr[16..24].try_into().expect("8 bytes"));
    ((prefix >> 32) as u32) & 0xfffc0000
}

fn aid_bytes32(id: &str) -> [u8; 32] {
    let v = load()
        .families
        .aid
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing aid vector {id}"));
    parse_hex32(&v.bytes32)
}

/// The base payload bytes (recipient already valid aid-rt-1).
fn base_payload() -> Vec<u8> {
    di(BASE_VECTOR).bytes()
}

/// Splices `amount`/`maxFee` (uint256 BE) into a payload's byte image.
fn with_amounts(mut payload: Vec<u8>, amount: u64, max_fee: u64) -> Vec<u8> {
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee));
    payload
}

/// The fully-consistent happy payload: valid amount/maxFee, valid recipient (unchanged).
fn happy_payload() -> Vec<u8> {
    with_amounts(base_payload(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW)
}

fn pack(bytes: &[u8]) -> Vec<Felt> {
    bytes_to_packed_u32_elements(bytes)
}

/// TEST-ONLY config words for the base vector: domain word `[domain, 0, 0, 0]` and identifier =
/// canonical key-Word of the vector's remoteToken (the masm_mint_shell `config_for` idiom).
fn config_of(id: &str, domain: u32) -> (Word, Word) {
    let domain_word = Word::new([Felt::from(domain), ZERO, ZERO, ZERO]);
    let identifier =
        Word::from(bytes32_to_storage_map_key(&parse_hex32(&fields_of(id).remote_token_hex)));
    (domain_word, identifier)
}

fn config(domain: u32) -> (Word, Word) {
    config_of(BASE_VECTOR, domain)
}

/// The usedNonces map key for the base vector's nonce (04-owned Rust mirror, by reference; == the
/// MASM `bytes32_to_key(nonce)` by TV-DUAL-1).
fn nonce_key_of(id: &str) -> Word {
    Word::from(bytes32_to_storage_map_key(&fields_of(id).bytes32("nonce")))
}

fn nonce_key() -> Word {
    nonce_key_of(BASE_VECTOR)
}

/// The happy recipient's `[suffix, prefix]` felts (the P2ID note storage order apply_mint_effects
/// writes), derived from the base vector's remoteRecipient (aid-rt-1, R-B layout).
fn recipient_storage_of(id: &str) -> [Felt; 2] {
    let rr = parse_hex32(&fields_of(id).remote_recipient_hex);
    let prefix = u64::from_be_bytes(rr[16..24].try_into().expect("8 bytes"));
    let suffix = u64::from_be_bytes(rr[24..32].try_into().expect("8 bytes"));
    [Felt::try_from(suffix).expect("suffix < p"), Felt::try_from(prefix).expect("prefix < p")]
}

fn recipient_storage() -> [Felt; 2] {
    recipient_storage_of(BASE_VECTOR)
}

// EXPORT PROBE (declared green scaffold — D-1A path check for the composition entry)
// ================================================================================================

#[test]
fn probe_mint_composition_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::xreserve_mint::mint";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical composition proc path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// HAPPY PATH FIRST (G4) — one valid mint commits exactly the four effects
// ================================================================================================

#[tokio::test]
async fn happy_end_to_end_mints_once() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
    )?;
    let executed = run_mint_composition(&h, composition_advice([0u32; 8], &attester))
        .await
        .expect("a fully valid deposit intent + attestation must mint");

    // (1) exactly one P2ID recipient note carrying amount - feeAmount (== reduced amount at MVP).
    assert_eq!(executed.output_notes().num_notes(), 1, "exactly one recipient note");
    let note = executed.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note must carry a fungible asset");
    assert_eq!(Felt::from(asset.amount()), Felt::from(REDUCED_AMOUNT), "note asset == reduced amount");
    assert_eq!(asset.faucet_id(), h.account_id, "asset minted by this faucet");

    // (2) it is the intended P2ID note: nonce-derived serial, canonical script root + storage
    // [suffix, prefix], Public note type, and the faucet as sender.
    let recipient = note.recipient().expect("public output note must carry its recipient");
    assert_eq!(
        recipient.serial_num(),
        nonce_key(),
        "recipient note serial must be the nonce-derived KEY"
    );
    assert_eq!(
        recipient.script().root(),
        P2idNote::script_root(),
        "recipient note script root must be the canonical P2ID script root"
    );
    assert_eq!(
        recipient.storage().items(),
        recipient_storage().as_slice(),
        "recipient note storage must be [target_id_suffix, target_id_prefix]"
    );
    assert_eq!(
        note.metadata().tag().as_u32(),
        expected_account_target_tag(BASE_VECTOR),
        "P2ID note tag must target the recipient (NoteTag::with_account_target: prefix HIGH u32)"
    );
    assert_eq!(
        note.metadata().note_type(),
        miden_protocol::note::NoteType::Public,
        "recipient note must be Public"
    );
    assert_eq!(note.metadata().sender(), h.account_id, "note sender is the faucet");

    // (3) token_supply rose by exactly the reduced amount.
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        executed.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply delta == reduced amount");

    // (4) the nonce was marked: usedNonces[KEY] == MARKER.
    let used = StorageSlotName::new(USED_NONCES_SLOT_LABEL)?;
    let StorageSlotDelta::Map(map_delta) =
        executed.account_delta().storage().get(&used).expect("usedNonces slot delta")
    else {
        panic!("usedNonces must be a Map slot delta");
    };
    let written = map_delta
        .entries()
        .get(&StorageMapKey::new(nonce_key()))
        .copied()
        .expect("the nonce KEY must appear in the usedNonces delta");
    assert_eq!(written, Word::from(MARKER), "nonce marker committed");
    Ok(())
}

// FAIL-CLOSED REJECTS — one per stage; each pins the EXACT error AND proves no supply/nonce effect
// ================================================================================================
// A trapped tx commits nothing (so no recipient note); the readback probe additionally proves
// token_config + usedNonces are unchanged on the SAME account.

/// D5a (R-MINT-6): the configured domain does not match the intent's remoteDomain.
#[tokio::test]
async fn reject_wrong_domain_fails_closed() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (_correct, identifier) = config(TEST_DOMAIN);
    let (wrong_domain, _) = config(TEST_WRONG_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        wrong_domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_DOMAIN"));
    run_composition_probe(&h).await.expect("wrong-domain reject must leave token_config + usedNonces unchanged");
    Ok(())
}

/// D5b (R-MINT-10): reduced amount < maxFee. The base vector ships amount(1M) < maxFee(2M) as-is.
#[tokio::test]
async fn reject_amount_below_fee_fails_closed() -> Result<()> {
    let payload = base_payload(); // unspliced: amount 1_000_000 < maxFee 2_000_000
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_AMOUNT_BELOW_FEE"));
    run_composition_probe(&h).await.expect("amount-below-fee reject must leave token_config + usedNonces unchanged");
    Ok(())
}

/// D5c (R-MINT-12): the nonce was already used (seeded). No-effects here checks token_supply only —
/// the nonce slot is non-empty BY FIXTURE (the seed), not by an effect of this mint.
#[tokio::test]
async fn reject_nonce_replay_fails_closed() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        Some((nonce_key(), Word::from(MARKER))), // seed the nonce as already used
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_supply_probe_src(0),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_NONCE_REPLAY"));
    run_composition_probe(&h).await.expect("replay reject must leave token_supply unchanged");
    Ok(())
}

/// D5d (R-MINT-13): the candidate attester pubkey is not allowlisted (empty xReserveAttesters).
#[tokio::test]
async fn reject_attestation_not_allowlisted_fails_closed() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None, // nobody allowlisted -> the candidate pubkey's commitment is absent
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));
    run_composition_probe(&h).await.expect("non-allowlisted reject must leave token_config + usedNonces unchanged");
    Ok(())
}

/// Recipient extraction: the remoteRecipient's 16-byte pad is non-zero (aid-rej-out-of-range), so
/// extraction (after the verify stages) traps fail-closed. Amounts are spliced valid so D5a-D5d pass.
#[tokio::test]
async fn reject_bad_recipient_fails_closed() -> Result<()> {
    let mut payload = with_amounts(base_payload(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW);
    payload[REMOTE_RECIPIENT_BYTE_OFF..REMOTE_RECIPIENT_BYTE_OFF + 32]
        .copy_from_slice(&aid_bytes32("aid-rej-out-of-range"));
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE"));
    run_composition_probe(&h).await.expect("bad-recipient reject must leave token_config + usedNonces unchanged");
    Ok(())
}

/// D5e (R-MINT-15): token_supply + amount exceeds max_supply. All verify stages + extraction pass;
/// the supply guard (first effect) traps before any write.
#[tokio::test]
async fn reject_supply_cap_fails_closed() -> Result<()> {
    let payload = happy_payload(); // reduced amount == 2
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1, // max_supply == 1, so 0 + 2 > 1
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    let result = run_mint_composition(&h, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_SUPPLY_CAP"));
    run_composition_probe(&h).await.expect("supply-cap reject must leave token_config + usedNonces unchanged");
    Ok(())
}

// ADDED ROWS (Codex red-suite re-audit) — forged sig, hookData happy, fee-over-max
// ================================================================================================

/// D5d (R-MINT-14): an allowlisted attester's pubkey paired with a FOREIGN valid signature (key B's,
/// over the same payload) must fail closed. The single materialized pubkey region feeds BOTH the
/// allowlist commitment and `verify_prehash`, so an allowlisted commitment cannot be paired with
/// another key's signature. (Mirrors the standalone D5d forged-sig seam test.)
#[tokio::test]
async fn reject_forged_signature_fails_closed() -> Result<()> {
    let payload = happy_payload();
    let a = gen_attester(1, &payload);
    let b = gen_attester(2, &payload);
    assert_ne!(a.commitment, b.commitment, "seam keys A and B must have distinct commitments");
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((a.commitment, Word::from(MARKER))), // allowlist A
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    // A's pubkey (allowlisted) + B's foreign-but-valid signature -> verify_prehash returns 0.
    let advice: Vec<Felt> = fee_advice_felts([0u32; 8])
        .into_iter()
        .chain(a.pubkey_felts.iter().copied())
        .chain(b.sig_felts.iter().copied())
        .collect();
    let result = run_mint_composition(&h, advice).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_SIG_INVALID"));
    run_composition_probe(&h).await.expect("forged-sig reject must leave token_config + usedNonces unchanged");
    Ok(())
}

/// Happy path over a NON-empty-hookData vector (`di-pos-hookdata`, 250 bytes = 240 + hookData 10).
/// The attester signs the EXACT spliced 250-byte payload, so the later green implementation must
/// keccak exactly `240 + hook_data_len` bytes — not a hardcoded 240, nor a padded `len_felts * 4`
/// (= 252). Same successful effects as the empty-hookData happy path.
#[tokio::test]
async fn happy_end_to_end_with_hookdata() -> Result<()> {
    let v = di("di-pos-hookdata");
    let payload = with_amounts(v.bytes(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW);
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config_of("di-pos-hookdata", TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), v.len_felts, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key_of("di-pos-hookdata"));
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
    )?;
    let executed = run_mint_composition(&h, composition_advice([0u32; 8], &attester))
        .await
        .expect("a valid hookData deposit intent + attestation must mint");

    assert_eq!(executed.output_notes().num_notes(), 1, "exactly one recipient note");
    let note = executed.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note must carry a fungible asset");
    assert_eq!(Felt::from(asset.amount()), Felt::from(REDUCED_AMOUNT), "note asset == reduced amount");
    assert_eq!(asset.faucet_id(), h.account_id, "asset minted by this faucet");
    let recipient = note.recipient().expect("public output note must carry its recipient");
    assert_eq!(
        recipient.serial_num(),
        nonce_key_of("di-pos-hookdata"),
        "recipient note serial must be the nonce-derived KEY"
    );
    assert_eq!(
        recipient.script().root(),
        P2idNote::script_root(),
        "recipient note script root must be the canonical P2ID script root"
    );
    assert_eq!(
        recipient.storage().items(),
        recipient_storage_of("di-pos-hookdata").as_slice(),
        "recipient note storage must be [target_id_suffix, target_id_prefix]"
    );
    assert_eq!(
        note.metadata().tag().as_u32(),
        expected_account_target_tag("di-pos-hookdata"),
        "P2ID note tag must target the recipient (NoteTag::with_account_target: prefix HIGH u32)"
    );
    assert_eq!(
        note.metadata().note_type(),
        miden_protocol::note::NoteType::Public,
        "recipient note must be Public"
    );
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        executed.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply delta == reduced amount");
    let used = StorageSlotName::new(USED_NONCES_SLOT_LABEL)?;
    let StorageSlotDelta::Map(map_delta) =
        executed.account_delta().storage().get(&used).expect("usedNonces slot delta")
    else {
        panic!("usedNonces must be a Map slot delta");
    };
    let written = map_delta
        .entries()
        .get(&StorageMapKey::new(nonce_key_of("di-pos-hookdata")))
        .copied()
        .expect("the nonce KEY must appear in the usedNonces delta");
    assert_eq!(written, Word::from(MARKER), "nonce marker committed");
    Ok(())
}

/// D5b (R-MINT-11): a valid intent (reduced amount >= maxFee) but an operator `feeAmount` that
/// reduces ABOVE maxFee must fail closed — proving the composition wires AND orders the feeAmount
/// advice (consumed by D5b, before the D5d pubkey/signature). The fee felts use the SAME u32-LE
/// packing as the payload uint256 fields.
#[tokio::test]
async fn reject_fee_over_max_fails_closed() -> Result<()> {
    let payload = happy_payload(); // reduced amount 2 >= maxFee 1
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let h = setup_mint_composition_account(
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &composition_noeffect_probe_src(0, nonce_key()),
    )?;
    // feeAmount reduces to 2 (> maxFee 1); packed exactly like a uint256 payload field.
    let fee = bytes_to_packed_u32_elements(&uint256_be(HAPPY_AMOUNT_RAW));
    let advice: Vec<Felt> = fee.into_iter().chain(attester.advice()).collect();
    let result = run_mint_composition(&h, advice).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_FEE_OVER_MAX"));
    run_composition_probe(&h).await.expect("fee-over-max reject must leave token_config + usedNonces unchanged");
    Ok(())
}
