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

/// First byte of the 32-byte `nonce` field within the DepositIntent header (`NONCE_FELT_OFF` * 4
/// bytes/felt; `asm/standards/xreserve/encoding/layout.masm:24`).
const NONCE_BYTE_OFF: usize = 51 * 4;

/// Distinct-nonce variant of a payload: perturbs the nonce field so the rotation can mint several
/// payloads on one evolving account without a D5c replay collision (each successful mint consumes its
/// nonce). XOR with a distinct non-zero byte yields nonces distinct from the base and from each other.
fn with_nonce(mut payload: Vec<u8>, perturbation: u8) -> Vec<u8> {
    payload[NONCE_BYTE_OFF] ^= perturbation;
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

// R-MINT-16 NO-REGRESSION — the deny guard does not touch the custom xreserve_mint path
// ================================================================================================

/// The custom `xreserve_mint` mints exactly as `happy_end_to_end_mints_once` does even when the
/// faucet carries the mint-deny guard as its active mint policy (composed via
/// `XReserveStablecoinBuilder`, deny oracle). `xreserve_mint` calls kernel `faucet::mint` directly
/// and bypasses the `policy_manager`, so the deny guard (which gates only the stock `mint_and_send`)
/// is irrelevant to it — all four happy effects must still hold. GREEN at the gate AND after Step 2
/// (the guard never sits on this path). The structural sibling of the mint_deny deny tests: deny the
/// stock surface, keep the custom surface fully working.
#[tokio::test]
async fn xreserve_mint_still_mints_on_guarded_account() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::OracleDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        false,
    )?;
    let executed = run_mint_composition(&gm.harness, composition_advice([0u32; 8], &attester))
        .await
        .expect("a fully valid deposit intent + attestation must mint even on a deny-guarded faucet");

    // (1) exactly one P2ID recipient note carrying amount - feeAmount (== reduced amount at MVP).
    assert_eq!(executed.output_notes().num_notes(), 1, "exactly one recipient note");
    let note = executed.output_notes().get_note(0);
    let asset = note
        .assets()
        .iter_fungible()
        .next()
        .expect("the recipient note must carry a fungible asset");
    assert_eq!(Felt::from(asset.amount()), Felt::from(REDUCED_AMOUNT), "note asset == reduced amount");
    assert_eq!(asset.faucet_id(), gm.harness.account_id, "asset minted by this faucet");

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
    assert_eq!(note.metadata().sender(), gm.harness.account_id, "note sender is the faucet");

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

// set_attester -> verify SEAM (P5-01) — the load-bearing non-vacuity proof
// ================================================================================================
// The setter trusts the caller's commitment Word verbatim (§5.5), so a storage-delta check is
// vacuous. Only an end-to-end attestation proves the key set_attester WROTE equals the key the D5d
// read path COMPUTES. These run on the RBAC-equipped production faucet (admin_holder = id(2)) with an
// EMPTY allowlist, then drive a real set_attester note tx (tx1) and a real mint tx (tx2) on the
// evolved account. The 5-step rotation (below) uses distinct-nonce payloads (`with_nonce`); the
// pause gate needs no mint and lives in `set_attester.rs`.

/// Positive seam (add enables) + negative-before control: an empty allowlist denies K's attestation
/// (R-MINT-13); after the ATTEST_ADMIN holder runs `set_attester(K, true)`, the SAME attestation
/// mints. Proves set's written key == the read path's computed key.
#[tokio::test]
async fn set_attester_enables_attestation() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None, // EMPTY allowlist — set_attester is the only way K gets admitted
        &driver,
        &probe,
        false,
    )?;
    let account = faucet_account(&gm.harness);

    // negative-before: K is not allowlisted -> the D5d read traps R-MINT-13 (the "before" anchor).
    let before = run_mint_against(&gm.harness, &account, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(before, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));

    // tx1: the ATTEST_ADMIN holder (id(2)) allowlists K.
    let set = run_set_attester_tx(&gm.harness, &account, test_account_id(2), attester.commitment, 1, 7)
        .await
        .expect("the ATTEST_ADMIN holder's set_attester(K, true) must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // positive seam: the SAME K-attestation now PASSES the gate and mints.
    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("set_attester(K, true) must enable K's attestation to mint (seam closes)");
    assert_eq!(minted.output_notes().num_notes(), 1, "exactly one recipient note");
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        minted.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply rose by the reduced amount");
    Ok(())
}

/// Negative-after (remove denies): after the holder enables then `set_attester(K, false)` removes K,
/// the SAME attestation traps R-MINT-13 — proving the removal write (EMPTY_WORD) genuinely closes the
/// seam (forbidden #6: a remove that writes a still-non-empty value would keep K verifying).
#[tokio::test]
async fn set_attester_remove_denies_attestation() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        false,
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: enable K.
    let enable = run_set_attester_tx(&gm.harness, &account, test_account_id(2), attester.commitment, 1, 7)
        .await
        .expect("enable must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(enable.account_delta())?;

    // tx2: remove K (enabled = 0 -> EMPTY_WORD).
    let remove = run_set_attester_tx(&gm.harness, &evolved, test_account_id(2), attester.commitment, 0, 9)
        .await
        .expect("remove must succeed");
    evolved.apply_delta(remove.account_delta())?;

    // the SAME K-attestation now traps R-MINT-13 (K is no longer allowlisted).
    let denied = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(denied, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));
    Ok(())
}

/// 5-step add-then-retire rotation (§4.K) on ONE evolving account, each step proven via the seam:
/// (1) enable K_old -> K_old mints; (2) enable K_new -> K_new mints; (3) disable K_old; (4) K_old
/// traps R-MINT-13; (5) K_new still mints. Three distinct-nonce payloads — each successful mint
/// (steps 1, 2, 5) consumes its nonce; the denied K_old attempt (step 4) traps at D5d BEFORE the
/// nonce SET, so it shares payload_c's nonce with step 5. K_old (seed 1) / K_new (seed 2) keep their
/// commitments across payloads; only the signature changes per payload.
#[tokio::test]
async fn set_attester_add_then_retire_rotation() -> Result<()> {
    let payload_a = with_nonce(happy_payload(), 1);
    let payload_b = with_nonce(happy_payload(), 2);
    let payload_c = with_nonce(happy_payload(), 3);
    let old_a = gen_attester(1, &payload_a); // K_old over payload_a
    let new_b = gen_attester(2, &payload_b); // K_new over payload_b
    let old_c = gen_attester(1, &payload_c); // K_old over payload_c (same commitment as old_a)
    let new_c = gen_attester(2, &payload_c); // K_new over payload_c (same commitment as new_b)
    assert_ne!(old_a.commitment, new_b.commitment, "K_old and K_new must be distinct keys");

    let (domain, identifier) = config(TEST_DOMAIN);
    // One driver per distinct-nonce payload (each successful mint consumes its nonce; the mint must
    // run as an installed account procedure, so one driver per payload).
    let driver_a = mint_composition_driver_src(&pack(&payload_a), LEN_FELTS, SCALE_EXP);
    let driver_b = mint_composition_driver_src(&pack(&payload_b), LEN_FELTS, SCALE_EXP);
    let driver_c = mint_composition_driver_src(&pack(&payload_c), LEN_FELTS, SCALE_EXP);
    let rh = setup_rotation_account(domain, identifier, &[&driver_a, &driver_b, &driver_c])?;
    let h = &rh.harness;
    let holder = test_account_id(2);
    let mut acct = faucet_account(h);

    // 1. enable K_old -> K_old mints (driver_a / payload_a, nonce_a).
    let s1 = run_set_attester_tx(h, &acct, holder, old_a.commitment, 1, 11).await.expect("enable K_old");
    acct.apply_delta(s1.account_delta())?;
    let m1 = run_rotation_mint(h, &rh.drivers[0], &acct, composition_advice([0u32; 8], &old_a))
        .await
        .expect("K_old mints once enabled");
    assert_eq!(m1.output_notes().num_notes(), 1, "step 1: K_old mints");
    acct.apply_delta(m1.account_delta())?;

    // 2. enable K_new -> K_new mints (driver_b / payload_b, nonce_b).
    let s2 = run_set_attester_tx(h, &acct, holder, new_b.commitment, 1, 12).await.expect("enable K_new");
    acct.apply_delta(s2.account_delta())?;
    let m2 = run_rotation_mint(h, &rh.drivers[1], &acct, composition_advice([0u32; 8], &new_b))
        .await
        .expect("K_new mints once enabled");
    assert_eq!(m2.output_notes().num_notes(), 1, "step 2: K_new mints");
    acct.apply_delta(m2.account_delta())?;

    // 3. disable K_old.
    let s3 = run_set_attester_tx(h, &acct, holder, old_a.commitment, 0, 13).await.expect("disable K_old");
    acct.apply_delta(s3.account_delta())?;

    // 4. K_old now traps R-MINT-13 (driver_c / payload_c; traps at D5d, so nonce_c is NOT consumed).
    let m4 = run_rotation_mint(h, &rh.drivers[2], &acct, composition_advice([0u32; 8], &old_c)).await;
    assert_transaction_executor_error!(m4, shell_error_by_name("ERR_XRESERVE_BAD_PK_COMMITMENT"));

    // 5. K_new still mints (driver_c / payload_c, nonce_c still fresh).
    let m5 = run_rotation_mint(h, &rh.drivers[2], &acct, composition_advice([0u32; 8], &new_c))
        .await
        .expect("K_new still mints after K_old is retired");
    assert_eq!(m5.output_notes().num_notes(), 1, "step 5: K_new still mints");
    Ok(())
}

// set_max_supply -> R-MINT-15 cap-enforcement SEAM (P5-01) — the load-bearing non-vacuity proof
// ================================================================================================
// A token_config[max_supply] storage-delta is vacuous; only a real mint proves set_max_supply changed
// what R-MINT-15 enforces (R-MINT-15 reads max_supply from the SAME token_config word set_max_supply
// writes). These run on the RBAC-equipped production faucet (admin_holder = id(2)) with K allowlisted,
// then drive a real set_max_supply note tx (tx1) and a real mint tx (tx2) on the apply_delta-evolved
// account. RED-suite: built IMMUTABLE (is_max_supply_mutable = false), so tx1's set_max_supply traps
// ERR_MAX_SUPPLY_NOT_MUTABLE and the seam can't close (red-for-the-right-reason); GREEN flips to `true`.

/// Lower-then-reject: start at cap 1_000_000 (a 2-unit mint is fine). The ATTEST_ADMIN holder lowers
/// the cap to 1; the SAME valid mint (amount 2) now exceeds it -> R-MINT-15 traps the EXACT
/// ERR_XRESERVE_SUPPLY_CAP. Lowering tightened what the mint enforces (forbidden #2). RED: tx1 traps
/// immutable.
#[tokio::test]
async fn set_max_supply_lower_then_over_cap_rejects() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))), // allowlist K so the mint passes D5d
        &driver,
        &probe,
        false, // RED: immutable -> set_max_supply traps; GREEN flips to true
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: the holder lowers the cap to 1 (below the 2-unit mint).
    let set = run_set_max_supply_tx(&gm.harness, &account, test_account_id(2), 1, 7)
        .await
        .expect("the ATTEST_ADMIN holder's set_max_supply(1) must succeed on a mutable faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: the SAME valid mint (amount 2) now exceeds the lowered cap -> R-MINT-15 traps.
    let over_cap =
        run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(over_cap, shell_error_by_name("ERR_XRESERVE_SUPPLY_CAP"));
    Ok(())
}

/// At-cap accepts (the positive boundary): the holder sets the cap exactly at the mint amount (2); the
/// 2-unit mint then fits (0 + 2 <= 2) and mints once, raising token_supply by the reduced amount. RED:
/// tx1 traps immutable.
#[tokio::test]
async fn set_max_supply_at_cap_accepts() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        false,
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: the holder sets the cap exactly at the mint amount (2).
    let set = run_set_max_supply_tx(&gm.harness, &account, test_account_id(2), 2, 7)
        .await
        .expect("the ATTEST_ADMIN holder's set_max_supply(2) must succeed on a mutable faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: the mint (amount 2) is exactly at the new cap -> mints once, token_supply -> 2.
    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("a mint exactly at the new cap must succeed");
    assert_eq!(minted.output_notes().num_notes(), 1, "exactly one recipient note");
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        minted.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply rose by the reduced amount");
    Ok(())
}

/// Raise-then-accept (with a negative-before control): start at cap 1, where the 2-unit mint traps
/// R-MINT-15 (in apply_mint_effects, BEFORE the nonce SET -> the nonce is NOT consumed). The holder
/// raises the cap to 1_000_000; the SAME mint now fits and mints (nonce still fresh). Proves the accept
/// is CAUSED by the raise (forbidden #2, the other direction). RED: tx1 traps immutable.
#[tokio::test]
async fn set_max_supply_raise_then_accepts() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let (domain, identifier) = config(TEST_DOMAIN);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1, // cap starts at 1 (below the 2-unit mint)
        0,
        domain,
        identifier,
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        false,
    )?;
    let account = faucet_account(&gm.harness);

    // negative-before: the cap is 1, so the 2-unit mint traps R-MINT-15 BEFORE the nonce SET (the nonce
    // is NOT consumed). The "before" anchor.
    let before =
        run_mint_against(&gm.harness, &account, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(before, shell_error_by_name("ERR_XRESERVE_SUPPLY_CAP"));

    // tx1: the holder raises the cap well above the mint.
    let set = run_set_max_supply_tx(&gm.harness, &account, test_account_id(2), 1_000_000, 7)
        .await
        .expect("the ATTEST_ADMIN holder's set_max_supply(1_000_000) must succeed on a mutable faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: the SAME mint now fits under the raised cap and mints (nonce still fresh).
    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("after raising the cap, the same mint must succeed");
    assert_eq!(minted.output_notes().num_notes(), 1, "exactly one recipient note");
    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) =
        minted.account_delta().storage().get(&cfg_slot).expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(cfg[0], Felt::from(REDUCED_AMOUNT), "token_supply rose by the reduced amount");
    Ok(())
}
