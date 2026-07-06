//! P5-01 `domain_init` (R-ADMIN-4) suite — RE-CALIBRATED to the §5.9 FOUR-FIELD closure (the
//! full-assembly slice): the OWNER-gated, init-once setter now writes ALL FOUR frozen CMP-A6 fields
//! (`domain:u32`, `source_domain:u32`, `xreserve_contract:bytes32` as two raw 8×u32-LE packed
//! words, `identifier:bytes32` as the pre-hashed key-Word — D-A6-XRC). This file proves: 4-field
//! write integrity (full read-back of all FIVE slot words + the fail-closed bytes32 round-trip),
//! init-once (a second write traps the EXACT ERR_XRESERVE_DOMAIN_REINIT and leaves every field
//! unchanged), the on-chain scalar/limb u32 guards (§5.9 types the scalars u32; malformed values
//! staged as RAW felts trap their EXACT error and write NOTHING), owner-SPECIFIC auth, the D5a
//! CONSUMPTION SEAM re-proven byte-identical through the 4-field init, and the sole-writer static
//! sweep (only `domain_init` writes the five domain-config slots).
//!
//! RED-SUITE (executing-red, full-assembly slice): the SHIPPED `domain_config.masm` writes only
//! `domain` + `identifier` from the OLD `[IDENTIFIER, domain, pad(11)]` stack. Driven with the NEW
//! 14-arg stack it still executes (the extra args are plain stack data): the identifier lands
//! correctly (top word), but "domain" reads the first XRC_HI limb — so the 4-field read-backs, the
//! matching-domain seam, and the guard/no-write tests all fail BEHAVIORALLY (real MockChain
//! execution, wrong state), while the sentinel/owner-gate mechanics (unchanged code) stay
//! green-on-arrival. Per-test red/green-on-arrival status is marked `RED:` / `GREEN-ON-ARRIVAL:` in
//! each doc comment (the CMP-B3 precedent).

mod support;

use std::path::PathBuf;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_processor::ExecutionError;
use miden_processor::operation::OperationError;
use miden_testing::assert_transaction_executor_error;
use rstest::rstest;
use support::*;
use xusdc_encoding::vectors::{DiFields, DiVector, load, parse_hex32};
use xusdc_encoding::xreserve::encoding::{
    bytes32_to_packed_felts, bytes32_to_storage_map_key, packed_felts_to_bytes32,
};

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3)
// (support::setup_guarded_mint_account -> XReserveStablecoinBuilder::new(.., id(1), id(2), id(3))).
// The owner-SPECIFIC auth proof needs distinct senders: the owner, a role holder (NOT owner), and a
// stranger (neither).
fn owner() -> AccountId {
    test_account_id(1)
}
fn role_holder_not_owner() -> AccountId {
    test_account_id(2)
}
fn non_owner() -> AccountId {
    test_account_id(99)
}

/// An empty value-slot word — the uninitialized domain-config the production faucet ships with
/// before `domain_init` writes it.
fn empty_word() -> Word {
    Word::from([0u32, 0, 0, 0])
}

/// A simple non-seam identifier for the pure-setter tests — any non-empty Word works; the seam
/// tests use the canonical remoteToken key instead.
fn dummy_identifier() -> Word {
    Word::from([11u32, 12, 13, 14])
}

/// Test `source_domain` (Circle-owned VALUE stays OPEN — Ethereum source domains start at 0 per
/// C-DOMAIN-1; this NONZERO fixture value keeps the read-back distinguishable from an unwritten
/// `[0,0,0,0]` slot, which a legitimate source_domain=0 would alias).
const TEST_SOURCE_DOMAIN: u32 = 3;

/// Test `xreserve_contract` bytes32 (Circle's real address is OPEN/parameterized): sequential
/// distinct bytes 0x10..0x2F, so all 8 packed limbs are distinct and nonzero — a hi/lo word swap or
/// a limb permutation changes the read-back.
fn test_xreserve_contract() -> [u8; 32] {
    core::array::from_fn(|i| 0x10 + i as u8)
}

/// The expected `[hi, lo]` slot words for a bytes32 under the D-A6-XRC raw 8×u32-LE realization
/// (04 codec BY REFERENCE: hi = packed felts[0..4] / wire bytes 0..16, lo = felts[4..8]).
fn expected_xrc_words(b: &[u8; 32]) -> (Word, Word) {
    let felts = bytes32_to_packed_felts(b);
    (
        Word::new([felts[0], felts[1], felts[2], felts[3]]),
        Word::new([felts[4], felts[5], felts[6], felts[7]]),
    )
}

/// A trivial driver/probe pair for the pure-setter tests (no mint is run; domain_init goes via a note).
fn trivial_driver_probe() -> (String, String) {
    (mint_composition_driver_src(&[Felt::from(0u32)], 60, 6), composition_supply_probe_src(0))
}

/// A guarded production faucet (Ownable2Step owner = id(1); DOM roles seeded) whose FIVE
/// domain-config slots are declared EMPTY — so `domain_init` is the writer and the init-once
/// sentinel reads EMPTY pre-init. `attesters_seed`/`nonce_seed` default empty for the pure-setter
/// tests.
fn uninit_faucet() -> Result<GuardedMint> {
    let (driver, probe) = trivial_driver_probe();
    setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        empty_word(),
        empty_word(),
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// Runs the canonical 4-field owner init against `account` and returns the executed tx.
async fn init_four_fields(
    gm: &GuardedMint,
    account: &miden_protocol::account::Account,
    sender: AccountId,
    domain: u32,
    identifier: Word,
    seed: u64,
) -> std::result::Result<
    miden_protocol::transaction::ExecutedTransaction,
    miden_tx::TransactionExecutorError,
> {
    run_domain_init_tx(
        &gm.harness,
        account,
        sender,
        domain,
        TEST_SOURCE_DOMAIN,
        &test_xreserve_contract(),
        identifier,
        seed,
    )
    .await
}

// SEAM FIXTURES (reconstructed from the canonical accept payload — mirrors xreserve_mint.rs)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const LEN_FELTS: u64 = 60;
const SCALE_EXP: u32 = 6;
const HAPPY_AMOUNT_RAW: u64 = 2_000_000;
const HAPPY_MAX_FEE_RAW: u64 = 1_000_000;
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

fn base_payload() -> Vec<u8> {
    di(BASE_VECTOR).bytes()
}

/// Splices `amount`/`maxFee` (uint256 BE) into a payload's byte image (so the keccak'd attestation
/// payload stays consistent with what the attester signs).
fn with_amounts(mut payload: Vec<u8>, amount: u64, max_fee: u64) -> Vec<u8> {
    payload[AMOUNT_BYTE_OFF..AMOUNT_BYTE_OFF + 32].copy_from_slice(&uint256_be(amount));
    payload[MAX_FEE_BYTE_OFF..MAX_FEE_BYTE_OFF + 32].copy_from_slice(&uint256_be(max_fee));
    payload
}

fn happy_payload() -> Vec<u8> {
    with_amounts(base_payload(), HAPPY_AMOUNT_RAW, HAPPY_MAX_FEE_RAW)
}

fn pack(bytes: &[u8]) -> Vec<Felt> {
    miden_protocol::utils::bytes_to_packed_u32_elements(bytes)
}

/// The configured identifier = the canonical key-Word of the vector's remoteToken (== what D5a's
/// `assert_eqw` compares against; the `config_of` idiom). This is what `domain_init` must store for the
/// matching mint to pass the identifier compare.
fn identifier_of(id: &str) -> Word {
    Word::from(bytes32_to_storage_map_key(&parse_hex32(&fields_of(id).remote_token_hex)))
}

fn nonce_key() -> Word {
    Word::from(bytes32_to_storage_map_key(&fields_of(BASE_VECTOR).bytes32("nonce")))
}

// EXPORT PROBE (declared green scaffold — D-1A flat-path check for the setter)
// ================================================================================================

/// GREEN-ON-ARRIVAL: the flat canonical path resolves already (the shipped 2-field proc).
#[test]
fn probe_domain_config_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .exports()
        .filter(|e| e.as_procedure().is_some())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::domain_config::domain_init";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// 4-FIELD WRITE INTEGRITY — the owner's domain_init configures ALL FIVE slots, full read-back
// ================================================================================================

/// The owner's 4-field `domain_init` succeeds and writes ALL FIVE config slots exactly: domain ==
/// [D,0,0,0] (D5a reads element 0), source_domain == [SD,0,0,0], xreserve_contract hi/lo == the
/// packed 8×u32-LE halves (04 codec by reference), identifier == I (full Word, verbatim). RED: the
/// shipped 2-field proc leaves source_domain/xrc empty and writes the wrong "domain".
#[tokio::test]
async fn domain_init_succeeds_and_configures() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("the owner's 4-field domain_init must succeed");

    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;

    let [domain_w, source_domain_w, xrc_hi_w, xrc_lo_w, identifier_w] =
        read_domain_config_words(&evolved)?;
    let (exp_hi, exp_lo) = expected_xrc_words(&test_xreserve_contract());
    assert_eq!(
        domain_w,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        "domain slot must be [domain, 0, 0, 0] (D5a reads element 0)"
    );
    assert_eq!(
        source_domain_w,
        Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
        "source_domain slot must be [source_domain, 0, 0, 0]"
    );
    assert_eq!(xrc_hi_w, exp_hi, "xreserve_contract_hi must be packed felts[0..4]");
    assert_eq!(xrc_lo_w, exp_lo, "xreserve_contract_lo must be packed felts[4..8]");
    assert_eq!(identifier_w, identifier, "identifier slot must be the supplied Word verbatim");
    Ok(())
}

/// Per-field read-back family (the task-named `domain_init_writes_all_four_fields`): after ONE
/// 4-field init, EACH field reads back exactly; the bytes32 additionally round-trips through the
/// FAIL-CLOSED inverse (`packed_felts_to_bytes32`, D-A6-XRC guard 1) back to the input bytes. RED:
/// every case but `identifier` fails against the shipped 2-field proc.
#[rstest]
#[case::domain(0)]
#[case::source_domain(1)]
#[case::xreserve_contract_hi(2)]
#[case::xreserve_contract_lo(3)]
#[case::identifier(4)]
#[case::xreserve_contract_roundtrip(5)]
#[tokio::test]
async fn domain_init_writes_all_four_fields(#[case] field: usize) -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();
    let xrc = test_xreserve_contract();

    let executed = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("the owner's 4-field domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    let (exp_hi, exp_lo) = expected_xrc_words(&xrc);

    match field {
        0 => assert_eq!(words[0], Word::from([TEST_DOMAIN, 0, 0, 0]), "domain"),
        1 => assert_eq!(words[1], Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]), "source_domain"),
        2 => assert_eq!(words[2], exp_hi, "xreserve_contract_hi"),
        3 => assert_eq!(words[3], exp_lo, "xreserve_contract_lo"),
        4 => assert_eq!(words[4], identifier, "identifier"),
        5 => {
            // The lossless read-back: reconstruct the stored bytes32 via the FAIL-CLOSED inverse
            // (a >u32 stored limb would error, never truncate) and compare with the input.
            let stored: [Felt; 8] = [
                words[2][0], words[2][1], words[2][2], words[2][3], words[3][0], words[3][1],
                words[3][2], words[3][3],
            ];
            let recovered = packed_felts_to_bytes32(&stored)
                .expect("stored xreserve_contract limbs must be valid u32s (fail-closed inverse)");
            assert_eq!(recovered, xrc, "GetAccount-readable bytes32 round-trip");
        },
        _ => unreachable!(),
    }
    Ok(())
}

// INIT-ONCE (R-ADMIN-4) — a second write traps the EXACT ERR_XRESERVE_DOMAIN_REINIT
// ================================================================================================

/// First 4-field `domain_init` succeeds; a SECOND traps the EXACT ERR_XRESERVE_DOMAIN_REINIT (the
/// init-once sentinel reads the now-non-empty identifier slot — ONE sentinel guarding the atomic
/// 4-field write, D-A6-XRC guard 3). GREEN-ON-ARRIVAL mechanics (the sentinel code is unchanged and
/// the identifier still lands in the top word), re-calibrated to the 4-field signature.
#[tokio::test]
async fn domain_init_reinit_traps() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let first = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("first domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(first.account_delta())?;

    let result = init_four_fields(&gm, &evolved, owner(), TEST_DOMAIN, identifier, 2).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

/// After the re-init trap, ALL FIVE config words are unchanged — per-field immutability under
/// R-ADMIN-4 (no setter exists for any field; the sentinel + the sole-writer sweep close the rest).
/// RED: the first init writes the wrong domain / nothing into the new slots, so the "unchanged"
/// baseline itself is wrong against the shipped proc.
#[tokio::test]
async fn domain_init_reinit_leaves_all_fields_unchanged() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let first = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("first domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(first.account_delta())?;
    let before = read_domain_config_words(&evolved)?;
    let (exp_hi, exp_lo) = expected_xrc_words(&test_xreserve_contract());
    assert_eq!(
        before,
        [
            Word::from([TEST_DOMAIN, 0, 0, 0]),
            Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
            exp_hi,
            exp_lo,
            identifier,
        ],
        "the first init must have written all four fields"
    );

    // A second init with DIFFERENT values traps and leaves every word untouched.
    let result = run_domain_init_tx(
        &gm.harness,
        &evolved,
        owner(),
        TEST_WRONG_DOMAIN,
        TEST_SOURCE_DOMAIN + 1,
        &[0xEEu8; 32],
        Word::from([91u32, 92, 93, 94]),
        2,
    )
    .await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    assert_eq!(
        read_domain_config_words(&evolved)?,
        before,
        "a trapped re-init must leave all five domain-config words unchanged"
    );
    Ok(())
}

/// R-ADMIN-4 hardening (Item 4, tests-first): `domain_init` with `identifier = EMPTY_WORD` traps
/// the EXACT ERR_XRESERVE_IDENTIFIER_EMPTY and writes NOTHING. The identifier IS the init-once
/// sentinel — an EMPTY identifier would never arm it (the "immutable" config stays silently
/// re-initializable, R-ADMIN-4 broken for that deploy) AND D5a would compare every intent's
/// identifier against EMPTY. Until now this was an unenforced doc-only assumption
/// ("non-empty by construction"); the guard enforces it on-chain. RED: the shipped proc has no
/// empty-identifier guard, so this init SUCCEEDS.
#[tokio::test]
async fn domain_init_empty_identifier_traps() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);

    let result = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, empty_word(), 1).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_IDENTIFIER_EMPTY")
    );

    // No-write proof: a trapped tx commits nothing; every domain-config slot stays empty.
    assert_eq!(
        read_domain_config_words(&account)?,
        [empty_word(); 5],
        "a trapped empty-identifier init must leave every domain-config slot unwritten"
    );
    Ok(())
}

/// R-ADMIN-4 with the PRODUCTION-shaped `domain = 0` (Circle domains can legitimately be 0): the
/// init succeeds, the stored domain word `[0,0,0,0]` is byte-identical to an UNWRITTEN slot, and
/// init-once still holds because the sentinel keys on the IDENTIFIER slot, never the domain slot
/// (`domain_config.masm:43-47`). Off-chain contract this test pins: a stored `[0,0,0,0]` aliases an
/// unwritten slot, so `GetAccount` readers MUST disambiguate "initialized-to-0" vs "never
/// initialized" via the **identifier** sentinel, never the domain/source_domain slots. Kills audit
/// mutant M28 (sentinel retargeted to the domain slot → a domain=0 deploy becomes re-initializable).
#[tokio::test]
async fn domain_init_with_zero_domain_is_still_init_once() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let first = init_four_fields(&gm, &account, owner(), 0, identifier, 1)
        .await
        .expect("domain_init with domain=0 (a legitimate Circle domain) must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(first.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(words[0], empty_word(), "stored domain=0 is byte-identical to an unwritten slot");
    assert_eq!(words[4], identifier, "the identifier sentinel is armed despite domain=0");

    let result = init_four_fields(&gm, &evolved, owner(), TEST_DOMAIN, identifier, 2).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

/// The `source_domain = 0` sibling — 0 is the PRODUCTION value (Circle source domains start at 0,
/// Ethereum first), which every other fixture deliberately routes around. Same pinned off-chain
/// contract: a stored `[0,0,0,0]` aliases an unwritten slot; readers disambiguate via the
/// identifier sentinel only. Init succeeds, reads back `[0,0,0,0]`, and re-init still traps the
/// EXACT ERR_XRESERVE_DOMAIN_REINIT.
#[tokio::test]
async fn domain_init_with_zero_source_domain_is_still_init_once() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let first = run_domain_init_tx(
        &gm.harness,
        &account,
        owner(),
        TEST_DOMAIN,
        0,
        &test_xreserve_contract(),
        identifier,
        1,
    )
    .await
    .expect("domain_init with source_domain=0 (the production Ethereum value) must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(first.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(words[0], Word::from([TEST_DOMAIN, 0, 0, 0]), "domain written exactly");
    assert_eq!(
        words[1],
        empty_word(),
        "stored source_domain=0 is byte-identical to an unwritten slot"
    );

    let result = init_four_fields(&gm, &evolved, owner(), TEST_DOMAIN, identifier, 2).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

/// Item 8: the `domain == u32::MAX` ACCEPT boundary (only the `u32::MAX + 1` trap side was
/// pinned). The maximal valid u32 passes the guard and reads back exactly `[u32::MAX,0,0,0]`.
#[tokio::test]
async fn domain_init_domain_at_u32_max_succeeds() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = init_four_fields(&gm, &account, owner(), u32::MAX, identifier, 1)
        .await
        .expect("domain_init with domain == u32::MAX (the accept boundary) must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(words[0], Word::from([u32::MAX, 0, 0, 0]), "domain == u32::MAX written exactly");
    assert_eq!(words[4], identifier, "the sentinel is armed");
    Ok(())
}

/// Item 8 sibling: the `source_domain == u32::MAX` ACCEPT boundary.
#[tokio::test]
async fn domain_init_source_domain_at_u32_max_succeeds() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = run_domain_init_tx(
        &gm.harness,
        &account,
        owner(),
        TEST_DOMAIN,
        u32::MAX,
        &test_xreserve_contract(),
        identifier,
        1,
    )
    .await
    .expect("domain_init with source_domain == u32::MAX (the accept boundary) must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(
        words[1],
        Word::from([u32::MAX, 0, 0, 0]),
        "source_domain == u32::MAX written exactly"
    );
    Ok(())
}

/// Item 9: the ALL-ZERO `xreserve_contract` ACCEPT pin — spec §5.9 mandates NO zero-guard on the
/// XRC field, so an all-zero bytes32 initializes successfully (both XRC slots read back
/// `[0,0,0,0]`) and the sentinel still arms (re-init traps the EXACT reinit error). This PINS the
/// no-guard behavior; it does NOT endorse it — an all-zero immutable XRC is a deploy footgun
/// flagged for the orchestrator's register (spec-conformant, not a defect).
#[tokio::test]
async fn domain_init_all_zero_xreserve_contract_succeeds() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = run_domain_init_tx(
        &gm.harness,
        &account,
        owner(),
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        &[0u8; 32],
        identifier,
        1,
    )
    .await
    .expect("domain_init with an all-zero xreserve_contract must succeed (spec §5.9: no guard)");
    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(words[2], empty_word(), "xreserve_contract_hi reads back all-zero");
    assert_eq!(words[3], empty_word(), "xreserve_contract_lo reads back all-zero");

    let result = init_four_fields(&gm, &evolved, owner(), TEST_DOMAIN, identifier, 2).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

/// Item 10: `domain_init` SUCCEEDS while the faucet is paused — deploy-time config is deliberately
/// NOT pause-gated (`domain_config.masm:10-11` "no pause gate — deploy-time config is orthogonal to
/// the operational pause"), while the three operational setters ARE pause-gated; this asymmetry was
/// pinned by no test. Anti-mutant: adding a pause gate to `domain_init` makes this fail with
/// "the contract is paused".
#[tokio::test]
async fn domain_init_succeeds_while_paused() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    // Pause first (DOM_PAUSER = id(2) = role_holder_not_owner()).
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, role_holder_not_owner(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_delta(paused.account_delta())?;
    assert_eq!(read_is_paused(&evolved)?, Word::from([1u32, 0, 0, 0]), "paused before init");

    // domain_init on the PAUSED faucet succeeds and writes all four fields.
    let executed = init_four_fields(&gm, &evolved, owner(), TEST_DOMAIN, identifier, 6)
        .await
        .expect("domain_init must succeed while paused (deploy-time config is not pause-gated)");
    evolved.apply_delta(executed.account_delta())?;
    let (exp_hi, exp_lo) = expected_xrc_words(&test_xreserve_contract());
    assert_eq!(
        read_domain_config_words(&evolved)?,
        [
            Word::from([TEST_DOMAIN, 0, 0, 0]),
            Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
            exp_hi,
            exp_lo,
            identifier,
        ],
        "the paused-state init wrote all four fields exactly"
    );
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "the faucet stays paused across domain_init"
    );
    Ok(())
}

// §5.9 SCALAR/LIMB u32 GUARDS (Round-P change 1) — malformed values staged as RAW felts trap the
// EXACT error BEFORE any write
// ================================================================================================

/// Shared body of the malformed-scalar/limb guard family: the malformed value staged DIRECTLY as a
/// raw > u32::MAX felt (bypassing the u32-typed Rust builder, which cannot produce it) must trap
/// the EXACT per-field guard error. RED: the shipped proc has no guards — the malformed init
/// SUCCEEDS, so the expected-trap assertion (`Execution was unexpectedly successful`) is the
/// behavioral red trigger. The trailing no-write read-back is the GREEN-phase contract
/// (belt-and-braces: a trapped tx commits nothing, so the un-evolved snapshot stays empty); it is
/// not itself the red signal.
async fn assert_malformed_value_traps(
    domain: u64,
    source_domain: u64,
    xrc_limb_index: usize,
    xrc_limb_value: u64,
    expected_err: &str,
) -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);

    // Well-formed limbs except the indexed malformed slot. Malformed values must sit in [2^32, p)
    // — valid FELT literals (the assembler rejects >= p = 2^64 - 2^32 + 1) that are NOT valid u32s
    // — exactly what the on-chain guard must catch. The index parameterization exercises BOTH
    // guard words: limbs 0..4 trap the HI-word u32assertw, limbs 4..8 the LO-word one (the
    // acceptance-audit surviving-mutant fix: index-0-only staging left the LO guard unexercised).
    let mut xrc_limbs = [0xABu64; 8];
    xrc_limbs[xrc_limb_index] = xrc_limb_value;

    let result = run_domain_init_tx_raw(
        &gm.harness,
        &account,
        owner(),
        domain,
        source_domain,
        &xrc_limbs,
        dummy_identifier(),
        1,
    )
    .await;
    // u32assert* surfaces as OperationError::U32AssertionFailed (not FailedAssertion), so the
    // named error is pinned on that variant's code AND message — the malformed_limb_traps_bad_limb
    // idiom (mint_recipient_account_id.rs).
    let expected = shell_error_by_name(expected_err);
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::OperationError {
            err: OperationError::U32AssertionFailed { ref err_code, ref err_msg, .. },
            ..
        } if *err_code == expected.code() && err_msg.as_deref() == Some(expected.message())
    );

    // No-write proof: a trapped tx commits nothing; every domain-config slot is still empty on the
    // (un-evolved) account.
    assert_eq!(
        read_domain_config_words(&account)?,
        [empty_word(); 5],
        "a guard trap must leave every domain-config slot unwritten"
    );
    Ok(())
}

/// §5.9 scalar exactness (Round-P change 1): domain > u32::MAX traps the EXACT
/// ERR_XRESERVE_DOMAIN_NOT_U32, nothing written. RED (no guard shipped).
#[tokio::test]
async fn domain_init_domain_over_u32_traps() -> Result<()> {
    assert_malformed_value_traps(
        u32::MAX as u64 + 1,
        TEST_SOURCE_DOMAIN as u64,
        0,
        0xAB,
        "ERR_XRESERVE_DOMAIN_NOT_U32",
    )
    .await
}

/// §5.9 scalar exactness (symmetric leg): source_domain > u32::MAX traps the EXACT
/// ERR_XRESERVE_SOURCE_DOMAIN_NOT_U32, nothing written. RED (no guard shipped).
#[tokio::test]
async fn domain_init_source_domain_over_u32_traps() -> Result<()> {
    assert_malformed_value_traps(
        TEST_DOMAIN as u64,
        u32::MAX as u64 + 1,
        0,
        0xAB,
        "ERR_XRESERVE_SOURCE_DOMAIN_NOT_U32",
    )
    .await
}

/// D-A6-XRC guard 2: an xreserve_contract limb > u32::MAX (2^32 — a valid felt below the field
/// modulus p = 2^64 − 2^32 + 1, but not a valid u32) traps the EXACT
/// ERR_XRESERVE_XRC_LIMB_NOT_U32, nothing written — at ANY limb position. The cases span BOTH
/// stored words so BOTH `u32assertw` guards are load-bearing: index 0 = the HI word's first limb,
/// indices 4 and 7 = the LO word's first and last limbs (the acceptance-audit surviving-mutant
/// fix: staging only index 0 left the LO-word guard removable with the suite green).
#[rstest]
#[case::hi_limb_0(0)]
#[case::lo_limb_4(4)]
#[case::lo_limb_7(7)]
#[tokio::test]
async fn domain_init_xrc_limb_over_u32_traps(#[case] xrc_limb_index: usize) -> Result<()> {
    assert_malformed_value_traps(
        TEST_DOMAIN as u64,
        TEST_SOURCE_DOMAIN as u64,
        xrc_limb_index,
        u32::MAX as u64 + 1,
        "ERR_XRESERVE_XRC_LIMB_NOT_U32",
    )
    .await
}

// OWNER-SPECIFIC AUTH — owner succeeds; a role holder who is NOT the owner is rejected
// ================================================================================================

/// The OWNER (id(1)), who holds NO DOM role, succeeds — proving the gate is the owner. RED: the
/// success read-back asserts the 4-field identifier write only (which lands), but the test drives
/// the 4-field note; it stays meaningful under both. GREEN-ON-ARRIVAL mechanics, re-calibrated.
#[tokio::test]
async fn domain_init_owner_not_admin_succeeds() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("the owner (not a DOM role holder) must be authorized for domain_init");

    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let stored = evolved.storage().get_item(&StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)?)?;
    assert_eq!(stored, identifier, "the owner's write configured the identifier");
    Ok(())
}

/// A seeded DOM role holder (id(2), DOM_PAUSER) who is NOT the owner is rejected with the EXACT
/// ERR_SENDER_NOT_OWNER and leaves the config unwritten — domain_init is OWNER-gated, not
/// role-gated. GREEN-ON-ARRIVAL mechanics (gate unchanged), re-calibrated to the 4-field note.
#[tokio::test]
async fn domain_init_admin_not_owner_rejects() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let result =
        init_four_fields(&gm, &account, role_holder_not_owner(), TEST_DOMAIN, identifier, 1).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // config unchanged: the owner's write on the original account still succeeds (had the role
    // holder's tx written, this would trap ERR_XRESERVE_DOMAIN_REINIT).
    init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 2)
        .await
        .expect("the owner write proves the rejected tx left the config unwritten");
    Ok(())
}

/// A stranger (id(99), neither owner nor role holder) is rejected with the EXACT
/// ERR_SENDER_NOT_OWNER. GREEN-ON-ARRIVAL mechanics, re-calibrated to the 4-field note.
#[tokio::test]
async fn domain_init_stranger_rejects() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);

    let result =
        init_four_fields(&gm, &account, non_owner(), TEST_DOMAIN, dummy_identifier(), 1).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

// CONSUMPTION SEAM — domain_init feeds the mint gate (real two-tx mint reading the configured
// slots), RE-PROVEN BYTE-IDENTICAL through the 4-field extension
// ================================================================================================

/// After the 4-field `domain_init(D, SD, XRC, I)`, the canonical deposit (remoteDomain == D,
/// remoteToken key == I) PASSES D5a's compare and mints — proving the extension left the two
/// D5a-read slots' encodings byte-identical ([D,0,0,0]; I verbatim), asserted EXPLICITLY before the
/// mint. RED: the shipped proc writes "domain" from the wrong stack position, so the byte-identity
/// assert and the mint both fail.
#[tokio::test]
async fn domain_init_then_matching_domain_mint_passes() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let identifier = identifier_of(BASE_VECTOR);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        empty_word(),
        empty_word(),
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        true,
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: the owner configures all four fields; the mint is checked against domain + identifier.
    let set = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // d5a_domain_identifier_seam_unchanged (byte-identity leg): the two D5a-read slots carry the
    // EXACT 2-field-era encodings after the 4-field init.
    let words = read_domain_config_words(&evolved)?;
    assert_eq!(words[0], Word::from([TEST_DOMAIN, 0, 0, 0]), "domain word byte-identical");
    assert_eq!(words[4], identifier, "identifier word byte-identical (verbatim)");

    // tx2: the canonical deposit (remoteDomain == TEST_DOMAIN, remoteToken key == identifier) mints.
    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("after domain_init(D, ..), a deposit targeting D must pass D5a and mint (seam closes)");
    assert_eq!(minted.output_notes().num_notes(), 1, "exactly one recipient note");
    Ok(())
}

/// After `domain_init(domain=D')` with D' != the deposit's remoteDomain, the canonical mint traps
/// the EXACT ERR_XRESERVE_WRONG_DOMAIN — the domain write genuinely controls D5a's gate (seam
/// non-vacuity). RED: the shipped proc stores the first XRC_HI limb as "domain", so the trap fires
/// for the WRONG reason (a junk domain, not D'); the test is re-calibrated and stays the exact-error
/// seam proof in green.
#[tokio::test]
async fn domain_init_then_wrong_domain_mint_rejects() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let identifier = identifier_of(BASE_VECTOR);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        empty_word(),
        empty_word(),
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        true,
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: configure a domain that does NOT match the canonical payload's remoteDomain (TEST_DOMAIN).
    let set = init_four_fields(&gm, &account, owner(), TEST_WRONG_DOMAIN, identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;
    // The wrong domain was WRITTEN exactly (not junk): [D',0,0,0].
    assert_eq!(
        read_domain_config_words(&evolved)?[0],
        Word::from([TEST_WRONG_DOMAIN, 0, 0, 0]),
        "the configured wrong-domain word must be exactly [D',0,0,0]"
    );

    // tx2: the canonical deposit (remoteDomain == TEST_DOMAIN != TEST_WRONG_DOMAIN) traps at D5a.
    let result = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_DOMAIN"));
    Ok(())
}

/// After `domain_init(domain=D, identifier=I')` with the correct domain but I' != the deposit's
/// remoteToken key, the canonical mint passes the domain compare and traps the EXACT
/// ERR_XRESERVE_WRONG_IDENTIFIER — the identifier write feeds D5a's identifier gate. RED: the
/// shipped proc's junk "domain" traps WRONG_DOMAIN before the identifier compare is reached.
#[tokio::test]
async fn domain_init_then_wrong_identifier_mint_rejects() -> Result<()> {
    let payload = happy_payload();
    let attester = gen_attester(1, &payload);
    let wrong_identifier = Word::from([42u32, 43, 44, 45]); // != the canonical remoteToken key
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        empty_word(),
        empty_word(),
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        true,
    )?;
    let account = faucet_account(&gm.harness);

    // tx1: configure the CORRECT domain but a WRONG identifier (so domain passes, identifier traps).
    let set = init_four_fields(&gm, &account, owner(), TEST_DOMAIN, wrong_identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: domain matches (TEST_DOMAIN) so D5a reaches the identifier compare, which mismatches.
    let result = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_IDENTIFIER"));
    Ok(())
}

/// Item-7 CHARACTERIZATION (surface, don't fix): a mint attempted BEFORE `domain_init`, crafted to
/// the audit-derived WORST-CASE shape — `remoteDomain = 0`. Pre-init the domain slot reads
/// `[0,0,0,0]`, so the D5a domain compare (R-MINT-6) PASSES for a remoteDomain=0 intent (0 == the
/// unwritten slot's 0 — the domain compare is NOT what forecloses this mint). The SOLE foreclosure
/// is the NEXT check, the R-MINT-7 identifier compare: the intent's remoteToken key-Word (a
/// Poseidon2 image via `bytes32_to_storage_map_key`) vs the EMPTY identifier slot. That is a
/// cryptographic ACCIDENT, not a designed guard — a Poseidon2 image equal to the zero Word is
/// practically unreachable, so the foreclosure is robust but undesigned. This test pins the exact
/// foreclosing error so any change to that mechanism (e.g. a future `domain_init`-required guard,
/// or a reordering of the D5a compares) surfaces loudly. The attestation is VALID over the edited
/// payload and the attester IS allowlisted — neither is what forecloses.
#[tokio::test]
async fn mint_before_domain_init_rejects() -> Result<()> {
    // The canonical happy payload with remoteDomain (u32 BE at byte offset 40, gen_vectors.rs:153)
    // zeroed — the worst case: it MATCHES the unwritten domain slot.
    let mut payload = happy_payload();
    payload[40..44].fill(0);
    let attester = gen_attester(1, &payload);
    let driver = mint_composition_driver_src(&pack(&payload), LEN_FELTS, SCALE_EXP);
    let probe = composition_noeffect_probe_src(0, nonce_key());
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
        1_000_000,
        0,
        empty_word(),
        empty_word(),
        None,
        Some((attester.commitment, Word::from(MARKER))),
        &driver,
        &probe,
        true,
    )?;
    let account = faucet_account(&gm.harness);

    // NO domain_init: all five domain-config slots are the exact pre-init state (EMPTY).
    let result = run_mint_against(&gm.harness, &account, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_IDENTIFIER"));
    Ok(())
}

// SOLE-WRITER STATIC SWEEP — only domain_init writes the five domain-config slots (immutability's
// structural leg; the N1A-family idiom)
// ================================================================================================

/// Collects `(basename, source)` for every `.masm` under the xreserve tree.
fn masm_sources() -> Result<Vec<(String, String)>> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "masm") {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();
                out.push((name, std::fs::read_to_string(&path)?));
            }
        }
        Ok(())
    }
    let dir: PathBuf = xusdc_encoding::xreserve_asm_dir();
    let mut out = Vec::new();
    walk(&dir, &mut out)?;
    anyhow::ensure!(!out.is_empty(), "the xreserve asm tree must not be empty");
    Ok(out)
}

/// STRUCTURAL immutability: (a) each of the five domain-config slot labels is DECLARED as a
/// `word("…")` const in exactly its canonical home (domain/identifier in deposit_intent_parser.masm,
/// the D5a reader; the three NEW labels in domain_config.masm, their only user); (b)
/// domain_config.masm performs exactly FIVE `native_account::set_item` writes (one per field); (c)
/// NO other file in the tree performs any `native_account::set_item` write against a domain-config
/// const. RED: the three new labels are declared nowhere and the shipped proc holds two writes.
#[test]
fn domain_config_sole_writer_sweep() -> Result<()> {
    let sources = masm_sources()?;
    let declared_in = |label: &str| -> Vec<String> {
        let needle = format!("word(\"{label}\")");
        sources
            .iter()
            .filter(|(_, src)| src.contains(&needle))
            .map(|(name, _)| name.clone())
            .collect()
    };

    // (a) canonical declaration homes.
    for label in [DOMAIN_CONFIG_SLOT_LABEL, IDENTIFIER_CONFIG_SLOT_LABEL] {
        assert_eq!(
            declared_in(label),
            vec!["deposit_intent_parser.masm".to_string()],
            "{label} must be declared exactly once, in the D5a reader"
        );
    }
    for label in [
        SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
        XRESERVE_CONTRACT_HI_SLOT_LABEL,
        XRESERVE_CONTRACT_LO_SLOT_LABEL,
    ] {
        assert_eq!(
            declared_in(label),
            vec!["domain_config.masm".to_string()],
            "{label} must be declared exactly once, in domain_config.masm (its only user)"
        );
    }

    // (b) domain_config.masm writes exactly the five fields.
    let domain_config = &sources
        .iter()
        .find(|(name, _)| name == "domain_config.masm")
        .expect("domain_config.masm present")
        .1;
    let writes = domain_config.matches("exec.native_account::set_item").count();
    assert_eq!(
        writes, 5,
        "domain_config.masm must perform exactly five set_item writes (one per §5.9 field slot)"
    );

    // (c) no other module writes account storage against a domain-config const: the parser (the
    // only other module referencing these labels) must contain no set_item at all.
    for (name, src) in &sources {
        if name == "domain_config.masm" {
            continue;
        }
        let references_config = [
            DOMAIN_CONFIG_SLOT_LABEL,
            IDENTIFIER_CONFIG_SLOT_LABEL,
            SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
            XRESERVE_CONTRACT_HI_SLOT_LABEL,
            XRESERVE_CONTRACT_LO_SLOT_LABEL,
        ]
        .iter()
        .any(|l| src.contains(&format!("word(\"{l}\")")))
            || src.contains("deposit_intent_parser::DOMAIN_CONFIG_SLOT")
            || src.contains("deposit_intent_parser::IDENTIFIER_CONFIG_SLOT");
        if references_config {
            assert!(
                !src.contains("exec.native_account::set_item"),
                "{name} references a domain-config slot AND performs storage writes — only \
                 domain_init may write the domain-config slots"
            );
        }
    }
    Ok(())
}
