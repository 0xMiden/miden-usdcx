//! P5-01 `domain_init` (R-ADMIN-4) suite: the OWNER-gated, init-once domain-config setter that writes
//! the `domain` + `identifier` slots the mint path's D5a compare (deposit_intent_parser.masm) already
//! reads. This file proves: write integrity (full-slot readback), init-once (a second write traps the
//! EXACT ERR_XRESERVE_DOMAIN_REINIT), owner-SPECIFIC auth (an owner who is NOT the ATTEST_ADMIN holder
//! succeeds; an ATTEST_ADMIN holder who is NOT the owner is rejected with ERR_SENDER_NOT_OWNER), and
//! the CONSUMPTION SEAM (after `domain_init(D, I)`, a real two-tx mint reading the configured slots
//! passes D5a for the matching domain/identifier and traps the exact D5a error for a mismatch).
//!
//! RED-SUITE (executing-red): `domain_config.masm` holds only the NAMED placeholder trap
//! (ERR_UNIMPLEMENTED_DOMAIN_INIT). Each behavior test asserts its FINAL (green) expectation and is
//! therefore RED here -- the owner/non-owner note reaches `call.domain_init`, then the terminal
//! placeholder reverts the tx. The GREEN commit wires the owner gate + init-once guard + the two slot
//! writes and removes the trap. `probe_domain_config_exports` is a declared green scaffold (the
//! placeholder makes the `domain_init` path resolve).

mod support;

use anyhow::Result;
use miden_protocol::account::{AccountId, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::vectors::{DiFields, DiVector, load, parse_hex32};
use xusdc_encoding::xreserve::encoding::bytes32_to_storage_map_key;

// The production builder seeds owner = id(1), admin_holder = id(2) (support::setup_guarded_mint_account
// -> XReserveStablecoinBuilder::new(.., id(1), id(2))). The owner-SPECIFIC auth proof needs all three
// distinct senders: the owner, the ATTEST_ADMIN holder (NOT owner), and a stranger (neither).
fn owner() -> AccountId {
    test_account_id(1)
}
fn admin_not_owner() -> AccountId {
    test_account_id(2)
}
fn non_owner() -> AccountId {
    test_account_id(99)
}

/// An empty value-slot word — the uninitialized domain/identifier config the production faucet ships
/// with before `domain_init` writes them.
fn empty_word() -> Word {
    Word::from([0u32, 0, 0, 0])
}

/// A simple non-seam identifier for the pure-setter tests (1/2/3) — any non-empty Word works; the seam
/// tests (4-6) use the canonical remoteToken key instead.
fn dummy_identifier() -> Word {
    Word::from([11u32, 12, 13, 14])
}

/// A trivial driver/probe pair for the pure-setter tests (no mint is run; domain_init goes via a note).
fn trivial_driver_probe() -> (String, String) {
    (mint_composition_driver_src(&[Felt::from(0u32)], 60, 6), composition_supply_probe_src(0))
}

/// A guarded production faucet (Ownable2Step owner = id(1), RBAC admin = id(2)) whose domain/identifier
/// config slots are declared EMPTY — so `domain_init` is the writer and the init-once sentinel reads
/// EMPTY pre-init. `attesters_seed`/`nonce_seed` default empty for the pure-setter tests.
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

// WRITE INTEGRITY — the owner's domain_init configures both slots, full-slot readback
// ================================================================================================

/// The owner's `domain_init(D, I)` succeeds and writes BOTH config slots exactly: domain == [D,0,0,0]
/// (D5a reads element 0) and identifier == I (full Word). RED: the placeholder traps before any write.
#[tokio::test]
async fn domain_init_succeeds_and_configures() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("the owner's domain_init must succeed");

    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;

    let domain_slot = StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL)?;
    let stored_domain = evolved.storage().get_item(&domain_slot)?;
    assert_eq!(
        stored_domain,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        "domain slot must be [domain, 0, 0, 0] (D5a reads element 0)"
    );

    let identifier_slot = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)?;
    let stored_identifier = evolved.storage().get_item(&identifier_slot)?;
    assert_eq!(stored_identifier, identifier, "identifier slot must be the supplied Word verbatim");
    Ok(())
}

// INIT-ONCE (R-ADMIN-4) — a second write traps the EXACT ERR_XRESERVE_DOMAIN_REINIT
// ================================================================================================

/// First `domain_init` succeeds; a SECOND traps the EXACT ERR_XRESERVE_DOMAIN_REINIT (the init-once
/// sentinel reads the now-non-empty identifier slot). RED: the placeholder traps the wrong error.
#[tokio::test]
async fn domain_init_reinit_traps() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let first = run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("first domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(first.account_delta())?;

    let result = run_domain_init_tx(&gm.harness, &evolved, owner(), TEST_DOMAIN, identifier, 2).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_DOMAIN_REINIT"));
    Ok(())
}

// OWNER-SPECIFIC AUTH — owner-not-admin succeeds; admin-not-owner is rejected
// ================================================================================================

/// The OWNER (id(1)), who does NOT hold ATTEST_ADMIN, succeeds — proving the gate is the owner, not the
/// ambient ATTEST_ADMIN authority that gates set_attester. RED: the placeholder traps before any write.
#[tokio::test]
async fn domain_init_owner_not_admin_succeeds() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let executed = run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("the owner (not an ATTEST_ADMIN holder) must be authorized for domain_init");

    let mut evolved = account.clone();
    evolved.apply_delta(executed.account_delta())?;
    let stored = evolved.storage().get_item(&StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)?)?;
    assert_eq!(stored, identifier, "the owner's write configured the identifier");
    Ok(())
}

/// The ATTEST_ADMIN holder (id(2)), who is NOT the owner, is rejected with the EXACT ERR_SENDER_NOT_OWNER
/// and leaves the config unwritten — proving domain_init is OWNER-gated, NOT ATTEST_ADMIN-gated (the
/// separation-of-duties distinction from set_attester). RED: the placeholder traps the wrong error.
#[tokio::test]
async fn domain_init_admin_not_owner_rejects() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);
    let identifier = dummy_identifier();

    let result =
        run_domain_init_tx(&gm.harness, &account, admin_not_owner(), TEST_DOMAIN, identifier, 1).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());

    // config unchanged: the owner's write on the original account still succeeds (had the admin tx
    // written, this would trap ERR_XRESERVE_DOMAIN_REINIT).
    run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, identifier, 2)
        .await
        .expect("the owner write proves the admin's rejected tx left the config unwritten");
    Ok(())
}

/// A stranger (id(99), neither owner nor ATTEST_ADMIN) is rejected with the EXACT ERR_SENDER_NOT_OWNER.
#[tokio::test]
async fn domain_init_stranger_rejects() -> Result<()> {
    let gm = uninit_faucet()?;
    let account = faucet_account(&gm.harness);

    let result =
        run_domain_init_tx(&gm.harness, &account, non_owner(), TEST_DOMAIN, dummy_identifier(), 1).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

// CONSUMPTION SEAM — domain_init feeds the mint gate (real two-tx mint reading the configured slots)
// ================================================================================================

/// After `domain_init(domain=D, identifier=I)`, the canonical deposit (remoteDomain == D, remoteToken
/// key == I) PASSES D5a's compare and mints — proving domain_init writes the IDENTICAL slots/encoding
/// D5a reads (end-to-end, two txs; NOT a storage delta). RED: tx1's placeholder traps, so the mint is
/// never reached.
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

    // tx1: the owner configures the domain + identifier the mint will be checked against.
    let set = run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: the canonical deposit (remoteDomain == TEST_DOMAIN, remoteToken key == identifier) mints.
    let minted = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester))
        .await
        .expect("after domain_init(D, I), a deposit targeting D must pass D5a and mint (seam closes)");
    assert_eq!(minted.output_notes().num_notes(), 1, "exactly one recipient note");
    Ok(())
}

/// After `domain_init(domain=D')` with D' != the deposit's remoteDomain, the canonical mint traps the
/// EXACT ERR_XRESERVE_WRONG_DOMAIN — proving domain_init's domain write genuinely controls D5a's domain
/// gate (seam non-vacuity). RED: tx1's placeholder traps, so the mint is never reached.
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
    let set = run_domain_init_tx(&gm.harness, &account, owner(), TEST_WRONG_DOMAIN, identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: the canonical deposit (remoteDomain == TEST_DOMAIN != TEST_WRONG_DOMAIN) traps at D5a.
    let result = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_DOMAIN"));
    Ok(())
}

/// After `domain_init(domain=D, identifier=I')` with the correct domain but I' != the deposit's
/// remoteToken key, the canonical mint passes the domain compare and traps the EXACT
/// ERR_XRESERVE_WRONG_IDENTIFIER — proving domain_init's identifier write feeds D5a's identifier gate.
/// RED: tx1's placeholder traps, so the mint is never reached.
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
    let set = run_domain_init_tx(&gm.harness, &account, owner(), TEST_DOMAIN, wrong_identifier, 1)
        .await
        .expect("owner domain_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_delta(set.account_delta())?;

    // tx2: domain matches (TEST_DOMAIN) so D5a reaches the identifier compare, which mismatches.
    let result = run_mint_against(&gm.harness, &evolved, composition_advice([0u32; 8], &attester)).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_WRONG_IDENTIFIER"));
    Ok(())
}
