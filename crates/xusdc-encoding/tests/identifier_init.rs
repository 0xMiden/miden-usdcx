//! `identifier_init` suite — the minimized, owner-gated, init-once identifier seeding
//! (R-ADMIN-4 under DEC-4). REPLACES the deleted `domain_config.rs` (the four-field
//! `domain_init` suite): since the Wave-1 S1 recomposition the identifier is the ONE
//! domain-config field written post-build (it is a provable fixpoint of the account id), while
//! `domain` / `source_domain` / `xreserve_contract` are BUILD-SEEDED by
//! `XReserveStablecoinBuilder::with_domain_config` — so the former scalar/limb u32 guards, the
//! 4-field write integrity, and the consumption-seam legs are gone with the surface they tested.
//!
//! What SURVIVES (this file): the owner-SPECIFIC auth gate (a DOM role holder and a stranger
//! both trap the EXACT ERR_SENDER_NOT_OWNER), the identifier-sentinel init-once (a re-init traps
//! the EXACT ERR_XRESERVE_IDENTIFIER_REINIT and changes nothing), the empty-identifier guard
//! (ERR_XRESERVE_IDENTIFIER_EMPTY — an EMPTY identifier could never arm the sentinel), the
//! not-pause-gated asymmetry (deploy-time config is orthogonal to the operational pause), and
//! the untouched-build-seed read-backs (the init writes ONLY the identifier slot; the production
//! build-seed itself is pinned pre-init).

mod support;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::AccountId;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::note::xreserve_admin::XReserveIdentifierInitNote;
use xusdc_encoding::xreserve::encoding::{
    account_id_to_bytes32, bytes32_to_packed_felts, bytes32_to_storage_map_key,
};

// The production builder seeds owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3)
// (support::setup_guarded_mint_account -> XReserveStablecoinBuilder::new(.., id(1), id(2), ..)).
// The owner-SPECIFIC auth proof needs distinct senders: the owner, a role holder (NOT owner),
// and a stranger (neither).
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn stranger() -> AccountId {
    test_account_id(9)
}

const MAX_SUPPLY: u64 = 1_000_000;

/// A simple non-seam identifier for the setter tests — any non-empty Word works (the pre-hashed
/// `bytes32_to_key` form is what production stores; the proc stores the Word verbatim).
fn dummy_identifier() -> Word {
    Word::from([11u32, 12, 13, 14])
}

/// The exact pre-init domain-config state the production fixture ships with (DEC-4): the three
/// build-seeded fields (`with_domain_config(TEST_DOMAIN, TEST_SOURCE_DOMAIN,
/// test_xreserve_contract())` — xrc as the packed 8x u32-LE hi/lo halves) plus the EMPTY
/// identifier the init note is the sole writer of.
fn pre_init_config() -> [Word; 5] {
    let xrc = bytes32_to_packed_felts(&test_xreserve_contract());
    [
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
        Word::new([xrc[0], xrc[1], xrc[2], xrc[3]]),
        Word::new([xrc[4], xrc[5], xrc[6], xrc[7]]),
        Word::empty(),
    ]
}

/// A trivial placeholder driver component (this suite drives `identifier_init` via notes only —
/// no mint driver runs — but the fixture requires component sources).
const NOOP_DRIVER_SRC: &str = "#! No-op driver placeholder (never invoked by this suite).\n\
                               #!\n\
                               #! Inputs:  [pad(16)]\n\
                               #! Outputs: [pad(16)]\n\
                               #!\n\
                               #! Invocation: call\n\
                               @account_procedure\n\
                               pub proc noop\n\
                               \x20\x20\x20\x20push.0 drop\n\
                               end\n";

/// The PRODUCTION-composed faucet (attestation mint policy active; Ownable2Step owner = id(1);
/// DOM roles seeded) with the domain config BUILD-SEEDED and the identifier slot EMPTY — so
/// `identifier_init` is the sole writer and the init-once sentinel reads EMPTY pre-init.
fn uninit_identifier_faucet() -> Result<GuardedMint> {
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        Word::empty(), // the identifier ships EMPTY (note-seeded, DEC-4)
        None,
        None,
        NOOP_DRIVER_SRC,
        &composition_supply_probe_src(0),
        true,
    )
}

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(8u32),
    ]))
}

// R2-F3 — the production factory BINDS the identifier to the target faucet (the own-id fixpoint)
// ================================================================================================

/// The production `XReserveIdentifierInitNote::create` DERIVES the seeded identifier from the
/// faucet id — `bytes32_to_key(account_id_to_bytes32(faucet_id))`, the account-id fixpoint —
/// instead of accepting an arbitrary Word. Three properties the auditor's finding turns on:
/// (1) the derived key equals `identifier_for(faucet_id)` and rides the built note's storage;
/// (2) it is DISTINCT per faucet (a note built for faucet A cannot seed faucet B's identity);
/// (3) `account_id_to_bytes32` is a real AccountId encoding (16 leading zero bytes), so the
/// seeded identity can never be the golden-vector remoteToken the fresh flows previously used
/// (which has no such structure).
#[test]
fn identifier_init_note_binds_the_identifier_to_the_faucet() -> Result<()> {
    let fa = test_faucet_id(1);
    let fb = test_faucet_id(2);

    let key_a: Word = bytes32_to_storage_map_key(&account_id_to_bytes32(fa)).into();
    let key_b: Word = bytes32_to_storage_map_key(&account_id_to_bytes32(fb)).into();
    assert_eq!(
        XReserveIdentifierInitNote::identifier_for(fa),
        key_a,
        "identifier_for(faucet) must be the own-id fixpoint key"
    );
    assert_ne!(
        key_a, key_b,
        "distinct faucets must derive DISTINCT identifiers (the note cannot be redirected)"
    );

    // the built note for faucet A carries key_a verbatim in its storage — not a vector token.
    let note = XReserveIdentifierInitNote::create(owner(), fa, &mut note_rng(1))?;
    let items = note.recipient().storage().items();
    assert_eq!(
        &items[0..4],
        key_a.as_elements(),
        "the note storage must carry the own-id derived identifier"
    );

    // the fixpoint source is a genuine AccountId-in-bytes32 encoding (16 leading zero bytes) —
    // the structural property the static golden-vector remoteToken lacks (the auditor's evidence).
    let encoded = account_id_to_bytes32(fa);
    assert_eq!(
        &encoded[0..16],
        &[0u8; 16],
        "account_id_to_bytes32 must be a real AccountId encoding (16 leading zero bytes)"
    );
    Ok(())
}

// EXPORT PROBE (flat-path check for the minimized setter)
// ================================================================================================

#[test]
fn probe_identifier_init_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    let canonical = "::xreserve::identifier_init::init_identifier";
    assert!(
        exports.iter().any(|e| e == canonical),
        "canonical setter path {canonical} missing; exports: {exports:?}"
    );
    Ok(())
}

// THE PRODUCTION BUILD-SEED — the pre-init state itself (DEC-4's build-time half)
// ================================================================================================

/// BEFORE any init, the five config words read back as the production build-seed: domain
/// `[TEST_DOMAIN,0,0,0]`, source_domain `[TEST_SOURCE_DOMAIN,0,0,0]`, the packed
/// `test_xreserve_contract()` hi/lo words, and the EMPTY identifier.
#[test]
fn production_build_seeds_the_domain_config() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);
    assert_eq!(
        read_domain_config_words(&account)?,
        pre_init_config(),
        "the production fixture must ship the build-seeded domain config + an EMPTY identifier",
    );
    Ok(())
}

// WRITE INTEGRITY — the owner's init writes the identifier verbatim and NOTHING else
// ================================================================================================

/// The owner's `identifier_init` succeeds, stores the identifier Word VERBATIM, and leaves the
/// four build-seeded config words byte-identical (before == after) — the minimized init touches
/// ONLY the identifier slot.
#[tokio::test]
async fn identifier_init_owner_writes_the_identifier_verbatim() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);
    let before = read_domain_config_words(&account)?;

    let executed = run_identifier_init_tx(&gm.harness, &account, owner(), dummy_identifier(), 1)
        .await
        .expect("the owner's identifier_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(executed.account_patch())?;

    let after = read_domain_config_words(&evolved)?;
    assert_eq!(
        after[4],
        dummy_identifier(),
        "identifier slot must be the supplied Word verbatim"
    );
    assert_eq!(
        after[..4],
        before[..4],
        "the four build-seeded config words must be UNCHANGED by the init (identifier-only write)"
    );
    Ok(())
}

// INIT-ONCE (R-ADMIN-4) — a second write traps the EXACT ERR_XRESERVE_IDENTIFIER_REINIT
// ================================================================================================

/// First `identifier_init` succeeds; a SECOND — even from the owner, with a different value —
/// traps the EXACT ERR_XRESERVE_IDENTIFIER_REINIT (the identifier slot IS the init-once
/// sentinel) and leaves all five config words unchanged.
#[tokio::test]
async fn identifier_init_reinit_traps_and_leaves_config_unchanged() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let first = run_identifier_init_tx(&gm.harness, &account, owner(), dummy_identifier(), 1)
        .await
        .expect("first identifier_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(first.account_patch())?;
    let before = read_domain_config_words(&evolved)?;
    assert_eq!(
        before[4],
        dummy_identifier(),
        "the first init must have armed the sentinel"
    );

    // A second init with a DIFFERENT identifier traps and leaves every word untouched.
    let result = run_identifier_init_tx(
        &gm.harness,
        &evolved,
        owner(),
        Word::from([91u32, 92, 93, 94]),
        2,
    )
    .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_IDENTIFIER_REINIT")
    );
    assert_eq!(
        read_domain_config_words(&evolved)?,
        before,
        "a trapped re-init must leave all five domain-config words unchanged"
    );
    Ok(())
}

// EMPTY-IDENTIFIER GUARD — an EMPTY input could never arm the sentinel, so it traps
// ================================================================================================

/// `identifier_init` with `identifier = EMPTY_WORD` traps the EXACT
/// ERR_XRESERVE_IDENTIFIER_EMPTY and writes NOTHING: an EMPTY identifier would leave the
/// init-once sentinel unarmed (silently re-initializable, R-ADMIN-4 broken) AND D5a would
/// compare every intent's identifier against EMPTY.
#[tokio::test]
async fn identifier_init_empty_identifier_traps() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let result = run_identifier_init_tx(&gm.harness, &account, owner(), Word::empty(), 1).await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_IDENTIFIER_EMPTY")
    );

    // No-write proof: a trapped tx commits nothing; the config stays the exact build-seed.
    assert_eq!(
        read_domain_config_words(&account)?,
        pre_init_config(),
        "a trapped empty-identifier init must leave the domain config at the build-seed"
    );
    Ok(())
}

// OWNER-SPECIFIC AUTH — a role holder who is NOT the owner and a stranger both reject
// ================================================================================================

/// Shared body of the non-owner reject family: the sender traps the EXACT ERR_SENDER_NOT_OWNER
/// and writes nothing (the config stays the pre-init build-seed).
async fn assert_identifier_init_nonowner_rejects(sender: AccountId, seed: u64) -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let result =
        run_identifier_init_tx(&gm.harness, &account, sender, dummy_identifier(), seed).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    assert_eq!(
        read_domain_config_words(&account)?,
        pre_init_config(),
        "a rejected non-owner init must write nothing"
    );
    Ok(())
}

/// A seeded DOM role holder (id(2), DOM_PAUSER) who is NOT the owner rejects —
/// `identifier_init` is OWNER-gated, not role-gated. The owner's follow-up init on the SAME
/// account still succeeds, proving the rejected tx left the sentinel unarmed (had it written,
/// this would trap ERR_XRESERVE_IDENTIFIER_REINIT).
#[tokio::test]
async fn identifier_init_dom_pauser_rejects() -> Result<()> {
    assert_identifier_init_nonowner_rejects(dom_pauser(), 3).await?;

    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);
    let rejected =
        run_identifier_init_tx(&gm.harness, &account, dom_pauser(), dummy_identifier(), 3).await;
    assert_transaction_executor_error!(rejected, err_sender_not_owner());
    run_identifier_init_tx(&gm.harness, &account, owner(), dummy_identifier(), 4)
        .await
        .expect("the owner write proves the rejected tx left the sentinel unarmed");
    Ok(())
}

/// A stranger (id(9), neither owner nor role holder) rejects with the EXACT
/// ERR_SENDER_NOT_OWNER and writes nothing.
#[tokio::test]
async fn identifier_init_stranger_rejects() -> Result<()> {
    assert_identifier_init_nonowner_rejects(stranger(), 5).await
}

// PAUSE ASYMMETRY — deploy-time config is NOT pause-gated
// ================================================================================================

/// `identifier_init` SUCCEEDS while the faucet is paused — deploy-time config is deliberately
/// NOT pause-gated (the operational setters ARE). Anti-mutant: adding a pause gate to
/// `init_identifier` makes this fail with "the contract is paused".
#[tokio::test]
async fn identifier_init_succeeds_while_paused() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    // Pause first (DOM_PAUSER = id(2)).
    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 6)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "paused before init"
    );

    // identifier_init on the PAUSED faucet succeeds and writes the identifier.
    let executed = run_identifier_init_tx(&gm.harness, &evolved, owner(), dummy_identifier(), 7)
        .await
        .expect(
            "identifier_init must succeed while paused (deploy-time config is not pause-gated)",
        );
    evolved.apply_patch(executed.account_patch())?;
    assert_eq!(
        read_domain_config_words(&evolved)?[4],
        dummy_identifier(),
        "the paused-state init wrote the identifier"
    );
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "the faucet stays paused across identifier_init"
    );
    Ok(())
}
