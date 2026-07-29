//! Custom `pause`/`unpause` suite (component CMP-F3): the DOM_PAUSER-gated emergency halt. The stock
//! `PausableManager` gates pause on the account-wide `Authority` (= owner), so a distinct pause role
//! needs a CUSTOM proc: `xreserve::pause_admin::{pause,unpause}` =
//! `rbac::assert_sender_has_role(DOM_PAUSER)` + the unauthenticated `pausable::pause`/`unpause`
//! primitives.
//!
//! The load-bearing proof is the PAUSE-HALT SEAM — a DOM_PAUSER pause must actually HALT the real
//! faucet, not just flip `is_paused`: a REAL attested mint (the Wave-1 S1 stock-`MintNote`
//! transport consumed by the production faucet, whose `execute_mint_policy` runs
//! `assert_not_paused` FIRST) AND a real `receive_and_burn` trap `ERR_PAUSABLE_IS_PAUSED` while
//! paused, and both resume on unpause (execute_burn_policy runs the same stock gate).
//!
//! DOMAIN-PAUSER-ONLY MODEL (IMPL-DEV-1 remediation): Circle's model gives the owner NO direct pause
//! path, so the stock `PausableManager` is REMOVED from the composition and the DOM_PAUSER custom
//! procs are the ONLY pause surface.
//! RED-SUITE (executing-red): `owner_has_no_pause_path` / `owner_has_no_unpause_path` assert an
//! owner-sent STOCK `PausableManager::pause`/`unpause` note now fails with the exact
//! `UnknownAccountProcedure` (the roots are gone from the account code) — RED while the prior
//! baseline still installs the manager. `dom_pauser_pause_halts_mint`/`_burn` double as the
//! `is_paused`-slot-survival guards (at v0.16 the slot is installed by the base `Pausable`
//! component the builder adds — #2944 moved it out of `FungibleFaucet` — and NEVER by the
//! deliberately-absent `PausableManager`, which installs zero storage).

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use rstest::rstest;
use support::*;
use xusdc_encoding::note::xreserve_admin::{
    XReserveIdentifierInitNote, XReservePauseNote, XReserveSetAttesterNote, XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_mint::{MintAttestation, XUsdcMintNote};
use xusdc_encoding::vectors::{load, DiVector};
use xusdc_encoding::xreserve::encoding::account_id_to_bytes32;

/// Deterministic note rng for the production admin notes (serial only; never affects the gate).
fn prod_note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

// The production builder seeds owner = id(1) (Ownable2Step), DOM_PAUSER = id(2), DOM_MANAGER = id(3).
fn owner() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn plain_non_owner() -> AccountId {
    test_account_id(99)
}

// Burn-faucet parameters (mirrors burn_policy.rs / set_min_burn.rs).
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const MIN_BURN_SIZE: u64 = 1_000;
const VALID_BURN: u64 = 5_000;

// The exact stock pause / role errors these tests pin (assert-specific-error-in-tests).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

// MINT-SEAM FIXTURES (the recomposed REAL stock-MintNote transport — mirrors mint_policy_e2e.rs)
// ================================================================================================

const BASE_VECTOR: &str = "di-pos-empty-hookdata";
const MINT_MAX_SUPPLY: u64 = 1_000_000_000_000;
const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;

/// First byte of the 32-byte `remoteRecipient` field (felt 19 x 4 bytes; DC-1).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// First byte of the 32-byte `remoteToken` field (felt 11 x 4 bytes; DC-1).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
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

/// The canonical accept payload with the wire amount / maxFee spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` replaced by
/// `account_id_to_bytes32(faucet_id)` (the own-id fixpoint the seeded identifier_init writes, so
/// D5a's identifier compare passes), and one nonce byte perturbed per variant so each mint consumes
/// a fresh D5c nonce.
fn payload_for(
    recipient: AccountId,
    amount: u64,
    nonce_variant: u8,
    faucet_id: AccountId,
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

/// A compilable stand-in for the DELETED custom mint driver (the Wave-1 S1 recomposition removed
/// `xreserve::xreserve_mint`, so the former generated driver no longer assembles): the stock-pause
/// negative probes never invoke the driver proc — the guarded fixture only needs a component that
/// compiles.
fn placeholder_driver_src() -> String {
    "#! Test driver stand-in: never invoked by this suite (the custom mint entry was deleted by\n\
     #! the Wave-1 S1 recomposition); the guarded fixture only requires a compilable component.\n\
     #!\n\
     #! Inputs:  [pad(16)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc drive\n\
     \x20\x20\x20\x20push.0 drop\n\
     end\n"
        .to_string()
}

/// A PRODUCTION-composed faucet under permissive (IncrNonce) auth — the fixture for the stock-pause
/// negative probes, where the missing stock PROC (not note-script auth) must be what fails.
fn production_pause_fixture() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([Felt::from(TEST_DOMAIN), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        Word::from([11u32, 12, 13, 14]),
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

/// The production faucet brought up for the mint-halt seams (the REAL stock-note transport,
/// network-auth): the identifier seeded (DEC-4 minimized init), attester 1 allowlisted, plus the
/// caller's extra admin notes — all seeded at genesis so each admin tx is block-provable. Mirrors
/// `mint_policy_e2e.rs`.
fn mint_fixture(extra_notes: impl Fn(AccountId) -> Vec<Note>) -> Result<ProductionFaucet> {
    setup_production_faucet(MINT_MAX_SUPPLY, 0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, MINT_AMOUNT, 0, faucet_id)).commitment;
        let route = faucet_id;
        let mut notes = vec![
            XReserveIdentifierInitNote::create(owner(), route, &mut prod_note_rng(951))
                .expect("building the owner identifier_init note"),
            XReserveSetAttesterNote::create(owner(), route, commitment, 1, &mut prod_note_rng(952))
                .expect("building the owner set_attester note"),
        ];
        notes.extend(extra_notes(recipient));
        notes
    })
}

/// Consumes the seeded bring-up notes `0..count`, committing a block each.
async fn bring_up(pf: &mut ProductionFaucet, count: usize) -> Result<()> {
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

/// Builds the REAL stock mint note over an attested payload (the production `XUsdcMintNote`
/// factory transport: intent + attestation + routing attachments).
fn attested_mint_note(pf: &ProductionFaucet, payload: &[u8], rng_seed: u64) -> Result<Note> {
    let attester = gen_attester(1, payload);
    XUsdcMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        payload,
        &MintAttestation::new(attester.sig_bytes, attester.pubkey_bytes),
        &mut prod_note_rng(rng_seed),
    )
    .map_err(|e| anyhow::anyhow!("building the attested stock mint note: {e}"))
}

/// Emits the attested mint note from the producer and consumes it on the faucet by id (the REAL
/// stock-note transport), returning the consume result for success- or exact-trap assertions.
async fn emit_and_consume_mint(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    rng_seed: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let note = attested_mint_note(pf, payload, rng_seed)?;
    emit_note_with_attachments(&mut pf.mock_chain, pf.producer_id, &note).await?;
    Ok(pf
        .mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .context("building the mint consume tx")?
        .execute()
        .await)
}

/// Reads the committed `token_supply` (token_config word element 0) of a burn faucet.
fn token_supply_of(account: &Account) -> Result<Felt> {
    Ok(read_token_config(account)?[0])
}

// EXPORT PROBE (declared green scaffold — flat-path check for the new pause procs)
// ================================================================================================

#[test]
fn probe_pause_admin_exports() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    let exports: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    for canonical in [
        "::xreserve::pause_admin::pause",
        "::xreserve::pause_admin::unpause",
    ] {
        assert!(
            exports.iter().any(|e| e == canonical),
            "canonical pause proc path {canonical} missing; exports: {exports:?}"
        );
    }
    Ok(())
}

// PAUSE-HALT SEAM — the non-vacuity must-have: a pause HALTS the real mint AND the real burn
// ================================================================================================

/// In the Domain-Pauser-only model (IMPL-DEV-1 remediation): the owner's STOCK pause path is GONE. An
/// owner-sent stock `PausableManager::pause` note still ASSEMBLES (StandardsLib is pre-linked) but the
/// production account no longer exposes the proc root, so execution fails with the EXACT
/// `UnknownAccountProcedure` host-event error ("… is not in the account procedure index map" — NOT
/// a MASM assert) and `is_paused` stays untouched. Replaces `paused_mint_traps` (the owner-stock-
/// pause → mint-trap scenario ceases to exist; its mint-halt purpose lives in
/// `dom_pauser_pause_halts_mint`). RED at the prior baseline: the owner stock pause SUCCEEDS.
#[tokio::test]
async fn owner_has_no_pause_path() -> Result<()> {
    let gm = production_pause_fixture()?;
    let account = faucet_account(&gm.harness);

    let result = run_pause_against(&gm.harness.mock_chain, &account, owner(), 5).await;
    let err = result.expect_err("the stock owner pause path must be gone (Option 1)");
    assert_unknown_account_procedure(&err);
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "a failed stock pause leaves is_paused unpaused"
    );
    Ok(())
}

/// The unpause twin: DOM_PAUSER pauses first (the flag REALLY flips), then an owner-sent stock
/// `PausableManager::unpause` note fails with the EXACT `UnknownAccountProcedure` and the faucet
/// STAYS paused — a surviving stock unpause would visibly clear the flag. RED at the prior
/// baseline: the owner stock unpause SUCCEEDS (gated only on the owner Authority).
#[tokio::test]
async fn owner_has_no_unpause_path() -> Result<()> {
    let gm = production_pause_fixture()?;
    let account = faucet_account(&gm.harness);

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the DOM_PAUSER pause really flipped is_paused"
    );

    let result = run_stock_unpause_against(&gm.harness.mock_chain, &evolved, owner(), 6).await;
    let err = result.expect_err("the stock owner unpause path must be gone (Option 1)");
    assert_unknown_account_procedure(&err);
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "a failed stock unpause leaves the faucet paused"
    );
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real mint: the seeded production `XReservePauseNote`
/// (DOM_PAUSER-sent, consumed by id under the network auth) pauses the faucet, then a REAL attested
/// stock mint note (the recomposed transport, emitted and consumed by id) traps the EXACT
/// `ERR_PAUSABLE_IS_PAUSED` at the policy dispatcher's stock pause gate — fail-closed (no supply
/// raised).
#[tokio::test]
async fn dom_pauser_pause_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|_| {
        vec![
            XReservePauseNote::create(dom_pauser(), test_faucet_id(1), &mut prod_note_rng(7))
                .expect("building the DOM_PAUSER pause note"),
        ]
    })?;
    bring_up(&mut pf, 3).await?; // identifier_init + set_attester + pause
    assert_eq!(
        read_is_paused(&pf.mock_chain.committed_account(pf.faucet_id)?.clone())?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the DOM_PAUSER pause really flipped is_paused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 1, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 71).await?;
    assert_transaction_executor_error!(result, err_paused());
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(0)?,
        "a halted mint must not raise supply"
    );
    Ok(())
}

/// F5 — the ALLOWLISTED PRODUCTION `XReservePauseNote` (DOM_PAUSER-sent) HALTS the real attested
/// mint through the UNAUTHENTICATED-note transport: the pause note executes as an unauthenticated
/// input (never block-committed first — routing target a placeholder PUBLIC id, routing-only), its
/// `is_paused=1` delta is applied to the evolved faucet, and the REAL stock mint note consumed
/// (unauthenticated) against that paused faucet traps the exact stock pause error — the emergency
/// stop reaches the mint gate whichever note transport carries it.
#[tokio::test]
async fn dom_pauser_production_pause_note_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|_| vec![])?;
    bring_up(&mut pf, 2).await?; // identifier_init + set_attester

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    let note = XReservePauseNote::create(dom_pauser(), test_faucet_id(1), &mut prod_note_rng(8))?;
    let paused = pf
        .mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("production pause tx build")
        .execute()
        .await
        .expect("the DOM_PAUSER production pause note pauses the mint faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "precondition: the production pause note really flipped is_paused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 2, pf.faucet_id);
    let mint_note = attested_mint_note(&pf, &payload, 72)?;
    let result = pf
        .mock_chain
        .build_transaction(evolved)
        .unauthenticated_input_note(mint_note.clone())
        .build()
        .expect("mint consume tx build")
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// F5 — the ALLOWLISTED PRODUCTION `XReservePauseNote` HALTS the real burn: the note-driven twin of
/// `dom_pauser_pause_halts_burn`.
#[tokio::test]
async fn dom_pauser_production_pause_note_halts_burn() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;

    // Block N: the user emits + commits the (valid-amount) burn note (faucet not yet paused).
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // The DOM_PAUSER production pause note pauses the faucet; apply its delta to the evolved account.
    let account = chain.committed_account(faucet_id)?.clone();
    let note = XReservePauseNote::create(dom_pauser(), test_faucet_id(1), &mut prod_note_rng(8))?;
    let paused = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("production pause tx build")
        .execute()
        .await
        .expect("the DOM_PAUSER production pause note pauses the burn faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed burn note against the paused account → assert_not_paused traps.
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// A DOM_PAUSER-triggered pause HALTS the real burn: DOM_PAUSER pauses, then a real `receive_and_burn`
/// traps the EXACT `ERR_PAUSABLE_IS_PAUSED` (execute_burn_policy's stock pause gate). RED: the pause
/// placeholder traps first.
#[tokio::test]
async fn dom_pauser_pause_halts_burn() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;

    // Block N: the user emits + commits the (valid-amount) burn note (faucet not yet paused).
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    // DOM_PAUSER pauses the faucet; evolve the committed faucet with the (uncommitted) pause delta.
    let account = chain.committed_account(faucet_id)?.clone();
    let paused = run_dom_pauser_pause(&chain, &account, dom_pauser(), 5)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;

    // The faucet consumes the committed burn note against the paused account → execute_burn_policy's
    // assert_not_paused traps the stock pause error (the valid amount isolates the pause gate).
    let result = chain
        .build_transaction(evolved)
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// UNPAUSE RESUMES both surfaces: after a DOM_PAUSER pause→unpause (both the seeded production
/// admin notes), a REAL attested stock mint mints again (one recipient note, token_supply += the
/// attested amount) AND a real burn decrements token_supply.
#[tokio::test]
async fn dom_pauser_unpause_resumes_mint_and_burn() -> Result<()> {
    // --- mint side ---
    let mut pf = mint_fixture(|_| {
        vec![
            XReservePauseNote::create(dom_pauser(), test_faucet_id(1), &mut prod_note_rng(9))
                .expect("building the DOM_PAUSER pause note"),
            XReserveUnpauseNote::create(dom_pauser(), test_faucet_id(1), &mut prod_note_rng(10))
                .expect("building the DOM_PAUSER unpause note"),
        ]
    })?;
    bring_up(&mut pf, 4).await?; // identifier_init + set_attester + pause + unpause
    assert_eq!(
        read_is_paused(&pf.mock_chain.committed_account(pf.faucet_id)?.clone())?,
        Word::from([0u32, 0, 0, 0]),
        "precondition: the pause→unpause round trip leaves the faucet unpaused"
    );

    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 3, pf.faucet_id);
    let minted = emit_and_consume_mint(&mut pf, &payload, 73)
        .await?
        .map_err(|e| anyhow::anyhow!("after unpause, the real attested mint mints again: {e}"))?;
    assert_eq!(
        minted.output_notes().num_notes(),
        1,
        "unpause resumes minting (one recipient note)"
    );
    pf.mock_chain.add_pending_executed_transaction(&minted)?;
    pf.mock_chain.prove_next_block()?;
    assert_eq!(
        committed_token_supply(&pf.mock_chain, pf.faucet_id)?,
        miden_protocol::asset::AssetAmount::new(MINT_AMOUNT)?,
        "token_supply rose by exactly the attested amount"
    );

    // --- burn side ---
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let BurnPolicyHarness {
        mut chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        ..
    } = bh;
    let tx0 = try_emit_burn_note(&chain, &burn_note, &asset, faucet_id, user_id)
        .await
        .expect("the user emits the burn note (test-setup invariant)");
    chain.add_pending_executed_transaction(&tx0)?;
    chain.prove_next_block()?;

    let bacct = chain.committed_account(faucet_id)?.clone();
    let bpaused = run_dom_pauser_pause(&chain, &bacct, dom_pauser(), 7)
        .await
        .expect("DOM_PAUSER pauses the burn faucet");
    let mut bevolved = bacct.clone();
    bevolved.apply_patch(bpaused.account_patch())?;
    let bunpaused = run_dom_pauser_unpause(&chain, &bevolved, dom_pauser(), 8)
        .await
        .expect("DOM_PAUSER unpauses the burn faucet");
    bevolved.apply_patch(bunpaused.account_patch())?;

    // The faucet consumes the committed burn note against the UNPAUSED account → the burn succeeds.
    let burned = chain
        .build_transaction(bevolved.clone())
        .authenticated_input_note(burn_note.id())
        .build()?
        .execute()
        .await
        .expect("after unpause, the real receive_and_burn decrements supply");
    let mut bfinal = bevolved.clone();
    bfinal.apply_patch(burned.account_patch())?;
    assert_eq!(
        token_supply_of(&bfinal)?,
        Felt::from((TOKEN_SUPPLY - VALID_BURN) as u32),
        "unpause resumes burning (token_supply decremented by the burn amount)"
    );
    Ok(())
}

// ROLE GATE + SEPARATION — the custom pause is DOM_PAUSER-specific, and a pauser is not the owner
// ================================================================================================

/// Shared: a non-DOM_PAUSER `sender` is rejected from the CUSTOM pause with the EXACT
/// `ERR_SENDER_LACKS_ROLE`, and `is_paused` is unchanged (the gate traps before the pausable write).
async fn assert_custom_pause_rejects(sender: AccountId) -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let result = run_dom_pauser_pause(&bh.chain, &account, sender, 5).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "a rejected custom pause leaves is_paused unchanged (unpaused)"
    );
    Ok(())
}

/// A plain non-holder (id 99) cannot pause via the custom proc.
#[tokio::test]
async fn non_dom_pauser_pause_rejects() -> Result<()> {
    assert_custom_pause_rejects(plain_non_owner()).await
}

/// The OWNER (id 1) is NOT a DOM_PAUSER holder, so the custom pause rejects the owner too — the custom
/// surface is role-gated, not owner-gated. In the Domain-Pauser-only model (the stock
/// `PausableManager` removed — `owner_has_no_pause_path`) this completes "the owner has no DIRECT
/// pause path": neither the stock nor the custom surface accepts the owner. (The owner keeps
/// Circle-conformant ROLE-ADMINISTRATION power — at v0.16 it reaches DOM_PAUSER membership through
/// the two-hop chain owner→ADMIN→DOM_MANAGER→DOM_PAUSER (#3215/S21, human-ratified), the CMP-F5
/// delegation being the operational rotation path proven in `role_admin.rs` — a rotation concern,
/// not a pause surface.)
#[tokio::test]
async fn owner_is_not_dom_pauser_on_custom_pause() -> Result<()> {
    assert_custom_pause_rejects(owner()).await
}

/// A DIFFERENT role holder (DOM_MANAGER id 3) cannot pause — forecloses a caller-supplied/spoofable role
/// symbol: only the hard-coded DOM_PAUSER symbol passes the gate.
#[tokio::test]
async fn other_role_holder_cannot_pause() -> Result<()> {
    assert_custom_pause_rejects(dom_manager()).await
}

/// The custom `unpause` role gate, proven NEGATIVELY (audit HIGH finding): a non-DOM_PAUSER sender
/// — stranger, owner, or a DIFFERENT role holder (DOM_MANAGER) — is rejected from `unpause` with
/// the EXACT stock `ERR_SENDER_LACKS_ROLE`, and the faucet STAYS paused (no state change). Unpause
/// is the security-critical direction (Circle designates unpause a joint-approval action): an ungated
/// unpause would let anyone re-enable a paused — possibly compromised — bridge.
#[rstest]
#[case::stranger(plain_non_owner())]
#[case::owner(owner())]
#[case::dom_manager(dom_manager())]
#[tokio::test]
async fn non_dom_pauser_unpause_rejects(#[case] sender: AccountId) -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    // Arm the negative on a genuinely paused faucet: a real DOM_PAUSER pause first.
    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 11)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "paused before the unpause probe"
    );

    let result = run_dom_pauser_unpause(&bh.chain, &evolved, sender, 12).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "a rejected custom unpause leaves the faucet paused (no state change)"
    );
    Ok(())
}

/// SEPARATION: the DOM_PAUSER holder (id 2) can pause but is NOT the owner — an owner-gated setter
/// (`set_min_burn_size`) rejects it with the EXACT `ERR_SENDER_NOT_OWNER` (reuses the CMP-F2 owner gate,
/// so this is a GREEN separation regression guard).
#[tokio::test]
async fn dom_pauser_cannot_call_owner_setters() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let result = run_set_min_burn_size_against(&bh.chain, &account, dom_pauser(), 5_000, 7).await;
    assert_transaction_executor_error!(result, err_sender_not_owner());
    Ok(())
}

// IDEMPOTENCY PINS — the stock pausable primitives are UNCONDITIONAL writes
// ================================================================================================

/// `pause` when ALREADY paused is idempotent SUCCESS: the stock `pausable::pause` is an
/// unconditional `set_item` write with no already-paused guard (pinned `=0.16.0-alpha.2`
/// `pausable/mod.masm`), so a redundant DOM_PAUSER pause succeeds and `is_paused` stays
/// `[1,0,0,0]`. Pin-bump drift tripwire: a future stock version that traps on a redundant pause
/// would silently change ops semantics — it fails HERE instead.
#[tokio::test]
async fn pause_when_already_paused_is_idempotent() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 13)
        .await
        .expect("the first DOM_PAUSER pause succeeds");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "paused after pause #1"
    );

    let again = run_dom_pauser_pause(&bh.chain, &evolved, dom_pauser(), 14)
        .await
        .expect("a redundant pause is idempotent success (stock pause is an unconditional write)");
    evolved.apply_patch(again.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "is_paused stays exactly [1,0,0,0] after the redundant pause"
    );
    Ok(())
}

/// `unpause` when NOT paused is idempotent SUCCESS: the stock `pausable::unpause` is an
/// unconditional `set_item` write with no not-paused guard (pinned `=0.16.0-alpha.2`
/// `pausable/mod.masm`) — the same pin-bump drift tripwire, in the unpause direction.
#[tokio::test]
async fn unpause_when_not_paused_is_idempotent() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();
    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "fresh faucet is unpaused"
    );

    let unpaused = run_dom_pauser_unpause(&bh.chain, &account, dom_pauser(), 15)
        .await
        .expect("unpausing an unpaused faucet is idempotent success (unconditional write)");
    let mut evolved = account.clone();
    evolved.apply_patch(unpaused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([0u32, 0, 0, 0]),
        "is_paused stays exactly [0,0,0,0] after the redundant unpause"
    );
    Ok(())
}

// OBSERVABILITY — is_paused reads back via GetAccount
// ================================================================================================

/// `is_paused` is a network-observable value slot: it reads back unpaused pre-pause and paused after a
/// DOM_PAUSER pause. RED: the pause placeholder traps, so the flag never flips.
#[tokio::test]
async fn is_paused_publicly_readable() -> Result<()> {
    let bh = setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        MIN_BURN_SIZE,
        VALID_BURN,
    )?;
    let account = bh.chain.committed_account(bh.faucet_id)?.clone();

    assert_eq!(
        read_is_paused(&account)?,
        Word::from([0u32, 0, 0, 0]),
        "is_paused reads back unpaused pre-pause (GetAccount observability)"
    );

    let paused = run_dom_pauser_pause(&bh.chain, &account, dom_pauser(), 9)
        .await
        .expect("DOM_PAUSER pauses the faucet");
    let mut evolved = account.clone();
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "after a DOM_PAUSER pause, is_paused reads back paused"
    );
    Ok(())
}
