//! Seeding the faucet's identifier: an administrator-only write that can happen exactly once.
//!
//! Of the faucet's five domain-config words, four — the domain, the source domain, and the two
//! halves of the xReserve contract address — are seeded by the builder when the account is
//! composed. Only the identifier is written after deployment, because it must be derived from the
//! account's own id, which is not known until the account exists. `init_identifier` is the sole
//! writer of that slot.
//!
//! Everything about the procedure is defensive, because the identifier is what the mint path
//! compares every incoming deposit's `remoteToken` against. A wrong identifier would either brick
//! minting or, worse, accept deposits meant for a different faucet.
//!
//! - It is gated on the OWNER specifically — a role holder is refused just like a stranger.
//! - It refuses the empty Word. An empty identifier would leave the slot indistinguishable from
//!   uninitialized, so the init-once check could never fire and the deposit compare would be
//!   against nothing.
//! - It is init-once. Once the slot is non-empty, a second write traps and changes nothing, so an
//!   identifier cannot be re-pointed after deposits have started flowing.
//! - It binds to the faucet's OWN id: the procedure recomputes the expected key on-chain from
//!   `get_id()` and rejects any other value. This is what makes the init safe to leave open on a
//!   fresh account — even if someone else's transaction lands first, they can only write the
//!   identifier the faucet was always going to have.
//! - It is deliberately NOT pause-gated: deployment-time configuration is orthogonal to the
//!   operational halt.
//!
//! Each write test also reads back the four build-seeded words to prove the init touched only the
//! identifier slot.

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

// The production builder seeds the administrator = id(1) (the sole ADMIN member), DOM_PAUSER =
// id(2), DOM_MANAGER = id(3)
// (support::setup_guarded_mint_account -> XReserveStablecoinBuilder::new(.., id(1), id(2), ..)).
// The auth proof needs distinct senders: the administrator, a role holder that is not one, and a
// stranger holding nothing.
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn stranger() -> AccountId {
    test_account_id(9)
}

const MAX_SUPPLY: u64 = 1_000_000;

/// The identifier key derived from the faucet's own account id — the only value `init_identifier`
/// will accept.
///
/// The procedure recomputes this on-chain from `get_id()` and requires the value committed in the
/// note to match before it writes anything, so this is computed here the same way rather than
/// pinned as a literal.
fn own_identifier(gm: &GuardedMint) -> Word {
    XReserveIdentifierInitNote::identifier_for(gm.harness.account_id)
}

/// A well-formed but FOREIGN identifier word — never the faucet's own-id key. Drives the
/// owner-gate negatives (which trap BEFORE the value is inspected) and the mismatch negative.
fn foreign_identifier() -> Word {
    Word::from([11u32, 12, 13, 14])
}

/// The domain-config state a freshly built faucet has before any init runs: the three fields the
/// builder seeds (domain, source domain, and the xReserve contract address packed into two words of
/// u32 limbs) plus an empty identifier slot.
///
/// Tests compare against this to prove a rejected init wrote nothing at all.
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

/// A production-composed faucet in exactly the state a real deployment is in before its first
/// init: the attestation mint policy active, the roles seeded, the domain config
/// build-seeded, and the identifier slot still empty.
fn uninit_identifier_faucet() -> Result<GuardedMint> {
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        MAX_SUPPLY,
        0,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        Word::empty(), // the identifier ships empty — the init note is its only writer
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

// THE FACTORY BINDS THE IDENTIFIER TO ITS TARGET FAUCET — the note can only carry that faucet's own key
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
    let note = XReserveIdentifierInitNote::create(administrator(), fa, &mut note_rng(1))?;
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

// THE BUILD SEED ITSELF — the four config words the builder writes, pinned before any init runs
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

// WRITE INTEGRITY — the administrator's init writes the identifier verbatim and NOTHING else
// ================================================================================================

/// The administrator's `identifier_init` with the faucet's OWN-id key succeeds, stores that Word, and
/// leaves the four build-seeded config words byte-identical (before == after) — the minimized
/// init touches ONLY the identifier slot, and the stored value IS the on-chain-derived fixpoint.
#[tokio::test]
async fn identifier_init_administrator_writes_the_own_id_key() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);
    let before = read_domain_config_words(&account)?;

    let executed = run_identifier_init_tx(
        &gm.harness,
        &account,
        administrator(),
        own_identifier(&gm),
        1,
    )
    .await
    .expect("the administrator's identifier_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(executed.account_patch())?;

    let after = read_domain_config_words(&evolved)?;
    assert_eq!(
        after[4],
        own_identifier(&gm),
        "identifier slot must hold the faucet's own-id fixpoint key"
    );
    assert_eq!(
        after[..4],
        before[..4],
        "the four build-seeded config words must be UNCHANGED by the init (identifier-only write)"
    );
    Ok(())
}

// OWN-ID BINDING — the procedure will only write the identifier derived from its own account id
// ================================================================================================

/// An init carrying any identifier other than the faucet's own traps and writes nothing.
///
/// Even sent by the administrator, a foreign value is refused: the procedure derives the expected key
/// on-chain from its own account id and requires the note's committed word to equal it. That
/// closes the deploy-time griefing window — a freshly deployed faucet's init is open to whoever
/// gets there first, but the only thing anyone can write is the identifier the faucet was always
/// going to have, so a front-run cannot bind it to a foreign identity.
#[tokio::test]
async fn identifier_init_foreign_identifier_rejects() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let result = run_identifier_init_tx(
        &gm.harness,
        &account,
        administrator(),
        foreign_identifier(),
        8,
    )
    .await;
    assert_transaction_executor_error!(
        result,
        shell_error_by_name("ERR_XRESERVE_IDENTIFIER_MISMATCH")
    );

    // no-write proof: a trapped tx commits nothing; the config stays the exact build-seed, so
    // the administrator's own-id init on the same account still succeeds (the sentinel stayed unarmed).
    assert_eq!(
        read_domain_config_words(&account)?,
        pre_init_config(),
        "a rejected foreign-identifier init must write nothing"
    );
    run_identifier_init_tx(
        &gm.harness,
        &account,
        administrator(),
        own_identifier(&gm),
        9,
    )
    .await
    .expect("the own-id init proves the rejected foreign init left the sentinel unarmed");
    Ok(())
}

// INIT-ONCE — once the identifier is set, a second write traps and changes nothing
// ================================================================================================

/// First `identifier_init` succeeds; a SECOND — even from the administrator, with a different value —
/// traps the EXACT ERR_XRESERVE_IDENTIFIER_REINIT (the identifier slot IS the init-once
/// sentinel) and leaves all five config words unchanged.
#[tokio::test]
async fn identifier_init_reinit_traps_and_leaves_config_unchanged() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let first = run_identifier_init_tx(
        &gm.harness,
        &account,
        administrator(),
        own_identifier(&gm),
        1,
    )
    .await
    .expect("first identifier_init must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(first.account_patch())?;
    let before = read_domain_config_words(&evolved)?;
    assert_eq!(
        before[4],
        own_identifier(&gm),
        "the first init must have armed the sentinel"
    );

    // A second init with a DIFFERENT identifier traps REINIT (the sentinel is read BEFORE the
    // own-id compare, so the init-once error wins over the mismatch) and touches nothing.
    let result = run_identifier_init_tx(
        &gm.harness,
        &evolved,
        administrator(),
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

/// Initializing with the empty Word traps and writes nothing.
///
/// The empty Word is what an uninitialized slot already reads as, so writing it would leave the
/// slot re-initializable forever — the init-once check has no other way to tell "set" from "not
/// set". It would also leave every incoming deposit's `remoteToken` being compared against
/// nothing. Rejecting it outright removes both problems.
#[tokio::test]
async fn identifier_init_empty_identifier_traps() -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let result =
        run_identifier_init_tx(&gm.harness, &account, administrator(), Word::empty(), 1).await;
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

// ADMINISTRATOR-SPECIFIC AUTH — a role holder who is not the administrator and a stranger both reject
// ================================================================================================

/// Shared body of the non-administrator reject family: the sender traps the EXACT role error the
/// account-wide authority raises, and writes nothing (the config stays the pre-init build-seed).
async fn assert_identifier_init_nonadmin_rejects(sender: AccountId, seed: u64) -> Result<()> {
    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);

    let result =
        run_identifier_init_tx(&gm.harness, &account, sender, foreign_identifier(), seed).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_domain_config_words(&account)?,
        pre_init_config(),
        "a rejected non-administrator init must write nothing"
    );
    Ok(())
}

/// A seeded DOM role holder (id(2), DOM_PAUSER) rejects — `identifier_init` resolves through the
/// account-wide authority to the built-in administrator role, which the Domain pauser does not
/// hold. The administrator's follow-up init on the SAME account still succeeds, proving the
/// rejected tx left the sentinel unarmed (had it written, this would trap
/// ERR_XRESERVE_IDENTIFIER_REINIT).
#[tokio::test]
async fn identifier_init_dom_pauser_rejects() -> Result<()> {
    assert_identifier_init_nonadmin_rejects(dom_pauser(), 3).await?;

    let gm = uninit_identifier_faucet()?;
    let account = faucet_account(&gm.harness);
    let rejected =
        run_identifier_init_tx(&gm.harness, &account, dom_pauser(), foreign_identifier(), 3).await;
    assert_transaction_executor_error!(rejected, err_sender_lacks_role());
    run_identifier_init_tx(
        &gm.harness,
        &account,
        administrator(),
        own_identifier(&gm),
        4,
    )
    .await
    .expect("the administrator write proves the rejected tx left the sentinel unarmed");
    Ok(())
}

/// A stranger (id(9), holding no role at all) rejects with the EXACT role error and writes
/// nothing.
#[tokio::test]
async fn identifier_init_stranger_rejects() -> Result<()> {
    assert_identifier_init_nonadmin_rejects(stranger(), 5).await
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
    let executed = run_identifier_init_tx(
        &gm.harness,
        &evolved,
        administrator(),
        own_identifier(&gm),
        7,
    )
    .await
    .expect("identifier_init must succeed while paused (deploy-time config is not pause-gated)");
    evolved.apply_patch(executed.account_patch())?;
    assert_eq!(
        read_domain_config_words(&evolved)?[4],
        own_identifier(&gm),
        "the paused-state init wrote the identifier"
    );
    assert_eq!(
        read_is_paused(&evolved)?,
        Word::from([1u32, 0, 0, 0]),
        "the faucet stays paused across identifier_init"
    );
    Ok(())
}
