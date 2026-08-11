//! Role management: who may appoint and remove the Domain Pauser.
//!
//! Circle's admin model has two roles. The Domain Pauser can halt the faucet; the Domain Manager
//! rotates who holds that role. Neither is the administrator, and the split is the point — an operator can
//! be given the ability to appoint pausers without being given the ability to pause, or to spend.
//!
//! The delegation is seeded at BUILD time, not configured at runtime. The builder writes the Domain
//! Pauser's role config as "one member, administered by the Domain Manager", which is byte-identical
//! to what a runtime `set_role_admin(DOM_PAUSER, DOM_MANAGER)` would have left behind. The Domain
//! Manager in turn is administered by the built-in admin role, whose membership the builder seeds on
//! the administrator's account — so Circle's requirement that the top of the tree remain the backstop
//! is met by reaching the Pauser through the Manager, not by any override.
//!
//! Role management runs on the standard role-action note, whose single script root carries grant,
//! revoke, set-role-admin and renounce alike. So the graph seeded at build time is a starting point
//! rather than a permanent one: each role's effective administrator can re-point the role it
//! administers, and because delegation is exclusive, the admin role has no authority over a role
//! that was delegated away. What that note admits is covered by `w2admin_surface_finalization.rs`;
//! what this file covers is the rotation the faucet actually performs. Every role-administration
//! procedure used here is the standard access-control code the account already exposes; the faucet
//! ships no custom MASM for roles at all.
//!
//! The load-bearing proof is a CAPABILITY seam, never a config read-back on its own. A config word
//! with the right bytes proves nothing if the gate that reads it is wired differently. So: after the
//! Domain Manager grants the role to a new account, that account's pause must actually HALT a real
//! attested mint, trapping the standard paused error; after the Manager revokes it, the same
//! account's pause must be rejected for lacking the role. The administrator's backstop is asserted the same
//! way — as pause power genuinely gained and lost through the two-hop chain — not as a storage read.
//!
//! One consequence worth stating plainly: the admin membership is bound to an ACCOUNT, and the
//! faucet has no ownership handshake that could move it implicitly. Rotating the administrator is a
//! grant to the incoming account and a revoke from the outgoing one, and the operational runbook
//! grants before it revokes so there is never a window with no administrator at all.
//!
//! Fixture rule: every test here runs against an account composed by the real production builder —
//! the seed and backstop pins via the guarded-mint fixture, the capability seams via the full
//! production faucet. The support harness's replica account is used by no test in this file; its
//! fidelity to the production seed is pinned separately in
//! `set_min_burn.rs::support_replica_carries_delegation_seed`.

mod support;

use anyhow::{Context, Result};
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{AccountId, RoleSymbol};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::note::{RbacAction, RbacActionNote};
use miden_testing::assert_transaction_executor_error;
use miden_tx::TransactionExecutorError;
use support::*;
use xusdc_encoding::account::xreserve::{DOM_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_mint::{MintAttestation, XUsdcMintNote};
use xusdc_encoding::vectors::{load, MiVector};
use xusdc_encoding::xreserve::encoding::account_id_to_bytes32;

// The production builder seeds the administrator = id(1) (the sole ADMIN member), DOM_PAUSER =
// id(2), DOM_MANAGER = id(3).
// id(4)/id(5) are fresh member candidates the rotation grants.
fn administrator() -> AccountId {
    test_account_id(1)
}
fn dom_pauser() -> AccountId {
    test_account_id(2)
}
fn dom_manager() -> AccountId {
    test_account_id(3)
}
fn new_pauser() -> AccountId {
    test_account_id(4)
}
fn second_pauser() -> AccountId {
    test_account_id(5)
}

// The fixed role aliases, via the production Rust constants (builder.rs) — the single source the
// seed, the notes, and the read-backs all share.
fn pauser_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (<=12)")
}
fn manager_sym() -> RoleSymbol {
    RoleSymbol::new(DOM_MANAGER_ROLE).expect("DOM_MANAGER is a fixed valid role symbol (<=12)")
}

// The exact stock errors these tests pin (assert-specific-error-in-tests; read from the pinned
// rbac.masm:50-51 / the stock pausable).
fn err_paused() -> MasmError {
    MasmError::from_static_str("the contract is paused")
}
fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}
fn err_not_role_admin() -> MasmError {
    // v16 #3215: the administrator path is gone from the stock component — the error re-keyed from
    // ERR_SENDER_NOT_OWNER_OR_ROLE_ADMIN to ERR_SENDER_NOT_ROLE_ADMIN (rbac.masm:66).
    MasmError::from_static_str("note sender does not hold the role's admin role")
}

// PRODUCTION FIXTURES (both compose via XReserveStablecoinBuilder::build_components — never the
// burn-oracle replica). Recreated from public support helpers per the established per-file pattern
// (set_attester.rs `guarded_faucet`, pause_admin.rs `guarded_mint_ready` are private to their files).
// ================================================================================================

/// Placeholder domain configuration. These tests reach the account through role-administration
/// notes and never run a mint, so nothing ever reads these words — they exist because the fixture
/// requires a value.
fn dummy_config() -> Word {
    Word::from([7u32, 0, 0, 0])
}

/// A do-nothing component that satisfies the shared fixture's requirement for a driver.
///
/// The gating tests never invoke it — they drive the account through notes — so it only has to
/// compile.
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

/// The LEAN production faucet — the base for the gating-matrix cells that never execute a mint.
fn production_faucet() -> Result<GuardedMint> {
    let driver = placeholder_driver_src();
    let probe = composition_supply_probe_src(0);
    let domain = dummy_config();
    setup_guarded_mint_account(
        GuardSelection::ProductionAttestation,
        1_000_000,
        0,
        domain,
        None,
        None,
        &driver,
        &probe,
        true,
    )
}

// FIXTURES FOR THE CAPABILITY SEAMS — a real attested mint through the real note transport, so a
// pause can be shown to halt something that would otherwise succeed (same shape as mint_policy_e2e.rs)
// ================================================================================================

// the DC-14 rows are the ones whose localToken / localDepositor are address-shaped,
// which the mint transport requires
const BASE_VECTOR: &str = "mi-pos-empty-hookdata";
const MINT_MAX_SUPPLY: u64 = 1_000_000_000_000;
const MINT_AMOUNT: u64 = 250_000_000;
const MAX_FEE_RAW: u64 = 1;

/// Byte offset of the 32-byte `remoteRecipient` field in a DepositIntent (felt 19, 4 bytes/felt).
const REMOTE_RECIPIENT_BYTE_OFF: usize = 19 * 4;
/// Byte offset of the 32-byte `remoteToken` field in a DepositIntent (felt 11, 4 bytes/felt).
const REMOTE_TOKEN_BYTE_OFF: usize = 11 * 4;
/// Byte offset of the 32-byte `nonce` field in a DepositIntent (felt 51, 4 bytes/felt).
const NONCE_BYTE_OFF: usize = 51 * 4;

fn mi(id: &str) -> &'static MiVector {
    load()
        .families
        .mi
        .iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("canonical artifact is missing mp vector {id}"))
}

/// The canonical accept payload with the wire amount / maxFee spliced in, `remoteRecipient`
/// replaced by the real recipient wallet, `remoteToken` replaced by
/// `account_id_to_bytes32(faucet_id)` (the own-id key the mint path derives, so the identifier
/// compare passes), and one nonce byte perturbed per variant so each mint consumes
/// a nonce the replay guard has not seen.
fn payload_for(
    recipient: AccountId,
    amount: u64,
    nonce_variant: u8,
    faucet_id: AccountId,
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

/// Deterministic note rng for the production admin/mint notes (serial only; never affects a gate).
fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is derived from `seed` so note ids stay stable; the gate reads the sender, never the
/// serial or the tag.
fn role_action_note(
    sender: AccountId,
    faucet_id: AccountId,
    action: RbacAction,
    seed: u32,
) -> Result<Note> {
    let note = RbacActionNote::builder()
        .sender(sender)
        .account(faucet_id)
        .action(action)
        .serial_number(Word::from([seed, 3, 4, 5]))
        .build()
        .map_err(|e| anyhow::anyhow!("building the standard role-action note: {e}"))?;
    Ok(Note::from(note))
}

/// A standard role-action note granting the Domain Pauser role to `member`.
fn grant_role_note(
    sender: AccountId,
    faucet_id: AccountId,
    member: AccountId,
    seed: u32,
) -> Result<Note> {
    role_action_note(
        sender,
        faucet_id,
        RbacAction::GrantRole {
            role: pauser_sym(),
            account: member,
        },
        seed,
    )
}

/// A standard role-action note revoking the Domain Pauser role from `member`.
fn revoke_role_note(
    sender: AccountId,
    faucet_id: AccountId,
    member: AccountId,
    seed: u32,
) -> Result<Note> {
    role_action_note(
        sender,
        faucet_id,
        RbacAction::RevokeRole {
            role: pauser_sym(),
            account: member,
        },
        seed,
    )
}

/// Brings up a production faucet ready to run a real mint, for the tests that check what a
/// rotated role can and cannot do.
///
/// It uses the real note transport and the account's own network authentication, allowlists one
/// attester, and adds whatever extra admin notes the caller needs. Everything is seeded at genesis so each admin transaction can be proved
/// into its own block. The same shape is used by `mint_policy_e2e.rs`.
fn mint_fixture(extra_notes: impl Fn(AccountId) -> Vec<Note>) -> Result<ProductionFaucet> {
    setup_production_faucet(MINT_MAX_SUPPLY, 0, |recipient, faucet_id| {
        let commitment =
            gen_attester(1, &payload_for(recipient, MINT_AMOUNT, 0, faucet_id)).commitment;
        let route = faucet_id;
        let mut notes = vec![XReserveSetAttesterNote::create(
            administrator(),
            route,
            commitment,
            1,
            &mut note_rng(952),
        )
        .expect("building the administrator set_attester note")];
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

/// Consumes a committed (seeded) note on the faucet, returning the raw result so callers assert
/// success or the exact trap. A REJECTED consume leaves the note unspent, so the SAME note can be
/// re-consumed after a capability change — exactly the rotation-seam artifact.
async fn consume_note(
    pf: &ProductionFaucet,
    note: &Note,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    pf.mock_chain
        .build_transaction(pf.faucet_id)
        .authenticated_input_note(note.id())
        .build()
        .expect("building the consume tx")
        .execute()
        .await
}

/// Consumes a committed note expecting success, committing a block.
async fn consume_and_commit(pf: &mut ProductionFaucet, note: &Note, what: &str) -> Result<()> {
    let tx = consume_note(pf, note)
        .await
        .map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    pf.mock_chain.add_pending_executed_transaction(&tx)?;
    pf.mock_chain.prove_next_block()?;
    Ok(())
}

/// Builds, emits, and consumes the REAL stock mint note over an attested payload (the production
/// `XUsdcMintNote` factory transport), returning the consume result.
async fn emit_and_consume_mint(
    pf: &mut ProductionFaucet,
    payload: &[u8],
    rng_seed: u64,
) -> Result<std::result::Result<ExecutedTransaction, TransactionExecutorError>> {
    let attester = gen_attester(1, payload);
    let note = XUsdcMintNote::create(
        pf.producer_id,
        pf.faucet_id,
        payload,
        &MintAttestation::new(attester.sig_bytes, attester.pubkey_bytes),
        &mut note_rng(rng_seed),
    )
    .map_err(|e| anyhow::anyhow!("building the attested stock mint note: {e}"))?;
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

// THE ROTATION SEAMS (RED) — role administration must change REAL pause capability, end-to-end
// ================================================================================================

/// THE grant seam (the Domain Manager rotates the Pauser): before the grant, id(4) has no
/// pause power (exact role trap on the seeded production pause note); a DOM_MANAGER-sent
/// `grant_role(DOM_PAUSER, id4)` then flips REAL capability — the SAME pause note (left unspent by
/// the rejected consume) now succeeds, and id(4)'s pause HALTS a real attested mint (the
/// recomposed stock-`MintNote` transport) at the exact `ERR_PAUSABLE_IS_PAUSED`.
#[tokio::test]
async fn dom_manager_grants_pauser_then_new_pauser_halts_mint() -> Result<()> {
    let mut pf = mint_fixture(|_| {
        vec![
            grant_role_note(dom_manager(), test_faucet_id(1), new_pauser(), 31)
                .expect("building the DOM_MANAGER grant_role note"),
            stock_pause_note(new_pauser(), test_faucet_id(1), 32)
                .expect("building the candidate's pause note"),
        ]
    })?;
    bring_up(&mut pf, 1).await?; // set_attester
    let grant_note = pf.seeded_notes[1].clone();
    let pause_note = pf.seeded_notes[2].clone();

    // Pre-grant: the candidate's pause REJECTS — the capability is genuinely absent before the grant.
    let pre = consume_note(&pf, &pause_note).await;
    assert_transaction_executor_error!(pre, err_sender_lacks_role());

    // The DOM_MANAGER holder grants DOM_PAUSER to id(4) (the delegated operational rotation path).
    consume_and_commit(
        &mut pf,
        &grant_note,
        "the delegated DOM_MANAGER grant must pass (DOM_PAUSER.admin_role == DOM_MANAGER)",
    )
    .await?;
    let faucet = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_role_membership(&faucet, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed the membership flag"
    );

    // The SAME pause note now succeeds...
    consume_and_commit(
        &mut pf,
        &pause_note,
        "the newly granted DOM_PAUSER member's pause must succeed",
    )
    .await?;

    // ...and HALTS the real attested mint at the exact stock pause error — the capability change
    // is REAL.
    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 1, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 33).await?;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

/// The revoke seam: a DOM_MANAGER-sent `revoke_role(DOM_PAUSER, id2)` strips the SEEDED pauser's
/// power — the revoked member's pause REJECTS the exact `ERR_SENDER_LACKS_ROLE` and `is_paused`
/// stays untouched. Also pins the stock revoke effects (membership cleared, member_count 1 -> 0,
/// the delegation RETAINED in the config — rbac.rs:79-82). RED: the revoke itself traps (no delegation).
#[tokio::test]
async fn dom_manager_revokes_pauser_then_pause_rejects() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        dom_manager(),
        &pauser_sym(),
        dom_pauser(),
        34,
    )
    .await
    .expect("the delegated DOM_MANAGER revoke passes (DOM_PAUSER.admin_role == DOM_MANAGER)");
    let mut evolved = account.clone();
    evolved.apply_patch(revoked.account_patch())?;

    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), dom_pauser())?[0],
        Felt::ZERO,
        "the revoked member's membership flag is cleared"
    );
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(
        config[0],
        Felt::ZERO,
        "DOM_PAUSER member_count decremented to 0"
    );
    assert_eq!(
        config[1],
        Felt::from(&manager_sym()),
        "the delegation survives the last-member revoke (admin config retained)"
    );

    // The revoked member's pause now REJECTS with the exact role error; is_paused is unchanged.
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 35).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed pause leaves is_paused untouched"
    );
    Ok(())
}

/// The FULL rotation, revoke-FIRST (the ordering that must survive the empty role): DOM_MANAGER
/// revokes the incumbent id(2) (member_count -> 0), THEN grants the successor id(4) — possible only
/// because the admin config is retained when the last member is revoked (rbac.rs:79-82; a wiped
/// delegation would deadlock rotation). The OLD pauser's pause rejects; the NEW pauser's pause HALTS
/// a real attested mint (the recomposed stock-`MintNote` transport).
#[tokio::test]
async fn dom_manager_rotates_pauser_revoke_then_grant() -> Result<()> {
    let mut pf = mint_fixture(|_| {
        let route = test_faucet_id(1);
        vec![
            revoke_role_note(dom_manager(), route, dom_pauser(), 36)
                .expect("building the DOM_MANAGER revoke_role note"),
            grant_role_note(dom_manager(), route, new_pauser(), 37)
                .expect("building the DOM_MANAGER grant_role note"),
            stock_pause_note(dom_pauser(), route, 38)
                .expect("building the OLD pauser's pause note"),
            stock_pause_note(new_pauser(), route, 39)
                .expect("building the NEW pauser's pause note"),
        ]
    })?;
    bring_up(&mut pf, 1).await?; // set_attester
    let revoke_note = pf.seeded_notes[1].clone();
    let grant_note = pf.seeded_notes[2].clone();
    let old_pause_note = pf.seeded_notes[3].clone();
    let new_pause_note = pf.seeded_notes[4].clone();

    consume_and_commit(
        &mut pf,
        &revoke_note,
        "the rotation's revoke leg must pass under the delegation",
    )
    .await?;
    consume_and_commit(
        &mut pf,
        &grant_note,
        "the rotation's grant leg must pass through the empty role (admin config retained)",
    )
    .await?;

    // The OLD pauser's pause rejects — rotation genuinely removed the incumbent's power.
    let old = consume_note(&pf, &old_pause_note).await;
    assert_transaction_executor_error!(old, err_sender_lacks_role());

    // The NEW pauser pauses, and the pause halts a REAL attested mint.
    consume_and_commit(
        &mut pf,
        &new_pause_note,
        "the rotated-in DOM_PAUSER member's pause must succeed",
    )
    .await?;
    let payload = payload_for(pf.recipient_id, MINT_AMOUNT, 2, pf.faucet_id);
    let result = emit_and_consume_mint(&mut pf, &payload, 40).await?;
    assert_transaction_executor_error!(result, err_paused());
    Ok(())
}

// THE SHIPPED DELEGATION SEED — what the builder wrote, read back off a production account
// ================================================================================================

/// The shipped-build provenance read-back — against the PRODUCTION `XReserveStablecoinBuilder`
/// account (NOT the burn-oracle support replica; that is pinned separately in
/// `set_min_burn.rs::support_replica_carries_delegation_seed`). Supplementary to the capability
/// seams above (the only config-word-level assertion in this file). RED: the production seed still
/// writes `admin_role = 0`.
#[tokio::test]
async fn shipped_delegation_reads_back() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let pauser_config = read_role_config(&account, &pauser_sym())?;
    assert_eq!(
        pauser_config[0],
        Felt::from(1u32),
        "DOM_PAUSER member_count == 1"
    );
    assert_eq!(
        pauser_config[1],
        Felt::from(&manager_sym()),
        "DOM_PAUSER.admin_role == DOM_MANAGER (the CMP-F5 delegation, seeded at build)"
    );
    assert_eq!(
        pauser_config[2],
        Felt::ZERO,
        "DOM_PAUSER config felt 2 is zero"
    );
    assert_eq!(
        pauser_config[3],
        Felt::ZERO,
        "DOM_PAUSER config felt 3 is zero"
    );

    assert_eq!(
        read_role_config(&account, &manager_sym())?,
        Word::from([Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "DOM_MANAGER stays ADMIN-administered (the seeded owner account's account-bound membership): [member_count=1, admin_role=0, 0, 0]"
    );

    assert_eq!(
        read_role_membership(&account, &pauser_sym(), dom_pauser())?[0],
        Felt::from(1u32),
        "the seeded DOM_PAUSER member id(2) is unchanged"
    );
    assert_eq!(
        read_role_membership(&account, &manager_sym(), dom_manager())?[0],
        Felt::from(1u32),
        "the seeded DOM_MANAGER member id(3) is unchanged"
    );
    Ok(())
}

// THE OWNER BACKSTOP (GREEN pins) — Circle's onlyOwner rotation authority, asserted POSITIVE
// ================================================================================================

/// The Circle top-of-tree BACKSTOP as a POSITIVE: the administrator
/// ACCOUNT holds the stock `ADMIN` role (an account-bound membership — it does not auto-follow an
/// account, so a handover re-seats it by grant then revoke), which is DOM_MANAGER's effective admin (
/// the implicit owner super-admin; `admin_role = 0` now resolves to `ADMIN`, rbac.masm:427-438).
/// The ADMIN-holding owner therefore rotates the MANAGER, and the manager rotates the PAUSER —
/// the same ultimate authority, one hop longer. Capability-level: the chain ends in a REAL pause by an
/// owner-rooted member (`is_paused` flips), not a config read-back.
#[tokio::test]
async fn administrator_can_still_grant_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // Hop 1: the administrator (ADMIN member) grants DOM_MANAGER to a new account.
    let granted_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        administrator(),
        &manager_sym(),
        second_pauser(),
        40,
    )
    .await
    .expect("the administrator backstop grant of DOM_MANAGER passes (it holds ADMIN)");
    let mut evolved = account.clone();
    evolved.apply_patch(granted_manager.account_patch())?;

    // Hop 2: the administrator-installed manager grants DOM_PAUSER to a new pauser.
    let granted_pauser = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        second_pauser(),
        &pauser_sym(),
        new_pauser(),
        41,
    )
    .await
    .expect("the administrator-installed DOM_MANAGER grants DOM_PAUSER (CMP-F5 delegation)");
    evolved.apply_patch(granted_pauser.account_patch())?;

    let paused = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, new_pauser(), 42)
        .await
        .expect("the administrator-rooted member pauses the faucet");
    evolved.apply_patch(paused.account_patch())?;
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::from(1u32),
        "the administrator-rooted pauser's pause is REAL (is_paused flipped)"
    );
    Ok(())
}

/// The backstop's other direction — the v15 proof re-expressed through the v16 authority chain,
/// ending (as it must) in a REAL loss of pause authority by an EXISTING pauser: the administrator (ADMIN
/// member) grants itself DOM_MANAGER — DOM_PAUSER's effective admin — then, so
/// empowered, REVOKES DOM_PAUSER from the seeded pauser id(2); that pauser's pause is then
/// REJECTED with the exact role error and `is_paused` never flips. The (seeded-ADMIN-member)
/// administrator therefore retains Circle's backstop ability to strip a live pauser, one hop longer than
/// (the membership is bound to the account, so an administratorship handover has to re-seat it).
#[tokio::test]
async fn administrator_can_still_revoke_pauser() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // Hop 1: the administrator (ADMIN member) takes DOM_MANAGER — DOM_PAUSER's effective admin.
    let self_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        administrator(),
        &manager_sym(),
        administrator(),
        42,
    )
    .await
    .expect("the administrator (ADMIN member) grants itself DOM_MANAGER");
    let mut evolved = account.clone();
    evolved.apply_patch(self_manager.account_patch())?;

    // Hop 2: now DOM_MANAGER-holding, the administrator revokes the SEEDED pauser id(2)'s DOM_PAUSER.
    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &evolved,
        administrator(),
        &pauser_sym(),
        dom_pauser(),
        43,
    )
    .await
    .expect("the DOM_MANAGER-holding administrator revokes the seeded pauser's DOM_PAUSER");
    evolved.apply_patch(revoked.account_patch())?;

    // The REAL loss of authority: the revoked pauser's pause is rejected and is_paused stays 0.
    let result = run_dom_pauser_pause(&gm.harness.mock_chain, &evolved, dom_pauser(), 44).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "the revoked pauser's failed pause leaves is_paused untouched"
    );
    Ok(())
}

/// The backstop's OTHER lever (v16, additive): the administrator (ADMIN member) can CUT the delegation
/// chain outright — revoking DOM_MANAGER from the seeded manager id(3) leaves that holder unable
/// to administer DOM_PAUSER at all (the exact role-admin error). Complements
/// [`administrator_can_still_revoke_pauser`], which strips an existing pauser directly.
#[tokio::test]
async fn administrator_can_revoke_dom_manager_cutting_the_delegation_chain() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    let revoked = run_revoke_role_against(
        &gm.harness.mock_chain,
        &account,
        administrator(),
        &manager_sym(),
        dom_manager(),
        45,
    )
    .await
    .expect("the administrator backstop revoke of DOM_MANAGER passes (it holds ADMIN)");
    let mut evolved = account.clone();
    evolved.apply_patch(revoked.account_patch())?;

    let denied = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        46,
    )
    .await;
    assert_transaction_executor_error!(denied, err_not_role_admin());
    assert_eq!(
        read_is_paused(&evolved)?[0],
        Felt::ZERO,
        "a failed grant leaves is_paused untouched"
    );
    Ok(())
}

// DELEGATION SEED SEMANTICS (proc-level characterization) — the seed is stock-config-shaped state
// ================================================================================================

/// PROC-LEVEL CHARACTERIZATION (permissive-auth fixture): the seeded delegation word is exactly
/// the state the stock procs operate on — the (DOM_MANAGER-holding) owner CLEARS it
/// (`set_role_admin(DOM_PAUSER, 0)`) and a DOM_MANAGER grant REJECTS; re-SETTING it makes the same
/// grant SUCCEED. `member_count` is preserved through both `set_role_admin` writes
/// (rbac.masm:168-174). This proves the build seed is byte-faithful stock-RBAC state; the deployed
/// graph is rotatable from that seed too, since the standard role-action note carries
/// `set_role_admin`.
#[tokio::test]
async fn administrator_reaches_set_role_admin_through_dom_manager() -> Result<()> {
    let gm = production_faucet()?;
    let account = faucet_account(&gm.harness);

    // `set_role_admin(DOM_PAUSER)` is gated on DOM_PAUSER's effective admin
    // (DOM_MANAGER), so the administrator reaches it by first granting ITSELF DOM_MANAGER — which it may
    // do as the ADMIN member (DOM_MANAGER's own effective admin). Two hops, same end authority.
    let self_manager = run_grant_role_against(
        &gm.harness.mock_chain,
        &account,
        administrator(),
        &manager_sym(),
        administrator(),
        52,
    )
    .await
    .expect("the administrator (ADMIN member) grants itself DOM_MANAGER");
    let mut evolved = account.clone();
    evolved.apply_patch(self_manager.account_patch())?;

    // Now DOM_MANAGER-holding, the administrator clears the delegation (admin_role -> 0).
    let cleared = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &evolved,
        administrator(),
        &pauser_sym(),
        None,
        53,
    )
    .await
    .expect("the DOM_MANAGER-holding owner clears the DOM_PAUSER delegation");
    evolved.apply_patch(cleared.account_patch())?;
    let config = read_role_config(&evolved, &pauser_sym())?;
    assert_eq!(config[1], Felt::ZERO, "the delegation is cleared");
    assert_eq!(
        config[0],
        Felt::from(1u32),
        "member_count is preserved through set_role_admin"
    );

    // With the delegation cleared, the DOM_MANAGER holder can no longer grant.
    let denied = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        54,
    )
    .await;
    assert_transaction_executor_error!(denied, err_not_role_admin());

    // The administrator re-delegates; the DOM_MANAGER grant now passes.
    let reset = run_set_role_admin_against(
        &gm.harness.mock_chain,
        &evolved,
        administrator(),
        &pauser_sym(),
        Some(&manager_sym()),
        55,
    )
    .await
    .expect("the administrator re-delegates DOM_PAUSER administration to DOM_MANAGER");
    evolved.apply_patch(reset.account_patch())?;
    assert_eq!(
        read_role_config(&evolved, &pauser_sym())?[1],
        Felt::from(&manager_sym()),
        "the delegation is restored"
    );

    let granted = run_grant_role_against(
        &gm.harness.mock_chain,
        &evolved,
        dom_manager(),
        &pauser_sym(),
        new_pauser(),
        56,
    )
    .await
    .expect("with the delegation in place the DOM_MANAGER grant passes");
    evolved.apply_patch(granted.account_patch())?;
    assert_eq!(
        read_role_membership(&evolved, &pauser_sym(), new_pauser())?[0],
        Felt::from(1u32),
        "the delegated grant landed"
    );
    Ok(())
}
