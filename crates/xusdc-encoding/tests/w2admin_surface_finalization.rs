//! The finalized admin surface: pure role-based administration, driven by the standard notes.
//!
//! Two changes land together here. The two-step ownership component is gone, so there is no owner
//! slot and no ownership handshake: every administrator-gated procedure resolves through the
//! account-wide authority to the administrator role, whose member is the account that used to hold
//! the administrator slot. The identifier initializer moved onto that same gate — it was the one faucet-owned
//! procedure still reading the administrator slot directly, and with the component dropped it would have
//! read a slot the account no longer declares.
//!
//! Role management moved to the standard role-action note. It carries four actions behind one
//! script root — grant, revoke, re-point a role's administrator, and renounce — and admitting the
//! root admits all four. The role graph is therefore runtime-mutable, which is a deliberate change
//! from the build-seeded frozen graph the faucet shipped with. The tests below drive each of the
//! four actions against the real faucet so what the composition now permits is on the record.
//!
//! Everything runs against the SHIPPED composition — the same components the deploy path builds and
//! the same keyless network auth — so nothing here can pass on a fixture that flatters the change.

mod support;

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountId, RoleSymbol, StorageMapKey, StorageSlotName};
use miden_protocol::note::{Note, NoteScriptRoot};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Ownable2Step, RoleBasedAccessControl};
use miden_standards::note::{
    BlocklistConfigNote, BurnNote, MintNote, PauseActionNote, RbacAction, RbacActionNote,
};
use miden_testing::assert_transaction_executor_error;
use support::w2admin::*;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, IDENTIFIER_CONFIG_SLOT_LABEL, XRESERVE_ATTESTERS_SLOT_LABEL,
};
use xusdc_encoding::note::xreserve_admin::{
    XReserveIdentifierInitNote, XReserveSetAttesterNote, XReserveSetMaxSupplyNote,
    XReserveSetMinBurnSizeNote,
};

const MAX_SUPPLY: u64 = 1_000_000;

// READERS AND FIXTURES
// ================================================================================================

/// The administrator role symbol configured for `role`. Zero means unset, which the standard
/// component resolves to the built-in administrator role.
fn read_role_admin(account: &Account, role: &RoleSymbol) -> Result<Felt> {
    Ok(read_role_config(account, role)?[1])
}

/// The member count recorded for `role`.
fn read_role_member_count(account: &Account, role: &RoleSymbol) -> Result<Felt> {
    Ok(read_role_config(account, role)?[0])
}

fn read_role_config(account: &Account, role: &RoleSymbol) -> Result<Word> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_config_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading role_config[{role}]: {e}"))
}

/// Whether `member` holds `role`.
fn read_role_membership(account: &Account, role: &RoleSymbol, member: AccountId) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::from(role),
        member.suffix(),
        member.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_membership_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading role_membership[{role}][{member}]: {e}"))
}

/// The attester allowlist entry for `commitment`.
fn read_attester(account: &Account, commitment: Word) -> Result<Word> {
    let slot = StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
        .context("the attester slot label is a valid constant")?;
    account
        .storage()
        .get_map_item(&slot, StorageMapKey::new(commitment))
        .map_err(|e| anyhow::anyhow!("reading xReserveAttesters[{commitment}]: {e}"))
}

/// The identifier config slot word.
fn read_identifier(account: &Account) -> Result<Word> {
    let slot = StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
        .context("the identifier slot label is a valid constant")?;
    account
        .storage()
        .get_item(&slot)
        .map_err(|e| anyhow::anyhow!("reading the identifier slot: {e}"))
}

/// A standard role-action note carrying `action`, sent by `sender` and tagged for `faucet_id`. The
/// serial is derived from `seed` so note ids stay stable; authorization rides on the sender.
fn role_note(
    sender: AccountId,
    faucet_id: AccountId,
    action: RbacAction,
    seed: u32,
) -> Result<Note> {
    let note = RbacActionNote::builder()
        .sender(sender)
        .account(faucet_id)
        .action(action)
        .serial_number(Word::from([seed, 53, 59, 61]))
        .build()
        .map_err(|e| anyhow::anyhow!("building the standard role-action note: {e}"))?;
    Ok(Note::from(note))
}

// THE FINALIZED COMPOSITION
// ================================================================================================

/// The two-step ownership component is gone: no component contributes its code, and no component
/// declares its owner-config slot. With it go the administratorship handshake and the second authority
/// handle that could drift from the administrator role.
#[test]
fn the_ownership_component_is_absent_from_the_composition() -> Result<()> {
    let components = production_component_set(MAX_SUPPLY, 0)?;

    assert!(
        !components
            .iter()
            .any(|c| c.component_code().as_package() == Ownable2Step::code().as_package()),
        "the shipped composition must no longer install the two-step ownership component"
    );
    assert!(
        !components
            .iter()
            .flat_map(|c| c.storage_slots().iter())
            .any(|slot| slot.name() == Ownable2Step::slot_name()),
        "no component may declare the administrator-config slot — the administrator slot is gone, not orphaned"
    );
    Ok(())
}

/// The callable surface is the ratified 70 roots, and not one of them is an administratorship procedure.
/// The count is asserted against the real composition, so a stale removal shows up here.
#[test]
fn the_callable_surface_is_seventy_roots_and_carries_no_ownership_row() -> Result<()> {
    let mut components = production_component_set(MAX_SUPPLY, 0)?;
    components.extend(
        XReserveStablecoinBuilder::auth_component()
            .map_err(|e| anyhow::anyhow!("the production auth component must build: {e}"))?,
    );

    let paths: Vec<String> = components
        .iter()
        .flat_map(|c| {
            c.component_code()
                .exports()
                .map(|e| e.path.to_string())
                .collect::<Vec<_>>()
        })
        .collect();

    assert_eq!(
        paths.len(),
        RATIFIED_CALLABLE_PROCEDURES,
        "the composed account must expose exactly the ratified callable-procedure count"
    );
    let ownership: Vec<&String> = paths
        .iter()
        .filter(|p| p.contains("ownable2step"))
        .collect();
    assert!(
        ownership.is_empty(),
        "no ownership procedure may remain callable, found: {ownership:?}"
    );
    Ok(())
}

/// The note-script allowlist is exactly the ratified nine roots: the two supply notes, the four
/// administrator-gated setters, the two standard config notes, and the ONE standard role-action
/// note that replaced the two bespoke role notes. Set equality, so a leftover root fails as loudly
/// as a missing one.
#[test]
fn the_note_allowlist_is_exactly_the_nine_ratified_roots() -> Result<()> {
    let allowlist = XReserveStablecoinBuilder::allowed_note_scripts();
    let expected: BTreeSet<NoteScriptRoot> = BTreeSet::from([
        MintNote::script_root(),
        BurnNote::script_root(),
        XReserveSetAttesterNote::script_root(),
        XReserveIdentifierInitNote::script_root(),
        XReserveSetMinBurnSizeNote::script_root(),
        XReserveSetMaxSupplyNote::script_root(),
        PauseActionNote::script_root(),
        BlocklistConfigNote::script_root(),
        RbacActionNote::script_root(),
    ]);

    assert_eq!(
        allowlist.len(),
        RATIFIED_ALLOWLIST_ROOTS,
        "the allowlist must hold exactly the ratified number of roots"
    );
    assert_eq!(
        allowlist, expected,
        "the allowlist must be exactly the nine ratified roots — the standard role-action note is \
         in, and both ownership notes and both bespoke role notes are out"
    );
    Ok(())
}

// THE IDENTIFIER INITIALIZER, NOW GATED BY THE ACCOUNT-WIDE AUTHORITY
// ================================================================================================

/// The initializer still works, and still seeds the faucet's own-id key. It reaches the same
/// authorized account it always did — the administrator role's sole member is the account that held
/// the administrator slot — so the only thing that moved is which gate it asks.
#[tokio::test]
async fn the_identifier_initializer_lands_for_the_administrator() -> Result<()> {
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            XReserveIdentifierInitNote::create(admin_holder(), faucet_id, &mut note_rng(301))
                .expect("the identifier_init note builds"),
        ]
    })?;

    let note = pf.seeded_notes[0].clone();
    let faucet_id = pf.faucet_id;
    let account = consume_and_commit(&mut pf, &note, "identifier_init").await?;

    assert_eq!(
        read_identifier(&account)?,
        XReserveIdentifierInitNote::identifier_for(faucet_id),
        "the initializer must seed the faucet's own-id key through the authority gate"
    );
    Ok(())
}

/// The gate still gates, and now speaks the role error. An account outside the administrator role
/// is refused — the authorized identity is unchanged, only the mechanism and therefore the trap
/// message moved, exactly as it did for every other setter when the authority flipped.
#[tokio::test]
async fn the_identifier_initializer_rejects_a_non_administrator_with_the_role_error() -> Result<()>
{
    let pf = admin_faucet(|faucet_id| {
        vec![
            XReserveIdentifierInitNote::create(stranger(), faucet_id, &mut note_rng(302))
                .expect("the identifier_init note builds"),
        ]
    })?;

    let note = pf.seeded_notes[0].clone();
    let result = consume(&pf, &note).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

// ROLE MANAGEMENT THROUGH THE STANDARD NOTE
// ================================================================================================

/// Rotation, the action the faucet actually performs: the Domain manager grants the Domain pauser
/// role to a new account and takes it away again, through the standard note.
#[tokio::test]
async fn the_stock_role_note_grants_and_revokes_a_role() -> Result<()> {
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            role_note(
                role_manager_holder(),
                faucet_id,
                RbacAction::GrantRole {
                    role: pauser_symbol(),
                    account: stranger(),
                },
                401,
            )
            .expect("the grant note builds"),
            role_note(
                role_manager_holder(),
                faucet_id,
                RbacAction::RevokeRole {
                    role: pauser_symbol(),
                    account: stranger(),
                },
                402,
            )
            .expect("the revoke note builds"),
        ]
    })?;

    let grant = pf.seeded_notes[0].clone();
    let revoke = pf.seeded_notes[1].clone();

    let after_grant = consume_and_commit(&mut pf, &grant, "grant_role").await?;
    assert_eq!(
        read_role_membership(&after_grant, &pauser_symbol(), stranger())?,
        set_word(),
        "the grant must record the new member"
    );
    assert_eq!(
        read_role_member_count(&after_grant, &pauser_symbol())?,
        Felt::from(2u32),
        "the grant must raise the role's member count"
    );

    let after_revoke = consume_and_commit(&mut pf, &revoke, "revoke_role").await?;
    assert_eq!(
        read_role_membership(&after_revoke, &pauser_symbol(), stranger())?,
        Word::empty(),
        "the revoke must clear the membership"
    );
    assert_eq!(
        read_role_member_count(&after_revoke, &pauser_symbol())?,
        Felt::from(1u32),
        "the revoke must restore the role's member count"
    );
    Ok(())
}

/// The role graph is now runtime-mutable — the accepted consequence of admitting the standard
/// note's single root. The Domain manager, which administers the Domain pauser role, re-points that
/// role's administrator at a different role, and the write lands.
#[tokio::test]
async fn the_stock_role_note_can_repoint_a_delegated_role_admin() -> Result<()> {
    let mut pf = admin_faucet(|faucet_id| {
        vec![role_note(
            role_manager_holder(),
            faucet_id,
            RbacAction::SetRoleAdmin {
                role: pauser_symbol(),
                admin_role: Some(blocklist_symbol()),
            },
            403,
        )
        .expect("the set-role-admin note builds")]
    })?;

    let before = pf
        .mock_chain
        .committed_account(pf.faucet_id)
        .context("reading the committed faucet")?
        .clone();
    assert_eq!(
        read_role_admin(&before, &pauser_symbol())?,
        Felt::from(&role_manager_symbol()),
        "the build seed must still delegate the Domain pauser's administration to the Domain manager"
    );

    let note = pf.seeded_notes[0].clone();
    let after = consume_and_commit(&mut pf, &note, "set_role_admin").await?;
    assert_eq!(
        read_role_admin(&after, &pauser_symbol())?,
        Felt::from(&blocklist_symbol()),
        "the delegated administrator must be able to re-point the role it administers"
    );
    Ok(())
}

/// The sharp edge of that mutability, recorded rather than discovered later: delegation is
/// exclusive, so the administrator role has no authority over a role that was delegated away. The
/// account that holds everything else cannot re-point the Domain pauser role.
#[tokio::test]
async fn the_administrator_cannot_repoint_an_exclusively_delegated_role() -> Result<()> {
    let pf = admin_faucet(|faucet_id| {
        vec![role_note(
            admin_holder(),
            faucet_id,
            RbacAction::SetRoleAdmin {
                role: pauser_symbol(),
                admin_role: None,
            },
            404,
        )
        .expect("the set-role-admin note builds")]
    })?;

    let note = pf.seeded_notes[0].clone();
    let result = consume(&pf, &note).await;
    assert_transaction_executor_error!(result, err_sender_not_role_admin());
    Ok(())
}

/// Self-renounce is reachable too, and it is ungated: a role holder drops its own membership with
/// no administrator involved, and the role is left empty until someone grants it again.
#[tokio::test]
async fn the_stock_role_note_can_renounce_a_held_role() -> Result<()> {
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            role_note(
                pauser_holder(),
                faucet_id,
                RbacAction::RenounceRole {
                    role: pauser_symbol(),
                },
                405,
            )
            .expect("the renounce note builds"),
            stock_pause_note(pauser_holder(), faucet_id, 406).expect("the pause note builds"),
        ]
    })?;

    let renounce = pf.seeded_notes[0].clone();
    let pause = pf.seeded_notes[1].clone();

    let after = consume_and_commit(&mut pf, &renounce, "renounce_role").await?;
    assert_eq!(
        read_role_membership(&after, &pauser_symbol(), pauser_holder())?,
        Word::empty(),
        "the holder must have dropped its own membership"
    );
    assert_eq!(
        read_role_member_count(&after, &pauser_symbol())?,
        Felt::ZERO,
        "the role must be left with no members"
    );

    // The capability goes with the membership: the former pauser can no longer pause.
    let result = consume(&pf, &pause).await;
    assert_transaction_executor_error!(result, err_sender_lacks_role());
    Ok(())
}

// THE REST OF THE ADMIN SURFACE
// ================================================================================================

/// Every remaining administrator- and role-gated action still lands with no ownership component in
/// the composition: the attester allowlist, the supply cap, the burn floor, the pause flag and the
/// transfer blocklist. None of them ever read the administrator slot, and this proves it rather than
/// assuming it.
#[tokio::test]
async fn every_remaining_admin_note_still_lands() -> Result<()> {
    let commitment = Word::from([7u32, 8, 9, 10]);
    let new_max_supply = MAX_SUPPLY * 2;
    let new_min_burn = 42u64;
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            XReserveSetAttesterNote::create(
                admin_holder(),
                faucet_id,
                commitment,
                1,
                &mut note_rng(501),
            )
            .expect("the set_attester note builds"),
            XReserveSetMaxSupplyNote::create(
                admin_holder(),
                faucet_id,
                new_max_supply,
                &mut note_rng(502),
            )
            .expect("the set_max_supply note builds"),
            XReserveSetMinBurnSizeNote::create(
                admin_holder(),
                faucet_id,
                new_min_burn,
                &mut note_rng(503),
            )
            .expect("the set_min_burn_size note builds"),
            stock_pause_note(pauser_holder(), faucet_id, 504).expect("the pause note builds"),
            stock_block_note(blocklist_holder(), faucet_id, stranger(), 505)
                .expect("the block note builds"),
        ]
    })?;

    let notes: Vec<Note> = pf.seeded_notes.clone();

    let after = consume_and_commit(&mut pf, &notes[0], "set_attester").await?;
    assert_eq!(
        read_attester(&after, commitment)?,
        set_word(),
        "the attester setter must still write its allowlist entry"
    );

    // token_config is [token_supply, max_supply, decimals, symbol] — the cap is word[1].
    let after = consume_and_commit(&mut pf, &notes[1], "set_max_supply").await?;
    assert_eq!(
        read_token_config(&after)?[1],
        Felt::try_from(new_max_supply).expect("the new supply cap is a valid felt"),
        "the supply cap setter must still land"
    );

    let after = consume_and_commit(&mut pf, &notes[2], "set_min_burn_size").await?;
    assert_eq!(
        read_min_burn_size(&after)?[0],
        Felt::try_from(new_min_burn).expect("the new burn floor is a valid felt"),
        "the burn-floor setter must still land"
    );

    let after = consume_and_commit(&mut pf, &notes[3], "pause").await?;
    assert_eq!(
        read_paused(&after)?,
        set_word(),
        "the Domain pauser must still be able to pause"
    );

    let after = consume_and_commit(&mut pf, &notes[4], "block_account").await?;
    assert_eq!(
        read_blocked(&after, stranger())?,
        set_word(),
        "the blocklist administrator must still be able to block"
    );
    Ok(())
}

// THE ADMINISTRATOR ROLE: THE ACCOUNT'S ONLY AUTHORITY HANDLE
// ================================================================================================
// With no ownership component, `ADMIN` membership is the whole of the faucet's administrative
// authority — there is no owner slot, no nominate-then-accept handshake, and no second handle that
// could serve as a backstop. Everything the administratorship component used to carry now rides on grants
// and revokes of this one role, so the handover sequence and its failure boundary are worth driving
// end to end rather than describing.

/// A successor account for the handover — deliberately not one of the seeded role holders, so
/// nothing it can do comes from a membership it already had.
fn successor() -> AccountId {
    test_account_id(77)
}

/// The safe handover, in the order the runbook prescribes: GRANT the administrator role to the
/// successor first, then REVOKE it from the predecessor. Each step is proven by CAPABILITY, not by
/// a storage read — the successor's administrator-gated write must land, and the predecessor's must
/// stop landing once revoked.
///
/// Granting before revoking is what keeps the account from ever having no administrator at all; the
/// reverse order is unrecoverable, which is the boundary the renounce test below pins.
#[tokio::test]
async fn the_administrator_role_hands_over_by_grant_then_revoke() -> Result<()> {
    let admin = RoleBasedAccessControl::admin_role();
    let successor_commitment = Word::from([21u32, 22, 23, 24]);
    let predecessor_commitment = Word::from([31u32, 32, 33, 34]);

    let mut pf = admin_faucet(|faucet_id| {
        vec![
            // 0 — the successor has no administrator-gated capability yet.
            XReserveSetAttesterNote::create(
                successor(),
                faucet_id,
                successor_commitment,
                1,
                &mut note_rng(601),
            )
            .expect("the successor's set_attester note builds"),
            // 1 — the incumbent grants the administrator role to the successor.
            role_note(
                admin_holder(),
                faucet_id,
                RbacAction::GrantRole {
                    role: RoleBasedAccessControl::admin_role(),
                    account: successor(),
                },
                602,
            )
            .expect("the ADMIN grant note builds"),
            // 2 — the same capability, retried after the grant.
            XReserveSetAttesterNote::create(
                successor(),
                faucet_id,
                successor_commitment,
                1,
                &mut note_rng(603),
            )
            .expect("the successor's second set_attester note builds"),
            // 3 — the successor revokes the predecessor.
            role_note(
                successor(),
                faucet_id,
                RbacAction::RevokeRole {
                    role: RoleBasedAccessControl::admin_role(),
                    account: admin_holder(),
                },
                604,
            )
            .expect("the ADMIN revoke note builds"),
            // 4 — the predecessor's capability, retried after the revoke.
            XReserveSetAttesterNote::create(
                admin_holder(),
                faucet_id,
                predecessor_commitment,
                1,
                &mut note_rng(605),
            )
            .expect("the predecessor's set_attester note builds"),
        ]
    })?;
    let notes: Vec<Note> = pf.seeded_notes.clone();

    // BEFORE — the successor holds nothing, so its administrator-gated write is refused.
    let refused = consume(&pf, &notes[0]).await;
    assert_transaction_executor_error!(refused, err_sender_lacks_role());

    // GRANT — the incumbent administrator adds the successor to the role.
    let granted = consume_and_commit(&mut pf, &notes[1], "grant ADMIN to the successor").await?;
    assert_eq!(
        read_role_membership(&granted, &admin, successor())?,
        set_word(),
        "the successor must now hold the administrator role"
    );
    assert_eq!(
        read_role_member_count(&granted, &admin)?,
        Felt::from(2u32),
        "the role must carry both administrators during the handover window"
    );

    // CAPABILITY GAINED — the same write the successor was refused now lands.
    let after = consume_and_commit(&mut pf, &notes[2], "successor set_attester").await?;
    assert_eq!(
        read_attester(&after, successor_commitment)?,
        set_word(),
        "the successor must gain the administrator-gated capability with the role"
    );

    // REVOKE — the successor removes the predecessor.
    let revoked =
        consume_and_commit(&mut pf, &notes[3], "revoke ADMIN from the predecessor").await?;
    assert_eq!(
        read_role_membership(&revoked, &admin, admin_holder())?,
        Word::empty(),
        "the predecessor must no longer hold the administrator role"
    );
    assert_eq!(
        read_role_member_count(&revoked, &admin)?,
        Felt::from(1u32),
        "the successor must be the sole administrator once the handover completes"
    );

    // CAPABILITY LOST — the predecessor's write is refused, and nothing of it lands.
    let refused = consume(&pf, &notes[4]).await;
    assert_transaction_executor_error!(refused, err_sender_lacks_role());
    let final_state = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_attester(&final_state, predecessor_commitment)?,
        Word::empty(),
        "the refused predecessor write must leave the attester allowlist untouched"
    );
    Ok(())
}

/// The handover cannot be hijacked: the administrator role administers ITSELF, so only a current
/// administrator may add another. An account holding a different role — here the Domain manager,
/// which administers the Domain pauser — is refused.
#[tokio::test]
async fn only_an_administrator_can_grant_the_administrator_role() -> Result<()> {
    let pf = admin_faucet(|faucet_id| {
        vec![role_note(
            role_manager_holder(),
            faucet_id,
            RbacAction::GrantRole {
                role: RoleBasedAccessControl::admin_role(),
                account: successor(),
            },
            606,
        )
        .expect("the ADMIN grant note builds")]
    })?;

    let note = pf.seeded_notes[0].clone();
    let result = consume(&pf, &note).await;
    assert_transaction_executor_error!(result, err_sender_not_role_admin());

    let account = pf.mock_chain.committed_account(pf.faucet_id)?.clone();
    assert_eq!(
        read_role_membership(&account, &RoleBasedAccessControl::admin_role(), successor())?,
        Word::empty(),
        "the refused grant must leave the administrator role's membership untouched"
    );
    Ok(())
}

/// THE ACCEPTED CATASTROPHIC BOUNDARY, pinned rather than left to be discovered.
///
/// Renounce is self-only and ungated, so the SOLE administrator can drop its own membership. Doing
/// so empties the administrator role, and because that role administers itself, nobody is left who
/// can grant it back. Two capabilities die with it, permanently: every administrator-gated
/// procedure, and the administration of every role that resolves to the administrator.
///
/// This state is unreachable by accident — it takes a deliberate renounce note that the faucet's own
/// tooling never builds — and it is the price of admitting the standard role note's single script
/// root. Recovery is a redeploy. The roles delegated away (the Domain pauser, administered by the
/// Domain manager) are unaffected, which is what the exclusivity of delegation buys.
#[tokio::test]
async fn a_sole_administrator_that_renounces_leaves_the_authority_tree_empty() -> Result<()> {
    let admin = RoleBasedAccessControl::admin_role();
    let mut pf = admin_faucet(|faucet_id| {
        vec![
            // 0 — the sole administrator renounces its own membership.
            role_note(
                admin_holder(),
                faucet_id,
                RbacAction::RenounceRole {
                    role: RoleBasedAccessControl::admin_role(),
                },
                607,
            )
            .expect("the ADMIN renounce note builds"),
            // 1 — an administrator-gated write, attempted afterwards.
            XReserveSetAttesterNote::create(
                admin_holder(),
                faucet_id,
                Word::from([41u32, 42, 43, 44]),
                1,
                &mut note_rng(608),
            )
            .expect("the post-renounce set_attester note builds"),
            // 2 — an attempt to grant the role back to anyone.
            role_note(
                admin_holder(),
                faucet_id,
                RbacAction::GrantRole {
                    role: RoleBasedAccessControl::admin_role(),
                    account: successor(),
                },
                609,
            )
            .expect("the recovery grant note builds"),
            // 3 — the Domain pauser, whose administration was delegated away, still works.
            role_note(
                role_manager_holder(),
                faucet_id,
                RbacAction::GrantRole {
                    role: pauser_symbol(),
                    account: successor(),
                },
                610,
            )
            .expect("the delegated grant note builds"),
        ]
    })?;
    let notes: Vec<Note> = pf.seeded_notes.clone();

    let emptied = consume_and_commit(&mut pf, &notes[0], "sole administrator renounce").await?;
    assert_eq!(
        read_role_membership(&emptied, &admin, admin_holder())?,
        Word::empty(),
        "the sole administrator must have dropped its own membership"
    );
    assert_eq!(
        read_role_member_count(&emptied, &admin)?,
        Felt::ZERO,
        "the administrator role must be left with no members at all"
    );

    // Every administrator-gated procedure is now unreachable.
    let refused = consume(&pf, &notes[1]).await;
    assert_transaction_executor_error!(refused, err_sender_lacks_role());

    // And the role cannot be granted back: it administers itself, and it is empty.
    let unrecoverable = consume(&pf, &notes[2]).await;
    assert_transaction_executor_error!(unrecoverable, err_sender_not_role_admin());

    // What survives: a role whose administration was delegated away is untouched by the loss.
    let delegated =
        consume_and_commit(&mut pf, &notes[3], "delegated grant after the renounce").await?;
    assert_eq!(
        read_role_membership(&delegated, &pauser_symbol(), successor())?,
        set_word(),
        "the Domain manager must still administer the Domain pauser after the administrator role \
         is emptied — exclusive delegation is what keeps that subtree alive"
    );
    Ok(())
}
