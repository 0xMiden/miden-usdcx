//! The Ownable2Step OWNER-TRANSFER seam, and the place where ownership and administration part
//! company.
//!
//! The owner slot still gates what it always gated: `identifier_init` and the transfer handshake
//! itself. It no longer gates the setters. Those carry no role of their own, so the account's
//! role-based authority resolves them to the built-in `ADMIN` role — seeded on the owner's account
//! at build, but account-bound thereafter. This suite drives the full two-step lifecycle on a
//! production burn-policy faucet using the minimum-burn setter as the authority probe, and the last
//! step is the one that matters: after acceptance the owner slot has moved and `ADMIN` has NOT, so
//! the new owner is rejected and the former owner still succeeds until the role is re-seated
//! through the grant and revoke notes.
//!
//! Stock semantics pinned (v0.15.3 `standards/access/ownable2step.masm`): `transfer_ownership` is
//! owner-gated and only NOMINATES (`owner_config = [owner, nominated]`); the current owner remains
//! in control until the nominated owner calls `accept_ownership`, which flips the owner half and
//! clears the nomination to `(0, 0)`.

mod support;

use anyhow::Result;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// The production builder seeds owner = id(1) (Ownable2Step); id(4) is a fresh account that holds
// no role and no authority until the two-step transfer completes.
fn owner() -> AccountId {
    test_account_id(1)
}
fn new_owner() -> AccountId {
    test_account_id(4)
}

const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 100_000;
const SEED_MIN: u64 = 1_000;

/// A production faucet whose owner is account 1.
///
/// These tests need some authority-gated operation to probe with, and the minimum-burn setter is
/// the convenient one — the note path it drives calls the standard `set_min_burn_amount`, which
/// resolves to the `ADMIN` role. Nothing here is about burning; the setter is purely the probe.
fn faucet_harness() -> Result<BurnPolicyHarness> {
    setup_burn_policy_account(
        BurnGuardSelection::OracleBurnReal,
        MAX_SUPPLY,
        TOKEN_SUPPLY,
        SEED_MIN,
        SEED_MIN,
    )
}

/// The faucet's CURRENT committed account (the admin txs' starting point).
fn faucet(h: &BurnPolicyHarness) -> Result<Account> {
    Ok(h.chain.committed_account(h.faucet_id)?.clone())
}

/// The storage word a floor of `v` is stored as: the value in the first element, zeros elsewhere.
/// This is the shape the standard minimum-burn policy keeps its floor in, and what
/// `support::read_min_burn_size` reads back.
fn min_word(v: u64) -> Word {
    Word::from([Felt::from(v as u32), Felt::ZERO, Felt::ZERO, Felt::ZERO])
}

/// The expected `owner_config` word `[owner_suffix, owner_prefix, nominated_suffix,
/// nominated_prefix]` — the nominated pair is `(0, 0)` when no transfer pends.
fn owner_config_word(owner: AccountId, nominated: Option<AccountId>) -> Word {
    let (nom_suffix, nom_prefix) = nominated
        .map(|id| (id.suffix(), id.prefix().as_felt()))
        .unwrap_or((Felt::ZERO, Felt::ZERO));
    Word::new([
        owner.suffix(),
        owner.prefix().as_felt(),
        nom_suffix,
        nom_prefix,
    ])
}

/// The full two-step owner-transfer lifecycle on the production composition, with the burn-floor
/// setter as the authority probe at every step.
///
/// The probe is an authority-gated setter with no role of its own, so it resolves to the
/// administrator role rather than to the owner slot. That makes it a probe of administrator
/// membership, not of ownership — and the last step is where the two come apart: rotating the owner
/// slot does not move administrator membership with it. Every reject pins the exact role error;
/// every accept pins an exact-value read-back.
#[tokio::test]
async fn owner_two_step_transfer_rotates_the_owner_slot_but_not_the_administrator() -> Result<()> {
    let h = faucet_harness()?;
    let account = faucet(&h)?;

    // 1. The owner nominates new_owner: the pending half is set, the owner half UNCHANGED.
    let nominated = run_transfer_ownership_against(&h.chain, &account, owner(), new_owner(), 41)
        .await
        .expect("the current owner's transfer_ownership must succeed");
    let mut evolved = account.clone();
    evolved.apply_patch(nominated.account_patch())?;
    assert_eq!(
        read_owner_config(&evolved)?,
        owner_config_word(owner(), Some(new_owner())),
        "transfer_ownership nominates without rotating: owner stays id(1), nominee id(4) pends"
    );

    // 2. The OLD owner is still authoritative before accept.
    let set = run_set_min_burn_size_against(&h.chain, &evolved, owner(), 2_000, 42)
        .await
        .expect("the current owner's setter must still succeed while the transfer pends");
    evolved.apply_patch(set.account_patch())?;
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(2_000),
        "old-owner write landed"
    );

    // 3. The PENDING nominee has no authority yet.
    let pending = run_set_min_burn_size_against(&h.chain, &evolved, new_owner(), 3_000, 43).await;
    assert_transaction_executor_error!(pending, err_sender_lacks_role());
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(2_000),
        "the pending nominee's rejected setter must not write"
    );

    // 4. The nominee accepts: owner rotates, the nomination clears to (0, 0).
    let accepted = run_accept_ownership_against(&h.chain, &evolved, new_owner(), 44)
        .await
        .expect("the nominated owner's accept_ownership must succeed");
    evolved.apply_patch(accepted.account_patch())?;
    assert_eq!(
        read_owner_config(&evolved)?,
        owner_config_word(new_owner(), None),
        "accept_ownership rotates the owner to id(4) and clears the nomination"
    );

    // 5. The owner slot rotated, but authority over the authority-gated setters did NOT follow it.
    //
    // Those setters carry no role of their own, so they resolve to the administrator role — and
    // administrator membership is account-based, seeded on the original owner's account. Rotating
    // the owner slot moves what the owner slot gates (`identifier_init` and the ownership handshake
    // itself); it does not move administrator membership. So after accept the NEW owner cannot set
    // the burn floor and the OLD owner still can, until the administrator role is granted to the
    // new owner and revoked from the old one — which is what the rotation runbook does, through the
    // grant and revoke role notes.
    let new_set = run_set_min_burn_size_against(&h.chain, &evolved, new_owner(), 3_000, 45).await;
    assert_transaction_executor_error!(new_set, err_sender_lacks_role());
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(2_000),
        "the new owner's setter is rejected until it holds the administrator role, so nothing wrote"
    );

    let old_set = run_set_min_burn_size_against(&h.chain, &evolved, owner(), 4_000, 46)
        .await
        .expect("the ex-owner still holds the administrator role, so its setter still succeeds");
    evolved.apply_patch(old_set.account_patch())?;
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(4_000),
        "the administrator's write landed even though it no longer holds the owner slot"
    );
    Ok(())
}
