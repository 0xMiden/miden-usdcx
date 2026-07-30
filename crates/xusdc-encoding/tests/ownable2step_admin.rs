//! The Ownable2Step OWNER-TRANSFER seam. The ENTIRE admin surface
//! (setters, role administration) hangs off the Ownable2Step owner, but no test exercised
//! `transfer_ownership` / `accept_ownership` on the production composition. This smoke test drives
//! the full two-step lifecycle on a production burn-policy faucet and pins the authority handover
//! with an owner-gated setter (`set_min_burn_size`) at every step:
//! nominate → old owner still authoritative → pending nominee rejected → accept → authority
//! rotated (new owner accepted, old owner rejected with the EXACT `ERR_SENDER_NOT_OWNER`).
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
/// These tests need some owner-gated operation to probe authority with, and the minimum-burn
/// setter is the convenient one — the note path it drives calls the standard
/// `set_min_burn_amount`. Nothing here is about burning; the setter is purely the probe.
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

/// The full two-step owner-transfer lifecycle on the production composition, with the owner-gated
/// setter as the authority probe at every step. Every reject pins the EXACT stock
/// `ERR_SENDER_NOT_OWNER`; every accept pins an exact-value read-back.
#[tokio::test]
async fn owner_two_step_transfer_rotates_authority() -> Result<()> {
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
    assert_transaction_executor_error!(pending, err_sender_not_owner());
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

    // 5. Authority rotated: the NEW owner's setter succeeds; the OLD owner's rejects exactly.
    let new_set = run_set_min_burn_size_against(&h.chain, &evolved, new_owner(), 3_000, 45)
        .await
        .expect("the new owner's setter must succeed after accept");
    evolved.apply_patch(new_set.account_patch())?;
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(3_000),
        "new-owner write landed"
    );

    let old = run_set_min_burn_size_against(&h.chain, &evolved, owner(), 4_000, 46).await;
    assert_transaction_executor_error!(old, err_sender_not_owner());
    assert_eq!(
        read_min_burn_size(&evolved)?,
        min_word(3_000),
        "the ex-owner's rejected setter must not write"
    );
    Ok(())
}
