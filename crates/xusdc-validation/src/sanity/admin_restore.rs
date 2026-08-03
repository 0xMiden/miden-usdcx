//! The admin suite's FINALLY-PHASE restore (best-effort, idempotent).
//!
//! [`restore_faucet`] runs after the admin CHECKS in ALL cases (see `admin::admin_suite`) — even
//! when a check errored mid-suite — so a caller-supplied faucet is never left paused,
//! attester-disabled, policy-mutated, or owned by the ephemeral wallet. Split out of `admin.rs` to
//! keep both files within the G3 file-size ceiling.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;

use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote,
    XReserveTransferOwnershipNote, XReserveUnpauseNote,
};

use crate::actors::{Actors, AttesterKey};

use super::admin::set_attester_enabled;
use super::driver::{
    attester_marker, is_paused, is_zero_word, max_supply, min_burn, owner_config, token_supply,
    SanityDriver,
};
use super::Ledger;

/// What the finally-phase restore must do about ownership — decided PURELY from the ON-CHAIN owner +
/// nominee (ground truth) versus the run's original owner + ephemeral wallet. Total (every state maps
/// to a defined action) so an accept-path failure — the ephemeral wallet unexpectedly OWNS the faucet
/// (a committed-but-unobserved accept), or is left NOMINATED (step-1 committed, accept never
/// completed) — is always detected and undone. Unit-tested without a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnershipRestore {
    /// The original owner still owns and nothing is nominated toward the ephemeral wallet.
    None,
    /// The ephemeral wallet OWNS the faucet — transfer it back to the original owner.
    TransferBack,
    /// The original owner still owns, but the ephemeral wallet is NOMINATED — cancel that nomination.
    CancelNomination,
    /// Owned by neither the original owner nor the ephemeral wallet — cannot restore.
    UnexpectedOwner(AccountId),
}

/// Pure ownership-restore decision from ground truth (see [`OwnershipRestore`]).
pub(crate) fn plan_ownership_restore(
    cur_owner: AccountId,
    nominated: Option<AccountId>,
    orig_owner: AccountId,
    ephemeral: AccountId,
) -> OwnershipRestore {
    if cur_owner == ephemeral {
        OwnershipRestore::TransferBack
    } else if cur_owner == orig_owner {
        if nominated == Some(ephemeral) {
            OwnershipRestore::CancelNomination
        } else {
            OwnershipRestore::None
        }
    } else {
        OwnershipRestore::UnexpectedOwner(cur_owner)
    }
}

/// How many refetch→plan→act cycles the ownership reconcile will attempt before giving up. Each cycle
/// re-observes fresh ON-CHAIN ground truth, so an accept that commits AFTER an earlier observation
/// (racing a `CancelNomination` into a `TransferBack`) is caught and re-planned on the next cycle.
/// Bounded so a persistently-failing action can never loop forever (2 actions is the deepest legit
/// path — a failed cancel followed by a transfer-back — so 4 leaves headroom for transient RPC errors).
pub(crate) const MAX_OWNERSHIP_RECONCILE_ATTEMPTS: usize = 4;

/// The node interactions the ownership reconcile loop needs, abstracted BEHIND A TRAIT so the bounded
/// refetch→plan→act loop can be driven by a scripted fake (no node) — including the post-snapshot
/// accept race a single snapshot cannot catch (the round-8 gap). The production impl is
/// [`DriverOwnershipOps`]; the test fakes live in `sanity::tests`.
pub(crate) trait OwnershipOps {
    /// The current on-chain `(owner, nominated)` ground truth.
    async fn observe(&mut self) -> Result<(AccountId, Option<AccountId>)>;
    /// Transfer ownership from the ephemeral wallet back to the original owner (+ accept it).
    async fn transfer_back(&mut self) -> Result<()>;
    /// Cancel a dangling ephemeral nomination (re-nominate the current owner to itself).
    async fn cancel_nomination(&mut self) -> Result<()>;
}

/// The terminal result of the bounded ownership reconcile loop (see [`reconcile_ownership`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnershipOutcome {
    /// The original owner owns and nothing is nominated toward the ephemeral wallet.
    Restored,
    /// Owned by an account that is neither the original owner nor the ephemeral wallet.
    UnexpectedOwner(AccountId),
    /// The reconcile budget was exhausted with the ephemeral wallet still owning/nominated.
    Unresolved(OwnershipRestore),
    /// A read (`observe`) failed, so the final ownership state could not be verified.
    ObserveFailed(String),
}

/// Reconciles ownership to the ORIGINAL owner in a BOUNDED refetch→plan→act→verify loop. Each cycle
/// re-observes fresh ground truth and re-plans, so a committed-but-unobserved accept — even one that
/// races an in-flight `CancelNomination` (the cancel then fails UNAUTHORIZED because the ephemeral
/// wallet already owns) — is observed on the next cycle and undone via `TransferBack`, instead of the
/// round-8 behaviour that recorded the single failed action and stopped. Human-readable action steps
/// accumulate in `trace`. Returns the terminal [`OwnershipOutcome`]; the caller records the ledger row.
pub(crate) async fn reconcile_ownership<O: OwnershipOps>(
    ops: &mut O,
    orig_owner: AccountId,
    ephemeral: AccountId,
    trace: &mut Vec<String>,
) -> OwnershipOutcome {
    for attempt in 0..=MAX_OWNERSHIP_RECONCILE_ATTEMPTS {
        let (cur_owner, nominated) = match ops.observe().await {
            Ok(v) => v,
            Err(e) => return OwnershipOutcome::ObserveFailed(format!("{e:#}")),
        };
        let (label, res) = match plan_ownership_restore(cur_owner, nominated, orig_owner, ephemeral)
        {
            OwnershipRestore::None => return OwnershipOutcome::Restored,
            OwnershipRestore::UnexpectedOwner(other) => {
                return OwnershipOutcome::UnexpectedOwner(other)
            }
            OwnershipRestore::TransferBack => {
                // The final cycle (attempt == MAX) is a pure VERIFY: no action budget left, so an
                // ephemeral wallet still owning is surfaced as Unresolved rather than silently passed.
                if attempt == MAX_OWNERSHIP_RECONCILE_ATTEMPTS {
                    return OwnershipOutcome::Unresolved(OwnershipRestore::TransferBack);
                }
                (
                    "transfer-back from the ephemeral wallet",
                    ops.transfer_back().await,
                )
            }
            OwnershipRestore::CancelNomination => {
                if attempt == MAX_OWNERSHIP_RECONCILE_ATTEMPTS {
                    return OwnershipOutcome::Unresolved(OwnershipRestore::CancelNomination);
                }
                (
                    "cancel a dangling ephemeral nomination",
                    ops.cancel_nomination().await,
                )
            }
        };
        match res {
            Ok(()) => trace.push(format!("{label}: committed")),
            // A committed accept can make this action STALE (e.g. a cancel sent by the no-longer-owner)
            // — record the failed attempt and let the NEXT cycle observe fresh truth + re-plan.
            Err(e) => trace.push(format!("{label}: attempt failed ({e:#}) — re-observing")),
        }
    }
    // `0..=MAX` always returns inside the loop: the final cycle reaches a terminal state or hits the
    // `attempt == MAX` guard above.
    unreachable!("the bounded reconcile loop returns within its attempt budget")
}

/// The production [`OwnershipOps`]: drives the real node via the [`SanityDriver`]. `transfer_back` /
/// `cancel_nomination` only run when the loop's plan says so — `TransferBack` only when the ephemeral
/// wallet OWNS (so the transfer's sender is the ephemeral wallet), `CancelNomination` only when the
/// original owner owns (so the cancel's sender is that owner).
struct DriverOwnershipOps<'a> {
    d: &'a mut SanityDriver,
    orig_owner: AccountId,
    ephemeral: AccountId,
}

impl OwnershipOps for DriverOwnershipOps<'_> {
    async fn observe(&mut self) -> Result<(AccountId, Option<AccountId>)> {
        let acct = self.d.fetch_faucet().await?;
        owner_config(&acct)
    }
    async fn transfer_back(&mut self) -> Result<()> {
        restore_ownership(self.d, self.ephemeral, self.orig_owner).await
    }
    async fn cancel_nomination(&mut self) -> Result<()> {
        cancel_nomination(self.d, self.orig_owner).await
    }
}

/// Cleanup after the admin checks: restores the faucet to its pre-suite owner + policy (unpaused,
/// mint attester allowlisted, `min_burn_size` + `max_supply` back to the snapshot) so a caller-
/// supplied faucet is NEVER left paused, attester-disabled, policy-mutated, or owned/nominated by the
/// ephemeral wallet — and it runs EVEN WHEN an admin check errored mid-suite. Ownership is driven by
/// the ON-CHAIN owner (ground truth, not a client-side flag), then restored FIRST because the policy
/// setters are administrator-gated. Every step acts only when a restore is actually needed (idempotent);
/// failures are RECORDED as surfaced findings, never propagated (`admin_suite` returns the ORIGINAL
/// error, if any).
pub(super) async fn restore_faucet(
    d: &mut SanityDriver,
    led: &mut Ledger,
    actors: &Actors,
    mint_attester: &AttesterKey,
    orig_min_burn: u64,
    orig_max_supply: u64,
) {
    let owner_id = actors.owner.id();
    let pauser_id = actors.pauser.id();
    let ephemeral_id = actors.new_pauser.id();

    // 1. OWNERSHIP — from ON-CHAIN ground truth, FIRST (policy setters are ADMIN-gated). A BOUNDED
    //    refetch→plan→act→verify loop reconciles against fresh truth each cycle, so an accept that
    //    committed but the client never observed (Err ≠ not-consumed), a dangling step-1 nomination, OR
    //    an accept that RACES an in-flight cancel is detected and undone — none of which a client-side
    //    boolean or a single snapshot could capture.
    restore_ownership_to_original(d, led, owner_id, ephemeral_id).await;

    // 2. POLICY — read the live faucet AFTER ownership has settled: ground truth for is_paused / min /
    //    max / supply. Read ONCE here (ownership ops do not touch those slots, and each policy setter
    //    below verifies its own read-back).
    let acct = match d.fetch_faucet().await {
        Ok(a) => a,
        Err(e) => {
            led.record(
                "ADMIN-RESTORE",
                "admin",
                "faucet restored to the pre-run owner + policy",
                false,
                format!("RESTORE FAILED — could not read the faucet: {e:#}"),
            );
            return;
        }
    };

    let mut actions: Vec<String> = Vec::new();
    let mut ok = true;

    // UNPAUSE if paused (DOM_PAUSER gated — independent of ownership).
    if is_paused(&acct).unwrap_or(false) {
        match restore_unpause(d, pauser_id).await {
            Ok(()) => actions.push("unpaused".into()),
            Err(e) => {
                ok = false;
                actions.push(format!("unpause FAILED ({e:#})"));
            }
        }
    }

    // RE-ALLOWLIST the mint attester if it was left disabled (ADMIN-gated).
    let commitment = mint_attester.commitment_word();
    let attester_disabled = attester_marker(&acct, commitment)
        .map(is_zero_word)
        .unwrap_or(false);
    if attester_disabled {
        match set_attester_enabled(
            d,
            owner_id,
            commitment,
            true,
            "set_attester(restore, enabled=1)",
        )
        .await
        {
            Ok(()) => actions.push("mint attester re-allowlisted".into()),
            Err(e) => {
                ok = false;
                actions.push(format!("attester re-allowlist FAILED ({e:#})"));
            }
        }
    }

    // RESTORE min_burn_size (ADMIN-gated).
    if min_burn(&acct).map(|m| m != orig_min_burn).unwrap_or(true) {
        match restore_min_burn(d, owner_id, orig_min_burn).await {
            Ok(()) => actions.push(format!("min_burn_size ← {orig_min_burn}")),
            Err(e) => {
                ok = false;
                actions.push(format!("min_burn_size restore FAILED ({e:#})"));
            }
        }
    }

    // RESTORE max_supply (ADMIN-gated). The run mints test tokens, so if that pushed token_supply
    // above the original cap, restore to that supply (the minimum valid cap) — supply is not fully
    // reversible; report the adjustment.
    let supply_now = token_supply(&acct).unwrap_or(0);
    let restored_max = orig_max_supply.max(supply_now);
    if max_supply(&acct).map(|m| m != restored_max).unwrap_or(true) {
        match restore_max_supply(d, owner_id, restored_max).await {
            Ok(()) if restored_max == orig_max_supply => {
                actions.push(format!("max_supply ← {orig_max_supply}"))
            }
            Ok(()) => actions.push(format!(
                "max_supply ← {restored_max} (orig {orig_max_supply} < supply {supply_now} after \
                 test-minting)"
            )),
            Err(e) => {
                ok = false;
                actions.push(format!("max_supply restore FAILED ({e:#})"));
            }
        }
    }

    let detail = if actions.is_empty() {
        "no policy drift to restore (faucet already at the pre-run values)".to_string()
    } else {
        actions.join("; ")
    };
    led.record(
        "ADMIN-POLICY-RESTORE",
        "admin",
        "faucet policy restored to the pre-run deployment values (unpaused, attester allowlisted, \
         min/max)",
        ok,
        detail,
    );
}

/// Restores ownership to the ORIGINAL owner from ON-CHAIN ground truth via the bounded reconcile loop
/// ([`reconcile_ownership`]), recording ONE ADMIN-OWNER-RESTORE row from the terminal outcome. Handles
/// every accept-path-failure state: the ephemeral wallet unexpectedly OWNS (transfer back), is merely
/// NOMINATED (cancel), an accept that RACES the cancel (re-observed + transferred back), or an
/// unexpected owner (surfaced as a failure).
async fn restore_ownership_to_original(
    d: &mut SanityDriver,
    led: &mut Ledger,
    orig_owner: AccountId,
    ephemeral: AccountId,
) {
    let what = "ownership restored to the ORIGINAL owner (the ephemeral wallet retains no control)";
    let mut trace: Vec<String> = Vec::new();
    let outcome = {
        let mut ops = DriverOwnershipOps {
            d,
            orig_owner,
            ephemeral,
        };
        reconcile_ownership(&mut ops, orig_owner, ephemeral, &mut trace).await
    };
    let steps = if trace.is_empty() {
        String::new()
    } else {
        format!(" [{}]", trace.join("; "))
    };
    match outcome {
        OwnershipOutcome::Restored => led.record(
            "ADMIN-OWNER-RESTORE",
            "admin",
            what,
            true,
            format!("owner = {orig_owner}; the ephemeral wallet retains no control{steps}"),
        ),
        OwnershipOutcome::UnexpectedOwner(other) => led.record(
            "ADMIN-OWNER-RESTORE",
            "admin",
            what,
            false,
            format!(
                "faucet owned by an UNEXPECTED account {other} (neither the original owner nor the \
                 ephemeral wallet) — cannot restore{steps}"
            ),
        ),
        OwnershipOutcome::Unresolved(remaining) => led.record(
            "ADMIN-OWNER-RESTORE",
            "admin",
            what,
            false,
            format!(
                "RESTORE UNRESOLVED after {MAX_OWNERSHIP_RECONCILE_ATTEMPTS} reconcile attempts — \
                 still needs {remaining:?}; the ephemeral wallet may retain control{steps}"
            ),
        ),
        OwnershipOutcome::ObserveFailed(e) => led.record(
            "ADMIN-OWNER-RESTORE",
            "admin",
            what,
            false,
            format!("RESTORE UNVERIFIED — could not read the on-chain owner: {e}{steps}"),
        ),
    }
}

/// Cancels a dangling ownership nomination by re-nominating the current owner to itself (the stock
/// ownable2step cancel path), so a previously-nominated ephemeral wallet can never accept later.
async fn cancel_nomination(d: &mut SanityDriver, owner_id: AccountId) -> Result<()> {
    let note =
        XReserveTransferOwnershipNote::create(owner_id, d.faucet_id, owner_id, d.hc.client.rng())
            .context("transfer_ownership (cancel nomination) note")?;
    d.commit_via_ntx_consumed(
        owner_id,
        note,
        "transfer_ownership (cancel dangling nomination)",
    )
    .await
    .context("committing the nomination cancel")?;
    Ok(())
}

/// Transfers ownership from `from_id` back to `to_id` and accepts it (the 2-step restore).
async fn restore_ownership(
    d: &mut SanityDriver,
    from_id: AccountId,
    to_id: AccountId,
) -> Result<()> {
    let back =
        XReserveTransferOwnershipNote::create(from_id, d.faucet_id, to_id, d.hc.client.rng())
            .context("transfer_ownership (restore) note")?;
    d.commit_via_ntx_consumed(
        from_id,
        back,
        "transfer_ownership (restore to original owner)",
    )
    .await
    .context("committing the ownership restore transfer")?;
    let accept = XReserveAcceptOwnershipNote::create(to_id, d.faucet_id, d.hc.client.rng())
        .context("accept_ownership (restore) note")?;
    d.commit_via_ntx_consumed(to_id, accept, "accept_ownership (restore)")
        .await
        .context("accepting the ownership restore")?;
    Ok(())
}

/// Unpauses the faucet (DOM_PAUSER), waiting for `is_paused` to clear.
async fn restore_unpause(d: &mut SanityDriver, pauser_id: AccountId) -> Result<()> {
    let note = XReserveUnpauseNote::create(pauser_id, d.faucet_id, d.hc.client.rng())
        .context("unpause note (restore)")?;
    d.commit_via_ntx(pauser_id, note, "unpause (restore)", |a| {
        is_paused(a).map(|p| !p).unwrap_or(false)
    })
    .await?;
    Ok(())
}

/// Sets `min_burn_size` back to `target` (ADMIN-gated), waiting for the read-back.
async fn restore_min_burn(d: &mut SanityDriver, owner_id: AccountId, target: u64) -> Result<()> {
    let note = XReserveSetMinBurnSizeNote::create(owner_id, d.faucet_id, target, d.hc.client.rng())
        .context("set_min_burn_size(restore) note")?;
    d.commit_via_ntx(owner_id, note, "set_min_burn_size(restore)", move |a| {
        min_burn(a).map(|m| m == target).unwrap_or(false)
    })
    .await?;
    Ok(())
}

/// Sets `max_supply` back to `target` (ADMIN-gated), waiting for the read-back.
async fn restore_max_supply(d: &mut SanityDriver, owner_id: AccountId, target: u64) -> Result<()> {
    let note = XReserveSetMaxSupplyNote::create(owner_id, d.faucet_id, target, d.hc.client.rng())
        .context("set_max_supply(restore) note")?;
    d.commit_via_ntx(owner_id, note, "set_max_supply(restore)", move |a| {
        max_supply(a).map(|m| m == target).unwrap_or(false)
    })
    .await?;
    Ok(())
}
