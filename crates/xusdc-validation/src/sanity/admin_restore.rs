//! The admin suite's FINALLY-PHASE restore (best-effort, idempotent).
//!
//! [`restore_faucet`] runs after the admin CHECKS in ALL cases (see `admin::admin_suite`) — even
//! when a check errored mid-suite — so a caller-supplied faucet is never left paused,
//! attester-disabled, policy-mutated, or with `ADMIN` held by SAN-HANDOVER's ephemeral successor.
//! Split out of `admin.rs` to keep both files within the G3 file-size ceiling.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_standards::note::PauseConfig;

use crate::actors::{Actors, AttesterKey};

use super::admin::{
    max_supply_config_note, min_burn_config_note, pause_config_note, set_admin_member,
    set_attester_enabled,
};
use super::driver::{
    attester_marker, holds_admin, is_paused, is_zero_word, max_supply, min_burn, token_supply,
    SanityDriver,
};
use super::Ledger;

/// The on-chain `ADMIN` membership of the two accounts SAN-HANDOVER moves the role between. This is
/// the whole ground truth the finally-phase restore plans from: `ADMIN` is the account's sole
/// authority handle, membership in it is binary, and there is no nomination step, so two booleans
/// describe every state the handover can be interrupted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminMembership {
    /// Whether the run's ORIGINAL administrator still holds `ADMIN`.
    pub(crate) original: bool,
    /// Whether the EPHEMERAL successor holds `ADMIN`.
    pub(crate) ephemeral: bool,
}

/// What the finally-phase restore must do about `ADMIN`, decided PURELY from [`AdminMembership`].
/// Total — every one of the four ground-truth states maps to a defined action — so a handover
/// interrupted at any step is detected and undone. Unit-tested without a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminRestore {
    /// The original holds `ADMIN` and the ephemeral successor does not.
    None,
    /// Only the successor holds `ADMIN`: grant the original back FIRST, then revoke the successor —
    /// the reverse order would empty `ADMIN`, which is permanent.
    GrantOriginalThenRevokeEphemeral,
    /// Both hold `ADMIN` (the handover committed its grant but not its revoke): revoke the successor.
    RevokeEphemeral,
    /// NEITHER holds `ADMIN`. The role has left the pair this run controls, so there is no
    /// ADMIN-capable sender left to restore with — the membership is carried so the surfaced row
    /// names the state that was observed.
    Unexpected(AdminMembership),
}

/// Pure `ADMIN`-restore decision from ground truth (see [`AdminRestore`]).
pub(crate) fn plan_admin_restore(membership: AdminMembership) -> AdminRestore {
    match (membership.original, membership.ephemeral) {
        (true, false) => AdminRestore::None,
        (false, true) => AdminRestore::GrantOriginalThenRevokeEphemeral,
        (true, true) => AdminRestore::RevokeEphemeral,
        (false, false) => AdminRestore::Unexpected(membership),
    }
}

/// How many refetch→plan→act cycles the `ADMIN` reconcile will attempt before giving up. Each cycle
/// re-observes fresh ON-CHAIN ground truth, so a grant or revoke that commits AFTER an earlier
/// observation is caught and re-planned on the next cycle. Bounded so a persistently-failing action
/// can never loop forever (2 actions is the deepest legit path — a grant followed by a revoke — so 4
/// leaves headroom for transient RPC errors).
pub(crate) const MAX_ADMIN_RECONCILE_ATTEMPTS: usize = 4;

/// The node interactions the `ADMIN` reconcile loop needs, abstracted BEHIND A TRAIT so the bounded
/// refetch→plan→act loop can be driven by a scripted fake (no node) — including the states a single
/// snapshot cannot catch, where an action commits but its result is never observed. The production
/// impl is [`DriverAdminOps`]; the test fakes live in `sanity::tests`.
pub(crate) trait AdminOps {
    /// The current on-chain `ADMIN` membership of the two accounts.
    async fn observe(&mut self) -> Result<AdminMembership>;
    /// Grant `ADMIN` back to the original administrator (sent by the successor, which holds it).
    async fn grant_original(&mut self) -> Result<()>;
    /// Revoke the ephemeral successor's `ADMIN` (sent by the original, which holds it).
    async fn revoke_ephemeral(&mut self) -> Result<()>;
}

/// The terminal result of the bounded `ADMIN` reconcile loop (see [`reconcile_admin`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdminOutcome {
    /// The original holds `ADMIN` and the ephemeral successor does not.
    Restored,
    /// Neither account holds `ADMIN` — nothing this run controls can restore it.
    Unexpected(AdminMembership),
    /// The reconcile budget was exhausted with the successor still holding `ADMIN`.
    Unresolved(AdminRestore),
    /// A read (`observe`) failed, so the final membership could not be verified.
    ObserveFailed(String),
}

/// Reconciles `ADMIN` back to the ORIGINAL administrator in a BOUNDED refetch→plan→act→verify loop.
/// Each cycle re-observes fresh ground truth and re-plans, so an action that committed but whose
/// result the client never saw is observed on the next cycle instead of being recorded as a failure
/// and abandoned. The two-action state acts on the GRANT only and lets the next cycle plan the
/// revoke, which is what keeps `ADMIN` from ever being emptied. Human-readable action steps
/// accumulate in `trace`; the caller records the ledger row from the terminal outcome.
pub(crate) async fn reconcile_admin<O: AdminOps>(
    ops: &mut O,
    trace: &mut Vec<String>,
) -> AdminOutcome {
    for attempt in 0..=MAX_ADMIN_RECONCILE_ATTEMPTS {
        let membership = match ops.observe().await {
            Ok(m) => m,
            Err(e) => return AdminOutcome::ObserveFailed(format!("{e:#}")),
        };
        let plan = plan_admin_restore(membership);
        // The final cycle is a pure VERIFY: no action budget is left, so a successor that still
        // holds ADMIN is surfaced as Unresolved rather than silently passed.
        if attempt == MAX_ADMIN_RECONCILE_ATTEMPTS
            && !matches!(plan, AdminRestore::None | AdminRestore::Unexpected(_))
        {
            return AdminOutcome::Unresolved(plan);
        }
        let (label, res) = match plan {
            AdminRestore::None => return AdminOutcome::Restored,
            AdminRestore::Unexpected(m) => return AdminOutcome::Unexpected(m),
            AdminRestore::GrantOriginalThenRevokeEphemeral => (
                "grant ADMIN back to the original",
                ops.grant_original().await,
            ),
            AdminRestore::RevokeEphemeral => (
                "revoke the ephemeral successor's ADMIN",
                ops.revoke_ephemeral().await,
            ),
        };
        match res {
            Ok(()) => trace.push(format!("{label}: committed")),
            // An action can be STALE by the time it lands (its effect already committed, or the
            // sender no longer holds ADMIN) — record the attempt and let the NEXT cycle observe
            // fresh truth and re-plan.
            Err(e) => trace.push(format!("{label}: attempt failed ({e:#}) — re-observing")),
        }
    }
    // `0..=MAX` always returns inside the loop: the final cycle reaches a terminal state or hits the
    // `attempt == MAX` guard above.
    unreachable!("the bounded reconcile loop returns within its attempt budget")
}

/// The production [`AdminOps`]: drives the real node via the [`SanityDriver`]. Each action's SENDER
/// is the account that holds `ADMIN` in the state its plan is reached from — the successor grants
/// (it is the sole holder there), the original revokes (it holds it again by then).
struct DriverAdminOps<'a> {
    d: &'a mut SanityDriver,
    original: AccountId,
    ephemeral: AccountId,
}

impl AdminOps for DriverAdminOps<'_> {
    async fn observe(&mut self) -> Result<AdminMembership> {
        let acct = self.d.fetch_faucet().await?;
        Ok(AdminMembership {
            original: holds_admin(&acct, self.original)?,
            ephemeral: holds_admin(&acct, self.ephemeral)?,
        })
    }
    async fn grant_original(&mut self) -> Result<()> {
        set_admin_member(
            self.d,
            self.ephemeral,
            self.original,
            true,
            "grant_role(ADMIN, original) (restore)",
        )
        .await
    }
    async fn revoke_ephemeral(&mut self) -> Result<()> {
        set_admin_member(
            self.d,
            self.original,
            self.ephemeral,
            false,
            "revoke_role(ADMIN, successor) (restore)",
        )
        .await
    }
}

/// Cleanup after the admin checks: restores the faucet to its pre-suite `ADMIN` membership and
/// policy (unpaused, mint attester allowlisted, `min_burn_size` + `max_supply` back to the snapshot)
/// so a caller-supplied faucet is NEVER left paused, attester-disabled, policy-mutated, or with
/// `ADMIN` held by the ephemeral successor — and it runs EVEN WHEN an admin check errored mid-suite.
/// `ADMIN` is reconciled FIRST because the policy setters are ADMIN-gated. Every target is read from
/// the live faucet (ground truth, not a client-side flag) and every step acts only when a restore is
/// actually needed (idempotent); failures are RECORDED as surfaced findings, never propagated
/// (`admin_suite` returns the ORIGINAL error, if any).
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
    let successor_id = actors.new_pauser.id();

    // 1. ADMIN — from ON-CHAIN ground truth, FIRST (the policy setters are ADMIN-gated). A BOUNDED
    //    refetch→plan→act→verify loop reconciles against fresh truth each cycle, so a SAN-HANDOVER
    //    interrupted at any step — grant committed but revoke not, revoke committed but the client
    //    never saw it — is detected and undone, which no client-side flag or single snapshot could do.
    restore_admin_to_original(d, led, owner_id, successor_id).await;

    // 2. POLICY — read the live faucet once: ground truth for is_paused / min / max / supply. Each
    //    policy setter below verifies its own read-back.
    let acct = match d.fetch_faucet().await {
        Ok(a) => a,
        Err(e) => {
            led.record(
                "ADMIN-RESTORE",
                "admin",
                "faucet restored to the pre-run policy",
                false,
                format!("RESTORE FAILED — could not read the faucet: {e:#}"),
            );
            return;
        }
    };

    let mut actions: Vec<String> = Vec::new();
    let mut ok = true;

    // UNPAUSE if paused (DOM_PAUSER gated).
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

/// Restores `ADMIN` to the ORIGINAL administrator from ON-CHAIN ground truth via the bounded
/// reconcile loop ([`reconcile_admin`]), recording ONE SAN-HANDOVER-RESTORE row from the terminal
/// outcome. Handles every state a handover can be interrupted in: the successor still sole holder
/// (grant back, then revoke), both holding (revoke the successor), neither holding (surfaced as a
/// failure — there is no ADMIN-capable sender left).
async fn restore_admin_to_original(
    d: &mut SanityDriver,
    led: &mut Ledger,
    original: AccountId,
    ephemeral: AccountId,
) {
    let what = "ADMIN restored to the ORIGINAL administrator (the ephemeral successor holds none)";
    let mut trace: Vec<String> = Vec::new();
    let outcome = {
        let mut ops = DriverAdminOps {
            d,
            original,
            ephemeral,
        };
        reconcile_admin(&mut ops, &mut trace).await
    };
    let steps = if trace.is_empty() {
        String::new()
    } else {
        format!(" [{}]", trace.join("; "))
    };
    match outcome {
        AdminOutcome::Restored => led.record(
            "SAN-HANDOVER-RESTORE",
            "admin",
            what,
            true,
            format!("ADMIN = {original}; the ephemeral successor holds none{steps}"),
        ),
        AdminOutcome::Unexpected(m) => led.record(
            "SAN-HANDOVER-RESTORE",
            "admin",
            what,
            false,
            format!(
                "NEITHER the original nor the ephemeral successor holds ADMIN ({m:?}) — no \
                 ADMIN-capable sender is left to restore with{steps}"
            ),
        ),
        AdminOutcome::Unresolved(remaining) => led.record(
            "SAN-HANDOVER-RESTORE",
            "admin",
            what,
            false,
            format!(
                "RESTORE UNRESOLVED after {MAX_ADMIN_RECONCILE_ATTEMPTS} reconcile attempts — still \
                 needs {remaining:?}; the ephemeral successor may retain ADMIN{steps}"
            ),
        ),
        AdminOutcome::ObserveFailed(e) => led.record(
            "SAN-HANDOVER-RESTORE",
            "admin",
            what,
            false,
            format!("RESTORE UNVERIFIED — could not read the on-chain ADMIN membership: {e}{steps}"),
        ),
    }
}

/// Unpauses the faucet (DOM_PAUSER), waiting for `is_paused` to clear.
async fn restore_unpause(d: &mut SanityDriver, pauser_id: AccountId) -> Result<()> {
    let note = pause_config_note(
        pauser_id,
        d.faucet_id,
        PauseConfig::Unpause,
        d.hc.client.rng(),
    )?;
    d.commit_via_ntx(pauser_id, note, "unpause (restore)", |a| {
        is_paused(a).map(|p| !p).unwrap_or(false)
    })
    .await?;
    Ok(())
}

/// Sets `min_burn_size` back to `target` (ADMIN-gated), waiting for the read-back.
async fn restore_min_burn(d: &mut SanityDriver, owner_id: AccountId, target: u64) -> Result<()> {
    let note = min_burn_config_note(owner_id, d.faucet_id, target, d.hc.client.rng())
        .context("set_min_burn_size(restore) note")?;
    d.commit_via_ntx(owner_id, note, "set_min_burn_size(restore)", move |a| {
        min_burn(a).map(|m| m == target).unwrap_or(false)
    })
    .await?;
    Ok(())
}

/// Sets `max_supply` back to `target` (ADMIN-gated), waiting for the read-back.
async fn restore_max_supply(d: &mut SanityDriver, owner_id: AccountId, target: u64) -> Result<()> {
    let note = max_supply_config_note(owner_id, d.faucet_id, target, d.hc.client.rng())
        .context("set_max_supply(restore) note")?;
    d.commit_via_ntx(owner_id, note, "set_max_supply(restore)", move |a| {
        max_supply(a).map(|m| m == target).unwrap_or(false)
    })
    .await?;
    Ok(())
}
