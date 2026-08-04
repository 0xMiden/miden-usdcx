//! The admin-surface check family + the attester-allowlist helpers.
//!
//! pause (mint+burn rejected) → unpause (mint AND burn work) → attester rotation (disabled attester's
//! mint rejected, re-enabled) → `set_min_burn_size` (below-min rejected, at/above-min accepted) →
//! `set_max_supply` (mutate + read back + tightened-cap ENFORCED + below-current-supply REJECTED) →
//! owner-gating → 2-step ownership transfer. Split out of `checks.rs` to keep both files within the
//! G3 file-size ceiling.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::Word;

use xusdc_encoding::note::xreserve_admin::{
    XReserveAcceptOwnershipNote, XReservePauseNote, XReserveSetAttesterNote,
    XReserveSetMaxSupplyNote, XReserveSetMinBurnSizeNote, XReserveTransferOwnershipNote,
    XReserveUnpauseNote,
};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;

use crate::actors::{Actors, AttesterKey};

use super::checks::{burn_items, fund_and_burn, mint_and_assert, mint_note_for, record_rejection};
use super::driver::{
    attester_marker, is_paused, is_zero_word, max_supply, min_burn, token_supply, SanityDriver,
};
use super::{
    Ledger, BURN_UNITS, LOWERED_MIN_BURN, MINT_ROUND_UNITS, RAISED_MAX_SUPPLY, RAISED_MIN_BURN,
};

// Admin-only nonce salts (distinct from the mint/burn salts in checks.rs).
const SALT_PAUSED_MINT: u8 = 0x77;
const SALT_MINT_AFTER_UNPAUSE: u8 = 0x88;
const SALT_DISABLED_ATTESTER: u8 = 0x99;
const SALT_MINT_TO_HOLDER_2: u8 = 0xA1;
const SALT_ENFORCE_CAP: u8 = 0xB2;

/// The stock `fungible::set_max_supply` guard: a new cap below the current token supply rejects.
const ERR_MAX_SUPPLY_BELOW_SUPPLY: &str = "new max supply is less than current token supply";

// ATTESTER ALLOWLIST HELPERS
// ================================================================================================

/// Emits a `set_attester(commitment, enabled)` note (ADMIN-role-gated) via path N and waits for the
/// allowlist marker to reach the expected set/clear state.
pub(crate) async fn set_attester_enabled(
    d: &mut SanityDriver,
    owner_id: AccountId,
    commitment: Word,
    enabled: bool,
    op: &str,
) -> Result<()> {
    let note = XReserveSetAttesterNote::create(
        owner_id,
        d.faucet_id,
        commitment,
        u8::from(enabled),
        d.hc.client.rng(),
    )
    .with_context(|| format!("building the {op} note"))?;
    d.commit_via_ntx(owner_id, note, op, |a| {
        attester_marker(a, commitment)
            .map(|m| is_zero_word(m) != enabled)
            .unwrap_or(false)
    })
    .await
    .with_context(|| format!("committing {op}"))?;
    Ok(())
}

/// Owner allowlists the mint attester (`set_attester enabled=1`) via path N.
pub(crate) async fn allowlist_attester(
    d: &mut SanityDriver,
    owner_id: AccountId,
    attester: &AttesterKey,
) -> Result<()> {
    set_attester_enabled(
        d,
        owner_id,
        attester.commitment_word(),
        true,
        "set_attester(mint attester, enabled=1)",
    )
    .await?;
    println!("mint attester allowlisted");
    Ok(())
}

// THE ADMIN SUITE
// ================================================================================================

/// The admin-surface entrypoint. SNAPSHOTs the faucet's deployment policy, runs the (destructive)
/// admin CHECKS, then — ALWAYS, even when a check errors mid-suite — runs a BEST-EFFORT
/// [`restore_faucet`] so a caller-supplied faucet is never left paused, attester-disabled,
/// policy-mutated, or owned by the ephemeral wallet. The checks' original error (if any) is what
/// this returns; restore failures are RECORDED as surfaced findings, never propagated over it.
pub(crate) async fn admin_suite(
    d: &mut SanityDriver,
    led: &mut Ledger,
    actors: &Actors,
    mint_attester: &AttesterKey,
    relayer_id: AccountId,
    recipient_id: AccountId,
) -> Result<()> {
    // SNAPSHOT the deployment policy BEFORE any mutation so the finally-phase restore has targets.
    let policy_before = d.fetch_faucet().await?;
    let orig_min_burn = min_burn(&policy_before)?;
    let orig_max_supply = max_supply(&policy_before)?;

    let result = admin_checks(d, led, actors, mint_attester, relayer_id, recipient_id).await;

    // FINALLY — best-effort restore, regardless of where (or whether) `admin_checks` errored. It
    // reads the faucet's ON-CHAIN owner/policy as ground truth (not any client-side flag), so an
    // accept-path failure that leaves ownership unexpectedly moved (or a nomination dangling) is
    // still detected and undone.
    super::admin_restore::restore_faucet(
        d,
        led,
        actors,
        mint_attester,
        orig_min_burn,
        orig_max_supply,
    )
    .await;

    result
}

/// The destructive admin CHECKS (assertions). Every mutation here is undone by [`restore_faucet`],
/// which `admin_suite` runs afterward in ALL cases — so this body uses `?` freely for hard infra
/// failures without stranding the faucet.
async fn admin_checks(
    d: &mut SanityDriver,
    led: &mut Ledger,
    actors: &Actors,
    mint_attester: &AttesterKey,
    relayer_id: AccountId,
    recipient_id: AccountId,
) -> Result<()> {
    use crate::assertions_cf::{ERR_NOT_OWNER, ERR_PAUSED, ERR_SUPPLY_CAP};
    use crate::assertions_de::ERR_XRESERVE_DISALLOWED_PUB_KEY;
    use crate::assertions_gj::ERR_BURN_BELOW_MIN;

    let owner_id = actors.owner.id();
    let pauser_id = actors.pauser.id();
    let holder_id = actors.holder.id();

    // ── PAUSE (DOM_PAUSER) → mint AND burn rejected while paused ──
    let pause = XReservePauseNote::create(pauser_id, d.faucet_id, d.hc.client.rng())
        .context("pause note")?;
    d.commit_via_ntx(pauser_id, pause, "pause", |a| is_paused(a).unwrap_or(false))
        .await
        .context("pausing")?;
    led.record(
        "ADMIN-PAUSE",
        "admin",
        "pause sets is_paused",
        true,
        "is_paused = true".to_string(),
    );

    let (m, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_PAUSED_MINT,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(m).await?;
    record_rejection(
        led,
        "ADMIN-PAUSE-MINT",
        "admin",
        "a mint while paused is REJECTED",
        &v,
        ERR_PAUSED,
    );

    // A burn while paused rejects (the pause gate fires before asset validation).
    let items = burn_items(BURN_UNITS).map_err(|e| anyhow::anyhow!(e))?;
    let burn_probe = XReserveBurnNote::create(holder_id, d.faucet_id, items, d.hc.client.rng())
        .context("building a burn probe note")?;
    let v = d.probe_consume(burn_probe).await?;
    record_rejection(
        led,
        "ADMIN-PAUSE-BURN",
        "admin",
        "a burn while paused is REJECTED",
        &v,
        ERR_PAUSED,
    );

    // ── UNPAUSE → mint works again ──
    let unpause = XReserveUnpauseNote::create(pauser_id, d.faucet_id, d.hc.client.rng())
        .context("unpause note")?;
    d.commit_via_ntx(pauser_id, unpause, "unpause", |a| {
        is_paused(a).map(|p| !p).unwrap_or(false)
    })
    .await
    .context("unpausing")?;
    led.record(
        "ADMIN-UNPAUSE",
        "admin",
        "unpause clears is_paused",
        true,
        "is_paused = false".to_string(),
    );

    mint_and_assert(
        d,
        led,
        relayer_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_MINT_AFTER_UNPAUSE,
        "ADMIN-UNPAUSE-MINT",
        "mint after unpause",
    )
    .await?;

    // ── ATTESTER ROTATION: disable the mint attester → its mint REJECTS → re-enable ──
    set_attester_enabled(
        d,
        owner_id,
        mint_attester.commitment_word(),
        false,
        "set_attester(mint attester, enabled=0)",
    )
    .await
    .context("disabling the mint attester")?;
    led.record(
        "ADMIN-ATTESTER-DISABLE",
        "admin",
        "set_attester(enabled=0) removes the attester from the allowlist",
        true,
        "attester allowlist marker cleared".to_string(),
    );
    let (by_disabled, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_DISABLED_ATTESTER,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(by_disabled).await?;
    record_rejection(
        led,
        "ADMIN-ATTESTER-ROTATED-OUT",
        "admin",
        "a mint by the rotated-out (disabled) attester is REJECTED",
        &v,
        ERR_XRESERVE_DISALLOWED_PUB_KEY,
    );
    set_attester_enabled(
        d,
        owner_id,
        mint_attester.commitment_word(),
        true,
        "set_attester(mint attester, re-enabled=1)",
    )
    .await
    .context("re-enabling the mint attester")?;
    led.record(
        "ADMIN-ATTESTER-REENABLE",
        "admin",
        "set_attester(enabled=1) re-adds the attester to the allowlist",
        true,
        "attester allowlist marker set again".to_string(),
    );

    // ── SET_MIN_BURN_SIZE: raise → below-min rejected; lower → at/above-min ACCEPTED ──
    let raise = XReserveSetMinBurnSizeNote::create(
        owner_id,
        d.faucet_id,
        RAISED_MIN_BURN,
        d.hc.client.rng(),
    )
    .context("set_min_burn_size(raise) note")?;
    d.commit_via_ntx(owner_id, raise, "set_min_burn_size(raise)", |a| {
        min_burn(a).map(|m| m == RAISED_MIN_BURN).unwrap_or(false)
    })
    .await
    .context("raising min_burn_size")?;
    led.record(
        "ADMIN-MINBURN-RAISE",
        "admin",
        "set_min_burn_size raises the minimum (read back)",
        true,
        format!("min_burn_size = {RAISED_MIN_BURN}"),
    );

    let items = burn_items(BURN_UNITS).map_err(|e| anyhow::anyhow!(e))?;
    let small_burn = XReserveBurnNote::create(holder_id, d.faucet_id, items, d.hc.client.rng())
        .context("below-min burn probe")?;
    let v = d.probe_consume(small_burn).await?;
    record_rejection(
        led,
        "ADMIN-MINBURN-REJECT",
        "admin",
        "a burn below the raised minimum is REJECTED",
        &v,
        ERR_BURN_BELOW_MIN,
    );

    let lower = XReserveSetMinBurnSizeNote::create(
        owner_id,
        d.faucet_id,
        LOWERED_MIN_BURN,
        d.hc.client.rng(),
    )
    .context("set_min_burn_size(lower) note")?;
    d.commit_via_ntx(owner_id, lower, "set_min_burn_size(lower)", |a| {
        min_burn(a).map(|m| m == LOWERED_MIN_BURN).unwrap_or(false)
    })
    .await
    .context("lowering min_burn_size")?;
    led.record(
        "ADMIN-MINBURN-LOWER",
        "admin",
        "set_min_burn_size lowers the minimum (read back)",
        true,
        format!("min_burn_size = {LOWERED_MIN_BURN}"),
    );

    // At/above-min burn ACCEPTED (also proves burn works AFTER unpause) — a real committed burn.
    fund_and_burn(
        d,
        led,
        mint_attester,
        relayer_id,
        holder_id,
        BURN_UNITS,
        SALT_MINT_TO_HOLDER_2,
        "ADMIN-BURN-OK",
    )
    .await
    .context("the at/above-min post-unpause burn")?;

    // ── SET_MAX_SUPPLY: mutate + read back → ENFORCE tightened cap → REJECT below-current-supply ──
    let setcap = XReserveSetMaxSupplyNote::create(
        owner_id,
        d.faucet_id,
        RAISED_MAX_SUPPLY,
        d.hc.client.rng(),
    )
    .context("set_max_supply(raise) note")?;
    let acct = d
        .commit_via_ntx(owner_id, setcap, "set_max_supply(raise)", |a| {
            max_supply(a)
                .map(|m| m == RAISED_MAX_SUPPLY)
                .unwrap_or(false)
        })
        .await
        .context("raising max_supply")?;
    led.record(
        "ADMIN-MAXSUPPLY-RAISE",
        "admin",
        "set_max_supply mutates + reads back the cap",
        max_supply(&acct)? == RAISED_MAX_SUPPLY,
        format!("max_supply = {}", max_supply(&acct)?),
    );

    // Tighten the cap to just above the running supply, then prove a mint exceeding the NEW cap is
    // rejected — the mutated cap is honored by the mint gate, not merely stored.
    let supply_now = token_supply(&d.fetch_faucet().await?)?;
    let tight_cap = supply_now + BURN_UNITS;
    let tighten =
        XReserveSetMaxSupplyNote::create(owner_id, d.faucet_id, tight_cap, d.hc.client.rng())
            .context("set_max_supply(tighten) note")?;
    d.commit_via_ntx(owner_id, tighten, "set_max_supply(tighten)", move |a| {
        max_supply(a).map(|m| m == tight_cap).unwrap_or(false)
    })
    .await
    .context("tightening max_supply")?;
    let (over_new_cap, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        BURN_UNITS * 2, // supply_now + 2·BURN_UNITS > tight_cap = supply_now + BURN_UNITS
        SALT_ENFORCE_CAP,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(over_new_cap).await?;
    record_rejection(
        led,
        "ADMIN-MAXSUPPLY-ENFORCE",
        "admin",
        "a mint exceeding the MUTATED (tightened) max_supply is REJECTED",
        &v,
        ERR_SUPPLY_CAP,
    );

    // The below-current-supply mutability GUARD: set_max_supply to a value BELOW token_supply is
    // REJECTED by the stock proc (ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY). The tightened cap
    // (supply + BURN_UNITS) is already ≥ supply, so no intermediate restore is needed here.
    let supply_guard = token_supply(&d.fetch_faucet().await?)?;
    let below = XReserveSetMaxSupplyNote::create(
        owner_id,
        d.faucet_id,
        supply_guard.saturating_sub(1),
        d.hc.client.rng(),
    )
    .context("set_max_supply(below current supply) note")?;
    let v = d.probe_consume(below).await?;
    record_rejection(
        led,
        "ADMIN-MAXSUPPLY-BELOW-SUPPLY",
        "admin",
        "set_max_supply BELOW the current token_supply is REJECTED (the mutability guard)",
        &v,
        ERR_MAX_SUPPLY_BELOW_SUPPLY,
    );

    // NOTE: min_burn_size + max_supply are left MUTATED here (min = LOWERED, max = TIGHTENED); the
    // finally-phase `restore_faucet` puts them — and the pause / attester / ownership state — back to
    // the pre-run snapshot. No positive mint runs after the tighten above, so the tightened cap does
    // not block the remaining (client-side reject) checks.

    // ── AUTHORITY GATING: a set_attester note from a sender without the ADMIN role is REJECTED.
    //    NOTE (parked-crate debt): the expected error below is still ERR_NOT_OWNER. Since the
    //    W2-ADMIN slice the setters resolve to the ADMIN role and raise ERR_SENDER_LACKS_ROLE
    //    instead. This crate is parked out of the workspace and cannot be compiled or run against
    //    the current pins, so the constant is left as-is rather than changed blind.
    let commitment = actors.attester_b.commitment_word();
    let rogue =
        XReserveSetAttesterNote::create(holder_id, d.faucet_id, commitment, 1, d.hc.client.rng())
            .context("unauthorized set_attester note")?;
    let v = d.probe_consume(rogue).await?;
    record_rejection(
        led,
        "ADMIN-OWNER-GATE",
        "admin",
        "an unauthorized admin note is REJECTED",
        &v,
        ERR_NOT_OWNER,
    );

    // ── OWNERSHIP TRANSFER (2-step) — LAST so it cannot break earlier owner-gated ops ──
    let new_owner_id = actors.new_pauser.id();
    let transfer = XReserveTransferOwnershipNote::create(
        owner_id,
        d.faucet_id,
        new_owner_id,
        d.hc.client.rng(),
    )
    .context("transfer_ownership note")?;
    d.commit_via_ntx_consumed(owner_id, transfer, "transfer_ownership")
        .await
        .context("committing transfer_ownership")?;
    led.record(
        "ADMIN-OWNER-TRANSFER",
        "admin",
        "transfer_ownership (step 1) commits",
        true,
        format!("pending owner ← {new_owner_id}"),
    );

    let accept = XReserveAcceptOwnershipNote::create(new_owner_id, d.faucet_id, d.hc.client.rng())
        .context("accept_ownership note")?;
    match d
        .commit_via_ntx_consumed(new_owner_id, accept, "accept_ownership")
        .await
    {
        Ok(_) => led.record(
            "ADMIN-OWNER-ACCEPT",
            "admin",
            "accept_ownership (step 2) completes the 2-step transfer",
            true,
            format!("owner ← {new_owner_id}"),
        ),
        Err(e) => led.record(
            "ADMIN-OWNER-ACCEPT",
            "admin",
            "accept_ownership (step 2) completes the 2-step transfer",
            false,
            format!("{e:#}"),
        ),
    }

    // Ownership restore is the FINALLY phase's job — [`super::admin_restore::restore_faucet`] reads
    // the ON-CHAIN owner as ground truth and undoes ANY move/nomination, so a failed or unobserved
    // accept above cannot leave the faucet stranded on the ephemeral wallet.
    Ok(())
}
