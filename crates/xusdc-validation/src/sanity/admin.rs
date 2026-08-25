//! The admin-surface check family + the attester-allowlist helpers.
//!
//! pause (mint+burn rejected) → unpause (mint AND burn work) → attester rotation (disabled attester's
//! mint rejected, re-enabled) → `set_min_burn_size` (below-min rejected, at/above-min accepted) →
//! `set_max_supply` (mutate + read back + tightened-cap ENFORCED + below-current-supply REJECTED) →
//! authority gating → SAN-HANDOVER (the `ADMIN` rotation arc). Split out of `checks.rs` to keep both
//! files within the G3 file-size ceiling.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::Note;
use miden_protocol::Word;
use miden_standards::account::access::RoleBasedAccessControl;
use miden_standards::note::{
    FaucetMetadataConfig, FaucetMetadataConfigNote, MinBurnAmountConfigNote, PauseConfig,
    PauseConfigNote, RbacConfig, RbacConfigNote,
};

use xusdc_encoding::note::xreserve_admin::XReserveSetAttesterNote;
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;

use crate::actors::{Actors, AttesterKey};

use super::checks::{burn_items, fund_and_burn, mint_and_assert, mint_note_for, record_rejection};
use super::driver::{
    attester_marker, holds_admin, is_paused, is_zero_word, max_supply, min_burn, token_supply,
    SanityDriver,
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

/// How far the SAN-HANDOVER sentinel moves `min_burn_size` off the value the handover starts from.
/// Any distinct value proves the write landed; the arc puts it back before the suite ends.
const HANDOVER_MIN_BURN_STEP: u64 = 1;

/// The stock `fungible::set_max_supply` guard: a new cap below the current token supply rejects.
const ERR_MAX_SUPPLY_BELOW_SUPPLY: &str = "new max supply is less than current token supply";

/// The standard pause-action note that applies `config` to `faucet_id`.
pub(super) fn pause_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: PauseConfig,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    let note = PauseConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(rng)
        .build()
        .context("building the pause configuration note")?;
    Ok(Note::from(note))
}

pub(super) fn max_supply_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    max_supply: u64,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    let note = FaucetMetadataConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(FaucetMetadataConfig::SetMaxSupply {
            max_supply: AssetAmount::new(max_supply).context("invalid maximum supply")?,
        })
        .generate_serial_number(rng)
        .build()
        .context("building the maximum-supply configuration note")?;
    Ok(Note::from(note))
}

pub(super) fn min_burn_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    min_burn_amount: u64,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    let note = MinBurnAmountConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .min_burn_amount(AssetAmount::new(min_burn_amount).context("invalid minimum burn amount")?)
        .generate_serial_number(rng)
        .build()
        .context("building the minimum-burn configuration note")?;
    Ok(Note::from(note))
}

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

// ADMIN-ROLE HELPERS
// ================================================================================================

/// The standard role-action note that grants or revokes `ADMIN` for `member`. The faucet allowlists
/// exactly this note script for role management, so it is the only surface that moves the role.
pub(super) fn admin_role_note(
    sender: AccountId,
    faucet_id: AccountId,
    member: AccountId,
    grant: bool,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    let role = RoleBasedAccessControl::admin_role();
    let config = if grant {
        RbacConfig::GrantRole {
            role,
            account: member,
        }
    } else {
        RbacConfig::RevokeRole {
            role,
            account: member,
        }
    };
    let note = RbacConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(rng)
        .build()
        .context("building the ADMIN role-action note")?;
    Ok(Note::from(note))
}

/// Commits a grant or revoke of `ADMIN` for `member` via path N and waits for the committed
/// membership to reach the requested state. `sender` must already hold `ADMIN`: the role administers
/// itself, so every caller picks the sender that holds it in the state it is acting from.
pub(super) async fn set_admin_member(
    d: &mut SanityDriver,
    sender: AccountId,
    member: AccountId,
    grant: bool,
    op: &str,
) -> Result<()> {
    let note = admin_role_note(sender, d.faucet_id, member, grant, d.hc.client.rng())
        .with_context(|| format!("building the {op} note"))?;
    d.commit_via_ntx(sender, note, op, move |a| {
        holds_admin(a, member).map(|h| h == grant).unwrap_or(false)
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
/// policy-mutated, or with `ADMIN` still held by the ephemeral successor. The checks' original error
/// (if any) is what this returns; restore failures are RECORDED as surfaced findings, never
/// propagated over it.
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
    // reads the faucet's ON-CHAIN policy as ground truth, not any client-side flag.
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
    use crate::assertions_cf::{ERR_LACKS_ROLE, ERR_PAUSED, ERR_SUPPLY_CAP};
    use crate::assertions_de::ERR_XRESERVE_DISALLOWED_PUB_KEY;
    use crate::assertions_gj::ERR_BURN_BELOW_MIN;

    let owner_id = actors.owner.id();
    let pauser_id = actors.pauser.id();
    let holder_id = actors.holder.id();

    // ── PAUSE (DOM_PAUSER) → mint AND burn rejected while paused ──
    let pause = pause_config_note(
        pauser_id,
        d.faucet_id,
        PauseConfig::Pause,
        d.hc.client.rng(),
    )?;
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
    let unpause = pause_config_note(
        pauser_id,
        d.faucet_id,
        PauseConfig::Unpause,
        d.hc.client.rng(),
    )?;
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
    let raise = min_burn_config_note(owner_id, d.faucet_id, RAISED_MIN_BURN, d.hc.client.rng())
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

    let lower = min_burn_config_note(owner_id, d.faucet_id, LOWERED_MIN_BURN, d.hc.client.rng())
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
    let setcap =
        max_supply_config_note(owner_id, d.faucet_id, RAISED_MAX_SUPPLY, d.hc.client.rng())
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
    let tighten = max_supply_config_note(owner_id, d.faucet_id, tight_cap, d.hc.client.rng())
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
    let below = max_supply_config_note(
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
    // finally-phase `restore_faucet` puts them — and the pause / attester state — back to
    // the pre-run snapshot. No positive mint runs after the tighten above, so the tightened cap does
    // not block the remaining (client-side reject) checks.

    // ── AUTHORITY GATING: a set_attester note from a sender without the ADMIN role is REJECTED.
    let commitment = actors.attester_b.commitment_word();
    let rogue =
        XReserveSetAttesterNote::create(holder_id, d.faucet_id, commitment, 1, d.hc.client.rng())
            .context("unauthorized set_attester note")?;
    let v = d.probe_consume(rogue).await?;
    record_rejection(
        led,
        "ADMIN-ROLE-GATE",
        "admin",
        "an unauthorized admin note is REJECTED",
        &v,
        ERR_LACKS_ROLE,
    );

    // ── SAN-HANDOVER — LAST, so a mid-arc failure cannot strand the earlier ADMIN-gated checks ──
    admin_handover(d, led, actors).await?;

    Ok(())
}

/// **SAN-HANDOVER** — the `ADMIN` rotation arc on a real node, through path N.
///
/// `ADMIN` is the faucet's sole authority handle, and grant-then-revoke of it is the product's
/// documented rotation path, so this drives that path end to end against an ephemeral successor:
/// hand the role out, prove the successor can actually USE it (not merely that the map says so),
/// prove the predecessor is locked out, then hand it back and prove the lockout reverses. Every
/// membership mutation commits through path N and is read back from the committed account, and the
/// two capability probes execute client-side so a rejected op cannot move state.
///
/// The order is lockout-safe throughout: a grant always precedes the matching revoke, so `ADMIN`
/// never drops below one member — an empty `ADMIN` on this faucet is permanent and would forfeit
/// every ADMIN-gated setter.
async fn admin_handover(d: &mut SanityDriver, led: &mut Ledger, actors: &Actors) -> Result<()> {
    use crate::assertions_cf::ERR_LACKS_ROLE;

    let original = actors.owner.id();
    let successor = actors.new_pauser.id();

    // The value the successor's ADMIN-gated write moves min_burn AWAY from, and the original moves
    // it back to — read from the live faucet so the restore target is the seeded value, not a guess.
    let seeded_min_burn = min_burn(&d.fetch_faucet().await?)?;

    // 1. HANDOVER OUT — the original grants ADMIN to the ephemeral successor.
    set_admin_member(d, original, successor, true, "grant_role(ADMIN, successor)")
        .await
        .context("granting ADMIN to the ephemeral successor")?;
    let acct = d.fetch_faucet().await?;
    led.record(
        "SAN-HANDOVER-GRANT",
        "admin",
        "the original ADMIN grants ADMIN to an ephemeral successor (both hold it)",
        holds_admin(&acct, successor)? && holds_admin(&acct, original)?,
        format!("ADMIN membership: original {original} + successor {successor}"),
    );

    // 2. SUCCESSOR CAPABILITY — proven by an ADMIN-gated WRITE that lands, not by reading the map.
    //    The sentinel must be a value the floor does not already hold, or the read-back would pass
    //    without anything having been written — so the step is checked, never wrapped.
    let sentinel = seeded_min_burn
        .checked_add(HANDOVER_MIN_BURN_STEP)
        .context("the min-burn floor is too high to carry a distinct handover sentinel")?;
    let note = min_burn_config_note(successor, d.faucet_id, sentinel, d.hc.client.rng())
        .context("set_min_burn_size(successor sentinel) note")?;
    let acct = d
        .commit_via_ntx(
            successor,
            note,
            "set_min_burn_size(successor sentinel)",
            move |a| min_burn(a).map(|m| m == sentinel).unwrap_or(false),
        )
        .await
        .context("the successor's ADMIN-gated write")?;
    led.record(
        "SAN-HANDOVER-SUCCESSOR-WRITES",
        "admin",
        "the successor's ADMIN-gated setter COMMITS and reads back (capability, not membership)",
        min_burn(&acct)? == sentinel,
        format!("min_burn_size = {} (sentinel {sentinel})", min_burn(&acct)?),
    );

    // 3. PREDECESSOR LOCKOUT — the successor revokes the original, whose next ADMIN op then rejects.
    set_admin_member(
        d,
        successor,
        original,
        false,
        "revoke_role(ADMIN, original)",
    )
    .await
    .context("revoking the original's ADMIN")?;
    let acct = d.fetch_faucet().await?;
    led.record(
        "SAN-HANDOVER-REVOKE-PREDECESSOR",
        "admin",
        "the successor revokes the predecessor's ADMIN, and the successor still holds it",
        !holds_admin(&acct, original)? && holds_admin(&acct, successor)?,
        format!("ADMIN membership: successor {successor} only"),
    );
    let locked_out =
        min_burn_config_note(original, d.faucet_id, seeded_min_burn, d.hc.client.rng())
            .context("set_min_burn_size(locked-out predecessor) note")?;
    let v = d.probe_consume(locked_out).await?;
    record_rejection(
        led,
        "SAN-HANDOVER-PREDECESSOR-LOCKED-OUT",
        "admin",
        "the revoked predecessor's next ADMIN-gated op is REJECTED",
        &v,
        ERR_LACKS_ROLE,
    );

    // 4. HANDOVER BACK — grant BEFORE revoke, so ADMIN is never empty even between the two commits.
    set_admin_member(
        d,
        successor,
        original,
        true,
        "grant_role(ADMIN, original) (handover back)",
    )
    .await
    .context("granting ADMIN back to the original")?;
    set_admin_member(
        d,
        original,
        successor,
        false,
        "revoke_role(ADMIN, successor)",
    )
    .await
    .context("revoking the ephemeral successor's ADMIN")?;
    let acct = d.fetch_faucet().await?;
    led.record(
        "SAN-HANDOVER-BACK",
        "admin",
        "ADMIN is back with the original alone, granted before the successor was revoked",
        holds_admin(&acct, original)? && !holds_admin(&acct, successor)?,
        format!("ADMIN membership: original {original} only"),
    );

    // The original proves its recovered capability the same way the successor proved its own: by
    // moving the sentinel back to the value the handover started from.
    let restore = min_burn_config_note(original, d.faucet_id, seeded_min_burn, d.hc.client.rng())
        .context("set_min_burn_size(sentinel restore) note")?;
    let acct = d
        .commit_via_ntx(
            original,
            restore,
            "set_min_burn_size(sentinel restore)",
            move |a| min_burn(a).map(|m| m == seeded_min_burn).unwrap_or(false),
        )
        .await
        .context("the original's post-handover ADMIN-gated write")?;
    led.record(
        "SAN-HANDOVER-ORIGINAL-WRITES",
        "admin",
        "the restored original's ADMIN-gated setter COMMITS and reads back the seeded value",
        min_burn(&acct)? == seeded_min_burn,
        format!("min_burn_size = {seeded_min_burn} (back to the pre-handover value)"),
    );

    let ejected = min_burn_config_note(successor, d.faucet_id, sentinel, d.hc.client.rng())
        .context("set_min_burn_size(ejected successor) note")?;
    let v = d.probe_consume(ejected).await?;
    record_rejection(
        led,
        "SAN-HANDOVER-SUCCESSOR-LOCKED-OUT",
        "admin",
        "the revoked successor's next ADMIN-gated op is REJECTED",
        &v,
        ERR_LACKS_ROLE,
    );

    Ok(())
}
