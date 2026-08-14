//! The check families: mint (scale-0 identity), attestation + fund-safety negatives, the burn arc
//! (structure + attester-consumability + DC-8 evidence), and the full admin surface (pause/unpause,
//! attester rotation, min-burn accept/reject, max-supply mutate + enforce, owner-gating, 2-step
//! ownership). Positive faucet consumptions commit via path N; negatives execute client-side.

use anyhow::{Context, Result};
use miden_protocol::account::AccountId;
use miden_protocol::note::Note;
use miden_standards::note::NetworkAccountTarget;

use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::note_decode::decode_burn_payload;
use withdrawal_listener_attester::validate::{
    validate_discovery, DiscoveredDetails, DiscoveryRecord,
};

use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};
use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::XReserveBurnItems;

use crate::actors::AttesterKey;
use crate::mintburn::{mint_payload_opt, nonce_key, MintDomainConfig, MINT_DOMAIN};
use crate::observations_cf::Verdict;

use super::driver::{
    is_zero_word, max_supply, token_supply, used_nonce_marker, word4, SanityDriver,
};
use super::{Ledger, BURN_UNITS, MINT_ROUND_UNITS};

// Distinct nonce salts so otherwise-identical mints carry distinct nonces (avoiding the replay gate
// across probes). The REPLAY negative deliberately reuses [`SALT_MINT_ROUND`] (the orchestrator
// mints the round amount with the same salt), so a single source keeps them aligned.
pub(crate) const SALT_MINT_ROUND: u8 = 0x11;
pub(crate) const SALT_MINT_NONROUND: u8 = 0x22;
const SALT_MINT_TO_HOLDER: u8 = 0x33;
const SALT_WRONG_ATTESTER: u8 = 0x44;
const SALT_FORGED_SIG: u8 = 0x55;
const SALT_OVER_CAP: u8 = 0x66;

/// The destination-domain a burn payload carries (local test value; DEV withdrawal identity).
const BURN_DEST_DOMAIN: u32 = 3;

// MINT-NOTE + BURN-ITEM HELPERS
// ================================================================================================

/// A production mint note for `amount_units` (raw==minted under scale-0) to `recipient`, signed by
/// `attester`. Returns `(note, payload)` so the caller can derive the nonce key. `config` is the
/// deployed faucet's domain config on the `--faucet-id` path (its `remoteDomain`/`remoteToken` are
/// spliced so the structural validation gate accepts the mint) and `None` on the fresh-LOCAL gate (the BASE_VECTOR
/// header is used unchanged).
pub(crate) fn mint_note_for(
    sender: AccountId,
    faucet_id: AccountId,
    attester: &AttesterKey,
    recipient: AccountId,
    amount_units: u64,
    nonce_salt: u8,
    config: Option<MintDomainConfig>,
    rng: &mut impl miden_protocol::crypto::rand::FeltRng,
) -> Result<(Note, Vec<u8>)> {
    // maxFee = 0 (R-MINT-10: maxFee ≤ amount trivially holds); scale-0 ⇒ raw amount == minted units.
    let payload = mint_payload_opt(config.as_ref(), recipient, amount_units, 0, nonce_salt);
    let attestation = attester.attestation_for(&payload);
    let note = XUsdcMintNote::create(sender, faucet_id, &payload, &attestation, rng)
        .context("building a production mint note")?;
    Ok((note, payload))
}

/// A mint note whose attestation is a forged signature over the WRONG digest (well-formed ECDSA that
/// `verify_prehash` runs to completion and rejects) — the R-MINT signature negative.
fn mint_note_forged_sig(
    sender: AccountId,
    faucet_id: AccountId,
    attester: &AttesterKey,
    recipient: AccountId,
    amount_units: u64,
    nonce_salt: u8,
    config: Option<MintDomainConfig>,
    rng: &mut impl miden_protocol::crypto::rand::FeltRng,
) -> Result<Note> {
    // Carry the deployed faucet's domain/identifier too, so the mint reaches the attestation verification signature gate
    // (a wrong domain would reject earlier at structural validation, hiding the signature negative under WRONG_DOMAIN).
    let payload = mint_payload_opt(config.as_ref(), recipient, amount_units, 0, nonce_salt);
    let forged: DepositAttestation = attester.attestation_over_digest([0xEE; 32]);
    XUsdcMintNote::create(sender, faucet_id, &payload, &forged, rng)
        .context("building a forged-signature mint note")
}

/// The mandated burn items (amount + local-test withdrawal identity).
pub(crate) fn burn_items(amount: u64) -> Result<XReserveBurnItems> {
    Ok(XReserveBurnItems {
        amount: miden_protocol::asset::AssetAmount::new(amount)
            .context("valid burn AssetAmount")?,
        dest_domain: BURN_DEST_DOMAIN,
        dest_recipient: [0xAB; 32],
        salt: [0xCD; 32],
    })
}

// PUBLIC ASSERTION HELPERS (also unit-tested offline)
// ================================================================================================

/// Structural assertions on a produced `XReserveBurnNote`: exactly ONE attachment — the scheme-2
/// `NetworkAccountTarget` routing to `faucet_id` — tag `0x4255_524E`, and the DC-7 payload fields
/// (amount/destDomain/destRecipient/salt) decoding to the expected values. `Ok(detail)` on a correct
/// note; `Err(specific reason)` naming the exact structural mismatch.
pub fn assert_burn_note_structure(
    note: &Note,
    faucet_id: AccountId,
    expected: &XReserveBurnItems,
) -> Result<String, String> {
    let tag = note.metadata().tag().as_u32();
    if tag != FIXED_XUSDC_BURN_TAG {
        return Err(format!(
            "burn tag 0x{tag:08X} != 0x{FIXED_XUSDC_BURN_TAG:08X}"
        ));
    }
    let num = note.attachments().num_attachments();
    if num != 1 {
        return Err(format!(
            "burn note carries {num} attachments, expected exactly 1 (the routing target)"
        ));
    }
    let target = NetworkAccountTarget::try_from(note.attachments())
        .map_err(|e| format!("no decodable NetworkAccountTarget attachment: {e}"))?;
    if target.target_id() != faucet_id {
        return Err(format!(
            "routing attachment targets {} != faucet {}",
            target.target_id(),
            faucet_id
        ));
    }
    let items = note.recipient().storage().items().to_vec();
    let decoded = decode_burn_payload(&items).map_err(|e| format!("DC-7 decode failed: {e:?}"))?;
    if u64::from(decoded.amount) != u64::from(expected.amount) {
        return Err(format!(
            "burn payload amount {} != expected {}",
            u64::from(decoded.amount),
            u64::from(expected.amount)
        ));
    }
    if decoded.dest_domain != expected.dest_domain {
        return Err(format!(
            "destDomain {} != {}",
            decoded.dest_domain, expected.dest_domain
        ));
    }
    if decoded.dest_recipient != expected.dest_recipient {
        return Err("destRecipient mismatch".to_string());
    }
    if decoded.salt != expected.salt {
        return Err("salt mismatch".to_string());
    }
    Ok(format!(
        "tag 0x{tag:08X}, one NetworkAccountTarget → faucet, amount={} destDomain={} (DC-7 decoded)",
        u64::from(decoded.amount),
        decoded.dest_domain
    ))
}

/// The withdrawal attester's OWN discovery/decode over the burn note: the exact-tag
/// `validate_discovery` checklist (findable-by-tag + decodable + sender-valid) plus a direct
/// `decode_burn_payload`. `Err` is the attester's own rejection reason (used both for the positive
/// check and to prove a foreign-tag note is REJECTED in the offline tests).
pub fn assert_attester_consumable(note: &Note, faucet_id: AccountId) -> Result<String, String> {
    let items = note.recipient().storage().items().to_vec();
    let tag = note.metadata().tag().as_u32();
    let record = DiscoveryRecord::new(
        tag,
        Some(DiscoveredDetails::from_metadata(
            items.clone(),
            note.metadata(),
        )),
    );
    let cfg = ListenerConfig::builder()
        .burn_tag(FIXED_XUSDC_BURN_TAG)
        .faucet_id(faucet_id)
        .build()
        .map_err(|e| format!("building the attester listener config: {e:?}"))?;
    let discovered = validate_discovery(&record, &cfg)
        .map_err(|e| format!("attester validate_discovery REJECTED the burn note: {e:?}"))?;
    let payload = decode_burn_payload(&items)
        .map_err(|e| format!("attester decode_burn_payload failed: {e:?}"))?;
    Ok(format!(
        "attester validate_discovery ACCEPTED (depositor {}, amount {}); decode_burn_payload OK",
        discovered.depositor(),
        u64::from(payload.amount)
    ))
}

// REJECTION MATCHING
// ================================================================================================

/// The deterministic `err_code` a MASM assertion of `msg` embeds — the SAME hash the assembler bakes
/// into the compiled proc and the v16 executor surfaces (the human string is absent from
/// `FailedAssertion`). Mirrors `assertions_de::err_code_for`.
pub(crate) fn err_code_for(msg: &str) -> u64 {
    miden_protocol::errors::MasmError::new(msg.to_string())
        .code()
        .as_canonical_u64()
}

/// Records a negative as pass iff the verdict is REJECTED and the captured error is the `expected`
/// gate — matched on the message substring OR the expected string's `err_code`.
pub(crate) fn record_rejection(
    led: &mut Ledger,
    id: &str,
    area: &str,
    what: &str,
    verdict: &Verdict,
    expected: &str,
) {
    match verdict {
        Verdict::Accepted => led.record(
            id,
            area,
            what,
            false,
            "ACCEPTED (defect — the gate did not fire)".to_string(),
        ),
        Verdict::Rejected(msg) => {
            let code_marker = format!("err_code: {}", err_code_for(expected));
            let ok = msg.contains(expected) || msg.contains(&code_marker);
            let detail = if ok {
                format!("REJECTED with the '{expected}' gate ({code_marker})")
            } else {
                format!(
                    "REJECTED but NOT with '{expected}' (nor its {code_marker}): {}",
                    truncate(msg, 200)
                )
            };
            led.record(id, area, what, ok, detail);
        }
    }
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n).collect();
        format!("{cut}…")
    }
}

// MINT CHECKS
// ================================================================================================

/// Runs one positive mint via path N and records the scale-0 identity assertions: supply delta ==
/// amount, recipient P2ID amount == amount, nonce marker written.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mint_and_assert(
    d: &mut SanityDriver,
    led: &mut Ledger,
    relayer_id: AccountId,
    attester: &AttesterKey,
    recipient_id: AccountId,
    amount: u64,
    salt: u8,
    id: &str,
    label: &str,
) -> Result<()> {
    let supply_before = token_supply(&d.fetch_faucet().await?)?;
    let (note, payload) = mint_note_for(
        relayer_id,
        d.faucet_id,
        attester,
        recipient_id,
        amount,
        salt,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let key = nonce_key(&payload);

    let committed = d
        .commit_via_ntx(relayer_id, note, &format!("mint {label}"), |a| {
            token_supply(a)
                .map(|s| s >= supply_before + amount)
                .unwrap_or(false)
        })
        .await
        .with_context(|| format!("committing mint {label} via path N"))?;
    let supply_after = token_supply(&committed)?;

    led.record(
        id,
        "mint",
        &format!("{label}: token_supply rises by EXACTLY the deposit amount (scale-0 identity)"),
        supply_after == supply_before + amount,
        format!(
            "supply {supply_before} → {supply_after} (Δ {}, expected {amount})",
            supply_after.saturating_sub(supply_before)
        ),
    );

    let marker = used_nonce_marker(&committed, key)?;
    led.record(
        &format!("{id}-NONCE"),
        "mint",
        &format!("{label}: usedNonces[nonce] marker written"),
        !is_zero_word(marker),
        format!("marker {:?}", word4(marker)),
    );

    match d.wait_for_target_note(recipient_id, amount).await {
        Ok(_) => led.record(
            &format!("{id}-DEST"),
            "mint",
            &format!("{label}: recipient receives a P2ID of EXACTLY {amount} units"),
            true,
            format!("recipient {recipient_id} ← {amount} units"),
        ),
        Err(e) => led.record(
            &format!("{id}-DEST"),
            "mint",
            &format!("{label}: recipient receives a P2ID of EXACTLY {amount} units"),
            false,
            format!("no matching P2ID: {e}"),
        ),
    }
    Ok(())
}

// FUND-SAFETY + ATTESTATION NEGATIVES
// ================================================================================================

/// wrong-attester, forged-signature, replay, over-cap — each executed CLIENT-SIDE and asserted to
/// REJECT with the exact gate error, leaving supply intact. `mint_attester` is the allowlisted key;
/// `wrong_attester` is a distinct non-allowlisted key.
pub(crate) async fn negatives_suite(
    d: &mut SanityDriver,
    led: &mut Ledger,
    relayer_id: AccountId,
    mint_attester: &AttesterKey,
    wrong_attester: &AttesterKey,
    recipient_id: AccountId,
) -> Result<()> {
    use crate::assertions_cf::ERR_SUPPLY_CAP;
    use crate::assertions_de::{
        ERR_XRESERVE_DISALLOWED_PUB_KEY, ERR_XRESERVE_NONCE_REPLAY, ERR_XRESERVE_SIG_INVALID,
    };

    let supply_before = token_supply(&d.fetch_faucet().await?)?;

    let (wrong, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        wrong_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_WRONG_ATTESTER,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(wrong).await?;
    record_rejection(
        led,
        "NEG-WRONG-ATTESTER",
        "attestation",
        "a mint by a non-allowlisted attester is REJECTED",
        &v,
        ERR_XRESERVE_DISALLOWED_PUB_KEY,
    );

    let forged = mint_note_forged_sig(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_FORGED_SIG,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(forged).await?;
    record_rejection(
        led,
        "NEG-FORGED-SIG",
        "attestation",
        "a mint with a forged signature is REJECTED",
        &v,
        ERR_XRESERVE_SIG_INVALID,
    );

    // Replay: reuse the round mint's nonce (same salt) → nonce-replay gate.
    let (replay, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        MINT_ROUND_UNITS,
        SALT_MINT_ROUND,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(replay).await?;
    record_rejection(
        led,
        "NEG-REPLAY",
        "fund-safety",
        "a replayed nonce is REJECTED (no double-mint)",
        &v,
        ERR_XRESERVE_NONCE_REPLAY,
    );

    // Over-cap: read the faucet's ACTUAL cap + supply (a fresh local deploy OR a deployment-specific
    // devnet cap — DEV-5 stays OPEN) and mint the MINIMAL amount that pushes token_supply past it, so
    // the probe is genuinely parameterized to whatever faucet is under test (never a hardcoded 2e12).
    let faucet_now = d.fetch_faucet().await?;
    let cap_now = max_supply(&faucet_now)?;
    let supply_now = token_supply(&faucet_now)?;
    let over_cap_amount = cap_now.saturating_sub(supply_now).saturating_add(1);
    let (overcap, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        recipient_id,
        over_cap_amount,
        SALT_OVER_CAP,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let v = d.probe_consume(overcap).await?;
    record_rejection(
        led,
        "NEG-OVER-CAP",
        "fund-safety",
        &format!(
            "a mint exceeding the faucet's CURRENT cap ({cap_now}, supply {supply_now}) is REJECTED"
        ),
        &v,
        ERR_SUPPLY_CAP,
    );

    let supply_after = token_supply(&d.fetch_faucet().await?)?;
    led.record(
        "NEG-NO-SUPPLY-MOVE",
        "fund-safety",
        "no rejected mint moved token_supply",
        supply_after == supply_before,
        format!("supply {supply_before} → {supply_after} (unchanged)"),
    );
    Ok(())
}

// BURN ARC
// ================================================================================================

/// Funds `holder` with `amount` (mint → holder → consume P2ID), builds a production burn note, and
/// commits the faucet's burn via path N. Returns the burn note (committed + consumed) for the DC-8
/// evidence read.
pub(crate) async fn fund_and_burn(
    d: &mut SanityDriver,
    led: &mut Ledger,
    mint_attester: &AttesterKey,
    relayer_id: AccountId,
    holder_id: AccountId,
    amount: u64,
    mint_salt: u8,
    id_prefix: &str,
) -> Result<Note> {
    let (mint, _) = mint_note_for(
        relayer_id,
        d.faucet_id,
        mint_attester,
        holder_id,
        amount,
        mint_salt,
        d.mint_config,
        d.hc.client.rng(),
    )?;
    let supply_before_fund = token_supply(&d.fetch_faucet().await?)?;
    d.commit_via_ntx(relayer_id, mint, "mint → holder (burn funding)", |a| {
        token_supply(a)
            .map(|s| s >= supply_before_fund + amount)
            .unwrap_or(false)
    })
    .await
    .context("funding the holder for the burn")?;
    let p2id = d
        .wait_for_target_note(holder_id, amount)
        .await
        .context("holder P2ID")?;
    d.target_consume(holder_id, p2id)
        .await
        .context("holder consuming its P2ID")?;
    let holder_bal = d.balance_of(holder_id).await?;
    led.record(
        &format!("{id_prefix}-FUND"),
        "burn",
        "the holder holds the minted xUSDC before burning",
        holder_bal >= amount,
        format!("holder balance {holder_bal} (need ≥ {amount})"),
    );

    let items = burn_items(amount).map_err(|e| anyhow::anyhow!(e))?;
    let burn = XReserveBurnNote::create(holder_id, d.faucet_id, items, d.hc.client.rng())
        .context("building the production burn note")?;

    let supply_before_burn = token_supply(&d.fetch_faucet().await?)?;
    let target_supply = supply_before_burn.saturating_sub(amount);
    let committed = d
        .commit_via_ntx(
            holder_id,
            burn.clone(),
            &format!("burn {amount}"),
            move |a| token_supply(a).map(|s| s == target_supply).unwrap_or(false),
        )
        .await
        .context("committing the burn via path N")?;
    led.record(
        &format!("{id_prefix}-AMOUNT"),
        "burn",
        "token_supply decrements by EXACTLY the burned amount",
        token_supply(&committed)? == target_supply,
        format!(
            "supply {supply_before_burn} → {} (Δ -{amount} expected)",
            token_supply(&committed)?
        ),
    );
    Ok(burn)
}

/// The mandated burn (50 xUSDC): fund + burn + supply decrement, plus the readiness checks on the
/// produced note — structure, attester-consumability, and the DC-8 evidence assembly against the
/// real committed+consumed note.
pub(crate) async fn burn_and_assert(
    d: &mut SanityDriver,
    led: &mut Ledger,
    mint_attester: &AttesterKey,
    relayer_id: AccountId,
    holder_id: AccountId,
) -> Result<()> {
    let expected_items = burn_items(BURN_UNITS).map_err(|e| anyhow::anyhow!(e))?;

    let burn = fund_and_burn(
        d,
        led,
        mint_attester,
        relayer_id,
        holder_id,
        BURN_UNITS,
        SALT_MINT_TO_HOLDER,
        "BURN",
    )
    .await?;

    // Structure: tag, single NetworkAccountTarget → faucet, DC-7 payload fields.
    match assert_burn_note_structure(&burn, d.faucet_id, &expected_items) {
        Ok(detail) => led.record(
            "BURN-STRUCT",
            "burn",
            "the burn note is a correct public XReserveBurnNote",
            true,
            detail,
        ),
        Err(e) => led.record(
            "BURN-STRUCT",
            "burn",
            "the burn note is a correct public XReserveBurnNote",
            false,
            e,
        ),
    }
    // Attester-consumability: findable-by-tag + decodable (the attester's OWN code).
    match assert_attester_consumable(&burn, d.faucet_id) {
        Ok(detail) => led.record(
            "BURN-ATTESTER",
            "burn",
            "the burn note is discoverable + decodable by the withdrawal attester",
            true,
            detail,
        ),
        Err(e) => led.record(
            "BURN-ATTESTER",
            "burn",
            "the burn note is discoverable + decodable by the withdrawal attester",
            false,
            e,
        ),
    }
    // Exact-tag SyncNotes discovery on the REAL node (the attester's B3 discovery RPC) — proving the
    // committed burn note is findable by its fixed tag, not merely decodable from an in-memory copy.
    let discover_what =
        "the committed burn note is discoverable by exact-tag SyncNotes on the node";
    match d.syncnotes_discovers(FIXED_XUSDC_BURN_TAG, burn.id()).await {
        Ok(true) => led.record(
            "BURN-DISCOVER",
            "burn",
            discover_what,
            true,
            format!(
                "SyncNotes(tag 0x{FIXED_XUSDC_BURN_TAG:08X}) returned note {}",
                burn.id()
            ),
        ),
        Ok(false) => led.record(
            "BURN-DISCOVER",
            "burn",
            discover_what,
            false,
            "SyncNotes(tag) did NOT return the committed burn note".to_string(),
        ),
        Err(e) => led.record(
            "BURN-DISCOVER",
            "burn",
            discover_what,
            false,
            format!("{e:#}"),
        ),
    }

    // DC-8 evidence: the attester's OWN assemble_evidence over the real committed+consumed note.
    match super::evidence::assert_burn_evidence(&d.hc, &burn, d.faucet_id).await {
        Ok(detail) => led.record(
            "BURN-EVIDENCE",
            "burn",
            "the DC-8 evidence packet (note_id/nullifier/block_num/burnTxId) assembles via the attester's assemble_evidence",
            true,
            detail,
        ),
        Err(e) => led.record(
            "BURN-EVIDENCE",
            "burn",
            "the DC-8 evidence packet (note_id/nullifier/block_num/burnTxId) assembles via the attester's assemble_evidence",
            false,
            e,
        ),
    }
    Ok(())
}
