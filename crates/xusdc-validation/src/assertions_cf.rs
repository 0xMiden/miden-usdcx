//! Rows-C (admin suite) + row-F (auth boundary) assertion suite — written test-first, before the
//! real-node driver (`crate::rows_cf`), judging the [`RowsCfObservations`] it produces.
//!
//! Matrix rows:
//! - **C1 `set_attester`** — allowlist attester A → rotate to B → a mint attested by A is REJECTED,
//!   by B ACCEPTED.
//! - **C2 `set_min_burn_size`** — raise → a below-new-min burn is REJECTED; lower → an at-min burn
//!   PASSES.
//! - **C3 `set_max_supply`** — adjust the cap; a mint exceeding it REJECTS (`ERR_XRESERVE_SUPPLY_CAP`).
//! - **C4 pause/unpause (DOM_PAUSER)** — paused ⇒ mint AND burn REJECTED; the owner's
//!   `set_attester`/`set_min_burn_size` STILL SUCCEED while paused (F6); unpause restores.
//! - **C5 role rotation** — DOM_MANAGER grants DOM_PAUSER to a new account (new pauser can pause,
//!   revoked cannot) — the CMP-F5 seam on a real node.
//! - **C6 negatives** — every admin note from a NON-authorized sender rejects at the proc gate.
//! - **Row F** — a non-allowlisted note is rejected by `AuthNetworkAccount`; a non-allowlisted
//!   (`nop`) tx-script transaction is rejected (the v16 tx-script allowlist admits ONLY the S12
//!   expiration root, so any other script traps).
//!
//! Every check reads the NODE-fetched verdicts/read-backs carried by [`RowsCfObservations`] — a green
//! here is a statement about the real chain, not about the client's local store.

use anyhow::{bail, ensure, Result};
use miden_protocol::errors::MasmError;

use crate::observations_cf::{
    AdminGateReject, C1SetAttester, C2MinBurn, C3MaxSupply, C4Pause, C5RoleRotation, RowF,
    RowsCfObservations, Verdict, Word4, MARKER_CLEAR, MARKER_SET,
};

// EXACT on-chain error substrings the rejects must carry (single source of truth in the shipped
// MASM: `deposit_intent_parser.masm` / `attestation.masm` / `mint_policy.masm` /
// `pause_admin.masm` for the xreserve-owned gates, and — since the Wave-1 S1 recomposition — the
// STOCK miden-standards MASM for the burn floor (`min_burn_amount.masm`), the supply cap
// (`fungible.masm` distribute), the owner/role gates, and the note/tx-script allowlist
// primitives). A reject that does not carry ITS error is not the gate the row proves — the
// assertion rejects it.
// ================================================================================================

/// attestation verification: the attester pubkey commitment is not in the on-chain `xReserveAttesters` allowlist.
pub const ERR_ATTESTER_NOT_ALLOWLISTED: &str =
    "deposit attester pubkey commitment is not allowlisted";
/// R-BURN-2 — the STOCK `MinBurnAmount::check_policy` floor gate (Wave-1 S1: the custom
/// `burn_policy.masm` below-min error is gone; the stock policy asserts `min <= amount`).
pub const ERR_BURN_BELOW_MIN: &str =
    "amount to be burned must exceed specified minimum burn amount";
/// R-MINT-15 semantics, now STOCK-owned (Wave-1 S1): the supply cap fires in the stock
/// `fungible.masm` distribute discipline, not a custom xreserve gate.
pub const ERR_SUPPLY_CAP: &str =
    "token_supply plus the amount passed to distribute would exceed the maximum supply";
/// R-BURN-3 / the mint pause gate: the contract is paused.
pub const ERR_PAUSED: &str = "the contract is paused";
/// The administrator gate on the ADMIN-role-gated admin setters.
pub const ERR_NOT_OWNER: &str = "note sender is not the owner";
/// The DOM_PAUSER role gate on the custom pause/unpause procs.
pub const ERR_LACKS_ROLE: &str = "note sender does not hold the required role";
/// `AuthNetworkAccount`: a consumed input note's script root is not in the note-script allowlist.
pub const ERR_NOTE_NOT_ALLOWLISTED: &str =
    "input note script root is not in the note script allowlist";
/// `AuthNetworkAccount`: the transaction script root is not in the tx-script allowlist.
pub const ERR_TX_SCRIPT_NOT_ALLOWLISTED: &str =
    "transaction script root is not in the tx script allowlist";

// SHARED CHECK HELPERS
// ================================================================================================

/// The `err_code` (the deterministic `error_code_from_msg` hash) a MASM assertion of `msg` embeds —
/// the SAME value the assembler bakes into the compiled proc and the executor surfaces. Lets a
/// reject be matched on its code when the message itself is absent (see [`assert_rejected_with`]).
fn err_code_for(msg: &str) -> u64 {
    // MasmError::code() == assembly::mast::error_code_from_msg(msg); protocol-version-stable.
    MasmError::new(msg.to_string()).code().as_canonical_u64()
}

/// Asserts a verdict is REJECTED and its captured error is the `expected` gate.
///
/// A gate is identified by EITHER its message OR its `err_code`: STOCK miden-standards MASM (the
/// owner / role / pause / note+tx-script-allowlist gates) surfaces a client-side trap with
/// `err_msg: None`, carrying only the deterministic `err_code`; xreserve-owned MASM (the
/// attestation / burn-policy / supply-cap gates) additionally carries the message text. So a reject
/// matches iff the captured error contains the expected message substring OR the expected error's
/// `err_code: <n>` — both derived from the single expected string, never a hardcoded magic number.
fn assert_rejected_with(v: &Verdict, expected: &str, ctx: &str) -> Result<()> {
    match v {
        Verdict::Accepted => {
            bail!(
                "{ctx}: expected a REJECT carrying '{expected}', but the consumption was ACCEPTED"
            )
        }
        Verdict::Rejected(err) => {
            let code_marker = format!("err_code: {}", err_code_for(expected));
            ensure!(
                err.contains(expected) || err.contains(&code_marker),
                "{ctx}: the consumption was rejected, but NOT with the expected gate error \
                 '{expected}' (nor its {code_marker}); got: {err}",
            );
            Ok(())
        }
    }
}

/// Asserts a verdict is ACCEPTED (the consumption executed against real chain state with no trap).
fn assert_accepted(v: &Verdict, ctx: &str) -> Result<()> {
    match v {
        Verdict::Accepted => Ok(()),
        Verdict::Rejected(err) => {
            bail!("{ctx}: expected the consumption to be ACCEPTED, but it was REJECTED: {err}")
        }
    }
}

/// Asserts a committed read-back word equals the expected marker.
fn assert_word(actual: Word4, expected: Word4, ctx: &str) -> Result<()> {
    ensure!(
        actual == expected,
        "{ctx}: read-back word mismatch (got {actual:?}, expected {expected:?})"
    );
    Ok(())
}

// ROW ASSERTIONS
// ================================================================================================

/// **C1 — `set_attester` + attester rotation.**
///
/// - After `set_attester(A, enabled=1)`, A's on-chain allowlist marker is `[1,0,0,0]`.
/// - After the rotation (`set_attester(A, 0)` + `set_attester(B, 1)`), A's marker is `[0,0,0,0]` and
///   B's marker is `[1,0,0,0]` — a real, committed rotation, not just an add.
/// - A mint whose attestation is signed by the rotated-out A is REJECTED with the not-allowlisted
///   error; a mint signed by the active B is ACCEPTED.
pub fn assert_c1(o: &C1SetAttester) -> Result<()> {
    assert_word(
        o.a_marker_after_enable,
        MARKER_SET,
        "C1: attester A after set_attester(A, enabled=1)",
    )?;
    assert_word(
        o.a_marker_after_rotate,
        MARKER_CLEAR,
        "C1: attester A after rotation (must be disabled)",
    )?;
    assert_word(
        o.b_marker_after_rotate,
        MARKER_SET,
        "C1: attester B after rotation (must be enabled)",
    )?;
    assert_rejected_with(
        &o.mint_by_a,
        ERR_ATTESTER_NOT_ALLOWLISTED,
        "C1: mint attested by the rotated-out A",
    )?;
    assert_accepted(&o.mint_by_b, "C1: mint attested by the active B")?;
    Ok(())
}

/// **C2 — `set_min_burn_size`.**
///
/// - The raise committed to exactly the intended value; a burn below it REJECTS with the below-min
///   error.
/// - The lower committed to exactly the intended value; an at-min burn is ACCEPTED.
pub fn assert_c2(o: &C2MinBurn) -> Result<()> {
    ensure!(
        o.committed_after_raise == o.raised_min,
        "C2: min_burn_size after the raise read back {} (expected the committed {})",
        o.committed_after_raise,
        o.raised_min,
    );
    ensure!(
        o.raised_min > o.lowered_min,
        "C2: the raised minimum must exceed the lowered minimum"
    );
    assert_rejected_with(
        &o.burn_below_raised,
        ERR_BURN_BELOW_MIN,
        "C2: a burn below the raised minimum",
    )?;
    ensure!(
        o.committed_after_lower == o.lowered_min,
        "C2: min_burn_size after the lower read back {} (expected the committed {})",
        o.committed_after_lower,
        o.lowered_min,
    );
    assert_accepted(
        &o.burn_at_lowered,
        "C2: a burn exactly at the lowered minimum",
    )?;
    Ok(())
}

/// **C3 — `set_max_supply`.**
///
/// - The cap committed to exactly the intended value (token-config read-back).
/// - A mint whose reduced amount exceeds the cap REJECTS with `ERR_XRESERVE_SUPPLY_CAP`; a mint
///   within the cap is ACCEPTED (baseline — the reject is the cap, not a broken mint path).
pub fn assert_c3(o: &C3MaxSupply) -> Result<()> {
    ensure!(
        o.max_supply_readback == o.committed_cap,
        "C3: max_supply read back {} (expected the committed {})",
        o.max_supply_readback,
        o.committed_cap,
    );
    assert_rejected_with(
        &o.over_cap_mint,
        ERR_SUPPLY_CAP,
        "C3: a mint exceeding the supply cap",
    )?;
    assert_accepted(
        &o.within_cap_mint,
        "C3: a mint within the supply cap (baseline)",
    )?;
    Ok(())
}

/// **C4 — pause / unpause (F6 semantics).**
///
/// - The DOM_PAUSER pause committed (`is_paused` == `[1,0,0,0]`).
/// - While paused, a mint AND a burn consumption are both REJECTED with the paused error.
/// - The owner's `set_attester` / `set_min_burn_size` STILL committed WHILE PAUSED (F6: owner
///   setters are not halted by pause) — the attester marker is `[1,0,0,0]` and the min-burn value
///   read back.
/// - The DOM_PAUSER unpause committed (`is_paused` == `[0,0,0,0]`); a mint after unpause is ACCEPTED.
pub fn assert_c4(o: &C4Pause) -> Result<()> {
    assert_word(
        o.is_paused_after_pause,
        MARKER_SET,
        "C4: is_paused after the DOM_PAUSER pause",
    )?;
    assert_rejected_with(&o.mint_while_paused, ERR_PAUSED, "C4: a mint while paused")?;
    assert_rejected_with(&o.burn_while_paused, ERR_PAUSED, "C4: a burn while paused")?;
    // F6: the owner's setters still succeed while paused.
    assert_word(
        o.owner_set_attester_while_paused_marker,
        MARKER_SET,
        "C4/F6: the owner's set_attester committed WHILE PAUSED",
    )?;
    ensure!(
        o.owner_set_min_burn_while_paused > 0,
        "C4/F6: the owner's set_min_burn_size WHILE PAUSED must commit a non-zero value \
         (got {})",
        o.owner_set_min_burn_while_paused,
    );
    assert_word(
        o.is_paused_after_unpause,
        MARKER_CLEAR,
        "C4: is_paused after the DOM_PAUSER unpause",
    )?;
    assert_accepted(&o.mint_after_unpause, "C4: a mint after unpause")?;
    Ok(())
}

/// **C5 — role rotation (CMP-F5 seam).**
///
/// - After the DOM_MANAGER grant, the new pauser's DOM_PAUSER membership is `[1,0,0,0]`; that new
///   pauser can PAUSE (committed `is_paused` == `[1,0,0,0]`) — the capability is proven, not assumed.
/// - After the DOM_MANAGER revoke, the membership is cleared (`[0,0,0,0]`); a pause attempt by the
///   revoked account is REJECTED with the role error.
pub fn assert_c5(o: &C5RoleRotation) -> Result<()> {
    assert_word(
        o.new_pauser_membership_after_grant,
        MARKER_SET,
        "C5: the new pauser's DOM_PAUSER membership after the DOM_MANAGER grant",
    )?;
    assert_word(
        o.is_paused_after_new_pauser_pause,
        MARKER_SET,
        "C5: is_paused after the NEW pauser pauses (capability proven)",
    )?;
    assert_word(
        o.new_pauser_membership_after_revoke,
        MARKER_CLEAR,
        "C5: the new pauser's membership after the DOM_MANAGER revoke",
    )?;
    assert_rejected_with(
        &o.revoked_pauser_pause,
        ERR_LACKS_ROLE,
        "C5: a pause by the revoked account",
    )?;
    Ok(())
}

/// **C6 — negatives.**
///
/// Every admin note from a NON-authorized sender must be REJECTED at the proc gate with ITS exact
/// gate error, AND the (allowlisted, routed) note must stay UNCONSUMED after the watch window (the
/// ntx-builder attempted it and failed the same gate — nothing committed). The set must be
/// non-empty and MUST cover both gate kinds (an authority-gated op from an unauthorized sender AND a pause from a
/// non-DOM_PAUSER) so the row proves both gates, not just one.
pub fn assert_c6(rejects: &[AdminGateReject]) -> Result<()> {
    ensure!(
        !rejects.is_empty(),
        "C6: the negative set must be non-empty"
    );
    let mut saw_owner_gate = false;
    let mut saw_role_gate = false;
    for r in rejects {
        let ctx = format!("C6: {} from a {}", r.op, r.sender);
        assert_rejected_with(&r.verdict, &r.expected_gate, &ctx)?;
        ensure!(
            r.note_unconsumed,
            "{ctx}: the rejected admin note was CONSUMED on-chain — a non-authorized sender's op \
             committed (the proc gate did not hold node-side)",
        );
        if r.expected_gate == ERR_NOT_OWNER {
            saw_owner_gate = true;
        }
        if r.expected_gate == ERR_LACKS_ROLE {
            saw_role_gate = true;
        }
    }
    ensure!(
        saw_owner_gate,
        "C6: the negative set must include at least one authority-gated op rejected from an unauthorized owner \
         ('{ERR_NOT_OWNER}')",
    );
    ensure!(
        saw_role_gate,
        "C6: the negative set must include a pause rejected from a non-DOM_PAUSER ('{ERR_LACKS_ROLE}')",
    );
    Ok(())
}

/// **Row F — the F5 auth boundary.**
///
/// - The faucet consuming a stock P2ID note (whose script root is NOT allowlisted) is REJECTED by
///   `AuthNetworkAccount` with the note-allowlist error.
/// - A non-allowlisted (`nop`) tx-script transaction executed against the faucet is REJECTED with
///   the tx-script-allowlist error (the v16 tx-script allowlist admits ONLY the S12 expiration
///   root — F1 sole-mint-surface preserved; any other script traps).
pub fn assert_f(o: &RowF) -> Result<()> {
    assert_rejected_with(
        &o.non_allowlisted_note,
        ERR_NOTE_NOT_ALLOWLISTED,
        "F: the faucet consuming a non-allowlisted (P2ID) note",
    )?;
    assert_rejected_with(
        &o.tx_script,
        ERR_TX_SCRIPT_NOT_ALLOWLISTED,
        "F: a tx-script transaction against the faucet",
    )?;
    Ok(())
}

/// Judges every rows-C/F observation. Returns the first failure; the driver / bin records per-row
/// verdicts separately for the evidence file.
pub fn assert_all(o: &RowsCfObservations) -> Result<()> {
    assert_c1(&o.c1)?;
    assert_c2(&o.c2)?;
    assert_c3(&o.c3)?;
    assert_c4(&o.c4)?;
    assert_c5(&o.c5)?;
    assert_c6(&o.c6)?;
    assert_f(&o.f)?;
    Ok(())
}
