//! Rows-G (two-block burn) + H (F7 same-block RIV) + I (burn negatives) + J (conservation)
//! assertion suite — written test-first, before the real-node driver (`crate::rows_gj`), judging the
//! [`RowsGjObservations`] it produces.
//!
//! Matrix rows (authoritative spec, `TASK-P5-01-PHASE4-LOCAL-NODE-VALIDATION-PLAN-BUILDER.md`):
//! - **G burn two-block (the Circle read-path proof)** — a holder creates the production
//!   `XReserveBurnNote` (block N committed) → the faucet consumes it (block N+1) ⇒
//!   `token_supply -= amount`; the committed note + nullifier PERSIST; `SyncNotes` filtered by tag
//!   `0x4255524E` discovers it; `GetNotesById` returns the full note + inclusion proof.
//! - **H burn same-block (the F7 RIV — EVIDENCE, not policy)** — create + consume the production
//!   `XReserveBurnNote` within one block; record precisely what survives. This is the DEV-7 evidence
//!   packet; the assertion verifies the evidence was CAPTURED and the erasure was OBSERVED, and does
//!   NOT decide acceptability (DEV-7 stays OPEN).
//! - **I burn negatives** — each REJECTED AND zero state change: below `min_burn_size`; while paused;
//!   wrong-asset (asset not this faucet's).
//! - **J conservation ledger** — `token_supply == Σ(minted) − Σ(burned)` exactly; per-step supply
//!   reads recorded; holder balance consistent.
//!
//! Every check reads the NODE-fetched verdicts/read-backs carried by [`RowsGjObservations`] — a green
//! here is a statement about the real chain, not about the client's local store.

use anyhow::{bail, ensure, Result};

use crate::observations_gj::{
    BurnNegative, BurnSameBlock, BurnTwoBlock, ConservationLedger, RowsGjObservations, Verdict,
};

/// The fixed, enumerated xUSDC burn-event note tag (DC-7): a FULL 32-bit exact-match value, ASCII
/// `"BURN"`. Single-sourced from the production note factory so a tag drift there fails the row.
pub use xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;

// EXACT on-chain error substrings the Row-I rejects must carry (single source of truth in the
// shipped MASM: `burn_policy.masm` for below-min, the stock `pausable` primitive for pause, the
// stock kernel `fungible_asset::validate_origin` for the wrong-asset origin gate). A reject that
// does not carry ITS error is not the gate the negative proves — the assertion rejects it. Below-min
// is an xreserve-OWNED gate (carries the message); pause + wrong-asset are STOCK/KERNEL gates that
// surface a client-side trap CODE-only (LNV-2 posture), so the matcher also accepts the derived
// `err_code`.
// ================================================================================================

/// R-BURN-2 (`burn_policy::check_policy`): the burn amount is below the configured minimum burn size.
pub const ERR_BURN_BELOW_MIN: &str = "burn amount is below the minimum burn size";
/// R-BURN-3 / the stock pause gate (`pausable::assert_not_paused`, `ERR_PAUSABLE_IS_PAUSED`): the
/// faucet is paused, so `execute_burn_policy` halts the burn before the policy runs.
pub const ERR_PAUSED: &str = "the contract is paused";
/// The stock kernel fungible-asset origin gate (`fungible_asset::validate_origin`,
/// `ERR_FUNGIBLE_ASSET_FAUCET_IS_NOT_ORIGIN`): the burned asset was not issued by this faucet, so
/// `faucet::burn` traps — a faucet can only burn its own token.
pub const ERR_WRONG_ASSET_ORIGIN: &str = "the origin of the fungible asset is not this faucet";

// SHARED CHECK HELPERS
// ================================================================================================

/// The `err_code` (the deterministic `error_code_from_msg` hash) a MASM/kernel assertion of `msg`
/// embeds — the SAME value the assembler bakes into the compiled proc and the executor surfaces.
/// Lets a reject be matched on its code when the message itself is absent.
fn err_code_for(msg: &str) -> u64 {
    miden_protocol::errors::MasmError::new(msg.to_string())
        .code()
        .as_canonical_u64()
}

/// Asserts a verdict is REJECTED and its captured error is the `expected` gate (matched on EITHER
/// the message substring OR the expected error's `err_code`, both derived from the single expected
/// string — never a hardcoded magic number).
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

// ROW ASSERTIONS
// ================================================================================================

/// **Row G — burn two-block (the Circle read-path proof).**
///
/// For the committed two-block burn:
/// - `token_supply` FELL by EXACTLY the burned amount (a real decrement, neither absent nor
///   over-counted);
/// - the holder's vault balance FELL by exactly the burned amount (custody-traced: the burned funds
///   left the holder into the note, single-sourced from the note's asset);
/// - the note carries the fixed xUSDC burn tag `0x4255524E`, its single asset is the burned amount
///   issued by THIS faucet;
/// - the note was COMMITTED before consumption, `SyncNotes` (tag-filtered) discovered it, and
///   `GetNotesById` STILL returns it AFTER the consume with a non-empty byte-exact capture whose
///   inclusion block equals the commit block (the durable Circle read-path);
/// - the note's nullifier is recorded after the consume (a real, non-replayable spend);
/// - the consume committed in a STRICTLY later block than the note (a genuine two-block flow).
pub fn assert_g(o: &BurnTwoBlock) -> Result<()> {
    let ctx = format!("G[{}]", o.label);
    ensure!(
        o.amount_units > 0,
        "{ctx}: a burn must move a non-zero amount"
    );
    let expected_supply = o.supply_before.checked_sub(o.amount_units).ok_or_else(|| {
        anyhow::anyhow!(
            "{ctx}: supply_before ({}) is less than the burned amount ({}) — the burn could not \
             have been valid",
            o.supply_before,
            o.amount_units,
        )
    })?;
    ensure!(
        o.supply_after == expected_supply,
        "{ctx}: token_supply must fall by exactly the burned amount ({} - {} = {}, but read back {})",
        o.supply_before,
        o.amount_units,
        expected_supply,
        o.supply_after,
    );
    let expected_holder = o
        .holder_balance_before
        .checked_sub(o.amount_units)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{ctx}: holder_balance_before ({}) is less than the burned amount ({})",
                o.holder_balance_before,
                o.amount_units,
            )
        })?;
    ensure!(
        o.holder_balance_after == expected_holder,
        "{ctx}: the holder balance must fall by the burned amount ({} - {} = {}, but read back {})",
        o.holder_balance_before,
        o.amount_units,
        expected_holder,
        o.holder_balance_after,
    );
    ensure!(
        o.note_tag == FIXED_XUSDC_BURN_TAG,
        "{ctx}: the burn note tag must be the fixed xUSDC burn tag (got {:#010x}, expected {:#010x})",
        o.note_tag,
        FIXED_XUSDC_BURN_TAG,
    );
    ensure!(
        o.note_asset_amount == o.amount_units,
        "{ctx}: the burn note asset amount must equal the burned amount (got {}, expected {})",
        o.note_asset_amount,
        o.amount_units,
    );
    ensure!(
        o.note_asset_is_faucet,
        "{ctx}: the burn note asset must be issued by THIS faucet",
    );
    ensure!(
        o.committed_before_consume,
        "{ctx}: the burn note must be a COMMITTED public note before consumption (GetNotesById \
         returned it at block N) — a two-block burn, not an ephemeral one",
    );
    ensure!(
        o.discovered_by_syncnotes,
        "{ctx}: SyncNotes filtered by the fixed burn tag must discover the note (the Circle \
         discovery path)",
    );
    ensure!(
        o.found_after_consume,
        "{ctx}: GetNotesById must STILL return the committed note AFTER the faucet consumed it — the \
         durable burn-event observability Circle's withdrawal attester relies on",
    );
    ensure!(
        o.nullifier_recorded_after_consume,
        "{ctx}: the burn note's nullifier must be recorded on-chain after the consume (a real, \
         non-replayable committed spend)",
    );
    ensure!(
        o.consume_block > o.note_commit_block,
        "{ctx}: the faucet consume must commit in a strictly later block than the note (a two-block \
         flow): note block {} vs consume block {}",
        o.note_commit_block,
        o.consume_block,
    );
    ensure!(
        !o.getnotesbyid_note_bytes_hex.is_empty(),
        "{ctx}: the byte-exact GetNotesById note capture must be non-empty (the examples-repo / \
         Njord deliverable)",
    );
    ensure!(
        !o.getnotesbyid_inclusion_proof_bytes_hex.is_empty(),
        "{ctx}: the byte-exact GetNotesById INCLUSION-PROOF capture must be non-empty — the full \
         response envelope is the note PLUS its inclusion proof (the proof half is what the \
         withdrawal attester needs to verify on-chain inclusion), not the note bytes alone",
    );
    ensure!(
        o.getnotesbyid_inclusion_block == o.note_commit_block,
        "{ctx}: the GetNotesById inclusion-proof block ({}) must equal the note commit block ({})",
        o.getnotesbyid_inclusion_block,
        o.note_commit_block,
    );
    Ok(())
}

/// **Row H — burn same-block (the F7 RIV, EVIDENCE not policy).**
///
/// This assertion verifies the DEV-7 evidence packet is COMPLETE and the RIV was exercised on the
/// REAL node — it makes **no acceptability decision** (DEV-7 stays OPEN). It is NOT a mere
/// "fields non-empty" check: it pins the substantive real-node observations.
/// - the production burn note IS a valid burn (consume ACCEPTED) carrying the fixed xUSDC burn tag;
/// - the executed consume applies a supply delta of EXACTLY the burned amount — the "supply delta
///   behavior" the RIV must record (not just that a never-committed note is absent);
/// - the REAL-NODE round-trip: SUBMITTING the faucet's consume via user RPC was REJECTED (a
///   committed same-block create+consume is unreachable on this network-account stack), with the
///   node rejection captured — this is what makes the row a real-node test rather than an unsubmitted
///   local execute;
/// - on-chain `token_supply` is UNCHANGED (neither the execute nor the rejected submit committed);
/// - the note never commits: NO committed note, NO on-chain nullifier, `SyncNotes` does NOT discover
///   it — the discovery-starvation the RIV records;
/// - the raw `GetNotesById` evidence + the mechanism description were captured.
pub fn assert_h(o: &BurnSameBlock) -> Result<()> {
    let ctx = format!("H[{}]", o.label);
    ensure!(
        o.consume_accepted,
        "{ctx}: the (unauthenticated) consume of the PRODUCTION burn note must be ACCEPTED — the RIV \
         subject is a VALID burn that simply leaves no discoverable artifact when its note never \
         commits",
    );
    ensure!(
        o.note_tag == FIXED_XUSDC_BURN_TAG,
        "{ctx}: the same-block note must carry the fixed xUSDC burn tag (got {:#010x}, expected \
         {:#010x}) — the RIV is about the PRODUCTION note",
        o.note_tag,
        FIXED_XUSDC_BURN_TAG,
    );
    // The supply-delta behavior (not just note-absence): the executed consume must move supply by
    // EXACTLY the burned amount — the account-state delta an on-chain same-block burn would apply.
    ensure!(
        o.executed_supply_delta == Some(o.amount_units),
        "{ctx}: the executed consume must apply a supply delta of exactly the burned amount \
         (expected Some({}), got {:?}) — the RIV must record the supply-delta behavior, not only \
         that a never-committed note is absent",
        o.amount_units,
        o.executed_supply_delta,
    );
    // The REAL-NODE round-trip: a user-submitted faucet consume MUST be refused — proving a
    // committed same-block create+consume is unreachable here (so the erasure can only be shown
    // client-side). A non-rejection means either the constraint changed or the row never submitted.
    ensure!(
        o.submit_via_user_rpc_rejected,
        "{ctx}: submitting the faucet's consume via user RPC must be REJECTED (a committed \
         same-block create+consume is unreachable on this network-account stack) — if it was NOT \
         rejected, surface it (the constraint changed, or the row did not actually submit)",
    );
    ensure!(
        !o.submit_rejection_error.is_empty(),
        "{ctx}: the node's submission-rejection error must be captured (non-empty) — the real-node \
         constraint proof for the DEV-7 packet",
    );
    ensure!(
        o.onchain_supply_after == o.onchain_supply_before,
        "{ctx}: on-chain token_supply must be UNCHANGED by the RIV (was {}, read back {}) — neither \
         the client-side execute nor the rejected submission committed",
        o.onchain_supply_before,
        o.onchain_supply_after,
    );
    // The OBSERVED discovery-starvation (the RIV finding, not an acceptability judgment): the
    // never-committed production burn note leaves nothing for Circle's SyncNotes / GetNotesById.
    ensure!(
        !o.committed_note_found,
        "{ctx}: RIV expectation — the never-committed burn note must NOT be a committed note, but \
         GetNotesById found one (surface this: the F7 behavior changed)",
    );
    ensure!(
        !o.nullifier_recorded,
        "{ctx}: RIV expectation — the never-committed burn note must leave NO on-chain nullifier, \
         but one was recorded (surface this)",
    );
    ensure!(
        !o.discovered_by_syncnotes,
        "{ctx}: RIV expectation — SyncNotes must NOT discover the never-committed burn note (the \
         starved Circle discovery path), but it did (surface this)",
    );
    ensure!(
        !o.raw_getnotesbyid_response.is_empty(),
        "{ctx}: the raw GetNotesById evidence must be captured (non-empty) for the DEV-7 packet",
    );
    ensure!(
        !o.mechanism.is_empty(),
        "{ctx}: the mechanism description must be recorded (the evidence is self-describing)",
    );
    Ok(())
}

/// The three DISTINCT Row-I burn-negative vectors the matrix requires, by canonical label. Coverage
/// is keyed on the LABEL (never the gate error alone), the LNV-3 audit lesson: distinct attack
/// surfaces that could collide on a shared error string must each be required independently, so a
/// driver cannot silently drop one.
const REQUIRED_NEGATIVES: [&str; 3] = ["below-min", "while-paused", "wrong-asset"];

/// **Row I — burn negatives.**
///
/// The set MUST cover all three negatives (below-min, while-paused, wrong-asset). For EVERY
/// negative:
/// - the consumption was REJECTED with ITS exact gate error (message OR derived err_code);
/// - the committed `token_supply` is UNCHANGED (`supply_after == supply_before`).
pub fn assert_i(negatives: &[BurnNegative]) -> Result<()> {
    for n in negatives {
        let ctx = format!("I[{}]", n.label);
        assert_rejected_with(&n.verdict, &n.expected_error, &ctx)?;
        ensure!(
            n.supply_after == n.supply_before,
            "{ctx}: committed token_supply must be UNCHANGED after the reject (was {}, read back {})",
            n.supply_before,
            n.supply_after,
        );
    }
    for label in REQUIRED_NEGATIVES {
        ensure!(
            negatives.iter().any(|n| n.label == label),
            "I: the burn negatives must include the '{label}' negative — all three matrix \
             burn-negative vectors (below-min, while-paused, wrong-asset) are required",
        );
    }
    Ok(())
}

/// **Row J — conservation ledger.**
///
/// - `final_supply == total_minted − total_burned` EXACTLY (the core conservation invariant), with
///   `total_minted >= total_burned` (no negative supply);
/// - the per-step supply reads are recorded and the LAST recorded step equals `final_supply` (the
///   ledger is anchored to the observed final state);
/// - the holder's final balance is custody-consistent: `holder_final_balance == total_minted −
///   total_burned` for this single-holder mint→burn arc (it received every mint and burned every
///   committed burn).
pub fn assert_j(o: &ConservationLedger) -> Result<()> {
    ensure!(
        o.total_minted >= o.total_burned,
        "J: total_minted ({}) must be >= total_burned ({}) — a conserved ledger never burns more \
         than was minted",
        o.total_minted,
        o.total_burned,
    );
    let expected = o.total_minted - o.total_burned;
    ensure!(
        o.final_supply == expected,
        "J: conservation broken — final token_supply must equal Σminted − Σburned ({} - {} = {}, \
         but read back {})",
        o.total_minted,
        o.total_burned,
        expected,
        o.final_supply,
    );
    ensure!(
        !o.steps.is_empty(),
        "J: the per-step supply ledger must be recorded (non-empty)",
    );
    let last = o.steps.last().expect("non-empty checked above");
    ensure!(
        last.supply == o.final_supply,
        "J: the last recorded supply step ('{}' = {}) must equal the final supply ({})",
        last.label,
        last.supply,
        o.final_supply,
    );
    ensure!(
        o.holder_final_balance == expected,
        "J: the holder's final balance must equal Σminted − Σburned ({}, but read back {}) — the \
         holder received every mint and burned every committed burn",
        expected,
        o.holder_final_balance,
    );
    Ok(())
}

/// Judges every rows-G/H/I/J observation. Returns the first failure; the driver / bin records
/// per-row verdicts separately for the evidence file.
pub fn assert_all(o: &RowsGjObservations) -> Result<()> {
    assert_g(&o.g)?;
    assert_h(&o.h)?;
    assert_i(&o.i)?;
    assert_j(&o.j)?;
    Ok(())
}
