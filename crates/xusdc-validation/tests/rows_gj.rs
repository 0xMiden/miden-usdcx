//! LNV-4 test suite — matrix rows G (burn two-block), H (F7 same-block RIV), I (burn negatives),
//! J (conservation), written TEST-FIRST against the rows-G/H/I/J assertion suite
//! (`xusdc_validation::assertions_gj`) + driver API.
//!
//! Two layers, exactly the LNV-1/2/3 partition:
//!
//! 1. **Assertion negatives** (no node, sandbox-safe — the DEFAULT suite). Synthetic
//!    [`RowsGjObservations`] built green, then each test breaks EXACTLY the one surface its row-check
//!    exists to reject, and proves the assertion rejects it (a silently-weakened assertion — e.g. the
//!    auditor's planted mutation — fails these). Plus one green-shape acceptance (guards against an
//!    always-failing suite). Row H's checks verify the F7 evidence was CAPTURED and the erasure was
//!    OBSERVED — never an acceptability decision (DEV-7 stays OPEN).
//! 2. **The real-node E2E** (`lnv4_rows_gj_against_real_local_node`): boots a FRESH local v0.15.1
//!    stack, deploys the production faucet, drives the whole G+H+I+J burn arc (Row-G/H/I via path N +
//!    client-side, the F7 RIV, the conservation ledger), and judges the observations. `#[ignore]`d in
//!    the default suite because it must bind loopback listener sockets (denied in hermetic audit
//!    sandboxes); run it with `-- --include-ignored` or the `lnv4_rows_gj` binary. The §11.2 gate
//!    claim rides ONLY on real runs + the human gate — a green default suite proves the assertion
//!    layer only.

use anyhow::{Context, Result};
use xusdc_validation::assertions_gj::{
    assert_all, assert_g, assert_h, assert_i, assert_j, ERR_BURN_BELOW_MIN, ERR_PAUSED,
    ERR_WRONG_ASSET_ORIGIN, FIXED_XUSDC_BURN_TAG,
};
use xusdc_validation::observations_gj::{
    BurnNegative, BurnSameBlock, BurnTwoBlock, ConservationLedger, RowsGjObservations, SupplyStep,
    Verdict,
};

// ── green synthetic fixtures ─────────────────────────────────────────────────────────────────

fn rej(msg: &str) -> Verdict {
    Verdict::Rejected(msg.to_string())
}

/// A green Row-G two-block burn: supply 100 → 0, holder 100 → 0, a committed note carrying the
/// fixed burn tag, discovered + persisted across the two-block flow.
fn green_g() -> BurnTwoBlock {
    BurnTwoBlock {
        label: "two-block-burn".to_string(),
        amount_units: 100,
        supply_before: 100,
        supply_after: 0,
        holder_balance_before: 100,
        holder_balance_after: 0,
        note_id: "0xburnnote".to_string(),
        note_tag: FIXED_XUSDC_BURN_TAG,
        note_commit_block: 20,
        consume_block: 22,
        committed_before_consume: true,
        discovered_by_syncnotes: true,
        found_after_consume: true,
        nullifier_recorded_after_consume: true,
        note_asset_amount: 100,
        note_asset_is_faucet: true,
        getnotesbyid_note_bytes_hex: "deadbeef".to_string(),
        getnotesbyid_inclusion_proof_bytes_hex: "cafe1234".to_string(),
        getnotesbyid_inclusion_block: 20,
    }
}

/// A green Row-H F7 same-block RIV: the production note IS a valid burn (consume accepted; supply
/// delta == amount), submitting the faucet consume is REJECTED by the node (a committed same-block is
/// unreachable), the note never commits (no committed note, no nullifier, not SyncNotes-discoverable),
/// and on-chain supply is unchanged. Evidence only; no acceptability decision.
fn green_h() -> BurnSameBlock {
    BurnSameBlock {
        label: "same-block-erasure".to_string(),
        amount_units: 100,
        mechanism:
            "unauthenticated consume of the production XReserveBurnNote; user-RPC submission \
                    rejected (committed same-block unreachable); note never commits"
                .to_string(),
        note_tag: FIXED_XUSDC_BURN_TAG,
        note_id: "0xsameblocknote".to_string(),
        consume_accepted: true,
        executed_supply_delta: Some(100),
        submit_via_user_rpc_rejected: true,
        submit_rejection_error:
            "RpcError(... Network transactions may not be submitted by users yet ...)".to_string(),
        onchain_supply_before: 100,
        onchain_supply_after: 100,
        committed_note_found: false,
        nullifier_recorded: false,
        discovered_by_syncnotes: false,
        raw_getnotesbyid_response: "GetNotesById([0xsameblocknote]) -> [] (not found)".to_string(),
    }
}

fn neg(label: &str, expected_error: &str, verdict: Verdict) -> BurnNegative {
    BurnNegative {
        label: label.to_string(),
        expected_error: expected_error.to_string(),
        verdict,
        supply_before: 100,
        supply_after: 100,
    }
}

fn green_i() -> Vec<BurnNegative> {
    vec![
        neg(
            "below-min",
            ERR_BURN_BELOW_MIN,
            rej("... burn amount is below the minimum burn size ..."),
        ),
        neg(
            "wrong-asset",
            ERR_WRONG_ASSET_ORIGIN,
            rej("... the origin of the fungible asset is not this faucet ..."),
        ),
        neg(
            "while-paused",
            ERR_PAUSED,
            rej("... the contract is paused ..."),
        ),
    ]
}

fn green_j() -> ConservationLedger {
    ConservationLedger {
        total_minted: 100,
        total_burned: 100,
        final_supply: 0,
        steps: vec![
            SupplyStep {
                label: "after-mint".to_string(),
                supply: 100,
            },
            SupplyStep {
                label: "after-two-block-burn".to_string(),
                supply: 0,
            },
        ],
        holder_final_balance: 0,
    }
}

fn green_obs() -> RowsGjObservations {
    RowsGjObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic".to_string(),
        holder_id: "0xholder".to_string(),
        g: green_g(),
        h: green_h(),
        i: green_i(),
        j: green_j(),
    }
}

// ── green-shape acceptance (guards against an always-failing suite) ──────────────────────────

#[test]
fn all_rows_accept_the_green_shape() -> Result<()> {
    assert_all(&green_obs())
}

// ── Row G negatives ───────────────────────────────────────────────────────────────────────────

#[test]
fn g_rejects_supply_not_decremented() {
    let mut g = green_g();
    g.supply_after = g.supply_before; // the burn did not lower token_supply
    let e = assert_g(&g).expect_err("G must reject when supply did not fall by the burn amount");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn g_rejects_supply_decremented_by_wrong_amount() {
    let mut g = green_g();
    g.supply_after = 1; // fell, but not by exactly the burned amount
    let e = assert_g(&g).expect_err("G must reject when supply fell by the wrong amount");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn g_rejects_holder_balance_not_debited() {
    let mut g = green_g();
    g.holder_balance_after = g.holder_balance_before; // holder kept the funds
    let e = assert_g(&g).expect_err("G must reject when the holder balance was not debited");
    assert!(format!("{e:#}").contains("holder"), "got: {e:#}");
}

#[test]
fn g_rejects_wrong_tag() {
    let mut g = green_g();
    g.note_tag = 0xdead_0000; // not the fixed xUSDC burn tag
    let e = assert_g(&g).expect_err("G must reject a note not carrying the fixed burn tag");
    assert!(format!("{e:#}").contains("tag"), "got: {e:#}");
}

#[test]
fn g_rejects_not_committed_before_consume() {
    let mut g = green_g();
    g.committed_before_consume = false; // the note was never a committed public note
    let e = assert_g(&g).expect_err("G must reject when the note was not committed before consume");
    assert!(format!("{e:#}").contains("COMMITTED"), "got: {e:#}");
}

#[test]
fn g_rejects_not_discovered_by_syncnotes() {
    let mut g = green_g();
    g.discovered_by_syncnotes = false; // Circle's tag-filtered discovery failed
    let e = assert_g(&g).expect_err("G must reject when SyncNotes did not discover the note");
    assert!(format!("{e:#}").contains("SyncNotes"), "got: {e:#}");
}

#[test]
fn g_rejects_not_found_after_consume() {
    let mut g = green_g();
    g.found_after_consume = false; // the committed note did not persist post-consume
    let e =
        assert_g(&g).expect_err("G must reject when the note did not persist after the consume");
    assert!(format!("{e:#}").contains("GetNotesById"), "got: {e:#}");
}

#[test]
fn g_rejects_nullifier_not_recorded() {
    let mut g = green_g();
    g.nullifier_recorded_after_consume = false; // no committed spend
    let e = assert_g(&g).expect_err("G must reject when the nullifier was not recorded");
    assert!(format!("{e:#}").contains("nullifier"), "got: {e:#}");
}

#[test]
fn g_rejects_single_block_flow() {
    let mut g = green_g();
    g.consume_block = g.note_commit_block; // consume in the SAME block (not two-block)
    let e = assert_g(&g).expect_err("G must reject a non-two-block flow");
    assert!(format!("{e:#}").contains("block"), "got: {e:#}");
}

#[test]
fn g_rejects_note_asset_amount_mismatch() {
    let mut g = green_g();
    g.note_asset_amount = g.amount_units - 1; // note carries less than the burned amount
    let e =
        assert_g(&g).expect_err("G must reject when the note asset amount != the burned amount");
    assert!(format!("{e:#}").contains("asset"), "got: {e:#}");
}

#[test]
fn g_rejects_note_asset_wrong_faucet() {
    let mut g = green_g();
    g.note_asset_is_faucet = false; // asset not issued by this faucet
    let e = assert_g(&g).expect_err("G must reject when the note asset is not this faucet's");
    assert!(format!("{e:#}").contains("faucet"), "got: {e:#}");
}

#[test]
fn g_rejects_empty_getnotesbyid_capture() {
    let mut g = green_g();
    g.getnotesbyid_note_bytes_hex = String::new(); // the byte-exact deliverable was not captured
    let e = assert_g(&g).expect_err("G must reject when the GetNotesById capture is empty");
    assert!(format!("{e:#}").contains("GetNotesById"), "got: {e:#}");
}

#[test]
fn g_rejects_inclusion_block_mismatch() {
    let mut g = green_g();
    g.getnotesbyid_inclusion_block = g.note_commit_block + 5; // proof height != commit block
    let e = assert_g(&g).expect_err("G must reject when the inclusion block != the commit block");
    assert!(format!("{e:#}").contains("inclusion"), "got: {e:#}");
}

#[test]
fn g_rejects_empty_inclusion_proof_capture() {
    let mut g = green_g();
    g.getnotesbyid_inclusion_proof_bytes_hex = String::new(); // proof half of the deliverable missing
    let e = assert_g(&g)
        .expect_err("G must reject when the GetNotesById inclusion-proof capture is empty");
    assert!(format!("{e:#}").contains("inclusion proof"), "got: {e:#}");
}

// ── Row H negatives (the F7 RIV evidence-completeness checks) ─────────────────────────────────

#[test]
fn h_rejects_consume_not_accepted() {
    let mut h = green_h();
    h.consume_accepted = false; // the production burn note was NOT consumable same-block
    let e = assert_h(&h).expect_err("H must reject when the same-block consume was not accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn h_rejects_wrong_tag() {
    let mut h = green_h();
    h.note_tag = 0xdead_0000; // the RIV must be about the production (fixed-tag) note
    let e =
        assert_h(&h).expect_err("H must reject a same-block note not carrying the fixed burn tag");
    assert!(format!("{e:#}").contains("tag"), "got: {e:#}");
}

#[test]
fn h_rejects_onchain_supply_changed() {
    let mut h = green_h();
    h.onchain_supply_after = h.onchain_supply_before - 100; // a same-block probe committed supply
    let e =
        assert_h(&h).expect_err("H must reject when on-chain supply moved (nothing was submitted)");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn h_rejects_committed_note_found() {
    let mut h = green_h();
    h.committed_note_found = true; // erasure did NOT happen — a finding to surface
    let e =
        assert_h(&h).expect_err("H must surface when a same-block note was unexpectedly committed");
    assert!(format!("{e:#}").contains("committed"), "got: {e:#}");
}

#[test]
fn h_rejects_nullifier_recorded() {
    let mut h = green_h();
    h.nullifier_recorded = true; // a nullifier persisted — a finding to surface
    let e = assert_h(&h).expect_err("H must surface when a same-block nullifier was recorded");
    assert!(format!("{e:#}").contains("nullifier"), "got: {e:#}");
}

#[test]
fn h_rejects_discovered_by_syncnotes() {
    let mut h = green_h();
    h.discovered_by_syncnotes = true; // SyncNotes discovered an erased note — a finding to surface
    let e = assert_h(&h).expect_err("H must surface when SyncNotes discovered a same-block note");
    assert!(format!("{e:#}").contains("SyncNotes"), "got: {e:#}");
}

#[test]
fn h_rejects_empty_raw_response() {
    let mut h = green_h();
    h.raw_getnotesbyid_response = String::new(); // the raw evidence was not captured
    let e = assert_h(&h).expect_err("H must reject when the raw GetNotesById evidence is empty");
    assert!(format!("{e:#}").contains("GetNotesById"), "got: {e:#}");
}

#[test]
fn h_rejects_empty_mechanism() {
    let mut h = green_h();
    h.mechanism = String::new(); // the evidence is not self-describing
    let e = assert_h(&h).expect_err("H must reject when the mechanism description is empty");
    assert!(format!("{e:#}").contains("mechanism"), "got: {e:#}");
}

#[test]
fn h_rejects_delta_not_equal_to_amount() {
    let mut h = green_h();
    h.executed_supply_delta = Some(h.amount_units - 1); // the burn moved supply by the WRONG amount
    let e = assert_h(&h)
        .expect_err("H must reject when the executed supply delta != the burned amount");
    assert!(format!("{e:#}").contains("delta"), "got: {e:#}");
}

#[test]
fn h_rejects_delta_absent() {
    let mut h = green_h();
    h.executed_supply_delta = None; // the supply-delta behavior was not captured at all
    let e =
        assert_h(&h).expect_err("H must reject when the executed supply delta was not captured");
    assert!(format!("{e:#}").contains("delta"), "got: {e:#}");
}

#[test]
fn h_rejects_submit_not_rejected() {
    // The whole point of the real-node round-trip: a user-submitted faucet consume MUST be refused
    // (a committed same-block is unreachable). If it was NOT rejected, either the constraint changed
    // or the row never actually submitted — a finding to surface, not a silent pass.
    let mut h = green_h();
    h.submit_via_user_rpc_rejected = false;
    let e = assert_h(&h)
        .expect_err("H must reject when the user-RPC faucet-consume submission was not rejected");
    assert!(format!("{e:#}").contains("submit"), "got: {e:#}");
}

#[test]
fn h_rejects_empty_submit_error() {
    let mut h = green_h();
    h.submit_rejection_error = String::new(); // the real-node rejection evidence was not captured
    let e = assert_h(&h).expect_err("H must reject when the submission rejection error is empty");
    assert!(format!("{e:#}").contains("rejection"), "got: {e:#}");
}

// ── Row I negatives ───────────────────────────────────────────────────────────────────────────

#[test]
fn i_rejects_a_non_rejected_negative() {
    let mut ev = green_i();
    ev[0].verdict = Verdict::Accepted; // a below-min burn was ACCEPTED
    let e = assert_i(&ev).expect_err("I must reject when a negative was accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn i_rejects_wrong_gate_error() {
    let mut ev = green_i();
    ev[0].verdict = rej("some entirely unrelated trap"); // rejected, but not by the below-min gate
    let e = assert_i(&ev).expect_err("I must reject a negative that failed for the wrong reason");
    assert!(format!("{e:#}").contains(ERR_BURN_BELOW_MIN), "got: {e:#}");
}

#[test]
fn i_rejects_supply_changed() {
    let mut ev = green_i();
    ev[0].supply_after = ev[0].supply_before - 1; // committed supply moved after a reject
    let e = assert_i(&ev).expect_err("I must reject when committed supply changed");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn i_requires_the_below_min_negative() {
    let ev: Vec<BurnNegative> = green_i()
        .into_iter()
        .filter(|n| n.label != "below-min")
        .collect();
    let e = assert_i(&ev).expect_err("I must require the below-min negative");
    assert!(format!("{e:#}").contains("below-min"), "got: {e:#}");
}

#[test]
fn i_requires_the_while_paused_negative() {
    let ev: Vec<BurnNegative> = green_i()
        .into_iter()
        .filter(|n| n.label != "while-paused")
        .collect();
    let e = assert_i(&ev).expect_err("I must require the while-paused negative");
    assert!(format!("{e:#}").contains("while-paused"), "got: {e:#}");
}

#[test]
fn i_requires_the_wrong_asset_negative() {
    let ev: Vec<BurnNegative> = green_i()
        .into_iter()
        .filter(|n| n.label != "wrong-asset")
        .collect();
    let e = assert_i(&ev).expect_err("I must require the wrong-asset negative");
    assert!(format!("{e:#}").contains("wrong-asset"), "got: {e:#}");
}

// ── err_code derivation tripwire (a stock/kernel reject may carry only its err_code) ───────────

/// The shape a stock/kernel gate produces on a client-side trap when the message text is absent: a
/// `FailedAssertion` carrying ONLY the `err_code` for `expected_msg`. `assert_rejected_with` must
/// match on the code too, so a genuine trap that surfaces code-only (the pause + wrong-asset gates)
/// is still recognized.
fn rejected_code_only(expected_msg: &str) -> Verdict {
    use miden_protocol::errors::MasmError;
    let code = MasmError::new(expected_msg.to_string())
        .code()
        .as_canonical_u64();
    Verdict::Rejected(format!(
        "TransactionExecutorError(TransactionProgramExecutionFailed(OperationError {{ \
         err: FailedAssertion {{ err_code: {code}, err_msg: None }} }}))"
    ))
}

#[test]
fn code_only_burn_gate_rejects_are_matched() {
    let mut ev = green_i();
    for n in &mut ev {
        n.verdict = rejected_code_only(&n.expected_error);
    }
    assert_i(&ev).expect("I must accept burn-gate rejects carried only by their err_code");
}

#[test]
fn code_only_reject_with_the_wrong_code_is_rejected() {
    let mut ev = green_i();
    ev[2].verdict = rejected_code_only("some entirely unrelated assertion"); // wrong code for pause
    let e = assert_i(&ev).expect_err("I must reject a code-only reject bearing the WRONG err_code");
    assert!(format!("{e:#}").contains(ERR_PAUSED), "got: {e:#}");
}

// ── Row J negatives ───────────────────────────────────────────────────────────────────────────

#[test]
fn j_rejects_conservation_broken() {
    let mut j = green_j();
    j.final_supply = 1; // != total_minted - total_burned (== 0)
    let e = assert_j(&j).expect_err("J must reject when final supply != Σminted − Σburned");
    assert!(format!("{e:#}").contains("conservation"), "got: {e:#}");
}

#[test]
fn j_rejects_burned_exceeds_minted() {
    let mut j = green_j();
    j.total_burned = j.total_minted + 1; // burned more than minted
    let e = assert_j(&j).expect_err("J must reject when total_burned exceeds total_minted");
    assert!(format!("{e:#}").contains("total_minted"), "got: {e:#}");
}

#[test]
fn j_rejects_empty_steps() {
    let mut j = green_j();
    j.steps = vec![]; // no per-step ledger recorded
    let e = assert_j(&j).expect_err("J must reject an empty per-step ledger");
    assert!(format!("{e:#}").contains("step"), "got: {e:#}");
}

#[test]
fn j_rejects_last_step_mismatch() {
    let mut j = green_j();
    j.steps.last_mut().unwrap().supply = 42; // last step != final supply
    let e = assert_j(&j).expect_err("J must reject when the last step != final supply");
    assert!(format!("{e:#}").contains("step"), "got: {e:#}");
}

#[test]
fn j_rejects_holder_balance_mismatch() {
    let mut j = green_j();
    j.holder_final_balance = 7; // != total_minted - total_burned
    let e =
        assert_j(&j).expect_err("J must reject when the holder balance is not custody-consistent");
    assert!(format!("{e:#}").contains("holder"), "got: {e:#}");
}

// ── the real-node E2E (the gate run for this slice) ──────────────────────────────────────────

/// Rows G + H + I + J against a REAL fresh local node: bootstrap genesis, start the four services,
/// deploy the production faucet, allowlist attester A, set a min burn size, mint to the holder, then
/// drive the full burn arc — the Row-G two-block burn committed via the ntx-builder / path N with
/// the holder creating the production `XReserveBurnNote`; the Row-H F7 same-block-erasure RIV
/// captured client-side (evidence only); the Row-I negatives (below-min, while-paused, wrong-asset)
/// proven by client-side kernel traps + committed-state read-backs; the Row-J conservation ledger —
/// and judge every row. Writes `evidence-gj.json` under the gitignored run root either way.
///
/// Ignored by default (NOT optional for the gate): it must bind loopback listener sockets for the
/// four node services, which hermetic audit sandboxes forbid. Run it with `-- --include-ignored` on
/// a network-enabled box (or the `lnv4_rows_gj` binary); the default suite's green carries no
/// real-node claim.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-node E2E: needs the v0.15.1 node binaries + loopback listener binds (denied in \
            sandboxed audit environments); run with `-- --include-ignored` or the lnv4_rows_gj \
            binary — the §11.2 gate claim rides on real runs + the human gate, never on the \
            default suite"]
async fn lnv4_rows_gj_against_real_local_node() -> Result<()> {
    use xusdc_validation::config::{repo_root, RunConfig};
    use xusdc_validation::evidence_gj::write_gj_evidence;
    use xusdc_validation::rows_gj::run_rows_gj;

    let label = format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let cfg = RunConfig::fresh(&repo_root(), &label);

    let obs = run_rows_gj(&cfg).await?;
    let verdicts: Vec<(&str, Result<()>)> = vec![
        ("G", assert_g(&obs.g)),
        ("H", assert_h(&obs.h)),
        ("I", assert_i(&obs.i)),
        ("J", assert_j(&obs.j)),
    ];
    let evidence = write_gj_evidence(&cfg, &obs, &verdicts)?;
    println!("LNV-4 evidence: {}", evidence.display());
    for (row, r) in verdicts {
        r.with_context(|| format!("row {row} failed on the real node"))?;
    }
    Ok(())
}
