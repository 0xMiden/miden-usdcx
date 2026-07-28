//! LNV-2 test suite — matrix rows C (admin suite) and F (auth boundary), written TEST-FIRST
//! against the rows-C/F assertion suite (`xusdc_validation::assertions_cf`) + driver API.
//!
//! Two layers, exactly the LNV-1 partition:
//!
//! 1. **Assertion negatives** (no node, sandbox-safe — the DEFAULT suite). Synthetic
//!    [`RowsCfObservations`] built green, then each test breaks EXACTLY the one surface its row-check
//!    exists to reject and proves the assertion rejects it (a silently-weakened assertion — e.g. the
//!    auditor's planted mutation — fails these). Plus one green-shape acceptance per row (guards
//!    against an always-failing suite).
//! 2. **The real-node E2E** (`lnv2_rows_cf_against_real_local_node`): boots a FRESH local v0.15.1
//!    stack, deploys the production faucet, drives the whole C+F arc (admin state changes committed
//!    via the ntx-builder / path N; mint/burn + auth-boundary rejects proven by client-side kernel
//!    traps), and judges the observations. `#[ignore]`d in the default suite because it must bind
//!    loopback listener sockets (denied in hermetic audit sandboxes); run it with
//!    `-- --include-ignored` or the `lnv2_rows_cf` binary. The full-matrix gate claim rides ONLY on real
//!    runs + the human gate — a green default suite proves the assertion layer only.

use anyhow::{Context, Result};
use xusdc_validation::assertions_cf::{
    assert_all, assert_c1, assert_c2, assert_c3, assert_c4, assert_c5, assert_c6, assert_f,
    ERR_ATTESTER_NOT_ALLOWLISTED, ERR_LACKS_ROLE, ERR_NOT_OWNER,
};
use xusdc_validation::observations_cf::{
    AdminGateReject, C1SetAttester, C2MinBurn, C3MaxSupply, C4Pause, C5RoleRotation, RowF,
    RowsCfObservations, Verdict, MARKER_CLEAR, MARKER_SET,
};

// ── green synthetic fixtures ─────────────────────────────────────────────────────────────────

fn rej(msg: &str) -> Verdict {
    Verdict::Rejected(msg.to_string())
}

fn green_c1() -> C1SetAttester {
    C1SetAttester {
        a_marker_after_enable: MARKER_SET,
        a_marker_after_rotate: MARKER_CLEAR,
        b_marker_after_rotate: MARKER_SET,
        mint_by_a: rej("... deposit attester pubkey commitment is not allowlisted ..."),
        mint_by_b: Verdict::Accepted,
    }
}

fn green_c2() -> C2MinBurn {
    C2MinBurn {
        raised_min: 50,
        committed_after_raise: 50,
        burn_below_raised: rej(
            "... amount to be burned must exceed specified minimum burn amount ...",
        ),
        lowered_min: 10,
        committed_after_lower: 10,
        burn_at_lowered: Verdict::Accepted,
    }
}

fn green_c3() -> C3MaxSupply {
    C3MaxSupply {
        committed_cap: 500,
        max_supply_readback: 500,
        over_cap_mint: rej("... token_supply plus the amount passed to distribute would exceed the maximum supply ..."),
        within_cap_mint: Verdict::Accepted,
    }
}

fn green_c4() -> C4Pause {
    C4Pause {
        is_paused_after_pause: MARKER_SET,
        mint_while_paused: rej("... the contract is paused ..."),
        burn_while_paused: rej("... the contract is paused ..."),
        owner_set_attester_while_paused_marker: MARKER_SET,
        owner_set_min_burn_while_paused: 7,
        is_paused_after_unpause: MARKER_CLEAR,
        mint_after_unpause: Verdict::Accepted,
    }
}

fn green_c5() -> C5RoleRotation {
    C5RoleRotation {
        new_pauser_membership_after_grant: MARKER_SET,
        is_paused_after_new_pauser_pause: MARKER_SET,
        new_pauser_membership_after_revoke: MARKER_CLEAR,
        revoked_pauser_pause: rej("... note sender does not hold the required role ..."),
    }
}

fn green_c6() -> Vec<AdminGateReject> {
    vec![
        AdminGateReject {
            op: "set_attester".to_string(),
            sender: "non-owner".to_string(),
            expected_gate: ERR_NOT_OWNER.to_string(),
            verdict: rej("trap: note sender is not the owner"),
            note_unconsumed: true,
        },
        AdminGateReject {
            op: "set_max_supply".to_string(),
            sender: "non-owner".to_string(),
            expected_gate: ERR_NOT_OWNER.to_string(),
            verdict: rej("trap: note sender is not the owner"),
            note_unconsumed: true,
        },
        AdminGateReject {
            op: "pause".to_string(),
            sender: "non-DOM_PAUSER".to_string(),
            expected_gate: ERR_LACKS_ROLE.to_string(),
            verdict: rej("trap: note sender does not hold the required role"),
            note_unconsumed: true,
        },
    ]
}

fn green_f() -> RowF {
    RowF {
        non_allowlisted_note: rej(
            "... input note script root is not in the note script allowlist ...",
        ),
        tx_script: rej("... transaction script root is not in the tx script allowlist ..."),
    }
}

fn green_obs() -> RowsCfObservations {
    RowsCfObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic".to_string(),
        c1: green_c1(),
        c2: green_c2(),
        c3: green_c3(),
        c4: green_c4(),
        c5: green_c5(),
        c6: green_c6(),
        f: green_f(),
    }
}

// ── green-shape acceptance (guards against an always-failing suite) ──────────────────────────

#[test]
fn all_rows_accept_the_green_shape() -> Result<()> {
    assert_all(&green_obs())
}

// ── C1 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c1_rejects_when_a_not_disabled_after_rotation() {
    let mut c1 = green_c1();
    c1.a_marker_after_rotate = MARKER_SET; // A stayed enabled — rotation did not disable it
    let e = assert_c1(&c1).expect_err("C1 must reject when A is not disabled after the rotation");
    assert!(format!("{e:#}").contains("disabled"), "got: {e:#}");
}

#[test]
fn c1_rejects_when_b_not_enabled_after_rotation() {
    let mut c1 = green_c1();
    c1.b_marker_after_rotate = MARKER_CLEAR; // B never got enabled
    let e = assert_c1(&c1).expect_err("C1 must reject when B is not enabled after the rotation");
    assert!(format!("{e:#}").contains("enabled"), "got: {e:#}");
}

#[test]
fn c1_rejects_when_mint_by_a_is_accepted() {
    let mut c1 = green_c1();
    c1.mint_by_a = Verdict::Accepted; // the rotated-out A still minted — the allowlist leaked
    let e = assert_c1(&c1).expect_err("C1 must reject when the rotated-out A's mint is accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn c1_rejects_mint_by_a_with_wrong_error() {
    let mut c1 = green_c1();
    c1.mint_by_a = rej("some unrelated failure"); // rejected, but not by the allowlist gate
    let e = assert_c1(&c1).expect_err("C1 must reject a mint-by-A failure that is not the gate");
    assert!(
        format!("{e:#}").contains(ERR_ATTESTER_NOT_ALLOWLISTED),
        "got: {e:#}"
    );
}

#[test]
fn c1_rejects_when_mint_by_b_is_rejected() {
    let mut c1 = green_c1();
    c1.mint_by_b = rej("the contract is paused"); // the active B could not mint
    let e = assert_c1(&c1).expect_err("C1 must reject when the active B's mint is rejected");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

// ── C2 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c2_rejects_min_readback_mismatch() {
    let mut c2 = green_c2();
    c2.committed_after_raise = 49; // the raise did not commit the intended value
    let e = assert_c2(&c2).expect_err("C2 must reject a min_burn_size read-back mismatch");
    assert!(format!("{e:#}").contains("read back"), "got: {e:#}");
}

#[test]
fn c2_rejects_below_min_burn_accepted() {
    let mut c2 = green_c2();
    c2.burn_below_raised = Verdict::Accepted; // a below-min burn slipped through
    let e = assert_c2(&c2).expect_err("C2 must reject when a below-min burn is accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn c2_rejects_at_min_burn_rejected() {
    let mut c2 = green_c2();
    c2.burn_at_lowered = rej("amount to be burned must exceed specified minimum burn amount"); // at-min wrongly rejected
    let e = assert_c2(&c2).expect_err("C2 must reject when an at-min burn is rejected");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

// ── C3 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c3_rejects_max_supply_readback_mismatch() {
    let mut c3 = green_c3();
    c3.max_supply_readback = 499; // set_max_supply did not commit the intended cap
    let e = assert_c3(&c3).expect_err("C3 must reject a max_supply read-back mismatch");
    assert!(format!("{e:#}").contains("read back"), "got: {e:#}");
}

#[test]
fn c3_rejects_over_cap_mint_accepted() {
    let mut c3 = green_c3();
    c3.over_cap_mint = Verdict::Accepted; // an over-cap mint slipped through
    let e = assert_c3(&c3).expect_err("C3 must reject when an over-cap mint is accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

// ── C4 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c4_rejects_not_paused_after_pause() {
    let mut c4 = green_c4();
    c4.is_paused_after_pause = MARKER_CLEAR; // the pause never took effect
    let e = assert_c4(&c4).expect_err("C4 must reject when is_paused is not set after pause");
    assert!(
        format!("{e:#}").contains("is_paused after the DOM_PAUSER pause"),
        "got: {e:#}"
    );
}

#[test]
fn c4_rejects_mint_not_halted_while_paused() {
    let mut c4 = green_c4();
    c4.mint_while_paused = Verdict::Accepted; // a mint minted while paused
    let e = assert_c4(&c4).expect_err("C4 must reject when a mint is accepted while paused");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn c4_rejects_burn_not_halted_while_paused() {
    let mut c4 = green_c4();
    c4.burn_while_paused = Verdict::Accepted; // a burn burned while paused
    let e = assert_c4(&c4).expect_err("C4 must reject when a burn is accepted while paused");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn c4_rejects_owner_setter_halted_while_paused() {
    let mut c4 = green_c4();
    c4.owner_set_attester_while_paused_marker = MARKER_CLEAR; // F6 violated: owner setter halted
    let e = assert_c4(&c4)
        .expect_err("C4/F6 must reject when the owner's setter did not commit while paused");
    assert!(format!("{e:#}").contains("WHILE PAUSED"), "got: {e:#}");
}

#[test]
fn c4_rejects_still_paused_after_unpause() {
    let mut c4 = green_c4();
    c4.is_paused_after_unpause = MARKER_SET; // unpause did not lift the halt
    let e = assert_c4(&c4).expect_err("C4 must reject when still paused after unpause");
    assert!(
        format!("{e:#}").contains("is_paused after the DOM_PAUSER unpause"),
        "got: {e:#}"
    );
}

// ── C5 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c5_rejects_no_membership_after_grant() {
    let mut c5 = green_c5();
    c5.new_pauser_membership_after_grant = MARKER_CLEAR; // the grant did not seat the member
    let e = assert_c5(&c5).expect_err("C5 must reject when the grant did not seat the new pauser");
    assert!(
        format!("{e:#}").contains("after the DOM_MANAGER grant"),
        "got: {e:#}"
    );
}

#[test]
fn c5_rejects_new_pauser_cannot_pause() {
    let mut c5 = green_c5();
    c5.is_paused_after_new_pauser_pause = MARKER_CLEAR; // the granted member could not actually pause
    let e = assert_c5(&c5).expect_err("C5 must reject when the new pauser could not pause");
    assert!(format!("{e:#}").contains("capability proven"), "got: {e:#}");
}

#[test]
fn c5_rejects_membership_not_cleared_after_revoke() {
    let mut c5 = green_c5();
    c5.new_pauser_membership_after_revoke = MARKER_SET; // the revoke did not clear the member
    let e = assert_c5(&c5).expect_err("C5 must reject when the revoke did not clear the member");
    assert!(
        format!("{e:#}").contains("after the DOM_MANAGER revoke"),
        "got: {e:#}"
    );
}

#[test]
fn c5_rejects_revoked_pauser_can_still_pause() {
    let mut c5 = green_c5();
    c5.revoked_pauser_pause = Verdict::Accepted; // the revoked account still paused
    let e = assert_c5(&c5).expect_err("C5 must reject when the revoked account can still pause");
    assert!(
        format!("{e:#}").contains("required role") || format!("{e:#}").contains("ACCEPTED"),
        "got: {e:#}"
    );
}

// ── C6 negatives ─────────────────────────────────────────────────────────────────────────────

#[test]
fn c6_rejects_empty_set() {
    let e = assert_c6(&[]).expect_err("C6 must reject an empty negative set");
    assert!(format!("{e:#}").contains("non-empty"), "got: {e:#}");
}

#[test]
fn c6_rejects_a_consumed_admin_note() {
    let mut c6 = green_c6();
    c6[0].note_unconsumed = false; // a non-authorized sender's note was CONSUMED
    let e =
        assert_c6(&c6).expect_err("C6 must reject when a non-authorized admin note was consumed");
    assert!(format!("{e:#}").contains("CONSUMED"), "got: {e:#}");
}

#[test]
fn c6_rejects_a_non_rejected_op() {
    let mut c6 = green_c6();
    c6[0].verdict = Verdict::Accepted; // a non-owner op executed
    let e = assert_c6(&c6).expect_err("C6 must reject when a non-authorized op executed");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn c6_requires_both_gate_kinds() {
    // Only owner-gated negatives, no role-gated one — the row must cover both gates.
    let c6 = vec![green_c6()[0].clone()];
    let e = assert_c6(&c6).expect_err("C6 must require a role-gated negative too");
    assert!(format!("{e:#}").contains("non-DOM_PAUSER"), "got: {e:#}");
}

// ── row F negatives ──────────────────────────────────────────────────────────────────────────

#[test]
fn f_rejects_p2id_note_accepted() {
    let mut f = green_f();
    f.non_allowlisted_note = Verdict::Accepted; // AuthNetworkAccount let a non-allowlisted note through
    let e = assert_f(&f).expect_err("F must reject when a non-allowlisted note is accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn f_rejects_tx_script_accepted() {
    let mut f = green_f();
    f.tx_script = Verdict::Accepted; // a tx-script ran against the faucet
    let e = assert_f(&f).expect_err("F must reject when a tx-script transaction is accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn f_rejects_wrong_reject_error() {
    let mut f = green_f();
    f.non_allowlisted_note = rej("some other trap"); // rejected, but not by the note allowlist
    let e = assert_f(&f).expect_err("F must reject a note failure that is not the allowlist gate");
    assert!(
        format!("{e:#}").contains("note script allowlist"),
        "got: {e:#}"
    );
}

// ── err_code derivation tripwire (stock-gate rejects carry only err_code, not the message) ───

/// A client-side execute of a faucet consumption that traps in a STOCK miden-standards proc (the
/// owner / role / pause / note-script-allowlist gates) surfaces `err_msg: None` — only the
/// deterministic `err_code`. `assert_rejected_with` therefore also matches on `err_code`, computed
/// from the expected message via `MasmError::code()` (== the assembler's `error_code_from_msg`).
/// This pins that derivation to the codes OBSERVED on the real node (2026-07-09 run), so a protocol
/// pin bump or an error-string drift that would silently break real-node matching fails HERE, fast.
#[test]
fn stock_gate_err_codes_match_the_real_node_observed_values() {
    use miden_protocol::errors::MasmError;
    let code = |s: &str| MasmError::new(s.to_string()).code().as_canonical_u64();
    assert_eq!(
        code("the contract is paused"),
        13643929038179635348,
        "C4 pause gate"
    );
    assert_eq!(code(ERR_NOT_OWNER), 7385238526269899403, "C6 owner gate");
    assert_eq!(code(ERR_LACKS_ROLE), 2534091087325248367, "C5 role gate");
    assert_eq!(
        code("input note script root is not in the note script allowlist"),
        2177567524790281771,
        "F note-allowlist gate",
    );
    assert_eq!(
        code("transaction script root is not in the tx script allowlist"),
        18283006182033373596,
        "F tx-script-allowlist gate",
    );
}

/// The shape a STOCK miden-standards gate produces on a client-side trap: a `FailedAssertion`
/// carrying ONLY the `err_code` for `expected_msg`, with `err_msg: None`. This is what the real node
/// surfaces for the owner / role / pause / note+tx-script-allowlist gates (§2.4 of the record) — the
/// message text is absent, so a row-check that matched ONLY on the message would spuriously reject a
/// genuine gate trap.
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

/// A stock-gate reject carried ONLY by its `err_code` (no message) is ACCEPTED by the row-check —
/// this exercises the `err_code` branch of `assert_rejected_with`, which the 30-min real-node run is
/// otherwise the only thing to cover. With that branch removed the auditor's mutation lands here.
#[test]
fn code_only_stock_gate_rejects_are_matched() {
    // Row F — both gates are stock (code-only on the real node).
    let f = RowF {
        non_allowlisted_note: rejected_code_only(
            "input note script root is not in the note script allowlist",
        ),
        tx_script: rejected_code_only("transaction script root is not in the tx script allowlist"),
    };
    assert_f(&f).expect("row F must accept stock-gate rejects carried only by their err_code");

    // C4 — the pause halt is a stock gate (code-only). The rest of the green C4 shape is message-based.
    let mut c4 = green_c4();
    c4.mint_while_paused = rejected_code_only("the contract is paused");
    c4.burn_while_paused = rejected_code_only("the contract is paused");
    assert_c4(&c4).expect("C4 must accept a code-only paused reject");

    // C6 — the owner/role gates are stock (code-only).
    let c6 = vec![
        AdminGateReject {
            op: "set_attester".to_string(),
            sender: "non-owner".to_string(),
            expected_gate: ERR_NOT_OWNER.to_string(),
            verdict: rejected_code_only(ERR_NOT_OWNER),
            note_unconsumed: true,
        },
        AdminGateReject {
            op: "pause".to_string(),
            sender: "non-DOM_PAUSER".to_string(),
            expected_gate: ERR_LACKS_ROLE.to_string(),
            verdict: rejected_code_only(ERR_LACKS_ROLE),
            note_unconsumed: true,
        },
    ];
    assert_c6(&c6).expect("C6 must accept code-only owner/role rejects");
}

/// A code-only reject whose `err_code` is for a DIFFERENT error must NOT satisfy the gate — the
/// err_code branch is SPECIFIC (it matches the expected error's code, not any code).
#[test]
fn code_only_reject_with_the_wrong_code_is_rejected() {
    let mut f = green_f();
    f.non_allowlisted_note = rejected_code_only("some entirely unrelated assertion");
    let e = assert_f(&f).expect_err("F must reject a code-only reject bearing the WRONG err_code");
    assert!(
        format!("{e:#}").contains("note script allowlist"),
        "got: {e:#}"
    );
}

// ── the real-node E2E (the gate run for this slice) ──────────────────────────────────────────

/// Rows C + F against a REAL fresh local node: bootstrap genesis, start the four services, deploy
/// the production faucet (domain config build-seeded to match the mint vector, identifier_init as
/// the first admin note), drive the whole admin + auth-boundary
/// arc (admin state changes committed via the ntx-builder / path N; mint/burn + auth rejects proven by
/// client-side kernel traps), and judge every row. Writes `evidence-cf.json` under the gitignored run
/// root either way.
///
/// Ignored by default (NOT optional for the gate): it must bind loopback listener sockets for the four
/// node services, which hermetic audit sandboxes forbid. Run it with `-- --include-ignored` on a
/// network-enabled box (or the `lnv2_rows_cf` binary); the default suite's green carries no real-node
/// claim.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-node E2E: needs the v0.15.1 node binaries + loopback listener binds (denied in \
            sandboxed audit environments); run with `-- --include-ignored` or the lnv2_rows_cf \
            binary — the §11.2 gate claim rides on real runs + the human gate, never on the \
            default suite"]
async fn lnv2_rows_cf_against_real_local_node() -> Result<()> {
    use xusdc_validation::config::{repo_root, RunConfig};
    use xusdc_validation::evidence_cf::write_cf_evidence;
    use xusdc_validation::rows_cf::run_rows_cf;

    let label = format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let cfg = RunConfig::fresh(&repo_root(), &label);

    let obs = run_rows_cf(&cfg).await?;
    let verdicts: Vec<(&str, Result<()>)> = vec![
        ("C1", assert_c1(&obs.c1)),
        ("C2", assert_c2(&obs.c2)),
        ("C3", assert_c3(&obs.c3)),
        ("C4", assert_c4(&obs.c4)),
        ("C5", assert_c5(&obs.c5)),
        ("C6", assert_c6(&obs.c6)),
        ("F", assert_f(&obs.f)),
    ];
    let evidence = write_cf_evidence(&cfg, &obs, &verdicts)?;
    println!("LNV-2 evidence: {}", evidence.display());
    for (row, r) in verdicts {
        r.with_context(|| format!("row {row} failed on the real node"))?;
    }
    Ok(())
}
