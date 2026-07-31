//! LNV-3 test suite — matrix rows D (mint happy path) and E (mint negatives), written TEST-FIRST
//! against the rows-D/E assertion suite (`xusdc_validation::assertions_de`) + driver API.
//!
//! Two layers, exactly the LNV-1/2 partition:
//!
//! 1. **Assertion negatives** (no node, sandbox-safe — the DEFAULT suite). Synthetic
//!    [`RowsDeObservations`] built green, then each test breaks EXACTLY the one surface its row-check
//!    exists to reject, and proves the assertion rejects it (a silently-weakened assertion — e.g. the
//!    auditor's planted mutation — fails these). Plus one green-shape acceptance per row (guards
//!    against an always-failing suite).
//! 2. **The real-node E2E** (`lnv3_rows_de_against_real_local_node`): boots a FRESH local v0.15.1
//!    stack, deploys the production faucet, drives the whole D+E arc (the happy-path mints committed
//!    via the ntx-builder / path N with the recipient consuming the emitted P2ID note; every negative
//!    proven by a client-side kernel trap + committed-state read-back), and judges the observations.
//!    `#[ignore]`d in the default suite because it must bind loopback listener sockets (denied in
//!    hermetic audit sandboxes); run it with `-- --include-ignored` or the `lnv3_rows_de` binary. The
//!    full-matrix gate claim rides ONLY on real runs + the human gate — a green default suite proves the
//!    assertion layer only.

use anyhow::{Context, Result};
use xusdc_validation::assertions_de::{
    assert_all, assert_d, assert_e, ERR_XRESERVE_DISALLOWED_PUB_KEY, ERR_XRESERVE_FEE_NONZERO,
    ERR_XRESERVE_NONCE_REPLAY, ERR_XRESERVE_SIG_INVALID,
};
use xusdc_validation::observations_de::{
    MintHappy, MintNegative, RowsDeObservations, Verdict, Word4, MARKER_CLEAR, MARKER_SET,
};

// ── green synthetic fixtures ─────────────────────────────────────────────────────────────────

fn rej(msg: &str) -> Verdict {
    Verdict::Rejected(msg.to_string())
}

const SERIAL_1: Word4 = [11, 22, 33, 44];
const SERIAL_2: Word4 = [55, 66, 77, 88];
const TAG_1: u32 = 0xfffc_0000;
const TAG_2: u32 = 0xa5a4_0000;

/// A green empty-hookData happy variant: supply +100, nonce set, a well-formed P2ID note carrying
/// 100 units to the recipient, consumed one block LATER.
fn green_d_empty() -> MintHappy {
    MintHappy {
        label: "empty-hookData".to_string(),
        hook_data_len: 0,
        amount_units: 100,
        supply_before: 0,
        supply_after: 100,
        nonce_marker_after: MARKER_SET,
        note_serial: SERIAL_1,
        expected_serial: SERIAL_1,
        note_is_p2id: true,
        note_tag: TAG_1,
        expected_tag: TAG_1,
        note_asset_amount: 100,
        note_asset_is_faucet: true,
        recipient_balance_before: 0,
        recipient_balance_after: 100,
        note_commit_block: 7,
        recipient_consume_block: 8,
    }
}

/// A green hookData-bearing happy variant: supply 100 -> 250, nonce set, a 150-unit note, consumed
/// later. The recipient already held 100 (from the empty variant), so its balance goes 100 -> 250.
fn green_d_hookdata() -> MintHappy {
    MintHappy {
        label: "hookData-bearing".to_string(),
        hook_data_len: 10,
        amount_units: 150,
        supply_before: 100,
        supply_after: 250,
        nonce_marker_after: MARKER_SET,
        note_serial: SERIAL_2,
        expected_serial: SERIAL_2,
        note_is_p2id: true,
        note_tag: TAG_2,
        expected_tag: TAG_2,
        note_asset_amount: 150,
        note_asset_is_faucet: true,
        recipient_balance_before: 100,
        recipient_balance_after: 250,
        note_commit_block: 11,
        recipient_consume_block: 12,
    }
}

fn green_d() -> Vec<MintHappy> {
    vec![green_d_empty(), green_d_hookdata()]
}

const COMMITTED_SUPPLY: u64 = 250;

fn neg(
    label: &str,
    expected_error: &str,
    verdict: Verdict,
    expects_nonce_set: bool,
) -> MintNegative {
    MintNegative {
        label: label.to_string(),
        expected_error: expected_error.to_string(),
        verdict,
        supply_before: COMMITTED_SUPPLY,
        supply_after: COMMITTED_SUPPLY,
        nonce_marker_after: if expects_nonce_set {
            MARKER_SET
        } else {
            MARKER_CLEAR
        },
        expects_nonce_set,
    }
}

fn green_e() -> Vec<MintNegative> {
    vec![
        neg(
            "replayed-nonce",
            ERR_XRESERVE_NONCE_REPLAY,
            rej("... deposit intent nonce has already been used ..."),
            true,
        ),
        neg(
            "forged-signature",
            ERR_XRESERVE_SIG_INVALID,
            rej("... deposit attestation signature verification failed ..."),
            false,
        ),
        neg(
            "non-allowlisted-attester",
            ERR_XRESERVE_DISALLOWED_PUB_KEY,
            rej("... deposit attester pubkey commitment is not allowlisted ..."),
            false,
        ),
        neg(
            "nonzero-fee",
            ERR_XRESERVE_FEE_NONZERO,
            rej("... mint fee amount must be zero ..."),
            false,
        ),
        neg(
            "tampered-payload",
            ERR_XRESERVE_SIG_INVALID,
            rej("... deposit attestation signature verification failed ..."),
            false,
        ),
    ]
}

fn green_obs() -> RowsDeObservations {
    RowsDeObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic".to_string(),
        recipient_id: "0xrecipient".to_string(),
        d: green_d(),
        e: green_e(),
    }
}

// ── green-shape acceptance (guards against an always-failing suite) ──────────────────────────

#[test]
fn all_rows_accept_the_green_shape() -> Result<()> {
    assert_all(&green_obs())
}

// ── Row D negatives ───────────────────────────────────────────────────────────────────────────

#[test]
fn d_rejects_supply_not_raised_by_amount() {
    let mut d = green_d();
    d[0].supply_after = d[0].supply_before; // the mint did not raise token_supply
    let e = assert_d(&d).expect_err("D must reject when supply did not rise by the mint amount");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn d_rejects_supply_raised_by_wrong_amount() {
    let mut d = green_d();
    d[0].supply_after = d[0].supply_before + d[0].amount_units + 1; // over-minted
    let e = assert_d(&d).expect_err("D must reject when supply rose by the wrong amount");
    assert!(format!("{e:#}").contains("token_supply"), "got: {e:#}");
}

#[test]
fn d_rejects_nonce_not_set() {
    let mut d = green_d();
    d[0].nonce_marker_after = MARKER_CLEAR; // usedNonces[nonce] never set
    let e = assert_d(&d).expect_err("D must reject when the nonce marker is not set after mint");
    assert!(format!("{e:#}").contains("nonce"), "got: {e:#}");
}

#[test]
fn d_rejects_serial_mismatch() {
    let mut d = green_d();
    d[0].note_serial = [1, 2, 3, 4]; // serial != nonce-derived key
    let e = assert_d(&d).expect_err("D must reject when the note serial != the nonce key");
    assert!(format!("{e:#}").contains("serial"), "got: {e:#}");
}

#[test]
fn d_rejects_non_p2id_note() {
    let mut d = green_d();
    d[0].note_is_p2id = false; // emitted note is not a canonical P2ID
    let e = assert_d(&d).expect_err("D must reject a non-P2ID recipient note");
    assert!(format!("{e:#}").contains("P2ID"), "got: {e:#}");
}

#[test]
fn d_rejects_tag_mismatch() {
    let mut d = green_d();
    d[0].note_tag = 0xdead_0000; // not the recipient account-target tag
    let e = assert_d(&d).expect_err("D must reject when the note tag != the recipient tag");
    assert!(format!("{e:#}").contains("tag"), "got: {e:#}");
}

#[test]
fn d_rejects_note_asset_amount_mismatch() {
    let mut d = green_d();
    d[0].note_asset_amount = d[0].amount_units - 1; // note carries less than the minted amount
    let e =
        assert_d(&d).expect_err("D must reject when the note asset amount != the minted amount");
    assert!(format!("{e:#}").contains("asset"), "got: {e:#}");
}

#[test]
fn d_rejects_note_asset_wrong_faucet() {
    let mut d = green_d();
    d[0].note_asset_is_faucet = false; // asset not issued by this faucet
    let e = assert_d(&d).expect_err("D must reject when the note asset is not this faucet's");
    assert!(format!("{e:#}").contains("faucet"), "got: {e:#}");
}

#[test]
fn d_rejects_recipient_balance_not_credited() {
    let mut d = green_d();
    d[0].recipient_balance_after = d[0].recipient_balance_before; // consume did not credit funds
    let e = assert_d(&d).expect_err("D must reject when the recipient balance was not credited");
    assert!(format!("{e:#}").contains("balance"), "got: {e:#}");
}

#[test]
fn d_rejects_single_block_flow() {
    let mut d = green_d();
    d[0].recipient_consume_block = d[0].note_commit_block; // consume in the SAME block (not two-block)
    let e = assert_d(&d).expect_err("D must reject a non-two-block flow");
    assert!(
        format!("{e:#}").contains("two-block") || format!("{e:#}").contains("block"),
        "got: {e:#}"
    );
}

#[test]
fn d_rejects_missing_empty_hookdata_variant() {
    let d = vec![green_d_hookdata()]; // only the hookData-bearing variant
    let e = assert_d(&d).expect_err("D must require an empty-hookData variant");
    assert!(
        format!("{e:#}").contains("hookData") || format!("{e:#}").contains("hook"),
        "got: {e:#}"
    );
}

#[test]
fn d_rejects_missing_hookdata_variant() {
    let d = vec![green_d_empty()]; // only the empty-hookData variant
    let e = assert_d(&d).expect_err("D must require a hookData-bearing variant");
    assert!(
        format!("{e:#}").contains("hookData") || format!("{e:#}").contains("hook"),
        "got: {e:#}"
    );
}

// ── Row E negatives ───────────────────────────────────────────────────────────────────────────

#[test]
fn e_rejects_empty_set() {
    let e = assert_e(&[]).expect_err("E must reject an empty negative set");
    assert!(
        format!("{e:#}").contains("non-empty") || format!("{e:#}").contains("must include"),
        "got: {e:#}"
    );
}

#[test]
fn e_rejects_a_non_rejected_negative() {
    let mut ev = green_e();
    ev[1].verdict = Verdict::Accepted; // a forged-signature mint was ACCEPTED
    let e = assert_e(&ev).expect_err("E must reject when a negative was accepted");
    assert!(format!("{e:#}").contains("ACCEPTED"), "got: {e:#}");
}

#[test]
fn e_rejects_wrong_gate_error() {
    let mut ev = green_e();
    ev[1].verdict = rej("some entirely unrelated trap"); // rejected, but not by the sig gate
    let e = assert_e(&ev).expect_err("E must reject a negative that failed for the wrong reason");
    assert!(
        format!("{e:#}").contains(ERR_XRESERVE_SIG_INVALID),
        "got: {e:#}"
    );
}

#[test]
fn e_rejects_supply_changed() {
    let mut ev = green_e();
    ev[0].supply_after = ev[0].supply_before + 1; // committed supply moved after a reject
    let e = assert_e(&ev).expect_err("E must reject when committed supply changed");
    assert!(format!("{e:#}").contains("supply"), "got: {e:#}");
}

#[test]
fn e_rejects_fresh_nonce_set_after_reject() {
    let mut ev = green_e();
    ev[1].nonce_marker_after = MARKER_SET; // a rejected fresh-nonce negative set its nonce anyway
    let e = assert_e(&ev)
        .expect_err("E must reject when a rejected fresh-nonce negative set its nonce");
    assert!(format!("{e:#}").contains("nonce"), "got: {e:#}");
}

#[test]
fn e_rejects_replay_nonce_not_set() {
    // The replay negative reuses an already-committed nonce; its marker MUST stay set. If the driver
    // observed it CLEARED, the row's precondition (a genuinely used nonce) never held.
    let mut ev = green_e();
    ev[0].nonce_marker_after = MARKER_CLEAR;
    let e = assert_e(&ev).expect_err("E must reject when the replay nonce is not set");
    assert!(format!("{e:#}").contains("nonce"), "got: {e:#}");
}

#[test]
fn e_requires_the_replay_negative() {
    // Drop the replay negative (the only expects_nonce_set one) — E must require it.
    let ev: Vec<MintNegative> = green_e()
        .into_iter()
        .filter(|n| !n.expects_nonce_set)
        .collect();
    let e = assert_e(&ev).expect_err("E must require the replay negative");
    assert!(
        format!("{e:#}").contains("replay") || format!("{e:#}").contains("nonce"),
        "got: {e:#}"
    );
}

#[test]
fn e_requires_the_forged_signature_negative() {
    // Remove ONLY forged-signature (tampered-payload stays). The two share the SIG_INVALID gate but
    // are DISTINCT attack surfaces — coverage must require each independently, so keeping the other
    // signature-gate negative must NOT satisfy this one.
    let ev: Vec<MintNegative> = green_e()
        .into_iter()
        .filter(|n| n.label != "forged-signature")
        .collect();
    let e = assert_e(&ev).expect_err("E must require the forged-signature negative distinctly");
    assert!(
        format!("{e:#}").contains("forged-signature")
            || format!("{e:#}").contains(ERR_XRESERVE_SIG_INVALID),
        "got: {e:#}"
    );
}

#[test]
fn e_requires_the_tampered_payload_negative() {
    // Remove ONLY tampered-payload (forged-signature stays). Symmetric to the forged-signature test:
    // the other SIG_INVALID vector must NOT cover for this one.
    let ev: Vec<MintNegative> = green_e()
        .into_iter()
        .filter(|n| n.label != "tampered-payload")
        .collect();
    let e = assert_e(&ev).expect_err("E must require the tampered-payload negative distinctly");
    assert!(
        format!("{e:#}").contains("tampered-payload")
            || format!("{e:#}").contains(ERR_XRESERVE_SIG_INVALID),
        "got: {e:#}"
    );
}

#[test]
fn e_requires_the_bad_attester_negative() {
    let ev: Vec<MintNegative> = green_e()
        .into_iter()
        .filter(|n| n.label != "non-allowlisted-attester")
        .collect();
    let e = assert_e(&ev).expect_err("E must require the non-allowlisted-attester negative");
    assert!(
        format!("{e:#}").contains(ERR_XRESERVE_DISALLOWED_PUB_KEY)
            || format!("{e:#}").contains("allowlist"),
        "got: {e:#}"
    );
}

#[test]
fn e_requires_the_fee_negative() {
    let ev: Vec<MintNegative> = green_e()
        .into_iter()
        .filter(|n| n.label != "nonzero-fee")
        .collect();
    let e = assert_e(&ev).expect_err("E must require the non-zero-fee negative");
    assert!(
        format!("{e:#}").contains(ERR_XRESERVE_FEE_NONZERO) || format!("{e:#}").contains("fee"),
        "got: {e:#}"
    );
}

// ── err_code derivation tripwire (a reject may carry only its err_code, not the message) ───────

/// The shape a MASM gate produces on a client-side trap when the message text is absent: a
/// `FailedAssertion` carrying ONLY the `err_code` for `expected_msg`. `assert_rejected_with` must
/// match on the code too (derived from the expected string via `MasmError::code()`), so a genuine
/// gate trap that surfaces code-only is still recognized.
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
fn code_only_mint_gate_rejects_are_matched() {
    let mut ev = green_e();
    for n in &mut ev {
        n.verdict = rejected_code_only(&n.expected_error);
    }
    assert_e(&ev).expect("E must accept mint-gate rejects carried only by their err_code");
}

#[test]
fn code_only_reject_with_the_wrong_code_is_rejected() {
    let mut ev = green_e();
    ev[3].verdict = rejected_code_only("some entirely unrelated assertion"); // wrong code for the fee gate
    let e = assert_e(&ev).expect_err("E must reject a code-only reject bearing the WRONG err_code");
    assert!(
        format!("{e:#}").contains(ERR_XRESERVE_FEE_NONZERO) || format!("{e:#}").contains("fee"),
        "got: {e:#}"
    );
}

// ── the real-node E2E (the gate run for this slice) ──────────────────────────────────────────

/// Rows D + E against a REAL fresh local node: bootstrap genesis, start the four services, deploy
/// the production faucet (domain config build-seeded to match the mint vector, identifier_init as
/// the first admin note), allowlist attester A, drive both
/// happy-path mints (empty-hookData + hookData-bearing) committed via the ntx-builder / path N with
/// the recipient consuming each emitted P2ID note, then every negative (replay, forged signature,
/// non-allowlisted attester, non-zero fee, tampered payload) proven by a client-side kernel trap +
/// committed-state read-back, and judge every row. Writes `evidence-de.json` under the gitignored
/// run root either way.
///
/// Ignored by default (NOT optional for the gate): it must bind loopback listener sockets for the
/// four node services, which hermetic audit sandboxes forbid. Run it with `-- --include-ignored` on
/// a network-enabled box (or the `lnv3_rows_de` binary); the default suite's green carries no
/// real-node claim.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real-node E2E: needs the v0.15.1 node binaries + loopback listener binds (denied in \
            sandboxed audit environments); run with `-- --include-ignored` or the lnv3_rows_de \
            binary — the §11.2 gate claim rides on real runs + the human gate, never on the \
            default suite"]
async fn lnv3_rows_de_against_real_local_node() -> Result<()> {
    use xusdc_validation::config::{repo_root, RunConfig};
    use xusdc_validation::evidence_de::write_de_evidence;
    use xusdc_validation::rows_de::run_rows_de;

    let label = format!(
        "test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let cfg = RunConfig::fresh(&repo_root(), &label);

    let obs = run_rows_de(&cfg).await?;
    let verdicts: Vec<(&str, Result<()>)> = vec![("D", assert_d(&obs.d)), ("E", assert_e(&obs.e))];
    let evidence = write_de_evidence(&cfg, &obs, &verdicts)?;
    println!("LNV-3 evidence: {}", evidence.display());
    for (row, r) in verdicts {
        r.with_context(|| format!("row {row} failed on the real node"))?;
    }
    Ok(())
}
