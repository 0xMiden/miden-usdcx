//! LNV-5 test suite — matrix rows K (ntx-builder liveness / path N) + L (clean logs) and the
//! consolidated full-matrix VALIDATION RECORD + evidence packets, written TEST-FIRST against the
//! rows-K/L observation, derivation, assertion, and record APIs.
//!
//! Two layers, exactly the LNV-1/2/3/4 partition:
//!
//! 1. **Derivation + assertion + record negatives** (no node, sandbox-safe — the DEFAULT suite).
//!    Synthetic observations/log fixtures built green (including VERBATIM ANSI-colored log-line
//!    shapes captured from real archived runs), then each test breaks EXACTLY the one surface its
//!    check exists to reject and proves the check rejects it (a silently-weakened check — e.g. the
//!    auditor's planted mutation — fails these). Plus green-shape acceptances (guard against an
//!    always-failing suite). The record tests pin the HUMAN-GATE invariant: the generated
//!    VALIDATION RECORD never self-declares the acceptance gate passed — the per-row results are
//!    machine verdicts; the GATE verdict is a human decision.
//! 2. **The real-node E2E** (`lnv5_full_matrix_against_real_local_node`): boots ONE fresh local
//!    v0.15.1 stack and drives the WHOLE A–L matrix on it (the LNV-1..4 drivers composed in order
//!    on the same node, then rows K + L derived from that single run). `#[ignore]`d in the default
//!    suite because it must bind loopback listener sockets (denied in hermetic audit sandboxes);
//!    run it with `-- --include-ignored` or the `lnv5_full_matrix` binary. The full-matrix acceptance-gate claim
//!    rides ONLY on real runs + the HUMAN gate — a green default suite proves the logic layer only.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountIdVersion, AccountType, AssetCallbackFlag,
};
use tempfile::TempDir;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_validation::assertions::ERR_DOMAIN_REINIT_TEXT;
use xusdc_validation::assertions_cf::{ERR_LACKS_ROLE, ERR_NOT_OWNER};
use xusdc_validation::assertions_de::{
    ERR_XRESERVE_BAD_PK_COMMITMENT, ERR_XRESERVE_FEE_NONZERO, ERR_XRESERVE_NONCE_REPLAY,
    ERR_XRESERVE_SIG_INVALID,
};
use xusdc_validation::assertions_gj::{
    ERR_BURN_BELOW_MIN, ERR_PAUSED, ERR_WRONG_ASSET_ORIGIN, FIXED_XUSDC_BURN_TAG,
};
use xusdc_validation::assertions_kl::{assert_k, assert_l};
use xusdc_validation::config::{DomainParams, RunConfig};
use xusdc_validation::deploy::{build_xreserve_component_seeded, production_components};
use xusdc_validation::observations::RowsAbObservations;
use xusdc_validation::observations_cf::{
    AdminGateReject, C1SetAttester, C2MinBurn, C3MaxSupply, C4Pause, C5RoleRotation, RowF,
    RowsCfObservations, Verdict, MARKER_CLEAR, MARKER_SET,
};
use xusdc_validation::observations_de::{MintHappy, MintNegative, RowsDeObservations};
use xusdc_validation::observations_gj::{
    BurnNegative, BurnSameBlock, BurnTwoBlock, ConservationLedger, RowsGjObservations, SupplyStep,
};
use xusdc_validation::observations_kl::{
    FlaggedLine, FullMatrixObservations, PathNCommit, RowKObservations, RowLObservations,
    ScannedLog, TriagedLine,
};
use xusdc_validation::record::{
    any_failed, full_matrix_outcomes, render_f7_packet, render_getnotesbyid_capture,
    render_ntx_verdict, render_validation_record, validate_row_outcomes, RecordContext, RowOutcome,
    MATRIX_ROW_IDS,
};
use xusdc_validation::rows_kl::{
    derive_row_k, is_panic_line, line_level, ntx_execution_evidence, pathn_commits_from,
    scan_log_text, scan_logs, strip_ansi, EXPECTED_LOG_LINES, NTX_EXECUTION_MARKER,
    REQUIRED_SERVICE_LOGS,
};

// ════════════════════════════════════════════════════════════════════════════════════════════
// VERBATIM log-line shapes from real archived runs (`local-node-data/lnv1/run-*/logs/*.log`).
// The ERROR/WARN vocabulary below is the COMPLETE set observed across every archived LNV-1..4
// run; the ANSI SGR escapes are exactly what the node services emit to a non-tty log file.
// ════════════════════════════════════════════════════════════════════════════════════════════

/// The sequencer rejecting the Row-H deliberate user-RPC submission (ANSI-colored, verbatim shape).
const REAL_SUBMIT_REJECT: &str = "\u{1b}[2m2026-07-10T19:46:25.559312Z\u{1b}[0m \u{1b}[31mERROR\u{1b}[0m \u{1b}[1mrpc\u{1b}[0m:\u{1b}[1msubmit_proven_tx\u{1b}[0m: \u{1b}[3merror\u{1b}[0m\u{1b}[2m=\u{1b}[0mcode: 'Client specified an invalid argument', message: \"Network transactions may not be submitted by users yet\" \u{1b}[2m\u{1b}[3mrpc.service\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"rpc.Api\"";

/// The ntx-builder failing a deliberately-unconsumable routed note (variant 1: filter_notes).
const REAL_NTX_ALL_FAILED: &str = "2026-07-10T08:14:36.107037Z ERROR ntx.actor.execute_transactions:ntx.execute_transaction:ntx.execute_transaction.filter_notes: error=all notes failed to be executed account_id=V1(AccountIdV1 { suffix: 5030960756410648064, prefix: 8554 })";

/// The ntx-builder failing a deliberately-unconsumable routed note (variant 2: the tx wrapper).
const REAL_NTX_TX_FAILED: &str = "2026-07-10T08:14:36.107156Z ERROR ntx.actor.execute_transactions: network transaction failed account_id=0x76b88125847236d145d190271cc986 note_ids=[NoteId(Word([9402371243822453137, 1414985401122621]))]";

/// The teardown SIGTERM-escalation shutdown line (ANSI-colored, verbatim shape).
const REAL_SHUTDOWN: &str = "\u{1b}[2m2026-07-10T19:48:33.574493Z\u{1b}[0m \u{1b}[31mERROR\u{1b}[0m Graceful shutdown timed out; exiting process \u{1b}[3mgrace_period\u{1b}[0m\u{1b}[2m=\u{1b}[0m10s";

/// The startup-ordering WARN (the ntx-builder retrying the sequencer RPC before it listens).
const REAL_WARN_RETRY: &str = "2026-07-10T08:00:19.003886Z  WARN rpc.client.block_subscription_with_retry: RPC connection failed while opening block subscription, retrying sleep_ms=155 err=RPC gRPC call failed";

/// The teardown WARN (the sequencer stops first; the block subscription drops). Note the ANSI
/// `[33m WARN[0m` token carries a LEADING SPACE inside the color scope.
const REAL_WARN_DROP: &str = "\u{1b}[2m2026-07-10T19:48:33.703531Z\u{1b}[0m \u{1b}[33m WARN\u{1b}[0m block subscription failed, reconnecting \u{1b}[3merr\u{1b}[0m\u{1b}[2m=\u{1b}[0mRPC gRPC call failed";

/// An INFO line that MENTIONS failure words (must NOT be classified: level token is INFO).
const REAL_INFO_NOTE_FAILED: &str = "2026-07-10T08:14:36.107213Z  INFO ntx.actor.execute_transactions: note failed: consumability check note.id=0x91916292d4ee7b82";

/// A multi-line-entry CONTINUATION line (no level token at all — must not be classified).
const REAL_CONTINUATION: &str =
    "  x assertion failed with error message: deposit intent nonce has already been used";

/// The ntx-builder EXECUTING a network transaction (the row-K node-side liveness marker).
const REAL_NTX_EXECUTING: &str = "2026-07-10T08:05:21.015932Z  INFO ntx.actor.execute_transactions: executing network transaction account_id=0x76b88125847236d145d190271cc986 note_ids=[NoteId(Word([12278310600132405841, 16545785898812]))]";

// ════════════════════════════════════════════════════════════════════════════════════════════
// ANSI / level-token / panic-line units
// ════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn strip_ansi_removes_sgr_sequences() {
    let stripped = strip_ansi(REAL_SUBMIT_REJECT);
    assert!(
        !stripped.contains('\u{1b}'),
        "no escape bytes may survive: {stripped}"
    );
    assert!(
        stripped.contains("ERROR") && stripped.contains("submit_proven_tx"),
        "the content must survive stripping: {stripped}"
    );
}

#[test]
fn strip_ansi_is_identity_on_plain_text() {
    let plain = "2026-07-10T08:00:19Z  INFO block committed block_num=7";
    assert_eq!(strip_ansi(plain), plain);
}

#[test]
fn line_level_finds_error_token_through_ansi() {
    assert_eq!(line_level(REAL_SUBMIT_REJECT), Some("ERROR"));
    assert_eq!(line_level(REAL_NTX_ALL_FAILED), Some("ERROR"));
    assert_eq!(line_level(REAL_SHUTDOWN), Some("ERROR"));
}

#[test]
fn line_level_finds_warn_token_with_leading_space_color_scope() {
    assert_eq!(line_level(REAL_WARN_DROP), Some("WARN"));
    assert_eq!(line_level(REAL_WARN_RETRY), Some("WARN"));
}

#[test]
fn line_level_is_token_equality_not_substring() {
    // INFO lines mentioning failures/errors must NOT classify (level token is INFO).
    assert_eq!(line_level(REAL_INFO_NOTE_FAILED), None);
    // `err=ERROR_LIKE` is a different token — not an ERROR level token.
    assert_eq!(
        line_level("2026-07-10T08:00:00Z  INFO worker: retry err=ERROR_LIKE code=5"),
        None
    );
    // Continuation lines of a multi-line entry carry no level token.
    assert_eq!(line_level(REAL_CONTINUATION), None);
}

#[test]
fn is_panic_line_detects_thread_panics() {
    assert!(is_panic_line("thread 'main' panicked at src/lib.rs:10:5:"));
    assert!(!is_panic_line(REAL_INFO_NOTE_FAILED));
    assert!(!is_panic_line(REAL_SUBMIT_REJECT));
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Row-L classification (scan_log_text)
// ════════════════════════════════════════════════════════════════════════════════════════════

fn scan_one(service: &str, text: &str) -> RowLObservations {
    let mut l = RowLObservations::default();
    scan_log_text(service, text, EXPECTED_LOG_LINES, &mut l);
    l
}

#[test]
fn clean_info_lines_flag_nothing() {
    let l = scan_one(
        "sequencer",
        "2026-07-10T08:00:00Z  INFO started\n2026-07-10T08:00:03Z  INFO block committed block_num=1\n",
    );
    assert!(l.unexpected_errors.is_empty());
    assert!(l.panics.is_empty());
    assert!(l.expected_errors.is_empty());
    assert!(l.triaged_warnings.is_empty());
    assert!(l.untriaged_warnings.is_empty());
}

#[test]
fn unexpected_error_is_flagged_with_service_attribution() {
    let l = scan_one(
        "validator",
        "2026-07-10T08:00:00Z ERROR storage corruption detected sector=9\n",
    );
    assert_eq!(
        l.unexpected_errors.len(),
        1,
        "the novel ERROR must be flagged"
    );
    assert_eq!(l.unexpected_errors[0].service, "validator");
    assert!(l.unexpected_errors[0].line.contains("storage corruption"));
    assert!(l.expected_errors.is_empty());
}

#[test]
fn expected_error_is_triaged_not_flagged() {
    let l = scan_one("sequencer", &format!("{REAL_SUBMIT_REJECT}\n"));
    assert!(
        l.unexpected_errors.is_empty(),
        "the deliberate Row-H rejection is EXPECTED"
    );
    assert_eq!(l.expected_errors.len(), 1);
    let t = &l.expected_errors[0];
    assert_eq!(t.service, "sequencer");
    assert!(t
        .line
        .contains("Network transactions may not be submitted by users yet"));
    assert!(
        !t.pattern.is_empty(),
        "the matched pattern must be recorded"
    );
    assert!(
        !t.explanation.is_empty(),
        "the triage explanation must be recorded"
    );
}

#[test]
fn panic_line_is_flagged_even_without_error_token() {
    let l = scan_one("ntx-builder", "thread 'tokio-runtime-worker' panicked at src/actor.rs:1:1:\nnote: run with RUST_BACKTRACE=1\n");
    assert_eq!(
        l.panics.len(),
        1,
        "a panic line must be flagged regardless of level tokens"
    );
    assert!(l.panics[0].line.contains("panicked"));
}

#[test]
fn warn_matching_pattern_is_triaged() {
    let l = scan_one("ntx-builder", &format!("{REAL_WARN_RETRY}\n"));
    assert!(l.untriaged_warnings.is_empty());
    assert_eq!(l.triaged_warnings.len(), 1);
    assert!(!l.triaged_warnings[0].explanation.is_empty());
}

#[test]
fn warn_without_pattern_is_untriaged() {
    let l = scan_one(
        "sequencer",
        "2026-07-10T08:00:00Z  WARN mempool depth unusually high depth=9000\n",
    );
    assert_eq!(
        l.untriaged_warnings.len(),
        1,
        "a novel WARN must surface for triage"
    );
    assert!(l.triaged_warnings.is_empty());
}

#[test]
fn error_scoped_pattern_must_not_triage_a_warn_line() {
    // A WARN line carrying an ERROR-scoped pattern substring stays UNTRIAGED: patterns are
    // level-scoped so an over-broad match cannot silently absorb novel warnings (and vice versa).
    let line = "2026-07-10T08:00:00Z  WARN retry: network transaction failed will-retry=true";
    let l = scan_one("ntx-builder", &format!("{line}\n"));
    assert_eq!(
        l.untriaged_warnings.len(),
        1,
        "the ERROR-scoped pattern must not triage a WARN-level line"
    );
    assert!(l.triaged_warnings.is_empty());
}

#[test]
fn expected_patterns_cover_the_complete_real_archived_vocabulary() {
    // The COMPLETE ERROR/WARN vocabulary observed across every archived LNV-1..4 run must be
    // triaged by the shipped pattern table — zero unexpected, zero untriaged — while plain
    // INFO/continuation lines classify as nothing.
    let text = [
        REAL_SUBMIT_REJECT,
        REAL_NTX_ALL_FAILED,
        REAL_NTX_TX_FAILED,
        REAL_SHUTDOWN,
        REAL_WARN_RETRY,
        REAL_WARN_DROP,
        REAL_INFO_NOTE_FAILED,
        REAL_CONTINUATION,
        REAL_NTX_EXECUTING,
    ]
    .join("\n");
    let l = scan_one("mixed", &text);
    assert!(
        l.unexpected_errors.is_empty(),
        "unexpected: {:?}",
        l.unexpected_errors
    );
    assert!(
        l.untriaged_warnings.is_empty(),
        "untriaged: {:?}",
        l.untriaged_warnings
    );
    assert!(l.panics.is_empty());
    assert_eq!(
        l.expected_errors.len(),
        4,
        "the four real ERROR shapes triage"
    );
    assert_eq!(
        l.triaged_warnings.len(),
        2,
        "the two real WARN shapes triage"
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Row-L directory scan (scan_logs) + assert_l
// ════════════════════════════════════════════════════════════════════════════════════════════

/// A fresh, auto-cleaned fixture dir under the cargo integration-test tmpdir.
///
/// Uses `tempfile` — a RANDOM, collision-resistant name plus RAII removal on drop — rather than a
/// fixed or PID-derived name: `CARGO_TARGET_TMPDIR` can be a SHARED `target/tmp` written by more
/// than one OS user (the anneal builder and auditor run this suite as different users), and any
/// predictable, persistent name left whoever ran second unable to clear or write into the other
/// user's dir (`remove_dir_all` → EPERM). A random name never collides across users, PID reuse, or
/// concurrent runs; the dir is removed when the returned handle drops. Callers keep the handle in
/// scope for the test body and read the path via `.path()`.
fn fixture_dir(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(&format!("rows-kl-{prefix}-"))
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("creating a unique fixture dir")
}

/// Writes a green four-service log dir (each required log non-empty and clean, plus a bootstrap
/// log that must also be scanned).
fn write_green_logs(dir: &Path) {
    for service in REQUIRED_SERVICE_LOGS {
        fs::write(
            dir.join(format!("{service}.log")),
            "2026-07-10T08:00:00Z  INFO service started\n2026-07-10T08:00:03Z  INFO healthy\n",
        )
        .expect("writing a fixture log");
    }
    fs::write(
        dir.join("bootstrap-validator.log"),
        "genesis block generated\n",
    )
    .expect("writing the bootstrap fixture log");
}

#[test]
fn scan_logs_builds_manifest_and_classifications() -> Result<()> {
    let dir = fixture_dir("manifest");
    write_green_logs(dir.path());
    // One real ANSI ERROR (expected) + one embedded-word INFO (not an error) in the sequencer log.
    fs::write(
        dir.path().join("sequencer.log"),
        format!("2026-07-10T08:00:00Z  INFO started\n{REAL_SUBMIT_REJECT}\n2026-07-10T08:00:02Z  INFO retry err=ERROR_LIKE\n"),
    )?;
    let l = scan_logs(dir.path(), EXPECTED_LOG_LINES)?;

    // Manifest: all *.log files scanned (4 required + 1 bootstrap), with line counts + bytes.
    assert!(
        l.scanned.len() >= 5,
        "all *.log files must be scanned: {:?}",
        l.scanned
    );
    let seq = l
        .scanned
        .iter()
        .find(|s| s.service == "sequencer")
        .expect("the sequencer log is in the manifest");
    assert_eq!(seq.lines, 3);
    assert!(seq.bytes > 0);
    assert_eq!(
        seq.error_lines, 1,
        "level-token counting: exactly the one real ERROR line"
    );
    assert_eq!(seq.warn_lines, 0);
    assert!(seq.path.ends_with("sequencer.log"));

    // Classification: the ANSI ERROR triaged as expected; nothing unexpected.
    assert_eq!(l.expected_errors.len(), 1);
    assert!(l.unexpected_errors.is_empty());
    assert!(
        assert_l(&l).is_ok(),
        "the green fixture dir must pass row L"
    );
    Ok(())
}

#[test]
fn scan_logs_errors_on_a_missing_dir() {
    let dir = fixture_dir("missing-dir");
    let missing = dir.path().join("does-not-exist");
    assert!(scan_logs(&missing, EXPECTED_LOG_LINES).is_err());
}

#[test]
fn assert_l_fails_on_a_missing_required_service_log() -> Result<()> {
    let dir = fixture_dir("missing-sequencer");
    write_green_logs(dir.path());
    fs::remove_file(dir.path().join("sequencer.log"))?;
    let l = scan_logs(dir.path(), EXPECTED_LOG_LINES)?;
    let err = assert_l(&l).expect_err("row L must fail when a required service log is missing");
    assert!(
        format!("{err:#}").contains("sequencer"),
        "must name the missing log: {err:#}"
    );
    Ok(())
}

#[test]
fn assert_l_fails_on_an_empty_required_service_log() -> Result<()> {
    let dir = fixture_dir("empty-txprover");
    write_green_logs(dir.path());
    fs::write(dir.path().join("tx-prover.log"), "")?;
    let l = scan_logs(dir.path(), EXPECTED_LOG_LINES)?;
    let err = assert_l(&l).expect_err("row L must fail when a required service log is empty");
    assert!(
        format!("{err:#}").contains("tx-prover"),
        "must name the empty log: {err:#}"
    );
    Ok(())
}

/// A green synthetic row-L observation (all four services scanned, one triaged error + warning).
fn green_l() -> RowLObservations {
    RowLObservations {
        scanned: REQUIRED_SERVICE_LOGS
            .iter()
            .map(|s| ScannedLog {
                service: (*s).to_string(),
                path: format!("logs/{s}.log"),
                bytes: 128,
                lines: 10,
                error_lines: 0,
                warn_lines: 0,
            })
            .collect(),
        unexpected_errors: vec![],
        panics: vec![],
        expected_errors: vec![TriagedLine {
            service: "sequencer".to_string(),
            line: "ERROR ... Network transactions may not be submitted by users yet".to_string(),
            pattern: "Network transactions may not be submitted by users yet".to_string(),
            explanation: "the deliberate Row-H RIV submission".to_string(),
        }],
        triaged_warnings: vec![TriagedLine {
            service: "ntx-builder".to_string(),
            line: "WARN RPC connection failed while opening block subscription, retrying"
                .to_string(),
            pattern: "RPC connection failed while opening block subscription, retrying".to_string(),
            explanation: "startup ordering: retries until the sequencer listens".to_string(),
        }],
        untriaged_warnings: vec![],
    }
}

#[test]
fn assert_l_accepts_the_green_shape() {
    assert!(assert_l(&green_l()).is_ok());
}

#[test]
fn assert_l_rejects_unexpected_errors() {
    let mut l = green_l();
    l.unexpected_errors.push(FlaggedLine {
        service: "validator".to_string(),
        line: "ERROR storage corruption".to_string(),
    });
    let err = assert_l(&l).expect_err("an unexpected ERROR line must fail row L");
    assert!(
        format!("{err:#}").contains("storage corruption"),
        "must quote the line: {err:#}"
    );
}

#[test]
fn assert_l_rejects_panics() {
    let mut l = green_l();
    l.panics.push(FlaggedLine {
        service: "ntx-builder".to_string(),
        line: "thread 'main' panicked at actor.rs".to_string(),
    });
    assert!(assert_l(&l).is_err(), "a panic line must fail row L");
}

#[test]
fn assert_l_rejects_untriaged_warnings() {
    let mut l = green_l();
    l.untriaged_warnings.push(FlaggedLine {
        service: "sequencer".to_string(),
        line: "WARN mempool depth unusually high".to_string(),
    });
    assert!(assert_l(&l).is_err(), "an untriaged WARN must fail row L");
}

#[test]
fn assert_l_rejects_an_empty_triage_explanation() {
    let mut l = green_l();
    l.expected_errors[0].explanation = String::new();
    assert!(
        assert_l(&l).is_err(),
        "a triaged line without an explanation is not triaged"
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Row-K evidence extraction + derivation + assert_k
// ════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn ntx_execution_evidence_extracts_marker_lines_ansi_stripped() {
    let ansi_marker = format!(
        "\u{1b}[2m2026-07-10T08:07:09Z\u{1b}[0m  INFO ntx.actor.execute_transactions: {NTX_EXECUTION_MARKER} account_id=0xabc"
    );
    let text = format!(
        "{REAL_NTX_EXECUTING}\n2026-07-10T08:05:22Z  INFO block committed\n{ansi_marker}\n"
    );
    let evidence = ntx_execution_evidence(&text);
    assert_eq!(
        evidence.len(),
        2,
        "exactly the two marker lines: {evidence:?}"
    );
    for line in &evidence {
        assert!(line.contains(NTX_EXECUTION_MARKER));
        assert!(
            !line.contains('\u{1b}'),
            "evidence lines must be ANSI-stripped"
        );
    }
}

fn mint_commit() -> PathNCommit {
    PathNCommit {
        op: "mint empty-hookData".to_string(),
        kind: "mint".to_string(),
        commit_block: Some(7),
        effect: "token_supply 0 → 100".to_string(),
    }
}

fn burn_commit() -> PathNCommit {
    PathNCommit {
        op: "burn two-block".to_string(),
        kind: "burn".to_string(),
        commit_block: Some(22),
        effect: "token_supply 100 → 0".to_string(),
    }
}

fn admin_commit() -> PathNCommit {
    PathNCommit {
        op: "set_attester(A, enabled=1)".to_string(),
        kind: "admin".to_string(),
        commit_block: None,
        effect: "attester A allowlist marker [1,0,0,0]".to_string(),
    }
}

fn ntx_evidence() -> Vec<String> {
    vec![strip_ansi(REAL_NTX_EXECUTING)]
}

#[test]
fn derive_row_k_yes_with_full_evidence() {
    let k = derive_row_k(
        vec![mint_commit(), burn_commit(), admin_commit()],
        ntx_evidence(),
    );
    assert!(
        k.auto_executes,
        "mint + burn commits + node-side markers = the ntx-builder is LIVE"
    );
    assert!(k.no_cause.is_none());
    assert!(!k.posture.is_empty());
    assert!(
        assert_k(&k).is_ok(),
        "the complete YES verdict must pass row K"
    );
}

#[test]
fn derive_row_k_clean_no_records_cause_and_client_side_posture() {
    let k = derive_row_k(vec![], vec![]);
    assert!(!k.auto_executes);
    let cause = k
        .no_cause
        .clone()
        .expect("a NO verdict must carry the exact cause");
    assert!(
        cause.contains("no path-N mint commit"),
        "the cause must name the missing mint: {cause}"
    );
    assert!(
        cause.contains("no path-N burn commit"),
        "the cause must name the missing burn: {cause}"
    );
    assert!(
        k.posture.contains("client-side (path C)"),
        "the spec's deployment-posture statement must be recorded: {}",
        k.posture
    );
    assert!(
        assert_k(&k).is_ok(),
        "a RECORDED clean NO passes row K (liveness is not a gate blocker)"
    );
}

#[test]
fn derive_row_k_partial_liveness_fails_assert_k() {
    // Mint executed but no burn commit observed: neither a YES nor a clean NO — row K must
    // SURFACE the inconsistency rather than silently downgrade to a posture statement.
    let k = derive_row_k(vec![mint_commit()], ntx_evidence());
    assert!(!k.auto_executes, "partial evidence cannot claim liveness");
    assert!(
        assert_k(&k).is_err(),
        "partial path-N evidence (mint without burn) must fail row K loudly"
    );
}

#[test]
fn assert_k_rejects_yes_without_burn_commit() {
    let k = RowKObservations {
        auto_executes: true,
        commits: vec![mint_commit(), admin_commit()],
        ntx_log_evidence: ntx_evidence(),
        no_cause: None,
        posture: "path N live".to_string(),
    };
    assert!(
        assert_k(&k).is_err(),
        "YES without burn evidence is incomplete (spec: mint AND burn)"
    );
}

#[test]
fn assert_k_rejects_yes_without_mint_commit() {
    let k = RowKObservations {
        auto_executes: true,
        commits: vec![burn_commit(), admin_commit()],
        ntx_log_evidence: ntx_evidence(),
        no_cause: None,
        posture: "path N live".to_string(),
    };
    assert!(
        assert_k(&k).is_err(),
        "YES without mint evidence is incomplete"
    );
}

#[test]
fn assert_k_rejects_yes_without_node_side_log_evidence() {
    let k = RowKObservations {
        auto_executes: true,
        commits: vec![mint_commit(), burn_commit()],
        ntx_log_evidence: vec![],
        no_cause: None,
        posture: "path N live".to_string(),
    };
    assert!(
        assert_k(&k).is_err(),
        "YES needs ntx-builder log markers, not client inference alone"
    );
}

#[test]
fn assert_k_rejects_no_without_cause() {
    let k = RowKObservations {
        auto_executes: false,
        commits: vec![],
        ntx_log_evidence: vec![],
        no_cause: None,
        posture: "relayer executes client-side (path C)".to_string(),
    };
    assert!(
        assert_k(&k).is_err(),
        "a NO verdict without the exact cause is not evidence"
    );
}

#[test]
fn assert_k_rejects_no_that_contradicts_observed_commits() {
    let k = RowKObservations {
        auto_executes: false,
        commits: vec![mint_commit(), burn_commit()],
        ntx_log_evidence: ntx_evidence(),
        no_cause: Some("claimed dead".to_string()),
        posture: "relayer executes client-side (path C)".to_string(),
    };
    assert!(
        assert_k(&k).is_err(),
        "a NO verdict with observed mint/burn commits is inconsistent"
    );
}

#[test]
fn assert_k_rejects_an_empty_posture() {
    let k = RowKObservations {
        auto_executes: true,
        commits: vec![mint_commit(), burn_commit()],
        ntx_log_evidence: ntx_evidence(),
        no_cause: None,
        posture: String::new(),
    };
    assert!(
        assert_k(&k).is_err(),
        "the deployment-posture statement must be recorded either way"
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Green synthetic sub-run observations (the LNV-2/3/4 green shapes, reused as extraction input)
// ════════════════════════════════════════════════════════════════════════════════════════════

fn rej(msg: &str) -> Verdict {
    Verdict::Rejected(msg.to_string())
}

fn green_cf() -> RowsCfObservations {
    RowsCfObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic-cf".to_string(),
        c1: C1SetAttester {
            a_marker_after_enable: MARKER_SET,
            a_marker_after_rotate: MARKER_CLEAR,
            b_marker_after_rotate: MARKER_SET,
            mint_by_a: rej("... deposit attester pubkey commitment is not allowlisted ..."),
            mint_by_b: Verdict::Accepted,
        },
        c2: C2MinBurn {
            raised_min: 50,
            committed_after_raise: 50,
            burn_below_raised: rej("... burn amount is below the minimum burn size ..."),
            lowered_min: 10,
            committed_after_lower: 10,
            burn_at_lowered: Verdict::Accepted,
        },
        c3: C3MaxSupply {
            committed_cap: 500,
            max_supply_readback: 500,
            over_cap_mint: rej("... mint amount exceeds the faucet supply cap ..."),
            within_cap_mint: Verdict::Accepted,
        },
        c4: C4Pause {
            is_paused_after_pause: MARKER_SET,
            mint_while_paused: rej("... the contract is paused ..."),
            burn_while_paused: rej("... the contract is paused ..."),
            owner_set_attester_while_paused_marker: MARKER_SET,
            owner_set_min_burn_while_paused: 7,
            is_paused_after_unpause: MARKER_CLEAR,
            mint_after_unpause: Verdict::Accepted,
        },
        c5: C5RoleRotation {
            new_pauser_membership_after_grant: MARKER_SET,
            is_paused_after_new_pauser_pause: MARKER_SET,
            new_pauser_membership_after_revoke: MARKER_CLEAR,
            revoked_pauser_pause: rej("... note sender does not hold the required role ..."),
        },
        c6: vec![
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
        ],
        f: RowF {
            non_allowlisted_note: rej(
                "... input note script root is not in the note script allowlist ...",
            ),
            tx_script: rej("... transaction script root is not in the tx script allowlist ..."),
        },
    }
}

const SERIAL_1: [u64; 4] = [11, 22, 33, 44];
const SERIAL_2: [u64; 4] = [55, 66, 77, 88];
const TAG_1: u32 = 0xfffc_0000;
const TAG_2: u32 = 0xa5a4_0000;

fn green_de() -> RowsDeObservations {
    let committed_supply = 250;
    let neg = |label: &str, expected: &str, msg: &str, expects_nonce_set: bool| MintNegative {
        label: label.to_string(),
        expected_error: expected.to_string(),
        verdict: rej(msg),
        supply_before: committed_supply,
        supply_after: committed_supply,
        nonce_marker_after: if expects_nonce_set {
            MARKER_SET
        } else {
            MARKER_CLEAR
        },
        expects_nonce_set,
    };
    RowsDeObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic-de".to_string(),
        recipient_id: "0xrecipient".to_string(),
        d: vec![
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
            },
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
            },
        ],
        e: vec![
            neg(
                "replayed-nonce",
                ERR_XRESERVE_NONCE_REPLAY,
                "... deposit intent nonce has already been used ...",
                true,
            ),
            neg(
                "forged-signature",
                ERR_XRESERVE_SIG_INVALID,
                "... deposit attestation signature verification failed ...",
                false,
            ),
            neg(
                "non-allowlisted-attester",
                ERR_XRESERVE_BAD_PK_COMMITMENT,
                "... deposit attester pubkey commitment is not allowlisted ...",
                false,
            ),
            neg(
                "nonzero-fee",
                ERR_XRESERVE_FEE_NONZERO,
                "... mint fee amount must be zero ...",
                false,
            ),
            neg(
                "tampered-payload",
                ERR_XRESERVE_SIG_INVALID,
                "... deposit attestation signature verification failed ...",
                false,
            ),
        ],
    }
}

fn green_gj() -> RowsGjObservations {
    RowsGjObservations {
        main_commit: "synthetic".to_string(),
        faucet_id: "0xsynthetic-gj".to_string(),
        holder_id: "0xholder".to_string(),
        g: BurnTwoBlock {
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
        },
        h: BurnSameBlock {
            label: "same-block-erasure".to_string(),
            amount_units: 100,
            mechanism: "unauthenticated consume of the production XReserveBurnNote; user-RPC \
                        submission rejected (committed same-block unreachable); note never commits"
                .to_string(),
            note_tag: FIXED_XUSDC_BURN_TAG,
            note_id: "0xsameblocknote".to_string(),
            consume_accepted: true,
            executed_supply_delta: Some(100),
            submit_via_user_rpc_rejected: true,
            submit_rejection_error:
                "RpcError(... Network transactions may not be submitted by users yet ...)"
                    .to_string(),
            onchain_supply_before: 100,
            onchain_supply_after: 100,
            committed_note_found: false,
            nullifier_recorded: false,
            discovered_by_syncnotes: false,
            raw_getnotesbyid_response: "GetNotesById([0xsameblocknote]) -> [] (not found)"
                .to_string(),
        },
        i: vec![
            BurnNegative {
                label: "below-min".to_string(),
                expected_error: ERR_BURN_BELOW_MIN.to_string(),
                verdict: rej("... burn amount is below the minimum burn size ..."),
                supply_before: 100,
                supply_after: 100,
            },
            // v16 kernel moved burn origin-validation from fungible_asset::validate_origin (v15
            // faucet.masm:61) to asset::validate_origin (v16 faucet.masm:72); the v15-era
            // expectation was stale. Unrelated to the blocklist/callback change; the stock burn
            // flow fires no asset callbacks.
            BurnNegative {
                label: "wrong-asset".to_string(),
                expected_error: ERR_WRONG_ASSET_ORIGIN.to_string(),
                verdict: rej("... the faucet is not the origin of the asset ..."),
                supply_before: 100,
                supply_after: 100,
            },
            BurnNegative {
                label: "while-paused".to_string(),
                expected_error: ERR_PAUSED.to_string(),
                verdict: rej("... the contract is paused ..."),
                supply_before: 100,
                supply_after: 100,
            },
        ],
        j: ConservationLedger {
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
        },
    }
}

#[test]
fn pathn_commits_extract_mint_burn_and_admin_evidence() {
    let commits = pathn_commits_from(&green_cf(), &green_de(), &green_gj());

    let mints: Vec<_> = commits.iter().filter(|c| c.kind == "mint").collect();
    let burns: Vec<_> = commits.iter().filter(|c| c.kind == "burn").collect();
    let admins: Vec<_> = commits.iter().filter(|c| c.kind == "admin").collect();

    assert_eq!(
        mints.len(),
        2,
        "both Row-D happy-path mints are path-N commits"
    );
    assert_eq!(
        mints[0].commit_block,
        Some(7),
        "mint #1 commit block = its note inclusion block"
    );
    assert_eq!(mints[1].commit_block, Some(11));
    assert!(
        mints[0].effect.contains('0') && mints[0].effect.contains("100"),
        "the supply movement is the effect: {}",
        mints[0].effect
    );

    assert_eq!(
        burns.len(),
        1,
        "the Row-G two-block burn is a path-N commit"
    );
    assert_eq!(
        burns[0].commit_block,
        Some(22),
        "burn commit block = the consume block"
    );

    assert!(
        admins.len() >= 10,
        "the rows-C admin arc commits via path N: {admins:?}"
    );
    let ops: Vec<&str> = admins.iter().map(|c| c.op.as_str()).collect();
    assert!(
        ops.iter().any(|o| o.contains("set_attester")),
        "ops: {ops:?}"
    );
    assert!(
        ops.iter().any(|o| o.contains("set_min_burn_size")),
        "ops: {ops:?}"
    );
    assert!(
        ops.iter().any(|o| o.contains("set_max_supply")),
        "ops: {ops:?}"
    );
    assert!(ops.iter().any(|o| o.contains("pause")), "ops: {ops:?}");

    for c in &commits {
        assert!(
            !c.op.is_empty() && !c.effect.is_empty(),
            "every commit carries op + effect"
        );
        assert!(
            matches!(c.kind.as_str(), "mint" | "burn" | "admin"),
            "kind: {}",
            c.kind
        );
    }
}

#[test]
fn pathn_commits_feed_a_passing_row_k() {
    let commits = pathn_commits_from(&green_cf(), &green_de(), &green_gj());
    let k = derive_row_k(commits, ntx_evidence());
    assert!(k.auto_executes);
    assert!(assert_k(&k).is_ok());
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// The full-matrix outcome map (the single verdict table the binary + E2E both use)
// ════════════════════════════════════════════════════════════════════════════════════════════

const MAX_SUPPLY: u64 = 1_000_000_000_000;

fn wallet_id(seed: u8) -> AccountId {
    // v16: `AccountId::dummy` gained an `AssetCallbackFlag` param (#3167 / MIGRATION-V16-ALPHA2.md
    // S6). These synthetic wallets register no transfer policy, so the flag is `Disabled`.
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// A production-shaped deployed faucet `Account` with the domain-config slots pre-seeded (the
/// tests/rows_ab.rs synthetic fixture, reused).
fn synthetic_deployed_faucet(domain: &DomainParams) -> Result<Account> {
    let xreserve = build_xreserve_component_seeded(Some(domain))?;
    let components = production_components(
        xreserve,
        wallet_id(1),
        wallet_id(2),
        wallet_id(3),
        wallet_id(4),
        MAX_SUPPLY,
    )?;
    let auth = XReserveStablecoinBuilder::auth_component()?;
    let account = AccountBuilder::new([7u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_auth_component(auth)
        .with_components(components)
        .build_existing()?;
    Ok(account)
}

fn green_ab() -> Result<RowsAbObservations> {
    let params = DomainParams::lnv1();
    let deployed = synthetic_deployed_faucet(&params)?;
    let after_reinit = synthetic_deployed_faucet(&params)?;
    let faucet_id = deployed.id();
    Ok(RowsAbObservations {
        main_commit: "synthetic".to_string(),
        faucet_id,
        deployed: Some(deployed),
        deploy_tx_id: "0xdeploytx".to_string(),
        deploy_block: 4,
        owner_id: wallet_id(1),
        domain_params: params,
        reinit_params: DomainParams::lnv1_reinit_attempt(),
        first_note_id: "0xnote1".to_string(),
        second_note_id: "0xnote2".to_string(),
        reinit_error: Some(format!("executor trap: {ERR_DOMAIN_REINIT_TEXT}")),
        after_reinit: Some(after_reinit),
        second_note_consumed: false,
    })
}

fn green_matrix() -> Result<FullMatrixObservations> {
    let commits = pathn_commits_from(&green_cf(), &green_de(), &green_gj());
    Ok(FullMatrixObservations {
        ab: green_ab()?,
        cf: green_cf(),
        de: green_de(),
        gj: green_gj(),
        k: derive_row_k(commits, ntx_evidence()),
        l: green_l(),
    })
}

#[test]
fn full_matrix_outcomes_green_produces_twelve_ordered_passes() -> Result<()> {
    let outcomes = full_matrix_outcomes(&green_matrix()?);
    assert_eq!(outcomes.len(), 12);
    let ids: Vec<&str> = outcomes.iter().map(|o| o.row.as_str()).collect();
    assert_eq!(ids, MATRIX_ROW_IDS.to_vec(), "rows A..L in matrix order");
    for o in &outcomes {
        assert!(
            o.pass,
            "row {} must pass on the green shape: {:?}",
            o.row, o.detail
        );
        assert!(!o.title.is_empty(), "every row carries its matrix title");
        assert!(
            o.detail.is_none(),
            "a passing row carries no failure detail"
        );
    }
    assert!(validate_row_outcomes(&outcomes).is_ok());
    assert!(!any_failed(&outcomes));
    Ok(())
}

#[test]
fn full_matrix_outcomes_maps_a_row_e_defect_to_row_e_only() -> Result<()> {
    let mut m = green_matrix()?;
    m.de.e.pop(); // drop one required mint negative → the row-E coverage check must fail
    let outcomes = full_matrix_outcomes(&m);
    for o in &outcomes {
        if o.row == "E" {
            assert!(
                !o.pass,
                "row E must fail when a required negative is missing"
            );
            assert!(o.detail.is_some(), "the failure detail must be recorded");
        } else {
            assert!(
                o.pass,
                "only row E may fail, but {} failed: {:?}",
                o.row, o.detail
            );
        }
    }
    assert!(any_failed(&outcomes));
    Ok(())
}

#[test]
fn full_matrix_outcomes_maps_a_row_l_defect_to_row_l_only() -> Result<()> {
    let mut m = green_matrix()?;
    m.l.unexpected_errors.push(FlaggedLine {
        service: "sequencer".to_string(),
        line: "ERROR unexplained".to_string(),
    });
    let outcomes = full_matrix_outcomes(&m);
    for o in &outcomes {
        if o.row == "L" {
            assert!(!o.pass, "row L must fail on an unexpected error line");
        } else {
            assert!(
                o.pass,
                "only row L may fail, but {} failed: {:?}",
                o.row, o.detail
            );
        }
    }
    Ok(())
}

fn synthetic_outcomes() -> Vec<RowOutcome> {
    MATRIX_ROW_IDS
        .iter()
        .map(|id| RowOutcome {
            row: (*id).to_string(),
            title: format!("row {id} title"),
            pass: true,
            detail: None,
        })
        .collect()
}

#[test]
fn validate_row_outcomes_rejects_a_missing_row() {
    let mut outcomes = synthetic_outcomes();
    outcomes.pop(); // drop L
    let err = validate_row_outcomes(&outcomes).expect_err("11 rows is not the matrix");
    assert!(
        format!("{err:#}").contains('L') || format!("{err:#}").contains("12"),
        "{err:#}"
    );
}

#[test]
fn validate_row_outcomes_rejects_a_duplicate_row() {
    let mut outcomes = synthetic_outcomes();
    outcomes[3].row = "C".to_string(); // D → C: duplicates C, drops D
    assert!(validate_row_outcomes(&outcomes).is_err());
}

#[test]
fn validate_row_outcomes_rejects_disorder() {
    let mut outcomes = synthetic_outcomes();
    outcomes.swap(3, 4); // D and E out of matrix order
    assert!(validate_row_outcomes(&outcomes).is_err());
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// The VALIDATION RECORD + evidence packets (renderers)
// ════════════════════════════════════════════════════════════════════════════════════════════

fn record_ctx() -> RecordContext {
    RecordContext {
        main_commit: "29dbcc4synthetic".to_string(),
        run_root: "local-node-data/lnv5/run-777".to_string(),
        ab_faucet_id: "0xfaucet-ab".to_string(),
        ab_deploy_tx_id: "0xdeploytx".to_string(),
        ab_deploy_block: 4,
        cf_faucet_id: "0xsynthetic-cf".to_string(),
        de_faucet_id: "0xsynthetic-de".to_string(),
        de_recipient_id: "0xrecipient".to_string(),
        gj_faucet_id: "0xsynthetic-gj".to_string(),
        gj_holder_id: "0xholder".to_string(),
    }
}

fn render_green_record() -> Result<String> {
    let m = green_matrix()?;
    Ok(render_validation_record(
        &record_ctx(),
        &full_matrix_outcomes(&m),
        &m.cf,
        &m.de,
        &m.gj,
        &m.k,
        &m.l,
    ))
}

#[test]
fn record_lists_every_matrix_row_with_its_verdict() -> Result<()> {
    let record = render_green_record()?;
    for id in MATRIX_ROW_IDS {
        assert!(
            record.contains(&format!("| {id} |")),
            "the record must carry a row line for {id}"
        );
    }
    assert!(record.contains("PASS"));
    Ok(())
}

#[test]
fn record_never_self_declares_the_gate() -> Result<()> {
    // THE acceptance-gate invariant: the per-row results are machine verdicts; the GATE verdict is a HUMAN
    // decision. Even an all-green record must say PENDING HUMAN ACCEPTANCE and never GATE PASSED.
    let record = render_green_record()?;
    let upper = record.to_uppercase();
    assert!(
        upper.contains("PENDING HUMAN ACCEPTANCE"),
        "the all-green record must defer the gate to the human"
    );
    assert!(
        !upper.contains("GATE PASSED"),
        "the record must never self-declare the gate"
    );
    assert!(
        !upper.contains("GATE PASS "),
        "the record must never self-declare the gate"
    );
    assert!(
        record.contains("§11.2"),
        "the record names the charter gate it feeds"
    );
    Ok(())
}

#[test]
fn record_quotes_ids_blocks_and_the_one_command() -> Result<()> {
    let record = render_green_record()?;
    let ctx = record_ctx();
    for needle in [
        ctx.main_commit.as_str(),
        ctx.run_root.as_str(),
        ctx.ab_faucet_id.as_str(),
        ctx.ab_deploy_tx_id.as_str(),
        ctx.gj_faucet_id.as_str(),
        "0xburnnote",
        "lnv5_full_matrix",
    ] {
        assert!(record.contains(needle), "the record must quote {needle}");
    }
    assert!(record.contains(&ctx.ab_deploy_block.to_string()));
    Ok(())
}

#[test]
fn record_with_a_failed_row_cannot_pass_and_quotes_the_detail() -> Result<()> {
    let m = green_matrix()?;
    let mut outcomes = full_matrix_outcomes(&m);
    outcomes[4].pass = false; // row E
    outcomes[4].detail = Some("synthetic-detail: negative coverage missing".to_string());
    let record =
        render_validation_record(&record_ctx(), &outcomes, &m.cf, &m.de, &m.gj, &m.k, &m.l);
    let upper = record.to_uppercase();
    assert!(
        upper.contains("GATE CANNOT PASS"),
        "a failed row blocks the gate loudly"
    );
    assert!(
        !upper.contains("PENDING HUMAN ACCEPTANCE"),
        "a failed record is not pending acceptance"
    );
    assert!(
        record.contains("synthetic-detail"),
        "the failure detail is quoted verbatim"
    );
    assert!(record.contains("FAIL"));
    Ok(())
}

#[test]
fn record_carries_the_row_l_triage_table() -> Result<()> {
    let record = render_green_record()?;
    let l = green_l();
    assert!(
        record.contains(&l.expected_errors[0].pattern),
        "the triage table quotes the expected-error pattern"
    );
    assert!(
        record.contains(&l.triaged_warnings[0].explanation),
        "the triage table quotes the warning explanation"
    );
    Ok(())
}

#[test]
fn f7_packet_is_evidence_only_and_complete() {
    let gj = green_gj();
    let packet = render_f7_packet(&gj, "29dbcc4synthetic");
    assert!(packet.contains("DEV-7"), "the packet is the DEV-7 input");
    assert!(packet.contains("OPEN"), "DEV-7 stays OPEN");
    let upper = packet.to_uppercase();
    assert!(
        !upper.contains("RESOLVED"),
        "the packet must not resolve the Circle decision"
    );
    assert!(
        upper.contains("ACCEPTABILITY"),
        "the packet states it makes no acceptability decision"
    );
    // Both lifecycles, with their raw evidence.
    assert!(packet.contains(&gj.g.note_id) && packet.contains(&gj.h.note_id));
    assert!(packet.contains(&gj.h.submit_rejection_error));
    assert!(packet.contains(&gj.h.raw_getnotesbyid_response));
    assert!(packet.contains(&gj.g.consume_block.to_string()));
    assert!(packet.contains("29dbcc4synthetic"));
}

#[test]
fn ntx_verdict_doc_states_yes_with_evidence() {
    let commits = pathn_commits_from(&green_cf(), &green_de(), &green_gj());
    let k = derive_row_k(commits, ntx_evidence());
    let doc = render_ntx_verdict(&k, "29dbcc4synthetic");
    assert!(
        doc.contains("VERDICT: YES"),
        "the liveness verdict is stated plainly"
    );
    assert!(
        doc.contains(&k.posture),
        "the deployment-posture statement is quoted"
    );
    assert!(
        doc.contains("mint") && doc.contains("burn"),
        "both consumption kinds evidenced"
    );
    assert!(
        doc.contains(NTX_EXECUTION_MARKER),
        "node-side log markers are quoted"
    );
}

#[test]
fn ntx_verdict_doc_states_no_with_cause_and_posture() {
    let k = derive_row_k(vec![], vec![]);
    let doc = render_ntx_verdict(&k, "29dbcc4synthetic");
    assert!(doc.contains("VERDICT: NO"));
    assert!(
        doc.contains("client-side (path C)"),
        "the spec's posture statement is quoted"
    );
    assert!(
        doc.contains(k.no_cause.as_deref().expect("a NO verdict carries a cause")),
        "the exact cause is quoted"
    );
}

#[test]
fn getnotesbyid_capture_is_byte_exact_and_self_describing() {
    let g = green_gj().g;
    let capture = render_getnotesbyid_capture(&g);
    // Self-describing header (comment lines) with the note id, the fixed tag, and the block.
    assert!(capture.contains(&g.note_id));
    assert!(
        capture.contains("0x4255524E"),
        "the fixed burn tag rides in the header"
    );
    assert!(capture.contains(&g.getnotesbyid_inclusion_block.to_string()));
    assert!(capture.contains("LNV-5"));
    // Byte-exactness: the non-comment payload lines ARE the two hex halves, verbatim, in order.
    let payloads: Vec<&str> = capture
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(
        payloads,
        vec![
            g.getnotesbyid_note_bytes_hex.as_str(),
            g.getnotesbyid_inclusion_proof_bytes_hex.as_str()
        ],
        "exactly the note hex then the inclusion-proof hex, unmodified"
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Config plumbing for the consolidated run root
// ════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn fresh_under_roots_the_run_under_the_named_track() {
    let cfg = RunConfig::fresh_under(Path::new("/repo"), "lnv5", "run-1");
    assert_eq!(
        cfg.stack.run_root,
        Path::new("/repo/local-node-data/lnv5/run-1"),
        "LNV-5 runs live under their own gitignored track"
    );
    // The LNV-1..4 single-run constructor keeps its historical layout.
    let legacy = RunConfig::fresh(Path::new("/repo"), "run-2");
    assert_eq!(
        legacy.stack.run_root,
        Path::new("/repo/local-node-data/lnv1/run-2")
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Stack service invocations (round-2 row-L disposition: the sequencer's gRPC connection-age
// override). The LNV-5 round-1 run surfaced sequencer panics at exactly the node's 30-minute
// DEFAULT_MAX_CONNECTION_AGE (tonic-0.14.6 resumed-after-completion, LNV5-ROW-L-FINDING.md);
// the HUMAN disposition is to extend that age at the STACK-BOOT CONFIG level (the v0.15.1
// sequencer CLI exposes `--rpc.grpc.max-connection-age <DURATION>`) so no connection can reach
// it within a gate run — while the row-L panic detector stays byte-for-byte as strict.
// ════════════════════════════════════════════════════════════════════════════════════════════

use xusdc_validation::config::{StackConfig, DEFAULT_V16_NODE_DIR};
use xusdc_validation::stack::{NodeStack, V16_SERVICES};

/// The v16 stack config resolves the client-repo dir (env-overridable) and points `log_dir` at the
/// v16 node's service-log directory — NOT the run root (the node is brought up by the client repo's
/// `start-test-node.sh`, so its logs live under the client repo's `target/test-node/data/logs`).
#[test]
fn v16_stack_config_targets_the_node_repo_logs() {
    // Env may be unset in the offline gate → the default provisioned path is used.
    std::env::remove_var("MIDEN_V16_NODE_DIR");
    let cfg = StackConfig::new(PathBuf::from("/repo/local-node-data/lnv5/run-x"));
    assert_eq!(cfg.client_repo_dir, PathBuf::from(DEFAULT_V16_NODE_DIR));
    assert_eq!(
        cfg.log_dir(),
        PathBuf::from(DEFAULT_V16_NODE_DIR).join("target/test-node/data/logs"),
        "the v16 log dir must be the node repo's data-log dir, not the run root"
    );
    assert_eq!(cfg.rpc_url(), "http://127.0.0.1:57291");
}

/// `MIDEN_V16_NODE_DIR` overrides the client-repo path.
#[test]
fn v16_node_dir_env_override() {
    std::env::set_var("MIDEN_V16_NODE_DIR", "/custom/miden-node");
    let cfg = StackConfig::new(PathBuf::from("/repo/run"));
    assert_eq!(cfg.client_repo_dir, PathBuf::from("/custom/miden-node"));
    assert_eq!(
        cfg.log_dir(),
        PathBuf::from("/custom/miden-node/target/test-node/data/logs")
    );
    std::env::remove_var("MIDEN_V16_NODE_DIR");
}

/// The four v16 services are named exactly as `start-test-node.sh` writes their logs.
#[test]
fn v16_services_are_the_four_node_processes() {
    assert_eq!(V16_SERVICES.len(), 4);
    for s in ["validator", "sequencer", "ntx-builder", "prover"] {
        assert!(V16_SERVICES.contains(&s), "missing v16 service {s}");
    }
    // A stack instance is not booted here (that needs a live node); the type is exercised by the
    // `#[ignore]`d live gate below and the `lnv_stack` binary.
    let _ = NodeStack::bootstrap_and_start; // symbol presence
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// THE REAL-NODE E2E — the consolidated full-matrix acceptance-gate run (ignored in the default suite; see the
// module docs. The gate claim rides ONLY on real runs + the HUMAN gate.)
// ════════════════════════════════════════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires the pinned v0.15.1 node binaries + loopback listener binds (the §11.2 gate run); run with -- --include-ignored or the lnv5_full_matrix binary"]
async fn lnv5_full_matrix_against_real_local_node() -> Result<()> {
    use xusdc_validation::config::repo_root;
    use xusdc_validation::rows_kl::run_full_matrix;

    let label = format!(
        "test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let cfg = RunConfig::fresh_under(&repo_root(), "lnv5", &label);
    let obs = run_full_matrix(&cfg).await?;
    let outcomes = full_matrix_outcomes(&obs);
    validate_row_outcomes(&outcomes)?;
    for o in &outcomes {
        anyhow::ensure!(
            o.pass,
            "matrix row {} ({}) FAILED: {:?}",
            o.row,
            o.title,
            o.detail
        );
    }
    Ok(())
}
