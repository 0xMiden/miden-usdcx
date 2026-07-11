//! The LNV-5 rows-K/L derivations + the consolidated full-matrix driver.
//!
//! **Row K (ntx-builder liveness / path N)** is derived, not re-driven: the LNV-2/3/4 sub-runs
//! already commit every positive faucet consumption via path N (the routed allowlisted note is
//! emitted from a wallet and the running ntx-builder auto-executes the faucet's consumption — the
//! LNV-1 §3.2 posture), so the consolidated run EXTRACTS that on-chain evidence from the sub-run
//! observations ([`pathn_commits_from`]) and pairs it with the node-side execution markers from
//! `ntx-builder.log` ([`ntx_execution_evidence`]). [`derive_row_k`] renders the verdict either
//! way: YES needs mint AND burn commits plus node-side markers; anything less is NO with the
//! exact missing-evidence cause and the spec's "relayer executes client-side (path C)" posture.
//!
//! **Row L (clean logs)** scans every archived `*.log` of the run ([`scan_logs`]). "Clean" means:
//! zero ERROR-level lines and zero panic lines that match NO expected pattern, and every WARN
//! triaged + explained. The expected-pattern table ([`EXPECTED_LOG_LINES`]) enumerates the
//! COMPLETE ERROR/WARN vocabulary observed across the archived LNV-1..4 runs, each entry tied to
//! the deliberate negative or stack lifecycle step that explains it. A deliberately-doomed routed
//! note CANNOT mask a failing positive: every positive commit is guarded by its own row's bounded
//! committed-effect poll, which times out loudly if the ntx-builder fails to execute it.
//!
//! Log lines are classified by their tracing level TOKEN after ANSI-stripping (the services write
//! SGR color codes into the log files), never by substring — an `INFO` line mentioning
//! `error=…`/`failed` classifies as nothing, and multi-line entry continuations carry no token.
//!
//! [`run_full_matrix`] is the consolidated §11.2 driver: ONE fresh stack, the four LNV-1..4
//! drivers composed in matrix order against it (each namespaced under its own client store), then
//! rows K + L derived from that single run. **Validator-not-fixer:** a failing sub-run or row is
//! a SURFACED finding, never a hot-fix.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::RunConfig;
use crate::observations_cf::{RowsCfObservations, Word4};
use crate::observations_de::RowsDeObservations;
use crate::observations_gj::RowsGjObservations;
use crate::observations_kl::{
    FlaggedLine, FullMatrixObservations, PathNCommit, RowKObservations, RowLObservations,
    ScannedLog, TriagedLine,
};
use crate::rows_ab::run_rows_ab_on;
use crate::rows_cf::run_rows_cf_on;
use crate::rows_de::run_rows_de_on;
use crate::rows_gj::run_rows_gj_on;
use crate::stack::NodeStack;

// ROW-K EVIDENCE VOCABULARY
// ================================================================================================

/// The ntx-builder's node-side execution marker (the line it logs when it picks up routed notes
/// and executes the network transaction; observed verbatim in every archived LNV-2/3/4 run).
pub const NTX_EXECUTION_MARKER: &str = "executing network transaction";

/// The row-K posture statement when the ntx-builder is LIVE (path N auto-executes).
pub const POSTURE_PATH_N_LIVE: &str =
    "path N LIVE: the node's ntx-builder auto-executes routed+allowlisted consumptions against \
     the network-account faucet (mint, burn, and admin all observed committing on this run); \
     client-side execution (path C) remains open to any permissionless relayer and stays the \
     harness posture for probes/negatives";

/// The spec's deployment-posture statement for a NO verdict.
pub const POSTURE_PATH_C_ONLY: &str = "relayer executes client-side (path C)";

// ROW-L EXPECTED-PATTERN TABLE
// ================================================================================================

/// An expected (triaged) log-line pattern: `pattern` identifies the line, `level` scopes which
/// tracing level it may triage (an ERROR-scoped pattern must never absorb a WARN line, and vice
/// versa), `explanation` records WHY the line is expected.
#[derive(Debug, Clone)]
pub struct ExpectedLogLine {
    /// The tracing level this pattern triages (`"ERROR"` or `"WARN"`).
    pub level: &'static str,
    /// The identifying substring (matched against the ANSI-stripped line).
    pub pattern: &'static str,
    /// The triage: which deliberate negative / lifecycle step explains the line.
    pub explanation: &'static str,
}

/// The COMPLETE expected ERROR/WARN vocabulary of a gate run — every entry grounded in the
/// archived LNV-1..4 logs and tied to a deliberate negative or a stack lifecycle step. Any
/// ERROR/WARN line matching none of these fails row L.
pub const EXPECTED_LOG_LINES: &[ExpectedLogLine] = &[
    ExpectedLogLine {
        level: "ERROR",
        pattern: "Network transactions may not be submitted by users yet",
        explanation: "the Row-H F7 RIV deliberately SUBMITS the faucet's consume of a \
                      never-committed burn note via user RPC and records the node's rejection as \
                      evidence that a committed same-block create+consume is unreachable on this \
                      stack; the sequencer logs that deliberate rejection here",
    },
    ExpectedLogLine {
        level: "ERROR",
        pattern: "all notes failed to be executed",
        explanation: "the ntx-builder attempting a deliberately-unconsumable routed allowlisted \
                      note — the rows-A/B second domain_init (init-once) and the rows-C6 \
                      non-authorized-sender admin notes; the on-chain MASM gate rejecting them \
                      NODE-SIDE is the negative's evidence (doomed notes are retried with \
                      backoff, so the line recurs). A failing POSITIVE cannot hide here: every \
                      positive commit is guarded by its row's bounded committed-effect poll",
    },
    ExpectedLogLine {
        level: "ERROR",
        pattern: "network transaction failed",
        explanation: "the wrapper line of the same deliberately-unconsumable routed-note \
                      attempts (see 'all notes failed to be executed'): rows-A/B second \
                      domain_init + rows-C6 non-authorized-sender admin notes, rejected by the \
                      on-chain MASM gates node-side",
    },
    ExpectedLogLine {
        level: "ERROR",
        pattern: "Graceful shutdown timed out; exiting process",
        explanation: "teardown: the harness SIGTERMs the four services in reverse start order \
                      and a service exceeding the grace window logs this while exiting — \
                      shutdown lifecycle, not attributable to any transaction",
    },
    ExpectedLogLine {
        level: "WARN",
        pattern: "RPC connection failed while opening block subscription, retrying",
        explanation: "startup ordering: the ntx-builder starts before the sequencer RPC listens \
                      and retries its block subscription with backoff until the sequencer is up",
    },
    ExpectedLogLine {
        level: "WARN",
        pattern: "block subscription failed, reconnecting",
        explanation: "teardown ordering: the sequencer stops first (reverse start order), \
                      dropping the ntx-builder's block subscription",
    },
];

/// The four service logs a gate run MUST archive (the stack's long-running processes).
pub const REQUIRED_SERVICE_LOGS: [&str; 4] = ["ntx-builder", "sequencer", "tx-prover", "validator"];

// LOG-LINE CLASSIFICATION PRIMITIVES
// ================================================================================================

/// Strips ANSI escape sequences (the SGR color codes the services write into their log files).
/// CSI sequences (`ESC [ … final-byte`) are dropped wholly; a bare ESC is dropped alone.
pub fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // Skip parameter/intermediate bytes through the final byte (0x40..=0x7e).
                for f in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&f) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The tracing level of a log line, by whitespace-token EQUALITY after ANSI-stripping — never by
/// substring, so `error=…` fields, `failed` messages, and multi-line continuations classify as
/// nothing. Only the levels row L judges are reported.
pub fn line_level(line: &str) -> Option<&'static str> {
    let stripped = strip_ansi(line);
    for token in stripped.split_whitespace() {
        match token {
            "ERROR" => return Some("ERROR"),
            "WARN" => return Some("WARN"),
            _ => {}
        }
    }
    None
}

/// Whether the line reports a Rust panic (`thread '…' panicked at …`). Checked independently of
/// the level token: a panic anywhere in a service log fails row L.
pub fn is_panic_line(line: &str) -> bool {
    strip_ansi(line).contains("panicked")
}

/// Classifies one service log's text into `out` (the five row-L line vectors; the archive
/// manifest is the caller's concern). Panic detection wins over level classification.
pub fn scan_log_text(
    service: &str,
    text: &str,
    expected: &[ExpectedLogLine],
    out: &mut RowLObservations,
) {
    for raw in text.lines() {
        let line = strip_ansi(raw);
        if is_panic_line(&line) {
            out.panics.push(FlaggedLine {
                service: service.to_string(),
                line,
            });
            continue;
        }
        let Some(level) = line_level(&line) else {
            continue;
        };
        let matched = expected
            .iter()
            .find(|e| e.level == level && line.contains(e.pattern));
        match (level, matched) {
            ("ERROR", Some(e)) => out.expected_errors.push(TriagedLine {
                service: service.to_string(),
                line,
                pattern: e.pattern.to_string(),
                explanation: e.explanation.to_string(),
            }),
            ("ERROR", None) => out.unexpected_errors.push(FlaggedLine {
                service: service.to_string(),
                line,
            }),
            ("WARN", Some(e)) => out.triaged_warnings.push(TriagedLine {
                service: service.to_string(),
                line,
                pattern: e.pattern.to_string(),
                explanation: e.explanation.to_string(),
            }),
            ("WARN", None) => out.untriaged_warnings.push(FlaggedLine {
                service: service.to_string(),
                line,
            }),
            _ => {}
        }
    }
}

/// Scans every `*.log` under the run's log dir: builds the archive manifest (token-based level
/// counts) and classifies every line against the expected-pattern table. The REQUIRED-services
/// completeness judgment lives in the row-L assertion, not here (observe vs judge).
pub fn scan_logs(log_dir: &Path, expected: &[ExpectedLogLine]) -> Result<RowLObservations> {
    let mut l = RowLObservations::default();
    let entries = fs::read_dir(log_dir)
        .with_context(|| format!("reading the log dir {}", log_dir.display()))?;
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("log"))
        .collect();
    files.sort();
    for path in files {
        let service = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading the service log {}", path.display()))?;
        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        l.scanned.push(ScannedLog {
            service: service.clone(),
            path: path.display().to_string(),
            bytes,
            lines: text.lines().count(),
            error_lines: text
                .lines()
                .filter(|ln| line_level(ln) == Some("ERROR"))
                .count(),
            warn_lines: text
                .lines()
                .filter(|ln| line_level(ln) == Some("WARN"))
                .count(),
        });
        scan_log_text(&service, &text, expected, &mut l);
    }
    Ok(l)
}

// ROW-K DERIVATION
// ================================================================================================

/// Extracts the ntx-builder's execution-marker lines from `ntx-builder.log` text (ANSI-stripped,
/// verbatim) — the node-side half of the row-K evidence.
pub fn ntx_execution_evidence(ntx_log_text: &str) -> Vec<String> {
    ntx_log_text
        .lines()
        .map(strip_ansi)
        .filter(|l| l.contains(NTX_EXECUTION_MARKER))
        .collect()
}

/// Extracts every path-N commit the sub-run observations prove on-chain: the rows-C admin arc
/// (committed read-backs), the rows-D happy-path mints (committed supply movements + the emitted
/// P2ID's inclusion block), and the row-G two-block burn (committed supply decrement + nullifier,
/// pinned at its consume block). Every entry is a consumption the ntx-builder ALONE could have
/// committed at this pin (post-deploy user RPC is closed to network accounts).
pub fn pathn_commits_from(
    cf: &RowsCfObservations,
    de: &RowsDeObservations,
    gj: &RowsGjObservations,
) -> Vec<PathNCommit> {
    let word = |m: &Word4| format!("[{},{},{},{}]", m[0], m[1], m[2], m[3]);
    let admin = |op: &str, effect: String| PathNCommit {
        op: op.to_string(),
        kind: "admin".to_string(),
        commit_block: None,
        effect,
    };

    let mut commits = vec![
        admin(
            "set_attester(A, enabled=1)",
            format!(
                "attester A allowlist marker {}",
                word(&cf.c1.a_marker_after_enable)
            ),
        ),
        admin(
            "set_attester(A, enabled=0) [C1 rotation]",
            format!(
                "attester A allowlist marker {}",
                word(&cf.c1.a_marker_after_rotate)
            ),
        ),
        admin(
            "set_attester(B, enabled=1) [C1 rotation]",
            format!(
                "attester B allowlist marker {}",
                word(&cf.c1.b_marker_after_rotate)
            ),
        ),
        admin(
            "set_min_burn_size (C2 raise)",
            format!("min_burn_size {}", cf.c2.committed_after_raise),
        ),
        admin(
            "set_min_burn_size (C2 lower)",
            format!("min_burn_size {}", cf.c2.committed_after_lower),
        ),
        admin(
            "set_max_supply (C3)",
            format!("max_supply {}", cf.c3.max_supply_readback),
        ),
        admin(
            "pause (C4, DOM_PAUSER)",
            format!("is_paused {}", word(&cf.c4.is_paused_after_pause)),
        ),
        admin(
            "set_attester while paused (C4/F6)",
            format!(
                "attester allowlist marker {}",
                word(&cf.c4.owner_set_attester_while_paused_marker)
            ),
        ),
        admin(
            "set_min_burn_size while paused (C4/F6)",
            format!("min_burn_size {}", cf.c4.owner_set_min_burn_while_paused),
        ),
        admin(
            "unpause (C4, DOM_PAUSER)",
            format!("is_paused {}", word(&cf.c4.is_paused_after_unpause)),
        ),
        admin(
            "role grant DOM_PAUSER (C5, DOM_MANAGER)",
            format!(
                "new-pauser membership {}",
                word(&cf.c5.new_pauser_membership_after_grant)
            ),
        ),
        admin(
            "pause (C5, new DOM_PAUSER)",
            format!(
                "is_paused {}",
                word(&cf.c5.is_paused_after_new_pauser_pause)
            ),
        ),
        admin(
            "role revoke DOM_PAUSER (C5, DOM_MANAGER)",
            format!(
                "new-pauser membership {}",
                word(&cf.c5.new_pauser_membership_after_revoke)
            ),
        ),
    ];

    for v in &de.d {
        commits.push(PathNCommit {
            op: format!("mint {}", v.label),
            kind: "mint".to_string(),
            commit_block: Some(v.note_commit_block),
            effect: format!(
                "token_supply {} → {}; usedNonces[nonce] set; recipient P2ID emitted",
                v.supply_before, v.supply_after
            ),
        });
    }

    commits.push(PathNCommit {
        op: "burn two-block".to_string(),
        kind: "burn".to_string(),
        commit_block: Some(gj.g.consume_block),
        effect: format!(
            "token_supply {} → {}; nullifier recorded: {}",
            gj.g.supply_before, gj.g.supply_after, gj.g.nullifier_recorded_after_consume
        ),
    });

    commits
}

/// Derives the row-K verdict from the evidence: YES iff the run observed at least one path-N
/// MINT commit AND one path-N BURN commit AND node-side execution markers; anything less is NO
/// with the exact missing-evidence cause + the spec's client-side posture statement. The verdict
/// is recorded either way — the assertion layer judges its completeness/consistency.
pub fn derive_row_k(commits: Vec<PathNCommit>, ntx_log_evidence: Vec<String>) -> RowKObservations {
    let has_mint = commits.iter().any(|c| c.kind == "mint");
    let has_burn = commits.iter().any(|c| c.kind == "burn");
    let has_marker = !ntx_log_evidence.is_empty();
    let auto_executes = has_mint && has_burn && has_marker;

    let (no_cause, posture) = if auto_executes {
        (None, POSTURE_PATH_N_LIVE.to_string())
    } else {
        let mut missing = Vec::new();
        if !has_mint {
            missing.push("no path-N mint commit was observed");
        }
        if !has_burn {
            missing.push("no path-N burn commit was observed");
        }
        if !has_marker {
            missing
                .push("no 'executing network transaction' markers were found in ntx-builder.log");
        }
        (
            Some(format!(
                "{} — stack: miden-node v0.15.1 four-service topology with the network-tx auth \
                 token wired (sequencer --rpc.network-tx-auth-header-value / ntx-builder \
                 --rpc.auth-header-value; see VALIDATION-RECORD.md §3)",
                missing.join("; ")
            )),
            POSTURE_PATH_C_ONLY.to_string(),
        )
    };

    RowKObservations {
        auto_executes,
        commits,
        ntx_log_evidence,
        no_cause,
        posture,
    }
}

// THE CONSOLIDATED FULL-MATRIX DRIVER
// ================================================================================================

/// Runs the WHOLE A–L matrix on ONE fresh local stack: boots the four-service stack once, drives
/// the LNV-1..4 sub-runs in matrix order against it (each under its own client-store namespace),
/// stops the stack (so the archived logs are complete), then derives rows K + L from that single
/// run. With `keep_stack` the services stay up for supervised inspection and the logs are scanned
/// live (partial by construction).
pub async fn run_full_matrix(cfg: &RunConfig) -> Result<FullMatrixObservations> {
    let mut stack = NodeStack::bootstrap_and_start(&cfg.stack)
        .context("bootstrapping + starting the local node stack")?;
    if cfg.keep_stack {
        stack.keep_on_drop();
    }

    let ab = run_rows_ab_on(cfg, "ab")
        .await
        .context("rows A/B sub-run (deploy + domain_init)")?;
    let cf = run_rows_cf_on(cfg, "cf")
        .await
        .context("rows C/F sub-run (admin + auth boundary)")?;
    let de = run_rows_de_on(cfg, "de")
        .await
        .context("rows D/E sub-run (mint lifecycle)")?;
    let gj = run_rows_gj_on(cfg, "gj")
        .await
        .context("rows G/H/I/J sub-run (burn lifecycle + conservation)")?;

    // Stop the services BEFORE reading the logs so the archives are complete (row L scans the
    // whole run, including teardown).
    if !cfg.keep_stack {
        stack.stop().context("stopping the node stack")?;
    }

    let ntx_log_path = cfg.stack.log_dir().join("ntx-builder.log");
    let ntx_text = fs::read_to_string(&ntx_log_path)
        .with_context(|| format!("reading {}", ntx_log_path.display()))?;
    let k = derive_row_k(
        pathn_commits_from(&cf, &de, &gj),
        ntx_execution_evidence(&ntx_text),
    );
    let l = scan_logs(&cfg.stack.log_dir(), EXPECTED_LOG_LINES)?;

    Ok(FullMatrixObservations {
        ab,
        cf,
        de,
        gj,
        k,
        l,
    })
}
