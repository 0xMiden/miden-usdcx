//! The consolidated LNV-5 gate artifacts: the per-row A–L verdict map, the generated
//! **VALIDATION RECORD**, the three evidence packets (F7 / ntx-builder liveness / the byte-exact
//! `GetNotesById` capture), and the machine-readable run evidence.
//!
//! Everything here is DETERMINISTIC RENDERING over the run's observations + verdicts — the one
//! command (`cargo run -p xusdc-validation --bin lnv5_full_matrix`) produces every artifact, so a
//! human can reproduce the whole packet from a fresh node and diff it.
//!
//! **The acceptance-gate invariant (pinned by tests): the generated record NEVER self-declares the gate.**
//! Per-row PASS/FAIL lines are machine verdicts; the GATE verdict line is either
//! `PENDING HUMAN ACCEPTANCE` (all rows green — a human reproduces, inspects, and declares) or
//! `GATE CANNOT PASS` (a row failed — a surfaced finding; validator-not-fixer: the fix is a
//! separate gated slice, then a re-run).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use serde::Serialize;

use crate::assertions::{assert_row_a, assert_row_b};
use crate::assertions_cf::{
    assert_c1, assert_c2, assert_c3, assert_c4, assert_c5, assert_c6, assert_f,
};
use crate::assertions_de::{assert_d, assert_e};
use crate::assertions_gj::{assert_g, assert_h, assert_i, assert_j};
use crate::assertions_kl::{assert_k, assert_l};
use crate::config::RunConfig;
use crate::evidence::{log_manifest, LogManifestEntry};
use crate::observations_cf::RowsCfObservations;
use crate::observations_de::RowsDeObservations;
use crate::observations_gj::{BurnTwoBlock, RowsGjObservations};
use crate::observations_kl::{FullMatrixObservations, RowKObservations, RowLObservations};

/// The twelve matrix rows, in matrix order (rows C1–C6 aggregate under row C).
pub const MATRIX_ROW_IDS: [&str; 12] = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L"];

/// The matrix row titles (the row names, condensed).
const MATRIX_ROW_TITLES: [(&str, &str); 12] = [
    ("A", "deploy + recognize"),
    ("B", "domain_init init-once"),
    ("C", "admin suite (C1–C6)"),
    ("D", "mint happy path"),
    ("E", "mint negatives"),
    ("F", "auth boundary (F5)"),
    ("G", "burn two-block (Circle read-path)"),
    ("H", "burn same-block (F7 RIV evidence)"),
    ("I", "burn negatives"),
    ("J", "conservation ledger"),
    ("K", "ntx-builder liveness (path N)"),
    ("L", "clean logs"),
];

fn title_of(id: &str) -> &'static str {
    MATRIX_ROW_TITLES
        .iter()
        .find(|(row, _)| *row == id)
        .map(|(_, title)| *title)
        .unwrap_or("")
}

/// One matrix row's verdict (the machine half of the record; the GATE verdict is human).
#[derive(Debug, Clone, Serialize)]
pub struct RowOutcome {
    /// The matrix row id ("A" … "L").
    pub row: String,
    /// The row's matrix title.
    pub title: String,
    /// Whether the row's assertion suite passed.
    pub pass: bool,
    /// The full failure chain when `pass` is false.
    pub detail: Option<String>,
}

/// Applies every row's assertion suite over the consolidated observations — THE single verdict
/// map the `lnv5_full_matrix` binary and the real-node E2E both use. Row C aggregates C1–C6.
pub fn full_matrix_outcomes(m: &FullMatrixObservations) -> Vec<RowOutcome> {
    let row_c = || -> Result<()> {
        assert_c1(&m.cf.c1).context("C1 set_attester + rotation")?;
        assert_c2(&m.cf.c2).context("C2 set_min_burn_size")?;
        assert_c3(&m.cf.c3).context("C3 set_max_supply")?;
        assert_c4(&m.cf.c4).context("C4 pause/unpause (F6)")?;
        assert_c5(&m.cf.c5).context("C5 role rotation")?;
        assert_c6(&m.cf.c6).context("C6 non-authorized-sender negatives")?;
        Ok(())
    };
    let results: Vec<(&str, Result<()>)> = vec![
        ("A", assert_row_a(&m.ab)),
        ("B", assert_row_b(&m.ab)),
        ("C", row_c()),
        ("D", assert_d(&m.de.d)),
        ("E", assert_e(&m.de.e)),
        ("F", assert_f(&m.cf.f)),
        ("G", assert_g(&m.gj.g)),
        ("H", assert_h(&m.gj.h)),
        ("I", assert_i(&m.gj.i)),
        ("J", assert_j(&m.gj.j)),
        ("K", assert_k(&m.k)),
        ("L", assert_l(&m.l)),
    ];
    results
        .into_iter()
        .map(|(id, r)| RowOutcome {
            row: id.to_string(),
            title: title_of(id).to_string(),
            pass: r.is_ok(),
            detail: r.err().map(|e| format!("{e:#}")),
        })
        .collect()
}

/// The outcome list must be EXACTLY the twelve matrix rows, in matrix order, each once — a
/// dropped, duplicated, or reordered row would falsify the record.
pub fn validate_row_outcomes(outcomes: &[RowOutcome]) -> Result<()> {
    ensure!(
        outcomes.len() == MATRIX_ROW_IDS.len(),
        "the validation matrix has {} rows (A–L), got {}",
        MATRIX_ROW_IDS.len(),
        outcomes.len()
    );
    for (outcome, expected) in outcomes.iter().zip(MATRIX_ROW_IDS) {
        ensure!(
            outcome.row == expected,
            "matrix row order violated: expected row {expected}, found row {}",
            outcome.row
        );
    }
    Ok(())
}

/// Whether any matrix row failed.
pub fn any_failed(outcomes: &[RowOutcome]) -> bool {
    outcomes.iter().any(|o| !o.pass)
}

/// The run-level identifiers the record quotes (everything else renders from the observations).
#[derive(Debug, Clone, Serialize)]
pub struct RecordContext {
    /// The `main` commit the harness was built from.
    pub main_commit: String,
    /// The run root (gitignored) holding the node data, stores, logs, and machine evidence.
    pub run_root: String,
    /// The rows-A/B faucet (the deploy + init-once subject).
    pub ab_faucet_id: String,
    /// The rows-A/B deploy transaction id and its commit block.
    pub ab_deploy_tx_id: String,
    pub ab_deploy_block: u32,
    /// The rows-C/F faucet (the admin-suite subject).
    pub cf_faucet_id: String,
    /// The rows-D/E faucet and recipient wallet.
    pub de_faucet_id: String,
    pub de_recipient_id: String,
    /// The rows-G/H/I/J faucet and holder (burner) wallet.
    pub gj_faucet_id: String,
    pub gj_holder_id: String,
}

impl RecordContext {
    /// Builds the context from a completed run.
    pub fn from_run(cfg: &RunConfig, m: &FullMatrixObservations) -> Self {
        Self {
            main_commit: m.ab.main_commit.clone(),
            run_root: cfg.stack.run_root.display().to_string(),
            ab_faucet_id: m.ab.faucet_id.to_string(),
            ab_deploy_tx_id: m.ab.deploy_tx_id.clone(),
            ab_deploy_block: m.ab.deploy_block,
            cf_faucet_id: m.cf.faucet_id.clone(),
            de_faucet_id: m.de.faucet_id.clone(),
            de_recipient_id: m.de.recipient_id.clone(),
            gj_faucet_id: m.gj.faucet_id.clone(),
            gj_holder_id: m.gj.holder_id.clone(),
        }
    }
}

fn verdict_cell(o: &RowOutcome) -> &'static str {
    if o.pass {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Renders the consolidated **VALIDATION RECORD** (markdown). Machine verdicts per row; the GATE
/// verdict defers to the human — see the module docs for the pinned invariant.
pub fn render_validation_record(
    ctx: &RecordContext,
    outcomes: &[RowOutcome],
    cf: &RowsCfObservations,
    de: &RowsDeObservations,
    gj: &RowsGjObservations,
    k: &RowKObservations,
    l: &RowLObservations,
) -> String {
    let mut s = String::new();
    let failed: Vec<&RowOutcome> = outcomes.iter().filter(|o| !o.pass).collect();

    s.push_str(
        "# LNV-5 Validation Record — the consolidated §11.2 full-matrix gate run (rows A–L)\n\n",
    );
    s.push_str(
        "One deterministic pass over the WHOLE validation matrix on ONE fresh local \
         `miden-node v0.15.1` stack: deploy → admin → mint → burn → conservation (the LNV-1..4 \
         drivers composed in matrix order on the same node), then row K (ntx-builder liveness) \
         and row L (clean logs) derived from that single run. Generated deterministically by the \
         gate command below — re-running it on a fresh node regenerates this record. \
         **Validator-not-fixer:** a failing row is a SURFACED finding, never a faucet hot-fix. \
         **Row H stays a Circle/DEV-7 EVIDENCE packet — no acceptability decision.**\n\n",
    );
    s.push_str(&format!(
        "- Built from `main` @ `{}`; run root `{}` (gitignored: node data, client stores, full \
         logs, machine evidence).\n",
        ctx.main_commit, ctx.run_root
    ));
    s.push_str(
        "- Pins (full toolchain/dep ledger: `VALIDATION-RECORD.md` §2): `miden-node` **v0.15.1** \
         installed binaries, four-service loopback stack (sequencer RPC 57291, validator 57292, \
         ntx-builder 57293, tx-prover 57294), isolated local genesis; `miden-client` \
         **=0.16.0-alpha.1** (crates.io); protocol family crates.io **=0.16.0-alpha.4**.\n\n",
    );

    s.push_str("## Reproduction (the one command)\n\n");
    s.push_str("```bash\ncargo run -p xusdc-validation --bin lnv5_full_matrix\n```\n\n");
    s.push_str(
        "Requirements: the four v0.15.1 node binaries on `PATH`, loopback ports 57291–57294 \
         free. The command bootstraps a FRESH genesis, runs the whole A–L matrix, tears the \
         stack down, and writes this record + the three evidence packets + \
         `evidence-lnv5.json`.\n\n",
    );

    s.push_str("## Result\n\n");
    s.push_str("| row | title | verdict |\n|---|---|---|\n");
    for o in outcomes {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            o.row,
            o.title,
            verdict_cell(o)
        ));
    }
    s.push('\n');

    if failed.is_empty() {
        s.push_str(
            "**GATE VERDICT: PENDING HUMAN ACCEPTANCE (§11.2).** Every matrix row passed its \
             assertion suite on this run, and per the charter the PASS is a HUMAN decision, \
             never self-declared: a human reproduces from a fresh node with the command above, \
             inspects this record, the archived logs, and the evidence packets, and declares \
             the gate outcome.\n\n",
        );
    } else {
        s.push_str(&format!(
            "**GATE VERDICT: GATE CANNOT PASS — {} row(s) FAILED.** Each failure is a surfaced \
             finding (validator-not-fixer): production fixes happen in a separate gated slice, \
             then the whole matrix re-runs on a fresh node.\n\n### Failing rows\n\n",
            failed.len()
        ));
        for o in &failed {
            s.push_str(&format!(
                "- row {} ({}): {}\n",
                o.row,
                o.title,
                o.detail.as_deref().unwrap_or("(no detail recorded)")
            ));
        }
        s.push('\n');
    }

    s.push_str("## Sub-run identities (one node, four slice subjects)\n\n");
    s.push_str("| slice | faucet | counterparty |\n|---|---|---|\n");
    s.push_str(&format!(
        "| rows A/B | `{}` | deploy tx `{}` @ block {} |\n",
        ctx.ab_faucet_id, ctx.ab_deploy_tx_id, ctx.ab_deploy_block
    ));
    s.push_str(&format!("| rows C/F | `{}` | — |\n", ctx.cf_faucet_id));
    s.push_str(&format!(
        "| rows D/E | `{}` | recipient `{}` |\n",
        ctx.de_faucet_id, ctx.de_recipient_id
    ));
    s.push_str(&format!(
        "| rows G–J | `{}` | holder `{}` |\n\n",
        ctx.gj_faucet_id, ctx.gj_holder_id
    ));
    s.push_str(
        "Each LNV slice deploys its own production-composition faucet on the SHARED fresh chain \
         (state isolation per network account); the drivers, assertions, and evidence shapes are \
         exactly the LNV-1..4 ones, re-executed in matrix order against one node.\n\n",
    );

    s.push_str("## Rows C/F — committed admin effects (path N) + auth boundary\n\n");
    s.push_str(&format!(
        "- C1 attester rotation: A enabled {:?} → rotated {:?}; B enabled {:?}; mint-by-A {}; \
         mint-by-B {}.\n",
        cf.c1.a_marker_after_enable,
        cf.c1.a_marker_after_rotate,
        cf.c1.b_marker_after_rotate,
        if cf.c1.mint_by_a.is_accepted() {
            "ACCEPTED (defect)"
        } else {
            "REJECTED"
        },
        if cf.c1.mint_by_b.is_accepted() {
            "ACCEPTED"
        } else {
            "REJECTED (defect)"
        },
    ));
    s.push_str(&format!(
        "- C2 min burn size: raised to {} (read back {}), below-min burn rejected; lowered to {} \
         (read back {}), at-min burn accepted.\n",
        cf.c2.raised_min,
        cf.c2.committed_after_raise,
        cf.c2.lowered_min,
        cf.c2.committed_after_lower
    ));
    s.push_str(&format!(
        "- C3 max supply: committed cap {} (read back {}); over-cap mint rejected, within-cap \
         accepted.\n",
        cf.c3.committed_cap, cf.c3.max_supply_readback
    ));
    s.push_str(&format!(
        "- C4 pause/unpause (F6): paused {:?} (mint+burn rejected; owner setters STILL commit \
         while paused: attester marker {:?}, min_burn {}), unpaused {:?} (mint accepted again).\n",
        cf.c4.is_paused_after_pause,
        cf.c4.owner_set_attester_while_paused_marker,
        cf.c4.owner_set_min_burn_while_paused,
        cf.c4.is_paused_after_unpause
    ));
    s.push_str(&format!(
        "- C5 role rotation: DOM_PAUSER granted {:?} → new pauser paused {:?} → revoked {:?} → \
         revoked pauser's pause rejected.\n",
        cf.c5.new_pauser_membership_after_grant,
        cf.c5.is_paused_after_new_pauser_pause,
        cf.c5.new_pauser_membership_after_revoke
    ));
    s.push_str(&format!(
        "- C6 non-authorized senders: {} admin ops rejected at the proc gate, each note also \
         UNCONSUMED node-side after a watch window.\n",
        cf.c6.len()
    ));
    s.push_str(
        "- Row F: the non-allowlisted note (stock P2ID at the faucet) and the tx-script \
         transaction are both REJECTED (the frozen F5 auth boundary).\n\n",
    );

    s.push_str("## Rows D/E — mint lifecycle\n\n");
    s.push_str(
        "| variant | amount | token_supply | note block → consume block |\n|---|---|---|---|\n",
    );
    for v in &de.d {
        s.push_str(&format!(
            "| {} | {} | {} → {} | {} → {} |\n",
            v.label,
            v.amount_units,
            v.supply_before,
            v.supply_after,
            v.note_commit_block,
            v.recipient_consume_block
        ));
    }
    s.push_str("\nMint negatives (each client-side REJECTED, zero state change):\n\n");
    for n in &de.e {
        s.push_str(&format!(
            "- {} → `{}` (supply {} → {}).\n",
            n.label, n.expected_error, n.supply_before, n.supply_after
        ));
    }
    s.push('\n');

    s.push_str("## Rows G/H/I/J — burn lifecycle + conservation\n\n");
    s.push_str(&format!(
        "- Row G (two-block, the Circle read-path): burn note `{}` (tag `0x{:08X}`) committed @ \
         block {}, consumed @ block {}; token_supply {} → {}; committed-before-consume {}, \
         SyncNotes-discovered {}, STILL `GetNotesById`-retrievable after consume {}, nullifier \
         recorded {}. Byte-exact capture: `LNV5-BURN-GETNOTESBYID-CAPTURE.hex`.\n",
        gj.g.note_id,
        gj.g.note_tag,
        gj.g.note_commit_block,
        gj.g.consume_block,
        gj.g.supply_before,
        gj.g.supply_after,
        gj.g.committed_before_consume,
        gj.g.discovered_by_syncnotes,
        gj.g.found_after_consume,
        gj.g.nullifier_recorded_after_consume
    ));
    s.push_str(&format!(
        "- Row H (F7 same-block RIV — EVIDENCE for Circle/DEV-7, which stays OPEN): note `{}`; \
         client-side consume accepted {}, executed supply delta {:?}; user-RPC submission \
         REJECTED {}; on-chain supply {} → {} (unchanged); committed note found {}, nullifier \
         {}, SyncNotes {}. Full packet: `LNV5-F7-EVIDENCE-PACKET.md`.\n",
        gj.h.note_id,
        gj.h.consume_accepted,
        gj.h.executed_supply_delta,
        gj.h.submit_via_user_rpc_rejected,
        gj.h.onchain_supply_before,
        gj.h.onchain_supply_after,
        gj.h.committed_note_found,
        gj.h.nullifier_recorded,
        gj.h.discovered_by_syncnotes
    ));
    s.push_str("- Row I burn negatives (each client-side REJECTED, zero state change):\n");
    for n in &gj.i {
        s.push_str(&format!(
            "  - {} → `{}` (supply {} → {}).\n",
            n.label, n.expected_error, n.supply_before, n.supply_after
        ));
    }
    s.push_str(&format!(
        "- Row J conservation: Σminted {} − Σburned {} == final token_supply {}; holder final \
         balance {}.\n\n",
        gj.j.total_minted, gj.j.total_burned, gj.j.final_supply, gj.j.holder_final_balance
    ));

    s.push_str("## Row K — ntx-builder liveness (path N)\n\n");
    s.push_str(&format!(
        "**VERDICT: {}.** {} path-N commits observed ({} mint / {} burn / {} admin); {} \
         node-side `executing network transaction` markers in `ntx-builder.log`. Posture: {}\n\n\
         Full verdict + evidence: `LNV5-NTX-LIVENESS-VERDICT.md`.\n\n",
        if k.auto_executes {
            "YES — the ntx-builder auto-executes"
        } else {
            "NO"
        },
        k.commits.len(),
        k.commits.iter().filter(|c| c.kind == "mint").count(),
        k.commits.iter().filter(|c| c.kind == "burn").count(),
        k.commits.iter().filter(|c| c.kind == "admin").count(),
        k.ntx_log_evidence.len(),
        k.posture
    ));
    if let Some(cause) = &k.no_cause {
        s.push_str(&format!("Cause: {cause}\n\n"));
    }

    s.push_str("## Row L — clean logs\n\n");
    s.push_str(
        "Definition: ZERO unexplained ERROR lines and ZERO panic lines across every archived \
         service log of the whole run, with every WARN triaged + explained. Lines produced by \
         our DELIBERATE negatives (the node-side rejections that ARE those negatives' evidence) \
         are triaged against the explicit pattern table below; a failing POSITIVE cannot hide \
         there because every positive commit is guarded by its own row's bounded \
         committed-effect poll. Anything unmatched fails the row.\n\n",
    );
    s.push_str(
        "| service log | lines | ERROR-level | WARN-level | bytes |\n|---|---|---|---|---|\n",
    );
    for sl in &l.scanned {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            sl.service, sl.lines, sl.error_lines, sl.warn_lines, sl.bytes
        ));
    }
    s.push_str(&format!(
        "\nScan result: **{} unexpected ERROR lines, {} panics, {} untriaged warnings** \
         ({} expected-error lines and {} warnings triaged).\n\n",
        l.unexpected_errors.len(),
        l.panics.len(),
        l.untriaged_warnings.len(),
        l.expected_errors.len(),
        l.triaged_warnings.len()
    ));
    s.push_str("Triage table (every matched pattern, with its explanation):\n\n");
    s.push_str("| level | pattern | occurrences | triage |\n|---|---|---|---|\n");
    let mut patterns: Vec<(&str, &str, &str)> = Vec::new();
    for t in &l.expected_errors {
        if !patterns.iter().any(|(_, p, _)| *p == t.pattern) {
            patterns.push(("ERROR", &t.pattern, &t.explanation));
        }
    }
    for t in &l.triaged_warnings {
        if !patterns.iter().any(|(_, p, _)| *p == t.pattern) {
            patterns.push(("WARN", &t.pattern, &t.explanation));
        }
    }
    for (level, pattern, explanation) in &patterns {
        let occurrences = l
            .expected_errors
            .iter()
            .filter(|t| &t.pattern == pattern)
            .count()
            + l.triaged_warnings
                .iter()
                .filter(|t| &t.pattern == pattern)
                .count();
        s.push_str(&format!(
            "| {level} | {pattern} | {occurrences} | {explanation} |\n"
        ));
    }
    if !l.unexpected_errors.is_empty() || !l.panics.is_empty() || !l.untriaged_warnings.is_empty() {
        s.push_str("\nFLAGGED (row-L failures):\n\n");
        for f in l
            .panics
            .iter()
            .chain(l.unexpected_errors.iter())
            .chain(l.untriaged_warnings.iter())
        {
            s.push_str(&format!("- [{}] {}\n", f.service, f.line));
        }
    }
    s.push('\n');

    s.push_str("## Deliverables of this run\n\n");
    s.push_str(&format!(
        "1. THIS record (generated; per-row PASS/FAIL + ids/blocks + triage).\n\
         2. `LNV5-F7-EVIDENCE-PACKET.md` — the Circle/DEV-7 same-block-erasure evidence (no \
         acceptability decision).\n\
         3. `LNV5-NTX-LIVENESS-VERDICT.md` — the row-K verdict + deployment posture.\n\
         4. `LNV5-BURN-GETNOTESBYID-CAPTURE.hex` — the byte-exact `GetNotesById` burn capture \
         (examples repo / Njord input).\n\
         5. `{}/evidence-lnv5.json` — the machine-readable evidence (full observations, \
         verdicts, log manifest) + the archived logs under the same run root.\n",
        ctx.run_root
    ));
    s
}

/// Renders the **F7 evidence packet** (Circle/DEV-7 input): the two-block read-path proof vs the
/// same-block-erasure RIV, raw node evidence quoted, NO acceptability decision — DEV-7 stays
/// OPEN.
pub fn render_f7_packet(gj: &RowsGjObservations, main_commit: &str) -> String {
    let g = &gj.g;
    let h = &gj.h;
    format!(
        "# LNV-5 F7 Evidence Packet — same-block burn erasure RIV (Circle / DEV-7 input)\n\n\
         **This packet is EVIDENCE ONLY: it makes NO acceptability decision. DEV-7 stays OPEN — \
         a Circle-owned decision.** Produced on a fresh local `miden-node v0.15.1` stack from \
         `main` @ `{main_commit}` by `cargo run -p xusdc-validation --bin lnv5_full_matrix` \
         (faucet `{faucet}`, holder `{holder}`).\n\n\
         The RIV question (F7): can the production `XReserveBurnNote` be created + consumed \
         within one block so its burn event is erased (starving Circle's `SyncNotes` / \
         `GetNotesById` discovery) while the supply delta still applies?\n\n\
         ## Lifecycle 1 — two-block burn (row G: the Circle read-path, PERSISTS)\n\n\
         | field | value |\n|---|---|\n\
         | burn note id | `{g_note}` |\n\
         | note tag | `0x{g_tag:08X}` (the fixed xUSDC burn tag) |\n\
         | committed in block | {g_commit} |\n\
         | consumed by the faucet in block | {g_consume} (strictly later) |\n\
         | token_supply | {g_before} → {g_after} |\n\
         | committed + `GetNotesById`-retrievable BEFORE consume | {g_pre} |\n\
         | `SyncNotes` (tag-filtered) discovery | {g_sync} |\n\
         | STILL `GetNotesById`-retrievable AFTER consume | {g_post} |\n\
         | nullifier recorded on-chain after consume | {g_null} |\n\n\
         The committed note + nullifier PERSIST after consumption — the withdrawal attester's \
         read-path holds. Byte-exact response capture (note + inclusion proof): \
         `LNV5-BURN-GETNOTESBYID-CAPTURE.hex`.\n\n\
         ## Lifecycle 2 — same-block / never-committed burn (row H: the erasure RIV)\n\n\
         Mechanism: {h_mechanism}\n\n\
         | field | value |\n|---|---|\n\
         | burn note id | `{h_note}` (same production note shape, tag `0x{h_tag:08X}`) |\n\
         | client-side (unauthenticated) consume executed | {h_accepted} — the production note \
         IS a valid burn |\n\
         | supply delta the executed consume applies | {h_delta:?} (== the burned amount) |\n\
         | SUBMITTING that consume via user RPC | rejected: {h_rejected} |\n\
         | the node's rejection (verbatim) | `{h_rejection}` |\n\
         | on-chain token_supply | {h_before} → {h_after} (UNCHANGED — nothing committed) |\n\
         | committed note found on the node | {h_found} |\n\
         | nullifier recorded on-chain | {h_null} |\n\
         | `SyncNotes` (tag-filtered) discovery | {h_sync} |\n\
         | raw `GetNotesById` evidence | `{h_raw}` |\n\n\
         ## The real-node constraint (why a COMMITTED same-block create+consume is unreachable \
         on this stack)\n\n\
         The faucet is a network account: post-deployment user-RPC submissions against it are \
         rejected by `miden-node v0.15.1` (captured verbatim above), the stock \
         `miden-client 0.16.0-alpha.1` cannot present the sequencer's `x-miden-network-tx-auth` header, \
         and the ntx-builder — the only commit path — consumes only COMMITTED notes, which \
         makes every committed burn consumption strictly-later-block (lifecycle 1). The \
         same-block-erasure hazard therefore does not materialize through any path available on \
         this stack, while the client-side execution shows what WOULD survive if a same-block \
         consume ever committed: the supply delta only — no note, no nullifier, no discovery.\n\n\
         **DEV-7 remains OPEN with Circle: this packet records the evidence for that decision \
         and decides nothing about acceptability.**\n",
        main_commit = main_commit,
        faucet = gj.faucet_id,
        holder = gj.holder_id,
        g_note = g.note_id,
        g_tag = g.note_tag,
        g_commit = g.note_commit_block,
        g_consume = g.consume_block,
        g_before = g.supply_before,
        g_after = g.supply_after,
        g_pre = g.committed_before_consume,
        g_sync = g.discovered_by_syncnotes,
        g_post = g.found_after_consume,
        g_null = g.nullifier_recorded_after_consume,
        h_mechanism = h.mechanism,
        h_note = h.note_id,
        h_tag = h.note_tag,
        h_accepted = h.consume_accepted,
        h_delta = h.executed_supply_delta,
        h_rejected = h.submit_via_user_rpc_rejected,
        h_rejection = h.submit_rejection_error,
        h_before = h.onchain_supply_before,
        h_after = h.onchain_supply_after,
        h_found = h.committed_note_found,
        h_null = h.nullifier_recorded,
        h_sync = h.discovered_by_syncnotes,
        h_raw = h.raw_getnotesbyid_response,
    )
}

/// Renders the **ntx-builder liveness verdict** (row K deliverable): the verdict, the on-chain
/// path-N commit evidence, the node-side log markers, and the deployment-posture statement.
pub fn render_ntx_verdict(k: &RowKObservations, main_commit: &str) -> String {
    let mut s = String::new();
    s.push_str("# LNV-5 ntx-builder Liveness Verdict (matrix row K — the F5-deferred check)\n\n");
    s.push_str(&format!(
        "Question: with the routing attachment + exec hint, does the node's ntx-builder \
         AUTO-execute the faucet's mint (and burn) consumptions? Produced from `main` @ \
         `{main_commit}` on the LNV-5 consolidated run.\n\n"
    ));
    s.push_str(&format!(
        "## VERDICT: {}\n\n",
        if k.auto_executes { "YES" } else { "NO" }
    ));
    if let Some(cause) = &k.no_cause {
        s.push_str(&format!("Cause (version/config): {cause}\n\n"));
    }
    s.push_str(&format!("**Deployment posture:** {}\n\n", k.posture));
    s.push_str(&format!(
        "## On-chain evidence — {} path-N commits ({} mint / {} burn / {} admin)\n\n",
        k.commits.len(),
        k.commits.iter().filter(|c| c.kind == "mint").count(),
        k.commits.iter().filter(|c| c.kind == "burn").count(),
        k.commits.iter().filter(|c| c.kind == "admin").count(),
    ));
    s.push_str("| kind | op | commit block | committed effect |\n|---|---|---|---|\n");
    for c in &k.commits {
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            c.kind,
            c.op,
            c.commit_block
                .map(|b| b.to_string())
                .unwrap_or_else(|| "—".to_string()),
            c.effect
        ));
    }
    s.push_str(&format!(
        "\n## Node-side evidence — {} `{}` markers in `ntx-builder.log`\n\n",
        k.ntx_log_evidence.len(),
        crate::rows_kl::NTX_EXECUTION_MARKER
    ));
    for line in k.ntx_log_evidence.iter().take(8) {
        s.push_str(&format!("    {line}\n"));
    }
    if k.ntx_log_evidence.len() > 8 {
        s.push_str(&format!(
            "    … {} more (full log archived under the run root)\n",
            k.ntx_log_evidence.len() - 8
        ));
    }
    s
}

/// Renders the **byte-exact `GetNotesById` capture** (row G deliverable, the LNV-4 file format):
/// self-describing comment header + the two hex payloads verbatim (note bytes, then the
/// inclusion-proof bytes).
pub fn render_getnotesbyid_capture(g: &BurnTwoBlock) -> String {
    format!(
        "# Byte-exact GetNotesById response for the committed production XReserveBurnNote (LNV-5 Row G).\n\
         # Deliverable for the examples repo / Njord follow-up. The FULL response content of\n\
         # NodeRpcClient::get_notes_by_id -> FetchedNote::Public(Note, NoteInclusionProof): BOTH halves,\n\
         # hex-encoded via Serializable::to_bytes — the note body AND its inclusion proof (the proof is\n\
         # what the withdrawal attester needs to verify the note's on-chain inclusion).\n\
         # note_id={}  tag=0x{:08X}  inclusion_block={}\n\
         #\n\
         # --- Note (miden_protocol::note::Note::to_bytes), {} bytes ---\n\
         {}\n\
         # --- NoteInclusionProof (miden_protocol::note::NoteInclusionProof::to_bytes), {} bytes ---\n\
         {}\n",
        g.note_id,
        g.note_tag,
        g.getnotesbyid_inclusion_block,
        g.getnotesbyid_note_bytes_hex.len() / 2,
        g.getnotesbyid_note_bytes_hex,
        g.getnotesbyid_inclusion_proof_bytes_hex.len() / 2,
        g.getnotesbyid_inclusion_proof_bytes_hex,
    )
}

/// The rows-A/B scalar summary embedded in the machine evidence (the full `Account` read-backs
/// are not serializable; their asserted surfaces live in the row verdicts).
#[derive(Serialize)]
struct AbSummary {
    faucet_id: String,
    owner_id: String,
    deploy_tx_id: String,
    deploy_block: u32,
    first_note_id: String,
    second_note_id: String,
    reinit_error: Option<String>,
    second_note_consumed: bool,
}

/// The machine-readable consolidated run evidence (`evidence-lnv5.json`).
#[derive(Serialize)]
struct Lnv5RunEvidence<'a> {
    main_commit: String,
    node_version: String,
    client_crate: String,
    protocol_rev: String,
    rpc_port: u16,
    validator_port: u16,
    ntx_builder_port: u16,
    tx_prover_port: u16,
    ab: AbSummary,
    cf: &'a RowsCfObservations,
    de: &'a RowsDeObservations,
    gj: &'a RowsGjObservations,
    k: &'a RowKObservations,
    l: &'a RowLObservations,
    rows: &'a [RowOutcome],
    logs: Vec<LogManifestEntry>,
}

/// Where the generated LNV-5 artifacts landed.
pub struct Lnv5Artifacts {
    pub record: PathBuf,
    pub f7_packet: PathBuf,
    pub ntx_verdict: PathBuf,
    pub capture: PathBuf,
    pub evidence_json: PathBuf,
}

/// Writes every LNV-5 artifact: the VALIDATION RECORD + the three evidence packets into
/// `crate_dir` (committed deliverables), and the machine evidence JSON under the gitignored run
/// root (next to the archived logs).
pub fn write_lnv5_artifacts(
    crate_dir: &Path,
    cfg: &RunConfig,
    ctx: &RecordContext,
    m: &FullMatrixObservations,
    outcomes: &[RowOutcome],
) -> Result<Lnv5Artifacts> {
    let record = crate_dir.join("VALIDATION-RECORD-LNV5.md");
    fs::write(
        &record,
        render_validation_record(ctx, outcomes, &m.cf, &m.de, &m.gj, &m.k, &m.l),
    )
    .with_context(|| format!("writing {}", record.display()))?;

    let f7_packet = crate_dir.join("LNV5-F7-EVIDENCE-PACKET.md");
    fs::write(&f7_packet, render_f7_packet(&m.gj, &ctx.main_commit))
        .with_context(|| format!("writing {}", f7_packet.display()))?;

    let ntx_verdict = crate_dir.join("LNV5-NTX-LIVENESS-VERDICT.md");
    fs::write(&ntx_verdict, render_ntx_verdict(&m.k, &ctx.main_commit))
        .with_context(|| format!("writing {}", ntx_verdict.display()))?;

    let capture = crate_dir.join("LNV5-BURN-GETNOTESBYID-CAPTURE.hex");
    fs::write(&capture, render_getnotesbyid_capture(&m.gj.g))
        .with_context(|| format!("writing {}", capture.display()))?;

    let evidence = Lnv5RunEvidence {
        main_commit: ctx.main_commit.clone(),
        node_version: "miden-node 0.15.1 (installed binaries)".to_string(),
        client_crate: "miden-client =0.16.0-alpha.1 (crates.io)".to_string(),
        protocol_rev: "0xMiden/protocol crates.io =0.16.0-alpha.4".to_string(),
        rpc_port: cfg.stack.rpc_port,
        validator_port: cfg.stack.validator_port,
        ntx_builder_port: cfg.stack.ntx_builder_port,
        tx_prover_port: cfg.stack.tx_prover_port,
        ab: AbSummary {
            faucet_id: m.ab.faucet_id.to_string(),
            owner_id: m.ab.owner_id.to_string(),
            deploy_tx_id: m.ab.deploy_tx_id.clone(),
            deploy_block: m.ab.deploy_block,
            first_note_id: m.ab.first_note_id.clone(),
            second_note_id: m.ab.second_note_id.clone(),
            reinit_error: m.ab.reinit_error.clone(),
            second_note_consumed: m.ab.second_note_consumed,
        },
        cf: &m.cf,
        de: &m.de,
        gj: &m.gj,
        k: &m.k,
        l: &m.l,
        rows: outcomes,
        logs: log_manifest(&cfg.stack.log_dir()),
    };
    let evidence_json = cfg.stack.run_root.join("evidence-lnv5.json");
    fs::create_dir_all(&cfg.stack.run_root).context("creating the run root")?;
    fs::write(
        &evidence_json,
        serde_json::to_vec_pretty(&evidence).context("serializing the LNV-5 evidence")?,
    )
    .with_context(|| format!("writing {}", evidence_json.display()))?;

    Ok(Lnv5Artifacts {
        record,
        f7_packet,
        ntx_verdict,
        capture,
        evidence_json,
    })
}
