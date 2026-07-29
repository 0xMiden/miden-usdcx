//! Integrity tripwire for the V16-NOW migration's per-hunk evidence ledger
//! (`docs/MIGRATION-V16-NEXT-EVIDENCE.md` §2).
//!
//! The ledger is the auditable record that every tripwire hunk of the migration falls into
//! exactly one sanctioned edit class. That record is only trustworthy if it is COMPLETE and
//! VERBATIM, so this file pins the properties a summarized or truncated ledger would lose:
//! every data row carries its file path, a well-formed full `@@` hunk header, and exactly one
//! sanctioned class; the sanctioned NEW test files appear as whole-file rows whose `@@ -0,0
//! +1,N @@` headers state each file's REAL line count (the cross-check that makes the row
//! verbatim rather than asserted); the ledger's own stated totals equal what its rows
//! actually count; and — the load-bearing half — the ledger's `(file, hunk header)` set equals,
//! BYTE FOR BYTE, what `git diff --unified=3 8a3fb04 -- <file>` emits over the ledger's declared
//! scope at test time, so a valid-looking but false coordinate/context, a dropped hunk, or a
//! phantom row all go RED.
//!
//! Lifecycle: the byte-for-byte leg compares the LIVE diff against the migration base, so it is
//! scoped to this migration branch's lifetime — the revert slice (FF-5) or the first later slice
//! that touches a covered file regenerates or retires the ledger AND this tripwire together (the
//! evidence file itself stays as the historical record).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

const EVIDENCE: &str = include_str!("../../../docs/MIGRATION-V16-NEXT-EVIDENCE.md");

/// The sanctioned NEW test files that must appear as whole-file class-4 rows, paired with their
/// ACTUAL current line counts (recomputed at compile time, so a file edit without a ledger
/// regeneration goes RED).
fn new_file_rows_expected() -> Vec<(&'static str, usize)> {
    vec![
        (
            "crates/xusdc-encoding/tests/config_note_absence.rs",
            include_str!("config_note_absence.rs").lines().count(),
        ),
        (
            "crates/xusdc-encoding/tests/fee_policy_provisional_pin.rs",
            include_str!("fee_policy_provisional_pin.rs")
                .lines()
                .count(),
        ),
        (
            "crates/xusdc-encoding/tests/migration_evidence_ledger.rs",
            include_str!("migration_evidence_ledger.rs").lines().count(),
        ),
    ]
}

/// A parsed ledger data row: (file, hunk header, class, note).
struct Row {
    file: String,
    hunk: String,
    class: String,
}

/// Parses the §2 ledger's data rows. A data row is a table row whose FIRST cell is a backticked
/// repo path (`crates/…` or `asm/…`); the header/separator rows and any prose tables elsewhere in
/// the file do not match that shape.
fn ledger_rows() -> Vec<Row> {
    let start = EVIDENCE
        .find("## 2.")
        .expect("the evidence file must contain the §2 ledger");
    EVIDENCE[start..]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("| `") {
                return None;
            }
            let cells: Vec<&str> = line.trim_matches('|').split(" | ").map(str::trim).collect();
            let file = cells.first()?.trim_matches('`').to_string();
            if !(file.starts_with("crates/") || file.starts_with("asm/")) {
                return None;
            }
            Some(Row {
                file,
                hunk: cells.get(1).map(|c| c.trim_matches('`').to_string())?,
                class: cells.get(2).map(|c| c.to_string())?,
            })
        })
        .collect()
}

/// Every data row is fully formed: a repo file path, a well-formed FULL `@@ -a,b +c,d @@` hunk
/// header (never a summary like "NO HUNKS" in a data row), and exactly ONE sanctioned class 1-6.
#[test]
fn every_ledger_row_carries_file_hunk_and_one_class() {
    let rows = ledger_rows();
    assert!(
        rows.len() >= 160,
        "the ledger must enumerate every tripwire hunk one row at a time; found only {} data \
         rows (a summarized or column-dropping ledger parses to nothing)",
        rows.len()
    );
    for row in &rows {
        assert!(
            row.file.ends_with(".rs") || row.file.ends_with(".masm") || row.file.ends_with(".md"),
            "ledger row for `{}` must name a concrete file",
            row.file
        );
        let h = &row.hunk;
        let well_formed =
            h.starts_with("@@ -") && h.contains(" +") && h.match_indices("@@").count() >= 2 && {
                let inner = &h[4..h[4..].find(" @@").map(|i| i + 4).unwrap_or(h.len())];
                inner
                    .split(" +")
                    .all(|part| part.chars().all(|c| c.is_ascii_digit() || c == ','))
            };
        assert!(
            well_formed,
            "ledger row for `{}` must carry a full verbatim `@@ -a,b +c,d @@ …` hunk header; \
             got `{h}`",
            row.file
        );
        assert!(
            ["1", "2", "3", "4", "5", "6"].contains(&row.class.as_str()),
            "ledger row for `{}` hunk `{h}` must carry exactly ONE sanctioned class 1-6; got \
             `{}`",
            row.file,
            row.class
        );
    }
}

/// The sanctioned NEW test files appear as whole-file class-4 rows whose `@@ -0,0 +1,N @@`
/// header states each file's REAL current line count — the verbatim cross-check for files that
/// did not exist at the diff base.
#[test]
fn new_file_rows_are_present_and_verbatim() {
    let rows = ledger_rows();
    for (file, lines) in new_file_rows_expected() {
        let row = rows
            .iter()
            .find(|r| r.file == file)
            .unwrap_or_else(|| panic!("the ledger must carry a whole-file row for `{file}`"));
        assert_eq!(
            row.class, "4",
            "the new-file row for `{file}` must be class 4 (sanctioned new test file)"
        );
        let expected_header = format!("@@ -0,0 +1,{lines} @@");
        assert_eq!(
            row.hunk, expected_header,
            "the new-file row for `{file}` must state the file's real line count verbatim"
        );
    }
}

/// The ledger's stated totals equal what its rows actually count: total data rows, distinct
/// `@@` hunks (a hunk split across two classes shares one header), and the split count.
#[test]
fn ledger_totals_reconcile_with_the_rows() {
    let rows = ledger_rows();
    let mut by_hunk: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in &rows {
        *by_hunk
            .entry((row.file.clone(), row.hunk.clone()))
            .or_insert(0) += 1;
    }
    let distinct = by_hunk.len();
    let splits = by_hunk.values().filter(|&&n| n > 1).count();

    let totals_line = EVIDENCE
        .lines()
        .find(|l| l.starts_with("TOTAL:"))
        .expect("the ledger must end with a `TOTAL:` reconciliation line");
    let expected = format!(
        "TOTAL: {} data rows over {} distinct `@@` hunks ({} hunks split into two class rows)",
        rows.len(),
        distinct,
        splits
    );
    assert_eq!(
        totals_line, expected,
        "the ledger's stated totals must reconcile with its actual rows"
    );
}

/// The files the migration deliberately left untouched are still listed explicitly as hunk-free
/// (the wire-freeze and untouched-tripwire halves of the record).
#[test]
fn hunk_free_files_are_listed_explicitly() {
    let start = EVIDENCE.find("## 2.").expect("§2 must exist");
    let section = &EVIDENCE[start..];
    for file in [
        "crates/xusdc-encoding/tests/vectors",
        "crates/xusdc-encoding/tests/constant_parity.rs",
        "crates/xusdc-encoding/tests/basic_asset_tripwire.rs",
        "crates/xusdc-encoding/tests/wave1_recomposition.rs",
        "crates/xusdc-encoding/tests/fixtures/pinned-standards/fungible.masm",
    ] {
        assert!(
            section.contains(file),
            "the hunk-free list must name `{file}` explicitly"
        );
    }
}

/// The ledger's declared scope: every tripwire file and every ROOT_HEX-enumeration file
/// (including the deliberately hunk-free ones — a hunk appearing there without a ledger row is
/// exactly the drift this must catch), plus the sanctioned new test files.
const COVERED_FILES: [&str; 39] = [
    "crates/xusdc-encoding/tests/account_callable_surface.rs",
    "crates/xusdc-encoding/tests/account_surface_unreachable.rs",
    "crates/xusdc-encoding/tests/surface_count_prose_conformance.rs",
    "crates/xusdc-encoding/tests/s12_expiration_tx_script_allowlist.rs",
    "crates/xusdc-encoding/tests/f5_network_account_auth.rs",
    "crates/xusdc-encoding/tests/mint_root_surface.rs",
    "crates/xusdc-encoding/tests/config_note_absence.rs",
    "crates/xusdc-encoding/tests/fee_policy_provisional_pin.rs",
    "crates/xusdc-encoding/tests/migration_evidence_ledger.rs",
    "crates/xusdc-encoding/tests/support/mod.rs",
    "crates/xusdc-encoding/tests/support/mint_transport.rs",
    "crates/xusdc-encoding/tests/f5_admin_notes.rs",
    "crates/xusdc-encoding/tests/xreserve_receive_and_burn.rs",
    "crates/xusdc-encoding/tests/fixtures/pinned-standards/policy_manager.masm",
    "crates/xusdc-encoding/tests/fixtures/pinned-standards/PROVENANCE.md",
    "crates/xusdc-encoding/tests/fixtures/pinned-standards/fungible.masm",
    "crates/xusdc-encoding/tests/mint_policy_binding_e2e.rs",
    "crates/xusdc-encoding/tests/mint_scale_conformance.rs",
    "crates/xusdc-encoding/tests/xreserve_burn.rs",
    "crates/xusdc-encoding/tests/burn_policy.rs",
    "crates/xusdc-encoding/tests/masm_dual.rs",
    "crates/xusdc-encoding/tests/assembled_faucet_e2e.rs",
    "crates/xusdc-encoding/tests/pause_admin.rs",
    "crates/xusdc-encoding/tests/role_admin.rs",
    "crates/xusdc-encoding/tests/transfer_blocklist_e2e.rs",
    "crates/xusdc-encoding/tests/transfer_blocklist_semantics.rs",
    "crates/xusdc-encoding/tests/builder_api.rs",
    "crates/xusdc-encoding/tests/constant_parity.rs",
    "crates/xusdc-encoding/tests/basic_asset_tripwire.rs",
    "crates/xusdc-encoding/tests/wave1_recomposition.rs",
    "crates/xusdc-encoding/tests/vectors",
    "crates/xusdc-encoding/src/note/xreserve_admin/ownership.rs",
    "crates/xusdc-encoding/src/note/xreserve_admin/mod.rs",
    "crates/xusdc-encoding/src/note/xreserve_admin/config.rs",
    "crates/xusdc-encoding/src/note/xreserve_admin/roles.rs",
    "crates/xusdc-encoding/src/note/xreserve_admin/blocklist.rs",
    "asm/standards/xreserve/mint_policy.masm",
    "crates/xusdc-encoding/tests/mint_policy_e2e.rs",
    "crates/xusdc-encoding/tests/masm_mint_shell.rs",
];

/// The migration's diff base (the branch point of `feat/v16-now-migration`).
const DIFF_BASE: &str = "8a3fb04";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The expected `(file, full hunk header)` set, derived from git itself at test time: every `@@`
/// line of `git diff --unified=3 8a3fb04 -- <file>` over the declared scope, verbatim. A
/// sanctioned NEW file that git has no base entry for (untracked in a fresh checkout) contributes
/// its synthesized whole-file header `@@ -0,0 +1,N @@` from its real line count — byte-identical
/// to what git emits for it once intent-to-add staged.
fn expected_hunks_from_git() -> BTreeSet<(String, String)> {
    let root = repo_root();
    let mut expected = BTreeSet::new();
    for file in COVERED_FILES {
        let out = Command::new("git")
            .current_dir(&root)
            .args(["diff", "--unified=3", DIFF_BASE, "--", file])
            .output()
            .expect("git diff must be runnable from the test (the repo is the test fixture)");
        assert!(
            out.status.success(),
            "git diff {DIFF_BASE} -- {file} must succeed"
        );
        let text = String::from_utf8_lossy(&out.stdout);
        let mut any = false;
        for line in text.lines() {
            if line.starts_with("@@ ") {
                expected.insert((file.to_string(), line.to_string()));
                any = true;
            }
        }
        if !any {
            let tracked = Command::new("git")
                .current_dir(&root)
                .args(["ls-files", "--error-unmatch", file])
                .output()
                .expect("git ls-files must be runnable");
            if !tracked.status.success() {
                let n = std::fs::read_to_string(root.join(file))
                    .unwrap_or_else(|e| panic!("covered new file `{file}` must be readable: {e}"))
                    .lines()
                    .count();
                expected.insert((file.to_string(), format!("@@ -0,0 +1,{n} @@")));
            }
        }
    }
    expected
}

/// BYTE-FOR-BYTE correspondence: the ledger's distinct `(file, hunk header)` pairs equal EXACTLY
/// what git emits for the baseline diff over the declared scope — same files, same headers, same
/// coordinates, same context text. A syntactically valid but false coordinate, a stale context
/// line, a dropped tracked hunk, or a phantom row all break the set equality.
#[test]
fn ledger_rows_match_the_baseline_diff_exactly() {
    let expected = expected_hunks_from_git();
    let actual: BTreeSet<(String, String)> = ledger_rows()
        .into_iter()
        .map(|r| (r.file, r.hunk))
        .collect();

    let missing: Vec<_> = expected.difference(&actual).collect();
    let phantom: Vec<_> = actual.difference(&expected).collect();
    assert!(
        missing.is_empty() && phantom.is_empty(),
        "the ledger must correspond BYTE FOR BYTE to `git diff --unified=3 {DIFF_BASE}` over its \
         declared scope.\nHunks in the diff but MISSING from the ledger ({}): {missing:#?}\nLedger \
         rows with NO matching diff hunk ({}): {phantom:#?}",
        missing.len(),
        phantom.len(),
    );
    assert_eq!(
        actual.len(),
        expected.len(),
        "distinct (file, hunk) pair counts must match"
    );
}
