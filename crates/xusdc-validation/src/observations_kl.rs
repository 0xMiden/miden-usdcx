//! Observations for automatic note execution and node-log checks.
//! The full run combines these with deployment, administration, mint, and burn observations.

use serde::Serialize;

use crate::observations::RowsAbObservations;
use crate::observations_cf::RowsCfObservations;
use crate::observations_de::RowsDeObservations;
use crate::observations_gj::RowsGjObservations;

/// One path-N (ntx-builder) auto-executed faucet consumption the consolidated run observed — the
/// sub-run drivers emitted the routed allowlisted note and polled the COMMITTED effect back from
/// the node, so each entry is on-chain evidence that the ntx-builder executed the consumption.
#[derive(Debug, Clone, Serialize)]
pub struct PathNCommit {
    /// The lifecycle op ("mint empty-hookData", "burn two-block", "set_attester(A, enabled=1)", …).
    pub op: String,
    /// The consumption kind: `"mint"` | `"burn"` | `"admin"`.
    pub kind: String,
    /// The block the commit was pinned at, where the sub-run observations record one (mint = the
    /// emitted P2ID note's inclusion block; burn = the consume block; admin ops record none).
    pub commit_block: Option<u32>,
    /// The committed on-chain effect read back from the NODE ("token_supply 0 → 100", …).
    pub effect: String,
}

/// **Row K** — the ntx-builder liveness verdict + evidence (the F5-deferred check, spec row K).
#[derive(Debug, Clone, Serialize)]
pub struct RowKObservations {
    /// The verdict: the running ntx-builder AUTO-executes routed+allowlisted consumptions against
    /// the network-account faucet (requires observed mint AND burn path-N commits plus node-side
    /// execution markers).
    pub auto_executes: bool,
    /// Every path-N commit the consolidated run observed (the on-chain half of the evidence).
    pub commits: Vec<PathNCommit>,
    /// `ntx-builder.log` execution-marker lines (ANSI-stripped, verbatim) — the node-side half.
    pub ntx_log_evidence: Vec<String>,
    /// When `auto_executes` is false: the exact cause (missing evidence + version/config context).
    pub no_cause: Option<String>,
    /// The deployment-posture statement, recorded EITHER way (the spec's "relayer executes
    /// client-side (path C)" statement when the verdict is NO).
    pub posture: String,
}

/// One scanned service log (the row-L archive manifest entry; level counts are token-based).
#[derive(Debug, Clone, Serialize)]
pub struct ScannedLog {
    /// The service name (the log's file stem: `sequencer`, `ntx-builder`, …).
    pub service: String,
    /// The archived log's path (under the gitignored run root).
    pub path: String,
    /// File size in bytes (a required service log must be non-empty).
    pub bytes: u64,
    /// Total lines scanned.
    pub lines: usize,
    /// Lines whose tracing level TOKEN is `ERROR` (ANSI-stripped token equality, not substring).
    pub error_lines: usize,
    /// Lines whose tracing level TOKEN is `WARN`.
    pub warn_lines: usize,
}

/// A log line that FAILS row L (an unexpected error, a panic, or an untriaged warning).
#[derive(Debug, Clone, Serialize)]
pub struct FlaggedLine {
    /// The service whose log carries the line.
    pub service: String,
    /// The line, ANSI-stripped, verbatim.
    pub line: String,
}

/// A non-clean log line matched to an expected pattern — triaged + explained, so it does not fail
/// row L (it is the recorded node-side face of a deliberate negative or of stack lifecycle noise).
#[derive(Debug, Clone, Serialize)]
pub struct TriagedLine {
    /// The service whose log carries the line.
    pub service: String,
    /// The line, ANSI-stripped, verbatim.
    pub line: String,
    /// The expected pattern that matched.
    pub pattern: String,
    /// WHY the line is expected (which deliberate negative / lifecycle step explains it).
    pub explanation: String,
}

/// **Row L** — the clean-logs scan over every archived service log of the consolidated run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RowLObservations {
    /// Every scanned `*.log` under the run's log dir (all four services MUST be present).
    pub scanned: Vec<ScannedLog>,
    /// ERROR-level lines matching NO expected pattern — must be empty for a PASS.
    pub unexpected_errors: Vec<FlaggedLine>,
    /// Panic lines (any level) — must be empty for a PASS.
    pub panics: Vec<FlaggedLine>,
    /// ERROR-level lines triaged against the expected-pattern table (each explained).
    pub expected_errors: Vec<TriagedLine>,
    /// WARN-level lines triaged against the expected-pattern table (each explained).
    pub triaged_warnings: Vec<TriagedLine>,
    /// WARN-level lines matching NO expected pattern — must be empty for a PASS (an unexplained
    /// warning is an untriaged warning; triage means classify + explain, not ignore).
    pub untriaged_warnings: Vec<FlaggedLine>,
}

/// Combined observations from a single node run.
#[derive(Debug)]
pub struct FullMatrixObservations {
    /// Rows A/B (deploy + recognize; `identifier_init` init-once).
    pub ab: RowsAbObservations,
    /// Rows C/F (admin suite; F5 auth boundary).
    pub cf: RowsCfObservations,
    /// Rows D/E (mint happy paths; mint negatives).
    pub de: RowsDeObservations,
    /// Rows G/H/I/J (burn two-block; F7 same-block RIV; burn negatives; conservation).
    pub gj: RowsGjObservations,
    /// Row K (ntx-builder liveness), derived from the sub-run observations + the ntx-builder log.
    pub k: RowKObservations,
    /// Row L (clean logs), scanned from the run's archived service logs.
    pub l: RowLObservations,
}
