//! Machine-readable run evidence.
//!
//! One JSON document per run under `<run_root>/evidence.json` (gitignored with the rest of the
//! run root): the pins, the observations (ids, blocks, errors), the per-row verdicts, and a
//! manifest of the archived node logs (path + size + ERROR/WARN counts). The validation record
//! quotes from this file; the full logs stay on disk.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::config::RunConfig;
use crate::observations::RowsAbObservations;

#[derive(Serialize)]
pub struct LogManifestEntry {
    pub service: String,
    pub path: String,
    pub bytes: u64,
    pub error_lines: usize,
    pub warn_lines: usize,
}

#[derive(Serialize)]
pub struct RowVerdict {
    pub row: String,
    pub pass: bool,
    /// The full failure chain when `pass` is false.
    pub detail: Option<String>,
}

#[derive(Serialize)]
pub struct RunEvidence {
    /// Pins: the `main` commit the harness was built from + the node/client pins.
    pub main_commit: String,
    pub node_version: String,
    pub client_crate: String,
    pub protocol_rev: String,
    /// Stack wiring (ports) for reproduction.
    pub rpc_port: u16,
    pub validator_port: u16,
    pub ntx_builder_port: u16,
    pub tx_prover_port: u16,
    /// Observations.
    pub faucet_id: String,
    pub owner_id: String,
    pub deploy_tx_id: String,
    pub deploy_block: u32,
    /// Verdicts.
    pub rows: Vec<RowVerdict>,
    /// Archived logs.
    pub logs: Vec<LogManifestEntry>,
}

/// Counts ERROR/WARN lines in a service log (case-sensitive level tokens as tracing emits them).
fn level_counts(path: &Path) -> (usize, usize) {
    match fs::read_to_string(path) {
        Ok(text) => {
            let errors = text.lines().filter(|l| l.contains("ERROR")).count();
            let warns = text.lines().filter(|l| l.contains("WARN")).count();
            (errors, warns)
        }
        Err(_) => (0, 0),
    }
}

/// Builds the log manifest for every `*.log` under the run's log dir.
pub fn log_manifest(log_dir: &Path) -> Vec<LogManifestEntry> {
    let mut entries = Vec::new();
    if let Ok(dir) = fs::read_dir(log_dir) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("log") {
                let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let (error_lines, warn_lines) = level_counts(&path);
                entries.push(LogManifestEntry {
                    service: path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    path: path.display().to_string(),
                    bytes,
                    error_lines,
                    warn_lines,
                });
            }
        }
    }
    entries.sort_by(|a, b| a.service.cmp(&b.service));
    entries
}

/// Writes `<run_root>/evidence.json` from the observations + per-row verdicts.
pub fn write_evidence(
    cfg: &RunConfig,
    obs: &RowsAbObservations,
    row_a: &Result<()>,
) -> Result<PathBuf> {
    let verdict = |row: &str, r: &Result<()>| RowVerdict {
        row: row.to_string(),
        pass: r.is_ok(),
        detail: r.as_ref().err().map(|e| format!("{e:#}")),
    };
    let evidence = RunEvidence {
        main_commit: obs.main_commit.clone(),
        node_version: "miden-node v16 (four-service stack via start-test-node.sh)".to_string(),
        client_crate: "miden-client =0.16.0-rc.1 (crates.io)".to_string(),
        protocol_rev: "0xMiden/protocol crates.io =0.16.0-rc.4".to_string(),
        rpc_port: cfg.stack.rpc_port,
        validator_port: cfg.stack.validator_port,
        ntx_builder_port: cfg.stack.ntx_builder_port,
        tx_prover_port: cfg.stack.tx_prover_port,
        faucet_id: obs.faucet_id.to_string(),
        owner_id: obs.owner_id.to_string(),
        deploy_tx_id: obs.deploy_tx_id.clone(),
        deploy_block: obs.deploy_block,
        rows: vec![verdict("A", row_a)],
        logs: log_manifest(&cfg.stack.log_dir()),
    };
    let path = cfg.stack.run_root.join("evidence.json");
    fs::create_dir_all(&cfg.stack.run_root).context("creating the run root")?;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&evidence).context("serializing evidence")?,
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
