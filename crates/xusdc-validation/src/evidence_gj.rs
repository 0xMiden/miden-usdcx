//! Serializes transaction observations, check results, and the node-log manifest.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::config::RunConfig;
use crate::evidence::{log_manifest, LogManifestEntry};
use crate::observations_gj::RowsGjObservations;

#[derive(Serialize)]
pub struct GjRowVerdict {
    pub row: String,
    pub pass: bool,
    /// The full failure chain when `pass` is false.
    pub detail: Option<String>,
}

#[derive(Serialize)]
pub struct GjRunEvidence {
    pub main_commit: String,
    pub node_version: String,
    pub client_crate: String,
    pub protocol_rev: String,
    pub rpc_port: u16,
    pub validator_port: u16,
    pub ntx_builder_port: u16,
    pub tx_prover_port: u16,
    pub faucet_id: String,
    pub holder_id: String,
    /// The full observation record (every burn read-back + the F7 RIV evidence).
    pub observations: RowsGjObservations,
    /// Per-row PASS/FAIL verdicts.
    pub rows: Vec<GjRowVerdict>,
    /// Archived node logs (path + size + ERROR/WARN counts).
    pub logs: Vec<LogManifestEntry>,
}

/// Writes `<run_root>/evidence-gj.json` from the observations + per-row verdicts.
pub fn write_gj_evidence(
    cfg: &RunConfig,
    obs: &RowsGjObservations,
    verdicts: &[(&str, Result<()>)],
) -> Result<PathBuf> {
    let rows = verdicts
        .iter()
        .map(|(row, r)| GjRowVerdict {
            row: (*row).to_string(),
            pass: r.is_ok(),
            detail: r.as_ref().err().map(|e| format!("{e:#}")),
        })
        .collect();
    let evidence = GjRunEvidence {
        main_commit: obs.main_commit.clone(),
        node_version: "miden-node 0.15.1 (installed binaries)".to_string(),
        client_crate: "miden-client =0.16.0-alpha.1 (crates.io)".to_string(),
        protocol_rev: "0xMiden/protocol crates.io =0.16.0-alpha.4".to_string(),
        rpc_port: cfg.stack.rpc_port,
        validator_port: cfg.stack.validator_port,
        ntx_builder_port: cfg.stack.ntx_builder_port,
        tx_prover_port: cfg.stack.tx_prover_port,
        faucet_id: obs.faucet_id.clone(),
        holder_id: obs.holder_id.clone(),
        observations: obs.clone(),
        rows,
        logs: log_manifest(&cfg.stack.log_dir()),
    };
    let path = cfg.stack.run_root.join("evidence-gj.json");
    fs::create_dir_all(&cfg.stack.run_root).context("creating the run root")?;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&evidence).context("serializing rows-G/H/I/J evidence")?,
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}
