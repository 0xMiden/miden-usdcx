//! LNV-5 — THE consolidated §11.2 full-matrix gate run: rows A–L, one command, one fresh node.
//!
//! Boots ONE fresh local stack and composes the LNV-1..4 drivers on it in matrix order (deploy →
//! admin → mint → burn → conservation), then settles row K (ntx-builder liveness / path N) and
//! row L (clean logs) from that single run. Writes the generated **VALIDATION RECORD**
//! (`VALIDATION-RECORD-LNV5.md`), the three evidence packets (`LNV5-F7-EVIDENCE-PACKET.md`,
//! `LNV5-NTX-LIVENESS-VERDICT.md`, `LNV5-BURN-GETNOTESBYID-CAPTURE.hex`) into the crate dir, and
//! the machine evidence (`evidence-lnv5.json`) + archived logs under the gitignored run root —
//! then tears the stack down. Exit code 0 = every row's assertion suite PASSED.
//!
//! **The gate itself is a HUMAN decision (§11.2): this binary never declares it.** A human
//! reproduces from a fresh node, inspects the record + logs + packets, and declares GATE PASS /
//! GATE FAILED. **Validator-not-fixer:** a failing row is a SURFACED finding, never a hot-fix.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv5_full_matrix [-- --keep-stack]
//! ```

use std::path::Path;

use anyhow::Result;
use xusdc_validation::config::{repo_root, RunConfig};
use xusdc_validation::record::{
    any_failed, full_matrix_outcomes, validate_row_outcomes, write_lnv5_artifacts, RecordContext,
};
use xusdc_validation::rows_kl::run_full_matrix;

#[tokio::main]
async fn main() -> Result<()> {
    let keep_stack = std::env::args().any(|a| a == "--keep-stack");
    let label = format!(
        "run-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after the epoch")
            .as_secs()
    );
    let mut cfg = RunConfig::fresh_under(&repo_root(), "lnv5", &label);
    cfg.keep_stack = keep_stack;

    println!(
        "LNV-5 full matrix (rows A–L) — run root: {}",
        cfg.stack.run_root.display()
    );
    let obs = run_full_matrix(&cfg).await?;

    let outcomes = full_matrix_outcomes(&obs);
    validate_row_outcomes(&outcomes)?;
    let ctx = RecordContext::from_run(&cfg, &obs);
    let artifacts = write_lnv5_artifacts(
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &cfg,
        &ctx,
        &obs,
        &outcomes,
    )?;

    println!("record:   {}", artifacts.record.display());
    println!("F7:       {}", artifacts.f7_packet.display());
    println!("ntx:      {}", artifacts.ntx_verdict.display());
    println!("capture:  {}", artifacts.capture.display());
    println!("evidence: {}", artifacts.evidence_json.display());
    for o in &outcomes {
        match &o.detail {
            None => println!("  row {} ({}): PASS", o.row, o.title),
            Some(detail) => println!("  row {} ({}): FAIL\n    {detail}", o.row, o.title),
        }
    }

    if any_failed(&outcomes) {
        // Validator-not-fixer: a failing row is a SURFACED finding — report loudly, never patch.
        anyhow::bail!(
            "LNV-5 full matrix: at least one row FAILED — see the record at {}",
            artifacts.record.display()
        );
    }
    println!(
        "LNV-5 full matrix: ALL 12 ROWS PASS — record + packets submitted for HUMAN gate \
         acceptance (§11.2; the gate verdict is a human decision)"
    );
    Ok(())
}
