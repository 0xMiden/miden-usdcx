//! Runs the full validation matrix on one fresh node and writes results and evidence.
//! A zero exit status means all assertions passed; final acceptance requires human review.

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
