//! Runs burns, discovery, and conservation checks on a fresh local node.
//! Writes evidence and stops the node unless `--keep-stack` is supplied.

use anyhow::Result;
use xusdc_validation::assertions_gj::{assert_g, assert_h, assert_i, assert_j};
use xusdc_validation::config::{repo_root, RunConfig};
use xusdc_validation::evidence_gj::write_gj_evidence;
use xusdc_validation::rows_gj::run_rows_gj;

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
    let mut cfg = RunConfig::fresh(&repo_root(), &label);
    cfg.keep_stack = keep_stack;

    println!(
        "LNV-4 rows G/H/I/J — run root: {}",
        cfg.stack.run_root.display()
    );
    let obs = run_rows_gj(&cfg).await?;

    let verdicts: Vec<(&str, Result<()>)> = vec![
        ("G burn two-block (Circle read-path)", assert_g(&obs.g)),
        ("H burn same-block (F7 RIV evidence)", assert_h(&obs.h)),
        ("I burn negatives", assert_i(&obs.i)),
        ("J conservation ledger", assert_j(&obs.j)),
    ];

    let evidence_path = write_gj_evidence(&cfg, &obs, &verdicts)?;
    println!("faucet:   {}", obs.faucet_id);
    println!("holder:   {}", obs.holder_id);
    println!("evidence: {}", evidence_path.display());

    let mut failed = false;
    for (row, r) in &verdicts {
        match r {
            Ok(()) => println!("  {row}: PASS"),
            Err(e) => {
                failed = true;
                println!("  {row}: FAIL\n    {e:#}");
            }
        }
    }

    if failed {
        // Validator-not-fixer: a failing row is a SURFACED finding — report loudly, never patch.
        anyhow::bail!(
            "LNV-4 rows G/H/I/J: at least one row FAILED — see evidence at {}",
            evidence_path.display()
        );
    }
    println!("LNV-4 rows G/H/I/J: ALL ROWS PASS");
    Ok(())
}
