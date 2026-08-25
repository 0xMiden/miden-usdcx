//! LNV-1 deploy smoke + row A: the one-command gate run for this slice.
//!
//! Boots a FRESH local stack, deploys the production faucet, applies the row-A assertion suite,
//! writes `evidence.json`, and tears the stack down. Exit code 0 = the row PASSES.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv1_rows_ab [-- --keep-stack]
//! ```

use anyhow::Result;
use xusdc_validation::assertions::assert_row_a;
use xusdc_validation::config::{repo_root, RunConfig};
use xusdc_validation::evidence::write_evidence;
use xusdc_validation::rows_ab::run_rows_ab;

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

    println!("LNV-1 row A — run root: {}", cfg.stack.run_root.display());
    let obs = run_rows_ab(&cfg).await?;

    let row_a = assert_row_a(&obs);
    let evidence_path = write_evidence(&cfg, &obs, &row_a)?;

    println!("faucet:    {}", obs.faucet_id);
    println!(
        "deploy tx: {} (block {})",
        obs.deploy_tx_id, obs.deploy_block
    );
    println!("evidence:  {}", evidence_path.display());
    match &row_a {
        Ok(()) => println!("row A (deploy + recognize): PASS"),
        Err(e) => println!("row A (deploy + recognize): FAIL\n  {e:#}"),
    }
    if row_a.is_err() {
        // Validator-not-fixer: a failing row is a SURFACED finding — report loudly, never patch.
        anyhow::bail!(
            "LNV-1 row A FAILED — see evidence at {}",
            evidence_path.display()
        );
    }
    Ok(())
}
