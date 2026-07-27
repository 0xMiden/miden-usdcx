//! LNV-1 deploy smoke + rows A/B: the one-command gate run for this slice.
//!
//! Boots a FRESH local stack, deploys the production faucet, drives `identifier_init` (init +
//! init-once reject), applies the row-A/B assertion suite, writes `evidence.json`, and tears the
//! stack down. Exit code 0 = both rows PASS.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv1_rows_ab [-- --keep-stack]
//! ```

use anyhow::Result;
use xusdc_validation::assertions::{assert_row_a, assert_row_b};
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

    println!(
        "LNV-1 rows A/B — run root: {}",
        cfg.stack.run_root.display()
    );
    let obs = run_rows_ab(&cfg).await?;

    let row_a = assert_row_a(&obs);
    let row_b = assert_row_b(&obs);
    let evidence_path = write_evidence(&cfg, &obs, &row_a, &row_b)?;

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
    match &row_b {
        Ok(()) => println!("row B (identifier_init init-once): PASS"),
        Err(e) => println!("row B (identifier_init init-once): FAIL\n  {e:#}"),
    }

    if row_a.is_err() || row_b.is_err() {
        // Validator-not-fixer: a failing row is a SURFACED finding — report loudly, never patch.
        anyhow::bail!(
            "LNV-1 rows A/B: at least one row FAILED — see evidence at {}",
            evidence_path.display()
        );
    }
    Ok(())
}
