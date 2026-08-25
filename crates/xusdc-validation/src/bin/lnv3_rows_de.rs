//! LNV-3 mint-lifecycle gate: the one-command rows-D/E run.
//!
//! Boots a FRESH local stack, deploys the production faucet (domain config build-seeded to match
//! the mint vector),
//! allowlists attester A, drives the whole rows-D (mint happy path) + row-E (mint negatives) arc —
//! the happy-path mints committed via the ntx-builder (path N) with the recipient consuming each
//! emitted P2ID note; every negative proven by a client-side kernel trap + committed-state read-back
//! — applies the rows-D/E assertion suite, writes `evidence-de.json`, and tears the stack down.
//! Exit code 0 = every row PASSES.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv3_rows_de [-- --keep-stack]
//! ```

use anyhow::Result;
use xusdc_validation::assertions_de::{assert_d, assert_e};
use xusdc_validation::config::{repo_root, RunConfig};
use xusdc_validation::evidence_de::write_de_evidence;
use xusdc_validation::rows_de::run_rows_de;

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
        "LNV-3 rows D/E — run root: {}",
        cfg.stack.run_root.display()
    );
    let obs = run_rows_de(&cfg).await?;

    let verdicts: Vec<(&str, Result<()>)> = vec![
        ("D mint happy path", assert_d(&obs.d)),
        ("E mint negatives", assert_e(&obs.e)),
    ];

    let evidence_path = write_de_evidence(&cfg, &obs, &verdicts)?;
    println!("faucet:    {}", obs.faucet_id);
    println!("recipient: {}", obs.recipient_id);
    println!("evidence:  {}", evidence_path.display());

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
            "LNV-3 rows D/E: at least one row FAILED — see evidence at {}",
            evidence_path.display()
        );
    }
    println!("LNV-3 rows D/E: ALL ROWS PASS");
    Ok(())
}
