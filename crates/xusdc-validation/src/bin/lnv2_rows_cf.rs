//! Runs administration and authorization checks on a fresh local node.
//! Writes evidence and stops the node unless `--keep-stack` is supplied.

use anyhow::Result;
use xusdc_validation::assertions_cf::{
    assert_c1, assert_c2, assert_c3, assert_c4, assert_c5, assert_c6, assert_f,
};
use xusdc_validation::config::{repo_root, RunConfig};
use xusdc_validation::evidence_cf::write_cf_evidence;
use xusdc_validation::rows_cf::run_rows_cf;

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
        "LNV-2 rows C/F — run root: {}",
        cfg.stack.run_root.display()
    );
    let obs = run_rows_cf(&cfg).await?;

    let verdicts: Vec<(&str, Result<()>)> = vec![
        ("C1 set_attester + rotation", assert_c1(&obs.c1)),
        ("C2 set_min_burn_size", assert_c2(&obs.c2)),
        ("C3 set_max_supply", assert_c3(&obs.c3)),
        ("C4 pause/unpause (F6)", assert_c4(&obs.c4)),
        ("C5 role rotation", assert_c5(&obs.c5)),
        ("C6 non-authorized negatives", assert_c6(&obs.c6)),
        ("F auth boundary", assert_f(&obs.f)),
    ];

    let evidence_path = write_cf_evidence(&cfg, &obs, &verdicts)?;
    println!("faucet:   {}", obs.faucet_id);
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
            "LNV-2 rows C/F: at least one row FAILED — see evidence at {}",
            evidence_path.display()
        );
    }
    println!("LNV-2 rows C/F: ALL ROWS PASS");
    Ok(())
}
