//! LNV-4 burn-lifecycle gate: the one-command rows-G/H/I/J run.
//!
//! Boots a FRESH local stack, deploys the production faucet (domain config build-seeded to match
//! the mint vector, identifier_init as the first admin note),
//! allowlists attester A, sets a minimum burn size, mints to the holder, then drives the whole
//! burn arc — the Row-G two-block burn committed via the ntx-builder (path N) with the holder
//! creating the production `XReserveBurnNote`; the Row-H F7 same-block-erasure RIV captured
//! client-side (evidence only, no acceptability decision); the Row-I negatives proven by client-side
//! kernel traps + committed-state read-backs; the Row-J conservation ledger — applies the
//! rows-G/H/I/J assertion suite, writes `evidence-gj.json` (incl. the byte-exact `GetNotesById`
//! capture), and tears the stack down. Exit code 0 = every row PASSES.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv4_rows_gj [-- --keep-stack]
//! ```

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
