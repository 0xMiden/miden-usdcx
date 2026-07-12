//! Manual stack control for supervised runs: `up` boots a fresh local stack and leaves it
//! running (pids recorded under the run root); `down <run-root>` stops a kept stack.
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv_stack -- up [run-label]
//! cargo run -p xusdc-validation --bin lnv_stack -- down <run-root>
//! ```

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use xusdc_validation::config::{repo_root, StackConfig};
use xusdc_validation::stack::NodeStack;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => {
            let label = args.get(1).cloned().unwrap_or_else(|| {
                format!(
                    "manual-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("system clock after the epoch")
                        .as_secs()
                )
            });
            let run_root = repo_root().join("local-node-data").join("lnv1").join(label);
            let config = StackConfig::new(run_root.clone());
            let mut stack = NodeStack::bootstrap_and_start(&config)?;
            stack.keep_on_drop();
            let pids: Vec<String> = stack
                .services()
                .iter()
                .map(|s| format!("{} {}", s.name, s.child.id()))
                .collect();
            fs::write(run_root.join("stack.pids"), pids.join("\n") + "\n")
                .context("writing the pidfile")?;
            println!(
                "stack UP at {} (rpc {})",
                run_root.display(),
                config.rpc_url()
            );
            println!(
                "stop with: cargo run -p xusdc-validation --bin lnv_stack -- down {}",
                run_root.display()
            );
            Ok(())
        }
        Some("down") => {
            let run_root = PathBuf::from(args.get(1).context("usage: lnv_stack down <run-root>")?);
            let pidfile = run_root.join("stack.pids");
            let pids = fs::read_to_string(&pidfile)
                .with_context(|| format!("reading {}", pidfile.display()))?;
            // Reverse start order: sequencer first, prover last.
            for line in pids.lines().rev() {
                if let Some((name, pid)) = line.split_once(' ') {
                    let status = std::process::Command::new("kill").arg(pid).status();
                    println!("kill {name} ({pid}): {status:?}");
                }
            }
            fs::remove_file(&pidfile).ok();
            Ok(())
        }
        _ => bail!("usage: lnv_stack up [label] | lnv_stack down <run-root>"),
    }
}
