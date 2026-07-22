//! Manual v16-node control for supervised runs: `up` boots a fresh v16 node (via the client repo's
//! `start-test-node.sh`) and leaves it running; `down` stops it (via `stop-test-node.sh`).
//!
//! ```text
//! cargo run -p xusdc-validation --bin lnv_stack -- up [run-label]
//! cargo run -p xusdc-validation --bin lnv_stack -- down
//! ```

use anyhow::{bail, Result};
use xusdc_validation::config::{repo_root, StackConfig};
use xusdc_validation::stack::{stop_node, NodeStack};

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
            println!("v16 node UP (rpc {})", config.rpc_url());
            println!("  logs: {}", config.log_dir().display());
            for s in stack.services() {
                println!("  service {}: {}", s.name, s.log_path.display());
            }
            println!("stop with: cargo run -p xusdc-validation --bin lnv_stack -- down");
            Ok(())
        }
        Some("down") => {
            // The node is managed by the client repo's script (which owns its pids); delegate.
            let config =
                StackConfig::new(repo_root().join("local-node-data").join("lnv1").join("_"));
            stop_node(&config)?;
            println!("v16 node stopped");
            Ok(())
        }
        _ => bail!("usage: lnv_stack up [label] | lnv_stack down"),
    }
}
