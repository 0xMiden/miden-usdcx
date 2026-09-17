//! `xusdc-genesis` — builds the genesis xUSDC faucet offline and writes its `.mac` account
//! file.
//!
//! ```text
//! cargo run -p xusdc-genesis -- --config <config.json> [--out-dir <dir>]
//! ```
//!
//! Exit 0 = the faucet built and its account file written. The id listing goes to stdout.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use xusdc_genesis::accounts::build_faucet;
use xusdc_genesis::config::GenesisToolConfig;
use xusdc_genesis::output::{render_listing, write_outputs};

struct Args {
    config: PathBuf,
    out_dir: Option<PathBuf>,
}

fn parse_args() -> Result<Option<Args>> {
    let mut config: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(PathBuf::from(it.next().context("--config needs a path")?));
            }
            "--out-dir" => {
                out_dir = Some(PathBuf::from(it.next().context("--out-dir needs a path")?));
            }
            "-h" | "--help" => {
                println!(
                    "xusdc-genesis — build the genesis xUSDC faucet offline\n\n\
                     Builds the genesis xUSDC faucet from the faucet parameters and the six\n\
                     role-account ids (hex or bech32) in the config file, then writes the\n\
                     faucet's .mac account file — the only file output — printing the ids\n\
                     (hex + bech32) to stdout.\n\n\
                     --config <PATH>    the JSON config (see the crate README for the schema)\n\
                     --out-dir <DIR>    where to write the outputs (overrides the config's\n\
                                        output_dir; required when the config sets none)\n"
                );
                return Ok(None);
            }
            other => bail!("unknown argument '{other}' (see --help)"),
        }
    }

    let config = config.context("--config is required (see --help)")?;
    Ok(Some(Args { config, out_dir }))
}

fn main() -> Result<()> {
    let Some(args) = parse_args()? else {
        return Ok(());
    };

    let config = GenesisToolConfig::load(&args.config)
        .with_context(|| format!("loading the config from {}", args.config.display()))?;
    let Some(out_dir) = args.out_dir.or_else(|| config.output_dir.clone()) else {
        bail!("no output directory: pass --out-dir or set output_dir in the config");
    };

    let faucet = build_faucet(&config).context("building the genesis faucet")?;
    write_outputs(&faucet, &out_dir)
        .with_context(|| format!("writing the outputs to {}", out_dir.display()))?;

    print!("{}", render_listing(&faucet, &config));
    println!("outputs written to {}", out_dir.display());
    Ok(())
}
