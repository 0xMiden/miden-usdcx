//! `xusdc-genesis` — builds the genesis xUSDC faucet and its distributor offline and writes
//! their `.mac` account files. The four commands, in launch order:
//!
//! ```text
//! cargo run -p xusdc-genesis -- new-distributor --out-dir <dir> [--auth-scheme <scheme>]
//! cargo run -p xusdc-genesis -- faucet --config <config.json> [--out-dir <dir>]
//! cargo run -p xusdc-genesis -- prefund --faucet <usdcx-faucet.mac> --distributor <distributor.mac> --out-dir <dir>
//! cargo run -p xusdc-genesis -- record-nonces --faucet <usdcx-faucet.mac> --nonces <nonces.json> --out-dir <dir>
//! ```
//!
//! Exit 0 = the account files written. The id listing goes to stdout. No command overwrites an
//! existing file.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use miden_protocol::account::auth::AuthScheme;
use xusdc_genesis::accounts::{build_faucet, new_distributor, prefund_distributor, record_nonces};
use xusdc_genesis::config::{GenesisToolConfig, UsedNoncesFile};
use xusdc_genesis::output::{
    read_account_file, render_ids, render_listing, write_distributor, write_faucet,
    DISTRIBUTOR_MAC_FILE, FAUCET_MAC_FILE,
};

/// Builds the genesis xUSDC faucet and its distributor offline, writes their .mac account files,
/// and prints their ids (hex + bech32).
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generates a fresh public basic wallet with a new signing key and writes it, key included,
    /// as distributor.mac (undeployed: nonce zero, empty vault).
    NewDistributor {
        /// Where to write distributor.mac.
        #[arg(long)]
        out_dir: PathBuf,
        /// The signing scheme of the generated key.
        #[arg(long, value_enum, default_value_t = AuthSchemeArg::EcdsaK256Keccak)]
        auth_scheme: AuthSchemeArg,
    },
    /// Builds the genesis faucet from the config's faucet parameters and role-account ids and
    /// writes it as usdcx-faucet.mac (nonce one, no seed).
    Faucet {
        /// The JSON config (see the crate README for the schema).
        #[arg(long)]
        config: PathBuf,
        /// Where to write usdcx-faucet.mac; overrides the config's output_dir and is required
        /// when the config sets none.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Gives the distributor the faucet's whole recorded token supply and writes it, key
    /// included, as a genesis-ready distributor.mac (nonce one, no seed).
    Prefund {
        /// The faucet file written by `faucet`.
        #[arg(long)]
        faucet: PathBuf,
        /// The distributor file written by `new-distributor` (or exported from the client).
        #[arg(long)]
        distributor: PathBuf,
        /// Where to write the prefunded distributor.mac.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Records the Circle deposit nonces in the JSON file as consumed and writes the result as a
    /// genesis-ready usdcx-faucet.mac.
    RecordNonces {
        /// The faucet file written by `faucet`.
        #[arg(long)]
        faucet: PathBuf,
        /// The nonces JSON (see the crate README for the schema).
        #[arg(long)]
        nonces: PathBuf,
        /// Where to write the amended usdcx-faucet.mac.
        #[arg(long)]
        out_dir: PathBuf,
    },
}

/// The signing schemes `new-distributor` can generate a key for.
#[derive(Clone, Copy, ValueEnum)]
enum AuthSchemeArg {
    EcdsaK256Keccak,
    Falcon512Poseidon2,
}

impl From<AuthSchemeArg> for AuthScheme {
    fn from(scheme: AuthSchemeArg) -> Self {
        match scheme {
            AuthSchemeArg::EcdsaK256Keccak => AuthScheme::EcdsaK256Keccak,
            AuthSchemeArg::Falcon512Poseidon2 => AuthScheme::Falcon512Poseidon2,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::NewDistributor {
            out_dir,
            auth_scheme,
        } => run_new_distributor(&out_dir, auth_scheme.into()),
        Command::Faucet { config, out_dir } => run_faucet(&config, out_dir),
        Command::Prefund {
            faucet,
            distributor,
            out_dir,
        } => run_prefund(&faucet, &distributor, &out_dir),
        Command::RecordNonces {
            faucet,
            nonces,
            out_dir,
        } => run_record_nonces(&faucet, &nonces, &out_dir),
    }
}

fn run_new_distributor(out_dir: &Path, scheme: AuthScheme) -> Result<()> {
    let distributor = new_distributor(scheme).context("generating the distributor")?;
    let path = write_distributor(&distributor, out_dir)?;
    print!(
        "{}",
        render_ids(
            &format!("distributor ({DISTRIBUTOR_MAC_FILE}, {scheme} key)"),
            distributor.account.id(),
        )
    );
    println!("written to {}", path.display());
    Ok(())
}

fn run_faucet(config_path: &Path, out_dir: Option<PathBuf>) -> Result<()> {
    let config = GenesisToolConfig::load(config_path)
        .with_context(|| format!("loading the config from {}", config_path.display()))?;
    let Some(out_dir) = out_dir.or_else(|| config.output_dir.clone()) else {
        bail!("no output directory: pass --out-dir or set output_dir in the config");
    };

    let faucet = build_faucet(&config).context("building the genesis faucet")?;
    let path = write_faucet(&faucet, &out_dir)?;
    print!("{}", render_listing(&faucet, &config));
    println!("written to {}", path.display());
    Ok(())
}

fn run_prefund(faucet_path: &Path, distributor_path: &Path, out_dir: &Path) -> Result<()> {
    let faucet = read_account_file(faucet_path)?.account;
    let distributor = read_account_file(distributor_path)?;
    let prefunded =
        prefund_distributor(&faucet, &distributor).context("prefunding the distributor")?;
    let path = write_distributor(&prefunded, out_dir)?;
    print!(
        "{}",
        render_ids(
            &format!("distributor ({DISTRIBUTOR_MAC_FILE}, prefunded)"),
            prefunded.account.id(),
        )
    );
    println!(
        "  balance: {} base units of the faucet {}",
        prefunded
            .account
            .vault()
            .get_balance(miden_protocol::asset::AssetId::new_fungible(faucet.id()))
            .context("reading the prefunded balance")?
            .as_u64(),
        faucet.id().to_hex(),
    );
    println!("written to {}", path.display());
    Ok(())
}

fn run_record_nonces(faucet_path: &Path, nonces_path: &Path, out_dir: &Path) -> Result<()> {
    let faucet = read_account_file(faucet_path)?.account;
    let nonces = UsedNoncesFile::load(nonces_path)
        .with_context(|| format!("loading the nonces from {}", nonces_path.display()))?
        .used_nonces;
    if nonces.is_empty() {
        bail!("{} lists no nonces", nonces_path.display());
    }

    let recorded = record_nonces(&faucet, &nonces).context("recording the consumed nonces")?;
    let path = write_faucet(&recorded, out_dir)?;
    print!(
        "{}",
        render_ids(
            &format!(
                "usdcx-faucet ({FAUCET_MAC_FILE}, {} nonces recorded)",
                nonces.len()
            ),
            recorded.id(),
        )
    );
    println!("written to {}", path.display());
    Ok(())
}
