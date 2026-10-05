use std::ffi::{OsStr, OsString};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use miden_usdcx::xreserve::encoding::CircleDomain;
use xreserve_deposit_relayer::config::Config as RelayerConfig;
use xusdc_attester::config::{
    parse_faucet_account_id, Cli as AttesterCli, Config as AttesterConfig,
};

#[derive(Parser)]
#[command(
    version,
    about = "Run the USDCx deposit relayer and withdrawal attester"
)]
#[command(
    override_usage = "usdcx-bridge [COMMON OPTIONS] --relayer [RELAYER OPTIONS] --attester [ATTESTER OPTIONS]"
)]
struct Common {
    /// Miden RPC endpoint used by both services.
    #[arg(long)]
    miden_rpc_url: String,
    /// Circle API base URL used by both services.
    #[arg(long)]
    circle_url: String,
    /// USDCx faucet account ID, written as lowercase hexadecimal with a 0x prefix.
    #[arg(long)]
    faucet_account_id: String,
}

pub(crate) struct Config {
    pub(crate) relayer: RelayerConfig,
    pub(crate) attester: AttesterConfig,
}

impl Config {
    pub(crate) fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Self> {
        let args: Vec<_> = args.into_iter().collect();
        let relayer_at = marker(&args, "--relayer")?;
        let attester_at = marker(&args, "--attester")?;
        if relayer_at >= attester_at {
            bail!("--relayer must come before --attester");
        }
        let common = Common::try_parse_from(&args[..relayer_at])?;
        parse_faucet_account_id(&common.faucet_account_id)?;

        let relayer_args = &args[relayer_at + 1..attester_at];
        let attester_args = &args[attester_at + 1..];
        for group in [relayer_args, attester_args] {
            for arg in group {
                let name = arg.as_encoded_bytes().split(|byte| *byte == b'=').next();
                if matches!(
                    name,
                    Some(
                        b"--miden-rpc-url"
                            | b"--miden-node-url"
                            | b"--circle-url"
                            | b"--faucet-account-id"
                            | b"--remote-domain"
                    )
                ) {
                    bail!(
                        "{} applies to both services and cannot be overridden after --relayer or --attester",
                        arg.to_string_lossy()
                    );
                }
            }
        }

        let shared = |program: &str, rpc_flag: &str| {
            [
                program,
                rpc_flag,
                &common.miden_rpc_url,
                "--circle-url",
                &common.circle_url,
                "--faucet-account-id",
                &common.faucet_account_id,
            ]
            .map(OsString::from)
            .to_vec()
        };
        let mut relayer = shared("xreserve-deposit-relayer", "--miden-node-url");
        relayer.extend([
            OsString::from("--remote-domain"),
            OsString::from(CircleDomain::MIDEN.as_u32().to_string()),
        ]);
        relayer.extend_from_slice(relayer_args);
        let relayer =
            RelayerConfig::try_parse_from(relayer).context("invalid relayer arguments")?;
        let mut attester = shared("xusdc-attester", "--miden-rpc-url");
        attester.extend_from_slice(attester_args);
        let attester = AttesterConfig::try_from(AttesterCli::try_parse_from(attester)?)
            .context("invalid attester arguments")?;
        Ok(Self { relayer, attester })
    }
}

fn marker(args: &[OsString], marker: &str) -> Result<usize> {
    let mut positions = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg == &OsStr::new(marker));
    let position = positions
        .next()
        .map(|(index, _)| index)
        .with_context(|| format!("missing {marker} argument group"))?;
    if positions.next().is_some() {
        bail!("{marker} argument group must occur exactly once");
    }
    Ok(position)
}

pub(crate) fn print_help() -> Result<()> {
    Common::command().print_long_help()?;
    println!("\n\nSet the RPC URL, Circle URL and faucet ID before --relayer. The relayer uses Circle's Miden domain.");
    println!("\nRelayer options after --relayer:\n");
    let mut relayer = RelayerConfig::command()
        .about("Relays Circle xReserve deposit attestations to the USDCx faucet")
        .override_usage("--relayer [OPTIONS]");
    for id in [
        "miden_node_url",
        "circle_url",
        "faucet_account_id",
        "remote_domain",
    ] {
        relayer = relayer.mut_arg(id, |arg| arg.hide(true).required(false));
    }
    relayer.print_long_help()?;
    println!("\n\nAttester options after --attester:\n");
    let mut attester = AttesterCli::command()
        .about("Run the USDCx withdrawal attester")
        .override_usage("--attester [OPTIONS]");
    for id in ["miden_rpc_url", "circle_url", "faucet_account_id"] {
        attester = attester.mut_arg(id, |arg| arg.hide(true).required(false));
    }
    attester.print_long_help()?;
    println!();
    Ok(())
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
