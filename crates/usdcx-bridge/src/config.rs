use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser};
use miden_protocol::account::AccountId;
use miden_usdcx::xreserve::encoding::CircleDomain;
use xreserve_deposit_relayer::circle::PageSize;
use xreserve_deposit_relayer::config::{parse_account_id, Config as RelayerConfig};
use xreserve_deposit_relayer::miden::ExpirationDelta;
use xreserve_deposit_relayer::mint::AttesterPublicKey;
use xusdc_attester::config::{Cli as AttesterCli, Config as AttesterConfig};

// The attester's options keep their own names, and its Miden RPC URL, Circle URL and faucet
// account ID are also the relayer's. The relayer's remaining options carry a `--relayer-` prefix.
#[derive(Parser)]
#[command(
    version,
    about = "Run the USDCx deposit relayer and withdrawal attester"
)]
pub(crate) struct Cli {
    #[command(flatten)]
    attester: AttesterCli,
    #[command(flatten, next_help_heading = "Deposit relayer options")]
    relayer: RelayerArgs,
}

#[derive(Args)]
struct RelayerArgs {
    /// The number of deposit attestations in one Circle response, between 1 and 1000. A page is
    /// minted as a single transaction.
    #[arg(long)]
    relayer_page_size: PageSize,

    /// The maximum duration of one Circle request made by the relayer (for example, "30s").
    #[arg(long, value_parser = humantime::parse_duration)]
    relayer_request_timeout: Duration,

    /// How long the relayer waits once it has caught up with Circle's deposit feed.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "5s")]
    relayer_poll_interval: Duration,

    /// The directory holding the relayer's Miden client state: its store, and the keystore the
    /// relayer account's signing key is read from.
    #[arg(long)]
    relayer_miden_data_dir: PathBuf,

    /// How many blocks a submitted mint transaction may still be included in before the relayer
    /// stops waiting and retries the page.
    #[arg(long, default_value = "64")]
    relayer_expiration_delta: ExpirationDelta,

    /// The account that creates the mint notes, as `0x`-prefixed hex or bech32.
    #[arg(long, value_parser = parse_account_id)]
    relayer_account_id: AccountId,

    /// The compressed SEC1 public key Circle signs deposit attestations with, as hex with an
    /// optional `0x` prefix.
    #[arg(long)]
    relayer_attester_public_key: AttesterPublicKey,

    /// The file that stores the relayer's progress.
    #[arg(long)]
    relayer_state_file: PathBuf,
}

pub(crate) struct Config {
    pub(crate) relayer: RelayerConfig,
    pub(crate) attester: AttesterConfig,
}

impl TryFrom<Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self> {
        let attester =
            AttesterConfig::try_from(cli.attester).context("invalid attester configuration")?;
        let relayer = RelayerConfig {
            circle_url: attester.circle_api_base_url().clone(),
            page_size: cli.relayer.relayer_page_size,
            request_timeout: cli.relayer.relayer_request_timeout,
            poll_interval: cli.relayer.relayer_poll_interval,
            remote_domain: CircleDomain::MIDEN,
            miden_node_url: attester
                .miden_rpc_url()
                .to_string()
                .parse()
                .context("Miden RPC URL is invalid")?,
            miden_data_dir: cli.relayer.relayer_miden_data_dir,
            expiration_delta: cli.relayer.relayer_expiration_delta,
            faucet_account_id: attester.faucet_account_id(),
            relayer_account_id: cli.relayer.relayer_account_id,
            attester_public_key: cli.relayer.relayer_attester_public_key,
            state_file: cli.relayer.relayer_state_file,
        };
        Ok(Self { relayer, attester })
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
