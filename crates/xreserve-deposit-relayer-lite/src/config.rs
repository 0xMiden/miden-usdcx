use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use miden_protocol::account::AccountId;
use url::Url;

#[derive(Debug, Clone, Parser)]
#[command(name = "xreserve-deposit-relayer-lite")]
#[command(about = "Relays Circle xReserve deposit attestations to the xUSDC faucet")]
pub struct Config {
    /// The Circle xReserve API URL.
    #[arg(long)]
    pub circle_url: Url,

    /// The number of attestations in one Circle response.
    #[arg(long, value_parser = parse_page_size)]
    pub page_size: u16,

    /// The maximum duration of one Circle request.
    #[arg(long, value_parser = parse_duration)]
    pub request_timeout: Duration,

    /// The Circle domain identifier for Miden.
    #[arg(long)]
    pub remote_domain: u32,

    /// The public xUSDC faucet account, as `0x`-prefixed hex or bech32.
    #[arg(long, value_parser = parse_account_id)]
    pub faucet_account_id: AccountId,

    /// The account that creates the mint notes, as `0x`-prefixed hex or bech32.
    #[arg(long, value_parser = parse_account_id)]
    pub relayer_account_id: AccountId,

    /// The compressed SEC1 public key for the attestation signature.
    #[arg(long)]
    pub attester_public_key: String,

    /// The file that stores relay progress.
    #[arg(long)]
    pub state_file: PathBuf,
}

/// Accepts either account ID form; the network prefix of a bech32 ID is parsed and then discarded.
fn parse_account_id(value: &str) -> Result<AccountId, String> {
    AccountId::parse(value)
        .map(|(account_id, _network_id)| account_id)
        .map_err(|error| error.to_string())
}

fn parse_page_size(value: &str) -> Result<u16, String> {
    let page_size = value.parse::<u16>().map_err(|error| error.to_string())?;
    if (1..=1000).contains(&page_size) {
        Ok(page_size)
    } else {
        Err("page size must be between 1 and 1000".to_string())
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let duration = humantime::parse_duration(value).map_err(|error| error.to_string())?;
    if duration.is_zero() {
        Err("request timeout must be greater than zero".to_string())
    } else {
        Ok(duration)
    }
}
