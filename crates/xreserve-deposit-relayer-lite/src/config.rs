use std::path::PathBuf;

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

    /// The Circle domain identifier for Miden.
    #[arg(long)]
    pub remote_domain: u32,

    /// The public xUSDC faucet account.
    #[arg(long, value_parser = parse_account_id)]
    pub faucet_account_id: AccountId,

    /// The account that creates the mint notes.
    #[arg(long, value_parser = parse_account_id)]
    pub relayer_account_id: AccountId,

    /// The compressed SEC1 public key for the attestation signature.
    #[arg(long)]
    pub attester_public_key: String,

    /// The file that stores relay progress.
    #[arg(long)]
    pub state_file: PathBuf,
}

fn parse_account_id(value: &str) -> Result<AccountId, String> {
    AccountId::parse(value)
        .map(|(account_id, _network_id)| account_id)
        .map_err(|error| error.to_string())
}
