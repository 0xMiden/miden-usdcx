use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use miden_protocol::account::AccountId;
use url::Url;

use crate::circle::{PageSize, RemoteDomain};
use crate::mint::AttesterPublicKey;

#[derive(Debug, Clone, Parser)]
#[command(name = "xreserve-deposit-relayer-lite")]
#[command(about = "Relays Circle xReserve deposit attestations to the xUSDC faucet")]
pub struct Config {
    /// The Circle xReserve API URL.
    #[arg(long)]
    pub circle_url: Url,

    /// The number of attestations in one Circle response, between 1 and 1000.
    #[arg(long)]
    pub page_size: PageSize,

    /// The maximum duration of one Circle request.
    #[arg(long, value_parser = humantime::parse_duration)]
    pub request_timeout: Duration,

    /// The Circle domain identifier for Miden.
    #[arg(long)]
    pub remote_domain: RemoteDomain,

    /// The public xUSDC faucet account, as `0x`-prefixed hex or bech32.
    #[arg(long, value_parser = parse_account_id)]
    pub faucet_account_id: AccountId,

    /// The account that creates the mint notes, as `0x`-prefixed hex or bech32.
    #[arg(long, value_parser = parse_account_id)]
    pub relayer_account_id: AccountId,

    /// The compressed SEC1 public key for the attestation signature, as hex with an optional `0x`
    /// prefix.
    #[arg(long)]
    pub attester_public_key: AttesterPublicKey,

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
