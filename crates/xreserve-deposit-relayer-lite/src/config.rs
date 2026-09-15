use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use miden_protocol::account::AccountId;
use url::Url;

use crate::circle::{PageSize, RemoteDomain};
use crate::miden::{ExpirationDelta, NotesPerTransaction};
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

    /// How long to wait once the scan has caught up with the feed. A deposit intent has no
    /// expiry, so polling harder buys nothing but rate-limit pressure.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "5s")]
    pub poll_interval: Duration,

    /// The Circle domain identifier for Miden.
    #[arg(long)]
    pub remote_domain: RemoteDomain,

    /// The RPC endpoint of the Miden node the mint transactions are submitted to.
    #[arg(long)]
    pub miden_node_url: Url,

    /// The directory holding the Miden client's state: its store, and the keystore the relayer
    /// account's signing key is read from.
    #[arg(long)]
    pub miden_data_dir: PathBuf,

    /// How many mint notes one transaction carries. A page with more notes than this is split
    /// across several transactions, which trades a longer proof for each against more of them.
    #[arg(long, default_value = "64")]
    pub notes_per_transaction: NotesPerTransaction,

    /// How many blocks a submitted mint transaction may still be included in. Once the chain is
    /// past that block the transaction can never land, and the relayer stops waiting and retries
    /// the page. A larger delta tolerates a slower chain; a smaller one notices sooner.
    #[arg(long, default_value = "64")]
    pub expiration_delta: ExpirationDelta,

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
