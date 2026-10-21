use std::path::PathBuf;
use std::time::Duration;

use anyhow::{ensure, Result};
use clap::Parser;
use miden_protocol::account::AccountId;
use url::Url;

use miden_usdcx::xreserve::encoding::CircleDomain;

use crate::circle::PageSize;
use crate::miden::ExpirationDelta;
use crate::mint::AttesterPublicKey;

#[derive(Debug, Clone, Parser)]
#[command(name = "xreserve-deposit-relayer")]
#[command(about = "Relays Circle xReserve deposit attestations to the xUSDC faucet")]
pub struct Config {
    /// The Circle xReserve API URL.
    #[arg(long)]
    pub circle_url: Url,

    /// Deposits requested per Circle page (1 to 1000), capped at 10 with local proving or 40 with
    /// remote proving. Each page is minted as one transaction.
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
    pub remote_domain: CircleDomain,

    /// The RPC endpoint of the Miden node the mint transactions are submitted to.
    #[arg(long)]
    pub miden_node_url: Url,

    /// Optional HTTP(S) endpoint for remote transaction proving. Without it, proofs run locally.
    #[arg(long, value_parser = parse_prover_url)]
    pub prover_url: Option<Url>,

    /// Maximum time for remote proving, including connection setup.
    #[arg(long, value_parser = parse_prover_timeout, default_value = "30s")]
    pub prover_timeout: Duration,

    /// The directory holding the Miden client's state: its store, and the keystore the relayer
    /// account's signing key is read from.
    #[arg(long)]
    pub miden_data_dir: PathBuf,

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

impl Config {
    /// The page size used for the configured proving mode, keeping smaller requests unchanged.
    pub fn effective_page_size(&self) -> PageSize {
        self.page_size.min(if self.prover_url.is_some() {
            PageSize::REMOTE_PROVING_MAX
        } else {
            PageSize::LOCAL_PROVING_MAX
        })
    }

    pub(crate) fn validate_prover(&self) -> Result<()> {
        if let Some(url) = &self.prover_url {
            validate_prover_url(url)?;
        }
        validate_prover_timeout(self.prover_timeout)
    }
}

/// Parses the remote prover URL for either service binary.
pub fn parse_prover_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    validate_prover_url(&url)?;
    Ok(url)
}

fn validate_prover_url(url: &Url) -> Result<()> {
    ensure!(
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
        "prover URL must be an HTTP(S) endpoint"
    );
    Ok(())
}

/// Parses a positive remote proving timeout for either service binary.
pub fn parse_prover_timeout(value: &str) -> Result<Duration> {
    let timeout = humantime::parse_duration(value)?;
    validate_prover_timeout(timeout)?;
    Ok(timeout)
}

fn validate_prover_timeout(timeout: Duration) -> Result<()> {
    ensure!(
        !timeout.is_zero(),
        "prover timeout must be greater than zero"
    );
    Ok(())
}

/// Accepts either account ID form; the network prefix of a bech32 ID is parsed and then discarded.
pub fn parse_account_id(value: &str) -> Result<AccountId, String> {
    AccountId::parse(value)
        .map(|(account_id, _network_id)| account_id)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prover_settings_require_http_and_a_positive_timeout() {
        for url in ["http://127.0.0.1:50051", "https://prover.example"] {
            assert!(parse_prover_url(url).is_ok());
        }
        for url in [
            "prover.example",
            "ftp://prover.example",
            "file:///tmp/prover",
        ] {
            assert!(parse_prover_url(url).is_err());
        }
        assert_eq!(parse_prover_timeout("2s").unwrap(), Duration::from_secs(2));
        assert!(parse_prover_timeout("0s").is_err());
        assert!(parse_prover_timeout("invalid").is_err());
    }
}
