//! Deployment-specific attester configuration.

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::Address;
use clap::{ArgAction, Parser, ValueEnum};
use miden_client::rpc::Endpoint;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
use miden_protocol::Word;
use reqwest::Url;

/// Command-line deployment settings for the attester.
#[derive(Debug, Parser)]
#[command(version, about = "Run the xUSDC withdrawal attester")]
pub struct Cli {
    /// Signing provider; development reads the two private-key environment variables.
    #[arg(long, value_enum)]
    signer_provider: SignerProvider,

    /// AWS region containing both KMS keys; required for aws-kms only.
    #[arg(long)]
    aws_kms_region: Option<String>,

    /// Immutable KMS key ARN; provide twice in the same order as --expected-signing-public-key.
    #[arg(long, action = ArgAction::Append)]
    aws_kms_key_arn: Vec<String>,

    /// Deadline for each KMS operation, including retries (for example, "10s").
    #[arg(long, value_parser = humantime::parse_duration)]
    aws_kms_operation_timeout: Option<Duration>,

    /// Miden node RPC URL, for example https://rpc.devnet.miden.io
    #[arg(long)]
    miden_rpc_url: String,

    /// Circle xReserve API base URL; must be an absolute HTTPS URL.
    #[arg(long)]
    circle_url: String,

    /// Timeout for each Circle HTTP request (for example, "10s" or "500ms").
    #[arg(long, value_parser = humantime::parse_duration)]
    request_timeout: Duration,

    /// Canonical 0x-prefixed lowercase Miden faucet account ID.
    #[arg(long)]
    faucet_account_id: String,

    /// Fixed part of the allowed fee per withdrawal, in the smallest USDC unit;
    /// --max-withdrawal-fee-bps adds a share of the burned amount on top. Every Circle route
    /// charges a fee (the smallest seen is 4350); Ethereum needs at least 1003500, Circle's flat
    /// fee there with forwarding on.
    #[arg(long)]
    max_withdrawal_fee: u64,

    /// Extra allowed fee in basis points of the burned amount, on top of --max-withdrawal-fee.
    /// Circle charges up to 1.5 basis points on most routes, so leave headroom, for example 3.
    #[arg(long)]
    max_withdrawal_fee_bps: u64,

    /// Fee for the CCTP leg of a forwarded withdrawal, in the smallest USDC unit. Circle reaches
    /// Solana, Linea, Codex, Monad, XDC, Ink, Plume, Starknet and EDGE through xReserve on Arc
    /// plus CCTP. Must stay below --max-withdrawal-fee, which on those routes also covers the
    /// Gateway leg (about 0.02 USDC at 1 USDC on the sandbox). This is a cap: CCTP deducts only
    /// the fee it actually charges. Set it to Circle's current forwarding fee for the most
    /// expensive forwarded destination plus 10 to 20 percent.
    #[arg(long)]
    cctp_forwarding_max_fee: u64,

    /// 0x-prefixed address of Circle's xReserve contract on Arc for the environment --circle-url
    /// points at; a forwarded response must name it as recipient and caller. Circle reaches
    /// Solana, Linea, Codex, Monad, XDC, Ink, Plume, Starknet and EDGE through xReserve on Arc
    /// plus CCTP.
    #[arg(long)]
    cctp_forwarder_address: String,

    /// Rolling withdrawal cap in the smallest USDC unit; zero pauses new submissions.
    #[arg(long)]
    withdrawal_limit: u64,

    /// Whole-hour rolling withdrawal window.
    #[arg(long, default_value_t = 24)]
    withdrawal_window_hours: u64,

    /// Fixed start of Circle's HTTP 400 withdrawal-limit message, the text before the numbers,
    /// for example "Withdrawal request exceeds rolling withdrawal limit"; enables automatic retries
    /// when set. Use the whole fixed text: a shorter start can also match Circle's other 400
    /// messages.
    #[arg(long)]
    withdrawal_cap_error_message: Option<String>,

    /// Delay between attester cycles (for example, "1s" or "500ms").
    #[arg(long, value_parser = humantime::parse_duration)]
    poll_interval: Duration,

    /// Block at which the faucet was deployed.
    #[arg(long)]
    faucet_deployment_block: u32,

    /// Out-of-band verified anchor block, at deployment or shortly before it, never after.
    #[arg(long)]
    trusted_anchor_block: u32,

    /// Canonical commitment of the out-of-band verified anchor block; an existing store keeps its original anchor.
    #[arg(long)]
    trusted_anchor_commitment: String,

    /// Public expected signing key; provide exactly twice, once for each independent signer.
    #[arg(long, action = ArgAction::Append, required = true)]
    expected_signing_public_key: Vec<String>,

    /// Minimum number of blocks required above a burn before submission.
    #[arg(long)]
    minimum_finality_depth_blocks: u32,

    /// Durable SQLite ledger path; only one attester instance may open it. Relative paths resolve from the process working directory.
    #[arg(long)]
    store_path: OsString,

    /// Releases every held burn and every held withdrawal once, after the store opens. Each
    /// released burn is prepared, checked and signed again from scratch; for a held withdrawal the
    /// old signed request is thrown away first. Meant for a single restart: while it is set, every
    /// start releases the holds again.
    #[arg(long)]
    release_holds: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignerProvider {
    Development,
    AwsKms,
}

/// Validated provider settings. No credentials or private keys are configuration fields.
#[derive(Debug)]
pub enum SignerConfig {
    Development,
    AwsKms {
        region: String,
        key_arns: [String; 2],
        operation_timeout: Duration,
    },
}

impl SignerConfig {
    fn from_cli(cli: &Cli) -> Result<Self, ConfigError> {
        match cli.signer_provider {
            SignerProvider::Development => {
                if cli.aws_kms_region.is_some()
                    || !cli.aws_kms_key_arn.is_empty()
                    || cli.aws_kms_operation_timeout.is_some()
                {
                    return Err(ConfigError::invalid(
                        "KMS options require the aws-kms signer provider",
                    ));
                }
                Ok(Self::Development)
            }
            SignerProvider::AwsKms => {
                let region = cli
                    .aws_kms_region
                    .as_deref()
                    .filter(|region| !region.is_empty())
                    .ok_or_else(|| ConfigError::invalid("AWS KMS region is required"))?;
                let [first, second] = cli.aws_kms_key_arn.as_slice() else {
                    return Err(ConfigError::invalid(
                        "exactly two distinct immutable KMS key ARNs are required",
                    ));
                };
                let account = |arn: &str| -> Option<String> {
                    let parts: Vec<_> = arn.split(':').collect();
                    let ["arn", "aws", "kms", arn_region, account, resource] = parts.as_slice()
                    else {
                        return None;
                    };
                    let key = resource.strip_prefix("key/")?;
                    (*arn_region == region
                        && region
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                        && account.len() == 12
                        && account.bytes().all(|c| c.is_ascii_digit())
                        && !key.is_empty()
                        && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
                    .then(|| (*account).to_owned())
                };
                if first == second || account(first).is_none() || account(first) != account(second)
                {
                    return Err(ConfigError::invalid("KMS key ARNs must be distinct immutable keys in the configured region and same account"));
                }
                let operation_timeout = cli
                    .aws_kms_operation_timeout
                    .filter(|timeout| !timeout.is_zero())
                    .ok_or_else(|| {
                        ConfigError::invalid(
                            "AWS KMS operation timeout must be supplied and greater than zero",
                        )
                    })?;
                Ok(Self::AwsKms {
                    region: region.to_owned(),
                    key_arns: [first.clone(), second.clone()],
                    operation_timeout,
                })
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct ConfigError {
    context: &'static str,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ConfigError {
    fn invalid(context: &'static str) -> Self {
        Self {
            context,
            source: None,
        }
    }

    fn with_source(context: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            context,
            source: Some(Box::new(source)),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    signer: SignerConfig,
    miden_rpc_url: Endpoint,
    circle_request_timeout: Duration,
    faucet_account_id: AccountId,
    circle_api_base_url: Url,
    max_withdrawal_fee: AssetAmount,
    max_withdrawal_fee_bps: u64,
    /// The CCTP leg's fee and the xReserve contract on Arc.
    cctp_forwarding: (u64, Address),
    withdrawal_limit: u64,
    withdrawal_window_ms: i64,
    withdrawal_cap_error_message: Option<String>,
    poll_interval: Duration,
    faucet_deployment_block: BlockNumber,
    trusted_anchor_block: BlockNumber,
    trusted_anchor_commitment: Word,
    minimum_finality_depth_blocks: u32,
    expected_signing_public_keys_hex: Vec<String>,
    /// Durable ledger state; deploy it on persistent storage for exactly one attester instance.
    store_path: PathBuf,
    release_holds: bool,
}

impl TryFrom<Cli> for Config {
    type Error = ConfigError;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let signer = SignerConfig::from_cli(&cli)?;
        let store_path = PathBuf::from(cli.store_path);
        let max_withdrawal_fee = AssetAmount::new(cli.max_withdrawal_fee).map_err(|source| {
            ConfigError::with_source("maximum withdrawal fee is invalid", source)
        })?;
        let forwarder = cli
            .cctp_forwarder_address
            .parse::<Address>()
            .map_err(|source| {
                ConfigError::with_source("cctp forwarder address is invalid", source)
            })?;
        if cli.cctp_forwarding_max_fee >= cli.max_withdrawal_fee {
            return Err(ConfigError::invalid(
                "cctp forwarding max fee must be below the maximum withdrawal fee",
            ));
        }
        let cctp_forwarding = (cli.cctp_forwarding_max_fee, forwarder);
        let withdrawal_window_ms = cli
            .withdrawal_window_hours
            .checked_mul(3_600_000)
            .filter(|milliseconds| *milliseconds > 0)
            .and_then(|milliseconds| i64::try_from(milliseconds).ok())
            .ok_or_else(|| {
                ConfigError::invalid("withdrawal window must be positive and fit in milliseconds")
            })?;
        if cli
            .withdrawal_cap_error_message
            .as_deref()
            .is_some_and(|message| message.trim().is_empty())
        {
            return Err(ConfigError::invalid(
                "withdrawal cap error message must not be empty",
            ));
        }

        if cli.request_timeout.is_zero() {
            return Err(ConfigError::invalid(
                "circle request timeout must be greater than zero",
            ));
        }
        if cli.poll_interval.is_zero() {
            return Err(ConfigError::invalid(
                "poll interval must be greater than zero",
            ));
        }
        if cli.minimum_finality_depth_blocks == 0 {
            return Err(ConfigError::invalid(
                "minimum finality depth must be greater than zero",
            ));
        }
        if cli.expected_signing_public_key.len() != 2 {
            return Err(ConfigError::invalid(
                "exactly two expected signing public keys are required",
            ));
        }

        let faucet_account_id = AccountId::from_hex(&cli.faucet_account_id)
            .map_err(|source| ConfigError::with_source("faucet account id is invalid", source))?;
        if faucet_account_id.to_hex() != cli.faucet_account_id {
            return Err(ConfigError::invalid(
                "faucet account id must use canonical 0x-prefixed lowercase hex",
            ));
        }

        let trusted_anchor_commitment = Word::parse(&cli.trusted_anchor_commitment)
            .map_err(|_| ConfigError::invalid("trusted anchor commitment is invalid"))?;
        if trusted_anchor_commitment.to_hex() != cli.trusted_anchor_commitment {
            return Err(ConfigError::invalid(
                "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
            ));
        }

        // `Endpoint::try_from` reads a bare word such as "mainnet" as an HTTPS host, so the scheme
        // must be written out.
        if !cli.miden_rpc_url.starts_with("https://") && !cli.miden_rpc_url.starts_with("http://") {
            return Err(ConfigError::invalid(
                "Miden RPC URL must start with https:// or http://",
            ));
        }
        let miden_rpc_url = Endpoint::try_from(cli.miden_rpc_url.as_str())
            .map_err(|_| ConfigError::invalid("Miden RPC URL is invalid"))?;

        let circle_api_base_url = Url::parse(&cli.circle_url)
            .map_err(|source| ConfigError::with_source("Circle API base URL is invalid", source))?;
        if circle_api_base_url.scheme() != "https" || circle_api_base_url.host_str().is_none() {
            return Err(ConfigError::invalid(
                "Circle API base URL must be an absolute HTTPS URL",
            ));
        }

        if store_path.as_os_str().is_empty() {
            return Err(ConfigError::invalid("store path must not be empty"));
        }
        let store_parent = store_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let store_parent_metadata = fs::metadata(store_parent).map_err(|source| {
            ConfigError::with_source("store path parent is not accessible", source)
        })?;
        if !store_parent_metadata.is_dir() {
            return Err(ConfigError::invalid(
                "store path parent must be a directory",
            ));
        }

        Ok(Self {
            signer,
            miden_rpc_url,
            circle_request_timeout: cli.request_timeout,
            faucet_account_id,
            circle_api_base_url,
            max_withdrawal_fee,
            max_withdrawal_fee_bps: cli.max_withdrawal_fee_bps,
            cctp_forwarding,
            withdrawal_limit: cli.withdrawal_limit,
            withdrawal_window_ms,
            withdrawal_cap_error_message: cli.withdrawal_cap_error_message,
            poll_interval: cli.poll_interval,
            faucet_deployment_block: BlockNumber::from(cli.faucet_deployment_block),
            trusted_anchor_block: BlockNumber::from(cli.trusted_anchor_block),
            trusted_anchor_commitment,
            minimum_finality_depth_blocks: cli.minimum_finality_depth_blocks,
            expected_signing_public_keys_hex: cli.expected_signing_public_key,
            store_path,
            release_holds: cli.release_holds,
        })
    }
}

impl Config {
    pub fn signer(&self) -> &SignerConfig {
        &self.signer
    }

    pub fn miden_rpc_url(&self) -> &Endpoint {
        &self.miden_rpc_url
    }

    pub(crate) fn circle_request_timeout(&self) -> Duration {
        self.circle_request_timeout
    }

    pub(crate) fn faucet_account_id(&self) -> AccountId {
        self.faucet_account_id
    }

    pub(crate) fn circle_api_base_url(&self) -> &Url {
        &self.circle_api_base_url
    }

    pub(crate) fn max_withdrawal_fee(&self) -> AssetAmount {
        self.max_withdrawal_fee
    }

    pub(crate) fn max_withdrawal_fee_bps(&self) -> u64 {
        self.max_withdrawal_fee_bps
    }

    pub(crate) fn cctp_forwarding(&self) -> (u64, Address) {
        self.cctp_forwarding
    }

    pub(crate) fn withdrawal_limit(&self) -> u64 {
        self.withdrawal_limit
    }

    pub(crate) fn withdrawal_window_ms(&self) -> i64 {
        self.withdrawal_window_ms
    }

    pub(crate) fn withdrawal_cap_error_message(&self) -> Option<&str> {
        self.withdrawal_cap_error_message.as_deref()
    }

    pub(crate) fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    pub(crate) fn faucet_deployment_block(&self) -> BlockNumber {
        self.faucet_deployment_block
    }

    pub(crate) fn trusted_anchor_block(&self) -> BlockNumber {
        self.trusted_anchor_block
    }

    pub(crate) fn trusted_anchor_commitment(&self) -> Word {
        self.trusted_anchor_commitment
    }

    pub(crate) fn minimum_finality_depth_blocks(&self) -> u32 {
        self.minimum_finality_depth_blocks
    }

    pub fn expected_signing_public_keys_hex(&self) -> &[String] {
        &self.expected_signing_public_keys_hex
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store_path
    }

    pub(crate) fn release_holds(&self) -> bool {
        self.release_holds
    }
}
