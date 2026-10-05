//! Deployment-specific attester configuration.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use alloy_primitives::Address;
use anyhow::{anyhow, bail, ensure, Context};
use clap::builder::NonEmptyStringValueParser;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use miden_client::rpc::Endpoint;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteId;
use miden_protocol::Word;
use reqwest::Url;

/// Command-line deployment settings for the attester.
#[derive(Debug, Parser)]
#[command(version, about = "Run the xUSDC withdrawal attester")]
pub struct Cli {
    /// Signing provider; only aws-kms is supported.
    #[arg(long, value_enum)]
    signer_provider: SignerProvider,

    /// AWS region containing both KMS keys; required for aws-kms only.
    #[arg(
        long,
        required_if_eq("signer_provider", "aws-kms"),
        value_parser = NonEmptyStringValueParser::new()
    )]
    aws_kms_region: Option<String>,

    /// The two immutable KMS key ARNs, one for each signer, in either order; required for aws-kms
    /// only.
    #[arg(
        long,
        num_args = 2,
        value_names = ["ARN1", "ARN2"],
        action = ArgAction::Set,
        required_if_eq("signer_provider", "aws-kms")
    )]
    aws_kms_key_arn: Vec<String>,

    /// Deadline for each KMS operation, including retries (for example, "10s"); required for
    /// aws-kms only.
    #[arg(
        long,
        value_parser = humantime::parse_duration,
        required_if_eq("signer_provider", "aws-kms")
    )]
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
    /// fee there.
    #[arg(long)]
    max_withdrawal_fee: u64,

    /// Extra allowed fee in basis points of the burned amount, on top of --max-withdrawal-fee.
    /// Circle charges up to 1.5 basis points on most routes, so leave headroom, for example 3.
    #[arg(long)]
    max_withdrawal_fee_bps: u64,

    /// Maximum CCTP fee for a forwarded withdrawal, in the smallest USDC unit.
    /// The total withdrawal fee limit must cover this fee and Circle's fee.
    /// CCTP deducts only the fee it charges, which may be lower than this limit.
    /// Allow 10 to 20 percent above Circle's current fee for the most expensive destination you support.
    #[arg(long)]
    cctp_forwarding_max_fee: u64,

    /// 0x-prefixed address of Circle's xReserve contract on Arc for the environment --circle-url
    /// points at; a forwarded response must name it as recipient and caller. Circle reaches
    /// Solana, Linea, Codex, Monad, XDC, Ink, Plume, Starknet and EDGE through xReserve on Arc
    /// plus CCTP.
    #[arg(long)]
    cctp_forwarder_address: Address,

    /// 0x-prefixed address of CCTP's TokenMessengerV2 contract on Arc for the environment
    /// --circle-url points at. A forwarded response must name it as the forwarding contract: the
    /// contract xReserve calls with the CCTP transfer.
    #[arg(long)]
    cctp_token_messenger_address: Address,

    /// Delay between attester cycles (for example, "1s" or "500ms").
    #[arg(long, value_parser = humantime::parse_duration)]
    poll_interval: Duration,

    /// Block at which the faucet was deployed, where a new store starts scanning; an existing store
    /// keeps the scan start it was created with.
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
}

/// The command line: run the attester, or release its holds once.
#[derive(Debug, Parser)]
#[command(
    version,
    about = "Run the xUSDC withdrawal attester",
    args_conflicts_with_subcommands = true
)]
pub struct Invocation {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub run: Option<Cli>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Stop the attester first. Without note IDs, list the holds. With note IDs, release them and
    /// exit. A released burn can be prepared again. Releasing a withdrawal deletes its saved signed
    /// request.
    ReleaseHolds {
        /// Existing durable SQLite ledger; only this command may open it while holds are released.
        #[arg(long)]
        store_path: OsString,
        /// Canonical 0x-prefixed lowercase Miden faucet account ID saved in the ledger.
        #[arg(long)]
        faucet_account_id: String,
        /// Out-of-band verified anchor block saved in the ledger.
        #[arg(long)]
        trusted_anchor_block: u32,
        /// Canonical commitment of the out-of-band verified anchor block saved in the ledger.
        #[arg(long)]
        trusted_anchor_commitment: String,
        /// Note ID of a held burn to release; repeat it for each burn. Name a held withdrawal only
        /// after checking that Circle did not accept its saved request.
        #[arg(long, action = ArgAction::Append)]
        note_id: Vec<String>,
        /// Use the first word of each line as a note ID. Before adding a held withdrawal, check that
        /// Circle did not accept its saved request. Releasing it deletes that request.
        #[arg(long)]
        note_ids_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignerProvider {
    AwsKms,
}

/// Validated provider settings. No credentials or private keys are configuration fields.
#[derive(Debug)]
pub enum SignerConfig {
    AwsKms {
        region: String,
        key_arns: [String; 2],
        operation_timeout: Duration,
    },
}

impl SignerConfig {
    fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let SignerProvider::AwsKms = cli.signer_provider;
        let (Some(region), [first, second], Some(operation_timeout)) = (
            &cli.aws_kms_region,
            cli.aws_kms_key_arn.as_slice(),
            cli.aws_kms_operation_timeout,
        ) else {
            bail!("the AWS KMS options are incomplete");
        };
        ensure!(first != second, "the two KMS key ARNs must differ");
        ensure!(
            !operation_timeout.is_zero(),
            "AWS KMS operation timeout must be greater than zero"
        );
        Ok(Self::AwsKms {
            region: region.clone(),
            key_arns: [first.clone(), second.clone()],
            operation_timeout,
        })
    }
}

/// What a forwarded withdrawal is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CctpForwarding {
    /// Cap on the CCTP leg's fee, in the smallest USDC unit.
    pub(crate) max_fee: u64,
    /// Circle's xReserve contract on Arc.
    pub(crate) forwarder: Address,
    /// CCTP's TokenMessengerV2 on Arc.
    pub(crate) token_messenger: Address,
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
    cctp_forwarding: CctpForwarding,
    poll_interval: Duration,
    faucet_deployment_block: BlockNumber,
    trusted_anchor_block: BlockNumber,
    trusted_anchor_commitment: Word,
    minimum_finality_depth_blocks: u32,
    expected_signing_public_keys_hex: Vec<String>,
    /// Durable ledger state; deploy it on persistent storage for exactly one attester instance.
    store_path: PathBuf,
}

impl TryFrom<Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        let signer = SignerConfig::from_cli(&cli)?;
        let store_path = PathBuf::from(cli.store_path);
        let max_withdrawal_fee = AssetAmount::new(cli.max_withdrawal_fee)
            .context("maximum withdrawal fee is invalid")?;
        let cctp_forwarding = CctpForwarding {
            max_fee: cli.cctp_forwarding_max_fee,
            forwarder: cli.cctp_forwarder_address,
            token_messenger: cli.cctp_token_messenger_address,
        };
        ensure!(
            cctp_forwarding.max_fee != 0,
            "cctp forwarding max fee must be above zero"
        );
        ensure!(
            cctp_forwarding.forwarder != Address::ZERO,
            "cctp forwarder address must not be zero"
        );
        ensure!(
            cctp_forwarding.token_messenger != Address::ZERO,
            "cctp token messenger address must not be zero"
        );
        ensure!(
            cctp_forwarding.forwarder != cctp_forwarding.token_messenger,
            "cctp forwarder and token messenger addresses must differ"
        );

        if cli.request_timeout.is_zero() {
            bail!("circle request timeout must be greater than zero");
        }
        if cli.poll_interval.is_zero() {
            bail!("poll interval must be greater than zero");
        }
        if cli.minimum_finality_depth_blocks == 0 {
            bail!("minimum finality depth must be greater than zero");
        }
        if cli.expected_signing_public_key.len() != 2 {
            bail!("exactly two expected signing public keys are required");
        }

        let faucet_account_id = parse_faucet_account_id(&cli.faucet_account_id)?;
        let trusted_anchor_commitment =
            parse_trusted_anchor_commitment(&cli.trusted_anchor_commitment)?;

        // `Endpoint::try_from` reads a bare word such as "mainnet" as an HTTPS host, so the scheme
        // must be written out.
        if !cli.miden_rpc_url.starts_with("https://") && !cli.miden_rpc_url.starts_with("http://") {
            bail!("Miden RPC URL must start with https:// or http://");
        }
        let miden_rpc_url = Endpoint::try_from(cli.miden_rpc_url.as_str())
            .map_err(|_| anyhow!("Miden RPC URL is invalid"))?;

        let circle_api_base_url =
            Url::parse(&cli.circle_url).context("Circle API base URL is invalid")?;
        if circle_api_base_url.scheme() != "https" || circle_api_base_url.host_str().is_none() {
            bail!("Circle API base URL must be an absolute HTTPS URL");
        }

        if store_path.as_os_str().is_empty() {
            bail!("store path must not be empty");
        }
        let store_parent = store_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let store_parent_metadata =
            fs::metadata(store_parent).context("store path parent is not accessible")?;
        if !store_parent_metadata.is_dir() {
            bail!("store path parent must be a directory");
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
            poll_interval: cli.poll_interval,
            faucet_deployment_block: BlockNumber::from(cli.faucet_deployment_block),
            trusted_anchor_block: BlockNumber::from(cli.trusted_anchor_block),
            trusted_anchor_commitment,
            minimum_finality_depth_blocks: cli.minimum_finality_depth_blocks,
            expected_signing_public_keys_hex: cli.expected_signing_public_key,
            store_path,
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

    pub fn faucet_account_id(&self) -> AccountId {
        self.faucet_account_id
    }

    pub fn circle_api_base_url(&self) -> &Url {
        &self.circle_api_base_url
    }

    pub(crate) fn max_withdrawal_fee(&self) -> AssetAmount {
        self.max_withdrawal_fee
    }

    pub(crate) fn max_withdrawal_fee_bps(&self) -> u64 {
        self.max_withdrawal_fee_bps
    }

    pub(crate) fn cctp_forwarding(&self) -> CctpForwarding {
        self.cctp_forwarding
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

    pub(crate) fn expected_signing_public_keys_hex(&self) -> &[String] {
        &self.expected_signing_public_keys_hex
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store_path
    }
}

pub fn parse_faucet_account_id(value: &str) -> anyhow::Result<AccountId> {
    let account_id = AccountId::from_hex(value).context("faucet account id is invalid")?;
    if account_id.to_hex() != value {
        bail!("faucet account id must use canonical 0x-prefixed lowercase hex");
    }
    Ok(account_id)
}

/// The note IDs given to `release-holds`: each --note-id, then the first word of each non-empty
/// line of --note-ids-file.
pub fn parse_note_ids(note_ids: &[String], file: Option<&Path>) -> anyhow::Result<Vec<NoteId>> {
    let mut words = note_ids.to_vec();
    if let Some(file) = file {
        let listed = fs::read_to_string(file)
            .with_context(|| format!("failed to read note IDs from {}", file.display()))?;
        words.extend(
            listed
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .map(String::from),
        );
    }
    ensure!(!words.is_empty(), "no note IDs given");
    words
        .iter()
        .map(|id| NoteId::try_from_hex(id).with_context(|| format!("note id {id} is invalid")))
        .collect()
}

pub fn parse_trusted_anchor_commitment(value: &str) -> anyhow::Result<Word> {
    let commitment =
        Word::parse(value).map_err(|_| anyhow!("trusted anchor commitment is invalid"))?;
    if commitment.to_hex() != value {
        bail!("trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex");
    }
    Ok(commitment)
}
