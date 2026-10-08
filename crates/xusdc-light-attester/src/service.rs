//! Shared startup and shutdown for the attester binaries.

use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::block::BlockNumber;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};
use usdcx_telemetry::Classify as _;
use usdcx_telemetry::FailureClass::Actionable;

use crate::attester::{list_holds, release_holds};
use crate::chain::MidenChainReader;
use crate::circle::CircleClient;
use crate::config::{
    parse_faucet_account_id, parse_note_ids, parse_trusted_anchor_commitment, Command, Config,
    SignerConfig,
};
use crate::signer::{KmsSigner, Signer, SignerPair};
use crate::Attester;

/// An initialized attester that has not started its withdrawal loop yet.
pub struct AttesterService {
    attester: Attester,
    circle_worker: JoinHandle<()>,
}

impl AttesterService {
    /// Connects the attester's dependencies and runs its startup checks, in the `attester.startup`
    /// span. A failure marks that span failed as `actionable`.
    #[instrument(name = "attester.startup", skip_all)]
    pub async fn start(config: Config) -> Result<Self> {
        Self::connect(config)
            .await
            .classify(Actionable("startup"))
            .map_err(|failure| {
                failure.report("attester startup failed");
                failure.error
            })
    }

    async fn connect(config: Config) -> Result<Self> {
        let (circle, circle_worker) =
            CircleClient::start(&config).context("failed to initialize Circle HTTP client")?;
        let SignerConfig::AwsKms {
            region,
            key_arns,
            operation_timeout,
        } = config.signer();
        let client = KmsSigner::client(region, *operation_timeout).await;
        let first = KmsSigner::connect(client.clone(), &key_arns[0])
            .await
            .context("failed to initialize first AWS KMS signer")?;
        let second = KmsSigner::connect(client, &key_arns[1])
            .await
            .context("failed to initialize second AWS KMS signer")?;
        let signers: [Box<dyn Signer>; 2] = [Box::new(first), Box::new(second)];
        let signers = SignerPair::new(signers)
            .await
            .context("failed to initialize the signer pair")?;
        let chain = MidenChainReader::new(config.miden_rpc_url());
        let attester = Attester::start(config, Box::new(chain), Box::new(circle), signers)
            .await
            .context("startup failed")?;
        Ok(Self {
            attester,
            circle_worker,
        })
    }

    /// Runs the attester, then waits for its Circle worker to finish outstanding requests.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let Self {
            mut attester,
            circle_worker,
        } = self;
        let result = attester.run(shutdown).await;
        // Closing the request queue lets the worker finish its current request and stop.
        drop(attester);
        circle_worker
            .await
            .context("Circle request worker failed")?;
        result
    }
}

/// Runs a one-off maintenance command against a stopped attester's store.
///
/// # Errors
///
/// - The command's arguments are malformed.
/// - The store cannot be opened, or was created for a different faucet or anchor.
pub fn run_command(command: Command) -> Result<()> {
    let Command::ReleaseHolds {
        store_path,
        faucet_account_id,
        trusted_anchor_block,
        trusted_anchor_commitment,
        note_id,
        note_ids_file,
    } = command;
    let faucet_account_id = parse_faucet_account_id(&faucet_account_id)?;
    let trusted_anchor_commitment = parse_trusted_anchor_commitment(&trusted_anchor_commitment)?;
    let store_path = Path::new(&store_path);
    let anchor_block = BlockNumber::from(trusted_anchor_block);
    if note_id.is_empty() && note_ids_file.is_none() {
        let holds = list_holds(
            store_path,
            faucet_account_id,
            anchor_block,
            trusted_anchor_commitment,
        )
        .context("failed to list held burns and withdrawals")?;
        for hold in holds {
            println!("{hold}");
        }
        return Ok(());
    }
    let note_ids = parse_note_ids(&note_id, note_ids_file.as_deref())?;
    let (burns, withdrawals) = release_holds(
        store_path,
        faucet_account_id,
        anchor_block,
        trusted_anchor_commitment,
        &note_ids,
    )
    .context("failed to release held burns and withdrawals")?;
    info!(burns, withdrawals, "released held burns and withdrawals");
    Ok(())
}
