//! Service startup and the sequential withdrawal-attester cycle.

use std::time::Instant;

use anyhow::Context;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::transaction::OutputNote;
use tokio_util::sync::CancellationToken;

use crate::burn::{BurnCandidate, DiscoveredBurn};
use crate::chain::{ChainError, ChainReader};
use crate::circle::CircleApi;
use crate::config::Config;
use crate::store::{ScanCursor, ScanState, Store, TrustedAnchor, INVALID};

#[derive(Debug)]
pub struct RunError;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoverError {
    #[error("Miden chain read failed")]
    Chain(#[source] ChainError),
    /// The authenticated chain changed or its reported tip moved behind durable state. Recovery is a
    /// deliberate operator action: stop, preserve the database, independently establish the
    /// canonical chain, and assess already-submitted Circle withdrawals before re-pinning.
    #[error("Miden chain diverged from the persisted authenticated chain")]
    ChainDiverged,
    #[error("attester store failed")]
    Store(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct SubmitError;

#[derive(Debug)]
pub struct PollError;

#[derive(Debug)]
#[non_exhaustive]
pub struct CycleReport {
    pub discover: Result<(), DiscoverError>,
    pub submit: Result<(), SubmitError>,
    pub poll: Result<(), PollError>,
}

#[allow(dead_code)]
pub struct Attester {
    config: Config,
    pub(crate) store: Store,
    chain: Box<dyn ChainReader>,
    circle: Box<dyn CircleApi>,
    trusted_anchor_block: Option<SignedBlock>,
}

#[allow(dead_code)]
impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle: Box<dyn CircleApi>,
    ) -> anyhow::Result<Self> {
        let trusted_anchor = TrustedAnchor {
            block_num: config.trusted_anchor_block(),
            commitment: config.trusted_anchor_commitment(),
        };
        chain
            .check_connection()
            .await
            .context("failed to connect to the Miden node")?;
        if !chain
            .account_exists(&config.faucet_account_id())
            .await
            .context("failed to check the configured faucet account")?
        {
            anyhow::bail!("configured faucet account does not exist");
        }

        // Check the out-of-band pin before creating a store, so a typo cannot bind a new database
        // to the wrong anchor. `validate(None)` checks the body, not the anchor's trustworthiness.
        let block = chain
            .block_by_number(trusted_anchor.block_num)
            .await
            .context("failed to load the configured trusted anchor")?;
        if block.header().block_num() != trusted_anchor.block_num
            || block.header().commitment() != trusted_anchor.commitment
            || block.validate(None).is_err()
        {
            anyhow::bail!(
                "configured trusted anchor is not the requested, self-consistent pinned block"
            );
        }

        // TODO(KMS): compare the configured public keys with the loaded signing keys.

        circle
            .check_connection()
            .await
            .context("failed to connect to the Circle API")?;

        let store = Store::open_or_create(
            config.store_path(),
            config.faucet_account_id(),
            ScanCursor {
                next_block: config.faucet_deployment_block(),
            },
            trusted_anchor,
        )
        .context("failed to open attester store")?;
        let scan_state = store
            .scan_state()
            .context("failed to load attester scan state")?;
        if trusted_anchor.block_num > scan_state.cursor.next_block {
            anyhow::bail!("trusted anchor must not be after the scan start");
        }
        let trusted_anchor_block = scan_state.authenticated_parent.is_none().then_some(block);

        Ok(Self {
            config,
            store,
            chain,
            circle,
            trusted_anchor_block,
        })
    }

    /// Drives cycles until `shutdown` is cancelled. A cancellation cuts the sleep between cycles
    /// short but never interrupts a running cycle, so the store is always left at a cycle boundary.
    pub async fn run(&mut self, shutdown: CancellationToken) -> Result<(), RunError> {
        while !shutdown.is_cancelled() {
            let _ = self.run_one_cycle(Instant::now()).await;
            tokio::select! {
                () = shutdown.cancelled() => {}
                () = tokio::time::sleep(self.config.poll_interval()) => {}
            }
        }

        Ok(())
    }

    pub async fn run_one_cycle(&mut self, now: Instant) -> CycleReport {
        let _ = now;
        todo!()
    }

    /// Scans the blocks that became final since the saved checkpoint. Each block's burn
    /// candidates and faucet consumptions are saved together with the advanced cursor and the
    /// block's header, one block per store transaction, so a crash never skips or half-records
    /// a block.
    pub(crate) async fn discover_burns(&mut self) -> Result<(), DiscoverError> {
        let saved_scan = self.store.scan_state()?;
        let Some(last_block_to_scan) = self.find_last_block_to_scan(&saved_scan).await? else {
            return Ok(());
        };
        let mut last_verified_header = self.load_previous_verified_header(&saved_scan).await?;

        // The anchor itself needs scanning once when it is also the faucet's deployment block.
        if saved_scan.authenticated_parent.is_none()
            && saved_scan.cursor.next_block == self.config.trusted_anchor_block()
        {
            let anchor = self.trusted_anchor_block.clone().context(INVALID)?;
            self.scan_and_save_block(&anchor)?;
        }

        let first_block_to_scan = last_verified_header.block_num().child();
        for block_num in block_range(first_block_to_scan, last_block_to_scan) {
            let block = self
                .fetch_and_verify_block(block_num, &last_verified_header)
                .await?;
            self.scan_and_save_block(&block)?;
            last_verified_header = block.header().clone();
        }

        Ok(())
    }

    async fn find_last_block_to_scan(
        &self,
        saved_scan: &ScanState,
    ) -> Result<Option<BlockNumber>, DiscoverError> {
        let last_verified_block_number = saved_scan
            .authenticated_parent
            .as_ref()
            .map_or(self.config.trusted_anchor_block(), BlockHeader::block_num);
        let scan_limits = self
            .chain
            .scan_limits()
            .await
            .map_err(DiscoverError::Chain)?;

        // Scan every available block. Withdrawal readiness separately requires verified depth.
        let last_block_to_scan = scan_limits.latest_committed_block;
        if last_block_to_scan < last_verified_block_number {
            return behind_verified_chain(saved_scan);
        }
        if last_block_to_scan < saved_scan.cursor.next_block {
            return Ok(None);
        }

        Ok(Some(last_block_to_scan))
    }

    async fn load_previous_verified_header(
        &self,
        saved_scan: &ScanState,
    ) -> Result<BlockHeader, DiscoverError> {
        let mut last_verified_header = match &saved_scan.authenticated_parent {
            Some(header) => header.clone(),
            None => self
                .trusted_anchor_block
                .as_ref()
                .map(|block| block.header().clone())
                .context(INVALID)?,
        };

        // The anchor may predate the faucet. Authenticate the intervening headers, but do not
        // inspect their notes because the configured deployment block is the scan start.
        if last_verified_header.block_num() < saved_scan.cursor.next_block {
            let first_predeployment_block = last_verified_header.block_num().child();
            let last_predeployment_block = saved_scan
                .cursor
                .next_block
                .parent()
                .ok_or(DiscoverError::ChainDiverged)?;
            for block_num in block_range(first_predeployment_block, last_predeployment_block) {
                last_verified_header = self
                    .fetch_and_verify_block(block_num, &last_verified_header)
                    .await?
                    .header()
                    .clone();
            }
        }

        Ok(last_verified_header)
    }

    /// Records one authenticated block: its new candidates, the burns its faucet transactions
    /// consumed, and the checkpoint moved past it, in a single store transaction.
    fn scan_and_save_block(&mut self, block: &SignedBlock) -> Result<(), DiscoverError> {
        let (new_burn_notes, new_burns) =
            find_burns_in_block(block, self.config.faucet_account_id(), &self.store)?;
        // Save this block atomically; a later RPC failure must not discard its progress.
        self.store.save_scan_progress(
            &new_burn_notes,
            &new_burns,
            &ScanState {
                cursor: ScanCursor {
                    next_block: block.header().block_num().child(),
                },
                authenticated_parent: Some(block.header().clone()),
            },
        )?;
        Ok(())
    }

    async fn fetch_and_verify_block(
        &self,
        block_num: BlockNumber,
        last_verified_header: &BlockHeader,
    ) -> Result<SignedBlock, DiscoverError> {
        let block = self
            .chain
            .block_by_number(block_num)
            .await
            .map_err(DiscoverError::Chain)?;
        if block.header().block_num() != block_num
            || block.validate(Some(last_verified_header)).is_err()
        {
            return Err(DiscoverError::ChainDiverged);
        }
        Ok(block)
    }

    async fn submit_withdrawals(&mut self) -> Result<(), SubmitError> {
        todo!()
    }

    async fn poll_withdrawal_statuses(&mut self, now: Instant) -> Result<(), PollError> {
        let _ = now;
        todo!()
    }
}

fn block_range(start: BlockNumber, end: BlockNumber) -> impl Iterator<Item = BlockNumber> {
    (start.as_u32()..=end.as_u32()).map(BlockNumber::from)
}

/// A scan bound below the verified chain is a divergence once a block has been authenticated;
/// before that, the node has merely not reached the anchor yet.
fn behind_verified_chain(saved_scan: &ScanState) -> Result<Option<BlockNumber>, DiscoverError> {
    if saved_scan.authenticated_parent.is_some() {
        Err(DiscoverError::ChainDiverged)
    } else {
        Ok(None)
    }
}

/// Collects the block's structurally valid burn notes and the candidates its faucet transactions
/// consumed. Reads candidates from earlier blocks out of the store and writes nothing.
fn find_burns_in_block(
    block: &SignedBlock,
    faucet_account_id: miden_protocol::account::AccountId,
    store: &Store,
) -> anyhow::Result<(Vec<BurnCandidate>, Vec<DiscoveredBurn>)> {
    let mut new_burn_notes = Vec::new();
    let mut new_burns = Vec::new();
    let block_num = block.header().block_num();
    // Discovery observes public notes retained in committed block output batches.
    for (_, output_note) in block
        .body()
        .output_note_batches()
        .iter()
        .flat_map(|batch| batch.iter())
    {
        let OutputNote::Public(note) = output_note else {
            continue;
        };
        let Ok(candidate) = BurnCandidate::new(note.clone(), block_num, faucet_account_id) else {
            continue;
        };
        // The same note published again has the same id and bytes: there is nothing new to save.
        if store.note_known(candidate.note_id())? {
            continue;
        }
        new_burn_notes.push(candidate);
    }

    // Transaction headers from this validated block authenticate the consuming account, input
    // nullifiers, and transaction ID. Do not use `created_nullifiers`, which `validate` does not
    // authenticate.
    for transaction in block.body().transactions().as_slice() {
        if transaction.account_id() != faucet_account_id {
            continue;
        }
        // Input notes expose nullifiers: match them against the notes saved from earlier blocks.
        // A note created and consumed in the same block is erased from the block's output notes,
        // so this block's own notes never match.
        for input_note in transaction.input_notes().iter() {
            let Some(candidate) = store.candidate_by_nullifier(input_note.nullifier())? else {
                continue;
            };
            new_burns.push(candidate.into_discovered(block_num, transaction.id()));
        }
    }

    Ok((new_burn_notes, new_burns))
}
