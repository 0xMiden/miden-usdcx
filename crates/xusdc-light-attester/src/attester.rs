//! Service startup and the sequential withdrawal-attester cycle.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::Context;
use miden_protocol::block::{BlockHeader, BlockNumber, ProvenBlock};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OutputNote;

use crate::chain::{ChainError, ChainReader};
use crate::circle::{CircleClient, HttpTransport};
use crate::config::Config;
use crate::store::{
    BurnCandidate, DiscoveredBurn, ScanCursor, ScanState, Store, StoreError, TrustedAnchor,
};
use miden_standards::note::BurnNote;

#[derive(Debug)]
pub struct RunError;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoverError {
    #[error("Miden chain read failed")]
    Chain(#[source] ChainError),
    /// The authenticated chain or its reported finality moved behind durable state. Recovery is a
    /// deliberate operator action: stop, preserve the database, independently establish the
    /// canonical chain, and assess already-submitted Circle withdrawals before re-pinning.
    #[error("Miden chain diverged from the persisted authenticated chain")]
    ChainDiverged,
    #[error("authenticated discovery evidence conflicts with the durable ledger")]
    ConflictingEvidence,
    #[error("attester store is invalid")]
    InvalidStore,
    #[error("the finality bound cannot be represented by the next-block cursor")]
    CursorOverflow,
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
    circle: CircleClient,
    burn_note_script_root: NoteScriptRoot,
    trusted_anchor_block: Option<ProvenBlock>,
}

#[allow(dead_code)]
impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle_transport: Box<dyn HttpTransport>,
    ) -> anyhow::Result<Self> {
        let burn_note_script_root = BurnNote::script_root();
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

        let circle = CircleClient::new(
            config.circle_api_base_url().clone(),
            config.circle_request_timeout(),
            circle_transport,
        );
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
            burn_note_script_root,
            trusted_anchor_block,
        })
    }

    /// Drives cycles until shutdown. Checks `shutdown` BETWEEN cycles and sleeps the full
    /// poll interval — no race, so no `select!` needed. Finishes the current cycle before
    /// returning; the process exits only between cycles.
    pub async fn run(
        &mut self,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), RunError> {
        while !shutdown.load(Ordering::Acquire) {
            let _ = self.run_one_cycle(Instant::now()).await;
            tokio::time::sleep(self.config.poll_interval()).await;
        }

        Ok(())
    }

    pub async fn run_one_cycle(&mut self, now: Instant) -> CycleReport {
        let _ = now;
        todo!()
    }

    pub(crate) async fn discover_burns(&mut self) -> Result<(), DiscoverError> {
        let saved_scan = self.store.scan_state().map_err(map_store_error)?;
        let Some(last_block_to_scan) = self.find_last_block_to_scan(&saved_scan).await? else {
            return Ok(());
        };
        let mut last_verified_header = self.load_previous_verified_header(&saved_scan).await?;

        // Transaction inputs expose nullifiers, so use them to match saved notes to faucet burns.
        let mut burn_notes_by_nullifier = self
            .store
            .candidates()
            .map_err(map_store_error)?
            .into_iter()
            .map(|candidate| (candidate.nullifier(), candidate))
            .collect();

        // The anchor itself needs scanning once when it is also the faucet's deployment block.
        if saved_scan.authenticated_parent.is_none()
            && saved_scan.cursor.next_block == self.config.trusted_anchor_block()
        {
            let anchor = self
                .trusted_anchor_block
                .clone()
                .ok_or(DiscoverError::InvalidStore)?;
            self.scan_and_save_block(&anchor, &mut burn_notes_by_nullifier)?;
        }

        let first_block_to_scan = last_verified_header.block_num().child();
        for block_num in block_range(first_block_to_scan, last_block_to_scan) {
            let block = self
                .fetch_and_verify_block(block_num, &last_verified_header)
                .await?;
            self.scan_and_save_block(&block, &mut burn_notes_by_nullifier)?;
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
            .scan_limits(last_verified_block_number)
            .await
            .map_err(DiscoverError::Chain)?;

        // Node-reported heights limit our scan; only block validation can authenticate its data.
        let Some(last_depth_safe_block) = scan_limits
            .latest_committed_block
            .checked_sub(self.config.minimum_finality_depth_blocks())
        else {
            return if saved_scan.authenticated_parent.is_some() {
                Err(DiscoverError::ChainDiverged)
            } else {
                Ok(None)
            };
        };
        let last_block_to_scan = std::cmp::min(scan_limits.proof_lag_block, last_depth_safe_block);
        if last_block_to_scan < last_verified_block_number {
            return Err(DiscoverError::ChainDiverged);
        }
        if last_block_to_scan < saved_scan.cursor.next_block {
            return Ok(None);
        }
        if last_block_to_scan == BlockNumber::MAX {
            return Err(DiscoverError::CursorOverflow);
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
                .ok_or(DiscoverError::InvalidStore)?,
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

    fn scan_and_save_block(
        &mut self,
        block: &ProvenBlock,
        burn_notes_by_nullifier: &mut BTreeMap<Nullifier, BurnCandidate>,
    ) -> Result<(), DiscoverError> {
        let (new_burn_notes, new_burns) = find_burns_in_block(
            block,
            self.config.faucet_account_id(),
            self.burn_note_script_root,
            burn_notes_by_nullifier,
        );
        // Save this block atomically; a later RPC failure must not discard its progress.
        self.store
            .save_scan_progress(
                &new_burn_notes,
                &new_burns,
                &ScanState {
                    cursor: ScanCursor {
                        next_block: block.header().block_num().child(),
                    },
                    authenticated_parent: Some(block.header().clone()),
                },
            )
            .map_err(map_store_error)
    }

    async fn fetch_and_verify_block(
        &self,
        block_num: BlockNumber,
        last_verified_header: &BlockHeader,
    ) -> Result<ProvenBlock, DiscoverError> {
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

fn find_burns_in_block(
    block: &ProvenBlock,
    faucet_account_id: miden_protocol::account::AccountId,
    burn_note_script_root: NoteScriptRoot,
    burn_notes_by_nullifier: &mut BTreeMap<Nullifier, BurnCandidate>,
) -> (Vec<BurnCandidate>, Vec<DiscoveredBurn>) {
    let mut new_burn_notes = Vec::new();
    let mut new_burns = Vec::new();
    let block_num = block.header().block_num();
    for (_, output_note) in block
        .body()
        .output_note_batches()
        .iter()
        .flat_map(|batch| batch.iter())
    {
        let OutputNote::Public(note) = output_note else {
            continue;
        };
        // Tags are forgeable. The full public note is selected by its authenticated script root.
        if note.recipient().script().root() != burn_note_script_root {
            continue;
        }
        let candidate = BurnCandidate {
            note: note.clone(),
            creation_block: block_num,
        };
        burn_notes_by_nullifier.insert(candidate.nullifier(), candidate.clone());
        new_burn_notes.push(candidate);
    }

    // Transaction headers from this validated block authenticate the consuming account, input
    // nullifiers, and transaction ID. Do not use `created_nullifiers`, which `validate` does not
    // authenticate.
    for transaction in block.body().transactions().as_slice() {
        if transaction.account_id() != faucet_account_id {
            continue;
        }
        for input_note in transaction.input_notes().iter() {
            if let Some(candidate) = burn_notes_by_nullifier.remove(&input_note.nullifier()) {
                new_burns.push(DiscoveredBurn {
                    note: candidate.note,
                    creation_block: candidate.creation_block,
                    consumption_block: block_num,
                    burn_tx_id: transaction.id(),
                });
            }
        }
    }

    (new_burn_notes, new_burns)
}

fn map_store_error(error: StoreError) -> DiscoverError {
    match error {
        StoreError::Conflict => DiscoverError::ConflictingEvidence,
        StoreError::Invalid | StoreError::Locked | StoreError::AnchorChanged => {
            DiscoverError::InvalidStore
        }
    }
}
