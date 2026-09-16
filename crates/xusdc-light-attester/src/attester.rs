//! Service startup and the sequential withdrawal-attester cycle.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use anyhow::Context;
use miden_protocol::block::{BlockHeader, BlockNumber, ProvenBlock};
use miden_protocol::note::Nullifier;
use miden_protocol::transaction::OutputNote;

use crate::burn::{validate_burn, BurnCandidate, DiscoveredBurn, ValidatedBurn};
use crate::chain::{ChainError, ChainReader};
use crate::circle::{CircleClient, HttpTransport};
use crate::config::Config;
use crate::signer::{Signer, SigningPublicKey};
use crate::store::{BurnHoldReason, ScanCursor, ScanState, Store, StoreError, TrustedAnchor};
use crate::submission::SavedSubmission;
use crate::verify::verify_prepared_response;

#[derive(Debug, thiserror::Error)]
pub enum CycleError {
    #[error("discovery stopped on a store failure")]
    Discovery(#[source] DiscoverError),
    #[error("withdrawal processing stopped")]
    Submission(#[from] SubmitError),
    #[error("polling stopped on a store failure")]
    Poll(#[source] SubmitError),
}

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
    Store(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("the scan height cannot be represented by the next-block cursor")]
    CursorOverflow,
}

impl From<StoreError> for DiscoverError {
    fn from(error: StoreError) -> Self {
        Self::Store(Box::new(error))
    }
}

pub use crate::submission::SubmitError;

#[derive(Debug)]
#[non_exhaustive]
pub struct CycleReport {
    pub discover: Result<(), DiscoverError>,
    pub submit: Result<(), SubmitError>,
}

pub struct Attester {
    pub(crate) config: Config,
    pub(crate) store: Store,
    chain: Box<dyn ChainReader>,
    pub(crate) circle: CircleClient,
    trusted_anchor_block: Option<ProvenBlock>,
    signers: [Box<dyn Signer>; 2],
    pub(crate) now: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle_transport: Box<dyn HttpTransport>,
        signers: [Box<dyn Signer>; 2],
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

        let [first, second] = config.expected_signing_public_keys_hex() else {
            anyhow::bail!("exactly two distinct, valid signing public keys are required");
        };
        let parse_key = |value: &str| {
            let mut bytes = [0; 33];
            hex::decode_to_slice(value.strip_prefix("0x").unwrap_or(value), &mut bytes)
                .context("configured signing public key is not valid hex")?;
            SigningPublicKey::from_compressed(bytes)
                .context("configured signing public key is not a valid curve point")
        };
        let expected = [parse_key(first)?, parse_key(second)?];
        let loaded = [
            signers[0]
                .public_key()
                .await
                .context("could not read a signing provider's public key")?,
            signers[1]
                .public_key()
                .await
                .context("could not read a signing provider's public key")?,
        ];
        if expected[0] == expected[1] || loaded[0] == loaded[1] {
            anyhow::bail!("exactly two distinct, valid signing public keys are required");
        }
        if !loaded.iter().all(|key| expected.contains(key)) {
            anyhow::bail!("loaded signing public keys do not match configuration");
        }

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
            trusted_anchor_block,
            signers,
            now: Box::new(SystemTime::now),
        })
    }

    /// Drives cycles until shutdown. Checks `shutdown` BETWEEN cycles and sleeps the full
    /// poll interval — no race, so no `select!` needed. Finishes the current cycle before
    /// returning on shutdown. A store failure aborts only this cycle; retry after the same delay.
    pub async fn run(&mut self, shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        while !shutdown.load(Ordering::Acquire) {
            match self.run_one_cycle().await {
                Ok(report) => {
                    if let Err(error) = report.discover {
                        eprintln!("discovery failed; new signing paused for this cycle: {error:?}");
                    }
                }
                Err(error) => eprintln!("cycle stopped; retrying after poll interval: {error:?}"),
            }
            tokio::time::sleep(self.config.poll_interval()).await;
        }
    }

    pub async fn run_one_cycle(&mut self) -> Result<CycleReport, CycleError> {
        let discover = self.discover_burns().await;
        if let Err(error @ DiscoverError::Store(_)) = discover {
            return Err(CycleError::Discovery(error));
        }

        // Snapshot the ledger before any submission changes status. Work that expires or is
        // newly submitted in this cycle must not be prepared or polled again in the same cycle.
        let recovery = self
            .store
            .submissions_to_recover()
            .map_err(SubmitError::from)?;
        let polling = self
            .store
            .submissions_to_poll()
            .map_err(SubmitError::from)?;
        let fresh = match &discover {
            Ok(proof_lag_block) => self
                .validate_ready_burns(*proof_lag_block)
                .map_err(SubmitError::from)?,
            Err(_) => Vec::new(),
        };
        self.recover_submissions(recovery).await?;
        let submit = self.submit_withdrawals(fresh).await;
        if let Err(
            error @ (SubmitError::InvalidStore | SubmitError::Conflict | SubmitError::Clock),
        ) = submit
        {
            return Err(CycleError::Submission(error));
        }
        self.poll_withdrawal_statuses(polling)
            .await
            .map_err(CycleError::Poll)?;
        Ok(CycleReport {
            discover: discover.map(|_| ()),
            submit,
        })
    }

    pub(crate) async fn discover_burns(&mut self) -> Result<BlockNumber, DiscoverError> {
        let saved_scan = self.store.scan_state()?;
        let scan_limits = self
            .chain
            .scan_limits()
            .await
            .map_err(DiscoverError::Chain)?;
        let Some(last_block_to_scan) =
            self.find_last_block_to_scan(&saved_scan, scan_limits.latest_committed_block)?
        else {
            return Ok(scan_limits.proof_lag_block);
        };
        let mut last_verified_header = self.load_previous_verified_header(&saved_scan).await?;

        // Transaction inputs expose nullifiers, so use them to match saved notes to faucet burns.
        let mut burn_notes_by_nullifier = self
            .store
            .candidates()?
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
                .ok_or(StoreError::Invalid)?;
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

        Ok(scan_limits.proof_lag_block)
    }

    fn find_last_block_to_scan(
        &self,
        saved_scan: &ScanState,
        last_block_to_scan: BlockNumber,
    ) -> Result<Option<BlockNumber>, DiscoverError> {
        let last_verified_block_number = saved_scan
            .authenticated_parent
            .as_ref()
            .map_or(self.config.trusted_anchor_block(), BlockHeader::block_num);
        // Scan every available block. Withdrawal readiness separately requires verified depth.
        if last_block_to_scan < last_verified_block_number {
            return Err(DiscoverError::ChainDiverged);
        }
        if last_block_to_scan < saved_scan.cursor.next_block {
            return Ok(None);
        }
        if last_block_to_scan == BlockNumber::MAX {
            return Err(DiscoverError::CursorOverflow);
        }

        // This bound also keeps the parent and predeployment child() calls below overflow.
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
                .ok_or(StoreError::Invalid)?,
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
        let next_block = block
            .header()
            .block_num()
            .as_u32()
            .checked_add(1)
            .map(BlockNumber::from)
            .ok_or(DiscoverError::CursorOverflow)?;
        let (new_burn_notes, new_burns) = find_burns_in_block(
            block,
            self.config.faucet_account_id(),
            burn_notes_by_nullifier,
        );
        // Save this block atomically; a later RPC failure must not discard its progress.
        self.store.save_scan_progress(
            &new_burn_notes,
            &new_burns,
            &ScanState {
                cursor: ScanCursor { next_block },
                authenticated_parent: Some(block.header().clone()),
            },
        )?;
        Ok(())
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

    pub(crate) fn validate_ready_burns(
        &mut self,
        proof_lag_block: BlockNumber,
    ) -> Result<Vec<ValidatedBurn>, StoreError> {
        let burns = self.store.burns_ready_for_withdrawal(
            proof_lag_block,
            self.config.minimum_finality_depth_blocks(),
        )?;
        let mut validated = Vec::new();
        for burn in burns {
            let note_id = burn.note_id();
            let burn_tx_id = burn.burn_tx_id();
            match validate_burn(burn) {
                Ok(burn) => validated.push(burn),
                Err(reason) => {
                    self.store.refuse_burn(note_id, reason)?;
                    eprintln!(
                        "refused burn: note={} transaction={} reason={}",
                        note_id,
                        burn_tx_id,
                        reason.as_str()
                    );
                }
            }
        }
        Ok(validated)
    }

    async fn submit_withdrawals(&mut self, burns: Vec<ValidatedBurn>) -> Result<(), SubmitError> {
        let mut first_error = None;
        for burn in burns {
            let note_id = burn.burn.note_id();
            // A waiting burn must not spend a prepare call or block smaller burns behind it.
            if !self.store.can_submit_burn(
                note_id,
                burn.amount,
                self.now_ms()?,
                self.config.withdrawal_window_ms(),
                self.config.withdrawal_limit(),
            )? {
                continue;
            }
            let result = async {
                let prepared = self
                    .circle
                    .prepare_withdrawal(&burn, self.config.use_circle_forwarding())
                    .await?;
                let verified = verify_prepared_response(&burn, prepared, &self.config)
                    .map_err(|error| SubmitError::Verification(Box::new(error)))?;
                let signed = verified
                    .sign([self.signers[0].as_ref(), self.signers[1].as_ref()])
                    .await?;
                self.submit_signed_withdrawal(&signed).await
            }
            .await;
            if let Err(error) = result {
                if matches!(
                    error,
                    SubmitError::InvalidStore | SubmitError::Conflict | SubmitError::Clock
                ) {
                    return Err(error);
                }
                let hold = match &error {
                    SubmitError::Prepare(CircleError::UnexpectedPrepareStatus {
                        status, ..
                    }) if !status.is_server_error() => Some(BurnHoldReason::PrepareRejected),
                    SubmitError::Prepare(CircleError::InvalidResponse(_)) => {
                        Some(BurnHoldReason::PrepareRejected)
                    }
                    SubmitError::Verification(_) => Some(BurnHoldReason::VerifyFailed),
                    _ => None,
                };
                if let Some(reason) = hold {
                    self.store.hold_burn(note_id, reason)?;
                }
                // Transport/server and signing failures remain eligible next cycle.
                eprintln!("withdrawal note={note_id} failed before submission: {error:?}");
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(crate) async fn poll_withdrawal_statuses(
        &mut self,
        submissions: Vec<SavedSubmission>,
    ) -> Result<(), SubmitError> {
        // Each saved ID gets one GET; the shared handler persists its outcome before we continue.
        for saved in submissions {
            self.advance_submission(saved).await?;
        }
        Ok(())
    }
}

fn block_range(start: BlockNumber, end: BlockNumber) -> impl Iterator<Item = BlockNumber> {
    (start.as_u32()..=end.as_u32()).map(BlockNumber::from)
}

fn find_burns_in_block(
    block: &ProvenBlock,
    faucet_account_id: miden_protocol::account::AccountId,
    burn_notes_by_nullifier: &mut BTreeMap<Nullifier, BurnCandidate>,
) -> (Vec<BurnCandidate>, Vec<DiscoveredBurn>) {
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
        let Ok(candidate) = BurnCandidate::try_new(note.clone(), block_num, faucet_account_id)
        else {
            continue;
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
                new_burns.push(candidate.into_discovered(block_num, transaction.id()));
            }
        }
    }

    (new_burn_notes, new_burns)
}
