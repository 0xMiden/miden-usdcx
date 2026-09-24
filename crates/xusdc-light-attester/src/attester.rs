//! Service startup and the sequential withdrawal-attester cycle.

use std::time::{Duration, SystemTime};

use anyhow::Context;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::transaction::OutputNote;
use reqwest::StatusCode;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::burn::{validate_burn, BurnCandidate, DiscoveredBurn, ValidatedBurn};
use crate::chain::{ChainError, ChainReader};
use crate::circle::{circle_message, CircleApi, CircleError};
use crate::config::Config;
use crate::signer::{Signer, SignerPair};
use crate::store::{BurnHoldReason, ScanCursor, ScanState, Store, TrustedAnchor, INVALID};
use crate::verify::VerifyError;

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

pub use crate::submission::SubmitError;

/// While Circle keeps answering 429, the pause between cycles doubles up to this limit.
const MAX_RATE_LIMITED_PAUSE: Duration = Duration::from_secs(60);

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
    pub(crate) circle: Box<dyn CircleApi>,
    trusted_anchor_block: Option<SignedBlock>,
    signers: SignerPair,
    pub(crate) now: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle: Box<dyn CircleApi>,
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

        let signers = SignerPair::new(signers, config.expected_signing_public_keys_hex()).await?;

        circle
            .check_connection()
            .await
            .context("failed to connect to the Circle API")?;

        let mut store = Store::open_or_create(
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
        if config.release_holds() {
            let (burns, withdrawals) = store
                .release_all_holds()
                .context("failed to release held burns and withdrawals")?;
            info!(burns, withdrawals, "released held burns and withdrawals");
        }

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

    /// Drives cycles until `shutdown` is cancelled. A cancellation cuts the sleep between cycles
    /// short but never interrupts a running cycle, so the store is always left at a cycle boundary.
    /// A store failure aborts only this cycle; the next one runs after the usual pause. After
    /// Circle answers 429, that pause doubles each cycle, up to a minute, until a cycle passes
    /// without one.
    pub async fn run(&mut self, shutdown: CancellationToken) {
        let mut pause = self.config.poll_interval();
        while !shutdown.is_cancelled() {
            match self.run_one_cycle().await {
                Ok(report) => {
                    if let Err(error) = report.discover {
                        warn!(
                            error = &error as &dyn std::error::Error,
                            "discovery failed; new signing paused for this cycle"
                        );
                    }
                }
                Err(error) => {
                    error!(
                        error = %format_args!("{error:#}"),
                        "cycle stopped; retrying after the pause between cycles"
                    );
                }
            }
            pause = if self.circle.rate_limited() {
                pause
                    .saturating_mul(2)
                    .min(MAX_RATE_LIMITED_PAUSE)
                    .max(self.config.poll_interval())
            } else {
                self.config.poll_interval()
            };
            tokio::select! {
                () = shutdown.cancelled() => {}
                () = tokio::time::sleep(pause) => {}
            }
        }
    }

    pub async fn run_one_cycle(&mut self) -> anyhow::Result<CycleReport> {
        self.circle.reset_rate_limit();
        let discover = self.discover_burns().await;
        // Only an unreachable node lets the rest of the cycle run. A store failure or a diverged
        // chain ends this cycle; the next one starts after the usual pause, and a diverged chain
        // keeps stopping every cycle until an operator has looked.
        if let Err(error @ (DiscoverError::Store(_) | DiscoverError::ChainDiverged)) = discover {
            return Err(error).context("discovery stopped");
        }

        // Snapshot the ledger before any submission changes status. Work that expires or is
        // newly submitted in this cycle must not be prepared or polled again in the same cycle.
        let recovery = self.store.submissions_to_recover()?;
        let polling = self.store.submissions_to_poll()?;
        let fresh = match &discover {
            Ok(proof_lag_block) => self.validate_ready_burns(*proof_lag_block)?,
            Err(_) => Vec::new(),
        };
        self.advance_submissions(recovery)
            .await
            .context("withdrawal processing stopped")?;
        let submit = match self.submit_withdrawals(fresh).await {
            Err(error) if error.is_fatal() => {
                return Err(error).context("withdrawal processing stopped")
            }
            submit => submit,
        };
        self.advance_submissions(polling)
            .await
            .context("polling stopped")?;
        Ok(CycleReport {
            discover: discover.map(|_| ()),
            submit,
        })
    }

    /// Scans the blocks that became final since the saved checkpoint. Each block's burn
    /// candidates and faucet consumptions are saved together with the advanced cursor and the
    /// block's header, one block per store transaction, so a crash never skips or half-records
    /// a block. Returns the node's proof-lag height, the bound for withdrawal readiness.
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

    /// Validates the burns that reached the configured waiting depth. A burn whose withdrawal
    /// payload does not decode is marked refused in the store, for good, so it is never loaded
    /// again; the rest are returned for submission.
    pub(crate) fn validate_ready_burns(
        &mut self,
        proof_lag_block: BlockNumber,
    ) -> anyhow::Result<Vec<ValidatedBurn>> {
        let burns = self.store.burns_ready_for_withdrawal(
            proof_lag_block,
            self.config.minimum_finality_depth_blocks(),
        )?;
        let mut validated = Vec::new();
        for burn in burns {
            let note_id = burn.note_id();
            let burn_tx_id = burn.burn_tx_id();
            match validate_burn(burn) {
                Some(burn) => validated.push(burn),
                None => {
                    self.store.refuse_burn(note_id)?;
                    warn!(
                        note_id = %note_id,
                        burn_transaction_id = %burn_tx_id,
                        "refused burn: withdrawal payload does not decode"
                    );
                }
            }
        }
        Ok(validated)
    }

    /// Takes each validated burn through prepare, verify, sign and submit. A store or clock
    /// failure stops the pass. A prepare 400, or a forwarded burn too small to pay the CCTP fee,
    /// holds the burn; any other failure is logged and retried next cycle. After a 429 the
    /// remaining burns wait for the next cycle.
    async fn submit_withdrawals(&mut self, burns: Vec<ValidatedBurn>) -> Result<(), SubmitError> {
        let mut first_error = None;
        for burn in burns {
            if self.circle.rate_limited() {
                break;
            }
            let note_id = burn.burn.note_id();
            // A waiting burn must not spend a prepare call or block smaller burns behind it.
            if !self.store.can_submit_burn(
                note_id,
                burn.amount,
                self.now_ms()?,
                self.config.withdrawal_window_ms(),
                self.config.withdrawal_limit(),
            )? {
                if burn.amount > self.config.withdrawal_limit() {
                    warn!(
                        note_id = %note_id,
                        amount = burn.amount,
                        limit = self.config.withdrawal_limit(),
                        "burn exceeds the withdrawal limit and waits until it is raised"
                    );
                }
                continue;
            }
            if let Err(error) = self.withdraw(&burn).await {
                if error.is_fatal() {
                    return Err(error);
                }
                let (hold, message) = burn_hold(&error);
                if let Some(reason) = hold {
                    self.store.hold_burn(note_id, reason)?;
                }
                warn!(
                    note_id = %note_id,
                    error = &error as &dyn std::error::Error,
                    hold_reason = ?hold,
                    circle_message = message.as_deref(),
                    "withdrawal failed before submission"
                );
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Prepares one burn's withdrawal with Circle, verifies the reply, signs it and submits it.
    async fn withdraw(&mut self, burn: &ValidatedBurn) -> Result<(), SubmitError> {
        let prepared = self
            .circle
            .prepare_withdrawal(burn, self.config.cctp_forwarding().0)
            .await?;
        let verified = prepared
            .verify(burn, &self.config)
            .map_err(|error| SubmitError::Verification(Box::new(error)))?;
        let signed = verified.sign(self.signers.as_refs()).await?;
        self.submit_signed_withdrawal(&signed).await
    }
}

/// The hold that a failure before submission puts on its burn, if any, and Circle's message for
/// the log.
pub(crate) fn burn_hold(error: &SubmitError) -> (Option<BurnHoldReason>, Option<String>) {
    match error {
        // A 400 is Circle refusing to prepare this burn.
        SubmitError::Prepare(CircleError::UnexpectedPrepareStatus { status, body })
            if *status == StatusCode::BAD_REQUEST =>
        {
            (Some(BurnHoldReason::PrepareRejected), circle_message(body))
        }
        // A forwarded burn too small to pay the configured CCTP fee fails the same way every
        // cycle until that fee changes.
        SubmitError::Verification(cause)
            if cause.downcast_ref::<VerifyError>() == Some(&VerifyError::TooSmallToForward) =>
        {
            (Some(BurnHoldReason::TooSmallToForward), None)
        }
        // Any other failure, including a reply that fails our other checks, is tried again next
        // cycle.
        _ => (None, None),
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
