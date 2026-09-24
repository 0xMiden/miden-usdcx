//! Service startup and the sequential withdrawal-attester cycle.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::note::NoteId;
use miden_protocol::transaction::OutputNote;
use miden_protocol::Word;
use reqwest::StatusCode;
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

use crate::burn::{validate_burn, BurnCandidate, DiscoveredBurn, ValidatedBurn};
use crate::chain::{ChainError, ChainReader};
use crate::circle::{circle_message, CircleApi, CircleError};
use crate::config::Config;
use crate::signer::SignerPair;
use crate::store::{BurnHoldReason, ScanCursor, ScanState, Store, TrustedAnchor, INVALID};
use crate::submission::SavedSubmission;

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

pub use crate::store::Hold;
pub use crate::submission::SubmitError;
pub use crate::verify::VerifyError;

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
}

impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle: Box<dyn CircleApi>,
        signers: SignerPair,
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

        signers.check_expected(config.expected_signing_public_keys_hex())?;

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
        let trusted_anchor_block = scan_state.authenticated_parent.is_none().then_some(block);
        // After a divergence, a restart must not send saved withdrawals while the node still
        // disagrees with the saved checkpoint.
        if let Some(checkpoint) = &scan_state.authenticated_parent {
            check_checkpoint(chain.as_ref(), checkpoint)
                .await
                .context("failed to check the saved checkpoint against the Miden node")?;
        }
        Ok(Self {
            config,
            store,
            chain,
            circle,
            trusted_anchor_block,
            signers,
        })
    }

    /// Drives cycles until `shutdown` is cancelled. A cancellation cuts the sleep between cycles
    /// short but never interrupts a running cycle, so the store is always left at a cycle boundary.
    /// A store failure aborts only this cycle; the next one runs after the usual pause. After
    /// Circle answers 429, that pause doubles each cycle, up to a minute, until a cycle passes
    /// without one. A diverged chain ends the run with its error.
    pub async fn run(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let mut pause = self.config.poll_interval();
        while !shutdown.is_cancelled() {
            let mut rate_limited = false;
            match self.cycle(&mut rate_limited).await {
                Ok(report) => {
                    if let Err(error) = report.discover {
                        warn!(
                            error = &error as &dyn std::error::Error,
                            "discovery failed; new signing paused for this cycle"
                        );
                    }
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<DiscoverError>(),
                        Some(DiscoverError::ChainDiverged)
                    ) =>
                {
                    return Err(error);
                }
                Err(error) => {
                    error!(
                        error = %format_args!("{error:#}"),
                        "cycle stopped; retrying after the pause between cycles"
                    );
                }
            }
            pause = if rate_limited {
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
        Ok(())
    }

    /// Runs one cycle on its own; a 429 from an earlier cycle does not carry over.
    #[cfg(test)]
    pub async fn run_one_cycle(&mut self) -> anyhow::Result<CycleReport> {
        self.cycle(&mut false).await
    }

    /// Circle's 429 sets `rate_limited`: the rest of the cycle then leaves Circle alone, and
    /// [`Self::run`] reads it to pace the next cycle.
    async fn cycle(&mut self, rate_limited: &mut bool) -> anyhow::Result<CycleReport> {
        let (proof_lag_block, discover) = discovery_outcome(self.discover_burns().await)?;

        let (to_recover, to_poll) = self.snapshot_submissions()?;
        let fresh_burns = match proof_lag_block {
            Some(block) => self.validate_ready_burns(block)?,
            None => Vec::new(),
        };

        self.advance_submissions(to_recover, rate_limited)
            .await
            .context("recovery stopped")?;
        let submit = self
            .submit_withdrawals(fresh_burns, rate_limited)
            .await
            .context("submission stopped")?;
        self.advance_submissions(to_poll, rate_limited)
            .await
            .context("polling stopped")?;
        Ok(CycleReport { discover, submit })
    }

    /// Loads the saved submissions to recover and to poll before anything changes their status,
    /// so work that expires or is newly submitted in this cycle waits for the next one.
    fn snapshot_submissions(&self) -> anyhow::Result<(Vec<SavedSubmission>, Vec<SavedSubmission>)> {
        Ok((
            self.store.submissions_to_recover()?,
            self.store.submissions_to_poll()?,
        ))
    }

    /// Scans the blocks committed since the saved checkpoint. Each block's burn
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
            // No new block to authenticate, so compare the saved checkpoint with the node's block
            // at that height: a same-height fork shows up only there.
            if let Some(checkpoint) = &saved_scan.authenticated_parent {
                check_checkpoint(self.chain.as_ref(), checkpoint).await?;
            }
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
        // inspect their notes because scanning starts at the store's scan start.
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

    /// Takes each validated burn through prepare, verify, sign and submit. A store error stops the
    /// cycle. A prepare 400, or a forwarded burn too small to pay the CCTP fee, holds the burn.
    /// Other errors are retried next cycle while later burns continue. A 429 stops Circle requests
    /// for this cycle.
    async fn submit_withdrawals(
        &mut self,
        burns: Vec<ValidatedBurn>,
        rate_limited: &mut bool,
    ) -> Result<Result<(), SubmitError>, SubmitError> {
        let mut first_error = None;
        for burn in burns {
            if *rate_limited {
                break;
            }
            let note_id = burn.burn.note_id();
            if let Err(error) = self.withdraw(&burn, rate_limited).await {
                if error.is_fatal() {
                    return Err(error);
                }
                let (hold, response, message) = burn_hold(&error);
                if let Some(reason) = hold {
                    self.store.hold_burn(note_id, reason, response)?;
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
        Ok(first_error.map_or(Ok(()), Err))
    }

    /// Prepares one burn's withdrawal with Circle, verifies the reply, signs it and submits it.
    async fn withdraw(
        &mut self,
        burn: &ValidatedBurn,
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        let prepared = self
            .circle
            .prepare_withdrawal(burn, self.config.cctp_forwarding().0)
            .await
            .inspect_err(|error| {
                *rate_limited |= matches!(error, CircleError::RateLimited { .. });
            })?;
        let verified = prepared.verify(burn, &self.config)?;
        let signed = verified.sign(&self.signers).await?;
        self.submit_signed_withdrawal(&signed, rate_limited).await
    }
}

/// Lists every held burn and held withdrawal in an existing store. Only the store is opened: no
/// Miden node, Circle service or signer is contacted.
pub fn list_holds(
    path: &Path,
    faucet_account_id: AccountId,
    anchor_block: BlockNumber,
    anchor_commitment: Word,
) -> anyhow::Result<Vec<Hold>> {
    open_existing(path, faucet_account_id, anchor_block, anchor_commitment)?.holds()
}

/// Releases the named holds in an existing store, and returns how many burns and withdrawals it
/// released. Only the store is opened: no Miden node, Circle service or signer is contacted.
pub fn release_holds(
    path: &Path,
    faucet_account_id: AccountId,
    anchor_block: BlockNumber,
    anchor_commitment: Word,
    note_ids: &[NoteId],
) -> anyhow::Result<(usize, usize)> {
    open_existing(path, faucet_account_id, anchor_block, anchor_commitment)?.release_holds(note_ids)
}

/// The existing store at `path`, checked against its faucet and trusted anchor; never created here.
fn open_existing(
    path: &Path,
    faucet_account_id: AccountId,
    anchor_block: BlockNumber,
    anchor_commitment: Word,
) -> anyhow::Result<Store> {
    Store::open_existing(
        path,
        faucet_account_id,
        TrustedAnchor {
            block_num: anchor_block,
            commitment: anchor_commitment,
        },
    )
}

/// Successful discovery returns the proof-lag height. A chain read failure lets recovery and
/// polling continue without new burns. A store error stops the cycle, and a chain divergence stops
/// the service.
fn discovery_outcome(
    discover: Result<BlockNumber, DiscoverError>,
) -> anyhow::Result<(Option<BlockNumber>, Result<(), DiscoverError>)> {
    match discover {
        Ok(proof_lag_block) => Ok((Some(proof_lag_block), Ok(()))),
        Err(error @ DiscoverError::Chain(_)) => Ok((None, Err(error))),
        Err(error @ (DiscoverError::Store(_) | DiscoverError::ChainDiverged)) => {
            Err(error).context("discovery stopped")
        }
    }
}

/// The hold that a failure before submission puts on its burn, its HTTP evidence, and Circle's
/// message for the log.
pub(crate) fn burn_hold(
    error: &SubmitError,
) -> (Option<BurnHoldReason>, Option<(u16, &[u8])>, Option<String>) {
    match error {
        // A 400 is Circle refusing to prepare this burn.
        SubmitError::Prepare(CircleError::UnexpectedPrepareStatus { status, body })
            if *status == StatusCode::BAD_REQUEST =>
        {
            (
                Some(BurnHoldReason::PrepareRejected),
                Some((status.as_u16(), body)),
                circle_message(body),
            )
        }
        // A forwarded burn too small to pay the configured CCTP fee fails the same way every
        // cycle until that fee changes.
        SubmitError::Verification(cause)
            if cause.downcast_ref::<VerifyError>() == Some(&VerifyError::TooSmallToForward) =>
        {
            (Some(BurnHoldReason::TooSmallToForward), None, None)
        }
        // Any other failure, including a reply that fails our other checks, is tried again next
        // cycle.
        _ => (None, None, None),
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

/// Fails with a divergence when the node's block at the checkpoint's height is another block.
async fn check_checkpoint(
    chain: &dyn ChainReader,
    checkpoint: &BlockHeader,
) -> Result<(), DiscoverError> {
    let block = chain
        .block_by_number(checkpoint.block_num())
        .await
        .map_err(DiscoverError::Chain)?;
    if block.header().commitment() != checkpoint.commitment() {
        return Err(DiscoverError::ChainDiverged);
    }
    Ok(())
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
