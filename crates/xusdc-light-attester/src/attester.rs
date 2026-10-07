//! Service startup and the sequential withdrawal-attester cycle.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockHeader, BlockNumber, SignedBlock};
use miden_protocol::note::NoteId;
use miden_protocol::transaction::OutputNote;
use miden_protocol::Word;
use reqwest::StatusCode;
use tokio_util::sync::CancellationToken;
use tracing::field::Empty;
use tracing::{error, info_span, instrument, Instrument as _, Span};
use usdcx_telemetry::FailureClass::{Actionable, Integrity, Transient};
use usdcx_telemetry::{Classified, Classify as _, Failure, FailureClass, FailureSpanExt as _};

use crate::burn::{BurnCandidate, DiscoveredBurn};
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

/// A failed chain read is retried next cycle, a diverged chain is never trusted again, and a store
/// failure needs an operator.
impl Classified for DiscoverError {
    fn failure(&self) -> FailureClass {
        match self {
            Self::Chain(_) => Transient("chain_read"),
            Self::ChainDiverged => Integrity("chain_diverged"),
            Self::Store(_) => Actionable("store"),
        }
    }
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
    /// The node's latest committed block, as this cycle's discovery read it.
    node_tip: Option<BlockNumber>,
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
            node_tip: None,
        })
    }

    /// Drives cycles until `shutdown` is cancelled. A cancellation cuts the sleep between cycles
    /// short but never interrupts a running cycle, so the store is always left at a cycle boundary.
    /// A store failure aborts only this cycle; the next one runs after the usual pause. After
    /// Circle answers 429, that pause doubles each cycle, up to a minute, until a cycle passes
    /// without one. A diverged chain ends the run with its error.
    ///
    /// Each cycle is an `attester.cycle` span with no parent, carrying the cycle's progress.
    pub async fn run(&mut self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let mut pause = self.config.poll_interval();
        while !shutdown.is_cancelled() {
            let mut rate_limited = false;
            self.traced_cycle(&mut rate_limited).await?;
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

    /// Runs one cycle in its `attester.cycle` span, logs how it ended and writes its progress on the
    /// span. Returns the error that ends the run, which is a diverged chain.
    #[instrument(
        name = "attester.cycle",
        parent = None,
        skip_all,
        fields(
            block.number = Empty,
            tip.number = Empty,
            tip.stale_duration_secs = Empty,
            burns.held.count = Empty,
            withdrawals.held.count = Empty,
            withdrawals.failed.count = Empty,
            withdrawals.pending.count = Empty,
            burns.unfinished.count = Empty,
            burns.unfinished.oldest_age_blocks = Empty,
        )
    )]
    async fn traced_cycle(&mut self, rate_limited: &mut bool) -> anyhow::Result<()> {
        let ended = finish_cycle(self.cycle(rate_limited).await);
        if let Err(failure) = self
            .record_progress(&Span::current())
            .classify(FailureClass::Actionable, "store")
        {
            failure.report("could not read the cycle's progress");
        }
        ended
    }

    /// Runs one cycle on its own; a 429 from an earlier cycle does not carry over.
    #[cfg(test)]
    pub async fn run_one_cycle(&mut self) -> anyhow::Result<CycleReport> {
        self.cycle(&mut false)
            .await
            .map_err(|failure| failure.error)
    }

    /// Circle's 429 sets `rate_limited`: the rest of the cycle then leaves Circle alone, and
    /// [`Self::run`] reads it to pace the next cycle.
    ///
    /// Discovery, recovery, submission and polling each run in a child span of their own, opened
    /// every cycle even when the phase has nothing to do.
    ///
    /// Every error that stops a cycle without being discovery's is the store's.
    async fn cycle(&mut self, rate_limited: &mut bool) -> Result<CycleReport, Failure> {
        let discovered = self
            .discover_burns()
            .instrument(info_span!("attester.discover"))
            .await;
        let (proof_lag_block, discover) = discovery_outcome(discovered)?;

        let (to_recover, to_poll) = self.snapshot_submissions().classify(Actionable("store"))?;
        let fresh_burns = match proof_lag_block {
            Some(block) => self.ready_burns(block).classify(Actionable("store"))?,
            None => Vec::new(),
        };

        self.advance_submissions(to_recover, rate_limited)
            .instrument(info_span!("attester.recover"))
            .await
            .context("recovery stopped")
            .classify(Actionable("store"))?;
        let submit = self
            .submit_withdrawals(fresh_burns, rate_limited)
            .instrument(info_span!("attester.submit"))
            .await
            .context("submission stopped")
            .classify(Actionable("store"))?;
        self.advance_submissions(to_poll, rate_limited)
            .instrument(info_span!("attester.poll"))
            .await
            .context("polling stopped")
            .classify(Actionable("store"))?;
        Ok(CycleReport { discover, submit })
    }

    /// Writes the cycle's progress on its span: the last verified block, the node's tip and how
    /// long ago the verified block was made, then the held, failed, pending and unfinished work.
    /// Every field but the tip is written each cycle, zeros included, so the alerts always find
    /// them; the tip is left out when discovery could not read it.
    fn record_progress(&self, span: &Span) -> anyhow::Result<()> {
        let verified = match self.store.scan_state()?.authenticated_parent {
            Some(header) => header,
            None => self
                .trusted_anchor_block
                .as_ref()
                .map(|block| block.header().clone())
                .context(INVALID)?,
        };
        let progress = self.store.progress()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let oldest_age_blocks = progress.oldest_unfinished_burn.map_or(0, |block| {
            verified.block_num().as_u32().saturating_sub(block.as_u32())
        });
        span.record("block.number", verified.block_num().as_u32());
        if let Some(tip) = self.node_tip {
            span.record("tip.number", tip.as_u32());
        }
        span.record(
            "tip.stale_duration_secs",
            now.saturating_sub(u64::from(verified.timestamp())),
        );
        span.record("burns.held.count", progress.burns_held);
        span.record("withdrawals.held.count", progress.withdrawals_held);
        span.record("withdrawals.failed.count", progress.withdrawals_failed);
        span.record("withdrawals.pending.count", progress.withdrawals_pending);
        span.record("burns.unfinished.count", progress.burns_unfinished);
        span.record("burns.unfinished.oldest_age_blocks", oldest_age_blocks);
        Ok(())
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
        self.node_tip = None;
        let saved_scan = self.store.scan_state()?;
        let scan_limits = self
            .chain
            .scan_limits()
            .await
            .map_err(DiscoverError::Chain)?;
        self.node_tip = Some(scan_limits.latest_committed_block);
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

    /// Loads the discovered burns that reached the configured waiting depth.
    pub(crate) fn ready_burns(
        &self,
        proof_lag_block: BlockNumber,
    ) -> anyhow::Result<Vec<DiscoveredBurn>> {
        self.store.burns_ready_for_withdrawal(
            proof_lag_block,
            self.config.minimum_finality_depth_blocks(),
        )
    }

    /// Takes each eligible burn through prepare, verify, sign and submit, each burn in an
    /// `attester.withdraw` span. A store error stops the cycle. A prepare 400, or a forwarded burn
    /// no larger than the CCTP fee, holds the burn. Other errors are retried next cycle while later
    /// burns continue. A 429 stops Circle requests for this cycle.
    async fn submit_withdrawals(
        &mut self,
        burns: Vec<DiscoveredBurn>,
        rate_limited: &mut bool,
    ) -> Result<Result<(), SubmitError>, SubmitError> {
        let mut first_error = None;
        for burn in burns {
            if *rate_limited {
                break;
            }
            match self.attempt_withdrawal(&burn, rate_limited).await {
                Ok(()) => {}
                Err(error) if error.is_fatal() => return Err(error),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Ok(first_error.map_or(Ok(()), Err))
    }

    /// Withdraws one burn in its own `attester.withdraw` span, so its failure lands there and never
    /// on the submission phase's span. A failure that is not fatal holds the burn when it calls for
    /// a hold, and is logged; a fatal one is returned for the cycle to stop on.
    #[instrument(name = "attester.withdraw", skip_all, fields(note.id = %burn.note_id()))]
    async fn attempt_withdrawal(
        &mut self,
        burn: &DiscoveredBurn,
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        let Err(error) = self.withdraw(burn, rate_limited).await else {
            return Ok(());
        };
        if error.is_fatal() {
            return Err(error);
        }
        let (hold, response, message) = burn_hold(&error);
        if let Some(reason) = hold {
            self.store.hold_burn(burn.note_id(), reason, response)?;
        }
        Span::current().record_error(&error);
        error!(
            note_id = %burn.note_id(),
            error = &error as &dyn std::error::Error,
            hold_reason = ?hold,
            circle_message = message.as_deref(),
            "withdrawal failed before submission"
        );
        Err(error)
    }

    /// Prepares one burn's withdrawal with Circle, verifies the reply, signs it and submits it.
    async fn withdraw(
        &mut self,
        burn: &DiscoveredBurn,
        rate_limited: &mut bool,
    ) -> Result<(), SubmitError> {
        let prepared = self
            .circle
            .prepare_withdrawal(burn, self.config.cctp_forwarding().max_fee)
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
) -> Result<(Option<BlockNumber>, Result<(), DiscoverError>), Failure> {
    match discover {
        Ok(proof_lag_block) => Ok((Some(proof_lag_block), Ok(()))),
        Err(error @ DiscoverError::Chain(_)) => Ok((None, Err(error))),
        Err(error @ (DiscoverError::Store(_) | DiscoverError::ChainDiverged)) => {
            Err(Failure::classified(error).context("discovery stopped"))
        }
    }
}

/// Logs how a cycle ended, inside its `attester.cycle` span. That span is marked failed only when
/// the cycle as a whole could not do its work: discovery failed, the chain diverged or the store
/// failed. A failure confined to one burn or one withdrawal leaves it alone. Returns the error that
/// ends the run, which is a diverged chain.
fn finish_cycle(outcome: Result<CycleReport, Failure>) -> anyhow::Result<()> {
    match outcome {
        Ok(CycleReport {
            discover: Ok(()), ..
        }) => Ok(()),
        Ok(CycleReport {
            discover: Err(error),
            ..
        }) => {
            Failure::classified(error)
                .report("discovery failed; new signing paused for this cycle");
            Ok(())
        }
        Err(failure) => {
            if matches!(
                failure.error.downcast_ref::<DiscoverError>(),
                Some(DiscoverError::ChainDiverged)
            ) {
                failure.report("chain diverged; stopping the attester");
                return Err(failure.error);
            }
            failure.report("cycle stopped; retrying after the pause between cycles");
            Ok(())
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
        // A forwarded burn no larger than the configured CCTP fee cannot pay it even without a
        // Circle fee, so it fails the same way every cycle until that fee changes.
        SubmitError::Verification(VerifyError::TooSmallToForward) => {
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
