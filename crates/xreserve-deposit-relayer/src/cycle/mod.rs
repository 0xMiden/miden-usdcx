//! **The orchestration** — `run_relayer_cycle`, the eight-step poll→validate→build→submit→track
//! pipeline, and the loop that runs it.
//!
//! # The one obligation this module exists to keep
//!
//! **No fetched attestation is ever silently dropped**. Every attestation the relayer pulls off a
//! Circle page leaves with a [`CycleEntry`] naming its fate and a reason for it, and raises one
//! [`RelayerEvent::Attestation`]. That is not a convention here; it is the shape of the code:
//!
//! * `classify_one` returns a `CycleEntry` — **not** a `Result`. There is no error to propagate,
//!   so there is no `?` in the loop, so there is no path on which a fetched attestation ends
//!   without a disposition. Every failure below is a DISPOSITION, not a return.
//! * The loop consumes the page BY VALUE and pushes one entry per element. It is a total map: it
//!   has no arity through which to lose an element. Reintroducing a drop would take a `filter`, a
//!   `continue`, or a `Result` on that path — each a visible edit, and each one a source sweep
//!   refuses.
//! * A reason is DERIVED from a typed value ([`Disposition::reason`]), so an entry with nothing to
//!   say is not constructible.
//!
//! A drop is not an error a caller could handle — it is an attestation that leaves no trace. So it
//! is designed out rather than tested for.
//!
//! # What a bug in here can and cannot do
//!
//! It can withhold a mint. It cannot authorize one. The authoritative parse, the amount reduction,
//! the nonce assert-then-set, the attester allowlist check, and the signature verification all
//! happen on-chain, inside the faucet's mint policy. Every gate below is the liveness mirror of one
//! of them, and the chain re-enforces all of them regardless of what the relayer decided.
//!
//! # The submit leg is a PORT
//!
//! [`MintSubmit`] has no production implementation — it needs a `miden-client` for v0.16, which has
//! no release. a later slice implements it. Nothing here fakes it (Miden behaviour must never be
//! faked), and `main` refuses to start without an adapter rather than mint nothing while looking
//! healthy.

pub mod submit;

use std::time::Instant;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;

use crate::circle::schema::{InfoResponse, ValidatedAttestation};
use crate::circle::{
    fetch_attestation_by_message_hash, fetch_info, poll_remote_domain_attestations, BatchQuery,
    CircleClient,
};
use crate::config::RelayerConfig;
use crate::error::RelayerError;
use crate::idempotency::{ClaimOutcome, IdempotencyStore};
use crate::miden::{build_mint_note, AttesterPubkey};
use crate::observability::{EventSink, RelayerEvent, RelayerMetrics};
use crate::validate::{check_domain_token_against_info, decode_and_validate_deposit_intent};

pub use submit::{production_submit_port, MintSubmission, MintSubmit, MintSubmitted};

mod report;

pub use report::{CycleEntry, CycleReport, Disposition};

/// The Miden identities a mint note is built from — fixed for the relayer's whole life, and every
/// one of them refused at STARTUP if it is malformed rather than at the first deposit.
///
/// Bundled because they travel together and are meaningless apart: the note is built BY `sender`
/// FOR `faucet` carrying `attester`'s key, and a builder taking three loose arguments — two of them
/// same-typed `AccountId`s with opposite meanings — is a builder in which swapping them still
/// compiles.
#[derive(Debug, Clone)]
pub struct MintIdentities {
    sender: AccountId,
    faucet: AccountId,
    attester: AttesterPubkey,
}

impl MintIdentities {
    /// The relayer's own account (the note's producer), the xUSDC faucet the note is routed at, and
    /// the operator-configured attester key that travels beside every signature.
    pub fn new(sender: AccountId, faucet: AccountId, attester: AttesterPubkey) -> Self {
        Self {
            sender,
            faucet,
            attester,
        }
    }

    /// Parses all three out of the operator's config.
    ///
    /// # Errors
    /// [`RelayerError::BadAccountId`] — `relayer_account_id` or `faucet_account_id` is not an
    /// `AccountId`. [`RelayerError::MalformedHex`] / [`RelayerError::BadAttesterPubkeyLength`] /
    /// [`RelayerError::InvalidAttesterPubkey`] — `attester_pubkey_hex` is not a 33-byte compressed
    /// SEC1 curve point. All refused here, at startup: a typo caught now costs a restart, and the
    /// same typo caught by the chain costs every mint until someone reads the logs.
    pub fn from_config(config: &RelayerConfig) -> Result<Self, RelayerError> {
        Ok(Self {
            sender: account_id("relayer_account_id", config.relayer_account_id())?,
            faucet: account_id("faucet_account_id", config.faucet_account_id())?,
            attester: AttesterPubkey::from_hex(config.attester_pubkey_hex())?,
        })
    }

    /// The relayer's own account — the mint note's sender/producer.
    pub fn sender(&self) -> AccountId {
        self.sender
    }

    /// The xUSDC faucet the mint note is routed at.
    pub fn faucet(&self) -> AccountId {
        self.faucet
    }

    /// The operator-configured attester public key. It is a KEY, not an authority: whether it is
    /// allowlisted is the faucet's `xReserveAttesters` to say, on-chain.
    pub fn attester(&self) -> &AttesterPubkey {
        &self.attester
    }
}

/// Parses a configured account id, naming the FIELD in the error — "some account id is bad" is not
/// something an operator can act on.
fn account_id(field: &'static str, value: &str) -> Result<AccountId, RelayerError> {
    AccountId::from_hex(value).map_err(|source| RelayerError::BadAccountId {
        field,
        value: value.to_string(),
        source: crate::error::Cause::new(source),
    })
}

/// Everything one [`run_relayer_cycle`] needs.
///
/// Borrowed and assembled by the caller, for the reason the withdrawal listener's `RunContext` is:
/// the seam that is PARKED (the submit adapter) is supplied from outside rather than
/// constructed here, so this module cannot grow a default for it. There is no default Circle
/// client, no default store, and above all no default submit port — a relayer missing one must not
/// start.
///
/// The metrics live here (owned, not borrowed) because they are the cycle's own running account of
/// what it did, and `&mut` is what keeps a counter from being bumped from two places at once.
pub struct RelayerCtx<'a, R: FeltRng> {
    config: &'a RelayerConfig,
    circle: &'a CircleClient,
    store: &'a IdempotencyStore,
    submit: &'a dyn MintSubmit,
    events: &'a dyn EventSink,
    identities: &'a MintIdentities,
    rng: &'a mut R,
    metrics: RelayerMetrics,
}

impl<'a, R: FeltRng> RelayerCtx<'a, R> {
    /// Assembles the context. Every part is required.
    pub fn new(
        config: &'a RelayerConfig,
        circle: &'a CircleClient,
        store: &'a IdempotencyStore,
        submit: &'a dyn MintSubmit,
        events: &'a dyn EventSink,
        identities: &'a MintIdentities,
        rng: &'a mut R,
    ) -> Self {
        Self {
            config,
            circle,
            store,
            submit,
            events,
            identities,
            rng,
            metrics: RelayerMetrics::new(),
        }
    }

    /// What this context's cycles have counted so far — cumulative across cycles, so a caller reads
    /// the service's totals rather than the last cycle's.
    pub fn metrics(&self) -> &RelayerMetrics {
        &self.metrics
    }
}

// THE ORCHESTRATION
// ================================================================================================

/// **Run ONE cycle: the eight steps below, in order.**
///
/// 1. **Poll** — `GET /v1/remote-domains/{d}/attestations` from the persisted cursor. Its envelope
///    checks (raw-keccak `messageHash == keccak256(payload)`, the 65-byte `r‖s‖v` shape — the
///    schema-decode and digest-binding checks) run inside the fetch, so what comes back is already
///    `ValidatedAttestation`: step 2 is the type, not a call.
/// 3. **Discovery** — `GET /v1/info` ONCE, and only if the optional fast-fail is on.
///
/// Steps 4–8 run per attestation, in `classify_one`, and then the cursor advances.
///
/// # Errors
/// A [`RelayerError`] from the PAGE fetch or the discovery fetch — the two steps that happen before
/// any attestation exists, so failing them drops nothing. A `400` fails the cycle; the next cycle
/// tries again from the same cursor. Nothing a single attestation does can fail this function: that
/// is what makes the no-drop invariant hold.
pub async fn run_relayer_cycle<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
) -> Result<CycleReport, RelayerError> {
    // The duration is recorded on EVERY exit — success or the early `?` of a broken poll/discovery/
    // store — so the latency histogram is not blind to failing cycles. The fallible body is
    // `run_cycle_inner`; this wrapper times it and records regardless of the outcome.
    let started = Instant::now();
    let outcome = run_cycle_inner(ctx).await;
    ctx.metrics
        .record_cycle_duration_ms(started.elapsed().as_millis() as u64);
    outcome
}

async fn run_cycle_inner<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
) -> Result<CycleReport, RelayerError> {
    let remote_domain = ctx.config.remote_domain();
    let mut entries = Vec::new();

    // ---- step 0 — the VALIDATED recovery policy, FIRST -----------------------------------------
    // Fail-closed on an operator config that cannot recover (a zero retry batch, a too-small stale
    // threshold): the binary refuses these at startup, and a directly invoked cycle refuses them here,
    // so the recovery machinery below never runs with an unsafe batch size or threshold.
    let recovery = ctx.config.recovery_policy()?;

    // ---- step 0a — free the CRASH-STRANDED: reclaim stale Pending claims, BEFORE discovery ------
    // A process death — or a terminal-state write that failed — between a claim and its settle leaves
    // a `Pending` record that `claim_nonce` blocks from re-claim and `retryable()` never returns. It
    // would be stranded forever. `reclaim_stale_pending` frees any `Pending` older than the validated
    // threshold back to `Failed` (re-claimable), so the retry drive below picks it up. It runs BEFORE
    // the optional `/v1/info` fetch, so a broken discovery endpoint cannot block local crash recovery —
    // reclaim is a purely local store operation and must not depend on Circle being reachable.
    ctx.store
        .reclaim_stale_pending(recovery.stale_claim_secs())?;

    // ---- step 3 (optional) — discovery, ONCE per cycle, BEFORE any per-attestation work --------
    // The answer is the same for every attestation this cycle handles — the retried ones AND the
    // freshly-polled ones — and Circle's ceiling is 5 QPS/IP, so it is fetched once and shared. A
    // failure here fails the CYCLE rather than quietly disabling the check: a fast-fail that stops
    // checking when discovery breaks is worse than one that is off, because the operator believes it
    // is on. (Reclaim above already ran, so this cannot block crash recovery.)
    let info = if ctx.config.domain_token_fast_fail() {
        Some(fetch_info(ctx.circle).await?)
    } else {
        None
    };

    // ---- step 0b — RECOVER the stranded: re-drive the retry work list ---------------------------
    // The cursor only moves forward, so a transient submit failure sits on a page the poll has
    // already passed and forward polling will never re-observe its attestation. `retryable()` is the
    // work list built for exactly this: each Failed record carries the `messageHash` its attestation
    // can be re-fetched by. Driven FIRST, so the oldest owed deposits are retried before new
    // ones are polled. A store-read failure here fails the cycle (nothing was fetched, so nothing is
    // dropped), the same as the cursor read below.
    drive_retry_queue(
        ctx,
        info.as_ref(),
        recovery.retry_batch_size(),
        &mut entries,
    )
    .await?;

    // ---- step 1 — poll one page, resuming from the persisted cursor ---------------------------
    let cursor = ctx.store.read_cursor(remote_domain)?;
    let query = BatchQuery::forward(
        ctx.config.poll_page_size(),
        cursor.as_ref().map(|c| c.page_after()),
    )?;
    let (page, cursors) =
        poll_remote_domain_attestations(ctx.circle, remote_domain, &query).await?;

    // ---- steps 4–7, per attestation ------------------------------------------------------------
    //
    // THE no-silent-drops shape. The page is consumed BY VALUE and every element pushes exactly one
    // entry: a total map, with no arity to lose an element through. `classify_one` returns a
    // `CycleEntry` and not a `Result`, so there is no `?` here that could skip a recording — every
    // failure inside it is a disposition, and a disposition is a report.
    let attestations = page.into_attestations();
    entries.reserve(attestations.len());
    for attestation in attestations {
        let entry = classify_one(ctx, attestation, info.as_ref()).await;
        record(ctx, &entry);
        entries.push(entry);
    }

    // ---- step 8 — advance the cursor ------------------------------------------------------------
    // An ABSENT `next` is the documented final page: the cursor is left where it is, because
    // there is no resume point past the end and writing an empty one would destroy the real one.
    let next_cursor = cursors.next_cursor().map(str::to_string);
    if let Some(next) = next_cursor.as_deref() {
        ctx.store.advance_cursor(remote_domain, next)?;
    }

    Ok(CycleReport::new(remote_domain, entries, next_cursor))
}

/// **Step 0 — re-drive the retry work list.** Re-fetch each stranded attestation by its
/// `messageHash`, and run it through the SAME pipeline as a freshly-polled one.
///
/// This is what makes a transient submit failure independent of the forward-only cursor. A `Failed`
/// record carries only its nonce and `messageHash` — not the payload or the signature — so the
/// retry cannot rebuild the note from the store alone; it re-fetches the attestation from Circle by
/// hash and hands the result to `classify_one`, which re-claims (the `Failed → Pending` edge),
/// rebuilds, and resubmits. A terminal `Rejected` record is NOT in this list, so a
/// permanently-refused deposit is never re-driven.
///
/// It is BOUNDED at [`RelayerConfig::retry_batch_size`] per cycle: the queue is drained a batch at
/// a time across cycles so one enormous backlog cannot starve the forward poll. The batch cannot be
/// monopolized by a stuck head, because every retry ATTEMPT re-stamps its row's timestamp, rotating
/// the tried rows behind the untried ones — so a persistently-unfetchable prefix does not starve
/// the tail. Every un-drained record stays `Failed` and is picked up a later cycle.
///
/// Every processed record pushes exactly one entry — a re-fetch that itself fails is reported
/// (`Deferred`) and leaves the record `Failed` (still owed), never dropped. No `filter`/`continue`
/// here, for the same reason the poll loop has none.
///
/// # Errors
/// [`RelayerError::IdempotencyStore`] / [`RelayerError::CorruptStoreRecord`] — the work list could not
/// be READ, or a re-stamp of a re-attempted row failed. Either fails the cycle (nothing was dropped;
/// the deposits stay `Failed` and are re-driven next cycle), the same as a failed cursor read.
async fn drive_retry_queue<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    info: Option<&InfoResponse>,
    batch_size: usize,
    entries: &mut Vec<CycleEntry>,
) -> Result<(), RelayerError> {
    let stranded = ctx.store.retryable(batch_size)?;
    for owed in stranded {
        let nonce = *owed.nonce_key();
        let message_hash = *owed.attestation_message_hash();
        let hash_hex = format!("0x{}", hex::encode(message_hash));

        let entry = match fetch_attestation_by_message_hash(ctx.circle, &hash_hex).await {
            // the attestation is back: run it through the one pipeline. `classify_one` re-claims the
            // Failed record (Failed → Pending), rebuilds, resubmits, and settles — so a retry that
            // fatally fails terminalizes, a transient one stays Failed, and a success lands. Its own
            // settle re-stamps the record, so a re-fetched-but-deferred one also rotates (below).
            Ok(attestation) => classify_one(ctx, attestation, info).await,
            // the re-fetch itself failed. The deposit is still owed and still valid (no intent
            // expiry), so it is reported as deferred and LEFT `Failed` — a later cycle re-fetches it.
            // It is not terminalized on a re-fetch error: a 404 (not published this second) or a
            // transient 5xx is not the deposit's fault, and the messageHash is well-formed by
            // construction, so a permanent 4xx is not a shape a valid stored hash produces.
            //
            // It IS rotated to the back of the timestamp-ordered work list via an ATOMIC CONDITIONAL
            // touch: `touch_failed_timestamp` re-stamps the row ONLY while it is still `Failed`. This
            // driver does not own the row (`retryable()` is a non-owning read another driver may share),
            // so an unconditional re-stamp could drag a row a concurrent driver has since claimed
            // (`Pending`) or submitted (`Submitted`) back to `Failed` — losing that driver's mint. The
            // conditional leaves any such live state untouched. The `?` propagates a real store failure
            // (a corrupt row): it is not swallowed, because a discarded error is how fairness silently
            // breaks.
            Err(error) => {
                ctx.store.touch_failed_timestamp(&nonce)?;
                CycleEntry::new(message_hash, Disposition::Deferred(error))
            }
        };

        record(ctx, &entry);
        entries.push(entry);
    }
    Ok(())
}

/// **Steps 4–7 for ONE attestation** — and the reason a drop is not expressible.
///
/// It returns a [`CycleEntry`], not a `Result<CycleEntry, _>`. Every refusal below becomes a
/// disposition; nothing propagates. So the caller's loop has no `?`, and an attestation that
/// reaches this function reaches a report.
///
/// The gates, in the documented order:
///
/// 4. **DepositIntent structural parse** through the shared encoding crate's codec — the liveness
///    mirror of the on-chain parse, which stays authoritative.
/// 5. **domain/token fast-fail**, if the operator turned it on (its expected values — the Miden
///    remote-domain id and the xUSDC identifier — are both Circle-owned and OPEN).
/// 6. **the idempotency claim** — atomic check-then-insert. The mint happens on `Claimed` and on
///    nothing else: the whole dedup, expressed as a type rather than as a discipline.
/// 7. build the note (the shared encoding crate's factory), submit it through the port, record the
///    outcome.
async fn classify_one<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    attestation: ValidatedAttestation,
    info: Option<&InfoResponse>,
) -> CycleEntry {
    let message_hash = attestation.message_hash();
    let entry = |disposition| CycleEntry::new(message_hash, disposition);

    // ---- step 4 — the DepositIntent, through the shared encoding crate's codec ------------------------------------
    // The envelope layer validated the BINDING, never the structure — Circle can and does sign a
    // payload this codec refuses — so this is where a non-DepositIntent stops.
    let intent = match decode_and_validate_deposit_intent(attestation.payload()) {
        Ok(intent) => intent,
        Err(error) => return entry(Disposition::Rejected(error)),
    };

    // ---- step 5 — the OPTIONAL fast-fail --------------------------------------------------------
    if let Some(info) = info {
        if let Err(error) = check_domain_token_against_info(&intent, info, ctx.config) {
            return entry(Disposition::Rejected(error));
        }
    }

    // ---- step 6 — the idempotency gate ----------------------------------------------------------
    // Keyed by the DepositIntent's own nonce — the same bytes32 the on-chain `usedNonces` assert
    // keys by, so the liveness backstop and the safety backstop dedup the same thing.
    let nonce = *intent.header().nonce().as_bytes();
    match ctx.store.claim_nonce(&nonce, &message_hash) {
        Ok(ClaimOutcome::Claimed(_)) => {}
        Ok(ClaimOutcome::AlreadySeen(record)) => {
            return entry(Disposition::Duplicate {
                status: record.status(),
            })
        }
        // a SECOND attestation, with a different messageHash, for a nonce the store already holds.
        // At most one of the two is the deposit that happened and the relayer cannot know which, so
        // it refuses to act and says so.
        Err(error @ RelayerError::NonceMessageHashMismatch { .. }) => {
            return entry(Disposition::ReconciliationRequired(error))
        }
        // the store was busy, or its disk was: a condition that clears. Without a working store there
        // is no dedup, so the relayer does NOT mint — it defers, and the next cycle re-claims.
        Err(error) if error.is_retryable() => return entry(Disposition::Deferred(error)),
        Err(error) => return entry(Disposition::Rejected(error)),
    }

    // ---- step 7a — build the note (the shared encoding crate owns every byte of it) -------------------------------
    let note = match build_mint_note(
        ctx.identities.sender(),
        ctx.identities.faucet(),
        ctx.config.remote_domain(),
        intent,
        attestation.attestation(),
        ctx.identities.attester(),
        &mut *ctx.rng,
    ) {
        Ok(note) => {
            ctx.metrics.record_note_built();
            note
        }
        Err(error) => {
            // the claim is released before the refusal is reported, so the nonce is not left owned by
            // an attempt that will never happen
            return entry(fail_and_reject(ctx, &nonce, error));
        }
    };

    // ---- step 7b — submit through the PORT, retrying the transient answers ----------------------
    let disposition = submit_with_retry(ctx, &note).await;

    // ---- step 7c — record the outcome durably ---------------------------------------------------
    entry(settle(ctx, &nonce, disposition))
}

/// Submits through the port, retrying [`RelayerError::TransientSubmit`] under the configured
/// attempt budget with the same exponential backoff the Circle half uses.
///
/// The Circle rate governor is deliberately NOT held here: its ceilings are Circle's documented
/// ones (5 QPS/IP, 35 QPS global), and a Miden node is not Circle. Spending a Circle rate token on
/// a Miden submit would throttle the fetches that other deposits are waiting on.
///
/// A budget that runs out DEFERS rather than rejects: the deposit intent has no expiry, so a node
/// that is behind now is a node that will accept this same attestation later.
async fn submit_with_retry<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    note: &miden_protocol::note::Note,
) -> Disposition {
    let max_attempts = ctx.config.max_retry_attempts().max(1);
    let base_delay_ms = ctx.config.backoff_base_ms();
    let submit_deadline = std::time::Duration::from_millis(ctx.config.submit_deadline_ms());

    let mut attempt = 1;
    loop {
        let submission = MintSubmission::new(ctx.identities.sender(), note);
        // Each attempt is bounded by the submit DEADLINE, so a hung node cannot keep this claim
        // `Pending` forever — that unbounded wait is what would make no `stale_claim_secs` safe. A
        // deadline hit is a TRANSIENT failure (the node may just be slow); it is retried like any
        // other, and the whole loop is bounded by `max_attempts × deadline + backoff`, which is exactly
        // the envelope `RecoveryPolicy` validates the reclaim threshold against.
        let error =
            match tokio::time::timeout(submit_deadline, ctx.submit.submit_mint_note(submission))
                .await
            {
                Ok(Ok(MintSubmitted::Accepted(tx_id))) => return Disposition::Submitted { tx_id },
                Ok(Ok(MintSubmitted::AlreadyMinted)) => return Disposition::AlreadyMinted,
                Ok(Err(error)) => error,
                Err(_elapsed) => RelayerError::TransientSubmit(crate::error::Cause::new(
                    submit::SubmitDeadlineExceeded {
                        after_ms: ctx.config.submit_deadline_ms(),
                    },
                )),
            };

        if !error.is_retryable() {
            return Disposition::Rejected(error);
        }
        if attempt >= max_attempts {
            return Disposition::Deferred(error);
        }

        ctx.metrics.record_submit_retry();
        // `base · 2^(attempt-1)`, saturating — the same curve `circle::retry` applies, and capped for
        // the same reason: a large attempt budget must not overflow the delay.
        let delay = base_delay_ms.saturating_mul(1u64 << (attempt - 1).min(20));
        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        attempt += 1;
    }
}

/// Writes what happened to the idempotency log, and turns a store failure into an honest
/// disposition.
///
/// The log write is not bookkeeping: it is what makes the next cycle's dedup — and its retry —
/// true. The terminal-vs-retryable split lives HERE:
///
/// * a `Deferred` transient failure is `record_failure` → `Failed`, the RETRYABLE pool the next
///   cycle re-drives from `retryable()`;
/// * a `Rejected` PERMANENT failure is `record_rejected` → `Rejected`, TERMINAL — not re-claimable
///   and not in the retry work list, so a node's permanent refusal is not re-fetched and
///   re-submitted on every subsequent cycle.
///
/// Conflating the two (recording both as `Failed`) would let a fatal submit loop forever and
/// leave a transient one's classification meaningless across cycles.
///
/// A write that FAILS after a successful submit is reported as
/// [`Disposition::ReconciliationRequired`] — the mint went out and the store does not know it,
/// which is precisely the state a relayer must not paper over, because its next cycle would
/// re-mint.
fn settle<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    nonce: &[u8; 32],
    disposition: Disposition,
) -> Disposition {
    let written = match &disposition {
        Disposition::Submitted { tx_id } => ctx.store.record_submission(nonce, *tx_id).map(|_| ()),
        Disposition::AlreadyMinted => ctx.store.record_already_minted(nonce).map(|_| ()),
        // TERMINAL: a permanent refusal is settled, not returned to the retryable pool — otherwise
        // the retry driver re-fetches and re-submits it every cycle forever
        Disposition::Rejected(_) => ctx.store.record_rejected(nonce).map(|_| ()),
        // RETRYABLE: a transient failure goes back into the pool — `is_nonce_submitted` answers false
        // for it again, and the next cycle's retry drive re-claims and re-fetches it
        Disposition::Deferred(_) => ctx.store.record_failure(nonce).map(|_| ()),
        Disposition::Duplicate { .. } | Disposition::ReconciliationRequired(_) => Ok(()),
    };

    match written {
        Ok(()) => disposition,
        Err(error) => {
            let minted = matches!(&disposition, Disposition::Submitted { .. });
            if minted {
                Disposition::ReconciliationRequired(error)
            } else {
                Disposition::Deferred(error)
            }
        }
    }
}

/// Settles a nonce whose mint note the shared encoding crate's factory would not build, and reports
/// the refusal.
///
/// A note-build failure is PERMANENT — a payload that is not a structurally valid DepositIntent
/// does not become one on a retry (`RelayerError::MintNoteBuild` is not retryable) — so the nonce
/// is TERMINALIZED (`record_rejected`), not returned to the retryable pool. Recording it `Failed`
/// would put it in the retry work list, where the next cycle would re-fetch it, re-decode it,
/// re-fail the build, and churn forever.
///
/// A store failure while terminalizing does not overwrite the reason the build was refused — that
/// is the fact the operator needs; the nonce stays `Pending` and the recovery sweep reclaims it.
fn fail_and_reject<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    nonce: &[u8; 32],
    error: RelayerError,
) -> Disposition {
    let _ = ctx.store.record_rejected(nonce);
    Disposition::Rejected(error)
}

/// Accounts for ONE processed attestation — the no-silent-drops obligation, discharged in ONE
/// place, so there is no disposition that can be produced without being counted AND observed.
///
/// It is the single accounting point on purpose: it records the attestation as processed
/// (`record_fetched`) AND increments exactly one terminal counter, so the metrics partition
/// (`attestations_fetched == the six terminal counters summed`) holds BY CONSTRUCTION — for a
/// freshly polled attestation and a re-driven one alike. A retry whose re-fetch failed is one
/// processed attestation too: it is counted here (as `deferred`) and reported, never dropped.
fn record<R: FeltRng>(ctx: &mut RelayerCtx<'_, R>, entry: &CycleEntry) {
    ctx.metrics.record_fetched();
    match entry.disposition() {
        Disposition::Submitted { .. } => ctx.metrics.record_note_submitted(),
        Disposition::AlreadyMinted => ctx.metrics.record_already_minted(),
        Disposition::Duplicate { .. } => ctx.metrics.record_duplicate(),
        Disposition::Rejected(_) => ctx.metrics.record_rejected(),
        Disposition::Deferred(_) => ctx.metrics.record_deferred(),
        Disposition::ReconciliationRequired(_) => ctx.metrics.record_reconciliation_required(),
    }

    let reason = entry.reason();
    ctx.events.emit(RelayerEvent::Attestation {
        message_hash: entry.message_hash_hex(),
        outcome: entry.outcome(),
        reason: reason.clone(),
    });

    if entry.disposition().alerts() {
        ctx.events.emit(RelayerEvent::Alert {
            endpoint: format!("mint {}", entry.message_hash_hex()),
            reason,
        });
    }
}

// THE LOOP
// ================================================================================================

/// **Run cycles until `shutdown` says stop.**
///
/// It keeps polling while a scan has more pages (there is no reason to sleep with a cursor in hand)
/// and waits `poll_interval_ms` once the scan reaches its end — a deposit intent has no expiry, so
/// polling harder buys nothing but rate-limit pressure.
///
/// A cycle that FAILS does not stop the loop: a 500 from Circle, or a transport blip, is exactly
/// what the next cycle is for, and the cursor was not advanced, so nothing was skipped. But the
/// failure is EMITTED — a loop that matched `Err(_)` and logged nothing would leave a
/// store/cursor/discovery failure making no progress with no operator signal. Every cycle therefore
/// emits its outcome: a `completed` event carrying the counts (so throughput is visible), or a
/// `failed` event carrying the error. The loop backs off before retrying rather than spinning on
/// it.
pub async fn run_relayer_loop<R: FeltRng>(
    ctx: &mut RelayerCtx<'_, R>,
    mut shutdown: impl FnMut() -> bool,
) {
    let idle = std::time::Duration::from_millis(ctx.config.poll_interval_ms());

    while !shutdown() {
        // A failed cycle waits too. It did not advance the cursor, so nothing was skipped — but a
        // loop that retried a 500 without pausing would spend the rate budget the retry needs.
        let pause = match run_relayer_cycle(ctx).await {
            Ok(report) => {
                ctx.events.emit(RelayerEvent::Cycle {
                    outcome: "completed",
                    detail: report.summary(),
                });
                report.scan_complete()
            }
            Err(error) => {
                ctx.events.emit(RelayerEvent::Cycle {
                    outcome: "failed",
                    detail: error.to_string(),
                });
                true
            }
        };

        // Surface the CUMULATIVE metrics after every cycle — success or failure — so an operator's
        // dashboard reads throughput (and a stall: a `submit_retries` or `deferred` count climbing
        // while `submitted` does not) without differencing successive cycle lines. This is the
        // production read of `metrics()`; `run_relayer_cycle` records the duration on both paths, so
        // the snapshot is complete even when nothing minted.
        ctx.events.emit(RelayerEvent::Metrics {
            detail: ctx.metrics.snapshot().render(),
        });

        if pause {
            tokio::time::sleep(idle).await;
        }
    }
}
