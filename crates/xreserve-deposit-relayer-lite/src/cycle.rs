//! The loop: poll a page, handle each attestation, advance the cursor.
//!
//! # The two rules that replace a retry subsystem
//!
//! 1. **A bad element is skipped, never fatal to the page.** Each attestation is decoded on its own
//!    and a failure logs and moves on. The sibling crate collects the page through
//!    `collect::<Result<_>>()?`, so ONE malformed attestation fails the whole fetch and the cursor
//!    never advances — the service wedges forever. That is the bug this design does not have.
//! 2. **A transient failure ends the cycle without advancing the cursor.** The next cycle re-fetches
//!    the same page and the submitted-nonce set skips what already went through. That is the entire
//!    retry mechanism: no re-fetch by messageHash, no failure pool, no work list.
//!
//! Everything else is a consequence. A permanent failure — an undecodable payload, an envelope that
//! does not bind, a note the builder refuses, a node that refuses outright — is skipped, because the
//! chain would refuse it too and a retry could only fail the same way.

use anyhow::Result;
use miden_protocol::crypto::rand::FeltRng;
use tracing::field::Empty;
use tracing::{error, info, instrument, warn, Span};

use xusdc_encoding::xreserve::encoding::DepositIntent;

use crate::circle::{Attestation, CircleClient};
use crate::config::Config;
use crate::mint::{build_mint_note, Identities};
use crate::store::Store;
use crate::submit::{MintSubmit, SubmitError, Submitted};

/// Everything one cycle needs. Borrowed and assembled by the caller, so this module cannot grow a
/// default for the submit port — a relayer missing one must not start.
pub struct Relayer<'a, R: FeltRng> {
    pub config: &'a Config,
    pub circle: &'a CircleClient,
    pub store: &'a Store,
    pub submit: &'a dyn MintSubmit,
    pub identities: &'a Identities,
    pub rng: &'a mut R,
}

/// How a cycle ended, and therefore whether the loop should pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The page was handled and there is another one — keep going without sleeping.
    MorePages,
    /// The feed is caught up.
    Idle,
    /// A transient failure held the page. The cursor did not move; the same page is next.
    Retry,
}

/// What became of one attestation.
enum Handled {
    /// A note went to the node.
    Submitted,
    /// Accounted for without a submit — a duplicate, or a permanent refusal the chain would repeat.
    Skipped,
    /// A transient failure. The page stops here and is re-fetched next cycle.
    Retry,
}

/// Fetches one page of attestations from the stored cursor and mints what is new.
///
/// Each attestation is decoded, checked against the submitted-nonce set, turned into a mint note and
/// submitted. The cursor advances only once the whole page is accounted for, so the return value is
/// what the loop needs to know: another page is waiting, the feed is caught up, or the page is still
/// owed and will be re-fetched.
///
/// # Errors
/// The page fetch or a store operation failed. Both leave the cursor where it was, so the next
/// cycle re-reads the same page and nothing is lost.
///
/// # Tracing
/// **`parent = None` is load-bearing.** `ForestLayer` buffers a span into its parent and only prints
/// once a ROOT span closes; the loop above this never returns, so an inherited parent would mean
/// nothing was ever printed. Detaching makes each cycle its own root, and a cycle's tree — with
/// every attestation nested under it — is emitted the moment that cycle ends.
#[instrument(
    parent = None,
    name = "cycle",
    skip_all,
    fields(
        remote_domain = relayer.config.remote_domain,
        resumed_from = Empty,
        fetched = Empty,
        submitted = Empty,
        outcome = Empty,
    ),
)]
pub async fn run_cycle<R: FeltRng>(relayer: &mut Relayer<'_, R>) -> Result<CycleOutcome> {
    let span = Span::current();

    let cursor = relayer.store.cursor()?;
    if let Some(cursor) = cursor.as_deref() {
        span.record("resumed_from", cursor);
    }

    let page = relayer
        .circle
        .attestations(
            relayer.config.remote_domain,
            relayer.config.poll_page_size,
            cursor.as_deref(),
        )
        .await?;
    span.record("fetched", page.attestations.len());

    let mut submitted = 0usize;
    for attestation in &page.attestations {
        match handle_one(relayer, attestation).await? {
            Handled::Submitted => submitted += 1,
            Handled::Skipped => {}
            // the page is held: everything before this element is already durably recorded, and
            // this element and everything after it is re-fetched next cycle
            Handled::Retry => {
                span.record("submitted", submitted);
                span.record("outcome", "retry");
                return Ok(CycleOutcome::Retry);
            }
        }
    }
    span.record("submitted", submitted);

    // An ABSENT next is the documented final page: the cursor stays where it is, because there is
    // no resume point past the end.
    match page.next {
        Some(next) => {
            relayer.store.set_cursor(&next)?;
            span.record("outcome", "more_pages");
            Ok(CycleOutcome::MorePages)
        }
        None => {
            span.record("outcome", "idle");
            Ok(CycleOutcome::Idle)
        }
    }
}

/// Decode → dedup → build → submit, for one attestation.
///
/// # Errors
/// Only a STORE failure. Every other failure is a skip or a retry, never a propagated error, which
/// is what keeps one bad attestation from failing the page.
///
/// # Tracing
/// The disposition is recorded as the span's `outcome` field rather than emitted as an event, so one
/// line in the cycle's tree says what became of this deposit. Only genuine failures also log an
/// event, because only they carry something the field cannot: the error.
#[instrument(
    name = "attestation",
    skip_all,
    fields(message_hash = %attestation.message_hash, nonce = Empty, outcome = Empty),
)]
async fn handle_one<R: FeltRng>(
    relayer: &mut Relayer<'_, R>,
    attestation: &Attestation,
) -> Result<Handled> {
    let span = Span::current();

    // ---- decode + bind the envelope (PERMANENT on failure) -------------------------------------
    let decoded = match attestation.decode() {
        Ok(decoded) => decoded,
        Err(error) => {
            span.record("outcome", "unbound_envelope");
            warn!(%error, "skipping an attestation whose envelope does not bind");
            return Ok(Handled::Skipped);
        }
    };

    // ---- the DepositIntent, through the shared codec (PERMANENT on failure) --------------------
    let intent = match DepositIntent::try_from(decoded.payload.as_slice()) {
        Ok(intent) => intent,
        Err(error) => {
            span.record("outcome", "not_a_deposit_intent");
            warn!(%error, "skipping an attestation that is not a deposit intent");
            return Ok(Handled::Skipped);
        }
    };

    // ---- the duplicate filter ------------------------------------------------------------------
    // Keyed by the intent's own nonce — the same bytes the on-chain `usedNonces` assert keys by.
    let nonce = *intent.header().nonce().as_bytes();
    span.record("nonce", hex::encode(nonce));

    if relayer.store.is_submitted(&nonce)? {
        span.record("outcome", "duplicate");
        return Ok(Handled::Skipped);
    }

    // ---- build the note (PERMANENT on failure) -------------------------------------------------
    let note = match build_mint_note(
        relayer.identities,
        relayer.config.remote_domain,
        intent,
        decoded.signature,
        &mut *relayer.rng,
    ) {
        Ok(note) => note,
        Err(error) => {
            span.record("outcome", "unbuildable");
            warn!(%error, "skipping an attestation whose note will not build");
            return Ok(Handled::Skipped);
        }
    };

    // ---- submit --------------------------------------------------------------------------------
    match relayer
        .submit
        .submit(relayer.identities.sender(), &note)
        .await
    {
        Ok(Submitted::Accepted(tx_id)) => {
            // durable BEFORE anything else can go wrong, so a crash loses at most this one submit
            relayer.store.mark_submitted(&nonce)?;
            span.record("outcome", "submitted");
            info!(tx_id, "submitted a mint note");
            Ok(Handled::Submitted)
        }
        Ok(Submitted::AlreadyMinted) => {
            relayer.store.mark_submitted(&nonce)?;
            span.record("outcome", "already_minted");
            Ok(Handled::Skipped)
        }
        Err(SubmitError::Fatal(error)) => {
            span.record("outcome", "refused");
            warn!(%error, "the node permanently refused this mint");
            Ok(Handled::Skipped)
        }
        Err(SubmitError::Transient(error)) => {
            span.record("outcome", "deferred");
            warn!(%error, "holding the page after a transient submit failure");
            Ok(Handled::Retry)
        }
    }
}

/// Runs cycles until `shutdown` says stop.
///
/// A failed cycle does not stop the loop — a 500 from Circle is exactly what the next cycle is for,
/// and the cursor did not move, so nothing was skipped. It does pause first: retrying a failure
/// without pausing would just spend the rate budget the retry needs.
pub async fn run_loop<R: FeltRng>(
    relayer: &mut Relayer<'_, R>,
    mut shutdown: impl FnMut() -> bool,
) {
    let idle = std::time::Duration::from_millis(relayer.config.poll_interval_ms);

    while !shutdown() {
        let pause = match run_cycle(relayer).await {
            Ok(CycleOutcome::MorePages) => false,
            Ok(CycleOutcome::Idle) => true,
            Ok(CycleOutcome::Retry) => true,
            Err(error) => {
                error!(?error, "the cycle failed; the cursor did not move");
                true
            }
        };

        if pause {
            tokio::time::sleep(idle).await;
        }
    }
}
