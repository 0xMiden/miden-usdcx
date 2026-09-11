//! Coordinates discovery validation, preparation, signing, evidence, submission, and status polling.
//! Each stage consumes the validated output of the previous stage. A run accepts one prepared
//! batch per burn, requires a valid quorum and authorized signers, and submits through the ledger.
//!
//! Node discovery and evidence arrive through adapters. Events contain identifiers and outcomes;
//! keys remain behind [`QuorumSigner`] and credentials remain in the client configuration.

mod error;

pub use error::RunError;

use miden_protocol::note::NoteId;

use crate::attester::{address_of, assemble_quorum, Address, SecretKey, Signature65};
use crate::circle::client::CircleClient;
use crate::circle::schema::{WithdrawalStatus, WithdrawalStatusKind};
use crate::circle::wire::Uuid;
use crate::config::ListenerConfig;
use crate::error::SignError;
use crate::evidence::{assemble_evidence, BurnEvidenceReads};
use crate::idempotency::{BurnKey, SubmissionStatus, SubmitLedger};
use crate::submit::{submit_withdraw, SubmitError, SubmitOutcome};
use crate::validate::{
    sign_validated, validate_discovery, validate_returned, DiscoveryRecord, ValidatedWithdrawal,
};
use crate::withdrawal_api::{
    authorize_submission, build_prepare_request, build_withdraw_batch, build_withdraw_request,
    poll_status, prepare,
};

/// One burn produces one `PrepareBurnIntentInput`, so Circle must return exactly one prepared
/// batch, and exactly one `WithdrawBatch` is submitted for it (one prepared batch, one submitted
/// batch).
///
/// Named rather than written as a bare `1` in three places: it is the cardinality rule the flow's
/// evidence attribution rests on, not an incidental length check (`masm-named-literals`).
pub const ONE_BATCH_PER_BURN: usize = 1;

/// …and that one batch carries exactly one burn intent (one prepared batch, one submitted batch).
///
/// **This is the half of the cardinality rule the batch count cannot see, and it is the dangerous
/// half.** `WithdrawBatch.burnIntents` is `1..=10` on the wire — Circle's schema calls it "either a
/// single burn intent or a burn intent set" — so one batch can carry a SET. Nothing upstream
/// refuses one: B5's field-by-field compare clears every intent that matches the burn payload, and
/// repeats of the burn's own intent all match it. The batch's `messageHashToSign` then covers the
/// whole set, so a single attester signature authorizes every member; the quorum is a well-formed
/// exactly-2; every signer is a registered attester; and `batches.len` is still 1.
///
/// The result would be one discovered burn funding N releases — a fan-in the burn evidence cannot
/// even describe, since it resolves ONE `burnTxId` from ONE note. So the rule is one burn ↔ one
/// payload ↔ one batch ↔ one intent, and this constant is the fourth term.
pub const ONE_INTENT_PER_BURN: usize = 1;

/// The index of the only batch there is, and of the only intent inside it. Both are `0`, and both
/// are named, because a bare `[0]` on this path reads as "the first of several" — which is
/// precisely the reading the two rules above exist to forbid.
const ONLY_BATCH: usize = 0;
const ONLY_INTENT: usize = 0;

// THE PORTS — what the node-backed slice fills in, and what a test drives
// ================================================================================================

/// A burn note as B3's discovery leg reports it: the note's id, and the raw
/// [`DiscoveryRecord`] the retrieval returned.
///
/// Both halves are needed and neither substitutes for the other. The record is what B3 VALIDATES
/// (the exact-32-bit tag, the `details = Some(..)` observability, the payload, the sender); the
/// note id is what the burn evidence is resolved FROM — and it must be the id of the very note the
/// record describes, which is why they travel as one value rather than as two arguments.
///
/// The feed behind it — the exact-tag `SyncNotes` scan and `GetNotesById` — needs `miden-client`,
/// which has no v0.16 release, so it is **PARKED** for the node-backed slice. This type is the seam
/// it lands on.
#[derive(Debug, Clone)]
pub struct DiscoveredNote {
    note_id: NoteId,
    record: DiscoveryRecord,
}

impl DiscoveredNote {
    /// The note `note_id`, as `record` reports it.
    pub fn new(note_id: NoteId, record: DiscoveryRecord) -> Self {
        Self { note_id, record }
    }

    /// The note's id — the evidence assembler's only entry key (never a transaction id: there is no
    /// by-`burnTxId` lookup).
    pub fn note_id(&self) -> NoteId {
        self.note_id
    }

    /// The raw discovery report, for B3 to validate.
    pub fn record(&self) -> &DiscoveryRecord {
        &self.record
    }
}

/// **B6.** The orchestration's ONLY signing entry: given the `ValidatedWithdrawal` the B5 gate
/// minted, produce, for each validated batch, the `(claimed signer, signature)` pairs
/// [`assemble_quorum`] will prove and order.
///
/// # The input type is the invariant
///
/// The port takes a `&ValidatedWithdrawal` and nothing else, so there is no implementation of it
/// production, test, or future — that can be invoked before B5 has passed: the argument does not
/// exist until [`validate_returned`] returns `Ok`. That is what
/// makes "the signer was not reached on the mismatch path" a property of the types rather than a
/// property of this file's control flow, and it is why the port exists at all rather than the
/// orchestration calling [`sign_validated`] inline: an interface a
/// test can COUNT is what turns "no signature was produced" from an outcome assertion into an
/// observation.
///
/// Returning the claimed ADDRESS alongside each signature is deliberate. `assemble_quorum` proves
/// the claim by recovering the signer from the signature; a port that returned bare signatures
/// would have left this module to recover them and then check them against themselves, which proves
/// nothing.
pub trait QuorumSigner {
    /// One `Vec<(Address, Signature65)>` per validated batch, in batch order.
    ///
    /// # Errors
    /// [`SignError`] — the curve refused a digest. No partial set is returned: a signer that cannot
    /// sign every batch signs none.
    fn sign_batches(
        &self,
        validated: &ValidatedWithdrawal,
    ) -> Result<Vec<Vec<(Address, Signature65)>>, SignError>;
}

/// The production [`QuorumSigner`]: the configured attester keys, each signing every cleared digest
/// through [`sign_validated`].
///
/// It reaches the raw [`sign`](crate::attester::sign) primitive nowhere — `sign_validated` is the
/// withdrawal flow's signing entry, and this is the withdrawal flow. The claimed address per
/// signature is derived from the KEY ([`address_of`]) rather than recovered from the signature just
/// produced, so `assemble_quorum`'s recovery check compares two independently-derived answers
/// instead of an answer with itself.
///
/// Signatures are emitted in ascending signer-address order, because that is the order Circle's
/// source-chain verifier requires — `assemble_quorum` still checks it, and still refuses a
/// duplicate signer (two handles for one key) rather than de-duplicating it into a below-threshold
/// bundle.
///
/// This holds real [`SecretKey`]s and is therefore the LOCAL/dev shape. Production custody is
/// KMS/HSM-backed and is `P4-OPS`'s: the config carries key HANDLES, never key material, and an
/// HSM-backed signer is another implementation of this same port.
pub struct LocalKeyQuorumSigner {
    keys: Vec<SecretKey>,
}

impl LocalKeyQuorumSigner {
    /// A signer over `keys`. The COUNT is not checked here: "exactly the threshold, no duplicate
    /// signer" is [`assemble_quorum`]'s answer to give, and giving it twice — in two places that
    /// can drift — is how one of them ends up the lenient one.
    pub fn new(keys: Vec<SecretKey>) -> Self {
        Self { keys }
    }
}

impl QuorumSigner for LocalKeyQuorumSigner {
    fn sign_batches(
        &self,
        validated: &ValidatedWithdrawal,
    ) -> Result<Vec<Vec<(Address, Signature65)>>, SignError> {
        let mut per_batch: Vec<Vec<(Address, Signature65)>> =
            vec![Vec::new(); validated.batch_count()];

        for key in &self.keys {
            let address = address_of(key);
            // B6 through the gated signer: it consumes the B5 token, so every digest signed here is
            // one B5 cleared, and the raw `sign` primitive is not on this path.
            for (batch, signature) in sign_validated(validated, key)?.into_iter().enumerate() {
                per_batch[batch].push((address, signature));
            }
        }

        for batch in &mut per_batch {
            batch.sort_by_key(|(address, _)| *address);
        }

        Ok(per_batch)
    }
}

// OBSERVABILITY — structured, and structurally secret-free
// ================================================================================================

/// One structured event, emitted as the orchestration passes each B-step.
///
/// Its fields are the whole vocabulary: which step, what happened, which note, and — once B7's
/// evidence has resolved one — which burn. There is deliberately no free-form payload and no
/// `Debug` of a config or a key: a field that could carry an attester key or the API credential is
/// a field that eventually does, and this service's logs are the one place a credential leaks
/// without anything failing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListenerEvent {
    /// The step this event belongs to, using the step names defined at the crate root: `"B3"`,
    /// `"B4"`, `"B5"`, `"B6"`, `"B7"`, `"B10"`.
    pub step: &'static str,

    /// What happened, as a short stable slug (`"validated"`, `"signed"`, `"submitted"`,
    /// `"do-not-sign-abort"`, …) — stable so an operator's alert can match on it.
    pub outcome: &'static str,

    /// The burn note this event is about.
    pub note_id: String,

    /// The evidence package's `burnTxId`, once B7 has resolved one. `None` before that — the flow
    /// does not have one to report, and reporting a placeholder would be worse than reporting
    /// nothing.
    pub burn_tx_id: Option<String>,
}

impl ListenerEvent {
    fn new(step: &'static str, outcome: &'static str, note_id: NoteId) -> Self {
        Self {
            step,
            outcome,
            note_id: note_id.to_hex(),
            burn_tx_id: None,
        }
    }

    fn with_burn(mut self, burn_tx_id: &str) -> Self {
        self.burn_tx_id = Some(burn_tx_id.to_string());
        self
    }
}

/// Where [`ListenerEvent`]s go — the operator's log, a metrics sink, or nowhere ([`NoopEvents`]).
///
/// A port rather than a logging dependency: this crate names no log framework (`P4-OPS` owns that
/// choice, a later slice), and a test that has to prove no secret is emitted needs to hold the
/// events, not scrape a global logger.
pub trait ListenerEvents {
    /// Record `event`. Implementations must not fail the flow: observability is not the withdrawal.
    fn emit(&self, event: &ListenerEvent);
}

/// The sink that drops every event — the default for a caller that has not wired one yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEvents;

impl ListenerEvents for NoopEvents {
    fn emit(&self, _event: &ListenerEvent) {}
}

// THE CONTEXT
// ================================================================================================

/// Everything one [`run_once`] needs: the static config, the Circle client, the durable idempotency
/// ledger, the B6 signer, the burn-evidence read port, and the event sink.
///
/// Borrowed rather than owned, and assembled by the caller, so the two seams that are PARKED (the
/// evidence reads, parked) and human-owned (key custody, a later slice) are supplied from outside
/// rather than constructed here.
pub struct RunContext<'a> {
    config: &'a ListenerConfig,
    circle: &'a CircleClient,
    ledger: &'a SubmitLedger,
    signer: &'a dyn QuorumSigner,
    evidence: &'a dyn BurnEvidenceReads,
    events: &'a dyn ListenerEvents,
}

impl<'a> RunContext<'a> {
    /// Assembles the context. Every part is required — there is no default Circle client, no
    /// default ledger, and above all no default signer or allowlist: a listener missing one of
    /// these must not start, rather than start and fail closed on every burn.
    pub fn new(
        config: &'a ListenerConfig,
        circle: &'a CircleClient,
        ledger: &'a SubmitLedger,
        signer: &'a dyn QuorumSigner,
        evidence: &'a dyn BurnEvidenceReads,
        events: &'a dyn ListenerEvents,
    ) -> Self {
        Self {
            config,
            circle,
            ledger,
            signer,
            evidence,
            events,
        }
    }

    fn emit(&self, event: ListenerEvent) {
        self.events.emit(&event);
    }
}

// THE OUTCOME
// ================================================================================================

/// What one B3→B10 run ACTUALLY resulted in.
///
/// Closed, and not `#[non_exhaustive]`, for [`SubmitOutcome`]'s reason: three of the four are NOT a
/// completed withdrawal, and they are exactly the ones a catch-all arm would swallow. Nothing here
/// means "the funds are out" except a [`Self::Withdrawn`] whose status is
/// [`WithdrawalStatusKind::Finalized`] — and the status is carried honestly rather than filtered,
/// so a caller reads it instead of inferring it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// B7 answered `201` and B10 polled the withdrawal to a stop. `status` is what Circle actually
    /// said: `finalized` is the one terminal success, `failed` is terminal, `expired` means a NEW
    /// withdrawal must be submitted, and a pending status means the poll's bound was not the point.
    Withdrawn {
        burn_tx_id: String,
        withdrawal_id: String,
        status: WithdrawalStatus,
    },

    /// B7 answered `409` naming a withdrawal, and it was RECOVERED by polling it — never re-sent.
    /// This is "we found out what actually happened", not "it worked".
    ConflictRecovered {
        burn_tx_id: String,
        withdrawal_id: String,
        status: WithdrawalStatus,
    },

    /// The ledger already accounts for this burn — an earlier pass, another process, or a restart.
    /// **ZERO Circle calls were made** for the submission; the decision happened before the wire.
    AlreadySubmitted {
        burn_tx_id: String,
        status: SubmissionStatus,
    },

    /// The burn is BLOCKED for an operator: an answer this service is not allowed to resolve on its
    /// own. Not a failure of the run — a refusal to guess.
    ReconciliationRequired {
        burn_tx_id: String,
        reason: ReconciliationReason,
    },
}

/// Why a burn was left for an operator. the idempotency store's vocabulary, deliberately reused
/// rather than paralleled.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconciliationReason {
    /// A `409` carrying only `conflict.burnTxId`: there is no withdrawal id to recover through, so
    /// resubmission stops.
    ConflictNamedNoWithdrawal,

    /// Circle echoed a `burnTxId` that is not the one submitted — in a `409` body, or in a status
    /// recovered through one. Circle documents: a defect, not a success.
    EchoMismatch { echoed: String },
}

// THE ORCHESTRATION
// ================================================================================================

/// **Run the B3→B10 flow for ONE discovered burn note.**
///
/// The stages, and what each one is gated on:
///
/// 1. **B3** — [`validate_discovery`]: exact-32-bit tag,
///    `details = Some(..)`, the burn payload through the shared encoding crate's codec,
///    `metadata.sender`. Circle is not touched until this passes.
/// 2. **B4** — [`build_prepare_request`] from the ONE
///    [`DiscoveredBurn`](crate::validate::DiscoveredBurn) B3 minted, so the payload and the
///    depositor cannot come from different notes.
/// 3. **B5** — [`prepare`], then
///    [`validate_returned`]. **This is the gate.** A mismatch
///    returns [`RunError::Validation`] and the run ends here: no token, therefore no signature,
///    therefore no submission.
/// 4. **cardinality** — exactly [`ONE_BATCH_PER_BURN`] validated batch, checked BEFORE the signer,
///    so a fan-out response never produces a signature over a batch this burn did not ask for.
/// 5. **B6** — [`QuorumSigner::sign_batches`] (takes the B5 token), then
///    [`assemble_quorum`]: exactly-2, each verifying to its
///    claimed signer, strictly ascending, no duplicate.
/// 6. **B7** — [`assemble_evidence`] (fail-closed),
///    [`build_withdraw_batch`] (takes the quorum
///    bundle), [`authorize_submission`] (every signer
///    a registered attester), then [`submit_withdraw`] (claims the
///    burn durably first; a `409` is RECOVERED, never re-sent).
/// 7. **B10** — [`poll_status`] to a stop, bound to the burn.
///
/// B8/B9 are Circle-side (evidence resolution and the source-chain release); they are not partner
/// steps and there is nothing here for them to do.
///
/// # Errors
/// A [`RunError`] naming the stage that refused. Every one of them stops THIS burn and leaves the
/// stages after it unrun — there is no "continue without" branch, because each stage's input is the
/// previous stage's proof.
pub async fn run_once(
    ctx: &RunContext<'_>,
    discovered: &DiscoveredNote,
) -> Result<Outcome, RunError> {
    let note_id = discovered.note_id();

    // ---- B3 — discovery. Nothing leaves the process until this passes. -------------------------
    let burn = validate_discovery(discovered.record(), ctx.config).inspect_err(|_| {
        ctx.emit(ListenerEvent::new("B3", "discovery-rejected", note_id));
    })?;
    ctx.emit(ListenerEvent::new("B3", "discovered", note_id));

    // ---- B4 — the API JSON, built from the ONE burn B3 minted. ---------------------------------
    let request = build_prepare_request(&burn, ctx.config)?;
    ctx.emit(ListenerEvent::new("B4", "prepare-request-built", note_id));

    // ---- B5 — ask Circle, then VALIDATE. This is the gate. -------------------------------------
    let response = prepare(ctx.circle, &request).await?;
    let validated = validate_returned(&response, &burn, ctx.config).inspect_err(|_| {
        // The DO-NOT-SIGN abort. No ValidatedWithdrawal exists past this point on this
        // branch, so the signer below is not reachable — this event RECORDS the refusal, it does not
        // cause it.
        ctx.emit(ListenerEvent::new("B5", "do-not-sign-abort", note_id));
    })?;

    // One burn ↔ one payload ↔ one batch — checked before the signer, so a fan-out response cannot
    // produce a signature over a batch this burn never asked Circle to prepare.
    if validated.batch_count() != ONE_BATCH_PER_BURN {
        ctx.emit(ListenerEvent::new(
            "B5",
            "batch-cardinality-refused",
            note_id,
        ));
        return Err(RunError::BatchCardinality {
            returned: validated.batch_count(),
        });
    }

    // …↔ one INTENT — the half of the same rule a batch count is blind to, and the dangerous half.
    // That one batch may carry a burn intent SET (`burnIntents` is 1..=10 on the wire), and B5 has
    // ALREADY cleared every member of it: each repeat of the burn's own intent matches the burn's own
    // payload, so the field-by-field compare passes on all of them. The batch's single
    // `messageHashToSign` then covers the whole set, so one attester signature authorizes every
    // member — one burn funding N releases, which the burn evidence cannot even describe (it
    // resolves ONE burnTxId from ONE note).
    //
    // Refused HERE, before the signer, because the artifact that must not exist is the signature over
    // a set this burn never asked Circle to prepare.
    let intents = response.batches()[ONLY_BATCH].burn_intents();
    if intents.len() != ONE_INTENT_PER_BURN {
        ctx.emit(ListenerEvent::new(
            "B5",
            "intent-cardinality-refused",
            note_id,
        ));
        return Err(RunError::IntentCardinality {
            returned: intents.len(),
        });
    }
    // Taken while the count is proven, and carried to B7 — so what reaches the wire is the intent this
    // check passed, not a second read of the response that a later edit could widen back to a set.
    let intent = intents[ONLY_INTENT].clone();
    ctx.emit(ListenerEvent::new("B5", "validated", note_id));

    // ---- B6 — sign. Reachable only with the token B5 just minted. ------------------------------
    let claims = ctx.signer.sign_batches(&validated)?;
    if claims.len() != validated.batch_count() {
        return Err(RunError::SignerCardinality {
            batches: validated.batch_count(),
            signed: claims.len(),
        });
    }
    let claims = claims
        .into_iter()
        .next()
        .expect("the batch count is ONE_BATCH_PER_BURN and the signer matched it");

    // Exactly-2, each verifying to its claimed signer, strictly ascending, no duplicate — the
    // OFF-chain mirror of Circle's on-chain verifier, minted as the bundle the batch builder demands.
    let quorum = assemble_quorum(&validated.digests()[0], claims)?;
    ctx.emit(ListenerEvent::new("B6", "signed", note_id));

    // ---- B7 — evidence, batch, authorization, submission. --------------------------------------
    // The evidence is assembled HERE, at submit, because `burnTxId` is a required `POST /v1/withdraw` body
    // field (the documented evidence field) — the batch cannot be built without it. It is fail-closed: incomplete, ambiguous
    // or self-contradicting reads yield no package and no submission.
    let evidence = assemble_evidence(ctx.evidence, note_id, ctx.config.faucet_id())?;
    let burn_tx_id = evidence.burn_tx_id().to_string();
    ctx.emit(ListenerEvent::new("B7", "evidence-assembled", note_id).with_burn(&burn_tx_id));

    let batch = build_withdraw_batch(
        // the ONE intent the cardinality gate above cleared — the builder takes a single intent, not
        // a vector, so a set cannot reach the wire even if this call site were rewritten
        intent,
        &quorum,
        &burn_tx_id,
        // carried from the request the intents were prepared for, never re-decided here
        request.batches()[ONLY_BATCH].use_circle_forwarding(),
    )?;
    let authorized =
        authorize_submission(build_withdraw_request(vec![batch])?, &validated, ctx.config)
            .inspect_err(|_| {
                ctx.emit(
                    ListenerEvent::new("B7", "submit-gate-refused", note_id).with_burn(&burn_tx_id),
                );
            })?;

    let outcome = submit_withdraw(ctx.circle, ctx.ledger, authorized).await?;

    // ---- B10 — read what happened. -------------------------------------------------------------
    settle(ctx, note_id, &burn_tx_id, outcome).await
}

/// Turn what `POST /v1/withdraw` answered into the run's outcome — polling to a stop on a `201`
/// (B10), and reporting every other answer as the thing it is.
///
/// The `409` arms do NOT poll again: [`submit_withdraw`](crate::submit::submit_withdraw) has
/// already recovered (or refused to), and re-asking would neither add evidence nor be allowed to
/// re-send.
async fn settle(
    ctx: &RunContext<'_>,
    note_id: NoteId,
    burn_tx_id: &str,
    outcome: SubmitOutcome,
) -> Result<Outcome, RunError> {
    match outcome {
        SubmitOutcome::Submitted(statuses) => {
            ctx.emit(ListenerEvent::new("B7", "submitted", note_id).with_burn(burn_tx_id));

            // One batch was submitted, and `decode_withdraw_created` already refused any array that
            // is not one status per batch — so this is the status for OUR burn.
            let created = &statuses[0];
            let withdrawal_id = Uuid::new(created.withdrawal_id())
                .expect("a decoded WithdrawalStatus carries a validated withdrawalId");

            let status = poll_status(ctx.circle, &withdrawal_id).await?;

            // The poll is already bound to the withdrawal id it asked about; this binds it to the
            // BURN. A status that names another burn is a defect, and reading it as this
            // burn's outcome is how one burn's `finalized` settles another burn's release.
            if !status.burn_tx_id().eq_ignore_ascii_case(burn_tx_id) {
                ctx.emit(ListenerEvent::new("B10", "echo-mismatch", note_id).with_burn(burn_tx_id));
                return Ok(Outcome::ReconciliationRequired {
                    burn_tx_id: burn_tx_id.to_string(),
                    reason: ReconciliationReason::EchoMismatch {
                        echoed: status.burn_tx_id().to_string(),
                    },
                });
            }

            // Only a terminal `finalized` settles a burn as done. `failed`, `expired` and
            // every pending status leave the ledger's claim exactly where `submit_withdraw` put it:
            // submitted, and not settled.
            if status.status() == WithdrawalStatusKind::Finalized {
                ctx.ledger
                    .record_finalized(&BurnKey::new(burn_tx_id), Some(status.withdrawal_id()))
                    .map_err(SubmitError::Ledger)?;
            }
            ctx.emit(ListenerEvent::new("B10", "polled", note_id).with_burn(burn_tx_id));

            Ok(Outcome::Withdrawn {
                burn_tx_id: burn_tx_id.to_string(),
                withdrawal_id: withdrawal_id.as_str().to_string(),
                status,
            })
        }

        SubmitOutcome::ConflictRecovered {
            withdrawal_id,
            status,
        } => {
            ctx.emit(ListenerEvent::new("B7", "conflict-recovered", note_id).with_burn(burn_tx_id));
            Ok(Outcome::ConflictRecovered {
                burn_tx_id: burn_tx_id.to_string(),
                withdrawal_id: withdrawal_id.as_str().to_string(),
                status,
            })
        }

        SubmitOutcome::ReconciliationRequired { burn_tx_id } => {
            ctx.emit(
                ListenerEvent::new("B7", "reconciliation-required", note_id).with_burn(&burn_tx_id),
            );
            Ok(Outcome::ReconciliationRequired {
                burn_tx_id,
                reason: ReconciliationReason::ConflictNamedNoWithdrawal,
            })
        }

        SubmitOutcome::ConflictEchoMismatch { echoed, .. } => {
            ctx.emit(ListenerEvent::new("B7", "echo-mismatch", note_id).with_burn(burn_tx_id));
            Ok(Outcome::ReconciliationRequired {
                burn_tx_id: burn_tx_id.to_string(),
                reason: ReconciliationReason::EchoMismatch { echoed },
            })
        }

        SubmitOutcome::AlreadySubmitted { burn_tx_id, status } => {
            ctx.emit(ListenerEvent::new("B7", "already-submitted", note_id).with_burn(&burn_tx_id));
            Ok(Outcome::AlreadySubmitted { burn_tx_id, status })
        }
    }
}
