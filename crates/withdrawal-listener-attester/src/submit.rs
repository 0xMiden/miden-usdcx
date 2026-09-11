//! Submits authorized withdrawals after acquiring durable burn claims.
//! Retries are bounded and restricted by the HTTP retry policy. A conflict ends submission:
//! a matching withdrawal ID permits status polling; ambiguous or inconsistent responses require
//! reconciliation. A conflict alone is never reported as a successful submission.
//!
//! Only `finalized` completes a withdrawal. Uncertain outcomes retain the claim to prevent
//! blind resubmission. Circle's acceptance of Miden transaction IDs remains OPEN.

use crate::circle::client::CircleClient;
use crate::circle::retry::with_backoff;
use crate::circle::schema::{
    WithdrawConflict, WithdrawRequest, WithdrawSubmissionResponse, WithdrawalStatus,
    WithdrawalStatusKind,
};
use crate::circle::wire::Uuid;
use crate::error::ListenerError;
use crate::idempotency::{BurnKey, ClaimOutcome, LedgerError, SubmissionStatus, SubmitLedger};
use crate::withdrawal_api::{
    decode, decode_withdraw_created, AuthorizedWithdrawal, PATH_WITHDRAW, STATUS_WITHDRAW_CONFLICT,
    STATUS_WITHDRAW_CREATED,
};

use core::fmt;

/// What a `POST /v1/withdraw` submission ACTUALLY resulted in.
///
/// The type is closed, and its shape is Circle's documented contract: **there is no path from a
/// `409` to [`Self::Submitted`]**, because [`Self::Submitted`] is constructed under a `201` and
/// nowhere else.
///
/// It is deliberately NOT `#[non_exhaustive]`. A caller must be forced to confront every outcome:
/// the three that are *not* a completed withdrawal are exactly the ones a catch-all arm would
/// quietly swallow, and swallowing them is how a duplicate becomes a second release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Circle answered **`201`**: the withdrawal(s) were created, one status per submitted batch.
    ///
    /// This is "Circle accepted the submission", NOT "the funds are out": the statuses inside are
    /// typically `created`, and only a later `finalized` is terminal success.
    Submitted(WithdrawSubmissionResponse),

    /// A **`409`** that named a `conflict.withdrawalId`, RECOVERED by polling
    /// `GET /v1/withdrawal/{withdrawalId}` — the real state, read rather than assumed.
    ///
    /// `status` is reported HONESTLY and is not filtered: `finalized` is the one terminal success;
    /// `failed`/`expired`/pending are NOT. This variant means "we found out what actually
    /// happened", never "it worked".
    ConflictRecovered {
        withdrawal_id: Uuid,
        status: WithdrawalStatus,
    },

    /// A **`409`** carrying only `conflict.burnTxId`: there is no withdrawal id to recover through,
    /// so resubmission STOPS and an operator must reconcile the burn. Not a failure of this service
    /// — an answer it is not allowed to resolve on its own.
    ReconciliationRequired { burn_tx_id: String },

    /// The `burnTxId` Circle echoed is NOT one this request submitted — in a `409` conflict body,
    /// or in a status recovered through one. Circle documents: "a 409 body that does not echo the
    /// original `burnTxId` → treat as a defect, not a success". The idempotency key must match; if
    /// it does not, this conflict is about some other burn, and nothing about it may be believed of
    /// ours.
    ConflictEchoMismatch {
        /// The `burnTxId`s this request actually carried.
        submitted: Vec<String>,
        /// What Circle echoed instead.
        echoed: String,
    },

    /// The ledger already accounts for this burn: it was claimed, submitted, settled or flagged by
    /// an earlier pass (or another process). **ZERO calls were made** — this is decided before the
    /// wire.
    AlreadySubmitted {
        burn_tx_id: String,
        status: SubmissionStatus,
    },
}

impl SubmitOutcome {
    /// The `201` submission response, and `None` for every other outcome — including every `409`
    /// one.
    ///
    /// The accessor exists so a caller can ask "did this submission actually go out?" without
    /// matching, and get an answer that cannot be `Some` for a conflict.
    pub fn submitted(&self) -> Option<&WithdrawSubmissionResponse> {
        match self {
            Self::Submitted(response) => Some(response),
            Self::ConflictRecovered { .. }
            | Self::ReconciliationRequired { .. }
            | Self::ConflictEchoMismatch { .. }
            | Self::AlreadySubmitted { .. } => None,
        }
    }
}

/// Why a submission could not be carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubmitError {
    /// Circle's answer, surfaced with its exact [`ListenerError`] — an exhausted `5xx` budget, a
    /// deterministic `400`, an undocumented status, an unreadable body. Never softened into an
    /// outcome: none of these is a withdrawal.
    Circle(ListenerError),

    /// The ledger refused. The submission did NOT go out — a listener that cannot record a claim
    /// must not make one.
    Ledger(LedgerError),

    /// ONE request carried the same `burnTxId` in two batches. It would ask Circle to release the
    /// same burn twice inside a single call, and the request's own second batch would be what
    /// triggers the `409`. Refused before the wire.
    DuplicateBurnInRequest { burn_tx_id: String },
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Circle(source) => write!(f, "the withdraw submission failed: {source}"),
            Self::Ledger(source) => write!(f, "the submit ledger refused: {source}"),
            Self::DuplicateBurnInRequest { burn_tx_id } => write!(
                f,
                "the withdraw request carries burn `{burn_tx_id}` in more than one batch"
            ),
        }
    }
}

impl core::error::Error for SubmitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Circle(source) => Some(source),
            Self::Ledger(source) => Some(source),
            Self::DuplicateBurnInRequest { .. } => None,
        }
    }
}

impl From<LedgerError> for SubmitError {
    fn from(source: LedgerError) -> Self {
        Self::Ledger(source)
    }
}

/// **Submit an authorized withdrawal, exactly once, ever.**
///
/// The order is the contract:
///
/// 1. **Refuse an intra-request duplicate** — the same burn twice in one body. Zero calls.
/// 2. **CLAIM every burn in the request, atomically and all-or-nothing**
///    (`SubmitLedger::claim_burns`). The claim is the decision: on [`ClaimOutcome::AlreadySeen`]
///    this returns [`SubmitOutcome::AlreadySubmitted`] having made ZERO calls, so a re-discovered
///    burn, a retry driver, or a restarted process cannot produce a second submission.
/// 3. **POST once, under the retry policy and the rate ceilings.** A `5xx` is retried within the
///    bound — it is the one failure Circle documents as transient, and Circle ANSWERED, so it did
///    not act. A `400` is not retried, a status-less transport failure is not retried (no answer is
///    no evidence: the withdrawal may be releasing with only the response lost), and a `409` is not
///    an error at all but a conflict to RECOVER.
/// 4. **Record the answer durably**, and fail closed on every ambiguity — attaching Circle's
///    `withdrawalId` only to the burn Circle actually bound it to.
///
/// The `authorized` token is CONSUMED, so one pre-submit fund-safety authorization
/// ([`authorize_submission`](crate::withdrawal_api::authorize_submission)) is spent on one
/// submission. Together with the claim, both gates a withdrawal must clear — "every signer is a
/// registered attester" and "this burn has never been submitted" — are structural, not
/// conventional.
///
/// # Errors
/// * [`SubmitError::DuplicateBurnInRequest`] — step 1.
/// * [`SubmitError::Ledger`] — the claim or a record failed; nothing was submitted, or the answer
///   could not be written down (which an operator must see).
/// * [`SubmitError::Circle`] — the exact Circle failure, surfaced. The burn is left recorded:
///   [`SubmissionStatus::Failed`] (re-claimable) ONLY for a deterministic `400`, where Circle
///   created nothing; [`SubmissionStatus::ReconciliationRequired`] for every ambiguous failure.
pub async fn submit_withdraw(
    circle: &CircleClient,
    ledger: &SubmitLedger,
    authorized: AuthorizedWithdrawal,
) -> Result<SubmitOutcome, SubmitError> {
    let request = authorized.into_request();
    let burns: Vec<String> = request
        .batches()
        .iter()
        .map(|batch| batch.burn_tx_id().to_string())
        .collect();
    let keys: Vec<BurnKey> = burns.iter().map(BurnKey::new).collect();

    // 1. an intra-request duplicate: two batches, one burn
    if let Some(at) = keys
        .iter()
        .enumerate()
        .find(|(i, k)| keys[..*i].contains(k))
    {
        return Err(SubmitError::DuplicateBurnInRequest {
            burn_tx_id: burns[at.0].clone(),
        });
    }

    // 2. THE decision point. Submitting on anything but `Claimed` is the double-withdrawal bug.
    match ledger.claim_burns(&keys)? {
        ClaimOutcome::AlreadySeen(record) => {
            return Ok(SubmitOutcome::AlreadySubmitted {
                burn_tx_id: record.burn_key().as_str().to_string(),
                status: record.status(),
            })
        }
        ClaimOutcome::Claimed(_) => {}
    }

    // 3. the ONE POST call site, bounded and rate-governed
    match with_backoff(circle, || attempt_withdraw(circle, &request)).await {
        Ok(Attempt::Created(statuses)) => settle_created(ledger, &keys, &burns, statuses),
        Ok(Attempt::Conflict(conflict)) => {
            recover_conflict(circle, ledger, &keys, &burns, conflict).await
        }
        Err(error) => {
            // 4. fail closed BEFORE surfacing: the burn must be blocked (or, for a 400 alone,
            // released back into the re-claimable pool) whatever the caller does with the error.
            settle_failure(ledger, &keys, &error)?;
            Err(SubmitError::Circle(error))
        }
    }
}

/// What ONE `POST /v1/withdraw` attempt produced. A `409` is an ATTEMPT OUTCOME, not an error which
/// is exactly what keeps it out of [`is_retryable`](crate::circle::retry::is_retryable)'s reach and
/// therefore out of the retry loop.
enum Attempt {
    Created(WithdrawSubmissionResponse),
    Conflict(WithdrawConflict),
}

/// One attempt: build the real request, execute it, apply Circle's documented status policy,
/// decode.
///
/// Everything that is a property of the PEER's answer rather than of the moment — a malformed body,
/// a cardinality mismatch, a `400`, an undocumented status — is an `Err` the retry loop will not
/// retry.
async fn attempt_withdraw(
    circle: &CircleClient,
    request: &WithdrawRequest,
) -> Result<Attempt, ListenerError> {
    let built = circle.build_post(PATH_WITHDRAW, request)?;
    let response = circle.execute(built).await?;

    match response.status() {
        STATUS_WITHDRAW_CREATED => Ok(Attempt::Created(decode_withdraw_created(
            response.body(),
            request.batches().len(),
        )?)),
        // the conflict body is the ONLY thing that says which withdrawal the duplicate hit; a 409 we
        // cannot read is an ambiguity, not a licence to try again
        STATUS_WITHDRAW_CONFLICT => Ok(Attempt::Conflict(decode(
            response.body(),
            "withdraw-conflict",
        )?)),
        other => Err(ListenerError::Http { status: other }),
    }
}

/// A `201`: bind each returned status to the burn it claims, then record.
///
/// The binding is by `burnTxId`, not by array position. Circle documents one element per submitted
/// batch, and the cardinality is already enforced — but "the same COUNT" is not "the same burns",
/// and pairing by index would attribute a withdrawal id to the wrong burn if the order ever
/// differed. Since an intra-request duplicate is refused above, each burn matches at most one
/// status, so the pairing is unambiguous. (Binding the submitted BATCH to `assemble_quorum`'s shape
/// check, and the batch↔burn cardinality question underneath it, belongs to the orchestration —
/// this is the `burnTxId` half of it.)
fn settle_created(
    ledger: &SubmitLedger,
    keys: &[BurnKey],
    burns: &[String],
    statuses: WithdrawSubmissionResponse,
) -> Result<SubmitOutcome, SubmitError> {
    // check EVERY pairing before writing ANY of it: a half-recorded submission would leave the rest of
    // the burns in `Pending` with no way back.
    for status in &statuses {
        if !echoes_one_of(burns, status.burn_tx_id()) {
            mark_all_reconciliation(ledger, keys)?;
            return Ok(SubmitOutcome::ConflictEchoMismatch {
                submitted: burns.to_vec(),
                echoed: status.burn_tx_id().to_string(),
            });
        }
    }

    let mut paired = Vec::with_capacity(keys.len());
    for burn in burns {
        match statuses
            .iter()
            .find(|s| s.burn_tx_id().eq_ignore_ascii_case(burn))
        {
            Some(status) => paired.push(status),
            None => {
                mark_all_reconciliation(ledger, keys)?;
                return Ok(SubmitOutcome::ConflictEchoMismatch {
                    submitted: burns.to_vec(),
                    echoed: burn.clone(),
                });
            }
        }
    }

    for (key, status) in keys.iter().zip(paired) {
        ledger.record_submission(key, Some(status.withdrawal_id()))?;
    }

    Ok(SubmitOutcome::Submitted(statuses))
}

/// A `409` — Circle's documented conflict response, clause by clause.
///
/// # A conflict names ONE burn, and may settle only that burn
///
/// A request carries 1-5 batches; the conflict body carries a single `burnTxId`. So the conflict is
/// evidence about exactly one of the submitted burns, and the others are simply not spoken about:
/// Circle refused the whole POST, and nothing here says what became of them.
///
/// This function therefore resolves the conflict to a specific INDEX, applies the recovered outcome
/// to that burn alone, and fails every other burn in the request closed. Applying the named burn's
/// `finalized` to its neighbours would write a durable claim that Circle released them — with no
/// evidence for them whatsoever — which both blocks them permanently and makes the per-burn record
/// a lie. (The neighbours are blocked rather than freed because "Circle almost certainly did not
/// create them" is not "Circle demonstrably did not create them". That costs liveness — an operator
/// must clear them — and it is the trade this whole module makes.)
async fn recover_conflict(
    circle: &CircleClient,
    ledger: &SubmitLedger,
    keys: &[BurnKey],
    burns: &[String],
    conflict: WithdrawConflict,
) -> Result<SubmitOutcome, SubmitError> {
    let echoed = conflict.burn_tx_id();

    // "a 409 body that does not echo the original burnTxId → treat as a defect, not a success". This
    // is checked FIRST: a conflict about another burn tells us nothing about ours, and chasing its
    // withdrawalId would read a stranger's withdrawal as our outcome.
    //
    // `position`, not "does any match": the INDEX is what binds the rest of this function to one burn.
    let Some(at) = position_of(burns, echoed) else {
        // The conflict's `withdrawalId` is deliberately DROPPED here, not carried into the records.
        // It describes a withdrawal of a burn we never submitted — it is bound to none of ours, so
        // storing it against any of them would be inventing evidence.
        mark_all_reconciliation(ledger, keys)?;
        return Ok(SubmitOutcome::ConflictEchoMismatch {
            submitted: burns.to_vec(),
            echoed: echoed.to_string(),
        });
    };

    // "if only conflict.burnTxId is present → stop resubmission and mark reconciliation required".
    // Every burn is blocked: the named one cannot be recovered (no id to poll), and the rest were
    // refused along with it. There is no id to attach to anything.
    let Some(withdrawal_id) = conflict.withdrawal_id() else {
        mark_all_reconciliation(ledger, keys)?;
        return Ok(SubmitOutcome::ReconciliationRequired {
            burn_tx_id: echoed.to_string(),
        });
    };

    // "if conflict.withdrawalId is present → recover by polling GET /v1/withdrawal/{withdrawalId}".
    // POLL — never re-POST. A poll that fails leaves every burn blocked: we asked what happened and did
    // not find out, which is the definition of ambiguous.
    let status = match crate::withdrawal_api::poll_status(circle, withdrawal_id).await {
        Ok(status) => status,
        Err(error) => {
            // Blocked, all of them — but the id belongs to `keys[at]` alone: the 409 bound it to that
            // burn and said nothing about the others.
            block_binding_id_to(ledger, keys, at, withdrawal_id)?;
            return Err(SubmitError::Circle(error));
        }
    };

    // The recovered status must be about the burn the CONFLICT named — not merely some burn in the
    // request. `poll_status` already binds the response to the requested withdrawalId; this binds it to
    // the one burn under discussion. "Echoes any of ours" would let a multi-burn request accept a
    // status for burn B as the resolution of a conflict about burn A.
    if !status.burn_tx_id().eq_ignore_ascii_case(&burns[at]) {
        // The status is incoherent, but the 409 itself still bound this id to `burns[at]` — that much
        // is Circle's own claim, and it is the lead an operator starts from. It goes there and nowhere
        // else.
        block_binding_id_to(ledger, keys, at, withdrawal_id)?;
        return Ok(SubmitOutcome::ConflictEchoMismatch {
            submitted: burns.to_vec(),
            echoed: status.burn_tx_id().to_string(),
        });
    }

    // "never report withdrawal success from a 409 alone" — and only `finalized` is terminal
    // success. `failed`, `expired` and every pending status leave the burn for an operator.
    //
    // Applied to `keys[at]` ONLY: it is the single burn this evidence is about.
    if status.status() == WithdrawalStatusKind::Finalized {
        ledger.record_finalized(&keys[at], Some(withdrawal_id.as_str()))?;
    } else {
        ledger.record_reconciliation_required(&keys[at], Some(withdrawal_id.as_str()))?;
    }

    // every OTHER burn in the request: no evidence, so no claim — blocked for an operator
    block_others(ledger, keys, at)?;

    Ok(SubmitOutcome::ConflictRecovered {
        withdrawal_id: withdrawal_id.clone(),
        status,
    })
}

/// Record a failed attempt, fail-closed.
///
/// The ONE case that is re-claimable is a deterministic `400`: Circle rejected the request, so
/// nothing was created and nothing can be double-released — the spec's "abort/fix-request". Every
/// other failure (an exhausted `5xx` budget, a status-less transport failure, a `201` we could not
/// read, an undocumented status) may have left a withdrawal in flight, so the burn is BLOCKED.
fn settle_failure(
    ledger: &SubmitLedger,
    keys: &[BurnKey],
    error: &ListenerError,
) -> Result<(), SubmitError> {
    if matches!(error, ListenerError::Http { status: 400 }) {
        for key in keys {
            ledger.record_failure(key)?;
        }
        return Ok(());
    }
    mark_all_reconciliation(ledger, keys)
}

/// Block every burn, claiming NOTHING about any of them.
///
/// The counterpart of [`block_binding_id_to`], and the default: a burn gets a `withdrawalId` only
/// where Circle actually named one FOR IT.
fn mark_all_reconciliation(ledger: &SubmitLedger, keys: &[BurnKey]) -> Result<(), SubmitError> {
    for key in keys {
        ledger.record_reconciliation_required(key, None)?;
    }
    Ok(())
}

/// Block every burn, attaching `withdrawal_id` to `keys[at]` — the ONE burn the conflict named —
/// and to no other.
///
/// # Why the index is not a detail
///
/// [`SubmissionRecord::withdrawal_id`](crate::idempotency::SubmissionRecord::withdrawal_id) is the
/// handle an OPERATOR polls: it answers "this burn is blocked — what happened to it?". Copying burn
/// A's id into burn B's record is therefore not untidiness, it is **durable false evidence**:
/// whoever reconciles B would poll A's withdrawal, read A's outcome, and attribute it to B — a
/// conclusion Circle never supported and this service manufactured.
///
/// A `409` binds one `withdrawalId` to one `burnTxId`. Blocking the neighbours is right (their
/// state is unknown); telling a story about them is not. So they are blocked with `None`.
fn block_binding_id_to(
    ledger: &SubmitLedger,
    keys: &[BurnKey],
    at: usize,
    withdrawal_id: &Uuid,
) -> Result<(), SubmitError> {
    ledger.record_reconciliation_required(&keys[at], Some(withdrawal_id.as_str()))?;
    block_others(ledger, keys, at)
}

/// Blocks every burn EXCEPT `keys[at]`, claiming nothing about them.
fn block_others(ledger: &SubmitLedger, keys: &[BurnKey], at: usize) -> Result<(), SubmitError> {
    for (i, key) in keys.iter().enumerate() {
        if i != at {
            ledger.record_reconciliation_required(key, None)?;
        }
    }
    Ok(())
}

/// WHICH of the `burnTxId`s this request carried `echoed` names, if any.
///
/// The index — not a yes/no — is what lets a conflict or a status bind to ONE burn, so evidence
/// about burn A can never settle burn B. Since an intra-request duplicate is refused before
/// anything is submitted, at most one burn can match, and the first is the only one.
///
/// The comparison ignores ASCII case because hex is case-insensitive as an IDENTIFIER: `0xAB…` and
/// `0xab…` name the same Miden transaction, and calling that a defect would push a perfectly
/// recoverable conflict into reconciliation. Anything beyond case is a different value and is
/// treated as one — which fails toward a blocked burn, never toward a second release.
fn position_of(burns: &[String], echoed: &str) -> Option<usize> {
    burns
        .iter()
        .position(|burn| burn.eq_ignore_ascii_case(echoed))
}

/// Whether `echoed` is one of the `burnTxId`s this request carried.
fn echoes_one_of(burns: &[String], echoed: &str) -> bool {
    position_of(burns, echoed).is_some()
}
