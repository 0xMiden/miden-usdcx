//! `POST /v1/withdraw` (`CMP-D6`) and `GET /v1/withdrawal/{withdrawalId}` (`CMP-D7`) — the
//! submission, and the withdrawal status both endpoints return.

use serde::{Deserialize, Serialize};

use super::intents::BurnIntent;
use crate::circle::wire::{present_non_null, Hex32, HexBytes, HexTxId, SchemaError, Uuid};

/// `WithdrawRequest.batches`: "up to five per request".
const BATCHES_MIN: usize = 1;
const BATCHES_MAX: usize = 5;
/// `WithdrawBatch.burnIntents`: "either a single burn intent or a burn intent set".
const BURN_INTENTS_MIN: usize = 1;
const BURN_INTENTS_MAX: usize = 10;
/// `WithdrawBatch.burnSignatures`: "multiple signatures are needed to meet the multi-sig threshold".
const BURN_SIGNATURES_MIN: usize = 2;

/// `POST /v1/withdraw` request — the top-level `batches[]` wrapper (`minItems 1`, `maxItems 5`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "WithdrawRequestRaw")]
pub struct WithdrawRequest {
    batches: Vec<WithdrawBatch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawRequestRaw {
    batches: Vec<WithdrawBatch>,
}

impl TryFrom<WithdrawRequestRaw> for WithdrawRequest {
    type Error = SchemaError;

    fn try_from(raw: WithdrawRequestRaw) -> Result<Self, Self::Error> {
        Self::new(raw.batches)
    }
}

impl WithdrawRequest {
    /// # Errors
    /// [`SchemaError::BatchCountOutOfRange`] — fewer than 1 or more than 5 batches. An EMPTY `batches`
    /// array is a request that asks Circle to do nothing, submitted as though it asked for something.
    pub fn new(batches: Vec<WithdrawBatch>) -> Result<Self, SchemaError> {
        if !(BATCHES_MIN..=BATCHES_MAX).contains(&batches.len()) {
            return Err(SchemaError::BatchCountOutOfRange(batches.len()));
        }

        Ok(Self { batches })
    }

    pub fn batches(&self) -> &[WithdrawBatch] {
        &self.batches
    }
}

/// One submitted batch.
///
/// Two of its rules are the schema's and are enforced here — `burnIntents` 1..=10, and
/// `burnSignatures` **`minItems 2`** (the partner's 2-of-n attester quorum). The rest of the quorum
/// contract — signatures in ascending signer-address order, no duplicates (`DC-11`, §10.9, T-LA-09) —
/// is NOT expressible in a JSON schema and is the quorum assembler's job.
///
/// So the signature list is carried **verbatim**: never sorted, never deduplicated. A wire type that
/// tidied it would repair the batch on its way out and hide from the quorum check the very defect the
/// quorum check exists to catch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "WithdrawBatchRaw"
)]
pub struct WithdrawBatch {
    burn_intents: Vec<BurnIntent>,
    burn_signatures: Vec<HexBytes>,

    /// The Miden burn transaction identifier — the burn-evidence field Circle resolves against a Miden
    /// node (`DEV-7`, OPEN). The REQUEST-side field has **no documented pattern** (unlike the response
    /// side's `^0x[a-fA-F0-9]+$`), so none is imposed.
    burn_tx_id: String,

    use_circle_forwarding: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WithdrawBatchRaw {
    burn_intents: Vec<BurnIntent>,
    burn_signatures: Vec<HexBytes>,
    burn_tx_id: String,
    use_circle_forwarding: bool,
}

impl TryFrom<WithdrawBatchRaw> for WithdrawBatch {
    type Error = SchemaError;

    fn try_from(raw: WithdrawBatchRaw) -> Result<Self, Self::Error> {
        Self::new(
            raw.burn_intents,
            raw.burn_signatures,
            raw.burn_tx_id,
            raw.use_circle_forwarding,
        )
    }
}

impl WithdrawBatch {
    /// # Errors
    /// * [`SchemaError::BurnIntentCountOutOfRange`] — not 1..=10 burn intents.
    /// * [`SchemaError::SignatureCountBelowThreshold`] — fewer than 2 signatures. Circle will not meet
    ///   its multi-sig threshold with one, so such a batch must never be submitted.
    pub fn new(
        burn_intents: Vec<BurnIntent>,
        burn_signatures: Vec<HexBytes>,
        burn_tx_id: String,
        use_circle_forwarding: bool,
    ) -> Result<Self, SchemaError> {
        if !(BURN_INTENTS_MIN..=BURN_INTENTS_MAX).contains(&burn_intents.len()) {
            return Err(SchemaError::BurnIntentCountOutOfRange(burn_intents.len()));
        }
        if burn_signatures.len() < BURN_SIGNATURES_MIN {
            return Err(SchemaError::SignatureCountBelowThreshold(
                burn_signatures.len(),
            ));
        }

        Ok(Self {
            burn_intents,
            burn_signatures,
            burn_tx_id,
            use_circle_forwarding,
        })
    }

    pub fn burn_intents(&self) -> &[BurnIntent] {
        &self.burn_intents
    }

    /// The signatures, exactly as supplied — in their original order, duplicates and all.
    pub fn burn_signatures(&self) -> &[HexBytes] {
        &self.burn_signatures
    }

    pub fn burn_tx_id(&self) -> &str {
        &self.burn_tx_id
    }

    pub fn use_circle_forwarding(&self) -> bool {
        self.use_circle_forwarding
    }
}

/// `POST /v1/withdraw` response — an **ARRAY**, one [`WithdrawalStatus`] per submitted batch.
///
/// It is a `Vec` alias rather than a wrapper struct because the wire body genuinely is a bare JSON
/// array. Modelling it as an object would fail to decode every real response.
pub type WithdrawSubmissionResponse = Vec<WithdrawalStatus>;

/// The `POST /v1/withdraw` **`409` conflict** body: the `burnTxId` is already tied to an active
/// withdrawal (`CIRCLE-API-SURFACE.md:74`).
///
/// # What this type is for, and what it must never enable
///
/// A `409` is a **duplicate conflict requiring recovery/reconciliation — NOT a success**, and never a
/// blind re-send (§10.10). This body is the only thing that says which withdrawal the duplicate
/// collided with, so decoding it is the difference between recovering the real state and guessing.
///
/// * `burnTxId` is **required**. It is the idempotency key, and the ONLY thing that binds this
///   conflict to the burn that was submitted — §10.10's "a 409 body that does not echo the original
///   `burnTxId` → treat as a defect" is uncheckable without it. A `409` whose body carries no
///   `burnTxId` therefore does not decode, becomes an exact
///   [`ListenerError::MalformedResponse`](crate::error::ListenerError::MalformedResponse), and (like
///   every ambiguity on this path) stops the submission rather than retrying it.
/// * `withdrawalId` is **optional**, because the two cases are genuinely different actions: present →
///   recover by polling `GET /v1/withdrawal/{withdrawalId}`; absent → stop resubmission and mark
///   reconciliation required. Modelling it as required would turn the second case into a decode error
///   and lose the distinction the spec draws.
///
/// Unknown fields are ACCEPTED here, unlike the request types. The OpenAPI documents status codes only
/// — there is no error-body schema at all (§10.11) — so this shape is inferred from the frozen fixture,
/// and refusing a field Circle happens to add would push an otherwise recoverable conflict into
/// reconciliation for no safety gain. The two fields that decide anything are still validated newtypes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawConflict {
    #[serde(
        default,
        deserialize_with = "present_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    withdrawal_id: Option<Uuid>,

    burn_tx_id: HexTxId,
}

impl WithdrawConflict {
    /// The withdrawal the duplicate collided with, when Circle named one — the id a recovery polls.
    /// `None` is the "stop and reconcile" case, not an error.
    pub fn withdrawal_id(&self) -> Option<&Uuid> {
        self.withdrawal_id.as_ref()
    }

    /// The `burnTxId` the conflict is keyed on. It MUST echo the submitted burn; a mismatch is a
    /// defect (§10.10), never a recovery and never a success.
    pub fn burn_tx_id(&self) -> &str {
        self.burn_tx_id.as_str()
    }
}

/// The withdrawal object — returned inside the `POST /v1/withdraw` array, and returned singly by
/// `GET /v1/withdrawal/{withdrawalId}`.
///
/// Required: `withdrawalId`, `burnTxId`, `status`, `useCircleForwarding`, `transferSpecHashes`.
/// Conditional: `attestationPayload`, `attestation`, `transactionHash`, `failureReason` (the last
/// "returned when `status` is 'failed'"). The conditional four may be **omitted**; none of them may
/// be present-and-`null` (§10.11: a malformed Circle response is rejected, not acted on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalStatus {
    withdrawal_id: Uuid,
    burn_tx_id: HexTxId,
    status: WithdrawalStatusKind,

    /// The full Gateway `Attestation`/`AttestationSet` payload Circle produced.
    #[serde(
        default,
        deserialize_with = "present_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    attestation_payload: Option<HexBytes>,

    /// The xReserve attestation signature.
    #[serde(
        default,
        deserialize_with = "present_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    attestation: Option<HexBytes>,

    use_circle_forwarding: bool,

    #[serde(
        default,
        deserialize_with = "present_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    transaction_hash: Option<Hex32>,

    /// Present when (and only when) the status is [`WithdrawalStatusKind::Failed`].
    #[serde(
        default,
        deserialize_with = "present_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    failure_reason: Option<String>,

    /// The `keccak256(encoded TransferSpec)` identifiers — the transfer's cross-chain identity. A
    /// wrong-length hash here identifies a different transfer, or none.
    transfer_spec_hashes: Vec<Hex32>,
}

impl WithdrawalStatus {
    pub fn withdrawal_id(&self) -> &str {
        self.withdrawal_id.as_str()
    }

    /// The burn-evidence field the submission was keyed on — and the key a 409 conflict is keyed on.
    pub fn burn_tx_id(&self) -> &str {
        self.burn_tx_id.as_str()
    }

    pub fn status(&self) -> WithdrawalStatusKind {
        self.status
    }

    pub fn attestation_payload(&self) -> Option<&str> {
        self.attestation_payload.as_ref().map(HexBytes::as_str)
    }

    pub fn attestation(&self) -> Option<&str> {
        self.attestation.as_ref().map(HexBytes::as_str)
    }

    pub fn use_circle_forwarding(&self) -> bool {
        self.use_circle_forwarding
    }

    pub fn transaction_hash(&self) -> Option<&str> {
        self.transaction_hash.as_ref().map(Hex32::as_str)
    }

    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    pub fn transfer_spec_hashes(&self) -> &[Hex32] {
        &self.transfer_spec_hashes
    }
}

/// The withdrawal status enum, verbatim: `created, verified, confirmed, finalized, expired, failed`.
///
/// A closed enum, not a `String`, so a status the service cannot reason about is refused at the
/// boundary rather than flowing into the terminal-state logic and being treated as "not yet done"
/// forever.
///
/// It is deliberately NOT `#[non_exhaustive]`. The repo's non-exhaustive-public-types rule exempts
/// protocol/schema enums whose closed set is contractual: a seventh status would be a CIRCLE WIRE
/// CHANGE, not a compatible library extension, and every `match` on it downstream — the terminal /
/// retryable partitions above all — should be forced to confront that rather than quietly falling
/// into a catch-all arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WithdrawalStatusKind {
    Created,
    Verified,
    Confirmed,
    /// **Terminal** (polling stops here), and the success case.
    Finalized,
    /// **Retryable, and NOT terminal.** The withdrawal window closed and a NEW withdrawal must be
    /// resubmitted (`TEST-AND-VERIFICATION-HARNESS.md:191`-`195`: only `finalized`/`failed` are
    /// terminal). Polling of THIS id stops because it cannot progress, but `expired` is a distinct
    /// resubmit outcome — never a completed withdrawal — so it is deliberately excluded from
    /// [`is_terminal`](Self::is_terminal) and reported through [`is_retryable`](Self::is_retryable).
    Expired,
    /// **Terminal** (polling stops here) and NOT retryable.
    Failed,
}

impl WithdrawalStatusKind {
    /// Whether this is a TERMINAL completion — only `finalized` (success) and `failed` (terminal
    /// failure). `expired` is deliberately **excluded**: the task and `TEST-AND-VERIFICATION-HARNESS.md`
    /// (`:191`-`:195`) define only `finalized`/`failed` as terminal, and treating `expired` as terminal
    /// would hand a resubmittable withdrawal to callers as though it were done. `expired`'s "stop
    /// polling" behavior is captured by [`is_retryable`](Self::is_retryable) instead.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Failed)
    }

    /// Whether the status is a RETRYABLE (resubmit) outcome — `expired` only. It is NOT terminal; a
    /// caller that sees it submits a NEW withdrawal. Reading this the wrong way round would either
    /// strand a recoverable withdrawal or replay one Circle has already refused.
    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Expired)
    }
}
