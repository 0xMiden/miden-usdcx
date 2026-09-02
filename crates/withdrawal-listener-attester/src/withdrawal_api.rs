//! `withdrawal_api` — the two request bodies the partner AUTHORS for Circle (the
//! [`PrepareWithdrawalRequest`] and the `POST /v1/withdraw` [`WithdrawRequest`] wrapper),
//! the READ-ONLY Circle drivers ([`prepare`] and [`poll_status`]), and the
//! submission pieces the withdraw POST is assembled from — the pre-submit fund-safety gate
//! ([`authorize_submission`]) and the `201` response contract (`decode_withdraw_created`).
//!
//! # The drivers, and the shapes that are load-bearing
//!
//! Each driver builds a real [`reqwest::Request`] through the [`CircleClient`], executes it against
//! the injected transport (the in-process schema-exact mock in the gate suite), applies the
//! per-endpoint HTTP-status policy, and decodes — never coercing a malformed body:
//!
//! * [`prepare`] — `POST /v1/prepare-withdrawal`; `200` → the top-level `batches[]`
//!   [`PrepareWithdrawalResponse`] wrapper.
//! * [`poll_status`] — `GET /v1/withdrawal/{withdrawalId}`; polls until it stops, which happens on
//!   a TERMINAL status (`finalized` success or `failed`) OR on the distinct RETRYABLE `expired`
//!   outcome (resubmit a new withdrawal — `expired` is NOT terminal). A `404` is its own exact
//!   [`ListenerError::WithdrawalNotFound`]; a `status` outside the six-member enum is a hard decode
//!   error, never defaulted.
//!
//! # `POST /v1/withdraw` is NOT driven from here — deliberately
//!
//! The submission lives in [`submit`](crate::submit), whole: the `409` conflict-recovery, the
//! bounded `5xx` retry, the rate ceilings, and — the reason it cannot be split — the **durable
//! per-burn idempotency claim** that must be taken before a request is even built.
//!
//! A raw `withdraw` driver did sit here once, so the endpoint's shape could be tested one request
//! at a time. It was a bypass: [`WithdrawRequest`] is `Clone` and [`authorize_submission`] is
//! public, so a caller could mint two authorizations for ONE burn and submit it twice without the
//! ledger ever hearing about it. It is gone rather than hidden, and what it proved — the
//! `batches[]` wrapper on the wire, the `201` ARRAY (one [`WithdrawalStatus`] per submitted batch;
//! modelling it as an object would fail to decode every real reply), the cardinality rule — is
//! proved through [`submit_withdraw`](crate::submit::submit_withdraw), which builds with this
//! module's [`CircleClient`] and decodes with this module's `decode_withdraw_created`.
//!
//! # Fund-safety: the pre-submit signer-allowlist gate ([`authorize_submission`])
//!
//! Circle verifies `ECDSA.recover(digest, sig) → addr` and `require(attesters[addr])` on the source
//! chain — but that is the LAST line of defense, at the fund-release boundary. Before ANY
//! `/v1/withdraw` submission, [`authorize_submission`] re-does that recovery OFF-chain against the
//! same `messageHashToSign` digests and requires every recovered signer to be a configured,
//! registered attester ([`AttesterAllowlist`](crate::attester::AttesterAllowlist)). It mints an
//! [`AuthorizedWithdrawal`] only on a full pass;
//! [`submit_withdraw`](crate::submit::submit_withdraw) takes that token and nothing else, so a
//! submission whose signers are not all registered attesters — or one with no allowlist configured
//! at all (fail-closed) — is **untypeable, not merely unreached**: the refusal happens before the
//! client is touched, guaranteeing ZERO `/v1/withdraw` calls. This is the fund-safety
//! carry-forward: [`assemble_quorum`](crate::attester::assemble_quorum) proves each signature
//! recovers to its CLAIMED signer, and this gate proves that signer is one the operator registered.
//!
//! # What these build, and — load-bearing — what they do NOT
//!
//! The partner builds **only the API JSON request** ([`build_prepare_request`]). It never
//! constructs the binary Gateway `TransferSpec`/`BurnIntent` — Circle encodes those server-side and
//! RETURNS the canonical `burnIntents[]`/`encoded`/`messageHashToSign`, which the partner then
//! validates (the pre-signing gate in `validate.rs`) and signs. A local binary reconstruction is
//! optional validation only (and deliberately not a re-derivation), and none happens here: there is
//! no binary encoder in this crate, and these builders emit JSON.
//!
//! # `remoteDepositor` is NOT `sourceDepositor`
//!
//! `remoteDepositor` is the Miden initiator — the burn note's `metadata.sender`, encoded through
//! the protocol's own `AccountId ↔ bytes32` packaging ([`EthEmbeddedAccountId::to_bytes32`], consumed by
//! reference, not re-implemented) and rendered as the OpenAPI's `^0x[a-fA-F0-9]{64}$`. It is a
//! **partner-built** field. `sourceDepositor` is a Gateway `TransferSpec` field Circle ASSIGNS
//! server-side; [`PrepareBurnIntentInput`] has no such field, so populating it partner-side is not
//! merely avoided here — it is untypeable (an exact match, never a prefix). Swapping the two would
//! name the wrong debtor.
//!
//! # Circle-owned questions this module touches — all still OPEN (parameterized, never resolved)
//!
//! * The `AccountId → bytes32` layout behind `remoteDepositor` is the shared encoding crate's, a
//!   DRAFT that `REQUIRES CIRCLE CONFIRMATION`; this module consumes it and asserts nothing about
//!   its approval.
//! * The forwarding scope (xReserve-only vs Gateway/CCTP). This builder does not invent a
//!   forwarding flow: `useCircleForwarding` is set to `false` and `forwardingOptions` is omitted.
//! * `sourceDepositor` is Circle-filled; the partner never populates it (above).
//! * The smallest-unit⇄decimal `value` scale (and dust/cap) is Circle-owned. The burn payload's
//!   `amount` is in the smallest token unit; this builder passes it through **unscaled** as a
//!   decimal-integer string, applying no `10^n` factor, so the scale stays Circle's to settle. It
//!   is placed in `valueIncludingFees` (the burned amount is the total debited on Miden, out of
//!   which Circle takes its fee), leaving `valueExcludingFees` unset — the value XOR is satisfied
//!   by exactly one field. The exact fee/scale semantics `REQUIRE CIRCLE CONFIRMATION`.
//! * **The credential scheme** — the OpenAPI declares NO security scheme, so the drivers invent none: the auth
//!   header is injected only when the operator configures an out-of-band key AND its header name
//!   (via the [`CircleClient`]'s [`AuthPosture`](crate::circle::auth::AuthPosture)), and no
//!   credential is hardcoded. Parameterized here, never resolved.
//! * Whether a Miden transaction id is an acceptable `burnTxId` is Circle's to confirm; the
//!   `withdraw` body carries whatever `burnTxId` the batch was built with, imposing no pattern the
//!   OpenAPI does not (the request-side field has none).

use miden_standards::interop::eth::EthEmbeddedAccountId;
use serde::de::DeserializeOwned;

use crate::attester::{recover_address, QuorumBundle, Signature65};
use crate::circle::client::CircleClient;
use crate::circle::schema::{
    BurnIntent, PrepareBurnIntentInput, PrepareWithdrawalRequest, PrepareWithdrawalResponse,
    WithdrawBatch, WithdrawRequest, WithdrawSubmissionResponse, WithdrawalStatus,
    WithdrawalStatusKind,
};
use crate::circle::wire::{DecimalAmount, Hex32, HexBytes, SchemaError, Uuid};
use crate::config::ListenerConfig;
use crate::error::{Cause, ListenerError, SubmitGateError};
use crate::validate::{DiscoveredBurn, ValidatedWithdrawal};

/// `POST /v1/prepare-withdrawal`.
const PATH_PREPARE_WITHDRAWAL: &str = "/v1/prepare-withdrawal";
/// `POST /v1/withdraw`.
pub(crate) const PATH_WITHDRAW: &str = "/v1/withdraw";
/// `GET /v1/withdrawal/{withdrawalId}` — prefix; the id is appended.
const PATH_WITHDRAWAL: &str = "/v1/withdrawal/";

/// `POST /v1/prepare-withdrawal` success status (Circle documents `200`).
const STATUS_PREPARE_OK: u16 = 200;
/// `POST /v1/withdraw` success status (Circle documents **`201`**).
pub(crate) const STATUS_WITHDRAW_CREATED: u16 = 201;
/// `POST /v1/withdraw` duplicate-conflict status (Circle documents **`409`** — "burnTxId already
/// tied to an active withdrawal"). Handled by [`submit_withdraw`](crate::submit::submit_withdraw),
/// NEVER as a success and never by re-sending.
pub(crate) const STATUS_WITHDRAW_CONFLICT: u16 = 409;
/// `GET /v1/withdrawal/{id}` success / not-found statuses (Circle documents `200`, `404`).
const STATUS_WITHDRAWAL_OK: u16 = 200;
const STATUS_WITHDRAWAL_NOT_FOUND: u16 = 404;

/// Builds the [`PrepareWithdrawalRequest`] — the API JSON the partner sends to
/// `POST /v1/prepare-withdrawal` — from ONE B3-validated burn and the static config. The single
/// [`PrepareBurnIntentInput`] is wrapped in the top-level `batches[]`.
///
/// # The payload and the sender arrive together, and that is the signature's job
///
/// The two values this request is built out of are the burn's `(amount, destDomain,
/// destRecipient, salt)` and the burner that `remoteDepositor` names. They came off ONE note, and
/// they have to stay off one note: shipping burn A's amount under burn B's depositor asks Circle to
/// release A's money and debit B for it. Nothing downstream can catch that — Circle returns the
/// spec it was asked for, so the gate compares A's amount against A's amount and passes, and the
/// signatures sign a canonical intent that is wrong in the one field nobody checked.
///
/// So the builder does not take them as two arguments. It takes a [`DiscoveredBurn`], whose only
/// constructor is [`validate_discovery`](crate::validate::validate_discovery)'s discovery pass, and
/// reads both out of it. There is no independent-argument form to reach past it — the mismatch is
/// not avoided here, it is untypeable.
///
/// The field mapping (per the request-schema table):
/// * `token` = `USDC`;
/// * `valueIncludingFees` = `payload.amount`, the smallest-unit amount as a decimal-integer string
///   (unscaled — the scale is still OPEN with Circle); `valueExcludingFees` unset;
/// * `remoteDomain` = `cfg.miden_domain` (Miden's Circle-assigned domain, itself still OPEN);
/// * `remoteDepositor` = the `sender`'s [`EthEmbeddedAccountId::to_bytes32`] form as `0x`-hex 32B;
/// * `finalDestinationDomain` / `finalDestinationRecipient` = the burn payload's `destDomain` /
///   `destRecipient`;
/// * `salt` = the burn payload's `salt` (so a rebuild of the SAME burn is byte-identical, rather
///   than drawing a fresh Circle-random salt);
/// * `useCircleForwarding` = `false`, `forwardingOptions`/`finalDestinationCaller` omitted (the
///   forwarding scope is still OPEN with Circle, so none is invented).
///
/// # Errors
/// The cross-field rules [`PrepareBurnIntentInput`] validates, reached through its builder:
/// * [`SchemaError::RemoteDomainBelowMinimum`] — `cfg.miden_domain < 1` (e.g. the config's `0`
///   placeholder while the Circle-assigned domain id is OPEN);
/// * [`SchemaError::DomainsMustDiffer`] — `remoteDomain == finalDestinationDomain`.
pub fn build_prepare_request(
    burn: &DiscoveredBurn,
    cfg: &ListenerConfig,
) -> Result<PrepareWithdrawalRequest, SchemaError> {
    let payload = burn.payload();
    let value = DecimalAmount::new(payload.amount.as_u64().to_string())
        .expect("a smallest-unit integer is a valid decimal amount");

    let input = PrepareBurnIntentInput::builder()
        // `token` defaults to USDC — the one enum member.
        .value_including_fees(value)
        .remote_domain(cfg.miden_domain())
        // the depositor comes out of the SAME `DiscoveredBurn` as the payload above
        .remote_depositor(hex32_of(
            &EthEmbeddedAccountId::from_account_id(burn.depositor()).to_bytes32(),
        ))
        .final_destination_domain(payload.dest_domain)
        .final_destination_recipient(hex32_of(payload.dest_recipient.as_bytes()))
        .salt(hex32_of(&payload.salt))
        .use_circle_forwarding(false)
        .build()?;

    Ok(PrepareWithdrawalRequest::new(vec![input]))
}

/// Builds the ONE `POST /v1/withdraw` [`WithdrawBatch`] for ONE burn: Circle's returned burn
/// intent, the [`QuorumBundle`]'s signatures, and the burn's `burnTxId`.
///
/// # This is the crate's only quorum-shaped path onto the wire
///
/// [`WithdrawBatch::new`] cannot enforce the quorum shape — it is the wire type, its schema says
/// only `burnSignatures: minItems 2`, and it must stay able to decode whatever Circle sends. So it
/// accepts three signatures, or two in descending order, or the same signer twice: each a
/// submission Circle's exactly-2 / strictly-ascending / no-duplicate-signer verifier rejects
/// (`Attestable.sol:75,333-381`), and none of them a shape the JSON schema can refuse.
/// [`authorize_submission`] does not cover it either — it checks signer MEMBERSHIP against the
/// allowlist, and membership is not shape.
///
/// This function is where the two meet: it takes a [`QuorumBundle`], whose only constructor is
/// [`assemble_quorum`](crate::attester::assemble_quorum)'s full-pass path, and renders its
/// signatures into the batch. A batch built through here therefore carries the on-chain shape by
/// construction.
///
/// # …and it takes ONE burn intent, not a vector
///
/// The wire's `burnIntents` is `1..=10` — "either a single burn intent or a burn intent set". This
/// builder deliberately cannot express the set, and the reason is the fan-in the batch count is
/// blind to: a batch carrying the same burn's intent twice passes the payload-and-terms compare on
/// both copies, and the batch's single `messageHashToSign` covers both, so one attester signature
/// would authorize two releases of one burn. The burn evidence cannot even describe that — it
/// resolves ONE `burnTxId` from ONE note.
///
/// So the type says one. A genuine intent-SET batch would need its own evidence story and its own
/// Circle-facing decision, and it would land as a deliberate widening of this signature
/// which is exactly the review this rule wants, rather than a `.to_vec` nobody looked twice at.
///
/// The `burnTxId` is the evidence package's (whether Circle accepts a Miden tx id there is OPEN —
/// this builder carries whatever it is given and asserts nothing about that question), and
/// `use_circle_forwarding` is carried from the prepare request the intent was returned for, so the
/// submission cannot claim a forwarding posture the preparation never asked for.
///
/// # Errors
/// [`SchemaError`] from the wire type's own construction. Both of its rules are in fact unreachable
/// through this entry point — one intent is inside `1..=10`, and a [`QuorumBundle`] always carries
/// exactly the threshold — but the `Result` is kept rather than `expect`ed away: the wire type owns
/// those rules, and a builder that swore they could not fire would be asserting something about a
/// type it does not control.
pub fn build_withdraw_batch(
    burn_intent: BurnIntent,
    quorum: &QuorumBundle,
    burn_tx_id: &str,
    use_circle_forwarding: bool,
) -> Result<WithdrawBatch, SchemaError> {
    let signatures = quorum
        .signatures()
        .iter()
        .map(|signature| {
            HexBytes::new(signature.to_hex())
                .expect("a 65-byte signature renders to a valid 0x-hex string")
        })
        .collect();

    WithdrawBatch::new(
        vec![burn_intent],
        signatures,
        burn_tx_id.to_string(),
        use_circle_forwarding,
    )
}

/// Wraps `WithdrawBatch[]` in the top-level [`WithdrawRequest`] `{ batches: [..] }` for
/// `POST /v1/withdraw` — never a bare array or bare batch.
///
/// The per-batch invariants (`burnIntents` `1..=10`, `burnSignatures >= 2`) are the
/// [`WithdrawBatch`] constructor's, established when each batch is built; this wrapper enforces the
/// batch-list bound.
///
/// # Errors
/// [`SchemaError::BatchCountOutOfRange`] — fewer than 1 or more than 5 batches.
pub fn build_withdraw_request(batches: Vec<WithdrawBatch>) -> Result<WithdrawRequest, SchemaError> {
    WithdrawRequest::new(batches)
}

/// `0x` + lowercase hex of 32 bytes — the `^0x[a-fA-F0-9]{64}$` rendering every 32-byte Circle
/// field uses. A 32-byte array always satisfies the regex, so the newtype construction cannot fail.
fn hex32_of(bytes: &[u8; 32]) -> Hex32 {
    Hex32::new(format!("0x{}", hex::encode(bytes)))
        .expect("32 bytes render to a valid 0x-hex 32-byte string")
}

// ================================================================================================
// HTTP DRIVERS
// ================================================================================================

/// `POST /v1/prepare-withdrawal`: send the top-level `batches[]`
/// [`PrepareWithdrawalRequest`] and decode the top-level `batches[]` [`PrepareWithdrawalResponse`].
///
/// # Errors
/// * [`ListenerError::Http`] — a non-`200` status (`400`/`500` are handled on their status alone;
///   no error body is parsed, Circle's documentation).
/// * [`ListenerError::MalformedResponse`] — a `200` body that does not decode into the schema.
/// * [`ListenerError::Transport`] / [`ListenerError::ResponseTooLarge`] — no HTTP status / an
///   oversized body.
pub async fn prepare(
    circle: &CircleClient,
    req: &PrepareWithdrawalRequest,
) -> Result<PrepareWithdrawalResponse, ListenerError> {
    let request = circle.build_post(PATH_PREPARE_WITHDRAWAL, req)?;
    let response = circle.execute(request).await?;
    if response.status() != STATUS_PREPARE_OK {
        return Err(ListenerError::Http {
            status: response.status(),
        });
    }
    decode(response.body(), "prepare-withdrawal")
}

/// The `201` body's decode + cardinality rule, owned here (it is the withdraw-submission response
/// contract) and applied by [`submit_withdraw`](crate::submit::submit_withdraw)'s attempt.
///
/// # There is deliberately no `pub async fn withdraw` beside it
///
/// A raw public driver that took an [`AuthorizedWithdrawal`] and POSTed it, with no idempotency
/// ledger involved, would be a bypass even with real token discipline — [`WithdrawRequest`] is
/// `Clone` and [`authorize_submission`] is public, so a caller could mint two authorizations for
/// ONE burn and submit it twice, or submit once there and again through
/// [`submit_withdraw`](crate::submit::submit_withdraw) while the ledger still believed the burn
/// unseen. That is the double-release the idempotency ledger exists to prevent, reachable without
/// touching the ledger at all, and a doc comment calling `submit_withdraw` "the production entry
/// point" would not make it unrepresentable.
///
/// So there is no such driver, hidden or otherwise:
/// [`submit_withdraw`](crate::submit::submit_withdraw) — which CLAIMS every burn durably before it
/// builds a request — is the only code in the crate that can execute a `POST /v1/withdraw`, and
/// there is no public function that will do it without a claim.
///
/// # Errors
/// # Errors
/// * [`ListenerError::MalformedResponse`] — the body is not the ARRAY shape (an object would be a
///   forbidden mis-model), or an element does not decode. Refused, never coerced.
/// * [`ListenerError::WithdrawResponseCardinality`] — not exactly one status object per submitted
///   batch. A short array leaves a batch unaccounted for; a long one associates a batch with
///   the wrong status, or trusts an unrelated withdrawal.
pub(crate) fn decode_withdraw_created(
    body: &[u8],
    submitted: usize,
) -> Result<WithdrawSubmissionResponse, ListenerError> {
    // decodes into a Vec<WithdrawalStatus> — the ARRAY, one element per submitted batch. An object
    // body here fails to decode rather than being silently accepted.
    let statuses: WithdrawSubmissionResponse = decode(body, "withdraw")?;

    if statuses.len() != submitted {
        return Err(ListenerError::WithdrawResponseCardinality {
            submitted,
            returned: statuses.len(),
        });
    }

    Ok(statuses)
}

/// One `GET /v1/withdrawal/{withdrawalId}`: the current [`WithdrawalStatus`], decoded from
/// the same object `POST /v1/withdraw` returns.
///
/// The id is a validated [`Uuid`], not a raw string: the newtype's pattern (`^[0-9a-fA-F-]{36}$`,
/// the UUID shape) admits no `/`, `.`, `?` or `#`, so it cannot inject a dot-segment or query and
/// alter the requested route — the path is safe by construction of its argument. And the decoded
/// response is BOUND to the request: its `withdrawalId` must equal the requested id, or a status
/// for a DIFFERENT withdrawal would be reported as this one's.
///
/// # Errors
/// * [`ListenerError::WithdrawalNotFound`] — a `404` (its own exact variant).
/// * [`ListenerError::Http`] — any other non-`200` status.
/// * [`ListenerError::MalformedResponse`] — a `200` body that does not decode, INCLUDING a `status`
///   string outside the six-member enum (refused, never defaulted).
/// * [`ListenerError::WithdrawalIdMismatch`] — the `200` body's `withdrawalId` is not the requested id.
/// * [`ListenerError::Transport`] / [`ListenerError::ResponseTooLarge`].
pub async fn poll_status_once(
    circle: &CircleClient,
    withdrawal_id: &Uuid,
) -> Result<WithdrawalStatus, ListenerError> {
    let path = format!("{PATH_WITHDRAWAL}{}", withdrawal_id.as_str());
    let request = circle.build_get(&path)?;
    let response = circle.execute(request).await?;
    match response.status() {
        STATUS_WITHDRAWAL_OK => {
            let status: WithdrawalStatus = decode(response.body(), "withdrawal-status")?;
            // Bind the response to the request: a schema-valid status for another withdrawal must never
            // be reported as this id's outcome.
            if status.withdrawal_id() != withdrawal_id.as_str() {
                return Err(ListenerError::WithdrawalIdMismatch {
                    requested: withdrawal_id.as_str().to_string(),
                    returned: status.withdrawal_id().to_string(),
                });
            }
            Ok(status)
        }
        STATUS_WITHDRAWAL_NOT_FOUND => Err(ListenerError::WithdrawalNotFound {
            withdrawal_id: withdrawal_id.as_str().to_string(),
        }),
        other => Err(ListenerError::Http { status: other }),
    }
}

/// `GET /v1/withdrawal/{withdrawalId}` polled until it stops — the poll loop.
///
/// It stops on either a TERMINAL status — `finalized` (success) or `failed` (terminal, no retry) —
/// or the distinct RETRYABLE `expired` outcome. `expired` is NOT terminal (only
/// `finalized`/`failed` are): the withdrawal window closed and a NEW withdrawal must be
/// resubmitted, so the caller must read `.status.is_retryable` and NOT conflate `expired` with a
/// completed withdrawal. Between polls on a not-yet-settled status it waits the client's
/// [`PollPolicy`](crate::circle::client::PollPolicy) interval, and it is bounded by the policy's
/// attempt ceiling.
///
/// # Errors
/// * everything [`poll_status_once`] can return;
/// * [`ListenerError::PollExhausted`] — the attempt ceiling was reached without the status settling
///   to a terminal (`finalized`/`failed`) or retryable (`expired`) outcome.
pub async fn poll_status(
    circle: &CircleClient,
    withdrawal_id: &Uuid,
) -> Result<WithdrawalStatus, ListenerError> {
    let policy = circle.poll_policy();
    let max_attempts = policy.max_attempts();
    for attempt in 1..=max_attempts {
        // A `404`, an unknown status, an id mismatch, or any other hard error is surfaced immediately
        // (via `?`) — the loop never swallows it as "not yet terminal", which would poll forever on a
        // bad answer.
        let status = poll_status_once(circle, withdrawal_id).await?;
        let kind = status.status();

        // `expired` is a RETRYABLE outcome — the withdrawal window closed and a NEW withdrawal must be
        // submitted. It STOPS the poll (this id cannot progress to `finalized`), but it is
        // handled through its own retryable branch rather than lumped with the `finalized`/`failed`
        // terminals: the caller reads `is_retryable` and resubmits, so `expired` is never conflated
        // with a completed withdrawal.
        if kind.is_retryable() {
            return Ok(status);
        }
        // `finalized` (success) or `failed` (terminal, no retry) — polling is done.
        if matches!(
            kind,
            WithdrawalStatusKind::Finalized | WithdrawalStatusKind::Failed
        ) {
            return Ok(status);
        }
        if attempt < max_attempts {
            tokio::time::sleep(policy.interval()).await;
        }
    }
    Err(ListenerError::PollExhausted {
        after: max_attempts,
    })
}

/// Decodes a 2xx body into `T`, mapping a schema violation (including a value outside a closed
/// enum) to [`ListenerError::MalformedResponse`] with its serde cause preserved. A malformed Circle
/// response is refused, never coerced.
pub(crate) fn decode<T: DeserializeOwned>(
    body: &[u8],
    context: &'static str,
) -> Result<T, ListenerError> {
    serde_json::from_slice(body).map_err(|source| ListenerError::MalformedResponse {
        context,
        source: Cause::new(source),
    })
}

// ================================================================================================
// PRE-SUBMIT SIGNER-ALLOWLIST GATE (fund-safety)
// ================================================================================================

/// Proof that a [`WithdrawRequest`] cleared the **pre-submit signer-allowlist gate** — every
/// `burnSignatures` signer in every batch recovered, over the batch's B5-validated
/// `messageHashToSign` digest, to a configured registered attester
/// ([`AttesterAllowlist`](crate::attester::AttesterAllowlist)).
///
/// Its ONLY constructor is [`authorize_submission`]'s full-pass path, and
/// [`submit_withdraw`](crate::submit::submit_withdraw) consumes it BY VALUE, so "submit a
/// withdrawal whose signers are not all registered attesters" is not a state this API can represent
/// — the same structural-gate discipline
/// [`ValidatedWithdrawal`] uses to reach signing.
///
/// It is deliberately **not `Clone`**: an authorization is minted from a specific validation and a
/// specific config allowlist, and is spent on exactly one submission, so it cannot be duplicated
/// and replayed.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedWithdrawal {
    request: WithdrawRequest,
}

impl AuthorizedWithdrawal {
    /// The gated request, ready to submit.
    pub fn request(&self) -> &WithdrawRequest {
        &self.request
    }

    /// Consumes the token, yielding the gated request.
    pub fn into_request(self) -> WithdrawRequest {
        self.request
    }
}

/// The **pre-submit signer-allowlist gate**: authorize a [`WithdrawRequest`] for submission iff
/// every `burnSignatures` signer, recovered over its batch's B5-validated `messageHashToSign`
/// digest, is a configured registered attester. THE fund-safety defense-in-depth that must run
/// before any `POST /v1/withdraw`.
///
/// The inputs are the two things this decision must be bound to, so a proof cannot be minted from
/// ad-hoc values:
/// * `validated` is the [`ValidatedWithdrawal`] the pre-signing gate
///   ([`validate_returned`](crate::validate::validate_returned)) produced — its
///   [`digests`](crate::validate::ValidatedWithdrawal::digests) are the only source of the
///   per-batch `messageHashToSign` values, so the recovery is over Circle's actual returned
///   digests, not a raw slice a caller could fabricate;
/// * `config` supplies the allowlist via [`ListenerConfig::attester_allowlist`] — the registered
///   attesters as CONFIGURED, not an arbitrary set.
///
/// Each signature in `request.batches[i]` is recovered over `validated.digests[i]` (the same
/// `ECDSA.recover` Circle runs on the source chain) and the recovered address is required to be in
/// the configured allowlist.
///
/// # Errors
/// * [`SubmitGateError::NoAttestersConfigured`] — the config allowlist is empty: fail closed rather
///   than authorize an unbounded signer set.
/// * [`SubmitGateError::BatchDigestCountMismatch`] — the request's batch count and the validated
///   digest count differ.
/// * [`SubmitGateError::BadSignatureHex`] / [`SubmitGateError::MalformedSignature`] — a signature
///   that is not decodable / not 65 bytes.
/// * [`SubmitGateError::SignerUnrecoverable`] — a signature that recovers to no signer.
/// * [`SubmitGateError::SignerNotAllowlisted`] — a signature whose recovered signer is not a
///   registered attester (the core refusal).
///
/// On ANY error no [`AuthorizedWithdrawal`] is produced, so
/// [`submit_withdraw`](crate::submit::submit_withdraw) cannot run: ZERO `/v1/withdraw` calls.
pub fn authorize_submission(
    request: WithdrawRequest,
    validated: &ValidatedWithdrawal,
    config: &ListenerConfig,
) -> Result<AuthorizedWithdrawal, SubmitGateError> {
    let allowlist = config.attester_allowlist();
    // Fail closed: an empty allowlist would authorize an unbounded signer set.
    if allowlist.is_empty() {
        return Err(SubmitGateError::NoAttestersConfigured);
    }

    let batches = request.batches();
    let digests = validated.digests();
    if batches.len() != digests.len() {
        return Err(SubmitGateError::BatchDigestCountMismatch {
            batches: batches.len(),
            digests: digests.len(),
        });
    }

    for (batch, (batch_data, digest)) in batches.iter().zip(digests).enumerate() {
        for (at, signature_hex) in batch_data.burn_signatures().iter().enumerate() {
            let bytes = decode_signature_hex(signature_hex.as_str())
                .ok_or(SubmitGateError::BadSignatureHex { batch, at })?;
            let signature = Signature65::from_bytes(&bytes).map_err(|_| {
                SubmitGateError::MalformedSignature {
                    batch,
                    at,
                    len: bytes.len(),
                }
            })?;
            // Recover the signer over the batch's own digest — the exact `ECDSA.recover` Circle runs
            // on the source chain — and require it to be a REGISTERED attester.
            let signer = recover_address(digest, &signature)
                .ok_or(SubmitGateError::SignerUnrecoverable { batch, at })?;
            if !allowlist.contains(&signer) {
                return Err(SubmitGateError::SignerNotAllowlisted { batch, at, signer });
            }
        }
    }

    Ok(AuthorizedWithdrawal { request })
}

/// Decodes a `0x`-hex signature body to raw bytes, or `None` if it is not decodable hex (e.g.
/// odd-length). The wire newtype permits `^0x[a-fA-F0-9]*$`, which includes odd digit counts.
fn decode_signature_hex(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).ok()
}
