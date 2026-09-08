//! The `ListenerError` taxonomy, grouped by which part of the flow refused: configuration (base
//! URL, auth-header injection, transport bounds), the Circle wire (HTTP status, schema decode, the
//! `409` conflict), the Miden reads (tag scan, note retrieval, evidence), validation (the discovery
//! and pre-signing checklists, and the do-not-sign abort), and the signature quorum.
//!
//! The enum is `#[non_exhaustive]`, so a new failure mode can be added without breaking callers.
//!
//! Errors are hand-rolled — this repository does not depend on `thiserror` — with lowercase,
//! unpunctuated messages per the Rust convention, and every variant preserves its underlying cause
//! through [`Error::source`](core::error::Error) rather than flattening it to a string.

use core::fmt;
use std::sync::Arc;

use xusdc_encoding::xreserve::encoding::EncodingError;

use crate::attester::Address;

/// A preserved lower-level cause whose own type is neither `Clone` nor `PartialEq` (a
/// `reqwest::Error`, a header/URL parse error). Wrapping it keeps [`ListenerError`]'s `Clone` +
/// `PartialEq` contract intact while still handing the ORIGINAL typed error to
/// [`Error::source`](core::error::Error) — so a caller can `downcast_ref` it and ask the concrete
/// question (`is_timeout`, say). Flattening it to a `String` would discard exactly what an
/// operator needs.
///
/// The deposit relayer has the same idiom, deliberately duplicated rather than shared: it is an
/// error-plumbing convention, not a wire format. Only the formats and codecs the two services must
/// agree on are single-owned (in `xusdc-encoding`); coupling two sibling services to share twelve
/// lines of `Arc<dyn Error>` would buy no protection.
#[derive(Debug, Clone)]
pub struct Cause(Arc<dyn core::error::Error + Send + Sync + 'static>);

impl Cause {
    /// Preserves `error` as an error source.
    pub fn new(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }

    /// The preserved cause, as a `dyn Error` — `downcast_ref` recovers its concrete type.
    pub fn as_error(&self) -> &(dyn core::error::Error + 'static) {
        &*self.0
    }
}

impl PartialEq for Cause {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0.to_string() == other.0.to_string()
    }
}

impl Eq for Cause {}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Everything the listener/attester can refuse to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenerError {
    /// The configured Circle base URL is not a usable `http`/`https` URL. Refused when the config
    /// is built, not on the first request.
    BadBaseUrl { url: String, source: Cause },

    /// An out-of-band API key is configured against a base URL that cannot protect it. A credential
    /// sent in the clear is a credential disclosed — and with no documented auth scheme the key
    /// could ride under any header name, so no transport-level convention will save it.
    InsecureAuthTransport { base_url: String },

    /// The configured auth header is not a legal header: an illegal NAME, or a value carrying a
    /// control character (a header-injection attempt). Rejected at construction, so a misconfigured
    /// key can never silently degrade into an unauthenticated request stream.
    ///
    /// The credential VALUE never appears in this error — only the header name.
    BadAuthHeader { name: String, source: Cause },

    /// An out-of-band API key is configured with no header name to send it under.
    ///
    /// The OpenAPI documents NO auth scheme, so there is no header this crate
    /// could pick that would not be an invention (Circle documents "do NOT invent an auth header").
    /// A key with nowhere documented to go is therefore a configuration error, not a prompt to
    /// guess `Authorization`. When Circle answers, the operator writes the answer into the config.
    AuthHeaderNameRequired,

    /// A configured faucet account id that is not an account id at all.
    BadFaucetId { value: String, source: Cause },

    /// A request that produced NO HTTP status — a connection failure, a timeout, a body that could
    /// not be read.
    ///
    /// **This is AMBIGUOUS, not transient, and the difference decides money.** No status means no
    /// evidence either way: on a `POST /v1/withdraw` the withdrawal may already have been created
    /// and be releasing, with only the response lost. So the submission path does NOT retry it
    /// ([`is_retryable`](crate::circle::retry::is_retryable) answers `false`) — it surfaces the
    /// failure and leaves the burn reconciliation-required. Reading this variant as "just try
    /// again" is the blind resubmission the `409` rule exists to prevent.
    Transport(Cause),

    /// The response exceeded the configured body ceiling. NOT transient — a peer that returns an
    /// oversized body will do it again, and the bytes past the ceiling are never buffered.
    ResponseTooLarge { limit: usize, actual: usize },

    /// A Circle response carried a non-success HTTP status the driver refuses. The OpenAPI
    /// documents status codes only — no error-body schema — so for the RAW drivers the status ALONE
    /// decides and the body is never parsed: every non-2xx that is not the poll's own `404` is this
    /// generic refusal.
    ///
    /// [`submit_withdraw`](crate::submit::submit_withdraw) is the one exception, and only for the
    /// `409`, whose body it MUST read: the conflict is the sole statement of which withdrawal the
    /// duplicate hit. Everything else it sees still lands here — an exhausted `5xx` budget, a
    /// deterministic `400`, an undocumented status — and none of them is ever a withdrawal.
    Http { status: u16 },

    /// `GET /v1/withdrawal/{withdrawalId}` answered `404` — no withdrawal under that id. It has its
    /// OWN variant, distinct from [`Self::Http`], because a poll `404` is a meaningful terminal
    /// answer ("unknown id"), not an opaque transport-level refusal.
    WithdrawalNotFound { withdrawal_id: String },

    /// A 2xx Circle body did not decode into the expected schema type — a malformed response, or a
    /// value outside a closed enum (a `status` string the six-member enum does not contain).
    /// Refused, never coerced or defaulted (Circle documents "malformed Circle response → reject,
    /// not signed"). The serde error is the preserved source. `context` names which decode failed
    /// (`prepare-withdrawal`, `withdraw`, `withdrawal-status`).
    MalformedResponse {
        context: &'static str,
        source: Cause,
    },

    /// A status poll ran to its attempt ceiling without the status settling — neither a TERMINAL
    /// completion (`finalized`/`failed`) nor the RETRYABLE `expired` outcome (`expired` is not
    /// terminal). NOT a settled answer — polling stopped because the bound was hit, so the caller
    /// must not read it as any final state.
    PollExhausted { after: u32 },

    /// A `POST /v1/withdraw` `201` array did not carry exactly one status object per submitted
    /// batch (Circle documents the response is "one element per submitted batch"). A shorter array
    /// leaves a batch's outcome unaccounted for; a longer one associates a batch with the wrong
    /// status (or trusts an unrelated withdrawal). Refused rather than mis-associated.
    WithdrawResponseCardinality { submitted: usize, returned: usize },

    /// A `GET /v1/withdrawal/{id}` `200` decoded to a [`WithdrawalStatus`] whose `withdrawalId` is
    /// NOT the id that was requested. A schema-valid status for a DIFFERENT withdrawal must never
    /// be reported as the requested one's outcome — that would attribute another withdrawal's
    /// `finalized`/`failed` state to this id. The response is bound to the request; a mismatch is
    /// refused.
    ///
    /// [`WithdrawalStatus`]: crate::circle::schema::WithdrawalStatus
    WithdrawalIdMismatch { requested: String, returned: String },
}

impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadBaseUrl { url, .. } => {
                write!(f, "circle base url `{url}` is not a valid http(s) url")
            }
            Self::InsecureAuthTransport { base_url } => write!(
                f,
                "an out-of-band api key is configured, but the circle base url `{base_url}` is not \
                 https — the credential would be sent in the clear"
            ),
            Self::BadAuthHeader { name, .. } => {
                write!(f, "auth header `{name}` is not a legal http header")
            }
            Self::AuthHeaderNameRequired => write!(
                f,
                "an out-of-band api key is configured but no auth header name is set, and no scheme \
                 is documented to fall back on (q-api-auth is open)"
            ),
            Self::BadFaucetId { value, .. } => {
                write!(f, "faucet id `{value}` is not a valid account id")
            }
            Self::Transport(cause) => write!(f, "circle request failed: {cause}"),
            Self::ResponseTooLarge { limit, actual } => write!(
                f,
                "circle response of {actual} bytes exceeds the {limit}-byte ceiling"
            ),
            Self::Http { status } => {
                write!(f, "circle answered with http status {status}")
            }
            Self::WithdrawalNotFound { withdrawal_id } => {
                write!(f, "no withdrawal found for id `{withdrawal_id}`")
            }
            Self::MalformedResponse { context, source } => {
                write!(f, "circle {context} response did not decode: {source}")
            }
            Self::PollExhausted { after } => write!(
                f,
                "status poll reached no terminal status after {after} attempts"
            ),
            Self::WithdrawResponseCardinality {
                submitted,
                returned,
            } => write!(
                f,
                "circle withdraw returned {returned} status objects for {submitted} submitted batches \
                 (expected one per batch)"
            ),
            Self::WithdrawalIdMismatch {
                requested,
                returned,
            } => write!(
                f,
                "circle returned a withdrawal status for id `{returned}`, not the requested `{requested}`"
            ),
        }
    }
}

impl core::error::Error for ListenerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BadBaseUrl { source, .. }
            | Self::BadAuthHeader { source, .. }
            | Self::BadFaucetId { source, .. }
            | Self::Transport(source) => Some(source.as_error()),
            Self::MalformedResponse { source, .. } => Some(source.as_error()),
            Self::InsecureAuthTransport { .. }
            | Self::AuthHeaderNameRequired
            | Self::ResponseTooLarge { .. }
            | Self::Http { .. }
            | Self::WithdrawalNotFound { .. }
            | Self::PollExhausted { .. }
            | Self::WithdrawResponseCardinality { .. }
            | Self::WithdrawalIdMismatch { .. } => None,
        }
    }
}

/// Everything [`note_decode`](crate::note_decode) can refuse to decode — the `DecodeError` the
/// documented policy names. Kept a type of its own rather than a [`ListenerError`] family: a decode
/// failure is a statement about ONE note's bytes, and the caller's response to it (skip the note,
/// alert) is not the response to a Circle transport failure.
///
/// Every variant is a REFUSAL. There is no lossy/partial success here by construction: a burn note
/// whose payload or sender does not decode yields no [`BurnPayload`](crate::types::BurnPayload) and
/// no depositor — never a zero-filled or otherwise fabricated one, which would hand Circle a
/// `remoteDepositor` no Miden account ever authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The withdrawal-payload attachment felts are not a well-formed burn payload — a felt count
    /// other than `BURN_NOTE_ITEMS_FELTS = 18`, an out-of-range `amount`/`destDomain`, or a non-`u32`
    /// bytes32 limb.
    ///
    /// The shared encoding crate's codec is the sole judge of that, and its verdict is carried
    /// here UNFLATTENED: the exact [`EncodingError`] it returned is the preserved source
    /// (`preserve-error-source`), so a caller that wants the codec's own answer can ask for it
    /// instead of parsing a string.
    BurnItemsMalformed { source: EncodingError },

    /// The discovered note carries no metadata at all, so there is no `metadata.sender` to read
    /// what a PRIVATE or erased note looks like from `GetNotesById` (`details = None`, where the
    /// design requires a Public burn note). Such a note is unacceptable for Circle observability,
    /// and it is refused rather than defaulted.
    SenderAbsent,

    /// The reported `metadata.sender` is the zero felt pair. No account has the zero id; a node (or
    /// a bug) reporting one is reporting nothing, and the ONE thing that must not happen next is
    /// its silent promotion into a zero `remoteDepositor` (`metadata.sender` is the exposed
    /// depositor by design — a zero there would be a burn attributed to nobody).
    SenderZero,

    /// The reported `metadata.sender` felts are not a canonical
    /// [`AccountId`](miden_protocol::account::AccountId) (an unknown id version, an out-of-field
    /// felt, a violated id constraint). The underlying `AccountIdError` is preserved as the source.
    SenderMalformed { source: Cause },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BurnItemsMalformed { source } => {
                write!(f, "burn note storage items are malformed: {source}")
            }
            Self::SenderAbsent => write!(
                f,
                "the discovered burn note carries no metadata, so it has no sender to read"
            ),
            Self::SenderZero => write!(f, "the burn note sender is the zero account id"),
            Self::SenderMalformed { source } => {
                write!(
                    f,
                    "the burn note sender is not a valid account id: {source}"
                )
            }
        }
    }
}

impl core::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BurnItemsMalformed { source } => Some(source),
            Self::SenderMalformed { source } => Some(source.as_error()),
            Self::SenderAbsent | Self::SenderZero => None,
        }
    }
}

/// Why [`attester::sign`](crate::attester::sign) refused to produce a signature.
///
/// `sign` consumes Circle's returned `messageHashToSign` as an OPAQUE 32-byte digest (its exact
/// derivation is still OPEN with Circle): it never re-derives the digest locally (no EIP-712, no
/// personal-sign, no Poseidon2), so the only thing it can reject about the input is its length. A
/// non-32-byte digest is a caller bug — a truncated hash, a hex string passed where raw bytes were
/// meant — and signing it anyway would put an attester signature over the wrong 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The digest handed to `sign` is not exactly 32 bytes. The signing input is Circle's returned
    /// digest, treated opaquely — `sign` does not hash, pad, or truncate it into shape.
    DigestLength { actual: usize },

    /// `k256` refused to produce a recoverable signature over the (valid, 32-byte) digest. Not
    /// reachable with a well-formed secret key and a 32-byte prehash; carried so a curve-level
    /// failure surfaces as a typed error with its `k256` cause preserved, never a `panic`.
    Ecdsa { source: Cause },

    /// The signature's recovery id is **x-reduced** (`2`/`3`) and so has no Ethereum `v`
    /// representation: OpenZeppelin-style `ECDSA.recover` on Circle's source chain accepts only `v`
    /// `27`/`28`. Rather than emit a `v = 29`/`30` signature the verifier would reject at the
    /// fund-release boundary, `sign` refuses. An x-reduced recovery id requires the signature's `r`
    /// to have wrapped the curve order, which happens with probability ≈ `2^-128` for a random
    /// key/digest — so this is a defensive refusal, not a path real inputs take.
    UnrepresentableRecoveryId { recovery_id: u8 },
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DigestLength { actual } => write!(
                f,
                "message hash to sign must be exactly 32 bytes, got {actual}"
            ),
            Self::Ecdsa { source } => write!(f, "ecdsa signing failed: {source}"),
            Self::UnrepresentableRecoveryId { recovery_id } => write!(
                f,
                "recovery id {recovery_id} is x-reduced and has no evm v (27/28) representation"
            ),
        }
    }
}

impl core::error::Error for SignError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ecdsa { source } => Some(source.as_error()),
            Self::DigestLength { .. } | Self::UnrepresentableRecoveryId { .. } => None,
        }
    }
}

/// Why a [`Signature65`](crate::attester::Signature65) could not be built from raw bytes.
///
/// The Circle wire form is fixed: secp256k1 ECDSA, 65 bytes `r‖s‖v` (`CIRCLE-DATA-SCHEMAS.md:184`).
/// A DER blob, a 64-byte `r‖s` with the recovery id dropped, or any other length is not that form,
/// and is refused at construction so a mis-shaped signature can never reach
/// [`assemble_quorum`](crate::attester::assemble_quorum) or the `/v1/withdraw` wire.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    /// The bytes are not exactly 65 (`r‖s‖v`). A 64-byte `r‖s`, a DER encoding, or a truncated
    /// signature all land here.
    Length { actual: usize },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "a burn signature must be exactly 65 bytes (r‖s‖v), got {actual}"
            ),
        }
    }
}

impl core::error::Error for SignatureError {}

/// Why [`assemble_quorum`](crate::attester::assemble_quorum) refused to assemble a `burnSignatures`
/// bundle.
///
/// The bundle Circle verifies on the source chain must be **exactly-threshold count, every
/// signature verifying to its claimed signer, ascending signer-address order, no duplicates**
/// (`MIN_SIGNATURE_THRESHOLD = 2`; `CIRCLE-DATA-SCHEMAS.md:196`; the recover-then-authorize step at
/// `:46`). This assembler enforces that contract BEFORE anything is submitted, so a set Circle
/// would reject — or worse, a single-key set that must NEVER be submitted — fails here as a typed
/// `Err` rather than on Circle's wire. Every rejection is exact: a duplicate signer is refused,
/// NEVER silently de-duplicated (a silent dedupe could shrink a 2-signer set to one and submit a
/// single-key quorum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuorumError {
    /// Fewer than `MIN_SIGNATURE_THRESHOLD` signatures. A single-key set is a non-gating local
    /// primitive and is NEVER submitted to Circle. Foreclosing the "threshold treated as ≥1"
    /// bug is the whole point of this variant.
    BelowThreshold { have: usize, need: usize },

    /// More than `MIN_SIGNATURE_THRESHOLD` signatures. Circle's source-chain verifier is
    /// **exactly-threshold** (`Attestable.sol:75,333-381`; `CIRCLE-DATA-SCHEMAS.md:196`), so an
    /// over-threshold bundle Circle would reject is refused here rather than at the fund-release
    /// boundary. Selecting an authorized exactly-threshold subset from a larger set of signatures
    /// is a separate, owner-specified concern; this assembler does not silently truncate.
    AboveThreshold { have: usize, need: usize },

    /// A signature does not verify against its CLAIMED signer address: `ECDSA.recover(digest, sig)`
    /// (the same recovery Circle performs) either fails outright — a `v` outside `27`/`28`, a
    /// malformed `r`/`s`, a digest the signature does not cover — or recovers a DIFFERENT address
    /// than the one it was paired with. Either way the signature is excluded from the quorum
    /// (`TEST-AND-VERIFICATION-HARNESS.md:157`); `at` is its index in the input.
    SignatureDoesNotVerify { at: usize },

    /// The same signer address appears more than once. Refused, not de-duplicated — Circle rejects
    /// a duplicate, and a silent dedupe here could collapse the count below threshold unnoticed.
    DuplicateSigner { address: Address },

    /// The signer addresses are not in strictly ascending order at the given index (`sigs[at]`'s
    /// address is not greater than `sigs[at - 1]`'s). Ordering is by the 20-byte signer ADDRESS
    /// (`ECDSA.recover` → address), never by pubkey or signature bytes.
    NotAscending { at: usize },
}

impl fmt::Display for QuorumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowThreshold { have, need } => write!(
                f,
                "a burn-signature quorum needs exactly {need} signatures, got {have}"
            ),
            Self::AboveThreshold { have, need } => write!(
                f,
                "a burn-signature quorum takes exactly {need} signatures, got {have}"
            ),
            Self::SignatureDoesNotVerify { at } => write!(
                f,
                "the signature at index {at} does not verify against its claimed signer address"
            ),
            Self::DuplicateSigner { address } => {
                write!(
                    f,
                    "signer address {address} appears more than once in the quorum"
                )
            }
            Self::NotAscending { at } => write!(
                f,
                "signer addresses are not in ascending order at index {at}"
            ),
        }
    }
}

impl core::error::Error for QuorumError {}

/// Why [`validate_discovery`](crate::validate::validate_discovery) refused a discovered note — the
/// ordered checklist that runs before Circle is ever asked to prepare intents.
///
/// The order is load-bearing and reflected in the variants' priority: the tag is matched FIRST (a
/// wrong-tag note is not this listener's note at all), THEN observability (a private note has
/// nothing to read), and only then is the payload decoded. Every case is a REFUSAL — no partial or
/// defaulted burn ever leaves this gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryReject {
    /// The note's tag is not the configured burn tag. Matched by **exact full-32-bit equality**,
    /// never a prefix (`SyncNotes` does not prefix-scan; the 16-bit prefix belongs to
    /// `SyncNullifiers` — an exact match, never a prefix). A note sharing only the high 16 bits is
    /// a DIFFERENT note.
    TagMismatch { expected: u32, actual: u32 },

    /// `GetNotesById` returned `details = None` — a PRIVATE or erased note, unobservable to
    /// Circle. A withdrawal must be backed by a `NoteType::Public` burn;
    /// a note Circle cannot see is refused rather than attested to.
    PrivateNoteUnobservable,

    /// The note came back public and tagged, but its withdrawal-payload attachment or its
    /// `metadata.sender` did not decode — the shared encoding crate's codec's / sender read's
    /// verdict, carried through UNFLATTENED as the preserved [`DecodeError`]
    /// (`preserve-error-source`).
    Decode(DecodeError),
}

impl fmt::Display for DiscoveryReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TagMismatch { expected, actual } => write!(
                f,
                "note tag {actual:#010x} is not the configured burn tag {expected:#010x}"
            ),
            Self::PrivateNoteUnobservable => write!(
                f,
                "the discovered burn note is private (details = none) and unobservable for circle"
            ),
            Self::Decode(source) => write!(f, "the discovered burn note did not decode: {source}"),
        }
    }
}

impl core::error::Error for DiscoveryReject {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::TagMismatch { .. } | Self::PrivateNoteUnobservable => None,
        }
    }
}

/// Why the pre-signing gate `validate_returned` refused
/// Circle's returned data — the field-by-field mismatch that MUST abort before any attester signs
/// (validation gates signing).
///
/// Every variant carries the batch index it fired on, so a mismatch in a LATER batch (not just
/// `batches[0]`) is named precisely. An `Err` here is a hard "DO NOT SIGN": control never reaches
/// the signer, and — because `validate_returned` mints the proof-of-validation token ONLY on a
/// full match — no signature over mismatching data can be produced structurally, not by convention.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationMismatch {
    /// The response carried no batches at all — there is nothing to validate or sign, and an empty
    /// prepare response is not a match of any withdrawal. Refused rather than signed vacuously.
    NoBatches,

    /// A batch carried an EMPTY `burnIntents` array — no intent to compare before signing.
    EmptyBurnIntents { batch: usize },

    /// A returned `burnIntents[].spec.value` (the amount, in the smallest token unit) does not
    /// equal the burn-note payload's `amount`.
    Amount {
        batch: usize,
        expected: u64,
        returned: String,
    },

    /// A returned `destinationDomain` does not equal the burn-note payload's `destDomain`.
    DestinationDomain {
        batch: usize,
        expected: u32,
        returned: u32,
    },

    /// A returned `destinationRecipient` does not equal the burn-note payload's `destRecipient`.
    DestinationRecipient {
        batch: usize,
        expected: String,
        returned: String,
    },

    /// A returned `burnIntents[].maxFee` exceeds the configured ceiling or the burn amount.
    MaxFee {
        batch: usize,
        ceiling: u64,
        amount: u64,
        returned: String,
    },

    /// A returned `destinationCaller` is not the zero caller the neutral request implies.
    DestinationCaller {
        batch: usize,
        expected: String,
        returned: String,
    },

    /// A returned `hookData` field diverges from the expected request terms.
    HookData {
        batch: usize,
        field: &'static str,
        expected: String,
        returned: String,
    },

    /// The batch's `messageHashToSign` is absent/empty — there is no digest to sign. (A TRULY
    /// missing field is refused earlier, at schema deserialization; this is the present-but-empty
    /// case.)
    MissingMessageHash { batch: usize },

    /// The batch's `messageHashToSign` is present but not a 32-byte digest (bad hex, or the wrong
    /// length). `attester::sign` requires exactly 32 bytes, so a non-signable digest is refused
    /// BEFORE signing rather than handed to the signer — a reject, not a sign.
    MalformedMessageHash { batch: usize, len: usize },
}

impl fmt::Display for ValidationMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBatches => write!(f, "circle returned no batches to validate"),
            Self::EmptyBurnIntents { batch } => {
                write!(f, "batch {batch}: contains no burn intents to validate")
            }
            Self::Amount {
                batch,
                expected,
                returned,
            } => write!(
                f,
                "batch {batch}: returned amount `{returned}` does not match the burn payload amount {expected}"
            ),
            Self::DestinationDomain {
                batch,
                expected,
                returned,
            } => write!(
                f,
                "batch {batch}: returned destination domain {returned} does not match the burn payload domain {expected}"
            ),
            Self::DestinationRecipient {
                batch,
                expected,
                returned,
            } => write!(
                f,
                "batch {batch}: returned destination recipient `{returned}` does not match the burn payload recipient `{expected}`"
            ),
            Self::MaxFee {
                batch,
                ceiling,
                amount,
                returned,
            } => write!(
                f,
                "batch {batch}: returned max fee `{returned}` exceeds the configured withdrawal fee ceiling {ceiling} or burn amount {amount}"
            ),
            Self::DestinationCaller {
                batch,
                expected,
                returned,
            } => write!(
                f,
                "batch {batch}: returned destination caller `{returned}` does not match the neutral caller `{expected}`"
            ),
            Self::HookData {
                batch,
                field,
                expected,
                returned,
            } => write!(
                f,
                "batch {batch}: returned hookData.{field} `{returned}` does not match `{expected}`"
            ),
            Self::MissingMessageHash { batch } => {
                write!(f, "batch {batch}: response is missing a message hash to sign")
            }
            Self::MalformedMessageHash { batch, len } => write!(
                f,
                "batch {batch}: message hash to sign must be exactly 32 bytes, got {len}"
            ),
        }
    }
}

impl core::error::Error for ValidationMismatch {}

/// Why the **pre-submit signer-allowlist gate**
/// ([`authorize_submission`](crate::withdrawal_api::authorize_submission)) refused to authorize a
/// `POST /v1/withdraw` — the off-chain fund-safety check that runs before any submission.
///
/// # The invariant this gate enforces
///
/// Circle's source-chain verifier already does `ECDSA.recover(digest, sig) → addr` and
/// `require(attesters[addr])` — but that is the LAST line of defense, at the fund-release boundary.
/// This gate re-does the recovery off-chain against the SAME `messageHashToSign` digests and
/// requires every recovered signer to be a **configured, registered attester**
/// ([`AttesterAllowlist`](crate::attester::AttesterAllowlist)). A signature from a key that is not
/// a registered attester — or a set with no configured allowlist at all — is refused here, and no
/// [`AuthorizedWithdrawal`](crate::withdrawal_api::AuthorizedWithdrawal) is minted, so `withdraw`
/// cannot be reached: **zero `/v1/withdraw` calls** on any rejection, structurally.
///
/// [`assemble_quorum`](crate::attester::assemble_quorum) already proves each signature recovers to
/// its CLAIMED signer; this gate is the complementary check that the claimed/recovered signer is
/// one the operator actually registered. The two together close the gap the quorum assembler leaves
/// open.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubmitGateError {
    /// No attester is configured in the allowlist. **Fail-closed**: an empty allowlist would
    /// authorize an UNBOUNDED signer set, so a submission is refused rather than sent, and the
    /// missing configuration is surfaced — never silently treated as "allow all".
    NoAttestersConfigured,

    /// The per-batch `messageHashToSign` digests do not line up 1:1 with the request's batches, so
    /// a batch's signatures cannot be checked against the digest they were produced over. Refused
    /// rather than guessing an alignment.
    BatchDigestCountMismatch { batches: usize, digests: usize },

    /// A `burnSignatures[at]` in `batches[batch]` is not a decodable byte string (odd-length hex).
    /// The wire newtype permits `^0x[a-fA-F0-9]*$` including an odd digit count; a signer cannot be
    /// recovered from bytes that do not decode, so it is refused.
    BadSignatureHex { batch: usize, at: usize },

    /// A `burnSignatures[at]` in `batches[batch]` is not exactly 65 bytes (`r‖s‖v`) — no signer can
    /// be recovered from it.
    MalformedSignature { batch: usize, at: usize, len: usize },

    /// A `burnSignatures[at]` in `batches[batch]` does not recover to ANY signer over the batch's
    /// digest — a `v` outside `27`/`28`, an `r`/`s` that is not a valid signature, or a digest the
    /// signature does not cover. It cannot be attributed to a registered attester, so it is
    /// refused.
    SignerUnrecoverable { batch: usize, at: usize },

    /// A `burnSignatures[at]` in `batches[batch]` recovered to `signer`, which is NOT in the
    /// configured attester allowlist. This is the core fund-safety refusal: a signature from an
    /// unregistered key must never ride a submission.
    SignerNotAllowlisted {
        batch: usize,
        at: usize,
        signer: Address,
    },
}

impl fmt::Display for SubmitGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAttestersConfigured => write!(
                f,
                "no attester is configured in the allowlist; refusing to submit with an unbounded \
                 signer set (fail-closed)"
            ),
            Self::BatchDigestCountMismatch { batches, digests } => write!(
                f,
                "the withdraw request has {batches} batches but {digests} per-batch digests were \
                 supplied; they must line up 1:1"
            ),
            Self::BadSignatureHex { batch, at } => write!(
                f,
                "batch {batch}: burn signature {at} is not decodable hex"
            ),
            Self::MalformedSignature { batch, at, len } => write!(
                f,
                "batch {batch}: burn signature {at} is {len} bytes, not the 65-byte r‖s‖v form"
            ),
            Self::SignerUnrecoverable { batch, at } => write!(
                f,
                "batch {batch}: burn signature {at} does not recover to any signer over the batch digest"
            ),
            Self::SignerNotAllowlisted { batch, at, signer } => write!(
                f,
                "batch {batch}: burn signature {at} recovered signer {signer}, which is not a \
                 configured attester"
            ),
        }
    }
}

impl core::error::Error for SubmitGateError {}
