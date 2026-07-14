//! The `RelayerError` taxonomy — STARTED in the scaffold slice with the DepositIntent
//! structural-reject family (the off-chain mirror of D5a; INV-DEPOSITINTENT-PARSE) plus the
//! NoteStorage felt-count guard, EXTENDED with the attestation-envelope family (DC-2,
//! INV-DEPOSIT-ATTESTATION-RAW-KECCAK): wire-hex decode, `messageHash` shape + raw-keccak binding,
//! and attestation shape — and EXTENDED here with the Circle TRANSPORT family: HTTP status, schema
//! decode, transport failure, and the client-side request-shape pre-conditions (`txHash` /
//! `depositMessageHash` patterns, `pageSize` bounds, rate/retry/auth/base-URL configuration). The
//! Miden-facing variants (note build, submit) land in a later slice. The enum is `#[non_exhaustive]`
//! so those additions are not breaking changes.
//!
//! **Retryability is a property of the error, not of the call site** ([`RelayerError::is_retryable`]):
//! HTTP 404 (attestation not yet published), 429 (throttle), 5xx, and a transport failure are
//! transient; HTTP 400, a schema-decode failure, a broken `messageHash` binding, and every
//! structural rejection are permanent. A single classification (`circle::client::classify_status`)
//! decides, so no call site can invent its own retry rule (§8.1 check 1, §8.4).

use core::fmt;
use std::sync::Arc;

use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

use crate::circle::status::{classify_status, StatusClass};

/// A preserved lower-level cause whose own type is neither `Clone` nor `PartialEq` (a
/// `reqwest::Error`, a `serde_json::Error`, a header/URL parse error). Wrapping it keeps
/// [`RelayerError`]'s `Clone` + `PartialEq` contract intact while still handing the ORIGINAL typed
/// error to [`Error::source`](core::error::Error) — so a caller can `downcast_ref::<reqwest::Error>`
/// it and ask, say, `is_timeout()` (G-RUST preserve-error-source). The alternative — flattening the
/// cause to a `String` — would have discarded exactly the information an operator needs.
///
/// `PartialEq` compares the rendered message: two causes are equal iff they render identically.
/// That is the only equality that means anything for an opaque foreign error, and it keeps
/// `assert_eq!` on relayer errors usable in tests.
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

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Which Circle-facing wire field failed to hex-decode. Named (not a string) so a caller — and a
/// test — asserts the EXACT field, never a coarse "some hex was bad".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexField {
    /// The DepositIntent `payload` hex.
    Payload,
    /// The attestation envelope's `messageHash` hex.
    MessageHash,
    /// The `attestation` (`r‖s‖v`) hex.
    Attestation,
    /// A Miden transaction id, as an operator pastes it back in (the idempotency log's
    /// `submitted_tx_id`). It is not a Circle wire field — but it decodes through the SAME hex
    /// taxonomy, because a second, parallel "bad hex" error family for the same failure is exactly
    /// the drift the single-owner rule exists to prevent.
    TxId,
    /// The operator-configured attester pubkey, as it is written in the relayer's config (33-byte
    /// compressed SEC1, hex). Also not a Circle wire field — and for the same reason as [`Self::TxId`]
    /// it decodes through the one hex taxonomy rather than growing a second one.
    AttesterPubkey,
}

impl fmt::Display for HexField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload => write!(f, "payload"),
            Self::MessageHash => write!(f, "messageHash"),
            Self::Attestation => write!(f, "attestation"),
            Self::TxId => write!(f, "transaction id"),
            Self::AttesterPubkey => write!(f, "attester pubkey"),
        }
    }
}

// The originating hex failure is CARRIED, not mirrored: `RelayerError::MalformedHex` holds the
// `hex::FromHexError` itself, so `Error::source()` traverses to it and a caller can `downcast_ref`
// the typed cause (G-RUST preserve-error-source). This costs the enum its `Eq` derive — the hex
// error is `PartialEq` but not `Eq` — which is the right trade: no caller compares relayer errors
// for total equality, but a Circle-input rejection must never discard WHY the input was malformed.

/// Relayer error taxonomy. Every DepositIntent field violation carries its OWN named variant so
/// callers (and the tests) assert the exact failed field, never a coarse `is_err()`. Each variant
/// also carries the originating unit-04 [`EncodingError`] as its error source — the field-specific
/// relayer name never discards the underlying cause (G-RUST preserve-error-source).
// `Eq` is deliberately absent: `MalformedHex` carries the originating `hex::FromHexError` (which is
// `PartialEq` but not `Eq`) so the typed cause survives in the `source()` chain. `PartialEq` is
// retained, so errors still compare by value.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RelayerError {
    /// `magic != 0x5a2e0acd` (DC-1 field 0).
    BadMagic(EncodingError),
    /// `version != 1` (DC-1 field 1).
    BadVersion(EncodingError),
    /// `payload.len() != 240 + hookDataLen` (DC-1 total-length relation).
    LengthMismatch(EncodingError),
    /// `amount == 0` (DC-1 field 2).
    ZeroAmount(EncodingError),
    /// `localToken == 0` (DC-1 field 6).
    ZeroLocalToken(EncodingError),
    /// `localDepositor == 0` (DC-1 field 7).
    ZeroLocalDepositor(EncodingError),
    /// payload shorter than the fixed 240-byte DepositIntent header.
    ShortHeader(EncodingError),
    /// the u32-LE preimage (60 header felts + `ceil(hookDataLen / 4)`) exceeds the 1024-felt
    /// NoteStorage bound (INV-NOTE-MODEL-CURRENT; anti-ASG-16 — the header is 60 felts, not 30).
    PreimageTooLarge(EncodingError),
    /// An encoding-layer error the DepositIntent path does not map to a specific field. Defensive
    /// catch-all; unit-04's DepositIntent parser/packer only emit the mapped variants above, so in
    /// practice this is never constructed by [`Self::from_deposit_intent`].
    DepositIntentCodec(EncodingError),

    // ATTESTATION-ENVELOPE FAMILY (DC-2; INV-DEPOSIT-ATTESTATION-RAW-KECCAK)
    // --------------------------------------------------------------------------------------------
    /// A Circle-facing wire field is not valid hex. Names WHICH field, and PRESERVES the originating
    /// [`hex::FromHexError`] as its source (the exact character and index) — reachable through the
    /// typed [`Self::hex_source`] accessor and the std [`Error::source`](core::error::Error) chain.
    MalformedHex {
        field: HexField,
        source: hex::FromHexError,
    },
    /// `messageHash` is not 32 bytes (a keccak256 digest is exactly 32). A SHAPE error, reported as
    /// such — never reclassified as a binding mismatch.
    BadMessageHashLength { actual: usize },
    /// `messageHash != keccak256(payload)` — the envelope does not bind the payload it claims to
    /// (INV-DEPOSIT-ATTESTATION-RAW-KECCAK). `expected` is the true RAW keccak256 of the full
    /// payload; `actual` is the digest Circle presented. Carrying both makes an operator's
    /// "which hash family did they send?" answerable straight from the log line.
    MessageHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The attestation is not exactly 65 bytes (`r‖s‖v`). Note 64 bytes — a `v`-less signature — is
    /// rejected here, not silently zero-extended.
    BadAttestationLength { actual: usize },

    // CIRCLE TRANSPORT FAMILY (§8.1 checks 1–2; §8.4)
    // --------------------------------------------------------------------------------------------
    /// A non-2xx HTTP status from Circle. The status ALONE decides what happens next
    /// (`classify_status`): 404 → retry (the attestation is not published yet), 429 → back off, 5xx
    /// → retry + alert, everything else (400 included) → permanent reject. **No error body is ever
    /// parsed** — the OpenAPI documents status codes only, with no error-body schema, so inventing
    /// one would be fiction.
    Http { status: u16 },
    /// The request never produced a status: connection refused, TLS failure, timeout, a body that
    /// could not be read. Transient — retried under the same ceilings as a 5xx. Preserves the
    /// originating `reqwest::Error`.
    Transport(Cause),
    /// A 2xx body did not match the documented schema (a missing/renamed field, a non-JSON body).
    /// Rejected, never forwarded on-chain. Preserves the originating `serde_json::Error` (which
    /// carries the line/column and the exact expectation that failed).
    Decode(Cause),
    /// `txHash` violates the documented `^0x[a-fA-F0-9]{64}$`. Rejected CLIENT-SIDE — no request is
    /// issued (spec §7.1: the relayer does not spend a request, or a rate-limit token, on an input
    /// the API cannot accept).
    BadTxHashFormat { tx_hash: String },
    /// `depositMessageHash` violates the documented `^0x[a-fA-F0-9]{64}$`. Rejected client-side, as
    /// above.
    BadMessageHashFormat { message_hash: String },
    /// A `?txHash=` response element carries `remoteDomain < 1`, violating the documented
    /// `minimum: 1`. A schema violation, so it is rejected rather than carried toward Miden.
    BadRemoteDomain { actual: u32 },
    /// `pageSize` outside the documented `1..=1000`. Refused at `BatchQuery` construction, so it
    /// cannot reach the wire.
    BadPageSize { actual: u16 },
    /// The configured Circle base URL is not a URL. Refused at client construction — never
    /// discovered mid-retry-loop. Preserves the originating parse error.
    BadBaseUrl { url: String, source: Cause },
    /// The configured auth header is not a legal HTTP header (an invalid name, or a value with a
    /// control character — a header-injection attempt). Refused at client construction, so a
    /// misconfigured key can never silently degrade into an unauthenticated request stream.
    /// Preserves the originating `http` crate error; the header VALUE is never carried here (it is
    /// the credential).
    BadAuthHeader { name: String, source: Cause },
    /// A rate ceiling of 0 QPS. Refused at construction: a 0-QPS window never opens, so a request
    /// would block forever — a deadlock is not a rate limit.
    BadRateLimit { qps_per_ip: u32, qps_global: u32 },
    /// A retry policy that cannot run: fewer than one attempt, or an alert threshold of 0 (which
    /// would alert before any attempt has failed).
    BadRetryPolicy {
        max_attempts: u32,
        alert_after_attempts: u32,
    },
    /// A credential is configured and the base URL is not HTTPS. Refused at client construction: over
    /// a plaintext transport the key is readable by anything on the path, and no amount of redaction
    /// in the logs changes that. (A plaintext base URL with NO credential is fine — the documented
    /// API declares no auth at all.)
    InsecureAuthTransport { url: String },
    /// One attempt exceeded the request deadline — the peer accepted the request and did not answer.
    /// TRANSIENT: retried like a 5xx. Without this the relayer would wait forever and never even
    /// reach its retry budget, so a single unresponsive peer could stall it silently.
    RequestTimeout { after_ms: u64 },
    /// The response body exceeds the configured ceiling. PERMANENT: re-requesting it would just
    /// download it again. The bytes past the ceiling are never buffered — the production transport
    /// refuses on the advertised `Content-Length`, and on the chunk that crosses the line if the
    /// length lied or was absent.
    ResponseTooLarge { limit: usize, actual: usize },
    /// Transport bounds that cannot work: a zero deadline (never met) or a zero body ceiling (rejects
    /// everything).
    BadTransportLimits {
        connect_timeout_ms: u64,
        request_timeout_ms: u64,
        max_response_bytes: usize,
    },
    /// A PRESENT `Link` header that cannot be parsed, or that advertises `next` without a cursor the
    /// scan could follow. It is NOT treated as "no next page": that is indistinguishable from a
    /// legitimate final page, so malformed metadata would silently truncate the scan and strand every
    /// attestation after it (§8.4 — nothing is dropped without a reason).
    BadPaginationMetadata { detail: String },
    /// The response came back from a URL other than the one requested — a redirect was FOLLOWED.
    /// The relayer follows none (`RedirectPolicy::Never`), so this can only mean that policy has
    /// regressed; the response is refused rather than trusted, because it was served by an origin the
    /// relayer never chose. PERMANENT: retrying would be redirected again, and every attempt is
    /// another chance for the credential to land somewhere it should not.
    RedirectFollowed { requested: String, followed: String },
    /// The by-hash endpoint returned an attestation for a DIFFERENT `depositMessageHash` than the one
    /// requested. It may be perfectly valid — a real attestation, for a real deposit — and it is
    /// still the wrong answer: the endpoint is a lookup BY the requested hash, and minting from
    /// someone else's DepositIntent is exactly what a buggy server, a mis-keyed cache, or a
    /// substitution on the path would cause.
    MessageHashNotRequested {
        requested: [u8; 32],
        returned: [u8; 32],
    },

    // ---- the idempotency seam (`idempotency`) -------------------------------------------------
    //
    // The seam is a LIVENESS backstop (the safety backstop is the on-chain `usedNonces`
    // assert-then-set), so its errors are about the two things a broken store can actually do:
    // withhold a mint forever, or attempt one twice. None of them is a "just carry on" condition —
    // that is why every one of them is a typed variant and not a logged warning.
    /// The store's own persistence failed — SQLite or the filesystem underneath it (the database
    /// cannot be opened or created, the disk is full, the file is locked past the busy timeout). The
    /// originating `rusqlite::Error` is PRESERVED as the source, so an operator sees the SQLite
    /// primary/extended code, not a flattened string.
    ///
    /// RETRYABLE: a busy database and a transient I/O fault both clear on their own. It is
    /// deliberately NOT the variant a corrupt or foreign store gets ([`Self::CorruptStoreRecord`],
    /// [`Self::UnsupportedStoreSchema`]) — retrying THOSE forever is how a relayer wedges silently.
    IdempotencyStore(Cause),
    /// A status transition was attempted on a nonce the store has never claimed. Recording a
    /// submission for an unknown nonce would mean inserting a log row with no attestation behind it
    /// — a mint the audit trail cannot explain. The caller must `claim_nonce` first.
    UnknownNonce { nonce_key: [u8; 32] },
    /// A transition the `SubmissionStatus` machine does not have an edge for — a settled record
    /// (`Committed` / `AlreadyMinted`) being resurrected, a commit for a transaction that was never
    /// submitted, or the double-submit of an in-flight one. Refused rather than applied: each of
    /// these is a caller bug whose silent acceptance would either strand or re-attempt a mint.
    IllegalStatusTransition {
        from: crate::idempotency::SubmissionStatus,
        to: crate::idempotency::SubmissionStatus,
    },
    /// A SECOND attestation, with a different `messageHash`, claiming a nonce the store has already
    /// claimed. At most one of the two is the deposit that actually happened; the store keeps the
    /// one it recorded (it never overwrites) and refuses the newcomer, so the operator — and the
    /// on-chain nonce assert — get to decide. Both digests are carried: "which one did I mint?" must
    /// be answerable from the error alone.
    NonceMessageHashMismatch {
        nonce_key: [u8; 32],
        stored: [u8; 32],
        observed: [u8; 32],
    },
    /// An empty (or whitespace-only) `Link` cursor token was handed to `advance_cursor`. It is not a
    /// resume point: persisting it would send `pageAfter=` on the next poll, and — the real damage —
    /// it would have destroyed the resume point that was there. Refused before the write.
    EmptyCursor { remote_domain: u32 },
    /// A row in the store cannot be read as the record it claims to be: a status string this build
    /// does not know, a nonce/hash/transaction-id blob of the wrong length. It is CORRUPTION (a
    /// foreign writer, a partial upgrade, a hand-edited row), and it is surfaced rather than
    /// defaulted — defaulting it to "not submitted" re-mints a deposit, and defaulting it the other
    /// way strands one.
    CorruptStoreRecord { detail: String },
    /// The store file carries a schema version this build does not know. Reading a layout written by
    /// a different version of the relayer is the one way a store can silently misread (or lose) the
    /// cursor, so the file is refused at open and the operator migrates it deliberately.
    UnsupportedStoreSchema { found: u32, expected: u32 },
    /// A Miden transaction id that is not 32 bytes. A truncated id in the log is a mint nobody can
    /// look up again.
    BadTxIdLength { actual: usize },
    // ---- the Miden-facing half (`miden::mint_note`) -------------------------------------------
    //
    // The relayer BUILDS a mint note; it does not define one. Every byte of the note's wire form is
    // unit-04's (`XReserveMintNote::create`), so every failure here is unit-04's verdict on the
    // inputs the relayer handed it — carried through, never re-judged and never re-worded.
    /// Unit-04's mint-note factory refused the inputs: the DepositIntent payload is structurally
    /// invalid or exceeds the 1024-felt `NoteStorage` bound (its `EncodingError` is the source), the
    /// attester pubkey is not a curve point, or the faucet id cannot carry the scheme-2 routing bind
    /// (it is not a public network account).
    ///
    /// PERMANENT. A payload that is not a DepositIntent does not become one on a retry, and a
    /// misconfigured faucet id does not fix itself — so this is deliberately not retryable: looping
    /// on it would park the relayer on one bad attestation and mint nothing else. The originating
    /// `NoteError` is PRESERVED as the source (and unit-04's `EncodingError` under it), so an
    /// operator reads WHICH rule the payload broke, not "note build failed".
    MintNoteBuild(Cause),
    /// The operator-configured attester pubkey is not 33 bytes. The allowlist the faucet checks
    /// against is keyed by the COMPRESSED SEC1 key (33 bytes) — an uncompressed 65-byte key, or a
    /// truncated one, is not that key, and is refused where it is configured rather than at the
    /// first mint.
    BadAttesterPubkeyLength { actual: usize },
    /// The operator-configured attester pubkey is 33 bytes that do not decode to a secp256k1 point
    /// (unit-04's SEC1 decompression is the judge — the same primitive that packs the affine felts
    /// the faucet verifies against, consumed by reference). A key that is not a point could never
    /// verify on-chain, so the relayer refuses to start a mint with it.
    InvalidAttesterPubkey(Cause),

    /// The configured idempotency-store path is not a durable file — SQLite would open it as an
    /// in-memory or temporary database that vanishes when the connection closes (`:memory:`, an
    /// empty filename, a `file:` URI whose parameters can select `mode=memory`).
    ///
    /// It is refused at CONSTRUCTION, because every one of those paths opens cleanly, accepts a
    /// claim, accepts a cursor advance — and loses both on restart. That is not a degraded store; it
    /// is a cache wearing the store's name, and it would re-scan the attestation window and
    /// re-attempt every mint in it. An operator's typo must not be able to spell it.
    EphemeralStorePath { path: String, detail: String },
}

impl RelayerError {
    /// Maps a unit-04 [`EncodingError`] from the DepositIntent parse/pack path onto the
    /// field-specific relayer taxonomy, KEEPING the original error as the mapped variant's source.
    /// The mapping is DepositIntent-context-specific (hence a named function, not a blanket
    /// `From`): `TruncatedHeader → ShortHeader` and `HookDataTooLarge → PreimageTooLarge`.
    pub(crate) fn from_deposit_intent(err: EncodingError) -> Self {
        // Select the variant constructor by inspecting the error (borrow only), then move the
        // error into it — the field-specific name AND the underlying cause are both retained.
        let variant: fn(EncodingError) -> Self = match &err {
            EncodingError::BadMagic => Self::BadMagic,
            EncodingError::BadVersion => Self::BadVersion,
            EncodingError::LengthMismatch => Self::LengthMismatch,
            EncodingError::TruncatedHeader => Self::ShortHeader,
            EncodingError::HookDataTooLarge => Self::PreimageTooLarge,
            EncodingError::ZeroField {
                field: DepositIntentField::Amount,
            } => Self::ZeroAmount,
            EncodingError::ZeroField {
                field: DepositIntentField::LocalToken,
            } => Self::ZeroLocalToken,
            EncodingError::ZeroField {
                field: DepositIntentField::LocalDepositor,
            } => Self::ZeroLocalDepositor,
            _ => Self::DepositIntentCodec,
        };
        variant(err)
    }

    /// The originating unit-04 [`EncodingError`] preserved by every DepositIntent-path variant — a
    /// typed view of the same value returned through the std [`Error::source`](core::error::Error)
    /// chain, so callers can inspect the exact underlying cause without a `downcast`.
    ///
    /// `None` for the envelope family — no unit-04 codec is involved on that path. (A malformed-hex
    /// rejection still preserves ITS cause: see [`Self::hex_source`].)
    pub fn encoding_source(&self) -> Option<&EncodingError> {
        match self {
            Self::BadMagic(e)
            | Self::BadVersion(e)
            | Self::LengthMismatch(e)
            | Self::ZeroAmount(e)
            | Self::ZeroLocalToken(e)
            | Self::ZeroLocalDepositor(e)
            | Self::ShortHeader(e)
            | Self::PreimageTooLarge(e)
            | Self::DepositIntentCodec(e) => Some(e),
            // the envelope and transport families never involve a unit-04 codec — they preserve
            // their own causes (`hex_source`, and the `Cause` carried by Transport/Decode/BadBaseUrl/
            // BadAuthHeader, all reachable through `source()`).
            _ => None,
        }
    }

    /// The originating [`hex::FromHexError`] preserved by [`Self::MalformedHex`] — the typed view of
    /// the same value the std [`Error::source`](core::error::Error) chain returns, so a caller can
    /// see WHICH character at WHICH index broke the decode without a `downcast`.
    ///
    /// `None` for every other variant (nothing was hex-decoded).
    pub fn hex_source(&self) -> Option<&hex::FromHexError> {
        match self {
            Self::MalformedHex { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Whether retrying the operation could plausibly succeed — the SINGLE retry decision in the
    /// relayer, so no call site can invent its own (§8.1 check 1; §8.4).
    ///
    /// Transient: HTTP 404 (Circle has not published the attestation *yet*), 429 (throttled), 5xx,
    /// and a transport failure. Permanent: HTTP 400 and every other 4xx, a schema-decode failure, a
    /// broken `messageHash` binding, and every structural/config rejection — retrying those would
    /// re-issue an identical request that must fail identically, burning the rate budget that the
    /// retryable failures need.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http { status } => matches!(
                classify_status(*status),
                StatusClass::RetryPending | StatusClass::RetryThrottle | StatusClass::RetryAlert
            ),
            // the connection died, or the peer went quiet: both are conditions that can clear
            Self::Transport(_) | Self::RequestTimeout { .. } => true,
            // the store was busy, or its disk was: a condition that clears. The store's PERMANENT
            // failures are separate variants on purpose — a corrupt record, a foreign schema, an
            // illegal transition and an unknown nonce are all caller/operator business, and retrying
            // them in a loop is how a relayer wedges without saying anything.
            Self::IdempotencyStore(_) => true,
            _ => false,
        }
    }

    /// Whether a RETRYABLE failure should raise an operator alert once the alert threshold is
    /// crossed (§8.4). A 5xx or a transport failure means Circle (or the network) is unhealthy — the
    /// operator wants to know. A 404 does NOT: "the attestation is not published yet" is the normal
    /// state of a deposit that just landed, and it alerts only if it never resolves within the
    /// attempt budget. A 429 is the rate governor's business, not the operator's, until it too runs
    /// out of attempts.
    pub(crate) fn alerts_while_retrying(&self) -> bool {
        match self {
            Self::Http { status } => matches!(classify_status(*status), StatusClass::RetryAlert),
            Self::Transport(_) | Self::RequestTimeout { .. } => true,
            _ => false,
        }
    }

    /// The HTTP status behind this error, when there is one — so an observability event can carry
    /// it without re-deriving it from the message.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Http { status } => Some(*status),
            _ => None,
        }
    }
}

impl fmt::Display for RelayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(_) => write!(f, "deposit intent magic mismatch"),
            Self::BadVersion(_) => write!(f, "deposit intent version mismatch"),
            Self::LengthMismatch(_) => write!(f, "deposit intent length relation violated"),
            Self::ZeroAmount(_) => write!(f, "deposit intent amount is zero"),
            Self::ZeroLocalToken(_) => write!(f, "deposit intent local token is zero"),
            Self::ZeroLocalDepositor(_) => write!(f, "deposit intent local depositor is zero"),
            Self::ShortHeader(_) => write!(f, "deposit intent payload is shorter than 240 bytes"),
            Self::PreimageTooLarge(_) => write!(
                f,
                "deposit intent preimage exceeds the 1024-felt note storage bound"
            ),
            Self::DepositIntentCodec(e) => write!(f, "deposit intent codec error: {e}"),
            // the cause is also reachable via source(); it is inlined here so a single logged line
            // is self-explanatory
            Self::MalformedHex { field, source } => {
                write!(f, "malformed {field} hex: {source}")
            }
            Self::BadMessageHashLength { actual } => write!(
                f,
                "message hash must be 32 bytes (keccak256), got {actual}"
            ),
            // the digests are the whole point of the diagnostic, so they are rendered in full
            Self::MessageHashMismatch { expected, actual } => write!(
                f,
                "message hash does not bind the payload: expected keccak256(payload) = 0x{}, got 0x{}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            Self::BadAttestationLength { actual } => write!(
                f,
                "attestation must be 65 bytes (r||s||v), got {actual}"
            ),
            Self::Http { status } => write!(f, "circle returned http {status}"),
            Self::Transport(source) => write!(f, "circle request failed in transport: {source}"),
            Self::Decode(source) => write!(f, "circle response does not match the schema: {source}"),
            Self::BadTxHashFormat { tx_hash } => write!(
                f,
                "txHash must match ^0x[a-fA-F0-9]{{64}}$, got `{tx_hash}`"
            ),
            Self::BadMessageHashFormat { message_hash } => write!(
                f,
                "depositMessageHash must match ^0x[a-fA-F0-9]{{64}}$, got `{message_hash}`"
            ),
            Self::BadRemoteDomain { actual } => {
                write!(f, "remoteDomain must be at least 1, got {actual}")
            }
            Self::BadPageSize { actual } => {
                write!(f, "pageSize must be within 1..=1000, got {actual}")
            }
            Self::BadBaseUrl { url, source } => {
                write!(f, "circle base url `{url}` is not a url: {source}")
            }
            // the header VALUE is the credential: it is never rendered, here or anywhere else
            Self::BadAuthHeader { name, source } => {
                write!(f, "auth header `{name}` is not a legal http header: {source}")
            }
            Self::BadRateLimit {
                qps_per_ip,
                qps_global,
            } => write!(
                f,
                "rate ceilings must be non-zero, got {qps_per_ip} qps/ip and {qps_global} qps global"
            ),
            Self::BadRetryPolicy {
                max_attempts,
                alert_after_attempts,
            } => write!(
                f,
                "retry policy needs at least one attempt and a non-zero alert threshold, got \
                 max_attempts = {max_attempts} and alert_after_attempts = {alert_after_attempts}"
            ),
            Self::InsecureAuthTransport { url } => write!(
                f,
                "an api credential must not cross a plaintext transport: `{url}` is not https"
            ),
            Self::RequestTimeout { after_ms } => {
                write!(f, "circle did not answer within {after_ms} ms")
            }
            Self::ResponseTooLarge { limit, actual } => write!(
                f,
                "circle response body exceeds the {limit}-byte ceiling (saw {actual} bytes)"
            ),
            Self::BadTransportLimits {
                connect_timeout_ms,
                request_timeout_ms,
                max_response_bytes,
            } => write!(
                f,
                "transport limits must be non-zero, got connect = {connect_timeout_ms} ms, \
                 request = {request_timeout_ms} ms, max response = {max_response_bytes} bytes"
            ),
            Self::BadPaginationMetadata { detail } => {
                write!(f, "malformed pagination metadata: {detail}")
            }
            // WHERE the response came from is the whole diagnostic: it names the origin that was
            // handed the request (and, if one was configured, the credential)
            Self::RedirectFollowed {
                requested,
                followed,
            } => write!(
                f,
                "a redirect was followed: requested `{requested}`, response came from `{followed}`                  — the relayer follows no redirect"
            ),
            // both digests are rendered: "which attestation did they send me instead?" must be
            // answerable straight from the log line
            Self::MessageHashNotRequested {
                requested,
                returned,
            } => write!(
                f,
                "circle returned an attestation for a different deposit: requested 0x{}, got 0x{}",
                hex::encode(requested),
                hex::encode(returned)
            ),
            // the cause is also reachable via source(); it is inlined so one logged line explains
            // itself (a SQLite code with no context is not an operator-actionable line)
            Self::IdempotencyStore(source) => {
                write!(f, "the idempotency store failed: {source}")
            }
            Self::UnknownNonce { nonce_key } => write!(
                f,
                "nonce 0x{} was never claimed — a submission cannot be recorded for it",
                hex::encode(nonce_key)
            ),
            Self::IllegalStatusTransition { from, to } => write!(
                f,
                "a mint cannot go from {from} to {to}"
            ),
            // both digests are the diagnostic: WHICH attestation is in the log, and which one was
            // refused, must be answerable from this line alone
            Self::NonceMessageHashMismatch {
                nonce_key,
                stored,
                observed,
            } => write!(
                f,
                "a second attestation claims nonce 0x{}: the log holds messageHash 0x{}, this one \
                 carries 0x{}",
                hex::encode(nonce_key),
                hex::encode(stored),
                hex::encode(observed)
            ),
            Self::EmptyCursor { remote_domain } => write!(
                f,
                "an empty pagination cursor is not a resume point for remote domain {remote_domain}"
            ),
            Self::CorruptStoreRecord { detail } => {
                write!(f, "the idempotency store holds an unreadable record: {detail}")
            }
            Self::UnsupportedStoreSchema { found, expected } => write!(
                f,
                "the idempotency store is at schema version {found}, this build speaks {expected}"
            ),
            Self::BadTxIdLength { actual } => {
                write!(f, "a miden transaction id must be 32 bytes, got {actual}")
            }
            // the path is echoed verbatim: the operator has to find it in their config, and the
            // detail says WHY sqlite would not have put it on disk
            Self::EphemeralStorePath { path, detail } => write!(
                f,
                "the idempotency store path `{path}` is not a durable file: {detail}"
            ),
            // unit-04's refusal is quoted, not paraphrased — it names the rule the inputs broke
            Self::MintNoteBuild(source) => {
                write!(f, "the mint note could not be built: {source}")
            }
            Self::BadAttesterPubkeyLength { actual } => write!(
                f,
                "the attester pubkey must be a 33-byte compressed sec1 key, got {actual} bytes"
            ),
            Self::InvalidAttesterPubkey(source) => {
                write!(f, "the attester pubkey is not a secp256k1 point: {source}")
            }
        }
    }
}

impl core::error::Error for RelayerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        // Every variant that HAS a lower-level cause exposes it here, so `source()` traverses to the
        // real typed error (`EncodingError` on the DepositIntent path, `hex::FromHexError` on the
        // wire-decode path) and callers can `downcast_ref` it. The remaining envelope variants
        // (length / binding mismatch) are genuine leaves — the relayer itself is the authority there,
        // so no cause exists and none is invented.
        match self {
            Self::MalformedHex { source, .. } => Some(source),
            Self::Transport(source)
            | Self::Decode(source)
            | Self::IdempotencyStore(source)
            | Self::MintNoteBuild(source)
            | Self::InvalidAttesterPubkey(source)
            | Self::BadBaseUrl { source, .. }
            | Self::BadAuthHeader { source, .. } => Some(source.as_error()),
            _ => self
                .encoding_source()
                .map(|e| e as &(dyn core::error::Error + 'static)),
        }
    }
}
