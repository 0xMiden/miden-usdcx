//! The `RelayerError` taxonomy: the DepositIntent structural-reject family (the off-chain mirror
//! of the on-chain parse) plus the NoteStorage felt-count guard; the attestation-envelope
//! family — wire-hex decode, `messageHash` shape + raw-keccak binding, and attestation shape; the
//! Circle TRANSPORT family — HTTP status, schema decode, transport failure, and the client-side
//! request-shape pre-conditions (`txHash` / `depositMessageHash` patterns, `pageSize` bounds,
//! rate/retry/auth/base-URL configuration); and the Miden-facing variants (note build, submit).
//! The enum is `#[non_exhaustive]` so additions are not breaking changes.
//!
//! **Retryability is a property of the error, not of the call site**
//! ([`RelayerError::is_retryable`]): HTTP 404 (attestation not yet published), 429 (throttle), 5xx,
//! and a transport failure are transient; HTTP 400, a schema-decode failure, a broken `messageHash`
//! binding, and every structural rejection are permanent. A single classification
//! (`circle::client::classify_status`) decides, so no call site can invent its own retry rule (the
//! HTTP-status check, the documented policy).

use core::fmt;
use std::sync::Arc;

use xusdc_encoding::xreserve::encoding::{DepositIntentField, EncodingError};

use crate::circle::status::{classify_status, StatusClass};

// The `Display` and `Error` (source-chain) renderings live in a sibling module, so this file
// stays the taxonomy — the enum, its construction, its classification — within its file-size
// ceiling.
// The split is by RESPONSIBILITY, not by variant: `render` adds no variant and owns none, it only
// renders the ones defined here.
mod render;

/// A preserved lower-level cause whose own type is neither `Clone` nor `PartialEq` (a
/// `reqwest::Error`, a `serde_json::Error`, a header/URL parse error). Wrapping it keeps
/// [`RelayerError`]'s `Clone` + `PartialEq` contract intact while still handing the ORIGINAL typed
/// error to [`Error::source`](core::error::Error) — so a caller can
/// `downcast_ref::<reqwest::Error>` it and ask, say, `is_timeout()` (G-RUST preserve-error-source).
/// The alternative — flattening the cause to a `String` — would have discarded exactly the
/// information an operator needs.
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
    /// compressed SEC1, hex). Also not a Circle wire field — and for the same reason as
    /// [`Self::TxId`] it decodes through the one hex taxonomy rather than growing a second one.
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
/// also carries the originating [`EncodingError`] from the shared encoding crate as its error
/// source — the field-specific relayer name never discards the underlying cause.
// `Eq` is deliberately absent: `MalformedHex` carries the originating `hex::FromHexError` (which is
// `PartialEq` but not `Eq`) so the typed cause survives in the `source()` chain. `PartialEq` is
// retained, so errors still compare by value.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RelayerError {
    /// `magic != 0x5a2e0acd` (DepositIntent header field 0).
    BadMagic(EncodingError),
    /// `version != 1` (DepositIntent header field 1).
    BadVersion(EncodingError),
    /// `payload.len() != 240 + hookDataLen` (the DepositIntent total-length relation).
    LengthMismatch(EncodingError),
    /// `amount == 0` (DepositIntent header field 2).
    ZeroAmount(EncodingError),
    /// `localToken == 0` (DepositIntent header field 6).
    ZeroLocalToken(EncodingError),
    /// `localDepositor == 0` (DepositIntent header field 7).
    ZeroLocalDepositor(EncodingError),
    /// payload shorter than the fixed 240-byte DepositIntent header.
    ShortHeader(EncodingError),
    /// the u32-LE preimage (60 header felts + `ceil(hookDataLen / 4)`) exceeds the 1024-felt
    /// NoteStorage bound (the header is 60 felts, not 30).
    PreimageTooLarge(EncodingError),
    /// An encoding-layer error the DepositIntent path does not map to a specific field. It carries
    /// the codec's own verdict verbatim, which is what the narrowing rejects arrive as: an
    /// identifier that is not an account id, a source-chain field that is not an address, an
    /// amount past the mintable cap. Those are the codec's vocabulary, not a relayer field
    /// taxonomy, so they are passed through rather than renamed.
    DepositIntentCodec(EncodingError),

    // ATTESTATION-ENVELOPE FAMILY (the raw-keccak binding and the 65-byte `r‖s‖v` shape)
    // --------------------------------------------------------------------------------------------
    /// A Circle-facing wire field is not valid hex. Names WHICH field, and PRESERVES the
    /// originating [`hex::FromHexError`] as its source (the exact character and index) — reachable
    /// through the typed [`Self::hex_source`] accessor and the std
    /// [`Error::source`](core::error::Error) chain.
    MalformedHex {
        field: HexField,
        source: hex::FromHexError,
    },
    /// `messageHash` is not 32 bytes (a keccak256 digest is exactly 32). A SHAPE error, reported as
    /// such — never reclassified as a binding mismatch.
    BadMessageHashLength { actual: usize },
    /// `messageHash != keccak256(payload)` — the envelope does not bind the payload it claims to.
    /// `expected` is the true RAW keccak256 of the full payload; `actual` is the digest Circle
    /// presented. Carrying both makes an operator's "which hash family did they send?" answerable
    /// straight from the log line.
    MessageHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The attestation is not exactly 65 bytes (`r‖s‖v`). Note 64 bytes — a `v`-less signature — is
    /// rejected here, not silently zero-extended.
    BadAttestationLength { actual: usize },

    // CIRCLE TRANSPORT FAMILY — the HTTP-status and schema-decode failures
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
    /// issued (the relayer does not spend a request, or a rate-limit token, on an input
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
    /// A recovery policy the relayer would be unsafe to run under (crash recovery): a
    /// `retry_batch_size` of 0 (which makes the retry work list return nothing forever, stranding
    /// every deposit behind the forward cursor) or a `stale_claim_secs` below the safety floor
    /// (which would reclaim another process's LIVE `Pending` claim, racing an in-flight submit).
    /// Refused at construction and at startup, never clamped: an operator's unsafe value must fail
    /// loudly, not be silently corrected into a different policy than the one they wrote.
    BadRecoveryPolicy {
        retry_batch_size: usize,
        stale_claim_secs: u64,
        /// The smallest `stale_claim_secs` this config would accept — the larger of the absolute
        /// floor and one second beyond the submit envelope. Carried so the operator is told what to
        /// set.
        required_min_stale_secs: u64,
    },
    /// A submit deadline of 0 ms — refused. `submit_with_retry` would build
    /// `Duration::from_millis(0)`, so every async submit that yields is classified as an instant
    /// timeout and every deposit is deferred back to `Failed` forever: the same silent-liveness
    /// failure the validated recovery policy exists to reject. Refused at startup and at the
    /// cycle's config gate.
    BadSubmitDeadline { submit_deadline_ms: u64 },
    /// A credential is configured and the base URL is not HTTPS. Refused at client construction:
    /// over a plaintext transport the key is readable by anything on the path, and no amount of
    /// redaction in the logs changes that. (A plaintext base URL with NO credential is fine — the
    /// documented API declares no auth at all.)
    InsecureAuthTransport { url: String },
    /// One attempt exceeded the request deadline — the peer accepted the request and did not
    /// answer. TRANSIENT: retried like a 5xx. Without this the relayer would wait forever and never
    /// even reach its retry budget, so a single unresponsive peer could stall it silently.
    RequestTimeout { after_ms: u64 },
    /// The response body exceeds the configured ceiling. PERMANENT: re-requesting it would just
    /// download it again. The bytes past the ceiling are never buffered — the production transport
    /// refuses on the advertised `Content-Length`, and on the chunk that crosses the line if the
    /// length lied or was absent.
    ResponseTooLarge { limit: usize, actual: usize },
    /// Transport bounds that cannot work: a zero deadline (never met) or a zero body ceiling
    /// (rejects everything).
    BadTransportLimits {
        connect_timeout_ms: u64,
        request_timeout_ms: u64,
        max_response_bytes: usize,
    },
    /// A PRESENT `Link` header that cannot be parsed, or that advertises `next` without a cursor
    /// the scan could follow. It is NOT treated as "no next page": that is indistinguishable from a
    /// legitimate final page, so malformed metadata would silently truncate the scan and strand
    /// every attestation after it — nothing is dropped without a reason.
    BadPaginationMetadata { detail: String },
    /// The response came back from a URL other than the one requested — a redirect was FOLLOWED.
    /// The relayer follows none (`RedirectPolicy::Never`), so this can only mean that policy has
    /// regressed; the response is refused rather than trusted, because it was served by an origin
    /// the relayer never chose. PERMANENT: retrying would be redirected again, and every attempt is
    /// another chance for the credential to land somewhere it should not.
    RedirectFollowed { requested: String, followed: String },
    /// The by-hash endpoint returned an attestation for a DIFFERENT `depositMessageHash` than the
    /// one requested. It may be perfectly valid — a real attestation, for a real deposit — and it
    /// is still the wrong answer: the endpoint is a lookup BY the requested hash, and minting from
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
    /// cannot be opened or created, the disk is full, the file is locked past the busy timeout).
    /// The originating `rusqlite::Error` is PRESERVED as the source, so an operator sees the SQLite
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
    /// on-chain nonce assert — get to decide. Both digests are carried: "which one did I mint?"
    /// must be answerable from the error alone.
    NonceMessageHashMismatch {
        nonce_key: [u8; 32],
        stored: [u8; 32],
        observed: [u8; 32],
    },
    /// An empty (or whitespace-only) `Link` cursor token was handed to `advance_cursor`. It is not
    /// a resume point: persisting it would send `pageAfter=` on the next poll, and — the real
    /// damage — it would have destroyed the resume point that was there. Refused before the write.
    EmptyCursor { remote_domain: u32 },
    /// A row in the store cannot be read as the record it claims to be: a status string this build
    /// does not know, a nonce/hash/transaction-id blob of the wrong length. It is CORRUPTION (a
    /// foreign writer, a partial upgrade, a hand-edited row), and it is surfaced rather than
    /// defaulted — defaulting it to "not submitted" re-mints a deposit, and defaulting it the other
    /// way strands one.
    CorruptStoreRecord { detail: String },
    /// The store file carries a schema version this build does not know. Reading a layout written
    /// by a different version of the relayer is the one way a store can silently misread (or lose)
    /// the cursor, so the file is refused at open and the operator migrates it deliberately.
    UnsupportedStoreSchema { found: u32, expected: u32 },
    /// A Miden transaction id that is not 32 bytes. A truncated id in the log is a mint nobody can
    /// look up again.
    BadTxIdLength { actual: usize },
    // ---- the Miden-facing half (`miden::mint_note`) -------------------------------------------
    //
    // The relayer BUILDS a mint note; it does not define one. Every byte of the note's wire form is
    // the shared encoding crate's (`XUsdcMintNote::create`), so every failure here is the shared
    // encoding crate's verdict on the
    // inputs the relayer handed it — carried through, never re-judged and never re-worded.
    /// Unit-04's mint-note factory refused the inputs: the DepositIntent payload is structurally
    /// invalid or exceeds the 1024-felt `NoteStorage` bound (its `EncodingError` is the source),
    /// the attester pubkey is not a curve point, or the faucet id cannot carry the scheme-2 routing
    /// bind (it is not a public network account).
    ///
    /// PERMANENT. A payload that is not a DepositIntent does not become one on a retry, and a
    /// misconfigured faucet id does not fix itself — so this is deliberately not retryable: looping
    /// on it would park the relayer on one bad attestation and mint nothing else. The originating
    /// `NoteError` is PRESERVED as the source (and the shared encoding crate's `EncodingError`
    /// under it), so an operator reads WHICH rule the payload broke, not "note build failed".
    MintNoteBuild(Cause),
    /// The operator-configured attester pubkey is not 33 bytes. The attester identity the faucet
    /// checks is derived from the COMPRESSED SEC1 key (33 bytes; the `xReserveAttesters` key is the
    /// Poseidon2 commitment over the affine coordinates it decompresses to) — an uncompressed
    /// 65-byte key, or a truncated one, is not that key, and is refused where it is configured
    /// rather than at the first mint.
    BadAttesterPubkeyLength { actual: usize },
    /// The operator-configured attester pubkey is 33 bytes that do not decode to a secp256k1 point
    /// (the shared encoding crate's SEC1 decompression is the judge — the same primitive that packs
    /// the affine felts the faucet verifies against, consumed by reference). A key that is not a
    /// point could never verify on-chain, so the relayer refuses to start a mint with it.
    InvalidAttesterPubkey(Cause),

    /// The configured idempotency-store path is not a durable file — SQLite would open it as an
    /// in-memory or temporary database that vanishes when the connection closes (`:memory:`, an
    /// empty filename, a `file:` URI whose parameters can select `mode=memory`).
    ///
    /// It is refused at CONSTRUCTION, because every one of those paths opens cleanly, accepts a
    /// claim, accepts a cursor advance — and loses both on restart. That is not a degraded store;
    /// it is a cache wearing the store's name, and it would re-scan the attestation window and
    /// re-attempt every mint in it. An operator's typo must not be able to spell it.
    EphemeralStorePath { path: String, detail: String },

    // ---- the Miden SUBMIT port (`cycle::MintSubmit`) -------------------------------------------
    //
    // The relayer hands a built note to a Miden node through a PORT. These are the answers the port
    // may give, and the seam's own absence. Which of them a real failure IS, is the adapter's mapping to make
    // against a real `miden-client`; the split — one retryable, one not — is the orchestration's
    // contract, and it is what keeps a node's sync lag from becoming a stranded deposit and a
    // permanent refusal from becoming an infinite loop.
    /// The node did not accept the transaction, for a reason that CAN clear: it is behind, it is
    /// syncing, the connection dropped mid-submit. RETRYABLE — and the deposit intent has no
    /// expiry, so the attestation is still valid whenever the node catches up.
    TransientSubmit(Cause),
    /// The node refused the transaction permanently — the built transaction is not one it will ever
    /// accept. NOT retryable: looping on it would park the relayer on one deposit and mint nothing
    /// else. The nonce is recorded `Failed` and an operator is alerted.
    FatalSubmit(Cause),
    /// **There is no production Miden submit adapter.** The port ([`crate::cycle::MintSubmit`]) is
    /// defined and the orchestration composes against it; its real implementation needs a
    /// `miden-client` for v0.16, which has no release.
    ///
    /// It is a typed refusal rather than a stub that returns success, and `main` fails on it at
    /// STARTUP rather than mid-flight: a relayer that starts, polls, validates and then silently
    /// never mints looks healthy for exactly as long as nobody checks the chain. Faking the leg
    /// instead is the one thing the mock boundary forbids outright (the mock boundary: Miden
    /// behaviour must not be faked for final acceptance).
    MintSubmitPortUnavailable,

    // ---- the OPTIONAL domain/token fast-fail (the optional domain/token fast-fail, `validate::domain_token`) ----------
    //
    // Every expected value here is Circle-owned and OPEN, and every one of these refusals is a
    // LIVENESS fast-fail: the authoritative compare is on-chain in the faucet's deposit-intent
    // parse, and a relayer that skipped
    // all three would mint exactly the same set of deposits, one block later.
    /// The attestation's `remoteDomain` is not the domain the relayer is configured for. The
    /// expected value is still OPEN (`REQUIRES CIRCLE CONFIRMATION`) — Circle has assigned Miden no
    /// domain id, so the configured value is a placeholder, which is why the check ships OFF.
    DomainMismatch { expected: u32, actual: u32 },
    /// The attestation's `remoteToken` is not the xUSDC identifier the relayer is configured for.
    /// The expected value AND its encoding are Circle-owned and OPEN (`REQUIRES CIRCLE
    /// CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL`).
    TokenMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// `GET /v1/info` does not advertise the remote domain the relayer is configured to expect —
    /// so the fast-fail's expected value is not Circle's, and it would refuse every honest deposit.
    /// Surfaced as the misconfiguration it is, rather than left to look like a flood of bad
    /// attestations.
    InfoDomainNotAdvertised { domain: u32 },

    /// A configured Miden account id (the faucet, or the relayer's own) is not a valid `AccountId`.
    /// Refused where it is CONFIGURED — at startup — because the alternative is discovering it on
    /// the first deposit that arrives.
    BadAccountId {
        field: &'static str,
        value: String,
        source: Cause,
    },
    /// The operator's config file cannot be read, or is not the documented shape. The binary's only
    /// I/O error: `config` itself does none, so this is raised where the file is read and nowhere
    /// else. The originating `io::Error`/`serde_json::Error` is preserved — "config invalid"
    /// without the line and column is a message that costs an operator an hour.
    BadConfigFile { path: String, source: Cause },
}

impl RelayerError {
    /// Maps an [`EncodingError`] from the shared encoding crate's DepositIntent parse/pack path
    /// onto the field-specific relayer taxonomy, KEEPING the original error as the mapped variant's
    /// source. The mapping is DepositIntent-context-specific (hence a named function, not a blanket
    /// `From`): `TruncatedHeader → ShortHeader` and `HookDataTooLarge → PreimageTooLarge`.
    ///
    /// This is the relayer's whole stake in decoding a payload: the codec is the shared crate's,
    /// this crate keeps no field model, no offsets and no second parse. That single ownership is
    /// what keeps the off-chain and on-chain views of the same bytes from drifting.
    ///
    /// Decoding is a LIVENESS check here, never a safety one. The faucet re-derives the message
    /// on-chain and re-runs every assert before it mints, so a bug in this path can only stop a
    /// legitimate deposit from being relayed, never cause an illegitimate one to be minted. What it
    /// buys is a fast local rejection naming the rule the payload broke, instead of a transaction
    /// that fails on-chain.
    pub fn from_deposit_intent(err: EncodingError) -> Self {
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

    /// The originating [`EncodingError`] from the shared encoding crate, preserved by every
    /// DepositIntent-path variant — a typed view of the same value returned through the std
    /// [`Error::source`](core::error::Error) chain, so callers can inspect the exact underlying
    /// cause without a `downcast`.
    ///
    /// `None` for the envelope family — no codec from the shared encoding crate is involved on
    /// that path. (A malformed-hex rejection still preserves ITS cause: see [`Self::hex_source`].)
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
            // the envelope and transport families never involve a codec from the shared encoding
            // crate: they preserve their own causes (`hex_source`, and the `Cause` carried by
            // Transport/Decode/BadBaseUrl/BadAuthHeader, all reachable through `source()`).
            _ => None,
        }
    }

    /// The originating [`hex::FromHexError`] preserved by [`Self::MalformedHex`] — the typed view
    /// of the same value the std [`Error::source`](core::error::Error) chain returns, so a caller
    /// can see WHICH character at WHICH index broke the decode without a `downcast`.
    ///
    /// `None` for every other variant (nothing was hex-decoded).
    pub fn hex_source(&self) -> Option<&hex::FromHexError> {
        match self {
            Self::MalformedHex { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Whether retrying the operation could plausibly succeed — the SINGLE retry decision in the
    /// relayer, so no call site can invent its own.
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
            // the node was behind, or the submit connection died: both clear on their own, and the
            // deposit intent has no expiry to run out while they do. `FatalSubmit` is the
            // deliberate other half — the node's permanent refusals are NOT retried, because a
            // relayer looping on one deposit mints nothing else.
            Self::TransientSubmit(_) => true,
            _ => false,
        }
    }

    /// Whether a RETRYABLE failure should raise an operator alert once the alert threshold is
    /// crossed. A 5xx or a transport failure means Circle (or the network) is unhealthy — the
    /// operator wants to know. A 404 does NOT: "the attestation is not published yet" is the normal
    /// state of a deposit that just landed, and it alerts only if it never resolves within the
    /// attempt budget. A 429 is the rate governor's business, not the operator's, until it too runs
    /// out of attempts.
    pub(crate) fn alerts_while_retrying(&self) -> bool {
        match self {
            Self::Http { status } => matches!(classify_status(*status), StatusClass::RetryAlert),
            Self::Transport(_) | Self::RequestTimeout { .. } => true,
            // the sync-lag rule: retry, and do NOT alert until the
            // threshold — a node briefly behind is the normal state of a node, not an incident.
            Self::TransientSubmit(_) => true,
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
