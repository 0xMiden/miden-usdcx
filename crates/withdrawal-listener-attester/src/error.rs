//! The `ListenerError` taxonomy — STARTED in this scaffold slice with the configuration family (the
//! base URL, the auth-header injection point, the transport bounds) and the transport failure the
//! Circle seam surfaces.
//!
//! The Circle-facing families (HTTP status, schema decode, the 409 conflict), the Miden-facing ones
//! (tag scan, note retrieval, evidence reads), the validation family (the B3/B5 checklists and the
//! "DO NOT SIGN" abort) and the quorum family land with their slices. The enum is `#[non_exhaustive]`
//! so those additions are not breaking changes.
//!
//! Errors are hand-rolled — the repo does not depend on `thiserror` — with lowercase, unpunctuated
//! messages (the Rust convention), and every variant preserves its underlying cause through
//! [`Error::source`](core::error::Error) rather than flattening it to a string.

use core::fmt;
use std::sync::Arc;

use xusdc_encoding::xreserve::encoding::EncodingError;

use crate::attester::Address;

/// A preserved lower-level cause whose own type is neither `Clone` nor `PartialEq` (a
/// `reqwest::Error`, a header/URL parse error). Wrapping it keeps [`ListenerError`]'s `Clone` +
/// `PartialEq` contract intact while still handing the ORIGINAL typed error to
/// [`Error::source`](core::error::Error) — so a caller can `downcast_ref` it and ask the concrete
/// question (`is_timeout()`, say). Flattening the cause to a `String` would discard exactly the
/// information an operator needs.
///
/// The idiom mirrors the deposit relayer's `Cause`. It is duplicated rather than shared because it
/// is an error-plumbing convention, not a wire format — the single-owner rule binds the formats and
/// codecs the two services must agree on (all of which live in `xusdc-encoding` and are consumed by
/// reference here), and a cross-dependency between two sibling services just to share twelve lines
/// of `Arc<dyn Error>` would couple them for no protection.
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
    /// The configured Circle base URL is not a usable `http`/`https` URL. Refused when the config is
    /// built, not on the first request.
    BadBaseUrl { url: String, source: Cause },

    /// An out-of-band API key is configured against a base URL that cannot protect it. A credential
    /// sent in the clear is a credential disclosed — and `Q-API-AUTH` being OPEN means the key could
    /// ride under any header name, so no transport-level convention will save it.
    InsecureAuthTransport { base_url: String },

    /// The configured auth header is not a legal header: an illegal NAME, or a value carrying a
    /// control character (a header-injection attempt). Rejected at construction, so a misconfigured
    /// key can never silently degrade into an unauthenticated request stream.
    ///
    /// The credential VALUE never appears in this error — only the header name.
    BadAuthHeader { name: String, source: Cause },

    /// An out-of-band API key is configured with no header name to send it under.
    ///
    /// `Q-API-AUTH` is OPEN: the OpenAPI documents NO auth scheme, so there is no header this crate
    /// could pick that would not be an invention (§10.12: "do NOT invent an auth header"). A key with
    /// nowhere documented to go is therefore a configuration error, not a prompt to guess
    /// `Authorization`. When Circle answers, the operator writes the answer into the config.
    AuthHeaderNameRequired,

    /// A configured faucet account id that is not an account id at all.
    BadFaucetId { value: String, source: Cause },

    /// A request that produced NO HTTP status — a connection failure, a timeout, a body that could
    /// not be read. Transient: the retry policy (a later slice) treats it as such.
    Transport(Cause),

    /// The response exceeded the configured body ceiling. NOT transient — a peer that returns an
    /// oversized body will do it again, and the bytes past the ceiling are never buffered.
    ResponseTooLarge { limit: usize, actual: usize },
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
            Self::InsecureAuthTransport { .. }
            | Self::AuthHeaderNameRequired
            | Self::ResponseTooLarge { .. } => None,
        }
    }
}

/// Everything [`note_decode`](crate::note_decode) can refuse to decode — the `DecodeError` §10.2
/// names. Kept a type of its own rather than a [`ListenerError`] family: a decode failure is a
/// statement about ONE note's bytes, and the caller's response to it (skip the note, alert) is not
/// the response to a Circle transport failure.
///
/// Every variant is a REFUSAL. There is no lossy/partial success here by construction: a burn note
/// whose payload or sender does not decode yields no [`BurnPayload`](crate::types::BurnPayload) and
/// no depositor — never a zero-filled or otherwise fabricated one, which would hand Circle a
/// `remoteDepositor` no Miden account ever authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The `NoteStorage.items` felts are not a `DC-7` burn payload — a felt count other than
    /// `BURN_NOTE_ITEMS_FELTS = 18`, an out-of-range `amount`/`destDomain`, or a non-`u32` bytes32
    /// limb.
    ///
    /// The unit-04 codec is the sole judge of that, and its verdict is carried here UNFLATTENED:
    /// the exact [`EncodingError`] it returned is the preserved source (`preserve-error-source`),
    /// so a caller that wants the codec's own answer can ask for it instead of parsing a string.
    BurnItemsMalformed { source: EncodingError },

    /// The discovered note carries no metadata at all, so there is no `metadata.sender` to read —
    /// what a PRIVATE or erased note looks like from `GetNotesById` (`details = None`,
    /// `INV-PUBLIC-BURN-OBSERVABILITY`). Such a note is unacceptable for Circle observability, and
    /// it is refused rather than defaulted.
    SenderAbsent,

    /// The reported `metadata.sender` is the zero felt pair. No account has the zero id; a node (or
    /// a bug) reporting one is reporting nothing, and the ONE thing that must not happen next is
    /// its silent promotion into a zero `remoteDepositor` (`INV-BURN-SENDER-PRIVACY-LEAK` names the
    /// sender as the exposed depositor — a zero there would be a burn attributed to nobody).
    SenderZero,

    /// The reported `metadata.sender` felts are not a canonical [`AccountId`](miden_protocol::account::AccountId)
    /// (an unknown id version, an out-of-field felt, a violated id constraint). The underlying
    /// `AccountIdError` is preserved as the source.
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
/// `sign` consumes Circle's returned `messageHashToSign` as an OPAQUE 32-byte digest
/// (`INV-OFFCHAIN-BURN-SIGNING`, `Q-CRY-2` — OPEN): it never re-derives the digest locally (no
/// EIP-712, no personal-sign, no Poseidon2), so the only thing it can reject about the input is its
/// length. A non-32-byte digest is a caller bug — a truncated hash, a hex string passed where raw
/// bytes were meant — and signing it anyway would put an attester signature over the wrong 32 bytes.
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
    /// fund-release boundary, `sign` refuses. An x-reduced recovery id requires the signature's `r` to
    /// have wrapped the curve order, which happens with probability ≈ `2^-128` for a random key/digest
    /// — so this is a defensive refusal, not a path real inputs take.
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
/// The Circle wire form is fixed: secp256k1 ECDSA, 65 bytes `r‖s‖v`
/// (`CIRCLE-DATA-SCHEMAS.md:184`). A DER blob, a 64-byte `r‖s` with the recovery id dropped, or any
/// other length is not that form, and is refused at construction so a mis-shaped signature can never
/// reach [`assemble_quorum`](crate::attester::assemble_quorum) or the `/v1/withdraw` wire.
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
/// The bundle Circle verifies on the source chain must be **exactly-threshold count, every signature
/// verifying to its claimed signer, ascending signer-address order, no duplicates**
/// (`MIN_SIGNATURE_THRESHOLD = 2`; `CIRCLE-DATA-SCHEMAS.md:196`; the recover-then-authorize step at
/// `:46`). This assembler enforces that contract BEFORE anything is submitted, so a set Circle would
/// reject — or worse, a single-key set that must NEVER be submitted (`INV-OFFCHAIN-BURN-SIGNING`;
/// §10.9) — fails here as a typed `Err` rather than on Circle's wire. Every rejection is exact: a
/// duplicate signer is refused, NEVER silently de-duplicated (a silent dedupe could shrink a 2-signer
/// set to one and submit a single-key quorum).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuorumError {
    /// Fewer than `MIN_SIGNATURE_THRESHOLD` signatures. A single-key set is a non-gating local
    /// primitive and is NEVER submitted to Circle (§10.9). Foreclosing the "threshold treated as ≥1"
    /// bug is the whole point of this variant.
    BelowThreshold { have: usize, need: usize },

    /// More than `MIN_SIGNATURE_THRESHOLD` signatures. Circle's source-chain verifier is
    /// **exactly-threshold** (`Attestable.sol:75,333-381`; `CIRCLE-DATA-SCHEMAS.md:196`), so an
    /// over-threshold bundle Circle would reject is refused here rather than at the fund-release
    /// boundary. Selecting an authorized exactly-threshold subset from a larger set of signatures is a
    /// separate, owner-specified concern; this assembler does not silently truncate.
    AboveThreshold { have: usize, need: usize },

    /// A signature does not verify against its CLAIMED signer address: `ECDSA.recover(digest, sig)`
    /// (the same recovery Circle performs) either fails outright — a `v` outside `27`/`28`, a
    /// malformed `r`/`s`, a digest the signature does not cover — or recovers a DIFFERENT address than
    /// the one it was paired with. Either way the signature is excluded from the quorum
    /// (`TEST-AND-VERIFICATION-HARNESS.md:157`); `at` is its index in the input.
    SignatureDoesNotVerify { at: usize },

    /// The same signer address appears more than once. Refused, not de-duplicated — Circle rejects a
    /// duplicate, and a silent dedupe here could collapse the count below threshold unnoticed.
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
