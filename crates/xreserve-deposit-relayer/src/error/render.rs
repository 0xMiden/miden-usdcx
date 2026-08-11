//! The human- and machine-facing renderings of [`RelayerError`](super::RelayerError): its `Display`
//! one-liners and its `Error::source` chain (which preserves the typed cause — an `EncodingError`,
//! a `hex::FromHexError`, a `reqwest`/`serde_json`/`rusqlite` error — for a caller to
//! `downcast_ref`).
//!
//! Split out of `error/mod.rs` so the taxonomy stays within its file-size ceiling. This module adds
//! NO variant and owns none: it only renders the ones the parent defines, so there is no duplicated
//! ownership to drift.

use core::fmt;

use super::RelayerError;

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
            Self::BadRecoveryPolicy {
                retry_batch_size,
                stale_claim_secs,
                required_min_stale_secs,
            } => write!(
                f,
                "recovery policy is unsafe: retry_batch_size must be >= 1 and stale_claim_secs must be \
                 >= {required_min_stale_secs} (the larger of the absolute floor and one second beyond \
                 the submit envelope), got retry_batch_size = {retry_batch_size} and stale_claim_secs \
                 = {stale_claim_secs}"
            ),
            Self::BadSubmitDeadline { submit_deadline_ms } => write!(
                f,
                "submit_deadline_ms must be >= 1: a 0ms deadline times out every submit instantly and \
                 defers every deposit forever, got {submit_deadline_ms}"
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
            // the shared encoding crate's refusal is quoted, not paraphrased — it names the rule
            // the inputs broke
            Self::MintNoteBuild(source) => {
                write!(f, "the mint note could not be built: {source}")
            }
            Self::MalformedAttesterIndex(source) => {
                write!(f, "the attester index is not a u32: {source}")
            }
            // the node's own words are quoted, not paraphrased: "which node, saying what" is the
            // whole diagnostic value of a submit failure
            Self::TransientSubmit(source) => write!(
                f,
                "the miden node did not accept the mint transaction (transient): {source}"
            ),
            Self::FatalSubmit(source) => write!(
                f,
                "the miden node permanently refused the mint transaction: {source}"
            ),
            Self::MintSubmitPortUnavailable => write!(
                f,
                "no miden submit adapter is configured: the submit port has no implementation until \
                 a miden-client release for v0.16 exists"
            ),
            Self::DomainMismatch { expected, actual } => write!(
                f,
                "the attestation's remote domain {actual} is not the configured domain {expected}"
            ),
            Self::TokenMismatch { expected, actual } => write!(
                f,
                "the attestation's remote token 0x{} is not the configured xusdc identifier 0x{}",
                hex::encode(actual),
                hex::encode(expected)
            ),
            Self::InfoDomainNotAdvertised { domain } => write!(
                f,
                "circle does not advertise the configured remote domain {domain}"
            ),
            Self::BadAccountId {
                field,
                value,
                source,
            } => write!(f, "the configured {field} `{value}` is not an account id: {source}"),
            Self::BadConfigFile { path, source } => {
                write!(f, "the config file `{path}` could not be read: {source}")
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
            | Self::MalformedAttesterIndex(source)
            | Self::TransientSubmit(source)
            | Self::FatalSubmit(source)
            | Self::BadBaseUrl { source, .. }
            | Self::BadAuthHeader { source, .. }
            | Self::BadAccountId { source, .. }
            | Self::BadConfigFile { source, .. } => Some(source.as_error()),
            _ => self
                .encoding_source()
                .map(|e| e as &(dyn core::error::Error + 'static)),
        }
    }
}
