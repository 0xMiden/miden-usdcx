//! The three attestation fetch shapes (`CMP-D3`/`CMP-D4`) — by `depositMessageHash`, by source-chain
//! `txHash`, and the batch/cursor poll.
//!
//! Every fetch runs the same ordered §8.1 gauntlet, and the ORDER is the point:
//!
//! 1. **request-shape pre-conditions, client-side** — a `txHash`/`depositMessageHash` that violates
//!    the documented `^0x[a-fA-F0-9]{64}$` is refused BEFORE a request is issued. The relayer does
//!    not spend a request (nor a rate-limit token) to be told by Circle what it already knows.
//! 2. **HTTP status** — 404/429/5xx retry with backoff, 400 (and every other 4xx, and every 3xx)
//!    rejects with no retry (in the client), under a request deadline and a response-size ceiling.
//! 3. **schema decode** — the exact OpenAPI shape, wrapper vs list included.
//! 4. **envelope binding** — `messageHash == keccak256(payload)` (RAW keccak) + the 65-byte `r‖s‖v`
//!    shape.
//! 5. **request↔response binding** (by-hash only) — the returned `messageHash` IS the hash that was
//!    asked for. Circle's by-hash endpoint is a LOOKUP BY that hash; a response carrying a different
//!    one answers a different question. It would pass every check above — it is a real attestation
//!    for a real deposit, just not the one requested — and would mint the WRONG DepositIntent. A
//!    buggy server, a cache keyed on the wrong thing, or a substitution anywhere on the path
//!    produces exactly that, so the relayer compares.
//!
//! What comes back is a [`ValidatedAttestation`], never a raw wire object — so a caller cannot
//! accidentally build a mint note from bytes whose hash was never checked. What comes back is still
//! not AUTHORIZED: the ECDSA verify, the attester-allowlist check, and the nonce assert-then-set are
//! on-chain at D5a–D5d (§1.2). These are liveness filters, and a relayer bug here can only WITHHOLD a
//! mint, never cause one.
//!
//! Nothing fetched is ever silently dropped: every rejection is emitted to the event sink with its
//! reason (§8.4).

use crate::circle::client::CircleClient;
use crate::circle::pagination::{parse_link_header, BatchQuery, PageCursors};
use crate::circle::schema::{
    AttestationListResponse, AttestationPage, AttestationResponse, AttestationsByTxHashResponse,
    ValidatedAttestation, ValidatedAttestationByTxHash,
};
use crate::error::{Cause, RelayerError};

/// Endpoint labels — what an event/log line names when it reports a rejection or a retry.
const ENDPOINT_BY_HASH: &str = "GET /v1/attestations/{depositMessageHash}";
const ENDPOINT_BY_TX_HASH: &str = "GET /v1/attestations?txHash=";
const ENDPOINT_BATCH: &str = "GET /v1/remote-domains/{remoteDomain}/attestations";

/// The documented hex-parameter pattern, `^0x[a-fA-F0-9]{64}$`: a `0x` prefix + 64 hex digits.
const HEX_PARAM_LEN: usize = 66;

/// `GET /v1/attestations/{depositMessageHash}` (`CMP-D3`) — the WRAPPER endpoint.
///
/// Deserializes `AttestationResponse { attestation: {...} }`, flattens its inner `.attestation`, and
/// returns it only if the envelope binds (`messageHash == keccak256(payload)`, 65-byte attestation)
/// AND the `messageHash` returned is the one that was requested.
///
/// # Errors
/// * [`RelayerError::BadMessageHashFormat`] — the param violates `^0x[a-fA-F0-9]{64}$` (no request is
///   issued).
/// * [`RelayerError::Http`] — a non-2xx that survived the retry policy (404 = not published yet, 400
///   = permanent, 3xx = a redirect, which is never followed).
/// * [`RelayerError::Transport`] / [`RelayerError::RequestTimeout`] / [`RelayerError::ResponseTooLarge`]
///   — the request never produced a usable response.
/// * [`RelayerError::Decode`] — the body is not the documented WRAPPER shape.
/// * [`RelayerError::MalformedHex`] / [`RelayerError::BadMessageHashLength`] /
///   [`RelayerError::MessageHashMismatch`] / [`RelayerError::BadAttestationLength`] — the envelope
///   does not hold up.
/// * [`RelayerError::MessageHashNotRequested`] — a valid attestation, for a DIFFERENT deposit than
///   the one asked for.
pub async fn fetch_attestation_by_message_hash(
    client: &CircleClient,
    message_hash: &str,
) -> Result<ValidatedAttestation, RelayerError> {
    let requested = parse_bytes32_param(message_hash).ok_or_else(|| {
        client.reject(
            ENDPOINT_BY_HASH,
            RelayerError::BadMessageHashFormat {
                message_hash: message_hash.to_string(),
            },
        )
    })?;

    let response = client
        .get(
            ENDPOINT_BY_HASH,
            &format!("/v1/attestations/{message_hash}"),
            &[],
        )
        .await?;

    let wrapper: AttestationResponse = decode(client, ENDPOINT_BY_HASH, &response.body)?;
    let validated = ValidatedAttestation::validate(wrapper.into_attestation())
        .map_err(|error| client.reject(ENDPOINT_BY_HASH, error))?;

    // the response must answer the question that was ASKED (see the module docs, step 5)
    let returned = validated.message_hash();
    if returned != requested {
        return Err(client.reject(
            ENDPOINT_BY_HASH,
            RelayerError::MessageHashNotRequested {
                requested,
                returned,
            },
        ));
    }

    Ok(validated)
}

/// `GET /v1/attestations?txHash=` (`CMP-D3` variant) — the LIST endpoint keyed by the source-chain
/// deposit transaction hash. Each element additionally carries `remoteDomain` (≥ 1).
///
/// # Errors
/// * [`RelayerError::BadTxHashFormat`] — `tx_hash` violates the REQUIRED `^0x[a-fA-F0-9]{64}$`
///   pattern. Refused CLIENT-SIDE: no request is issued.
/// * [`RelayerError::BadRemoteDomain`] — an element's `remoteDomain` is below the documented minimum
///   of 1.
/// * otherwise as [`fetch_attestation_by_message_hash`] (status / transport / decode / envelope).
pub async fn fetch_attestations_by_tx_hash(
    client: &CircleClient,
    tx_hash: &str,
) -> Result<Vec<ValidatedAttestationByTxHash>, RelayerError> {
    if parse_bytes32_param(tx_hash).is_none() {
        return Err(client.reject(
            ENDPOINT_BY_TX_HASH,
            RelayerError::BadTxHashFormat {
                tx_hash: tx_hash.to_string(),
            },
        ));
    }

    let response = client
        .get(
            ENDPOINT_BY_TX_HASH,
            "/v1/attestations",
            &[("txHash", tx_hash.to_string())],
        )
        .await?;

    let list: AttestationsByTxHashResponse = decode(client, ENDPOINT_BY_TX_HASH, &response.body)?;

    list.into_attestations()
        .into_iter()
        .map(|element| {
            ValidatedAttestationByTxHash::validate(element)
                .map_err(|error| client.reject(ENDPOINT_BY_TX_HASH, error))
        })
        .collect()
}

/// `GET /v1/remote-domains/{remoteDomain}/attestations` (`CMP-D4`) — one page of the batch poll, plus
/// the `Link`-header cursors.
///
/// The caller advances `cursors.next_cursor()` into the next [`BatchQuery::forward`] and persists it
/// as the last-cursor; `next_cursor() == None` ends the scan (§8.2 pagination boundary). The cursor
/// PERSISTENCE itself is the idempotency seam's job (a later slice) — this function is pure fetch.
///
/// # Errors
/// * [`RelayerError::BadPaginationMetadata`] — a PRESENT `Link` header that cannot be parsed, or that
///   advertises `next` without a usable cursor. It is NOT read as a final page: that would silently
///   truncate the scan (see [`crate::circle::pagination`]).
/// * otherwise as [`fetch_attestation_by_message_hash`]: every element of the page runs the SAME
///   envelope checks, so a single bad element rejects the page rather than slipping through the list
///   shape.
pub async fn poll_remote_domain_attestations(
    client: &CircleClient,
    remote_domain: u32,
    query: &BatchQuery,
) -> Result<(AttestationPage, PageCursors), RelayerError> {
    let response = client
        .get(
            ENDPOINT_BATCH,
            &format!("/v1/remote-domains/{remote_domain}/attestations"),
            &query.query_params(),
        )
        .await?;

    let list: AttestationListResponse = decode(client, ENDPOINT_BATCH, &response.body)?;
    let attestations = list
        .into_attestations()
        .into_iter()
        .map(|object| {
            ValidatedAttestation::validate(object)
                .map_err(|error| client.reject(ENDPOINT_BATCH, error))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // an ABSENT Link header is the documented final page; a PRESENT one must parse
    let cursors = match response.link.as_deref() {
        None => PageCursors::default(),
        Some(header) => parse_link_header(header, client.base())
            .map_err(|error| client.reject(ENDPOINT_BATCH, error))?,
    };

    Ok((AttestationPage::new(attestations), cursors))
}

/// Deserializes a 2xx body into the documented shape, recording (never dropping) a schema violation.
pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    client: &CircleClient,
    endpoint: &str,
    body: &[u8],
) -> Result<T, RelayerError> {
    serde_json::from_slice(body)
        .map_err(|source| client.reject(endpoint, RelayerError::Decode(Cause::new(source))))
}

/// The documented `^0x[a-fA-F0-9]{64}$` check for a bytes32 request parameter, returning the decoded
/// 32 bytes.
///
/// Exact: a lower-case `0x` prefix (the pattern anchors it — `0X` does not match), 64 hex digits,
/// nothing else. No trimming, no case-folding of the prefix, no "helpful" repair — a parameter the
/// API would reject is a parameter the relayer rejects, and it says so before it spends a request.
fn parse_bytes32_param(value: &str) -> Option<[u8; 32]> {
    if value.len() != HEX_PARAM_LEN || !value.starts_with("0x") {
        return None;
    }
    let digits = &value[2..];
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    hex::decode(digits).ok()?.try_into().ok()
}
