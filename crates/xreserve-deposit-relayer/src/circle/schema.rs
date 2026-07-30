//! The Circle wire schema — serde types deserialized EXACTLY per the OpenAPI
//! (`CIRCLE-API-SURFACE.md`), plus the validated forms the rest of the relayer consumes.
//!
//! Three response shapes, and the difference between them is load-bearing:
//!
//! * `GET /v1/attestations/{depositMessageHash}` returns a **WRAPPER** — the attestation object is
//!   nested under a top-level `attestation` key ([`AttestationResponse`], live OpenAPI YAML
//!   L391–398). The relayer deserializes the wrapper, then flattens its inner `.attestation`.
//! * `GET /v1/attestations?txHash=` returns a **LIST** whose elements carry an extra `remoteDomain`
//!   ([`AttestationsByTxHashResponse`]) — no wrapper.
//! * `GET /v1/remote-domains/{d}/attestations` returns a **LIST** ([`AttestationListResponse`]) —
//!   no wrapper, and its pagination travels in the `Link` HEADER, not the body.
//!
//! Only the by-hash endpoint is wrapped. Getting that wrong in either direction is a real defect
//! (one shape silently decodes to nothing useful), which is why the by-hash decoder rejects a bare
//! top-level object rather than accepting both shapes "to be safe".
//!
//! **Decoded ≠ trusted.** A [`AttestationObject`] is only what Circle *said*.
//! [`ValidatedAttestation`] is the type that has passed the schema-decode and digest-binding checks
//! — schema decode, `messageHash == keccak256(payload)` (RAW keccak, not EIP-712), and the 65-byte
//! `r‖s‖v` shape — and it is the only attestation type the rest of the relayer accepts. The type
//! system therefore carries the validation order: you cannot get bytes to build a note from without
//! having gone through the binding check. What it does NOT carry is any grant of authority — the
//! ECDSA verify and the attester-allowlist check are on-chain in the faucet's attestation check.
//! Validated means "worth spending a Miden transaction on", never "authorized to mint".

use serde::{Deserialize, Serialize};

use crate::error::RelayerError;
use crate::validate::envelope::{validate_attestation_envelope, verify_message_hash_bytes};

/// `remoteDomain` has `minimum: 1` on the `?txHash=` response elements
/// (`CIRCLE-API-SURFACE.md:51`).
const REMOTE_DOMAIN_MIN: u32 = 1;

// RESPONSE SHAPES
// ================================================================================================

/// The attestation object: the three wire fields, `0x`-hex, camelCase on the wire
/// (`CIRCLE-API-SURFACE.md:44`). The inner object of the by-hash wrapper, and the element of both
/// list shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationObject {
    /// `0x`-hex — the encoded DepositIntent (the fixed 240-byte big-endian header plus `hookData`).
    payload: String,
    /// `0x`-hex, 32 bytes — `keccak256(payload)` (raw keccak, not EIP-712).
    message_hash: String,
    /// `0x`-hex, 65 bytes — the raw secp256k1 `r‖s‖v` attestation signature.
    attestation: String,
}

impl AttestationObject {
    pub fn payload(&self) -> &str {
        &self.payload
    }

    pub fn message_hash(&self) -> &str {
        &self.message_hash
    }

    pub fn attestation(&self) -> &str {
        &self.attestation
    }
}

/// `GET /v1/attestations/{depositMessageHash}` — the WRAPPER. The ONLY wrapped response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    attestation: AttestationObject,
}

impl AttestationResponse {
    /// Flattens the wrapper to its inner attestation object.
    pub fn into_attestation(self) -> AttestationObject {
        self.attestation
    }
}

/// One element of the `?txHash=` list: the attestation object PLUS `remoteDomain`
/// (`CIRCLE-API-SURFACE.md:51`). The three shared fields are the same [`AttestationObject`] — the
/// shape is defined once and flattened, never re-declared (a second copy could drift).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationByTxHash {
    #[serde(flatten)]
    attestation: AttestationObject,
    remote_domain: u32,
}

/// `GET /v1/attestations?txHash=` — a LIST (no wrapper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationsByTxHashResponse {
    attestations: Vec<AttestationByTxHash>,
}

impl AttestationsByTxHashResponse {
    pub fn into_attestations(self) -> Vec<AttestationByTxHash> {
        self.attestations
    }
}

/// `GET /v1/remote-domains/{remoteDomain}/attestations` — a LIST (no wrapper); pagination is in the
/// `Link` header, not the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationListResponse {
    attestations: Vec<AttestationObject>,
}

impl AttestationListResponse {
    pub fn into_attestations(self) -> Vec<AttestationObject> {
        self.attestations
    }
}

// VALIDATED FORMS (what the rest of the relayer consumes)
// ================================================================================================

/// An attestation that has passed the schema-decode and digest-binding checks: it decoded, its
/// `messageHash` IS `keccak256(payload)` (raw keccak, over the full payload), and its attestation
/// is exactly 65 bytes.
///
/// It carries the decoded bytes — the payload, the verified digest, the `r‖s‖v` — so no consumer
/// re-decodes hex or re-derives the digest (one binding computation, one source of truth), and it
/// keeps the originating wire [`AttestationObject`] so a log line can quote exactly what Circle
/// sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAttestation {
    object: AttestationObject,
    payload: Vec<u8>,
    message_hash: [u8; 32],
    attestation: [u8; 65],
}

impl ValidatedAttestation {
    /// Runs the envelope checks over a decoded wire object.
    ///
    /// # Errors
    /// * [`RelayerError::MalformedHex`] — a wire field is not hex.
    /// * [`RelayerError::BadMessageHashLength`] — `messageHash` is not 32 bytes.
    /// * [`RelayerError::MessageHashMismatch`] — the hash does not bind the payload.
    /// * [`RelayerError::BadAttestationLength`] — the attestation is not 65 bytes.
    pub fn validate(object: AttestationObject) -> Result<Self, RelayerError> {
        let (payload, message_hash) =
            verify_message_hash_bytes(object.payload(), object.message_hash())?;
        let attestation = validate_attestation_envelope(object.attestation())?;

        Ok(Self {
            object,
            payload,
            message_hash,
            attestation,
        })
    }

    /// The decoded DepositIntent payload — the exact bytes the on-chain parse will see.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The verified `keccak256(payload)` digest.
    pub fn message_hash(&self) -> [u8; 32] {
        self.message_hash
    }

    /// The 65-byte `r‖s‖v` attestation. Only its shape is checked here; whether it actually
    /// verifies is decided on-chain, by the faucet's attestation check.
    pub fn attestation(&self) -> [u8; 65] {
        self.attestation
    }

    /// The originating wire object, verbatim.
    pub fn object(&self) -> &AttestationObject {
        &self.object
    }
}

/// A validated `?txHash=` element: the attestation plus its `remoteDomain` (≥ 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAttestationByTxHash {
    attestation: ValidatedAttestation,
    remote_domain: u32,
}

impl ValidatedAttestationByTxHash {
    /// Validates the envelope AND the documented `remoteDomain` minimum.
    ///
    /// # Errors
    /// * [`RelayerError::BadRemoteDomain`] — `remoteDomain < 1`, violating the OpenAPI minimum.
    /// * every error of [`ValidatedAttestation::validate`].
    pub fn validate(element: AttestationByTxHash) -> Result<Self, RelayerError> {
        if element.remote_domain < REMOTE_DOMAIN_MIN {
            return Err(RelayerError::BadRemoteDomain {
                actual: element.remote_domain,
            });
        }
        let remote_domain = element.remote_domain;

        Ok(Self {
            attestation: ValidatedAttestation::validate(element.attestation)?,
            remote_domain,
        })
    }

    pub fn attestation(&self) -> &ValidatedAttestation {
        &self.attestation
    }

    /// The source-chain-reported remote domain (≥ 1). NOT authoritative for the mint: the
    /// authoritative `remoteDomain == self.domain` compare is on-chain in the faucet's
    /// deposit-intent parse, and which remote-domain id Circle assigns Miden is still OPEN
    /// (REQUIRES CIRCLE CONFIRMATION).
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }
}

/// One page of the batch poll: its validated attestations. The cursors live in
/// [`PageCursors`](super::pagination::PageCursors), parsed from the `Link` header, because that is
/// where Circle puts them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationPage {
    attestations: Vec<ValidatedAttestation>,
}

impl AttestationPage {
    pub(crate) fn new(attestations: Vec<ValidatedAttestation>) -> Self {
        Self { attestations }
    }

    pub fn attestations(&self) -> &[ValidatedAttestation] {
        &self.attestations
    }

    pub fn into_attestations(self) -> Vec<ValidatedAttestation> {
        self.attestations
    }
}

// GET /v1/info
// ================================================================================================

/// `GET /v1/info` — the discovery response (`CIRCLE-API-SURFACE.md:30`).
///
/// The relayer reads Miden's domain config and the xUSDC identifier from it. Both values are
/// Circle-owned and OPEN — the Miden domain id is unassigned, and the AccountId↔bytes32 encoding of
/// the token identifier is unconfirmed — so the relayer DISCOVERS them here rather than assuming
/// them, and the authoritative compare happens on-chain in the faucet's deposit-intent parse
/// regardless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    source_domains: Vec<SourceDomain>,
    remote_domains: Vec<RemoteDomain>,
}

impl InfoResponse {
    pub fn source_domains(&self) -> &[SourceDomain] {
        &self.source_domains
    }

    pub fn remote_domains(&self) -> &[RemoteDomain] {
        &self.remote_domains
    }

    /// The remote domain with this id, if Circle advertises it.
    pub fn remote_domain(&self, domain: u32) -> Option<&RemoteDomain> {
        self.remote_domains.iter().find(|d| d.domain == domain)
    }
}

/// A source (deposit-side) domain: where native USDC is locked in Circle's xReserve contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceDomain {
    chain: String,
    network: String,
    domain: u32,
    contract_address: String,
    tokens: Vec<String>,
}

impl SourceDomain {
    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn domain(&self) -> u32 {
        self.domain
    }

    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
}

/// A remote (mint-side) domain — Miden, once Circle assigns it one (still OPEN).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDomain {
    chain: String,
    network: String,
    domain: u32,
    tokens: Vec<RemoteToken>,
}

impl RemoteDomain {
    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn domain(&self) -> u32 {
        self.domain
    }

    pub fn tokens(&self) -> &[RemoteToken] {
        &self.tokens
    }

    /// The identifier Circle advertises for `remote_token` on this domain — the xUSDC id the mint's
    /// `remoteToken` field must carry. Its encoding is still OPEN (REQUIRES CIRCLE CONFIRMATION),
    /// so it is carried as the opaque string Circle sends and compared, never re-derived.
    pub fn token_identifier(&self, remote_token: &str) -> Option<&str> {
        self.tokens
            .iter()
            .find(|t| t.remote_token == remote_token)
            .map(RemoteToken::remote_token_identifier)
    }
}

/// A token on a remote domain: `{remoteToken, remoteTokenIdentifier, associatedNativeToken}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteToken {
    remote_token: String,
    remote_token_identifier: String,
    associated_native_token: String,
}

impl RemoteToken {
    pub fn remote_token(&self) -> &str {
        &self.remote_token
    }

    pub fn remote_token_identifier(&self) -> &str {
        &self.remote_token_identifier
    }

    pub fn associated_native_token(&self) -> &str {
        &self.associated_native_token
    }
}
