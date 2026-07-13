//! The seam's value types: the transaction id, the status machine, the log record, and what a claim
//! answers.

use core::fmt;

use crate::error::{HexField, RelayerError};

/// A Miden transaction id — the 32-byte commitment of the transaction a mint went out in.
///
/// It is a newtype over the bytes, not `miden_protocol::transaction::TransactionId`, because the
/// relayer library stays Miden-free until the submit slice (only the tests reach for the protocol
/// crate today). That slice converts at its own boundary; the log's on-disk shape does not change
/// when it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the rendering an operator pastes back out of a log or a block explorer: 64 hex
    /// characters, upper or lower case, with or without the `0x` prefix.
    ///
    /// # Errors
    /// [`RelayerError::MalformedHex`] (field [`HexField::TxId`]) — not hex. The decode goes through
    /// the crate's ONE hex taxonomy, not a second parallel one.
    /// [`RelayerError::BadTxIdLength`] — hex, but not 32 bytes. A truncated id in the log is a mint
    /// nobody can look up again.
    pub fn from_hex(rendered: &str) -> Result<Self, RelayerError> {
        let body = rendered
            .strip_prefix("0x")
            .or_else(|| rendered.strip_prefix("0X"))
            .unwrap_or(rendered);

        let bytes = hex::decode(body).map_err(|source| RelayerError::MalformedHex {
            field: HexField::TxId,
            source,
        })?;

        let sized: [u8; 32] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| RelayerError::BadTxIdLength {
                    actual: bytes.len(),
                })?;

        Ok(Self(sized))
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// Where a nonce sits between "Circle published an attestation for it" and "the mint is on chain".
///
/// The machine, and every edge it has:
///
/// ```text
///                        ┌──────────────────────────► AlreadyMinted (terminal)
///                        │                                   ▲
///     claim_nonce        │                                   │
///  (a fresh nonce)       │                                   │
///          │             │                                   │
///          ▼             │                                   │
///       Pending ─────────┴───────────────────────► Submitted ┴──────► Committed (terminal)
///          │  ▲                                       │
///          │  │ claim_nonce (the RETRY claim)         │
///          ▼  │                                       │
///        Failed ◄─────────────────────────────────────┘
/// ```
///
/// * `Pending` — claimed; a mint is being built or submitted right now. It BLOCKS a second attempt,
///   which is what makes the claim a claim.
/// * `Submitted` — a Miden transaction carrying the mint went out; its id is in the record.
/// * `Committed` — that transaction is in a block. Terminal.
/// * `AlreadyMinted` — the chain says the nonce is already in `usedNonces`: the on-chain safety
///   backstop already fired. Terminal, because another attempt could only fail the same assert.
/// * `Failed` — the attempt did not mint. It is the ONE status that does not block a retry: treating
///   a transient submit failure as "submitted" would strand the deposit forever, and a redundant
///   attempt is bounded by the on-chain nonce assert.
///
/// The edges that are deliberately ABSENT are the design:
/// * nothing leaves a terminal status — a settled mint cannot be re-opened;
/// * there is no `Submitted → Submitted` — that is the double-submit the seam exists to prevent;
/// * there is no `Failed → Submitted` — the way out of `Failed` is the ATOMIC re-claim
///   (`claim_nonce`, the `Failed → Pending` edge), never a bare submission. A caller that reads "not
///   submitted" and then submits is running the read-then-write race, and this is what makes that
///   spelling impossible rather than merely discouraged;
/// * `Pending` is reachable ONLY from a claim (fresh insert, or the retry edge) — a record cannot be
///   pushed back into an owned state by any other API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubmissionStatus {
    Pending,
    Submitted,
    Committed,
    AlreadyMinted,
    Failed,
}

impl SubmissionStatus {
    /// The stable on-disk token. Changing one of these strings changes the schema — bump
    /// [`crate::idempotency::STORE_SCHEMA_VERSION`] if it ever happens.
    pub(super) const fn as_token(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Committed => "committed",
            Self::AlreadyMinted => "already_minted",
            Self::Failed => "failed",
        }
    }

    /// The inverse of [`Self::as_token`]. An unknown token is CORRUPTION, never a default: guessing
    /// "not submitted" would re-mint a deposit that may already be on chain, and guessing the other
    /// way would strand one.
    pub(super) fn from_token(token: &str) -> Result<Self, RelayerError> {
        match token {
            "pending" => Ok(Self::Pending),
            "submitted" => Ok(Self::Submitted),
            "committed" => Ok(Self::Committed),
            "already_minted" => Ok(Self::AlreadyMinted),
            "failed" => Ok(Self::Failed),
            unknown => Err(RelayerError::CorruptStoreRecord {
                detail: format!("`{unknown}` is not a submission status this build knows"),
            }),
        }
    }

    /// Whether a nonce in this status must NOT be submitted again — the question
    /// [`crate::idempotency::IdempotencyStore::is_nonce_submitted`] answers, and the same predicate
    /// that decides whether a re-observation is a re-claim.
    ///
    /// Everything blocks except [`Self::Failed`]: an in-flight, submitted, committed or
    /// already-minted nonce has nothing to gain from another attempt, while a failed one has never
    /// minted and must be retryable.
    pub fn blocks_resubmission(self) -> bool {
        !matches!(self, Self::Failed)
    }

    /// Whether the mint is settled: on chain ([`Self::Committed`]), or the chain has told us the
    /// nonce was already minted ([`Self::AlreadyMinted`]). A settled record has no outgoing edge.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::AlreadyMinted)
    }

    /// The machine, in one place — every edge in the diagram above, and nothing else.
    pub(super) fn can_transition_to(self, to: Self) -> bool {
        match (self, to) {
            // a settled mint stays settled
            (from, _) if from.is_terminal() => false,
            // the RETRY claim: the only way out of Failed, and the only way back into an owned state
            (Self::Failed, Self::Pending) => true,
            // the mint went out
            (Self::Pending, Self::Submitted) => true,
            // ... and landed
            (Self::Submitted, Self::Committed) => true,
            // it did not mint: back into the retryable pool. A failure can be recorded whether the
            // transaction was sent or not, and a repeated failure just re-stamps the record
            (Self::Pending | Self::Submitted | Self::Failed, Self::Failed) => true,
            // the chain says the nonce is spent — learnable at any pre-terminal point
            (_, Self::AlreadyMinted) => true,
            // no commit without a submission; no re-submit of an in-flight transaction; no submit
            // that skipped the retry claim; no other route back to Pending
            _ => false,
        }
    }
}

impl fmt::Display for SubmissionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// One nonce's entry in the submitted-nonce log.
///
/// The fields are `pub(super)` — writable only inside the seam, which is the one place that owns a
/// SQLite transaction — and read from outside through the accessors below. A caller that could
/// mutate a record in place could un-record a mint.
///
/// `timestamp` is the time of the LAST status change. A re-observation of an in-flight nonce is not
/// a change: it does not touch the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub(super) nonce_key: [u8; 32],
    pub(super) attestation_message_hash: [u8; 32],
    pub(super) submitted_tx_id: Option<TxId>,
    pub(super) block_num: Option<u32>,
    pub(super) status: SubmissionStatus,
    pub(super) timestamp: u64,
}

impl IdempotencyRecord {
    /// The DepositIntent `nonce` (DC-1 field 9) — the key the on-chain `usedNonces` map is keyed by
    /// (through unit-04's `bytes32_to_storage_map_key`, which this crate never re-derives).
    pub fn nonce_key(&self) -> &[u8; 32] {
        &self.nonce_key
    }

    /// The attestation envelope's `messageHash` — `keccak256(payload)` (DC-2). It BINDS the record to
    /// one attestation: a second attestation claiming the same nonce with a different hash is refused
    /// rather than allowed to overwrite it. It is also the handle a retry re-fetches the payload by.
    pub fn attestation_message_hash(&self) -> &[u8; 32] {
        &self.attestation_message_hash
    }

    /// The Miden transaction the mint went out in — `None` until it does. It SURVIVES a failure and a
    /// retry claim: it is the evidence of what was actually sent, and a new submission replaces it.
    pub fn submitted_tx_id(&self) -> Option<&TxId> {
        self.submitted_tx_id.as_ref()
    }

    /// The block that transaction committed in — `None` until it does.
    pub fn block_num(&self) -> Option<u32> {
        self.block_num
    }

    pub fn status(&self) -> SubmissionStatus {
        self.status
    }

    /// When the record last CHANGED status (Unix seconds, from the store's
    /// [`Clock`](crate::idempotency::Clock)).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// What [`crate::idempotency::IdempotencyStore::claim_nonce`] answered. The caller mints on
/// [`Self::Claimed`] and on nothing else — the whole dedup, expressed as a type rather than as a
/// discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This observer owns the nonce and must mint it. Either it was never seen before (a fresh
    /// `Pending` record), or its previous attempt FAILED and this observer won the retry — the two
    /// are the same instruction, so they are the same variant. (The record tells them apart: a retry
    /// claim carries the failed attempt's transaction id.)
    Claimed(IdempotencyRecord),
    /// The nonce is already owned or already settled — a re-poll of the same attestation, or another
    /// observer got there first. NO second mint attempt follows.
    AlreadySeen(IdempotencyRecord),
}

impl ClaimOutcome {
    /// Whether this observer won the claim — i.e. whether it, and only it, may mint.
    pub fn is_claimed(&self) -> bool {
        matches!(self, Self::Claimed(_))
    }

    /// The record, either way.
    pub fn record(&self) -> &IdempotencyRecord {
        match self {
            Self::Claimed(record) | Self::AlreadySeen(record) => record,
        }
    }
}
