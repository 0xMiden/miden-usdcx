//! The OUTCOME types the orchestration produces: what became of one attestation ([`Disposition`]),
//! the reported record of it ([`CycleEntry`]), and a whole cycle's account ([`CycleReport`]).
//!
//! Split out of `cycle/mod.rs` so the orchestration stays within its file-size ceiling. These are
//! the vocabulary the no-silent-drops rule is stated in — a `Disposition` renders a non-empty
//! reason for every arm, and a `CycleReport`'s terminal counters partition its `fetched()` — so
//! they live together, apart from the control flow that produces them.

use crate::error::RelayerError;
use crate::idempotency::{SubmissionStatus, TxId};

// THE OUTCOME OF ONE ATTESTATION
// ================================================================================================

/// What happened to ONE fetched attestation. **Every** fetched attestation gets exactly one.
///
/// Closed, and NOT `#[non_exhaustive]`: five of the six are not a mint, and they are exactly the
/// ones a catch-all arm would flatten into "handled". Nothing here means the deposit is on chain
/// except [`Self::Submitted`] — and even that means "the node took the transaction", which is why
/// the idempotency log records `Submitted` and not `Committed`.
#[derive(Debug, Clone, PartialEq)]
pub enum Disposition {
    /// A mint note was built and the node accepted it, in `tx_id`. The log holds it.
    Submitted { tx_id: TxId },
    /// The on-chain `usedNonces` assert fired (the on-chain replay guard) — this deposit was
    /// already minted, by an earlier attempt or a competing relayer. The SAFETY backstop, observed.
    /// Terminal, and not a defect.
    AlreadyMinted,
    /// The idempotency store had already recorded this nonce, in `status` — a re-poll of the same
    /// window, another observer's claim, or a restart. **No second mint was attempted.** A LIVENESS
    /// backstop: the authoritative one is the on-chain nonce assert above.
    Duplicate { status: SubmissionStatus },
    /// Permanently refused: a structurally invalid DepositIntent (the structural DepositIntent
    /// check), a domain/token fast-fail (check 5), a note the shared encoding crate's factory would
    /// not build, or a node's permanent refusal. It will never be submitted, and the error says
    /// why.
    Rejected(RelayerError),
    /// A TRANSIENT failure left it for a later cycle — the store was busy, the node was behind. It
    /// is neither minted nor refused, and the deposit intent has no expiry, so the next cycle
    /// re-claims it.
    Deferred(RelayerError),
    /// An operator must resolve it: an answer this relayer is not allowed to guess at. Today the
    /// one case is two different attestations claiming one nonce — at most one is the deposit that
    /// happened, and picking wrong either strands a deposit or re-mints one.
    ReconciliationRequired(RelayerError),
}

impl Disposition {
    /// A short, STABLE slug — what an operator's alert matches on. Stability is the point: renaming
    /// one silently breaks every alert built on it.
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Submitted { .. } => "submitted",
            Self::AlreadyMinted => "already-minted",
            Self::Duplicate { .. } => "duplicate",
            Self::Rejected(_) => "rejected",
            Self::Deferred(_) => "deferred",
            Self::ReconciliationRequired(_) => "reconciliation-required",
        }
    }

    /// Why, in one line — the no-silent-drops obligation, rendered.
    ///
    /// DERIVED, never stored: the refusing arms render their typed error, the settling arms render
    /// the fact. So there is no constructor that can produce a disposition with nothing to say, and
    /// "logged with a reason" is a property of the type rather than of every call site remembering.
    pub fn reason(&self) -> String {
        match self {
            Self::Submitted { tx_id } => format!("submitted to the miden node in tx {tx_id}"),
            Self::AlreadyMinted => {
                "the on-chain nonce assert reports this deposit is already minted".to_string()
            }
            Self::Duplicate { status } => {
                format!("the idempotency store already holds this nonce as {status}")
            }
            Self::Rejected(error) | Self::Deferred(error) | Self::ReconciliationRequired(error) => {
                error.to_string()
            }
        }
    }

    /// Whether an operator must be told. A refusal and a conflict yes; a duplicate, a mint, and the
    /// chain's own nonce trap no — those are the system working (the alert policy).
    pub(crate) fn alerts(&self) -> bool {
        matches!(self, Self::Rejected(_) | Self::ReconciliationRequired(_))
    }
}

/// One fetched attestation and what became of it.
///
/// Constructed only by the orchestration, so an entry cannot exist without an attestation behind it
/// — and an attestation cannot pass through the loop without producing one.
#[derive(Debug, Clone, PartialEq)]
pub struct CycleEntry {
    /// How this attestation is NAMED, in the report and in the log: the `0x`-hex of the verified
    /// `messageHash` when the envelope check passed, and the RAW wire value Circle sent when it did
    /// not. Held as the rendered identifier rather than as 32 bytes because a refused element may
    /// have no 32 bytes to hold — and fabricating some (zeros for a `messageHash` that is not 32
    /// hex digits) would give every such element the same name, which is exactly the traceability
    /// the entry exists to provide.
    message_hash: String,
    disposition: Disposition,
}

impl CycleEntry {
    /// Pairs a fetched attestation's VERIFIED `messageHash` with what became of it — the
    /// constructor for everything past the envelope check, where the digest is known to be 32
    /// bytes.
    pub(crate) fn new(message_hash: [u8; 32], disposition: Disposition) -> Self {
        Self {
            message_hash: format!("0x{}", hex::encode(message_hash)),
            disposition,
        }
    }

    /// Pairs a page element the envelope check REFUSED with its refusal, naming it by the raw wire
    /// `messageHash` Circle sent for it, verbatim. That string is the only name such an element has:
    /// its `messageHash` is unverified and may not even be 32 hex digits, so it is reported as it
    /// arrived rather than repaired into something that looks verified.
    pub(crate) fn refused(message_hash: String, disposition: Disposition) -> Self {
        Self {
            message_hash,
            disposition,
        }
    }

    /// The `messageHash` as an operator greps for it — the identifier that makes this fate
    /// traceable to one deposit, and to the element Circle actually served.
    pub fn message_hash_hex(&self) -> String {
        self.message_hash.clone()
    }

    /// What happened.
    pub fn disposition(&self) -> &Disposition {
        &self.disposition
    }

    /// The stable outcome slug ([`Disposition::outcome`]).
    pub fn outcome(&self) -> &'static str {
        self.disposition.outcome()
    }

    /// Why ([`Disposition::reason`]) — never empty.
    pub fn reason(&self) -> String {
        self.disposition.reason()
    }
}

/// What one cycle did.
///
/// The entries are in PAGE ORDER, one per fetched attestation, so "which deposit was the third one"
/// is answerable — and so `fetched() == entries().len()` is the no-drop invariant, stated where a
/// caller can check it.
#[derive(Debug, Clone, PartialEq)]
pub struct CycleReport {
    remote_domain: u32,
    entries: Vec<CycleEntry>,
    next_cursor: Option<String>,
}

impl CycleReport {
    /// Assembles a cycle's report from its ordered entries and the cursor it advanced to. The ONLY
    /// constructor — `fetched()` is derived from `entries`, never tracked apart, so a count that
    /// could disagree with the entries (the shape of a silent drop) is not representable.
    pub(crate) fn new(
        remote_domain: u32,
        entries: Vec<CycleEntry>,
        next_cursor: Option<String>,
    ) -> Self {
        Self {
            remote_domain,
            entries,
            next_cursor,
        }
    }

    /// The remote domain this cycle polled.
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    /// Every fetched attestation and its fate, in page order.
    pub fn entries(&self) -> &[CycleEntry] {
        &self.entries
    }

    /// How many attestations were fetched. Equal to `entries().len()` BY CONSTRUCTION — the count
    /// is not tracked separately, because a count that could disagree with the entries is a count
    /// that eventually does, and the gap between them would be exactly the silent drop.
    pub fn fetched(&self) -> usize {
        self.entries.len()
    }

    /// The `Link`-header `next` cursor, persisted for the next poll. `None` ends the scan.
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }

    /// Whether this page was the last one (the documented end-of-scan condition: `next == None`).
    pub fn scan_complete(&self) -> bool {
        self.next_cursor.is_none()
    }

    /// Entries whose outcome is `outcome`. A `fold` rather than a `filter().count()` on purpose:
    /// the no-silent-drops sweep reads this file for the shapes that can lose an element, and it
    /// cannot tell a `filter` over reported entries from a `filter` over the fetched page. Keeping
    /// the file free of them keeps the sweep exact instead
    /// of clever.
    fn count(&self, outcome: &str) -> usize {
        self.entries
            .iter()
            .fold(0, |n, entry| n + usize::from(entry.outcome() == outcome))
    }

    /// Attestations minted this cycle.
    pub fn submitted(&self) -> usize {
        self.count("submitted")
    }

    /// Attestations permanently refused.
    pub fn rejected(&self) -> usize {
        self.count("rejected")
    }

    /// Attestations the idempotency gate refused a second mint for.
    pub fn duplicates(&self) -> usize {
        self.count("duplicate")
    }

    /// Attestations the chain reports already minted.
    pub fn already_minted(&self) -> usize {
        self.count("already-minted")
    }

    /// Attestations left for a later cycle by a transient failure.
    pub fn deferred(&self) -> usize {
        self.count("deferred")
    }

    /// Attestations left for an operator.
    pub fn reconciliation_required(&self) -> usize {
        self.count("reconciliation-required")
    }

    /// A one-line count summary the loop emits per cycle, so an operator sees throughput move. The
    /// terminal counters partition `fetched()`, so this line is also the no-drop invariant,
    /// visible.
    pub fn summary(&self) -> String {
        format!(
            "domain={} fetched={} submitted={} rejected={} duplicate={} already_minted={} \
             deferred={} reconciliation_required={} scan_complete={}",
            self.remote_domain,
            self.fetched(),
            self.submitted(),
            self.rejected(),
            self.duplicates(),
            self.already_minted(),
            self.deferred(),
            self.reconciliation_required(),
            self.scan_complete(),
        )
    }
}
