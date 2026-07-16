//! The burn-evidence assembler (`DC-8`, §10.7) — and the honesty of what it tells Circle.
//!
//! `INV-BURN-EVIDENCE-TRUST` is one sentence: **retrievable ≠ cryptographically proved.** Circle
//! releases native USDC against the package this module builds, so every label on it is a claim the
//! partner is making about what Miden can and cannot prove. Getting one wrong in the generous
//! direction releases money against a burn that did not happen. This is `DEV-7`, the **HIGHEST-RISK**
//! deviation in the integration, and it is **OPEN** — the tx-linkage is labelled to Circle as
//! node-trusted, and whether Circle accepts a Miden tx id as a `burnTxId` at all, with or without the
//! evidence behind it, is Circle's to answer.
//!
//! # The two overclaims this module exists to make impossible
//!
//! **Strength.** `SyncTransactions` tx-linkage (R-9/R-10) and the `SyncNullifiers` spend observation
//! (R-5) come with no inclusion proof — the node says so and that is the whole of it. Labelling
//! either CRYPTOGRAPHIC would tell Circle the partner can prove what it can only repeat.
//!
//! **Scope**, which is subtler and worse. A `GetNotesById` inclusion proof IS cryptographic, and what
//! it proves is that the note was **created**. It is silent on whether the note was ever consumed.
//! "This note exists and was created in block N" is not "this burn happened" — so a CRYPTOGRAPHIC
//! label must never be readable as a confirmed burn. [`ProvenFact`] is the type-level answer: every
//! element carries what it proves alongside how strongly, and no element is both cryptographic and a
//! consumption claim. [`EvidencePackage::consumption_trust`] answers the question Circle actually
//! cares about — how well the *burn* is proved — and today the answer is always NODE-TRUSTED.
//!
//! A genuine burn record is therefore `note_id` (**what** — creation, cryptographic) **plus** a
//! consumption signal (**that it burned** — node-trusted). Neither half is sufficient. And nothing
//! here settles a withdrawal: only Circle's own terminal `finalized` does that (§10.10).
//!
//! # There is no `burnTxId`-only path, and its absence is structural
//!
//! `GetTransactionById` / tx-by-hash **DOES NOT EXIST** on Miden (R-8) — so a `burnTxId`-only
//! redemption is not merely discouraged, it is unresolvable. `burnTxId` alone proves nothing. This
//! module encodes that as an absence rather than a rule to remember: [`BurnEvidenceReads`] has no
//! by-hash method, and [`assemble_evidence`]'s only entry key is a [`NoteId`], so there is no call
//! that could resolve a burn from a transaction id (anti-`ASG-4`). If Circle ever requires
//! cryptographic by-hash resolution, the paths are sponsoring `U1` (`OPTIONAL-UPSTREAM`) or running
//! the full-block upgrade — both `DEV-7`-gated, neither assumed here.
//!
//! # Fail-closed
//!
//! Evidence that is missing, ambiguous, or self-contradicting yields
//! [`EvidenceError::ReconciliationRequired`], never a package. The vocabulary is deliberately W7's —
//! the posture it established for a `409` that names no withdrawal — because "the safe answer when we
//! cannot tell" should have exactly one name in this service.
//!
//! # This slice's boundary
//!
//! [`BurnEvidenceReads`] is a crate-local port, and the adapter behind it in the tests is a unit
//! stand-in. `miden-client` has no v0.16 release, so the real reads are **W10** (PARKED). The port is
//! shaped as a 1:1 image of the three RPCs the real client will expose — `GetNotesById`,
//! `SyncTransactions(faucet_id)`, `SyncNullifiers` — so W10 maps onto it without reshaping the
//! assembler. The labels below encode the researched v15/`next` trust model; W10 re-verifies them
//! against the real v16 node. **If v16 evidence ever contradicts a label — stronger OR weaker — that
//! is a spec-level event: stop and surface it. Labels change through a `DEV-7` decision, never
//! silently.**

use core::fmt;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, NoteInclusionProof, Nullifier};
use miden_protocol::transaction::TransactionId;

use crate::error::Cause;
use crate::types::EvidencePackage;

// THE READ PORT
// ================================================================================================

/// The three Miden reads the evidence rests on — the crate's port onto a v16 client that does not
/// exist yet (W10, PARKED).
///
/// Each method is one RPC, kept a 1:1 image of it so the real adapter is a translation rather than a
/// redesign. Note what is **not** here, and cannot be added: there is no by-transaction-hash lookup,
/// because Miden has none (`GetTransactionById` does not exist, R-8). A `burnTxId` is something this
/// module *outputs*; it is never something it can look anything up by (anti-`ASG-4`).
pub trait BurnEvidenceReads {
    /// `GetNotesById([note_id])` — the note, its details, and its inclusion proof.
    ///
    /// # Errors
    /// The read failed. An unknown note id is a failed read, not an answer.
    fn note_by_id(&self, note_id: NoteId) -> Result<NoteRecord, EvidenceReadError>;

    /// `SyncTransactions(account_ids = [faucet_id])` — the faucet's transactions. **NODE-TRUSTED**:
    /// the node reports these and nothing proves them (R-9/R-10).
    ///
    /// The stream contains the transaction that CREATED the burn note as well as the one that
    /// consumed it. Telling them apart is [`assemble_evidence`]'s job and is not optional.
    ///
    /// # Errors
    /// The read failed.
    fn faucet_transactions(
        &self,
        faucet_id: AccountId,
    ) -> Result<Vec<TransactionRecord>, EvidenceReadError>;

    /// `SyncNullifiers([nullifier])` — whether the node has seen the nullifier spent.
    /// **NODE-TRUSTED**: there is no inclusion proof for a spend, and no `CheckNullifiers` RPC to
    /// cross-check it with (R-5).
    ///
    /// # Errors
    /// The read failed.
    fn nullifier_status(&self, nullifier: Nullifier) -> Result<NullifierRecord, EvidenceReadError>;
}

/// A `GetNotesById` reply for one note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRecord {
    /// The note the node is answering about. [`assemble_evidence`] checks it is the one that was
    /// asked about — attaching another burn's evidence to this one would be durable false evidence.
    pub note_id: NoteId,

    /// `None` for a PRIVATE note: the node holds no details, so the burn is unobservable and there is
    /// nothing to assemble (§10.11, V-2).
    pub details: Option<PublicNoteDetails>,
}

/// The details a PUBLIC note carries — the cryptographic half of the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNoteDetails {
    /// The note's nullifier, derived from the note itself. It is the key the spend observation and
    /// the tx-linkage are both looked up by.
    pub nullifier: Nullifier,

    /// The proof of the note's membership in its block's note root (R-2) — **CRYPTOGRAPHIC**, and it
    /// proves CREATION. The package's `block_num` is read out of this proof's location and out of
    /// nothing else, which is what entitles that field to a cryptographic label.
    pub inclusion_proof: NoteInclusionProof,
}

/// One `SyncTransactions` record. **NODE-TRUSTED** in its entirety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRecord {
    /// The transaction id — a candidate `burnTxId` (`DEV-7`: whether Circle accepts one is OPEN).
    pub transaction_id: TransactionId,

    /// The account the transaction ran against.
    pub account_id: AccountId,

    /// The block it landed in — node-reported, and never the source of the package's `block_num`.
    pub block_num: BlockNumber,

    /// The nullifiers of the notes this transaction CONSUMED. This is the only field that can link a
    /// transaction to a burn.
    pub input_note_nullifiers: Vec<Nullifier>,

    /// Proofs for the notes this transaction CREATED.
    ///
    /// **These do not prove input-note consumption** (R-9/R-10) — the field is here because the real
    /// RPC carries it, and it is named `output_note_proofs` rather than `note_proofs` so that reading
    /// it as consumption evidence has to be a deliberate act. The burn note's own creating
    /// transaction appears in the faucet's stream carrying the burn note right here; matching a
    /// transaction on "does it mention our note" would select it and publish the note's MINT as the
    /// transaction that burned it.
    pub output_note_proofs: Vec<(NoteId, NoteInclusionProof)>,
}

/// A `SyncNullifiers` observation. **NODE-TRUSTED** (R-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierRecord {
    /// The nullifier the node is answering about.
    pub nullifier: Nullifier,

    /// `Some(block)` — the node reports the nullifier spent there. `None` — the node does not report
    /// it spent, which is not proof it was not: it is the absence of a signal, and absence is
    /// handled by refusing to assemble rather than by guessing.
    pub spent_in_block: Option<BlockNumber>,
}

// THE ASSEMBLER
// ================================================================================================

/// Assembles the `DC-8` burn-evidence package for the burn note `note_id` burned by `faucet_id`.
///
/// The entry key is the **note id**, and that is the anti-`ASG-4` rule in the signature: evidence is
/// resolved from the note outward. There is no by-`burnTxId` entry point, because Miden offers no
/// by-hash lookup to build one on (R-8).
///
/// What it does, and why in this order:
///
/// 1. **`GetNotesById`** — the note must be public and committed. Its inclusion proof is the
///    CRYPTOGRAPHIC creation evidence, and the package's `block_num` comes from that proof's
///    location. This step proves the note EXISTS; it proves nothing about a burn.
/// 2. **`SyncNullifiers`** — the spend observation. Without it there is no reason to believe the
///    note was ever consumed, and a note that exists is not a burn.
/// 3. **`SyncTransactions(faucet_id)`** — the linkage, resolved by finding the faucet transaction
///    whose INPUT nullifiers contain the burn note's. Output-note proofs are not consulted; they
///    would select the transaction that minted the note.
///
/// Steps 2 and 3 must agree with each other and with step 1. Where they do not, the node has
/// contradicted itself and there is no honest package to build.
///
/// # Errors
/// * [`EvidenceError::Read`] — one of the three reads failed. Not an answer; not "no burn".
/// * [`EvidenceError::NoteNotObservable`] — the note is private (`details = None`), so the burn is
///   unobservable (§10.11).
/// * [`EvidenceError::WrongNoteAnswered`] / [`EvidenceError::WrongNullifierAnswered`] — the port
///   answered about something else.
/// * [`EvidenceError::ReconciliationRequired`] — the reads are incomplete, ambiguous, or mutually
///   inconsistent. Fail-closed: an operator reconciles it, and no half-evidenced burn goes to Circle.
pub fn assemble_evidence<P>(
    port: &P,
    note_id: NoteId,
    faucet_id: AccountId,
) -> Result<EvidencePackage, EvidenceError>
where
    P: BurnEvidenceReads + ?Sized,
{
    // 1. The note, and its CRYPTOGRAPHIC creation proof.
    let record = port.note_by_id(note_id)?;
    if record.note_id != note_id {
        return Err(EvidenceError::WrongNoteAnswered {
            asked: note_id,
            answered: record.note_id,
        });
    }
    let details = record
        .details
        .ok_or(EvidenceError::NoteNotObservable { note_id })?;

    let nullifier = details.nullifier;
    let create_block = details.inclusion_proof.location().block_num();

    // 2. The spend observation. NODE-TRUSTED, and required: a created note is not a burned one.
    let spend = port.nullifier_status(nullifier)?;
    if spend.nullifier != nullifier {
        return Err(EvidenceError::WrongNullifierAnswered {
            asked: nullifier,
            answered: spend.nullifier,
        });
    }
    let reconciliation = |reason| EvidenceError::ReconciliationRequired { note_id, reason };
    let spend_block = spend
        .spent_in_block
        .ok_or_else(|| reconciliation(AmbiguityReason::NoSpendObserved))?;

    // A note is created in one block and can only be consumed in a later one (INV-TWO-BLOCK-BURN).
    // A node reporting otherwise is reporting something the chain does not do, so the report is not
    // evidence of anything.
    if spend_block <= create_block {
        return Err(reconciliation(
            AmbiguityReason::ConsumptionPrecedesCreation {
                create_block: create_block.as_u32(),
                spend_block: spend_block.as_u32(),
            },
        ));
    }

    // 3. The linkage — the faucet transaction that CONSUMED this note. Matched on input nullifiers
    //    and on nothing else: `output_note_proofs` would match the transaction that created the note
    //    (R-9/R-10), which is in this very stream.
    let transactions = port.faucet_transactions(faucet_id)?;
    let consuming = transactions
        .iter()
        .filter(|tx| tx.account_id == faucet_id && tx.input_note_nullifiers.contains(&nullifier));

    // Which transaction ids claim this burn. Ids first, bodies second: the two questions are
    // different, and answering them together is what makes an implementation order-dependent.
    //
    // The same transaction reported twice is one transaction — a duplicate row is a node artifact,
    // and refusing a well-evidenced burn over one would be fail-closed in name only. Two DIFFERENT
    // transactions claiming the same nullifier is the real ambiguity. Collected rather than
    // `dedup`ed, which would only collapse ADJACENT duplicates: nothing promises the node groups its
    // rows.
    let mut claimed_ids: Vec<TransactionId> = Vec::new();
    for tx in consuming {
        if !claimed_ids.contains(&tx.transaction_id) {
            claimed_ids.push(tx.transaction_id);
        }
    }

    let burn_tx_id = match claimed_ids.as_slice() {
        [] => return Err(reconciliation(AmbiguityReason::NoConsumingTransaction)),
        [only] => *only,
        many => {
            return Err(reconciliation(
                AmbiguityReason::AmbiguousConsumingTransactions { count: many.len() },
            ))
        }
    };

    // One id, but does the node tell ONE story about it? Every row carrying that id must be the same
    // row. If two disagree — a different block, a different set of consumed notes, a different
    // account — then at least one is false, and there is no way to tell which.
    //
    // Collapsing by id and keeping the first would hide exactly this: with the honest row first the
    // burn is published, with the impostor first it is refused, and the package's contents become a
    // function of the node's row order. That is nondeterministic re-assembly on the path that
    // releases money, so contradicting rows fail closed instead.
    //
    // The scan is over the WHOLE stream, not just the rows that passed the filter above: a second row
    // for this id saying it consumed nothing would have been dropped by the filter, leaving one
    // "clean" candidate and the contradiction unnoticed.
    let rows: Vec<&TransactionRecord> = transactions
        .iter()
        .filter(|tx| tx.transaction_id == burn_tx_id)
        .collect();
    let burn_tx = rows
        .first()
        .copied()
        .expect("the id was taken from a row of this same stream");
    if rows.iter().any(|row| *row != burn_tx) {
        return Err(reconciliation(
            AmbiguityReason::ContradictoryTransactionRows { count: rows.len() },
        ));
    }

    // The two node-trusted reads must agree. Neither can be checked, so a disagreement leaves nothing
    // to choose between — and choosing anyway would publish a linkage no evidence supports.
    if burn_tx.block_num != spend_block {
        return Err(reconciliation(
            AmbiguityReason::SpendBlockDisagreesWithLinkage {
                spend_block: spend_block.as_u32(),
                linkage_block: burn_tx.block_num.as_u32(),
            },
        ));
    }

    Ok(EvidencePackage::new(
        burn_tx.transaction_id.to_hex(),
        note_id.as_word().as_bytes(),
        nullifier.as_word().as_bytes(),
        // From the inclusion proof's location — the only source that earns a CRYPTOGRAPHIC label.
        create_block.as_u32(),
    ))
}

/// The OPTIONAL full-block path (§10.7, `IMPL-FULLBLOCK-PATH`) — **deferred, and not implemented.**
///
/// It is the one route that would upgrade the tx-linkage from node-trusted to cryptographic:
/// `GetBlockByNumber{include_proof}` → validate the `SignedBlock` → recompute the header's
/// `tx_commitment` from `OrderedTransactionHeaders` (a sequential hash over `(transaction_id,
/// account_id)` tuples) → confirm `(burnTxId, faucet_id)` is committed → confirm that header's
/// `input_notes` contains the burn nullifier (R-11..R-13). It is P2, it is labelled `REQUIRES
/// IMPLEMENTATION VALIDATION`, and the question of whether Circle needs it is `DEV-7`. All of that
/// stays OPEN, so the path is not built — [`BurnEvidenceReads`] deliberately exposes no block read to
/// build it on.
///
/// It returns a typed error rather than a panicking placeholder. A panic is not a deferral: this
/// service releases money, the function is public, and a caller reaching a path that was never built
/// should get a refusal it can handle, not a dead process (`return-error-not-panic`).
///
/// # Errors
/// Always [`EvidenceError::FullBlockUpgradeNotImplemented`]. The labels on `package` are unchanged —
/// nothing ran, so nothing is upgraded.
pub fn full_block_upgrade(package: &EvidencePackage) -> Result<EvidencePackage, EvidenceError> {
    let _ = package;
    Err(EvidenceError::FullBlockUpgradeNotImplemented)
}

// ERRORS
// ================================================================================================

/// Why the evidence could not be assembled honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceError {
    /// One of the three reads failed. This is an absence of INFORMATION, and it is deliberately not
    /// collapsed into "no burn" — the two call for different operator responses.
    Read(EvidenceReadError),

    /// The note is private: `GetNotesById` returned `details = None`, so the burn is unobservable
    /// (§10.11, V-2). A burn note must be `NoteType::Public` to be evidence at all
    /// (`INV-PUBLIC-BURN-OBSERVABILITY`).
    NoteNotObservable { note_id: NoteId },

    /// The port answered about a different note than the one asked about.
    WrongNoteAnswered { asked: NoteId, answered: NoteId },

    /// The port answered about a different nullifier than the one asked about.
    WrongNullifierAnswered {
        asked: Nullifier,
        answered: Nullifier,
    },

    /// The evidence is incomplete, ambiguous, or self-contradicting — **so the burn is blocked for an
    /// operator rather than reported as anything.**
    ///
    /// This is the fail-closed posture W7 established for a `409` that names no withdrawal, under the
    /// same name on purpose. A withheld withdrawal costs a burn its latency; a withdrawal released on
    /// evidence nobody could stand behind costs the reserve.
    ReconciliationRequired {
        note_id: NoteId,
        reason: AmbiguityReason,
    },

    /// The full-block upgrade is deferred (P2, `IMPL-FULLBLOCK-PATH`, OPEN).
    FullBlockUpgradeNotImplemented,
}

/// What about the evidence could not be resolved. Each variant is a state in which an honest package
/// cannot be built, named so an operator knows what to go and look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmbiguityReason {
    /// The node does not report the nullifier spent. The note's creation is cryptographically proved
    /// and that is not a burn — the note may simply be sitting there unspent.
    NoSpendObserved,

    /// The nullifier is reported spent, but no transaction of the faucet's claims to have consumed
    /// it. The `burnTxId` is unresolved, and there is no by-hash lookup to resolve it with (R-8).
    NoConsumingTransaction,

    /// Two or more DIFFERENT transactions claim to have consumed the same nullifier. One of them is
    /// wrong and nothing available here can say which.
    AmbiguousConsumingTransactions { count: usize },

    /// The node reported ONE transaction id with two or more different bodies — same id, disagreeing
    /// on the block it landed in, on what it consumed, or on whose account it ran against.
    ///
    /// This is a contradiction rather than a duplicate, and the difference is the whole point: an
    /// identical row repeated is a node artifact and collapses harmlessly, whereas two different
    /// stories about one transaction mean at least one of them is false. Picking either — including
    /// by the accident of which arrived first — publishes a linkage the node itself contradicted, and
    /// makes the package's contents depend on row order.
    ContradictoryTransactionRows { count: usize },

    /// The spend observation and the tx-linkage name different blocks. Both are node-trusted, neither
    /// is checkable, and they contradict each other.
    SpendBlockDisagreesWithLinkage {
        spend_block: u32,
        linkage_block: u32,
    },

    /// The reported spend is in the creation block or earlier — a state the chain does not produce
    /// (`INV-TWO-BLOCK-BURN`).
    ConsumptionPrecedesCreation { create_block: u32, spend_block: u32 },
}

/// A failed Miden read, naming the RPC it failed on and preserving the underlying cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReadError {
    rpc: &'static str,
    cause: Cause,
}

impl EvidenceReadError {
    /// Preserves `cause` as the reason `rpc` failed.
    pub fn new(rpc: &'static str, cause: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self {
            rpc,
            cause: Cause::new(cause),
        }
    }

    /// The RPC that failed, as the node's API names it.
    pub fn rpc(&self) -> &'static str {
        self.rpc
    }
}

impl fmt::Display for EvidenceReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} read failed: {}", self.rpc, self.cause)
    }
}

impl core::error::Error for EvidenceReadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.cause.as_error())
    }
}

impl From<EvidenceReadError> for EvidenceError {
    fn from(error: EvidenceReadError) -> Self {
        Self::Read(error)
    }
}

impl fmt::Display for AmbiguityReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSpendObserved => {
                write!(f, "the node does not report the burn nullifier spent")
            }
            Self::NoConsumingTransaction => write!(
                f,
                "no faucet transaction reports consuming the burn note, and a burnTxId cannot be \
                 resolved by hash"
            ),
            Self::AmbiguousConsumingTransactions { count } => write!(
                f,
                "{count} different transactions claim to have consumed the burn note"
            ),
            Self::ContradictoryTransactionRows { count } => write!(
                f,
                "the node reported one transaction id with {count} different bodies"
            ),
            Self::SpendBlockDisagreesWithLinkage {
                spend_block,
                linkage_block,
            } => write!(
                f,
                "the spend is reported in block {spend_block} but the consuming transaction is in \
                 block {linkage_block}"
            ),
            Self::ConsumptionPrecedesCreation {
                create_block,
                spend_block,
            } => write!(
                f,
                "the burn note is reported spent in block {spend_block}, at or before the block \
                 {create_block} that created it"
            ),
        }
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => error.fmt(f),
            Self::NoteNotObservable { note_id } => write!(
                f,
                "burn note {} is not public, so the burn is unobservable",
                note_id.to_hex()
            ),
            Self::WrongNoteAnswered { asked, answered } => write!(
                f,
                "asked about note {} and was answered about {}",
                asked.to_hex(),
                answered.to_hex()
            ),
            Self::WrongNullifierAnswered { asked, answered } => write!(
                f,
                "asked about nullifier {} and was answered about {}",
                asked.to_hex(),
                answered.to_hex()
            ),
            Self::ReconciliationRequired { note_id, reason } => write!(
                f,
                "burn note {} requires reconciliation: {reason}",
                note_id.to_hex()
            ),
            Self::FullBlockUpgradeNotImplemented => write!(
                f,
                "the optional full-block evidence upgrade is not implemented"
            ),
        }
    }
}

impl core::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}
