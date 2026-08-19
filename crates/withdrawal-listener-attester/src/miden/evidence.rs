//! **B7's reads** — the `miden-client` implementation of [`BurnEvidenceReads`].
//!
//! Three RPCs, three translations, and not one judgement. Every fail-closed rule about the evidence
//! — the note must be public, a spend must actually be observed, the linkage must be a faucet
//! transaction that consumed THIS nullifier, the reads must not contradict each other — lives in
//! [`assemble_evidence`](crate::evidence::assemble_evidence). This module's whole job is to make
//! the node's answers arrive shaped the way the assembler believes they are.
//!
//! # The three ways a translation could lie
//!
//! * **The note read.** A note the node does not know about is a FAILED READ, not "no burn": the
//!   two call for different operator responses, and collapsing them would report a state nobody
//!   observed. And the ANSWERED note id is carried through as answered, so the assembler's
//!   `WrongNoteAnswered` guard has something to catch — stamping the asked-for id onto the reply
//!   would quietly attach one burn's evidence to another. The reply can also answer about one note
//!   MORE THAN ONCE, and two such rows can disagree about whether the note is observable or about
//!   where it was created, so they are reconciled ([`reconcile_note_reply`]) rather than searched:
//!   the first row is not the answer, it is only the first.
//! * **The spend observation.** `SyncNullifiers` is queried by 16-bit PREFIX, so the reply carries
//!   strangers' nullifiers that happen to share it. Only the exact nullifier is this burn's spend.
//! * **The linkage.** A `SyncTransactions` record carries both what a transaction CONSUMED and what
//!   it CREATED. The burn note's own minting transaction is in the very same stream, so the two
//!   must not mix: consumed nullifiers come from the transaction header's input notes and from
//!   nowhere else.
//!
//! # Node-provided is NODE-TRUSTED — including the inclusion data
//!
//! Everything this module returns is a node's word, and it is labelled as one: [`READ_TRUST`] is
//! `NodeTrusted`, for all three reads. `SyncTransactions` and `SyncNullifiers` obviously carry no
//! proof — but neither does a `GetNotesById` inclusion proof, as far as anything HERE knows. It
//! arrives as proof MATERIAL: no merkle path is checked against an authenticated block header
//! anywhere in this process, so a fabricated one reads exactly like a real one. Unverified is
//! unverified, and a CRYPTOGRAPHIC label belongs only to something this process verified itself.
//!
//! So nothing in this module claims one, and nothing here upgrades a label. Whether Miden's
//! evidence is strong enough — and what strength the package's own elements should therefore carry
//! — is a Circle-owned question, not a consequence of the reads becoming real.
//!
//! # The scan window
//!
//! `SyncTransactions` and `SyncNullifiers` are range queries, and the port's methods are not. The
//! adapter therefore holds the FIRST block it is allowed to look at — the deployment's own starting
//! point — and resolves the upper bound from the node's chain tip on each read, so evidence for a
//! burn that landed a second ago is inside the window rather than just past it.

use async_trait::async_trait;
use miden_client::rpc::domain::note::{CommittedNote, FetchedNote};
use miden_client::rpc::domain::nullifier::NullifierUpdate;
use miden_client::rpc::NodeRpcClient;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::{InputNoteCommitment, TransactionHeader};

use crate::evidence::{
    BurnEvidenceReads, EvidenceReadError, NoteRecord, NullifierRecord, PublicNoteDetails,
    TransactionRecord,
};
use crate::types::ProofStrength;

/// The RPC names this module can fail on, spelled as the node's API spells them.
const GET_NOTES_BY_ID: &str = "GetNotesById";
const SYNC_NULLIFIERS: &str = "SyncNullifiers";
const SYNC_TRANSACTIONS: &str = "SyncTransactions";
const GET_BLOCK_HEADER_BY_NUMBER: &str = "GetBlockHeaderByNumber";

/// What an answer from this module is worth **on its own**: [`ProofStrength::NodeTrusted`], for
/// every one of the three reads.
///
/// The two sync reads carry no proof at all. The note read carries an inclusion proof — and it is
/// node-trusted too, because nothing here verifies it: the merkle path is never checked against an
/// authenticated block header, so what arrives is proof material a node handed over, indistinguishable
/// from a fabricated one. Labelling it CRYPTOGRAPHIC would be claiming a check that did not happen.
///
/// This is the ADAPTER's statement about its own reads. What strength each element of an assembled
/// [`EvidencePackage`](crate::types::EvidencePackage) carries is the documented evidence table's to
/// say, and moving that table is a Circle-owned decision rather than an implementation detail — so
/// this constant exists to be honest about the input, not to overrule the table.
pub const READ_TRUST: ProofStrength = ProofStrength::NodeTrusted;

// THE PURE TRANSLATIONS
// ================================================================================================

/// A `GetNotesById` reply for `asked` → the assembler's [`NoteRecord`].
///
/// `None` means the node returned nothing for the id, and that is an `Err`: an unknown note is an
/// absence of INFORMATION, not evidence that no burn happened. A private note IS an answer, and it
/// answers `details = None` — the node holds no details, so the burn is unobservable.
///
/// The record's `note_id` is the id the node ANSWERED about, never `asked`. That is what lets
/// [`assemble_evidence`](crate::evidence::assemble_evidence) notice a node answering about a
/// different note instead of silently accepting its evidence as this burn's.
///
/// The inclusion proof is carried through exactly as it arrived, and it is [`READ_TRUST`] —
/// NODE-TRUSTED — like every other datum here. Nothing in this function checks it against a block
/// header, so it is the node's word about the note's creation rather than a verified proof of it.
///
/// # Errors
/// [`EvidenceReadError`] when the node returned no note for `asked`.
pub fn note_record(
    asked: NoteId,
    fetched: Option<&FetchedNote>,
) -> Result<NoteRecord, EvidenceReadError> {
    let Some(fetched) = fetched else {
        return Err(EvidenceReadError::new(
            GET_NOTES_BY_ID,
            NoteNotReturned(asked),
        ));
    };

    let details = match fetched {
        FetchedNote::Public(note, inclusion_proof) => Some(PublicNoteDetails {
            // derived from the note itself, not reported alongside it.
            nullifier: note.nullifier(),
            inclusion_proof: inclusion_proof.clone(),
        }),
        FetchedNote::Private(..) => None,
    };

    Ok(NoteRecord {
        note_id: fetched.id(),
        details,
    })
}

/// A whole `GetNotesById` reply → the assembler's [`NoteRecord`] for `asked`, with every row that
/// answers about `asked` reconciled into ONE answer.
///
/// The reply is not a lookup table. It may carry rows for notes nobody asked about, and it may carry
/// the SAME id more than once — the client's verifying wrapper checks that requested ids come back,
/// not that each comes back once. So the rows for `asked` are collected rather than searched, and
/// they must tell one story:
///
/// * **no row** — the failed read [`note_record`] already reports. An unknown note is an absence of
///   information, never "no burn".
/// * **one row, or several that yield the SAME record** — that record. A row repeated identically is
///   one answer told twice, a node artifact; refusing a well-evidenced burn over it would be
///   fail-closed in name only. The same rule [`nullifier_record`] lives by.
/// * **rows that disagree** — a failed read. Two rows for one note can differ about whether it is
///   observable at all (public versus private) or about WHERE it was created (two inclusion-proof
///   locations), and those are opposite answers for the same burn: one says assemble a package with
///   this creation block, the other says refuse it or use another. Nothing here can say which is
///   true, and taking whichever the node listed first would make the package — and the money — a
///   function of row order. So neither is taken.
///
/// Rows are compared as the [`NoteRecord`] each one yields, which is exactly the evidence that would
/// reach [`assemble_evidence`](crate::evidence::assemble_evidence): two rows agreeing on everything
/// this crate publishes are one answer, whatever else differs inside the reply.
///
/// # Errors
/// [`EvidenceReadError`] when the node returned no row for `asked`, or rows that contradict each
/// other.
pub fn reconcile_note_reply(
    asked: NoteId,
    fetched: &[FetchedNote],
) -> Result<NoteRecord, EvidenceReadError> {
    let mut answer: Option<NoteRecord> = None;

    for row in fetched.iter().filter(|note| note.id() == asked) {
        let candidate = note_record(asked, Some(row))?;
        match &answer {
            None => answer = Some(candidate),
            Some(seen) if *seen == candidate => {}
            Some(_) => {
                return Err(EvidenceReadError::new(
                    GET_NOTES_BY_ID,
                    ContradictoryNote(asked),
                ))
            }
        }
    }

    match answer {
        Some(record) => Ok(record),
        // not one row for it: the same failed read, reported by the one function that owns it.
        None => note_record(asked, None),
    }
}

/// A `SyncNullifiers` reply → the assembler's [`NullifierRecord`] for `asked`.
///
/// The query is by 16-bit prefix, so `updates` legitimately carries other nullifiers. Only rows for
/// `asked` count; no row at all is the ABSENCE of a signal (`spent_in_block = None`), which the
/// assembler turns into a refusal rather than into "unspent".
///
/// A row repeated identically is one observation told twice — a node artifact, and refusing a
/// well-evidenced burn over it would be fail-closed in name only. Two rows for `asked` naming
/// DIFFERENT blocks is a contradiction: at least one is false, nothing here can say which, and
/// choosing either would publish a spend block no evidence supports. That fails the read.
///
/// # Errors
/// [`EvidenceReadError`] when the node reports `asked` spent in two different blocks.
pub fn nullifier_record(
    asked: Nullifier,
    updates: &[NullifierUpdate],
) -> Result<NullifierRecord, EvidenceReadError> {
    let mut spent_in_block: Option<BlockNumber> = None;
    for update in updates.iter().filter(|update| update.nullifier == asked) {
        match spent_in_block {
            None => spent_in_block = Some(update.block_num),
            Some(seen) if seen == update.block_num => {}
            Some(seen) => {
                return Err(EvidenceReadError::new(
                    SYNC_NULLIFIERS,
                    ContradictorySpend {
                        first: seen.as_u32(),
                        second: update.block_num.as_u32(),
                    },
                ))
            }
        }
    }

    Ok(NullifierRecord {
        nullifier: asked,
        spent_in_block,
    })
}

/// One `SyncTransactions` record → the assembler's [`TransactionRecord`].
///
/// The consumed nullifiers come from the transaction header's INPUT notes and from nowhere else,
/// and the created notes stay in `output_note_proofs`. That separation is the point of this
/// function: the transaction that MINTED the burn note is in the same faucet stream and names the
/// note, so a translation that let an output note reach the consumed side would let the assembler
/// resolve the mint as the burn.
pub fn transaction_record(
    block_num: BlockNumber,
    header: &TransactionHeader,
    output_notes: &[CommittedNote],
) -> TransactionRecord {
    TransactionRecord {
        transaction_id: header.id(),
        account_id: header.account_id(),
        block_num,
        input_note_nullifiers: header
            .input_notes()
            .iter()
            .map(InputNoteCommitment::nullifier)
            .collect(),
        output_note_proofs: output_notes
            .iter()
            .map(|note| (*note.note_id(), note.inclusion_proof().clone()))
            .collect(),
    }
}

// THE CLIENT-BACKED ADAPTER
// ================================================================================================

/// The `miden-client` [`BurnEvidenceReads`].
///
/// `block_from` is the earliest block the deployment is allowed to look at — a genesis or a
/// deployment height, supplied by the operator rather than guessed, because a window that started
/// after the burn note was created would make its evidence permanently unresolvable. The upper
/// bound is the node's chain tip, re-read per call.
pub struct RpcBurnEvidenceReads<R> {
    rpc: R,
    block_from: BlockNumber,
}

impl<R> RpcBurnEvidenceReads<R> {
    /// Reads evidence from `rpc`, scanning from `block_from` to the chain tip.
    pub fn new(rpc: R, block_from: BlockNumber) -> Self {
        Self { rpc, block_from }
    }
}

impl<R> RpcBurnEvidenceReads<R>
where
    R: NodeRpcClient + Send + Sync,
{
    /// The node's current chain tip — the upper bound of every range read below.
    ///
    /// # Errors
    /// [`EvidenceReadError`] when the header read fails. A range that cannot be bounded is a failed
    /// read, never a silently narrowed one.
    async fn chain_tip(&self) -> Result<BlockNumber, EvidenceReadError> {
        let (header, _) = self
            .rpc
            .get_block_header_by_number(None, false)
            .await
            .map_err(|source| EvidenceReadError::new(GET_BLOCK_HEADER_BY_NUMBER, source))?;
        Ok(header.block_num())
    }
}

#[async_trait]
impl<R> BurnEvidenceReads for RpcBurnEvidenceReads<R>
where
    R: NodeRpcClient + Send + Sync,
{
    async fn note_by_id(&self, note_id: NoteId) -> Result<NoteRecord, EvidenceReadError> {
        let fetched = self
            .rpc
            .get_notes_by_id(&[note_id])
            .await
            .map_err(|source| EvidenceReadError::new(GET_NOTES_BY_ID, source))?;

        // the node is not required to answer about only what was asked, and nothing stops it
        // answering about this note TWICE — so the reply is reconciled rather than searched. Taking
        // the first matching row would let the node decide, by row order, whether this burn is
        // observable and which block created it.
        reconcile_note_reply(note_id, &fetched)
    }

    async fn faucet_transactions(
        &self,
        faucet_id: AccountId,
    ) -> Result<Vec<TransactionRecord>, EvidenceReadError> {
        let block_to = self.chain_tip().await?;
        let records = self
            .rpc
            .sync_transactions(self.block_from, block_to, vec![faucet_id])
            .await
            .map_err(|source| EvidenceReadError::new(SYNC_TRANSACTIONS, source))?;

        // every row is translated, including rows for another account: the faucet filter is the
        // assembler's, and filtering here would hide a node answering about the wrong account.
        Ok(records
            .iter()
            .map(|record| {
                transaction_record(
                    record.block_num,
                    &record.transaction_header,
                    &record.output_notes,
                )
            })
            .collect())
    }

    async fn nullifier_status(
        &self,
        nullifier: Nullifier,
    ) -> Result<NullifierRecord, EvidenceReadError> {
        let block_to = self.chain_tip().await?;
        let updates = self
            .rpc
            .sync_nullifiers(&[nullifier.prefix()], self.block_from, block_to)
            .await
            .map_err(|source| EvidenceReadError::new(SYNC_NULLIFIERS, source))?;

        nullifier_record(nullifier, &updates)
    }
}

// THE CAUSES
// ================================================================================================

/// The cause behind a note read that came back without the note that was asked for.
///
/// Public so a caller — or a test — can tell the two note-read failures apart BY TYPE rather than by
/// reading a message: "the node did not answer" and "the node answered twice, differently" call for
/// different operator responses, and a string comparison is not a way to distinguish them.
#[derive(Debug)]
pub struct NoteNotReturned(NoteId);

impl NoteNotReturned {
    /// The note the read asked about and did not get.
    pub fn note_id(&self) -> NoteId {
        self.0
    }
}

impl core::fmt::Display for NoteNotReturned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the node returned no note for id {}", self.0.to_hex())
    }
}

impl core::error::Error for NoteNotReturned {}

/// The cause behind a note read whose rows for one id did not agree with each other.
///
/// Public for the same reason as [`NoteNotReturned`], and it is the one an operator must not miss:
/// a node contradicting itself about a burn is a different situation from a node that simply has
/// nothing to say.
#[derive(Debug)]
pub struct ContradictoryNote(NoteId);

impl ContradictoryNote {
    /// The note the node told two stories about.
    pub fn note_id(&self) -> NoteId {
        self.0
    }
}

impl core::fmt::Display for ContradictoryNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the node returned rows that disagree about note {}",
            self.0.to_hex()
        )
    }
}

impl core::error::Error for ContradictoryNote {}

/// The cause behind a spend reply that reported one nullifier spent in two different blocks.
#[derive(Debug)]
struct ContradictorySpend {
    first: u32,
    second: u32,
}

impl core::fmt::Display for ContradictorySpend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the node reports the nullifier spent in block {} and in block {}",
            self.first, self.second
        )
    }
}

impl core::error::Error for ContradictorySpend {}
