//! Shared fixtures for the burn-evidence suites: the unit adapter standing in for the three
//! Miden reads, and the records each case is built from.
//!
//! It is a UNIT adapter, not a mock of Miden. It hands back exactly the records a case is about, so
//! the assertions land on the assembler's REASONING over those records rather than on a
//! re-implemented node. The real reads are parked on a `miden-client` with no v0.16 release — which
//! is also why this file exists at all rather than a local-node harness.
//!
//! Split out to stay within the ~700-line Rust file ceiling that `crate_posture.rs` sweeps for, the
//! same way `submit_support` carries the `POST /v1/withdraw` suites.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

#[path = "../support/mod.rs"]
pub mod support;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{NoteId, NoteInclusionProof, Nullifier};
use miden_protocol::transaction::TransactionId;
use miden_protocol::{Felt, Word};

use withdrawal_listener_attester::evidence::{
    assemble_evidence, BurnEvidenceReads, EvidenceError, EvidenceReadError, NoteRecord,
    NullifierRecord, PublicNoteDetails, TransactionRecord,
};
use withdrawal_listener_attester::types::EvidencePackage;

// ================================================================================================

/// A real, parseable xUSDC faucet id, not a fabricated one.
pub const FAUCET_ID_HEX: &str = "0xbb405fd9fe431bd1135a292de098cb";

/// The keyed `BasicWallet` holder account is the negative control for the faucet filter, and it is
/// the realistic one: the burner is the account most likely to appear alongside the faucet in a
/// transaction stream, so "not the faucet" is tested against the id that genuinely is not.
pub const OTHER_ACCOUNT_ID_HEX: &str = "0x0a8770f581c324b114fb42884cddc9";

/// The block the burn note is created in, and the block it is consumed in. They differ by one
/// because a burn note cannot be created and consumed in the same block and still be observable (a
/// burn note is created in block N and consumed in block ≥ N+1) — so a fixture that used one block
/// for both would be testing a state the chain does not produce.
pub const CREATE_BLOCK: u32 = 42;
pub const CONSUME_BLOCK: u32 = 43;

pub fn faucet_id() -> AccountId {
    AccountId::from_hex(FAUCET_ID_HEX).expect("a real, parseable faucet id")
}

pub fn other_account_id() -> AccountId {
    AccountId::from_hex(OTHER_ACCOUNT_ID_HEX).expect("a real, parseable account id")
}

/// A distinct `Word` per `n` — the opaque 32-byte identifiers this file needs, and nothing more.
/// `Felt::new` is fallible at the v16 base (values ≥ p are rejected), so it is unwrapped explicitly
/// rather than through a `From` that would silently reduce (`felt-construction`); every `n` here is
/// a small literal well inside the field.
pub fn word(n: u64) -> Word {
    let felt = |v: u64| Felt::new(v).expect("test value is in the field");
    Word::from([felt(0), felt(0), felt(0), felt(n)])
}

pub fn burn_note_id() -> NoteId {
    NoteId::from_raw(word(0xB0_1E))
}

pub fn burn_nullifier() -> Nullifier {
    Nullifier::from_raw(word(0x_4E_55_4C_4C))
}

pub fn burn_tx_id() -> TransactionId {
    TransactionId::from_raw(word(0xB0_11))
}

/// A note inclusion proof for `block` — the CRYPTOGRAPHIC creation evidence (`GetNotesById`).
/// The path is empty because nothing here verifies the Merkle path itself; what is under test is
/// whether the assembler reads the block number OUT OF THIS PROOF rather than believing a
/// node-reported field.
pub fn inclusion_proof(block: u32) -> NoteInclusionProof {
    NoteInclusionProof::new(
        BlockNumber::from(block),
        0,
        SparseMerklePath::from_parts(0, Vec::new()).expect("an empty path"),
    )
    .expect("a valid inclusion proof")
}

/// The `GetNotesById` reply for a public burn note created in `CREATE_BLOCK`.
pub fn public_burn_note() -> NoteRecord {
    NoteRecord {
        note_id: burn_note_id(),
        details: Some(PublicNoteDetails {
            nullifier: burn_nullifier(),
            inclusion_proof: inclusion_proof(CREATE_BLOCK),
        }),
    }
}

/// The `SyncTransactions(account_ids=[faucet_id])` record for the tx that CONSUMED the burn note —
/// the linkage, and the only thing that makes a `burnTxId` mean anything.
pub fn consuming_tx() -> TransactionRecord {
    TransactionRecord {
        transaction_id: burn_tx_id(),
        account_id: faucet_id(),
        block_num: BlockNumber::from(CONSUME_BLOCK),
        input_note_nullifiers: vec![burn_nullifier()],
        output_note_proofs: Vec::new(),
    }
}

/// The `SyncTransactions` record for the tx that CREATED the burn note. It names the note — in
/// `output_note_proofs`, which proves the note was minted BY it, and proves nothing whatsoever
/// about the note being consumed. It is in the faucet's transaction stream exactly like
/// the consuming one, which is what makes confusing the two a live risk rather than a theoretical
/// one.
pub fn creating_tx() -> TransactionRecord {
    TransactionRecord {
        transaction_id: TransactionId::from_raw(word(0xC0_FF_EE)),
        account_id: faucet_id(),
        block_num: BlockNumber::from(CREATE_BLOCK),
        input_note_nullifiers: Vec::new(),
        output_note_proofs: vec![(burn_note_id(), inclusion_proof(CREATE_BLOCK))],
    }
}

/// The `SyncNullifiers` observation that the burn nullifier was spent — NODE-TRUSTED, no proof.
pub fn observed_spend() -> NullifierRecord {
    NullifierRecord {
        nullifier: burn_nullifier(),
        spent_in_block: Some(BlockNumber::from(CONSUME_BLOCK)),
    }
}

/// A scripted stand-in for the three Miden reads. It is a UNIT adapter, not a mock of Miden: it
/// hands back exactly the records a case is about, so the assertions are about the assembler's
/// reasoning over those records. The real reads are parked for the node-backed slice.
pub struct UnitPort {
    pub note: Result<NoteRecord, EvidenceReadError>,
    pub txs: Result<Vec<TransactionRecord>, EvidenceReadError>,
    pub spend: Result<NullifierRecord, EvidenceReadError>,
}

impl UnitPort {
    /// The honest, fully-evidenced burn: a public note with its creation proof, the faucet's
    /// creating AND consuming transactions, and the observed spend.
    pub fn honest() -> Self {
        Self {
            note: Ok(public_burn_note()),
            txs: Ok(vec![creating_tx(), consuming_tx()]),
            spend: Ok(observed_spend()),
        }
    }
}

impl BurnEvidenceReads for UnitPort {
    fn note_by_id(&self, _note_id: NoteId) -> Result<NoteRecord, EvidenceReadError> {
        self.note.clone()
    }

    fn faucet_transactions(
        &self,
        _faucet_id: AccountId,
    ) -> Result<Vec<TransactionRecord>, EvidenceReadError> {
        self.txs.clone()
    }

    fn nullifier_status(
        &self,
        _nullifier: Nullifier,
    ) -> Result<NullifierRecord, EvidenceReadError> {
        self.spend.clone()
    }
}

pub fn assemble(port: &UnitPort) -> Result<EvidencePackage, EvidenceError> {
    assemble_evidence(port, burn_note_id(), faucet_id())
}
