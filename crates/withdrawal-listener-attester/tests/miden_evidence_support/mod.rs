//! Shared fixtures for the two `miden::evidence` suites: the node replies each case is built from,
//! and the assertions that pin WHICH read failure occurred.
//!
//! Split out so `miden_evidence_adapter.rs` (the translations) and `miden_evidence_wiring.rs` (the
//! adapter over a programmable node) build their cases from ONE set of replies — a fixture copied
//! per target is a fixture that drifts — and stay inside the ~700-line Rust file ceiling.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use miden_client::rpc::domain::note::{CommittedNote, FetchedNote};

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::note::{
    Note, NoteAttachments, NoteId, NoteInclusionProof, NoteMetadata, NoteTag, NoteType, Nullifier,
    PartialNoteMetadata,
};
use miden_protocol::transaction::{
    InputNoteCommitment, InputNotes, TransactionHeader, TransactionId,
};
use miden_protocol::{Felt, Word};

use withdrawal_listener_attester::evidence::{EvidenceReadError, NoteRecord};
use withdrawal_listener_attester::miden::evidence::{ContradictoryNote, NoteNotReturned};

// THE REPLIES
// ================================================================================================

pub const CREATE_BLOCK: u32 = 42;
pub const CONSUME_BLOCK: u32 = 43;

pub fn faucet_id() -> AccountId {
    AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").expect("a real, parseable faucet id")
}

pub fn other_account_id() -> AccountId {
    AccountId::from_hex("0x0a8770f581c324b114fb42884cddc9").expect("a real, parseable account id")
}

pub fn word(n: u64) -> Word {
    let felt = |v: u64| Felt::new(v).expect("a value inside the field");
    Word::from([felt(0), felt(0), felt(0), felt(n)])
}

pub fn burn_nullifier() -> Nullifier {
    Nullifier::from_raw(word(0x4E55_4C4C))
}

/// A different nullifier that SHARES the burn nullifier's 16-bit prefix — the row a prefix-scanned
/// `SyncNullifiers` reply legitimately carries alongside the one that was asked about.
pub fn prefix_sharing_nullifier() -> Nullifier {
    let mut elements = burn_nullifier().as_word().as_elements().to_vec();
    // the prefix comes from the most significant felt, so changing a different limb keeps it.
    elements[0] = Felt::from(0x1234u32);
    let candidate = Nullifier::from_raw(Word::from([
        elements[0],
        elements[1],
        elements[2],
        elements[3],
    ]));
    assert_eq!(
        candidate.prefix(),
        burn_nullifier().prefix(),
        "the fixture must actually share the queried prefix"
    );
    assert_ne!(candidate, burn_nullifier());
    candidate
}

pub fn burn_tx_id() -> TransactionId {
    TransactionId::from_raw(word(0xB011))
}

pub fn inclusion_proof(block: u32) -> NoteInclusionProof {
    NoteInclusionProof::new(
        BlockNumber::from(block),
        0,
        SparseMerklePath::from_parts(0, Vec::new()).expect("an empty path"),
    )
    .expect("a valid inclusion proof")
}

pub fn note_id(n: u64) -> NoteId {
    NoteId::from_raw(word(n))
}

pub fn metadata(note_type: NoteType) -> NoteMetadata {
    NoteMetadata::new(
        PartialNoteMetadata::new(other_account_id(), note_type).with_tag(NoteTag::new(0x4255_524E)),
        &NoteAttachments::empty(),
    )
}

pub fn private_reply(id: NoteId) -> FetchedNote {
    FetchedNote::Private(
        id,
        metadata(NoteType::Private),
        NoteAttachments::empty(),
        inclusion_proof(CREATE_BLOCK),
    )
}

/// A `SyncTransactions` header for `account`, consuming `consumed`.
pub fn header(id: TransactionId, account: AccountId, consumed: &[Nullifier]) -> TransactionHeader {
    TransactionHeader::new_unchecked(
        id,
        account,
        Word::empty(),
        Word::empty(),
        InputNotes::new_unchecked(
            consumed
                .iter()
                .copied()
                .map(InputNoteCommitment::from)
                .collect(),
        ),
        Vec::new(),
    )
}

pub fn committed(id: NoteId, block: u32) -> CommittedNote {
    CommittedNote::new(id, metadata(NoteType::Public), inclusion_proof(block))
}

/// The burn note the evidence is about, built by the shared encoding crate's factory so its id and
/// nullifier are a real note's rather than opaque words.
pub fn burn_note() -> Note {
    use miden_protocol::asset::AssetAmount;
    use miden_protocol::crypto::rand::RandomCoin;
    use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
    use xusdc_encoding::xreserve::encoding::{ForeignChainAddress, XReserveBurnItems};

    let items = XReserveBurnItems {
        amount: AssetAmount::new(10_000_000).expect("an in-range amount"),
        dest_domain: 0,
        dest_recipient: ForeignChainAddress::new([0x74; 32]),
        salt: [0x5a; 32],
    };
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(3u32),
        Felt::from(5u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]));
    XReserveBurnNote::create(other_account_id(), faucet_id(), items, &mut rng)
        .expect("the burn note factory builds a note")
}

// THE ASSERTIONS
// ================================================================================================

/// Pins a read failure as THE CONTRADICTION: the `GetNotesById` RPC, and the contradictory-rows
/// cause by TYPE rather than by message. Asserting a bare `Err` here would be satisfied by an
/// unanswered read — the very failure these cases must not be confused with.
pub fn assert_contradiction(result: Result<NoteRecord, EvidenceReadError>, why: &str) {
    let error = result.expect_err(why);
    assert_eq!(error.rpc(), "GetNotesById", "{why}");
    let cause = core::error::Error::source(&error).expect("a read failure carries its cause");
    assert!(
        cause.downcast_ref::<ContradictoryNote>().is_some(),
        "{why} — expected the contradiction, got: {error}"
    );
}

/// The other half of that pair: an UNANSWERED read. Named separately so neither failure can quietly
/// stand in for the other when an implementation changes.
pub fn assert_unanswered(result: Result<NoteRecord, EvidenceReadError>, why: &str) {
    let error = result.expect_err(why);
    assert_eq!(error.rpc(), "GetNotesById", "{why}");
    let cause = core::error::Error::source(&error).expect("a read failure carries its cause");
    assert!(
        cause.downcast_ref::<NoteNotReturned>().is_some(),
        "{why} — expected an unanswered read, got: {error}"
    );
    assert!(
        cause.downcast_ref::<ContradictoryNote>().is_none(),
        "an unanswered read is not a contradiction: {error}"
    );
}
