//! Shared fixtures for the two `miden::discovery` suites: the scan rows and retrieval replies each
//! case is built from.
//!
//! Split out so `miden_discovery_adapter.rs` (the translations) and `miden_discovery_wiring.rs`
//! (the adapter over a programmable node) build their cases from ONE set of replies — a fixture
//! copied per target is a fixture that drifts — and stay inside the ~700-line Rust file ceiling.
//!
//! The happy-path fixtures are REAL burn notes, built by the shared encoding crate's own factory:
//! the same call the on-chain note is created by, so a disagreement between the write side and the
//! read side fails a case rather than hiding in a hand-assembled reply.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use miden_client::rpc::domain::note::{CommittedNote, FetchedNote};

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::merkle::SparseMerklePath;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{
    Note, NoteAttachments, NoteId, NoteInclusionProof, NoteMetadata, NoteTag, NoteType,
    PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};

use withdrawal_listener_attester::config::ListenerConfig;
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};
use xusdc_encoding::xreserve::encoding::{ForeignChainAddress, XReserveBurnItems};

// THE REPLIES
// ================================================================================================

pub const BURN_AMOUNT: u64 = 10_000_000;
pub const CREATE_BLOCK: u32 = 42;

pub fn cfg() -> ListenerConfig {
    ListenerConfig::builder()
        .burn_tag(FIXED_XUSDC_BURN_TAG)
        .build()
        .expect("a valid config")
}

pub fn faucet_id() -> AccountId {
    cfg().faucet_id()
}

/// The burner — a real, parseable account id that is not the faucet.
pub fn burner() -> AccountId {
    AccountId::from_hex("0x0a8770f581c324b114fb42884cddc9").expect("a real, parseable account id")
}

pub fn items(amount: u64) -> XReserveBurnItems {
    XReserveBurnItems {
        amount: AssetAmount::new(amount).expect("an in-range amount"),
        dest_domain: 0,
        dest_recipient: ForeignChainAddress::new([0x74; 32]),
        salt: [0x5a; 32],
    }
}

pub fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from(7u32),
        Felt::from(11u32),
        Felt::from(13u32),
    ]))
}

/// A REAL xUSDC burn note, built by the shared encoding crate's own factory — the write side of the
/// pair this adapter reads.
pub fn real_burn_note(amount: u64) -> Note {
    seeded_burn_note(1, amount)
}

/// The same note factory with the randomness chosen by the caller: two seeds are two DIFFERENT
/// notes. The reconciliation cases need that — distinct real ids for a scan to list and a retrieval
/// to answer for, or to leave unanswered.
pub fn seeded_burn_note(seed: u64, amount: u64) -> Note {
    XReserveBurnNote::create(burner(), faucet_id(), items(amount), &mut note_rng(seed))
        .expect("the burn note factory builds a note")
}

/// A public note as `GetNotesById` answers it.
pub fn public_reply(note: &Note) -> FetchedNote {
    FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK))
}

/// A private note as `GetNotesById` answers it: an id, its metadata, and no columns.
pub fn private_reply(id: NoteId) -> FetchedNote {
    let metadata = NoteMetadata::new(
        PartialNoteMetadata::new(burner(), NoteType::Private)
            .with_tag(NoteTag::new(FIXED_XUSDC_BURN_TAG)),
        &NoteAttachments::empty(),
    );
    FetchedNote::Private(
        id,
        metadata,
        NoteAttachments::empty(),
        inclusion_proof(CREATE_BLOCK),
    )
}

pub fn inclusion_proof(block: u32) -> NoteInclusionProof {
    NoteInclusionProof::new(
        BlockNumber::from(block),
        0,
        SparseMerklePath::from_parts(0, Vec::new()).expect("an empty path"),
    )
    .expect("a valid inclusion proof")
}

/// The scan record for a note the node reports at `tag` — metadata only, exactly as `SyncNotes`
/// answers before any retrieval.
pub fn committed(note_id: NoteId, tag: u32, note_type: NoteType) -> CommittedNote {
    let metadata = NoteMetadata::new(
        PartialNoteMetadata::new(burner(), note_type).with_tag(NoteTag::new(tag)),
        &NoteAttachments::empty(),
    );
    CommittedNote::new(note_id, metadata, inclusion_proof(CREATE_BLOCK))
}

pub fn note_id(n: u64) -> NoteId {
    let felt = |v: u64| Felt::new(v).expect("a value inside the field");
    NoteId::from_raw(Word::from([felt(n), felt(0), felt(0), felt(0)]))
}
