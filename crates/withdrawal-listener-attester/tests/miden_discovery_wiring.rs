//! The `miden-client`-backed discovery leg, driven as an ADAPTER over a programmable node.
//!
//! `miden_discovery_adapter.rs` drives the translations directly. This file drives
//! [`RpcBurnNoteDiscovery`] itself, because two of the decisions that decide whether a burn is ever
//! processed are made in the adapter rather than in a translation: whether the scan's ids are
//! actually RECONCILED against the retrieval's answers, and whether the exact-tag filter is what
//! chooses the ids to retrieve. Neither is observable from a test that only calls the pure
//! functions — the adapter could go back to quietly mapping whatever came back, and every case in
//! the other file would still pass.
//!
//! NON-GATING: no node runs here — [`ScriptedRpc`] answers what a case programmed and panics on
//! anything else, so an adapter reading something no case programmed fails loudly.

use miden_protocol::block::BlockNumber;
use miden_protocol::note::NoteType;

use withdrawal_listener_attester::miden::discovery::{
    BurnNoteDiscovery, RetrievalGap, RpcBurnNoteDiscovery,
};
use withdrawal_listener_attester::validate::validate_discovery;
use xusdc_encoding::note::xreserve_burn::FIXED_XUSDC_BURN_TAG;

// the programmable node, and the replies both discovery suites are built from (shared fixtures).
#[path = "miden_discovery_support/mod.rs"]
mod miden_discovery_support;
#[path = "rpc_support/mod.rs"]
mod rpc_support;

use miden_discovery_support::*;
use rpc_support::{sync_block, ScriptedRpc};

/// **The fund-safety fix, at the adapter.** The scan matches two burns; the node's retrieval answers
/// for one. The read FAILS, naming the burn that went missing — rather than returning a
/// one-note range that looks complete and lets a cursor move past the other.
#[tokio::test]
async fn the_adapter_fails_the_read_when_the_retrieval_omits_a_scanned_burn() {
    let answered = seeded_burn_note(1, BURN_AMOUNT);
    let omitted = seeded_burn_note(2, BURN_AMOUNT);
    let (answered_id, omitted_id) = (answered.id(), omitted.id());

    let rpc = ScriptedRpc::new()
        .on_sync_notes(move |_from, _to, _tags| {
            vec![sync_block(
                CREATE_BLOCK,
                vec![
                    committed(answered_id, FIXED_XUSDC_BURN_TAG, NoteType::Public),
                    committed(omitted_id, FIXED_XUSDC_BURN_TAG, NoteType::Public),
                ],
            )]
        })
        .on_get_notes_by_id(move |_ids| vec![public_reply(&seeded_burn_note(1, BURN_AMOUNT))]);

    let error = RpcBurnNoteDiscovery::new(rpc, FIXED_XUSDC_BURN_TAG)
        .discover(BlockNumber::from(1), BlockNumber::from(CREATE_BLOCK))
        .await
        .expect_err("a scanned burn the retrieval skipped must not vanish");

    assert_eq!(error.rpc(), "GetNotesById");
    let gap = core::error::Error::source(&error)
        .expect("the gap is the cause")
        .downcast_ref::<RetrievalGap>()
        .expect("the cause names what went missing");
    assert_eq!(gap.omitted(), [omitted_id]);
    assert!(gap.duplicated().is_empty());
}

/// A retrieval that answers one scanned id TWICE fails at the adapter too — the mirror image, and
/// the reason the read is "exactly once" rather than "at least once".
#[tokio::test]
async fn the_adapter_fails_the_read_when_the_retrieval_answers_one_burn_twice() {
    let note = seeded_burn_note(1, BURN_AMOUNT);
    let id = note.id();

    let rpc = ScriptedRpc::new()
        .on_sync_notes(move |_from, _to, _tags| {
            vec![sync_block(
                CREATE_BLOCK,
                vec![committed(id, FIXED_XUSDC_BURN_TAG, NoteType::Public)],
            )]
        })
        .on_get_notes_by_id(move |_ids| {
            let note = seeded_burn_note(1, BURN_AMOUNT);
            vec![public_reply(&note), public_reply(&note)]
        });

    let error = RpcBurnNoteDiscovery::new(rpc, FIXED_XUSDC_BURN_TAG)
        .discover(BlockNumber::from(1), BlockNumber::from(CREATE_BLOCK))
        .await
        .expect_err("one burn answered twice is not one answer");

    let gap = core::error::Error::source(&error)
        .expect("a cause")
        .downcast_ref::<RetrievalGap>()
        .expect("the cause is the gap");
    assert_eq!(gap.duplicated(), [id]);
}

/// The complete range, through the adapter: every scanned burn is retrieved and reported, in scan
/// order, with the details the checklist judges. Without this the refusals above would be satisfied
/// by an adapter that failed every read.
#[tokio::test]
async fn the_adapter_reports_every_scanned_burn_when_the_retrieval_is_complete() {
    let first = seeded_burn_note(1, BURN_AMOUNT);
    let second = seeded_burn_note(2, BURN_AMOUNT);
    let (first_id, second_id) = (first.id(), second.id());

    let rpc = ScriptedRpc::new()
        .on_sync_notes(move |_from, _to, _tags| {
            vec![sync_block(
                CREATE_BLOCK,
                vec![
                    committed(first_id, FIXED_XUSDC_BURN_TAG, NoteType::Public),
                    committed(second_id, FIXED_XUSDC_BURN_TAG, NoteType::Public),
                ],
            )]
        })
        // answered in the OPPOSITE order to the scan, as a node may
        .on_get_notes_by_id(move |_ids| {
            vec![
                public_reply(&seeded_burn_note(2, BURN_AMOUNT)),
                public_reply(&seeded_burn_note(1, BURN_AMOUNT)),
            ]
        });

    let discovered = RpcBurnNoteDiscovery::new(rpc, FIXED_XUSDC_BURN_TAG)
        .discover(BlockNumber::from(1), BlockNumber::from(CREATE_BLOCK))
        .await
        .expect("a complete retrieval is a complete range");

    // a `SyncNotes` block keys its notes by id, so the order the SCAN yields is the id order — and
    // the point of the case is that it is the scan's order rather than the retrieval's, which is
    // the reverse of it here.
    let mut expected = vec![first_id, second_id];
    expected.sort();
    assert_eq!(
        discovered
            .iter()
            .map(|note| note.note_id())
            .collect::<Vec<_>>(),
        expected,
        "the range follows the scan, not the node's row order"
    );
    for record in &discovered {
        validate_discovery(record.record(), &cfg())
            .expect("a real burn note still passes the checklist through the adapter");
    }
}

/// **The exact-tag filter, at the adapter.** A stranger's note sharing only the burn tag's 16-bit
/// prefix is scanned alongside a real burn; the retrieval is asked about the BURN and nothing else.
/// A prefix-matching adapter would ask about both and hand the stranger to the checklist.
#[tokio::test]
async fn the_adapter_retrieves_only_the_notes_whose_tag_matches_exactly() {
    let burn = seeded_burn_note(1, BURN_AMOUNT);
    let burn_id = burn.id();
    let stranger_id = note_id(0x5747);
    let prefix_only = FIXED_XUSDC_BURN_TAG & 0xFFFF_0000;
    assert_ne!(prefix_only, FIXED_XUSDC_BURN_TAG);

    let rpc = ScriptedRpc::new()
        .on_sync_notes(move |_from, _to, _tags| {
            vec![sync_block(
                CREATE_BLOCK,
                vec![
                    committed(burn_id, FIXED_XUSDC_BURN_TAG, NoteType::Public),
                    committed(stranger_id, prefix_only, NoteType::Public),
                ],
            )]
        })
        .on_get_notes_by_id(move |ids| {
            assert_eq!(
                ids,
                [burn_id],
                "only the exact-tag match may be retrieved: {ids:?}"
            );
            vec![public_reply(&seeded_burn_note(1, BURN_AMOUNT))]
        });

    let discovered = RpcBurnNoteDiscovery::new(rpc, FIXED_XUSDC_BURN_TAG)
        .discover(BlockNumber::from(1), BlockNumber::from(CREATE_BLOCK))
        .await
        .expect("the exact-tag burn is discovered");

    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].note_id(), burn_id);
}

/// A scan that matched nothing never retrieves. Asserted by NOT programming `GetNotesById` at all:
/// the double panics on an unprogrammed call, so an adapter that asked anyway fails this case
/// rather than quietly making a pointless round trip with an empty id list.
#[tokio::test]
async fn an_empty_scan_never_reaches_the_retrieval() {
    let rpc = ScriptedRpc::new().on_sync_notes(|_from, _to, _tags| Vec::new());

    let discovered = RpcBurnNoteDiscovery::new(rpc, FIXED_XUSDC_BURN_TAG)
        .discover(BlockNumber::from(1), BlockNumber::from(CREATE_BLOCK))
        .await
        .expect("an empty range is an empty answer");

    assert!(discovered.is_empty());
}
