//! The `miden-client`-backed burn-evidence reads, driven as an ADAPTER over a programmable node.
//!
//! `miden_evidence_adapter.rs` drives the translations directly. This file drives
//! [`RpcBurnEvidenceReads`] itself, because the decision that costs money is made in the adapter
//! rather than in a translation: WHICH row of a `GetNotesById` reply becomes the answer. A node may
//! answer about one note twice, and the two rows can disagree about whether the burn is observable
//! at all or about the block that created it. With only the translations covered, the read could go
//! back to taking the first matching row and every case in the other file would still pass.
//!
//! NON-GATING: no node runs here — [`ScriptedRpc`] answers what a case programmed and panics on
//! anything else.

use miden_client::rpc::domain::note::FetchedNote;
use miden_client::rpc::domain::nullifier::NullifierUpdate;

use miden_protocol::block::BlockNumber;

use withdrawal_listener_attester::evidence::BurnEvidenceReads;
use withdrawal_listener_attester::miden::evidence::RpcBurnEvidenceReads;

// the programmable node, and the replies both evidence suites are built from (shared fixtures).
#[path = "miden_evidence_support/mod.rs"]
mod miden_evidence_support;
#[path = "rpc_support/mod.rs"]
mod rpc_support;

use miden_evidence_support::*;
use rpc_support::ScriptedRpc;

/// **The fix, at the adapter.** A node answers about this note TWICE, disagreeing about where it
/// was created. `note_by_id` refuses — in both row orders, because taking the first row passes one
/// of them and publishes a creation block chosen by the node's ordering.
#[tokio::test]
async fn the_adapter_refuses_a_node_that_answers_one_note_twice_disagreeing() {
    for honest_first in [true, false] {
        let note = burn_note();
        let rpc = ScriptedRpc::new().on_get_notes_by_id(move |_ids| {
            let note = burn_note();
            let honest = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));
            let impostor = FetchedNote::Public(note, inclusion_proof(CREATE_BLOCK + 100));
            if honest_first {
                vec![honest, impostor]
            } else {
                vec![impostor, honest]
            }
        });

        let reads = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0));
        assert_contradiction(
            reads.note_by_id(note.id()).await,
            "contradictory rows are not an answer, whichever came first",
        );
    }
}

/// The same at the adapter for OBSERVABILITY: one row says public, the other private. Opposite
/// answers — a package or a refusal — and neither is chosen by row order.
#[tokio::test]
async fn the_adapter_refuses_a_node_that_disagrees_about_observability() {
    for public_first in [true, false] {
        let note = burn_note();
        let rpc = ScriptedRpc::new().on_get_notes_by_id(move |_ids| {
            let note = burn_note();
            let id = note.id();
            let public = FetchedNote::Public(note, inclusion_proof(CREATE_BLOCK));
            let private = private_reply(id);
            if public_first {
                vec![public, private]
            } else {
                vec![private, public]
            }
        });

        let reads = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0));
        assert_contradiction(
            reads.note_by_id(note.id()).await,
            "a note cannot be both observable and not",
        );
    }
}

/// A node that repeats the note identically is telling one story twice, and the adapter reads it —
/// this is the case that keeps the refusal above from being "any repeat fails".
#[tokio::test]
async fn the_adapter_reads_a_note_a_node_repeated_identically() {
    let note = burn_note();
    let rpc = ScriptedRpc::new().on_get_notes_by_id(move |_ids| {
        let note = burn_note();
        vec![
            FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK)),
            FetchedNote::Public(note, inclusion_proof(CREATE_BLOCK)),
        ]
    });

    let reads = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0));
    let record = reads
        .note_by_id(note.id())
        .await
        .expect("one answer told twice is still an answer");

    assert_eq!(record.note_id, note.id());
    let details = record.details.expect("the note is public");
    assert_eq!(details.nullifier, note.nullifier());
    assert_eq!(
        details.inclusion_proof.location().block_num(),
        BlockNumber::from(CREATE_BLOCK)
    );
}

/// The happy path through the adapter, so the refusals above are not the only outcome it can
/// produce: one row, and the record carries what the node said.
#[tokio::test]
async fn the_adapter_reads_the_note_a_node_answered_with() {
    let note = burn_note();
    let rpc = ScriptedRpc::new().on_get_notes_by_id(move |_ids| {
        vec![FetchedNote::Public(
            burn_note(),
            inclusion_proof(CREATE_BLOCK),
        )]
    });

    let reads = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0));
    let record = reads.note_by_id(note.id()).await.expect("the note reads");

    assert_eq!(record.note_id, note.id());
    assert!(record.details.is_some());
}

/// A node that answers only about somebody else's note has not answered this read. That is the
/// FAILED READ `NoteNotReturned`, and it is a different failure from a contradiction — pinned by
/// type, so neither can quietly stand in for the other.
#[tokio::test]
async fn the_adapter_reports_a_reply_about_another_note_as_an_unanswered_read() {
    let note = burn_note();
    let rpc =
        ScriptedRpc::new().on_get_notes_by_id(move |_ids| vec![private_reply(note_id(0x5747))]);

    let reads = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0));
    assert_unanswered(
        reads.note_by_id(note.id()).await,
        "another note's row is not this note's answer",
    );
}

/// The spend read at the adapter: `SyncNullifiers` is asked by 16-bit PREFIX, so the reply carries
/// a stranger's nullifier that shares it. The adapter must ask by prefix and then answer about the
/// EXACT nullifier — reading the reply's first row would attribute someone else's spend to this
/// burn.
#[tokio::test]
async fn the_adapter_asks_by_prefix_and_answers_about_the_exact_nullifier() {
    let asked = burn_nullifier();
    let stranger = prefix_sharing_nullifier();

    let rpc = ScriptedRpc::new()
        .with_chain_tip(CONSUME_BLOCK + 5)
        .on_sync_nullifiers(move |prefixes, _from, _to| {
            assert_eq!(
                prefixes,
                [asked.prefix()],
                "the scan is by the nullifier's own 16-bit prefix"
            );
            vec![
                // the stranger's row comes FIRST, as a prefix scan may well return it
                NullifierUpdate {
                    nullifier: prefix_sharing_nullifier(),
                    block_num: BlockNumber::from(CONSUME_BLOCK + 1),
                },
                NullifierUpdate {
                    nullifier: burn_nullifier(),
                    block_num: BlockNumber::from(CONSUME_BLOCK),
                },
            ]
        });

    let record = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0))
        .nullifier_status(asked)
        .await
        .expect("the spend reply reads");

    assert_ne!(asked, stranger, "the fixture must be two nullifiers");
    assert_eq!(record.nullifier, asked);
    assert_eq!(
        record.spent_in_block,
        Some(BlockNumber::from(CONSUME_BLOCK)),
        "the exact row's block, never the stranger's"
    );
}

/// …and a node that reports this burn's nullifier spent in two different blocks fails the read at
/// the adapter, rather than the first row deciding when the burn happened.
#[tokio::test]
async fn the_adapter_refuses_a_node_that_reports_two_spend_blocks() {
    let rpc = ScriptedRpc::new()
        .with_chain_tip(CONSUME_BLOCK + 5)
        .on_sync_nullifiers(|_prefixes, _from, _to| {
            vec![
                NullifierUpdate {
                    nullifier: burn_nullifier(),
                    block_num: BlockNumber::from(CONSUME_BLOCK),
                },
                NullifierUpdate {
                    nullifier: burn_nullifier(),
                    block_num: BlockNumber::from(CONSUME_BLOCK + 2),
                },
            ]
        });

    let error = RpcBurnEvidenceReads::new(rpc, BlockNumber::from(0))
        .nullifier_status(burn_nullifier())
        .await
        .expect_err("one nullifier cannot be spent in two blocks");

    assert_eq!(error.rpc(), "SyncNullifiers");
}
