//! The `miden-client`-backed burn-evidence reads: the `GetNotesById` note read, the
//! `SyncNullifiers` spend observation, and the `SyncTransactions` linkage, translated into the
//! records [`assemble_evidence`] reasons over.
//!
//! # The translation is where the money is
//!
//! The assembler's fail-closed rules are already proven against a unit adapter. What is NOT proven
//! by those suites is that a real node reply arrives at the assembler shaped the way the assembler
//! believes. Three translations decide that, and each has a wrong answer that would look right:
//!
//! * **The note read.** A note the node does not know about is a FAILED READ, not "no burn" — and
//!   the answered note id must be carried through as answered, so the assembler's
//!   `WrongNoteAnswered` check has something to catch.
//! * **The spend observation.** `SyncNullifiers` is asked by 16-bit PREFIX, so the reply carries
//!   other accounts' nullifiers that happen to share it. Reading the first row would attribute a
//!   stranger's spend to this burn.
//! * **The linkage.** A `SyncTransactions` record carries both the notes a transaction CONSUMED
//!   and the notes it CREATED. The burn note's own minting transaction is in the same stream, so a
//!   translation that let output notes reach `input_note_nullifiers` would publish the MINT as the
//!   transaction that burned the note.
//!
//! Each is a pure function over the client's reply types, driven here directly. The records they
//! produce are then fed through the REAL [`assemble_evidence`], so the file ends by proving the
//! translated shapes actually assemble rather than merely look plausible.
//!
//! NON-GATING: no node runs here.

use assert_matches::assert_matches;

use miden_client::rpc::domain::note::FetchedNote;
use miden_client::rpc::domain::nullifier::NullifierUpdate;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;

use withdrawal_listener_attester::evidence::{
    assemble_evidence, BurnEvidenceReads, EvidenceError, EvidenceReadError, NoteRecord,
    NullifierRecord, TransactionRecord,
};
use withdrawal_listener_attester::miden::evidence::{
    note_record, nullifier_record, reconcile_note_reply, transaction_record, READ_TRUST,
};
use withdrawal_listener_attester::types::ProofStrength;

use async_trait::async_trait;

// FIXTURES
// ================================================================================================

// the node replies every case here is built from — shared with `miden_evidence_wiring.rs`.
#[path = "miden_evidence_support/mod.rs"]
mod miden_evidence_support;

use miden_evidence_support::*;

// THE NOTE READ
// ================================================================================================

/// A public note's reply carries the note's own nullifier and the node's inclusion data, and the
/// proof's block is the one the package's `block_num` is read out of.
#[test]
fn a_public_note_reply_carries_its_nullifier_and_the_nodes_inclusion_data() {
    let note = burn_note();
    let fetched = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));

    let record = note_record(note.id(), Some(&fetched)).expect("a public note reply reads");
    assert_eq!(record.note_id, note.id());
    let details = record.details.expect("a public note has details");
    assert_eq!(details.nullifier, note.nullifier());
    assert_eq!(
        details.inclusion_proof.location().block_num(),
        BlockNumber::from(CREATE_BLOCK)
    );
}

/// A PRIVATE note's reply carries no details — the node holds none, so the burn is unobservable and
/// the assembler refuses it by name rather than assembling half a package.
#[test]
fn a_private_note_reply_is_unobservable() {
    let id = note_id(0xB01E);
    let record = note_record(id, Some(&private_reply(id))).expect("a private note reply reads");

    assert!(record.details.is_none());
    assert_matches!(
        futures_block_on(assemble_evidence(
            &StaticPort {
                note: Ok(record),
                txs: Ok(Vec::new()),
                spend: Ok(NullifierRecord {
                    nullifier: burn_nullifier(),
                    spent_in_block: None,
                }),
            },
            id,
            faucet_id(),
        )),
        Err(EvidenceError::NoteNotObservable { .. })
    );
}

/// **An unknown note is a failed READ, not an answer.** `GetNotesById` returning nothing for the id
/// is an absence of information; collapsing it into "no burn" would report a state nobody observed.
#[test]
fn an_absent_note_is_a_failed_read() {
    assert_matches!(note_record(note_id(0xB01E), None), Err(_));
}

/// The mapping carries the ANSWERED id through, rather than the asked-about one, so the assembler's
/// own `WrongNoteAnswered` guard has something to catch. A translation that stamped the asked id
/// onto the reply would silently attach another burn's evidence to this one.
#[test]
fn the_answered_note_id_is_carried_through_not_overwritten() {
    let answered = note_id(0xDEAD);
    let asked = note_id(0xB01E);
    let record = note_record(asked, Some(&private_reply(answered))).expect("the reply reads");

    assert_eq!(
        record.note_id, answered,
        "the record must say what the node answered about"
    );
    assert_matches!(
        futures_block_on(assemble_evidence(
            &StaticPort {
                note: Ok(record),
                txs: Ok(Vec::new()),
                spend: Ok(NullifierRecord {
                    nullifier: burn_nullifier(),
                    spent_in_block: None,
                }),
            },
            asked,
            faucet_id(),
        )),
        Err(EvidenceError::WrongNoteAnswered { .. })
    );
}

// THE SPEND OBSERVATION
// ================================================================================================

/// The queried nullifier's own row is the observation, and it names the block the node reports it
/// spent in.
#[test]
fn the_matching_update_is_the_spend_observation() {
    let updates = vec![NullifierUpdate {
        nullifier: burn_nullifier(),
        block_num: BlockNumber::from(CONSUME_BLOCK),
    }];

    let record = nullifier_record(burn_nullifier(), &updates).expect("the reply reads");
    assert_eq!(record.nullifier, burn_nullifier());
    assert_eq!(
        record.spent_in_block,
        Some(BlockNumber::from(CONSUME_BLOCK))
    );
}

/// **The prefix trap.** `SyncNullifiers` is asked by 16-bit prefix, so a stranger's nullifier
/// sharing that prefix rides along in the reply. Reading it as this burn's spend would report a
/// consumption that never happened; only the exact nullifier counts.
#[test]
fn a_prefix_sharing_row_is_not_this_burns_spend() {
    let updates = vec![NullifierUpdate {
        nullifier: prefix_sharing_nullifier(),
        block_num: BlockNumber::from(CONSUME_BLOCK),
    }];

    let record = nullifier_record(burn_nullifier(), &updates).expect("the reply reads");
    assert_eq!(record.nullifier, burn_nullifier());
    assert_eq!(
        record.spent_in_block, None,
        "another nullifier's spend is not this one's"
    );
}

/// The exact row is found even when it is not first — the reply's row order is the node's, not a
/// contract.
#[test]
fn the_exact_row_is_found_behind_a_prefix_sharing_one() {
    let updates = vec![
        NullifierUpdate {
            nullifier: prefix_sharing_nullifier(),
            block_num: BlockNumber::from(7),
        },
        NullifierUpdate {
            nullifier: burn_nullifier(),
            block_num: BlockNumber::from(CONSUME_BLOCK),
        },
    ];

    let record = nullifier_record(burn_nullifier(), &updates).expect("the reply reads");
    assert_eq!(
        record.spent_in_block,
        Some(BlockNumber::from(CONSUME_BLOCK))
    );
}

/// An empty reply is the ABSENCE of a signal, not proof the note is unspent — reported as
/// `spent_in_block = None`, which the assembler turns into a refusal rather than a package.
#[test]
fn no_row_at_all_is_no_observation() {
    let record = nullifier_record(burn_nullifier(), &[]).expect("the reply reads");
    assert_eq!(record.spent_in_block, None);
}

/// The node reporting ONE nullifier spent in TWO different blocks has contradicted itself. Neither
/// row can be checked, so picking either would publish a linkage no evidence supports — the read
/// fails instead.
#[test]
fn contradictory_rows_for_one_nullifier_fail_the_read() {
    let updates = vec![
        NullifierUpdate {
            nullifier: burn_nullifier(),
            block_num: BlockNumber::from(CONSUME_BLOCK),
        },
        NullifierUpdate {
            nullifier: burn_nullifier(),
            block_num: BlockNumber::from(CONSUME_BLOCK + 5),
        },
    ];

    assert_matches!(nullifier_record(burn_nullifier(), &updates), Err(_));
}

/// …and the same row repeated is a node artifact, not a contradiction: one story, told twice.
#[test]
fn an_identical_repeated_row_is_still_one_observation() {
    let row = NullifierUpdate {
        nullifier: burn_nullifier(),
        block_num: BlockNumber::from(CONSUME_BLOCK),
    };
    let record = nullifier_record(burn_nullifier(), &[row.clone(), row])
        .expect("a repeat is not a conflict");

    assert_eq!(
        record.spent_in_block,
        Some(BlockNumber::from(CONSUME_BLOCK))
    );
}

// THE LINKAGE
// ================================================================================================

/// The consumed nullifiers come from the transaction header's INPUT notes, and the created notes
/// come from the record's output notes. The two are kept apart, because the burn note's own minting
/// transaction is in this very stream.
#[test]
fn the_linkage_separates_consumed_inputs_from_created_outputs() {
    let created = note_id(0xC0FFEE);
    let record = transaction_record(
        BlockNumber::from(CONSUME_BLOCK),
        &header(burn_tx_id(), faucet_id(), &[burn_nullifier()]),
        &[committed(created, CONSUME_BLOCK)],
    );

    assert_eq!(record.transaction_id, burn_tx_id());
    assert_eq!(record.account_id, faucet_id());
    assert_eq!(record.block_num, BlockNumber::from(CONSUME_BLOCK));
    assert_eq!(record.input_note_nullifiers, vec![burn_nullifier()]);
    assert_eq!(
        record
            .output_note_proofs
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![created]
    );
}

/// **The mint-versus-burn trap.** The transaction that CREATED the burn note names it in its output
/// notes and consumes nothing. Its mapped record must therefore carry no input nullifiers — if the
/// created note leaked into `input_note_nullifiers`, the assembler would resolve the note's MINT as
/// the transaction that burned it.
#[test]
fn the_creating_transaction_maps_to_no_consumed_nullifier() {
    let burn_note_id = note_id(0xB01E);
    let record = transaction_record(
        BlockNumber::from(CREATE_BLOCK),
        &header(TransactionId::from_raw(word(0xC0FFEE)), faucet_id(), &[]),
        &[committed(burn_note_id, CREATE_BLOCK)],
    );

    assert!(
        record.input_note_nullifiers.is_empty(),
        "a creating transaction consumed nothing"
    );
    assert_eq!(
        record
            .output_note_proofs
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![burn_note_id]
    );
}

/// A transaction that ran against a DIFFERENT account is mapped faithfully, so the assembler's
/// faucet filter — not the adapter — is what excludes it.
#[test]
fn a_foreign_accounts_transaction_is_reported_with_its_own_account_id() {
    let record = transaction_record(
        BlockNumber::from(CONSUME_BLOCK),
        &header(burn_tx_id(), other_account_id(), &[burn_nullifier()]),
        &[],
    );

    assert_eq!(record.account_id, other_account_id());
}

// THE TRANSLATED SHAPES ACTUALLY ASSEMBLE
// ================================================================================================

/// The composition case: the three translated records, fed to the REAL assembler, produce the
/// package — with `block_num` read out of the inclusion proof (the CREATE block, not the consume
/// one) and the `burnTxId` resolved from the consuming transaction.
#[tokio::test]
async fn the_translated_records_assemble_into_the_package() {
    let note = burn_note();
    let fetched = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));
    let nullifier = note.nullifier();

    let port = StaticPort {
        note: Ok(note_record(note.id(), Some(&fetched)).expect("the note reply reads")),
        txs: Ok(vec![
            transaction_record(
                BlockNumber::from(CREATE_BLOCK),
                &header(TransactionId::from_raw(word(0xC0FFEE)), faucet_id(), &[]),
                &[committed(note.id(), CREATE_BLOCK)],
            ),
            transaction_record(
                BlockNumber::from(CONSUME_BLOCK),
                &header(burn_tx_id(), faucet_id(), &[nullifier]),
                &[],
            ),
        ]),
        spend: Ok(nullifier_record(
            nullifier,
            &[NullifierUpdate {
                nullifier,
                block_num: BlockNumber::from(CONSUME_BLOCK),
            }],
        )
        .expect("the spend reply reads")),
    };

    let package = assemble_evidence(&port, note.id(), faucet_id())
        .await
        .expect("the translated records assemble");

    assert_eq!(package.burn_tx_id(), burn_tx_id().to_hex());
    assert_eq!(
        package.block_num(),
        CREATE_BLOCK,
        "block_num comes from the inclusion proof, which proves CREATION"
    );
    assert_eq!(package.nullifier(), nullifier.as_word().as_bytes());
}

/// **The label rule.** The inclusion data in a `GetNotesById` reply is the NODE's word: this
/// adapter checks no merkle path against an authenticated block header, and an unverified proof is
/// proof MATERIAL rather than a proof. So everything this module answers with is NODE-TRUSTED
/// ([`READ_TRUST`]), and nothing it returns may be labelled CRYPTOGRAPHIC.
///
/// The second half is what makes the label honest rather than decorative: a proof of nothing — an
/// empty path, a block the note was never in — comes back byte-for-byte as it arrived. The adapter
/// verifies it in no way whatsoever, which is precisely why it may claim nothing about it.
#[test]
fn node_provided_inclusion_data_is_node_trusted_never_cryptographic() {
    assert_eq!(
        READ_TRUST,
        ProofStrength::NodeTrusted,
        "an unverified node answer is a node's word, whatever it contains"
    );

    let note = burn_note();
    let fabricated = inclusion_proof(CREATE_BLOCK + 7);
    let fetched = FetchedNote::Public(note.clone(), fabricated.clone());

    let record = note_record(note.id(), Some(&fetched)).expect("a public note reply reads");
    let details = record.details.expect("a public note has details");

    assert_eq!(
        details.inclusion_proof, fabricated,
        "the node's proof material is carried through unchecked — nothing here verifies it, so \
         nothing here may call it cryptographic"
    );
}

/// …and the labels are unchanged by the adapter landing: an inclusion proof still proves CREATION,
/// so the burn claim stays NODE-TRUSTED. Reading real node data does not upgrade what Miden proves.
#[tokio::test]
async fn reading_from_a_node_does_not_upgrade_any_trust_label() {
    let note = burn_note();
    let fetched = FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));
    let nullifier = note.nullifier();

    let port = StaticPort {
        note: Ok(note_record(note.id(), Some(&fetched)).expect("the note reply reads")),
        txs: Ok(vec![transaction_record(
            BlockNumber::from(CONSUME_BLOCK),
            &header(burn_tx_id(), faucet_id(), &[nullifier]),
            &[],
        )]),
        spend: Ok(nullifier_record(
            nullifier,
            &[NullifierUpdate {
                nullifier,
                block_num: BlockNumber::from(CONSUME_BLOCK),
            }],
        )
        .expect("the spend reply reads")),
    };

    let package = assemble_evidence(&port, note.id(), faucet_id())
        .await
        .expect("the translated records assemble");

    assert_eq!(package.consumption_trust(), ProofStrength::NodeTrusted);
    assert_eq!(package.burn_tx_id_strength(), ProofStrength::NodeTrusted);
    assert_eq!(package.nullifier_strength(), ProofStrength::NodeTrusted);
}

// THE HARNESS
// ================================================================================================

/// A port that hands back exactly the records a case built — so what is under test is the
/// TRANSLATION feeding the assembler, not a second re-implementation of a node.
struct StaticPort {
    note: Result<NoteRecord, EvidenceReadError>,
    txs: Result<Vec<TransactionRecord>, EvidenceReadError>,
    spend: Result<NullifierRecord, EvidenceReadError>,
}

#[async_trait]
impl BurnEvidenceReads for StaticPort {
    async fn note_by_id(&self, _note_id: NoteId) -> Result<NoteRecord, EvidenceReadError> {
        self.note.clone()
    }

    async fn faucet_transactions(
        &self,
        _faucet_id: AccountId,
    ) -> Result<Vec<TransactionRecord>, EvidenceReadError> {
        self.txs.clone()
    }

    async fn nullifier_status(
        &self,
        _nullifier: Nullifier,
    ) -> Result<NullifierRecord, EvidenceReadError> {
        self.spend.clone()
    }
}

/// Drives one future to completion inside a `#[test]` — the two shape assertions above are about
/// the mapping, and wrapping them in a runtime attribute would say they are about async behaviour.
fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

// THE NOTE REPLY — ONE STORY PER NOTE, OR NONE
// ================================================================================================

/// A row repeated identically is one answer told twice — a node artifact, and refusing a
/// well-evidenced burn over it would be fail-closed in name only. The same rule the spend
/// observation already lives by.
#[test]
fn an_identically_repeated_note_row_is_still_one_answer() {
    let note = burn_note();
    let reply = vec![
        FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK)),
        FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK)),
    ];

    let record =
        reconcile_note_reply(note.id(), &reply).expect("one answer told twice is one answer");

    assert_eq!(
        record,
        note_record(
            note.id(),
            Some(&FetchedNote::Public(
                note.clone(),
                inclusion_proof(CREATE_BLOCK)
            ))
        )
        .expect("the single-row reply reads"),
        "the repeat must reconcile to exactly the single-row answer"
    );
}

/// **Order must not decide the evidence.** Two rows for one note disagreeing about WHERE it was
/// created are a node contradicting itself: nothing here can say which block is true, and taking
/// whichever came first would make the package's `block_num` a function of the node's row order on
/// the path that releases money. Both orders are driven, because a first-row implementation passes
/// one of them.
#[test]
fn rows_disagreeing_about_the_creation_block_fail_the_read_in_either_order() {
    let note = burn_note();
    let honest = || FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));
    let impostor = || FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK + 100));

    assert_contradiction(
        reconcile_note_reply(note.id(), &[honest(), impostor()]),
        "the honest row first must not rescue a contradictory reply",
    );
    assert_contradiction(
        reconcile_note_reply(note.id(), &[impostor(), honest()]),
        "nor may the impostor first decide the creation block",
    );
}

/// The same trap on OBSERVABILITY. One row says the note is public (assemble a package), the other
/// says private (refuse it as unobservable) — opposite outcomes for the same burn, decided by which
/// row the node happened to list first. Neither is picked.
#[test]
fn rows_disagreeing_about_observability_fail_the_read_in_either_order() {
    let note = burn_note();
    let public = || FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK));
    let private = || private_reply(note.id());

    assert_contradiction(
        reconcile_note_reply(note.id(), &[public(), private()]),
        "the public row first must not decide that the burn is observable",
    );
    assert_contradiction(
        reconcile_note_reply(note.id(), &[private(), public()]),
        "nor may the private row first decide that it is not",
    );
}

/// A reply carrying rows for OTHER notes is fine — the node is not required to answer about only
/// what was asked. Those rows are not this note's answer, and they neither supply one nor spoil it.
#[test]
fn rows_for_other_notes_neither_answer_nor_spoil_this_ones() {
    let note = burn_note();
    let stranger = private_reply(note_id(0x5747));

    let reply = vec![
        private_reply(note_id(0x1111)),
        FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK)),
        stranger,
    ];
    let record =
        reconcile_note_reply(note.id(), &reply).expect("the one row for this note answers");
    assert_eq!(record.note_id, note.id());
    assert!(
        record.details.is_some(),
        "this note's own row is the public one"
    );

    // …and a reply that answers only about someone else answers nothing here — the UNANSWERED
    // read, which is a different failure from a contradiction and is pinned as one.
    assert_unanswered(
        reconcile_note_reply(note.id(), &[private_reply(note_id(0x1111))]),
        "another note's row is not this note's answer",
    );
}

/// An empty reply is the failed read it always was — reconciling rows does not turn "the node said
/// nothing" into "no burn".
#[test]
fn an_empty_reply_is_still_a_failed_read() {
    assert_unanswered(
        reconcile_note_reply(note_id(0xB01E), &[]),
        "nothing said is not an answer",
    );
}

/// And the fail-closed consequence, end to end: a contradictory note reply never becomes a package.
/// The read failed, so there is no evidence to assemble — not a package built from the surviving
/// row.
#[test]
fn a_contradictory_note_reply_never_yields_a_package() {
    let note = burn_note();
    let nullifier = note.nullifier();
    let contradictory = reconcile_note_reply(
        note.id(),
        &[
            FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK)),
            FetchedNote::Public(note.clone(), inclusion_proof(CREATE_BLOCK + 100)),
        ],
    )
    .expect_err("the reply contradicts itself");

    let port = StaticPort {
        note: Err(contradictory),
        txs: Ok(vec![transaction_record(
            BlockNumber::from(CONSUME_BLOCK),
            &header(burn_tx_id(), faucet_id(), &[nullifier]),
            &[],
        )]),
        spend: Ok(NullifierRecord {
            nullifier,
            spent_in_block: Some(BlockNumber::from(CONSUME_BLOCK)),
        }),
    };

    assert_matches!(
        futures_block_on(assemble_evidence(&port, note.id(), faucet_id())),
        Err(EvidenceError::Read(_)),
        "otherwise a node could pick the burn's evidence by ordering its rows"
    );
}
