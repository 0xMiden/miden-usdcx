//! **Burn-evidence trust labeling** — the highest-risk Circle-owned open deviation.
//!
//! NON-GATING. The Miden-real half of the same assembler driven against a live node through the
//! real v16 client — is parked on a `miden-client` that has no v0.16 release. What runs here is the
//! assembler's LOGIC over a unit adapter standing in for the read port. That is a deliberate
//! boundary, not a shortcut: what this file is testing is not whether the node answers, it is
//! whether the answers are described to Circle honestly.
//!
//! # Why the labels are the product
//!
//! Circle releases native USDC against this package. Every element of it is a claim the partner
//! makes, and the governing trust rule is one sentence: **retrievable ≠ cryptographically proved**.
//! Two ways to lie, both of which release money that was never burned:
//!
//! 1. **Overclaiming strength.** `SyncTransactions` tx-linkage and the `SyncNullifiers`
//!    spend observation carry NO inclusion proof — the node simply says so. Labelling either
//!    CRYPTOGRAPHIC tells Circle the partner can prove what it can only repeat.
//! 2. **Overclaiming SCOPE.** The subtler one, and the reason this file has a whole family for it:
//!    a `GetNotesById` inclusion proof is cryptographic, and it proves the note was **CREATED**. It
//!    says nothing about whether the note was ever consumed. "This note exists" is not "this burn
//!    happened", and a CRYPTOGRAPHIC label sitting next to a creation fact must never be readable
//!    as a confirmed burn.
//!
//! So a genuine burn record is `note_id` (**what**, creation, CRYPTOGRAPHIC) **plus** a consumption
//! signal (**that it burned**, NODE-TRUSTED). `burnTxId` alone proves nothing at all —
//! `GetTransactionById` does not exist on Miden, so there is no by-hash resolution to fall
//! back on. That structural never a transaction id rule, and the other absences, are asserted in
//! the sibling `evidence_structural_absence.rs`.
//!
//! # Fail-closed
//!
//! Uncertain, missing, or self-contradicting evidence is never rounded up to "confirmed". It
//! becomes `reconciliation-required` — the same vocabulary and the same conservatism the
//! idempotency ledger established for a `409` naming no withdrawal, deliberately reused rather than
//! re-invented under a second name.

use assert_matches::assert_matches;
use rstest::rstest;

use miden_protocol::block::BlockNumber;
use miden_protocol::note::{NoteId, Nullifier};
use miden_protocol::transaction::TransactionId;

use withdrawal_listener_attester::evidence::{
    AmbiguityReason, EvidenceError, EvidenceReadError, NoteRecord, NullifierRecord,
    TransactionRecord,
};
use withdrawal_listener_attester::types::{ProofStrength, ProvenFact};

#[path = "evidence_support/mod.rs"]
mod evidence_support;

use evidence_support::*;

// THE LABELS — the per-element proof strengths, verbatim from Circle's documented evidence
// table
// ================================================================================================

/// The four labels the evidence table pins (`MIDEN-RPC-BURN-EVIDENCE.md:69`-`:72`, quoted in
/// Circle's documentation). Asserted as one table because the failure that matters is a SINGLE
/// element drifting upward while the other three stay honest.
#[test]
fn the_package_carries_the_documented_per_element_proof_strengths() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(
        package.note_id_strength(),
        ProofStrength::Cryptographic,
        "the GetNotesById inclusion path proves membership in the block note root (R-2)"
    );
    assert_eq!(
        package.block_num_strength(),
        ProofStrength::Cryptographic,
        "via that same note inclusion proof"
    );
    assert_eq!(
        package.burn_tx_id_strength(),
        ProofStrength::NodeTrusted,
        "SyncTransactions tx-linkage carries no inclusion proof (R-9/R-10)"
    );
    assert_eq!(
        package.nullifier_strength(),
        ProofStrength::NodeTrusted,
        "SyncNullifiers is a spend OBSERVATION; there is no CheckNullifiers RPC (R-5)"
    );
}

/// The package's contents are the reads, not a rewrite of them.
#[test]
fn the_package_carries_the_four_elements_it_read() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(package.burn_tx_id(), burn_tx_id().to_hex());
    assert_eq!(package.note_id(), burn_note_id().as_word().as_bytes());
    assert_eq!(package.nullifier(), burn_nullifier().as_word().as_bytes());
}

/// `block_num` is the CREATION block, read out of the inclusion proof that makes it cryptographic —
/// not the consuming transaction's block, which is node-trusted hearsay sitting right next to it.
///
/// The two differ by construction (creation and consumption are always in different blocks), so an
/// implementation that took the block from the linkage would return `CONSUME_BLOCK` here and be
/// labelling a node-trusted number CRYPTOGRAPHIC.
#[test]
fn block_num_is_read_from_the_inclusion_proof_not_from_the_node_trusted_linkage() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(package.block_num(), CREATE_BLOCK);
    assert_ne!(
        package.block_num(),
        CONSUME_BLOCK,
        "the consuming tx's block is NODE-TRUSTED and must not be published under a CRYPTOGRAPHIC label"
    );
}

/// Re-assembly is deterministic and the labels are stable. A label that moved between two reads of
/// the same burn would mean the strength is a function of the node's mood rather than of what Miden
/// proves.
#[test]
fn the_package_and_its_labels_are_stable_across_reassembly() {
    let port = UnitPort::honest();
    let first = assemble(&port).expect("the honest port assembles");
    let second = assemble(&port).expect("the honest port assembles again");

    assert_eq!(
        first, second,
        "re-assembling the same burn is deterministic"
    );
    assert_eq!(first.elements(), second.elements(), "the labels are stable");
}

// THE SCOPE OF A CRYPTOGRAPHIC LABEL — creation is not consumption
// ================================================================================================

/// The structural form of Addendum-B(1): **no element is both CRYPTOGRAPHIC and a consumption
/// claim.** An inclusion proof proves creation; every "the burn happened" signal Miden offers today
/// is a node report. If those two ever meet on one element, the package tells Circle it can prove a
/// burn it cannot.
///
/// Asserted over `elements()` rather than field by field, so an element added later is covered by
/// this test the day it appears rather than the day someone remembers to extend it.
#[test]
fn no_element_is_both_cryptographic_and_a_consumption_claim() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    for element in package.elements() {
        assert!(
            !(element.strength == ProofStrength::Cryptographic
                && element.proves.is_consumption_claim()),
            "{} claims to CRYPTOGRAPHICALLY prove consumption ({:?}) — Miden proves no such thing",
            element.name,
            element.proves
        );
    }
}

/// What each element proves, named. The strengths above say how well; these say of WHAT — and the
/// pair is what makes "cryptographic" unable to quietly mean "burned".
#[test]
fn each_element_names_the_fact_it_actually_proves() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(package.note_id_proves(), ProvenFact::NoteCreatedInBlock);
    assert_eq!(package.block_num_proves(), ProvenFact::NoteCreatedInBlock);
    assert_eq!(
        package.burn_tx_id_proves(),
        ProvenFact::NoteConsumedByTransaction
    );
    assert_eq!(package.nullifier_proves(), ProvenFact::NullifierSpent);
}

/// A creation fact is not a consumption claim, and both node reports are.
#[rstest]
#[case::creation(ProvenFact::NoteCreatedInBlock, false)]
#[case::linkage(ProvenFact::NoteConsumedByTransaction, true)]
#[case::spend(ProvenFact::NullifierSpent, true)]
fn a_creation_fact_is_not_a_consumption_claim(
    #[case] fact: ProvenFact,
    #[case] is_consumption: bool,
) {
    assert_eq!(fact.is_consumption_claim(), is_consumption);
}

/// The package's *burn-happened* claim is NODE-TRUSTED — always, today. It is derived from the
/// consumption elements' own labels rather than asserted as a constant, so the day one of them is
/// upgraded (the full-block path) this answer moves with it and cannot be
/// left behind as a stale promise.
#[test]
fn the_burn_happened_claim_is_node_trusted_however_strong_the_creation_proof_is() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(
        package.consumption_trust(),
        ProofStrength::NodeTrusted,
        "the cryptographic creation proof must not lift the burn claim with it"
    );
}

// THE MISLABEL NEGATIVE — an output-note proof is not proof of consumption
// ================================================================================================

/// The non-vacuity oracle. The faucet's transaction stream contains the tx that CREATED the burn
/// note, carrying that very note in `output_note_proofs`. An assembler that matched a tx on "does
/// it mention our note" would pick it, and publish the note's own MINT as the `burnTxId` — a
/// cryptographically-proof-backed transaction id for a burn that never happened.
///
/// Output-note proofs do NOT prove input-note consumption. With only the creating tx
/// present, there is no linkage, and the answer is `reconciliation-required` — never a package.
#[test]
fn a_transaction_that_merely_created_the_note_is_never_accepted_as_the_burn() {
    let port = UnitPort {
        txs: Ok(vec![creating_tx()]),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::NoConsumingTransaction,
            ..
        })
    );
}

/// The same adapter with the consuming tx restored picks the CONSUMING one — not the creating one
/// that is still sitting in the same stream. Without this, the test above would pass on an
/// implementation that simply never resolves anything.
#[test]
fn the_burn_tx_id_is_the_consuming_transaction_not_the_creating_one() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_eq!(package.burn_tx_id(), burn_tx_id().to_hex());
    assert_ne!(
        package.burn_tx_id(),
        creating_tx().transaction_id.to_hex(),
        "the tx that minted the note must never be published as the tx that burned it"
    );
}

/// A transaction belonging to some other account is not the faucet's burn, however tidily it
/// matches the nullifier. `SyncTransactions` is filtered by account for a reason; the assembler
/// re-checks it rather than trusting the port to have honoured the filter.
#[test]
fn another_accounts_transaction_is_not_accepted_as_the_faucets_burn() {
    let port = UnitPort {
        txs: Ok(vec![TransactionRecord {
            account_id: other_account_id(),
            ..consuming_tx()
        }]),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::NoConsumingTransaction,
            ..
        })
    );
}

// FAIL-CLOSED — ambiguity is reconciliation-required, never "confirmed"
// ================================================================================================

/// The node does not report the nullifier spent. The note exists and its creation is
/// CRYPTOGRAPHICALLY proved — and that is exactly the trap: a creation proof is not a burn. With no
/// consumption signal the burn may simply not have happened.
#[test]
fn a_creation_proof_without_an_observed_spend_never_yields_a_package() {
    let port = UnitPort {
        spend: Ok(NullifierRecord {
            nullifier: burn_nullifier(),
            spent_in_block: None,
        }),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::NoSpendObserved,
            ..
        })
    );
}

/// The node contradicts itself: `SyncNullifiers` says the spend landed in one block, the linkage
/// says another. Both are node-trusted, neither can be checked, so there is nothing to pick between
/// them — and picking anyway would publish a number no evidence supports.
#[test]
fn a_spend_block_that_disagrees_with_the_linkage_is_refused() {
    let port = UnitPort {
        spend: Ok(NullifierRecord {
            nullifier: burn_nullifier(),
            spent_in_block: Some(BlockNumber::from(CONSUME_BLOCK + 7)),
        }),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::SpendBlockDisagreesWithLinkage { .. },
            ..
        })
    );
}

/// A note cannot be consumed in or before the block that created it. A node reporting otherwise is
/// reporting something the chain does not do — so the report is not evidence.
#[rstest]
#[case::same_block(CREATE_BLOCK)]
#[case::before(CREATE_BLOCK - 1)]
fn a_spend_at_or_before_the_creation_block_is_refused(#[case] spent_in: u32) {
    let port = UnitPort {
        spend: Ok(NullifierRecord {
            nullifier: burn_nullifier(),
            spent_in_block: Some(BlockNumber::from(spent_in)),
        }),
        txs: Ok(vec![TransactionRecord {
            block_num: BlockNumber::from(spent_in),
            ..consuming_tx()
        }]),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::ConsumptionPrecedesCreation { .. },
            ..
        })
    );
}

/// Two distinct transactions both claiming to consume the same nullifier. One of them is wrong and
/// nothing here can say which — so neither is published. A first-match implementation would pick
/// one and be right half the time, at the cost of a release against a fabricated tx id the other
/// half.
#[test]
fn two_transactions_claiming_the_same_burn_are_refused_rather_than_picked_between() {
    let impostor = TransactionRecord {
        transaction_id: TransactionId::from_raw(word(0xDE_AD)),
        ..consuming_tx()
    };
    let port = UnitPort {
        txs: Ok(vec![consuming_tx(), impostor]),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::AmbiguousConsumingTransactions { count: 2 },
            ..
        })
    );
}

/// The SAME transaction reported twice is one transaction, not an ambiguity — a duplicate in the
/// stream is a node artifact, and refusing it would block a perfectly evidenced burn. The negative
/// control for the case above: it proves that test is about CONFLICTING linkage rather than about
/// counting rows.
#[test]
fn the_same_transaction_reported_twice_is_not_an_ambiguity() {
    let port = UnitPort {
        txs: Ok(vec![consuming_tx(), consuming_tx()]),
        ..UnitPort::honest()
    };

    let package = assemble(&port).expect("one tx reported twice is still one tx");
    assert_eq!(package.burn_tx_id(), burn_tx_id().to_hex());
}

/// **Two rows for ONE transaction id that disagree about that transaction.** The node has
/// contradicted itself about a single tx — same id, same nullifier, same account, different block —
/// and exactly one of the two rows is true.
///
/// Collapsing them by id and keeping whichever arrived first makes the answer depend on the node's
/// row order: with the honest row first the burn is published, with the impostor first it is
/// refused. That is nondeterministic re-assembly on the fund-safety path, and half the time it
/// publishes a linkage that came from a row the node itself contradicted. Both orders must refuse.
///
/// Parameterized over the order precisely because the order is the bug
/// (`parametrize-related-tests`).
#[rstest]
#[case::honest_row_first(false)]
#[case::conflicting_row_first(true)]
fn conflicting_rows_for_one_transaction_id_are_refused_in_either_order(
    #[case] conflict_first: bool,
) {
    // same id, same nullifier, same account — it disagrees ONLY about which block the tx landed in,
    // so it survives every filter the assembler applies before the linkage is chosen.
    let contradiction = TransactionRecord {
        block_num: BlockNumber::from(CONSUME_BLOCK + 1),
        ..consuming_tx()
    };
    let txs = if conflict_first {
        vec![contradiction, consuming_tx()]
    } else {
        vec![consuming_tx(), contradiction]
    };
    let port = UnitPort {
        txs: Ok(txs),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::ContradictoryTransactionRows { count: 2 },
            ..
        }),
        "a node that reports one transaction two different ways has not evidenced a burn"
    );
}

/// The contradiction is caught even when the second row would NOT have passed the linkage filter:
/// one row says this transaction consumed the burn note, the other says it consumed nothing. The
/// filter runs first and would drop the second row, leaving a single "clean" candidate — so the
/// check has to look at every row carrying the chosen id, not only at the rows that survived.
#[test]
fn a_contradictory_row_is_caught_even_when_the_filter_would_have_dropped_it() {
    let says_it_consumed_nothing = TransactionRecord {
        input_note_nullifiers: Vec::new(),
        ..consuming_tx()
    };
    let port = UnitPort {
        txs: Ok(vec![consuming_tx(), says_it_consumed_nothing]),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::ContradictoryTransactionRows { .. },
            ..
        })
    );
}

/// A read that failed is not an absence of evidence — it is an absence of information. Each of the
/// three reads surfaces its failure rather than being folded into "no burn".
#[rstest]
#[case::note("GetNotesById")]
#[case::transactions("SyncTransactions")]
#[case::nullifiers("SyncNullifiers")]
fn a_failing_read_surfaces_rather_than_reading_as_no_burn(#[case] rpc: &'static str) {
    let failure = EvidenceReadError::new(rpc, std::io::Error::other("the node is down"));
    let mut port = UnitPort::honest();
    match rpc {
        "GetNotesById" => port.note = Err(failure),
        "SyncTransactions" => port.txs = Err(failure),
        _ => port.spend = Err(failure),
    }

    assert_matches!(assemble(&port), Err(EvidenceError::Read(e)) if e.rpc() == rpc);
}

// THE NOTE ITSELF — unobservable and unknown notes
// ================================================================================================

/// A private note: `GetNotesById` returns `details = None` and the burn is unobservable.
/// There is no payload, no nullifier, and therefore no evidence to assemble.
#[test]
fn a_private_note_is_rejected_as_unobservable() {
    let port = UnitPort {
        note: Ok(NoteRecord {
            note_id: burn_note_id(),
            details: None,
        }),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::NoteNotObservable { .. })
    );
}

/// The port answering about a DIFFERENT note than the one asked about. Assembling anyway would
/// attach another burn's evidence to this one — the same class of durable false evidence
/// `conflict_evidence.rs` forecloses on the Circle side.
#[test]
fn a_port_answering_about_a_different_note_is_refused() {
    let port = UnitPort {
        note: Ok(NoteRecord {
            note_id: NoteId::from_raw(word(0x_07_4E_52)),
            ..public_burn_note()
        }),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::WrongNoteAnswered { .. })
    );
}

/// The same, for the nullifier read: an observation about some other nullifier says nothing about
/// this burn.
#[test]
fn a_port_answering_about_a_different_nullifier_is_refused() {
    let port = UnitPort {
        spend: Ok(NullifierRecord {
            nullifier: Nullifier::from_raw(word(0x_07_4E_52)),
            spent_in_block: Some(BlockNumber::from(CONSUME_BLOCK)),
        }),
        ..UnitPort::honest()
    };

    assert_matches!(
        assemble(&port),
        Err(EvidenceError::WrongNullifierAnswered { .. })
    );
}
