//! The structural half: **the things that must NOT exist.**
//!
//! Its companion `evidence_trust_labeling.rs` asserts what the assembler DOES. This file asserts
//! what nothing can do, which needs a different kind of test: no test can call a function that must
//! not be callable, so these read the source and the wire instead. That is the crate's established
//! idiom for a property that is an ABSENCE (`submit_idempotency.rs`'s
//! `no_public_api_can_post_a_withdrawal_without_the_ledger`; `crate_posture.rs`'s manifest reads) —
//! a decision the compiler cannot hold is pinned mechanically, so it cannot quietly revert.
//!
//! Three absences, each of which would be a fund-safety defect:
//!
//! * **No `burnTxId`-only resolution** (never a transaction id). `GetTransactionById` does not
//!   exist on Miden, so there is nothing to resolve a burn from a transaction id with.
//! * **No way to manufacture an `EvidencePackage`.** Every fail-closed check lives inside
//!   `assemble_evidence`; a public constructor would be a door around all of them.
//! * **No invented wire transport.** `burnTxId` is the only evidence field `POST /v1/withdraw`
//!   documents, and whether Circle would take more is OPEN with Circle, and not this crate's to
//!   assume.
//!
//! Split from `evidence_trust_labeling.rs` to stay within the ~700-line Rust file ceiling.

use assert_matches::assert_matches;
use rstest::rstest;

use withdrawal_listener_attester::circle::schema::{BurnIntent, WithdrawBatch};
use withdrawal_listener_attester::circle::wire::HexBytes;
use withdrawal_listener_attester::evidence::{
    full_block_upgrade, EvidenceError, EvidenceReadError,
};
use withdrawal_listener_attester::types::ProofStrength;

#[path = "evidence_support/mod.rs"]
mod evidence_support;

use evidence_support::support;
use evidence_support::*;

// ANTI-the evidence-labelling trap — there is no `burnTxId`-only path, and it is absent rather than
// merely unused
// ================================================================================================

/// `GetTransactionById` / tx-by-hash **DOES NOT EXIST** on Miden. A path that resolved a burn
/// from a `burnTxId` alone therefore could not exist either — so the port's own source is read
/// here for the method names that must be absent from it.
#[test]
fn no_port_method_resolves_a_transaction_by_its_hash() {
    let source = evidence_source();

    for forbidden in [
        "get_transaction_by_id",
        "transaction_by_id",
        "tx_by_hash",
        "transaction_by_hash",
        "GetTransactionById",
    ] {
        assert!(
            !source.contains(forbidden),
            "`{forbidden}` appears in evidence.rs — tx-by-hash does not exist on Miden (R-8), so \
             nothing may be resolved from a burnTxId alone (ASG-4)"
        );
    }
}

/// **An `EvidencePackage` cannot be manufactured — the assembler is the only way to get one.**
///
/// This is the load-bearing half of every other assertion in this file. All the fail-closed checks
/// — the observed spend, the linkage, the block agreement — live inside `assemble_evidence`, and a
/// public `EvidencePackage::new` would let a caller skip every one of them and hand Circle a
/// package whose `burnTxId`, nullifier and block are literals nobody read from a node. The value
/// would be indistinguishable from an assembled one: same type, same labels, same
/// `consumption_trust()` reporting NODE-TRUSTED for consumption evidence that was never observed at
/// all.
///
/// So the constructor is `pub(crate)`: a package outside this crate is proof the checks ran. The
/// honest limit is the same as the ledger's — in-crate code can still call it, and in-crate the one
/// caller is `assemble_evidence`, which is what the sweep below pins.
#[test]
fn an_evidence_package_cannot_be_constructed_outside_the_crate() {
    let types = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/types.rs"),
    )
    .expect("src/types.rs")
    .lines()
    .filter(|line| !line.trim_start().starts_with("//"))
    .collect::<Vec<_>>()
    .join("\n");

    assert!(
        types.contains("pub(crate) fn new("),
        "EvidencePackage::new must be pub(crate) — a public constructor is a path to a package that \
         skipped every consumption check the assembler exists to run"
    );
    assert!(
        !types.contains("pub fn new("),
        "EvidencePackage::new is `pub` again — external code can now mint the same evidence token \
         assemble_evidence returns, with no observed spend and no linkage behind it"
    );
}

/// …and in-crate, `assemble_evidence` is the only thing that mints one. `evidence.rs` is where the
/// checks are, so a second construction site anywhere else would be a package built beside them.
#[test]
fn the_assembler_is_the_only_construction_site_for_a_package() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = Vec::new();

    for entry in walk_rust_files(&src) {
        let text = std::fs::read_to_string(&entry).expect("a source file");
        let count = text.matches("EvidencePackage::new(").count();
        if count > 0 {
            sites.push(format!("{}: {count}", entry.display()));
        }
    }

    assert_eq!(
        sites,
        vec![format!("{}: 1", src.join("evidence.rs").display())],
        "exactly one construction site, and it is the assembler"
    );
}

/// Every `.rs` file under `dir`, recursively.
fn walk_rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("a readable directory")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// The assembler's only entry key is a `NoteId`. There is no by-tx entry point to call, and the
/// evidence cannot be reached from a transaction id.
#[test]
fn the_assembler_has_no_by_transaction_entry_point() {
    let source = evidence_source();

    for forbidden in [
        "fn assemble_evidence_by_tx",
        "fn assemble_evidence_from_tx",
        "fn assemble_by_burn_tx_id",
    ] {
        assert!(
            !source.contains(forbidden),
            "`{forbidden}` would be a burnTxId-only resolution path (ASG-4)"
        );
    }
}

/// The functional half of the absence: with the note unknown to the node, a fully-populated
/// transaction stream that names the burn tx and a spend observation to match yield NOTHING. Every
/// scrap of `burnTxId`-side evidence is present and it is still not a burn — because `burnTxId`
/// alone proves nothing.
#[test]
fn a_burn_tx_id_and_a_spend_observation_without_the_note_yield_no_evidence() {
    let port = UnitPort {
        note: Err(EvidenceReadError::new(
            "GetNotesById",
            std::io::Error::other("unknown note id"),
        )),
        ..UnitPort::honest()
    };

    assert_matches!(assemble(&port), Err(EvidenceError::Read(_)));
}

// THE FULL-BLOCK UPGRADE — deferred, and deferred as a typed error
// ================================================================================================

/// P2, deliberately not built (`REQUIRES IMPLEMENTATION VALIDATION`, still open).
/// The skeleton returns its exact deferral `Err`; a panicking placeholder would take down a service
/// that releases money, on a path a caller is free to try (`return-error-not-panic`).
#[test]
fn the_full_block_upgrade_returns_its_exact_deferral_error() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");

    assert_matches!(
        full_block_upgrade(&package),
        Err(EvidenceError::FullBlockUpgradeNotImplemented)
    );
}

/// And the deferral does not quietly upgrade the labels it was going to upgrade: the tx-linkage is
/// still NODE-TRUSTED after the call, because nothing ran.
#[test]
fn the_deferred_upgrade_leaves_the_tx_linkage_node_trusted() {
    let package = assemble(&UnitPort::honest()).expect("the honest port assembles");
    let _ = full_block_upgrade(&package);

    assert_eq!(package.burn_tx_id_strength(), ProofStrength::NodeTrusted);
    assert_eq!(package.consumption_trust(), ProofStrength::NodeTrusted);
}

/// No panicking placeholder anywhere in the module — the sweep the gate runs, as a test, so it
/// fails in CI rather than in a review.
///
/// These two `contains` calls are the only place either macro's name is written in this crate: a
/// `grep -rn "todo!\|unimplemented!"` over the crate finds this test asserting their absence, and
/// nothing else. They are spelled out rather than assembled from fragments, because a guard that
/// hides from the sweep it implements is worse than no guard.
#[test]
fn the_module_has_no_panicking_placeholder() {
    let source = evidence_source();

    assert!(!source.contains("todo!"));
    assert!(!source.contains("unimplemented!"));
}

/// `src/evidence.rs` with its comments stripped — the DECLARATIONS, not the prose about them.
///
/// The module documents at length that `GetTransactionById` does not exist and must never be relied
/// on, which is exactly the string these absence tests hunt for. A sweep that read the explanation
/// as the thing it forbids would assert the opposite of what it means to — the same trap
/// `crate_posture.rs` sidesteps with `manifest_declarations()`.
fn evidence_source() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/evidence.rs"),
    )
    .expect("src/evidence.rs")
    .lines()
    .filter(|line| !line.trim_start().starts_with("//"))
    .collect::<Vec<_>>()
    .join("\n")
}

/// The comment-stripper above must not be a way to hide a violation in a trailing comment, nor may
/// it strip so much that the sweeps run against an empty string. This pins both ends: the real
/// declarations survive, the prose does not.
#[test]
fn the_source_sweep_reads_declarations_and_not_prose() {
    let source = evidence_source();

    assert!(
        source.contains("pub fn assemble_evidence"),
        "the sweep must still see the module's declarations"
    );
    assert!(
        !source.contains("retrievable"),
        "the sweep must not see the module's prose (this word appears only in its doc comments)"
    );
}

// THE WIRE — assembling evidence invents no transport for it
// ================================================================================================

/// **`burnTxId` is the only evidence field `POST /v1/withdraw` has.** `note_id`, `nullifier` and
/// `block_num` are assembled, labelled, and go NOWHERE on the wire — because whether Circle accepts
/// them, or accepts a Miden tx id as a `burnTxId` at all, is **OPEN**: `REQUIRES CIRCLE
/// CONFIRMATION`. Inventing a field for them would be answering a Circle-owned question by shipping
/// an assumption, and the shipped assumption would be the thing money moves against.
///
/// So the batch renders the four fields the OpenAPI documents and no fifth.
#[test]
fn the_withdraw_wire_carries_burn_tx_id_and_no_other_evidence_field() {
    let batch = serde_json::to_value(a_batch()).expect("a batch serializes");
    let keys: Vec<&str> = batch
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();

    assert_eq!(
        keys,
        [
            "burnIntents",
            "burnSignatures",
            "burnTxId",
            "useCircleForwarding"
        ],
        "the POST /v1/withdraw batch is schema-exact: burnTxId is its ONLY evidence field"
    );
}

/// And the schema refuses one being added: the extra evidence cannot be smuggled onto the wire even
/// by a caller who wants it there. `deny_unknown_fields` is what makes the test above a rule rather
/// than an observation about today's struct.
#[rstest]
#[case::note_id("noteId")]
#[case::nullifier("nullifier")]
#[case::block_num("blockNum")]
#[case::evidence("burnEvidence")]
fn an_invented_evidence_field_is_refused_by_the_withdraw_schema(#[case] field: &str) {
    let mut body = serde_json::to_value(a_batch()).expect("a batch serializes");
    body.as_object_mut()
        .expect("a JSON object")
        .insert(field.to_string(), serde_json::json!("0xdeadbeef"));

    let error = serde_json::from_value::<WithdrawBatch>(body)
        .expect_err("an undocumented evidence field must be refused");

    // Pin the SPECIFIC failure, not `is_err()`. `serde_json::Error` is opaque rather than an enum
    // this crate can `assert_matches!` on, so the two things that identify the intended rejection are
    // asserted directly: the DATA category (a schema violation — not a syntax error, not an I/O
    // error), and the unknown-field refusal naming the field that was injected. Accepting any error
    // here would let an unrelated deserialization regression pass this family off as green.
    assert_eq!(
        error.classify(),
        serde_json::error::Category::Data,
        "the refusal must be the schema rejecting the field, not a malformed-JSON error"
    );
    let message = error.to_string();
    assert!(
        message.contains("unknown field") && message.contains(field),
        "`{field}` must be refused BY NAME as an unknown field — DEV-7 is OPEN, and a wire that \
         accepted it would have resolved it; got: {message}"
    );
}

/// A schema-valid batch (1 intent, 2 signatures), built from the frozen `prepare_withdrawal_200`
/// fixture's canonical intent rather than from a hand-written one — the same construction
/// `build_withdraw_request.rs` uses, so this file cannot drift onto a private idea of the shape.
fn a_batch() -> WithdrawBatch {
    let prepared = support::fixture_json("prepare_withdrawal_200");
    let intents: Vec<BurnIntent> =
        serde_json::from_value(prepared["batches"][0]["burnIntents"].clone())
            .expect("the fixture burnIntents deserialize");

    WithdrawBatch::new(
        intents,
        vec![
            HexBytes::new(format!("0x{}", "11".repeat(65))).unwrap(),
            HexBytes::new(format!("0x{}", "22".repeat(65))).unwrap(),
        ],
        burn_tx_id().to_hex(),
        false,
    )
    .expect("a 1-intent, 2-signature batch is valid")
}
