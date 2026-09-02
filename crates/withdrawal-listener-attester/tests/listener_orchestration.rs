//! The **happy path**, the **DO-NOT-SIGN abort**, and the **batch↔burn cardinality**, driven end
//! to end against the schema-exact Circle mock and the unit evidence adapter. **NON-GATING** (the
//! real-node leg is parked; see `listener_support/mod.rs`).
//!
//! Its siblings: `listener_quorum_and_conflict.rs` (the quorum shape, the allowlist gate, the
//! discovery gate's refusals, the `409` contract, idempotency, fail-closed evidence, observability)
//! and `listener_structural_absence.rs` (what the orchestration must not be able to do). Split to
//! stay within the ~700-line Rust ceiling, over one `listener_support` fixture module.
//!
//! # What is actually being proven here, and why the oracle is not the return value
//!
//! Every case in this file is about an ORDER, and an order is not observable in an outcome. A run
//! that signed a mismatching response and then discarded the signature returns the same `Err` as a
//! run that never signed at all. So the assertions land on two things the return value cannot fake:
//!
//! * **the mock's CALL LOG** — how many `POST /v1/prepare-withdrawal`, `POST /v1/withdraw` and
//!   `GET /v1/withdrawal/{id}` requests were actually built and sent;
//! * **a COUNTING signer** — how many times the orchestration reached the signing step.
//!
//! `signer.calls() == 0` on every do-not-sign path, and `withdraw_posts == 0` on every
//! stage-refusal, are the whole point of the file.
//!
//! # The invariants this half maps to
//!
//! * Circle's returned spec must match the burn note before signing — the mismatch family.
//! * The batch↔burn cardinality (one prepared batch, one submitted batch: one burn, one payload, one batch) — the cardinality family.
use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::{json, Value};

use withdrawal_listener_attester::attester::{recover_address, Address, MIN_SIGNATURE_THRESHOLD};
use withdrawal_listener_attester::circle::schema::WithdrawalStatusKind;
use withdrawal_listener_attester::error::{ListenerError, ValidationMismatch};
use withdrawal_listener_attester::idempotency::SubmissionStatus;
use withdrawal_listener_attester::listener::{
    run_once, Outcome, RunContext, RunError, ONE_BATCH_PER_BURN, ONE_INTENT_PER_BURN,
};

#[path = "listener_support/mod.rs"]
mod listener_support;

use listener_support::evidence_support::UnitPort;
use listener_support::mock_circle::{Reply, Script};
use listener_support::*;

// ================================================================================================
// HAPPY PATH — discovery through to the status poll
// ================================================================================================

/// The whole flow, once: a public, correctly-tagged burn note is discovered, Circle prepares
/// intents that match it, two registered attesters sign, the evidence assembles, ONE withdrawal is
/// submitted, and the status poll takes it to `finalized`.
///
/// The counted oracle is the point: **exactly one** `POST /v1/withdraw`, carrying **exactly one**
/// batch with **exactly two** signatures.
#[tokio::test]
async fn happy_path_b3_to_b10_submits_exactly_one_withdrawal_with_two_signatures() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    let outcome = run_once(&ctx, &discovered())
        .await
        .expect("the happy path runs");

    assert_matches!(
        outcome,
        Outcome::Withdrawn { ref burn_tx_id, ref status, .. }
            if *burn_tx_id == listener_support::burn_tx_id()
                && status.status() == WithdrawalStatusKind::Finalized
    );
    assert_eq!(prepare_posts(&mock), 1, "B5 asked Circle exactly once");
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "exactly ONE withdrawal was submitted"
    );
    assert!(status_gets(&mock) >= 1, "B10 polled the withdrawal");
    assert_eq!(signer.calls(), 1, "B6 ran exactly once");

    let body = withdraw_body(&mock, 0);
    let batches = body["batches"].as_array().expect("the batches[] wrapper");
    assert_eq!(
        batches.len(),
        ONE_BATCH_PER_BURN,
        "one burn is one batch on the wire"
    );
    assert_eq!(
        batches[0]["burnSignatures"].as_array().unwrap().len(),
        MIN_SIGNATURE_THRESHOLD,
        "the submitted batch carries exactly the threshold"
    );
}

/// The signatures that reach the wire ARE `assemble_quorum`'s shape: exactly the threshold, each
/// recovering to a REGISTERED attester over the validated digest, strictly ascending by signer
/// address, no duplicate. This is the off-chain mirror of Circle's source-chain verifier, asserted
/// on the bytes the driver actually sent rather than on the value the assembler returned.
#[tokio::test]
async fn the_submitted_signatures_carry_the_on_chain_quorum_shape() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    run_once(&ctx, &discovered())
        .await
        .expect("the happy path runs");

    let digest = fixture_digest();
    let signers: Vec<Address> = withdraw_body(&mock, 0)["batches"][0]["burnSignatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hex| {
            let bytes = decode_signature(hex.as_str().unwrap());
            recover_address(&digest, &bytes).expect("every submitted signature recovers")
        })
        .collect();

    assert_eq!(signers.len(), MIN_SIGNATURE_THRESHOLD, "exactly-2");
    assert!(
        signers.windows(2).all(|w| w[0] < w[1]),
        "strictly ascending by signer address, so no duplicate either: {signers:?}"
    );
    for signer in &signers {
        assert!(
            cfg.attester_allowlist().contains(signer),
            "every submitted signer is a registered attester: {signer}"
        );
    }
}

/// The `burnTxId` on the wire is the one the evidence assembler resolved — not a value the
/// orchestration invented, and not the note id. If the evidence port resolves a different burn
/// transaction, the wire follows it.
#[tokio::test]
async fn the_wire_burn_tx_id_is_the_assembled_evidence_burn_tx_id() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    run_once(&ctx, &discovered())
        .await
        .expect("the happy path runs");

    assert_eq!(
        withdraw_body(&mock, 0)["batches"][0]["burnTxId"]
            .as_str()
            .unwrap(),
        listener_support::burn_tx_id(),
        "the batch is keyed on DC-8's burnTxId"
    );
    assert_ne!(
        withdraw_body(&mock, 0)["batches"][0]["burnTxId"]
            .as_str()
            .unwrap(),
        note_id().to_hex(),
        "and it is the TRANSACTION that consumed the note, not the note itself"
    );
}

/// A `finalized` status poll settles the burn in the durable ledger — so the next pass sees a
/// settled burn rather than re-deriving one.
#[tokio::test]
async fn a_finalized_poll_settles_the_burn_in_the_ledger() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    run_once(&ctx, &discovered())
        .await
        .expect("the happy path runs");

    assert_eq!(
        ledger_status(&ledger, &listener_support::burn_tx_id()),
        Some(SubmissionStatus::Finalized)
    );
}

/// A non-terminal poll answer does NOT settle the burn. Only Circle's `finalized` is terminal
/// success — reporting `expired` or `failed` as done would mark a burn released that was
/// not.
#[rstest]
#[case::expired("expired")]
#[case::failed("failed")]
#[case::created("created")]
#[tokio::test]
async fn a_non_finalized_poll_answer_never_settles_the_burn(#[case] status: &str) {
    let mock = mock(
        Script::new()
            .prepare(vec![Reply::json(200, prepare_200())])
            .withdraw(vec![Reply::json(201, created_201())])
            .status(vec![Reply::json(200, status_200(status))]),
    );
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    let outcome = run_once(&ctx, &discovered()).await;

    // `created` never settles, so the poll runs to its bound and surfaces PollExhausted rather than
    // reporting a pending status as an answer; `expired`/`failed` stop the poll and are reported
    // honestly, but neither settles the ledger.
    if status == "created" {
        assert_matches!(
            outcome,
            Err(RunError::Circle(ListenerError::PollExhausted { after })) if after == POLL_ATTEMPTS
        );
    } else {
        let expected = match status {
            "expired" => WithdrawalStatusKind::Expired,
            "failed" => WithdrawalStatusKind::Failed,
            other => panic!("unmapped status `{other}`"),
        };
        assert_matches!(
            outcome,
            Ok(Outcome::Withdrawn { ref status, .. }) if status.status() == expected
        );
    }
    assert_ne!(
        ledger_status(&ledger, &listener_support::burn_tx_id()),
        Some(SubmissionStatus::Finalized),
        "`{status}` is not a release: the burn must not be settled as finalized"
    );
}

// ================================================================================================
// THE DO-NOT-SIGN ABORT — validation gates signing
// ================================================================================================

/// **The mandatory negative.** Circle returns a spec that does not match the burn or request-owned
/// terms → the run aborts with the exact `ValidationMismatch`, **the signer is invoked zero
/// times**, and **no `POST /v1/withdraw` is issued**.
///
/// Each mismatch class is its own case (Circle's documentation lists them separately), and the
/// missing/empty digest is here too: a non-signable hash must be refused BEFORE signing, not handed
/// to the signer. Each case pins its EXACT `ValidationMismatch`. A wildcard would pass for a run
/// that refused the amount mismatch because it thought the RECIPIENT was wrong — i.e. for a build
/// in which the amount comparison had silently stopped working, which is the one this table exists
/// to catch.
///
/// The expected error is derived from the same `payload()` the request was built from rather than
/// written out as a literal: a literal would be a second source of truth for the fixture, and the
/// natural response to a fixture edit would be to "correct" the literal until the test passed
/// again.
#[rstest]
#[case::amount("value", json!("999"))]
#[case::destination_domain("destinationDomain", json!(WRONG_DOMAIN))]
#[case::destination_recipient("destinationRecipient", json!(WRONG_RECIPIENT))]
#[tokio::test]
async fn a_b5_spec_mismatch_produces_no_signature_and_no_withdraw(
    #[case] field: &str,
    #[case] value: Value,
) {
    let expected = match field {
        "value" => ValidationMismatch::Amount {
            batch: 0,
            expected: payload().amount.as_u64(),
            returned: String::from("999"),
        },
        "destinationDomain" => ValidationMismatch::DestinationDomain {
            batch: 0,
            expected: payload().dest_domain,
            returned: WRONG_DOMAIN,
        },
        "destinationRecipient" => ValidationMismatch::DestinationRecipient {
            batch: 0,
            expected: format!("0x{}", hex::encode(payload().dest_recipient.as_bytes())),
            returned: String::from(WRONG_RECIPIENT),
        },
        other => panic!("unmapped mismatch class `{other}`"),
    };

    let mock = mock(happy_script().prepare(vec![Reply::json(
        200,
        prepare_200_with_spec_field(field, value),
    )]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(outcome, Err(RunError::Validation(actual)) if actual == expected);
    assert_eq!(
        signer.calls(),
        0,
        "the signer must be UNREACHED on a B5 mismatch (B5 gates B6)"
    );
    assert_eq!(withdraw_posts(&mock), 0, "and nothing was submitted");
}

/// The fields not carried directly by the four-field burn attachment are still bound before
/// signing: the listener derives the expected neutral terms from the discovered burn plus config,
/// and any divergence aborts at B5.
#[rstest]
#[case::max_fee(&["maxFee"], json!("1001"), "maxFee")]
#[case::salt(
    &["spec", "salt"],
    json!("0x2222222222222222222222222222222222222222222222222222222222222222"),
    "salt"
)]
#[case::destination_caller(
    &["spec", "destinationCaller"],
    json!("0x0000000000000000000000000000000000000000000000000000000000000001"),
    "destinationCaller"
)]
#[case::hook_remote_domain(&["spec", "hookData", "remoteDomain"], json!(10_002), "hookData.remoteDomain")]
#[case::hook_remote_depositor(
    &["spec", "hookData", "remoteDepositor"],
    json!("0x0000000000000000000000000000000000000000000000000000000000000000"),
    "hookData.remoteDepositor"
)]
#[case::hook_remote_token(
    &["spec", "hookData", "remoteToken"],
    json!("0x0000000000000000000000000000000000000000000000000000000000000000"),
    "hookData.remoteToken"
)]
#[case::hook_forwarding_contract(
    &["spec", "hookData", "forwardingContractAddress"],
    json!("0x0000000000000000000000000000000000000001"),
    "hookData.forwardingContractAddress"
)]
#[case::hook_forwarding_calldata(
    &["spec", "hookData", "forwardingCalldata"],
    json!("0x12345678"),
    "hookData.forwardingCalldata"
)]
#[tokio::test]
async fn a_b5_redemption_term_mismatch_produces_no_signature_and_no_withdraw(
    #[case] path: &[&str],
    #[case] value: Value,
    #[case] expected: &str,
) {
    let mock = mock(happy_script().prepare(vec![Reply::json(
        200,
        prepare_200_with_intent_field(path, value),
    )]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    let err = match outcome {
        Err(RunError::Validation(err)) => err,
        other => panic!("expected B5 validation refusal, got {other:?}"),
    };
    match expected {
        "maxFee" => assert_matches!(err, ValidationMismatch::MaxFee { batch: 0, .. }),
        "salt" => assert_matches!(err, ValidationMismatch::Salt { batch: 0, .. }),
        "destinationCaller" => {
            assert_matches!(err, ValidationMismatch::DestinationCaller { batch: 0, .. })
        }
        "hookData.remoteDomain" => {
            assert_matches!(
                err,
                ValidationMismatch::HookData {
                    batch: 0,
                    field: "remoteDomain",
                    ..
                }
            )
        }
        "hookData.remoteDepositor" => {
            assert_matches!(
                err,
                ValidationMismatch::HookData {
                    batch: 0,
                    field: "remoteDepositor",
                    ..
                }
            )
        }
        "hookData.remoteToken" => {
            assert_matches!(
                err,
                ValidationMismatch::HookData {
                    batch: 0,
                    field: "remoteToken",
                    ..
                }
            )
        }
        "hookData.forwardingContractAddress" => {
            assert_matches!(
                err,
                ValidationMismatch::HookData {
                    batch: 0,
                    field: "forwardingContractAddress",
                    ..
                }
            )
        }
        "hookData.forwardingCalldata" => {
            assert_matches!(
                err,
                ValidationMismatch::HookData {
                    batch: 0,
                    field: "forwardingCalldata",
                    ..
                }
            )
        }
        other => panic!("unmapped mismatch class `{other}`"),
    }
    assert_eq!(
        signer.calls(),
        0,
        "the signer must be UNREACHED on a B5 term mismatch"
    );
    assert_eq!(withdraw_posts(&mock), 0, "and nothing was submitted");
}

/// The digest itself: present-but-empty, and present-but-not-32-bytes. Both are refused by the gate
/// with their exact variants, and neither reaches the signer.
#[rstest]
#[case::empty("", ValidationMismatch::MissingMessageHash { batch: 0 })]
#[case::short("0xdeadbeef", ValidationMismatch::MalformedMessageHash { batch: 0, len: 4 })]
#[tokio::test]
async fn a_non_signable_digest_is_refused_before_the_signer(
    #[case] hash: &str,
    #[case] expected: ValidationMismatch,
) {
    let mock = mock(happy_script().prepare(vec![Reply::json(200, prepare_200_with_hash(hash))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(outcome, Err(RunError::Validation(actual)) if actual == expected);
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

/// Re-running an aborted flow against the SAME mismatching response aborts again. The listener does
/// not "remember" that it once looked at this burn and sign it on the retry — a mismatch is a
/// property of the response, and it is re-derived every pass.
#[tokio::test]
async fn re_running_a_mismatching_burn_aborts_again_and_still_never_signs() {
    let mock = mock(happy_script().prepare(vec![Reply::json(
        200,
        prepare_200_with_spec_field("value", json!("999")),
    )]));
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    for pass in 1..=2 {
        assert_matches!(
            run_once(&ctx, &discovered()).await,
            Err(RunError::Validation(ValidationMismatch::Amount {
                batch: 0,
                ..
            })),
            "pass {pass} must abort"
        );
    }

    assert_eq!(signer.calls(), 0, "neither pass reached the signer");
    assert_eq!(withdraw_posts(&mock), 0, "neither pass submitted anything");
    assert_eq!(
        ledger_status(&ledger, &listener_support::burn_tx_id()),
        None,
        "and the burn was never claimed — the ledger is not reached before B5 passes"
    );
}

/// A non-`200` from `POST /v1/prepare-withdrawal` is Circle's answer, surfaced — never a reason to
/// sign anything.
#[rstest]
#[case::bad_request(400)]
#[case::server_error(500)]
#[tokio::test]
async fn a_failed_prepare_never_reaches_the_signer(#[case] status: u16) {
    let mock = mock(happy_script().prepare(vec![Reply::json(status, json!({}))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Err(RunError::Circle(ListenerError::Http { status: actual })) if actual == status
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

// ================================================================================================
// CARDINALITY — one burn ↔ one payload ↔ one batch, both directions
// ================================================================================================

/// **Fan-out**: Circle answers a one-burn prepare with TWO batches. Refused before the signer — a
/// signature over the second batch's digest is exactly the artifact that must not exist, and a
/// submission carrying two batches for one burn would ask Circle to release it twice.
#[tokio::test]
async fn a_two_batch_prepare_response_is_refused_before_the_signer() {
    let mock = mock(happy_script().prepare(vec![Reply::json(200, prepare_200_with_batches(2))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(outcome, Err(RunError::BatchCardinality { returned: 2 }));
    assert_eq!(
        signer.calls(),
        0,
        "no signature over a batch this burn never asked for"
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

/// An EMPTY prepare response — no batch at all. There is no spec to compare and no digest to bind,
/// so the gate refuses rather than minting a signing token vacuously.
#[tokio::test]
async fn an_empty_prepare_response_is_refused_before_the_signer() {
    let mock = mock(happy_script().prepare(vec![Reply::json(200, prepare_200_with_batches(0))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Err(RunError::Validation(ValidationMismatch::NoBatches))
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

/// **Fan-in — the one the batch count cannot see.** Circle answers a one-burn prepare with ONE
/// batch carrying the matching burn intent `n` times.
///
/// Every check upstream of this passes, and that is exactly why it needs its own gate. Each
/// repeated intent matches the burn and request-owned terms, so the field-by-field compare clears
/// every one of them; the batch's `messageHashToSign` covers the whole intent SET, so a single
/// attester signature authorizes all `n`; the quorum is a perfectly well-formed exactly-2; every
/// signer is a registered attester; and `batches.len()` is still 1, so a gate that counts BATCHES
/// sees nothing wrong at all. The result would be one discovered burn funding `n` releases — the
/// fan-in the evidence package's single `burnTxId` cannot even describe.
///
/// So the cardinality rule is one burn ↔ one payload ↔ one batch ↔ **one intent**, and it is
/// enforced before the signer: a signature over a set this burn never asked for is the artifact
/// that must not exist.
#[rstest]
#[case::two_intents(2)]
#[case::three_intents(3)]
#[case::the_schema_maximum(10)]
#[tokio::test]
async fn a_batch_carrying_the_burn_intent_more_than_once_is_refused_before_the_signer(
    #[case] n: usize,
) {
    let mock = mock(happy_script().prepare(vec![Reply::json(200, prepare_200_with_intents(n))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Err(RunError::IntentCardinality { returned }) if returned == n
    );
    assert_eq!(
        signer.calls(),
        0,
        "one signature would have authorized every one of the {n} intents"
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

/// The other direction of the same rule: a batch with NO burn intent. Its digest would be bound to
/// no amount, no domain and no recipient — a signature over nothing at all.
#[tokio::test]
async fn a_batch_carrying_no_burn_intent_is_refused_before_the_signer() {
    let mock = mock(happy_script().prepare(vec![Reply::json(200, prepare_200_with_intents(0))]));
    let (outcome, signer) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Err(RunError::Validation(ValidationMismatch::EmptyBurnIntents {
            batch: 0
        }))
    );
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

/// The wire half of the same rule, on the happy path: the submitted batch carries **exactly one**
/// burn intent. Without this, the refusals above could all pass while the honest path still shipped
/// a set — the count on the wire is what Circle actually acts on.
#[tokio::test]
async fn the_submitted_batch_carries_exactly_one_burn_intent() {
    let mock = mock(happy_script());
    let (outcome, _) = run_against(&mock, config(), UnitPort::honest()).await;
    outcome.expect("the happy path runs");

    assert_eq!(
        withdraw_body(&mock, 0)["batches"][0]["burnIntents"]
            .as_array()
            .expect("the burnIntents array")
            .len(),
        ONE_INTENT_PER_BURN,
        "one burn is one intent on the wire"
    );
}

/// A signer that returns a different NUMBER of signature sets than there are validated batches is
/// refused rather than aligned by guessing — an alignment guess is how one batch is submitted with
/// another batch's signatures.
#[rstest]
#[case::too_few(0)]
#[case::too_many(2)]
#[tokio::test]
async fn a_signer_whose_sets_do_not_line_up_with_the_batches_never_submits(#[case] sets: usize) {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::new(Behaviour::Sets(sets));
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Err(RunError::SignerCardinality { batches: 1, signed }) if signed == sets
    );
    assert_eq!(withdraw_posts(&mock), 0);
}
