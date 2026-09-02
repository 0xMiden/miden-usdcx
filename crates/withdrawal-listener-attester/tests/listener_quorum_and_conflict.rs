//! The **quorum shape on the wire**, the **pre-submit allowlist gate**, **the discovery gate's
//! refusals**, the **`409` contract**, **idempotency**, **fail-closed evidence**, and the
//! **secret-free event trace**. **NON-GATING** (the real-node leg is parked).
//!
//! Its siblings: `listener_orchestration.rs` (the happy path, the DO-NOT-SIGN abort, cardinality)
//! and `listener_structural_absence.rs`. Split to stay within the ~700-line Rust file ceiling, over
//! one `listener_support` fixture module.
//!
//! The oracle is the same and for the same reason: an outcome cannot distinguish a run that
//! recovered a `409` by polling from one that re-POSTed it and reported the answer. Only the mock's
//! CALL LOG can, so that is what every case here asserts on.
//!
//! # The invariants this half maps to
//!
//! * The quorum contract (`Attestable.sol:75,333-381` — exactly-2 / strictly-ascending /
//!   no-duplicate-signer) BOUND to the submitted batch.
//! * Circle's documented `409` contract (recover by polling, never re-send, never success-from-409)
//!   and the per-burn idempotency claim.
//! * Fail-closed burn evidence, and burn-note observability /
//!   an exact match, never a prefix, at discovery.
use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::json;

use withdrawal_listener_attester::attester::MIN_SIGNATURE_THRESHOLD;
use withdrawal_listener_attester::circle::schema::WithdrawalStatusKind;
use withdrawal_listener_attester::error::{DiscoveryReject, QuorumError, SubmitGateError};
use withdrawal_listener_attester::evidence::{
    AmbiguityReason, EvidenceError, EvidenceReadError, NullifierRecord,
};
use withdrawal_listener_attester::idempotency::SubmissionStatus;
use withdrawal_listener_attester::listener::{
    run_once, Outcome, ReconciliationReason, RunContext, RunError,
};

#[path = "listener_support/mod.rs"]
mod listener_support;

use listener_support::evidence_support::UnitPort;
use listener_support::mock_circle::Reply;
use listener_support::*;

// ================================================================================================
// THE QUORUM GATE — the submitted batch carries assemble_quorum's SHAPE, or it is not submitted
// ================================================================================================

/// Every signature-set shape Circle's source-chain verifier rejects is refused HERE, off-chain, and
/// **none of them reaches `POST /v1/withdraw`**.
///
/// The signer is driven to produce each shape deliberately, so the case is about the
/// orchestration's binding to `assemble_quorum` rather than about the production signer happening
/// to behave. In particular the single-signature case is the "≥2 treated as enough" bug and the
/// three-signature case is the "more is safer" one — Circle's verifier is exactly-2
/// (`Attestable.sol:75,333-381`). Each case pins its EXACT `QuorumError`. The distinction is not
/// cosmetic: a below-threshold set reported as `NotAscending`, or a duplicate silently reported as
/// `BelowThreshold`, would mean the count check and the duplicate check had swapped places — and
/// `DuplicateSigner` in particular must never degrade into a count error, because "de-duplicate
/// then count" is exactly how a 2-signer set collapses into a submitted single-key quorum.
#[rstest]
#[case::below_threshold(
    vec![ATTESTER_A],
    QuorumError::BelowThreshold { have: 1, need: MIN_SIGNATURE_THRESHOLD }
)]
#[case::above_threshold(
    vec![ATTESTER_A, ATTESTER_B, OUTSIDER],
    QuorumError::AboveThreshold { have: 3, need: MIN_SIGNATURE_THRESHOLD }
)]
#[case::duplicate_signer(vec![ATTESTER_A, ATTESTER_A], QuorumError::DuplicateSigner { address: address(ATTESTER_A) })]
#[tokio::test]
async fn a_signature_set_that_is_not_the_on_chain_shape_never_reaches_the_wire(
    #[case] keys: Vec<u8>,
    #[case] expected: QuorumError,
) {
    let digest = fixture_digest();
    let mut pairs: Vec<_> = keys.iter().map(|k| signed_pair(*k, &digest)).collect();
    pairs.sort_by_key(|(address, _)| *address); // ascending, so the COUNT/dup rule is what fires

    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::new(Behaviour::Fixed(pairs));
    let events = CapturingEvents::new();
    let cfg = config_allowing(&[ATTESTER_A, ATTESTER_B, OUTSIDER]);
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Err(RunError::Quorum(actual)) if actual == expected
    );
    assert_eq!(
        withdraw_posts(&mock),
        0,
        "a set that is not exactly-2 / no-duplicate never becomes a batch"
    );
}

/// Descending signer order is refused too, and it is the case an allowlist check would miss
/// entirely: both signers ARE registered attesters, so membership passes — **membership is not
/// shape**, and Circle's verifier requires strictly ascending.
#[tokio::test]
async fn a_descending_signature_set_never_reaches_the_wire() {
    let digest = fixture_digest();
    let mut pairs = vec![
        signed_pair(ATTESTER_A, &digest),
        signed_pair(ATTESTER_B, &digest),
    ];
    pairs.sort_by_key(|(address, _)| *address);
    pairs.reverse(); // strictly DESCENDING — every signer still allowlisted

    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::new(Behaviour::Fixed(pairs));
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Err(RunError::Quorum(QuorumError::NotAscending { at: 1 }))
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

/// A signature paired with a signer that did not produce it is refused — the `ECDSA.recover`-then-
/// authorize step, run off-chain before the wire rather than at Circle's fund-release boundary.
#[tokio::test]
async fn a_signature_that_does_not_verify_to_its_claimed_signer_never_reaches_the_wire() {
    let digest = fixture_digest();
    let (_, sig_a) = signed_pair(ATTESTER_A, &digest);
    // claimed = the OUTSIDER's address, signature = A's — a mis-attributed pair
    let mut pairs = vec![(address(OUTSIDER), sig_a), signed_pair(ATTESTER_B, &digest)];
    pairs.sort_by_key(|(address, _)| *address);
    // the exact index the refusal must name, resolved AFTER the sort rather than assumed: the pairs
    // are ordered by address, and which side the outsider lands on is a fact about two keccak hashes,
    // not something this test gets to decide.
    let mis_attributed_at = pairs
        .iter()
        .position(|(claimed, _)| *claimed == address(OUTSIDER))
        .expect("the mis-attributed pair is in the set");

    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::new(Behaviour::Fixed(pairs));
    let events = CapturingEvents::new();
    let cfg = config_allowing(&[ATTESTER_A, ATTESTER_B, OUTSIDER]);
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Err(RunError::Quorum(QuorumError::SignatureDoesNotVerify { at }))
            if at == mis_attributed_at
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

// ================================================================================================
// THE PRE-SUBMIT ALLOWLIST GATE — sign happens, submit does not
// ================================================================================================

/// A signature from a key that is not a registered attester: the run does sign — validation passed,
/// so signing legitimately happens — and then the allowlist gate refuses, so **zero**
/// `/v1/withdraw` calls go out.
///
/// The signer count being ONE here is as load-bearing as the zeros above: it proves the pipeline
/// really is validate → sign → authorize → submit, and that the refusal is the AUTHORIZE stage
/// failing closed rather than an earlier stage never having run.
#[tokio::test]
async fn an_unregistered_signer_is_refused_after_signing_and_before_any_submit() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    // ATTESTER_B signs but is NOT registered
    let cfg = config_allowing(&[ATTESTER_A]);
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        // exact: the refusal must name the UNREGISTERED signer, not merely fire. Naming the wrong one
        // would send an operator to revoke a key that was never the problem.
        Err(RunError::Gate(SubmitGateError::SignerNotAllowlisted { batch: 0, signer, .. }))
            if signer == address(ATTESTER_B)
    );
    assert_eq!(signer.calls(), 1, "B5 passed, so B6 ran — the order held");
    assert_eq!(
        withdraw_posts(&mock),
        0,
        "and the gate stopped the submission"
    );
    assert_eq!(
        ledger_status(&ledger, &listener_support::burn_tx_id()),
        None,
        "a refused submission never claims the burn"
    );
}

/// No allowlist configured at all → fail closed. An empty allowlist is not "allow everything".
#[tokio::test]
async fn an_empty_allowlist_fails_closed_and_never_submits() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config_allowing(&[]);
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Err(RunError::Gate(SubmitGateError::NoAttestersConfigured))
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

// ================================================================================================
// DISCOVERY — nothing leaves the process before discovery passes
// ================================================================================================

/// A wrong-tag note is not this listener's note. Circle is never asked about it — the tag is
/// matched by exact full-32-bit equality, so a note sharing the high 16 bits is a DIFFERENT note
/// (an exact match, never a prefix).
#[tokio::test]
async fn a_wrong_tag_note_is_refused_before_circle_is_touched() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    // the configured tag with its LOW half changed: a prefix-scan would match, an exact scan must not
    let near_miss = (BURN_TAG & 0xFFFF_0000) | 0x0000_DEAD;
    let note = discovered_with(near_miss, Some(payload()));

    assert_matches!(
        run_once(&ctx, &note).await,
        Err(RunError::Discovery(DiscoveryReject::TagMismatch { .. }))
    );
    assert_eq!(prepare_posts(&mock), 0, "Circle was never asked");
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

/// A private/erased note (`details = None`) is unobservable to Circle and is refused, not attested
/// to.
#[tokio::test]
async fn a_private_note_is_refused_before_circle_is_touched() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered_with(BURN_TAG, None)).await,
        Err(RunError::Discovery(
            DiscoveryReject::PrivateNoteUnobservable
        ))
    );
    assert_eq!(prepare_posts(&mock), 0);
    assert_eq!(signer.calls(), 0);
    assert_eq!(withdraw_posts(&mock), 0);
}

// ================================================================================================
// THE 409 — recovered by polling, NEVER re-sent
// ================================================================================================

/// A `409` naming a `withdrawalId` is RECOVERED by polling it. The oracle is the call log:
/// **exactly one** `POST /v1/withdraw` ever went out, and the recovery is a `GET`.
#[tokio::test]
async fn a_409_recovers_via_poll_and_never_re_sends() {
    let mock = mock(
        happy_script()
            .withdraw(vec![Reply::json(409, conflict_409(true))])
            .status(vec![Reply::json(200, status_200("finalized"))]),
    );
    let (outcome, _) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Ok(Outcome::ConflictRecovered { ref status, .. })
            if status.status() == WithdrawalStatusKind::Finalized
    );
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "a 409 is NEVER answered by a second POST"
    );
    assert!(status_gets(&mock) >= 1, "it is answered by a poll");
}

/// A `409` carrying only `conflict.burnTxId` has no withdrawal to recover through: resubmission
/// STOPS and the burn is left for an operator. No second POST, and no poll either — there is
/// nothing to poll.
#[tokio::test]
async fn a_409_naming_no_withdrawal_stops_and_requires_reconciliation() {
    let mock = mock(happy_script().withdraw(vec![Reply::json(409, conflict_409(false))]));
    let (outcome, _) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Ok(Outcome::ReconciliationRequired {
            reason: ReconciliationReason::ConflictNamedNoWithdrawal,
            ..
        })
    );
    assert_eq!(withdraw_posts(&mock), 1, "no re-send");
    assert_eq!(status_gets(&mock), 0, "and no id to poll");
}

/// A `409` that echoes a DIFFERENT `burnTxId` is a defect, not a recovery: it is about some other
/// burn, so nothing about it may be believed of ours — and its `withdrawalId` is not chased.
#[tokio::test]
async fn a_409_echoing_another_burn_is_a_defect_and_is_not_chased() {
    let mut body = conflict_409(true);
    body["burnTxId"] = json!("0x1111111111111111111111111111111111111111111111111111111111111111");
    let mock = mock(happy_script().withdraw(vec![Reply::json(409, body)]));
    let (outcome, _) = run_against(&mock, config(), UnitPort::honest()).await;

    assert_matches!(
        outcome,
        Ok(Outcome::ReconciliationRequired {
            reason: ReconciliationReason::EchoMismatch { .. },
            ..
        })
    );
    assert_eq!(withdraw_posts(&mock), 1);
    assert_eq!(
        status_gets(&mock),
        0,
        "a stranger's withdrawalId is never polled as ours"
    );
}

// ================================================================================================
// IDEMPOTENCY — one burn is submitted at most once, ever
// ================================================================================================

/// Re-running an already-withdrawn burn does **not** double-submit. The second pass re-does
/// discovery through signing (the flow is stateless up to the ledger) and then the durable claim
/// answers: `AlreadySubmitted`, with **zero** further `POST /v1/withdraw` calls.
#[tokio::test]
async fn re_running_an_already_withdrawn_burn_does_not_double_submit() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Ok(Outcome::Withdrawn { .. })
    );
    let posts_after_first = withdraw_posts(&mock);

    let second = run_once(&ctx, &discovered()).await;

    assert_matches!(
        second,
        Ok(Outcome::AlreadySubmitted {
            status: SubmissionStatus::Finalized,
            ..
        })
    );
    assert_eq!(posts_after_first, 1);
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "the second pass submitted NOTHING — the ledger decided before the wire"
    );
}

/// …and the claim is DURABLE, not a property of one process: a second, independently-opened ledger
/// over the same file refuses the burn just the same. This is the restart case.
#[tokio::test]
async fn a_restarted_process_does_not_re_submit_a_claimed_burn() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = config();
    let port = UnitPort::honest();

    {
        let ledger = ledger_in(&dir);
        let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);
        run_once(&ctx, &discovered())
            .await
            .expect("the first run submits");
    }

    // a second handle on the SAME file — the process restarted
    let reopened = ledger_in(&dir);
    let ctx = RunContext::new(&cfg, &circle, &reopened, &signer, &port, &events);
    assert_matches!(
        run_once(&ctx, &discovered()).await,
        Ok(Outcome::AlreadySubmitted { .. })
    );
    assert_eq!(withdraw_posts(&mock), 1);
}

// ================================================================================================
// THE EVIDENCE FAILS CLOSED — a burn with no honest evidence is never submitted
// ================================================================================================

/// The nullifier is not reported spent: the note's CREATION is cryptographically proved and that is
/// not a burn. No package, therefore no `burnTxId`, therefore no batch — and the signer HAS run, so
/// this is the evidence stage failing closed rather than an earlier stage having stopped things.
#[tokio::test]
async fn evidence_with_no_observed_spend_blocks_the_burn_and_never_submits() {
    let mock = mock(happy_script());
    let port = UnitPort {
        spend: Ok(NullifierRecord {
            nullifier: listener_support::evidence_support::burn_nullifier(),
            spent_in_block: None,
        }),
        ..UnitPort::honest()
    };
    let (outcome, signer) = run_against(&mock, config(), port).await;

    assert_matches!(
        outcome,
        Err(RunError::Evidence(EvidenceError::ReconciliationRequired {
            reason: AmbiguityReason::NoSpendObserved,
            ..
        }))
    );
    assert_eq!(signer.calls(), 1, "B6 ran; B7's evidence is what refused");
    assert_eq!(withdraw_posts(&mock), 0);
}

/// A failed evidence READ is an absence of information, not "no burn" — and it is likewise never a
/// submission.
#[tokio::test]
async fn a_failed_evidence_read_never_submits() {
    let mock = mock(happy_script());
    let port = UnitPort {
        note: Err(EvidenceReadError::new(
            "GetNotesById",
            std::io::Error::other("node unreachable"),
        )),
        ..UnitPort::honest()
    };
    let (outcome, _) = run_against(&mock, config(), port).await;

    // exact: the failure must name the RPC that failed. "some read broke" and "GetNotesById is
    // unreachable" are different operator responses, and the taxonomy exists to tell them apart.
    assert_matches!(
        outcome,
        Err(RunError::Evidence(EvidenceError::Read(error))) if error.rpc() == "GetNotesById"
    );
    assert_eq!(withdraw_posts(&mock), 0);
}

// ================================================================================================
// OBSERVABILITY — structured, and no secret in it
// ================================================================================================

/// **No emitted event carries key material or a credential.** The run is driven with a config
/// holding a real out-of-band API token and with signers holding real secret keys; every event, as
/// an operator's log would render it, is swept for the token, the key bytes, and the derived
/// signatures.
///
/// The oracle is the RENDERED event (`Debug`), not the struct's field list: a field that
/// stringifies a secret would pass a shape check and leak anyway.
#[tokio::test]
async fn no_emitted_event_carries_key_material_or_a_credential() {
    const TOKEN: &str = "sk-live-the-circle-credential-that-must-never-be-logged";

    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let signer = CountingSigner::production();
    let events = CapturingEvents::new();
    let cfg = withdrawal_listener_attester::config::ListenerConfig::builder()
        .burn_tag(BURN_TAG)
        .miden_domain(MIDEN_DOMAIN)
        .max_withdrawal_fee(fixture_max_fee())
        .attester_allowlist(
            withdrawal_listener_attester::attester::AttesterAllowlist::new([
                address(ATTESTER_A),
                address(ATTESTER_B),
            ]),
        )
        .api_auth_token(withdrawal_listener_attester::config::SecretString::new(
            TOKEN,
        ))
        .api_auth_header("x-circle-key")
        .build()
        .expect("a config with a credential over the https default base url is valid");
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    run_once(&ctx, &discovered())
        .await
        .expect("the happy path runs");

    let log = events.rendered();
    assert!(!log.is_empty(), "the run emitted events at all");
    assert!(
        !log.contains(TOKEN),
        "the api credential must never reach an event: {log}"
    );
    for attester in [ATTESTER_A, ATTESTER_B] {
        let key_hex = hex::encode([attester; 32]);
        assert!(
            !log.to_lowercase().contains(&key_hex),
            "attester key material must never reach an event: {log}"
        );
    }
    let (_, signature) = signed_pair(ATTESTER_A, &fixture_digest());
    assert!(
        !log.to_lowercase().contains(&signature.to_hex()[2..]),
        "not even a signature belongs in an event: {log}"
    );
}

/// The happy path emits a structured trace through the B-steps, in order — so an operator can see
/// where a burn is, and an alert can match on a stable slug.
#[tokio::test]
async fn the_happy_path_emits_a_step_trace_in_flow_order() {
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

    let steps: Vec<String> = events.steps().into_iter().map(|(step, _)| step).collect();
    for expected in ["B3", "B4", "B5", "B6", "B7", "B10"] {
        assert!(
            steps.contains(&expected.to_string()),
            "every B-step reports: missing {expected} in {steps:?}"
        );
    }
    let position = |s: &str| steps.iter().position(|x| x == s).unwrap();
    assert!(
        position("B3") < position("B5")
            && position("B5") < position("B6")
            && position("B6") < position("B7")
            && position("B7") < position("B10"),
        "and they report in flow order: {steps:?}"
    );
    assert!(
        events
            .events()
            .iter()
            .filter(|e| e.step == "B3" || e.step == "B4" || e.step == "B5")
            .all(|e| e.burn_tx_id.is_none()),
        "no burnTxId is reported before DC-8 resolves one"
    );
}
