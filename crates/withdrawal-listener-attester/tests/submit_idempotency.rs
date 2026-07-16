//! `T-LA-13` — **per-burn cross-invocation idempotency**: the durable claim, and the fact that
//! there is NO way around it.
//!
//! The property: the same burn — re-discovered, retried, or met again after a restart — is submitted to
//! Circle **at most once, ever**. Unlike the deposit relayer's nonce log (whose real backstop is the
//! faucet's on-chain `usedNonces` assert), this ledger has nothing behind it but Circle's `409`, and
//! §10.10 forbids answering a `409` by re-sending. So the claim IS the safety property.
//!
//! Every case asserts on the mock's CALL LOG — an outcome alone would pass for a driver that submitted
//! twice and reported tidily.

use std::slice;

use assert_matches::assert_matches;
use rstest::rstest;

use withdrawal_listener_attester::idempotency::{
    BurnKey, ClaimOutcome, LedgerError, SubmissionStatus, SubmitLedger,
};
use withdrawal_listener_attester::submit::{submit_withdraw, SubmitError, SubmitOutcome};

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::{MockCircle, Reply, Script};
use submit_support::*;

// ================================================================================================
// THERE IS NO PATH AROUND THE CLAIM
// ================================================================================================

/// **The claim cannot be bypassed, because there is no public function that submits without it.**
///
/// This is a source-level guard, and it is here because the property is an ABSENCE — no test can call
/// a function that must not exist. The crate already guards decisions this way where the compiler
/// cannot (`crate_posture.rs` reads the manifest to pin `k256` as a library dependency).
///
/// The history it pins: `withdrawal_api::withdraw` used to be a PUBLIC raw driver that POSTed straight
/// from an `AuthorizedWithdrawal` with no ledger. `WithdrawRequest` is `Clone` and
/// `authorize_submission` is public, so a caller could mint two tokens for one burn and submit it
/// twice — the exact double-release the ledger exists to prevent, reachable without touching the
/// ledger at all. Calling `submit_withdraw` "the production entry point" in a doc comment did not
/// make that unrepresentable; deleting the driver did.
#[test]
fn no_public_api_can_post_a_withdrawal_without_the_ledger() {
    let withdrawal_api = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/withdrawal_api.rs"),
    )
    .unwrap();

    assert!(
        !withdrawal_api.contains("pub async fn withdraw("),
        "a public raw withdraw driver would let a caller POST /v1/withdraw without a ledger claim — \
         the submission path must go through `submit::submit_withdraw`, which requires one"
    );

    // …and the `/v1/withdraw` route is REACHED from exactly one module: the one that claims first.
    //
    // `withdrawal_api` still owns the path constant (it owns the endpoint's shapes), so its single
    // mention there must be the declaration and nothing else — a second mention would be a request
    // being built against the route outside the claim. `prepare` and `poll_status` are deliberately not
    // implicated: they are read-only, they release nothing, and no ledger governs them.
    assert_eq!(
        mentions_of("PATH_WITHDRAW", &withdrawal_api),
        1,
        "`withdrawal_api` may DECLARE the /v1/withdraw path, but must not build a request against it \
         — that call site belongs in `submit`, after the claim"
    );

    let submit = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/submit.rs"),
    )
    .unwrap();
    assert!(
        submit.contains("build_post(PATH_WITHDRAW"),
        "submit.rs is where the one POST /v1/withdraw call site belongs"
    );
    assert!(
        submit.contains("claim_burns"),
        "and it must claim before it builds"
    );
}

/// How many times `ident` appears in `source` as a whole identifier.
///
/// Whole-identifier, because the paths this file reasons about are `PATH_WITHDRAW` and
/// `PATH_WITHDRAWAL` — one is a prefix of the other, and a substring count would silently conflate the
/// money path with the read-only status poll.
fn mentions_of(ident: &str, source: &str) -> usize {
    source
        .match_indices(ident)
        .filter(|(at, _)| {
            let after = source[at + ident.len()..].chars().next();
            !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
        .count()
}

// ================================================================================================
// THE SAME BURN IS SUBMITTED AT MOST ONCE
// ================================================================================================

/// The core fund-safety property: a re-discovered burn, re-authorized and re-submitted, produces ZERO
/// second POSTs.
#[tokio::test]
async fn the_same_burn_is_never_submitted_twice() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    let first = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the first submission goes out");
    assert_matches!(first, SubmitOutcome::Submitted(_));
    assert_eq!(withdraw_posts(&mock), 1);

    // the SAME burn, a fresh authorization (a re-discovery, a retry driver, a restarted loop)
    let second = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the second is refused, not errored");

    assert_matches!(
        &second,
        SubmitOutcome::AlreadySubmitted { burn_tx_id, status }
            if burn_tx_id == BURN_TX_ID && *status == SubmissionStatus::Submitted
    );
    assert!(!matches!(second, SubmitOutcome::Submitted(_)));
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "STILL exactly one POST — the burn was already submitted"
    );
}

/// Durability: a RESTARTED process (a second, independent handle on the same file) still refuses. An
/// in-memory store would pass every test above and fail exactly here — which is why the ledger insists
/// on a real file.
#[tokio::test]
async fn a_restarted_process_reopens_the_ledger_and_still_refuses_the_same_burn() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock);

    {
        let ledger = ledger_in(&dir);
        submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
            .await
            .expect("submitted");
    } // the process "dies" — the handle is dropped

    let reopened = ledger_in(&dir);
    let after_restart = submit_withdraw(&client, &reopened, authorized_for(BURN_TX_ID))
        .await
        .expect("refused");

    assert_matches!(after_restart, SubmitOutcome::AlreadySubmitted { .. });
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "a restart must not re-release funds"
    );
}

/// A 409-recovered burn is ALSO blocked afterwards: the conflict path records state durably too, so
/// the next pass does not re-POST it.
#[tokio::test]
async fn a_burn_that_hit_a_409_is_blocked_from_a_later_resubmission() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("recovered");
    let second = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("refused");

    assert_matches!(second, SubmitOutcome::AlreadySubmitted { .. });
    assert_eq!(withdraw_posts(&mock), 1);
}

/// A DIFFERENT burn is not blocked — the ledger keys per burn, it is not a global stop switch. (The
/// negative control: a ledger that blocked everything would pass every "never twice" test above.)
///
/// The mock is scripted with a `201` per burn, each echoing the burn it answers — because the driver
/// BINDS the returned status to the burn it submitted, a dishonest reply here would be caught as an
/// echo mismatch rather than proving anything about the ledger.
#[tokio::test]
async fn a_different_burn_is_submitted_normally() {
    let mock = MockCircle::start(Script::new().withdraw(vec![
        Reply::json(201, support::fixture_json("withdraw_201")),
        Reply::json(201, created_body_for(OTHER_BURN_TX_ID)),
    ]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("first burn");
    let other = submit_withdraw(&client, &ledger, authorized_for(OTHER_BURN_TX_ID))
        .await
        .expect("a different burn is a different withdrawal");

    assert_matches!(other, SubmitOutcome::Submitted(_));
    assert_eq!(withdraw_posts(&mock), 2, "two burns, two submissions");
}

/// The key is the `burnTxId` as an IDENTIFIER, not as bytes-on-the-wire: hex is case-insensitive, so
/// the SAME burn written in upper case is the same burn and is still refused.
#[tokio::test]
async fn the_same_burn_in_different_hex_case_is_the_same_burn() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("submitted");
    let upper = format!("0x{}", BURN_TX_ID[2..].to_ascii_uppercase());
    let second = submit_withdraw(&client, &ledger, authorized_for(&upper))
        .await
        .expect("refused");

    assert_matches!(second, SubmitOutcome::AlreadySubmitted { .. });
    assert_eq!(withdraw_posts(&mock), 1);
}

/// A request carrying the same burn in TWO batches is refused OUTRIGHT — zero POSTs. It would ask
/// Circle to release the same burn twice inside one call, and the 409 would fire on our own request.
#[tokio::test]
async fn a_request_carrying_the_same_burn_twice_is_refused_before_any_call() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let err = submit_withdraw(
        &client_for(&mock),
        &ledger,
        authorized_with_the_same_burn_twice(),
    )
    .await
    .expect_err("a duplicate burn inside one request is a defect");

    assert_matches!(err, SubmitError::DuplicateBurnInRequest { ref burn_tx_id } if burn_tx_id == BURN_TX_ID);
    assert_eq!(withdraw_posts(&mock), 0, "refused before the wire");
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        None,
        "and nothing was claimed — the refusal rolls back cleanly"
    );
}

/// A multi-burn request in which ONE burn is already accounted for is refused ENTIRELY — zero POSTs,
/// and the fresh burns are left unclaimed rather than stranded in `Pending`.
#[tokio::test]
async fn a_multi_burn_request_touching_one_seen_burn_makes_no_call_and_strands_nothing() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        201,
        support::fixture_json("withdraw_201"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the first burn goes out");
    assert_eq!(withdraw_posts(&mock), 1);

    let outcome = submit_withdraw(
        &client,
        &ledger,
        authorized_for_burns(&[OTHER_BURN_TX_ID, BURN_TX_ID]),
    )
    .await
    .expect("refused");

    assert_matches!(outcome, SubmitOutcome::AlreadySubmitted { .. });
    assert_eq!(withdraw_posts(&mock), 1, "STILL one — nothing new went out");
    assert_eq!(
        status_of(&ledger, OTHER_BURN_TX_ID),
        None,
        "the fresh burn must not be stranded in Pending by a refused request"
    );
}

// ================================================================================================
// THE LEDGER ITSELF
// ================================================================================================

/// SQLite's ephemeral databases are spelled as ordinary filenames, so an operator's config can hand
/// one in — and it would take every claim and lose them all on restart: a cache wearing the ledger's
/// name. It is refused.
#[rstest]
#[case::memory(":memory:")]
#[case::memory_upper(":MEMORY:")]
#[case::empty("")]
fn the_ledger_refuses_an_ephemeral_path(#[case] path: &str) {
    assert_matches!(
        SubmitLedger::open(path).expect_err("an ephemeral ledger is not a ledger"),
        LedgerError::EphemeralStorePath { .. }
    );
}

#[test]
fn the_ledger_refuses_a_memory_uri_because_sqlite_interprets_it() {
    // the pinned libsqlite3-sys compiles SQLite with -DSQLITE_USE_URI, so this really does open a
    // database with no file behind it. The enforcement is asking SQLite where the database landed.
    assert_matches!(
        SubmitLedger::open("file:submitted?mode=memory").expect_err("no file behind it"),
        LedgerError::EphemeralStorePath { .. }
    );
}

/// The claim is the decision point, and it is atomic: of two claims on the same burn exactly one is
/// `Claimed`.
#[test]
fn claiming_the_same_burn_twice_yields_claimed_then_already_seen() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let key = BurnKey::new(BURN_TX_ID);

    assert_matches!(
        ledger.claim_burns(slice::from_ref(&key)).unwrap(),
        ClaimOutcome::Claimed(_)
    );
    assert_matches!(
        ledger.claim_burns(&[key]).unwrap(),
        ClaimOutcome::AlreadySeen(r) if r.status() == SubmissionStatus::Pending
    );
}

/// An all-or-nothing multi-key claim: if ANY key in the set is already seen, NOTHING is claimed.
/// Otherwise a partial claim would strand the other burns in `Pending` forever.
#[test]
fn a_multi_burn_claim_that_hits_an_already_seen_burn_claims_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let taken = BurnKey::new(BURN_TX_ID);
    let fresh = BurnKey::new(OTHER_BURN_TX_ID);

    ledger.claim_burns(slice::from_ref(&taken)).unwrap();
    let outcome = ledger.claim_burns(&[fresh.clone(), taken]).unwrap();

    assert_matches!(outcome, ClaimOutcome::AlreadySeen(_));
    assert_eq!(
        ledger.record(&fresh).unwrap().map(|r| r.status()),
        None,
        "the fresh burn must NOT be left claimed by a rolled-back attempt"
    );
}

/// The status machine has no edge that could authorize a second release: a `Submitted` burn cannot be
/// walked back to a re-claimable state.
#[rstest]
#[case::submitted(SubmissionStatus::Submitted)]
#[case::finalized(SubmissionStatus::Finalized)]
#[case::reconciliation(SubmissionStatus::ReconciliationRequired)]
#[case::pending(SubmissionStatus::Pending)]
fn every_status_but_failed_blocks_resubmission(#[case] status: SubmissionStatus) {
    assert!(
        status.blocks_resubmission(),
        "{status:?} must block a re-send"
    );
}

#[test]
fn only_a_failed_burn_is_re_claimable() {
    assert!(!SubmissionStatus::Failed.blocks_resubmission());
}

#[test]
fn a_submitted_burn_cannot_be_walked_back_to_failed() {
    // Failed is the RE-CLAIMABLE state. If a submitted burn could reach it, a retry driver would
    // re-POST a burn Circle may already be releasing — the exact double-withdrawal this ledger exists
    // to prevent.
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let key = BurnKey::new(BURN_TX_ID);
    ledger.claim_burns(slice::from_ref(&key)).unwrap();
    ledger
        .record_submission(&key, Some(CONFLICT_WITHDRAWAL_ID))
        .unwrap();

    assert_matches!(
        ledger.record_failure(&key),
        Err(LedgerError::IllegalStatusTransition {
            from: SubmissionStatus::Submitted,
            to: SubmissionStatus::Failed
        })
    );
}

#[test]
fn recording_against_an_unclaimed_burn_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    assert_matches!(
        ledger.record_submission(&BurnKey::new(BURN_TX_ID), None),
        Err(LedgerError::UnknownBurn { .. })
    );
}
