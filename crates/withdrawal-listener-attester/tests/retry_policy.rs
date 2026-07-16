//! `T-LA-13` (3/4) — the **retry/backoff policy** and the refusal
//! to act on a malformed response (§10.10, §10.11). The documented rate ceilings the submit path runs
//! under are `rate_ceilings.rs` — they govern the WHOLE flow, not just retries, so they are not a
//! retry concern.
//!
//! # The one rule this file exists to pin
//!
//! `POST /v1/withdraw` is **not idempotent**. Retrying it is re-asking Circle to release funds, so the
//! only failure that may be retried is one where Circle DEMONSTRABLY did not act — §10.10 names exactly
//! one: "5xx → bounded retry with backoff". Everything else is surfaced.
//!
//! A **status-less transport failure is the sharp case**, and it goes the other way from what
//! intuition suggests: a timeout or a connection reset can happen *after* Circle accepted the
//! withdrawal and before the answer got back, so re-POSTing it is precisely the blind resubmission the
//! money-path rule forbids. "No answer" is ambiguity, and ambiguity fails closed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::json;

use withdrawal_listener_attester::circle::retry::{is_retryable, RetryPolicy};
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::error::ListenerError;
use withdrawal_listener_attester::idempotency::SubmissionStatus;
use withdrawal_listener_attester::submit::{submit_withdraw, SubmitError, SubmitOutcome};

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::transports::CountingFailingTransport;
use submit_support::mock_circle::{MockCircle, Reply, Script};
use submit_support::*;

// ================================================================================================
// WHAT MAY BE RETRIED — and, above all, what may not
// ================================================================================================

/// A 5xx is the ONE documented transient: retried, but BOUNDED — and when the budget runs out the
/// failure is SURFACED, never swallowed and never assumed successful.
#[tokio::test]
async fn a_5xx_is_retried_within_bounds_and_then_surfaced() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        500,
        support::fixture_json("withdraw_500"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(3, 0));

    let err = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("an exhausted retry budget is a failure, not a success");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::Http { status: 500 })
    );
    assert_eq!(
        withdraw_posts(&mock),
        3,
        "exactly the policy's attempt budget — not unbounded, not one"
    );
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "an exhausted 5xx is AMBIGUOUS (the request may have landed) — it must not become re-claimable"
    );
}

/// The bound follows the policy, so the retry count is a real policy and not a hardcoded constant.
#[rstest]
#[case::one(1)]
#[case::two(2)]
#[case::five(5)]
#[tokio::test]
async fn the_5xx_attempt_count_is_exactly_the_configured_bound(#[case] attempts: u32) {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(503)]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(attempts, 0));

    let _ = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID)).await;

    assert_eq!(withdraw_posts(&mock), attempts as usize);
}

/// A 5xx that clears within the budget succeeds — the retry is real, not decorative.
#[tokio::test]
async fn a_5xx_that_recovers_within_the_budget_succeeds() {
    let mock = MockCircle::start(Script::new().withdraw(vec![
        Reply::Status(500),
        Reply::json(201, support::fixture_json("withdraw_201")),
    ]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the second attempt lands");

    assert_matches!(outcome, SubmitOutcome::Submitted(_));
    assert_eq!(withdraw_posts(&mock), 2);
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::Submitted)
    );
}

/// **A status-less transport failure is NOT retried.**
///
/// This is the money-path rule in its sharpest form. A timeout or connection reset carries no
/// information about whether Circle acted: the withdrawal may already be created and releasing, with
/// only the response lost. Re-POSTing on "no answer" is a blind resubmission — so the attempt is made
/// EXACTLY ONCE, the ambiguity is surfaced, and the burn is left blocked for an operator.
///
/// The counting transport is the oracle: it fails the way a dead network does (no status, ever) and
/// records how many times the driver asked.
#[tokio::test]
async fn a_status_less_transport_failure_is_attempted_exactly_once_and_surfaced() {
    let transport = Arc::new(CountingFailingTransport::new());
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = CircleClient::new(
        "https://xreserve-api.mock",
        withdrawal_listener_attester::circle::auth::AuthPosture::None,
    )
    .unwrap()
    .with_transport(transport.clone())
    // a GENEROUS budget: if transport failures were retryable this would issue 5 POSTs
    .with_retry_policy(RetryPolicy::new(5, 0));

    let err = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("a status-less failure is never a success");

    assert_matches!(err, SubmitError::Circle(ListenerError::Transport(_)));
    assert_eq!(
        transport.attempts(),
        1,
        "a timeout may have landed AFTER Circle accepted the withdrawal — re-POSTing it is the \
         blind resubmission the 409 rule exists to prevent"
    );
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "the burn's real state is unknown: block it, do not retry it and do not free it"
    );
}

/// A deterministic 400 is NOT retried: the identical request must fail identically, so a retry only
/// burns the rate budget the transient failures need. Exactly ONE attempt, surfaced.
#[tokio::test]
async fn a_deterministic_400_is_not_retried() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::json(
        400,
        support::fixture_json("withdraw_400"),
    )]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(5, 0));

    let err = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("a 400 aborts");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::Http { status: 400 })
    );
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "a deterministic 400 must be attempted exactly once"
    );
}

/// A 400 means Circle REJECTED the request — nothing was created. That burn is therefore re-claimable
/// once the request is fixed (the spec's "abort/fix-request"), and a later, corrected submission does
/// go out.
#[tokio::test]
async fn a_400_leaves_the_burn_re_claimable_for_a_fixed_request() {
    let mock = MockCircle::start(Script::new().withdraw(vec![
        Reply::json(400, support::fixture_json("withdraw_400")),
        Reply::json(201, support::fixture_json("withdraw_201")),
    ]));
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    let client = client_for(&mock);

    let _ = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID)).await;
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::Failed),
        "a rejected request created nothing"
    );

    let retried = submit_withdraw(&client, &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("the fixed request goes out");
    assert_matches!(retried, SubmitOutcome::Submitted(_));
    assert_eq!(withdraw_posts(&mock), 2);
}

/// A 409 is NEVER retried — even with a generous budget and a 409 that would keep repeating.
#[tokio::test]
async fn a_409_is_never_retried() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_burn_only())])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(5, 0));

    let _ = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID)).await;

    assert_eq!(withdraw_posts(&mock), 1);
}

/// The retry classification, stated directly.
///
/// Two entries are load-bearing and both say `false`: a **`409`** (retrying a duplicate conflict is the
/// double-withdrawal footgun) and a **`Transport`** failure (no status = no evidence Circle did not
/// act). §10.10 names 5xx and 5xx alone as the retryable case; everything else fails closed.
#[rstest]
#[case::http_500(ListenerError::Http { status: 500 }, true)]
#[case::http_502(ListenerError::Http { status: 502 }, true)]
#[case::http_503(ListenerError::Http { status: 503 }, true)]
#[case::http_599(ListenerError::Http { status: 599 }, true)]
#[case::http_400(ListenerError::Http { status: 400 }, false)]
#[case::http_404(ListenerError::Http { status: 404 }, false)]
#[case::http_409(ListenerError::Http { status: 409 }, false)]
#[case::http_418(ListenerError::Http { status: 418 }, false)]
#[case::too_large(ListenerError::ResponseTooLarge { limit: 1, actual: 2 }, false)]
#[case::cardinality(ListenerError::WithdrawResponseCardinality { submitted: 1, returned: 2 }, false)]
#[case::poll_exhausted(ListenerError::PollExhausted { after: 3 }, false)]
fn the_retry_classification_matches_the_spec(
    #[case] error: ListenerError,
    #[case] retryable: bool,
) {
    assert_eq!(is_retryable(&error), retryable, "{error}");
}

#[test]
fn neither_a_status_less_failure_nor_a_malformed_body_is_retryable() {
    let transport = ListenerError::Transport(withdrawal_listener_attester::error::Cause::new(
        std::io::Error::other("connection reset"),
    ));
    assert!(
        !is_retryable(&transport),
        "no status means no evidence that Circle did NOT act — re-POSTing a withdrawal on that is a \
         blind resubmission"
    );

    let malformed = ListenerError::MalformedResponse {
        context: "withdraw",
        source: withdrawal_listener_attester::error::Cause::new(std::io::Error::other("bad json")),
    };
    assert!(
        !is_retryable(&malformed),
        "a peer that returns an unreadable body returns it again"
    );
}

/// The backoff is exponential, from the configured base — and a large attempt count cannot overflow
/// the delay into a panic or a zero wait.
#[test]
fn the_backoff_grows_exponentially_from_the_base_and_saturates() {
    let policy = RetryPolicy::new(8, 100);
    assert_eq!(policy.backoff_for(1), Duration::from_millis(100));
    assert_eq!(policy.backoff_for(2), Duration::from_millis(200));
    assert_eq!(policy.backoff_for(3), Duration::from_millis(400));
    assert_eq!(policy.backoff_for(4), Duration::from_millis(800));

    // no panic, no wraparound to a tiny delay
    assert!(RetryPolicy::new(u32::MAX, u64::MAX).backoff_for(u32::MAX) >= Duration::from_secs(1));
}

#[test]
fn a_zero_attempt_budget_is_clamped_so_the_request_is_still_tried_once() {
    assert_eq!(RetryPolicy::new(0, 10).max_attempts(), 1);
}

/// The backoff actually SLEEPS between attempts — a policy whose delay is never awaited is a retry
/// storm wearing a policy's name.
#[tokio::test]
async fn the_backoff_delay_is_actually_waited_between_attempts() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(500)]));
    let dir = tempfile::tempdir().unwrap();
    // 3 attempts, 150ms base → waits of 150ms + 300ms = 450ms between the three
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(3, 150));

    let started = Instant::now();
    let _ = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID)).await;
    let elapsed = started.elapsed();

    assert_eq!(withdraw_posts(&mock), 3);
    assert!(
        elapsed >= Duration::from_millis(400),
        "the backoff must be awaited, took {elapsed:?}"
    );
}

// ================================================================================================
// MALFORMED RESPONSES (§10.11 — reject, never coerce)
// ================================================================================================

/// A `201` body that does not decode is an EXACT `Err`; nothing is acted on (no poll), and the burn is
/// left blocked — Circle created SOMETHING we cannot read, which is the definition of ambiguous.
#[tokio::test]
async fn a_201_body_that_does_not_decode_is_rejected_and_nothing_is_acted_on() {
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(
                201,
                json!([support::fixture_json("malformed_body")]),
            )])
            .status(vec![Reply::json(200, status_body("finalized"))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let err = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect_err("a malformed body is never coerced");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::MalformedResponse {
            context: "withdraw",
            ..
        })
    );
    assert_eq!(status_gets(&mock), 0, "nothing was acted on");
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "fail closed: a 201 we cannot read is not a re-sendable burn"
    );
}

/// A `201` is bound to the burn it answers, not merely counted. A status object echoing a `burnTxId`
/// this request never submitted is a DEFECT — recording it as this burn's submission would tie our burn
/// to a stranger's withdrawal id, and every later poll would then read the wrong withdrawal.
#[tokio::test]
async fn a_201_echoing_a_burn_that_was_not_submitted_is_a_defect() {
    let mock = MockCircle::start(
        Script::new().withdraw(vec![Reply::json(201, created_body_for(OTHER_BURN_TX_ID))]),
    );
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);

    let outcome = submit_withdraw(&client_for(&mock), &ledger, authorized_for(BURN_TX_ID))
        .await
        .expect("handled");

    assert_matches!(
        &outcome,
        SubmitOutcome::ConflictEchoMismatch { echoed, .. } if echoed == OTHER_BURN_TX_ID
    );
    assert!(
        !matches!(outcome, SubmitOutcome::Submitted(_)),
        "cardinality alone is not identity: the same COUNT is not the same burns"
    );
    assert_eq!(
        status_of(&ledger, BURN_TX_ID),
        Some(SubmissionStatus::ReconciliationRequired),
        "our burn's real state is now unknown — fail closed"
    );
}

/// An UNDOCUMENTED status is an exact `Err`, surfaced — never guessed at, and (no `Retry-After`/`429`
/// being documented) never given invented handling.
#[tokio::test]
async fn an_undocumented_status_is_an_exact_err_surfaced_without_retry() {
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(429)]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_for(&mock).with_retry_policy(RetryPolicy::new(4, 0));

    let err = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID))
        .await
        .expect_err("429 is not documented for this endpoint");

    assert_matches!(
        err,
        SubmitError::Circle(ListenerError::Http { status: 429 })
    );
    assert_eq!(
        withdraw_posts(&mock),
        1,
        "no invented 429/Retry-After handling — surfaced as-is"
    );
}
