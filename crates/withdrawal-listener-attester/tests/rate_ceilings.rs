//! **The documented Circle rate ceilings — 5 QPS/IP, 35 QPS global** (Circle documents:
//! `CIRCLE-API-SURFACE.md:18`, tagged "at NDA writing").
//!
//! These were part of the retry suite while the only governed thing was a retry. They are not a
//! retry concern: the ceilings are Circle's limit on **every request this process makes**, and the
//! withdrawal flow makes three kinds — the `prepare` POST, the `withdraw` POST (and its retries),
//! and the `GET /v1/withdrawal/{id}` polls that a `409` recovery runs. So they live here, over the
//! whole flow.
//!
//! # Coverage is the property, and a stopwatch cannot see it
//!
//! It is tempting to test a ceiling only by timing: make N requests, assert it took a window to
//! roll. That test passes for a governor that never saw half the requests — because an UNGOVERNED
//! request costs no time, and the ones that are governed still roll the window on schedule. The
//! hole is invisible exactly where it matters.
//!
//! So the oracle here is [`RateGovernor::granted`]: the count of permits actually taken. "Every
//! request took a permit" is then a deterministic equality, not an inference from a duration — and
//! it catches both an ungoverned request (too few) and a double-counted one (too many, which
//! silently halves the real ceiling). The timing assertions stay as the complementary half: they
//! prove a granted permit actually *waits*.
//!
//! A recovery poll loop is the case that motivates all this. A `409` can fan out into many `GET`s
//! per conflict, and concurrent conflicts start independent loops — the single easiest way for this
//! service to exceed the ceilings and get the partner's IP throttled by Circle.

use std::sync::Arc;
use std::time::{Duration, Instant};

use withdrawal_listener_attester::circle::rate::RateGovernor;
use withdrawal_listener_attester::circle::retry::RetryPolicy;
use withdrawal_listener_attester::circle::CircleClient;
use withdrawal_listener_attester::submit::submit_withdraw;
use withdrawal_listener_attester::withdrawal_api::prepare;

#[path = "submit_support/mod.rs"]
mod submit_support;

use submit_support::mock_circle::{MockCircle, Reply, Script};
use submit_support::*;

/// A client on `governor`, with backoff and poll cadence set to zero — so any time measured is the
/// GOVERNOR's, never a sleep from another policy.
fn client_on(mock: &MockCircle, governor: &Arc<RateGovernor>) -> CircleClient {
    client_for(mock)
        .with_rate_governor(Arc::clone(governor))
        .with_retry_policy(RetryPolicy::new(3, 0))
}

// ================================================================================================
// THE CEILINGS THEMSELVES
// ================================================================================================

#[test]
fn the_documented_ceilings_are_five_per_ip_and_thirty_five_global() {
    let governor = RateGovernor::documented();
    assert_eq!(governor.qps_per_ip(), 5);
    assert_eq!(governor.qps_global(), 35);
}

#[tokio::test]
async fn the_rate_governor_enforces_the_per_ip_ceiling() {
    let governor = RateGovernor::new(5, 35);
    let started = Instant::now();
    let mut stamps = Vec::new();
    for _ in 0..8 {
        // the instant the GOVERNOR recorded — the sample its own ceiling is enforced against. A second
        // `Instant::now()` here would be a different sample, and near a window boundary the two
        // disagree.
        stamps.push(governor.acquire("xreserve-api.mock").await);
    }
    let elapsed = started.elapsed();

    assert_max_in_any_window(&stamps, 5);
    assert!(
        elapsed >= Duration::from_millis(950),
        "the 6th of 8 must wait for the window to roll, took {elapsed:?}"
    );
    assert_eq!(governor.granted(), 8, "and every one of them took a permit");
}

#[tokio::test]
async fn the_rate_governor_enforces_the_global_ceiling_across_hosts() {
    // per-IP set high, so only the GLOBAL ceiling can bind
    let governor = RateGovernor::new(10_000, 35);
    let started = Instant::now();
    let mut stamps = Vec::new();
    for i in 0..40 {
        let host = if i % 2 == 0 { "host-a" } else { "host-b" };
        stamps.push(governor.acquire(host).await);
    }

    assert_max_in_any_window(&stamps, 35);
    assert!(started.elapsed() >= Duration::from_millis(950));
}

#[tokio::test]
async fn the_per_ip_window_is_keyed_by_host() {
    // one shared window would make the documented per-IP ceiling a 5-QPS TOTAL budget — wrong.
    let governor = RateGovernor::new(1, 10_000);

    let started = Instant::now();
    let _ = governor.acquire("host-a").await;
    let _ = governor.acquire("host-b").await;
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "different hosts must not contend"
    );

    let started = Instant::now();
    let _ = governor.acquire("host-a").await;
    assert!(started.elapsed() >= Duration::from_millis(950));
}

#[test]
fn a_zero_ceiling_is_clamped_so_a_window_can_never_fail_to_open() {
    // a 0-QPS window never opens: an acquisition would block forever. Clamping turns a runtime deadlock
    // into a 1-QPS crawl the operator can see.
    let governor = RateGovernor::new(0, 0);
    assert_eq!(governor.qps_per_ip(), 1);
    assert_eq!(governor.qps_global(), 1);
}

// ================================================================================================
// EVERY REQUEST THE FLOW MAKES IS GOVERNED — not just the POST
// ================================================================================================

/// **A `409` recovery's polls take permits.**
///
/// This is the case a POST-only governor misses entirely. One conflict fans out into a `GET` per
/// poll, and concurrent conflicts run independent loops — so recovery is the easiest way for this
/// service to blow through 5 QPS/IP and get throttled, precisely while it is trying to work out
/// whether real money has already moved.
#[tokio::test]
async fn a_409_recovery_poll_takes_a_rate_permit_for_every_get() {
    let governor = Arc::new(RateGovernor::new(10_000, 10_000)); // non-binding: COUNT, don't time
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            // three GETs: created → confirmed → finalized
            .status(vec![
                Reply::json(200, status_body("created")),
                Reply::json(200, status_body("confirmed")),
                Reply::json(200, status_body("finalized")),
            ]),
    );
    let dir = tempfile::tempdir().unwrap();

    submit_withdraw(
        &client_on(&mock, &governor),
        &ledger_in(&dir),
        authorized_for(BURN_TX_ID),
    )
    .await
    .expect("recovered");

    let posts = withdraw_posts(&mock);
    let gets = status_gets(&mock);
    assert_eq!(posts, 1);
    assert_eq!(gets, 3, "the recovery really did poll three times");
    assert_eq!(
        governor.granted(),
        posts + gets,
        "every request the flow made must have taken a permit — the recovery GETs are requests to \
         Circle exactly like the POST is, and a ceiling that does not see them is not a ceiling"
    );
}

/// The same property under a BINDING ceiling: the polls must actually wait their turn, not merely
/// be counted.
#[tokio::test]
async fn a_409_recovery_poll_waits_for_the_ceiling() {
    let governor = Arc::new(RateGovernor::new(2, 35));
    let mock = MockCircle::start(
        Script::new()
            .withdraw(vec![Reply::json(409, conflict_body_full())])
            .status(vec![
                Reply::json(200, status_body("created")),
                Reply::json(200, status_body("created")),
                Reply::json(200, status_body("finalized")),
            ]),
    );
    let dir = tempfile::tempdir().unwrap();

    let started = Instant::now();
    submit_withdraw(
        &client_on(&mock, &governor),
        &ledger_in(&dir),
        authorized_for(BURN_TX_ID),
    )
    .await
    .expect("recovered");
    let elapsed = started.elapsed();

    // 1 POST + 3 GETs = 4 requests at 2 QPS/IP → the 3rd cannot go until the window rolls
    assert_eq!(governor.granted(), 4);
    assert!(
        elapsed >= Duration::from_millis(950),
        "the 3rd of 4 requests must wait for the 2-QPS window to roll, took {elapsed:?}"
    );
}

/// The `prepare` POST is governed too — it is a request to Circle like any other.
#[tokio::test]
async fn the_prepare_driver_takes_a_rate_permit() {
    let governor = Arc::new(RateGovernor::new(10_000, 10_000));
    let mock = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("prepare_withdrawal_200"),
    )]));

    prepare(&client_on(&mock, &governor), &a_prepare_request())
        .await
        .expect("prepared");

    assert_eq!(governor.granted(), 1, "prepare is a Circle request as well");
}

/// The whole flow, end to end, on ONE governor: prepare + submit + recovery polls. The count is the
/// total number of requests the mock saw — no request escapes the ceiling.
#[tokio::test]
async fn every_request_the_withdrawal_flow_makes_takes_exactly_one_permit() {
    let governor = Arc::new(RateGovernor::new(10_000, 10_000));
    let mock = MockCircle::start(
        Script::new()
            .prepare(vec![Reply::json(
                200,
                support::fixture_json("prepare_withdrawal_200"),
            )])
            .withdraw(vec![
                Reply::Status(500), // a retried attempt
                Reply::json(409, conflict_body_full()),
            ])
            .status(vec![
                Reply::json(200, status_body("created")),
                Reply::json(200, status_body("finalized")),
            ]),
    );
    let dir = tempfile::tempdir().unwrap();
    let client = client_on(&mock, &governor);

    prepare(&client, &a_prepare_request())
        .await
        .expect("prepared");
    submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID))
        .await
        .expect("recovered");

    // 1 prepare + 2 withdraw attempts (500 then 409) + 2 status polls
    assert_eq!(mock.request_count(), 5, "the flow made five requests");
    assert_eq!(
        governor.granted(),
        5,
        "exactly one permit each: fewer means a request slipped past the ceiling, more means the \
         budget is double-counted and the real ceiling is a fraction of the documented one"
    );
}

/// **Exactly one permit per attempt — not two.**
///
/// Double-acquiring is the mirror-image bug of missing the governor, and it is quieter: the service
/// still "respects" the ceiling, it just silently runs at half the documented rate forever. It
/// becomes possible the moment the permit lives at more than one layer, so it is pinned here.
#[tokio::test]
async fn a_retried_attempt_takes_exactly_one_permit_per_attempt() {
    let governor = Arc::new(RateGovernor::new(10_000, 10_000));
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(500)]));
    let dir = tempfile::tempdir().unwrap();
    let client = client_on(&mock, &governor).with_retry_policy(RetryPolicy::new(3, 0));

    let _ = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID)).await;

    assert_eq!(withdraw_posts(&mock), 3);
    assert_eq!(
        governor.granted(),
        3,
        "three attempts, three permits — one per request that actually went out"
    );
}

/// The retry path takes a permit for EVERY attempt, retries included: a retry storm that ignored
/// the ceiling is the fastest way to get the partner's IP throttled.
#[tokio::test]
async fn the_submit_retries_take_a_rate_permit_for_every_attempt() {
    let governor = Arc::new(RateGovernor::new(2, 35));
    let mock = MockCircle::start(Script::new().withdraw(vec![Reply::Status(500)]));
    let dir = tempfile::tempdir().unwrap();
    // 2 QPS/IP with a zero backoff: 4 attempts cannot fit in under one window roll
    let client = client_on(&mock, &governor).with_retry_policy(RetryPolicy::new(4, 0));

    let started = Instant::now();
    let _ = submit_withdraw(&client, &ledger_in(&dir), authorized_for(BURN_TX_ID)).await;
    let elapsed = started.elapsed();

    assert_eq!(withdraw_posts(&mock), 4);
    assert_eq!(governor.granted(), 4);
    assert!(
        elapsed >= Duration::from_millis(950),
        "attempts 3 and 4 must wait for the 2-QPS window to roll, took {elapsed:?}"
    );
}

/// One governor shared by two clients is what makes the GLOBAL ceiling global. A per-client
/// governor would silently multiply the 35 QPS budget by the number of clients in the process.
#[tokio::test]
async fn clients_sharing_a_governor_share_one_budget() {
    let governor = Arc::new(RateGovernor::new(10_000, 10_000));
    let mock_a = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("prepare_withdrawal_200"),
    )]));
    let mock_b = MockCircle::start(Script::new().prepare(vec![Reply::json(
        200,
        support::fixture_json("prepare_withdrawal_200"),
    )]));

    prepare(&client_on(&mock_a, &governor), &a_prepare_request())
        .await
        .unwrap();
    prepare(&client_on(&mock_b, &governor), &a_prepare_request())
        .await
        .unwrap();

    assert_eq!(
        governor.granted(),
        2,
        "both clients' requests are counted against the one shared budget"
    );
}

/// No 1-second window over `stamps` may contain more than `limit` of them.
fn assert_max_in_any_window(stamps: &[Instant], limit: usize) {
    for (i, start) in stamps.iter().enumerate() {
        let inside = stamps[i..]
            .iter()
            .take_while(|s| s.duration_since(*start) < Duration::from_secs(1))
            .count();
        assert!(
            inside <= limit,
            "window at index {i} contains {inside} acquisitions, over the {limit} ceiling"
        );
    }
}
