//! The loop's cursor discipline: advance only after the page is on chain; never advance past a
//! failure; never let one bad attestation wedge the feed.

mod fixtures;

use fixtures::{
    attestation, error_response, page, undecodable_attestation, Answer, Fixture, MockCircle,
    ScriptedMiden,
};
use xreserve_deposit_relayer_lite::{run_cycle, CycleOutcome};

/// A full page mints in ONE transaction and the cursor advances.
#[tokio::test]
async fn a_page_mints_in_one_transaction() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(2), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let miden = ScriptedMiden::accepting();

    let outcome = run_cycle(&mut fixture.relayer(&miden)).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(miden.submissions(), vec![3], "three notes, one transaction");
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// **The issue-#160 wedge-bug regression, at the loop level.** A malformed attestation mid-page is
/// skipped, its neighbours still mint, and the cursor ADVANCES — the feed cannot wedge.
#[tokio::test]
async fn a_malformed_attestation_does_not_wedge_the_page() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), undecodable_attestation(), attestation(3)],
        Some("page-2"),
    )]);
    let mut fixture = Fixture::new(mock);
    let miden = ScriptedMiden::accepting();

    let outcome = run_cycle(&mut fixture.relayer(&miden)).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages, "the cycle must not fail");
    assert_eq!(miden.submissions(), vec![2], "the two good deposits mint");
    assert_eq!(
        fixture.store.cursor().unwrap().as_deref(),
        Some("page-2"),
        "THE bug: the cursor must advance past a page carrying a bad element"
    );
}

/// A failed submit holds the cursor, and the next cycle replays the SAME page and finishes it.
/// At-least-once in action: the replay re-submits all three notes; on a real chain the duplicates
/// are refused by the faucet's usedNonces assert.
#[tokio::test]
async fn a_failed_submit_holds_the_cursor_and_the_page_is_replayed() {
    let same_page = || {
        page(
            &[attestation(1), attestation(2), attestation(3)],
            Some("page-2"),
        )
    };
    let mock = MockCircle::new(vec![same_page(), same_page()]);
    let mut fixture = Fixture::new(mock.clone());
    let miden = ScriptedMiden::script(vec![Answer::Fail]);

    let error = run_cycle(&mut fixture.relayer(&miden)).await.unwrap_err();
    assert!(error.to_string().contains("unreachable"), "{error}");
    assert_eq!(
        fixture.store.cursor().unwrap(),
        None,
        "the cursor must NOT advance past a page that is not on chain"
    );

    let outcome = run_cycle(&mut fixture.relayer(&miden)).await.unwrap();
    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(
        miden.submissions(),
        vec![3],
        "the replayed page lands whole"
    );
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// A multi-page scan resumes each fetch from the cursor the previous page handed back.
#[tokio::test]
async fn a_scan_resumes_from_the_stored_cursor() {
    let mock = MockCircle::new(vec![
        page(&[attestation(1)], Some("page-2")),
        page(&[attestation(2)], None),
    ]);
    let mut fixture = Fixture::new(mock.clone());
    let miden = ScriptedMiden::accepting();

    assert_eq!(
        run_cycle(&mut fixture.relayer(&miden)).await.unwrap(),
        CycleOutcome::MorePages
    );
    assert_eq!(
        run_cycle(&mut fixture.relayer(&miden)).await.unwrap(),
        CycleOutcome::Idle
    );

    let requests = mock.requests();
    assert_eq!(requests[0], (fixture.config.remote_domain, None));
    assert_eq!(
        requests[1],
        (fixture.config.remote_domain, Some("page-2".to_string()))
    );
}

/// An empty page submits NO transaction and still advances.
#[tokio::test]
async fn an_empty_page_advances_without_a_transaction() {
    let mock = MockCircle::new(vec![page(&[], Some("page-2"))]);
    let mut fixture = Fixture::new(mock);
    let miden = ScriptedMiden::accepting();

    let outcome = run_cycle(&mut fixture.relayer(&miden)).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert!(miden.submissions().is_empty());
    assert_eq!(fixture.store.cursor().unwrap().as_deref(), Some("page-2"));
}

/// The final page (no Link header) reports Idle and leaves the cursor alone — there is no resume
/// point past the end of the feed.
#[tokio::test]
async fn the_final_page_is_idle_and_keeps_the_cursor() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], None)]);
    let mut fixture = Fixture::new(mock);
    let miden = ScriptedMiden::accepting();

    let outcome = run_cycle(&mut fixture.relayer(&miden)).await.unwrap();

    assert_eq!(outcome, CycleOutcome::Idle);
    assert_eq!(miden.submissions(), vec![1]);
    assert_eq!(fixture.store.cursor().unwrap(), None);
}

/// A Circle failure fails the cycle before anything is submitted, and the cursor stays put.
#[tokio::test]
async fn a_circle_failure_holds_the_cursor() {
    let mock = MockCircle::new(vec![error_response(500)]);
    let mut fixture = Fixture::new(mock);
    let miden = ScriptedMiden::accepting();

    let error = run_cycle(&mut fixture.relayer(&miden)).await.unwrap_err();

    assert!(error.to_string().contains("500"), "{error}");
    assert!(miden.submissions().is_empty());
    assert_eq!(fixture.store.cursor().unwrap(), None);
}

/// There is no production Miden adapter, and the refusal says why.
#[test]
fn there_is_no_production_miden_adapter() {
    let error = xreserve_deposit_relayer_lite::miden::production_miden_client()
        .unwrap_err()
        .to_string();
    assert!(error.contains("miden-client"), "unexpected error: {error}");
}
