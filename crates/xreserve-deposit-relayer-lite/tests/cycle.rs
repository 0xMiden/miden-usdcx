//! The loop advances its cursor only after the page is on-chain, keeps it unchanged after a
//! failure, and skips malformed attestations without blocking the feed.

mod fixtures;

use fixtures::{
    attestation, error_response, page, undecodable_attestation, Answer, Fixture, MockCircle,
    ScriptedMiden,
};
use xreserve_deposit_relayer_lite::{run_cycle, CycleOutcome};

/// A full page mints in one transaction and advances the cursor.
#[tokio::test]
async fn a_page_mints_in_one_transaction() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), attestation(2), attestation(3)],
        Some("page-2"),
    )]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock, miden.clone());

    let outcome = run_cycle(&mut fixture.relayer).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(miden.submissions(), vec![3], "three notes, one transaction");
    assert_eq!(
        fixture.relayer.store.cursor().unwrap().as_deref(),
        Some("page-2")
    );
}

/// A malformed attestation is skipped while its neighbours mint and the cursor advances.
#[tokio::test]
async fn a_malformed_attestation_does_not_wedge_the_page() {
    let mock = MockCircle::new(vec![page(
        &[attestation(1), undecodable_attestation(), attestation(3)],
        Some("page-2"),
    )]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock, miden.clone());

    let outcome = run_cycle(&mut fixture.relayer).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages, "the cycle must not fail");
    assert_eq!(miden.submissions(), vec![2], "the two good deposits mint");
    assert_eq!(
        fixture.relayer.store.cursor().unwrap().as_deref(),
        Some("page-2"),
        "the cursor must advance past a page carrying a bad element"
    );
}

/// A failed submission leaves the cursor unchanged, and the next cycle replays the same page.
/// The replay resubmits all three notes; on-chain replay protection rejects any duplicate mints.
#[tokio::test]
async fn a_failed_submit_holds_the_cursor_and_the_page_is_replayed() {
    let same_page = || {
        page(
            &[attestation(1), attestation(2), attestation(3)],
            Some("page-2"),
        )
    };
    let mock = MockCircle::new(vec![same_page(), same_page()]);
    let miden = ScriptedMiden::script(vec![Answer::Fail]);
    let mut fixture = Fixture::new(mock.clone(), miden.clone());

    let error = run_cycle(&mut fixture.relayer).await.unwrap_err();
    assert!(error.to_string().contains("unreachable"), "{error}");
    assert_eq!(
        fixture.relayer.store.cursor().unwrap(),
        None,
        "the cursor must not advance past a page that is not on-chain"
    );

    let outcome = run_cycle(&mut fixture.relayer).await.unwrap();
    assert_eq!(outcome, CycleOutcome::MorePages);
    assert_eq!(
        miden.submissions(),
        vec![3],
        "the replayed page lands whole"
    );
    assert_eq!(
        fixture.relayer.store.cursor().unwrap().as_deref(),
        Some("page-2")
    );
}

/// A multi-page scan resumes each fetch from the cursor the previous page handed back.
#[tokio::test]
async fn a_scan_resumes_from_the_stored_cursor() {
    let mock = MockCircle::new(vec![
        page(&[attestation(1)], Some("page-2")),
        page(&[attestation(2)], None),
    ]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock.clone(), miden.clone());

    assert_eq!(
        run_cycle(&mut fixture.relayer).await.unwrap(),
        CycleOutcome::MorePages
    );
    assert_eq!(
        run_cycle(&mut fixture.relayer).await.unwrap(),
        CycleOutcome::CaughtUp
    );

    let requests = mock.requests();
    assert_eq!(requests[0], (fixture.relayer.config.remote_domain, None));
    assert_eq!(
        requests[1],
        (
            fixture.relayer.config.remote_domain,
            Some("page-2".to_string())
        )
    );
}

/// An empty page advances without submitting a transaction.
#[tokio::test]
async fn an_empty_page_advances_without_a_transaction() {
    let mock = MockCircle::new(vec![page(&[], Some("page-2"))]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock, miden.clone());

    let outcome = run_cycle(&mut fixture.relayer).await.unwrap();

    assert_eq!(outcome, CycleOutcome::MorePages);
    assert!(miden.submissions().is_empty());
    assert_eq!(
        fixture.relayer.store.cursor().unwrap().as_deref(),
        Some("page-2")
    );
}

/// A page without a next cursor reports that the feed is caught up and leaves the cursor unchanged.
#[tokio::test]
async fn the_final_page_reports_caught_up_and_keeps_the_cursor() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], None)]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock, miden.clone());

    let outcome = run_cycle(&mut fixture.relayer).await.unwrap();

    assert_eq!(outcome, CycleOutcome::CaughtUp);
    assert_eq!(miden.submissions(), vec![1]);
    assert_eq!(fixture.relayer.store.cursor().unwrap(), None);
}

/// A Circle failure fails the cycle before anything is submitted, and the cursor stays put.
#[tokio::test]
async fn a_circle_failure_holds_the_cursor() {
    let mock = MockCircle::new(vec![error_response(500)]);
    let miden = ScriptedMiden::accepting();
    let mut fixture = Fixture::new(mock, miden.clone());

    let error = run_cycle(&mut fixture.relayer).await.unwrap_err();

    assert!(error.to_string().contains("500"), "{error}");
    assert!(miden.submissions().is_empty());
    assert_eq!(fixture.relayer.store.cursor().unwrap(), None);
}

/// There is no production Miden adapter, and the refusal says why.
#[test]
fn there_is_no_production_miden_adapter() {
    let error = xreserve_deposit_relayer_lite::miden::production_miden_client()
        .unwrap_err()
        .to_string();
    assert!(error.contains("miden-client"), "unexpected error: {error}");
}
