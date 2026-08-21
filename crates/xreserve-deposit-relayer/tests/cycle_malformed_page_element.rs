//! **One malformed element on a page refuses that element, not the page.**
//!
//! Circle's attestation stream is append-only, so an attestation that fails its envelope check
//! never ages out of it. A refusal that failed the whole page would fail it again next cycle, from
//! the same cursor, forever — every deposit behind one bad element withheld by it.
//!
//! This suite pins the opposite: the bad element is reported like any other refusal — one entry,
//! one reason, one alert, under the name Circle sent for it — the elements beside it reach their
//! normal fate, and the cursor moves past the page. The counterweight is here too: a failure of the
//! PAGE still fails the cycle, because nothing was fetched and nothing is dropped.
//!
//! The driver, the attester fixtures and the page builders these tests share live in
//! [`cycle_support`]; every assertion is here.

mod cycle_support;
mod fixtures;
mod mint_support;
mod mock_circle;

use assert_matches::assert_matches;
use serde_json::json;

use xreserve_deposit_relayer::cycle::Disposition;
use xreserve_deposit_relayer::error::HexField::{MessageHash, Payload};
use xreserve_deposit_relayer::error::RelayerError as Refusal;

use cycle_support::{
    alerts, attestation_events, every_malformed_shape_page, linked_page,
    page_with_an_ordinary_rejection, poisoned_page, poisoned_then_final_pages, run_cycles,
    run_one_page, valid_attesters, OTHER_UNDECODABLE_HASH, PAGE_AFTER_CURSOR, UNDECODABLE_HASH,
};

// THE PAGE SURVIVES ITS WORST ELEMENT
// ================================================================================================

/// Valid, MALFORMED, valid — in that order, so a refusal that swallowed the rest of the page and one
/// that swallowed only what followed it are both visible. The refused element is named by the
/// `messageHash` Circle sent for it, raises the terminal event every other outcome raises, is
/// counted like every other refusal, never joins the retry queue, and does not hold the cursor.
#[tokio::test]
async fn a_malformed_element_refuses_only_itself() {
    let poisoned = valid_attesters(3);
    let ran = run_one_page(poisoned_page(&poisoned, 1)).await;
    let report = ran.report(0);

    let outcomes: Vec<&str> = report.entries().iter().map(|e| e.outcome()).collect();
    assert_eq!(outcomes, vec!["submitted", "rejected", "submitted"]);
    assert_eq!(ran.submits, 2, "both valid attestations still minted");

    let refused = &report.entries()[1];
    assert_eq!(
        refused.message_hash_hex(),
        poisoned[1].message_hash_hex(),
        "the refusal names the deposit Circle sent it for"
    );
    assert_matches!(
        refused.disposition(),
        Disposition::Rejected(Refusal::BadAttestationLength { actual: 66 })
    );
    assert!(!refused.reason().trim().is_empty());

    // one terminal event per fetched element, and the counters still partition what was fetched
    let terminal = attestation_events(&ran.events);
    assert_eq!(terminal.len(), 3);
    assert_eq!(terminal[1], (poisoned[1].message_hash_hex(), "rejected"));
    assert_eq!(
        report.submitted()
            + report.rejected()
            + report.duplicates()
            + report.already_minted()
            + report.deferred()
            + report.reconciliation_required(),
        report.fetched()
    );
    assert_eq!(ran.metrics.attestations_fetched, 3);
    assert_eq!(ran.metrics.attestations_rejected, 1);

    // a refused element holds no claim, so the retry driver never re-fetches it — and the cursor
    // moved past the page, which one left in front of the bad element would re-poll forever
    assert_eq!(ran.retryable, 0);
    assert_eq!(report.next_cursor(), Some(PAGE_AFTER_CURSOR));
    assert_eq!(ran.cursor.as_deref(), Some(PAGE_AFTER_CURSOR));
}

/// Every malformed shape the envelope check can produce, together on ONE page beside a valid
/// element: each is refused on its own terms, none of them takes the page down, and the two whose
/// `messageHash` cannot even be decoded keep their OWN raw wire names. A refusal that fabricated a
/// name for those two would collapse them onto one operator grep key and discard what Circle sent.
#[tokio::test]
async fn every_malformed_shape_is_refused_under_its_own_name() {
    let ran = run_one_page(every_malformed_shape_page(&valid_attesters(7))).await;
    let report = ran.report(0);

    assert_eq!((report.submitted(), report.rejected()), (1, 6));
    let refused: Vec<&Refusal> = report.entries()[1..]
        .iter()
        .map(|entry| assert_matches!(entry.disposition(), Disposition::Rejected(error) => error))
        .collect();
    assert_matches!(refused[0], Refusal::BadAttestationLength { actual: 66 });
    assert_matches!(refused[1], Refusal::MessageHashMismatch { actual, .. } if actual == &[0x11; 32]);
    assert_matches!(refused[2], Refusal::BadMessageHashLength { actual: 31 });
    assert_matches!(refused[3], Refusal::MalformedHex { field, .. } if field == &Payload);
    assert_matches!(refused[4], Refusal::MalformedHex { field, .. } if field == &MessageHash);
    assert_matches!(refused[5], Refusal::MalformedHex { field, .. } if field == &MessageHash);

    // the two undecodable hashes are reported — and logged — under the distinct raw values Circle
    // sent for them, not under one fabricated stand-in
    let named: Vec<String> = report.entries()[5..]
        .iter()
        .map(|entry| entry.message_hash_hex())
        .collect();
    assert_eq!(named, vec![UNDECODABLE_HASH, OTHER_UNDECODABLE_HASH]);
    let logged: Vec<String> = attestation_events(&ran.events)
        .into_iter()
        .map(|(message_hash, _)| message_hash)
        .collect();
    assert_eq!(logged[5..], named[..], "the log names them the same way");
    assert_eq!(ran.cursor.as_deref(), Some(PAGE_AFTER_CURSOR));
}

/// A malformed element raises exactly ONE operator alert — the cardinality a normal per-attestation
/// rejection raises. One layer owns the alert; two layers alerting on one refusal would double every
/// malformed element in an operator's alert stream.
#[tokio::test]
async fn a_refused_element_raises_exactly_one_alert() {
    let malformed = run_one_page(poisoned_page(&valid_attesters(1), 0)).await;
    let ordinary = run_one_page(page_with_an_ordinary_rejection()).await;

    assert_eq!(malformed.report(0).rejected(), 1);
    assert_eq!(ordinary.report(0).rejected(), 1);
    assert_eq!(
        alerts(&malformed.events),
        alerts(&ordinary.events),
        "a malformed element must not alert more than an ordinary rejection does"
    );
    assert_eq!(alerts(&malformed.events), 1, "one refusal, one alert");
}

/// **The failure mode this slice exists to remove.** Cycle 1 polls a page carrying a poisoned
/// element; cycle 2 must poll the NEXT page rather than the same one. The oracle is the wire: the
/// second batch request carries the first page's `pageAfter`.
#[tokio::test]
async fn a_poisoned_page_does_not_stall_the_next_cycle() {
    let ran = run_cycles(poisoned_then_final_pages(&valid_attesters(3)), 2).await;

    let first = ran.report(0);
    assert_eq!((first.rejected(), first.submitted()), (1, 1));
    assert_eq!(first.next_cursor(), Some(PAGE_AFTER_CURSOR));
    assert_eq!(ran.report(1).submitted(), 1, "the next page minted");
    assert!(ran.report(1).scan_complete());

    assert_eq!(ran.requests.len(), 2);
    assert_eq!(
        ran.requests[0].query("pageAfter"),
        None,
        "cycle 1 started at the beginning"
    );
    assert_eq!(
        ran.requests[1].query("pageAfter"),
        Some(PAGE_AFTER_CURSOR),
        "cycle 2 re-polled the poisoned page instead of moving past it — the stall is still here"
    );
}

/// The counterweight: a body that is not the documented list shape fails the CYCLE and leaves the
/// cursor alone. Nothing was fetched, so nothing is dropped — and the relayer must not skip a
/// window it never read.
#[tokio::test]
async fn a_page_that_does_not_decode_still_fails_the_cycle() {
    let ran = run_cycles(vec![linked_page(json!({ "items": [] }))], 1).await;

    assert_matches!(
        ran.cycles[0].as_ref().expect_err("the cycle fails"),
        Refusal::Decode(_)
    );
    assert_eq!(
        ran.cursor, None,
        "a cycle that read nothing must not move the resume point"
    );
}
