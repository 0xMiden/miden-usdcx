//! `tests/circle_pagination_contract.rs` — the batch poll and discovery: `T-RLY-03` (the full
//! documented `BatchQuery` surface, the `Link`-header cursors, the forward scan and its termination,
//! and the malformed pagination metadata that must NOT be mistaken for a final page) and `T-RLY-04`
//! (`GET /v1/info`, the public no-`domain`-param shape).
//!
//! No live Circle leg (§11): every Circle endpoint is `REQUIRES CIRCLE CONFIRMATION` and is
//! exercised against the in-process schema-exact mock ([`mock_circle`]) — the relayer builds a real
//! `reqwest::Request` and the mock's axum router answers it, binding no socket. The attestation wire
//! data is the partner test vector from [`fixtures`] — a real secp256k1 signature over the real
//! raw-keccak digest of a canonical DC-1 DepositIntent payload — so the keccak binding these tests
//! assert is a genuine binding, not a self-consistent invention.

mod fixtures;
mod mock_circle;

use assert_matches::assert_matches;
use rstest::rstest;
use serde_json::json;

use fixtures::{test_vector, PartnerAttester, TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA};
use mock_circle::{
    attestation_page, batch_href, client_for, info_body, link_header, Endpoint, MockCircle, Reply,
    Script, FIXTURE_MIDEN_DOMAIN, FIXTURE_XUSDC_IDENTIFIER,
};

use xreserve_deposit_relayer::circle::{
    fetch_info, poll_remote_domain_attestations, AuthPosture, BatchQuery,
};
use xreserve_deposit_relayer::error::RelayerError;

// T-RLY-03 — batch poll: full BatchQuery surface + Link-header cursors
// ================================================================================================

/// The `BatchQuery` type models ALL FIVE documented params, and every one of them reaches the wire
/// under its exact OpenAPI name — `pageSize`, `pageAfter`, `pageBefore`, `from`, `to`.
///
/// **The two cursors are covered in SEPARATE requests, because Circle forbids sending them
/// together** ("`pageAfter`: do not use with `pageBefore`", and vice versa — the list-attestations
/// endpoint reference). A single request carrying both would be an invalid request that a real
/// endpoint may answer with 400, so a fixture asserting it would enshrine a request the relayer must
/// never make. Full surface, two legal requests: `pageSize + pageAfter + from + to`, then
/// `pageSize + pageBefore + from + to`.
#[tokio::test]
async fn t_rly_03_batch_poll_puts_the_full_documented_query_surface_on_the_wire() {
    let vector = test_vector();
    let next_href = batch_href(FIXTURE_MIDEN_DOMAIN, 2, Some(("pageAfter", "Y3Vyc29yLTI=")));
    let self_href = batch_href(FIXTURE_MIDEN_DOMAIN, 2, Some(("pageAfter", "Y3Vyc29yLTE=")));
    let first_href = batch_href(FIXTURE_MIDEN_DOMAIN, 2, None);
    let prev_href = batch_href(
        FIXTURE_MIDEN_DOMAIN,
        2,
        Some(("pageBefore", "Y3Vyc29yLTA=")),
    );
    let link = link_header(&[
        ("self", &self_href),
        ("first", &first_href),
        ("next", &next_href),
        ("prev", &prev_href),
    ]);
    let mock = MockCircle::start(
        Script::new().batch(vec![Reply::ok_linked(attestation_page(&[&vector]), link)]),
    );
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    // REQUEST 1 — the forward window: pageSize + pageAfter + from + to
    let forward = BatchQuery::new(2)
        .expect("pageSize 2 is within 1..=1000")
        .with_page_after("Y3Vyc29yLTE=")
        .with_from("2026-07-01T00:00:00Z")
        .with_to("2026-07-13T00:00:00Z");

    let (page, cursors) = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &forward)
        .await
        .expect("the page decodes");

    // the page body decodes (LIST shape, no wrapper) and every element is envelope-validated
    assert_eq!(page.attestations().len(), 1);
    assert_eq!(page.attestations()[0].payload(), vector.payload());
    assert_eq!(page.attestations()[0].attestation().len(), 65);

    let requests = mock.requests_to(Endpoint::Batch);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        format!("/v1/remote-domains/{FIXTURE_MIDEN_DOMAIN}/attestations")
    );
    assert_eq!(requests[0].query("pageSize"), Some("2"));
    assert_eq!(requests[0].query("pageAfter"), Some("Y3Vyc29yLTE="));
    assert_eq!(requests[0].query("from"), Some("2026-07-01T00:00:00Z"));
    assert_eq!(requests[0].query("to"), Some("2026-07-13T00:00:00Z"));
    assert_eq!(
        requests[0].query("pageBefore"),
        None,
        "pageBefore must NOT ride along with pageAfter — Circle forbids the combination"
    );
    assert_eq!(requests[0].query.len(), 4);

    // REQUEST 2 — the backward window: pageSize + pageBefore + from + to (the same five documented
    // params, minus the forbidden pairing)
    let backward = BatchQuery::new(2)
        .expect("pageSize 2 is within 1..=1000")
        .with_page_before("Y3Vyc29yLTA=")
        .with_from("2026-07-01T00:00:00Z")
        .with_to("2026-07-13T00:00:00Z");

    poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &backward)
        .await
        .expect("the page decodes");

    let requests = mock.requests_to(Endpoint::Batch);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].query("pageSize"), Some("2"));
    assert_eq!(requests[1].query("pageBefore"), Some("Y3Vyc29yLTA="));
    assert_eq!(requests[1].query("from"), Some("2026-07-01T00:00:00Z"));
    assert_eq!(requests[1].query("to"), Some("2026-07-13T00:00:00Z"));
    assert_eq!(
        requests[1].query("pageAfter"),
        None,
        "pageAfter must NOT ride along with pageBefore"
    );
    assert_eq!(requests[1].query.len(), 4);

    // all four Link rels are parsed, and the pagination cursor is extracted from each href
    assert_eq!(cursors.next_cursor(), Some("Y3Vyc29yLTI="));
    assert_eq!(
        cursors.self_().and_then(|l| l.cursor()),
        Some("Y3Vyc29yLTE=")
    );
    assert_eq!(
        cursors.prev().and_then(|l| l.cursor()),
        Some("Y3Vyc29yLTA=")
    );
    assert!(
        cursors.first().is_some_and(|l| l.cursor().is_none()),
        "the `first` link exists and carries no cursor"
    );
}

/// **The forbidden combination is unrepresentable.** Circle's list-attestations endpoint says
/// `pageAfter` must not be used with `pageBefore` (and vice versa), so `BatchQuery` holds ONE
/// cursor, not two independent `Option`s: setting either replaces the other. A caller cannot
/// construct — and therefore cannot send — the invalid request at all.
#[rstest]
#[case::after_then_before(true)]
#[case::before_then_after(false)]
#[tokio::test]
async fn t_rly_03_the_two_cursors_are_mutually_exclusive(#[case] after_first: bool) {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::new(10).expect("valid");
    let query = if after_first {
        query.with_page_after("AFTER").with_page_before("BEFORE")
    } else {
        query.with_page_before("BEFORE").with_page_after("AFTER")
    };

    // the LAST cursor set is the one that survives — the other is not merely dropped from the wire,
    // it is not in the query at all
    let (expected_name, expected_value, absent_name) = if after_first {
        ("pageBefore", "BEFORE", "pageAfter")
    } else {
        ("pageAfter", "AFTER", "pageBefore")
    };
    if after_first {
        assert_eq!(query.page_before(), Some("BEFORE"));
        assert_eq!(query.page_after(), None);
    } else {
        assert_eq!(query.page_after(), Some("AFTER"));
        assert_eq!(query.page_before(), None);
    }

    poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect("the page decodes");

    let request = &mock.requests_to(Endpoint::Batch)[0];
    assert_eq!(request.query(expected_name), Some(expected_value));
    assert_eq!(
        request.query(absent_name),
        None,
        "the two cursors may never be sent together"
    );
    assert_eq!(request.query.len(), 2, "pageSize + exactly one cursor");
}

/// The steady-state forward poll: follow `Link: rel=next` until it is absent, feeding each page's
/// `next` cursor back as the following request's `pageAfter`. A `next == None` page terminates the
/// scan. The forward query carries ONLY `pageSize` + `pageAfter` — `from`/`to`/`pageBefore` are
/// intentionally unset.
#[tokio::test]
async fn t_rly_03_forward_poll_advances_the_next_cursor_until_it_is_absent() {
    let vector_a = test_vector();
    let vector_b = PartnerAttester::new().attest(&fixtures::canonical_payload(
        TEST_VECTOR_PAYLOAD_ID_EMPTY_HOOKDATA,
    ));
    let page_2_href = batch_href(
        FIXTURE_MIDEN_DOMAIN,
        1,
        Some(("pageAfter", "cursor-page-2")),
    );
    let mock = MockCircle::start(Script::new().batch(vec![
        // page 1: one attestation + a `next` cursor
        Reply::ok_linked(
            attestation_page(&[&vector_a]),
            link_header(&[("next", &page_2_href)]),
        ),
        // page 2: one attestation, NO `next` rel → the scan terminates
        Reply::ok_linked(
            attestation_page(&[&vector_b]),
            link_header(&[("self", &page_2_href)]),
        ),
    ]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    // the forward poll loop: start with no cursor, advance while `next` is Some
    let mut cursor: Option<String> = None;
    let mut collected = Vec::new();
    loop {
        let query = BatchQuery::forward(1, cursor.as_deref()).expect("valid forward query");
        let (page, cursors) =
            poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
                .await
                .expect("page fetch");
        collected.extend(page.into_attestations());
        match cursors.next_cursor() {
            Some(next) => cursor = Some(next.to_string()),
            None => break,
        }
    }

    assert_eq!(
        collected.len(),
        2,
        "both pages were consumed, then the scan stopped"
    );
    assert_eq!(collected[0].payload(), vector_a.payload());
    assert_eq!(collected[1].payload(), vector_b.payload());

    let requests = mock.requests_to(Endpoint::Batch);
    assert_eq!(requests.len(), 2, "exactly two pages were fetched");
    // page 1: forward poll with no cursor yet → pageSize only
    assert_eq!(requests[0].query("pageSize"), Some("1"));
    assert_eq!(requests[0].query("pageAfter"), None);
    assert_eq!(requests[0].query.len(), 1);
    // page 2: the cursor from page 1's `Link: rel=next` is fed back as `pageAfter`
    assert_eq!(requests[1].query("pageAfter"), Some("cursor-page-2"));
    assert_eq!(requests[1].query("pageSize"), Some("1"));
    assert_eq!(
        requests[1].query.len(),
        2,
        "the forward poll leaves from/to/pageBefore unset"
    );
}

/// RFC 8288 permits a RELATIVE href in a `Link` header. The cursor must still be extracted (a
/// parser that only handles absolute URLs would silently lose the cursor and re-scan page 1
/// forever).
#[tokio::test]
async fn t_rly_03_link_header_with_a_relative_href_still_yields_the_cursor() {
    let vector = test_vector();
    let relative = format!(
        "/v1/remote-domains/{FIXTURE_MIDEN_DOMAIN}/attestations?pageSize=1&pageAfter=cursor-rel"
    );
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        link_header(&[("next", &relative)]),
    )]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(1, None).expect("valid query");
    let (_page, cursors) = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect("page fetch");

    assert_eq!(cursors.next_cursor(), Some("cursor-rel"));
}

/// A page with NO `Link` header at all terminates the scan (no cursors, no panic).
#[tokio::test]
async fn t_rly_03_a_page_without_a_link_header_terminates_the_scan() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(1, None).expect("valid query");
    let (page, cursors) = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect("page fetch");

    assert_eq!(page.attestations().len(), 1);
    assert_eq!(cursors.next_cursor(), None);
}

/// An element of a batch page whose envelope does not bind its payload is rejected — the batch path
/// runs the SAME §8.1 checks as the by-hash path (a bad element cannot slip through the list shape).
#[tokio::test]
async fn t_rly_03_a_batch_page_element_with_a_broken_binding_is_rejected() {
    let vector = test_vector();
    let mut page = attestation_page(&[&vector]);
    page["attestations"][0]["messageHash"] =
        json!("0x0000000000000000000000000000000000000000000000000000000000000002");
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok(page)]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(1, None).expect("valid query");
    let err = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect_err("the element's envelope does not bind its payload");

    assert_matches!(err, RelayerError::MessageHashMismatch { .. });
    assert_eq!(sink.rejections().len(), 1);
}

/// `pageSize` is documented as 1–1000. The bound is enforced in the constructor, so an out-of-range
/// page size cannot reach the wire at all.
#[rstest]
#[case::zero(0, false)]
#[case::min(1, true)]
#[case::max(1000, true)]
#[case::over_max(1001, false)]
fn t_rly_03_batch_query_enforces_the_documented_page_size_bounds(
    #[case] page_size: u16,
    #[case] valid: bool,
) {
    let result = BatchQuery::new(page_size);
    if valid {
        assert_eq!(result.expect("in range").page_size(), page_size);
    } else {
        assert_matches!(
            result.expect_err("out of range"),
            RelayerError::BadPageSize { actual } if actual == page_size
        );
    }
}

// T-RLY-04 — GET /v1/info (the public no-`domain`-param shape)
// ================================================================================================

#[tokio::test]
async fn t_rly_04_info_is_fetched_with_no_domain_param_and_both_domain_lists_decode() {
    let mock = MockCircle::start(Script::new().info(vec![Reply::ok(info_body())]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let info = fetch_info(&client).await.expect("/v1/info decodes");

    // (2) the DEFAULT request shape carries NO `domain` query param — the public/OpenAPI form. The
    //     NDA's `/v1/info?domain={domain}` is a recorded CONFLICT (Q-INFO-PARAM, REQUIRES CIRCLE
    //     CONFIRMATION), not the implemented default.
    let requests = mock.requests_to(Endpoint::Info);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/info");
    assert!(
        requests[0].query.is_empty(),
        "the public shape takes NO query params (least of all `domain`)"
    );

    // (1) the relayer reads the Miden domain config + the xUSDC identifier out of the response
    let source = &info.source_domains()[0];
    assert_eq!(source.chain(), "Ethereum");
    assert_eq!(source.network(), "testnet");
    assert_eq!(source.domain(), 0);
    assert_eq!(
        source.contract_address(),
        "0x0000000000000000000000000000000000001234"
    );
    assert_eq!(source.tokens(), ["USDC"]);

    let remote = info
        .remote_domain(FIXTURE_MIDEN_DOMAIN)
        .expect("the Miden remote domain is discoverable by id");
    assert_eq!(remote.chain(), "Miden");
    assert_eq!(remote.network(), "devnet");
    assert_eq!(remote.tokens().len(), 1);
    assert_eq!(remote.tokens()[0].remote_token(), "xUSDC");
    assert_eq!(
        remote.tokens()[0].remote_token_identifier(),
        FIXTURE_XUSDC_IDENTIFIER
    );
    assert_eq!(remote.tokens()[0].associated_native_token(), "USDC");
    assert_eq!(
        remote.token_identifier("xUSDC"),
        Some(FIXTURE_XUSDC_IDENTIFIER)
    );
    assert_eq!(remote.token_identifier("DAI"), None);
}

/// `/v1/info` documents 500 (and no 404). A 500 is transient → retried under the same policy as
/// every other endpoint.
#[tokio::test]
async fn t_rly_04_info_retries_a_500_then_succeeds() {
    let mock =
        MockCircle::start(Script::new().info(vec![Reply::Status(500), Reply::ok(info_body())]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let info = fetch_info(&client).await.expect("the retry succeeds");
    assert_eq!(info.remote_domains().len(), 1);
    assert_eq!(mock.requests_to(Endpoint::Info).len(), 2);
}

// T-RLY-03 (cont.) — MALFORMED pagination metadata is never mistaken for the end of the scan
// ================================================================================================
//
// The scan terminates on `next == None`. That makes "no next link" a LOAD-BEARING signal, and it is
// exactly why a `Link` header the relayer cannot parse must not be silently discarded: discarding it
// produces the same `next == None` as a legitimate final page, so a corrupted (or truncated, or
// hostile) header would quietly stop the relayer mid-stream. Deposits already attested would simply
// never be minted, and nothing would be logged — the silent drop §8.4 forbids.
//
// So: an ABSENT Link header is terminal (the documented final page). A PRESENT one must parse, must
// carry at least one relation the relayer understands, and — if it advertises `next` — must carry a
// cursor that can actually advance the scan. Anything else is a typed rejection with an alert.

/// A present `Link` header that is not a `Link` header at all.
#[tokio::test]
async fn t_rly_03_a_garbage_link_header_is_rejected_not_read_as_end_of_scan() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        "this is not a link header",
    )]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    let err = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect_err("unparseable pagination metadata must not be read as a final page");

    assert_matches!(err, RelayerError::BadPaginationMetadata { .. });
    assert_eq!(sink.rejections().len(), 1, "logged with a reason");
    assert_eq!(sink.alerts().len(), 1, "an operator must hear about it");
}

/// A `next` link with no cursor in it. It advertises that more pages exist, and gives the relayer no
/// way to reach them: treating that as the end of the scan would strand every later page.
#[tokio::test]
async fn t_rly_03_a_next_link_without_a_cursor_is_rejected() {
    let vector = test_vector();
    let cursorless = batch_href(FIXTURE_MIDEN_DOMAIN, 10, None);
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        link_header(&[("next", &cursorless)]),
    )]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    let err = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect_err("a `next` relation the relayer cannot follow is not a final page");

    assert_matches!(err, RelayerError::BadPaginationMetadata { .. });
    assert_eq!(sink.alerts().len(), 1);
}

/// A `Link` header whose href is not a URL at all.
#[tokio::test]
async fn t_rly_03_a_link_with_an_unparseable_href_is_rejected() {
    let vector = test_vector();
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        "<http://[not a url>; rel=\"next\"",
    )]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    assert_matches!(
        poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
            .await
            .expect_err("an unparseable href"),
        RelayerError::BadPaginationMetadata { .. }
    );
}

/// A `Link` header carrying only relations the relayer does not understand. It is not obviously a
/// final page — it is metadata the relayer cannot reason about — so it is refused rather than
/// guessed at.
#[tokio::test]
async fn t_rly_03_a_link_with_no_recognized_relation_is_rejected() {
    let vector = test_vector();
    let href = batch_href(FIXTURE_MIDEN_DOMAIN, 10, Some(("pageAfter", "c")));
    let mock = MockCircle::start(Script::new().batch(vec![Reply::ok_linked(
        attestation_page(&[&vector]),
        link_header(&[("last", &href)]),
    )]));
    let (client, _sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    assert_matches!(
        poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
            .await
            .expect_err("no relation the relayer understands"),
        RelayerError::BadPaginationMetadata { .. }
    );
}

/// A `Link` header that is not valid UTF-8. The bytes are legal in an HTTP header and illegal as
/// pagination metadata — and dropping them, as a `to_str().ok()` would, is the same silent
/// end-of-scan.
#[tokio::test]
async fn t_rly_03_a_non_utf8_link_header_is_rejected() {
    let vector = test_vector();
    // 0xFF is not valid UTF-8 anywhere, and HeaderValue accepts it
    let raw = vec![
        b'<', 0xff, 0xfe, b'>', b';', b' ', b'r', b'e', b'l', b'=', b'"', b'n', b'e', b'x', b't',
        b'"',
    ];
    let mock = MockCircle::start(
        Script::new().batch(vec![Reply::ok_raw_link(attestation_page(&[&vector]), raw)]),
    );
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    let err = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect_err("a Link header that is not text");

    assert_matches!(err, RelayerError::BadPaginationMetadata { .. });
    assert_eq!(sink.alerts().len(), 1);
}

/// The counterweight: a page with NO `Link` header at all IS the documented final page, and must
/// still terminate the scan cleanly. (Without this, "reject malformed metadata" could be satisfied by
/// rejecting everything — including the normal end of a scan.)
#[tokio::test]
async fn t_rly_03_an_absent_link_header_remains_the_terminal_case() {
    let vector = test_vector();
    let mock =
        MockCircle::start(Script::new().batch(vec![Reply::ok(attestation_page(&[&vector]))]));
    let (client, sink) = client_for(&mock, AuthPosture::None);

    let query = BatchQuery::forward(10, None).expect("valid query");
    let (page, cursors) = poll_remote_domain_attestations(&client, FIXTURE_MIDEN_DOMAIN, &query)
        .await
        .expect("no Link header is a clean final page, not an error");

    assert_eq!(page.attestations().len(), 1);
    assert_eq!(cursors.next_cursor(), None);
    assert!(sink.rejections().is_empty() && sink.alerts().is_empty());
}
