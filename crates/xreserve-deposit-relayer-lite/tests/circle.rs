//! The Circle client: T-H1 … T-H7.

mod support;

use std::sync::Arc;

use support::{attestation, error_response, page, test_config, MockCircle, TEST_REMOTE_DOMAIN};
use xreserve_deposit_relayer_lite::circle::{CircleClient, HttpResponse};
use xreserve_deposit_relayer_lite::config::Config;

/// Builds a client over `mock`, with a chance to adjust the config.
fn client(mock: Arc<MockCircle>, adjust: impl FnOnce(&mut Config)) -> CircleClient {
    let mut config = test_config("unused.db".into());
    adjust(&mut config);
    CircleClient::new(&config, mock)
}

/// T-H1 — the request is the documented endpoint, carrying only the two parameters the forward scan
/// uses.
#[tokio::test]
async fn the_request_names_the_endpoint_and_its_two_parameters() {
    let mock = MockCircle::one_page(&[]);
    let circle = client(mock.clone(), |_| {});

    circle
        .attestations(TEST_REMOTE_DOMAIN, 25, Some("the-cursor"))
        .await
        .unwrap();

    let request = &mock.requests()[0];
    assert!(
        request.url.contains(&format!(
            "/v1/remote-domains/{TEST_REMOTE_DOMAIN}/attestations"
        )),
        "unexpected url: {}",
        request.url
    );
    assert!(request.url.contains("pageSize=25"), "{}", request.url);
    assert!(
        request.url.contains("pageAfter=the-cursor"),
        "{}",
        request.url
    );
    // the parameters the lite client does NOT model
    assert!(!request.url.contains("pageBefore"), "{}", request.url);
}

/// T-H2 — the configured credential is injected into the configured header, and nothing is sent
/// when none is configured.
#[tokio::test]
async fn the_credential_is_injected_only_when_configured() {
    let mock = MockCircle::one_page(&[]);
    let circle = client(mock.clone(), |config| {
        config.api_auth_token = Some("sekrit".to_string());
        config.api_auth_header = "X-Api-Key".to_string();
    });
    circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap();

    assert_eq!(
        mock.requests()[0].headers,
        vec![("X-Api-Key".to_string(), "sekrit".to_string())]
    );

    let bare_mock = MockCircle::one_page(&[]);
    let bare = client(bare_mock.clone(), |_| {});
    bare.attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap();

    assert!(bare_mock.requests()[0].headers.is_empty());
}

/// T-H3 — the `next` cursor is read out of the `Link` header.
#[tokio::test]
async fn the_next_cursor_comes_from_the_link_header() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], Some("page-2"))]);
    let circle = client(mock, |_| {});

    let fetched = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap();

    assert_eq!(fetched.next.as_deref(), Some("page-2"));
    assert_eq!(fetched.attestations.len(), 1);
}

/// T-H4 — an ABSENT `Link` header is the documented final page, not an error.
#[tokio::test]
async fn an_absent_link_header_is_the_final_page() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], None)]);
    let circle = client(mock, |_| {});

    let fetched = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap();

    assert_eq!(fetched.next, None);
}

/// T-H5 — a PRESENT but unparseable `Link` header is an ERROR.
///
/// It must never be read as "no next page": a corrupted header would then look exactly like the end
/// of the feed and the scan would stop early and silently.
#[tokio::test]
async fn an_unparseable_link_header_is_an_error() {
    let mock = MockCircle::new(vec![HttpResponse {
        link: Some("this is not a link header".to_string()),
        ..page(&[attestation(1)], None)
    }]);
    let circle = client(mock, |_| {});

    let error = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("Link header"), "unexpected error: {error}");
}

/// T-H6 — a body beyond the ceiling is refused.
#[tokio::test]
async fn an_oversize_body_is_refused() {
    let mock = MockCircle::new(vec![page(&[attestation(1)], None)]);
    let circle = client(mock, |config| config.max_response_bytes = 8);

    let error = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("ceiling"), "unexpected error: {error}");
}

/// T-H7 — a body that is not the documented shape produces a clear decode error.
#[tokio::test]
async fn schema_drift_is_a_decode_error() {
    let mock = MockCircle::new(vec![HttpResponse {
        status: 200,
        body: br#"{"items":[]}"#.to_vec(),
        link: None,
    }]);
    let circle = client(mock, |_| {});

    let error = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("decoding"), "unexpected error: {error}");
}

/// A non-200 fails the fetch rather than being decoded as a page.
#[tokio::test]
async fn a_non_200_fails_the_fetch() {
    let mock = MockCircle::new(vec![error_response(500)]);
    let circle = client(mock, |_| {});

    let error = circle
        .attestations(TEST_REMOTE_DOMAIN, 10, None)
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("500"), "unexpected error: {error}");
}
