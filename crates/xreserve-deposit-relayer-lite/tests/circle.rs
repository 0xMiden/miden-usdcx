//! Pure tests for Circle request construction and response decoding.

mod fixtures;

use fixtures::{next_link, page_body, wire_attestation};
use xreserve_deposit_relayer_lite::circle::{build_page_url, decode_page};

/// The request is the documented endpoint carrying only `pageSize` and `pageAfter`.
#[test]
fn the_request_names_the_endpoint_and_its_two_parameters() {
    let base_url = "https://circle.test".parse().unwrap();
    let url = build_page_url(&base_url, 7, 250, Some("the-cursor")).unwrap();

    assert_eq!(
        url.as_str(),
        "https://circle.test/v1/remote-domains/7/attestations?pageSize=250&pageAfter=the-cursor"
    );
}

/// An opaque cursor with URL-hostile bytes survives request construction percent-encoded.
#[test]
fn the_cursor_is_percent_encoded() {
    let base_url = "https://circle.test".parse().unwrap();
    let url = build_page_url(&base_url, 7, 100, Some("a+b/c=")).unwrap();

    assert!(url.as_str().contains("pageAfter=a%2Bb%2Fc%3D"), "{url}");
}

/// The `next` cursor is read from the `Link` header.
#[test]
fn the_next_cursor_comes_from_the_link_header() {
    let body = page_body(&[wire_attestation(1)]);
    let link = next_link("page-2");
    let page = decode_page(200, &body, Some(&link)).unwrap();

    assert_eq!(page.next.as_deref(), Some("page-2"));
    assert_eq!(page.attestations.len(), 1);
}

/// An absent `Link` header is the documented final page, not an error.
#[test]
fn an_absent_link_header_is_the_final_page() {
    let body = page_body(&[wire_attestation(1)]);
    let page = decode_page(200, &body, None).unwrap();

    assert_eq!(page.next, None);
}

/// A present but unparseable `Link` header is an error rather than the end of the feed.
#[test]
fn an_unparseable_link_header_is_an_error() {
    let body = page_body(&[wire_attestation(1)]);
    let error = decode_page(200, &body, Some("this is not a link header"))
        .unwrap_err()
        .to_string();

    assert!(error.contains("Link header"), "unexpected error: {error}");
}

/// A non-200 response fails rather than being decoded as a page.
#[test]
fn a_non_200_fails_the_fetch() {
    let error = decode_page(500, br#"{"message":"upstream failure"}"#, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("500"), "unexpected error: {error}");
}

/// A body that is not the documented shape is a clear decode error.
#[test]
fn schema_drift_is_a_decode_error() {
    let error = decode_page(200, br#"{"items":[]}"#, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("decoding"), "unexpected error: {error}");
}
