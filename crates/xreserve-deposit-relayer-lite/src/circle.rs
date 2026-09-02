//! One paginated GET against Circle's attestation feed:
//! `GET /v1/remote-domains/{d}/attestations?pageSize=&pageAfter=`.
//!
//! Pagination travels in the RFC 8288 `Link` header, not the body. An absent header is the
//! documented final page, while a present but unparseable header is an error. Treating the second
//! as the first would make a corrupted header look like the end of the feed and silently end the
//! scan early.
//!
//! No authentication is sent because Circle has not documented an authentication scheme yet.

use std::fmt;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::Url;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::store::CircleCursor;

/// The number of attestations requested per page, within Circle's documented `pageSize` range of
/// 1 through 1000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u16);

impl PageSize {
    const MIN: u16 = 1;
    const MAX: u16 = 1000;
}

impl TryFrom<u16> for PageSize {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self> {
        ensure!(
            (Self::MIN..=Self::MAX).contains(&value),
            "page size must be between {} and {}, got {value}",
            Self::MIN,
            Self::MAX
        );
        Ok(Self(value))
    }
}

impl FromStr for PageSize {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let value: u16 = value.parse().context("the page size is not a number")?;
        Self::try_from(value)
    }
}

impl fmt::Display for PageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One entry of Circle's attestation feed: the encoded DepositIntent and the attester's signature
/// over it. Circle publishes each field as `0x`-hex; the hex is decoded here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The encoded DepositIntent.
    #[serde(deserialize_with = "hex_bytes")]
    pub payload: Vec<u8>,
    /// `keccak256(payload)`. Identifies the attestation when it is reported as skipped; the chain
    /// recomputes and verifies it.
    #[serde(deserialize_with = "hex_array")]
    pub message_hash: [u8; 32],
    /// The 65-byte `r‖s‖v` secp256k1 signature, published under the `attestation` key.
    #[serde(rename = "attestation", deserialize_with = "hex_array")]
    pub signature: [u8; 65],
}

/// The list response body. Pagination is in the `Link` header rather than this body.
#[derive(Debug, Deserialize)]
struct ListResponse {
    attestations: Vec<Attestation>,
}

/// One page of the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub attestations: Vec<Attestation>,
    /// The cursor for the next page, or `None` at the end of the feed.
    pub next: Option<CircleCursor>,
}

impl Page {
    /// Response-size ceiling, so a runaway body cannot exhaust memory.
    const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

    /// Decodes one successful Circle response into a page.
    ///
    /// # Errors
    ///
    /// - The body does not match Circle's attestation schema.
    /// - A present `Link` header is malformed.
    pub fn decode(body: &[u8], link: Option<&str>) -> Result<Self> {
        let list: ListResponse =
            serde_json::from_slice(body).context("decoding the circle attestation page")?;
        let next = match link {
            // An absent `Link` header is the documented final page.
            None => None,
            Some(header) => parse_next_link(header)?,
        };

        Ok(Self {
            attestations: list.attestations,
            next: next.map(CircleCursor::new),
        })
    }

    /// Returns the cursor for the next page, or `None` when the feed is caught up.
    pub fn next_cursor(&self) -> Option<&CircleCursor> {
        self.next.as_ref()
    }
}

/// The Circle-facing HTTP client.
#[derive(Debug)]
pub struct CircleClient {
    base_url: Url,
    page_size: PageSize,
    client: reqwest::blocking::Client,
}

impl CircleClient {
    /// Creates a Circle client with the configured page size and request timeout.
    ///
    /// # Errors
    ///
    /// - The request timeout is zero.
    /// - The reqwest client cannot be constructed.
    pub fn new(base_url: Url, page_size: PageSize, request_timeout: Duration) -> Result<Self> {
        ensure!(
            !request_timeout.is_zero(),
            "request timeout must be greater than zero"
        );
        let client = reqwest::blocking::Client::builder()
            .timeout(request_timeout)
            .build()
            .context("building the circle http client")?;

        Ok(Self {
            base_url,
            page_size,
            client,
        })
    }

    /// Fetches the page after `cursor`, or the first page when it is `None`.
    ///
    /// # Errors
    ///
    /// - The request fails or times out.
    /// - Circle answers with a non-success status.
    /// - The response exceeds the size ceiling.
    /// - The response does not decode as a page (see [`Page::decode`]).
    pub fn fetch_page(&self, remote_domain: u32, cursor: Option<&CircleCursor>) -> Result<Page> {
        let response = self
            .client
            .get(self.page_url(remote_domain, cursor))
            .send()
            .context("the circle request failed")?;
        ensure!(
            response.status().is_success(),
            "circle answered {} for the attestation page",
            response.status()
        );

        let link = response
            .headers()
            .get(reqwest::header::LINK)
            .map(|value| value.to_str())
            .transpose()
            .context("decoding the circle Link header")?
            .map(str::to_owned);

        // Read one byte past the ceiling rather than `bytes()`: a runaway body must not be
        // buffered in full before it is rejected.
        let mut body = Vec::new();
        response
            .take(Page::MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .context("reading the circle response")?;
        ensure!(
            body.len() <= Page::MAX_RESPONSE_BYTES,
            "the circle response exceeded the {}-byte ceiling",
            Page::MAX_RESPONSE_BYTES
        );

        Page::decode(&body, link.as_deref())
    }

    /// The URL of one attestation page.
    fn page_url(&self, remote_domain: u32, cursor: Option<&CircleCursor>) -> Url {
        let mut url = self.base_url.clone();
        let path = format!(
            "{}/v1/remote-domains/{remote_domain}/attestations",
            self.base_url.path().trim_end_matches('/')
        );
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);

        url.query_pairs_mut()
            .append_pair("pageSize", &self.page_size.to_string());
        // `append_pair` percent-encodes the opaque cursor, which may carry base64's `+`, `/`, and
        // `=`.
        if let Some(cursor) = cursor {
            url.query_pairs_mut()
                .append_pair("pageAfter", cursor.as_str());
        }

        url
    }
}

/// Extracts the `pageAfter` token of the `rel="next"` relation from a `Link` header.
///
/// # Errors
///
/// - The header is not a valid RFC 8288 `Link` header with relation parameters.
fn parse_next_link(header: &str) -> Result<Option<String>> {
    let links =
        parse_link_header::parse_with_rel(header).context("parsing the circle Link header")?;

    Ok(links.get("next").and_then(|link| {
        link.uri
            .query_pairs()
            .find(|(key, _)| key == "pageAfter")
            .map(|(_, value)| value.into_owned())
    }))
}

/// Deserializes Circle wire hex, tolerating the optional `0x` prefix the API emits.
fn hex_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(deserializer)?;
    hex::decode(text.strip_prefix("0x").unwrap_or(&text)).map_err(de::Error::custom)
}

/// Deserializes Circle wire hex of exactly `N` bytes.
fn hex_array<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let bytes = hex_bytes(deserializer)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| de::Error::invalid_length(bytes.len(), &format!("{N} bytes of hex").as_str()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Attestation, CircleClient, Page, PageSize};
    use crate::store::CircleCursor;

    /// A page size within the documented range.
    fn page_size(value: u16) -> PageSize {
        PageSize::try_from(value).unwrap()
    }

    /// A client over a placeholder base URL; nothing here sends a request.
    fn client(page_size: u16) -> CircleClient {
        CircleClient::new(
            "https://circle.test".parse().unwrap(),
            self::page_size(page_size),
            Duration::from_secs(1),
        )
        .unwrap()
    }

    /// A syntactically valid wire attestation whose fields are arbitrary bytes.
    fn attestation(seed: u8) -> Attestation {
        Attestation {
            payload: vec![seed; 8],
            message_hash: [seed; 32],
            signature: [seed; 65],
        }
    }

    /// Encodes these attestations as a Circle list response body.
    fn page_body(attestations: &[Attestation]) -> Vec<u8> {
        let items: Vec<_> = attestations
            .iter()
            .map(|attestation| {
                serde_json::json!({
                    "payload": format!("0x{}", hex::encode(&attestation.payload)),
                    "messageHash": format!("0x{}", hex::encode(attestation.message_hash)),
                    "attestation": format!("0x{}", hex::encode(attestation.signature)),
                })
            })
            .collect();

        serde_json::json!({ "attestations": items })
            .to_string()
            .into_bytes()
    }

    /// Builds a `Link` header carrying the next cursor.
    fn next_link(cursor: &str) -> String {
        format!(
            "<https://circle.test/v1/remote-domains/1/attestations?pageSize=100&pageAfter={cursor}>; rel=\"next\""
        )
    }

    /// The documented range is accepted and everything outside it is refused.
    #[test]
    fn the_page_size_is_bounded() {
        assert!(PageSize::try_from(0).is_err());
        assert!(PageSize::try_from(1).is_ok());
        assert!(PageSize::try_from(1000).is_ok());
        assert!(PageSize::try_from(1001).is_err());
        assert!("abc".parse::<PageSize>().is_err());
        assert_eq!("250".parse::<PageSize>().unwrap(), page_size(250));
    }

    /// The request is the documented endpoint carrying only `pageSize` and `pageAfter`.
    #[test]
    fn the_request_names_the_endpoint_and_its_two_parameters() {
        let cursor = CircleCursor::new("the-cursor");
        let url = client(250).page_url(7, Some(&cursor));

        assert_eq!(
            url.as_str(),
            "https://circle.test/v1/remote-domains/7/attestations?pageSize=250&pageAfter=the-cursor"
        );
    }

    /// An opaque cursor with URL-hostile bytes survives request construction percent-encoded.
    #[test]
    fn the_cursor_is_percent_encoded() {
        let cursor = CircleCursor::new("a+b/c=");
        let url = client(100).page_url(7, Some(&cursor));

        assert!(url.as_str().contains("pageAfter=a%2Bb%2Fc%3D"), "{url}");
    }

    /// The wire hex decodes to the bytes it encodes.
    #[test]
    fn the_attestation_fields_are_decoded_from_hex() {
        let body = page_body(&[attestation(1)]);
        let page = Page::decode(&body, None).unwrap();

        assert_eq!(page.attestations, vec![attestation(1)]);
    }

    /// A fixed-size field of the wrong length is a decode error, not a truncation.
    #[test]
    fn a_wrong_length_field_is_a_decode_error() {
        let body =
            br#"{"attestations":[{"payload":"0x00","messageHash":"0x00","attestation":"0x00"}]}"#;
        let error = Page::decode(body, None).unwrap_err().to_string();

        assert!(error.contains("decoding"), "unexpected error: {error}");
    }

    /// The `next` cursor is read from the `Link` header.
    #[test]
    fn the_next_cursor_comes_from_the_link_header() {
        let body = page_body(&[attestation(1)]);
        let link = next_link("page-2");
        let page = Page::decode(&body, Some(&link)).unwrap();

        assert_eq!(page.next, Some(CircleCursor::new("page-2")));
        assert_eq!(page.attestations.len(), 1);
    }

    /// An absent `Link` header is the documented final page, not an error.
    #[test]
    fn an_absent_link_header_is_the_final_page() {
        let body = page_body(&[attestation(1)]);
        let page = Page::decode(&body, None).unwrap();

        assert_eq!(page.next, None);
    }

    /// A present but unparseable `Link` header is an error rather than the end of the feed.
    #[test]
    fn an_unparseable_link_header_is_an_error() {
        let body = page_body(&[attestation(1)]);
        let error = Page::decode(&body, Some("this is not a link header"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("Link header"), "unexpected error: {error}");
    }

    /// A body that is not the documented shape is a clear decode error.
    #[test]
    fn schema_drift_is_a_decode_error() {
        let error = Page::decode(br#"{"items":[]}"#, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("decoding"), "unexpected error: {error}");
    }
}
