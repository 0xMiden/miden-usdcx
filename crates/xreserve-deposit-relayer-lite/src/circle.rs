//! One paginated GET against Circle's attestation feed:
//! `GET /v1/remote-domains/{d}/attestations?pageSize=&pageAfter=`.
//!
//! Pagination travels in the RFC 8288 `Link` header, not the body. An absent header is the
//! documented final page, while a present but unparseable header is an error. Treating the second
//! as the first would make a corrupted header look like the end of the feed and silently end the
//! scan early.
//!
//! The feed is ordered newest first, so the first page holds the most recent deposits and the
//! `next` relation leads into the past. Circle publishes no way to ask for the opposite order.
//!
//! No authentication is sent because Circle has not documented an authentication scheme yet.

use std::fmt;
use std::io::Read;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::Url;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use tracing::field::Empty;
use tracing::{instrument, Span};

use xusdc_encoding::xreserve::encoding::Signature;

/// Circle's opaque `pageAfter` pagination token, held exactly as the feed returned it.
///
/// Circle builds it from the attestation time and message hash of the entry a page ended at, so it
/// names an entry rather than an offset. Deposits arriving at the head of the feed therefore do not
/// shift what it addresses, which is what makes it safe to store and hand back after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CircleCursor(String);

impl CircleCursor {
    /// Wraps a token taken verbatim from a Circle feed response.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The token, ready to be sent back as the `pageAfter` query parameter.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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

/// The Circle domain identifier of the chain whose attestations are read — Miden. It names the
/// feed in the request path and is the domain every mint note is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteDomain(u32);

impl RemoteDomain {
    /// Wraps a Circle domain identifier. Every `u32` is a well-formed identifier.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}

impl From<RemoteDomain> for u32 {
    fn from(domain: RemoteDomain) -> Self {
        domain.0
    }
}

impl FromStr for RemoteDomain {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let value: u32 = value
            .parse()
            .context("the remote domain is not a 32-bit number")?;
        Ok(Self::new(value))
    }
}

impl fmt::Display for RemoteDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The width of the `keccak256` digest that names a deposit.
const MESSAGE_HASH_BYTES: usize = 32;

/// `keccak256` of an attestation's payload, which is what names one deposit in the feed.
///
/// It identifies an attestation in a log line and in the relayer's stored progress; the chain
/// recomputes and verifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageHash([u8; MESSAGE_HASH_BYTES]);

impl MessageHash {
    /// Wraps a digest as the feed published it.
    pub const fn new(bytes: [u8; MESSAGE_HASH_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for MessageHash {
    /// Renders the `0x`-hex form Circle publishes, so a log line can be matched against the feed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for MessageHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_array(deserializer).map(Self)
    }
}

impl Serialize for MessageHash {
    /// Writes the `0x`-hex form the feed publishes, so what the store holds is the text an
    /// operator can search the feed for, and is what [`Deserialize`] reads back.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
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
    /// The digest naming this deposit.
    pub message_hash: MessageHash,
    /// The attester's signature over the payload, published under the `attestation` key.
    #[serde(rename = "attestation", deserialize_with = "hex_signature")]
    pub signature: Signature,
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
    #[instrument(
        name = "circle.fetch_page",
        skip_all,
        fields(remote_domain = %remote_domain, status = Empty, attestations = Empty, next = Empty),
    )]
    pub fn fetch_page(
        &self,
        remote_domain: RemoteDomain,
        cursor: Option<&CircleCursor>,
    ) -> Result<Page> {
        let span = Span::current();
        let response = self
            .client
            .get(self.page_url(remote_domain, cursor))
            .send()
            .context("the circle request failed")?;
        span.record("status", response.status().as_u16());
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

        let page = Page::decode(&body, link.as_deref())?;
        span.record("attestations", page.attestations.len());
        if let Some(next) = page.next_cursor() {
            span.record("next", next.as_str());
        }
        Ok(page)
    }

    /// The URL of one attestation page.
    fn page_url(&self, remote_domain: RemoteDomain, cursor: Option<&CircleCursor>) -> Url {
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

/// Deserializes Circle wire hex into the signature type the mint note is built from.
fn hex_signature<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
    hex_array(deserializer).map(Signature::new)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        Attestation, CircleClient, CircleCursor, MessageHash, Page, PageSize, RemoteDomain,
        Signature,
    };

    /// The domain the request tests address.
    const REMOTE_DOMAIN: RemoteDomain = RemoteDomain::new(7);

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
            message_hash: MessageHash::new([seed; 32]),
            signature: Signature::new([seed; 65]),
        }
    }

    /// Encodes these attestations as a Circle list response body.
    fn page_body(attestations: &[Attestation]) -> Vec<u8> {
        let items: Vec<_> = attestations
            .iter()
            .map(|attestation| {
                serde_json::json!({
                    "payload": format!("0x{}", hex::encode(&attestation.payload)),
                    "messageHash": attestation.message_hash.to_string(),
                    "attestation": format!("0x{}", hex::encode(attestation.signature.as_bytes())),
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

    /// A message hash written to the store reads back unchanged, so a restart stops at the same
    /// attestation. It is written in the form the feed publishes, so an operator reading the file
    /// can search the feed for it.
    #[test]
    fn a_message_hash_survives_the_store_round_trip() {
        let message_hash = MessageHash::new([0x5A; 32]);
        let json = serde_json::to_string(&message_hash).unwrap();

        assert_eq!(json, format!("\"{message_hash}\""));
        assert_eq!(
            serde_json::from_str::<MessageHash>(&json).unwrap(),
            message_hash
        );
    }

    /// A cursor written to the store reads back verbatim, so a resumed scan asks Circle for the
    /// page it stopped at.
    #[test]
    fn a_cursor_survives_the_store_round_trip() {
        let cursor = CircleCursor::new("a+b/c=");
        let json = serde_json::to_string(&cursor).unwrap();

        assert_eq!(serde_json::from_str::<CircleCursor>(&json).unwrap(), cursor);
    }

    /// A remote domain is any 32-bit number and nothing else.
    #[test]
    fn the_remote_domain_is_a_32_bit_number() {
        assert_eq!("7".parse::<RemoteDomain>().unwrap(), REMOTE_DOMAIN);
        assert_eq!(u32::from(REMOTE_DOMAIN), 7);
        assert!("abc".parse::<RemoteDomain>().is_err());
        assert!("-1".parse::<RemoteDomain>().is_err());
        assert!("4294967296".parse::<RemoteDomain>().is_err());
    }

    /// The request is the documented endpoint carrying only `pageSize` and `pageAfter`.
    #[test]
    fn the_request_names_the_endpoint_and_its_two_parameters() {
        let cursor = CircleCursor::new("the-cursor");
        let url = client(250).page_url(REMOTE_DOMAIN, Some(&cursor));

        assert_eq!(
            url.as_str(),
            "https://circle.test/v1/remote-domains/7/attestations?pageSize=250&pageAfter=the-cursor"
        );
    }

    /// An opaque cursor with URL-hostile bytes survives request construction percent-encoded.
    #[test]
    fn the_cursor_is_percent_encoded() {
        let cursor = CircleCursor::new("a+b/c=");
        let url = client(100).page_url(REMOTE_DOMAIN, Some(&cursor));

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
