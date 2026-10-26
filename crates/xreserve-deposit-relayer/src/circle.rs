//! One paginated GET against Circle's attestation feed:
//! `GET /v1/remote-domains/{d}/attestations?pageSize=&pageAfter=`.
//!
//! Pagination travels in the RFC 8288 `Link` header, not the body. An absent header is the
//! documented final page, while a header that cannot be parsed, or whose `next` relation carries
//! no token, is an error. Treating either as the final page would make a corrupted header look
//! like the end of the feed and silently end the scan early.
//!
//! The feed is ordered newest first, so the first page holds the most recent deposits and the
//! `next` relation leads into the past. Circle publishes no way to ask for the opposite order.
//!
//! No authentication is sent because Circle has not documented an authentication scheme yet.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use reqwest::{StatusCode, Url};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use tracing::field::Empty;
use tracing::{instrument, Span};
use usdcx_telemetry::FailureClass::Transient;
use usdcx_telemetry::{Classify, Failure};

use miden_usdcx::xreserve::encoding::{CircleDomain, Signature};

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
///
/// The relayer caps this further for its proving mode. One page becomes one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageSize(u16);

impl PageSize {
    const MIN: u16 = 1;
    pub(crate) const LOCAL_PROVING_MAX: Self = Self(10);
    pub(crate) const REMOTE_PROVING_MAX: Self = Self(40);
    /// The largest page Circle documents, before applying the proving limit.
    pub const MAX: u16 = 1000;
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
    #[serde(deserialize_with = "payload_field")]
    pub payload: Vec<u8>,
    /// The digest naming this deposit.
    #[serde(deserialize_with = "message_hash_field")]
    pub message_hash: MessageHash,
    /// The attester's signature over the payload, published under the `attestation` key.
    #[serde(rename = "attestation", deserialize_with = "signature_field")]
    pub signature: Signature,
}

/// One entry of a page, in the place Circle served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Attestation(Attestation),
    /// An entry that is not a readable attestation: a field is missing, is not hex, or has the
    /// wrong length. It keeps its place, so the scan can tell whether it sits above the watermark,
    /// and its message hash when that much could be read.
    Undecodable {
        /// Where the entry sits on its page, counting from 1, so it can be found in the feed
        /// again when it has no readable message hash to look for.
        position: usize,
        message_hash: Option<MessageHash>,
        /// Which field did not decode and why, and the entry's `messageHash` as Circle sent it
        /// when that is not a hash.
        reason: String,
    },
}

impl Entry {
    /// How much of a `messageHash` that is not a hash is reported. A hash is 66 characters, and
    /// the text comes from outside, so a longer one is cut rather than written out in full.
    const MAX_REPORTED_HASH_CHARS: usize = 80;

    /// Decodes the element at `position` of the list response, counting from 1. One that does
    /// not decode is kept as [`Entry::Undecodable`] rather than failing the page: the page would
    /// fail the same way on every retry, and every deposit behind it would wait.
    fn decode(position: usize, value: &serde_json::Value) -> Self {
        let error = match Attestation::deserialize(value) {
            Ok(attestation) => return Self::Attestation(attestation),
            Err(error) => error,
        };
        let sent_hash = value.get("messageHash");
        let message_hash = sent_hash.and_then(|hash| MessageHash::deserialize(hash).ok());
        let reason = match (message_hash, sent_hash) {
            // Without a readable hash the text Circle sent is the closest thing to a name.
            (None, Some(sent)) => {
                let sent: String = sent
                    .to_string()
                    .chars()
                    .take(Self::MAX_REPORTED_HASH_CHARS)
                    .collect();
                format!("{error} (its messageHash is {sent})")
            }
            _ => error.to_string(),
        };
        Self::Undecodable {
            position,
            message_hash,
            reason,
        }
    }

    /// The digest naming this entry, when it could be read.
    pub fn message_hash(&self) -> Option<MessageHash> {
        match self {
            Self::Attestation(attestation) => Some(attestation.message_hash),
            Self::Undecodable { message_hash, .. } => *message_hash,
        }
    }
}

impl From<Attestation> for Entry {
    fn from(attestation: Attestation) -> Self {
        Self::Attestation(attestation)
    }
}

/// The list response body. Pagination is in the `Link` header rather than this body. The entries
/// are decoded one by one, so one that does not decode does not take the page with it.
#[derive(Debug, Deserialize)]
struct ListResponse {
    attestations: Vec<serde_json::Value>,
}

/// One page of the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The page's entries, newest first.
    pub entries: Vec<Entry>,
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
    /// - The body is not Circle's list response. An entry of the list that does not decode is not
    ///   an error: it becomes an [`Entry::Undecodable`].
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
            entries: list
                .attestations
                .iter()
                .enumerate()
                .map(|(index, value)| Entry::decode(index + 1, value))
                .collect(),
            next: next.map(CircleCursor::new),
        })
    }
}

/// The Circle-facing HTTP client.
#[derive(Debug)]
pub struct CircleClient {
    base_url: Url,
    page_size: PageSize,
    client: reqwest::Client,
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
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .context("building the circle http client")?;

        Ok(Self {
            base_url,
            page_size,
            client,
        })
    }

    /// Reduces later requests to the local proving cap. Returns whether the size changed.
    pub(crate) fn limit_to_local_proving(&mut self) -> bool {
        let smaller = self.page_size.min(PageSize::LOCAL_PROVING_MAX);
        let changed = smaller != self.page_size;
        self.page_size = smaller;
        changed
    }

    /// Fetches the page after `cursor`, or the first page when it is `None`.
    ///
    /// Every failure is transient: the page is fetched again on the next scan.
    ///
    /// # Errors
    ///
    /// - The request fails or times out (`circle_unavailable`).
    /// - Circle answers `429` (`rate_limited`) or another non-success status
    ///   (`unexpected_status`).
    /// - The response exceeds the size ceiling or does not decode as a page (see [`Page::decode`])
    ///   (`invalid_response`).
    #[instrument(
        name = "relayer.fetch_page",
        skip_all,
        fields(remote_domain = %remote_domain, status = Empty, attestations.count = Empty, next = Empty),
    )]
    pub async fn fetch_page(
        &self,
        remote_domain: CircleDomain,
        cursor: Option<&CircleCursor>,
    ) -> Result<Page, Failure> {
        let span = Span::current();
        let mut response = self
            .client
            .get(self.page_url(remote_domain, cursor))
            .send()
            .await
            .context("the circle request failed")
            .classify(Transient("circle_unavailable"))?;
        let status = response.status();
        span.record("status", status.as_u16());
        if !status.is_success() {
            let class = if status == StatusCode::TOO_MANY_REQUESTS {
                Transient("rate_limited")
            } else {
                Transient("unexpected_status")
            };
            return Err(Failure::new(
                class,
                anyhow!("circle answered {status} for the attestation page"),
            ));
        }

        let link = response
            .headers()
            .get(reqwest::header::LINK)
            .map(|value| value.to_str())
            .transpose()
            .context("decoding the circle Link header")
            .classify(Transient("invalid_response"))?
            .map(str::to_owned);

        // Read chunk by chunk rather than `bytes()`: a runaway body must not be buffered in full
        // before it is rejected.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading the circle response")
            .classify(Transient("circle_unavailable"))?
        {
            body.extend_from_slice(&chunk);
            if body.len() > Page::MAX_RESPONSE_BYTES {
                return Err(Failure::new(
                    Transient("invalid_response"),
                    anyhow!(
                        "the circle response exceeded the {}-byte ceiling",
                        Page::MAX_RESPONSE_BYTES
                    ),
                ));
            }
        }

        let page = Page::decode(&body, link.as_deref()).classify(Transient("invalid_response"))?;
        if page.entries.len() > usize::from(self.page_size.0) {
            return Err(Failure::new(
                Transient("invalid_response"),
                anyhow!(
                    "circle returned more than the requested {} deposits",
                    self.page_size
                ),
            ));
        }
        span.record("attestations.count", page.entries.len());
        if let Some(next) = &page.next {
            span.record("next", next.as_str());
        }
        Ok(page)
    }

    /// The URL of one attestation page.
    fn page_url(&self, remote_domain: CircleDomain, cursor: Option<&CircleCursor>) -> Url {
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

/// Extracts the `pageAfter` token of the `rel="next"` relation from a `Link` header, or `None`
/// when the header has no such relation.
///
/// # Errors
///
/// - The header is not a valid RFC 8288 `Link` header with relation parameters.
/// - The `next` relation carries no `pageAfter` token, or an empty one.
fn parse_next_link(header: &str) -> Result<Option<String>> {
    let links =
        parse_link_header::parse_with_rel(header).context("parsing the circle Link header")?;
    let Some(next) = links.get("next") else {
        return Ok(None);
    };

    // A `next` relation says the feed continues. Without a token there is no page to ask for, and
    // reading that as the final page would end the scan and move the watermark past the entries
    // it never reached.
    let token = next
        .uri
        .query_pairs()
        .find(|(key, _)| key == "pageAfter")
        .map(|(_, value)| value.into_owned())
        .filter(|token| !token.is_empty());
    token
        .map(Some)
        .context("the circle Link header's next relation carries no pageAfter token")
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

/// Names the field in a decoding error, so a skipped entry says which of its fields was at fault.
fn named<T, E: de::Error>(field: &str, decoded: Result<T, E>) -> Result<T, E> {
    decoded.map_err(|error| E::custom(format!("`{field}`: {error}")))
}

/// Deserializes an attestation's `payload`.
fn payload_field<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    named("payload", hex_bytes(deserializer))
}

/// Deserializes an attestation's `messageHash`.
fn message_hash_field<'de, D: Deserializer<'de>>(deserializer: D) -> Result<MessageHash, D::Error> {
    named("messageHash", MessageHash::deserialize(deserializer))
}

/// Deserializes an attestation's `attestation` into the signature type the mint note is built
/// from.
fn signature_field<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
    named("attestation", hex_array(deserializer).map(Signature::new))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::{
        Attestation, CircleClient, CircleCursor, CircleDomain, Entry, MessageHash, Page, PageSize,
        Signature,
    };

    /// The domain the request tests address.
    const REMOTE_DOMAIN: CircleDomain = CircleDomain::new(7);

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

        assert_eq!(page.entries, vec![attestation(1).into()]);
    }

    /// An entry that does not decode keeps its place and does not take the page with it. It says
    /// where on the page it sits and which field was at fault, and keeps its message hash when
    /// that much could be read. When it could not, it reports the text Circle sent in its place.
    #[test]
    fn an_entry_that_does_not_decode_keeps_its_place() {
        let readable = |seed: u8| {
            serde_json::json!({
                "payload": format!("0x{}", hex::encode([seed; 8])),
                "messageHash": MessageHash::new([seed; 32]).to_string(),
                "attestation": format!("0x{}", hex::encode([seed; 65])),
            })
        };
        let named = MessageHash::new([2; 32]);
        let mut short_signature = readable(2);
        short_signature["attestation"] = "0x00".into();
        let mut short_hash = readable(9);
        short_hash["messageHash"] = "0x1234".into();
        let body = serde_json::json!({ "attestations": [
            readable(1),
            short_signature,
            short_hash,
            "not an entry",
            readable(3),
        ]})
        .to_string();

        let page = Page::decode(body.as_bytes(), None).unwrap();

        let undecodable = |position, message_hash, reason: &str| Entry::Undecodable {
            position,
            message_hash,
            reason: reason.into(),
        };
        assert_eq!(
            page.entries,
            [
                attestation(1).into(),
                undecodable(
                    2,
                    Some(named),
                    "`attestation`: invalid length 1, expected 65 bytes of hex"
                ),
                undecodable(
                    3,
                    None,
                    "`messageHash`: invalid length 2, expected 32 bytes of hex \
                     (its messageHash is \"0x1234\")"
                ),
                undecodable(
                    4,
                    None,
                    "invalid type: string \"not an entry\", expected struct Attestation"
                ),
                attestation(3).into(),
            ]
        );
    }

    /// A `messageHash` that is not a hash comes from outside, so only its start is reported.
    #[test]
    fn a_long_unreadable_message_hash_is_cut_when_reported() {
        let body = serde_json::json!({ "attestations": [{
            "payload": "0x00",
            "messageHash": "z".repeat(500),
            "attestation": format!("0x{}", "00".repeat(65)),
        }]})
        .to_string();

        let page = Page::decode(body.as_bytes(), None).unwrap();

        let Entry::Undecodable { reason, .. } = &page.entries[0] else {
            panic!("the entry must not decode");
        };
        assert!(
            reason.ends_with(&format!("(its messageHash is \"{})", "z".repeat(79))),
            "{reason}"
        );
    }

    /// The `next` cursor is read from the `Link` header.
    #[test]
    fn the_next_cursor_comes_from_the_link_header() {
        let body = page_body(&[attestation(1)]);
        let link = next_link("page-2");
        let page = Page::decode(&body, Some(&link)).unwrap();

        assert_eq!(page.next, Some(CircleCursor::new("page-2")));
        assert_eq!(page.entries.len(), 1);
    }

    /// An absent `Link` header is the documented final page, not an error.
    #[test]
    fn an_absent_link_header_is_the_final_page() {
        let body = page_body(&[attestation(1)]);
        let page = Page::decode(&body, None).unwrap();

        assert_eq!(page.next, None);
    }

    /// A `Link` header without a `next` relation is the final page too.
    #[test]
    fn a_link_header_without_a_next_relation_is_the_final_page() {
        let body = page_body(&[attestation(1)]);
        let link = "<https://circle.test/v1/remote-domains/1/attestations>; rel=\"first\"";
        let page = Page::decode(&body, Some(link)).unwrap();

        assert_eq!(page.next, None);
    }

    /// A `next` relation that cannot be followed is an error rather than the end of the feed, which
    /// would move the watermark past the pages below it.
    #[rstest]
    #[case::no_token(
        "<https://circle.test/v1/remote-domains/1/attestations?pageSize=100>; rel=\"next\""
    )]
    #[case::empty_token(
        "<https://circle.test/v1/remote-domains/1/attestations?pageSize=100&pageAfter=>; rel=\"next\""
    )]
    fn a_next_relation_without_a_token_is_an_error(#[case] link: &str) {
        let body = page_body(&[attestation(1)]);
        let error = format!("{:#}", Page::decode(&body, Some(link)).unwrap_err());

        assert!(
            error.contains("no pageAfter token"),
            "unexpected error: {error}"
        );
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
