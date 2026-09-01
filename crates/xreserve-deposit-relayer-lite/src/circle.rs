//! One paginated GET against Circle's attestation feed:
//! `GET /v1/remote-domains/{d}/attestations?pageSize=&pageAfter=`.
//!
//! Pagination travels in the RFC 8288 `Link` header, not the body. An absent header is the
//! documented final page, while a present but unparseable header is an error. Treating the second
//! as the first would make a corrupted header look like the end of the feed and silently end the
//! scan early.
//!
//! No authentication is sent because Circle has not documented an authentication scheme yet.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::Url;
use serde::Deserialize;

/// Response-size ceiling, so a runaway body cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The three wire fields Circle publishes per attestation, `0x`-hex, camelCase on the wire.
/// These values are not validated here; they represent what Circle returned, while the chain
/// decides whether they authorize a mint.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The encoded DepositIntent.
    pub payload: String,
    /// `keccak256(payload)` — carried for log lines; the chain recomputes and verifies it.
    pub message_hash: String,
    /// The 65-byte `r‖s‖v` signature.
    pub attestation: String,
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
    /// The `pageAfter` token for the next page, or `None` at the end of the feed.
    pub next: Option<String>,
}

/// The Circle feed operation used by the relay loop.
///
/// Production uses [`CircleClient`]. Relay-loop tests implement this domain-level seam without
/// mocking HTTP details.
pub trait CircleFeed: Send + Sync {
    fn fetch_page<'a>(
        &'a self,
        remote_domain: u32,
        page_after: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Page>> + Send + 'a>>;
}

/// The Circle-facing HTTP client.
#[derive(Debug)]
pub struct CircleClient {
    base_url: Url,
    page_size: u16,
    client: reqwest::Client,
}

impl CircleClient {
    /// Creates a Circle client with the configured page size and request timeout.
    ///
    /// # Errors
    ///
    /// - The page size is outside Circle's supported range of 1 through 1000.
    /// - The request timeout is zero.
    /// - The reqwest client cannot be constructed.
    pub fn new(base_url: Url, page_size: u16, request_timeout: Duration) -> Result<Self> {
        ensure!(
            (1..=1000).contains(&page_size),
            "page_size must be between 1 and 1000"
        );
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

    async fn fetch_page_inner(&self, remote_domain: u32, page_after: Option<&str>) -> Result<Page> {
        let url = build_page_url(&self.base_url, remote_domain, self.page_size, page_after)?;
        let mut response = self
            .client
            .get(url)
            .send()
            .await
            .context("the circle request failed")?;
        let status = response.status().as_u16();
        let link = response
            .headers()
            .get(reqwest::header::LINK)
            .map(|value| value.to_str())
            .transpose()
            .context("decoding the circle Link header")?
            .map(str::to_owned);

        // Accumulate with a ceiling rather than `bytes()`: a runaway body must not be buffered in
        // full before it is rejected.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("reading the circle response")?
        {
            ensure!(
                body.len() + chunk.len() <= MAX_RESPONSE_BYTES,
                "the circle response exceeded the {MAX_RESPONSE_BYTES}-byte ceiling"
            );
            body.extend_from_slice(&chunk);
        }

        decode_page(status, &body, link.as_deref())
    }
}

impl CircleFeed for CircleClient {
    fn fetch_page<'a>(
        &'a self,
        remote_domain: u32,
        page_after: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Page>> + Send + 'a>> {
        Box::pin(self.fetch_page_inner(remote_domain, page_after))
    }
}

/// Builds the URL for one Circle attestation page.
///
/// # Errors
///
/// - The page size is outside Circle's supported range of 1 through 1000.
pub fn build_page_url(
    base_url: &Url,
    remote_domain: u32,
    page_size: u16,
    page_after: Option<&str>,
) -> Result<Url> {
    ensure!(
        (1..=1000).contains(&page_size),
        "page_size must be between 1 and 1000"
    );

    let mut url = base_url.clone();
    let path = format!(
        "{}/v1/remote-domains/{remote_domain}/attestations",
        base_url.path().trim_end_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);

    url.query_pairs_mut()
        .append_pair("pageSize", &page_size.to_string());
    // `append_pair` percent-encodes the opaque cursor, which may carry base64's `+`, `/`, and `=`.
    if let Some(cursor) = page_after {
        url.query_pairs_mut().append_pair("pageAfter", cursor);
    }

    Ok(url)
}

/// Decodes one Circle response into a feed page.
///
/// # Errors
///
/// - Circle returns a status other than 200.
/// - The response body does not match Circle's attestation schema.
/// - A present `Link` header is malformed.
pub fn decode_page(status: u16, body: &[u8], link: Option<&str>) -> Result<Page> {
    ensure!(
        status == 200,
        "circle answered {status} for the attestation page"
    );

    let list: ListResponse =
        serde_json::from_slice(body).context("decoding the circle attestation page")?;
    let next = match link {
        // An absent `Link` header is the documented final page.
        None => None,
        Some(header) => parse_next_link(header)?,
    };

    Ok(Page {
        attestations: list.attestations,
        next,
    })
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
