//! The Circle half: one paginated GET, decoded and bound per element.
//!
//! Only `GET /v1/remote-domains/{d}/attestations` is implemented, and only the two query parameters
//! the forward scan uses (`pageSize`, `pageAfter`). The rest of Circle's documented surface is not
//! modelled, because nothing here calls it.
//!
//! Pagination travels in the RFC-8288 `Link` **header**, not the body, and the distinction between
//! its two absent-ish cases is load-bearing: an **absent** header is the documented final page,
//! while a **present but unparseable** one is an error. Reading the second as the first would make
//! a corrupted header look exactly like the end of the feed, and the scan would stop early and
//! silently.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, ensure, Context, Result};
use reqwest::Url;
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use tracing::field::Empty;
use tracing::{instrument, Span};

use crate::config::Config;

/// A raw secp256k1 attestation is `r` (32) ‖ `s` (32) ‖ `v` (1).
const ATTESTATION_LEN: usize = 65;

// THE TRANSPORT SEAM
// ================================================================================================

/// One outbound GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// The `Link` header verbatim, if there was one.
    pub link: Option<String>,
}

/// The HTTP seam.
///
/// Production is [`ReqwestTransport`]. Tests install a recording fake instead, which is why this
/// exists at all: the audit/CI sandbox denies `bind(127.0.0.1:0)`, so a mock Circle cannot be a
/// socket server and the seam has to sit above the socket. Putting it here rather than at the
/// socket also means a test asserts on the exact [`HttpRequest`] the client built.
pub trait Transport: fmt::Debug + Send + Sync {
    fn get<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'a>>;
}

/// The production transport.
#[derive(Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
    max_response_bytes: usize,
}

impl ReqwestTransport {
    /// Builds the client with the configured timeout and response ceiling.
    #[instrument(name = "transport.build", skip_all)]
    pub fn from_config(config: &Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .build()
            .context("building the circle http client")?;

        Ok(Self {
            client,
            max_response_bytes: config.max_response_bytes,
        })
    }
}

impl Transport for ReqwestTransport {
    fn get<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'a>> {
        Box::pin(async move {
            let mut outbound = self.client.get(&request.url);
            for (name, value) in &request.headers {
                outbound = outbound.header(name, value);
            }

            let response = outbound.send().await.context("the circle request failed")?;
            let status = response.status().as_u16();
            let link = response
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);

            // Accumulate with a ceiling rather than calling `bytes()`: a runaway body must not be
            // buffered in full before it is rejected.
            let mut response = response;
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .context("reading the circle response")?
            {
                ensure!(
                    body.len() + chunk.len() <= self.max_response_bytes,
                    "the circle response exceeded the {}-byte ceiling",
                    self.max_response_bytes
                );
                body.extend_from_slice(&chunk);
            }

            Ok(HttpResponse { status, body, link })
        })
    }
}

// THE WIRE SCHEMA
// ================================================================================================

/// The three wire fields Circle publishes, `0x`-hex, camelCase on the wire.
///
/// Decoded is not validated: this is only what Circle *said*. [`Attestation::decode`] is what binds
/// the envelope to the payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    /// The encoded DepositIntent.
    pub payload: String,
    /// `keccak256(payload)` — raw keccak, not EIP-712.
    pub message_hash: String,
    /// The 65-byte `r‖s‖v` signature.
    pub attestation: String,
}

/// The list response body. Pagination is NOT in here — it is in the `Link` header.
#[derive(Debug, Deserialize)]
struct ListResponse {
    attestations: Vec<Attestation>,
}

/// An attestation whose envelope binds: the hex decoded, `messageHash == keccak256(payload)`, and
/// the signature is exactly 65 bytes.
///
/// This is a liveness filter, not an authorization: the ECDSA verify and the attester-allowlist
/// check are on-chain and faucet-owned. Passing here means "worth spending a transaction on", never
/// "authorized to mint".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAttestation {
    pub payload: Vec<u8>,
    pub message_hash: [u8; 32],
    pub signature: [u8; ATTESTATION_LEN],
}

impl Attestation {
    /// Decodes the three fields and binds the envelope.
    ///
    /// # Errors
    /// Any field is not hex, the digest is not 32 bytes, the signature is not 65 bytes, or
    /// `messageHash != keccak256(payload)`. Every one of these is PERMANENT — the same bytes fail
    /// the same way next time — so the caller skips the attestation rather than retrying it.
    #[instrument(level = "trace", name = "attestation.decode", skip_all)]
    pub fn decode(&self) -> Result<DecodedAttestation> {
        let payload = decode_hex(&self.payload).context("the payload is not hex")?;
        let presented = decode_hex(&self.message_hash).context("the messageHash is not hex")?;
        let signature = decode_hex(&self.attestation).context("the attestation is not hex")?;

        let presented: [u8; 32] = presented
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("the messageHash is {} bytes, not 32", presented.len()))?;

        let signature: [u8; ATTESTATION_LEN] = signature.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "the attestation is {} bytes, not {ATTESTATION_LEN}",
                signature.len()
            )
        })?;

        // THE binding: raw keccak256 over the FULL payload — the digest the faucet recomputes
        // on-chain and verifies the signature against.
        let expected: [u8; 32] = Keccak256::digest(&payload).into();
        ensure!(
            presented == expected,
            "the messageHash does not bind the payload: expected keccak256 {}, got {}",
            hex::encode(expected),
            hex::encode(presented)
        );

        Ok(DecodedAttestation {
            payload,
            message_hash: presented,
            signature,
        })
    }
}

/// One page of the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub attestations: Vec<Attestation>,
    /// The `pageAfter` token for the next page, or `None` at the end of the feed.
    pub next: Option<String>,
}

// THE CLIENT
// ================================================================================================

/// The Circle-facing client.
#[derive(Debug)]
pub struct CircleClient {
    base_url: String,
    transport: Arc<dyn Transport>,
    auth: Option<(String, String)>,
    max_response_bytes: usize,
}

impl CircleClient {
    /// Assembles the client over `transport`.
    pub fn new(config: &Config, transport: Arc<dyn Transport>) -> Self {
        let auth = config
            .api_auth_token
            .as_ref()
            .map(|token| (config.api_auth_header.clone(), token.clone()));

        Self {
            base_url: config.circle_base_url.trim_end_matches('/').to_string(),
            transport,
            auth,
            max_response_bytes: config.max_response_bytes,
        }
    }

    /// Fetches one page of attestations for `remote_domain`, resuming after `page_after`.
    ///
    /// # Errors
    /// The request failed, the status was not 200, the body was oversize or would not decode, or a
    /// `Link` header was present and unparseable.
    #[instrument(
        name = "circle.attestations",
        skip_all,
        fields(remote_domain, page_size, status = Empty, returned = Empty, next = Empty),
    )]
    pub async fn attestations(
        &self,
        remote_domain: u32,
        page_size: u16,
        page_after: Option<&str>,
    ) -> Result<Page> {
        let span = Span::current();
        let mut url = Url::parse(&format!(
            "{}/v1/remote-domains/{remote_domain}/attestations",
            self.base_url
        ))
        .context("the configured circle_base_url is not a url")?;

        // `query_pairs_mut` percent-encodes for us: the cursor is an opaque token and may carry
        // base64's `+`, `/` and `=`, every one of which changes meaning unescaped in a query.
        url.query_pairs_mut()
            .append_pair("pageSize", &page_size.to_string());
        if let Some(cursor) = page_after {
            url.query_pairs_mut().append_pair("pageAfter", cursor);
        }
        let url = url.into();

        let headers = self
            .auth
            .as_ref()
            .map(|(name, value)| vec![(name.clone(), value.clone())])
            .unwrap_or_default();

        let response = self.transport.get(HttpRequest { url, headers }).await?;
        span.record("status", response.status);

        ensure!(
            response.status == 200,
            "circle answered {} for the attestation page",
            response.status
        );
        ensure!(
            response.body.len() <= self.max_response_bytes,
            "the circle response exceeded the {}-byte ceiling",
            self.max_response_bytes
        );

        let list: ListResponse = serde_json::from_slice(&response.body)
            .context("decoding the circle attestation page")?;

        let next = match response.link.as_deref() {
            // an ABSENT Link header is the documented final page
            None => None,
            Some(header) => parse_next_link(header)?,
        };

        span.record("returned", list.attestations.len());
        if let Some(next) = next.as_deref() {
            span.record("next", next);
        }

        Ok(Page {
            attestations: list.attestations,
            next,
        })
    }
}

/// Extracts the `pageAfter` token of the `rel="next"` relation from a `Link` header.
///
/// # Errors
/// The header parses to no relations at all — it is malformed, and treating that as "no next page"
/// would silently end the scan.
#[instrument(level = "trace", skip_all)]
fn parse_next_link(header: &str) -> Result<Option<String>> {
    let mut relations = 0usize;
    let mut next = None;

    for entry in header.split(',') {
        let mut parts = entry.split(';');
        let Some(target) = parts.next() else { continue };
        let target = target.trim();

        let Some(url) = target
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
        else {
            continue;
        };

        let Some(rel) = parts.find_map(|part| {
            let part = part.trim();
            let value = part.strip_prefix("rel=")?;
            Some(value.trim_matches('"').to_string())
        }) else {
            continue;
        };

        relations += 1;
        if rel == "next" {
            next = query_param(url, "pageAfter");
        }
    }

    ensure!(
        relations > 0,
        "the circle Link header carried no usable relation: `{header}`"
    );

    Ok(next)
}

/// Reads one query parameter out of a URL, percent-decoding its value.
fn query_param(url: &str, name: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Decodes a Circle wire-hex field, tolerating the optional `0x` prefix the API emits.
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    match hex::decode(digits) {
        Ok(bytes) => Ok(bytes),
        Err(error) => bail!("{error}"),
    }
}
