//! Circle requests. Prepared authorizations and submission identities are checked separately.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use miden_standards::interop::eth::EthEmbeddedAccountId;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::Instant;
use xusdc_encoding::account::xreserve::USDCX_DECIMALS;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::burn::ValidatedBurn;
use crate::config::Config;
use crate::submission::SavedSubmission;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CircleError {
    #[error("Circle API is unavailable")]
    Unavailable,
    #[error("Circle request failed")]
    Transport(#[source] reqwest::Error),
    #[error("Circle returned HTTP {0}")]
    UnexpectedStatus(StatusCode),
    #[error("Circle prepare returned HTTP {status}")]
    UnexpectedPrepareStatus { status: StatusCode, body: Vec<u8> },
    #[error("Circle prepare response is malformed")]
    InvalidResponse(#[source] serde_json::Error),
    #[error("Circle response body exceeds {MAX_RESPONSE_BODY_BYTES} bytes")]
    BodyTooLarge,
}

#[derive(Debug)]
pub struct RawResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

impl RawResponse {
    pub fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self { status, body }
    }
}

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Circle's replies are a few kilobytes; refusing more than 1 MiB keeps an oversized body out of
/// memory.
const MAX_RESPONSE_BODY_BYTES: usize = 1 << 20;
/// Circle allows five requests per second from one IP address; a quarter of a second between two
/// requests stays below that.
pub(crate) const REQUEST_GAP: Duration = Duration::from_millis(250);

/// The calls the attester makes to Circle's xReserve API. [`CircleClient`] makes them over HTTPS;
/// this is a trait so that the attester can be tested without Circle.
pub trait CircleApi: Send + Sync {
    /// Checks at startup that Circle's API answers.
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>>;

    /// Asks Circle to prepare the withdrawal of this burn. The reply is only decoded; it must be
    /// verified before anything is signed.
    fn prepare_withdrawal<'a>(
        &'a self,
        burn: &'a ValidatedBurn,
        use_circle_forwarding: bool,
    ) -> Pin<Box<dyn Future<Output = Result<UnverifiedPrepareResponse, CircleError>> + Send + 'a>>;

    /// Sends the saved withdrawal request to its saved endpoint, exactly as saved.
    fn post_submission<'a>(
        &'a self,
        saved: &'a SavedSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>>;

    /// Looks up the withdrawal with Circle's ID on the saved endpoint's host.
    fn get_withdrawal<'a>(
        &'a self,
        saved: &'a SavedSubmission,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>>;

    /// Whether Circle has answered 429. The remaining requests then wait for a later cycle.
    fn rate_limited(&self) -> bool;
}

/// Circle's xReserve API over HTTPS. Requests go out at least [`REQUEST_GAP`] apart.
pub struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    client: reqwest::Client,
    next_request: Mutex<Instant>,
    rate_limited: AtomicBool,
}

impl CircleClient {
    pub fn new(config: &Config) -> Result<Self, CircleError> {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("xusdc-attester/", env!("CARGO_PKG_VERSION")))
            // Circle is only ever reached over HTTPS.
            .https_only(true)
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|client| Self {
                base_url: config.circle_api_base_url().clone(),
                request_timeout: config.circle_request_timeout(),
                client,
                next_request: Mutex::new(Instant::now()),
                rate_limited: AtomicBool::new(false),
            })
            .map_err(CircleError::Transport)
    }

    pub(crate) fn info_request(&self) -> Result<reqwest::Request, CircleError> {
        let url = self
            .base_url
            .join("/v1/info")
            .map_err(|_| CircleError::Unavailable)?;
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        *request.timeout_mut() = Some(self.request_timeout);
        Ok(request)
    }

    /// Sends one request once the gap since the previous one has passed.
    pub(crate) async fn send(&self, request: reqwest::Request) -> Result<RawResponse, CircleError> {
        // Take the next free slot before waiting, so requests started together still go out
        // one gap apart.
        let start = {
            let mut next_request = self
                .next_request
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let start = (*next_request).max(Instant::now());
            *next_request = start + REQUEST_GAP;
            start
        };
        tokio::time::sleep_until(start).await;
        let response = self
            .client
            .execute(request)
            .await
            .map_err(CircleError::Transport)?;
        self.read_reply(response).await
    }

    /// Reads Circle's reply, refusing a body larger than [`MAX_RESPONSE_BODY_BYTES`]. A 429 is
    /// remembered, so the rest of the cycle leaves Circle alone.
    pub(crate) async fn read_reply(
        &self,
        mut response: reqwest::Response,
    ) -> Result<RawResponse, CircleError> {
        let status = response.status();
        // Read chunk by chunk and stop once the total passes the cap, so an oversized or
        // endless reply is refused before it is buffered; the declared length is not trusted.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(CircleError::Transport)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
                return Err(CircleError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            self.rate_limited.store(true, Ordering::Relaxed);
        }
        Ok(RawResponse::new(status, body))
    }

    pub(crate) fn prepare_request(
        &self,
        burn: &ValidatedBurn,
        use_circle_forwarding: bool,
    ) -> Result<reqwest::Request, CircleError> {
        let batch = PrepareBatch::from_burn(burn, use_circle_forwarding);
        let url = self
            .base_url
            .join("/v1/prepare-withdrawal")
            .map_err(|_| CircleError::Unavailable)?;
        let mut request = reqwest::Request::new(reqwest::Method::POST, url);
        *request.timeout_mut() = Some(self.request_timeout);
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        *request.body_mut() = Some(json!({ "batches": [batch] }).to_string().into());
        Ok(request)
    }
}

impl CircleApi for CircleClient {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>> {
        Box::pin(async move { read_info(&self.send(self.info_request()?).await?) })
    }

    fn prepare_withdrawal<'a>(
        &'a self,
        burn: &'a ValidatedBurn,
        use_circle_forwarding: bool,
    ) -> Pin<Box<dyn Future<Output = Result<UnverifiedPrepareResponse, CircleError>> + Send + 'a>>
    {
        Box::pin(async move {
            let request = self.prepare_request(burn, use_circle_forwarding)?;
            read_prepared(self.send(request).await?)
        })
    }

    fn post_submission<'a>(
        &'a self,
        saved: &'a SavedSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move {
            let url = Url::parse(&saved.endpoint).map_err(|_| CircleError::Unavailable)?;
            let mut request = reqwest::Request::new(reqwest::Method::POST, url);
            *request.timeout_mut() = Some(self.request_timeout);
            request.headers_mut().insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("application/json"),
            );
            // A retry must send the saved authorization, not rebuild it from today's config.
            *request.body_mut() = Some(saved.body.clone().into());
            self.send(request).await
        })
    }

    fn get_withdrawal<'a>(
        &'a self,
        saved: &'a SavedSubmission,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move {
            let mut url = Url::parse(&saved.endpoint)
                .and_then(|url| url.join("/v1/withdrawal/"))
                .map_err(|_| CircleError::Unavailable)?;
            url.path_segments_mut()
                .map_err(|_| CircleError::Unavailable)?
                .pop_if_empty()
                .push(id);
            let mut request = reqwest::Request::new(reqwest::Method::GET, url);
            *request.timeout_mut() = Some(self.request_timeout);
            self.send(request).await
        })
    }

    fn rate_limited(&self) -> bool {
        self.rate_limited.load(Ordering::Relaxed)
    }
}

/// Circle's API counts as reachable only when its info endpoint answers 200.
pub(crate) fn read_info(response: &RawResponse) -> Result<(), CircleError> {
    if response.status == StatusCode::OK {
        Ok(())
    } else {
        Err(CircleError::UnexpectedStatus(response.status))
    }
}

/// A 200 must decode as a prepared withdrawal. Any other status keeps Circle's status and body,
/// so the caller can tell a refusal from a failure.
pub(crate) fn read_prepared(
    response: RawResponse,
) -> Result<UnverifiedPrepareResponse, CircleError> {
    if response.status != StatusCode::OK {
        return Err(CircleError::UnexpectedPrepareStatus {
            status: response.status,
            body: response.body,
        });
    }
    serde_json::from_slice(&response.body).map_err(CircleError::InvalidResponse)
}

/// Where a signed withdrawal request is sent. It is saved with the request, so a retry goes to the
/// same place even if the configured URL changes.
pub(crate) fn submission_endpoint(base_url: &Url) -> Result<String, CircleError> {
    base_url
        .join("/v1/withdraw")
        .map(|url| url.to_string())
        .map_err(|_| CircleError::Unavailable)
}

/// One burn's entry in the prepare-withdrawal request, with Circle's field names.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PrepareBatch {
    token: &'static str,
    remote_domain: u32,
    remote_depositor: String,
    final_destination_domain: u32,
    final_destination_recipient: String,
    value_including_fees: String,
    salt: String,
    use_circle_forwarding: bool,
}

impl PrepareBatch {
    pub(crate) fn from_burn(burn: &ValidatedBurn, use_circle_forwarding: bool) -> Self {
        let units_per_usdc = 10_u64.pow(u32::from(USDCX_DECIMALS));
        let note = burn.burn.note().as_note();
        let amount = burn.amount;
        let sender = EthEmbeddedAccountId::from_account_id(note.metadata().sender());
        // Circle takes whole-USDC decimal strings, not smallest-unit integers.
        let value_including_fees = format!(
            "{}.{:0width$}",
            amount / units_per_usdc,
            amount % units_per_usdc,
            width = usize::from(USDCX_DECIMALS),
        );
        // Circle's salt is the note serial. The attachment only holds the destination.
        let salt = note.serial_num().to_hex();
        Self {
            token: "USDC",
            remote_domain: MIDEN_DOMAIN,
            remote_depositor: format!("0x{}", hex::encode(sender.to_bytes32())),
            final_destination_domain: burn.items.dest_domain,
            final_destination_recipient: format!(
                "0x{}",
                hex::encode(burn.items.dest_recipient.as_bytes())
            ),
            value_including_fees,
            salt,
            use_circle_forwarding,
        }
    }
}

/// Decoded wire data, not a verified or signable withdrawal.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct UnverifiedPrepareResponse {
    pub(crate) batches: Vec<UnverifiedPrepareBatch>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnverifiedPrepareBatch {
    pub(crate) burn_intents: Vec<BurnIntent>,
    pub(crate) encoded: String,
    pub(crate) message_hash_to_sign: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BurnIntent {
    pub(crate) max_block_height: String,
    pub(crate) max_fee: String,
    pub(crate) spec: TransferSpec,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferSpec {
    pub(crate) version: u32,
    pub(crate) source_domain: u32,
    pub(crate) destination_domain: u32,
    pub(crate) source_contract: String,
    pub(crate) destination_contract: String,
    pub(crate) source_token: String,
    pub(crate) destination_token: String,
    pub(crate) source_depositor: String,
    pub(crate) destination_recipient: String,
    pub(crate) source_signer: String,
    pub(crate) destination_caller: String,
    pub(crate) value: String,
    pub(crate) salt: String,
    pub(crate) hook_data: StructuredHookData,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StructuredHookData {
    pub(crate) remote_domain: u32,
    pub(crate) remote_depositor: String,
    pub(crate) remote_token: String,
    pub(crate) forwarding_contract_address: String,
    pub(crate) forwarding_calldata: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WithdrawalResponse {
    pub(crate) withdrawal_id: String,
    // Circle's field name stays burnTxId; for Miden its value is the burn note ID.
    #[serde(rename = "burnTxId")]
    pub(crate) burn_note_id: String,
    pub(crate) status: String,
    pub(crate) use_circle_forwarding: bool,
    pub(crate) transfer_spec_hashes: Vec<String>,
    pub(crate) failure_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConflictResponse {
    pub(crate) conflict: Option<WithdrawalConflict>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WithdrawalConflict {
    pub(crate) withdrawal_id: Option<String>,
    #[serde(rename = "burnTxId")]
    pub(crate) burn_note_id: Option<String>,
}
