//! Client for Circle's xReserve API: the startup reachability check, the prepare-withdrawal and
//! withdraw requests, and the withdrawal status lookup. A prepared withdrawal is verified before it
//! is signed, and a reply to a submission counts only if it names the saved withdrawal.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use miden_standards::interop::eth::EthEmbeddedAccountId;
use miden_usdcx::account::xreserve::USDCX_DECIMALS;
use miden_usdcx::xreserve::encoding::CircleDomain;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tokio::time::Instant;
use usdcx_telemetry::FailureClass::{Actionable, Transient};
use usdcx_telemetry::{Classified, FailureClass};

use crate::burn::DiscoveredBurn;
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
    #[error("Circle request URL is invalid")]
    InvalidUrl(#[source] url::ParseError),
    /// Circle asks the attester to slow down, so the rest of the cycle leaves Circle alone.
    #[error("Circle returned HTTP 429 Too Many Requests")]
    RateLimited {
        /// Circle's reply, unless it could not be read in full.
        body: Option<Vec<u8>>,
        #[source]
        read_error: Option<Box<CircleError>>,
    },
}

/// A request that cannot be built needs an operator; every other failure is retried next cycle.
impl Classified for CircleError {
    fn failure(&self) -> FailureClass {
        match self {
            Self::InvalidUrl(_) => Actionable("invalid_url"),
            Self::RateLimited { .. } => Transient("rate_limited"),
            Self::Unavailable | Self::Transport(_) => Transient("circle_unavailable"),
            Self::UnexpectedStatus(_) | Self::UnexpectedPrepareStatus { .. } => {
                Transient("unexpected_status")
            }
            Self::InvalidResponse(_) | Self::BodyTooLarge => Transient("invalid_response"),
        }
    }
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

/// Whether Circle's reply is its withdrawal-limit rejection: a 400 whose `message` starts with
/// `prefix`.
pub(crate) fn is_withdrawal_limit(status: StatusCode, body: &[u8], prefix: &str) -> bool {
    status == StatusCode::BAD_REQUEST
        && serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|reply| {
                reply["message"]
                    .as_str()
                    .map(|message| message.starts_with(prefix))
            })
            .unwrap_or(false)
}

/// Circle's `message` from an error reply, cut to [`MAX_LOGGED_MESSAGE_CHARS`] characters.
pub(crate) fn circle_message(body: &[u8]) -> Option<String> {
    let reply: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(
        reply["message"]
            .as_str()?
            .chars()
            .take(MAX_LOGGED_MESSAGE_CHARS)
            .collect(),
    )
}

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Circle's replies are a few kilobytes; refusing more than 1 MiB keeps an oversized body out of
/// memory.
const MAX_RESPONSE_BODY_BYTES: usize = 1 << 20;
/// Circle's message is outside text written into our logs; 200 characters keep the reason
/// readable without letting a long reply flood them.
const MAX_LOGGED_MESSAGE_CHARS: usize = 200;
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
    /// `forwarding_max_fee` is the configured cap for the selected secondary leg: CCTP or an
    /// explicitly supported xReserve redeposit. It does not authorize an arbitrary returned route.
    fn prepare_withdrawal<'a>(
        &'a self,
        burn: &'a DiscoveredBurn,
        forwarding_max_fee: u64,
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
}

/// Circle's xReserve API over HTTPS. Requests are sent one at a time, at least [`REQUEST_GAP`]
/// apart.
pub struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    client: reqwest::Client,
    /// The earliest time the next request may go out. Holding the lock is a caller's turn to send.
    next_dispatch: Mutex<Instant>,
}

impl CircleClient {
    pub fn new(config: &Config) -> Result<Self, CircleError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("xusdc-attester/", env!("CARGO_PKG_VERSION")))
            // Circle is only ever reached over HTTPS.
            .https_only(true)
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(CircleError::Transport)?;
        Ok(Self {
            base_url: config.circle_api_base_url().clone(),
            request_timeout: config.circle_request_timeout(),
            client,
            next_dispatch: Mutex::new(Instant::now()),
        })
    }

    pub(crate) fn info_request(&self) -> Result<reqwest::Request, CircleError> {
        let url = self
            .base_url
            .join("/v1/info")
            .map_err(CircleError::InvalidUrl)?;
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        *request.timeout_mut() = Some(self.request_timeout);
        Ok(request)
    }

    /// Sends one request once it is this caller's turn and at least [`REQUEST_GAP`] has passed
    /// since the previous attempt ended, failed or not. A caller that stops waiting before its
    /// request goes out takes no turn.
    pub(crate) async fn send(&self, request: reqwest::Request) -> Result<RawResponse, CircleError> {
        let mut next_dispatch = self.next_dispatch.lock().await;
        tokio::time::sleep_until(*next_dispatch).await;
        // Counted from the start too, so a caller that stops waiting for the answer still keeps
        // the next request a gap away.
        *next_dispatch = Instant::now() + REQUEST_GAP;
        let result = match self.client.execute(request).await {
            Ok(response) => read_reply(response).await,
            Err(error) => Err(CircleError::Transport(error)),
        };
        *next_dispatch = Instant::now() + REQUEST_GAP;
        result
    }

    pub(crate) fn prepare_request(
        &self,
        burn: &DiscoveredBurn,
        forwarding_max_fee: u64,
    ) -> Result<reqwest::Request, CircleError> {
        let batch = PrepareBatch::from_burn(burn, forwarding_max_fee);
        let url = self
            .base_url
            .join("/v1/prepare-withdrawal")
            .map_err(CircleError::InvalidUrl)?;
        let mut request = reqwest::Request::new(reqwest::Method::POST, url);
        *request.timeout_mut() = Some(self.request_timeout);
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        *request.body_mut() = Some(json!({ "batches": [batch] }).to_string().into());
        Ok(request)
    }

    pub(crate) fn submission_request(
        &self,
        saved: &SavedSubmission,
    ) -> Result<reqwest::Request, CircleError> {
        let mut request = reqwest::Request::new(reqwest::Method::POST, saved.endpoint.clone());
        *request.timeout_mut() = Some(self.request_timeout);
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        // A retry must send the saved authorization, not rebuild it from today's config.
        *request.body_mut() = Some(saved.body.clone().into());
        Ok(request)
    }

    pub(crate) fn status_request(
        &self,
        saved: &SavedSubmission,
        id: &str,
    ) -> Result<reqwest::Request, CircleError> {
        let mut url = saved
            .endpoint
            .join("/v1/withdrawal/")
            .map_err(CircleError::InvalidUrl)?;
        url.path_segments_mut()
            .map_err(|_| CircleError::Unavailable)?
            .pop_if_empty()
            .push(id);
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        *request.timeout_mut() = Some(self.request_timeout);
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
        burn: &'a DiscoveredBurn,
        forwarding_max_fee: u64,
    ) -> Pin<Box<dyn Future<Output = Result<UnverifiedPrepareResponse, CircleError>> + Send + 'a>>
    {
        Box::pin(async move {
            let request = self.prepare_request(burn, forwarding_max_fee)?;
            read_prepared(self.send(request).await?)
        })
    }

    fn post_submission<'a>(
        &'a self,
        saved: &'a SavedSubmission,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move { self.send(self.submission_request(saved)?).await })
    }

    fn get_withdrawal<'a>(
        &'a self,
        saved: &'a SavedSubmission,
        id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + 'a>> {
        Box::pin(async move { self.send(self.status_request(saved, id)?).await })
    }
}

/// Reads Circle's reply, refusing a body larger than [`MAX_RESPONSE_BODY_BYTES`]. A 429 comes back
/// as [`CircleError::RateLimited`], with Circle's reply if it could be read in full.
pub(crate) async fn read_reply(
    mut response: reqwest::Response,
) -> Result<RawResponse, CircleError> {
    let status = response.status();
    // Read chunk by chunk and stop once the total passes the cap, so an oversized or endless
    // reply is refused before it is buffered; the declared length is not trusted.
    let mut body = Vec::new();
    let read = async {
        while let Some(chunk) = response.chunk().await.map_err(CircleError::Transport)? {
            if body.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
                return Err(CircleError::BodyTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(())
    }
    .await;
    match read {
        Ok(()) if status == StatusCode::TOO_MANY_REQUESTS => Err(CircleError::RateLimited {
            body: Some(body),
            read_error: None,
        }),
        Err(error) if status == StatusCode::TOO_MANY_REQUESTS => Err(CircleError::RateLimited {
            body: None,
            read_error: Some(Box::new(error)),
        }),
        Ok(()) => Ok(RawResponse::new(status, body)),
        Err(error) => Err(error),
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
pub(crate) fn submission_endpoint(base_url: &Url) -> Result<Url, CircleError> {
    base_url
        .join("/v1/withdraw")
        .map_err(CircleError::InvalidUrl)
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
    value_including_fees: UsdcDecimals,
    salt: String,
    use_circle_forwarding: bool,
    forwarding_options: ForwardingOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ForwardingOptions {
    max_fee: UsdcDecimals,
    uses_fast_finality: bool,
}

impl PrepareBatch {
    pub(crate) fn from_burn(burn: &DiscoveredBurn, forwarding_max_fee: u64) -> Self {
        let note = burn.note().as_note();
        let sender = EthEmbeddedAccountId::from_account_id(note.metadata().sender());
        // The burn's note ID: unique to this burn and fixed by the note itself, unlike the serial
        // number, which the burner chooses.
        let salt = burn.note_id().to_hex();
        Self {
            token: "USDC",
            remote_domain: CircleDomain::MIDEN.as_u32(),
            remote_depositor: format!("0x{}", hex::encode(sender.to_bytes32())),
            final_destination_domain: burn.items().dest_domain.as_u32(),
            final_destination_recipient: format!(
                "0x{}",
                hex::encode(burn.items().dest_recipient.as_bytes())
            ),
            value_including_fees: burn.amount().into(),
            salt,
            use_circle_forwarding: true,
            forwarding_options: ForwardingOptions {
                max_fee: forwarding_max_fee.into(),
                uses_fast_finality: true,
            },
        }
    }
}

/// An amount as Circle takes it: a decimal string of whole USDC with all six fractional digits,
/// so 1_000_001 smallest units is "1.000001", not a smallest-unit integer.
#[derive(Debug, Serialize)]
#[serde(transparent)]
struct UsdcDecimals(String);

impl From<u64> for UsdcDecimals {
    fn from(units: u64) -> Self {
        let units_per_usdc = 10_u64.pow(u32::from(USDCX_DECIMALS));
        Self(format!(
            "{}.{:0width$}",
            units / units_per_usdc,
            units % units_per_usdc,
            width = usize::from(USDCX_DECIMALS),
        ))
    }
}

/// Decoded wire data, not a verified or signable withdrawal.
#[derive(Debug, Deserialize)]
pub struct UnverifiedPrepareResponse {
    pub(crate) batches: Vec<UnverifiedPrepareBatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnverifiedPrepareBatch {
    pub(crate) burn_intents: Vec<BurnIntent>,
    pub(crate) encoded: String,
    pub(crate) message_hash_to_sign: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BurnIntent {
    pub(crate) max_block_height: String,
    pub(crate) max_fee: String,
    pub(crate) spec: TransferSpec,
}

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
