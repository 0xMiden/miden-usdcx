//! Circle reachability and prepare requests. Responses are not trusted for signing.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use miden_standards::interop::eth::EthEmbeddedAccountId;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use tokio::time::Instant;
use xusdc_encoding::account::xreserve::USDCX_DECIMALS;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::burn::ValidatedBurn;
use crate::config::Config;

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
}

#[derive(Debug)]
pub struct RawResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl RawResponse {
    pub fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self { status, body }
    }
}

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
}

/// Circle's xReserve API over HTTPS. Requests go out at least [`REQUEST_GAP`] apart.
pub struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    client: reqwest::Client,
    next_request: Mutex<Instant>,
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
        let status = response.status();
        let body = response.bytes().await.map_err(CircleError::Transport)?;
        Ok(RawResponse::new(status, body.to_vec()))
    }

    /// Decodes Circle's reply only. Its contents must be verified before signing.
    #[allow(dead_code)]
    pub(crate) async fn prepare_withdrawal(
        &self,
        burn: &ValidatedBurn,
        use_circle_forwarding: bool,
    ) -> Result<UnverifiedPrepareResponse, CircleError> {
        let units_per_usdc = 10_u64.pow(u32::from(USDCX_DECIMALS));
        let note = burn.burn.note.as_note();
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
        let batch = json!({
            "token": "USDC",
            "remoteDomain": MIDEN_DOMAIN,
            "remoteDepositor": format!("0x{}", hex::encode(sender.to_bytes32())),
            "finalDestinationDomain": burn.items.dest_domain,
            "finalDestinationRecipient": format!(
                "0x{}", hex::encode(burn.items.dest_recipient.as_bytes())
            ),
            "valueIncludingFees": value_including_fees,
            "salt": salt,
            "useCircleForwarding": use_circle_forwarding,
        });
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
        let response = self.send(request).await?;
        if response.status != StatusCode::OK {
            return Err(CircleError::UnexpectedPrepareStatus {
                status: response.status,
                body: response.body,
            });
        }
        serde_json::from_slice(&response.body).map_err(CircleError::InvalidResponse)
    }
}

impl CircleApi for CircleClient {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>> {
        Box::pin(async move { read_info(&self.send(self.info_request()?).await?) })
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

/// Decoded wire data, not a verified or signable withdrawal.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub(crate) struct UnverifiedPrepareResponse {
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
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BurnIntent {
    pub(crate) max_block_height: String,
    pub(crate) max_fee: String,
    pub(crate) spec: TransferSpec,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StructuredHookData {
    pub(crate) remote_domain: u32,
    pub(crate) remote_depositor: String,
    pub(crate) remote_token: String,
    pub(crate) forwarding_contract_address: String,
    pub(crate) forwarding_calldata: String,
}
