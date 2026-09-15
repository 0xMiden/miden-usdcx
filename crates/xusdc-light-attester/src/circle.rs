//! Circle reachability and prepare requests. Responses are not trusted for signing.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use miden_standards::interop::eth::EthEmbeddedAccountId;
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use xusdc_encoding::account::xreserve::USDCX_DECIMALS;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::validation::ValidatedBurn;

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

pub trait HttpTransport: Send + Sync {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>>;
}

pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, CircleError> {
        reqwest::Client::builder()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map(|client| Self { client })
            .map_err(CircleError::Transport)
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>> {
        Box::pin(async move {
            let response = self
                .client
                .execute(request)
                .await
                .map_err(CircleError::Transport)?;
            let status = response.status();
            let body = response.bytes().await.map_err(CircleError::Transport)?;
            Ok(RawResponse::new(status, body.to_vec()))
        })
    }
}

#[allow(dead_code)]
pub(crate) struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    use_circle_forwarding: bool,
    transport: Box<dyn HttpTransport>,
}

impl CircleClient {
    pub(crate) fn new(
        base_url: Url,
        request_timeout: Duration,
        use_circle_forwarding: bool,
        transport: Box<dyn HttpTransport>,
    ) -> Self {
        Self {
            base_url,
            request_timeout,
            use_circle_forwarding,
            transport,
        }
    }

    pub(crate) async fn check_connection(&self) -> Result<(), CircleError> {
        let url = self
            .base_url
            .join("/v1/info")
            .map_err(|_| CircleError::Unavailable)?;
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        *request.timeout_mut() = Some(self.request_timeout);
        let response = self.transport.execute(request).await?;

        if response.status == StatusCode::OK {
            Ok(())
        } else {
            Err(CircleError::UnexpectedStatus(response.status))
        }
    }

    /// Decodes Circle's reply only. Its contents must be verified before signing.
    #[allow(dead_code)]
    pub(crate) async fn prepare_withdrawals(
        &self,
        burns: &[ValidatedBurn],
    ) -> Result<UnverifiedPrepareResponse, CircleError> {
        if burns.is_empty() {
            return Ok(UnverifiedPrepareResponse { batches: vec![] });
        }

        let units_per_usdc = 10_u64.pow(u32::from(USDCX_DECIMALS));
        let batches: Vec<_> = burns
            .iter()
            .map(|burn| {
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
                json!({
                    "token": "USDC",
                    "remoteDomain": MIDEN_DOMAIN,
                    "remoteDepositor": format!("0x{}", hex::encode(sender.to_bytes32())),
                    "finalDestinationDomain": burn.items.dest_domain,
                    "finalDestinationRecipient": format!(
                        "0x{}", hex::encode(burn.items.dest_recipient.as_bytes())
                    ),
                    "valueIncludingFees": value_including_fees,
                    "salt": salt,
                    "useCircleForwarding": self.use_circle_forwarding,
                })
            })
            .collect();
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
        *request.body_mut() = Some(json!({ "batches": batches }).to_string().into());
        let response = self.transport.execute(request).await?;
        if response.status != StatusCode::OK {
            return Err(CircleError::UnexpectedPrepareStatus {
                status: response.status,
                body: response.body,
            });
        }
        serde_json::from_slice(&response.body).map_err(CircleError::InvalidResponse)
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
