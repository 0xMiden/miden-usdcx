//! Circle requests. Prepared authorizations and submission identities are checked separately.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use miden_standards::interop::eth::EthEmbeddedAccountId;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use xusdc_encoding::account::xreserve::USDCX_DECIMALS;
use xusdc_encoding::xreserve::MIDEN_DOMAIN;

use crate::burn::ValidatedBurn;
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

pub(crate) struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    transport: Box<dyn HttpTransport>,
}

impl CircleClient {
    pub(crate) fn new(
        base_url: Url,
        request_timeout: Duration,
        transport: Box<dyn HttpTransport>,
    ) -> Self {
        Self {
            base_url,
            request_timeout,
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

    pub(crate) fn submission_endpoint(&self) -> Result<String, CircleError> {
        self.base_url
            .join("/v1/withdraw")
            .map(|url| url.to_string())
            .map_err(|_| CircleError::Unavailable)
    }

    pub(crate) async fn post_submission(
        &self,
        saved: &SavedSubmission,
    ) -> Result<RawResponse, CircleError> {
        let url = Url::parse(&saved.endpoint).map_err(|_| CircleError::Unavailable)?;
        let mut request = reqwest::Request::new(reqwest::Method::POST, url);
        *request.timeout_mut() = Some(self.request_timeout);
        request.headers_mut().insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        // A retry must send the saved authorization, not rebuild it from today's config.
        *request.body_mut() = Some(saved.body.clone().into());
        self.transport.execute(request).await
    }

    pub(crate) async fn get_withdrawal(
        &self,
        saved: &SavedSubmission,
        id: &str,
    ) -> Result<RawResponse, CircleError> {
        let mut url = Url::parse(&saved.endpoint)
            .and_then(|url| url.join("/v1/withdrawal/"))
            .map_err(|_| CircleError::Unavailable)?;
        url.path_segments_mut()
            .map_err(|_| CircleError::Unavailable)?
            .pop_if_empty()
            .push(id);
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        *request.timeout_mut() = Some(self.request_timeout);
        self.transport.execute(request).await
    }

    /// Decodes Circle's reply only. Its contents must be verified before signing.
    pub(crate) async fn prepare_withdrawal(
        &self,
        burn: &ValidatedBurn,
        use_circle_forwarding: bool,
    ) -> Result<UnverifiedPrepareResponse, CircleError> {
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
#[derive(Debug, Deserialize)]
pub(crate) struct UnverifiedPrepareResponse {
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
