//! Circle API reachability boundary used during startup.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::{StatusCode, Url};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CircleError {
    #[error("Circle API is unavailable")]
    Unavailable,
    #[error("Circle request failed")]
    Transport(#[source] reqwest::Error),
    #[error("Circle returned HTTP {0}")]
    UnexpectedStatus(StatusCode),
}

#[derive(Debug)]
pub struct RawResponse {
    status: StatusCode,
}

impl RawResponse {
    pub fn new(status: StatusCode) -> Self {
        Self { status }
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

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

impl ReqwestTransport {
    pub fn new() -> Result<Self, CircleError> {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("xusdc-attester/", env!("CARGO_PKG_VERSION")))
            // Circle is only ever reached over HTTPS. The crate's own tests may use plain HTTP.
            .https_only(cfg!(not(test)))
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
            self.client
                .execute(request)
                .await
                .map(|response| RawResponse::new(response.status()))
                .map_err(CircleError::Transport)
        })
    }
}

#[allow(dead_code)]
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
}
