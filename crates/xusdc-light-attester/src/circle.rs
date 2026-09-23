//! Circle API reachability boundary used during startup.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use reqwest::{StatusCode, Url};
use tokio::time::Instant;

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
    next_request: Mutex<Instant>,
}

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Circle allows five requests per second from one IP address; a quarter of a second between two
/// requests stays below that.
pub(crate) const REQUEST_GAP: Duration = Duration::from_millis(250);

impl ReqwestTransport {
    pub fn new() -> Result<Self, CircleError> {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("xusdc-attester/", env!("CARGO_PKG_VERSION")))
            // Circle is only ever reached over HTTPS. The crate's own tests may use plain HTTP.
            .https_only(cfg!(not(test)))
            .build()
            .map(|client| Self {
                client,
                next_request: Mutex::new(Instant::now()),
            })
            .map_err(CircleError::Transport)
    }
}

impl HttpTransport for ReqwestTransport {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>> {
        Box::pin(async move {
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
