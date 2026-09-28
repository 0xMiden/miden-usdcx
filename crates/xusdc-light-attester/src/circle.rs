//! Circle API reachability boundary used during startup.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::{StatusCode, Url};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;

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

/// Stop waiting for a Circle connection after 10 s, even when the configured request timeout is
/// longer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Circle allows five requests per second from one IP address; a quarter of a second between two
/// requests stays below that.
pub(crate) const REQUEST_GAP: Duration = Duration::from_millis(250);
/// Requests wait in a short queue for the worker; a caller waits for room when it is full.
const REQUEST_QUEUE: usize = 16;

/// The calls the attester makes to Circle's xReserve API. [`CircleClient`] makes them over HTTPS;
/// this is a trait so that the attester can be tested without Circle.
pub trait CircleApi: Send + Sync {
    /// Checks at startup that Circle's API answers.
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), CircleError>> + Send + '_>>;
}

/// Circle's xReserve API over HTTPS. Every request goes through one worker, which sends them one
/// at a time, at least [`REQUEST_GAP`] apart.
pub struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    requests: mpsc::Sender<Job>,
}

/// A request queued for the worker, and where its answer goes.
struct Job {
    request: reqwest::Request,
    reply: oneshot::Sender<Result<RawResponse, CircleError>>,
}

impl CircleClient {
    /// Builds the client and starts its worker, which ends once the client is dropped and the
    /// queued requests are done: await the returned handle to let them finish. Call this inside
    /// the Tokio runtime.
    pub fn start(config: &Config) -> Result<(Self, JoinHandle<()>), CircleError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .user_agent(concat!("xusdc-attester/", env!("CARGO_PKG_VERSION")))
            // Circle is only ever reached over HTTPS.
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(CircleError::Transport)?;
        let (requests, jobs) = mpsc::channel(REQUEST_QUEUE);
        let worker = tokio::spawn(request_worker(client, jobs));
        let circle = Self {
            base_url: config.circle_api_base_url().clone(),
            request_timeout: config.circle_request_timeout(),
            requests,
        };
        Ok((circle, worker))
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

    /// Queues one request for the worker and waits for its answer.
    pub(crate) async fn send(&self, request: reqwest::Request) -> Result<RawResponse, CircleError> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Job { request, reply })
            .await
            .map_err(|_| CircleError::Unavailable)?;
        response.await.map_err(|_| CircleError::Unavailable)?
    }
}

/// Sends the queued requests one at a time, each at least [`REQUEST_GAP`] after the previous
/// attempt ended, failed or not. A request whose caller stopped waiting is skipped; one already
/// sent is finished.
async fn request_worker(client: reqwest::Client, mut jobs: mpsc::Receiver<Job>) {
    let mut next_dispatch = Instant::now();
    while let Some(job) = jobs.recv().await {
        if job.reply.is_closed() {
            continue;
        }
        tokio::time::sleep_until(next_dispatch).await;
        if job.reply.is_closed() {
            continue;
        }
        let result = client
            .execute(job.request)
            .await
            .map(|response| RawResponse::new(response.status()))
            .map_err(CircleError::Transport);
        // The gap counts from when this attempt ended, so two dispatches are always further apart.
        next_dispatch = Instant::now() + REQUEST_GAP;
        let _ = job.reply.send(result);
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
