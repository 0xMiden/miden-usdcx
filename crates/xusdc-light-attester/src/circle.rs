//! Circle API reachability boundary used during startup.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use reqwest::Url;

#[derive(Debug)]
pub struct CircleError;

#[derive(Debug)]
pub struct RawResponse;

pub trait HttpTransport: Send + Sync {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>>;
}

#[allow(dead_code)]
pub(crate) struct CircleClient {
    base_url: Url,
    request_timeout: Duration,
    transport: Box<dyn HttpTransport>,
}

#[allow(dead_code, unused_variables)]
impl CircleClient {
    pub(crate) fn new(
        base_url: Url,
        request_timeout: Duration,
        transport: Box<dyn HttpTransport>,
    ) -> Self {
        todo!()
    }

    pub(crate) async fn check_connection(&self) -> Result<(), CircleError> {
        todo!()
    }
}
