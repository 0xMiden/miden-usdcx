//! Startup configuration and preflight contract tests.

mod config;
mod preflight;
mod store;

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_protocol::account::AccountId;
use reqwest::{Method, StatusCode};
use tempfile::TempDir;

use crate::attester::{Attester, StartError};
use crate::chain::{ChainError, ChainReader};
use crate::circle::{CircleError, HttpTransport, RawResponse};
use crate::config::Config;

const FAUCET_ACCOUNT_ID: &str = "0xbb405fd9fe431bd1135a292de098cb";
const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CONFIG_FILE: &str = "attester.toml";
const STORE_FILE: &str = "state/checkpoints/withdrawal-cursor.sqlite3";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(275);

pub(super) fn config_toml(deployment_block: u64) -> String {
    format!(
        "circle_request_timeout_ms = {}\n\
         faucet_account_id_hex = \"{FAUCET_ACCOUNT_ID}\"\n\
         circle_api_base_url = \"https://circle.example.invalid\"\n\
         poll_interval_ms = 1000\n\
         faucet_deployment_block = {deployment_block}\n\
         expected_signing_public_keys_hex = [\"{SIGNING_KEY_ONE}\", \"{SIGNING_KEY_TWO}\"]\n\
         store_path = \"{STORE_FILE}\"\n",
        REQUEST_TIMEOUT.as_millis()
    )
}

fn write_config(tempdir: &TempDir, deployment_block: u32) -> PathBuf {
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config_toml(u64::from(deployment_block))).unwrap();
    path
}

fn load_config(tempdir: &TempDir, deployment_block: u32) -> Config {
    Config::load(&write_config(tempdir, deployment_block)).unwrap()
}

pub(super) fn create_store_parent(tempdir: &TempDir) -> PathBuf {
    let path = tempdir.path().join(STORE_FILE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

fn faucet_account_id() -> AccountId {
    AccountId::from_hex(FAUCET_ACCOUNT_ID).unwrap()
}

#[derive(Clone, Copy)]
pub(super) enum ChainState {
    Ready,
    Unreachable,
    FaucetMissing,
}

struct FakeChain(ChainState);

impl ChainReader for FakeChain {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send + '_>> {
        Box::pin(async move {
            match self.0 {
                ChainState::Unreachable => Err(ChainError::Unavailable),
                ChainState::Ready | ChainState::FaucetMissing => Ok(()),
            }
        })
    }

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(account_id == &faucet_account_id() && matches!(self.0, ChainState::Ready))
        })
    }
}

#[derive(Clone, Copy)]
enum CircleState {
    Response(StatusCode),
    TransportError,
}

#[derive(Debug, PartialEq, Eq)]
struct ObservedRequest {
    method: Method,
    url: String,
    timeout: Option<Duration>,
}

struct FakeCircle {
    state: CircleState,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}

impl FakeCircle {
    fn new(state: CircleState) -> (Self, Arc<Mutex<Vec<ObservedRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                state,
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }
}

impl HttpTransport for FakeCircle {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>> {
        self.requests.lock().unwrap().push(ObservedRequest {
            method: request.method().clone(),
            url: request.url().to_string(),
            timeout: request.timeout().copied(),
        });
        let state = self.state;
        Box::pin(async move {
            match state {
                CircleState::Response(status) => Ok(RawResponse::new(status)),
                CircleState::TransportError => Err(CircleError::Unavailable),
            }
        })
    }
}

fn ready_circle() -> Box<dyn HttpTransport> {
    let (circle, _) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    Box::new(circle)
}

pub(super) async fn start(
    config: Config,
    chain: ChainState,
    circle: Box<dyn HttpTransport>,
) -> Result<Attester, StartError> {
    Attester::start(config, Box::new(FakeChain(chain)), circle).await
}
