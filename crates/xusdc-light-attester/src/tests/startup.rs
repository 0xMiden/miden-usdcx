//! Coarse startup contract tests, authored before startup is implemented.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use reqwest::Method;
use tempfile::TempDir;

use crate::attester::{Attester, StartError};
use crate::chain::{ChainError, ChainReader};
use crate::circle::{CircleError, HttpTransport, RawResponse};
use crate::config::{Config, ConfigError};
use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::store::{ScanCursor, Store};

const FAUCET_ACCOUNT_ID: &str = "0xbb405fd9fe431bd1135a292de098cb";
const SIGNING_KEY_ONE: &str =
    "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SIGNING_KEY_TWO: &str =
    "0x02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CONFIG_FILE: &str = "attester.toml";
const STORE_FILE: &str = "attester.sqlite3";
const REQUEST_TIMEOUT: Duration = Duration::from_millis(275);
const LOCK_CHILD_CONFIG: &str = "XUSDC_LIGHT_ATTESTER_LOCK_CHILD_CONFIG";

fn config_toml(fallback_block: u32) -> String {
    format!(
        "request_timeout_ms = {}\n\
         faucet_account_id = \"{FAUCET_ACCOUNT_ID}\"\n\
         circle_api_base_url = \"https://circle.example.invalid\"\n\
         poll_interval_ms = 1000\n\
         fallback_checkpoint_block = {fallback_block}\n\
         expected_signing_public_keys = [\"{SIGNING_KEY_ONE}\", \"{SIGNING_KEY_TWO}\"]\n\
         store_path = \"{STORE_FILE}\"\n",
        REQUEST_TIMEOUT.as_millis()
    )
}

fn write_config(tempdir: &TempDir, fallback_block: u32) -> std::path::PathBuf {
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config_toml(fallback_block)).unwrap();
    path
}

fn load_config(tempdir: &TempDir, fallback_block: u32) -> Config {
    Config::load(&write_config(tempdir, fallback_block)).unwrap()
}

fn faucet_account_id() -> AccountId {
    AccountId::from_hex(FAUCET_ACCOUNT_ID).unwrap()
}

fn signing_key(value: &str) -> SigningPublicKey {
    let bytes: [u8; 33] = hex::decode(value.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    SigningPublicKey(bytes)
}

#[derive(Clone, Copy)]
enum ChainState {
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
                ChainState::Unreachable => Err(ChainError),
                ChainState::Ready | ChainState::FaucetMissing => Ok(()),
            }
        })
    }

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>> {
        Box::pin(async move {
            if account_id != &faucet_account_id() {
                return Ok(false);
            }
            Ok(matches!(self.0, ChainState::Ready))
        })
    }
}

struct FakeSigner(SigningPublicKey);

impl Signer for FakeSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        Box::pin(async move { Ok(self.0) })
    }
}

fn valid_signers() -> Vec<Box<dyn Signer>> {
    vec![
        Box::new(FakeSigner(signing_key(SIGNING_KEY_ONE))),
        Box::new(FakeSigner(signing_key(SIGNING_KEY_TWO))),
    ]
}

#[derive(Clone, Copy)]
enum CircleState {
    Ready,
    Unreachable,
}

struct FakeCircle(CircleState);

impl HttpTransport for FakeCircle {
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> Pin<Box<dyn Future<Output = Result<RawResponse, CircleError>> + Send + '_>> {
        Box::pin(async move {
            match self.0 {
                CircleState::Ready => Ok(RawResponse),
                CircleState::Unreachable => {
                    assert_eq!(request.method(), Method::GET);
                    assert_eq!(
                        request.url().as_str(),
                        "https://circle.example.invalid/v1/info"
                    );
                    assert_eq!(request.timeout(), Some(&REQUEST_TIMEOUT));
                    Err(CircleError)
                }
            }
        })
    }
}

async fn start(
    config: Config,
    chain: ChainState,
    circle: CircleState,
    signers: Vec<Box<dyn Signer>>,
) -> Result<Attester, StartError> {
    Attester::start(
        config,
        Box::new(FakeChain(chain)),
        Box::new(FakeCircle(circle)),
        signers,
    )
    .await
}

#[test]
fn invalid_config_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let invalid = config_toml(1).replace("https://circle", "http://circle");
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, invalid).unwrap();

    assert!(matches!(Config::load(&path), Err(ConfigError)));
}

#[tokio::test]
async fn new_store_starts_at_deployment_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let attester = start(
        load_config(&tempdir, 1_234_567),
        ChainState::Ready,
        CircleState::Ready,
        valid_signers(),
    )
    .await
    .unwrap();

    assert_eq!(
        attester.store.scan_cursor().unwrap().next_block,
        BlockNumber::from(1_234_567u32)
    );
}

#[tokio::test]
async fn existing_store_resumes_from_saved_block() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = tempdir.path().join(STORE_FILE);
    let saved_block = BlockNumber::from(91u32);
    let store = Store::open_or_create(
        &store_path,
        faucet_account_id(),
        ScanCursor {
            next_block: saved_block,
        },
    )
    .unwrap();
    drop(store);

    let attester = start(
        load_config(&tempdir, 700),
        ChainState::Ready,
        CircleState::Ready,
        valid_signers(),
    )
    .await
    .unwrap();

    assert_eq!(
        attester.store.scan_cursor().unwrap().next_block,
        saved_block
    );
}

#[tokio::test]
async fn invalid_store_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(tempdir.path().join(STORE_FILE), b"not a store").unwrap();

    let result = start(
        load_config(&tempdir, 1),
        ChainState::Ready,
        CircleState::Ready,
        valid_signers(),
    )
    .await;

    assert!(matches!(result, Err(StartError::InvalidStore)));
}

#[tokio::test]
async fn store_cannot_be_opened_twice() {
    if let Some(config_path) = std::env::var_os(LOCK_CHILD_CONFIG) {
        let result = start(
            Config::load(Path::new(&config_path)).unwrap(),
            ChainState::Ready,
            CircleState::Ready,
            valid_signers(),
        )
        .await;
        assert!(matches!(result, Err(StartError::StoreLocked)));
        return;
    }

    let tempdir = tempfile::tempdir().unwrap();
    let config_path = write_config(&tempdir, 1);
    let store = Store::open_or_create(
        &tempdir.path().join(STORE_FILE),
        faucet_account_id(),
        ScanCursor {
            next_block: BlockNumber::from(1u32),
        },
    )
    .unwrap();

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::startup::store_cannot_be_opened_twice")
        .env(LOCK_CHILD_CONFIG, config_path)
        .status()
        .unwrap();
    drop(store);

    assert!(status.success());
}

#[tokio::test]
async fn invalid_signers_are_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let duplicate_signers: Vec<Box<dyn Signer>> = vec![
        Box::new(FakeSigner(signing_key(SIGNING_KEY_ONE))),
        Box::new(FakeSigner(signing_key(SIGNING_KEY_ONE))),
    ];

    let result = start(
        load_config(&tempdir, 1),
        ChainState::Ready,
        CircleState::Ready,
        duplicate_signers,
    )
    .await;

    assert!(matches!(result, Err(StartError::InvalidSignerSet)));
}

#[tokio::test]
async fn unreachable_miden_node_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let result = start(
        load_config(&tempdir, 1),
        ChainState::Unreachable,
        CircleState::Ready,
        valid_signers(),
    )
    .await;

    assert!(matches!(result, Err(StartError::MidenNodeUnavailable)));
}

#[tokio::test]
async fn missing_faucet_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let result = start(
        load_config(&tempdir, 1),
        ChainState::FaucetMissing,
        CircleState::Ready,
        valid_signers(),
    )
    .await;

    assert!(matches!(result, Err(StartError::FaucetMissing)));
}

#[tokio::test]
async fn unreachable_circle_api_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let result = start(
        load_config(&tempdir, 1),
        ChainState::Ready,
        CircleState::Unreachable,
        valid_signers(),
    )
    .await;

    assert!(matches!(result, Err(StartError::CircleUnavailable)));
}
