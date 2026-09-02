//! Service startup and the sequential withdrawal-attester cycle.

use std::time::Instant;

use miden_protocol::note::NoteScriptRoot;

use crate::chain::{ChainError, ChainReader};
use crate::circle::{CircleClient, CircleError, HttpTransport};
use crate::config::Config;
use crate::store::{ScanCursor, Store, StoreError};
use miden_standards::note::BurnNote;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    #[error("attester store is invalid")]
    InvalidStore,
    #[error("attester store is locked by another process")]
    StoreLocked,
    #[error("Miden node is unavailable")]
    MidenNodeUnavailable(#[source] ChainError),
    #[error("configured faucet account does not exist")]
    FaucetMissing,
    #[error("Circle API is unavailable")]
    CircleUnavailable(#[source] CircleError),
}

#[derive(Debug)]
pub struct RunError;

#[derive(Debug)]
pub struct DiscoverError;

#[derive(Debug)]
pub struct SubmitError;

#[derive(Debug)]
pub struct PollError;

#[derive(Debug)]
#[non_exhaustive]
pub struct CycleReport {
    pub discover: Result<(), DiscoverError>,
    pub submit: Result<(), SubmitError>,
    pub poll: Result<(), PollError>,
}

#[allow(dead_code)]
pub struct Attester {
    config: Config,
    pub(crate) store: Store,
    chain: Box<dyn ChainReader>,
    circle: CircleClient,
    burn_note_script_root: NoteScriptRoot,
}

#[allow(dead_code)]
impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle_transport: Box<dyn HttpTransport>,
    ) -> Result<Self, StartError> {
        let burn_note_script_root = BurnNote::script_root();
        let store = Store::open_or_create(
            config.store_path(),
            config.faucet_account_id(),
            ScanCursor {
                next_block: config.faucet_deployment_block(),
            },
        )
        .map_err(|error| match error {
            StoreError::Invalid => StartError::InvalidStore,
            StoreError::Locked => StartError::StoreLocked,
        })?;

        chain
            .check_connection()
            .await
            .map_err(StartError::MidenNodeUnavailable)?;
        if !chain
            .account_exists(&config.faucet_account_id())
            .await
            .map_err(StartError::MidenNodeUnavailable)?
        {
            return Err(StartError::FaucetMissing);
        }

        // TODO(KMS): compare the configured public keys with the loaded signing keys.

        let circle = CircleClient::new(
            config.circle_api_base_url().clone(),
            config.circle_request_timeout(),
            circle_transport,
        );
        circle
            .check_connection()
            .await
            .map_err(StartError::CircleUnavailable)?;

        Ok(Self {
            config,
            store,
            chain,
            circle,
            burn_note_script_root,
        })
    }

    /// Drives cycles until shutdown. Checks `shutdown` BETWEEN cycles and sleeps the full
    /// poll interval — no race, so no `select!` needed. Finishes the current cycle before
    /// returning; the process exits only between cycles.
    pub async fn run(
        &mut self,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), RunError> {
        let _ = shutdown;
        todo!()
    }

    pub async fn run_one_cycle(&mut self, now: Instant) -> CycleReport {
        let _ = now;
        todo!()
    }

    async fn discover_burns(&mut self) -> Result<(), DiscoverError> {
        todo!()
    }

    async fn submit_withdrawals(&mut self) -> Result<(), SubmitError> {
        todo!()
    }

    async fn poll_withdrawal_statuses(&mut self, now: Instant) -> Result<(), PollError> {
        let _ = now;
        todo!()
    }
}
