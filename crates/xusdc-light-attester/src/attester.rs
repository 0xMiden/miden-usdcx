//! Service startup and the sequential withdrawal-attester cycle.

use std::time::Instant;

use anyhow::Context;
use miden_protocol::note::NoteScriptRoot;

use crate::chain::ChainReader;
use crate::circle::CircleApi;
use crate::config::Config;
use crate::store::{ScanCursor, Store};
use miden_standards::note::BurnNote;

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
    circle: Box<dyn CircleApi>,
    burn_note_script_root: NoteScriptRoot,
}

#[allow(dead_code)]
impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle: Box<dyn CircleApi>,
    ) -> anyhow::Result<Self> {
        let burn_note_script_root = BurnNote::script_root();
        let store = Store::open_or_create(
            config.store_path(),
            config.faucet_account_id(),
            ScanCursor {
                next_block: config.faucet_deployment_block(),
            },
        )
        .context("failed to open attester store")?;

        chain
            .check_connection()
            .await
            .context("failed to connect to the Miden node")?;
        if !chain
            .account_exists(&config.faucet_account_id())
            .await
            .context("failed to check the configured faucet account")?
        {
            anyhow::bail!("configured faucet account does not exist");
        }

        // TODO(KMS): compare the configured public keys with the loaded signing keys.

        circle
            .check_connection()
            .await
            .context("failed to connect to the Circle API")?;

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
