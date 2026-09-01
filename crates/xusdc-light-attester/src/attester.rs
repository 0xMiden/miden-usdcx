//! Service startup and the sequential withdrawal-attester cycle.

use std::time::Instant;

use miden_protocol::note::NoteScriptRoot;

use crate::chain::ChainReader;
use crate::circle::{CircleClient, HttpTransport};
use crate::config::Config;
use crate::signer::Signer;
use crate::store::Store;

#[derive(Debug)]
#[non_exhaustive]
pub enum StartError {
    InvalidStore,
    StoreLocked,
    InvalidSignerSet,
    SignerUnavailable,
    MidenNodeUnavailable,
    FaucetMissing,
    CircleUnavailable,
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
    signers: Vec<Box<dyn Signer>>,
    burn_note_script_root: NoteScriptRoot,
}

#[allow(dead_code, unused_variables)]
impl Attester {
    pub async fn start(
        config: Config,
        chain: Box<dyn ChainReader>,
        circle_transport: Box<dyn HttpTransport>,
        signers: Vec<Box<dyn Signer>>,
    ) -> Result<Self, StartError> {
        todo!()
    }

    /// Drives cycles until shutdown. Checks `shutdown` BETWEEN cycles and sleeps the full
    /// poll interval — no race, so no `select!` needed. Finishes the current cycle before
    /// returning; the process exits only between cycles.
    pub async fn run(
        &mut self,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), RunError> {
        todo!()
    }

    pub async fn run_one_cycle(&mut self, now: Instant) -> CycleReport {
        todo!()
    }

    async fn discover_burns(&mut self) -> Result<(), DiscoverError> {
        todo!()
    }

    async fn submit_withdrawals(&mut self) -> Result<(), SubmitError> {
        todo!()
    }

    async fn poll_withdrawal_statuses(&mut self, now: Instant) -> Result<(), PollError> {
        todo!()
    }
}
