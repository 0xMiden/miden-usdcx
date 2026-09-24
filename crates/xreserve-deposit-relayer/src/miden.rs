//! Miden transaction submission for mint-note pages.
//!
//! [`MidenClient`] is the surface the relay loop needs; [`NodeClient`] implements it against a
//! Miden node. Submitting is only half the job: the node accepts a transaction into its mempool
//! long before it lands in a block, so every submission here is followed by a wait for inclusion.
//! Until that wait succeeds the page is not done, and the scan's progress does not move past it.
//!
//! Every mint transaction is given an expiration block, so the wait always has an answer. A
//! transaction the chain has reached the expiration block of can no longer be included by anyone:
//! the wait ends in failure on a fact about the chain rather than on a guess about how long is too
//! long, and the page is retried.
//!
//! One page is one transaction. That is what makes the retry above clean: a page either lands
//! whole or lands not at all, so a retry never re-mints a deposit an earlier attempt already got on
//! chain. An operator who wants smaller proofs turns the page size down, which shrinks the
//! transaction and the retry unit together.

use std::fmt;
use std::fs;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use miden_client::builder::ClientBuilder;
use miden_client::keystore::FilesystemKeyStore;
use miden_client::rpc::{Endpoint, GrpcClient};
use miden_client::store::TransactionFilter;
use miden_client::transaction::{TransactionRequestBuilder, TransactionStatus};
use miden_client::Client;
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::note::Note;
use miden_protocol::transaction::TransactionId;
use miden_protocol::MAX_OUTPUT_NOTES_PER_TX;
use tracing::field::{display, Empty};
use tracing::{instrument, Span};

use crate::circle::PageSize;
use crate::config::Config;

/// How long one node RPC call may take. The calls are a state sync and a transaction submission
/// against a node the relayer operator runs, so this is a liveness bound, not a tuning knob.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait between asking the node whether a submitted transaction made it into a block.
/// Blocks are produced far more slowly than this, so a shorter interval only adds traffic.
const INCLUSION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The file the Miden client keeps its store in, inside the configured data directory.
const STORE_FILE: &str = "store.sqlite3";

/// The directory the relayer account's signing key is read from, inside the configured data
/// directory.
const KEYSTORE_DIR: &str = "keystore";

/// A whole page has to fit in one transaction for the page to be the retry unit, and it always
/// does: the largest page Circle is asked for is smaller than the most output notes the protocol
/// lets a transaction create. Raising [`PageSize::MAX`] past that ceiling fails the build here
/// rather than at the node.
const _: () = assert!(PageSize::MAX as usize <= MAX_OUTPUT_NOTES_PER_TX);

/// Submits a page of mint notes to Miden and waits for them to be included on chain.
///
/// This is the surface the relay loop needs from a Miden client. It is a trait so that the loop
/// can be exercised without a node.
pub trait MidenClient: fmt::Debug + Send {
    /// Submits `notes` from `sender` as ONE transaction and returns its identifier, already
    /// included in a block.
    ///
    /// The caller counts the page as handled after this method succeeds. Returning before
    /// inclusion could move the watermark past deposits whose transaction is later dropped.
    fn submit_notes(&mut self, sender: AccountId, notes: Vec<Note>) -> Result<TransactionId>;
}

/// How many blocks past the one it was built against a mint transaction may still be included in.
///
/// This is what makes "it will never land" an observable fact rather than an assumption: once the
/// chain is past a transaction's expiration block, no block can carry it any more. Too small a
/// delta expires transactions that were merely slow to prove or to reach a block; too large a one
/// leaves a page waiting longer before the relayer gives up on it and retries.
///
/// The delta is non-zero by construction: zero would expire a transaction at the very block it was
/// built against, leaving it no block it could ever be included in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirationDelta(NonZeroU16);

impl ExpirationDelta {
    /// The delta, as the number of blocks the transaction request is given.
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for ExpirationDelta {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self> {
        NonZeroU16::new(value)
            .map(Self)
            .context("the expiration delta must be at least 1 block, got 0")
    }
}

impl FromStr for ExpirationDelta {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let value: u16 = value
            .parse()
            .context("the expiration delta is not a number of blocks")?;
        Self::try_from(value)
    }
}

impl fmt::Display for ExpirationDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A Miden client pointed at a node, with the relayer's account tracked and its signing key to
/// hand.
pub struct NodeClient {
    /// `miden-client` is asynchronous and the relay loop is not, so every call is driven to
    /// completion on this runtime.
    runtime: tokio::runtime::Runtime,
    client: Client<FilesystemKeyStore>,
    expiration_delta: ExpirationDelta,
}

/// Hand-written because the Miden client holds a node connection and a local store, neither of
/// which has a useful rendering.
impl fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeClient")
            .field("expiration_delta", &self.expiration_delta)
            .finish_non_exhaustive()
    }
}

impl NodeClient {
    /// Connects to the configured node, opens the local store and keystore, and starts tracking
    /// the relayer's account.
    ///
    /// The relayer account must already exist on chain and its signing key must already be in the
    /// keystore directory; this only teaches the local client about the account. Everything that
    /// can be refused is refused here, so the service never starts polling Circle unless it can
    /// also mint.
    ///
    /// # Errors
    ///
    /// - The node URL is not an endpoint, or the node cannot be reached.
    /// - The data directory, its store, or its keystore cannot be opened.
    /// - The node does not know the relayer account.
    pub fn new(config: &Config) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building the runtime the miden client runs on")?;

        let endpoint = Endpoint::try_from(config.miden_node_url.as_str())
            .map_err(|error| anyhow!("the miden node url is not an endpoint: {error}"))?;

        let data_dir = &config.miden_data_dir;
        fs::create_dir_all(data_dir).with_context(|| {
            format!("creating the miden data directory `{}`", data_dir.display())
        })?;
        let keystore = FilesystemKeyStore::new(data_dir.join(KEYSTORE_DIR))
            .map_err(|error| anyhow!("opening the miden keystore: {error}"))?;

        let mut client = runtime
            .block_on(
                ClientBuilder::new()
                    .rpc(Arc::new(GrpcClient::new(
                        &endpoint,
                        RPC_TIMEOUT.as_millis() as u64,
                    )))
                    .sqlite_store(data_dir.join(STORE_FILE))
                    .authenticator(Arc::new(keystore))
                    .build(),
            )
            .context("building the miden client")?;

        let relayer = config.relayer_account_id;
        runtime.block_on(async {
            client
                .sync_state()
                .await
                .context("the first sync with the miden node")?;

            // A store carried over from an earlier run already tracks the account; a fresh one has
            // to be told about it, which fails loudly if the node has never seen it.
            if client.get_account(relayer).await?.is_none() {
                client
                    .import_account_by_id(relayer)
                    .await
                    .with_context(|| {
                        format!("the node does not know the relayer account {relayer}")
                    })?;
            }

            Ok::<(), anyhow::Error>(())
        })?;

        Ok(Self {
            runtime,
            client,
            expiration_delta: config.expiration_delta,
        })
    }
}

impl MidenClient for NodeClient {
    /// Submits the whole page as one transaction and returns once the node has included it.
    ///
    /// The notes are the transaction's own output notes: the relayer's account creates them, and
    /// the faucet consumes them afterwards on its own.
    #[instrument(
        name = "transaction",
        skip_all,
        fields(
            notes.count = notes.len(),
            transaction.id = Empty,
            expiration_block = Empty,
            block = Empty,
        ),
    )]
    fn submit_notes(&mut self, sender: AccountId, notes: Vec<Note>) -> Result<TransactionId> {
        let span = Span::current();
        let request = TransactionRequestBuilder::new()
            .own_output_notes(notes)
            .expiration_delta(self.expiration_delta.get())
            .build()
            .context("building the mint transaction")?;

        let Self {
            runtime, client, ..
        } = self;

        runtime.block_on(async {
            // The transaction executes against the account's committed state, so that state has to
            // be current before it is built.
            client
                .sync_state()
                .await
                .context("syncing before the mint transaction")?;

            let transaction = client
                .submit_new_transaction(sender, request)
                .await
                .context("submitting the mint transaction")?;
            span.record("transaction.id", display(transaction));

            loop {
                // Only a sync moves a submitted transaction out of `Pending`: it is how the node
                // reports which transactions reached a block.
                client
                    .sync_state()
                    .await
                    .context("syncing while waiting for the mint transaction")?;

                let record = client
                    .get_transactions(TransactionFilter::Ids(vec![transaction]))
                    .await
                    .context("reading the mint transaction's status")?
                    .pop()
                    .with_context(|| {
                        format!("the client stopped tracking the transaction {transaction}")
                    })?;
                let expiration_block = record.details.expiration_block_num;
                span.record("expiration_block", expiration_block.as_u32());

                // The chain tip as this client last saw it, which the sync above just refreshed.
                let chain_tip = client
                    .get_sync_height()
                    .await
                    .context("reading how far the chain has been synced")?;

                match inclusion(&record.status, chain_tip, expiration_block)
                    .with_context(|| format!("the mint transaction {transaction} never landed"))?
                {
                    Inclusion::Included(block) => {
                        span.record("block", block.as_u32());
                        return Ok(transaction);
                    }
                    Inclusion::Waiting => tokio::time::sleep(INCLUSION_POLL_INTERVAL).await,
                }
            }
        })
    }
}

/// What a submitted transaction's latest status means to the caller waiting on it.
#[derive(Debug, PartialEq, Eq)]
enum Inclusion {
    /// The transaction is in this block.
    Included(BlockNumber),
    /// Not yet, and there is still time.
    Waiting,
}

/// Reads a submitted transaction's status against the chain it is waiting on.
///
/// A discarded transaction can never commit, so it ends the wait as an error rather than something
/// to keep polling. A chain that has reached the transaction's expiration block ends it the same
/// way, and for the same reason: no later block can carry the transaction, so waiting on it would
/// never end. Either way the relay loop retries the page from the cursor.
///
/// The tip reaching the expiration block is already decisive. The tip is a height the client has
/// synced, so by the time it reads the expiration block the transaction would have been reported as
/// committed if that block carried it.
fn inclusion(
    status: &TransactionStatus,
    chain_tip: BlockNumber,
    expiration_block: BlockNumber,
) -> Result<Inclusion> {
    match status {
        TransactionStatus::Committed { block_number, .. } => Ok(Inclusion::Included(*block_number)),
        TransactionStatus::Discarded(cause) => bail!("the node discarded it: {cause}"),
        TransactionStatus::Pending if chain_tip >= expiration_block => bail!(
            "it expired at block {} and the chain is at {}",
            expiration_block.as_u32(),
            chain_tip.as_u32()
        ),
        TransactionStatus::Pending => Ok(Inclusion::Waiting),
    }
}

#[cfg(test)]
mod tests {
    use miden_client::transaction::DiscardCause;
    use rstest::rstest;

    use super::*;

    /// The block the transactions under test expire at.
    const EXPIRATION_BLOCK: u32 = 100;

    /// A committed status reporting this block.
    fn committed(block: u32) -> TransactionStatus {
        TransactionStatus::Committed {
            block_number: BlockNumber::from(block),
            commit_timestamp: 0,
        }
    }

    /// Reads a status against a chain whose tip is at this block.
    fn inclusion_at(status: &TransactionStatus, chain_tip: u32) -> Result<Inclusion> {
        inclusion(
            status,
            BlockNumber::from(chain_tip),
            BlockNumber::from(EXPIRATION_BLOCK),
        )
    }

    /// A transaction in a block is included, even once the chain is past its expiration block —
    /// expiry only ever bounds where it could land, never unlands it.
    #[rstest]
    #[case::before_expiry(EXPIRATION_BLOCK - 1)]
    #[case::past_expiry(EXPIRATION_BLOCK + 1)]
    fn a_committed_transaction_is_included(#[case] chain_tip: u32) {
        assert_eq!(
            inclusion_at(&committed(7), chain_tip).unwrap(),
            Inclusion::Included(BlockNumber::from(7))
        );
    }

    /// A pending transaction is waited for while a block that could still carry it is to come.
    #[test]
    fn a_pending_transaction_is_waited_for() {
        assert_eq!(
            inclusion_at(&TransactionStatus::Pending, EXPIRATION_BLOCK - 1).unwrap(),
            Inclusion::Waiting
        );
    }

    /// Once the chain has synced the expiration block without the transaction in it, no block can
    /// carry it any more, so the wait ends rather than running forever.
    #[rstest]
    #[case::at_expiry(EXPIRATION_BLOCK)]
    #[case::past_expiry(EXPIRATION_BLOCK + 1)]
    fn a_pending_transaction_the_chain_has_reached_the_expiry_of_is_an_error(
        #[case] chain_tip: u32,
    ) {
        let error = inclusion_at(&TransactionStatus::Pending, chain_tip).unwrap_err();
        assert!(
            error.to_string().contains("expired at block 100"),
            "unexpected error: {error}"
        );
    }

    /// A discarded transaction can never commit, so waiting on it would never end.
    #[test]
    fn a_discarded_transaction_is_an_error() {
        let error = inclusion_at(
            &TransactionStatus::Discarded(DiscardCause::Expired),
            EXPIRATION_BLOCK - 1,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("discarded"),
            "unexpected error: {error}"
        );
    }

    /// An expiration delta of at least one block leaves the transaction a block to land in.
    #[test]
    fn a_supported_expiration_delta_is_accepted() {
        assert_eq!(ExpirationDelta::try_from(1).unwrap().get(), 1);
    }

    /// A zero delta would expire the transaction where it was built, so it is refused.
    #[test]
    fn a_zero_expiration_delta_is_refused() {
        let error = format!("{:#}", "0".parse::<ExpirationDelta>().unwrap_err());
        assert!(
            error.contains("at least 1 block"),
            "unexpected error: {error}"
        );
    }

    /// A delta that is not a number of blocks is refused where it is parsed.
    #[test]
    fn an_expiration_delta_that_is_not_a_number_is_refused() {
        let error = format!("{:#}", "soon".parse::<ExpirationDelta>().unwrap_err());
        assert!(
            error.contains("not a number of blocks"),
            "unexpected error: {error}"
        );
    }
}
