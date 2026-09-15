//! Miden transaction submission for mint-note pages.
//!
//! [`MidenClient`] is the surface the relay loop needs; [`NodeClient`] implements it against a
//! Miden node. Submitting is only half the job: the node accepts a transaction into its mempool
//! long before it lands in a block, so every submission here is followed by a wait for inclusion.
//! Until that wait succeeds the page is not done, and the Circle cursor does not move.
//!
//! Every mint transaction is given an expiration block, so the wait always has an answer. A
//! transaction the chain has passed the expiration block of can no longer be included by anyone:
//! the wait ends in failure on a fact about the chain rather than on a guess about how long is too
//! long, and the page is retried.

use std::fmt;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
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

/// Submits a page of mint notes to Miden and waits for them to be included on chain.
///
/// This is the surface the relay loop needs from a Miden client. It is a trait so that the loop
/// can be exercised without a node.
pub trait MidenClient: fmt::Debug + Send {
    /// Submits `notes` from `sender` and returns the identifier of every transaction it took, each
    /// already included in a block.
    ///
    /// The caller counts the page as handled after this method succeeds. Returning before
    /// inclusion could move the watermark past deposits whose transactions are later dropped.
    fn submit_notes(&mut self, sender: AccountId, notes: Vec<Note>) -> Result<Vec<TransactionId>>;
}

/// How many mint notes one transaction carries.
///
/// A page can hold more notes than one transaction should: the protocol caps a transaction's
/// output notes outright, and the cost of proving one grows with every note in it. Pages larger
/// than this are split across several transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotesPerTransaction(usize);

impl NotesPerTransaction {
    const MIN: usize = 1;
    /// The protocol's own ceiling on the notes one transaction may create. Taking it from the
    /// protocol rather than restating it means this bound cannot drift from the one that is
    /// actually enforced.
    const MAX: usize = MAX_OUTPUT_NOTES_PER_TX;

    /// The count, ready to chunk a page by.
    pub fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<usize> for NotesPerTransaction {
    type Error = anyhow::Error;

    fn try_from(value: usize) -> Result<Self> {
        ensure!(
            (Self::MIN..=Self::MAX).contains(&value),
            "notes per transaction must be between {} and {}, got {value}",
            Self::MIN,
            Self::MAX
        );
        Ok(Self(value))
    }
}

impl FromStr for NotesPerTransaction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let value: usize = value
            .parse()
            .context("the notes per transaction is not a number")?;
        Self::try_from(value)
    }
}

impl fmt::Display for NotesPerTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How many blocks past the one it was built against a mint transaction may still be included in.
///
/// This is what makes "it will never land" an observable fact rather than an assumption: once the
/// chain is past a transaction's expiration block, no block can carry it any more. Too small a
/// delta expires transactions that were merely slow to prove or to reach a block; too large a one
/// leaves a page waiting longer before the relayer gives up on it and retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirationDelta(u16);

impl ExpirationDelta {
    /// Zero would expire a transaction at the very block it was built against, leaving it no block
    /// it could ever be included in.
    const MIN: u16 = 1;

    /// The delta, as the number of blocks the transaction request is given.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ExpirationDelta {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self> {
        ensure!(
            value >= Self::MIN,
            "the expiration delta must be at least {} block, got {value}",
            Self::MIN
        );
        Ok(Self(value))
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
    notes_per_transaction: NotesPerTransaction,
    expiration_delta: ExpirationDelta,
}

/// Hand-written because the Miden client holds a node connection and a local store, neither of
/// which has a useful rendering.
impl fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeClient")
            .field("notes_per_transaction", &self.notes_per_transaction)
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
            notes_per_transaction: config.notes_per_transaction,
            expiration_delta: config.expiration_delta,
        })
    }

    /// Submits one transaction carrying `notes` and returns once the node has included it.
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
    fn submit_transaction(&mut self, sender: AccountId, notes: Vec<Note>) -> Result<TransactionId> {
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

impl MidenClient for NodeClient {
    /// Submits the page as one transaction per [`NotesPerTransaction`] notes, in order, waiting
    /// for each to be included before starting the next.
    ///
    /// A failure part-way leaves the transactions already included on chain. That is safe rather
    /// than tidy: the page is retried whole, the retry rebuilds every note with a fresh serial
    /// number, and the faucet's on-chain record of spent deposit nonces refuses the ones that
    /// already minted.
    #[instrument(name = "submit_notes", skip_all, fields(notes.count = notes.len()))]
    fn submit_notes(&mut self, sender: AccountId, notes: Vec<Note>) -> Result<Vec<TransactionId>> {
        let mut submitted = Vec::new();
        for chunk in notes.chunks(self.notes_per_transaction.get()) {
            submitted.push(self.submit_transaction(sender, chunk.to_vec())?);
        }
        Ok(submitted)
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
/// to keep polling. A chain that has moved past the transaction's expiration block ends it the same
/// way, and for the same reason: no later block can carry the transaction, so waiting on it would
/// never end. Either way the relay loop retries the page from the cursor.
///
/// The expiration block itself is still a block the transaction may be included in, so only a tip
/// strictly past it is decisive.
fn inclusion(
    status: &TransactionStatus,
    chain_tip: BlockNumber,
    expiration_block: BlockNumber,
) -> Result<Inclusion> {
    match status {
        TransactionStatus::Committed { block_number, .. } => Ok(Inclusion::Included(*block_number)),
        TransactionStatus::Discarded(cause) => bail!("the node discarded it: {cause}"),
        TransactionStatus::Pending if chain_tip > expiration_block => bail!(
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

    /// A pending transaction is waited for while a block that could still carry it is to come —
    /// including at the expiration block itself, which is the last one that can.
    #[rstest]
    #[case::before_expiry(EXPIRATION_BLOCK - 1)]
    #[case::at_expiry(EXPIRATION_BLOCK)]
    fn a_pending_transaction_is_waited_for(#[case] chain_tip: u32) {
        assert_eq!(
            inclusion_at(&TransactionStatus::Pending, chain_tip).unwrap(),
            Inclusion::Waiting
        );
    }

    /// Once the chain is past the expiration block, no block can carry the transaction, so the
    /// wait ends rather than running forever.
    #[test]
    fn a_pending_transaction_the_chain_has_passed_is_an_error() {
        let error = inclusion_at(&TransactionStatus::Pending, EXPIRATION_BLOCK + 1).unwrap_err();
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

    /// The count is accepted across its whole documented range, including the protocol's own
    /// ceiling on a transaction's output notes.
    #[rstest]
    #[case::one(1)]
    #[case::the_protocol_ceiling(MAX_OUTPUT_NOTES_PER_TX)]
    fn a_supported_note_count_is_accepted(#[case] value: usize) {
        assert_eq!(
            NotesPerTransaction::try_from(value).unwrap().get(),
            value,
            "a supported count must survive the round trip"
        );
    }

    /// A count that would build an empty or over-full transaction is refused.
    #[rstest]
    #[case::zero(0)]
    #[case::past_the_protocol_ceiling(MAX_OUTPUT_NOTES_PER_TX + 1)]
    fn an_unsupported_note_count_is_refused(#[case] value: usize) {
        let error = format!("{:#}", NotesPerTransaction::try_from(value).unwrap_err());
        assert!(
            error.contains("notes per transaction"),
            "unexpected error: {error}"
        );
    }

    /// A count that is not a number is refused where it is parsed, not where it is used.
    #[test]
    fn a_note_count_that_is_not_a_number_is_refused() {
        let error = format!("{:#}", "many".parse::<NotesPerTransaction>().unwrap_err());
        assert!(error.contains("not a number"), "unexpected error: {error}");
    }
}
