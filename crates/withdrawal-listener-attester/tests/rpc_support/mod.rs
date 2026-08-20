//! A programmable [`NodeRpcClient`] — the seam that lets a case drive an ADAPTER rather than only
//! the pure function inside it.
//!
//! # Why this exists
//!
//! Each node-facing adapter is two RPCs and a translation. The translations are pure and are driven
//! directly, but that leaves the WIRING untested: which reply the adapter hands to which
//! translation, and — the part that decides money — whether it RECONCILES a reply or just picks a
//! row out of it. A reply row is chosen inside the adapter, so only the trait can observe it: with
//! the translations tested alone, an adapter could go back to `find(..)`-ing the first matching row
//! and every one of those tests would still pass.
//!
//! So this double answers the reads a case programs, with values the case built, and **panics on
//! every other call**. There is no default answer: an adapter reaching for an RPC a case did not
//! program is a fact the case should state, not something to paper over with an empty `Ok`.
//!
//! It is a transport, not an expectation engine. It records nothing and asserts nothing; the cases
//! do that against what the adapter returns.
//!
//! # What it deliberately cannot reach
//!
//! `SyncTransactions` stays unprogrammable: the client's own `TransactionRecord` carries a
//! `pub(crate)` field, so no code outside `miden-client` can build one. The linkage translation is
//! therefore driven as a pure function, and the gap is a limit of the pinned client rather than a
//! choice made here.

#![allow(dead_code)] // a shared fixture module: each test target uses the subset it needs.

use std::collections::BTreeSet;

use async_trait::async_trait;

use miden_client::rpc::domain::account::{AccountProof, GetAccountRequest};
use miden_client::rpc::domain::account_vault::AccountVaultInfo;
use miden_client::rpc::domain::note::{CommittedNote, FetchedNote, SyncNotesBlock};
use miden_client::rpc::domain::nullifier::NullifierUpdate;
use miden_client::rpc::domain::storage_map::StorageMapInfo;
use miden_client::rpc::domain::sync::{ChainMmrInfo, SyncTarget};
use miden_client::rpc::domain::transaction::TransactionRecord as RpcTransactionRecord;
use miden_client::rpc::encryption::{AttestedTransactionEncryptionKey, SealedTransactionInputs};
use miden_client::rpc::{NetworkNoteStatusInfo, NodeRpcClient, RpcError, RpcLimits, RpcStatusInfo};

use miden_protocol::account::AccountId;
use miden_protocol::address::NetworkId;
use miden_protocol::batch::{ProposedBatch, ProvenBatch};
use miden_protocol::block::{BlockHeader, BlockNumber, FeeParameters, ProvenBlock, ValidatorKeys};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::crypto::merkle::mmr::MmrProof;
use miden_protocol::crypto::merkle::MerklePath;
use miden_protocol::note::{NoteId, NoteScript, NoteTag};
use miden_protocol::transaction::ProvenTransaction;
use miden_protocol::Word;

/// What a case programs for `GetNotesById`: the reply, built fresh per call because
/// [`FetchedNote`] is not `Clone`.
type NotesReply = Box<dyn Fn(&[NoteId]) -> Result<Vec<FetchedNote>, RpcError> + Send + Sync>;

/// What a case programs for `SyncNotes`.
type ScanReply = Box<
    dyn Fn(BlockNumber, BlockNumber, &BTreeSet<NoteTag>) -> Result<Vec<SyncNotesBlock>, RpcError>
        + Send
        + Sync,
>;

/// What a case programs for `SyncNullifiers`.
type SpendReply = Box<
    dyn Fn(&[u16], BlockNumber, BlockNumber) -> Result<Vec<NullifierUpdate>, RpcError>
        + Send
        + Sync,
>;

/// A node that answers only what a case told it to.
#[derive(Default)]
pub struct ScriptedRpc {
    notes: Option<NotesReply>,
    scan: Option<ScanReply>,
    spends: Option<SpendReply>,
    tip: Option<BlockNumber>,
}

impl ScriptedRpc {
    /// A node that answers nothing. Program the reads the case is about; the rest stay panics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Programs `GetNotesById`. The closure sees the ids that were actually asked for, so a case
    /// can answer about a different note — or about one note twice — exactly as a node may.
    pub fn on_get_notes_by_id<F>(mut self, reply: F) -> Self
    where
        F: Fn(&[NoteId]) -> Vec<FetchedNote> + Send + Sync + 'static,
    {
        self.notes = Some(Box::new(move |ids| Ok(reply(ids))));
        self
    }

    /// Programs `SyncNotes`.
    pub fn on_sync_notes<F>(mut self, reply: F) -> Self
    where
        F: Fn(BlockNumber, BlockNumber, &BTreeSet<NoteTag>) -> Vec<SyncNotesBlock>
            + Send
            + Sync
            + 'static,
    {
        self.scan = Some(Box::new(move |from, to, tags| Ok(reply(from, to, tags))));
        self
    }

    /// Programs `SyncNullifiers`.
    pub fn on_sync_nullifiers<F>(mut self, reply: F) -> Self
    where
        F: Fn(&[u16], BlockNumber, BlockNumber) -> Vec<NullifierUpdate> + Send + Sync + 'static,
    {
        self.spends = Some(Box::new(move |prefixes, from, to| {
            Ok(reply(prefixes, from, to))
        }));
        self
    }

    /// Programs the chain tip `GetBlockHeaderByNumber(None)` answers with.
    pub fn with_chain_tip(mut self, block: u32) -> Self {
        self.tip = Some(BlockNumber::from(block));
        self
    }
}

#[async_trait]
impl NodeRpcClient for ScriptedRpc {
    async fn get_notes_by_id(&self, note_ids: &[NoteId]) -> Result<Vec<FetchedNote>, RpcError> {
        let reply = self
            .notes
            .as_ref()
            .expect("this case did not program GetNotesById");
        reply(note_ids)
    }

    async fn sync_notes(
        &self,
        block_from: BlockNumber,
        block_to: BlockNumber,
        note_tags: &BTreeSet<NoteTag>,
    ) -> Result<Vec<SyncNotesBlock>, RpcError> {
        let reply = self
            .scan
            .as_ref()
            .expect("this case did not program SyncNotes");
        reply(block_from, block_to, note_tags)
    }

    async fn sync_nullifiers(
        &self,
        prefix: &[u16],
        block_from: BlockNumber,
        block_to: BlockNumber,
    ) -> Result<Vec<NullifierUpdate>, RpcError> {
        let reply = self
            .spends
            .as_ref()
            .expect("this case did not program SyncNullifiers");
        reply(prefix, block_from, block_to)
    }

    async fn get_block_header_by_number(
        &self,
        block_num: Option<BlockNumber>,
        _include_mmr_proof: bool,
    ) -> Result<(BlockHeader, Option<MmrProof>), RpcError> {
        let tip = self.tip.expect("this case did not program a chain tip");
        Ok((block_header(block_num.unwrap_or(tip)), None))
    }

    // …and nothing else. An adapter that calls one of these is reading something no case
    // programmed, which is a finding about the adapter rather than a gap in the double.

    async fn set_genesis_commitment(&self, _commitment: Word) -> Result<(), RpcError> {
        unimplemented!("SetGenesisCommitment is not part of any read under test")
    }

    fn has_genesis_commitment(&self) -> Option<Word> {
        unimplemented!("the genesis commitment is not part of any read under test")
    }

    async fn get_transaction_encryption_key(
        &self,
    ) -> Result<AttestedTransactionEncryptionKey, RpcError> {
        unimplemented!("GetTransactionEncryptionKey is not part of any read under test")
    }

    async fn submit_proven_transaction(
        &self,
        _proven_transaction: ProvenTransaction,
        _sealed_transaction_inputs: SealedTransactionInputs,
    ) -> Result<BlockNumber, RpcError> {
        unimplemented!("this crate never submits a transaction")
    }

    async fn submit_proven_batch(
        &self,
        _proven_batch: ProvenBatch,
        _proposed_batch: ProposedBatch,
        _transaction_inputs: Vec<SealedTransactionInputs>,
    ) -> Result<BlockNumber, RpcError> {
        unimplemented!("this crate never submits a batch")
    }

    async fn get_block_by_number(
        &self,
        _block_num: BlockNumber,
        _include_proof: bool,
    ) -> Result<ProvenBlock, RpcError> {
        unimplemented!("GetBlockByNumber is not part of any read under test")
    }

    async fn sync_chain_mmr(
        &self,
        _current_block_height: BlockNumber,
        _upper_bound: SyncTarget,
    ) -> Result<ChainMmrInfo, RpcError> {
        unimplemented!("SyncChainMmr is not part of any read under test")
    }

    async fn get_account(
        &self,
        _account_id: AccountId,
        _request: GetAccountRequest,
    ) -> Result<(BlockNumber, AccountProof), RpcError> {
        unimplemented!("GetAccount is not part of any read under test")
    }

    async fn get_note_script_by_root(&self, _root: Word) -> Result<Option<NoteScript>, RpcError> {
        unimplemented!("GetNoteScriptByRoot is not part of any read under test")
    }

    async fn sync_storage_maps(
        &self,
        _block_from: BlockNumber,
        _block_to: BlockNumber,
        _account_id: AccountId,
    ) -> Result<StorageMapInfo, RpcError> {
        unimplemented!("SyncStorageMaps is not part of any read under test")
    }

    async fn sync_account_vault(
        &self,
        _block_from: BlockNumber,
        _block_to: BlockNumber,
        _account_id: AccountId,
    ) -> Result<AccountVaultInfo, RpcError> {
        unimplemented!("SyncAccountVault is not part of any read under test")
    }

    async fn sync_transactions(
        &self,
        _block_from: BlockNumber,
        _block_to: BlockNumber,
        _account_ids: Vec<AccountId>,
    ) -> Result<Vec<RpcTransactionRecord>, RpcError> {
        unimplemented!("this case did not program SyncTransactions")
    }

    async fn get_network_id(&self) -> Result<NetworkId, RpcError> {
        unimplemented!("GetNetworkId is not part of any read under test")
    }

    async fn get_rpc_limits(&self) -> Result<RpcLimits, RpcError> {
        unimplemented!("GetRpcLimits is not part of any read under test")
    }

    fn has_rpc_limits(&self) -> Option<RpcLimits> {
        unimplemented!("the RPC limits are not part of any read under test")
    }

    async fn set_rpc_limits(&self, _limits: RpcLimits) {
        unimplemented!("the RPC limits are not part of any read under test")
    }

    async fn get_status_unversioned(&self) -> Result<RpcStatusInfo, RpcError> {
        unimplemented!("GetStatus is not part of any read under test")
    }

    async fn get_network_note_status(
        &self,
        _note_id: NoteId,
    ) -> Result<NetworkNoteStatusInfo, RpcError> {
        unimplemented!("GetNetworkNoteStatus is not part of any read under test")
    }
}

// THE BLOCK FIXTURES
// ================================================================================================

/// A block header for `block` — the empty roots a case never reads, because nothing in this crate
/// verifies a header. It exists because `SyncNotes` replies and the chain-tip read are shaped around
/// one.
pub fn block_header(block: BlockNumber) -> BlockHeader {
    let validator = SigningKey::new().public_key();

    BlockHeader::new(
        0,
        Word::empty(),
        block,
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        Word::empty(),
        ValidatorKeys::new(vec![validator]).expect("one validator key is a valid set"),
        FeeParameters::new(fee_faucet_id(), 0),
        0,
    )
}

/// One `SyncNotes` block carrying `notes` — the scan reply shape.
pub fn sync_block(block: u32, notes: Vec<CommittedNote>) -> SyncNotesBlock {
    SyncNotesBlock {
        block_header: block_header(BlockNumber::from(block)),
        mmr_path: MerklePath::new(Vec::new()),
        notes: notes
            .into_iter()
            .map(|note| (*note.note_id(), note))
            .collect(),
    }
}

/// A real, parseable faucet id for the header's fee parameters.
fn fee_faucet_id() -> AccountId {
    AccountId::from_hex("0xbb405fd9fe431bd1135a292de098cb").expect("a real, parseable faucet id")
}
