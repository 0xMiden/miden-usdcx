use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::{
    BlockBody, BlockHeader, BlockNumber, BlockProof, BlockSignatures, FeeParameters, ProvenBlock,
    ValidatorKeys,
};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachments, NoteId, NoteRecipient, NoteScript,
    NoteStorage, NoteTag, NoteType, Nullifier, PartialNoteMetadata,
};
use miden_protocol::testing::validator_keys::{random_validator_set, sign_all};
use miden_protocol::transaction::{
    InputNoteCommitment, InputNotes, OrderedTransactionHeaders, OutputNote, PublicOutputNote,
    RawOutputNote, TransactionHeader,
};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::{Felt, Word};
use miden_standards::note::{BurnNote, NetworkAccountTarget, NoteExecutionHint};
use reqwest::{header::HeaderMap, Method, StatusCode};
use xusdc_encoding::note::xreserve_burn::XUsdcBurnAttachment;
use xusdc_encoding::xreserve::encoding::{ForeignChainAddress, XReserveBurnItems};

use crate::chain::{ChainError, ChainReader, ScanLimits};
use crate::circle::{CircleError, HttpTransport, RawResponse};
use crate::signer::{DevelopmentSigner, Signer};

pub(super) const FAUCET_ACCOUNT_ID: &str = "0xbb405fd9fe431bd1135a292de098cb";

pub(super) fn faucet_account_id() -> AccountId {
    AccountId::from_hex(FAUCET_ACCOUNT_ID).unwrap()
}

pub(super) fn development_signers() -> [Box<dyn Signer>; 2] {
    [1, 2].map(|scalar| {
        let mut key = [0; 32];
        key[31] = scalar;
        Box::new(DevelopmentSigner::from_bytes(key).unwrap()) as Box<dyn Signer>
    })
}

pub(super) fn scan_limits(latest_committed_block: u32, proof_lag_block: u32) -> ScanLimits {
    ScanLimits {
        latest_committed_block: BlockNumber::from(latest_committed_block),
        proof_lag_block: BlockNumber::from(proof_lag_block),
    }
}

/// The one fake [`ChainReader`] for the whole suite.
///
/// It serves blocks from a fixed vector and records what was asked for. The builder methods cover
/// the failure modes: an unreachable node, a faucet that is not on chain, and a single height the
/// node refuses to serve. Keeping one fake means both test files exercise the same model of the
/// chain, so a behaviour proved in one file still holds in the other.
pub(super) struct TestChain {
    blocks: Vec<ProvenBlock>,
    scan_limits: Arc<Mutex<ScanLimits>>,
    requests: Arc<Mutex<Vec<BlockNumber>>>,
    scan_limit_requests: Arc<Mutex<usize>>,
    missing: Option<BlockNumber>,
    reachable: bool,
    faucet_present: bool,
}

pub(super) struct ChainControls {
    pub(super) scan_limits: Arc<Mutex<ScanLimits>>,
    pub(super) requests: Arc<Mutex<Vec<BlockNumber>>>,
    pub(super) scan_limit_requests: Arc<Mutex<usize>>,
}

impl TestChain {
    pub(super) fn new(blocks: Vec<ProvenBlock>, scan_limits: ScanLimits) -> (Self, ChainControls) {
        let scan_limits = Arc::new(Mutex::new(scan_limits));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let scan_limit_requests = Arc::new(Mutex::new(0));
        (
            Self {
                blocks,
                scan_limits: Arc::clone(&scan_limits),
                requests: Arc::clone(&requests),
                scan_limit_requests: Arc::clone(&scan_limit_requests),
                missing: None,
                reachable: true,
                faucet_present: true,
            },
            ChainControls {
                scan_limits,
                requests,
                scan_limit_requests,
            },
        )
    }

    /// A chain serving only the startup anchor at genesis, which is all the preflight tests read.
    pub(super) fn anchor_only() -> Self {
        Self::new(vec![startup_anchor().clone()], scan_limits(0, 0)).0
    }

    pub(super) fn missing_at(mut self, block_num: u32) -> Self {
        self.missing = Some(BlockNumber::from(block_num));
        self
    }

    pub(super) fn unreachable(mut self) -> Self {
        self.reachable = false;
        self
    }

    pub(super) fn faucet_missing(mut self) -> Self {
        self.faucet_present = false;
        self
    }
}

impl ChainReader for TestChain {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send + '_>> {
        let reachable = self.reachable;
        Box::pin(async move {
            if reachable {
                Ok(())
            } else {
                Err(ChainError::Unavailable)
            }
        })
    }

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>> {
        Box::pin(async move { Ok(*account_id == faucet_account_id() && self.faucet_present) })
    }

    fn scan_limits(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ScanLimits, ChainError>> + Send + '_>> {
        *self.scan_limit_requests.lock().unwrap() += 1;
        let scan_limits = *self.scan_limits.lock().unwrap();
        Box::pin(async move { Ok(scan_limits) })
    }

    fn block_by_number(
        &self,
        block_num: BlockNumber,
    ) -> Pin<Box<dyn Future<Output = Result<ProvenBlock, ChainError>> + Send + '_>> {
        self.requests.lock().unwrap().push(block_num);
        let result = if self.missing == Some(block_num) {
            Err(ChainError::Unavailable)
        } else {
            self.blocks
                .get(block_num.as_usize())
                .cloned()
                .ok_or(ChainError::Unavailable)
        };
        Box::pin(async move { result })
    }
}

#[derive(Clone)]
pub(super) enum CircleState {
    Response(StatusCode),
    ResponseBody(StatusCode, Vec<u8>),
    TransportError,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ObservedRequest {
    pub(super) method: Method,
    pub(super) url: String,
    pub(super) timeout: Option<Duration>,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

pub(super) struct FakeCircle {
    state: CircleState,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}

impl FakeCircle {
    pub(super) fn new(state: CircleState) -> (Self, Arc<Mutex<Vec<ObservedRequest>>>) {
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
            headers: request.headers().clone(),
            body: request
                .body()
                .map(|body| {
                    body.as_bytes()
                        .expect("test requests have buffered bodies")
                        .to_vec()
                })
                .unwrap_or_default(),
        });
        let state = self.state.clone();
        Box::pin(async move {
            match state {
                CircleState::Response(status) => Ok(RawResponse::new(status, Vec::new())),
                CircleState::ResponseBody(status, body) => Ok(RawResponse::new(status, body)),
                CircleState::TransportError => Err(CircleError::Unavailable),
            }
        })
    }
}

pub(super) fn ready_circle() -> Box<dyn HttpTransport> {
    let (circle, _) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    Box::new(circle)
}

pub(super) struct TestNote {
    pub(super) id: NoteId,
    pub(super) nullifier: Nullifier,
    pub(super) public_note: Option<PublicOutputNote>,
    pub(super) output: OutputNote,
}

pub(super) struct BlockFactory {
    faucet_account_id: AccountId,
    signers: Vec<SigningKey>,
    validator_keys: ValidatorKeys,
    blocks: Vec<ProvenBlock>,
}

impl BlockFactory {
    pub(super) fn new(faucet_account_id: AccountId) -> Self {
        let (signers, validator_keys) = random_validator_set(1);
        Self {
            faucet_account_id,
            signers,
            validator_keys,
            blocks: Vec::new(),
        }
    }

    pub(super) fn push(
        &mut self,
        output_notes: Vec<OutputNote>,
        transactions: Vec<TransactionHeader>,
    ) -> ProvenBlock {
        let block_num = BlockNumber::from(self.blocks.len() as u32);
        let output_note_batches = if output_notes.is_empty() {
            Vec::new()
        } else {
            vec![output_notes.into_iter().enumerate().collect()]
        };
        let body = BlockBody::new_unchecked(
            Vec::new(),
            output_note_batches,
            Vec::new(),
            OrderedTransactionHeaders::new_unchecked(transactions),
        );
        let previous = self.blocks.last();
        let header = BlockHeader::new(
            0,
            previous.map_or(Word::empty(), |block| block.header().commitment()),
            block_num,
            Word::empty(),
            Word::empty(),
            Word::empty(),
            body.compute_block_note_tree().root(),
            body.transactions().commitment(),
            Word::empty(),
            self.validator_keys.clone(),
            FeeParameters::new(self.faucet_account_id, 0),
            block_num.as_u32(),
        );
        let signatures = previous.map_or_else(
            || BlockSignatures::new(Vec::new()).unwrap(),
            |parent| {
                sign_all(
                    parent.header().validator_keys(),
                    &self.signers,
                    header.commitment(),
                )
            },
        );
        let block = ProvenBlock::new_unchecked(header, body, signatures, BlockProof::new_dummy());
        self.blocks.push(block.clone());
        block
    }

    pub(super) fn blocks(&self) -> Vec<ProvenBlock> {
        self.blocks.clone()
    }
}

pub(super) fn note(script: NoteScript, note_type: NoteType, tag: u32, serial: u64) -> TestNote {
    let note = if script.root() == BurnNote::script_root() {
        let asset = FungibleAsset::new(faucet_account_id(), 100).unwrap();
        Note::with_attachments(
            NoteAssets::new(vec![asset.into()]).unwrap(),
            PartialNoteMetadata::new(faucet_account_id(), note_type).with_tag(NoteTag::new(tag)),
            NoteRecipient::new(
                word(serial),
                script,
                NoteStorage::new(Asset::Fungible(asset).as_elements().to_vec()).unwrap(),
            ),
            NoteAttachments::new(vec![
                NoteAttachment::from(
                    NetworkAccountTarget::new(faucet_account_id(), NoteExecutionHint::Always)
                        .unwrap(),
                ),
                NoteAttachment::from(&XUsdcBurnAttachment::new(XReserveBurnItems {
                    dest_domain: 9,
                    dest_recipient: ForeignChainAddress::new([serial as u8; 32]),
                })),
            ])
            .unwrap(),
        )
    } else {
        Note::new(
            NoteAssets::default(),
            PartialNoteMetadata::new(faucet_account_id(), note_type).with_tag(NoteTag::new(tag)),
            NoteRecipient::new(word(serial), script, NoteStorage::default()),
        )
    };
    test_note(note)
}

pub(super) fn test_note(note: Note) -> TestNote {
    let id = note.id();
    let nullifier = note.nullifier();
    let output = RawOutputNote::Full(note).into_output_note().unwrap();
    let public_note = match &output {
        OutputNote::Public(note) => Some(note.clone()),
        OutputNote::Private(_) => None,
    };
    TestNote {
        id,
        nullifier,
        public_note,
        output,
    }
}

pub(super) fn transaction(account_id: AccountId, nullifiers: &[Nullifier]) -> TransactionHeader {
    TransactionHeader::new(
        account_id,
        Word::empty(),
        word(nullifiers.len() as u64 + 1),
        InputNotes::new(
            nullifiers
                .iter()
                .copied()
                .map(InputNoteCommitment::from)
                .collect(),
        )
        .unwrap(),
        Vec::new(),
    )
}

pub(super) fn word(value: u64) -> Word {
    Word::new([
        Felt::new(value).unwrap(),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ])
}

pub(super) fn startup_anchor() -> &'static ProvenBlock {
    static ANCHOR: LazyLock<ProvenBlock> = LazyLock::new(|| {
        // The lock test starts a second process; both processes must serve the same test anchor.
        let signer = SigningKey::read_from_bytes(&[1; 32]).unwrap();
        let mut factory = BlockFactory {
            faucet_account_id: faucet_account_id(),
            validator_keys: ValidatorKeys::new(vec![signer.public_key()]).unwrap(),
            signers: vec![signer],
            blocks: Vec::new(),
        };
        factory.push(Vec::new(), Vec::new())
    });
    &ANCHOR
}
