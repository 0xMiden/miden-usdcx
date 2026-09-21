//! Injectable reads from the Miden chain needed by startup and discovery.

use std::future::Future;
use std::pin::Pin;

use miden_client::grpc_support::DEFAULT_GRPC_TIMEOUT_MS;
use miden_client::rpc::domain::account::GetAccountRequest;
use miden_client::rpc::domain::sync::SyncTarget;
use miden_client::rpc::node::{EndpointError, GetAccountError};
use miden_client::rpc::{
    Endpoint, GrpcClient, GrpcError, NodeRpcClient, RpcEndpoint, RpcError, VerifyingRpcClient,
};
use miden_protocol::account::AccountId;
use miden_protocol::block::{BlockNumber, ProvenBlock};

/// Node-reported limits used only to decide how far a discovery pass may scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub latest_committed_block: BlockNumber,
    /// The latest block at the node's reported proof lag. This is a pacing limit, not proof.
    pub proof_lag_block: BlockNumber,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("Miden node is unavailable")]
    Unavailable,
    #[error("Miden RPC request failed")]
    Rpc(#[source] RpcError),
}

pub trait ChainReader: Send + Sync {
    fn check_connection(&self)
        -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send + '_>>;

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>>;

    fn scan_limits(
        &self,
        last_verified_block: BlockNumber,
    ) -> Pin<Box<dyn Future<Output = Result<ScanLimits, ChainError>> + Send + '_>>;

    fn block_by_number(
        &self,
        block_num: BlockNumber,
    ) -> Pin<Box<dyn Future<Output = Result<ProvenBlock, ChainError>> + Send + '_>>;
}

pub struct MidenChainReader {
    rpc: VerifyingRpcClient<GrpcClient>,
}

impl MidenChainReader {
    pub fn devnet() -> Self {
        let grpc = GrpcClient::new(&Endpoint::devnet(), DEFAULT_GRPC_TIMEOUT_MS);
        Self {
            rpc: VerifyingRpcClient::new(grpc),
        }
    }
}

impl ChainReader for MidenChainReader {
    fn check_connection(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send + '_>> {
        Box::pin(async move {
            self.rpc
                .get_status_unversioned()
                .await
                .map(|_| ())
                .map_err(ChainError::Rpc)
        })
    }

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>> {
        Box::pin(async move {
            match self
                .rpc
                .get_account(*account_id, GetAccountRequest::new())
                .await
            {
                Ok(_) => Ok(true),
                Err(error) if is_missing_account(&error) => Ok(false),
                Err(error) => Err(ChainError::Rpc(error)),
            }
        })
    }

    fn scan_limits(
        &self,
        last_verified_block: BlockNumber,
    ) -> Pin<Box<dyn Future<Output = Result<ScanLimits, ChainError>> + Send + '_>> {
        Box::pin(async move {
            let status = self
                .rpc
                .get_status_unversioned()
                .await
                .map_err(ChainError::Rpc)?;
            // This response supplies a conservative lag boundary only. Discovery authenticates
            // every block it scans instead of treating this endpoint as proof.
            let proven = self
                .rpc
                .sync_chain_mmr(last_verified_block, SyncTarget::ProvenChainTip)
                .await
                .map_err(ChainError::Rpc)?;

            Ok(ScanLimits {
                latest_committed_block: BlockNumber::from(status.chain_tip),
                proof_lag_block: proven.block_to,
            })
        })
    }

    fn block_by_number(
        &self,
        block_num: BlockNumber,
    ) -> Pin<Box<dyn Future<Output = Result<ProvenBlock, ChainError>> + Send + '_>> {
        Box::pin(async move {
            self.rpc
                // Block proofs are not used in this protocol version; the caller authenticates
                // each full block against its already-trusted parent header.
                .get_block_by_number(block_num, false)
                .await
                .map_err(ChainError::Rpc)
        })
    }
}

fn is_missing_account(error: &RpcError) -> bool {
    matches!(
        error.endpoint_error(),
        Some(EndpointError::GetAccount(
            GetAccountError::AccountNotFound | GetAccountError::AccountNotPublic
        ))
    ) || {
        // Devnet currently omits the typed endpoint detail for a missing account.
        matches!(
            error,
            RpcError::RequestError {
                endpoint: RpcEndpoint::GetAccount,
                error_kind: GrpcError::InvalidArgument,
                endpoint_error: None,
                ..
            }
        )
    }
}
