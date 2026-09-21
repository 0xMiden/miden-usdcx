//! Injectable reads from the Miden chain needed during startup.

use std::future::Future;
use std::pin::Pin;

use miden_client::grpc_support::DEFAULT_GRPC_TIMEOUT_MS;
use miden_client::rpc::domain::account::GetAccountRequest;
use miden_client::rpc::node::{EndpointError, GetAccountError};
use miden_client::rpc::{
    Endpoint, GrpcClient, GrpcError, NodeRpcClient, RpcEndpoint, RpcError, VerifyingRpcClient,
};
use miden_protocol::account::AccountId;

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
