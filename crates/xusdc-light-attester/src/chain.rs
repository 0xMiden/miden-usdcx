//! Injectable reads from the Miden chain needed during startup.

use std::future::Future;
use std::pin::Pin;

use miden_protocol::account::AccountId;

#[derive(Debug)]
pub struct ChainError;

pub trait ChainReader: Send + Sync {
    fn check_connection(&self)
        -> Pin<Box<dyn Future<Output = Result<(), ChainError>> + Send + '_>>;

    fn account_exists<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ChainError>> + Send + 'a>>;
}
