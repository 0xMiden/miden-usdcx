//! Durable scan cursor and the single-writer store boundary.

use std::path::Path;

use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ScanCursor {
    /// The exact next block included in the next scan.
    pub(crate) next_block: BlockNumber,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum StoreError {
    Invalid,
    Locked,
}

#[allow(dead_code)]
pub(crate) struct Store {
    connection: rusqlite::Connection,
    writer_lock: StoreLock,
}

#[derive(Debug)]
struct StoreLock;

#[allow(dead_code, unused_variables)]
impl Store {
    pub(crate) fn open_or_create(
        path: &Path,
        faucet_account_id: AccountId,
        fallback_cursor: ScanCursor,
    ) -> Result<Self, StoreError> {
        todo!()
    }

    pub(crate) fn scan_cursor(&self) -> Result<ScanCursor, StoreError> {
        todo!()
    }
}
