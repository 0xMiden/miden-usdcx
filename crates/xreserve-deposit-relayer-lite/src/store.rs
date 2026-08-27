//! The relayer's entire persistent state: the Circle feed cursor, in one file.
//!
//! There is deliberately no per-deposit ledger. The cursor only advances after a page's mint
//! transaction is on chain, so a crash replays at most one page — and the faucet's on-chain
//! `usedNonces` assert refuses the replayed mints. Losing the file entirely is likewise safe,
//! just slow: the next run re-scans the feed from the beginning and the chain absorbs every
//! duplicate.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// The persisted `pageAfter` cursor.
#[derive(Debug)]
pub struct CursorStore {
    path: PathBuf,
}

impl CursorStore {
    /// A store over the file at `path`. The file need not exist yet.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Where the last completed scan got to, or `None` on a first run.
    pub fn cursor(&self) -> Result<Option<String>> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                let cursor = text.trim();
                Ok((!cursor.is_empty()).then(|| cursor.to_string()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("reading the cursor at `{}`", self.path.display())),
        }
    }

    /// Durably replaces the cursor: write a sibling temp file, fsync, rename. `rename(2)` is
    /// atomic on POSIX, so a crash leaves either the old cursor or the new one, never a torn one.
    pub fn set_cursor(&self, page_after: &str) -> Result<()> {
        let tmp = self.path.with_extension("tmp");

        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("creating the temporary cursor at `{}`", tmp.display()))?;
        file.write_all(page_after.as_bytes())
            .with_context(|| format!("writing the temporary cursor at `{}`", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing the temporary cursor at `{}`", tmp.display()))?;
        fs::rename(&tmp, &self.path).with_context(|| {
            format!(
                "replacing the cursor at `{}` with `{}`",
                self.path.display(),
                tmp.display()
            )
        })
    }
}
