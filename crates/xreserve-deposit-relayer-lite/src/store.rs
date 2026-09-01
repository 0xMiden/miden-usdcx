//! The relayer's entire persistent state: the Circle feed cursor, in one file.
//!
//! There is deliberately no per-deposit ledger. The cursor only advances after a page's mint
//! transaction is on chain, so a crash replays at most one page — and the faucet's on-chain
//! `usedNonces` assert refuses the replayed mints. Losing the file entirely is likewise safe,
//! just slow: the cursor is a Circle pagination token that never appears on chain, so it cannot
//! be rebuilt from chain state — the next run re-scans the feed from the beginning and the chain
//! absorbs every duplicate.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Circle's opaque `pageAfter` pagination token, held exactly as the feed returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircleCursor(String);

impl CircleCursor {
    /// Wraps a token taken verbatim from a Circle feed response.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The token, ready to be sent back as the `pageAfter` query parameter.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The store holding the persisted [`CircleCursor`].
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// A store over the file at `path`. The file need not exist yet.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Where the last completed scan got to, or `None` on a first run.
    pub fn cursor(&self) -> Result<Option<CircleCursor>> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                let cursor = text.trim();
                Ok((!cursor.is_empty()).then(|| CircleCursor::new(cursor)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("reading the cursor at `{}`", self.path.display())),
        }
    }

    /// Durably replaces the cursor: after this returns, a crash leaves either the old cursor or
    /// the new one on disk, never a torn one.
    pub fn set_cursor(&self, cursor: &CircleCursor) -> Result<()> {
        // Write a sibling temp file, fsync it, then rename over the real file. The rename is atomic
        // on the POSIX hosts this binary targets, which is what rules out the torn state.
        let tmp = self.path.with_extension("tmp");

        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("creating the temporary cursor at `{}`", tmp.display()))?;
        file.write_all(cursor.as_str().as_bytes())
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

#[cfg(test)]
mod tests {
    use super::{CircleCursor, Store};

    /// What was written survives the handle being dropped and the file reopened.
    #[test]
    fn the_cursor_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor");

        Store::new(path.clone())
            .set_cursor(&CircleCursor::new("page-2"))
            .unwrap();

        let reopened = Store::new(path);
        assert_eq!(
            reopened.cursor().unwrap(),
            Some(CircleCursor::new("page-2"))
        );
    }

    /// A first run reads `None`, not an error.
    #[test]
    fn a_first_run_has_no_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("cursor"));
        assert_eq!(store.cursor().unwrap(), None);
    }

    /// The newest write wins — the file holds one value, not a history.
    #[test]
    fn the_cursor_is_replaced_not_appended() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("cursor"));

        store.set_cursor(&CircleCursor::new("first")).unwrap();
        store.set_cursor(&CircleCursor::new("second")).unwrap();

        assert_eq!(store.cursor().unwrap(), Some(CircleCursor::new("second")));
    }
}
