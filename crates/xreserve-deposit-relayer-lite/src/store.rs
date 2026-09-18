//! The relayer's whole persistent state: how far the scan of the Circle feed got, in one file.
//!
//! The **watermark** is the newest attestation the last completed scan handled, and so where the
//! next scan stops. It is never sent to Circle: `pageAfter` addresses the entries *older* than the
//! one it names, the wrong way round for a feed that grows at its head. Nothing is lost by it
//! being a stop condition instead — Circle builds its tokens from an entry's attestation time and
//! message hash, so a token names an attestation just as the watermark does, and the walk covers
//! the same pages either way.
//!
//! The **scan progress** is what an unfinished scan leaves behind, so that a restart part way
//! through a backlog neither re-fetches nor re-mints the pages that already landed. A pass runs in
//! one direction, so how far it got is a point rather than a set, and a `pageAfter` token names
//! that point — built from an entry, it is unmoved by deposits arriving at the head meanwhile.
//! What it cannot carry is where the pass started, which the head has moved on from by the end, so
//! [`ScanProgress`] records that too. Both are dropped once the watermark takes over.
//!
//! There is deliberately no per-deposit ledger. Progress advances only once a page's mints are on
//! chain, so a crash replays at most the page in flight, and the faucet's `usedNonces` assert
//! refuses those. Losing the file is safe too, just slow: the next scan runs to the oldest entry
//! in the feed and the chain absorbs every duplicate.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::circle::{CircleCursor, MessageHash};

/// Everything the relayer carries from one poll to the next.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    /// The newest attestation the last completed scan handled, and so where the next scan stops.
    ///
    /// `None` means no scan has ever finished, and the next one runs to the oldest entry in the
    /// feed.
    pub watermark: Option<MessageHash>,

    /// The scan that has not finished, if there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanProgress>,
}

/// How far a scan got before it was interrupted, so the next poll resumes rather than starts over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    /// The head of the feed when this scan started, which becomes the watermark once it finishes.
    ///
    /// It is recorded rather than recomputed at the end because by then the head has moved on, and
    /// the deposits that arrived in the meantime belong to the scan after this one.
    pub head: MessageHash,

    /// The page this scan resumes at: the cursor of the page after the last one whose mint
    /// transactions reached the chain. Every page above it is minted.
    pub resume: CircleCursor,
}

/// The store holding the persisted [`State`].
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    /// A store over the file at `path`. The file need not exist yet.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The state the last poll left behind, or an empty state on a first run.
    ///
    /// # Errors
    ///
    /// - The file cannot be read.
    /// - The file is not the state this relayer writes. It is not treated as a first run, because
    ///   that would silently re-mint the whole feed.
    pub fn state(&self) -> Result<State> {
        match fs::read_to_string(&self.path) {
            Ok(text) if text.trim().is_empty() => Ok(State::default()),
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("reading the state at `{}`", self.path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(error) => Err(error)
                .with_context(|| format!("reading the state at `{}`", self.path.display())),
        }
    }

    /// Durably replaces the state: after this returns, a crash leaves either the old state or the
    /// new one on disk, never a torn one.
    ///
    /// # Errors
    ///
    /// - The file cannot be written, synced or renamed into place.
    pub fn set_state(&self, state: &State) -> Result<()> {
        // Write a sibling temp file, fsync it, then rename over the real file. The rename is atomic
        // on the POSIX hosts this binary targets, which is what rules out the torn state.
        let tmp = self.path.with_extension("tmp");
        // Pretty, because an operator reading this file is reading it to find out where the relayer
        // thinks it is.
        let encoded =
            serde_json::to_vec_pretty(state).context("encoding the state the relayer reached")?;

        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("creating the temporary state at `{}`", tmp.display()))?;
        file.write_all(&encoded)
            .with_context(|| format!("writing the temporary state at `{}`", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing the temporary state at `{}`", tmp.display()))?;
        fs::rename(&tmp, &self.path).with_context(|| {
            format!(
                "replacing the state at `{}` with `{}`",
                self.path.display(),
                tmp.display()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanProgress, State, Store};
    use crate::circle::{CircleCursor, MessageHash};

    /// A state holding both a finished scan's watermark and an unfinished scan's progress.
    fn in_progress() -> State {
        State {
            watermark: Some(MessageHash::new([0x11; 32])),
            scan: Some(ScanProgress {
                head: MessageHash::new([0x22; 32]),
                resume: CircleCursor::new("page-2"),
            }),
        }
    }

    /// A store over a fresh file that the test owns.
    fn store(dir: &tempfile::TempDir) -> Store {
        Store::new(dir.path().join("state"))
    }

    /// What was written survives the handle being dropped and the file reopened, so a restart part
    /// way through a backlog resumes at the page it stopped at.
    #[test]
    fn the_progress_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        store(&dir).set_state(&in_progress()).unwrap();

        assert_eq!(store(&dir).state().unwrap(), in_progress());
    }

    /// A first run reads an empty state, not an error.
    #[test]
    fn a_first_run_has_no_state() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(store(&dir).state().unwrap(), State::default());
    }

    /// The newest write wins — the file holds one state, not a history.
    #[test]
    fn the_state_is_replaced_not_appended() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);

        store.set_state(&in_progress()).unwrap();
        let finished = State {
            watermark: Some(MessageHash::new([0x22; 32])),
            scan: None,
        };
        store.set_state(&finished).unwrap();

        assert_eq!(store.state().unwrap(), finished);
    }

    /// A file that is not this relayer's state is an error rather than a first run, which would
    /// re-mint the whole feed.
    #[test]
    fn an_unreadable_state_is_not_a_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        std::fs::write(dir.path().join("state"), "not the state").unwrap();

        let error = format!("{:#}", store.state().unwrap_err());
        assert!(error.contains("reading the state"), "unexpected: {error}");
    }
}
