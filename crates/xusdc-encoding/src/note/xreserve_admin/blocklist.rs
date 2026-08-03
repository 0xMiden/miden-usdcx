//! The transfer-blocklist admin note: the standard blocklist config note, constrained so the
//! faucet cannot be blocked against itself.
//!
//! The note itself is entirely standard — one script root covering both actions, dispatched on a
//! selector in note storage, calling the standard blocklist manager's `block_account` /
//! `unblock_account`, which authorize the note sender through the account-wide authority. Nothing
//! about it is faucet-specific and nothing here reimplements it: the standard [`BlocklistConfigNote`]
//! supplies the script, its root, and the builder directly, and the allowlist and callable-surface
//! checks use it as-is.
//!
//! What is faucet-specific is which notes are worth creating. The blocklist is the faucet's active
//! send and receive transfer policy, so blocking the faucet's own id would freeze it as a transfer
//! party: minting-and-sending and receiving-and-burning would both trap, halting the core function.
//! The standard block procedure validates nothing about its target, so [`block_note`] refuses to
//! build such a note in the first place — the one guard the standard note cannot express.
//!
//! That refusal is a guard against operator error, not an authorization boundary. The blocklist
//! administrator holds the role and can assemble the standard note directly, past this guard —
//! recovery in that case is an unblock note, which carries no assets and so lands even while the
//! faucet is blocked against itself. Unblocking is always allowed here, because unblocking the
//! faucet is exactly how that state is undone.

use core::fmt;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::Note;
use miden_standards::note::{BlocklistConfig, BlocklistConfigNote};

/// Why a blocklist admin note could not be built.
#[derive(Debug)]
#[non_exhaustive]
pub enum XReserveBlocklistNoteError {
    /// The note would have blocked the faucet itself, freezing it as a transfer party.
    SelfBlockRejected { faucet_id: AccountId },
    /// The standard note could not be assembled.
    Note(NoteError),
}

impl fmt::Display for XReserveBlocklistNoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfBlockRejected { faucet_id } => write!(
                f,
                "refusing to build a note that blocks the faucet's own account {faucet_id}; the \
                 blocklist is the faucet's active send and receive transfer policy, so blocking it \
                 would freeze it as a transfer party and halt both minting and redeeming"
            ),
            Self::Note(_) => write!(f, "the standard blocklist config note could not be built"),
        }
    }
}

impl core::error::Error for XReserveBlocklistNoteError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Note(source) => Some(source),
            Self::SelfBlockRejected { .. } => None,
        }
    }
}

impl From<NoteError> for XReserveBlocklistNoteError {
    fn from(source: NoteError) -> Self {
        Self::Note(source)
    }
}

/// Builds a note that adds `account` to `faucet_id`'s transfer blocklist over the standard
/// [`BlocklistConfigNote`].
///
/// Both actions ride one script root, so the note-script allowlist carries a single entry for
/// blocking and unblocking alike. The blocklist administrator role gates them: the note sender is
/// kernel-forced, and the standard manager resolves that sender against the role the faucet's
/// procedure-role map assigns to each procedure.
///
/// # Errors
///
/// Returns [`XReserveBlocklistNoteError::SelfBlockRejected`] if `account` is `faucet_id`:
/// blocking the faucet freezes it as a transfer party. Returns
/// [`XReserveBlocklistNoteError::Note`] if the standard note cannot be assembled.
pub fn block_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    account: AccountId,
    rng: &mut R,
) -> Result<Note, XReserveBlocklistNoteError> {
    if account == faucet_id {
        return Err(XReserveBlocklistNoteError::SelfBlockRejected { faucet_id });
    }
    build_blocklist_note(
        sender,
        faucet_id,
        BlocklistConfig::BlockAccount { account },
        rng,
    )
}

/// Builds a note that removes `account` from `faucet_id`'s transfer blocklist over the standard
/// [`BlocklistConfigNote`].
///
/// Unblocking the faucet itself is permitted — it is the recovery path from a self-block that was
/// assembled past [`block_note`].
///
/// # Errors
///
/// Returns [`XReserveBlocklistNoteError::Note`] if the standard note cannot be assembled.
pub fn unblock_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    account: AccountId,
    rng: &mut R,
) -> Result<Note, XReserveBlocklistNoteError> {
    build_blocklist_note(
        sender,
        faucet_id,
        BlocklistConfig::UnblockAccount { account },
        rng,
    )
}

/// Assembles the standard [`BlocklistConfigNote`] for `config`, tagged for the faucet and sent by
/// `sender`.
fn build_blocklist_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    config: BlocklistConfig,
    rng: &mut R,
) -> Result<Note, XReserveBlocklistNoteError> {
    let note = BlocklistConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(rng)
        .build()
        .map_err(XReserveBlocklistNoteError::Note)?;
    Ok(Note::from(note))
}
