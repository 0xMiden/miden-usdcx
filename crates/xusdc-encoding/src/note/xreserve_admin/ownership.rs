//! Ownable2Step admin note factories: `transfer_ownership`, `accept_ownership`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Word;

use super::{build_admin_note, compile_admin_note_script};

// TRANSFER_OWNERSHIP
// ================================================================================================

const TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_transfer_ownership_note.masm");

static TRANSFER_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The PINNED transfer_ownership admin note-script root: binds transitively to the stock
/// `ownable2step::transfer_ownership`'s digest.
pub const XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x5bd39b30a487d6a385acd220c43a82980e63cfe37ba4d86efd58ffbd7a6c7c0a";

/// The current-owner-gated `transfer_ownership` admin note — step one of the two-step handover.
/// Storage layout: `[new_owner_suffix, new_owner_prefix]`.
pub struct XReserveTransferOwnershipNote;

impl XReserveTransferOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned transfer_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds a `transfer_ownership` admin note: `sender` is the current owner (for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_owner` the nominated owner. The params live in
    /// note storage.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_owner: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![new_owner.suffix(), new_owner.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}

// ACCEPT_OWNERSHIP
// ================================================================================================

const ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_accept_ownership_note.masm");

static ACCEPT_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The pinned `accept_ownership` note-script root, which binds transitively to the digest of the
/// standard `ownable2step::accept_ownership` it calls.
///
/// Accepting with no nomination outstanding rejects on the sender-versus-nominated-owner compare:
/// a note sender is never the zero address, so an unset nomination can never match.
pub const XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xbd3521ade61e55d119662701fb02c171177a698711ac1a1bfd7ae36f839152c1";

/// The nominated-owner-gated, parameter-less `accept_ownership` admin note — step two of the
/// two-step transfer.
pub struct XReserveAcceptOwnershipNote;

impl XReserveAcceptOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned accept_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds an `accept_ownership` admin note (param-less): `sender` is the nominated (pending) owner
    /// (for success), `faucet_id` the target faucet (PUBLIC). Carries no storage payload.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}
