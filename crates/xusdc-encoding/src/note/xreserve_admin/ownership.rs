//! Ownable2Step admin note factories: `transfer_ownership`, `accept_ownership`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Word;

use super::{build_admin_note, compile_admin_note_script};

// TRANSFER_OWNERSHIP (allowlist row 10)
// ================================================================================================

const TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_transfer_ownership_note.masm");

static TRANSFER_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The PINNED transfer_ownership admin note-script root (`masm-rust-constant-parity`): binds
/// transitively to the stock `ownable2step::transfer_ownership`'s digest.
pub const XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x5bd39b30a487d6a385acd220c43a82980e63cfe37ba4d86efd58ffbd7a6c7c0a";

/// The current-owner-gated stock `transfer_ownership` admin note (F5, step 1 of the 2-step transfer).
/// Storage layout: `[new_owner_suffix, new_owner_prefix]`.
pub struct XReserveTransferOwnershipNote;

impl XReserveTransferOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 10). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned transfer_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds a `transfer_ownership` admin note: `sender` is the current owner (for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_owner` the nominated owner. The params live in
    /// note storage; NOTE_ARGS are ignored.
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

// ACCEPT_OWNERSHIP (allowlist row 11)
// ================================================================================================

const ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_accept_ownership_note.masm");

static ACCEPT_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The PINNED accept_ownership admin note-script root (`masm-rust-constant-parity`): binds
/// transitively to the stock `ownable2step::accept_ownership`'s digest.
pub const XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x4480f83f0c08d6c0d7e3480c62f0dc296a29489fd631ce78615bacb017352104";

/// The nominated-owner-gated, PARAM-LESS stock `accept_ownership` admin note (F5, step 2 of the
/// 2-step transfer).
pub struct XReserveAcceptOwnershipNote;

impl XReserveAcceptOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 11). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned accept_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds an `accept_ownership` admin note (param-less): `sender` is the nominated (pending) owner
    /// (for success), `faucet_id` the target faucet (PUBLIC). Carries no storage payload; NOTE_ARGS
    /// are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}
