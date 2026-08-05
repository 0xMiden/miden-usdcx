//! The `set_min_burn_size` admin note factory.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Felt;

use super::{build_admin_note, compile_admin_note_script};

const SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_min_burn_size_note.masm");

static SET_MIN_BURN_SIZE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC));

/// The administrator-gated `set_min_burn_size` admin note. Storage layout: `[new_min]` with
/// `new_min >= 1` (the note script's zero-floor guard — the stock setter itself accepts 0). The
/// stock setter it targets resolves through the account-wide authority to the built-in `ADMIN` role,
/// which is account-bound and is the faucet's only authority handle.
pub struct XReserveSetMinBurnSizeNote;

impl XReserveSetMinBurnSizeNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to the stock
    /// `min_burn_amount::set_min_burn_amount`'s digest plus the note-side zero-floor guard; the
    /// allowlist row for this note derives from the same compiled script.
    pub fn script_root() -> NoteScriptRoot {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.root()
    }

    /// Builds a `set_min_burn_size` admin note: `sender` is the admin party (an `ADMIN` role
    /// holder, for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_min` the new minimum burn size. The param lives in
    /// note storage.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_min: u64,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let new_min_felt = Felt::try_from(new_min).map_err(|e| {
            NoteError::other_with_source("min burn size exceeds the field modulus", e)
        })?;
        build_admin_note(sender, faucet_id, Self::script(), vec![new_min_felt], rng)
    }
}
