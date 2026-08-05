//! The `set_max_supply` admin note factory.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Felt;

use super::{build_admin_note, compile_admin_note_script};

const SET_MAX_SUPPLY_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_max_supply_note.masm");

static SET_MAX_SUPPLY_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MAX_SUPPLY_NOTE_SCRIPT_SRC));

/// The administrator-gated stock `set_max_supply` admin note. Storage layout:
/// `[new_max_supply]`. The stock setter resolves through the account-wide authority to the built-in
/// `ADMIN` role, which is account-bound and is the faucet's only authority handle.
pub struct XReserveSetMaxSupplyNote;

impl XReserveSetMaxSupplyNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MAX_SUPPLY_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to the stock
    /// `fungible::set_max_supply`'s digest; the allowlist row for this note derives from the same
    /// compiled script.
    pub fn script_root() -> NoteScriptRoot {
        SET_MAX_SUPPLY_NOTE_SCRIPT.root()
    }

    /// Builds a `set_max_supply` admin note: `sender` is the admin party (an `ADMIN` role holder,
    /// for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_max_supply` the new cap. The param lives in note
    /// storage.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_max_supply: u64,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let cap_felt = Felt::try_from(new_max_supply)
            .map_err(|e| NoteError::other_with_source("max supply exceeds the field modulus", e))?;
        build_admin_note(sender, faucet_id, Self::script(), vec![cap_felt], rng)
    }
}
