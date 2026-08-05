use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};

use super::{build_admin_note, compile_admin_note_script};

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The administrator-gated `set_attester` admin note. Storage layout: `[pk_commitment(4),
/// enabled]`. Consumed against the faucet network account; `attester_admin::set_attester` gates on
/// the (kernel-forced) note sender through the account-wide authority, resolving to the built-in
/// `ADMIN` role.
pub struct XReserveSetAttesterNote;

impl XReserveSetAttesterNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_set_attester_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        SET_ATTESTER_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to `attester_admin::set_attester`'s
    /// digest; the allowlist row for this note derives from the same compiled script.
    pub fn script_root() -> NoteScriptRoot {
        SET_ATTESTER_NOTE_SCRIPT.root()
    }

    /// Builds a `set_attester` admin note: `commitment` is the attester pubkey commitment (the
    /// xReserveAttesters map key), `enabled` = 1 (allowlist) or 0 (remove).
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        commitment: Word,
        enabled: u8,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![
            commitment[0],
            commitment[1],
            commitment[2],
            commitment[3],
            Felt::from(u32::from(enabled)),
        ];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}
