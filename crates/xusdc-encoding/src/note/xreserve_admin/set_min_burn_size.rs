use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::Felt;

use super::build_admin_note;
use crate::xreserve_lib::note_script;

static SET_MIN_BURN_SIZE_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    note_script(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/notes/xreserve-set-min-burn-size-note.masp"
    )))
});

/// The dedicated `set_min_burn_size` note-storage type: the single `[new_min]` item, built with a
/// `bon` builder (`XReserveSetMinBurnSizeNoteStorage::builder().new_min(..).build()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct XReserveSetMinBurnSizeNoteStorage {
    new_min: u64,
}

impl XReserveSetMinBurnSizeNoteStorage {
    /// The `NoteStorage.items` felt count: `[new_min]`.
    pub const NUM_ITEMS: usize = 1;

    /// The new minimum burn size (`new_min >= 1`; the note script enforces the zero floor).
    pub fn new_min(&self) -> u64 {
        self.new_min
    }

    /// The single `[new_min]` felt item. Errors if `new_min` exceeds the field modulus.
    fn into_items(self) -> Result<Vec<Felt>, NoteError> {
        let felt = Felt::try_from(self.new_min).map_err(|e| {
            NoteError::other_with_source("min burn size exceeds the field modulus", e)
        })?;
        Ok(vec![felt])
    }
}

/// The administrator-gated `set_min_burn_size` admin note. Storage layout: `[new_min]` with
/// `new_min >= 1` (the note script's zero-floor guard — the stock setter itself accepts 0). The
/// stock setter it targets resolves through the account-wide authority to the built-in `ADMIN`
/// role.
pub struct XReserveSetMinBurnSizeNote;

#[bon::bon]
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

    /// Builds a `set_min_burn_size` admin note via a `bon` builder: `sender` the admin party,
    /// `faucet_id` the target faucet (PUBLIC), `storage` the typed
    /// [`XReserveSetMinBurnSizeNoteStorage`] payload.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        storage: XReserveSetMinBurnSizeNoteStorage,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(
            sender,
            faucet_id,
            Self::script(),
            storage.into_items()?,
            rng,
        )
    }

    /// Convenience constructor over the raw `new_min` param (a thin delegator to the
    /// [`builder`](Self::builder)); retained because the frozen conformance suites pin this signature.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_min: u64,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(
                XReserveSetMinBurnSizeNoteStorage::builder()
                    .new_min(new_min)
                    .build(),
            )
            .rng(rng)
            .build()
    }
}
