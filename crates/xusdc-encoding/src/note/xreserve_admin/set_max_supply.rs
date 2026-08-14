use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::Package;
use miden_protocol::Felt;

use super::build_admin_note;

static SET_MAX_SUPPLY_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let package = Package::read_from_bytes_trusted(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/notes/xreserve-set-max-supply-note.masp"
    )))
    .expect("the shipped note package deserializes");
    NoteScript::from_package(&package).expect("the note package exports exactly one note script")
});

/// The dedicated `set_max_supply` note-storage type: the single `[new_max_supply]` item, built with
/// a `bon` builder (`XReserveSetMaxSupplyNoteStorage::builder().new_max_supply(..).build()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct XReserveSetMaxSupplyNoteStorage {
    new_max_supply: u64,
}

impl XReserveSetMaxSupplyNoteStorage {
    /// The `NoteStorage.items` felt count: `[new_max_supply]`.
    pub const NUM_ITEMS: usize = 1;

    /// The new maximum supply cap.
    pub fn new_max_supply(&self) -> u64 {
        self.new_max_supply
    }

    /// The single `[new_max_supply]` felt item. Errors if the value exceeds the field modulus.
    fn into_items(self) -> Result<Vec<Felt>, NoteError> {
        let felt = Felt::try_from(self.new_max_supply)
            .map_err(|e| NoteError::other_with_source("max supply exceeds the field modulus", e))?;
        Ok(vec![felt])
    }
}

/// The administrator-gated stock `set_max_supply` admin note. Storage layout: `[new_max_supply]`.
/// The stock setter resolves through the account-wide authority to the built-in `ADMIN` role.
pub struct XReserveSetMaxSupplyNote;

#[bon::bon]
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

    /// Builds a `set_max_supply` admin note via a `bon` builder: `sender` the admin party,
    /// `faucet_id` the target faucet (PUBLIC), `storage` the typed
    /// [`XReserveSetMaxSupplyNoteStorage`] payload.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        storage: XReserveSetMaxSupplyNoteStorage,
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

    /// Convenience constructor over the raw `new_max_supply` param (a thin delegator to the
    /// [`builder`](Self::builder)); retained because the frozen conformance suites pin this signature.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_max_supply: u64,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(
                XReserveSetMaxSupplyNoteStorage::builder()
                    .new_max_supply(new_max_supply)
                    .build(),
            )
            .rng(rng)
            .build()
    }
}
