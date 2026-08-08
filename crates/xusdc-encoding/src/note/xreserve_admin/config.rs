//! Config / setter admin note factories: `set_attester`,
//! `set_min_burn_size`, `set_max_supply`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};

use super::{build_admin_note, compile_admin_note_script};

// SET_ATTESTER
// ================================================================================================

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The dedicated `set_attester` note-storage type: the `NoteStorage.items` payload
/// `[pk_commitment(4), enabled]`. Built with a `bon` builder
/// (`XReserveSetAttesterNoteStorage::builder().commitment(..).enabled(..).build()`), mirroring the
/// standards `PswapNoteStorage` pattern, and converted to its felt items by [`Self::into_items`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct XReserveSetAttesterNoteStorage {
    commitment: Word,
    enabled: u8,
}

impl XReserveSetAttesterNoteStorage {
    /// The `NoteStorage.items` felt count: `[commitment(4), enabled]`.
    pub const NUM_ITEMS: usize = 5;

    /// The attester pubkey commitment (the xReserveAttesters map key).
    pub fn commitment(&self) -> Word {
        self.commitment
    }

    /// `1` = allowlist the attester, `0` = remove it.
    pub fn enabled(&self) -> u8 {
        self.enabled
    }

    /// The `NoteStorage.items` felt layout `[commitment(4), enabled]`.
    pub fn into_items(self) -> Vec<Felt> {
        vec![
            self.commitment[0],
            self.commitment[1],
            self.commitment[2],
            self.commitment[3],
            Felt::from(u32::from(self.enabled)),
        ]
    }
}

/// The administrator-gated `set_attester` admin note. Storage layout:
/// `[pk_commitment(4), enabled]`. Consumed against the faucet network account;
/// `attester_admin::set_attester` gates on the (kernel-forced) note sender through the account-wide
/// authority, which — the procedure carrying no role of its own — resolves it to the built-in
/// `ADMIN` role. `ADMIN` membership is account-bound, and it is the faucet's only authority handle:
/// the sender that succeeds is whichever account currently holds the role.
pub struct XReserveSetAttesterNote;

#[bon::bon]
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

    /// Builds a `set_attester` admin note via a `bon` builder
    /// (`XReserveSetAttesterNote::builder().sender(..).faucet_id(..).storage(..).rng(..).build()`):
    /// `sender` is the admin party (an `ADMIN` role holder, for success), `faucet_id` the target
    /// faucet (PUBLIC), `storage` the typed [`XReserveSetAttesterNoteStorage`] payload.
    #[builder]
    pub fn new<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        storage: XReserveSetAttesterNoteStorage,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), storage.into_items(), rng)
    }

    /// Convenience constructor over the raw `commitment` / `enabled` params. Retained (a thin
    /// delegator to the [`builder`](Self::builder)) because the frozen conformance suites pin this
    /// signature; new callers should prefer the typed builder.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        commitment: Word,
        enabled: u8,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(
                XReserveSetAttesterNoteStorage::builder()
                    .commitment(commitment)
                    .enabled(enabled)
                    .build(),
            )
            .rng(rng)
            .build()
    }
}

// SET_MIN_BURN_SIZE
// ================================================================================================

const SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_min_burn_size_note.masm");

static SET_MIN_BURN_SIZE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC));

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
/// stock setter it targets resolves through the account-wide authority to the built-in `ADMIN` role,
/// which is account-bound and is the faucet's only authority handle.
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

// SET_MAX_SUPPLY
// ================================================================================================

const SET_MAX_SUPPLY_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_max_supply_note.masm");

static SET_MAX_SUPPLY_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MAX_SUPPLY_NOTE_SCRIPT_SRC));

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

/// The administrator-gated stock `set_max_supply` admin note. Storage layout:
/// `[new_max_supply]`. The stock setter resolves through the account-wide authority to the built-in
/// `ADMIN` role, which is account-bound and is the faucet's only authority handle.
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
