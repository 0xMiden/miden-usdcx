use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Felt;

use super::{build_admin_note, compile_admin_note_script};
use crate::xreserve::encoding::{PublicKey, PUBKEY_FELTS};

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The dedicated `set_attester` note-storage type: the `NoteStorage.items` payload
/// `[pub_key(16), attester_idx]`. Built with a `bon` builder
/// (`XReserveSetAttesterNoteStorage::builder().pub_key(..).attester_index(..).build()`), mirroring
/// the standards `PswapNoteStorage` pattern, and converted to its felt items by [`Self::into_items`].
///
/// The public key leads the layout so it lands word-aligned in the memory the account procedure
/// stages it into; a key of sixteen zeros is how an attester is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct XReserveSetAttesterNoteStorage {
    pub_key: [Felt; PUBKEY_FELTS],
    attester_index: u32,
}

impl XReserveSetAttesterNoteStorage {
    /// The `NoteStorage.items` felt count: `[pub_key(16), attester_idx]`.
    pub const NUM_ITEMS: usize = PUBKEY_FELTS + 1;

    /// Enables an attester at `attester_index` by writing its affine public key there.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if the compressed key does not decode to a curve point — such a key
    /// could never verify on-chain either.
    pub fn enable(attester_index: u32, pub_key: &PublicKey) -> Result<Self, NoteError> {
        let pub_key = pub_key.to_affine_felts().map_err(|source| {
            NoteError::other_with_source("attester pubkey rejected by the shared codec", source)
        })?;
        Ok(Self::builder()
            .pub_key(pub_key)
            .attester_index(attester_index)
            .build())
    }

    /// Disables the attester at `attester_index` by zeroing its key.
    pub fn disable(attester_index: u32) -> Self {
        Self::builder()
            .pub_key([Felt::from(0u32); PUBKEY_FELTS])
            .attester_index(attester_index)
            .build()
    }

    /// The attester's affine secp256k1 public key, as the 16 u32-LE felts the faucet stores.
    pub fn pub_key(&self) -> &[Felt; PUBKEY_FELTS] {
        &self.pub_key
    }

    /// The array index this key is written at.
    pub fn attester_index(&self) -> u32 {
        self.attester_index
    }

    /// The `NoteStorage.items` felt layout `[pub_key(16), attester_idx]`.
    pub fn into_items(self) -> Vec<Felt> {
        let mut items = Vec::with_capacity(Self::NUM_ITEMS);
        items.extend(self.pub_key);
        items.push(Felt::from(self.attester_index));
        items
    }
}

/// The administrator-gated `set_attester` admin note. Storage layout: `[pub_key(16),
/// attester_idx]`. Consumed against the faucet network account; `attestation::set_attester` gates
/// on the (kernel-forced) note sender through the account-wide authority, resolving to the built-in
/// `ADMIN` role, and reads this storage itself rather than taking it across the `call` boundary.
pub struct XReserveSetAttesterNote;

#[bon::bon]
impl XReserveSetAttesterNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_set_attester_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        SET_ATTESTER_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to `attestation::set_attester`'s
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

    /// Convenience constructor that enables `pub_key` at `attester_index` — a thin delegator to the
    /// [`builder`](Self::builder) over [`XReserveSetAttesterNoteStorage::enable`].
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if the compressed key does not decode to a curve point, or if the
    /// note itself cannot be built.
    pub fn enable<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        attester_index: u32,
        pub_key: &PublicKey,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(XReserveSetAttesterNoteStorage::enable(
                attester_index,
                pub_key,
            )?)
            .rng(rng)
            .build()
    }

    /// Convenience constructor that disables the attester at `attester_index` by zeroing its key.
    ///
    /// # Errors
    ///
    /// Returns a [`NoteError`] if the note cannot be built.
    pub fn disable<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        attester_index: u32,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        Self::builder()
            .sender(sender)
            .faucet_id(faucet_id)
            .storage(XReserveSetAttesterNoteStorage::disable(attester_index))
            .rng(rng)
            .build()
    }
}
