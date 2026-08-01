//! Config / setter admin note factories: `set_attester`, `identifier_init`,
//! `set_min_burn_size`, `set_max_supply`, `pause`, `unpause`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteRecipient, NoteScript, NoteScriptRoot, NoteStorage, NoteTag, NoteType,
    PartialNoteMetadata,
};
use miden_protocol::{Felt, Word};

use super::{build_admin_note, compile_admin_note_script, routing_attachments};

// SET_ATTESTER
// ================================================================================================

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The PINNED set_attester admin note-script root: the MAST root of the compiled
/// `xreserve_set_attester_note.masm` with the xreserve library linked. It binds transitively to
/// `attester_admin::set_attester`'s digest, so any edit of the note script or of the proc it calls
/// changes this root.
pub const XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x2763aaac15ebd657c7d0e5f952aacb953faedd224b4e465871bac4baa67df42f";

/// The owner-gated `set_attester` admin note. Storage layout: `[pk_commitment(4), enabled]`.
/// Consumed against the faucet network account; `attester_admin::set_attester` gates on the (kernel-
/// forced) note sender being the owner.
pub struct XReserveSetAttesterNote;

impl XReserveSetAttesterNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_set_attester_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        SET_ATTESTER_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal
    /// [`XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX`].
    pub fn script_root() -> NoteScriptRoot {
        SET_ATTESTER_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_attester note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_attester` admin note: `sender` is the admin party (the owner, for success),
    /// `faucet_id` the target faucet (PUBLIC), `commitment` the attester pubkey commitment (the
    /// xReserveAttesters map key), `enabled` = 1 (allowlist) or 0 (remove). The params live in note
    /// storage.
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
        let storage = NoteStorage::new(items)?;
        let serial_num = rng.draw_word();
        let recipient = NoteRecipient::new(serial_num, Self::script(), storage);
        let metadata = PartialNoteMetadata::new(sender, NoteType::Public)
            .with_tag(NoteTag::with_account_target(faucet_id));
        let attachments = routing_attachments(faucet_id)?;
        Ok(Note::with_attachments(
            NoteAssets::new(vec![])?,
            metadata,
            recipient,
            attachments,
        ))
    }
}

// IDENTIFIER_INIT
// ================================================================================================

const IDENTIFIER_INIT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_identifier_init_note.masm");

static IDENTIFIER_INIT_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(IDENTIFIER_INIT_NOTE_SCRIPT_SRC));

/// The PINNED identifier_init admin note-script root: the MAST root of the compiled
/// `xreserve_identifier_init_note.masm` with the xreserve library linked. It binds transitively to
/// `identifier_init::init_identifier`'s digest, so any edit of the note script or of the proc it
/// calls changes this root. The root therefore covers the own-id binding: the proc derives
/// `bytes32_to_key(account_id_to_bytes32(get_id()))` on-chain and rejects a mismatched committed
/// identifier.
pub const XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xac81d9ab1fd5f66252ac77a668342b0656f6f3b102a0efbc219e42b05f82b89e";

/// The owner-gated, init-once `identifier_init` admin note. The identifier is the ONE domain-config
/// field the account-id fixpoint forces past build time; the other three are build-seeded by the
/// `XReserveStablecoinBuilder`. Storage layout: `[IDENTIFIER(4)]`. Consumed against the faucet
/// network account; `identifier_init::init_identifier` gates on the (kernel-forced) note sender
/// being the owner AND rejects a second initialization.
pub struct XReserveIdentifierInitNote;

impl XReserveIdentifierInitNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_identifier_init_note.masm`
    /// with the xreserve library linked).
    pub fn script() -> NoteScript {
        IDENTIFIER_INIT_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal
    /// [`XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX`].
    pub fn script_root() -> NoteScriptRoot {
        IDENTIFIER_INIT_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_IDENTIFIER_INIT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned identifier_init note-script root hex is a valid word"),
        )
    }

    /// Builds an `identifier_init` admin note: `sender` is the admin party (the owner, for
    /// success) and `faucet_id` the target faucet (PUBLIC). The seeded identifier is DERIVED from
    /// `faucet_id` — `bytes32_to_storage_map_key(account_id_to_bytes32(faucet_id))`, the canonical
    /// key of the faucet's own account id as bytes32 — so the init is BOUND to its target and
    /// cannot seed a token that belongs to another identity. This is a PROVISIONAL position — the
    /// AccountId↔bytes32 codec and the identifier==own-id equivalence stay OPEN with Circle — and is
    /// changeable if Circle assigns a different identifier. The derived key lives in note storage.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let identifier: Word = crate::xreserve::encoding::bytes32_to_storage_map_key(
            &crate::xreserve::encoding::account_id_to_bytes32(faucet_id),
        )
        .into();
        let items = vec![identifier[0], identifier[1], identifier[2], identifier[3]];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }

    /// The provisional identifier this factory seeds for `faucet_id`: the canonical
    /// `bytes32_to_storage_map_key(account_id_to_bytes32(faucet_id))` key (the own-id fixpoint,
    /// pending Circle confirmation). Exposed so callers can assert the seeded identity and splice a
    /// matching `remoteToken` into the mint payload the faucet's identifier compare reads.
    pub fn identifier_for(faucet_id: AccountId) -> Word {
        crate::xreserve::encoding::bytes32_to_storage_map_key(
            &crate::xreserve::encoding::account_id_to_bytes32(faucet_id),
        )
        .into()
    }
}

// SET_MIN_BURN_SIZE
// ================================================================================================

const SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_min_burn_size_note.masm");

static SET_MIN_BURN_SIZE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC));

/// The PINNED set_min_burn_size admin note-script root: binds transitively to the STOCK
/// `min_burn_amount::set_min_burn_amount`'s digest plus the note-side zero-floor guard.
pub const XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x7ae46ecf82c7968a867c88d982659ba55989c49238c5e1ba6fa1a8c6a1008566";

/// The owner-gated `set_min_burn_size` admin note. Storage layout: `[new_min]` with
/// `new_min >= 1` (the note script's zero-floor guard — the stock setter itself accepts 0).
pub struct XReserveSetMinBurnSizeNote;

impl XReserveSetMinBurnSizeNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_min_burn_size note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_min_burn_size` admin note: `sender` is the admin party (the owner, for success),
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

// SET_MAX_SUPPLY
// ================================================================================================

const SET_MAX_SUPPLY_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_max_supply_note.masm");

static SET_MAX_SUPPLY_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MAX_SUPPLY_NOTE_SCRIPT_SRC));

/// The PINNED set_max_supply admin note-script root: binds transitively to the stock
/// `fungible::set_max_supply`'s digest.
pub const XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x70b18f7063f760b727dd194df5699fd5aa3453ed53ffb317b91711d4c597e018";

/// The owner-gated stock `set_max_supply` admin note. Storage layout: `[new_max_supply]`.
pub struct XReserveSetMaxSupplyNote;

impl XReserveSetMaxSupplyNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MAX_SUPPLY_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        SET_MAX_SUPPLY_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_max_supply note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_max_supply` admin note: `sender` is the admin party (the owner, for success),
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

// PAUSE
// ================================================================================================

const PAUSE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_pause_note.masm");

static PAUSE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(PAUSE_NOTE_SCRIPT_SRC));

/// The PINNED pause admin note-script root: binds transitively to `pause_admin::pause`'s digest.
pub const XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xf505ce1232e61d9829825ee65a7db8d0cd5de182a7f16593aa212d5cf0d198a8";

/// The DOM_PAUSER-gated, PARAM-LESS `pause` admin note.
pub struct XReservePauseNote;

impl XReservePauseNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        PAUSE_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        PAUSE_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned pause note-script root hex is a valid word"),
        )
    }

    /// Builds a `pause` admin note (param-less): `sender` is the DOM_PAUSER holder (for success),
    /// `faucet_id` the target faucet (PUBLIC). Carries no storage payload.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}

// UNPAUSE
// ================================================================================================

const UNPAUSE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_unpause_note.masm");

static UNPAUSE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(UNPAUSE_NOTE_SCRIPT_SRC));

/// The PINNED unpause admin note-script root: binds transitively to `pause_admin::unpause`'s digest.
pub const XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x8df1f866ebc97f423119ab04400e2c09a8680aac3bbb03f91a4fe271dfa9578c";

/// The DOM_PAUSER-gated, PARAM-LESS `unpause` admin note.
pub struct XReserveUnpauseNote;

impl XReserveUnpauseNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        UNPAUSE_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        UNPAUSE_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned unpause note-script root hex is a valid word"),
        )
    }

    /// Builds an `unpause` admin note (param-less): `sender` is the DOM_PAUSER holder (for success),
    /// `faucet_id` the target faucet (PUBLIC). Carries no storage payload.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}
