//! Config / setter admin note factories: `set_attester`, `domain_init`,
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

// SET_ATTESTER (allowlist row 3)
// ================================================================================================

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The PINNED set_attester admin note-script root (`masm-rust-constant-parity`): the MAST root of
/// the compiled `xreserve_set_attester_note.masm` with the xreserve library linked. It binds
/// transitively to `attester_admin::set_attester`'s digest, so ANY edit of the note script or the
/// proc it calls trips the parity assertion (`script_root() == pinned_script_root()`) and forces a
/// conscious re-pin.
pub const XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x442a0c19b0bbce60630f7c52758b296a4ba74e6b7b02b6603f94481c161bc962";

/// The owner-gated `set_attester` admin note (F5). Storage layout: `[pk_commitment(4), enabled]`.
/// Consumed against the faucet network account; `attester_admin::set_attester` gates on the (kernel-
/// forced) note sender being the owner.
pub struct XReserveSetAttesterNote;

impl XReserveSetAttesterNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_set_attester_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        SET_ATTESTER_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 3). Must equal the pinned
    /// [`XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX`] (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        SET_ATTESTER_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_attester note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_attester` admin note: `sender` is the admin party (the owner, for success),
    /// `faucet_id` the target faucet (PUBLIC), `commitment` the attester pubkey commitment (the
    /// xReserveAttesters map key), `enabled` = 1 (allowlist) or 0 (remove). The params live in note
    /// storage; the executor-controlled `NOTE_ARGS` are ignored by the script.
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

// DOMAIN_INIT (allowlist row 12)
// ================================================================================================

const DOMAIN_INIT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_domain_init_note.masm");

static DOMAIN_INIT_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(DOMAIN_INIT_NOTE_SCRIPT_SRC));

/// The PINNED domain_init admin note-script root (`masm-rust-constant-parity`): the MAST root of the
/// compiled `xreserve_domain_init_note.masm` with the xreserve library linked. It binds transitively
/// to `domain_config::domain_init`'s digest, so ANY edit of the note script or the proc it calls trips
/// the parity assertion (`script_root() == pinned_script_root()`) and forces a conscious re-pin.
pub const XRESERVE_DOMAIN_INIT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x04f024d51f121941346180c762b18521505c3d42ab3cea43ebffe6e07041619d";

/// The owner-gated, init-once `domain_init` admin note (F5). Storage layout:
/// `[IDENTIFIER(4), XRC_HI(4), XRC_LO(4), source_domain, domain]`. Consumed against the faucet
/// network account; `domain_config::domain_init` gates on the (kernel-forced) note sender being the
/// owner AND rejects a second initialization.
pub struct XReserveDomainInitNote;

impl XReserveDomainInitNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_domain_init_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        DOMAIN_INIT_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 12). Must equal the pinned
    /// [`XRESERVE_DOMAIN_INIT_NOTE_SCRIPT_ROOT_HEX`] (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        DOMAIN_INIT_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_DOMAIN_INIT_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_DOMAIN_INIT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned domain_init note-script root hex is a valid word"),
        )
    }

    /// Builds a `domain_init` admin note: `sender` is the admin party (the owner, for success),
    /// `faucet_id` the target faucet (PUBLIC), and the domain-config fields — `domain`/`source_domain`
    /// (u32 scalars), `xreserve_contract` (raw bytes32, packed by the shared-encoding codec into 8 u32-LE limbs),
    /// and `identifier` (the pre-hashed `bytes32_to_key` Word). The params live in note storage; the
    /// executor-controlled `NOTE_ARGS` are ignored by the script.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        domain: u32,
        source_domain: u32,
        xreserve_contract: &[u8; 32],
        identifier: Word,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        // Storage order = the proc Inputs order (offset 0 = Inputs top): IDENTIFIER(4), then the
        // packed XRESERVE_CONTRACT hi/lo (8), then source_domain, then domain. The note script
        // marshals these deepest-first so IDENTIFIER element 0 lands on top of the call frame.
        let xrc = crate::xreserve::encoding::bytes32_to_packed_felts(xreserve_contract);
        let items = vec![
            identifier[0],
            identifier[1],
            identifier[2],
            identifier[3],
            xrc[0],
            xrc[1],
            xrc[2],
            xrc[3],
            xrc[4],
            xrc[5],
            xrc[6],
            xrc[7],
            Felt::from(source_domain),
            Felt::from(domain),
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

// SET_MIN_BURN_SIZE (allowlist row 4)
// ================================================================================================

const SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_min_burn_size_note.masm");

static SET_MIN_BURN_SIZE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MIN_BURN_SIZE_NOTE_SCRIPT_SRC));

/// The PINNED set_min_burn_size admin note-script root (`masm-rust-constant-parity`): binds
/// transitively to `min_burn_admin::set_min_burn_size`'s digest, so any edit of the note or the proc
/// it calls trips parity and forces a conscious re-pin.
pub const XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x87e7bb5161151a5d8f06dbace738b19116f7adc6f3e17efdaced03a84837cf84";

/// The owner-gated `set_min_burn_size` admin note (F5). Storage layout: `[new_min]`.
pub struct XReserveSetMinBurnSizeNote;

impl XReserveSetMinBurnSizeNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 4). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        SET_MIN_BURN_SIZE_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_MIN_BURN_SIZE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_min_burn_size note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_min_burn_size` admin note: `sender` is the admin party (the owner, for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_min` the new minimum burn size. The param lives in
    /// note storage; the executor-controlled `NOTE_ARGS` are ignored by the script.
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

// SET_MAX_SUPPLY (allowlist row 5)
// ================================================================================================

const SET_MAX_SUPPLY_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_set_max_supply_note.masm");

static SET_MAX_SUPPLY_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_MAX_SUPPLY_NOTE_SCRIPT_SRC));

/// The PINNED set_max_supply admin note-script root (`masm-rust-constant-parity`): binds transitively
/// to the stock `fungible::set_max_supply`'s digest.
pub const XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x70b18f7063f760b727dd194df5699fd5aa3453ed53ffb317b91711d4c597e018";

/// The owner-gated stock `set_max_supply` admin note (F5). Storage layout: `[new_max_supply]`.
pub struct XReserveSetMaxSupplyNote;

impl XReserveSetMaxSupplyNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        SET_MAX_SUPPLY_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 5). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        SET_MAX_SUPPLY_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_SET_MAX_SUPPLY_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned set_max_supply note-script root hex is a valid word"),
        )
    }

    /// Builds a `set_max_supply` admin note: `sender` is the admin party (the owner, for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_max_supply` the new cap. The param lives in note
    /// storage; NOTE_ARGS are ignored.
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

// PAUSE (allowlist row 6)
// ================================================================================================

const PAUSE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_pause_note.masm");

static PAUSE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(PAUSE_NOTE_SCRIPT_SRC));

/// The PINNED pause admin note-script root (`masm-rust-constant-parity`): binds transitively to
/// `pause_admin::pause`'s digest.
pub const XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xf505ce1232e61d9829825ee65a7db8d0cd5de182a7f16593aa212d5cf0d198a8";

/// The DOM_PAUSER-gated, PARAM-LESS `pause` admin note (F5).
pub struct XReservePauseNote;

impl XReservePauseNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        PAUSE_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 6). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        PAUSE_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_PAUSE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned pause note-script root hex is a valid word"),
        )
    }

    /// Builds a `pause` admin note (param-less): `sender` is the DOM_PAUSER holder (for success),
    /// `faucet_id` the target faucet (PUBLIC). Carries no storage payload; the note ARGS are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}

// UNPAUSE (allowlist row 7)
// ================================================================================================

const UNPAUSE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_unpause_note.masm");

static UNPAUSE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(UNPAUSE_NOTE_SCRIPT_SRC));

/// The PINNED unpause admin note-script root (`masm-rust-constant-parity`): binds transitively to
/// `pause_admin::unpause`'s digest.
pub const XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x8df1f866ebc97f423119ab04400e2c09a8680aac3bbb03f91a4fe271dfa9578c";

/// The DOM_PAUSER-gated, PARAM-LESS `unpause` admin note (F5).
pub struct XReserveUnpauseNote;

impl XReserveUnpauseNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        UNPAUSE_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 7). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        UNPAUSE_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_UNPAUSE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned unpause note-script root hex is a valid word"),
        )
    }

    /// Builds an `unpause` admin note (param-less): `sender` is the DOM_PAUSER holder (for success),
    /// `faucet_id` the target faucet (PUBLIC). Carries no storage payload; the note ARGS are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}
