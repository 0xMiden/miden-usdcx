//! Config / setter admin note factories: `set_attester`, `identifier_init`,
//! `set_min_burn_size`, `set_max_supply`.

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

/// The administrator-gated `set_attester` admin note. Storage layout:
/// `[pk_commitment(4), enabled]`. Consumed against the faucet network account;
/// `attester_admin::set_attester` gates on the (kernel-forced) note sender through the account-wide
/// authority, which — the procedure carrying no role of its own — resolves it to the built-in
/// `ADMIN` role. `ADMIN` membership is account-bound, and it is the faucet's only authority handle:
/// the sender that succeeds is whichever account currently holds the role.
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

    /// Builds a `set_attester` admin note: `sender` is the admin party (an `ADMIN` role holder, for
    /// success),
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

/// The administrator-gated, init-once `identifier_init` admin note. The identifier is the ONE
/// domain-config field the account-id fixpoint forces past build time; the other three are
/// build-seeded by the `XReserveStablecoinBuilder`. Storage layout: `[IDENTIFIER(4)]`. Consumed
/// against the faucet network account; `identifier_init::init_identifier` gates on the
/// (kernel-forced) note sender
/// through the account-wide authority, which resolves it to the built-in `ADMIN` role, AND
/// rejects a second initialization.
pub struct XReserveIdentifierInitNote;

impl XReserveIdentifierInitNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_identifier_init_note.masm`
    /// with the xreserve library linked).
    pub fn script() -> NoteScript {
        IDENTIFIER_INIT_NOTE_SCRIPT.clone()
    }

    /// The compiled note-script root. It binds transitively to
    /// `identifier_init::init_identifier`'s digest — including the proc's own-id derivation,
    /// `bytes32_to_key(account_id_to_bytes32(get_id()))` — and the allowlist row for this note
    /// derives from the same compiled script.
    pub fn script_root() -> NoteScriptRoot {
        IDENTIFIER_INIT_NOTE_SCRIPT.root()
    }

    /// Builds an `identifier_init` admin note: `sender` is the admin party (an `ADMIN` holder, for
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

// SET_MAX_SUPPLY
// ================================================================================================

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
