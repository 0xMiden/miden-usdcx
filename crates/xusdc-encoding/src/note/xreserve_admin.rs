//! Faucet-owned ADMIN note factories (F5): the production, root-pinned, storage-param admin notes
//! the faucet network account consumes to drive its owner/role-gated admin procs.
//!
//! Each admin note (a) carries its parameters CREATOR-COMMITTED in `NoteStorage.items` (never
//! `NOTE_ARGS`, which the network executor controls); (b) uses a FIXED, root-pinned note script
//! (independent of the param values, so it can be allowlisted); and (c) carries a scheme-2
//! `NetworkAccountTarget` routing bind to the faucet (routing-only). The note script marshals the
//! params onto the stack and `call`s the unchanged sender-gated admin proc — the note sender is
//! kernel-forced, so the proc's owner/role gate is sound under permissionless network execution.
//!
//! This module ships allowlist row 3 (`set_attester`) as the reference op; rows 4-13 (the remaining
//! ratified admin note scripts) are pending.

use std::sync::{Arc, LazyLock};

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachments, NoteRecipient, NoteScript, NoteScriptRoot,
    NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::StandardsLib;

/// Compiles an admin note-script source with the shipped `xreserve` component library linked so its
/// `call.<module>::<proc>` resolves to the SAME proc installed on the faucet account (mirrors the
/// mint-note recipe / the test harness' `assemble_xreserve_lib`).
fn compile_admin_note_script(src: &str) -> NoteScript {
    let assembler = TransactionKernel::assembler()
        .with_dynamic_library(StandardsLib::default())
        .expect("the standards library links into the xreserve assembler")
        .with_warnings_as_errors(true);
    let library = Arc::unwrap_or_clone(
        assembler
            .assemble_library_from_dir(crate::xreserve_asm_dir(), "xreserve")
            .expect("the shipped xreserve component library assembles"),
    );
    CodeBuilder::new()
        .with_dynamically_linked_library(&library)
        .expect("the xreserve library links into the admin-note script assembler")
        .compile_note_script(src)
        .expect("the admin note script compiles")
}

/// Attaches the scheme-2 `NetworkAccountTarget` routing bind (routing-only) to a faucet-targeted
/// admin note. Requires a PUBLIC faucet id.
fn routing_attachments(faucet_id: AccountId) -> Result<NoteAttachments, NoteError> {
    let target = NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
        NoteError::other_with_source("faucet id is not a public network account", err)
    })?;
    NoteAttachments::new(vec![NoteAttachment::from(target)])
}

// SET_ATTESTER (allowlist row 3)
// ================================================================================================

const SET_ATTESTER_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_set_attester_note.masm");

static SET_ATTESTER_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(SET_ATTESTER_NOTE_SCRIPT_SRC));

/// The PINNED set_attester admin note-script root (`masm-rust-constant-parity`): the MAST root of
/// the compiled `xreserve_set_attester_note.masm` with the xreserve library linked. It binds
/// transitively to `attester_admin::set_attester`'s digest, so ANY edit of the note script or the
/// proc it calls trips the parity assertion (`script_root() == pinned_script_root()`) and forces a
/// conscious re-pin.
pub const XRESERVE_SET_ATTESTER_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xc324299a70124e4ca6c55130195e53b3aca9304e9d2a6ad1a1110252d6d27b0d";

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
        Ok(Note::with_attachments(NoteAssets::new(vec![])?, metadata, recipient, attachments))
    }
}

// DOMAIN_INIT (allowlist row 13)
// ================================================================================================

const DOMAIN_INIT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_domain_init_note.masm");

static DOMAIN_INIT_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(DOMAIN_INIT_NOTE_SCRIPT_SRC));

/// The PINNED domain_init admin note-script root (`masm-rust-constant-parity`): the MAST root of the
/// compiled `xreserve_domain_init_note.masm` with the xreserve library linked. It binds transitively
/// to `domain_config::domain_init`'s digest, so ANY edit of the note script or the proc it calls trips
/// the parity assertion (`script_root() == pinned_script_root()`) and forces a conscious re-pin.
pub const XRESERVE_DOMAIN_INIT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

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

    /// The note-script root (allowlist row 13). Must equal the pinned
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
    /// `faucet_id` the target faucet (PUBLIC), and the §5.9 config fields — `domain`/`source_domain`
    /// (u32 scalars), `xreserve_contract` (raw bytes32, packed by the 04 codec into 8 u32-LE limbs),
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
        Ok(Note::with_attachments(NoteAssets::new(vec![])?, metadata, recipient, attachments))
    }
}
