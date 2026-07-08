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
//! This module ships the ratified allowlist rows 3-13; `set_attester` (row 3) is the reference.

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

    /// The note-script root (allowlist row 3).
    pub fn script_root() -> NoteScriptRoot {
        SET_ATTESTER_NOTE_SCRIPT.root()
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
