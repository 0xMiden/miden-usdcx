//! Faucet-owned ADMIN note factories: the production, root-pinned, storage-param admin notes
//! the faucet network account consumes to drive its role-gated admin procs.
//!
//! Each admin note (a) carries its parameters CREATOR-COMMITTED in `NoteStorage.items` (never
//! `NOTE_ARGS`, which the network executor controls); (b) uses a FIXED, root-pinned note script
//! (independent of the param values, so it can be allowlisted); and (c) carries a scheme-2
//! `NetworkAccountTarget` routing bind to the faucet (routing-only). The note script marshals the
//! params onto the stack and `call`s the unchanged sender-gated admin proc — the note sender is
//! kernel-forced, so the proc's role gate is sound under permissionless network execution.
//!
//! This module ships the faucet-owned rows of the note-script allowlist: the `set_attester`
//! reference op, `set_min_burn_size` (targeting the STOCK `set_min_burn_amount` with a note-side
//! zero-floor guard), `set_max_supply`, and `identifier_init` (the minimized identifier-only init;
//! the other domain-config fields are build-seeded). All four resolve, through the account-wide
//! authority, to the built-in `ADMIN` role.
//!
//! Three admin surfaces do NOT ship a faucet-owned note script, because a standard note already
//! covers each of them and calls the standard component the faucet installs. Pausing uses the
//! standard pause-action note directly, with no faucet wrapper at all. Role management uses the
//! standard role-action note, whose single script root carries grant, revoke, set-role-admin and
//! renounce alike. The blocklist uses the standard blocklist-config note through [`blocklist`]'s
//! thin factory, which exists solely to refuse building a note that would block the faucet itself.
//!
//! There is no ownership note either: the faucet installs no two-step ownership component, so
//! rotation is a grant and a revoke of the `ADMIN` role through the standard role-action note.

use std::sync::Arc;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::{Linkage, Path as MasmPath};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachments, NoteRecipient, NoteScript, NoteStorage,
    NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::Felt;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::StandardsLib;

mod blocklist;
mod config;

pub use blocklist::*;
pub use config::*;

/// Compiles an admin note-script source with the shipped `xreserve` component library linked so its
/// `call.<module>::<proc>` resolves to the SAME proc installed on the faucet account.
pub(super) fn compile_admin_note_script(src: &str) -> NoteScript {
    let assembler = TransactionKernel::assembler()
        .with_package(Arc::new(StandardsLib::default().into()), Linkage::Dynamic)
        .expect("the standards library links into the xreserve assembler")
        .with_warnings_as_errors(true);
    let library = *assembler
        .assemble_library_from_root(
            crate::xreserve_asm_dir().join("mod.masm"),
            Some(MasmPath::new("xreserve")),
        )
        .expect("the shipped xreserve component library assembles");
    CodeBuilder::new()
        .with_dynamically_linked_package(&library)
        .expect("the xreserve library links into the admin-note script assembler")
        .compile_note_script(src)
        .expect("the admin note script compiles")
}

/// Attaches the scheme-2 `NetworkAccountTarget` routing bind (routing-only) to a faucet-targeted
/// admin note. Requires a PUBLIC faucet id.
pub(super) fn routing_attachments(faucet_id: AccountId) -> Result<NoteAttachments, NoteError> {
    let target =
        NetworkAccountTarget::new(faucet_id, NoteExecutionHint::Always).map_err(|err| {
            NoteError::other_with_source("faucet id is not a public network account", err)
        })?;
    NoteAttachments::new(vec![NoteAttachment::from(target)])
}

/// Assembles an admin note from its fixed-root `script` + the creator-committed storage `items`,
/// carrying the scheme-2 `NetworkAccountTarget` routing bind to `faucet_id` (routing-only). Shared by
/// every admin-note factory: the notes differ only in their script + the felt payload they commit;
/// the metadata (PUBLIC, faucet-tagged), the serial draw, the empty asset set, and the routing
/// attachment are identical. `sender` is the (kernel-forced) admin party the wrapped proc's gate reads.
pub(super) fn build_admin_note<R: FeltRng>(
    sender: AccountId,
    faucet_id: AccountId,
    script: NoteScript,
    items: Vec<Felt>,
    rng: &mut R,
) -> Result<Note, NoteError> {
    let storage = NoteStorage::new(items)?;
    let serial_num = rng.draw_word();
    let recipient = NoteRecipient::new(serial_num, script, storage);
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

// ROLE MANAGEMENT — NO FACTORY (the standard role-action note covers it)
// ================================================================================================
// There is no faucet-owned role note. The standard role-action note is allowlisted instead, and its
// single script root carries all four of the standard role component's management actions: grant,
// revoke, set-role-admin and renounce. Admitting the root admits all four, so the role-admin graph
// the build seeds is runtime-mutable rather than frozen, and a role holder can drop its own
// membership. That exposure is deliberate and human-ratified; the allowlist doc in
// `account::xreserve::builder` states what it means for the account.
//
// Authorization is unchanged by the move: every action is gated by the standard role component
// against the note sender — grant, revoke and set-role-admin on the target role's effective admin
// role, renounce on the sender's own membership.
