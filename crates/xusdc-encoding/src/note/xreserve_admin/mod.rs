//! Faucet-owned ADMIN note factories: the root-pinned, storage-param admin notes the faucet
//! network account consumes to drive its owner/role-gated admin procs.
//!
//! Each admin note (a) carries its parameters CREATOR-COMMITTED in `NoteStorage.items`; (b) uses a
//! FIXED, root-pinned note script (independent of the param values, so it can be allowlisted); and
//! (c) carries a scheme-2
//! `NetworkAccountTarget` routing bind to the faucet (routing-only). The note script marshals the
//! params onto the stack and `call`s the unchanged sender-gated admin proc — the note sender is
//! kernel-forced, so the proc's owner/role gate is sound under permissionless network execution.
//!
//! The notes are `set_attester`, `set_min_burn_size` (targeting the STOCK `set_min_burn_amount`
//! with a note-side zero-floor guard), `set_max_supply`, `pause`, `unpause`, `grant_role`,
//! `revoke_role`, `transfer_ownership`, `accept_ownership`, `identifier_init` (the
//! identifier-only init; the other domain-config fields are build-seeded), and the
//! BLK_MANAGER-gated `block_account` / `unblock_account`. There is deliberately no
//! `set_role_admin` note: the role-admin delegation graph is build-seeded and deploys frozen — see
//! the SET_ROLE_ADMIN section below.

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
mod ownership;
mod roles;

pub use blocklist::*;
pub use config::*;
pub use ownership::*;
pub use roles::*;

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

// SET_ROLE_ADMIN — NO FACTORY
// ================================================================================================
// There is deliberately no `XReserveSetRoleAdminNote`, matching `renounce_role`, which also has no
// factory and is never allowlisted. The role-admin graph is build-seeded by `seeded_dom_roles_rbac`
// and deploys frozen; rotation goes through `grant_role`/`revoke_role`, with the owner as the
// backstop. The stock `rbac::set_role_admin` account procedure remains composed but is unreachable,
// since no allowlisted note reaches it.
