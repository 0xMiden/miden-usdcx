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
//! This module ships allowlist rows 3-14: the `set_attester` reference op, the ratified owner/role/
//! pause admin note scripts (`set_min_burn_size` — retargeted at the STOCK `set_min_burn_amount`
//! with a note-side zero-floor guard since the Wave-1 S1 recomposition —, `set_max_supply`,
//! `pause`, `unpause`, `grant_role`, `revoke_role`, `transfer_ownership`, `accept_ownership`,
//! `identifier_init` — the minimized DEC-4 replacement of the former four-field `domain_init`),
//! and the F4-reversal transfer-blocklist admin notes (`block_account`, `unblock_account`,
//! BLK_MANAGER-gated). There is deliberately NO `set_role_admin` note (S21 disposition flip,
//! human-ratified 2026-07-14): the role-admin delegation graph is build-seeded and deploys frozen
//! — see the SET_ROLE_ADMIN section below.

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
/// `call.<module>::<proc>` resolves to the SAME proc installed on the faucet account (mirrors the
/// mint-note recipe / the test harness' `assemble_xreserve_lib`).
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

// SET_ROLE_ADMIN — NO FACTORY (S21 disposition flip, human-ratified 2026-07-14)
// ================================================================================================
// The former `XReserveSetRoleAdminNote` (allowlist row 10 of the old 13-root set, pinned root
// 0x0c69fe1a19ee27196780be8d7815920e6a5da49e05ee10b9a615c4ee7a778648) was REMOVED together with
// its note script, matching the `renounce_role` precedent (also no factory, never allowlisted):
// the role-admin graph is BUILD-SEEDED (`seeded_dom_roles_rbac`) and deploys frozen; rotation is
// `grant_role`/`revoke_role` (CIR-ADMIN-3). The stock `rbac::set_role_admin` account procedure
// remains composed but is present-but-UNREACHABLE — enforced by `tests/account_callable_surface.rs`
// and the preserved-former-note rejection tests in `tests/f5_admin_notes.rs`.
