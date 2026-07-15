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
//! This module ships allowlist rows 3-12: the `set_attester` reference op and the remaining ratified
//! admin note scripts (`set_min_burn_size`, `set_max_supply`, `pause`, `unpause`, `grant_role`,
//! `revoke_role`, `transfer_ownership`, `accept_ownership`, `domain_init`). There is deliberately
//! NO `set_role_admin` note (S21 disposition flip, human-ratified 2026-07-14): the role-admin
//! delegation graph is build-seeded and deploys frozen — see the SET_ROLE_ADMIN section below.

use std::sync::{Arc, LazyLock};

use miden_protocol::account::AccountId;
use miden_protocol::assembly::{Linkage, Path as MasmPath};
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
        .with_dynamically_linked_library(&library)
        .expect("the xreserve library links into the admin-note script assembler")
        .compile_note_script(src)
        .expect("the admin note script compiles")
}

/// Attaches the scheme-2 `NetworkAccountTarget` routing bind (routing-only) to a faucet-targeted
/// admin note. Requires a PUBLIC faucet id.
fn routing_attachments(faucet_id: AccountId) -> Result<NoteAttachments, NoteError> {
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
fn build_admin_note<R: FeltRng>(
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
    include_str!("../../../../asm/standards/notes/xreserve_domain_init_note.masm");

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
    include_str!("../../../../asm/standards/notes/xreserve_set_min_burn_size_note.masm");

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

// PAUSE (allowlist row 6)
// ================================================================================================

const PAUSE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_pause_note.masm");

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
    include_str!("../../../../asm/standards/notes/xreserve_unpause_note.masm");

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

// GRANT_ROLE (allowlist row 8)
// ================================================================================================

const GRANT_ROLE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_grant_role_note.masm");

static GRANT_ROLE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(GRANT_ROLE_NOTE_SCRIPT_SRC));

/// The PINNED grant_role admin note-script root (`masm-rust-constant-parity`): binds transitively to
/// the stock `rbac::grant_role`'s digest.
pub const XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x39e47eb27d42b5eb91ff800800bf43b64f0c6ee761ddb02ed197112809513d8e";

/// The role-admin-gated stock `grant_role` admin note (F5; v0.16 #3215 — the sender must hold the
/// granted role's EFFECTIVE admin: its delegated admin, else the built-in `ADMIN` role, which the
/// builder seeds on the owner. MIGRATION-V16-ALPHA2.md S2/S21). Storage layout:
/// `[role_symbol, account_suffix, account_prefix]`.
pub struct XReserveGrantRoleNote;

impl XReserveGrantRoleNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        GRANT_ROLE_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 8). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        GRANT_ROLE_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned grant_role note-script root hex is a valid word"),
        )
    }

    /// Builds a `grant_role` admin note: `sender` is the admin party (a holder of the granted role's
    /// effective admin role — v0.16 #3215; for
    /// success), `faucet_id` the target faucet (PUBLIC), `role_symbol` the RBAC role element, `member`
    /// the account to grant it to. The params live in note storage; NOTE_ARGS are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        role_symbol: Felt,
        member: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![role_symbol, member.suffix(), member.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
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

// TRANSFER_OWNERSHIP (allowlist row 10)
// ================================================================================================

const TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_transfer_ownership_note.masm");

static TRANSFER_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(TRANSFER_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The PINNED transfer_ownership admin note-script root (`masm-rust-constant-parity`): binds
/// transitively to the stock `ownable2step::transfer_ownership`'s digest.
pub const XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x5bd39b30a487d6a385acd220c43a82980e63cfe37ba4d86efd58ffbd7a6c7c0a";

/// The current-owner-gated stock `transfer_ownership` admin note (F5, step 1 of the 2-step transfer).
/// Storage layout: `[new_owner_suffix, new_owner_prefix]`.
pub struct XReserveTransferOwnershipNote;

impl XReserveTransferOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 10). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        TRANSFER_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_TRANSFER_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned transfer_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds a `transfer_ownership` admin note: `sender` is the current owner (for success),
    /// `faucet_id` the target faucet (PUBLIC), `new_owner` the nominated owner. The params live in
    /// note storage; NOTE_ARGS are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        new_owner: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![new_owner.suffix(), new_owner.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}

// ACCEPT_OWNERSHIP (allowlist row 11)
// ================================================================================================

const ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_accept_ownership_note.masm");

static ACCEPT_OWNERSHIP_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(ACCEPT_OWNERSHIP_NOTE_SCRIPT_SRC));

/// The PINNED accept_ownership admin note-script root (`masm-rust-constant-parity`): binds
/// transitively to the stock `ownable2step::accept_ownership`'s digest.
pub const XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x4480f83f0c08d6c0d7e3480c62f0dc296a29489fd631ce78615bacb017352104";

/// The nominated-owner-gated, PARAM-LESS stock `accept_ownership` admin note (F5, step 2 of the
/// 2-step transfer).
pub struct XReserveAcceptOwnershipNote;

impl XReserveAcceptOwnershipNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 11). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        ACCEPT_OWNERSHIP_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_ACCEPT_OWNERSHIP_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned accept_ownership note-script root hex is a valid word"),
        )
    }

    /// Builds an `accept_ownership` admin note (param-less): `sender` is the nominated (pending) owner
    /// (for success), `faucet_id` the target faucet (PUBLIC). Carries no storage payload; NOTE_ARGS
    /// are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        build_admin_note(sender, faucet_id, Self::script(), vec![], rng)
    }
}

// SET_MAX_SUPPLY (allowlist row 5)
// ================================================================================================

const SET_MAX_SUPPLY_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_set_max_supply_note.masm");

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

// REVOKE_ROLE (allowlist row 9)
// ================================================================================================

const REVOKE_ROLE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../asm/standards/notes/xreserve_revoke_role_note.masm");

static REVOKE_ROLE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(REVOKE_ROLE_NOTE_SCRIPT_SRC));

/// The PINNED revoke_role admin note-script root (`masm-rust-constant-parity`): binds transitively to
/// the stock `rbac::revoke_role`'s digest.
pub const XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x109245c8d4f8c2873ff3c244fecf6db931e00d1ee0c7d61863107f4b78a4d9ba";

/// The role-admin-gated stock `revoke_role` admin note (F5; v0.16 #3215 — the sender must hold the
/// revoked role's EFFECTIVE admin: its delegated admin, else the built-in `ADMIN` role, which the
/// builder seeds on the owner. MIGRATION-V16-ALPHA2.md S2/S21). Storage layout:
/// `[role_symbol, account_suffix, account_prefix]`.
pub struct XReserveRevokeRoleNote;

impl XReserveRevokeRoleNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        REVOKE_ROLE_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 9). Must equal the pinned constant (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        REVOKE_ROLE_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned revoke_role note-script root hex is a valid word"),
        )
    }

    /// Builds a `revoke_role` admin note: `sender` is the admin party (a holder of the revoked role's
    /// effective admin role — v0.16 #3215; for
    /// success), `faucet_id` the target faucet (PUBLIC), `role_symbol` the RBAC role element, `member`
    /// the account to revoke it from. The params live in note storage; NOTE_ARGS are ignored.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        role_symbol: Felt,
        member: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![role_symbol, member.suffix(), member.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}
