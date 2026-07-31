//! RBAC role admin note factories: `grant_role`, `revoke_role`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::{Felt, Word};

use super::{build_admin_note, compile_admin_note_script};

// GRANT_ROLE
// ================================================================================================

const GRANT_ROLE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_grant_role_note.masm");

static GRANT_ROLE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(GRANT_ROLE_NOTE_SCRIPT_SRC));

/// The PINNED grant_role admin note-script root: binds transitively to the stock
/// `rbac::grant_role`'s digest.
pub const XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x39e47eb27d42b5eb91ff800800bf43b64f0c6ee761ddb02ed197112809513d8e";

/// The role-admin-gated stock `grant_role` admin note (the sender must hold the
/// granted role's EFFECTIVE admin: its delegated admin, else the built-in `ADMIN` role, which the
/// builder seeds on the owner). Storage layout:
/// `[role_symbol, account_suffix, account_prefix]`.
pub struct XReserveGrantRoleNote;

impl XReserveGrantRoleNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        GRANT_ROLE_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        GRANT_ROLE_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_GRANT_ROLE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned grant_role note-script root hex is a valid word"),
        )
    }

    /// Builds a `grant_role` admin note: `sender` is the admin party (a holder of the granted role's
    /// effective admin role, for
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

// REVOKE_ROLE
// ================================================================================================

const REVOKE_ROLE_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_revoke_role_note.masm");

static REVOKE_ROLE_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(REVOKE_ROLE_NOTE_SCRIPT_SRC));

/// The PINNED revoke_role admin note-script root: binds transitively to the stock
/// `rbac::revoke_role`'s digest.
pub const XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x109245c8d4f8c2873ff3c244fecf6db931e00d1ee0c7d61863107f4b78a4d9ba";

/// The role-admin-gated stock `revoke_role` admin note (the sender must hold the
/// revoked role's EFFECTIVE admin: its delegated admin, else the built-in `ADMIN` role, which the
/// builder seeds on the owner). Storage layout:
/// `[role_symbol, account_suffix, account_prefix]`.
pub struct XReserveRevokeRoleNote;

impl XReserveRevokeRoleNote {
    /// The compiled, fixed-root note script.
    pub fn script() -> NoteScript {
        REVOKE_ROLE_NOTE_SCRIPT.clone()
    }

    /// The note-script root, which must equal the pinned constant.
    pub fn script_root() -> NoteScriptRoot {
        REVOKE_ROLE_NOTE_SCRIPT.root()
    }

    /// [`XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX`] as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_REVOKE_ROLE_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned revoke_role note-script root hex is a valid word"),
        )
    }

    /// Builds a `revoke_role` admin note: `sender` is the admin party (a holder of the revoked role's
    /// effective admin role, for
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
