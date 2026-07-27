//! F4-reversal transfer-blocklist admin note factories: `block_account`, `unblock_account`.

use std::sync::LazyLock;

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};
use miden_protocol::Word;

use super::{build_admin_note, compile_admin_note_script};

// BLOCK_ACCOUNT (allowlist row 13 — F4-reversal transfer blocklist)
// ================================================================================================

const BLOCK_ACCOUNT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_block_account_note.masm");

static BLOCK_ACCOUNT_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(BLOCK_ACCOUNT_NOTE_SCRIPT_SRC));

/// The PINNED block_account admin note-script root (`masm-rust-constant-parity`): the MAST root of
/// the compiled `xreserve_block_account_note.masm` with the xreserve library linked. It binds
/// transitively to `blocklist_admin::block_account`'s digest, so ANY edit of the note script or the
/// proc it calls trips the parity assertion (`script_root() == pinned_script_root()`) and forces a
/// conscious re-pin.
pub const XRESERVE_BLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xed7e56fde54ba1ffa244b92e048560db8233e3a744c4af95b8f363fc4214d9dc";

/// The BLK_MANAGER-gated `block_account` admin note (F4-reversal). Storage layout:
/// `[account_suffix, account_prefix]` — the account to block. Consumed against the faucet network
/// account; `blocklist_admin::block_account` gates on the (kernel-forced) note sender holding the
/// `BLK_MANAGER` role.
pub struct XReserveBlockAccountNote;

impl XReserveBlockAccountNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_block_account_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        BLOCK_ACCOUNT_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 13). Must equal the pinned
    /// [`XRESERVE_BLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX`] (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        BLOCK_ACCOUNT_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_BLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_BLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned block_account note-script root hex is a valid word"),
        )
    }

    /// Builds a `block_account` admin note: `sender` is the admin party (the BLK_MANAGER holder, for
    /// success), `faucet_id` the target faucet (PUBLIC), `account` the account to block. The params
    /// live in note storage; the executor-controlled `NOTE_ARGS` are ignored by the script.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        account: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![account.suffix(), account.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}

// UNBLOCK_ACCOUNT (allowlist row 14 — F4-reversal transfer blocklist)
// ================================================================================================

const UNBLOCK_ACCOUNT_NOTE_SCRIPT_SRC: &str =
    include_str!("../../../../../asm/standards/notes/xreserve_unblock_account_note.masm");

static UNBLOCK_ACCOUNT_NOTE_SCRIPT: LazyLock<NoteScript> =
    LazyLock::new(|| compile_admin_note_script(UNBLOCK_ACCOUNT_NOTE_SCRIPT_SRC));

/// The PINNED unblock_account admin note-script root (`masm-rust-constant-parity`): the MAST root of
/// the compiled `xreserve_unblock_account_note.masm` with the xreserve library linked. It binds
/// transitively to `blocklist_admin::unblock_account`'s digest, so ANY edit of the note script or the
/// proc it calls trips the parity assertion (`script_root() == pinned_script_root()`) and forces a
/// conscious re-pin.
pub const XRESERVE_UNBLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0xeed9a3d1ef3589a8039dcd3174e410e8ca1a0c0f977d4ecc412e226ba2a343d2";

/// The BLK_MANAGER-gated `unblock_account` admin note (F4-reversal). Storage layout:
/// `[account_suffix, account_prefix]` — the account to unblock. Consumed against the faucet network
/// account; `blocklist_admin::unblock_account` gates on the (kernel-forced) note sender holding the
/// `BLK_MANAGER` role.
pub struct XReserveUnblockAccountNote;

impl XReserveUnblockAccountNote {
    /// The compiled, fixed-root note script (the shipped `xreserve_unblock_account_note.masm` with the
    /// xreserve library linked).
    pub fn script() -> NoteScript {
        UNBLOCK_ACCOUNT_NOTE_SCRIPT.clone()
    }

    /// The note-script root (allowlist row 14). Must equal the pinned
    /// [`XRESERVE_UNBLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX`] (parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        UNBLOCK_ACCOUNT_NOTE_SCRIPT.root()
    }

    /// The PINNED note-script root ([`XRESERVE_UNBLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX`]).
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            Word::parse(XRESERVE_UNBLOCK_ACCOUNT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned unblock_account note-script root hex is a valid word"),
        )
    }

    /// Builds an `unblock_account` admin note: `sender` is the admin party (the BLK_MANAGER holder, for
    /// success), `faucet_id` the target faucet (PUBLIC), `account` the account to unblock. The params
    /// live in note storage; the executor-controlled `NOTE_ARGS` are ignored by the script.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        account: AccountId,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let items = vec![account.suffix(), account.prefix().as_felt()];
        build_admin_note(sender, faucet_id, Self::script(), items, rng)
    }
}
