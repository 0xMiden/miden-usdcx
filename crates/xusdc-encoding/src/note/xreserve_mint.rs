//! `XReserveMintNote` (CMP-B1, D4): the production mint note — carries a signed Circle
//! DepositIntent to the faucet, whose network transaction consumes it and drives the fully-gated
//! `xreserve_mint::mint` (D5a→D5e) end to end.
//!
//! Transport layout (spec §5.1:250-252, §5.10; DC-1/DC-2/DC-3):
//! - `NoteStorage.items` = the u32-LE-packed DepositIntent preimage — the 04 codec
//!   [`deposit_intent_to_packed_felts`] consumed BY REFERENCE (60 header felts +
//!   ⌈hookDataLen/4⌉ hookData felts, ≤ 1024).
//! - ONE [`NoteAttachments`] attachment (scheme [`XRESERVE_MINT_ATTACHMENT_SCHEME`]) = 9 words:
//!   `[feeAmount(8 limbs, MVP zero — DEV-8), pubkey(9), signature(17), pad(2)]`, matching the
//!   frozen `mint` advice contract `[feeAmount(8), pubkey(9), signature(17)]`
//!   (`xreserve_mint.masm` doc). The byte→felt packing reuses the 04 codec
//!   [`compressed_pubkey_felts`] / [`signature_felts`] by reference.
//! - `NoteType::Public` is FORCED (network-tx observability mandate); the tag is the faucet
//!   account-target tag (`NoteTag::with_account_target`, TAG-1 — burn notes carry the fixed
//!   `0x4255524E` tag instead precisely so mint notes own the account-target routing identity).
//! - The note script (`asm/standards/notes/xreserve_mint_note.masm`) `call`s the account-side
//!   `receive_and_mint` note-entry wrapper, which stages storage into the account call frame,
//!   hash-verifies the attachment content, surfaces it to the advice stack, and
//!   `exec.xreserve_mint::mint`s. Its root is pinned as [`XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX`]
//!   (`masm-rust-constant-parity`; the parity test recompiles and compares).
//!
//! Like the sibling [`super::xreserve_burn::XReserveBurnNote`] this is an N-11 unit-struct
//! factory; the one divergence is the CUSTOM note script + pinned root (burn reuses the stock
//! `BurnNote` script; mint has no stock analog — stock `mint_and_send` is denied, R-MINT-16).

use miden_protocol::account::AccountId;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot};

/// The mint-note attachment scheme (u16, project-chosen; 0 is reserved, ≤ 65534). Not a
/// Circle-owned value.
pub const XRESERVE_MINT_ATTACHMENT_SCHEME: u16 = 1;

/// The attachment word count: `[feeAmount(8), pubkey(9), signature(17), pad(2)]` = 36 felts.
pub const XRESERVE_MINT_ATTACHMENT_NUM_WORDS: usize = 9;

/// The PINNED mint-note script root (`masm-rust-constant-parity`): the MAST root of the compiled
/// `xreserve_mint_note.masm` with the xreserve library linked. Drift (any wrapper or script edit)
/// trips the parity test, which recompiles and compares.
///
/// RED-SUITE PLACEHOLDER: all-zero until the green implementation pins the real root.
pub const XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

/// The Circle deposit attestation crossing the note boundary (DC-2/DC-3): the raw 65-byte
/// `r‖s‖v` ECDSA signature over `keccak256(payload)` and the raw 33-byte compressed SEC1
/// candidate pubkey. Lengths are type-enforced; felt packing happens in [`XReserveMintNote`]
/// via the 04 codec by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintAttestation {
    signature: [u8; 65],
    pubkey: [u8; 33],
}

impl MintAttestation {
    /// Bundles a raw 65-byte `r‖s‖v` signature with the 33-byte compressed candidate pubkey.
    pub fn new(signature: [u8; 65], pubkey: [u8; 33]) -> Self {
        Self { signature, pubkey }
    }

    /// The raw 65-byte `r‖s‖v` signature (`v` carried, unused on-chain).
    pub fn signature(&self) -> &[u8; 65] {
        &self.signature
    }

    /// The raw 33-byte compressed SEC1 candidate pubkey.
    pub fn pubkey(&self) -> &[u8; 33] {
        &self.pubkey
    }
}

/// The production mint note (CMP-B1). A unit-struct factory in the N-11 idiom.
pub struct XReserveMintNote;

impl XReserveMintNote {
    /// The custom mint-note consume script (compiled from
    /// `asm/standards/notes/xreserve_mint_note.masm` with the xreserve component library linked).
    ///
    /// RED-SUITE STUB: an executing trap script so the suite runs red-for-the-right-reason.
    pub fn script() -> NoteScript {
        miden_standards::code_builder::CodeBuilder::new()
            .compile_note_script(
                "@note_script\n\
                 pub proc main\n\
                 \x20\x20\x20\x20push.0 assert.err=\"xreserve mint note script unimplemented\"\n\
                 end\n",
            )
            .expect("the stub mint-note script compiles")
    }

    /// The mint-note script root (must equal the pinned
    /// [`XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX`]; parity-tested).
    pub fn script_root() -> NoteScriptRoot {
        Self::script().root()
    }

    /// The pinned root constant as a [`NoteScriptRoot`].
    pub fn pinned_script_root() -> NoteScriptRoot {
        NoteScriptRoot::from_raw(
            miden_protocol::Word::parse(XRESERVE_MINT_NOTE_SCRIPT_ROOT_HEX)
                .expect("the pinned mint-note script root hex is a valid word"),
        )
    }

    /// Creates the production mint note: `sender` is the producer/relayer account, `faucet_id`
    /// the consuming faucet (account-target tag), `deposit_intent` the RAW DepositIntent payload
    /// bytes (validated + packed via the 04 codec by reference), `attestation` the raw sig +
    /// candidate pubkey (packed 17 + 9 felts into the single attachment, after the MVP-zero
    /// feeAmount limbs — DEV-8). Asset-less; `NoteType::Public` forced.
    ///
    /// RED-SUITE STUB: unimplemented — every consuming test runs and fails here.
    pub fn create<R: FeltRng>(
        _sender: AccountId,
        _faucet_id: AccountId,
        _deposit_intent: &[u8],
        _attestation: &MintAttestation,
        _rng: &mut R,
    ) -> Result<Note, NoteError> {
        Err(NoteError::other("xreserve mint note constructor unimplemented"))
    }
}
