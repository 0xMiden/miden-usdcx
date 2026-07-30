//! Decoding and structurally validating a DepositIntent before it is relayed.
//!
//! This is a LIVENESS check, not a safety one. The faucet parses the intent again on-chain, reduces
//! the amount again, and re-runs every field assert before it mints; a bug here can only stop a
//! legitimate deposit from being relayed, never cause an illegitimate one to be minted. What it
//! buys is a fast, local rejection with a precise reason, instead of a transaction that fails
//! on-chain.
//!
//! The wire layout — byte offsets, field widths, the u32-little-endian packing, and the
//! note-storage size bound — is owned by the shared `xusdc-encoding` crate and used from here; this
//! module never restates an offset or re-implements the codec. That single ownership is what keeps
//! the off-chain and on-chain views of the same bytes from drifting.
//!
//! One arithmetic trap is worth naming, because it is easy to get wrong and silently wrong: the
//! 240-byte header packs to 60 field elements, not 30. Each element holds four bytes, not eight.

use xusdc_encoding::xreserve::encoding::{
    deposit_intent_to_packed_felts, parse_deposit_intent_header, DepositIntentHeader,
    DEPOSIT_INTENT_HEADER_FELTS, DEPOSIT_INTENT_HEADER_LEN,
};

use crate::error::RelayerError;

/// A structurally validated DepositIntent — **valid by construction**. The ONLY way to
/// obtain one is [`decode_and_validate_deposit_intent`], which runs the full structural parse and
/// the NoteStorage-bound guard; the fields are private and read-only via accessors, so a caller
/// cannot forge a zero amount, an inconsistent `hook_data_len`/`hook_data`, or an unrelated
/// `raw_preimage`.
///
/// The parsed header fields are held as the shared encoding crate's canonical
/// [`DepositIntentHeader`] (not a duplicated field model). `amount` and `max_fee` are carried RAW
/// (32-byte big-endian) — the relayer performs NO `uint256 → AssetAmount` reduction; that happens
/// on-chain in the faucet's amount reduction. `raw_preimage` is the exact `240 + hookDataLen` bytes
/// the Miden-facing slice u32-LE-packs into `NoteStorage`.
#[derive(Debug, Clone)]
pub struct DepositIntent {
    header: DepositIntentHeader,
    hook_data: Vec<u8>,
    raw_preimage: Vec<u8>,
}

impl DepositIntent {
    /// `magic` (header field 0; validated `== 0x5a2e0acd`).
    pub fn magic(&self) -> u32 {
        self.header.magic
    }

    /// `version` (header field 1; validated `== 1`).
    pub fn version(&self) -> u32 {
        self.header.version
    }

    /// `amount` — RAW 32-byte big-endian uint256; NOT reduced off-chain.
    pub fn amount(&self) -> &[u8; 32] {
        &self.header.amount
    }

    /// `remoteDomain` (header field 3).
    pub fn remote_domain(&self) -> u32 {
        self.header.remote_domain
    }

    /// `remoteToken` (header field 4).
    pub fn remote_token(&self) -> &[u8; 32] {
        &self.header.remote_token
    }

    /// `remoteRecipient` (header field 5).
    pub fn remote_recipient(&self) -> &[u8; 32] {
        &self.header.remote_recipient
    }

    /// `localToken` (header field 6; validated non-zero).
    pub fn local_token(&self) -> &[u8; 32] {
        &self.header.local_token
    }

    /// `localDepositor` (header field 7; validated non-zero).
    pub fn local_depositor(&self) -> &[u8; 32] {
        &self.header.local_depositor
    }

    /// `maxFee` — RAW 32-byte big-endian uint256; NOT reduced off-chain.
    pub fn max_fee(&self) -> &[u8; 32] {
        &self.header.max_fee
    }

    /// `nonce` (header field 9).
    pub fn nonce(&self) -> &[u8; 32] {
        &self.header.nonce
    }

    /// `hookDataLen` (header field 10; validated `== hook_data().len()`).
    pub fn hook_data_len(&self) -> u32 {
        self.header.hook_data_len
    }

    /// The variable `hookData` bytes (header field 11), exactly `hook_data_len()` bytes long.
    pub fn hook_data(&self) -> &[u8] {
        &self.hook_data
    }

    /// The exact `240 + hookDataLen` on-wire preimage the Miden-facing slice u32-LE-packs into
    /// `NoteStorage`.
    pub fn raw_preimage(&self) -> &[u8] {
        &self.raw_preimage
    }

    /// The u32-LE felt count of the `NoteStorage` preimage: `60 + ceil(hookDataLen / 4)`. Derived
    /// from the ACTUAL preimage bytes (`hook_data().len()`), not a trusted length field, and the
    /// header is [`DEPOSIT_INTENT_HEADER_FELTS`] (= 60, imported from the shared encoding crate) —
    /// never 240/8 = 30.
    pub fn preimage_felt_len(&self) -> usize {
        DEPOSIT_INTENT_HEADER_FELTS + self.hook_data.len().div_ceil(4)
    }
}

/// Decodes and structurally validates a DepositIntent payload — the off-chain fast-fail mirror of
/// the parse the faucet performs on-chain.
///
/// Every offset, field check, packing rule, and the note-storage size bound come from the shared
/// encoding crate; this function's own work is mapping each rejection onto the field-specific
/// relayer error, so an operator sees which rule the payload broke.
///
/// The checks, all performed by the shared codec: `magic == 0x5a2e0acd`, `version == 1`, `len ==
/// 240 + hookDataLen`, `amount != 0`, `localToken != 0`, `localDepositor != 0`, and that the u32-LE
/// preimage fits the 1024-felt `NoteStorage` bound. Returns the exact failed-field variant on
/// rejection.
pub fn decode_and_validate_deposit_intent(payload: &[u8]) -> Result<DepositIntent, RelayerError> {
    // Structural parse + field checks — the shared encoding crate owns the offsets and the
    // structural
    // checks (magic/version/length/zero-field/truncation).
    let header = parse_deposit_intent_header(payload).map_err(RelayerError::from_deposit_intent)?;

    // Felt-count / NoteStorage-bound guard (four bytes per felt, so 60 and never 30). Delegated to
    // the shared encoding crate's packer so the
    // 60-felt header count and the 1024-felt bound have exactly one owner; an oversized preimage
    // surfaces as `PreimageTooLarge`. (This re-runs the structural checks, which already passed.)
    deposit_intent_to_packed_felts(payload).map_err(RelayerError::from_deposit_intent)?;

    // `parse_deposit_intent_header` guarantees `payload.len() == 240 + hookDataLen >= 240`, so the
    // hookData slice and the full-preimage copy below are in-bounds and mutually consistent.
    Ok(DepositIntent {
        header,
        hook_data: payload[DEPOSIT_INTENT_HEADER_LEN..].to_vec(),
        raw_preimage: payload.to_vec(),
    })
}
