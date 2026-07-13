//! Off-chain DepositIntent structural decoder + validator — the fast-fail mirror of the on-chain
//! D5a parse (INV-DEPOSITINTENT-PARSE, DC-1). This is a LIVENESS check: the authoritative parse,
//! the `uint256 → AssetAmount` amount reduction, and every safety check run on-chain in
//! `xreserve_mint`; a relayer bug here can only withhold a mint, never authorize one (§1.2).
//!
//! The layout, byte offsets, field checks, u32-LE packing, and the 1024-felt NoteStorage bound are
//! OWNED by unit-04 (`xusdc-encoding`, `xreserve::encoding`) and consumed here BY REFERENCE
//! (single-owner rule). This module NEVER re-derives an offset or re-implements the codec — in
//! particular it never computes the header as `240 / 8 = 30` felts (the banned ASG-16 shortcut);
//! the 240-byte header is 60 u32-LE felts.

use xusdc_encoding::xreserve::encoding::{
    deposit_intent_to_packed_felts, parse_deposit_intent_header, DepositIntentHeader,
    DEPOSIT_INTENT_HEADER_FELTS, DEPOSIT_INTENT_HEADER_LEN,
};

use crate::error::RelayerError;

/// A structurally validated DepositIntent (DC-1) — **valid by construction**. The ONLY way to
/// obtain one is [`decode_and_validate_deposit_intent`], which runs the full structural parse and
/// the NoteStorage-bound guard; the fields are private and read-only via accessors, so a caller
/// cannot forge a zero amount, an inconsistent `hook_data_len`/`hook_data`, or an unrelated
/// `raw_preimage`.
///
/// The parsed header fields are held as unit-04's canonical [`DepositIntentHeader`] (not a
/// duplicated field model). `amount` and `max_fee` are carried RAW (32-byte big-endian) — the
/// relayer performs NO `uint256 → AssetAmount` reduction; that happens on-chain at D5b.
/// `raw_preimage` is the exact `240 + hookDataLen` bytes the Miden-facing slice u32-LE-packs into
/// `NoteStorage`.
#[derive(Debug, Clone)]
pub struct DepositIntent {
    header: DepositIntentHeader,
    hook_data: Vec<u8>,
    raw_preimage: Vec<u8>,
}

impl DepositIntent {
    /// `magic` (DC-1 field 0; validated `== 0x5a2e0acd`).
    pub fn magic(&self) -> u32 {
        self.header.magic
    }

    /// `version` (DC-1 field 1; validated `== 1`).
    pub fn version(&self) -> u32 {
        self.header.version
    }

    /// `amount` — RAW 32-byte big-endian uint256; NOT reduced off-chain.
    pub fn amount(&self) -> &[u8; 32] {
        &self.header.amount
    }

    /// `remoteDomain` (DC-1 field 3).
    pub fn remote_domain(&self) -> u32 {
        self.header.remote_domain
    }

    /// `remoteToken` (DC-1 field 4).
    pub fn remote_token(&self) -> &[u8; 32] {
        &self.header.remote_token
    }

    /// `remoteRecipient` (DC-1 field 5).
    pub fn remote_recipient(&self) -> &[u8; 32] {
        &self.header.remote_recipient
    }

    /// `localToken` (DC-1 field 6; validated non-zero).
    pub fn local_token(&self) -> &[u8; 32] {
        &self.header.local_token
    }

    /// `localDepositor` (DC-1 field 7; validated non-zero).
    pub fn local_depositor(&self) -> &[u8; 32] {
        &self.header.local_depositor
    }

    /// `maxFee` — RAW 32-byte big-endian uint256; NOT reduced off-chain.
    pub fn max_fee(&self) -> &[u8; 32] {
        &self.header.max_fee
    }

    /// `nonce` (DC-1 field 9).
    pub fn nonce(&self) -> &[u8; 32] {
        &self.header.nonce
    }

    /// `hookDataLen` (DC-1 field 10; validated `== hook_data().len()`).
    pub fn hook_data_len(&self) -> u32 {
        self.header.hook_data_len
    }

    /// The variable `hookData` bytes (DC-1 field 11), exactly `hook_data_len()` bytes long.
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
    /// header is [`DEPOSIT_INTENT_HEADER_FELTS`] (= 60, imported from unit-04) — anti-ASG-16, never
    /// 240/8 = 30.
    pub fn preimage_felt_len(&self) -> usize {
        DEPOSIT_INTENT_HEADER_FELTS + self.hook_data.len().div_ceil(4)
    }
}

/// Decodes and structurally validates a DepositIntent payload (the off-chain fast-fail mirror of
/// D5a). Delegates every offset, field check, packing rule, and the 1024-felt bound to unit-04, and
/// maps each unit-04 rejection onto the field-specific relayer variant.
///
/// Asserts (via unit-04): `magic == 0x5a2e0acd`, `version == 1`, `len == 240 + hookDataLen`,
/// `amount != 0`, `localToken != 0`, `localDepositor != 0`, and that the u32-LE preimage fits the
/// 1024-felt `NoteStorage` bound. Returns the exact failed-field variant on rejection.
pub fn decode_and_validate_deposit_intent(payload: &[u8]) -> Result<DepositIntent, RelayerError> {
    // Structural parse + field checks — unit-04 owns the offsets and the INV-DEPOSITINTENT-PARSE
    // checks (magic/version/length/zero-field/truncation).
    let header = parse_deposit_intent_header(payload).map_err(RelayerError::from_deposit_intent)?;

    // Felt-count / NoteStorage-bound guard (anti-ASG-16). Delegated to unit-04's packer so the
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
