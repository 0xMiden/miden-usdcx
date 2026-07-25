//! DepositIntent layout + parse family, frozen signatures per the shared-encoding spec
//! (INV-DEPOSITINTENT-PARSE; DC-1). Implemented per the frozen validation order — this library
//! owns the STRUCTURAL checks only (magic, version, truncation, length relation,
//! amount/localToken/localDepositor nonzero); the domain/identifier equality compares are
//! faucet-owned (D5a steps 5–6) and out of scope. The hookData cap is
//! `REQUIRES CIRCLE CONFIRMATION` (DEV-6) — the 1024-felt NoteStorage bound is the documented
//! default, not a resolution.

use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::Felt;

use super::error::EncodingError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositIntentField {
    Magic,
    Version,
    Amount,
    RemoteDomain,
    RemoteToken,
    RemoteRecipient,
    LocalToken,
    LocalDepositor,
    MaxFee,
    Nonce,
    HookDataLen,
    HookData,
}

/// DC-1 constants (the 240-byte header packs to 60 u32-LE felts, 4 bytes per felt — NOT 240/8).
pub const DEPOSIT_INTENT_HEADER_LEN: usize = 240;
pub const DEPOSIT_INTENT_MAGIC: u32 = 0x5a2e_0acd;
pub const DEPOSIT_INTENT_VERSION: u32 = 1;
pub const DEPOSIT_INTENT_HEADER_FELTS: usize = 60;

/// The NoteStorage felt bound (the DEV-6 hookData cap default).
const MAX_NOTE_STORAGE_FELTS: usize = 1024;

/// Fixed-offset accessor (offsets per the DC-1 table, byte positions on the wire).
pub fn deposit_intent_field_offset(field: DepositIntentField) -> usize {
    match field {
        DepositIntentField::Magic => 0,
        DepositIntentField::Version => 4,
        DepositIntentField::Amount => 8,
        DepositIntentField::RemoteDomain => 40,
        DepositIntentField::RemoteToken => 44,
        DepositIntentField::RemoteRecipient => 76,
        DepositIntentField::LocalToken => 108,
        DepositIntentField::LocalDepositor => 140,
        DepositIntentField::MaxFee => 172,
        DepositIntentField::Nonce => 204,
        DepositIntentField::HookDataLen => 236,
        DepositIntentField::HookData => 240,
    }
}

#[derive(Debug, Clone)]
pub struct DepositIntentHeader {
    pub magic: u32,
    pub version: u32,
    pub amount: [u8; 32],
    pub remote_domain: u32,
    pub remote_token: [u8; 32],
    pub remote_recipient: [u8; 32],
    pub local_token: [u8; 32],
    pub local_depositor: [u8; 32],
    pub max_fee: [u8; 32],
    pub nonce: [u8; 32],
    pub hook_data_len: u32,
}

/// Reads a big-endian u32 wire field (the caller has bounds-checked the slice).
fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("4-byte window"))
}

/// Copies a 32-byte wire field (the caller has bounds-checked the slice).
fn bytes32_at(bytes: &[u8], offset: usize) -> [u8; 32] {
    bytes[offset..offset + 32]
        .try_into()
        .expect("32-byte window")
}

/// Structural parse + the library-owned checks (truncation, magic, version, non-zero
/// fields, total-length relation). Does NOT perform the faucet-owned domain/identifier
/// equality compares (D5a steps 5–6).
pub fn parse_deposit_intent_header(bytes: &[u8]) -> Result<DepositIntentHeader, EncodingError> {
    // the bounds guard necessarily precedes any field read (the TruncatedHeader case)
    if bytes.len() < DEPOSIT_INTENT_HEADER_LEN {
        return Err(EncodingError::TruncatedHeader);
    }

    let magic = be_u32(
        bytes,
        deposit_intent_field_offset(DepositIntentField::Magic),
    );
    if magic != DEPOSIT_INTENT_MAGIC {
        return Err(EncodingError::BadMagic);
    }

    let version = be_u32(
        bytes,
        deposit_intent_field_offset(DepositIntentField::Version),
    );
    if version != DEPOSIT_INTENT_VERSION {
        return Err(EncodingError::BadVersion);
    }

    let amount = bytes32_at(
        bytes,
        deposit_intent_field_offset(DepositIntentField::Amount),
    );
    if amount.iter().all(|&b| b == 0) {
        return Err(EncodingError::ZeroField {
            field: DepositIntentField::Amount,
        });
    }

    let local_token = bytes32_at(
        bytes,
        deposit_intent_field_offset(DepositIntentField::LocalToken),
    );
    if local_token.iter().all(|&b| b == 0) {
        return Err(EncodingError::ZeroField {
            field: DepositIntentField::LocalToken,
        });
    }

    let local_depositor = bytes32_at(
        bytes,
        deposit_intent_field_offset(DepositIntentField::LocalDepositor),
    );
    if local_depositor.iter().all(|&b| b == 0) {
        return Err(EncodingError::ZeroField {
            field: DepositIntentField::LocalDepositor,
        });
    }

    let hook_data_len = be_u32(
        bytes,
        deposit_intent_field_offset(DepositIntentField::HookDataLen),
    );
    // total = 240 + hookDataLen, computed in u64 so an adversarial length cannot overflow
    let expected_len = (DEPOSIT_INTENT_HEADER_LEN as u64) + u64::from(hook_data_len);
    if bytes.len() as u64 != expected_len {
        return Err(EncodingError::LengthMismatch);
    }

    Ok(DepositIntentHeader {
        magic,
        version,
        amount,
        remote_domain: be_u32(
            bytes,
            deposit_intent_field_offset(DepositIntentField::RemoteDomain),
        ),
        remote_token: bytes32_at(
            bytes,
            deposit_intent_field_offset(DepositIntentField::RemoteToken),
        ),
        remote_recipient: bytes32_at(
            bytes,
            deposit_intent_field_offset(DepositIntentField::RemoteRecipient),
        ),
        local_token,
        local_depositor,
        max_fee: bytes32_at(
            bytes,
            deposit_intent_field_offset(DepositIntentField::MaxFee),
        ),
        nonce: bytes32_at(
            bytes,
            deposit_intent_field_offset(DepositIntentField::Nonce),
        ),
        hook_data_len,
    })
}

/// The u32-LE-packed on-chain preimage: 60 felts for the header plus ceil(hookDataLen/4)
/// felts of hookData (the same `bytes_to_packed_u32_elements` primitive). Validates the
/// structure first, then errors `HookDataTooLarge` past the 1024-felt NoteStorage bound
/// (DEV-6 default).
pub fn deposit_intent_to_packed_felts(bytes: &[u8]) -> Result<Vec<Felt>, EncodingError> {
    parse_deposit_intent_header(bytes)?;
    let felts = bytes_to_packed_u32_elements(bytes);
    if felts.len() > MAX_NOTE_STORAGE_FELTS {
        return Err(EncodingError::HookDataTooLarge);
    }
    Ok(felts)
}
// TESTS — TV-DI-1..9
// ================================================================================================

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use super::*;
    use crate::vectors::load;

    /// TV-DI-1 (happy path, written first): a full header + hookData parses to the exact
    /// per-field values at the DC-1 offsets.
    #[test]
    fn tv_di_1_positive_parse() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let bytes = vec.bytes();
            let h = parse_deposit_intent_header(&bytes)
                .unwrap_or_else(|e| panic!("vector {}: must parse, got {e}", vec.id));
            let f = vec.fields.as_ref().expect("accept vector carries fields");
            assert_eq!(h.magic, f.magic, "vector {}: magic", vec.id);
            assert_eq!(h.version, f.version, "vector {}: version", vec.id);
            assert_eq!(
                h.remote_domain, f.remote_domain,
                "vector {}: remoteDomain",
                vec.id
            );
            assert_eq!(
                h.hook_data_len, f.hook_data_len,
                "vector {}: hookDataLen",
                vec.id
            );
            assert_eq!(h.amount, f.bytes32("amount"), "vector {}: amount", vec.id);
            assert_eq!(
                h.remote_token,
                f.bytes32("remote_token"),
                "vector {}: remoteToken",
                vec.id
            );
            assert_eq!(
                h.remote_recipient,
                f.bytes32("remote_recipient"),
                "vector {}: remoteRecipient",
                vec.id
            );
            assert_eq!(
                h.local_token,
                f.bytes32("local_token"),
                "vector {}: localToken",
                vec.id
            );
            assert_eq!(
                h.local_depositor,
                f.bytes32("local_depositor"),
                "vector {}: localDepositor",
                vec.id
            );
            assert_eq!(h.max_fee, f.bytes32("max_fee"), "vector {}: maxFee", vec.id);
            assert_eq!(h.nonce, f.bytes32("nonce"), "vector {}: nonce", vec.id);
        }
    }

    /// TV-DI-2..6 (negative, parametrized): each structural violation rejects with its
    /// SPECIFIC variant (one named case per frozen harness row).
    #[rstest]
    #[case::tv_di_2_bad_magic("di-rej-bad-magic")]
    #[case::tv_di_3_bad_version("di-rej-bad-version")]
    #[case::tv_di_4_zero_amount("di-rej-zero-amount")]
    #[case::tv_di_5_zero_local_token("di-rej-zero-local-token")]
    #[case::tv_di_5_zero_local_depositor("di-rej-zero-local-depositor")]
    #[case::tv_di_6_length_mismatch("di-rej-length-mismatch")]
    #[case::tv_di_6_truncated_header("di-rej-truncated")]
    fn tv_di_rejects(#[case] id: &str) {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == id)
            .expect("vector present");
        let result = parse_deposit_intent_header(&vec.bytes());
        match vec.expected_variant.as_deref() {
            Some("BadMagic") => assert_matches!(result, Err(EncodingError::BadMagic), "{id}"),
            Some("BadVersion") => assert_matches!(result, Err(EncodingError::BadVersion), "{id}"),
            Some("ZeroField:Amount") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::Amount
                }),
                "{id}"
            ),
            Some("ZeroField:LocalToken") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalToken
                }),
                "{id}"
            ),
            Some("ZeroField:LocalDepositor") => assert_matches!(
                result,
                Err(EncodingError::ZeroField {
                    field: DepositIntentField::LocalDepositor
                }),
                "{id}"
            ),
            Some("LengthMismatch") => {
                assert_matches!(result, Err(EncodingError::LengthMismatch), "{id}")
            }
            Some("TruncatedHeader") => {
                assert_matches!(result, Err(EncodingError::TruncatedHeader), "{id}")
            }
            other => panic!("vector {id}: unexpected expected_variant {other:?}"),
        }
    }

    /// TV-DI-7 (boundary, anti-ASG-16): the packed header is exactly 60 felts (NOT 30),
    /// equals the committed preimage, stays within the 1024-felt bound, and the overflow
    /// vector rejects with `HookDataTooLarge` (DEV-6 stays OPEN).
    #[test]
    fn tv_di_7_sixty_felts_and_1024_bound() {
        let v = load();
        for vec in v.families.di.iter().filter(|v| v.kind == "accept") {
            let felts = deposit_intent_to_packed_felts(&vec.bytes())
                .unwrap_or_else(|e| panic!("vector {}: must pack, got {e}", vec.id));
            let expected = vec.preimage_values();
            assert_eq!(
                felts.len(),
                expected.len(),
                "vector {}: total felts",
                vec.id
            );
            assert_eq!(
                &felts[..60],
                &expected[..60],
                "vector {}: 60-felt header",
                vec.id
            );
            assert_eq!(felts, expected, "vector {}: full preimage", vec.id);
            assert!(felts.len() <= 1024, "vector {}: NoteStorage bound", vec.id);
        }
        let overflow = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-rej-hookdata-overflow")
            .expect("vector");
        assert_matches!(
            deposit_intent_to_packed_felts(&overflow.bytes()),
            Err(EncodingError::HookDataTooLarge),
            "hookData past the 1024-felt bound must reject (DEV-6 label preserved)"
        );
    }

    /// TV-DI-8 (determinism/immutability): parsing borrows the input immutably and the
    /// bytes are unchanged afterwards (note-input immutability analogue).
    #[test]
    fn tv_di_8_input_immutable() {
        let v = load();
        let vec = v
            .families
            .di
            .iter()
            .find(|v| v.id == "di-pos-hookdata")
            .expect("vector");
        let bytes = vec.bytes();
        let before = bytes.clone();
        let _ = parse_deposit_intent_header(&bytes);
        assert_eq!(bytes, before, "input must be unchanged by parsing");
    }

    /// TV-DI-9 (layout table): every field offset equals the DC-1 byte offset.
    #[test]
    fn tv_di_9_offsets_table() {
        let expected: [(DepositIntentField, usize); 12] = [
            (DepositIntentField::Magic, 0),
            (DepositIntentField::Version, 4),
            (DepositIntentField::Amount, 8),
            (DepositIntentField::RemoteDomain, 40),
            (DepositIntentField::RemoteToken, 44),
            (DepositIntentField::RemoteRecipient, 76),
            (DepositIntentField::LocalToken, 108),
            (DepositIntentField::LocalDepositor, 140),
            (DepositIntentField::MaxFee, 172),
            (DepositIntentField::Nonce, 204),
            (DepositIntentField::HookDataLen, 236),
            (DepositIntentField::HookData, 240),
        ];
        for (field, off) in expected {
            assert_eq!(
                deposit_intent_field_offset(field),
                off,
                "DC-1 offset of {field:?}"
            );
        }
    }
}
