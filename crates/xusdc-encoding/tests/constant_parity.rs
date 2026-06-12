//! Constant-parity test (decision D-3): the MASM constants and their Rust counterparts
//! must satisfy the DERIVED cross-language relations (felt offsets are byte offsets / 4;
//! the packed magic/version are the u32-LE reinterpretations of the big-endian wire
//! values; the error strings are byte-identical). One-sided edits fail mechanically —
//! the `masm-rust-constant-parity` obligation (V2-05 seam closed at the constant layer).

use std::collections::BTreeMap;

use xusdc_encoding::xreserve::encoding::{
    DEPOSIT_INTENT_HEADER_FELTS, DEPOSIT_INTENT_HEADER_LEN, DEPOSIT_INTENT_MAGIC,
    DEPOSIT_INTENT_VERSION, DepositIntentField, ERR_MESSAGES, deposit_intent_field_offset,
};
use xusdc_encoding::{ENCODING_MOD_MASM, LAYOUT_MASM};

/// Parses `const NAME = <value>` / `pub const NAME = <value>` lines from a MASM source.
/// Returns (numeric constants, string constants).
fn parse_masm_consts(src: &str) -> (BTreeMap<String, u64>, BTreeMap<String, String>) {
    let mut nums = BTreeMap::new();
    let mut strs = BTreeMap::new();
    for line in src.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("pub const ").or_else(|| line.strip_prefix("const ")) {
            Some(r) => r,
            None => continue,
        };
        let Some((name, value)) = rest.split_once('=') else { continue };
        let (name, value) = (name.trim().to_string(), value.trim());
        if let Some(stripped) = value.strip_prefix('"') {
            if let Some(s) = stripped.strip_suffix('"') {
                strs.insert(name, s.to_string());
            }
        } else if let Some(hex) = value.strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                nums.insert(name, v);
            }
        } else if let Ok(v) = value.parse::<u64>() {
            nums.insert(name, v);
        }
    }
    (nums, strs)
}

fn layout_num(nums: &BTreeMap<String, u64>, name: &str) -> u64 {
    *nums.get(name).unwrap_or_else(|| panic!("layout.masm must define const {name}"))
}

/// DC-1 relation: every MASM felt offset × 4 equals the Rust byte offset, the packed
/// magic/version equal the LE reinterpretation of the BE wire values, the header felt
/// count matches both sides, and the NoteStorage bound is the frozen 1024 (N-4).
#[test]
fn masm_rust_constant_parity() {
    let (nums, _) = parse_masm_consts(LAYOUT_MASM);

    let offsets: [(&str, DepositIntentField); 12] = [
        ("MAGIC_FELT_OFF", DepositIntentField::Magic),
        ("VERSION_FELT_OFF", DepositIntentField::Version),
        ("AMOUNT_FELT_OFF", DepositIntentField::Amount),
        ("REMOTE_DOMAIN_FELT_OFF", DepositIntentField::RemoteDomain),
        ("REMOTE_TOKEN_FELT_OFF", DepositIntentField::RemoteToken),
        ("REMOTE_RECIPIENT_FELT_OFF", DepositIntentField::RemoteRecipient),
        ("LOCAL_TOKEN_FELT_OFF", DepositIntentField::LocalToken),
        ("LOCAL_DEPOSITOR_FELT_OFF", DepositIntentField::LocalDepositor),
        ("MAX_FEE_FELT_OFF", DepositIntentField::MaxFee),
        ("NONCE_FELT_OFF", DepositIntentField::Nonce),
        ("HOOK_DATA_LEN_FELT_OFF", DepositIntentField::HookDataLen),
        ("HOOK_DATA_FELT_OFF", DepositIntentField::HookData),
    ];
    for (masm_name, field) in offsets {
        assert_eq!(
            layout_num(&nums, masm_name) * 4,
            deposit_intent_field_offset(field) as u64,
            "DC-1 offset relation for {masm_name} (MASM felt offset x 4 == Rust byte offset)"
        );
    }

    assert_eq!(
        layout_num(&nums, "DEPOSIT_INTENT_MAGIC_PACKED"),
        u32::from_le_bytes(DEPOSIT_INTENT_MAGIC.to_be_bytes()) as u64,
        "packed magic must be the u32-LE reinterpretation of the BE wire magic"
    );
    assert_eq!(
        layout_num(&nums, "DEPOSIT_INTENT_VERSION_PACKED"),
        u32::from_le_bytes(DEPOSIT_INTENT_VERSION.to_be_bytes()) as u64,
        "packed version must be the u32-LE reinterpretation of the BE wire version"
    );
    assert_eq!(
        layout_num(&nums, "DEPOSIT_INTENT_HEADER_FELTS"),
        DEPOSIT_INTENT_HEADER_FELTS as u64,
        "header felt count must match across languages"
    );
    assert_eq!(
        DEPOSIT_INTENT_HEADER_LEN as u64,
        layout_num(&nums, "DEPOSIT_INTENT_HEADER_FELTS") * 4,
        "header byte length must be 4x the felt count (C-10 packing)"
    );
    assert_eq!(
        layout_num(&nums, "MAX_NOTE_STORAGE_FELTS"),
        1024,
        "NoteStorage felt bound is frozen at 1024 (EL N-4 :100)"
    );
}

/// Error-string parity: every Rust `ERR_*` MasmError has an identically-named MASM
/// constant with a byte-identical message string in `encoding/mod.masm`.
#[test]
fn masm_rust_error_string_parity() {
    let (_, strs) = parse_masm_consts(ENCODING_MOD_MASM);
    for (name, message) in ERR_MESSAGES {
        let masm = strs
            .get(name)
            .unwrap_or_else(|| panic!("encoding/mod.masm must define const {name} = \"...\""));
        assert_eq!(masm, message, "error message parity for {name}");
    }
}
