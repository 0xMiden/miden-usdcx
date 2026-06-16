//! Constant-parity test (decision D-3): the MASM constants and their Rust counterparts
//! must satisfy the DERIVED cross-language relations (felt offsets are byte offsets / 4;
//! the packed magic/version are the u32-LE reinterpretations of the big-endian wire
//! values; the error strings are byte-identical). One-sided edits fail mechanically —
//! the `masm-rust-constant-parity` obligation (V2-05 seam closed at the constant layer).
//!
//! CS-5 hardening: parity is BIDIRECTIONAL — every constant parsed from the MASM
//! sources (numeric, string, and `word("…")` slot-name) must be covered by a parity row
//! or a documented exemption, so a new MASM-only constant fails this suite; the
//! `SCALE_EXP_MAX`/`MAX_SCALE_EXP` pair and `POW2_32` carry explicit rows; the 01 shell
//! module is included by reference (the 04 crate's `lib.rs` embeds only 04-owned
//! sources).

mod support;

use std::collections::BTreeMap;

use xusdc_encoding::xreserve::encoding::{
    DEPOSIT_INTENT_HEADER_FELTS, DEPOSIT_INTENT_HEADER_LEN, DEPOSIT_INTENT_MAGIC,
    DEPOSIT_INTENT_VERSION, DepositIntentField, ERR_MESSAGES, MAX_SCALE_EXP, PUBKEY_FELTS,
    deposit_intent_field_offset,
};
use xusdc_encoding::{ENCODING_MOD_MASM, LAYOUT_MASM};

/// The FAUCET(01) shell module source, read test-side by reference.
const SHELL_MASM: &str =
    include_str!("../../../asm/standards/xreserve/deposit_intent_parser.masm");

/// The FAUCET(01) D5d attestation-verify shell module source, read test-side by reference.
const ATTESTATION_VERIFY_MASM: &str =
    include_str!("../../../asm/standards/xreserve/attestation_verify.masm");

/// The FAUCET(01) D5e mint write-phase shell module source, read test-side by reference.
const XRESERVE_MINT_MASM: &str =
    include_str!("../../../asm/standards/xreserve/xreserve_mint.masm");

/// Faucet-owned shell error constants declared in MASM, pinned against the test-side
/// `support::SHELL_ERR_TABLE` (the single Rust source).
const SHELL_ERRORS_DECLARED: &[&str] = &[
    "ERR_XRESERVE_WRONG_DOMAIN",
    "ERR_XRESERVE_WRONG_IDENTIFIER",
    // D5b R-MINT-10 / R-MINT-11
    "ERR_XRESERVE_AMOUNT_BELOW_FEE",
    "ERR_XRESERVE_FEE_OVER_MAX",
    // D5c R-MINT-12
    "ERR_XRESERVE_NONCE_REPLAY",
    // D5d R-MINT-13 / R-MINT-14 (attestation_verify.masm)
    "ERR_XRESERVE_BAD_PK_COMMITMENT",
    "ERR_XRESERVE_SIG_INVALID",
    // D5e R-MINT-15 (xreserve_mint.masm)
    "ERR_XRESERVE_SUPPLY_CAP",
];

/// Expected `word("…")` slot-name constants of the shell module (name → label), pinned
/// against the test-side label consts.
const EXPECTED_SHELL_WORD_CONSTS: &[(&str, &str)] = &[
    ("DOMAIN_CONFIG_SLOT", support::DOMAIN_CONFIG_SLOT_LABEL),
    ("IDENTIFIER_CONFIG_SLOT", support::IDENTIFIER_CONFIG_SLOT_LABEL),
    ("USED_NONCES_SLOT", support::USED_NONCES_SLOT_LABEL),
];

/// Expected `word("…")` slot-name constant of the D5d attestation-verify shell module.
const EXPECTED_ATTESTATION_WORD_CONSTS: &[(&str, &str)] =
    &[("XRESERVE_ATTESTERS_SLOT", support::XRESERVE_ATTESTERS_SLOT_LABEL)];

/// Expected `word("…")` slot-name constant of the D5e mint shell module. `TOKEN_CONFIG_SLOT` is
/// hard-coded byte-identical to the standard FungibleFaucet slot label (CANONICAL-OWNERSHIP-MAP
/// :41; fungible.masm:26); `USED_NONCES_SLOT` is IMPORTED from deposit_intent_parser (no
/// redeclaration → not parsed here, no duplicate parity row, G1).
const EXPECTED_XRESERVE_MINT_WORD_CONSTS: &[(&str, &str)] =
    &[("TOKEN_CONFIG_SLOT", support::TOKEN_CONFIG_SLOT_LABEL)];

/// The D5d attestation-verify shell declares no numeric constants (word-aligned `@locals`
/// offsets are literal, matching `encoding/mod.masm::pubkey_commitment` and the precompile canary).
const ATTESTATION_COVERED_NUMS: &[&str] = &[];

/// D5e mint-shell numeric constants (NONCE_USED_MARKER is a Word array literal, not parsed).
/// P2ID_NUM_STORAGE_ITEMS is the local note-storage item count for the P2ID recipient build (2,
/// matching notes/p2id.masm's storage format); no Rust counterpart, covered here (CS-5).
const XRESERVE_MINT_COVERED_NUMS: &[&str] = &["P2ID_NUM_STORAGE_ITEMS"];

/// Numeric-constant coverage sets (bidirectional sweep): every numeric const parsed
/// from a MASM source must appear in its file's set — extending a MASM file with a new
/// numeric constant REQUIRES a parity row here.
const LAYOUT_COVERED_NUMS: &[&str] = &[
    "MAGIC_FELT_OFF",
    "VERSION_FELT_OFF",
    "AMOUNT_FELT_OFF",
    "REMOTE_DOMAIN_FELT_OFF",
    "REMOTE_TOKEN_FELT_OFF",
    "REMOTE_RECIPIENT_FELT_OFF",
    "LOCAL_TOKEN_FELT_OFF",
    "LOCAL_DEPOSITOR_FELT_OFF",
    "MAX_FEE_FELT_OFF",
    "NONCE_FELT_OFF",
    "HOOK_DATA_LEN_FELT_OFF",
    "HOOK_DATA_FELT_OFF",
    "DEPOSIT_INTENT_MAGIC_PACKED",
    "DEPOSIT_INTENT_VERSION_PACKED",
    "DEPOSIT_INTENT_HEADER_FELTS",
    "MAX_NOTE_STORAGE_FELTS",
];
const ENCODING_COVERED_NUMS: &[&str] = &["SCALE_EXP_MAX", "POW2_32", "PUBKEY_FELTS"];
const SHELL_COVERED_NUMS: &[&str] = &[];

/// Parses `const NAME = <value>` / `pub const NAME = <value>` lines from a MASM source.
/// Returns (numeric constants, string constants, word("…") slot-name constants).
fn parse_masm_consts(
    src: &str,
) -> (BTreeMap<String, u64>, BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut nums = BTreeMap::new();
    let mut strs = BTreeMap::new();
    let mut words = BTreeMap::new();
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
        } else if let Some(label) = value.strip_prefix("word(\"") {
            if let Some(l) = label.strip_suffix("\")") {
                words.insert(name, l.to_string());
            }
        } else if let Some(hex) = value.strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                nums.insert(name, v);
            }
        } else if let Ok(v) = value.parse::<u64>() {
            nums.insert(name, v);
        }
    }
    (nums, strs, words)
}

fn num(nums: &BTreeMap<String, u64>, name: &str, file: &str) -> u64 {
    *nums.get(name).unwrap_or_else(|| panic!("{file} must define const {name}"))
}

/// DC-1 relation: every MASM felt offset × 4 equals the Rust byte offset, the packed
/// magic/version equal the LE reinterpretation of the BE wire values, the header felt
/// count matches both sides, the NoteStorage bound is the frozen 1024 (N-4), and the
/// CS-5 rows pin the reducer's scale bound and limb base.
#[test]
fn masm_rust_constant_parity() {
    let (nums, _, _) = parse_masm_consts(LAYOUT_MASM);

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
            num(&nums, masm_name, "layout.masm") * 4,
            deposit_intent_field_offset(field) as u64,
            "DC-1 offset relation for {masm_name} (MASM felt offset x 4 == Rust byte offset)"
        );
    }

    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_MAGIC_PACKED", "layout.masm"),
        u32::from_le_bytes(DEPOSIT_INTENT_MAGIC.to_be_bytes()) as u64,
        "packed magic must be the u32-LE reinterpretation of the BE wire magic"
    );
    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_VERSION_PACKED", "layout.masm"),
        u32::from_le_bytes(DEPOSIT_INTENT_VERSION.to_be_bytes()) as u64,
        "packed version must be the u32-LE reinterpretation of the BE wire version"
    );
    assert_eq!(
        num(&nums, "DEPOSIT_INTENT_HEADER_FELTS", "layout.masm"),
        DEPOSIT_INTENT_HEADER_FELTS as u64,
        "header felt count must match across languages"
    );
    assert_eq!(
        DEPOSIT_INTENT_HEADER_LEN as u64,
        num(&nums, "DEPOSIT_INTENT_HEADER_FELTS", "layout.masm") * 4,
        "header byte length must be 4x the felt count (C-10 packing)"
    );
    assert_eq!(
        num(&nums, "MAX_NOTE_STORAGE_FELTS", "layout.masm"),
        1024,
        "NoteStorage felt bound is frozen at 1024 (EL N-4 :100)"
    );

    // CS-5 rows: the reducer's bound and limb base (names differ across languages for
    // the scale bound by frozen decision — MASM SCALE_EXP_MAX, Rust MAX_SCALE_EXP)
    let (enc_nums, _, _) = parse_masm_consts(ENCODING_MOD_MASM);
    assert_eq!(
        num(&enc_nums, "SCALE_EXP_MAX", "encoding/mod.masm"),
        MAX_SCALE_EXP as u64,
        "scale-exponent bound parity (MASM SCALE_EXP_MAX vs Rust MAX_SCALE_EXP)"
    );
    assert_eq!(
        num(&enc_nums, "POW2_32", "encoding/mod.masm"),
        1u64 << 32,
        "u32 limb base must be 2^32"
    );
    assert_eq!(
        num(&enc_nums, "PUBKEY_FELTS", "encoding/mod.masm"),
        PUBKEY_FELTS as u64,
        "compressed-pubkey felt count parity (33 bytes -> 9 u32-LE felts; ATT commitment input)"
    );
}

/// Error-string parity, Rust → MASM: every Rust `ERR_*` MasmError has an
/// identically-named MASM constant with a byte-identical message string in
/// `encoding/mod.masm`.
#[test]
fn masm_rust_error_string_parity() {
    let (_, strs, _) = parse_masm_consts(ENCODING_MOD_MASM);
    for (name, message) in ERR_MESSAGES {
        let masm = strs
            .get(name)
            .unwrap_or_else(|| panic!("encoding/mod.masm must define const {name} = \"...\""));
        assert_eq!(masm, message, "error message parity for {name}");
    }
}

/// Shell error-string parity, test-side Rust → MASM: every DECLARED faucet shell error
/// has an identically-named shell-module constant with the byte-identical
/// `support::SHELL_ERR_TABLE` message. (Staged: the list grows with the implementation
/// commits that declare the MASM consts.)
#[test]
fn masm_shell_error_string_parity() {
    // the faucet shell errors live across both shell modules (deposit_intent_parser.masm +
    // attestation_verify.masm); merge their string consts before the lookup.
    let (_, mut strs, _) = parse_masm_consts(SHELL_MASM);
    let (_, att_strs, _) = parse_masm_consts(ATTESTATION_VERIFY_MASM);
    let (_, mint_strs, _) = parse_masm_consts(XRESERVE_MINT_MASM);
    strs.extend(att_strs);
    strs.extend(mint_strs);
    for name in SHELL_ERRORS_DECLARED {
        let expected = support::SHELL_ERR_TABLE
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.message())
            .unwrap_or_else(|| panic!("SHELL_ERR_TABLE must carry {name}"));
        let masm = strs.get(*name).unwrap_or_else(|| {
            panic!("a faucet shell module must define const {name} = \"...\"")
        });
        assert_eq!(masm, expected, "shell error message parity for {name}");
    }
}

/// CS-5 bidirectional sweep: every constant parsed from every MASM source must be
/// covered by a parity row or a documented exemption — a new MASM-only constant
/// (numeric, string, or `word("…")`) fails here until it gets a row.
#[test]
fn masm_constants_bidirectional() {
    // every MASM-only string constant must be a known error (04 table or the faucet shell
    // table); a new one fails here until it gets a row (CS-5)
    let known_err = |name: &str| {
        ERR_MESSAGES.iter().any(|(n, _)| *n == name)
            || support::SHELL_ERR_TABLE.iter().any(|(n, _)| *n == name)
    };
    let sources: [(&str, &str, &[&str], &[(&str, &str)]); 5] = [
        ("layout.masm", LAYOUT_MASM, LAYOUT_COVERED_NUMS, &[]),
        ("encoding/mod.masm", ENCODING_MOD_MASM, ENCODING_COVERED_NUMS, &[]),
        ("deposit_intent_parser.masm", SHELL_MASM, SHELL_COVERED_NUMS, EXPECTED_SHELL_WORD_CONSTS),
        (
            "attestation_verify.masm",
            ATTESTATION_VERIFY_MASM,
            ATTESTATION_COVERED_NUMS,
            EXPECTED_ATTESTATION_WORD_CONSTS,
        ),
        (
            "xreserve_mint.masm",
            XRESERVE_MINT_MASM,
            XRESERVE_MINT_COVERED_NUMS,
            EXPECTED_XRESERVE_MINT_WORD_CONSTS,
        ),
    ];
    for (file, src, covered_nums, expected_words) in sources {
        let (nums, strs, words) = parse_masm_consts(src);
        for name in nums.keys() {
            assert!(
                covered_nums.contains(&name.as_str()),
                "unmapped MASM numeric constant {name} in {file}: add a parity row or a \
                 documented exemption (CS-5)"
            );
        }
        for name in strs.keys() {
            assert!(
                known_err(name),
                "unmapped MASM string constant {name} in {file}: add an error parity row \
                 or a documented exemption (CS-5)"
            );
        }
        for name in words.keys() {
            assert!(
                expected_words.iter().any(|(n, _)| n == name),
                "unmapped MASM word(\"…\") constant {name} in {file}: add a slot-label \
                 parity row (CS-5)"
            );
        }
        for (name, label) in expected_words {
            let masm_label = words
                .get(*name)
                .unwrap_or_else(|| panic!("{file} must define const {name} = word(\"…\")"));
            assert_eq!(masm_label, label, "slot-label parity for {name} in {file}");
        }
    }
}
