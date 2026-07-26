//! Constant-parity test: the MASM constants and their Rust counterparts
//! must satisfy the DERIVED cross-language relations (felt offsets are byte offsets / 4;
//! the packed magic/version are the u32-LE reinterpretations of the big-endian wire
//! values; the error strings are byte-identical). One-sided edits fail mechanically —
//! the `masm-rust-constant-parity` obligation, closed at the constant layer.
//!
//! Bidirectional hardening: parity is BIDIRECTIONAL — every constant parsed from the MASM
//! sources (numeric, string, and `word("…")` slot-name) must be covered by a parity row
//! or a documented exemption, so a new MASM-only constant fails this suite; the
//! `SCALE_EXP_MAX`/`MAX_SCALE_EXP` pair and `POW2_32` carry explicit rows; the faucet shell
//! module is included by reference (the encoding crate's `lib.rs` embeds only its own
//! sources).

mod support;

use std::collections::BTreeMap;

use miden_protocol::account::RoleSymbol;
use xusdc_encoding::account::xreserve::{BLK_MANAGER_ROLE, DOM_PAUSER_ROLE};
use xusdc_encoding::note::xreserve_mint::{
    XRESERVE_MINT_ATTACHMENT_NUM_WORDS, XRESERVE_MINT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::{
    deposit_intent_field_offset, DepositIntentField, DEPOSIT_INTENT_HEADER_FELTS,
    DEPOSIT_INTENT_HEADER_LEN, DEPOSIT_INTENT_MAGIC, DEPOSIT_INTENT_VERSION, ERR_MESSAGES,
    MAX_SCALE_EXP, PUBKEY_FELTS,
};
use xusdc_encoding::{ENCODING_MOD_MASM, LAYOUT_MASM};

/// The faucet shell module source, read test-side by reference.
const SHELL_MASM: &str = include_str!("../../../asm/standards/xreserve/deposit_intent_parser.masm");

/// The faucet D5d attestation-verify shell module source, read test-side by reference.
const ATTESTATION_VERIFY_MASM: &str =
    include_str!("../../../asm/standards/xreserve/attestation_verify.masm");

/// The faucet D5e mint write-phase shell module source, read test-side by reference.
const XRESERVE_MINT_MASM: &str = include_str!("../../../asm/standards/xreserve/xreserve_mint.masm");

/// The faucet R-MINT-16 mint-deny guard module source, read test-side by reference.
const MINT_DENY_GUARD_MASM: &str =
    include_str!("../../../asm/standards/xreserve/mint_deny_guard.masm");

/// The faucet set_attester admin module source, read test-side by reference.
const ATTESTER_ADMIN_MASM: &str =
    include_str!("../../../asm/standards/xreserve/attester_admin.masm");

/// The faucet R-ADMIN-4 domain-config init-once setter module source, read test-side by
/// reference.
const DOMAIN_CONFIG_MASM: &str = include_str!("../../../asm/standards/xreserve/domain_config.masm");

/// The faucet CMP-A10 R-BURN-1/2 burn-policy module source, read test-side by reference.
const BURN_POLICY_MASM: &str = include_str!("../../../asm/standards/xreserve/burn_policy.masm");

const MIN_BURN_ADMIN_MASM: &str =
    include_str!("../../../asm/standards/xreserve/min_burn_admin.masm");

/// The faucet CMP-F3 DOM_PAUSER custom pause/unpause module source, read test-side by reference.
const PAUSE_ADMIN_MASM: &str = include_str!("../../../asm/standards/xreserve/pause_admin.masm");

/// The faucet F4-reversal BLK_MANAGER custom block/unblock module source, read test-side by reference.
const BLOCKLIST_ADMIN_MASM: &str =
    include_str!("../../../asm/standards/xreserve/blocklist_admin.masm");

/// The faucet CMP-B1 mint-note-entry transport shim module source, read test-side by reference.
const MINT_NOTE_ENTRY_MASM: &str =
    include_str!("../../../asm/standards/xreserve/xreserve_mint_note_entry.masm");

/// Faucet-owned shell error constants declared in MASM, pinned against the test-side
/// `support::SHELL_ERR_TABLE` (the single Rust source).
const SHELL_ERRORS_DECLARED: &[&str] = &[
    "ERR_XRESERVE_WRONG_DOMAIN",
    "ERR_XRESERVE_WRONG_IDENTIFIER",
    // D5b R-MINT-10 (F2's feeAmount==0 reuses ERR_XRESERVE_FEE_NONZERO, declared below; the old
    // R-MINT-11 <= maxFee compare + ERR_XRESERVE_FEE_OVER_MAX are subsumed and removed)
    "ERR_XRESERVE_AMOUNT_BELOW_FEE",
    // D5c R-MINT-12
    "ERR_XRESERVE_NONCE_REPLAY",
    // D5d R-MINT-13 / R-MINT-14 (attestation_verify.masm)
    "ERR_XRESERVE_BAD_PK_COMMITMENT",
    "ERR_XRESERVE_SIG_INVALID",
    // D5e R-MINT-15 (xreserve_mint.masm)
    "ERR_XRESERVE_SUPPLY_CAP",
    // F2 fee guard, declared in BOTH deposit_intent_parser.masm (D5b advice-gate) and
    // xreserve_mint.masm (D5e apply_mint_effects) — same string ⇒ shared felt code
    "ERR_XRESERVE_FEE_NONZERO",
    // recipient AccountId extraction (xreserve_mint.masm)
    "ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE",
    "ERR_XRESERVE_RECIPIENT_BAD_LIMB",
    "ERR_XRESERVE_RECIPIENT_NONCANONICAL",
    // R-MINT-16 mint-deny guard (mint_deny_guard.masm)
    "ERR_XRESERVE_MINT_DENIED",
    // R-ADMIN-4 domain-config init-once setter (domain_config.masm)
    "ERR_XRESERVE_DOMAIN_REINIT",
    // scalar/limb u32 guards (domain_config.masm)
    "ERR_XRESERVE_DOMAIN_NOT_U32",
    "ERR_XRESERVE_SOURCE_DOMAIN_NOT_U32",
    "ERR_XRESERVE_XRC_LIMB_NOT_U32",
    // R-ADMIN-4 empty-identifier init guard (domain_config.masm)
    "ERR_XRESERVE_IDENTIFIER_EMPTY",
    // CMP-A10 R-BURN-1 / R-BURN-2 burn policy (burn_policy.masm)
    "ERR_XRESERVE_BURN_ZERO",
    "ERR_XRESERVE_BURN_BELOW_MIN",
    // CMP-B1 mint-note-entry transport-shape guards (xreserve_mint_note_entry.masm).
    "ERR_XRESERVE_MINT_NOTE_STORAGE_TOO_SHORT",
    "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_MISSING",
    "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT",
    "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_NUM_WORDS",
    // F5: the scheme-2 NetworkAccountTarget routing attachment presence guard.
    "ERR_XRESERVE_MINT_NOTE_TARGET_MISSING",
];

/// Expected `word("…")` slot-name constants of the shell module (name → label), pinned
/// against the test-side label consts.
const EXPECTED_SHELL_WORD_CONSTS: &[(&str, &str)] = &[
    ("DOMAIN_CONFIG_SLOT", support::DOMAIN_CONFIG_SLOT_LABEL),
    (
        "IDENTIFIER_CONFIG_SLOT",
        support::IDENTIFIER_CONFIG_SLOT_LABEL,
    ),
    ("USED_NONCES_SLOT", support::USED_NONCES_SLOT_LABEL),
];

/// Expected `word("…")` slot-name constant of the D5d attestation-verify shell module.
const EXPECTED_ATTESTATION_WORD_CONSTS: &[(&str, &str)] = &[(
    "XRESERVE_ATTESTERS_SLOT",
    support::XRESERVE_ATTESTERS_SLOT_LABEL,
)];

/// Expected `word("…")` slot-name constant of the set_attester admin module. Its
/// `XRESERVE_ATTESTERS_SLOT` MUST be byte-identical to attestation_verify's (the setter writes the
/// SAME slot the D5d read path keys); the shared label is the single Rust source. (The
/// `ATTESTER_ENABLED_MARKER` Word array literal is not parity-parsed, like `NONCE_USED_MARKER`.)
const EXPECTED_ATTESTER_ADMIN_WORD_CONSTS: &[(&str, &str)] = &[(
    "XRESERVE_ATTESTERS_SLOT",
    support::XRESERVE_ATTESTERS_SLOT_LABEL,
)];

/// Expected `word("…")` slot-name constant of the D5e mint shell module. `TOKEN_CONFIG_SLOT` is
/// hard-coded byte-identical to the standard FungibleFaucet slot label
/// (docs/governing/CANONICAL-OWNERSHIP-MAP.md; fungible.masm:26); `USED_NONCES_SLOT` is IMPORTED
/// from deposit_intent_parser (no redeclaration → not parsed here, no duplicate parity row).
const EXPECTED_XRESERVE_MINT_WORD_CONSTS: &[(&str, &str)] =
    &[("TOKEN_CONFIG_SLOT", support::TOKEN_CONFIG_SLOT_LABEL)];

/// Expected `word("…")` slot-name constants of the 4-field `domain_config.masm`: the THREE new
/// slots it owns and writes (`source_domain`, `xreserve_contract_hi/lo` — the raw 8×u32-LE
/// realization of the xreserve_contract bytes32). The `domain`/`identifier` consts stay IMPORTED
/// from deposit_intent_parser (no redeclaration → no duplicate parity row).
const EXPECTED_DOMAIN_CONFIG_WORD_CONSTS: &[(&str, &str)] = &[
    (
        "SOURCE_DOMAIN_CONFIG_SLOT",
        support::SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    ),
    (
        "XRESERVE_CONTRACT_HI_SLOT",
        support::XRESERVE_CONTRACT_HI_SLOT_LABEL,
    ),
    (
        "XRESERVE_CONTRACT_LO_SLOT",
        support::XRESERVE_CONTRACT_LO_SLOT_LABEL,
    ),
];

/// Expected `word("…")` slot-name constant of the CMP-A10 burn-policy module. `MIN_BURN_SIZE_SLOT`
/// MUST be byte-identical to the future CMP-F2 `set_min_burn_size` setter's slot (the reader↔setter
/// slot identity); the shared label is the single Rust source (`support::MIN_BURN_SIZE_SLOT_LABEL`).
const EXPECTED_BURN_POLICY_WORD_CONSTS: &[(&str, &str)] =
    &[("MIN_BURN_SIZE_SLOT", support::MIN_BURN_SIZE_SLOT_LABEL)];

/// Expected `word("…")` slot-name constant of the CMP-F2 `set_min_burn_size` setter module. It writes
/// the SAME `MIN_BURN_SIZE_SLOT` CMP-A10's `burn_policy` reads (the setter↔reader slot identity), so it
/// re-declares the const byte-identically (the attester_admin↔attestation_verify precedent) and binds
/// the shared Rust label `support::MIN_BURN_SIZE_SLOT_LABEL`.
const EXPECTED_MIN_BURN_ADMIN_WORD_CONSTS: &[(&str, &str)] =
    &[("MIN_BURN_SIZE_SLOT", support::MIN_BURN_SIZE_SLOT_LABEL)];

/// The D5d attestation-verify shell declares no numeric constants (word-aligned `@locals`
/// offsets are literal, matching `encoding/mod.masm::pubkey_commitment` and the precompile canary).
const ATTESTATION_COVERED_NUMS: &[&str] = &[];

/// D5e mint-shell numeric constants (NONCE_USED_MARKER is a Word array literal, not parsed).
/// P2ID_NUM_STORAGE_ITEMS is the local note-storage item count for the P2ID recipient build (2,
/// matching notes/p2id.masm's storage format); no Rust counterpart, covered here.
const XRESERVE_MINT_COVERED_NUMS: &[&str] = &["P2ID_NUM_STORAGE_ITEMS"];

/// CMP-F3 pause-admin numeric const: DOM_PAUSER_ROLE (the encoded RoleSymbol felt), parity-asserted
/// against `RoleSymbol::new(DOM_PAUSER_ROLE).as_element()` in `masm_rust_constant_parity` below.
const PAUSE_ADMIN_COVERED_NUMS: &[&str] = &["DOM_PAUSER_ROLE"];

/// F4-reversal blocklist-admin numeric const: BLK_MANAGER_ROLE (the encoded RoleSymbol felt),
/// parity-asserted against `RoleSymbol::new(BLK_MANAGER_ROLE).as_element()` in
/// `masm_rust_constant_parity` below.
const BLOCKLIST_ADMIN_COVERED_NUMS: &[&str] = &["BLK_MANAGER_ROLE"];

/// CMP-B1 mint-note-entry numeric consts: the attachment scheme + word count are parity-asserted
/// against the Rust `XRESERVE_MINT_ATTACHMENT_SCHEME` / `XRESERVE_MINT_ATTACHMENT_NUM_WORDS` in
/// `masm_rust_constant_parity` below (the constructor builds what the wrapper verifies).
/// `INTENT_PTR` (the account-frame staging address, the proven driver convention) and
/// `DEPOSIT_SCALE_EXP` (the faucet-side DC-5 scale, DEV-5 parameterization point, MVP 6 — the
/// canonical fixture scale) are wrapper-owned with no Rust counterpart, covered here.
const MINT_NOTE_ENTRY_COVERED_NUMS: &[&str] = &[
    "INTENT_PTR",
    "XRESERVE_MINT_ATTACHMENT_SCHEME",
    "XRESERVE_MINT_ATTACHMENT_NUM_WORDS",
    "DEPOSIT_SCALE_EXP",
    // F5: WORD_NUM_ELEMENTS for the indexed attachment-commitment address math.
    "WORD_NUM_ELEMENTS",
];

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
) -> (
    BTreeMap<String, u64>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
) {
    let mut nums = BTreeMap::new();
    let mut strs = BTreeMap::new();
    let mut words = BTreeMap::new();
    for line in src.lines() {
        let line = line.trim();
        let rest = match line
            .strip_prefix("pub const ")
            .or_else(|| line.strip_prefix("const "))
        {
            Some(r) => r,
            None => continue,
        };
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
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
    *nums
        .get(name)
        .unwrap_or_else(|| panic!("{file} must define const {name}"))
}

/// DC-1 relation: every MASM felt offset × 4 equals the Rust byte offset, the packed
/// magic/version equal the LE reinterpretation of the BE wire values, the header felt
/// count matches both sides, the NoteStorage bound is the frozen 1024, and the
/// extra rows pin the reducer's scale bound and limb base.
#[test]
fn masm_rust_constant_parity() {
    let (nums, _, _) = parse_masm_consts(LAYOUT_MASM);

    let offsets: [(&str, DepositIntentField); 12] = [
        ("MAGIC_FELT_OFF", DepositIntentField::Magic),
        ("VERSION_FELT_OFF", DepositIntentField::Version),
        ("AMOUNT_FELT_OFF", DepositIntentField::Amount),
        ("REMOTE_DOMAIN_FELT_OFF", DepositIntentField::RemoteDomain),
        ("REMOTE_TOKEN_FELT_OFF", DepositIntentField::RemoteToken),
        (
            "REMOTE_RECIPIENT_FELT_OFF",
            DepositIntentField::RemoteRecipient,
        ),
        ("LOCAL_TOKEN_FELT_OFF", DepositIntentField::LocalToken),
        (
            "LOCAL_DEPOSITOR_FELT_OFF",
            DepositIntentField::LocalDepositor,
        ),
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
        "header byte length must be 4x the felt count (4 bytes per felt)"
    );
    assert_eq!(
        num(&nums, "MAX_NOTE_STORAGE_FELTS", "layout.masm"),
        1024,
        "NoteStorage felt bound is frozen at 1024"
    );

    // extra rows: the reducer's bound and limb base (names differ across languages for
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
        "affine-pubkey felt count parity (qx||qy -> 16 u32-LE felts; ATT commitment input)"
    );

    // CMP-F3: the DOM_PAUSER role-symbol MASM const must equal the Rust encoding
    // RoleSymbol::new(DOM_PAUSER_ROLE).as_element() (base-27 over A-Z/_). A one-sided edit fails here.
    // Felt::as_int() does NOT exist at the pin; as_canonical_u64 is the inherent u64 accessor at
    // miden-field 0.25.1 (the repo migrated as_int()->as_canonical_u64; used in account_id.rs).
    let (pause_nums, _, _) = parse_masm_consts(PAUSE_ADMIN_MASM);
    assert_eq!(
        num(&pause_nums, "DOM_PAUSER_ROLE", "pause_admin.masm"),
        RoleSymbol::new(DOM_PAUSER_ROLE)
            .expect("DOM_PAUSER is a valid RoleSymbol")
            .as_element()
            .as_canonical_u64(),
        "DOM_PAUSER role-symbol felt parity (MASM const == RoleSymbol::new(DOM_PAUSER_ROLE).as_element())"
    );

    // F4-reversal: the BLK_MANAGER role-symbol MASM const must equal the Rust encoding
    // RoleSymbol::new(BLK_MANAGER_ROLE).as_element() (base-27 over A-Z/_). A one-sided edit — the
    // exact mutation check (d) — fails here, so the transfer-blocklist role gate cannot silently drift.
    let (blocklist_nums, _, _) = parse_masm_consts(BLOCKLIST_ADMIN_MASM);
    assert_eq!(
        num(&blocklist_nums, "BLK_MANAGER_ROLE", "blocklist_admin.masm"),
        RoleSymbol::new(BLK_MANAGER_ROLE)
            .expect("BLK_MANAGER is a valid RoleSymbol")
            .as_element()
            .as_canonical_u64(),
        "BLK_MANAGER role-symbol felt parity (MASM const == RoleSymbol::new(BLK_MANAGER_ROLE).as_element())"
    );

    // CMP-B1: the mint-note attachment scheme + word count must match across languages — the
    // Rust constructor builds exactly what the MASM wrapper locates (find_attachment by scheme)
    // and size-asserts (num_words == 9). A one-sided edit fails here.
    let (entry_nums, _, _) = parse_masm_consts(MINT_NOTE_ENTRY_MASM);
    assert_eq!(
        num(
            &entry_nums,
            "XRESERVE_MINT_ATTACHMENT_SCHEME",
            "xreserve_mint_note_entry.masm"
        ),
        XRESERVE_MINT_ATTACHMENT_SCHEME as u64,
        "mint-note attachment scheme parity (MASM wrapper == Rust constructor)"
    );
    assert_eq!(
        num(
            &entry_nums,
            "XRESERVE_MINT_ATTACHMENT_NUM_WORDS",
            "xreserve_mint_note_entry.masm"
        ),
        XRESERVE_MINT_ATTACHMENT_NUM_WORDS as u64,
        "mint-note attachment word-count parity (MASM wrapper == Rust constructor)"
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
/// `support::SHELL_ERR_TABLE` message.
#[test]
fn masm_shell_error_string_parity() {
    // the faucet shell errors live across both shell modules (deposit_intent_parser.masm +
    // attestation_verify.masm); merge their string consts before the lookup.
    let (_, mut strs, _) = parse_masm_consts(SHELL_MASM);
    let (_, att_strs, _) = parse_masm_consts(ATTESTATION_VERIFY_MASM);
    let (_, mint_strs, _) = parse_masm_consts(XRESERVE_MINT_MASM);
    let (_, deny_strs, _) = parse_masm_consts(MINT_DENY_GUARD_MASM);
    let (_, domain_strs, _) = parse_masm_consts(DOMAIN_CONFIG_MASM);
    let (_, burn_strs, _) = parse_masm_consts(BURN_POLICY_MASM);
    let (_, note_entry_strs, _) = parse_masm_consts(MINT_NOTE_ENTRY_MASM);
    strs.extend(att_strs);
    strs.extend(mint_strs);
    strs.extend(deny_strs);
    strs.extend(domain_strs);
    strs.extend(burn_strs);
    strs.extend(note_entry_strs);
    for name in SHELL_ERRORS_DECLARED {
        let expected = support::SHELL_ERR_TABLE
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, e)| e.message())
            .unwrap_or_else(|| panic!("SHELL_ERR_TABLE must carry {name}"));
        let masm = strs
            .get(*name)
            .unwrap_or_else(|| panic!("a faucet shell module must define const {name} = \"...\""));
        assert_eq!(masm, expected, "shell error message parity for {name}");
    }
}

/// Bidirectional sweep: every constant parsed from every MASM source must be
/// covered by a parity row or a documented exemption — a new MASM-only constant
/// (numeric, string, or `word("…")`) fails here until it gets a row.
#[test]
fn masm_constants_bidirectional() {
    // every MASM-only string constant must be a known error (the encoding table or the faucet
    // shell table); a new one fails here until it gets a row
    let known_err = |name: &str| {
        ERR_MESSAGES.iter().any(|(n, _)| *n == name)
            || support::SHELL_ERR_TABLE.iter().any(|(n, _)| *n == name)
    };
    let sources: [(&str, &str, &[&str], &[(&str, &str)]); 13] = [
        ("layout.masm", LAYOUT_MASM, LAYOUT_COVERED_NUMS, &[]),
        (
            "encoding/mod.masm",
            ENCODING_MOD_MASM,
            ENCODING_COVERED_NUMS,
            &[],
        ),
        (
            "deposit_intent_parser.masm",
            SHELL_MASM,
            SHELL_COVERED_NUMS,
            EXPECTED_SHELL_WORD_CONSTS,
        ),
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
        // R-MINT-16: the deny guard declares only ERR_XRESERVE_MINT_DENIED (a known shell error via
        // SHELL_ERR_TABLE); no numeric or word("…") constants.
        ("mint_deny_guard.masm", MINT_DENY_GUARD_MASM, &[], &[]),
        // set_attester: pins XRESERVE_ATTESTERS_SLOT to the shared label (no numeric consts;
        // the owner-gate traps reuse the stock ERR_SENDER_NOT_OWNER / ERR_PAUSABLE_IS_PAUSED, not declared here).
        (
            "attester_admin.masm",
            ATTESTER_ADMIN_MASM,
            &[],
            EXPECTED_ATTESTER_ADMIN_WORD_CONSTS,
        ),
        // 4-field domain_init: declares ERR_XRESERVE_DOMAIN_REINIT
        // + the three u32-guard errors + the ERR_XRESERVE_IDENTIFIER_EMPTY init guard
        // — all known shell errors via SHELL_ERR_TABLE — and the THREE new slot consts it
        // owns (source_domain + xreserve_contract hi/lo); the domain/identifier consts stay
        // IMPORTED from deposit_intent_parser (not redeclared -> no duplicate parity row).
        (
            "domain_config.masm",
            DOMAIN_CONFIG_MASM,
            &[],
            EXPECTED_DOMAIN_CONFIG_WORD_CONSTS,
        ),
        // CMP-A10 burn policy: declares the two ERR_XRESERVE_BURN_* errors (known shell errors via
        // SHELL_ERR_TABLE) + the MIN_BURN_SIZE_SLOT word const (pinned to MIN_BURN_SIZE_SLOT_LABEL); no
        // numeric consts.
        (
            "burn_policy.masm",
            BURN_POLICY_MASM,
            &[],
            EXPECTED_BURN_POLICY_WORD_CONSTS,
        ),
        // CMP-F2 set_min_burn_size: re-declares the MIN_BURN_SIZE_SLOT word const byte-identically to
        // burn_policy.masm (the setter↔reader slot identity); no numeric consts, no new errors (the
        // gate traps reuse the stock ERR_SENDER_NOT_OWNER / ERR_PAUSABLE_IS_PAUSED).
        (
            "min_burn_admin.masm",
            MIN_BURN_ADMIN_MASM,
            &[],
            EXPECTED_MIN_BURN_ADMIN_WORD_CONSTS,
        ),
        // CMP-F3 pause_admin: declares the numeric DOM_PAUSER_ROLE role-symbol const (parity-asserted in
        // masm_rust_constant_parity); no word("…") consts, and no new string errors (the role gate reuses
        // the stock ERR_SENDER_LACKS_ROLE, the primitive reuses ERR_PAUSABLE_IS_PAUSED).
        (
            "pause_admin.masm",
            PAUSE_ADMIN_MASM,
            PAUSE_ADMIN_COVERED_NUMS,
            &[],
        ),
        // F4-reversal blocklist_admin: declares the numeric BLK_MANAGER_ROLE role-symbol const
        // (parity-asserted in masm_rust_constant_parity); no word("…") consts, and no new string
        // errors (the role gate reuses the stock ERR_SENDER_LACKS_ROLE, the primitive reuses the
        // stock ERR_ACCOUNT_IS_BLOCKED).
        (
            "blocklist_admin.masm",
            BLOCKLIST_ADMIN_MASM,
            BLOCKLIST_ADMIN_COVERED_NUMS,
            &[],
        ),
        // CMP-B1 note-entry transport shim: declares the four ERR_XRESERVE_MINT_NOTE_* transport
        // guards (known shell errors via SHELL_ERR_TABLE) + the four numeric consts covered/
        // parity-asserted above; no word("…") consts (it touches NO storage slot — a transport
        // shim; every slot access lives in the procs `mint` execs).
        (
            "xreserve_mint_note_entry.masm",
            MINT_NOTE_ENTRY_MASM,
            MINT_NOTE_ENTRY_COVERED_NUMS,
            &[],
        ),
    ];
    for (file, src, covered_nums, expected_words) in sources {
        let (nums, strs, words) = parse_masm_consts(src);
        for name in nums.keys() {
            assert!(
                covered_nums.contains(&name.as_str()),
                "unmapped MASM numeric constant {name} in {file}: add a parity row or a \
                 documented exemption"
            );
        }
        for name in strs.keys() {
            assert!(
                known_err(name),
                "unmapped MASM string constant {name} in {file}: add an error parity row \
                 or a documented exemption"
            );
        }
        for name in words.keys() {
            assert!(
                expected_words.iter().any(|(n, _)| n == name),
                "unmapped MASM word(\"…\") constant {name} in {file}: add a slot-label \
                 parity row"
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

/// Parity for the installed authority mode: under the reconciled Circle-faithful owner-gated
/// model the production builder's `Authority` slot must carry exactly
/// `OwnerControlled` = `[OWNER_CONTROLLED, 0, 0, 0]`, so the account-wide gate resolves the setters
/// (`set_attester` / `set_min_burn_size` / stock `set_max_supply`) to the Ownable2Step owner. The built
/// `ATTEST_ADMIN` role + `RbacControlled` gate are removed; drifting the installed mode fails here.
#[test]
fn owner_controlled_authority_parity() -> anyhow::Result<()> {
    use miden_protocol::Word;
    use miden_standards::account::access::Authority;

    let driver = support::mint_composition_driver_src(&[miden_protocol::Felt::from(0u32)], 60, 6);
    let probe = support::composition_supply_probe_src(0);
    let gm = support::setup_guarded_mint_account(
        support::GuardSelection::ProductionDeny,
        1_000_000,
        0,
        Word::from([7u32, 0, 0, 0]),
        Word::from([11u32, 12, 13, 14]),
        None,
        None,
        &driver,
        &probe,
        true,
    )?;
    let account = support::faucet_account(&gm.harness);

    let installed = Authority::try_from_storage(account.storage())?;
    assert_eq!(
        installed,
        Authority::OwnerControlled,
        "the installed Authority must be OwnerControlled (owner-gated setters)"
    );
    Ok(())
}
