//! Constant-parity test: the MASM constants and their Rust counterparts
//! must satisfy the DERIVED cross-language relations (felt offsets are byte offsets / 4;
//! the packed magic/version are the u32-LE reinterpretations of the big-endian wire
//! values; the error strings are byte-identical). One-sided edits fail mechanically —
//! the `masm-rust-constant-parity` obligation, closed at the constant layer.
//!
//! Bidirectional hardening: parity is BIDIRECTIONAL — every constant parsed from the MASM
//! sources (numeric, string, and `word("…")` slot-name) must be covered by a parity row
//! or a documented exemption, so a new MASM-only constant fails this suite; the faucet shell
//! modules are included by reference (the encoding crate's `lib.rs` embeds only its own
//! sources). The generic scale/limb primitives (pow10, the u32 limb merge) are consumed from
//! the linked miden-standards library and declare no local constants here. Wave-1 S1 re-materialization: the deleted custom-transport modules
//! (`xreserve_mint` / `xreserve_mint_note_entry` / `mint_deny_guard` / `burn_policy` /
//! `min_burn_admin` / `domain_config`) left the sweep; the attestation mint policy
//! (`mint_policy.masm`) and the minimized `identifier_init.masm` joined it, with the
//! attachment-scheme rows (rider A8: schemes >= 4, clear of the reserved value 1 and the
//! standard values 2/3) and the DC-5 scale row pinned against the `XUsdcMintNote` factory
//! constants.

mod support;

use std::collections::BTreeMap;

use miden_protocol::note::NoteAttachmentScheme;
use miden_standards::note::NetworkAccountTarget;
use xusdc_encoding::note::xreserve_mint::{
    XUSDC_DEPOSIT_SCALE_EXP, XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME,
    XUSDC_MINT_ATTESTATION_NUM_WORDS, XUSDC_MINT_INTENT_ATTACHMENT_SCHEME,
};
use xusdc_encoding::xreserve::encoding::{
    deposit_intent_field_offset, DepositIntentField, DEPOSIT_INTENT_HEADER_FELTS,
    DEPOSIT_INTENT_HEADER_LEN, DEPOSIT_INTENT_MAGIC, DEPOSIT_INTENT_VERSION, ERR_MESSAGES,
    PUBKEY_FELTS,
};
use xusdc_encoding::{ENCODING_MOD_MASM, LAYOUT_MASM};

/// The faucet shell module source, read test-side by reference.
const SHELL_MASM: &str = include_str!("../../../asm/standards/xreserve/deposit_intent_parser.masm");

/// The faucet D5d attestation-verify shell module source, read test-side by reference.
const ATTESTATION_VERIFY_MASM: &str =
    include_str!("../../../asm/standards/xreserve/attestation_verify.masm");

/// The Wave-1 S1 attestation mint policy module source (the ACTIVE mint policy; owns the
/// attachment transport + ASSERT-MATCH binding constants), read test-side by reference.
const MINT_POLICY_MASM: &str = include_str!("../../../asm/standards/xreserve/mint_policy.masm");

/// The minimized identifier-init module source (DEC-4), read test-side by reference.
const IDENTIFIER_INIT_MASM: &str =
    include_str!("../../../asm/standards/xreserve/identifier_init.masm");

/// The faucet set_attester admin module source, read test-side by reference.
const ATTESTER_ADMIN_MASM: &str =
    include_str!("../../../asm/standards/xreserve/attester_admin.masm");

/// Faucet-owned shell error constants declared in MASM, pinned against the test-side
/// `support::SHELL_ERR_TABLE` (the single Rust source).
const SHELL_ERRORS_DECLARED: &[&str] = &[
    "ERR_XRESERVE_WRONG_DOMAIN",
    "ERR_XRESERVE_WRONG_IDENTIFIER",
    // D5b R-MINT-10 (F2's feeAmount==0 reuses ERR_XRESERVE_FEE_NONZERO, declared below; the old
    // R-MINT-11 <= maxFee compare + ERR_XRESERVE_FEE_OVER_MAX are subsumed and removed)
    "ERR_XRESERVE_AMOUNT_BELOW_FEE",
    // the maxFee/fee staging's too-large guard (deposit_intent_parser.masm)
    "ERR_X_TOO_LARGE",
    // D5c R-MINT-12
    "ERR_XRESERVE_NONCE_REPLAY",
    // D5d R-MINT-13 / R-MINT-14 (attestation_verify.masm)
    "ERR_XRESERVE_DISALLOWED_PUB_KEY",
    "ERR_XRESERVE_SIG_INVALID",
    // F2 fee guard (deposit_intent_parser.masm; DEC-2 keep-zero)
    "ERR_XRESERVE_FEE_NONZERO",
    // the attested-recipient extraction's pad check (mint_policy.masm; the limb and
    // canonical-range rejects are the standards eth::build_felt's)
    "ERR_XRESERVE_RECIPIENT_OUT_OF_RANGE",
    // Wave-1 S1 transport-shape guards on the stock MintNote's attachments (mint_policy.masm)
    "ERR_XRESERVE_MINT_NOTE_INTENT_MISSING",
    "ERR_XRESERVE_MINT_NOTE_ATTESTATION_MISSING",
    "ERR_XRESERVE_MINT_NOTE_TARGET_MISSING",
    "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT",
    "ERR_XRESERVE_MINT_NOTE_INTENT_TOO_SHORT",
    "ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB",
    "ERR_XRESERVE_MINT_NOTE_INTENT_WORDS",
    "ERR_XRESERVE_MINT_NOTE_ATTESTATION_NUM_WORDS",
    // Wave-1 S1 ASSERT-MATCH binding (mint_policy.masm)
    "ERR_XRESERVE_MINT_RECIPIENT_MISMATCH",
    "ERR_XRESERVE_MINT_AMOUNT_MISMATCH",
    "ERR_XRESERVE_MINT_TAG_MISMATCH",
    "ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC",
    // R-ADMIN-4 identifier init-once + non-empty + own-id binding guards (identifier_init.masm;
    // DEC-4 + the round-3 on-chain derivation)
    "ERR_XRESERVE_IDENTIFIER_REINIT",
    "ERR_XRESERVE_IDENTIFIER_EMPTY",
    "ERR_XRESERVE_IDENTIFIER_MISMATCH",
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

/// Expected `word("…")` slot-name constants of the D5d attestation-verify shell module: NONE. It
/// imports `XRESERVE_ATTESTERS_SLOT` (and the enabled marker) from the setter module rather than
/// redeclaring them, so the two sides cannot drift by construction.
const EXPECTED_ATTESTATION_WORD_CONSTS: &[(&str, &str)] = &[];

/// Expected `word("…")` slot-name constant of the set_attester admin module — the single MASM-side
/// declaration of the slot the D5d read path also keys; the shared label is the single Rust source.
/// (The `ATTESTER_ENABLED_MARKER` / `ATTESTER_DISABLED_MARKER` Word array literals are not
/// parity-parsed, like `NONCE_USED_MARKER`.)
const EXPECTED_ATTESTER_ADMIN_WORD_CONSTS: &[(&str, &str)] = &[(
    "XRESERVE_ATTESTERS_SLOT",
    support::XRESERVE_ATTESTERS_SLOT_LABEL,
)];

/// The D5d attestation-verify shell's numeric constants: its `@locals` offsets (the keccak
/// digest's two words — procedure-local addresses with no Rust counterpart) and `PUBKEY_FELTS`,
/// which IS parity-asserted against the Rust codec in `masm_rust_constant_parity` below.
const ATTESTATION_COVERED_NUMS: &[&str] = &["DIGEST_LO_LOC", "DIGEST_HI_LOC", "PUBKEY_FELTS"];

/// Wave-1 S1 attestation mint-policy numeric consts: the two attachment schemes + the
/// attestation word count + the DC-5 scale are parity-asserted against the `XUsdcMintNote`
/// factory constants in `masm_rust_constant_parity` below (the constructor builds what the
/// policy verifies); `DEPOSIT_INTENT_HEADER_WORDS` carries a derived relation row (x 4 == the
/// header felt count). The `P2ID_NUM_STORAGE_ITEMS` note-storage count (2, matching
/// notes/p2id.masm), the `*_LOC` procedure-local offsets of `check_policy` (including the four
/// derived from the shared layout's field offsets), and the
/// `NONCE_USED_MARKER`/`P2ID_SCRIPT_ROOT` Word array literals (not parity-parsed) are
/// policy-owned with no Rust counterpart, covered here.
const MINT_POLICY_COVERED_NUMS: &[&str] = &[
    "XUSDC_MINT_INTENT_ATTACHMENT_SCHEME",
    "XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME",
    "XUSDC_MINT_ATTESTATION_NUM_WORDS",
    "DEPOSIT_INTENT_HEADER_WORDS",
    "P2ID_NUM_STORAGE_ITEMS",
    "ASSET_VALUE_LOC",
    "RECIPIENT_LOC",
    "TAG_LOC",
    "NOTE_TYPE_LOC",
    "ATTACHMENT_COMMITMENTS_LOC",
    "ATTESTATION_LOC",
    "ATTESTATION_FEE_AMOUNT_LOC",
    "ATTESTATION_PUBKEY_LOC",
    "ATTESTATION_SIGNATURE_LOC",
    "NONCE_KEY_LOC",
    "P2ID_TARGET_ID_SUFFIX_LOC",
    "P2ID_TARGET_ID_PREFIX_LOC",
    "HOOK_DATA_LEN_BYTES_LOC",
    "LEN_FELTS_LOC",
    "INTENT_LOC",
    "INTENT_REMOTE_RECIPIENT_LOC",
    "INTENT_NONCE_LOC",
    "INTENT_HOOK_DATA_LEN_LOC",
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
const ENCODING_COVERED_NUMS: &[&str] = &[];
// the faucet-side deposit scale lives with the parser's amount/fee stage (DEV-5 OPEN,
// provisional scale-0), parity-asserted against the Rust factory constant below.
const SHELL_COVERED_NUMS: &[&str] = &["DEPOSIT_SCALE_EXP"];

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
/// extra rows pin the reducer's scale bound and limb base plus the Wave-1 S1
/// attachment-scheme / word-count / scale rows.
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

    // extra row: the affine-pubkey felt count
    let (att_nums, _, _) = parse_masm_consts(ATTESTATION_VERIFY_MASM);
    assert_eq!(
        num(&att_nums, "PUBKEY_FELTS", "attestation_verify.masm"),
        PUBKEY_FELTS as u64,
        "affine-pubkey felt count parity (qx||qy -> 16 u32-LE felts; ATT commitment input)"
    );

    // The DOM_PAUSER / BLK_MANAGER role symbols no longer appear in any MASM constant. They used
    // to be hard-coded felts in the custom pause and blocklist wrappers, which is what this suite
    // pinned; the wrappers are gone and the symbols now live in the account's procedure-role map,
    // written from the SAME Rust constants by `XReserveAdminAuthority`. There is nothing left to
    // keep in step across languages, so the parity rows are gone with the wrappers. The role
    // identity is pinned instead where it is now expressed: the felt encodings in
    // `builder_api.rs` (`RoleSymbol::new(DOM_PAUSER_ROLE)` / `RoleSymbol::new(BLK_MANAGER_ROLE)`)
    // and the materialized map in `w2admin_production_admin_effects.rs`.

    // Wave-1 S1: the mint-note attachment schemes + attestation word count + DC-5 scale must
    // match across languages — the XUsdcMintNote factory builds exactly what the attestation
    // policy locates (find_attachment by scheme), size-asserts (num_words == 11), and reduces at
    // (scale 0). A one-sided edit — the exact mutation check (e) — fails here.
    let (policy_nums, _, _) = parse_masm_consts(MINT_POLICY_MASM);
    assert_eq!(
        num(
            &policy_nums,
            "XUSDC_MINT_INTENT_ATTACHMENT_SCHEME",
            "mint_policy.masm"
        ),
        XUSDC_MINT_INTENT_ATTACHMENT_SCHEME as u64,
        "intent attachment scheme parity (MASM policy == Rust factory)"
    );
    assert_eq!(
        num(
            &policy_nums,
            "XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME",
            "mint_policy.masm"
        ),
        XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME as u64,
        "attestation attachment scheme parity (MASM policy == Rust factory)"
    );
    assert_eq!(
        num(
            &policy_nums,
            "XUSDC_MINT_ATTESTATION_NUM_WORDS",
            "mint_policy.masm"
        ),
        XUSDC_MINT_ATTESTATION_NUM_WORDS as u64,
        "attestation attachment word-count parity (MASM policy == Rust factory)"
    );
    let (shell_nums, _, _) = parse_masm_consts(SHELL_MASM);
    assert_eq!(
        num(&shell_nums, "DEPOSIT_SCALE_EXP", "deposit_intent_parser.masm"),
        XUSDC_DEPOSIT_SCALE_EXP as u64,
        "DC-5 deposit-scale parity (MASM parser == Rust factory; DEV-5 OPEN, provisional scale-0 identity)"
    );
    // derived relation: the header word floor x 4 == the header felt count (60 / 4 = 15).
    assert_eq!(
        num(
            &policy_nums,
            "DEPOSIT_INTENT_HEADER_WORDS",
            "mint_policy.masm"
        ) * 4,
        DEPOSIT_INTENT_HEADER_FELTS as u64,
        "the intent attachment's header word floor must be the packed header felt count / 4"
    );
    // rider A8 (ratified): the xUSDC schemes sit at >= 4 — clear of the protocol-reserved
    // "none" value 1 and the standard values 2 (NetworkAccountTarget, carried on this very
    // note) and 3 (Pswap). Executable so a scheme regression cannot slip in one-sided.
    for (name, scheme) in [
        ("intent", XUSDC_MINT_INTENT_ATTACHMENT_SCHEME),
        ("attestation", XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME),
    ] {
        assert!(
            scheme >= 4,
            "the {name} scheme must be >= 4 (rider A8: off the reserved/standard values)"
        );
        assert_ne!(
            NoteAttachmentScheme::new(scheme).expect("xusdc schemes are valid"),
            NetworkAccountTarget::ATTACHMENT_SCHEME,
            "the {name} scheme must not collide with the standard NetworkAccountTarget scheme"
        );
    }
    assert_ne!(
        XUSDC_MINT_INTENT_ATTACHMENT_SCHEME, XUSDC_MINT_ATTESTATION_ATTACHMENT_SCHEME,
        "the two xUSDC schemes must be distinct (find_attachment dispatches on them)"
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
    // the faucet shell errors live across the four shell modules (deposit_intent_parser +
    // attestation_verify + mint_policy + identifier_init); merge their string consts before
    // the lookup.
    let (_, mut strs, _) = parse_masm_consts(SHELL_MASM);
    let (_, att_strs, _) = parse_masm_consts(ATTESTATION_VERIFY_MASM);
    let (_, policy_strs, _) = parse_masm_consts(MINT_POLICY_MASM);
    let (_, init_strs, _) = parse_masm_consts(IDENTIFIER_INIT_MASM);
    strs.extend(att_strs);
    strs.extend(policy_strs);
    strs.extend(init_strs);
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
    let sources: [(&str, &str, &[&str], &[(&str, &str)]); 7] = [
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
        // Wave-1 S1 attestation mint policy: declares the transport + binding errors (known
        // shell errors via SHELL_ERR_TABLE) and the covered/parity-asserted numeric consts; its
        // slot consts stay IMPORTED (USED_NONCES from deposit_intent_parser) — no word("…")
        // consts of its own (the NONCE_USED_MARKER / P2ID_SCRIPT_ROOT Word array literals are
        // not parity-parsed).
        (
            "mint_policy.masm",
            MINT_POLICY_MASM,
            MINT_POLICY_COVERED_NUMS,
            &[],
        ),
        // DEC-4 identifier_init: declares the REINIT + EMPTY guards (known shell errors via
        // SHELL_ERR_TABLE); the identifier slot const stays IMPORTED from deposit_intent_parser
        // (not redeclared -> no duplicate parity row); no numeric consts. The three build-seeded
        // domain-config fields have NO MASM reader/writer anymore — their labels live Rust-side
        // only (the builder seeds them), so no slot-label parity rows exist for them.
        ("identifier_init.masm", IDENTIFIER_INIT_MASM, &[], &[]),
        // set_attester: pins XRESERVE_ATTESTERS_SLOT to the shared label (no numeric consts;
        // the authority-gate traps reuse the stock ADMIN-role and pause errors, not declared here).
        (
            "attester_admin.masm",
            ATTESTER_ADMIN_MASM,
            &[],
            EXPECTED_ATTESTER_ADMIN_WORD_CONSTS,
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

/// Parity for the installed authority mode: the production builder's `Authority` slot must carry
/// exactly `RbacControlled` = `[RBAC_CONTROLLED, 0, 0, 0]`, which is what makes the per-procedure
/// role map load-bearing — the pause and blocklist managers resolve to their assigned roles, and
/// every other gated procedure (`set_attester`, the stock `set_min_burn_amount` / `set_max_supply`,
/// the policy setters) falls back to the administrator role. Drifting the installed mode fails
/// here: under the administrator-controlled mode the role map would be ignored and pausing would land back
/// on the administrator, the one identity Circle's model keeps it away from.
#[test]
fn rbac_controlled_authority_parity() -> anyhow::Result<()> {
    use miden_standards::account::access::Authority;

    let components = support::production_component_set(1_000_000, 0)?;
    let authority_slot = Authority::authority_slot();
    let word = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == authority_slot)
        .map(|s| s.value())
        .ok_or_else(|| anyhow::anyhow!("the composed set must carry the Authority slot"))?;
    // the authority_config word is [mode, is_frozen, 0, 0] with RbacControlled = 2 (authority.rs);
    // compare the full word so a smuggled tail felt — or a frozen flag — cannot hide.
    assert_eq!(
        word,
        miden_protocol::Word::from([2u32, 0, 0, 0]),
        "the installed Authority must be RbacControlled: the manager procedures carry roles and \
         every other gated procedure falls back to the administrator role"
    );
    Ok(())
}
