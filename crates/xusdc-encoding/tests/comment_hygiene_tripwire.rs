//! Comment-hygiene tripwire: source comments carry plain English, never internal
//! process/ticket/requirement-id tokens.
//!
//! Every requirement, invariant, decision, and reject-condition id that used to be cited inline
//! is indexed in `docs/REQUIREMENTS-TRACEABILITY.md` (id -> implementing procedure/function +
//! verifying test). Comments describe the code in prose a reviewer can follow with no external
//! lookups; this test keeps the banned token families from creeping back in.
//!
//! Scope: comment text ONLY, extracted from every `.masm` file under `asm/`, every `.rs` file
//! and `Cargo.toml` under `crates/`, and the workspace-root `Cargo.toml`. String literals are
//! code, not comments — a token inside an assert message, a test probe, or a rendered-output
//! template never trips this test (and must not be "cleaned": tests assert on those bytes).
//!
//! Exemptions (see `EXEMPT_PATHS`): a small set of byte-frozen conformance files, the parked
//! validation crate, and byte-pinned upstream fixture copies. Their leftover tokens are recorded
//! in the traceability index's residue table and belong to later authorized passes.
//!
//! Two kinds of token are refused. The first are ids that identify a requirement, invariant,
//! decision, ticket, or process slice — they mean nothing to a reader outside this program and
//! belong in the index, not inline. The second are the short LOCAL labels a file uses to number
//! its own steps (`S4`, `B5`, `D5c`, `N1A`). Those are legitimate when the file's own header
//! defines the sequence, and opaque anywhere else, so they are refused everywhere except in the
//! files named by `SEQUENCE_MARKER_FILES` — each of which defines its sequence in full.
//!
//! The `PENDING_FILES` allowlist exists so the cleanup can land in independently mergeable
//! batches: files still awaiting their humanize pass are skipped by the scan and the list
//! SHRINKS with every batch — it must only ever lose entries, ending empty.

use std::fs;
use std::path::{Path, PathBuf};

#[path = "hygiene/mod.rs"]
mod hygiene;

use hygiene::extract::*;

/// The workspace root, resolved from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Workspace-relative path prefixes excluded from the scan, each with the reason it is exempt.
const EXEMPT_PATHS: &[&str] = &[
    // this file: the banned patterns themselves live here (as string literals).
    "crates/xusdc-encoding/tests/comment_hygiene_tripwire.rs",
    // byte-frozen conformance tripwires — cleaned only by a later authorized pass.
    "crates/xusdc-encoding/tests/constant_parity.rs",
    "crates/xusdc-encoding/tests/account_callable_surface.rs",
    "crates/xusdc-encoding/tests/basic_asset_tripwire.rs",
    // the golden-vector loader and data — byte-frozen with the vectors they serve.
    "crates/xusdc-encoding/src/vectors.rs",
    "crates/xusdc-encoding/tests/vectors/",
    // byte-pinned upstream fixture copies — do not touch.
    "crates/xusdc-encoding/tests/fixtures/pinned-standards/",
    // parked crate: out of `workspace.members`, pledged byte-intact, not compilable here.
    "crates/xusdc-validation/",
];

/// Files still awaiting their humanize pass, skipped by the scan.
///
/// The list existed so the cleanup could land in independently mergeable batches with the suite
/// green throughout: each batch removed its own files as it humanized them. It is now EMPTY, which
/// is the finished state — every in-scope file is scanned unconditionally. Adding an entry here
/// would silently exempt a file, so it must only ever shrink.
const PENDING_FILES: &[&str] = &[];

/// Files allowed to use ONE named family of short step labels, because their own header defines
/// that sequence in full — a reader never has to look anything up.
///
/// The permission is per FAMILY, not per file: a file that defines its `S` lifecycle earns `S4`,
/// and still trips on a `D5c` or a `B5` it never explains. Everywhere else all four families are
/// refused, because a label whose meaning lives in a document outside this repository is exactly
/// what this test exists to prevent.
const SEQUENCE_MARKER_FILES: &[(&str, &str)] = &[
    // header numbers every lifecycle stage the file drives, in order.
    ("crates/xusdc-encoding/tests/assembled_faucet_e2e.rs", "S"),
    // header defines the mint-pipeline stages the sections and test names use.
    ("crates/xusdc-encoding/tests/masm_mint_shell.rs", "D5"),
    // the withdrawal steps are an operator-facing vocabulary: this service tags every event it
    // emits with the step it belongs to, so the names appear in logs and alert rules. The crate
    // root defines all of them in prose and the orchestration walks them in order — everywhere
    // else in the crate, and for every other family, the steps are named in words instead.
    ("crates/withdrawal-listener-attester/src/lib.rs", "B"),
    (
        "crates/withdrawal-listener-attester/src/listener/mod.rs",
        "B",
    ),
];

/// Tokens a file must keep because a test outside this one asserts the literal is present.
///
/// `auth.rs` is scanned by `withdrawal-listener-attester/tests/auth_posture.rs`, which requires the
/// still-open Circle credential question to be named there and never marked resolved. Stripping the
/// id would silently disarm that guard, and that guard is not one this task may edit — so the id
/// stays exactly where it is load-bearing, and nowhere else.
const PINNED_TOKENS: &[(&str, &str)] = &[(
    "crates/withdrawal-listener-attester/src/circle/auth.rs",
    "Q-API-AUTH",
)];

/// Returns the first banned token found in one line of COMMENT text, if any.
///
/// The families are matched with word boundaries so ordinary prose ("device", "xUSDC-...",
/// "invariant") can never trip them; see the self-tests at the bottom for the exact shapes.
fn find_banned(text: &str, allowed_sequence_family: Option<&str>) -> Option<String> {
    let bytes = text.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // A short label stands alone: neither side may be a word character, and neither may be `-`
    // (which is what keeps a regex character class such as `[a-fA-F0-9]` out of the `F0` family).
    let is_label_boundary = |b: u8| !is_word(b) && b != b'-';

    // an id family: literal prefix (boundary-checked on the left), then a required tail class.
    #[derive(Clone, Copy)]
    enum Tail {
        Digit,          // e.g. "DEV-" then 0-9
        Upper,          // e.g. "INV-" then A-Z
        UpperThenDigit, // e.g. "CMP-" then A-Z then 0-9
        None,           // the literal alone suffices
    }
    let families: &[(&str, Tail, bool)] = &[
        // (prefix literal, required tail, case-insensitive)
        ("IMPL-DEV-", Tail::Digit, false),
        ("DEV-", Tail::Digit, false),
        ("DEC-", Tail::Digit, false),
        ("CMP-", Tail::UpperThenDigit, false),
        ("R-MINT-", Tail::Digit, false),
        ("R-BURN-", Tail::Digit, false),
        ("R-ADMIN-", Tail::Digit, false),
        ("DC-", Tail::Digit, false),
        ("NS-", Tail::Digit, false),
        ("CIR-", Tail::Upper, false),
        ("INV-", Tail::Upper, false),
        ("CC-", Tail::Upper, false),
        ("Q-DOM", Tail::None, false),
        ("Q-CRY", Tail::None, false),
        ("Q-PRV", Tail::None, false),
        ("TV-DUAL", Tail::None, false),
        // internal-document cross-references and process/slice labels: an outside reader cannot
        // resolve any of these without a document that is not in this repository.
        ("ASG-", Tail::Digit, false),
        ("unit-0", Tail::Digit, false),
        ("§", Tail::None, false),
        ("V16-NOW", Tail::None, false),
        ("R2-F", Tail::Digit, false),
        // the withdrawal requirement tags and the remaining internal question / implementation
        // ids: each names a numbered row or decision in a document that is not in this repository.
        ("R-", Tail::Digit, false),
        ("Q-", Tail::Upper, false),
        ("IMPL-", Tail::Upper, false),
        ("F4-reversal", Tail::None, true),
        ("F4 reversal", Tail::None, true),
        ("MIGRATION-V16", Tail::None, false),
        ("anneal", Tail::None, true),
    ];

    let matches_at = |i: usize, pat: &str, ci: bool| -> bool {
        let end = i + pat.len();
        if end > bytes.len() {
            return false;
        }
        let seg = &bytes[i..end];
        if ci {
            seg.eq_ignore_ascii_case(pat.as_bytes())
        } else {
            seg == pat.as_bytes()
        }
    };

    for i in 0..bytes.len() {
        // left word boundary for every family.
        if i > 0 && is_word(bytes[i - 1]) {
            continue;
        }
        for &(pat, tail, ci) in families {
            if !matches_at(i, pat, ci) {
                continue;
            }
            let after = i + pat.len();
            let hit = match tail {
                Tail::Digit => bytes.get(after).is_some_and(u8::is_ascii_digit),
                Tail::Upper => bytes.get(after).is_some_and(u8::is_ascii_uppercase),
                Tail::UpperThenDigit => {
                    bytes.get(after).is_some_and(u8::is_ascii_uppercase)
                        && bytes.get(after + 1).is_some_and(u8::is_ascii_digit)
                }
                // a bare literal is banned as a stem: "TV-DUAL-3", "Q-DOM-1", and
                // "MIGRATION-V16-NEXT" all extend the literal and all trip.
                Tail::None => true,
            };
            if hit {
                let shown: String = text[i..].chars().take(24).collect();
                return Some(shown);
            }
        }
        // "Wave1" / "Wave-1" (case-insensitive).
        if matches_at(i, "Wave", true) {
            let mut j = i + 4;
            if bytes.get(j) == Some(&b'-') {
                j += 1;
            }
            if bytes.get(j).is_some_and(u8::is_ascii_digit) {
                return Some(text[i..].chars().take(24).collect());
            }
        }
        // "round-1" (case-insensitive, catches "Round-3" too).
        if matches_at(i, "round-", true) && bytes.get(i + 6).is_some_and(u8::is_ascii_digit) {
            return Some(text[i..].chars().take(24).collect());
        }
        // Short local labels. `is_label_boundary` also rejects a `-` neighbour so a regex
        // character class in prose (`[a-fA-F0-9]`) is not read as an `F0` label.
        let label_at = |start: usize, head: &str, digits: usize, suffix_upper: bool| -> bool {
            if !matches_at(start, head, false) {
                return false;
            }
            if start > 0 && !is_label_boundary(bytes[start - 1]) {
                return false;
            }
            let mut j = start + head.len();
            let mut seen = 0usize;
            while seen < digits && bytes.get(j).is_some_and(u8::is_ascii_digit) {
                j += 1;
                seen += 1;
            }
            if seen == 0 {
                return false;
            }
            if suffix_upper && bytes.get(j).is_some_and(|b| (b'A'..=b'D').contains(b)) {
                j += 1;
            }
            bytes.get(j).is_none_or(|&b| is_label_boundary(b))
        };
        // process/slice labels: opaque wherever they appear.
        for (head, digits) in [("W", 2), ("G", 1), ("PA", 1), ("F", 1), ("R", 1)] {
            if label_at(i, head, digits, false) {
                return Some(text[i..].chars().take(24).collect());
            }
        }
        // test-case ids (`T-RLY-11`): the test FUNCTION name carries the id; a comment must not.
        if matches_at(i, "T-", false) {
            let mut j = i + 2;
            let mut uppers = 0usize;
            while uppers < 4 && bytes.get(j).is_some_and(u8::is_ascii_uppercase) {
                j += 1;
                uppers += 1;
            }
            if uppers >= 2
                && bytes.get(j) == Some(&b'-')
                && bytes.get(j + 1).is_some_and(u8::is_ascii_digit)
            {
                return Some(text[i..].chars().take(24).collect());
            }
        }
        // File-local step labels: legitimate only in the file whose header defines THAT family.
        for (head, digits, suffix) in [
            ("S", 2, false),
            ("B", 2, false),
            ("A", 2, false),
            ("N", 1, true),
        ] {
            if allowed_sequence_family == Some(head) {
                continue;
            }
            if label_at(i, head, digits, suffix) {
                return Some(text[i..].chars().take(24).collect());
            }
        }
        if allowed_sequence_family != Some("D5")
            && matches_at(i, "D5", false)
            && bytes.get(i + 2).is_some_and(|b| (b'a'..=b'e').contains(b))
            && bytes.get(i + 3).is_none_or(|&b| is_label_boundary(b))
            && (i == 0 || is_label_boundary(bytes[i - 1]))
        {
            return Some(text[i..].chars().take(24).collect());
        }
        // bare issue tags: keep only full URLs — a github.com line is fine.
        if !text.contains("github.com") {
            if matches_at(i, "vm#", false) && bytes.get(i + 3).is_some_and(u8::is_ascii_digit) {
                return Some(text[i..].chars().take(24).collect());
            }
            for pat in ["protocol#", "protocol #"] {
                if matches_at(i, pat, false)
                    && bytes.get(i + pat.len()).is_some_and(u8::is_ascii_digit)
                {
                    return Some(text[i..].chars().take(24).collect());
                }
            }
        }
    }
    None
}

/// The scan itself, reusable so the self-tests can drive it over synthetic input.
fn scan_file(rel: &str, src: &str) -> Vec<String> {
    let comments = if rel.ends_with(".rs") {
        rust_comments(src)
    } else if rel.ends_with(".toml") {
        toml_comments(src)
    } else {
        masm_comments(src)
    };
    let allowed_sequence_family = SEQUENCE_MARKER_FILES
        .iter()
        .find(|(f, _)| *f == rel)
        .map(|(_, family)| *family);
    let pinned: Vec<&str> = PINNED_TOKENS
        .iter()
        .filter(|(f, _)| *f == rel)
        .map(|(_, tok)| *tok)
        .collect();
    comments
        .iter()
        .flat_map(|(n, c)| {
            let pinned = &pinned;
            c.lines().enumerate().filter_map(move |(k, l)| {
                find_banned(l, allowed_sequence_family)
                    // a token a guard outside this test pins in this exact file is not a finding.
                    .filter(|hit| !pinned.iter().any(|p| hit.starts_with(p)))
                    .map(|tok| format!("{rel}:{}: `{}`", n + k, tok.trim_end()))
            })
        })
        .collect()
}

#[test]
fn comments_carry_no_internal_process_tokens() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_files(&root.join("asm"), &mut files);
    collect_files(&root.join("crates"), &mut files);
    files.push(root.join("Cargo.toml"));
    files.sort();

    let mut violations = Vec::new();
    let mut scanned = 0usize;
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("scanned files live under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPT_PATHS.iter().any(|e| rel.starts_with(e)) {
            continue;
        }
        if PENDING_FILES.iter().any(|p| rel == *p) {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
        violations.extend(scan_file(&rel, &src));
        scanned += 1;
    }
    assert!(
        scanned > 50,
        "the walk found only {scanned} files — scope bug"
    );
    assert!(
        violations.is_empty(),
        "{} comment line(s) carry internal process tokens (each id belongs in \
         docs/REQUIREMENTS-TRACEABILITY.md; the comment should say what the code does in plain \
         English):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

// SELF-TESTS: the scanner must catch each banned family and must NOT read string literals.
// ================================================================================================

#[test]
fn every_banned_family_trips_in_a_comment() {
    let cases = [
        "DEV-5",
        "IMPL-DEV-21",
        "DEC-4",
        "CMP-A10",
        "CMP-F5",
        "Wave-1",
        "Wave1",
        "round-6",
        "Round-3",
        "anneal",
        "TV-DUAL-3",
        "R2-F4",
        "MIGRATION-V16-ALPHA2.md",
        "R-MINT-11",
        "R-BURN-1",
        "R-ADMIN-4",
        "DC-7",
        "CIR-API",
        "INV-MINT",
        "CC-A",
        "Q-DOM-1",
        "Q-CRY",
        "Q-PRV-5",
        "NS-2",
        "vm#3342",
        "protocol#2927",
        "protocol #2927",
        "F4-reversal",
        "F4 REVERSAL",
    ];
    for tok in cases {
        let masm = format!("# a comment citing {tok} here\nadd\n");
        assert!(
            !scan_file("t.masm", &masm).is_empty(),
            "`{tok}` in a MASM comment must trip the scan"
        );
        let rust = format!("// a comment citing {tok} here\nfn f() {{}}\n");
        assert!(
            !scan_file("t.rs", &rust).is_empty(),
            "`{tok}` in a Rust comment must trip the scan"
        );
    }
}

#[test]
fn internal_document_references_and_process_labels_trip() {
    // Every one of these needs a document outside this repository to make sense.
    let cases = [
        "ASG-16", "unit-04", "§1.2", "(F5)", "(F6)", "R2-F3", "V16-NOW", "T-RLY-11", "T-LA-04",
        "W10", "G4", "PA2",
    ];
    for tok in cases {
        let masm = format!("# a comment citing {tok} here\nadd\n");
        assert!(
            !scan_file("t.masm", &masm).is_empty(),
            "`{tok}` in a MASM comment must trip the scan"
        );
        let rust = format!("// a comment citing {tok} here\nfn f() {{}}\n");
        assert!(
            !scan_file("t.rs", &rust).is_empty(),
            "`{tok}` in a Rust comment must trip the scan"
        );
    }
}

#[test]
fn file_local_step_labels_trip_outside_the_files_that_define_them() {
    let cases = ["S4", "S12", "B3", "B5", "D5a", "D5c", "N1A", "A2"];
    for tok in cases {
        let rust = format!("//! the {tok} stage runs first\nfn f() {{}}\n");
        assert!(
            !scan_file("crates/xusdc-encoding/tests/somewhere_else.rs", &rust).is_empty(),
            "`{tok}` must trip in a file whose header does not define the sequence"
        );
    }
    // the id families are banned everywhere, allowlist or not.
    for (f, _) in SEQUENCE_MARKER_FILES {
        assert!(
            !scan_file(f, "//! see DEV-5 and ASG-16\n").is_empty(),
            "{f} must still be scanned for the id families"
        );
    }
}

#[test]
fn a_sequence_allowlist_covers_only_the_family_that_file_defines() {
    // The permission is per family. A file that defines its `S` lifecycle may write `S4`, and must
    // still trip on the families it never explains — that is the difference between documenting a
    // sequence and holding a blanket pass.
    let family_probe = [
        ("S", "S4"),
        ("B", "B5"),
        ("A", "A2"),
        ("N", "N1A"),
        ("D5", "D5c"),
    ];
    for (file, defined) in SEQUENCE_MARKER_FILES {
        for (family, tok) in family_probe {
            let src = format!("//! the {tok} step\n");
            let hits = scan_file(file, &src);
            if family == *defined {
                assert!(
                    hits.is_empty(),
                    "{file} defines the `{family}` sequence, so `{tok}` must be accepted there"
                );
            } else {
                assert!(
                    !hits.is_empty(),
                    "{file} does not define the `{family}` sequence, so `{tok}` must still trip"
                );
            }
        }
    }
}

#[test]
fn a_token_a_foreign_guard_pins_is_exempt_only_in_that_one_file() {
    for (file, tok) in PINNED_TOKENS {
        let src = format!("//! the {tok} question stays OPEN\n");
        assert!(
            scan_file(file, &src).is_empty(),
            "{tok} is pinned in {file} by a guard this task may not edit"
        );
        assert!(
            !scan_file("crates/xusdc-encoding/src/lib.rs", &src).is_empty(),
            "{tok} must still trip everywhere else"
        );
    }
}

#[test]
fn every_toml_string_form_is_treated_as_code() {
    // A `#` inside any of TOML's four string forms is part of the value, never a comment — and a
    // banned token inside one is code that tests may assert on byte-for-byte.
    let literal = "name = 'DEV-5 # not a comment ASG-16'\n";
    assert!(
        scan_file("Cargo.toml", literal).is_empty(),
        "a single-quoted TOML literal string must not be read as a comment"
    );
    let multi_basic = "text = \"\"\"\nDEV-5 # still inside the value\nunit-04 §3\n\"\"\"\n";
    assert!(
        scan_file("Cargo.toml", multi_basic).is_empty(),
        "a multi-line basic TOML string must not be read as a comment"
    );
    let multi_literal = "text = '''\nR-MINT-11 # still inside the value\nW10 (F5)\n'''\n";
    assert!(
        scan_file("Cargo.toml", multi_literal).is_empty(),
        "a multi-line literal TOML string must not be read as a comment"
    );
    // a backslash is an ordinary character in a literal string, so it cannot escape the closer
    let trailing_backslash = "a = 'c:\\path\\'\nb = 1 # cites DEV-5\n";
    assert!(
        !scan_file("Cargo.toml", trailing_backslash).is_empty(),
        "the literal string must close so the following real comment is still scanned"
    );
    // and a real comment after any of them is still scanned
    let after = "name = 'ok'  # parked per DEC-4\n";
    assert!(!scan_file("Cargo.toml", after).is_empty());
}

#[test]
fn ordinary_prose_does_not_trip() {
    let benign = [
        "the device driver rounds values",       // device / rounds
        "xUSDC-denominated amounts",             // xUSDC- is not the codec-decision family
        "the invariant holds for every account", // prose, not an id
        "wavelength 5 is unrelated",             // Wave needs a digit right after
        "see https://github.com/0xMiden/miden-vm/issues/3342 (vm#3342)", // full URL line
        "a workaround-free design",              // round- inside a word
        "the CMP-B path",                        // the component family needs letter+digit
        "matches ^0x[a-fA-F0-9]{64}$ exactly",   // a hex character class is not an `F0` label
        "the value is a W3C-registered form",    // a label may not run into letters
        "consumed in block N+1, never block N",  // `N` needs a digit right after it
        "the GNU toolchain and the SHA256 hash", // labels may not run into letters
    ];
    for text in benign {
        let masm = format!("# {text}\n");
        assert!(
            scan_file("t.masm", &masm).is_empty(),
            "benign prose `{text}` must not trip the scan"
        );
    }
}

#[test]
fn string_literals_never_trip() {
    // Rust: probes, assert messages, and raw strings keep their tokens — they are code.
    let rust = r##"
fn f() {
    let probe = "DEV-7 stays OPEN";
    assert!(src.contains("R-MINT-11"), "the CMP-A10 guard");
    let raw = r#"MIGRATION-V16 TV-DUAL-3"#;
    let c = '#';
    let lt: &'static str = "Wave-1 round-6 anneal";
}
"##;
    assert!(
        scan_file("t.rs", rust).is_empty(),
        "tokens inside Rust string/char literals must not trip the scan"
    );
    // ...but the same tokens in comments DO trip.
    let rust_bad = "// the DEV-7 evidence package\nfn f() {}\n";
    assert!(!scan_file("t.rs", rust_bad).is_empty());
    let rust_block = "/* a Wave-1 note */\nfn f() {}\n";
    assert!(!scan_file("t.rs", rust_block).is_empty());

    // MASM: error-message strings keep their tokens; a `#` inside a string is not a comment.
    let masm = "const ERR_X = \"DEV-5 cap awaits Circle # not a comment R-MINT-9\"\n";
    assert!(
        scan_file("t.masm", masm).is_empty(),
        "tokens inside MASM string constants must not trip the scan"
    );

    // TOML: quoted values keep their tokens; a `#` comment after them is scanned.
    let toml_ok = "name = \"DEV-5-fixture\"\n";
    assert!(scan_file("Cargo.toml", toml_ok).is_empty());
    let toml_bad = "members = [\"crates/a\"] # parked per DEC-4\n";
    assert!(!scan_file("Cargo.toml", toml_bad).is_empty());
}

#[test]
fn doc_comments_and_trailing_comments_trip() {
    let rust = "/// resolves R-ADMIN-4 for the setter\nfn f() {}\n";
    assert!(!scan_file("t.rs", rust).is_empty());
    let rust_trailing = "let x = 1; // per CIR-FEE-3 scaling\n";
    assert!(!scan_file("t.rs", rust_trailing).is_empty());
    let rust_inner = "//! module docs citing NS-1 here\n";
    assert!(!scan_file("t.rs", rust_inner).is_empty());
}
