//! The prose gate's own self-tests: each scan catches the defect it claims to and leaves good
//! prose alone, and the extractor reads exactly the comments a reader sees.
//!
//! A `#[path]` module of `comment_prose_quality.rs`, split out to keep every file inside the
//! governing Rust line ceiling. Its `#[test]`s run with the rest of that target.

use super::*;

// ================================================================================================
// SELF-TESTS — the scans catch what they claim to, and leave good prose alone
// ================================================================================================

#[test]
fn the_scans_catch_their_own_defects() {
    assert_eq!(
        doubled_word("the the shared encoding crate is the judge").as_deref(),
        Some("the the")
    );
    assert_eq!(doubled_word("CODE CODE is two code spans"), None);
    assert_eq!(
        doubled_word("the ECDSA verify: verify_prehash over the pubkey"),
        None,
        "punctuation between two spellings of a word is not a stutter"
    );
    assert_eq!(
        doubled_word("the limbs at base+0..base+3, element-0 on top"),
        None,
        "an offset expression is not a stutter"
    );
    assert_eq!(
        doubled_word("it must not grow a stand-in in the meantime"),
        None,
        "a hyphenated compound is one word"
    );
    assert_eq!(
        doubled_word("5 at 0.99s + 5 at 1.01s is a boundary burst"),
        None,
        "a dropped number separates the words either side of it"
    );
    assert_eq!(
        repeated_phrase("proven against a real local node against a real local node").as_deref(),
        Some("against a real local node against a real local node")
    );
    assert_eq!(
        repeated_phrase("the burn payload's amount, the burn payload's domain"),
        None,
        "a parallel list is not a stutter"
    );
    assert_eq!(
        garbled_emphasis("A WHAT a piece of evidence proves").as_deref(),
        Some("A WHAT")
    );
    assert_eq!(
        garbled_emphasis("The WHY outlives the deferral"),
        None,
        "a shouted noun after a definite article is emphasis, not a broken sentence"
    );
    assert_eq!(
        garbled_emphasis("it carries (a) WHAT + WHY, (b) WHICH slice introduces it"),
        None,
        "`(a)` is an enumerator, not an article"
    );
    assert_eq!(
        repeated_phrase("CODE at CODE CODE at CODE CODE at CODE"),
        None,
        "a run of masked code spans is a field list, not a stutter"
    );
    assert!(glued_path("the alternatives weighed, in./PERSISTENCE-CHOICE.md (guarded)").is_some());
    assert_eq!(
        glued_path("the record is in `./PERSISTENCE-CHOICE.md`"),
        None,
        "a path with its separator intact is a reference, not debris"
    );
}

#[test]
fn the_masm_skeleton_rule_reads_the_sections_it_requires() {
    let described = "\
#! Reduces an amount.
#!
#! Inputs:  [U_UPPER, scale_exp]
#! Outputs: [y]
#!
#! Where:
#! - U_UPPER is the upper word.
#! - scale_exp is the exponent.
#! - y is the reduced amount.
#!
#! Invocation: exec
proc demo
    add
end
";
    let p = &procs(described)[0];
    assert!(p.doc.iter().any(|l| l.starts_with("Where:")));
    assert_eq!(
        stack_item_names("Inputs:  [U_UPPER, scale_exp]"),
        vec!["U_UPPER".to_string(), "scale_exp".to_string()],
    );
    assert!(
        stack_item_names("Inputs:  [pad(16)]").is_empty(),
        "padding names no stack item, so it needs no `Where:` definition"
    );
    assert!(
        stack_item_names("Outputs: []").is_empty(),
        "an empty stack list names nothing"
    );

    // the description is what sits before the first section marker.
    let head: Vec<&String> = p
        .doc
        .iter()
        .take_while(|l| !DOC_SECTIONS.iter().any(|s| l.starts_with(s)))
        .collect();
    assert!(head.iter().any(|l| l.contains("Reduces an amount")));
}

#[test]
fn manifest_comments_are_in_scope() {
    let src = r#"
[package]
description = "a value with a # inside it, which is a value and not a comment"

[dependencies]
# The transport crate, and why this pin.
serde = { workspace = true }   # a trailing note the operator reads too
weird = { version = "1", features = ["a#b"] }
"#;
    let bodies: Vec<String> = comment_lines("crates/demo/Cargo.toml", src)
        .into_iter()
        .map(|c| c.body)
        .collect();
    assert_eq!(
        bodies,
        vec![
            "The transport crate, and why this pin.".to_string(),
            "a trailing note the operator reads too".to_string(),
        ],
        "the standalone AND trailing manifest comments are prose; a `#` inside a value is not"
    );
    assert!(sources().iter().any(|(rel, _)| rel == "Cargo.toml"));
    assert!(sources()
        .iter()
        .any(|(rel, _)| rel == "crates/xreserve-deposit-relayer/Cargo.toml"));
}

#[test]
fn rust_trailing_and_block_comments_are_in_scope() {
    let src = r##"
//! The module doc.
/* a block comment
 * over two lines
 */
fn f() -> &'static str {
    let s = "// not a comment"; // but this trailing one is
    let r = r#"/* also not a comment */"#;
    let c = '"';
    s
}
"##;
    let bodies: Vec<String> = comment_lines("crates/demo/src/lib.rs", src)
        .into_iter()
        .map(|c| c.body)
        .filter(|b| !b.is_empty())
        .collect();
    assert_eq!(
        bodies,
        vec![
            "The module doc.".to_string(),
            "a block comment".to_string(),
            "over two lines".to_string(),
            "but this trailing one is".to_string(),
        ],
        "trailing and block comments are read; markers inside literals are not"
    );
}

#[test]
fn the_grammar_and_delimiter_rules_catch_what_they_claim() {
    let clashes = |t: &str| {
        tokenize(&mask_code(t)).windows(2).any(|p| {
            p[1].adjacent
                && DETERMINERS_BEFORE.contains(&p[0].word.as_str())
                && DETERMINERS_AFTER.contains(&p[1].word.as_str())
        })
    };
    assert!(
        clashes("Maps a the shared encoding crate error onto the relayer taxonomy."),
        "`a the` is two determiners in a row"
    );
    assert!(
        !clashes("Maps an error from the shared encoding crate onto the relayer taxonomy."),
        "an ordinary sentence must not trip the clash rule"
    );
    assert!(
        PHRASE_MISLEAD_INS.contains(&"originating"),
        "`originating the shared encoding crate` is missing its preposition"
    );
    assert!(
        !PHRASE_MISLEAD_INS.contains(&"offset"),
        "`the offset the shared encoding crate defines` is a reduced relative clause, not a defect"
    );

    // delimiters: a half-open interval, a padded stack list, and a code span are not imbalances.
    for balanced in [
        "the quotient stays in [p, 2^64) after the split (and never wraps)",
        "=> [account_id_suffix, account_id_prefix, pad(16)]",
        "the `VALUE)junk` form is rejected",
    ] {
        let n = normalize_delimiters(balanced);
        assert_eq!(
            n.matches('(').count(),
            n.matches(')').count(),
            "parens: {balanced}"
        );
        assert_eq!(
            n.matches('[').count(),
            n.matches(']').count(),
            "brackets: {balanced}"
        );
    }
    let dangling = normalize_delimiters("the scheme is REQUIRES CIRCLE CONFIRMATION): none");
    assert_ne!(
        dangling.matches('(').count(),
        dangling.matches(')').count(),
        "a stray closing paren left by a removed citation must trip"
    );
}

#[test]
fn extraction_reads_comments_and_never_string_literals() {
    let src = r#"
//! The module doc.
fn f() {
    let s = "// not a comment, and not the the prose scanner's business";
    let t = "https://example.invalid/a";
}
/// The item doc — one sentence.
fn g() {}
"#;
    let found = blocks("crates/demo/src/lib.rs", src);
    let all: Vec<&str> = found
        .iter()
        .flat_map(|b| b.sentences.iter())
        .map(|s| s.text.as_str())
        .collect();
    assert_eq!(all.len(), 2, "exactly the two real comments: {all:?}");
    assert!(all.iter().any(|s| s.contains("module doc")));
    assert!(all.iter().any(|s| s.contains("item doc")));
    assert_eq!(
        found.iter().filter(|b| b.level == DocLevel::Module).count(),
        1
    );
}

#[test]
fn structural_lines_are_not_read_as_narrative() {
    let src = "\
#! Description of the proc.
#!
#! Inputs:  [A, B]
#! Outputs: [C]
#! Where:
#! - A is the upper word.
#! - B is the lower word.
#!
#! Invocation: exec
proc.demo
    # => [A, B]
    add
end
";
    let found = blocks("asm/demo.masm", src);
    let all: Vec<&str> = found
        .iter()
        .flat_map(|b| b.sentences.iter())
        .map(|s| s.text.as_str())
        .collect();
    assert!(
        all.iter()
            .all(|s| !s.starts_with("- ") && !s.contains("=>")),
        "bullets and stack trackers must not be scanned as prose: {all:?}"
    );
    assert!(all.iter().any(|s| s.contains("Description of the proc")));
}

#[test]
fn the_citation_residue_rule_catches_what_it_claims() {
    assert!(
        citation_residue("the two recovery hints COMPONENT-SPEC Circle's documentation reads")
            .is_some()
    );
    assert_eq!(
        citation_residue(
            "the field tables in `CIRCLE-API-SURFACE.md` and `CIRCLE-DATA-SCHEMAS.md`"
        ),
        None,
        "a document reference written with its extension is a reference, not residue"
    );
    assert!(
        citation_residue("binding harness (Envelope validation. The matching test row)").is_some()
    );
    assert!(citation_residue("the mock boundary.2 — the fixtures are frozen").is_some());
    assert_eq!(
        citation_residue("since protocol v0.16 (alpha.2) the surface grew"),
        None,
        "version notation is not a footnote digit"
    );
    assert_eq!(
        citation_residue("consumed first by `loc_storew_le.0`, then executed"),
        None,
        "an identifier inside a code span is code"
    );
    assert!(
        citation_residue("the sender read (`the corresponding test row`)").is_some(),
        "a placeholder wrapped in backticks is still a placeholder"
    );
    assert!(
        citation_residue("pinned by `COMPONENT-SPEC`").is_some(),
        "a bare document name inside a code span is still bare"
    );
    assert_eq!(
        citation_residue("the tables in `CIRCLE-API-SURFACE.md`"),
        None,
        "a code span holding a real reference is not residue"
    );
    assert!(
        !opens_like_a_sentence("— the auth posture: no credential is hardcoded."),
        "an orphaned em dash is the tail of a deleted head"
    );
    assert!(
        !opens_like_a_sentence("(shared across test targets) the fixture corpus."),
        "a standalone parenthetical is not the file's title"
    );
    assert!(!opens_like_a_sentence(
        ", and the discovery gate refuses it."
    ));
    assert!(!opens_like_a_sentence(
        "which burn each piece of evidence is attached to."
    ));
    assert!(opens_like_a_sentence(
        "The `409` conflict-recovery contract."
    ));
    assert!(opens_like_a_sentence(
        "**Burn-evidence trust labeling** — the highest-risk path."
    ));
    assert!(opens_like_a_sentence("`XUsdcMintNote` builds the note."));
}

#[test]
fn the_opener_scan_reads_past_a_blank_first_doc_line() {
    let blank_led = "//!\n//! — the auth posture, which stays OPEN.\n//!\npub fn f() {}\n";
    assert_eq!(
        module_doc_opener(blank_led).as_deref(),
        Some("— the auth posture, which stays OPEN."),
        "a blank `//!` is a separator; the sentence below it is the opener"
    );
    assert!(!opens_like_a_sentence(
        &module_doc_opener(blank_led).unwrap()
    ));

    let attributed = "#![allow(dead_code)]\n\n//! Shared test support.\n";
    assert_eq!(
        module_doc_opener(attributed).as_deref(),
        Some("Shared test support."),
        "an inner attribute above the doc does not hide the opener"
    );

    assert_eq!(
        module_doc_opener("// an ordinary comment\npub fn f() {}\n"),
        None,
        "a file with no module doc has no opener to judge"
    );
}

#[test]
fn the_self_determined_phrase_rule_separates_a_clash_from_a_clause() {
    for broken in [
        "the batch path runs the SAME Circle's documentation checks as the by-hash path",
        "a page carrying one attestation for EVERY Circle's documentation row",
        "The Circle's documentation conflation, caught here",
        "Maps a the shared encoding crate error onto the taxonomy",
        "leaf errors with no the shared encoding crate cause",
    ] {
        assert!(
            !self_determined_phrase_misuse(broken).is_empty(),
            "must flag: {broken}"
        );
    }
    for fine in [
        "the burn payload in the shape Circle's documentation describes",
        "the conflation Circle's documentation warns against, caught here",
        "one sentence in Circle's documentation covers it",
        "the offset the shared encoding crate defines",
        "an error from the shared encoding crate is preserved as the source",
    ] {
        assert_eq!(
            self_determined_phrase_misuse(fine),
            Vec::<String>::new(),
            "must not flag: {fine}"
        );
    }
}
