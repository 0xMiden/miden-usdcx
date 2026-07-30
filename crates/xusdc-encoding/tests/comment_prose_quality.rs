//! Comment prose-quality gate: a comment says a thing once, says it in readable English, and says
//! something that is true of the code beneath it.
//!
//! The companion tripwire (`comment_hygiene_tripwire.rs`) proves comments carry no internal
//! process ids. Token-freedom is the floor, not the goal: a comment can be free of every banned
//! token and still be unreadable — the same invariant restated at the module, type, and inline
//! level, a run-on that has to be re-read to be parsed, a half-edited sentence left mid-rewrite,
//! or a description that contradicts the code. This file refuses those mechanically.
//!
//! The checks, and what each one is protecting:
//!
//! - **Doubled words and immediately repeated phrases.** The residue of an interrupted rewrite
//!   ("the the shared encoding crate", "against a real local node against a real local node").
//! - **Garbled emphasis.** An indefinite article in front of a shouted interrogative ("A WHAT a
//!   piece of evidence proves") is a sentence that was being restructured and never finished.
//! - **Grammar the eye trips on.** Two determiners in a row ("a the shared encoding crate", "no
//!   the codec"), and a phrase that already carries its own determiner being handed a second one:
//!   the residue of a search-and-replace that never reread its sentence.
//! - **Delimiters that never close.** An opening quote, paren, bracket, or backtick with no
//!   partner is a citation that was half-removed, and it leaves the sentence unreadable.
//! - **No residue of a half-removed citation.** A bare document name, a placeholder phrase left
//!   where a reference used to be, a doubled slash, a footnote digit glued to a word.
//! - **A module doc that opens with a sentence.** A file whose first line begins on an em dash, a
//!   parenthetical, or a lowercase word is one whose opening was deleted.
//! - **No run-on narrative.** A single sentence past the word budget is a paragraph wearing a
//!   sentence's punctuation; split it, or make it the list it wants to be.
//! - **No wrap artifacts.** A comment line opening on a full stop, or a path glued to the word
//!   before it (`in./RECORD.md`), is an edit that was never finished.
//! - **The MASM doc skeleton survives consolidation.** Every procedure keeps its description and
//!   its `Inputs:` / `Outputs:` / `Where:` / `Invocation:` sections, plus `Panics if:` when it
//!   asserts. `Where:` is mandatory, not conditional — renaming that section is losing it.
//! - **The mint-note docs match the note the code builds.** The one factual claim in this repo that
//!   a reader is most likely to act on: where the attested amount actually travels. A block that
//!   calls the note asset-less must say in the same breath that the amount is in its storage.
//!
//! Scope and judgement calls, all deliberate:
//!
//! - Comment text only, taken from `.masm` files under `asm/`, `.rs` files under `crates/`, and
//!   every `Cargo.toml` (the manifests' comments carry the dependency rationale). TRAILING
//!   comments after code and `/* … */` blocks are read as well; a marker inside a string literal,
//!   a raw string, a char literal, or a TOML value never is, because that is code.
//! - Style is NOT judged here, and SEMANTIC repetition is not judged at all: a comment that
//!   mentions implementation history, a later slice, or where a property is tested is accepted,
//!   and so is restating a contract at the module, type, and inline levels. What is still refused
//!   is repetition inside one sentence — a word or phrase typed twice in a row is a typo, not a
//!   restatement — along with prose that is malformed, contradicts the code, or runs away with
//!   itself.
//! - Bullet lines, markdown tables, headings, and MASM stack trackers (`# => [...]`) are
//!   enumerations and diagrams, not narrative: parallel phrasing is a virtue there, so they are
//!   excluded from the repetition and length rules. Turning a run-on into a bullet list is a
//!   legitimate fix, not an evasion — a list is read as a list.
//! - Code spans and URLs are masked to a single placeholder token before any word-level rule runs;
//!   `` `a` `` next to `` `b` `` is not a doubled word, and a long URL is not a long sentence.
//! - The same byte-frozen files the hygiene tripwire exempts are exempt here, for the same reason:
//!   they may not be edited, so a rule they fail would be unfixable.

use std::fs;

/// The most words one narrative sentence may carry. Chosen from the corpus, not from taste: the
/// median comment sentence here is 16 words and 99% are under 62, so a sentence past this is a
/// paragraph that never got its full stop.
const MAX_SENTENCE_WORDS: usize = 80;

#[path = "prose/mod.rs"]
mod prose;

use prose::extract::*;
use prose::rules::*;
use prose::text::*;

// ================================================================================================
// THE SCANS
// ================================================================================================

#[test]
fn comments_carry_no_doubled_words_or_stuttered_phrases() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for block in blocks(&rel, &src) {
            for s in &block.sentences {
                if let Some(d) = doubled_word(&s.text) {
                    hits.push(format!(
                        "{rel}:{} doubled word `{d}` in: {}",
                        s.line, s.text
                    ));
                }
                if let Some(p) = repeated_phrase(&s.text) {
                    hits.push(format!("{rel}:{} repeated phrase `{p}`", s.line));
                }
            }
        }
    }
    report(
        "carry a doubled word or a stuttered phrase (the residue of an interrupted rewrite)",
        hits,
    );
}

#[test]
fn comments_carry_no_half_rewritten_sentences() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for block in blocks(&rel, &src) {
            for s in &block.sentences {
                if let Some(g) = garbled_emphasis(&s.text) {
                    hits.push(format!(
                        "{rel}:{} `{g}` is not a sentence: {}",
                        s.line, s.text
                    ));
                }
            }
        }
    }
    report(
        "leave an article in front of a shouted interrogative — finish the sentence or drop it",
        hits,
    );
}

#[test]
fn comments_carry_no_wrap_artifacts() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for cl in comment_lines(&rel, &src) {
            let b = cl.body.trim();
            if b.is_empty() {
                continue;
            }
            // an opening full stop, comma, semicolon, colon, or slash is a line that lost the
            // words it belonged to. `...` is this codebase's deliberate continuation marker and is
            // a sentence's own opening, not debris.
            let first = b.chars().next().unwrap_or(' ');
            if matches!(first, '.' | ',' | ';' | ':' | ')' | ']') && !b.starts_with("...") {
                hits.push(format!("{rel}:{} opens with `{first}`: {b}", cl.line));
            }
            if let Some(g) = glued_path(&cl.body) {
                hits.push(format!("{rel}:{} glues a path to a word: {g}", cl.line));
            }
        }
    }
    report(
        "open on punctuation or glue a path to the word before it — rewrap the sentence",
        hits,
    );
}

#[test]
fn comments_read_as_english() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for (line, raw) in raw_blocks(&rel, &src) {
            let text = mask_code(&raw);

            // two determiners in a row, with nothing but a space between them.
            let toks = tokenize(&text);
            for pair in toks.windows(2) {
                if pair[1].adjacent
                    && DETERMINERS_BEFORE.contains(&pair[0].word.as_str())
                    && DETERMINERS_AFTER.contains(&pair[1].word.as_str())
                {
                    hits.push(format!(
                        "{rel}:{line} `{} {}` is two determiners in a row",
                        pair[0].word, pair[1].word
                    ));
                }
            }

            // a phrase that supplies its own `the`, handed a second determiner or a bare
            // participle by a replacement that never reread the sentence.
            for complaint in self_determined_phrase_misuse(&raw) {
                hits.push(format!("{rel}:{line} {complaint}"));
            }
        }
    }
    report("do not parse as English", hits);
}

#[test]
fn comment_blocks_close_every_delimiter_they_open() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for (line, raw) in raw_blocks(&rel, &src) {
            let text = normalize_delimiters(&raw);
            let unbalanced = [
                (
                    "parentheses",
                    text.matches('(').count(),
                    text.matches(')').count(),
                ),
                (
                    "brackets",
                    text.matches('[').count(),
                    text.matches(']').count(),
                ),
            ];
            for (name, open, close) in unbalanced {
                if open != close {
                    hits.push(format!(
                        "{rel}:{line} leaves {name} unbalanced ({open} open, {close} close)"
                    ));
                }
            }
            if text.matches('"').count() % 2 == 1 {
                hits.push(format!("{rel}:{line} leaves a double quote unclosed"));
            }
            if raw.matches('`').count() % 2 == 1 {
                hits.push(format!("{rel}:{line} leaves a code span unclosed"));
            }
        }
    }
    report(
        "open a delimiter they never close — usually the residue of a half-removed citation",
        hits,
    );
}

#[test]
fn narrative_sentences_stay_within_the_readability_budget() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for block in blocks(&rel, &src) {
            for s in &block.sentences {
                let count = words(&s.text).len();
                if count > MAX_SENTENCE_WORDS {
                    hits.push(format!(
                        "{rel}:{} is {count} words (budget {MAX_SENTENCE_WORDS}): {}…",
                        s.line,
                        s.text.chars().take(90).collect::<String>()
                    ));
                }
            }
        }
    }
    report(
        "run past the one-sentence word budget — split them, or make them the list they want to be",
        hits,
    );
}

// ================================================================================================
// THE MASM DOC SKELETON
// ================================================================================================

#[test]
fn masm_procs_keep_their_mandatory_doc_sections() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        if !rel.ends_with(".masm") {
            continue;
        }
        for p in procs(&src) {
            let mut missing: Vec<String> = Vec::new();

            // the DESCRIPTION: prose before the first section marker. A proc reduced to its stack
            // contract tells a reader the shape of the call and nothing about what it is for.
            let described = p
                .doc
                .iter()
                .take_while(|l| !DOC_SECTIONS.iter().any(|s| l.starts_with(s)))
                .any(|l| !l.trim().is_empty());
            if !described {
                missing.push("a description".to_string());
            }

            for section in ["Inputs:", "Outputs:", "Invocation:"] {
                if !p.doc.iter().any(|l| l.starts_with(section)) {
                    missing.push(format!("`{section}`"));
                }
            }
            if p.asserts && !p.doc.iter().any(|l| l.starts_with("Panics if")) {
                missing.push("`Panics if:`".to_string());
            }

            // `Where:` is mandatory structure, not a conditional: every procedure says what the
            // things on its stack ARE, padding included, so renaming or dropping the section is
            // losing the half of the contract that names them.
            if !p.doc.iter().any(|l| l.starts_with("Where:")) {
                missing.push("`Where:`".to_string());
            }

            if !missing.is_empty() {
                hits.push(format!(
                    "{rel}:{} `{}` is missing {}",
                    p.line,
                    p.name,
                    missing.join(", ")
                ));
            }
        }
    }
    report(
        "lost a mandatory doc section — consolidating prose must not cost a proc its description or its stack contract",
        hits,
    );
}

// ================================================================================================
// DOC ↔ CODE: WHERE THE ATTESTED AMOUNT TRAVELS
// ================================================================================================

#[test]
fn mint_note_docs_agree_with_the_note_the_code_builds() {
    let root = workspace_root();
    let factory = fs::read_to_string(root.join("crates/xusdc-encoding/src/note/xreserve_mint.rs"))
        .expect("the mint-note factory source");
    let builder =
        fs::read_to_string(root.join("crates/xreserve-deposit-relayer/src/miden/mint_note.rs"))
            .expect("the relayer's mint-note builder source");

    // The code fact every comment on this path has to agree with: the attested amount is built
    // into a fungible asset and handed to the mint-note STORAGE constructor, so it rides inside
    // the note's storage even though nothing is attached to `note.assets()`.
    let code = code_only(&factory);
    assert!(
        code.contains("FungibleAsset::new"),
        "the factory must construct the attested amount as a fungible asset"
    );
    assert!(
        code.contains("MintNoteStorage::new_fungible_public"),
        "the attested asset must go into the mint note's storage"
    );

    // No comment anywhere may tell the reader the opposite.
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for block in blocks(&rel, &src) {
            for s in &block.sentences {
                let lowered = s.text.to_ascii_lowercase();
                for phrase in AMOUNT_TRANSPORT_FALSEHOODS {
                    if lowered.contains(phrase) {
                        hits.push(format!("{rel}:{} claims `{phrase}`: {}", s.line, s.text));
                    }
                }
            }
        }
    }
    report(
        "contradict the note the code builds: the attested amount rides in the mint note's storage",
        hits,
    );

    // "asset-less" is true of `note.assets()` and false of the note as a whole, so a block that
    // says it has to say, in the same breath, where the amount actually is. A reader who stops at
    // the first half is left believing the note carries no value. Read RAW here — the word
    // "storage" often arrives inside `MintNoteStorage`, which the prose masker would hide.
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for (line, text) in raw_blocks(&rel, &src) {
            let text = text.to_ascii_lowercase();
            let claims_assetless = text.contains("asset-less")
                || text.contains("assetless")
                || text.contains("no asset is attached")
                || text.contains("nothing is attached");
            if claims_assetless && !text.contains("storage") {
                hits.push(format!("{rel}:{line} calls the note asset-less without saying the amount is embedded in its storage"));
            }
        }
    }
    report(
        "call a mint note asset-less without saying where the attested amount travels",
        hits,
    );

    // And the builder's own doc has to say where the amount goes, positively.
    let doc = doc_above(&builder, "pub fn build_mint_note").to_ascii_lowercase();
    assert!(
        doc.contains("storage"),
        "the `build_mint_note` doc must say the amount travels in the note's storage; it reads: {doc}"
    );
    assert!(
        doc.contains("asset"),
        "the `build_mint_note` doc must say what is (and is not) attached to the note; it reads: {doc}"
    );
    assert!(
        doc.contains("mint"),
        "the `build_mint_note` doc must say the faucet mints the amount on consumption; it reads: {doc}"
    );
}

#[path = "prose/selftest.rs"]
mod selftest;

#[test]
fn comments_carry_no_stripped_citation_residue() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        for (line, raw) in raw_blocks(&rel, &src) {
            if let Some(what) = citation_residue(&raw) {
                hits.push(format!("{rel}:{line} carries {what}"));
            }
        }
    }
    report(
        "carry the residue of a half-removed citation — finish the sentence or drop the reference",
        hits,
    );
}

#[test]
fn module_docs_open_with_a_sentence() {
    let mut hits = Vec::new();
    for (rel, src) in sources() {
        if !rel.ends_with(".rs") {
            continue;
        }
        // the file's opening SENTENCE, which is the first doc line that carries words: a leading
        // blank `//!` is a separator, not the opening, and skipping the file on one would let the
        // fragment underneath it through.
        let opener = module_doc_opener(&src);
        if let Some(first) = opener {
            if !opens_like_a_sentence(&first) {
                hits.push(format!("{rel}:1 opens mid-sentence: {first}"));
            }
        }
    }
    report(
        "start their module doc in the middle of a sentence — say what the file IS, in a sentence",
        hits,
    );
}
