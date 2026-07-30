//! The prose gate's rules: the pure detectors each check applies to one comment block, plus the
//! MASM doc-block parser the structure check reads.
//!
//! A `#[path]` module of `comment_prose_quality.rs`, split out to keep every file inside the
//! governing Rust line ceiling.

use std::collections::BTreeSet;

use crate::prose::extract::*;
use crate::prose::text::*;

/// Interrogative pronouns that cannot follow an indefinite article in English. Shouted for
/// emphasis in this codebase's prose, which is exactly how a half-finished rewrite leaves one
/// stranded ("A WHAT a piece of evidence proves").
pub const INTERROGATIVES: &[&str] = &["WHAT", "WHICH", "WHOM", "WHOSE"];

/// Finds a word typed twice in a row with nothing but a space between ("the the").
pub fn doubled_word(text: &str) -> Option<String> {
    let t = tokenize(text);
    t.windows(2)
        .find(|pair| pair[1].adjacent && pair[0].word == pair[1].word && pair[0].word != "code")
        .map(|pair| format!("{} {}", pair[0].word, pair[1].word))
}

/// Finds a phrase of three or more words repeated immediately after itself, within one clause.
///
/// The repeat must be uninterrupted (no punctuation anywhere inside it) and must carry at least
/// two real words: a run of masked code spans is a field list, not a stutter.
pub fn repeated_phrase(text: &str) -> Option<String> {
    for clause in clauses(text) {
        let t = tokenize(&clause);
        for n in 3..=6usize {
            if t.len() < 2 * n {
                break;
            }
            for i in 0..=t.len() - 2 * n {
                let run = &t[i..i + 2 * n];
                if !run[1..].iter().all(|tok| tok.adjacent) {
                    continue;
                }
                let real: BTreeSet<&str> = run
                    .iter()
                    .map(|tok| tok.word.as_str())
                    .filter(|w| *w != "code")
                    .collect();
                if real.len() < 2 {
                    continue;
                }
                let first: Vec<&String> = run[..n].iter().map(|tok| &tok.word).collect();
                let second: Vec<&String> = run[n..].iter().map(|tok| &tok.word).collect();
                if first == second {
                    return Some(
                        run.iter()
                            .map(|tok| tok.word.clone())
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
            }
        }
    }
    None
}

/// Finds an indefinite article followed by a shouted interrogative — the residue of a sentence
/// that was being restructured and never finished.
pub fn garbled_emphasis(text: &str) -> Option<String> {
    let raw: Vec<&str> = text.split_whitespace().collect();
    for pair in raw.windows(2) {
        // `(a)` is an enumerator, not an article.
        if pair[0].starts_with('(') || pair[0].ends_with(')') {
            continue;
        }
        let first = pair[0].trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let second = pair[1].trim_matches(|c: char| !c.is_ascii_alphanumeric());
        let article = first.eq_ignore_ascii_case("a") || first.eq_ignore_ascii_case("an");
        if article && INTERROGATIVES.contains(&second) {
            return Some(format!("{first} {second}"));
        }
    }
    None
}

/// Finds a reference glued to the word before it (`in./PERSISTENCE-CHOICE.md`), the residue of a
/// path that lost its separator during an edit.
pub fn glued_path(body: &str) -> Option<String> {
    let bytes: Vec<char> = body.chars().collect();
    for (i, w) in bytes.windows(2).enumerate() {
        if w[0] == '.' && w[1] == '/' && i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
            let tail: String = bytes[i - 1..].iter().take(32).collect();
            return Some(tail);
        }
    }
    None
}

/// Determiners that cannot be followed immediately by another determiner.
pub const DETERMINERS_BEFORE: &[&str] = &["a", "an", "the", "no"];
/// The determiners the clash rule looks for in second position.
pub const DETERMINERS_AFTER: &[&str] = &["a", "an", "the"];

/// Noun phrases that already carry their own determiner. This refactor replaced internal unit
/// labels with them wholesale, and every site where the old label had its own article or an
/// adjectival participle in front was left ungrammatical ("carries the originating the shared
/// encoding crate error").
pub const SELF_DETERMINED_PHRASES: &[&str] = &[
    "the shared encoding crate",
    "the encoding crate",
    // a possessive determines its own phrase, so an article in front of it is residue: this
    // refactor replaced stripped section citations with "Circle's documentation" and left the
    // articles that had belonged to the citation behind ("the SAME Circle's documentation checks").
    "circle's documentation",
];

/// Words that may stand between a determiner and a self-determined phrase without breaking the
/// sentence: they end the first noun phrase and start a new relation.
pub const PREPOSITIONS: &[&str] = &[
    "from", "in", "of", "by", "to", "into", "onto", "with", "against", "inside", "within",
    "through", "as", "per", "via", "and", "or", "that", "than", "because", "since", "for", "on",
    "at", "between", "across", "over", "under", "about",
];

/// Words that cannot sit directly in front of a self-determined phrase: an article (the phrase
/// already has one) or a participle that needs a preposition to reach it ("originating FROM the
/// shared encoding crate"). An ordinary noun before it is fine — "the offset the shared encoding
/// crate defines" is a reduced relative clause, not a defect.
pub const PHRASE_MISLEAD_INS: &[&str] = &[
    "a",
    "an",
    "the",
    "no",
    "every",
    "each",
    "another",
    "originating",
    "stemming",
    "arising",
];

/// Normalizes the notations whose delimiters legitimately do not pair: a half-open mathematical
/// interval (`[0, 2^64)`) and a code span, whose contents are code and not prose.
pub fn normalize_delimiters(text: &str) -> String {
    let masked = mask_code(text);
    let mut out = String::with_capacity(masked.len());
    let mut rest = masked.as_str();
    while let Some(open) = rest.find('[') {
        let (head, tail) = rest.split_at(open);
        out.push_str(head);
        // an interval closes with `)` instead of `]` and holds nothing but its two bounds, so the
        // FIRST delimiter after the `[` decides: a `)` with a comma before it and no nesting in
        // between is `[lo, hi)`; anything else is an ordinary bracket, `[pad(16)]` included.
        match tail[1..].find(['[', ']', '(', ')']) {
            Some(end) if (&tail.as_bytes()[1..])[end] == b')' && tail[1..=end].contains(',') => {
                out.push_str("INTERVAL");
                rest = &tail[end + 2..];
            }
            _ => {
                out.push('[');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// One procedure and the doc block above it.
pub struct Proc {
    pub name: String,
    pub line: usize,
    pub doc: Vec<String>,
    pub asserts: bool,
}

/// The section markers a proc's doc block is built from. Everything before the first one is the
/// DESCRIPTION — the sentences that say what the procedure does and why.
pub const DOC_SECTIONS: &[&str] = &["Inputs:", "Outputs:", "Where:", "Panics if", "Invocation:"];

/// The named stack items on an `Inputs:` / `Outputs:` marker line, which a `Where:` section has to
/// define. Padding markers and bare numbers name nothing, so `[pad(16)]` needs no definitions.
pub fn stack_item_names(line: &str) -> Vec<String> {
    let Some(open) = line.find('[') else {
        return Vec::new();
    };
    let mut depth = 0usize;
    let mut list = "";
    for (off, c) in line[open..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    list = &line[open + 1..open + off];
                    break;
                }
            }
            _ => {}
        }
    }

    let mut names: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in list.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            names.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        names.push(cur);
    }
    names.retain(|n| n.chars().any(|c| c.is_ascii_alphabetic()) && n != "pad" && n != "ARGS");
    names
}

/// Every `proc` in a MASM source, with its doc block and whether its body can trap.
pub fn procs(src: &str) -> Vec<Proc> {
    let lines: Vec<&str> = src.lines().collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            t.starts_with("proc ") || t.starts_with("pub proc ")
        })
        .map(|(i, _)| i)
        .collect();

    let mut out = Vec::new();
    for (k, &i) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let asserts = lines[i + 1..end]
            .iter()
            .filter(|l| !l.trim_start().starts_with('#'))
            .any(|l| l.contains("assert") || l.contains("err="));

        // walk back over the attributes and the doc block.
        let mut doc = Vec::new();
        let mut j = i;
        while j > 0 {
            let t = lines[j - 1].trim_start();
            if t.starts_with("#!") {
                doc.push(t.trim_start_matches("#!").trim().to_string());
            } else if !t.starts_with('@') {
                break;
            }
            j -= 1;
        }
        doc.reverse();

        out.push(Proc {
            name: lines[i].trim().to_string(),
            line: i + 1,
            doc,
            asserts,
        });
    }
    out
}

/// The non-comment lines of a Rust source: what the code actually does.
pub fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The doc block immediately above the first line containing `anchor`.
pub fn doc_above(src: &str, anchor: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains(anchor))
        .unwrap_or_else(|| panic!("`{anchor}` must exist in the source"));

    let mut doc = Vec::new();
    let mut j = at;
    while j > 0 {
        let t = lines[j - 1].trim_start();
        if t.starts_with("///") {
            doc.push(t.trim_start_matches("///").trim().to_string());
        } else if !t.starts_with("#[") {
            break;
        }
        j -= 1;
    }
    doc.reverse();
    doc.join(" ")
}

/// Wordings that would tell a reader the attested amount does not travel with the note.
pub const AMOUNT_TRANSPORT_FALSEHOODS: &[&str] = &[
    "amount is not transported",
    "amount is not carried",
    "amount is not travelling",
    "amount does not travel",
    "does not transport the amount",
    "no amount is transported",
    "carries no amount",
    // the note's STORAGE is on the wire and carries the asset value, so "on the wire" is exactly
    // where the asset-less claim stops being true.
    "asset-less on the wire",
    "assetless on the wire",
];

/// Runs of consecutive comment lines, joined verbatim: the text a reader sees, with nothing masked.
pub fn raw_blocks(rel: &str, src: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut prev = 0usize;
    for cl in comment_lines(rel, src) {
        match out.last_mut() {
            Some((_, text)) if cl.line == prev + 1 => {
                text.push(' ');
                text.push_str(&cl.body);
            }
            _ => out.push((cl.line, cl.body.clone())),
        }
        prev = cl.line;
    }
    out
}

/// Document names this repository cites. Written with the `.md` extension they are a reference a
/// reader can follow; written bare, they are the residue of a citation that was half-removed and
/// left a shouted token stranded mid-sentence ("the two recovery hints COMPONENT-SPEC Circle's
/// documentation reads").
pub const DOCUMENT_NAMES: &[&str] = &[
    "COMPONENT-SPEC",
    "CIRCLE-API-SURFACE",
    "CIRCLE-DATA-SCHEMAS",
    "CIRCLE-CONFORMANCE",
    "PERSISTENCE-CHOICE",
    "DEFERRED-DEPENDENCIES",
    "TEST-AND-VERIFICATION-HARNESS",
    "ENCODING-COMPONENT-SPEC",
    "FAUCET-COMPONENT-SPEC",
    "RIV-ADVICE-KEY",
];

/// Placeholder phrases an automated edit left behind where a citation used to be. Each one reads
/// as a reference to something the reader cannot see, because there is nothing to see.
pub const PLACEHOLDER_PHRASES: &[&str] = &[
    "the corresponding test row",
    "the matching test row",
    "the corresponding row",
    "the matching row",
];

/// Finds the residue of a stripped citation in one comment block: a bare document name, a
/// placeholder phrase, a doubled slash, or a word glued to a bare footnote digit.
pub fn citation_residue(raw: &str) -> Option<String> {
    // Names and phrases are searched in the RAW text, with the backticks opened out: an automated
    // edit that dropped a citation often left the placeholder INSIDE a code span, and masking the
    // span first would hide exactly the defect this rule exists to find. Only the footnote-digit
    // rule below reads the masked form, because there an identifier really is code.
    let searchable = raw.replace('`', " ");
    let text = mask_code(raw);

    for name in DOCUMENT_NAMES {
        let mut from = 0usize;
        while let Some(at) = searchable[from..].find(name) {
            let at = from + at;
            if !searchable[at + name.len()..].starts_with(".md") {
                return Some(format!("bare document name `{name}`"));
            }
            from = at + name.len();
        }
    }

    let lowered = searchable.to_ascii_lowercase();
    for phrase in PLACEHOLDER_PHRASES {
        if lowered.contains(phrase) {
            return Some(format!("placeholder phrase `{phrase}`"));
        }
    }

    if searchable.contains(" / / ") || searchable.contains("/ /)") {
        return Some("a doubled slash where a citation was removed".to_string());
    }

    // "the mock boundary.2": a long English word carrying a bare footnote digit. Short words are
    // left alone — `le.0` and `alpha.2` are code and version notation, not prose.
    let chars: Vec<char> = text.chars().collect();
    for (i, w) in chars.windows(3).enumerate() {
        if w[0].is_ascii_alphabetic() && w[1] == '.' && w[2].is_ascii_digit() {
            let word_len = chars[..=i]
                .iter()
                .rev()
                .take_while(|c| c.is_ascii_lowercase())
                .count();
            let ends_here = chars.get(i + 3).is_none_or(|c| !c.is_ascii_alphanumeric());
            if word_len >= 6 && ends_here {
                let word: String = chars[i + 1 - word_len..i + 3].iter().collect();
                return Some(format!("a footnote digit glued to `{word}`"));
            }
        }
    }

    None
}

/// True when a module doc's first line opens the way a sentence does. A lowercase opener is the
/// tail of a sentence whose head was deleted ("which burn each piece of evidence is attached to").
pub fn opens_like_a_sentence(first_line: &str) -> bool {
    let t = first_line.trim_start_matches(['*', '_', '#', ' ']).trim();
    match t.chars().next() {
        None => true,
        // a capital opens a sentence; a code span or an intra-doc link opens one by naming its
        // subject ("`XUsdcMintNote` builds the note").
        Some(c) => c.is_ascii_uppercase() || c == '`' || c == '[',
    }
}

/// The first line of a file's module doc that carries words.
///
/// A module doc may open with a blank `//!` separator, and the sentence a reader actually starts
/// on is the first one below it — so the scan advances past empty lines instead of giving up on
/// the file, which would hide exactly the fragment it is looking for.
pub fn module_doc_opener(src: &str) -> Option<String> {
    src.lines()
        .map(str::trim_start)
        .skip_while(|l| !l.starts_with("//!"))
        .take_while(|l| l.starts_with("//!") || l.trim().is_empty() || l.starts_with("#!["))
        .filter(|l| l.starts_with("//!"))
        .map(|l| l.trim_start_matches("//!").trim().to_string())
        .find(|body| !body.is_empty())
}

/// Every misuse of a self-determined phrase in one comment block.
///
/// These phrases carry their own determiner, so an article or a bare participle in front of one is
/// the residue of a replacement that never reread its sentence. Two shapes are refused: the
/// determiner sitting directly in front ("no THE SHARED ENCODING CRATE codec"), and a determiner
/// reaching over an adjective to it ("the SAME CIRCLE'S DOCUMENTATION checks"). A noun in that
/// middle position is a reduced relative clause instead — "the shape CIRCLE'S DOCUMENTATION
/// describes" — and is left alone.
pub fn self_determined_phrase_misuse(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lowered = raw.to_ascii_lowercase();

    for phrase in SELF_DETERMINED_PHRASES {
        let mut from = 0usize;
        while let Some(at) = lowered[from..].find(phrase) {
            let at = from + at;
            let lead = lowered[..at]
                .trim_end()
                .rsplit(|c: char| !c.is_ascii_alphabetic())
                .next();
            let before: Vec<&str> = lowered[..at]
                .split(|c: char| !c.is_ascii_alphabetic() && c != '\'')
                .filter(|t| !t.is_empty())
                .collect();
            let after = lowered[at + phrase.len()..]
                .split(|c: char| !c.is_ascii_alphabetic() && c != '\'')
                .find(|t| !t.is_empty())
                .unwrap_or_default();

            // a phrase can head a reduced relative clause, and there a verb follows it.
            let trailing_possessive = lowered[at + phrase.len()..].starts_with("'s");
            let clause = trailing_possessive || after.ends_with('s') || after.ends_with("ed");
            // …but a SHOUTED word in front of it is an adjective, never the head of such a clause,
            // however verb-like the word after the phrase happens to look.
            let emphasis_adjective = raw
                .get(..at)
                .and_then(|b| b.split_whitespace().next_back())
                .is_some_and(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_uppercase()));

            if let Some(lead) = lead.filter(|l| !l.is_empty()) {
                if PHRASE_MISLEAD_INS.contains(&lead) {
                    out.push(format!(
                        "`{lead} {phrase}` needs a preposition or a determiner the phrase does not \
                         already carry"
                    ));
                } else if (!clause || emphasis_adjective)
                    && before.len() >= 2
                    && DETERMINERS_AFTER.contains(&before[before.len() - 2])
                    && !PREPOSITIONS.contains(&lead)
                {
                    out.push(format!(
                        "`{} {lead} {phrase} {after}` opens one noun phrase with two determiners",
                        before[before.len() - 2]
                    ));
                }
            }
            from = at + phrase.len();
        }
    }
    out
}
