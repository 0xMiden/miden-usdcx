//! Shared machinery for the comment prose-quality gate: reading comments out of MASM,
//! TOML, and Rust sources, and grouping them into the blocks and sentences a reader sees.
//!
//! Split out of `comment_prose_quality.rs` to keep every file inside the governing Rust line
//! ceiling. It is a `#[path]` module of that test, never a test target of its own.

// ================================================================================================
// COMMENT EXTRACTION
// ================================================================================================

/// Which doc level a run of comment lines sits at: `//!` describes the file, everything else
/// describes the item below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocLevel {
    Module,
    Item,
}

/// One comment line, already stripped of its marker.
#[derive(Debug, Clone)]
pub struct CommentLine {
    pub line: usize,
    pub body: String,
    pub level: DocLevel,
    /// A line that is an enumeration, a table row, a heading, or a MASM stack tracker — read as
    /// structure rather than as narrative prose.
    pub structural: bool,
}

/// A run of consecutive comment lines at one doc level: what a reader takes in as one block.
#[derive(Debug, Clone)]
pub struct Block {
    pub level: DocLevel,
    pub sentences: Vec<Sentence>,
}

/// One narrative sentence, with the line the block it came from starts at.
#[derive(Debug, Clone)]
pub struct Sentence {
    pub line: usize,
    pub text: String,
}

/// True when a comment line is structure rather than prose.
pub fn is_structural(body: &str) -> bool {
    let t = body.trim_start();
    // MASM stack trackers: `# => [ASSET_VALUE, tag, ...]`.
    if t.starts_with("=>") {
        return true;
    }
    // markdown headings inside Rust doc comments.
    if t.starts_with('#') {
        return true;
    }
    // markdown table rows and any line carrying a column separator.
    if t.contains('|') {
        return true;
    }
    // section banners: a rule of `=` or `-` characters.
    if t.len() > 3 && t.chars().all(|c| c == '=' || c == '-') {
        return true;
    }
    // bullets and numbered items.
    if t.starts_with("- ") || t.starts_with("* ") || t.starts_with("+ ") {
        return true;
    }
    let mut chars = t.chars();
    if let Some(first) = chars.next() {
        if first.is_ascii_digit() {
            let rest: String = chars.collect();
            if rest.starts_with(". ") || rest.starts_with(") ") {
                return true;
            }
        }
    }
    false
}

/// Every comment in one MASM source: the text from an unquoted `#` to end of line.
///
/// A `#` inside a quoted error message is CODE — an error string is asserted on byte for byte —
/// so string state is tracked and a marker inside one is never read as prose.
pub fn masm_raw_comments(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let mut in_string = false;
        let mut escaped = false;
        for (i, c) in line.char_indices() {
            match c {
                '\\' if in_string && !escaped => {
                    escaped = true;
                    continue;
                }
                '"' if !escaped => in_string = !in_string,
                '#' if !in_string => {
                    out.push((n + 1, line[i..].to_string()));
                    break;
                }
                _ => {}
            }
            escaped = false;
        }
    }
    out
}

/// Every comment in one TOML manifest: the text from a `#` that sits outside a string value.
///
/// All four TOML string forms are values, not prose — basic `"…"`, literal `'…'`, and the two
/// multi-line forms, which can carry a `#` across many lines — so string state persists across
/// lines. A trailing `#` after a dependency entry IS a comment and is read.
pub fn toml_raw_comments(src: &str) -> Vec<(usize, String)> {
    #[derive(PartialEq)]
    enum In {
        Code,
        Basic,
        Literal,
        MultiBasic,
        MultiLiteral,
    }
    let mut out = Vec::new();
    let mut state = In::Code;
    for (n, line) in src.lines().enumerate() {
        let b = line.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            match state {
                In::Code => {
                    if b[i..].starts_with(b"\"\"\"") {
                        state = In::MultiBasic;
                        i += 3;
                    } else if b[i..].starts_with(b"'''") {
                        state = In::MultiLiteral;
                        i += 3;
                    } else if b[i] == b'"' {
                        state = In::Basic;
                        i += 1;
                    } else if b[i] == b'\'' {
                        state = In::Literal;
                        i += 1;
                    } else if b[i] == b'#' {
                        out.push((n + 1, line[i..].to_string()));
                        break;
                    } else {
                        i += 1;
                    }
                }
                In::Basic => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i] == b'"' {
                        state = In::Code;
                        i += 1;
                    } else {
                        i += 1;
                    }
                }
                In::Literal => {
                    if b[i] == b'\'' {
                        state = In::Code;
                    }
                    i += 1;
                }
                In::MultiBasic => {
                    if b[i] == b'\\' {
                        i += 2;
                    } else if b[i..].starts_with(b"\"\"\"") {
                        state = In::Code;
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
                In::MultiLiteral => {
                    if b[i..].starts_with(b"'''") {
                        state = In::Code;
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
            }
        }
        if state == In::Basic || state == In::Literal {
            state = In::Code;
        }
    }
    out
}

/// Every comment in one Rust source: `//`-family line comments — including the TRAILING ones that
/// follow code — and `/* */` blocks, with string, raw-string, char, and lifetime spans skipped so
/// a comment marker inside a literal is never read as prose.
pub fn rust_raw_comments(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(src.len(), |e| i + e);
                out.push((line, src[i..end].to_string()));
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let start_line = line;
                let mut depth = 1usize;
                let mut j = i + 2;
                while j < b.len() && depth > 0 {
                    if b[j] == b'\n' {
                        line += 1;
                        j += 1;
                    } else if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                out.push((start_line, src[i..j].to_string()));
                i = j;
            }
            b'r' if matches!(b.get(i + 1), Some(&b'"') | Some(&b'#')) => {
                let mut hashes = 0usize;
                let mut j = i + 1;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) == Some(&b'"') {
                    j += 1;
                    let mut closer = vec![b'"'];
                    closer.extend(std::iter::repeat_n(b'#', hashes));
                    while j < b.len() {
                        if b[j] == b'\n' {
                            line += 1;
                        }
                        if b[j..].starts_with(&closer) {
                            j += closer.len();
                            break;
                        }
                        j += 1;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() {
                    match b[j] {
                        b'\\' => {
                            if b.get(j + 1) == Some(&b'\n') {
                                line += 1;
                            }
                            j += 2;
                        }
                        b'\n' => {
                            line += 1;
                            j += 1;
                        }
                        b'"' => {
                            j += 1;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                i = j;
            }
            b'\'' => {
                let rest = &b[i + 1..];
                let is_char_lit = match rest.first() {
                    Some(b'\\') => true,
                    Some(_) => rest.get(1) == Some(&b'\''),
                    None => false,
                };
                if is_char_lit {
                    let mut j = i + 1;
                    if b.get(j) == Some(&b'\\') {
                        j += 2;
                        while j < b.len() && b[j] != b'\'' {
                            j += 1;
                        }
                        j += 1;
                    } else {
                        j += 2;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Splits one extracted comment into marker-stripped `(line offset, body, level)` triples: a block
/// comment spans several lines, and each of its lines is a line of prose in its own right.
pub fn strip_markers(rel: &str, line: usize, text: &str) -> Vec<(usize, String, DocLevel)> {
    if rel.ends_with(".masm") || rel.ends_with(".toml") {
        let body = text
            .trim_start_matches('#')
            .strip_prefix('!')
            .unwrap_or_else(|| text.trim_start_matches('#'));
        return vec![(line, body.to_string(), DocLevel::Item)];
    }

    if let Some(rest) = text.strip_prefix("//!") {
        return vec![(line, rest.to_string(), DocLevel::Module)];
    }
    if let Some(rest) = text.strip_prefix("///") {
        return vec![(line, rest.to_string(), DocLevel::Item)];
    }
    if let Some(rest) = text.strip_prefix("//") {
        return vec![(line, rest.to_string(), DocLevel::Item)];
    }

    // a `/* … */` block: strip the fences and any leading `*` decoration, one entry per line.
    let level = if text.starts_with("/*!") {
        DocLevel::Module
    } else {
        DocLevel::Item
    };
    let inner = text
        .trim_start_matches("/*")
        .trim_start_matches('!')
        .trim_start_matches('*')
        .trim_end_matches("*/");
    inner
        .lines()
        .enumerate()
        .map(|(k, l)| {
            let body = l
                .trim_start()
                .trim_start_matches("* ")
                .trim_start_matches('*');
            (line + k, body.to_string(), level)
        })
        .collect()
}

/// Extracts every comment in one file, marker-stripped, in source order.
///
/// Comments after code count too — a trailing `// …` on a statement and a trailing `# …` on a
/// dependency entry are prose a reviewer reads — while a marker inside a string literal never
/// does, because the literal is code.
pub fn comment_lines(rel: &str, src: &str) -> Vec<CommentLine> {
    let raw = if rel.ends_with(".masm") {
        masm_raw_comments(src)
    } else if rel.ends_with(".toml") {
        toml_raw_comments(src)
    } else {
        rust_raw_comments(src)
    };

    let mut out = Vec::new();
    let mut bullet_indent: Option<usize> = None;

    for (line, text) in raw {
        for (idx, body, level) in strip_markers(rel, line, &text) {
            let body = body.as_str();
            // the indent INSIDE the comment is what tells a wrapped bullet from a new paragraph.
            let indent = body.len() - body.trim_start().len();
            let body = body.trim().to_string();
            let structural = if is_structural(&body) {
                bullet_indent = Some(indent);
                true
            } else if body.is_empty() {
                bullet_indent = None;
                true
            } else if bullet_indent.is_some_and(|b| indent > b) {
                // a wrapped bullet: still part of the enumeration above it, not new narrative.
                true
            } else {
                bullet_indent = None;
                false
            };

            out.push(CommentLine {
                line: idx,
                structural,
                body,
                level,
            });
        }
    }

    out
}

/// Masks code spans and URLs to a single placeholder token.
///
/// Everything word-level downstream — doubled words, repeated phrases, sentence length, content
/// overlap — would otherwise be reading identifiers and paths as English.
pub fn mask_code(text: &str) -> String {
    // URLs first: one token each, but the punctuation AROUND the token stays — a full stop after
    // a link still ends the sentence.
    let mut urled = String::with_capacity(text.len());
    for (i, word) in text.split_whitespace().enumerate() {
        if i > 0 {
            urled.push(' ');
        }
        if word.contains("://") {
            // the punctuation AROUND the link survives on both sides: an opening `(` that was
            // dropped here would read as an unbalanced parenthesis downstream.
            let head: String = word
                .chars()
                .take_while(|c| matches!(c, '(' | '[' | '"' | '`' | '<'))
                .collect();
            let tail: String = word
                .chars()
                .rev()
                .take_while(|c| {
                    matches!(
                        c,
                        '.' | ',' | ';' | ':' | ')' | ']' | '!' | '?' | '"' | '`' | '>'
                    )
                })
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            urled.push_str(&head);
            urled.push_str("CODE");
            urled.push_str(&tail);
        } else {
            urled.push_str(word);
        }
    }

    // then the code spans, character by character, so every mark outside a span survives.
    let mut out = String::with_capacity(urled.len());
    let mut in_span = false;
    for c in urled.chars() {
        if c == '`' {
            if !in_span {
                out.push_str("CODE");
            }
            in_span = !in_span;
            continue;
        }
        if !in_span {
            out.push(c);
        }
    }

    out.trim().to_string()
}

/// Splits prose into sentences on terminal punctuation.
pub fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        cur.push(c);
        if matches!(c, '.' | '!' | '?') && chars.peek().is_some_and(|n| n.is_whitespace()) {
            out.push(cur.trim().to_string());
            cur.clear();
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }

    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// Groups a file's comment lines into blocks and each block's narrative into sentences.
///
/// Structural lines break the narrative run — a bullet list interrupts a paragraph, so the prose
/// before it and after it are never joined into one sentence that spans them.
pub fn blocks(rel: &str, src: &str) -> Vec<Block> {
    let lines = comment_lines(rel, src);
    let mut out: Vec<Block> = Vec::new();
    let mut current: Option<Block> = None;
    let mut para: Vec<String> = Vec::new();
    let mut para_line = 0usize;
    let mut prev_line = 0usize;

    fn flush(para: &mut Vec<String>, para_line: usize, block: &mut Option<Block>) {
        if para.is_empty() {
            return;
        }
        let joined = para.join(" ");
        para.clear();
        if let Some(b) = block.as_mut() {
            for s in split_sentences(&mask_code(&joined)) {
                b.sentences.push(Sentence {
                    line: para_line,
                    text: s,
                });
            }
        }
    }

    for cl in lines {
        let contiguous = cl.line == prev_line + 1;
        let same_level = current.as_ref().is_some_and(|b| b.level == cl.level);
        if !(contiguous && same_level) {
            flush(&mut para, para_line, &mut current);
            if let Some(b) = current.take() {
                out.push(b);
            }
            current = Some(Block {
                level: cl.level,
                sentences: Vec::new(),
            });
        }
        prev_line = cl.line;

        if cl.structural || cl.body.is_empty() {
            flush(&mut para, para_line, &mut current);
            continue;
        }
        if para.is_empty() {
            para_line = cl.line;
        }
        para.push(cl.body.clone());
    }
    flush(&mut para, para_line, &mut current);
    if let Some(b) = current.take() {
        out.push(b);
    }

    out
}
