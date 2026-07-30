//! Shared machinery for the comment prose-quality gate: the word-level primitives every rule shares —
//! tokenizing, masking code spans, and scoring how much two sentences share.
//!
//! Split out of `comment_prose_quality.rs` to keep every file inside the governing Rust line
//! ceiling. It is a `#[path]` module of that test, never a test target of its own.

use std::fs;
use std::path::{Path, PathBuf};

// ================================================================================================
// WORD-LEVEL HELPERS
// ================================================================================================

/// One word of a sentence, and whether nothing but spaces separated it from the word before it.
///
/// The adjacency flag is what tells a stutter from ordinary prose: "the the" is a defect,
/// "verify: verify_prehash" and "base+0..base+3" are not — punctuation sits between them.
#[derive(Debug, Clone)]
pub struct Token {
    pub word: String,
    pub adjacent: bool,
}

/// Splits a sentence into words. A word carries letters, digits, apostrophes, and the internal
/// `_`/`-` of an identifier or a compound, so `stand-in` and `verify_prehash` stay ONE word each.
pub fn tokenize(text: &str) -> Vec<Token> {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '\'' || c == '_' || c == '-';
    let mut out: Vec<Token> = Vec::new();
    let mut cur = String::new();
    let mut gap_clean = true;

    for c in text.chars() {
        if is_word(c) {
            cur.push(c);
            continue;
        }
        if !cur.is_empty() {
            out.push(Token {
                word: cur.to_ascii_lowercase(),
                adjacent: gap_clean,
            });
            cur.clear();
            gap_clean = true;
        }
        if !c.is_whitespace() {
            gap_clean = false;
        }
    }
    if !cur.is_empty() {
        out.push(Token {
            word: cur.to_ascii_lowercase(),
            adjacent: gap_clean,
        });
    }

    // numbers are dropped, and dropping one separates the words either side of it: "5 at 0.99s +
    // 5 at" must not read as a doubled "at".
    let mut kept: Vec<Token> = Vec::new();
    let mut broke = false;
    for t in out {
        if t.word
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        {
            kept.push(Token {
                adjacent: t.adjacent && !broke,
                ..t
            });
            broke = false;
        } else {
            broke = true;
        }
    }
    kept
}

/// The alphabetic words of a sentence, in order, lowercased.
pub fn words(text: &str) -> Vec<String> {
    tokenize(text).into_iter().map(|t| t.word).collect()
}

/// Splits a sentence at punctuation into the clauses a repeated phrase must sit inside.
///
/// "the burn payload's amount, the burn payload's domain" is a parallel list, not a stutter; only
/// an uninterrupted repeat is one.
pub fn clauses(text: &str) -> Vec<String> {
    text.split([',', ';', ':', '(', ')', '[', ']', '"', '/'])
        .flat_map(|part| part.split('—'))
        .flat_map(|part| part.split(" - "))
        .map(|part| part.to_string())
        .collect()
}

/// Every in-scope source file, workspace-relative, with its contents.
///
/// The manifests are in scope with the code: the workspace-root `Cargo.toml` and every crate's,
/// whose comment blocks carry the dependency rationale a reviewer reads first.
pub fn sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut paths = vec![root.join("Cargo.toml")];
    for dir in ["asm", "crates"] {
        collect_files(&root.join(dir), &mut paths);
    }
    paths.sort();

    let mut out = Vec::new();
    for path in paths {
        let rel = path
            .strip_prefix(&root)
            .expect("a path under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPT_PATHS.iter().any(|e| rel.starts_with(e)) {
            continue;
        }
        let src = fs::read_to_string(&path).expect("a readable source file");
        out.push((rel, src));
    }
    out
}

/// Collects `.rs` and `.masm` files under `dir`, skipping build output.
pub fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_files(&path, out);
        } else {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default();
            if ext == "masm" || ext == "rs" || name == "Cargo.toml" {
                out.push(path);
            }
        }
    }
}

/// Renders a failure list as one panic message: every site, so the whole remaining fix list is
/// visible in a single run.
pub fn report(kind: &str, hits: Vec<String>) {
    assert!(
        hits.is_empty(),
        "{} comment(s) {}:\n{}",
        hits.len(),
        kind,
        hits.join("\n")
    );
}

/// The workspace root, resolved from this crate's manifest directory.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Workspace-relative path prefixes excluded from the scan, each with the reason it is exempt.
pub const EXEMPT_PATHS: &[&str] = &[
    // the gate itself: its own rules are quoted here as prose examples.
    "crates/xusdc-encoding/tests/comment_prose_quality.rs",
    "crates/xusdc-encoding/tests/prose/",
    // byte-frozen conformance tripwires — editable only by a later authorized pass.
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
