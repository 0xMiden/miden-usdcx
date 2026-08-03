//! MASM structure-conformance suite: mechanically enforces the
//! 0xMiden/protocol MASM source conventions the repo is bound to — the adjudicated rules of
//! the repository's MASM structure conventions (file/section structure, imports,
//! doc-comment blocks, constants/errors organization, inline `# =>` trackers) as pinned by the
//! `.claude/skills/masm-*` skill set and grounded against `protocol@v0.15.3` (`681fc9058`).
//!
//! Structure ONLY: every rule here is satisfiable by comment/whitespace/import/name-level edits
//! that leave each assembled MAST root byte-identical. The behavioural net (roots, export paths,
//! parity) stays in `constant_parity.rs` / `mint_root_surface.rs` / the execution suites — this
//! file polices the source *shape* so a structural regression fails loud.
//!
//! Deliberate non-rules (repo-frozen decisions this suite must NOT fight):
//! - `@locals` offsets stay literal in the parity-swept component modules — the bidirectional
//!   sweep (`constant_parity.rs`) pins the exact per-file numeric-constant sets and is frozen, so
//!   promoting locals offsets to named constants is out of scope for a structure pass.
//! - Note scripts keep their prose `#` file headers (content is load-bearing provenance; protocol's
//!   thin notes carry none, but stripping content is a comment-content decision, not a form one).

use std::fs;
use std::path::{Path, PathBuf};

/// A single rule violation, rendered as `relative/path.masm:line: message`.
type Violations = Vec<String>;

/// The known top-level section banner titles, in their mandatory relative order
/// (masm-file-structure skill; protocol `access/authority.masm` / `access/ownable2step.masm`).
const SECTION_ORDER: [&str; 5] = [
    "TYPE ALIASES",
    "CONSTANTS",
    "ERRORS",
    "PUBLIC INTERFACE",
    "HELPER PROCEDURES",
];

/// The exact banner separator: `# ` plus 97 `=` (99 columns, the dominant protocol width).
const SEPARATOR_LEN: usize = 99;

fn asm_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../asm")
}

fn collect_masm_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("asm directory must be readable") {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_masm_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "masm") {
            out.push(path);
        }
    }
}

/// Every `.masm` source as `(repo-relative path, contents)`, sorted for stable failure output.
fn masm_sources() -> Vec<(String, String)> {
    let root = asm_root();
    let mut files = Vec::new();
    collect_masm_files(&root, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "no .masm files found under {}",
        root.display()
    );
    files
        .into_iter()
        .map(|p| {
            let rel = format!("asm/{}", p.strip_prefix(&root).unwrap().display());
            let src = fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
            (rel, src)
        })
        .collect()
}

fn is_note_script(rel: &str) -> bool {
    rel.starts_with("asm/standards/notes/")
}

fn is_impl_module(rel: &str) -> bool {
    rel.starts_with("asm/standards/xreserve/")
}

/// The code part of a line: everything before the first `#` that is outside a string literal.
fn code_part(line: &str) -> &str {
    let mut in_string = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Import-group rank per the protocol layout: kernel/protocol first, then the standards
/// library, then the core library, then the repo's own `xreserve` modules
/// (`fungible.masm` / `p2id.masm` order, generalized to the three `miden::*` families).
fn use_group_rank(use_path: &str) -> u8 {
    if use_path.starts_with("miden::protocol") {
        0
    } else if use_path.starts_with("miden::standards") {
        1
    } else if use_path.starts_with("miden::core") {
        2
    } else {
        3
    }
}

/// Runs `check` over every MASM source and asserts it reported no violations.
fn assert_rule<F>(rule: &str, mut check: F)
where
    F: FnMut(&str, &str, &mut Violations),
{
    let mut violations = Vec::new();
    for (rel, src) in masm_sources() {
        check(&rel, &src, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "MASM structure rule `{rule}` violated at {} site(s):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// A procedure with its `#!` doc block and body, extracted for the doc-semantics rules.
struct ProcDoc {
    /// 1-indexed line of the `proc` / `pub proc` declaration.
    proc_line: usize,
    name: String,
    is_note_entry: bool,
    /// Whether the declaration carries `@account_procedure` — the attribute that publishes the
    /// procedure on the composed account's callable interface.
    is_account_procedure: bool,
    /// Doc lines in source order, each `(1-indexed line, full text)`.
    doc: Vec<(usize, String)>,
    /// Body lines (after the declaration, up to the column-0 `end`).
    body: Vec<String>,
}

impl ProcDoc {
    fn doc_text(&self) -> String {
        self.doc
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The documented invocation kind (`exec` / `call` / `dynexec` / `dyncall`), if declared.
    fn invocation(&self) -> Option<&str> {
        self.doc
            .iter()
            .find_map(|(_, l)| l.strip_prefix("#! Invocation: "))
            .map(str::trim)
    }
}

/// Extracts every procedure of `src` with its doc block (walking back over `@` attributes) and its
/// body (up to the column-0 `end`).
fn proc_docs(src: &str) -> Vec<ProcDoc> {
    let lines: Vec<&str> = src.lines().collect();
    let mut procs = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let name = match line
            .strip_prefix("pub proc ")
            .or_else(|| line.strip_prefix("proc "))
        {
            Some(rest) => rest.split_whitespace().next().unwrap_or(rest).to_string(),
            None => continue,
        };
        let mut j = i;
        let mut is_note_entry = false;
        let mut is_account_procedure = false;
        while j > 0 && lines[j - 1].starts_with('@') {
            if lines[j - 1].starts_with("@note_script") {
                is_note_entry = true;
            }
            if lines[j - 1].trim() == "@account_procedure" {
                is_account_procedure = true;
            }
            j -= 1;
        }
        let mut doc = Vec::new();
        while j > 0 && lines[j - 1].starts_with("#!") {
            doc.push((j, lines[j - 1].to_string()));
            j -= 1;
        }
        doc.reverse();
        let body: Vec<String> = lines[i + 1..]
            .iter()
            .take_while(|&&l| l != "end")
            .map(|l| (*l).to_string())
            .collect();
        procs.push(ProcDoc {
            proc_line: i + 1,
            name,
            is_note_entry,
            is_account_procedure,
            doc,
            body,
        });
    }
    procs
}

/// The bracketed stack list of a doc line (`Inputs:  [ARGS, pad(12)]` -> `ARGS, pad(12)`), if the
/// line carries one.
fn bracket_list(line: &str) -> Option<&str> {
    let start = line.find('[')?;
    let mut depth = 0usize;
    for (off, c) in line[start..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&line[start + 1..start + off]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits a stack list on top-level commas.
fn split_stack_items(list: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in list.chars() {
        match c {
            '[' | '(' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ']' | ')' | '}' => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if depth == 0 => {
                items.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        items.push(cur.trim().to_string());
    }
    items
}

/// The element count of one documented stack item: `pad(N)` / `name(N)` spans count N, Word-shaped
/// UPPER_SNAKE names count 4, single felts count 1. Open-ended (`...`) and malformed spans are
/// errors — a fixed-size boundary cannot be counted through them.
fn stack_item_elements(item: &str) -> Result<usize, String> {
    if item == "..." {
        return Err("open-ended `...` item".to_string());
    }
    if let Some(open) = item.find('(') {
        // a span is `<ident>(N)` exactly: named prefix, numeric count, nothing trailing.
        let Some(close) = item.rfind(')') else {
            return Err(format!("unclosed span `{item}`"));
        };
        if close != item.len() - 1 {
            return Err(format!("trailing text after span `{item}`"));
        }
        let name = &item[..open];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("malformed span name `{item}`"));
        }
        return item[open + 1..close]
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("non-numeric span `{item}`"));
    }
    let ident: String = item
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        return Err(format!("unrecognized stack item `{item}`"));
    }
    if ident.len() != item.len() {
        // e.g. `VALUE)junk` — the whole item must be the identifier (or a `name(N)` span,
        // handled above).
        return Err(format!("trailing text after identifier `{item}`"));
    }
    let is_word = ident.len() > 1
        && ident.chars().any(|c| c.is_ascii_uppercase())
        && !ident.chars().any(|c| c.is_ascii_lowercase());
    Ok(if is_word { 4 } else { 1 })
}

/// All identifiers inside the top-level bracket list of `line`.
fn bracket_idents(line: &str) -> Vec<String> {
    let Some(list) = bracket_list(line) else {
        return Vec::new();
    };
    let mut idents = Vec::new();
    let mut cur = String::new();
    for c in list.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else if !cur.is_empty() {
            idents.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        idents.push(cur);
    }
    idents.retain(|i| i.chars().any(|c| c.is_ascii_alphabetic()) && i != "pad");
    idents
}

// IMPORT HYGIENE
// ================================================================================================

/// No leading `::` path separator on `use` lines or inline `exec.`/`call.` targets: cross-module
/// references resolve through a `use` import and the short module alias, the protocol form
/// (`use miden::standards::faucets::fungible as faucet` + `call.faucet::…`, `notes/burn.masm`).
#[test]
fn references_resolve_through_imports_not_absolute_paths() {
    assert_rule("no absolute-path references", |rel, src, out| {
        for (n, line) in src.lines().enumerate() {
            let code = code_part(line);
            if code.trim_start().starts_with("use ::") {
                out.push(format!(
                    "{rel}:{}: `use ::…` has a leading path separator",
                    n + 1
                ));
            }
            for needle in ["exec.::", "call.::", "syscall.::"] {
                if code.contains(needle) {
                    out.push(format!(
                        "{rel}:{}: inline absolute-path invocation `{needle}…` (import the module \
                         with `use` and invoke through its alias)",
                        n + 1
                    ));
                }
            }
        }
    });
}

/// `use` lines are grouped by family in the protocol order: `miden::protocol`, then
/// `miden::standards`, then `miden::core`, then the repo's own `xreserve` modules.
#[test]
fn use_lines_follow_protocol_group_order() {
    assert_rule("use-group order", |rel, src, out| {
        let mut last_rank = 0u8;
        for (n, line) in src.lines().enumerate() {
            if let Some(path) = line.strip_prefix("use ") {
                // v0.25 item-import form: `use {A, B} from module` — the group is the MODULE
                // after ` from ` (a multi-line braced import ranks on its closing line, where
                // the module path appears; its member lines don't start with `use `).
                let path = match path.split_once(" from ") {
                    Some((_, module)) => module,
                    None => path,
                };
                if path.trim().ends_with('{') {
                    // opening line of a multi-line braced import: module unknown here.
                    continue;
                }
                let rank = use_group_rank(path.trim());
                if rank < last_rank {
                    out.push(format!(
                        "{rel}:{}: `use {}` is out of group order (protocol -> standards -> core \
                         -> xreserve)",
                        n + 1,
                        path.trim()
                    ));
                }
                last_rank = rank;
            }
        }
    });
}

/// The import block is contiguous: no blank or non-`use` lines between the first and the last
/// `use` statement (masm-file-structure: "No blank lines between imports").
#[test]
fn use_block_is_contiguous() {
    assert_rule("contiguous use block", |rel, src, out| {
        let lines: Vec<&str> = src.lines().collect();
        let first = lines.iter().position(|l| l.starts_with("use "));
        let last = lines
            .iter()
            .rposition(|l| l.starts_with("use ") || l.trim_start().starts_with("} from "));
        if let (Some(first), Some(last)) = (first, last) {
            let mut in_braced = false;
            for (i, line) in lines.iter().enumerate().take(last).skip(first) {
                if i == first {
                    in_braced = line.starts_with("use {") && !line.contains('}');
                    continue;
                }
                if in_braced {
                    // member/closing lines of a v0.25 multi-line braced import.
                    if line.trim_start().starts_with("} from ") {
                        in_braced = false;
                    }
                    continue;
                }
                if line.starts_with("use ") {
                    in_braced = line.starts_with("use {") && !line.contains('}');
                    continue;
                }
                out.push(format!(
                    "{rel}:{}: non-import line inside the `use` block",
                    i + 1
                ));
            }
        }
    });
}

// CONSTANTS & ERRORS
// ================================================================================================

/// Every constant is declared before the first procedure (masm-constants: placement).
#[test]
fn constants_precede_procedures() {
    assert_rule("constants before procedures", |rel, src, out| {
        let mut seen_proc = false;
        for (n, line) in src.lines().enumerate() {
            if line.starts_with("proc ") || line.starts_with("pub proc ") {
                seen_proc = true;
            }
            if seen_proc && (line.starts_with("const ") || line.starts_with("pub const ")) {
                out.push(format!(
                    "{rel}:{}: constant declared after a procedure",
                    n + 1
                ));
            }
        }
    });
}

/// `ERR_*` constants form the trailing errors group (after every non-error constant), are
/// SCREAMING_SNAKE named, carry string messages, and the messages do not end with a period
/// (masm-constants + protocol `fungible.masm:40-48`).
#[test]
fn error_constants_are_grouped_last_and_string_valued() {
    assert_rule("error-constant grouping/form", |rel, src, out| {
        let mut seen_err = false;
        for (n, line) in src.lines().enumerate() {
            let Some(decl) = line
                .strip_prefix("pub const ")
                .or_else(|| line.strip_prefix("const "))
            else {
                continue;
            };
            let Some((name, value)) = decl.split_once('=') else {
                continue;
            };
            let (name, value) = (name.trim(), value.trim());
            if name.starts_with("ERR_") {
                seen_err = true;
                if !name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    out.push(format!(
                        "{rel}:{}: error constant `{name}` is not SCREAMING_SNAKE",
                        n + 1
                    ));
                }
                if !value.starts_with('"') {
                    out.push(format!(
                        "{rel}:{}: error constant `{name}` must carry a string message",
                        n + 1
                    ));
                } else if value.trim_end_matches('"').ends_with('.') {
                    out.push(format!(
                        "{rel}:{}: error message of `{name}` must not end with a period",
                        n + 1
                    ));
                }
            } else if seen_err {
                out.push(format!(
                    "{rel}:{}: non-error constant `{name}` declared after the ERR_ group",
                    n + 1
                ));
            }
        }
    });
}

/// Constant declarations put spaces around `=` (masm-constants: formatting).
#[test]
fn constant_declarations_space_the_equals_sign() {
    assert_rule("const spacing", |rel, src, out| {
        for (n, line) in src.lines().enumerate() {
            let Some(decl) = line
                .strip_prefix("pub const ")
                .or_else(|| line.strip_prefix("const "))
            else {
                continue;
            };
            let Some(eq) = decl.find('=') else { continue };
            if !decl[..eq].ends_with(' ') || !decl[eq + 1..].starts_with(' ') {
                out.push(format!(
                    "{rel}:{}: `const` declaration lacks spaces around `=`",
                    n + 1
                ));
            }
        }
    });
}

// SECTION BANNERS
// ================================================================================================

/// Section banners are `# TITLE` directly above a 99-column `# ===…` separator; titles come from
/// the known section set and appear in the mandatory order; a section banner exists for every
/// populated section kind (masm-file-structure; separators per protocol `access/authority.masm`).
#[test]
fn section_banners_are_known_ordered_and_exhaustive() {
    assert_rule("section banners", |rel, src, out| {
        let lines: Vec<&str> = src.lines().collect();
        let mut last_rank = 0usize;
        let mut titles_seen = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !(line.starts_with("# =") && line[2..].chars().all(|c| c == '=')) {
                continue;
            }
            if line.len() != SEPARATOR_LEN {
                out.push(format!(
                    "{rel}:{}: banner separator is {} columns (want {SEPARATOR_LEN})",
                    i + 1,
                    line.len()
                ));
            }
            let Some(title_line) = i.checked_sub(1).map(|p| lines[p]) else {
                out.push(format!(
                    "{rel}:{}: separator with no banner title above",
                    i + 1
                ));
                continue;
            };
            let Some(raw_title) = title_line.strip_prefix("# ") else {
                out.push(format!(
                    "{rel}:{}: separator with no banner title above",
                    i + 1
                ));
                continue;
            };
            // the base title is the leading ALL-CAPS run; qualifiers follow after ` — ` or `(`.
            let base: String = raw_title
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == ' ')
                .collect();
            let base = base.trim();
            let Some(rank) = SECTION_ORDER.iter().position(|s| *s == base) else {
                out.push(format!(
                    "{rel}:{}: unknown section banner `{raw_title}` (allowed: {})",
                    i,
                    SECTION_ORDER.join(", ")
                ));
                continue;
            };
            if rank < last_rank {
                out.push(format!(
                    "{rel}:{}: section `{base}` out of order (want {})",
                    i,
                    SECTION_ORDER.join(" -> ")
                ));
            }
            last_rank = rank;
            titles_seen.push(base.to_string());
        }

        // populated sections must carry their banner.
        let has_non_err_const = src.lines().any(|l| {
            let d = l
                .strip_prefix("pub const ")
                .or_else(|| l.strip_prefix("const "));
            d.is_some_and(|d| !d.trim_start().starts_with("ERR_"))
        });
        let has_err_const = src.lines().any(|l| {
            let d = l
                .strip_prefix("pub const ")
                .or_else(|| l.strip_prefix("const "));
            d.is_some_and(|d| d.trim_start().starts_with("ERR_"))
        });
        let has_pub_proc = src.lines().any(|l| l.starts_with("pub proc "));
        let has_helper_proc = src.lines().any(|l| l.starts_with("proc "));
        let requirements = [
            (has_non_err_const, "CONSTANTS"),
            (has_err_const, "ERRORS"),
            (has_pub_proc, "PUBLIC INTERFACE"),
            (has_helper_proc, "HELPER PROCEDURES"),
        ];
        for (needed, title) in requirements {
            if needed && !titles_seen.iter().any(|t| t == title) {
                out.push(format!(
                    "{rel}:1: populated section without a `# {title}` banner"
                ));
            }
        }
    });
}

/// Public procedures come before non-`pub` helpers (masm-file-structure section order for the
/// repo's standalone modules, the adjudicated project rule of the MASM structure research report).
#[test]
fn public_procedures_precede_helpers() {
    assert_rule("public-before-helpers", |rel, src, out| {
        let mut seen_helper = false;
        for (n, line) in src.lines().enumerate() {
            if line.starts_with("proc ") {
                seen_helper = true;
            } else if line.starts_with("pub proc ") && seen_helper {
                out.push(format!(
                    "{rel}:{}: `pub proc` declared after a non-pub helper procedure",
                    n + 1
                ));
            }
        }
    });
}

// DOC-COMMENT BLOCKS
// ================================================================================================

/// Every procedure carries a `#!` doc block directly above it (attributes may sit between) with
/// `Inputs:` and `Outputs:` sections, and — for procs that are not `@note_script` entries — an
/// `Invocation:` line naming exec/call/dynexec/dyncall (masm-doc-comments; protocol uniform style).
fn check_doc_completeness(rel: &str, src: &str, out: &mut Violations) {
    for proc in proc_docs(src) {
        if proc.doc.is_empty() {
            out.push(format!(
                "{rel}:{}: procedure without a `#!` doc block",
                proc.proc_line
            ));
            continue;
        }
        // a section is a line-anchored `#! <marker>` that carries a stack contract: a bracket
        // list on the marker line itself, prose after the marker, or the kernel multi-line form
        // (indented `Operand stack:` / `Advice stack:` sub-lines with bracket lists).
        for marker in ["Inputs:", "Outputs:"] {
            let anchored = proc.doc.iter().enumerate().any(|(k, (_, l))| {
                let Some(rest) = l.strip_prefix("#! ") else {
                    return false;
                };
                let Some(payload) = rest.strip_prefix(marker) else {
                    return false;
                };
                if !payload.trim().is_empty() {
                    return true;
                }
                proc.doc[k + 1..]
                    .iter()
                    .take_while(|(_, l2)| l2.starts_with("#!   "))
                    .any(|(_, l2)| {
                        (l2.contains("Operand stack:") || l2.contains("Advice stack:"))
                            && bracket_list(l2).is_some()
                    })
            });
            if !anchored {
                out.push(format!(
                    "{rel}:{}: doc block missing a `#! {marker}` section line with a stack \
                     contract",
                    proc.proc_line
                ));
            }
        }
        if !proc.is_note_entry {
            let has_invocation = ["exec", "call", "dynexec", "dyncall"]
                .iter()
                .any(|kind| proc.invocation() == Some(*kind));
            if !has_invocation {
                out.push(format!(
                    "{rel}:{}: doc block missing `Invocation: exec|call|dynexec|dyncall`",
                    proc.proc_line
                ));
            }
        }
    }
}

#[test]
fn procedures_carry_complete_doc_blocks() {
    assert_rule("doc-block completeness", check_doc_completeness);
}

/// Note-script entry docs follow the protocol shape (`notes/burn.masm` / `notes/mint.masm`):
/// the kernel dyncalls `main` with the note args on top, so the contract is
/// `Inputs:  [ARGS, pad(12)]` / `Outputs: [pad(16)]`, and the entry declares
/// `Invocation: dyncall` (masm-doc-comments: invocation always specified).
#[test]
fn note_script_entry_docs_follow_protocol_shape() {
    assert_rule("note-entry doc shape", |rel, src, out| {
        if !is_note_script(rel) {
            return;
        }
        let required = [
            "#! Inputs:  [ARGS, pad(12)]",
            "#! Outputs: [pad(16)]",
            "#! Invocation: dyncall",
        ];
        for line in required {
            if !src.lines().any(|l| l == line) {
                out.push(format!("{rel}:1: note entry doc missing `{line}`"));
            }
        }
    });
}

// ASSERTIONS
// ================================================================================================

/// Every assertion instruction names an `ERR_*` constant via `.err=` — no bare asserts, no inline
/// string errors (masm-error-constants; protocol `fungible.masm:198-199`).
#[test]
fn assertions_name_error_constants() {
    const ASSERT_OPS: [&str; 7] = [
        "assert",
        "assertz",
        "assert_eq",
        "assert_eqw",
        "u32assert",
        "u32assert2",
        "u32assertw",
    ];
    assert_rule("named assertion errors", |rel, src, out| {
        for (n, line) in src.lines().enumerate() {
            for token in code_part(line).split_whitespace() {
                let (op, suffix) = match token.split_once('.') {
                    Some((op, suffix)) => (op, Some(suffix)),
                    None => (token, None),
                };
                if !ASSERT_OPS.contains(&op) {
                    continue;
                }
                match suffix {
                    Some(s) if s.starts_with("err=ERR_") => {}
                    Some(s) if s.starts_with("err=\"") => out.push(format!(
                        "{rel}:{}: `{op}` carries an inline string error (declare an ERR_ constant)",
                        n + 1
                    )),
                    _ => out.push(format!(
                        "{rel}:{}: `{op}` without `.err=ERR_…`",
                        n + 1
                    )),
                }
            }
        }
    });
}

// INLINE STACK TRACKERS
// ================================================================================================

/// A standalone `# => […]` tracker is followed by a blank line unless the next line is `end`, a
/// control-flow keyword, another tracker, or a continuation comment (masm-inline-comments rule 3).
#[test]
fn stack_trackers_are_followed_by_a_blank_line() {
    assert_rule("tracker blank-line rule", |rel, src, out| {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("# =>") {
                continue;
            }
            let Some(next) = lines.get(i + 1) else {
                continue;
            };
            let next = next.trim_start();
            let allowed = next.is_empty()
                || next.starts_with('#')
                || next == "end"
                || next.starts_with("else");
            if !allowed {
                out.push(format!(
                    "{rel}:{}: `# =>` tracker not followed by a blank line (next: `{next}`)",
                    i + 1
                ));
            }
        }
    });
}

// FILE HYGIENE & HEADERS
// ================================================================================================

/// No trailing whitespace, no tabs, exactly one trailing newline.
#[test]
fn files_are_whitespace_clean() {
    assert_rule("whitespace hygiene", |rel, src, out| {
        for (n, line) in src.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                out.push(format!("{rel}:{}: trailing whitespace", n + 1));
            }
            if line.contains('\t') {
                out.push(format!("{rel}:{}: tab character", n + 1));
            }
        }
        if !src.ends_with('\n') || src.ends_with("\n\n") {
            out.push(format!("{rel}:1: file must end with exactly one newline"));
        }
    });
}

// DOC-BLOCK SEMANTICS (protocol `notes/p2id.masm` / `notes/mint.masm` shapes)
// ================================================================================================

/// Alias -> full module path for every module import of `src` (all import families; `->` aliases
/// honored; constant imports — SCREAMING last segment — skipped).
fn import_aliases(src: &str) -> std::collections::BTreeMap<String, String> {
    let mut aliases = std::collections::BTreeMap::new();
    for line in src.lines() {
        let Some(path) = line.strip_prefix("use ") else {
            continue;
        };
        // v0.25 item-import form (`use {A, B} from module`): the braced items are constants /
        // procedures referenced bare, not module aliases — skip (incl. multi-line openers).
        if path.trim_start().starts_with('{') {
            continue;
        }
        // v0.25 module-alias form: `use module as alias` (the v0.15 `->` arrow is gone).
        let (path, alias) = match path.split_once(" as ") {
            Some((p, a)) => (p.trim(), Some(a.trim().to_string())),
            None => (path.trim(), None),
        };
        let last = path.rsplit("::").next().unwrap_or(path);
        let is_const_import = last.chars().all(|c| c.is_ascii_uppercase() || c == '_');
        if !is_const_import {
            aliases.insert(alias.unwrap_or_else(|| last.to_string()), path.to_string());
        }
    }
    aliases
}

/// Every note script declares the account procedures it calls, in the protocol form
/// (`Requires that the account exposes:` + `- <path> procedure.` bullets, `notes/burn.masm:12`),
/// and the declared FULL paths match the body's `call.` targets resolved through the note's own
/// imports — a bullet naming the right procedure under the wrong module fails.
fn check_note_requires(rel: &str, src: &str, out: &mut Violations) {
    if !is_note_script(rel) {
        return;
    }
    let aliases = import_aliases(src);
    for proc in proc_docs(src) {
        if !proc.is_note_entry {
            continue;
        }
        if !proc
            .doc_text()
            .contains("Requires that the account exposes:")
        {
            out.push(format!(
                "{rel}:{}: note entry doc missing `Requires that the account exposes:`",
                proc.proc_line
            ));
            continue;
        }
        // the FULL paths the body actually `call`s, resolved through this note's imports.
        let mut called: Vec<String> = Vec::new();
        for token in proc
            .body
            .iter()
            .flat_map(|l| code_part(l).split_whitespace())
        {
            let Some(target) = token.strip_prefix("call.") else {
                continue;
            };
            match target.split_once("::") {
                Some((alias, rest)) => match aliases.get(alias) {
                    Some(module) => called.push(format!("{module}::{rest}")),
                    None => out.push(format!(
                        "{rel}:{}: `call.{target}` does not resolve through this note's \
                         imports, so its `Requires` entry cannot be verified",
                        proc.proc_line
                    )),
                },
                None => out.push(format!(
                    "{rel}:{}: `call.{target}` is not a module-qualified account procedure",
                    proc.proc_line
                )),
            }
        }
        let required: Vec<String> = proc
            .doc
            .iter()
            .filter_map(|(_, l)| l.strip_prefix("#! - "))
            .filter_map(|b| b.strip_suffix(" procedure."))
            .filter(|p| p.contains("::"))
            .map(str::to_string)
            .collect();
        for path in &called {
            if !required.contains(path) {
                out.push(format!(
                    "{rel}:{}: called procedure `{path}` not listed by its full path under \
                     `Requires that the account exposes:`",
                    proc.proc_line
                ));
            }
        }
        for path in &required {
            if !called.contains(path) {
                out.push(format!(
                    "{rel}:{}: `Requires` lists `{path}` but the note body never calls it",
                    proc.proc_line
                ));
            }
        }
    }
}

#[test]
fn note_docs_declare_required_account_procedures() {
    assert_rule("note Requires-section", check_note_requires);
}

/// The registered storage posture of every shipped note (the ratified per-note layouts):
/// `"read"` notes stage their own storage (`exec.active_note::get_storage`), `"transport"` notes
/// carry storage consumed account-side by a shim (no direct read), `"none"` notes are
/// storage-less. The storage-documentation rule keys off this registration, so removing a
/// storage-carrying note's section fails even when the note never reads storage itself; a new
/// note fails until it gets a row (the registration pattern).
const NOTE_STORAGE_TABLE: [(&str, &str); 12] = [
    ("xreserve_accept_ownership_note.masm", "none"),
    ("xreserve_block_account_note.masm", "read"),
    ("xreserve_grant_role_note.masm", "read"),
    ("xreserve_identifier_init_note.masm", "read"),
    ("xreserve_pause_note.masm", "none"),
    ("xreserve_revoke_role_note.masm", "read"),
    ("xreserve_set_attester_note.masm", "read"),
    ("xreserve_set_max_supply_note.masm", "read"),
    ("xreserve_set_min_burn_size_note.masm", "read"),
    ("xreserve_transfer_ownership_note.masm", "read"),
    ("xreserve_unblock_account_note.masm", "read"),
    ("xreserve_unpause_note.masm", "none"),
];

/// A note script's storage posture matches its registration: storage-carrying notes (`read` or
/// `transport`) document the layout in the protocol form (`Note storage is assumed to be as
/// follows:`, `notes/p2id.masm:34`); storage-less notes carry neither the section nor a storage
/// read; the body's `get_storage` usage must agree with the registered mode.
fn check_note_storage(rel: &str, src: &str, out: &mut Violations) {
    if !is_note_script(rel) {
        return;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let Some(&(_, mode)) = NOTE_STORAGE_TABLE.iter().find(|(n, _)| *n == name) else {
        out.push(format!(
            "{rel}:1: note is not registered in NOTE_STORAGE_TABLE — declare whether it \
             carries storage (read / transport / none)"
        ));
        return;
    };
    let reads_storage = src
        .lines()
        .any(|l| code_part(l).contains("exec.active_note::get_storage"));
    let has_section = src.contains("Note storage is assumed to be as follows:");
    match mode {
        "read" | "transport" => {
            if !has_section {
                out.push(format!(
                    "{rel}:1: storage-carrying note without a `Note storage is assumed to be \
                     as follows:` section"
                ));
            }
            if (mode == "read") != reads_storage {
                out.push(format!(
                    "{rel}:1: registered storage mode `{mode}` disagrees with the body's \
                     `get_storage` usage"
                ));
            }
        }
        _ => {
            if has_section {
                out.push(format!(
                    "{rel}:1: note documents storage but is registered storage-less"
                ));
            }
            if reads_storage {
                out.push(format!(
                    "{rel}:1: note reads storage but is registered storage-less"
                ));
            }
        }
    }
}

#[test]
fn note_docs_describe_carried_storage() {
    assert_rule("note storage-section", check_note_storage);
}

/// Doc-block sections appear at most once each and in the protocol order — description prose
/// first (capitalized, first paragraph ends a sentence), then Requires / Inputs / Outputs /
/// {Note storage, Where} / Panics if / Invocation, with Invocation as the block's last line.
fn check_doc_sections(rel: &str, src: &str, out: &mut Violations) {
    const RANKED: [(&str, u8); 7] = [
        ("Requires that the account exposes:", 0),
        ("Inputs:", 1),
        ("Outputs:", 2),
        ("Note storage is assumed to be as follows:", 3),
        ("Where:", 3),
        ("Panics if:", 4),
        ("Invocation:", 5),
    ];
    {
        for proc in proc_docs(src) {
            if proc.doc.is_empty() {
                continue;
            }
            let marker_of = |line: &str| -> Option<(&'static str, u8)> {
                let text = line.strip_prefix("#! ")?;
                RANKED
                    .iter()
                    .find(|(m, _)| text.starts_with(m))
                    .map(|&(m, r)| (m, r))
            };
            // description-first: prose line, capitalized, and the first paragraph ends a sentence.
            let (first_no, first) = &proc.doc[0];
            let first_text = first.strip_prefix("#! ").unwrap_or_default();
            if marker_of(first).is_some()
                || !first_text
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
            {
                out.push(format!(
                    "{rel}:{first_no}: doc block must open with a capitalized description \
                     sentence, not a section marker"
                ));
            }
            // the description opens with a capitalized present-tense verb (Returns, Computes,
            // Asserts, …). Mechanical proxy: `[A-Z][a-z]+` ending in
            // `s`, e.g. "Consumes" passes while the imperative "Consume" or a noun lead fails;
            // common non-verb sentence leads that also end in `s` are stop-listed.
            const NON_VERB_LEADS: [&str; 5] = ["This", "Thus", "Its", "These", "Whereas"];
            let first_word: &str = first_text.split_whitespace().next().unwrap_or_default();
            let is_present_tense_verb = first_word.len() >= 3
                && first_word
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
                && first_word.chars().skip(1).all(|c| c.is_ascii_lowercase())
                && first_word.ends_with('s')
                && !NON_VERB_LEADS.contains(&first_word);
            if !is_present_tense_verb {
                out.push(format!(
                    "{rel}:{first_no}: description must open with a capitalized present-tense \
                     verb (found `{first_word}`)"
                ));
            }
            let description: Vec<&str> = proc
                .doc
                .iter()
                .take_while(|(_, l)| *l != "#!" && marker_of(l).is_none())
                .map(|(_, l)| l.as_str())
                .collect();
            let para_ends_sentence = description
                .last()
                .and_then(|l| l.strip_prefix("#! "))
                .is_some_and(|t| t.trim_end().ends_with('.'));
            if !para_ends_sentence {
                out.push(format!(
                    "{rel}:{first_no}: the doc description paragraph does not end a sentence \
                     with a period"
                ));
            }
            let mut last_rank = 0u8;
            let mut seen: Vec<&str> = Vec::new();
            for (no, line) in &proc.doc {
                let Some((marker, rank)) = marker_of(line) else {
                    continue;
                };
                if seen.contains(&marker) {
                    out.push(format!("{rel}:{no}: duplicate doc section `{marker}`"));
                }
                seen.push(marker);
                if rank < last_rank {
                    out.push(format!(
                        "{rel}:{no}: doc section `{marker}` out of protocol order"
                    ));
                }
                last_rank = rank;
                if marker == "Invocation:" && proc.doc.last().map(|(n, _)| *n) != Some(*no) {
                    out.push(format!(
                        "{rel}:{no}: `Invocation:` must be the doc block's last line"
                    ));
                }
            }
        }
    }
}

#[test]
fn doc_sections_follow_canonical_order() {
    assert_rule("doc-section order", check_doc_sections);
}

/// `Invocation: call` / `dyncall` procedures document exactly 16 stack elements on both sides of
/// the boundary — `pad(N)` spans count N, Words count 4, felts count 1 (masm-padding; protocol
/// `fungible.masm:217-247`).
fn check_call_boundary_docs(rel: &str, src: &str, out: &mut Violations) {
    for proc in proc_docs(src) {
        if !matches!(proc.invocation(), Some("call") | Some("dyncall")) {
            continue;
        }
        for marker in ["Inputs:", "Outputs:"] {
            let Some((no, line)) = proc
                .doc
                .iter()
                .find(|(_, l)| l.strip_prefix("#! ").is_some_and(|t| t.starts_with(marker)))
            else {
                out.push(format!(
                    "{rel}:{}: call-boundary proc `{}` has no `#! {marker}` line to check \
                     against the 16-element contract",
                    proc.proc_line, proc.name
                ));
                continue;
            };
            let Some(list) = bracket_list(line) else {
                out.push(format!(
                    "{rel}:{no}: `{marker}` of call-boundary proc `{}` carries no parseable \
                     `[…]` stack list (the 16-element contract must be explicit)",
                    proc.name
                ));
                continue;
            };
            let mut total = 0usize;
            let mut malformed = false;
            for item in split_stack_items(list) {
                match stack_item_elements(&item) {
                    Ok(n) => total += n,
                    Err(reason) => {
                        malformed = true;
                        out.push(format!(
                            "{rel}:{no}: `{marker}` of call-boundary proc `{}` has a \
                             non-countable stack item ({reason}) — a call/dyncall boundary \
                             documents exactly 16 elements",
                            proc.name
                        ));
                    }
                }
            }
            if !malformed && total != 16 {
                out.push(format!(
                    "{rel}:{no}: `{marker}` of call-boundary proc `{}` documents {total} \
                     stack elements (a call/dyncall boundary is exactly 16)",
                    proc.name
                ));
            }
        }
    }
}

#[test]
fn call_boundary_docs_span_sixteen_elements() {
    assert_rule("call-boundary 16-element docs", check_call_boundary_docs);
}

/// Every `exec.` / `call.` site targeting an `xreserve` procedure matches the target's documented
/// `Invocation:` kind — the doc contract reflects how the procedure is actually invoked.
#[test]
fn invocation_docs_match_invocation_sites() {
    let mut proc_invocations: std::collections::BTreeMap<(String, String), String> =
        std::collections::BTreeMap::new();
    for (rel, src) in masm_sources() {
        if !is_impl_module(&rel) {
            continue;
        }
        let module = rel
            .trim_start_matches("asm/standards/")
            .trim_end_matches(".masm")
            .trim_end_matches("/mod")
            .replace('/', "::");
        for proc in proc_docs(&src) {
            if let Some(kind) = proc.invocation() {
                proc_invocations.insert((module.clone(), proc.name.clone()), kind.to_string());
            }
        }
    }
    assert_rule("invocation-doc vs call-site", |rel, src, out| {
        // alias -> full xreserve module path, from this file's imports.
        let mut aliases: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for line in src.lines() {
            let Some(path) = line.strip_prefix("use ") else {
                continue;
            };
            let (path, alias) = match path.split_once("->") {
                Some((p, a)) => (p.trim(), Some(a.trim().to_string())),
                None => (path.trim(), None),
            };
            let last = path.rsplit("::").next().unwrap_or(path);
            let is_const_import = last.chars().all(|c| c.is_ascii_uppercase() || c == '_');
            if path.starts_with("xreserve::") && !is_const_import {
                aliases.insert(alias.unwrap_or_else(|| last.to_string()), path.to_string());
            }
        }
        let own_module = is_impl_module(rel).then(|| {
            rel.trim_start_matches("asm/standards/")
                .trim_end_matches(".masm")
                .trim_end_matches("/mod")
                .replace('/', "::")
        });
        for (n, line) in src.lines().enumerate() {
            for token in code_part(line).split_whitespace() {
                let (site_kind, target) = match token
                    .strip_prefix("exec.")
                    .map(|t| ("exec", t))
                    .or_else(|| token.strip_prefix("call.").map(|t| ("call", t)))
                {
                    Some(x) => x,
                    None => continue,
                };
                let (module, proc_name) = match target.rsplit_once("::") {
                    Some((qualifier, p)) => {
                        let alias = qualifier.split("::").next().unwrap_or(qualifier);
                        match aliases.get(alias) {
                            Some(m) => (m.clone(), p.to_string()),
                            None => continue, // non-xreserve target (kernel / core / standards)
                        }
                    }
                    None => match &own_module {
                        Some(m) => (m.clone(), target.to_string()),
                        None => continue,
                    },
                };
                let Some(doc_kind) = proc_invocations.get(&(module.clone(), proc_name.clone()))
                else {
                    continue;
                };
                if doc_kind != site_kind {
                    out.push(format!(
                        "{rel}:{}: `{site_kind}.{target}` but `{module}::{proc_name}` is \
                         documented `Invocation: {doc_kind}`",
                        n + 1
                    ));
                }
            }
        }
    });
}

/// `@account_procedure` and `#! Invocation: exec` are mutually exclusive. The attribute publishes
/// a procedure on the composed account's callable interface, and an interface procedure is always
/// entered across the account boundary — by `call`, or by the stock policy manager's `dynexec`
/// dispatch on a pinned root. A helper documented `Invocation: exec` is inlined into its caller's
/// context instead, so carrying the attribute only widens the callable surface without adding any
/// reachable entry point.
///
/// The second half of the check keeps the first half honest: the attribute is read off the
/// declaration's contiguous attribute run, so an `@account_procedure` line that never reaches a
/// declaration would make the pairing check silently vacuous on it.
fn check_exec_helpers_are_off_the_account_interface(rel: &str, src: &str, out: &mut Violations) {
    let procs = proc_docs(src);
    for proc in &procs {
        if proc.is_account_procedure && proc.invocation() == Some("exec") {
            out.push(format!(
                "{rel}:{}: `{}` carries `@account_procedure` and documents `Invocation: exec` — \
                 an account-interface procedure is entered by `call` or by `dynexec` dispatch, so \
                 an exec-only helper must not be published on the interface",
                proc.proc_line, proc.name
            ));
        }
    }
    let declared = src
        .lines()
        .filter(|l| l.trim() == "@account_procedure")
        .count();
    let attached = procs.iter().filter(|p| p.is_account_procedure).count();
    if declared != attached {
        out.push(format!(
            "{rel}: the file carries {declared} `@account_procedure` line(s) but only {attached} \
             attach to a procedure declaration — a detached attribute is invisible to the \
             interface check"
        ));
    }
}

#[test]
fn account_interface_procedures_are_never_exec_only() {
    assert_rule(
        "no @account_procedure on an exec-only procedure",
        check_exec_helpers_are_off_the_account_interface,
    );
}

/// A procedure whose body asserts directly must document its `Panics if:` conditions
/// (masm-doc-comments: list direct conditions from `assert*`).
fn check_direct_asserts_documented(rel: &str, src: &str, out: &mut Violations) {
    const ASSERT_OPS: [&str; 7] = [
        "assert",
        "assertz",
        "assert_eq",
        "assert_eqw",
        "u32assert",
        "u32assert2",
        "u32assertw",
    ];
    for proc in proc_docs(src) {
        let asserts_directly = proc.body.iter().any(|l| {
            code_part(l)
                .split_whitespace()
                .any(|t| ASSERT_OPS.contains(&t.split('.').next().unwrap_or(t)))
        });
        if !asserts_directly {
            continue;
        }
        // the section must exist AND carry at least one `- <condition>` bullet — a bare
        // `Panics if:` line documents nothing.
        let panics_at = proc
            .doc
            .iter()
            .position(|(_, l)| l.starts_with("#! Panics if:"));
        let Some(panics_at) = panics_at else {
            out.push(format!(
                "{rel}:{}: `{}` asserts directly but its doc has no `Panics if:` section",
                proc.proc_line, proc.name
            ));
            continue;
        };
        let has_condition_bullet = proc.doc[panics_at + 1..]
            .iter()
            .take_while(|(_, l)| l.starts_with("#! - ") || l.starts_with("#!   "))
            .any(|(_, l)| l.starts_with("#! - "));
        if !has_condition_bullet {
            out.push(format!(
                "{rel}:{}: `{}` has a `Panics if:` section without any condition bullets",
                proc.proc_line, proc.name
            ));
        }
    }
}

#[test]
fn direct_assertions_are_documented_in_panics() {
    assert_rule(
        "direct asserts imply Panics-if doc",
        check_direct_asserts_documented,
    );
}

/// Bullets under `Requires` / `Note storage` / `Where:` / `Panics if:` are `- ` items ending with
/// a period (masm-doc-comments: definitions end with a period; `Requires` bullets name the
/// procedure in the protocol `- <path> procedure.` form).
fn check_doc_bullets(rel: &str, src: &str, out: &mut Violations) {
    const BULLET_SECTIONS: [&str; 4] = [
        "Requires that the account exposes:",
        "Note storage is assumed to be as follows:",
        "Where:",
        "Panics if:",
    ];
    {
        for proc in proc_docs(src) {
            // pass 1: collect (section, start line, accumulated text) per bullet.
            let mut bullets: Vec<(&str, usize, String)> = Vec::new();
            let mut sections_seen: Vec<(&str, usize)> = Vec::new();
            let mut in_section: Option<&str> = None;
            for (no, line) in &proc.doc {
                let text = line.strip_prefix("#!").unwrap_or_default();
                if let Some(section) = BULLET_SECTIONS.iter().find(|s| text.trim() == **s) {
                    sections_seen.push((section, *no));
                    in_section = Some(section);
                    continue;
                }
                let Some(section) = in_section else { continue };
                if let Some(item) = text.strip_prefix(" - ") {
                    bullets.push((section, *no, item.to_string()));
                } else if text.starts_with("   ") && !bullets.is_empty() {
                    let (_, _, b) = bullets.last_mut().unwrap();
                    b.push(' ');
                    b.push_str(text.trim());
                } else if text.trim().is_empty() {
                    in_section = None;
                }
            }
            // pass 2: validate — every declared section carries at least one bullet, and every
            // bullet is a terminated sentence.
            for (section, no) in &sections_seen {
                if !bullets.iter().any(|(s, _, _)| s == section) {
                    out.push(format!(
                        "{rel}:{no}: `{section}` section declared without any `- ` bullets"
                    ));
                }
            }
            for (section, no, text) in bullets {
                if !text.trim_end().ends_with('.') {
                    out.push(format!(
                        "{rel}:{no}: bullet under `{section}` does not end with a period"
                    ));
                }
                if section == "Requires that the account exposes:"
                    && !(text.contains("::") && text.trim_end().ends_with(" procedure."))
                {
                    out.push(format!(
                        "{rel}:{no}: `Requires` bullet must name the full `<path> procedure.` \
                         (protocol notes form)"
                    ));
                }
            }
        }
    }
}

#[test]
fn doc_bullets_are_terminated_sentences() {
    assert_rule("doc bullets are sentences", check_doc_bullets);
}

/// Inline `# =>` trackers are well-formed: balanced brackets, a stack list present, lowercase
/// `pad(`, and any name shared with the proc's documented stack lists keeps the doc's exact
/// capitalization (masm-inline-comments rule 4).
#[test]
fn stack_trackers_are_well_formed() {
    assert_rule("tracker form", |rel, src, out| {
        for proc in proc_docs(src) {
            let doc_idents: Vec<String> = proc
                .doc
                .iter()
                .filter(|(_, l)| {
                    ["Inputs:", "Outputs:", "Operand stack:", "Advice stack:"]
                        .iter()
                        .any(|m| l.contains(m))
                })
                .flat_map(|(_, l)| bracket_idents(l))
                .collect();
            for (off, line) in proc.body.iter().enumerate() {
                let trimmed = line.trim_start();
                let Some(tracker) = trimmed.strip_prefix("# =>") else {
                    continue;
                };
                let line_no = proc.proc_line + 1 + off;
                let mut depth = 0i64;
                for c in tracker.chars() {
                    match c {
                        '[' | '(' => depth += 1,
                        ']' | ')' => depth -= 1,
                        _ => {}
                    }
                }
                if depth != 0 || !tracker.contains('[') {
                    out.push(format!(
                        "{rel}:{line_no}: malformed `# =>` tracker (unbalanced or missing \
                         stack list)"
                    ));
                    continue;
                }
                if tracker.contains("PAD(") || tracker.contains("Pad(") {
                    out.push(format!("{rel}:{line_no}: `pad(N)` spans stay lowercase"));
                }
                for ident in bracket_idents(tracker) {
                    if let Some(doc_ident) = doc_idents
                        .iter()
                        .find(|d| d.eq_ignore_ascii_case(&ident) && **d != ident)
                    {
                        out.push(format!(
                            "{rel}:{line_no}: tracker name `{ident}` differs in case from the \
                             doc block's `{doc_ident}`"
                        ));
                    }
                }
            }
        }
    });
}

/// A `Where:` section, when present, defines the documented stack items: every bullet is an
/// `is`/`are` definition, and every identifier named in the `Inputs:`/`Outputs:` marker-line
/// stack lists is defined in the section (brace shorthand `name_{a,b}` expands)
/// (masm-doc-comments).
fn check_where_definitions(rel: &str, src: &str, out: &mut Violations) {
    for proc in proc_docs(src) {
        let Some(where_at) = proc.doc.iter().position(|(_, l)| l == "#! Where:") else {
            continue;
        };
        // collect the section: bullets (with their continuations) up to the blank `#!` line.
        let mut where_text = String::new();
        let mut bullets: Vec<(usize, String)> = Vec::new();
        for (no, line) in &proc.doc[where_at + 1..] {
            let text = line.strip_prefix("#!").unwrap_or_default();
            if text.trim().is_empty() {
                break;
            }
            where_text.push_str(text);
            where_text.push(' ');
            if let Some(item) = text.strip_prefix(" - ") {
                bullets.push((*no, item.to_string()));
            } else if let Some((_, b)) = bullets.last_mut() {
                b.push(' ');
                b.push_str(text.trim());
            }
        }
        for (no, bullet) in &bullets {
            if !(bullet.contains(" is ") || bullet.contains(" are ")) {
                out.push(format!(
                    "{rel}:{no}: `Where:` bullet is not an is/are definition"
                ));
            }
        }
        // expand `name_{a,b}` brace shorthand so grouped definitions cover their items.
        let mut expanded = where_text.clone();
        let mut rest = where_text.as_str();
        while let Some(open) = rest.find("_{") {
            let prefix_start = rest[..open]
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map_or(0, |p| p + 1);
            let prefix = &rest[prefix_start..open];
            if let Some(close) = rest[open..].find('}') {
                for part in rest[open + 2..open + close].split(',') {
                    expanded.push_str(&format!(" {prefix}_{} ", part.trim()));
                }
                rest = &rest[open + close..];
            } else {
                break;
            }
        }
        // every identifier documented on the Inputs:/Outputs: marker lines must be defined —
        // matched as a whole token, so `other_value` does not cover `value`.
        let defined: std::collections::BTreeSet<&str> = expanded
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
            .collect();
        for marker in ["#! Inputs:", "#! Outputs:"] {
            for (no, line) in &proc.doc {
                if !line.starts_with(marker) {
                    continue;
                }
                for ident in bracket_idents(line) {
                    if ident != "ARGS" && !defined.contains(ident.as_str()) {
                        out.push(format!(
                            "{rel}:{no}: stack item `{ident}` is not defined in the `Where:` \
                             section"
                        ));
                    }
                }
            }
        }
    }
}

#[test]
fn where_sections_define_the_documented_stack_items() {
    assert_rule("Where-definition semantics", check_where_definitions);
}

/// Ordinary in-procedure `#` comments begin with a lowercase letter (or a non-letter such as a
/// digit, bracket, or dash) — never an uppercase letter (masm-inline-comments rule 1).
fn check_inline_comment_case(rel: &str, src: &str, out: &mut Violations) {
    for proc in proc_docs(src) {
        for (off, line) in proc.body.iter().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with('#') || trimmed.starts_with("#!") || trimmed.starts_with("# =>")
            {
                continue;
            }
            let text = trimmed.trim_start_matches('#').trim_start();
            if text.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                out.push(format!(
                    "{rel}:{}: in-procedure comment begins with an uppercase letter (inline \
                     comments start lowercase): `{}`",
                    proc.proc_line + 1 + off,
                    text.chars().take(48).collect::<String>()
                ));
            }
        }
    }
}

#[test]
fn inline_comments_start_lowercase() {
    assert_rule("inline-comment case", check_inline_comment_case);
}

/// A stack-item NAME is UPPER_SNAKE (a Word) or lower_snake (a felt) — never mixed case, never
/// punctuated (the repo's stack-item naming convention).
fn valid_stack_name(name: &str) -> bool {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let has_upper = name.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = name.chars().any(|c| c.is_ascii_lowercase());
    !(has_upper && has_lower)
}

/// One atomic stack item: `...`, a numeric literal, or a valid name optionally carrying a
/// `(…)` span, `[…]` array span, or `_{a,b}` multi-felt brace group at its end. A trailing
/// prime (`acc'`) and unspaced numeric arithmetic (`addr+1`, `result*10`) are the attested
/// evolving-value tracker notations; an alphabetic right-hand side (`fee-amount`) is not.
fn valid_stack_atom(atom: &str) -> bool {
    let atom = atom.strip_suffix('\'').unwrap_or(atom);
    if atom == "..." || (!atom.is_empty() && atom.chars().all(|c| c.is_ascii_digit())) {
        return true;
    }
    if let Some(brace) = atom.find("_{") {
        return atom.ends_with('}')
            && valid_stack_name(&atom[..brace])
            && brace + 2 < atom.len() - 1;
    }
    if let Some(open) = atom.find(['(', '[']) {
        let closer = if atom.as_bytes()[open] == b'(' {
            ')'
        } else {
            ']'
        };
        return atom.ends_with(closer)
            && valid_stack_name(&atom[..open])
            && open + 1 < atom.len() - 1;
    }
    if let Some(op) = atom.find(['+', '-', '*', '/']) {
        let (lhs, rhs) = (&atom[..op], &atom[op + 1..]);
        return !rhs.is_empty() && rhs.chars().all(|c| c.is_ascii_digit()) && valid_stack_name(lhs);
    }
    valid_stack_name(atom)
}

/// Stack items in doc stack lists and `# =>` trackers follow the three-tier grammar: each item is
/// an UPPER_SNAKE Word or lower_snake felt (optionally spanned `name(N)` / `NAME[N]` or brace
/// grouped), a numeric literal, `...`, or a spaced expression of such atoms — punctuated or
/// mixed-case items are invalid (masm-formatting FMT capitalization).
fn check_stack_item_naming(rel: &str, src: &str, out: &mut Violations) {
    let flag_items = |no: usize, context: &str, line: &str, out: &mut Violations| {
        let Some(list) = bracket_list(line) else {
            return;
        };
        for item in split_stack_items(list) {
            // spaced binary expressions (`amount - fee_amount`) must strictly alternate
            // operand / operator; anything else (including spans whose parentheses contain
            // spaces) is one atom.
            let has_spaced_op = [" - ", " + ", " * ", " / "]
                .iter()
                .any(|op| item.contains(op));
            let ok = if has_spaced_op {
                let tokens: Vec<&str> = item.split(' ').filter(|t| !t.is_empty()).collect();
                tokens.len() % 2 == 1
                    && tokens.iter().enumerate().all(|(i, t)| {
                        if i % 2 == 1 {
                            matches!(*t, "-" | "+" | "*" | "/")
                        } else {
                            valid_stack_atom(t)
                        }
                    })
            } else {
                valid_stack_atom(&item)
            };
            if !ok {
                out.push(format!(
                    "{rel}:{no}: invalid stack item `{item}` in {context} (Words are \
                     UPPER_SNAKE, felts are lower_snake; spans are `name(N)`)"
                ));
            }
        }
    };
    for proc in proc_docs(src) {
        for (no, line) in &proc.doc {
            let is_stack_line = line.starts_with("#! Inputs:")
                || line.starts_with("#! Outputs:")
                || line.contains("Operand stack:")
                || line.contains("Advice stack:");
            if is_stack_line {
                flag_items(*no, "a doc stack list", line, out);
            }
        }
        for (off, line) in proc.body.iter().enumerate() {
            let trimmed = line.trim_start();
            if let Some(tracker) = trimmed.strip_prefix("# =>") {
                flag_items(proc.proc_line + 1 + off, "a `# =>` tracker", tracker, out);
            }
        }
    }
}

#[test]
fn stack_item_names_follow_the_capitalization_grammar() {
    assert_rule("stack-item naming grammar", check_stack_item_naming);
}

// FILE HYGIENE & HEADERS (continued)
// ================================================================================================

/// Implementation modules open with the fully-qualified namespace header line
/// (`# xreserve::<module>`, protocol `fungible.masm:1`); note scripts open with their prose
/// `#` header naming the script (the repo's adjudicated note-header form).
#[test]
fn files_open_with_their_canonical_header() {
    assert_rule("file headers", |rel, src, out| {
        let first = src.lines().next().unwrap_or_default();
        if is_impl_module(rel) {
            let module = rel
                .trim_start_matches("asm/standards/")
                .trim_end_matches(".masm")
                .trim_end_matches("/mod")
                .replace('/', "::");
            let expected = format!("# {module}");
            if first != expected {
                out.push(format!(
                    "{rel}:1: header line must be `{expected}` (found `{first}`)"
                ));
            }
        } else if is_note_script(rel) {
            let stem = rel
                .trim_start_matches("asm/standards/notes/")
                .trim_end_matches(".masm");
            if !first.starts_with(&format!("# {stem}")) {
                out.push(format!("{rel}:1: note header must open with `# {stem}`"));
            }
        }
    });
}

// CHECKER SELF-TESTS — the rules themselves must flag the known evasion shapes
// ================================================================================================
// Each negative case feeds a synthetic source that LOOKS conformant to a naive presence check but
// violates the governing requirement; the rule must report it. Positive controls guard against
// over-tightening. This is the same adversarial method an auditor applies (planted
// mutations), made a permanent part of the suite.

/// Runs one checker over a synthetic source and returns its violations.
fn run_check(check: fn(&str, &str, &mut Violations), rel: &str, src: &str) -> Violations {
    let mut out = Violations::new();
    check(rel, src, &mut out);
    out
}

const SYNTH_NOTE_REL: &str = "asm/standards/notes/xreserve_set_attester_note.masm";

/// A minimal conformant admin-note source (calls through an import, full-path Requires bullet).
fn synth_note(requires_bullet: &str, call_line: &str) -> String {
    format!(
        "# xreserve_set_attester_note — synthetic fixture.\n\n\
         use xreserve::attester_admin\n\n\
         #! Consumes the synthetic admin note.\n\
         #!\n\
         #! Requires that the account exposes:\n\
         #! - {requires_bullet} procedure.\n\
         #!\n\
         #! Inputs:  [ARGS, pad(12)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Panics if:\n\
         #! - the gate rejects the sender.\n\
         #!\n\
         #! Invocation: dyncall\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20dropw\n\
         \x20\x20\x20\x20{call_line}\n\
         \x20\x20\x20\x20exec.sys::truncate_stack\nend\n"
    )
}

#[test]
fn checker_accepts_full_path_requires_bullet() {
    let src = synth_note(
        "xreserve::attester_admin::set_attester",
        "call.attester_admin::set_attester",
    );
    assert_eq!(
        run_check(check_note_requires, SYNTH_NOTE_REL, &src),
        Vec::<String>::new(),
        "a correct full-path Requires bullet must pass"
    );
}

#[test]
fn checker_flags_wrong_module_in_requires_bullet() {
    // same terminal procedure name, wrong module — the exact-path requirement must fail this.
    let src = synth_note(
        "xreserve::wrong_module::set_attester",
        "call.attester_admin::set_attester",
    );
    assert!(
        !run_check(check_note_requires, SYNTH_NOTE_REL, &src).is_empty(),
        "a Requires bullet naming the wrong module must be flagged"
    );
}

#[test]
fn checker_flags_unresolvable_call_target_in_note() {
    // `call` through an alias the note never imports — the requirement cannot be verified.
    let src = synth_note(
        "xreserve::attester_admin::set_attester",
        "call.mystery::set_attester",
    );
    assert!(
        !run_check(check_note_requires, SYNTH_NOTE_REL, &src).is_empty(),
        "a call target that does not resolve through the note's imports must be flagged"
    );
}

#[test]
fn checker_flags_missing_storage_section_on_transport_note() {
    // the mint note carries storage consumed account-side (no direct get_storage read);
    // deleting its storage section must still be detected.
    let src = synth_note(
        "xreserve::xreserve_mint_note_entry::receive_and_mint",
        "call.note_entry::receive_and_mint",
    )
    .replace(
        "use xreserve::attester_admin",
        "use xreserve::xreserve_mint_note_entry as note_entry",
    )
    .replace("# xreserve_pause_note", "# xreserve_mint_note");
    let rel = "asm/standards/notes/xreserve_mint_note.masm";
    assert!(
        !run_check(check_note_storage, rel, &src).is_empty(),
        "a storage-carrying (transport) note without the storage section must be flagged"
    );
}

#[test]
fn checker_flags_storage_section_on_storage_less_note() {
    let src = synth_note("xreserve::attester_admin::set_attester", "call.attester_admin::set_attester").replace(
        "#! Panics if:",
        "#! Note storage is assumed to be as follows:\n#! - phantom is not real (item 0).\n#!\n#! Panics if:",
    );
    assert!(
        !run_check(check_note_storage, SYNTH_NOTE_REL, &src).is_empty(),
        "a storage section on a registered storage-less note must be flagged"
    );
}

#[test]
fn checker_flags_unregistered_note_storage_posture() {
    let src = synth_note(
        "xreserve::attester_admin::set_attester",
        "call.attester_admin::set_attester",
    );
    assert!(
        !run_check(
            check_note_storage,
            "asm/standards/notes/xreserve_brand_new_note.masm",
            &src
        )
        .is_empty(),
        "a note absent from the storage registration table must be flagged"
    );
}

#[test]
fn checker_flags_panics_section_without_condition_bullets() {
    let src = "#! Asserts the synthetic condition.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: []\n\
               #!\n\
               #! Panics if:\n\
               #!\n\
               #! Invocation: exec\n\
               proc check_something\n\
               \x20\x20\x20\x20assert.err=ERR_SYNTHETIC\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_direct_asserts_documented, rel, src).is_empty(),
        "a bare `Panics if:` with no condition bullets must be flagged"
    );
}

#[test]
fn checker_flags_open_ended_call_boundary_list() {
    let src = "#! Does the synthetic call.\n\
               #!\n\
               #! Inputs:  [VALUE, ...]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_entry\n\
               \x20\x20\x20\x20dropw\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_call_boundary_docs, rel, src).is_empty(),
        "an open-ended `...` list on a call boundary must be flagged (the boundary is exactly 16)"
    );
}

#[test]
fn checker_flags_call_boundary_without_stack_list() {
    let src = "#! Does the synthetic call.\n\
               #!\n\
               #! Inputs:\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_entry\n\
               \x20\x20\x20\x20dropw\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_call_boundary_docs, rel, src).is_empty(),
        "a call-boundary Inputs line without a parseable stack list must be flagged"
    );
}

#[test]
fn checker_flags_inputs_marker_present_only_as_prose() {
    let src = "#! Does the synthetic thing. The Inputs: are described elsewhere; Outputs: too.\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_doc_completeness, rel, src).is_empty(),
        "Inputs/Outputs mentioned only in prose (no `#! Inputs:` marker line) must be flagged"
    );
}

#[test]
fn checker_flags_description_paragraph_without_sentence_end() {
    // the first paragraph trails off with a colon; a period elsewhere (v1.2) must not satisfy
    // the sentence rule.
    let src = "#! Does the synthetic thing (v1.2) but trails off:\n\
               #!\n\
               #! More prose that ends properly.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_doc_sections, rel, src).is_empty(),
        "a description paragraph that does not end a sentence must be flagged"
    );
}

#[test]
fn checker_accepts_conformant_component_proc() {
    let src = "#! Applies the synthetic write to the slot.\n\
               #!\n\
               #! Inputs:  [VALUE, flag, pad(11)]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Where:\n\
               #! - VALUE is the synthetic word.\n\
               #! - flag is the synthetic felt.\n\
               #!\n\
               #! Panics if:\n\
               #! - the synthetic gate rejects.\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_write\n\
               \x20\x20\x20\x20assert.err=ERR_SYNTHETIC\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    let checks: [fn(&str, &str, &mut Violations); 8] = [
        check_doc_completeness,
        check_doc_sections,
        check_call_boundary_docs,
        check_direct_asserts_documented,
        check_doc_bullets,
        check_where_definitions,
        check_inline_comment_case,
        check_stack_item_naming,
    ];
    for check in checks {
        assert_eq!(
            run_check(check, rel, src),
            Vec::<String>::new(),
            "a fully conformant call proc must pass every doc rule"
        );
    }
}

#[test]
fn checker_flags_non_verb_description_lead() {
    // "Consume entry point …" is an imperative label, not the required capitalized
    // present-tense verb ("Consumes …").
    let src = "#! Consume entry point of the synthetic note: crosses into the account context.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_doc_sections, rel, src).is_empty(),
        "a description that does not open with a present-tense verb must be flagged"
    );
}

#[test]
fn checker_flags_trailing_junk_after_call_boundary_span() {
    // `VALUE(12)junk` must be rejected as malformed, not counted as 12 elements.
    let src = "#! Does the synthetic call.\n\
               #!\n\
               #! Inputs:  [VALUE(12)junk, pad(4)]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_entry\n\
               \x20\x20\x20\x20dropw\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_call_boundary_docs, rel, src).is_empty(),
        "a span with trailing text must be flagged as malformed on a call boundary"
    );
}

#[test]
fn checker_flags_uppercase_inline_comment() {
    let src = "#! Does the synthetic read.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20# Reads the slot before the write.\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_inline_comment_case, rel, src).is_empty(),
        "an in-procedure comment beginning with an uppercase letter must be flagged"
    );
}

#[test]
fn checker_accepts_lowercase_and_non_letter_inline_comments() {
    let src = "#! Does the synthetic read.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20# reads the slot before the write (R-MINT-13 mid-line is fine).\n\
               \x20\x20\x20\x20# ---- staging ----\n\
               \x20\x20\x20\x20# => [value]\n\
               \x20\x20\x20\x20# [value, other] marshal order.\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert_eq!(
        run_check(check_inline_comment_case, rel, src),
        Vec::<String>::new(),
        "lowercase, decoration, tracker, and non-letter comment leads must pass"
    );
}

#[test]
fn checker_flags_mixed_case_stack_item_name() {
    let src = "#! Does the synthetic move.\n\
               #!\n\
               #! Inputs:  [feeAmount, pad(15)]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_entry\n\
               \x20\x20\x20\x20dropw\n\
               \x20\x20\x20\x20# => [feeAmount, pad(15)]\n\
               \x20\x20\x20\x20dropw\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_stack_item_naming, rel, src).is_empty(),
        "a mixed-case stack-item name must be flagged (Words UPPER_SNAKE, felts lower_snake)"
    );
}

#[test]
fn checker_flags_where_bullet_without_definition_verb() {
    let src = "#! Does the synthetic write.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: []\n\
               #!\n\
               #! Where:\n\
               #! - value: the synthetic felt.\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_where_definitions, rel, src).is_empty(),
        "a Where bullet that is not an is/are definition must be flagged"
    );
}

#[test]
fn checker_flags_where_section_missing_an_input_definition() {
    let src = "#! Does the synthetic write.\n\
               #!\n\
               #! Inputs:  [VALUE, other_felt]\n\
               #! Outputs: []\n\
               #!\n\
               #! Where:\n\
               #! - VALUE is the synthetic word.\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_where_definitions, rel, src).is_empty(),
        "a documented stack item missing from the Where definitions must be flagged"
    );
}

#[test]
fn checker_flags_unparenthesized_span_junk() {
    // `VALUE)junk` must be rejected as malformed — not silently counted as the Word `VALUE`.
    let src = "#! Does the synthetic call.\n\
               #!\n\
               #! Inputs:  [VALUE)junk, pad(12)]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: call\n\
               pub proc synthetic_entry\n\
               \x20\x20\x20\x20dropw\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_call_boundary_docs, rel, src).is_empty(),
        "an item with trailing text after its identifier must be flagged as malformed"
    );
}

#[test]
fn checker_flags_pronoun_lead_description() {
    // `This` ends in `s` but is a demonstrative, not the required present-tense verb.
    let src = "#! This operation documents the synthetic flow.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_doc_sections, rel, src).is_empty(),
        "a pronoun/demonstrative description lead must be flagged despite ending in `s`"
    );
}

#[test]
fn checker_flags_hyphenated_stack_item() {
    // `fee-amount` is neither lower_snake nor UPPER_SNAKE; punctuation-splitting must not
    // launder it into two valid identifiers.
    let src = "#! Does the synthetic move.\n\
               #!\n\
               #! Inputs:  [fee-amount]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_stack_item_naming, rel, src).is_empty(),
        "a hyphenated stack item must be flagged as a grammar violation"
    );
}

#[test]
fn checker_accepts_expression_and_array_stack_items() {
    // spaced operator expressions and `NAME[N]` array spans are protocol-attested forms.
    let src = "#! Does the synthetic move.\n\
               #!\n\
               #! Inputs:  [amount, fee_amount]\n\
               #! Outputs: [pad(16)]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\n\
               \x20\x20\x20\x20# => [amount - fee_amount, DIGEST_U32[8], pad(4)]\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert_eq!(
        run_check(check_stack_item_naming, rel, src),
        Vec::<String>::new(),
        "spaced expressions and array-span items must pass the naming grammar"
    );
}

#[test]
fn checker_flags_expression_with_trailing_operand() {
    // spaced expressions must alternate operand/operator — `amount - fee_amount extra` is
    // neither a valid atom nor a valid binary expression.
    let src = "#! Does the synthetic move.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\n\
               \x20\x20\x20\x20# => [amount - fee_amount extra, pad(4)]\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_stack_item_naming, rel, src).is_empty(),
        "an expression with two consecutive operands must be flagged"
    );
}

#[test]
fn checker_flags_expression_with_double_operator() {
    let src = "#! Does the synthetic move.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: [value]\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\n\
               \x20\x20\x20\x20# => [amount - - fee_amount, pad(4)]\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_stack_item_naming, rel, src).is_empty(),
        "an expression with two consecutive operators must be flagged"
    );
}

#[test]
fn checker_flags_where_definition_token_collision() {
    // `other_value` must not satisfy the definition requirement for `value` by substring.
    let src = "#! Does the synthetic write.\n\
               #!\n\
               #! Inputs:  [value]\n\
               #! Outputs: []\n\
               #!\n\
               #! Where:\n\
               #! - other_value is the synthetic felt.\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert!(
        !run_check(check_where_definitions, rel, src).is_empty(),
        "Where coverage must match whole tokens, not substrings"
    );
}

#[test]
fn checker_accepts_brace_shorthand_where_definitions() {
    let src = "#! Does the synthetic extraction.\n\
               #!\n\
               #! Inputs:  [id_suffix, id_prefix]\n\
               #! Outputs: []\n\
               #!\n\
               #! Where:\n\
               #! - id_{suffix,prefix} are the two synthetic felts.\n\
               #!\n\
               #! Invocation: exec\n\
               proc synthetic_helper\n\
               \x20\x20\x20\x20drop drop\nend\n";
    let rel = "asm/standards/xreserve/synthetic.masm";
    assert_eq!(
        run_check(check_where_definitions, rel, src),
        Vec::<String>::new(),
        "brace-shorthand Where definitions must cover their expanded items"
    );
}

/// A minimal implementation-module procedure carrying `attrs` (each line already newline
/// terminated, or empty for none) and the given documented invocation kind.
fn synth_proc(attrs: &str, invocation: &str) -> String {
    format!(
        "# xreserve::synthetic\n\n\
         #! Does the synthetic move.\n\
         #!\n\
         #! Inputs:  [VALUE]\n\
         #! Outputs: []\n\
         #!\n\
         #! Where:\n\
         #! - VALUE is the synthetic word.\n\
         #!\n\
         #! Invocation: {invocation}\n\
         {attrs}pub proc synthetic_helper\n\
         \x20\x20\x20\x20dropw\nend\n"
    )
}

const SYNTH_PROC_REL: &str = "asm/standards/xreserve/synthetic.masm";

#[test]
fn checker_accepts_an_exec_helper_that_is_off_the_interface() {
    let src = synth_proc("", "exec");
    assert_eq!(
        run_check(
            check_exec_helpers_are_off_the_account_interface,
            SYNTH_PROC_REL,
            &src
        ),
        Vec::<String>::new(),
        "an exec helper without the attribute is the conformant shape"
    );
}

#[test]
fn checker_flags_an_exec_procedure_published_on_the_interface() {
    // the exact mutation the audit planted on `verify_attestation`: the attribute comes back on
    // a procedure whose own doc says it is entered by `exec`.
    let src = synth_proc("@account_procedure\n", "exec");
    assert!(
        !run_check(
            check_exec_helpers_are_off_the_account_interface,
            SYNTH_PROC_REL,
            &src
        )
        .is_empty(),
        "an exec-only procedure carrying `@account_procedure` must be flagged"
    );
}

#[test]
fn checker_accepts_a_dynexec_procedure_on_the_interface() {
    // the mint policy's `check_policy` shape: the stock policy manager dispatches it by root, so
    // it must stay on the account interface. Only the `exec` pairing is forbidden, and the
    // attribute run may carry `@locals` alongside.
    let src = synth_proc("@locals(4)\n@account_procedure\n", "dynexec");
    assert_eq!(
        run_check(
            check_exec_helpers_are_off_the_account_interface,
            SYNTH_PROC_REL,
            &src
        ),
        Vec::<String>::new(),
        "a dynexec-dispatched account procedure must keep its attribute"
    );
}

#[test]
fn checker_flags_a_detached_account_procedure_attribute() {
    // a blank line between the attribute and the declaration detaches it from the attribute run;
    // the parity half of the rule refuses to go vacuous on it.
    let src = synth_proc("@account_procedure\n\n", "exec");
    assert!(
        !run_check(
            check_exec_helpers_are_off_the_account_interface,
            SYNTH_PROC_REL,
            &src
        )
        .is_empty(),
        "an `@account_procedure` line that reaches no declaration must be flagged"
    );
}
