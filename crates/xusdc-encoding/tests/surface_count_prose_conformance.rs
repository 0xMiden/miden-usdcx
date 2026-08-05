//! ANTI-DRIFT GUARD: the audit-facing COUNT PROSE in the callable-surface
//! conformance modules must match the EXECUTABLE surface, not a superseded value. These are
//! security-reasoning tests; stale "17 / 62 / 12" prose next to a `[&str; 64]` constant makes a
//! failure message lie about what the account actually exposes.
//!
//! This guard DERIVES the authoritative counts from the shipped composition (so it cannot itself go
//! stale) and then scans the conformance sources: every superseded count-phrase must be ABSENT and
//! every authoritative one PRESENT. It is the machine that keeps the prose honest — change the real
//! surface and this fails until BOTH the constants and the prose are updated together.

mod support;

use std::path::Path;

use anyhow::{Context, Result};
use support::production_component_set;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

const MAX_SUPPLY: u64 = 1_000_000;

/// The requirement→implementation→test map whose locators must all still resolve.
const REGISTER: &str = include_str!("../../../docs/REQUIREMENTS-TRACEABILITY.md");

/// The top-level orientation doc whose admin overview must name only live procedures.
const README: &str = include_str!("../../../README.md");

/// Module basenames the register legitimately cites that live UPSTREAM in miden-standards rather
/// than in this repository's `asm/` tree. They are live files, just not ours.
const STOCK_MASM_MODULES: [&str; 2] = ["fungible.masm", "min_burn_amount.masm"];

/// The conformance sources whose count-prose this guard keeps in sync with the executable surface.
/// (`include_str!` resolves relative to THIS file — i.e. the `tests/` dir.)
const SOURCES: [(&str, &str); 5] = [
    (
        "account_callable_surface.rs",
        include_str!("account_callable_surface.rs"),
    ),
    (
        "account_surface_unreachable.rs",
        include_str!("account_surface_unreachable.rs"),
    ),
    ("mint_root_surface.rs", include_str!("mint_root_surface.rs")),
    // the w2admin suites assert the same two counts and narrate them in prose and in TEST NAMES,
    // which is where the last round of drift hid: a name like `..._sixty_two_procedures` keeps
    // claiming a superseded count long after the constant it asserts against moved.
    (
        "w2admin_production_admin_effects.rs",
        include_str!("w2admin_production_admin_effects.rs"),
    ),
    (
        "w2admin_surface_finalization.rs",
        include_str!("w2admin_surface_finalization.rs"),
    ),
];

/// Derive `(xreserve_roots, stock_roots, total_roots, note_allowlist)` from the SAME composition the
/// account ships: the production component set + the `AuthNetworkAccount` auth component, counting
/// each component's callable exports and partitioning the xreserve roots by their `::xreserve::`
/// path. This is the single executable source of truth the prose must agree with.
fn derive_surface_counts() -> Result<(usize, usize, usize, usize)> {
    let mut components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;
    components.extend(
        XReserveStablecoinBuilder::auth_component()
            .context("the production auth component must build")?,
    );
    let mut total = 0usize;
    let mut xreserve = 0usize;
    for component in &components {
        let code: &_ = component.component_code();
        for export in code.exports() {
            total += 1;
            if export.path.to_string().contains("::xreserve::") {
                xreserve += 1;
            }
        }
    }
    let stock = total - xreserve;
    let notes = XReserveStablecoinBuilder::allowed_note_scripts().len();
    Ok((xreserve, stock, total, notes))
}

#[test]
fn conformance_prose_counts_match_the_executable_surface() -> Result<()> {
    let (xreserve, stock, total, notes) = derive_surface_counts()?;

    // Ground truth first — pins the derivation so this guard is NOT tautological: if the shipped
    // surface ever changes, this fails loudly (and the whole point below — the prose — must follow).
    assert_eq!(
        (xreserve, stock, total, notes),
        (2, 59, 61, 8),
        "the executable callable surface changed ({xreserve} xreserve + {stock} stock = {total} \
         roots, {notes}-note allowlist) — update the ratified constants AND every count-phrase in \
         the conformance prose together (MIGRATION-V16-ALPHA2.md stock-surface discipline)"
    );

    // The CURRENT authoritative count-phrases must appear in the prose (derived, not hard-coded).
    let all: String = SOURCES
        .iter()
        .map(|(_, s)| *s)
        .collect::<Vec<_>>()
        .join("\n");
    for needle in [
        format!("{total}-root"),
        format!("{notes}-root note-script allowlist"),
        format!("the {xreserve} callable roots"),
        format!("{stock} stock"),
    ] {
        assert!(
            all.contains(&needle),
            "the conformance prose is missing the authoritative count token `{needle}` — the \
             executable surface is {xreserve} xreserve + {stock} stock = {total} roots, \
             {notes}-note allowlist"
        );
    }

    // The SUPERSEDED count-phrases must be gone from EACH source (a stale token is a lie about
    // the real surface). Each is a count the surface DID carry under an earlier composition
    // (fewer xreserve roots, a different stock-row total, a smaller note allowlist), so any of
    // them reappearing in prose means the text no longer describes the executable account.
    let superseded = [
        // — superseded when the identifier-init note and procedure were removed —
        "62-root",
        "sixty-two",
        "sixty_two",
        "ratified 62 roots",
        "seven admin/config notes",
        "the seven admin notes",
        "the seven admin",
        "one of the 9",
        "among the 9",
        "the 9 are the two supply notes",
        "the four administrator-gated",
        "the 3 callable roots",
        "the 3 sanctioned roots",
        "the 3 frozen",
        "9-root note-script allowlist",
        "75-root",
        "64 stock",
        "12-root",
        "64-root",
        "49 stock",
        "14-root",
        "60 stock",
        "the 15 callable roots",
        "the 15 sanctioned roots",
        "the 15 frozen",
        "the 17 callable roots",
        "the 17 sanctioned roots",
        "the 17 frozen",
        "45 stock",
        "the 10 admin",
        "the 19 callable roots",
        "the 19 sanctioned roots",
        "the 19 frozen",
        "46 stock",
        "75-root",
        "the 15 callable roots",
        "the 15 sanctioned roots",
        "the 15 frozen",
        "74-root",
        "the 14 callable roots",
        "the 14 sanctioned roots",
        "the 14 frozen",
        "69-root",
        "the 10 callable roots",
        "the 10 sanctioned roots",
        "the 10 frozen",
        "65-root",
        "the 6 callable roots",
        "the 6 sanctioned roots",
        "the 6 frozen",
    ];
    for (name, src) in SOURCES {
        for bad in superseded {
            assert!(
                !src.contains(bad),
                "stale surface-count token `{bad}` still present in {name} — the executable surface \
                 is {xreserve} xreserve + {stock} stock = {total} roots and the note allowlist is \
                 {notes}; audit-facing prose must not claim a superseded count (round-6 finding #2)"
            );
        }
    }

    // The CANONICAL RECORD must carry the current surface too: the deviation register's live
    // claim and the docs inventory's latest-state delta are what a security reviewer reads
    // first, so a code-side re-materialization that leaves them behind splits the authority.
    // These docs deliberately PRESERVE superseded counts as struck-through provenance, so the
    // check here is presence of the current claim, not absence of history.
    let canonical: [(&str, &str, String); 2] = [
        (
            "docs/spec/GLOSSARY.md",
            include_str!("../../../docs/spec/GLOSSARY.md"),
            format!("the callable surface is **{total}** ({xreserve} xreserve + {stock} stock)"),
        ),
        (
            "docs/DOCS-INVENTORY.md",
            include_str!("../../../docs/DOCS-INVENTORY.md"),
            format!("re-materialized to **{total}**"),
        ),
    ];
    // The requirements register is the repository's ONLY map from a requirement to the procedure
    // that implements it and the test that proves it. A row still naming a file or symbol that was
    // removed is worse than no row: it sends a reviewer to something that is not there.
    //
    // The check DERIVES what must exist from the tree rather than listing what must not appear. A
    // denylist would have to spell the very names the removal is supposed to have erased, and it
    // would go stale the moment something else is deleted; asking "does every locator this file
    // cites still resolve?" keeps working for the next removal without being edited.
    let stale = stale_register_locators(REGISTER);
    assert!(
        stale.is_empty(),
        "docs/REQUIREMENTS-TRACEABILITY.md cites locators that no longer resolve: {stale:?} — the \
         register is the sole requirement→implementation→test map, so a locator that does not \
         exist makes it materially false"
    );

    // The README's admin overview names the procedures an operator can actually drive. A name that
    // is neither a live callable procedure nor a shipped note script is an invitation to call
    // something that is not there.
    let readme_stale = stale_readme_admin_terms(README, &live_callable_leaves()?);
    assert!(
        readme_stale.is_empty(),
        "README.md's admin overview names {readme_stale:?}, which the shipped account neither \
         exposes as a callable procedure nor ships as a note script"
    );

    for (name, src, needle) in &canonical {
        assert!(
            src.contains(needle.as_str()),
            "the canonical record {name} does not carry the current surface claim `{needle}` — \
             the executable surface is {xreserve} xreserve + {stock} stock = {total} roots; the \
             register and the inventory must state the live count (with the superseded one \
             preserved as provenance)"
        );
    }
    Ok(())
}

// DERIVED EXISTENCE CHECKS
// ================================================================================================

/// Everything the checks below resolve locators against, read from the working tree at test time.
struct TreeFacts {
    masm_names: Vec<String>,
    masm_source: String,
    test_names: Vec<String>,
    crate_source: String,
    note_script_names: Vec<String>,
}

fn tree_facts() -> TreeFacts {
    fn walk(root: &Path, ext: &str, names: &mut Vec<String>, source: &mut String) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, ext, names, source);
            } else if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    names.push(name.to_string());
                }
                if let Ok(text) = std::fs::read_to_string(&path) {
                    source.push_str(&text);
                    source.push('\n');
                }
            }
        }
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf();

    let (mut masm_names, mut masm_source) = (Vec::new(), String::new());
    walk(&repo.join("asm"), "masm", &mut masm_names, &mut masm_source);

    let (mut note_script_names, mut sink) = (Vec::new(), String::new());
    walk(
        &repo.join("asm/standards/notes"),
        "masm",
        &mut note_script_names,
        &mut sink,
    );

    let (mut test_names, mut test_sink) = (Vec::new(), String::new());
    if let Ok(crates) = std::fs::read_dir(repo.join("crates")) {
        for entry in crates.flatten() {
            walk(
                &entry.path().join("tests"),
                "rs",
                &mut test_names,
                &mut test_sink,
            );
        }
    }

    let (mut _src_names, mut crate_source) = (Vec::new(), String::new());
    walk(
        &repo.join("crates/xusdc-encoding/src"),
        "rs",
        &mut _src_names,
        &mut crate_source,
    );

    TreeFacts {
        masm_names,
        masm_source,
        test_names,
        crate_source,
        note_script_names,
    }
}

/// Pulls every backticked token of the given shape out of `doc`.
fn backticked(doc: &str, shape: impl Fn(&str) -> bool) -> Vec<String> {
    doc.split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| shape(t))
        .map(|t| t.to_string())
        .collect()
}

/// The locators the requirements register cites that no longer resolve anywhere in the tree.
///
/// Four shapes are resolved, each against the artifact that would have to exist for the citation to
/// be honest: a faucet-owned error constant against the MASM that declares it, a test file against
/// every crate's `tests/` directory, a MASM module against `asm/` (or the upstream stock set), and
/// an admin-note factory or slot-label constant against the encoding crate's own sources.
fn stale_register_locators(register: &str) -> Vec<String> {
    let facts = tree_facts();
    let mut stale = Vec::new();

    for err in backticked(register, |t| {
        t.starts_with("ERR_XRESERVE_") && t.chars().all(|c| c.is_ascii_uppercase() || c == '_')
    }) {
        if !facts.masm_source.contains(&format!("const {err} =")) {
            stale.push(err);
        }
    }
    for file in backticked(register, |t| t.starts_with("tests/") && t.ends_with(".rs")) {
        let base = file.rsplit('/').next().unwrap_or(&file).to_string();
        if !facts.test_names.contains(&base) {
            stale.push(file);
        }
    }
    for module in backticked(register, |t| t.ends_with(".masm") && !t.contains(' ')) {
        let base = module.rsplit('/').next().unwrap_or(&module).to_string();
        if !facts.masm_names.contains(&base) && !STOCK_MASM_MODULES.contains(&base.as_str()) {
            stale.push(module);
        }
    }
    for symbol in backticked(register, |t| {
        (t.starts_with("XReserve") && t.ends_with("Note"))
            || (t.ends_with("_SLOT_LABEL") && t.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
    }) {
        if !facts.crate_source.contains(&symbol) {
            stale.push(symbol);
        }
    }
    stale
}

/// The leaf names of every procedure the shipped composition makes callable.
fn live_callable_leaves() -> Result<Vec<String>> {
    let mut components =
        production_component_set(MAX_SUPPLY, 0).context("the production composition must build")?;
    components.extend(
        XReserveStablecoinBuilder::auth_component()
            .context("the production auth component must build")?,
    );
    Ok(components
        .iter()
        .flat_map(|c| {
            c.component_code()
                .exports()
                .map(|e| {
                    let path = e.path.to_string();
                    path.rsplit("::").next().unwrap_or(&path).to_string()
                })
                .collect::<Vec<_>>()
        })
        .collect())
}

/// The snake_case procedure names the README's admin overview promises that the account does not
/// actually expose — neither as a callable procedure nor as a shipped note script.
fn stale_readme_admin_terms(readme: &str, callable_leaves: &[String]) -> Vec<String> {
    let facts = tree_facts();
    let Some(start) = readme.find("- **Admin.**") else {
        return vec!["the README has no admin overview to check".to_string()];
    };
    let bullet = &readme[start..];
    let bullet = &bullet[..bullet.find("\n\n").unwrap_or(bullet.len())];

    backticked(bullet, |t| {
        t.contains('_')
            && t.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    })
    .into_iter()
    .filter(|term| {
        !callable_leaves.iter().any(|leaf| leaf == term)
            && !facts
                .note_script_names
                .iter()
                .any(|n| n.contains(term.as_str()))
    })
    .collect()
}

// NON-VACUITY CONTROLS — the derived checks must actually reject something
// ================================================================================================

/// A register citing artifacts that do not exist is caught for every shape the check resolves.
///
/// The synthetic names below are invented on purpose: the guard's whole point is that it no longer
/// has to spell a removed artifact to notice one, so its own control must not spell one either.
#[test]
fn the_register_check_rejects_every_shape_of_dangling_locator() {
    for line in [
        "| X | y | `ERR_XRESERVE_NO_SUCH_GUARD` | z |",
        "| X | y | `tests/no_such_suite_at_all.rs` | z |",
        "| X | y | `no_such_module_at_all.masm` | z |",
        "| X | y | `XReserveNoSuchThingNote` | z |",
        "| X | y | `NO_SUCH_THING_SLOT_LABEL` | z |",
    ] {
        assert!(
            !stale_register_locators(line).is_empty(),
            "the register check must reject the dangling locator in {line}"
        );
    }
}

/// A live register row is NOT flagged — the check discriminates rather than rejecting everything.
#[test]
fn the_register_check_accepts_live_locators() {
    let live = "| X | `ERR_XRESERVE_WRONG_IDENTIFIER` | `deposit_intent_parser.masm` | \
                `tests/masm_mint_shell.rs` | `XReserveSetAttesterNote` | `USED_NONCES_SLOT_LABEL` |";
    assert!(
        stale_register_locators(live).is_empty(),
        "the register check must accept locators that resolve"
    );
}

/// The README check names a promised procedure the account does not expose, and stays quiet about
/// one it does.
#[test]
fn the_readme_admin_check_rejects_a_procedure_the_account_does_not_expose() -> Result<()> {
    let leaves = live_callable_leaves()?;
    let invented = "- **Admin.** `ADMIN` gates `no_such_setter_at_all`.\n\n";
    assert_eq!(
        stale_readme_admin_terms(invented, &leaves),
        vec!["no_such_setter_at_all".to_string()],
        "the README check must reject a setter the account does not expose"
    );
    let real = "- **Admin.** `ADMIN` gates `set_attester`.\n\n";
    assert!(
        stale_readme_admin_terms(real, &leaves).is_empty(),
        "the README check must accept a setter the account really exposes"
    );
    Ok(())
}
