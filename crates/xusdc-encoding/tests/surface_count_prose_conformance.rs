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

use anyhow::{Context, Result};
use support::production_component_set;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

const MAX_SUPPLY: u64 = 1_000_000;

/// The conformance sources whose count-prose this guard keeps in sync with the executable surface.
/// (`include_str!` resolves relative to THIS file — i.e. the `tests/` dir.)
const SOURCES: [(&str, &str); 3] = [
    (
        "account_callable_surface.rs",
        include_str!("account_callable_surface.rs"),
    ),
    (
        "account_surface_unreachable.rs",
        include_str!("account_surface_unreachable.rs"),
    ),
    ("mint_root_surface.rs", include_str!("mint_root_surface.rs")),
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
        (3, 59, 62, 9),
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
    Ok(())
}
