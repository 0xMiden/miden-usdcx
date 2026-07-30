//! Documentation-hygiene guards for the builder/admin-note module split. Splitting the
//! monolithic builder and admin-note files into directory modules left two documentation
//! defects; these tests keep the fixes from regressing.
//!
//! * intra-doc links — the moved builder error enum (`builder/error.rs`) documents four items
//!   that live OUTSIDE its module scope (`AssetAmount::MAX` and the three `super::` config
//!   consts). After the split a bare `` [`Name`] `` intra-doc link no longer resolves, so
//!   `RUSTDOCFLAGS='-D warnings' cargo doc` fails link validation. Each link must carry an
//!   explicit module-qualified destination. (This guard checks the source shape; the
//!   authoritative check is the `cargo doc` gate — the two agree by construction.)
//! * decision record — the transfer-blocklist decision record must point reviewers at the
//!   CURRENT admin-note module tree for the pinned block/unblock roots, not the removed
//!   monolithic `src/note/xreserve_admin.rs` file.

const BUILDER_ERROR_SRC: &str = include_str!("../src/account/xreserve/builder/error.rs");
const DECISION_F4: &str = include_str!("../../../docs/DECISION-F4-REVERSAL-TRANSFER-BLOCKLIST.md");

/// The sources that introduce or discuss the deposit-amount scale — the ones the open-status
/// governance scan guards against marking the Circle-owned amount-cap decision as
/// answered/resolved/approved.
const DEV5_SCANNED_SOURCES: &[(&str, &str)] = &[
    (
        "asm/standards/xreserve/mint_policy.masm",
        include_str!("../../../asm/standards/xreserve/mint_policy.masm"),
    ),
    (
        "src/note/xreserve_mint.rs",
        include_str!("../src/note/xreserve_mint.rs"),
    ),
    (
        "docs/WAVE1-S1-RECOMPOSITION.md",
        include_str!("../../../docs/WAVE1-S1-RECOMPOSITION.md"),
    ),
    (
        "tests/mint_scale_conformance.rs",
        include_str!("mint_scale_conformance.rs"),
    ),
];

/// A Circle-owned open decision may never be marked
/// approved/accepted/resolved/answered. The amount cap / scale / dust tolerance are
/// Circle-OPEN; the faucet ships only the PROVISIONAL scale-0 position. This scan asserts
/// that no source line carrying an open-status anchor — the phrase "REQUIRES CIRCLE
/// CONFIRMATION" or "pending Circle" (or, in the docs, the historical amount-cap id) — also
/// carries a resolution word, and that every scanned source still carries at least one
/// anchor line. The provisional wording cannot silently drift into an implied Circle
/// approval, and the scan cannot silently go vacuous by the anchors disappearing.
#[test]
fn dev5_stays_open_in_the_wave1_sources() {
    // resolution words (lower-cased match) that must never sit on an anchor line.
    const FORBIDDEN: [&str; 5] = ["answered", "resolved", "approved", "accepted", "closed"];
    // the open-status anchors: the humanized marker phrases plus the historical id, which
    // survives in the docs.
    const ANCHORS: [&str; 3] = ["REQUIRES CIRCLE CONFIRMATION", "pending Circle", "DEV-5"];
    for (path, src) in DEV5_SCANNED_SOURCES {
        let mut anchor_lines = 0usize;
        for (lineno, line) in src.lines().enumerate() {
            if !ANCHORS.iter().any(|anchor| line.contains(anchor)) {
                continue;
            }
            anchor_lines += 1;
            let lower = line.to_lowercase();
            for word in FORBIDDEN {
                assert!(
                    !lower.contains(word),
                    "{path}:{} marks the Circle-owned amount-cap decision '{word}': `{}` — the \
                     cap/scale/dust decision stays OPEN; describe only the provisional scale-0 \
                     position (BUILDER-GATES G6 / ground rule 6)",
                    lineno + 1,
                    line.trim()
                );
            }
        }
        assert!(
            anchor_lines > 0,
            "{path}: no open-status anchor line found — the Circle-owned amount-cap decision \
             must stay visibly OPEN (\"pending Circle\" / \"REQUIRES CIRCLE CONFIRMATION\") in \
             this source (BUILDER-GATES G6 / ground rule 6)"
        );
    }
}

/// Every out-of-scope intra-doc link in the moved error module carries an explicit
/// path destination, so rustdoc resolves it under `-D warnings`. The four items are the ones the
/// split moved out of scope (`AssetAmount::MAX` from `miden_protocol`, and the three `pub const`s
/// that stayed in the parent `builder` module).
#[test]
fn builder_error_intra_doc_links_are_module_qualified() {
    for dest in [
        "(miden_protocol::asset::AssetAmount::MAX)",
        "(super::REQUIRED_XRESERVE_SLOT_LABELS)",
        "(super::USDCX_DECIMALS)",
        "(super::USDCX_TOKEN_SYMBOL)",
    ] {
        assert!(
            BUILDER_ERROR_SRC.contains(dest),
            "builder/error.rs is missing the module-qualified intra-doc link destination `{dest}` — \
             after the round-6 split these items are out of this module's scope, so a bare \
             `[`Name`]` link fails `RUSTDOCFLAGS=-D warnings cargo doc` (round-7 finding #2)"
        );
    }
}

/// The decision record names the current admin-note module (the block/unblock factory
/// source), not the removed monolithic file.
#[test]
fn decision_record_names_the_current_admin_note_module() {
    assert!(
        !DECISION_F4.contains("src/note/xreserve_admin.rs"),
        "DECISION-F4 still points at the REMOVED monolithic `src/note/xreserve_admin.rs`; after the \
         round-6 split the pinned block/unblock roots live in the `src/note/xreserve_admin/` module \
         tree (round-7 finding #3)"
    );
    assert!(
        DECISION_F4.contains("src/note/xreserve_admin/blocklist.rs"),
        "DECISION-F4 must name the CURRENT source of the pinned block/unblock roots \
         (`src/note/xreserve_admin/blocklist.rs`, the block_account/unblock_account factories)"
    );
}
