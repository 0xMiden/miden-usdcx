//! Round-7 DOC-HYGIENE guards for the round-6 module split. Splitting `builder.rs` and
//! `xreserve_admin.rs` into directory modules left two documentation defects; these tests keep the
//! fixes from regressing.
//!
//! * finding #2 — the moved builder error enum (`builder/error.rs`) documents four items that live
//!   OUTSIDE its module scope (`AssetAmount::MAX` and the three `super::` config consts). After the
//!   split a bare `` [`Name`] `` intra-doc link no longer resolves, so
//!   `RUSTDOCFLAGS='-D warnings' cargo doc` fails link validation. Each link must carry an explicit
//!   module-qualified destination. (This guard checks the source shape; the authoritative check is
//!   the `cargo doc` gate the round runs — the two agree by construction.)
//! * finding #3 — the F4-reversal decision record must point reviewers at the CURRENT admin-note
//!   module tree for the pinned block/unblock roots, not the removed monolithic
//!   `src/note/xreserve_admin.rs` file.

const BUILDER_ERROR_SRC: &str = include_str!("../src/account/xreserve/builder/error.rs");
const DECISION_F4: &str = include_str!("../../../docs/DECISION-F4-REVERSAL-TRANSFER-BLOCKLIST.md");

/// The Wave-1 S1 sources that introduce or discuss the DC-5 scale — the ones the R2-F4 governance
/// scan guards against marking the Circle-owned DEV-5 decision as answered/resolved/approved.
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

/// R2-F4 (BUILDER-GATES G6 / ground rule 6): a Circle-owned `DEV-*`/`Q-*` open decision may never
/// be marked approved/accepted/resolved/answered. DEV-5 (amount cap / scale / dust tolerance) is
/// Circle-OPEN; the faucet ships only the PROVISIONAL scale-0 position. This scan asserts no
/// Wave-1 S1 source line that mentions `DEV-5` also carries a resolution word — so the provisional
/// wording cannot silently drift into an implied Circle approval.
#[test]
fn dev5_stays_open_in_the_wave1_sources() {
    // resolution words (lower-cased match) that must never sit on a DEV-5 line.
    const FORBIDDEN: [&str; 5] = ["answered", "resolved", "approved", "accepted", "closed"];
    for (path, src) in DEV5_SCANNED_SOURCES {
        for (lineno, line) in src.lines().enumerate() {
            if !line.contains("DEV-5") {
                continue;
            }
            let lower = line.to_lowercase();
            for word in FORBIDDEN {
                assert!(
                    !lower.contains(word),
                    "{path}:{} marks the Circle-owned DEV-5 decision '{word}': `{}` — DEV-5 \
                     (cap/scale/dust) stays OPEN; describe only the provisional scale-0 position \
                     (BUILDER-GATES G6 / ground rule 6)",
                    lineno + 1,
                    line.trim()
                );
            }
        }
    }
}

/// finding #2: every out-of-scope intra-doc link in the moved error module carries an explicit
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

/// finding #3: the decision record names the current admin-note module (the block/unblock factory
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
