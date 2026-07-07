//! R-MINT-16 mint-deny guard suite (P5-01): the inherited stock `mint_and_send` MUST be denied so
//! the custom `xreserve_mint` is the provably SOLE supply-increasing surface (INV-MINT-SECURITY,
//! §5.2). The guarded faucet is composed via `XReserveStablecoinBuilder` (deny guard = the active
//! mint policy of a `TokenPolicyManager`); `mint_and_send` routes through
//! `policy_manager::execute_mint_policy` -> `dynexec` of the active mint-policy proc root, so the
//! deny guard's `check_policy` gates every stock mint.
//!
//! The deny guard (`mint_deny_guard.masm::check_policy`) traps unconditionally, so stock
//! `mint_and_send` is denied (ERR_XRESERVE_MINT_DENIED) and the custom `xreserve_mint` is the sole
//! supply-increasing surface. The allow-all oracle is the non-vacuity control: on a CODE-IDENTICAL
//! account with the allow-all policy active (differing ONLY in `active_mint_policy_proc_root`),
//! `mint_and_send` SUCCEEDS and raises supply — so the deny arm's trap is policy-caused, not a
//! missing-slot / zero-root / proc-not-found artifact. The allow-vs-deny fixtures are composed by the
//! TEST-ONLY `support::oracle_components`; production composition (deny-only) is
//! `XReserveStablecoinBuilder::build_components`.

mod support;

use std::collections::BTreeMap;

use anyhow::Result;
use miden_protocol::account::{StorageSlotDelta, StorageSlotName};
use miden_protocol::{Felt, Word};
use miden_testing::assert_transaction_executor_error;
use support::*;

// A dummy recipient for the stock mint_and_send note. `mint_and_send` does not validate the
// recipient — it just emits a P2ID-shaped note carrying it (mirrors the protocol faucet test's
// `Word::from([0, 1, 2, 3u32])`).
fn dummy_recipient() -> Word {
    Word::from([0u32, 1, 2, 3])
}

// Dummy faucet config words for the guarded fixtures. The deny suite drives the inherited stock
// `mint_and_send`, which routes through the policy manager and NEVER reads the xreserve domain /
// identifier config slots (those are read only by the custom `xreserve_mint`), so any valid words
// suffice here.
fn dummy_config() -> (Word, Word) {
    (
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        Word::from([11u32, 12, 13, 14]),
    )
}

// Arbitrary tag for the emitted note (the protocol faucet test pushes a raw u32 literal here).
const MINT_TAG: u32 = 4;
// Private note type (NoteType::PRIVATE == 0). A Private note publishes only the recipient DIGEST, so
// a raw-`Word` recipient (whose note details are not staged in the advice provider) is valid — a
// Public note would trip `before_created`'s PublicNoteMissingDetails on the opaque recipient. This
// matches the protocol's own faucet mint test (scripts/faucet.rs: NoteType::Private + raw recipient).
// The note's privacy is irrelevant to R-MINT-16: the suite only needs mint_and_send to run (allow
// oracle) / be denied (deny oracle) and to (not) raise supply.
const MINT_NOTE_TYPE: u8 = 0;
// Our composition installs NO transfer policies, so the faucet registers no asset callbacks -> the
// minted asset key must carry has_callbacks=false (enable_callbacks = 0). The allow-all success test
// is the empirical oracle for this bit (it must SUCCEED and raise supply).
const ENABLE_CALLBACKS: u8 = 0;

const MINT_AMOUNT: u64 = 100;

/// A trivial-but-valid driver/probe pair for the guarded fixtures. The deny suite drives the stock
/// `mint_and_send` entrypoint (a tx script, not these driver procs), so the composition driver/probe
/// are UNUSED by these tests — they only need to compile against the `xreserve` library so the
/// account assembles. Reuses the canonical composition helpers with a dummy supply readback.
fn unused_driver_probe() -> (String, String) {
    // a minimal valid composition driver (staged preimage of 1 felt, never executed by this suite)
    let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
    let probe = composition_supply_probe_src(0);
    (driver, probe)
}

// ALLOW-ALL ORACLE (GREEN) — proves the fixture reaches a *working* mint_and_send
// ================================================================================================

/// With the allow-all policy ACTIVE, the stock `mint_and_send` must SUCCEED: it emits exactly one
/// recipient note and raises `token_supply` by the minted amount. This pins the fixture + invocation
/// (callbacks bit, script compilation, auth) as correct, so a deny trap under the deny oracle is
/// attributable to the policy and not a fixture artifact.
#[tokio::test]
async fn mint_and_send_succeeds_under_allow_all() -> Result<()> {
    let (driver, probe) = unused_driver_probe();
    let (domain, identifier) = dummy_config();
    let gm = setup_guarded_mint_account(
        GuardSelection::OracleAllowAll,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        false,
    )?;
    let executed = run_mint_and_send(
        &gm.harness,
        dummy_recipient(),
        MINT_NOTE_TYPE,
        MINT_TAG,
        MINT_AMOUNT,
        ENABLE_CALLBACKS,
    )
    .await
    .expect("allow-all mint_and_send must succeed");

    assert_eq!(
        executed.output_notes().num_notes(),
        1,
        "allow-all mint_and_send must emit exactly one recipient note"
    );

    let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
    let StorageSlotDelta::Value(cfg) = executed
        .account_delta()
        .storage()
        .get(&cfg_slot)
        .expect("token_config slot delta")
    else {
        panic!("token_config must be a Value slot delta");
    };
    assert_eq!(
        cfg[0],
        Felt::from(MINT_AMOUNT as u32),
        "allow-all mint_and_send must raise token_supply by the minted amount"
    );
    Ok(())
}

// DENY (EXPECTED RED at the gate — mint_and_send SUCCEEDS under the no-op guard)
// ================================================================================================

/// With the deny guard ACTIVE, the stock `mint_and_send` traps with the EXACT ERR_XRESERVE_MINT_DENIED
/// — declared ONLY in `mint_deny_guard.masm`, so the trap is unambiguously the deny guard. Paired with
/// `mint_and_send_succeeds_under_allow_all` on a code-identical account, this is the non-vacuity proof.
#[tokio::test]
async fn deny_mint_and_send_traps() -> Result<()> {
    let (driver, probe) = unused_driver_probe();
    let (domain, identifier) = dummy_config();
    let gm = setup_guarded_mint_account(
        GuardSelection::OracleDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        false,
    )?;
    let result = run_mint_and_send(
        &gm.harness,
        dummy_recipient(),
        MINT_NOTE_TYPE,
        MINT_TAG,
        MINT_AMOUNT,
        ENABLE_CALLBACKS,
    )
    .await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_MINT_DENIED"));
    Ok(())
}

/// The denied stock `mint_and_send` produces NO `token_supply` effect: the guard traps, so the tx
/// returns `Err` and commits nothing. We observe the effect on the mint tx's OWN delta rather than a
/// separate readback probe, because this harness builds each tx from genesis and never commits between
/// calls — a probe would always read genesis and could not witness a *successful* mint's effect; the
/// delta can. Were the policy ever to let the mint through, the resulting `Ok` delta would carry a
/// `token_supply += amount` rise and trip the assertion.
#[tokio::test]
async fn denied_path_no_supply_effect() -> Result<()> {
    let (driver, probe) = unused_driver_probe();
    let (domain, identifier) = dummy_config();
    let gm = setup_guarded_mint_account(
        GuardSelection::OracleDeny,
        1_000_000,
        0,
        domain,
        identifier,
        None,
        None,
        &driver,
        &probe,
        false,
    )?;
    let result = run_mint_and_send(
        &gm.harness,
        dummy_recipient(),
        MINT_NOTE_TYPE,
        MINT_TAG,
        MINT_AMOUNT,
        ENABLE_CALLBACKS,
    )
    .await;

    // A denied mint must not raise supply. The guard traps (Err) so the path commits nothing; the
    // `if let Ok` below is defense-in-depth — were the policy ever to let the mint through, the
    // executed tx's delta must carry NO token_supply rise.
    if let Ok(executed) = result {
        let cfg_slot = StorageSlotName::new(TOKEN_CONFIG_SLOT_LABEL)?;
        let raised = match executed.account_delta().storage().get(&cfg_slot) {
            Some(StorageSlotDelta::Value(cfg)) => cfg[0] != Felt::from(0u32),
            _ => false,
        };
        assert!(
            !raised,
            "a denied stock mint_and_send must NOT raise token_supply, but the executed mint \
             carries a token_supply delta (the no-op deny guard let the mint through)"
        );
    }
    Ok(())
}

// STATIC SCAFFOLDS (GREEN)
// ================================================================================================

/// The assembled `xreserve` library must export the deny guard's `check_policy` at the flat path
/// `xreserve::mint_deny_guard::check_policy`. Mirrors `probe_mint_composition_exports`' exports() API.
#[test]
fn probe_mint_deny_guard_export() -> Result<()> {
    let lib = assemble_xreserve_lib()?;
    assert!(
        lib.exports()
            .filter(|e| e.as_procedure().is_some())
            .any(|e| e
                .path()
                .to_string()
                .ends_with("xreserve::mint_deny_guard::check_policy")),
        "the xreserve library must export xreserve::mint_deny_guard::check_policy; exports: {:?}",
        lib.exports()
            .filter(|e| e.as_procedure().is_some())
            .map(|e| e.path().to_string())
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Static supply-DECREMENT surface enumeration over the `xreserve` MASM tree (CMP-B3): there is NO
/// local `exec.faucet::burn` (the decrement primitive) and NO `xreserve_receive_and_burn.masm` — the
/// burn decrement is the STOCK `receive_and_burn` (linked miden-standards), BY DESIGN (CMP-B3
/// stock-suffices determination), not a deferred local proc.
///
/// The supply-RAISE sole-surface guarantee (only `mint` is a callable supply-raising root) is now
/// enforced at the correct account-code-commitment / procedure-root level by
/// `mint_root_surface::production_supply_raising_root_set_is_exactly_mint` — it replaced the former
/// file-grep RAISE sweep (F3), a text proxy that could not see the over-exported `apply_mint_effects`
/// (F1). Must be GREEN.

/// Recursively collects every `*.masm` under the xreserve tree (skipping any `canary/` subtree)
/// as file-name -> source. Shared by the two static sweeps below.
fn collect_xreserve_masm() -> BTreeMap<String, String> {
    fn collect(dir: &std::path::Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).expect("reading the xreserve asm dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("canary") {
                    continue;
                }
                collect(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("masm") {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap().to_string();
                let src = std::fs::read_to_string(&path).expect("reading a masm file");
                out.insert(name, src);
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(&xusdc_encoding::xreserve_asm_dir(), &mut files);
    assert!(
        files.contains_key("xreserve_mint.masm"),
        "the sweep must see xreserve_mint.masm; saw: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    files
}

#[test]
fn no_local_supply_decrement_surface() {
    let files = collect_xreserve_masm();

    // NO local supply-DECREMENT surface, BY DESIGN: the burn decrement is the stock receive_and_burn
    // (linked miden-standards), so the local tree has no `faucet::burn` caller and no custom consume proc.
    for (name, src) in &files {
        assert_eq!(
            src.lines().filter(|l| l.contains("exec.faucet::burn")).count(),
            0,
            "`exec.faucet::burn` (the supply-decrement primitive) must NOT appear in {name}: the burn \
             decrement is the stock receive_and_burn, not a local surface (CMP-B3 sole-decrement)"
        );
    }
    assert!(
        !files.contains_key("xreserve_receive_and_burn.masm"),
        "no xreserve_receive_and_burn.masm exists by design — the stock receive_and_burn is the burn \
         path (CMP-B3 stock-suffices determination); a custom consume proc requires a cited stock gap"
    );
}

/// L11 (P5-01 CMP-B1 ride-along): the RAISE-side static write-integrity sweep the F1 slice
/// dropped, re-added as a COMPLEMENT to — not a replacement for — the procedure-root enumeration
/// (`mint_root_surface::production_supply_raising_root_set_is_exactly_mint`). The enumeration
/// proves WHICH roots are callable; this sweep proves the WRITE SITE topology: across the whole
/// local tree there is exactly one `token_supply` write, it is the RAISE, and the kernel mint
/// primitives live only in `xreserve_mint.masm`. Its tree-wide "exactly one" clauses
/// automatically police every new xreserve file forever — including the CMP-B1
/// `xreserve_mint_note_entry.masm` transport shim (which must carry NO supply write and NO mint
/// primitive). Must be GREEN.
#[test]
fn token_supply_raise_write_integrity_static_sweep() {
    let files = collect_xreserve_masm();

    // (1) the kernel mint primitives appear ONLY in xreserve_mint.masm.
    for primitive in ["exec.faucet::mint", "exec.faucet::create_fungible_asset"] {
        for (name, src) in &files {
            let hits = src.lines().filter(|l| l.contains(primitive)).count();
            if name == "xreserve_mint.masm" {
                assert!(
                    hits >= 1,
                    "xreserve_mint.masm must carry the supply primitive `{primitive}` (its mint site)"
                );
            } else {
                assert_eq!(
                    hits, 0,
                    "`{primitive}` is a supply-raising primitive and must NOT appear in {name} \
                     (only xreserve_mint.masm may raise supply, INV-MINT-SECURITY §5.2)"
                );
            }
        }
    }

    // (2) WRITE-SURFACE ENUMERATION: exactly ONE TOKEN_CONFIG_SLOT supply-write across the WHOLE
    // local tree (not one *file*) — robust to a second/smuggled write-back anywhere, incl. inside
    // xreserve_mint.masm or the CMP-B1 note-entry shim. Filter on `set_item` (not `get_item`) so
    // the supply READ is excluded.
    let mut writes: Vec<(String, usize)> = Vec::new();
    for (name, src) in &files {
        for (idx, line) in src.lines().enumerate() {
            if line.contains("set_item") && line.contains("TOKEN_CONFIG_SLOT") {
                writes.push((name.clone(), idx));
            }
        }
    }
    assert_eq!(
        writes.len(),
        1,
        "exactly one local TOKEN_CONFIG_SLOT supply-write must exist; saw: {writes:?}"
    );
    let (write_file, write_idx) = &writes[0];
    assert_eq!(
        write_file, "xreserve_mint.masm",
        "the sole local supply-write must be in xreserve_mint.masm; saw it in {write_file}"
    );

    // (3) DIRECTION bound to the write SITE: the nearest preceding non-comment code line must be
    // the known RAISE `loc_load.20 add` (a `sub`/other op feeding the write-back would be a
    // supply-LOWER). NOT a proc-wide no-`sub` rule — apply_mint_effects legitimately contains
    // `sub` (supply-cap headroom, amount math), so a proc-wide rule would false-positive.
    let mint_lines: Vec<&str> = files["xreserve_mint.masm"].lines().collect();
    let preceding = mint_lines[..*write_idx]
        .iter()
        .rev()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .expect("the supply-write must have a preceding code line");
    assert_eq!(
        preceding, "loc_load.20 add",
        "the sole supply-write must be fed by the RAISE `loc_load.20 add` (a `sub`/other op \
         feeding the write is a supply-LOWER); saw: {preceding:?}"
    );
}
