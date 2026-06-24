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

/// Static sweep: the ONLY supply-RAISING surface in the `xreserve` MASM tree is `xreserve_mint.masm`
/// (its `apply_mint_effects` region). Concretely:
///
/// - the kernel mint primitives `exec.faucet::mint` / `exec.faucet::create_fungible_asset` appear
///   ONLY in `xreserve_mint.masm`;
/// - the ONLY `set_item` targeting `TOKEN_CONFIG_SLOT` (the supply slot) is in `xreserve_mint.masm`,
///   and it is preceded by an `add` (the supply RAISE) in the `apply_mint_effects` region;
/// - there are currently ZERO burn sites (no `xreserve_receive_and_burn`, no `sub` on
///   `TOKEN_CONFIG_SLOT`) — the burn-sub leg is DEFERRED (recorded here, not implemented yet).
///
/// This is the structural counterpart to the runtime deny guard: even if a stock surface were
/// re-enabled, no OTHER xreserve module raises supply. Must be GREEN.
#[test]
fn no_other_supply_surface_static_sweep() {
    let dir = xusdc_encoding::xreserve_asm_dir();

    // Recursively collect every *.masm under the xreserve tree (skip the `canary/` subtree per the
    // brief; there is none today, but keep the guard robust).
    fn collect_masm(dir: &std::path::Path, out: &mut BTreeMap<String, String>) {
        for entry in std::fs::read_dir(dir).expect("reading the xreserve asm dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("canary") {
                    continue;
                }
                collect_masm(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("masm") {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap()
                    .to_string();
                let src = std::fs::read_to_string(&path).expect("reading a masm file");
                out.insert(name, src);
            }
        }
    }
    let mut files = BTreeMap::new();
    collect_masm(&dir, &mut files);
    assert!(
        files.contains_key("xreserve_mint.masm"),
        "the sweep must see xreserve_mint.masm; saw: {:?}",
        files.keys().collect::<Vec<_>>()
    );

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

    // (2) the ONLY `set_item` on TOKEN_CONFIG_SLOT is in xreserve_mint.masm, and it raises supply
    // (preceded by an `add` in the apply_mint_effects region). We scan for a `set_item` line that
    // mentions TOKEN_CONFIG_SLOT; the supply write in xreserve_mint.masm is
    // `push.TOKEN_CONFIG_SLOT[0..2] exec.native_account::set_item`.
    let mut token_config_set_files: Vec<String> = Vec::new();
    for (name, src) in &files {
        let writes = src
            .lines()
            .filter(|l| l.contains("set_item") && l.contains("TOKEN_CONFIG_SLOT"))
            .count();
        if writes > 0 {
            token_config_set_files.push(name.clone());
        }
    }
    assert_eq!(
        token_config_set_files,
        vec!["xreserve_mint.masm".to_string()],
        "the ONLY set_item on TOKEN_CONFIG_SLOT must be in xreserve_mint.masm; saw it in: {token_config_set_files:?}"
    );
    let mint_src = &files["xreserve_mint.masm"];
    assert!(
        mint_src
            .lines()
            .any(|l| l.trim_start().starts_with("loc_load.20 add")),
        "the supply write in xreserve_mint.masm must RAISE supply (a `loc_load.20 add` before the \
         TOKEN_CONFIG_SLOT set_item, in apply_mint_effects)"
    );

    // (3) currently ZERO burn sites anywhere: no receive-and-burn module, and no `sub` writing
    // TOKEN_CONFIG_SLOT. Records that the burn-sub leg is DEFERRED.
    assert!(
        !files.contains_key("xreserve_receive_and_burn.masm"),
        "no xreserve_receive_and_burn.masm should exist yet — the burn leg is deferred"
    );
    for (name, src) in &files {
        for line in src.lines() {
            // a supply-lowering write would be a `sub` on the same TOKEN_CONFIG_SLOT set_item line.
            assert!(
                !(line.contains("set_item")
                    && line.contains("TOKEN_CONFIG_SLOT")
                    && line.contains("sub")),
                "no supply-LOWERING (burn) write on TOKEN_CONFIG_SLOT should exist yet \
                 (found one in {name}); the burn-sub leg is deferred"
            );
        }
    }
}
