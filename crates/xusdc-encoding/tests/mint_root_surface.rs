//! XRESERVE COMPONENT CALLABLE-ROOT PIN (F1 lineage, recut by the Wave-1 S1 recomposition). The
//! core invariant — mintable ONLY with a valid Circle Deposit Attestation — is carried by the
//! composition since the recomposition: the ONLY supply-raising account procedure is the STOCK
//! `fungible_faucet::mint_and_send`, and every invocation passes the ACTIVE attestation mint
//! policy (`xreserve::mint_policy::check_policy`) — the posture proven end-to-end in
//! `wave1_recomposition.rs` / `mint_policy_e2e.rs`. The bespoke mint transport the original F1
//! demotion policed (`xreserve_mint::mint`, its `apply_mint_effects` write stage, the
//! `receive_and_mint` note-entry shim) is DELETED, so the former executing exploit legs (an
//! external `call` of the demoted `apply_mint_effects` root; the effects-public re-assembly)
//! dissolved with their subject — there is no bespoke effects surface left to demote.
//!
//! What stays is the component-level tripwire: the xreserve library's callable-root set is FROZEN
//! at the 15 sanctioned roots below, enumerated at BOTH layers — the manifest's exported paths and
//! the `@account_procedure`-filtered account interface — so any new export (a potential new
//! supply door) fails loudly.

mod support;

use anyhow::Result;
use miden_protocol::Word;
use support::*;

/// The frozen sanctioned callable-root set of the shipped `xreserve` library after the Wave-1 S1
/// recomposition: the shared-encoding + parser + attestation procs, the admin wrappers
/// (`attester_admin::set_attester`, `pause_admin::{pause,unpause}`, and the two F4-reversal
/// `blocklist_admin::{block_account,unblock_account}` BLK_MANAGER-gated wrappers), the attestation
/// mint policy `mint_policy::check_policy` (the ACTIVE mint policy — a pure gate, no supply
/// arithmetic of its own), and the minimized DEC-4 `identifier_init::init_identifier`
/// (owner-gated, init-once) = 15. The custom transport/burn/config roots of the pre-slice set
/// (`xreserve_mint::mint`, `xreserve_mint_note_entry::receive_and_mint`,
/// `mint_deny_guard::check_policy`, `burn_policy::check_policy`,
/// `min_burn_admin::set_min_burn_size`, `domain_config::domain_init`) are DELETED with their
/// modules. NO xreserve root raises supply — the sole supply-raising procedure is the stock
/// `mint_and_send`, gated by the attestation policy. Any drift (a new export, i.e. a potential
/// new supply door) trips `production_xreserve_callable_root_set_is_frozen`.
/// Paths render absolute (leading `::`) at assembler 0.23.3.
const FROZEN_CALLABLE_ROOTS: [&str; 15] = [
    "::xreserve::attestation_verify::verify_attestation",
    "::xreserve::attester_admin::set_attester",
    "::xreserve::blocklist_admin::block_account",
    "::xreserve::blocklist_admin::unblock_account",
    "::xreserve::deposit_intent_parser::assert_deposit_intent",
    "::xreserve::deposit_intent_parser::assert_mint_amounts",
    "::xreserve::deposit_intent_parser::assert_nonce_unused",
    "::xreserve::encoding::bytes32_to_key",
    "::xreserve::encoding::parse_deposit_intent",
    "::xreserve::encoding::pubkey_commitment",
    "::xreserve::encoding::uint256_to_asset_amount",
    "::xreserve::identifier_init::init_identifier",
    "::xreserve::mint_policy::check_policy",
    "::xreserve::pause_admin::pause",
    "::xreserve::pause_admin::unpause",
];

/// The attestation mint policy's library path — the anchor by which the xreserve component is
/// located in the production component set.
const MINT_POLICY_PATH: &str = "xreserve::mint_policy::check_policy";

// PROCEDURE-ROOT SOLE-SURFACE ENUMERATION (the two-layer frozen tripwire)
// ================================================================================================

#[test]
fn production_xreserve_callable_root_set_is_frozen() -> Result<()> {
    let components = production_component_set(1_000_000, 0)?;

    // the xreserve component is the one that exports the attestation mint policy.
    let xreserve = components
        .iter()
        .find(|c| c.get_procedure_root_by_path(MINT_POLICY_PATH).is_some())
        .expect("a production component must export xreserve::mint_policy::check_policy");

    // the account's callable procedure roots (the code-commitment membership set).
    let callable: std::collections::BTreeSet<Word> = xreserve
        .procedures()
        .map(|(root, _is_auth)| Word::from(root))
        .collect();

    // Frozen tripwire, source layer: the exported-proc set is EXACTLY the 15 sanctioned roots.
    let lib: &miden_protocol::assembly::Library = xreserve.component_code().as_ref();
    let mut paths: Vec<String> = lib
        .manifest
        .exports()
        .filter(|e| e.is_procedure())
        .map(|e| e.path().to_string())
        .collect();
    paths.sort();
    let mut expected: Vec<String> = FROZEN_CALLABLE_ROOTS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    expected.sort();
    assert_eq!(
        paths, expected,
        "the xreserve callable-root set drifted from the frozen sanctioned set (a new export is a \
         potential new supply door)"
    );

    // Frozen tripwire, INTERFACE layer (v16 — MIGRATION-V16-ALPHA2.md S19): at alpha.2 the
    // account interface is FILTERED by `@account_procedure` (`AccountComponentCode::exports`),
    // while the raw `Library::exports()` above still lists every `pub proc` regardless of the
    // attribute — so a missing annotation would leave the path-level compare green while the
    // procedure silently vanished from the account. Resolve each frozen path to its MAST root
    // and require SET-EQUALITY with the filtered interface (`callable`, computed above from
    // `xreserve.procedures()`): any missing or extra annotation fails loudly.
    let frozen_roots: std::collections::BTreeSet<Word> = FROZEN_CALLABLE_ROOTS
        .iter()
        .map(|path| {
            Word::from(
                xreserve
                    .get_procedure_root_by_path(path.trim_start_matches("::"))
                    .unwrap_or_else(|| {
                        panic!("frozen path {path} must resolve in the xreserve library")
                    }),
            )
        })
        .collect();
    assert_eq!(
        callable, frozen_roots,
        "the FILTERED account-interface root set (@account_procedure) must equal the 15 frozen \
         roots exactly — a missing annotation drops a sanctioned proc from the account, an extra \
         one opens an unsanctioned callable root"
    );
    Ok(())
}
