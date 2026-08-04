//! The component-level tripwire: the xreserve library's callable-root set is FROZEN
//! at the 3 sanctioned roots below, enumerated at the `@account_procedure`-filtered account
//! interface — so any new export (a potential new supply door) fails loudly.

mod support;

use std::collections::BTreeSet;

use anyhow::Result;
use miden_protocol::account::AccountProcedureRoot;
use support::*;

/// The frozen sanctioned callable-root set of the shipped `xreserve` library.
const FROZEN_CALLABLE_ROOTS: [&str; 3] = [
    "::xreserve::attester_admin::set_attester",
    "::xreserve::identifier_init::init_identifier",
    "::xreserve::mint_policy::check_policy",
];

/// The attestation mint policy's library path — the anchor by which the xreserve component is
/// located in the production component set.
const MINT_POLICY_PATH: &str = "xreserve::mint_policy::check_policy";

// PROCEDURE-ROOT SURFACE ENUMERATION
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
    let callable: BTreeSet<AccountProcedureRoot> =
        xreserve.procedures().map(|(root, _is_auth)| root).collect();

    // Resolve each frozen path to its MAST root and require SET-EQUALITY with the filtered
    // @account_procedure-annotated procedures any missing or extra annotation fails loudly.
    let frozen_roots: BTreeSet<AccountProcedureRoot> = FROZEN_CALLABLE_ROOTS
        .iter()
        .map(|path| {
            xreserve
                .get_procedure_root_by_path(path.trim_start_matches("::"))
                .expect("frozen path {path} must resolve in the xreserve library")
        })
        .collect();
    assert_eq!(
        callable, frozen_roots,
        "the FILTERED account-interface root set (@account_procedure) must equal the frozen \
         roots exactly — a missing annotation drops a sanctioned proc from the account, an extra \
         one opens an unsanctioned callable root"
    );
    Ok(())
}
