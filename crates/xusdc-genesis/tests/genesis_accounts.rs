//! Structural invariants of the built genesis faucet: nonce-one genesis form and the native-fee
//! rebinding.
//!
//! There is deliberately NO MockChain smoke test in this crate: a genesis account exists before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from the `.mac` file) belongs to `crates/xusdc-validation`.

mod common;

use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::Felt;
use miden_standards::account::fees::FeePolicyManager;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_genesis::accounts::build_faucet;
use xusdc_genesis::config::Role;

use crate::common::fixture_config;

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN
/// asset, and whose id equals the plain `build_account` id at the same seed — the genesis build
/// changes the fee binding and the nonce, never the identity.
#[test]
fn the_faucet_is_a_native_fee_genesis_account() {
    let config = fixture_config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert_eq!(
        faucet.nonce(),
        Felt::ONE,
        "a genesis faucet carries nonce one"
    );
    assert!(faucet.seed().is_none(), "a genesis faucet carries no seed");
    assert_eq!(
        faucet
            .storage()
            .get_item(FeePolicyManager::fee_asset_id_slot())
            .expect("the faucet installs the fee-asset slot"),
        AssetId::new_fungible(faucet.id()).to_word(),
        "the fee-asset slot must be rebound to the faucet's own asset",
    );

    // Rebuild the PLAIN (nonce-zero, operator-placeholder) account from the same inputs: the id
    // must match, proving the genesis build derived the id before the rebinding.
    let plain = XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(config.faucet.max_supply).expect("valid max_supply"))
        .token_supply(AssetAmount::new(config.faucet.token_supply).expect("valid token_supply"))
        .owner(config.role_id(Role::Owner))
        .attest_admin_holder(config.role_id(Role::AttestAdmin))
        .pauser_holder(config.role_id(Role::Pauser))
        .unpauser_holder(config.role_id(Role::Unpauser))
        .blocklist_manager_holder(config.role_id(Role::BlocklistManager))
        .fee_parameters(FeeParameters::new(
            config.role_id(Role::Operator),
            config.faucet.verification_base_fee,
        ))
        .domain(config.faucet.domain)
        .build()
        .expect("the builder must compose")
        .build_account(config.faucet.seed.as_bytes())
        .expect("the plain build must succeed");
    assert_eq!(
        faucet.id(),
        plain.id(),
        "the genesis faucet id must equal the plain build_account id at the same seed",
    );
}
