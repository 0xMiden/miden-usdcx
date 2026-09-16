//! Structural invariants of the built genesis faucet: nonce-one genesis form and the native-fee
//! rebinding.
//!
//! There is deliberately NO MockChain smoke test in this crate: a genesis account exists before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from the `.mac` file) belongs to `crates/xusdc-validation`.

mod common;

use miden_protocol::account::StorageMapKey;
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::FeePolicyManager;
use xusdc_encoding::account::xreserve::{XReserveFaucetExtension, XReserveStablecoinBuilder};
use xusdc_genesis::accounts::{build_faucet, placeholder_fee_faucet_id};
use xusdc_genesis::config::Role;

use crate::common::Fixture;

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN
/// asset, and whose id equals the plain `build_account` id at the same seed — the genesis build
/// changes the fee binding and the nonce, never the identity.
#[test]
fn the_faucet_is_a_native_fee_genesis_account() {
    let fixture = Fixture::new();
    let config = fixture.config();
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

    // Rebuild the PLAIN (nonce-zero, placeholder-fee) account from the same inputs: the id
    // must match, proving the genesis build derived the id before the fee-asset swap.
    let plain = XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(config.faucet.max_supply).expect("valid max_supply"))
        .token_supply(AssetAmount::new(config.faucet.token_supply).expect("valid token_supply"))
        .owner(config.account_id(Role::Owner))
        .attest_admin_holder(config.account_id(Role::AttestAdmin))
        .pauser_holder(config.account_id(Role::Pauser))
        .unpauser_holder(config.account_id(Role::Unpauser))
        .blocklist_manager_holder(config.account_id(Role::BlocklistManager))
        .fee_parameters(FeeParameters::new(
            placeholder_fee_faucet_id(),
            config.faucet.verification_base_fee,
        ))
        .domain(config.faucet.domain)
        .attesters(config.faucet.attesters.clone())
        .build()
        .expect("the builder must compose")
        .build_account(config.faucet.seed)
        .expect("the plain build must succeed");
    assert_eq!(
        faucet.id(),
        plain.id(),
        "the genesis faucet id must equal the plain build_account id at the same seed",
    );
}

/// The built faucet carries an enabled attester-allowlist row for every configured key.
#[test]
fn the_configured_attesters_are_allowlisted_in_storage() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert!(
        !config.faucet.attesters.is_empty(),
        "the fixture must exercise a non-empty allowlist",
    );
    for key in &config.faucet.attesters {
        assert_eq!(
            faucet
                .storage()
                .get_map_item(
                    XReserveFaucetExtension::xreserve_attesters_slot(),
                    StorageMapKey::new(key.to_commitment()),
                )
                .expect("the faucet installs the attester allowlist slot"),
            Word::from([1u32, 0, 0, 0]),
            "the built faucet must carry the enabled row for every configured attester",
        );
    }
}
