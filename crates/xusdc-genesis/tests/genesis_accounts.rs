//! Structural invariants of the built genesis faucet: nonce-one genesis form and the native-fee
//! rebinding.
//!
//! There is deliberately NO MockChain smoke test in this crate: a genesis account exists before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from the `.mac` file) belongs to `crates/xusdc-validation`.

mod common;

use miden_protocol::account::StorageMapKey;
use miden_protocol::asset::AssetId;
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::FeePolicyManager;
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_genesis::accounts::build_faucet;

use crate::common::Fixture;

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN
/// asset.
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

/// The built faucet records every configured deposit nonce as consumed.
#[test]
fn the_configured_used_nonces_are_recorded_as_consumed() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");

    assert!(
        !config.faucet.used_nonces.is_empty(),
        "the fixture must exercise a non-empty nonce list",
    );
    for nonce in &config.faucet.used_nonces {
        assert_eq!(
            faucet
                .storage()
                .get_map_item(
                    XReserveFaucetExtension::used_nonces_slot(),
                    nonce.to_storage_map_key(),
                )
                .expect("the faucet installs the nonce registry slot"),
            Word::from([1u32, 0, 0, 0]),
            "the built faucet must record every configured nonce as consumed",
        );
    }
}
