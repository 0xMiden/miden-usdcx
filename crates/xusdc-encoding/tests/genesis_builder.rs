//! Invariant tests for `XReserveStablecoinBuilder::build_genesis_account` — the genesis-only
//! native-fee-faucet build beside the byte-identity suite.
//!
//! The genesis build must reuse the plain `build_account` identity (the id is derived while the
//! fee parameters still carry the operator placeholder), then rebind the fee-asset slot to the
//! faucet's OWN asset, record the listed nonces as consumed, and promote the account to nonce one
//! with no seed. A forgotten rebinding or a drifted id fails here.

mod support;

use miden_protocol::asset::AssetId;
use miden_protocol::Felt;
use miden_standards::account::fees::FeePolicyManager;
use support::mint_transport::{marker, read_map_word};
use support::{production_builder, test_fee_faucet_id, TEST_DOMAIN};
use xusdc_encoding::account::xreserve::XReserveFaucetExtension;
use xusdc_encoding::xreserve::encoding::DepositNonce;

/// The fixed account seed, matching the byte-identity suite's anchor seed.
const SEED: [u8; 32] = [7u8; 32];
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 0;

/// The genesis build keeps the plain build's id, carries nonce one and no seed, and its
/// fee-asset slot is rebound from the operator placeholder to the faucet's own asset.
#[test]
fn genesis_build_rebinds_the_fee_asset_and_promotes_to_nonce_one() {
    let builder = production_builder(MAX_SUPPLY, TOKEN_SUPPLY, TEST_DOMAIN)
        .expect("the production builder must construct");
    let genesis = builder
        .build_genesis_account(SEED, &[])
        .expect("the genesis build must succeed");
    let plain = builder
        .build_account(SEED)
        .expect("the plain build must succeed");

    assert_eq!(
        genesis.id(),
        plain.id(),
        "the genesis build must not change the seed-derived account id",
    );
    assert_eq!(
        genesis.nonce(),
        Felt::ONE,
        "a genesis account must carry nonce one (it exists at genesis, it is not deployed)",
    );
    assert!(
        genesis.seed().is_none(),
        "a genesis account must carry no seed (it cannot be deployed in a transaction)",
    );

    let fee_slot = FeePolicyManager::fee_asset_id_slot();
    assert_eq!(
        genesis
            .storage()
            .get_item(fee_slot)
            .expect("the genesis account installs the fee-asset slot"),
        AssetId::new_fungible(genesis.id()).to_word(),
        "the genesis fee-asset slot must hold the faucet's OWN asset (the native fee faucet)",
    );
    // The plain build still holds the operator placeholder, proving the genesis path performed
    // an actual rebinding rather than the grind already using the final value.
    assert_eq!(
        plain
            .storage()
            .get_item(fee_slot)
            .expect("the plain account installs the fee-asset slot"),
        AssetId::new_fungible(test_fee_faucet_id()).to_word(),
        "the plain build must keep the placeholder fee asset the id was ground with",
    );
}

/// The genesis build records every listed nonce as consumed without changing the account id.
#[test]
fn genesis_build_records_the_used_nonces_and_keeps_the_id() {
    let builder = production_builder(MAX_SUPPLY, TOKEN_SUPPLY, TEST_DOMAIN)
        .expect("the production builder must construct");
    let consumed = DepositNonce::new([0x55; 32]);
    let genesis = builder
        .build_genesis_account(SEED, &[consumed])
        .expect("the genesis build must succeed");
    let plain = builder
        .build_account(SEED)
        .expect("the plain build must succeed");

    assert_eq!(
        genesis.id(),
        plain.id(),
        "recording a consumed nonce must not change the account id",
    );
    let slot = XReserveFaucetExtension::used_nonces_slot();
    assert_eq!(
        read_map_word(&genesis, slot, consumed.to_word()).expect("the registry slot exists"),
        marker(),
        "a listed nonce must carry the consumed marker",
    );
}
