//! Structural invariants of the built genesis accounts: nonce-one promotion of the provided
//! wallets, the faucet's native-fee rebinding, and the operator's genesis supply.
//!
//! There is deliberately NO MockChain smoke test in this crate: genesis accounts exist before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from these `.mac` files) belongs to `crates/xusdc-validation`.

mod common;

use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::Felt;
use miden_standards::account::fees::FeePolicyManager;
use rstest::rstest;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_genesis::accounts::{build_all, GenesisAccounts};
use xusdc_genesis::config::{GenesisToolConfig, Role};

use crate::common::Fixture;

fn build_fixture() -> (GenesisToolConfig, GenesisAccounts) {
    let fixture = Fixture::new();
    let config = fixture.config();
    let accounts = build_all(&config).expect("the dev fixture must build");
    (config, accounts)
}

/// The faucet is a genesis account (nonce one, no seed) whose fee-asset slot holds its OWN
/// asset, and whose id equals the plain `build_account` id at the same seed — the genesis build
/// changes the fee binding and the nonce, never the identity.
#[test]
fn the_faucet_is_a_native_fee_genesis_account() {
    let (config, accounts) = build_fixture();
    let faucet = &accounts.faucet;

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
        .owner(config.provided(Role::Owner).account().id())
        .attest_admin_holder(config.provided(Role::AttestAdmin).account().id())
        .pauser_holder(config.provided(Role::Pauser).account().id())
        .unpauser_holder(config.provided(Role::Unpauser).account().id())
        .blocklist_manager_holder(config.provided(Role::BlocklistManager).account().id())
        .fee_parameters(FeeParameters::new(
            config.provided(Role::Operator).account().id(),
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

/// Every provided wallet is normalized to a genesis account: nonce one, no seed, the id
/// unchanged from the provided account, and the provided file's secret keys passed through.
#[rstest]
#[case::operator(Role::Operator)]
#[case::owner(Role::Owner)]
#[case::attest_admin(Role::AttestAdmin)]
#[case::pauser(Role::Pauser)]
#[case::unpauser(Role::Unpauser)]
#[case::blocklist_manager(Role::BlocklistManager)]
fn every_wallet_is_a_nonce_one_genesis_account(#[case] role: Role) {
    let (config, accounts) = build_fixture();
    let wallet = accounts.wallet(role);
    assert_eq!(
        wallet.account.nonce(),
        Felt::ONE,
        "the {} wallet must carry nonce one",
        role.as_str(),
    );
    assert!(
        wallet.account.seed().is_none(),
        "the {} wallet must carry no seed",
        role.as_str(),
    );
    assert_eq!(
        wallet.account.id(),
        config.provided(role).account().id(),
        "promotion must never change the {} wallet's id",
        role.as_str(),
    );
    assert_eq!(
        wallet.secrets.len(),
        1,
        "the fixture embeds one secret per wallet, passed through into the .mac",
    );
}

/// The operator's genesis vault holds exactly the faucet's initial `token_supply` of the
/// faucet's own asset (the genesis circulating supply equals the issued-supply tracker), and no
/// other wallet holds anything.
#[test]
fn the_operator_vault_matches_the_initial_supply() {
    let (config, accounts) = build_fixture();
    let faucet_asset = AssetId::new_fungible(accounts.faucet.id());

    let operator = accounts.wallet(Role::Operator);
    assert_eq!(
        operator
            .account
            .vault()
            .get_balance(faucet_asset)
            .expect("the operator vault holds the faucet asset")
            .as_u64(),
        config.faucet.token_supply,
        "the operator must hold exactly the genesis token_supply",
    );

    for role in Role::ALL.into_iter().filter(|role| *role != Role::Operator) {
        assert_eq!(
            accounts.wallet(role).account.vault().assets().count(),
            0,
            "the {} wallet's genesis vault must be empty",
            role.as_str(),
        );
    }
}
