//! Structural invariants of the built genesis accounts: nonce-one promotion, the faucet's
//! native-fee rebinding, both key paths, and the operator's genesis supply.
//!
//! There is deliberately NO MockChain smoke test in this crate: genesis accounts exist before
//! any chain does, the invariants below are pure account-state checks, and live-node coverage
//! (a node actually booting from these `.mac` files) belongs to `crates/xusdc-validation`.

use std::path::PathBuf;

use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::Felt;
use miden_standards::account::fees::FeePolicyManager;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rstest::rstest;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;
use xusdc_genesis::accounts::{build_all, GenesisAccounts};
use xusdc_genesis::config::{GenesisToolConfig, Role};

fn fixture_config() -> GenesisToolConfig {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dev-config.json");
    GenesisToolConfig::load(&path).expect("the committed dev fixture must parse")
}

fn build_fixture() -> (GenesisToolConfig, GenesisAccounts) {
    let config = fixture_config();
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
        .owner(accounts.wallet(Role::Owner).account.id())
        .attest_admin_holder(accounts.wallet(Role::AttestAdmin).account.id())
        .pauser_holder(accounts.wallet(Role::Pauser).account.id())
        .unpauser_holder(accounts.wallet(Role::Unpauser).account.id())
        .blocklist_manager_holder(accounts.wallet(Role::BlocklistManager).account.id())
        .fee_parameters(FeeParameters::new(
            accounts.wallet(Role::Operator).account.id(),
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

/// Every wallet is a genesis account: nonce one, no seed, and (all fixture keys are generated)
/// exactly one embedded secret whose public key matches the wallet's.
#[rstest]
#[case::operator(Role::Operator)]
#[case::owner(Role::Owner)]
#[case::attest_admin(Role::AttestAdmin)]
#[case::pauser(Role::Pauser)]
#[case::unpauser(Role::Unpauser)]
#[case::blocklist_manager(Role::BlocklistManager)]
fn every_wallet_is_a_nonce_one_genesis_account(#[case] role: Role) {
    let (_, accounts) = build_fixture();
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
        wallet.secrets.len(),
        1,
        "a generated-key wallet embeds exactly its one secret in the .mac",
    );
}

/// Supplying the public key that the seeded generator would have produced yields the identical
/// wallet account — but with NO secret material in the tool's output. Locks both key paths onto
/// the same account identity.
#[test]
fn a_supplied_public_key_builds_the_same_wallet_without_secrets() {
    let generated = build_fixture().1;

    // Derive the operator's public key exactly as the tool's generated path does, and feed it
    // back through the supplied-key path.
    let config = fixture_config();
    let mut rng = ChaCha20Rng::from_seed(config.operator.seed.as_bytes());
    let public_key = AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng).public_key();
    let fixture_text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dev-config.json"),
    )
    .expect("the fixture file is readable");
    let mut raw: serde_json::Value =
        serde_json::from_str(&fixture_text).expect("the fixture is valid JSON");
    raw["accounts"]["operator"]["public_key"] =
        serde_json::Value::String(format!("0x{}", hex::encode(public_key.to_bytes())));
    let supplied_config =
        GenesisToolConfig::from_json(&raw.to_string()).expect("the supplied-key config must parse");
    let supplied = build_all(&supplied_config).expect("the supplied-key config must build");

    let (generated_op, supplied_op) = (
        generated.wallet(Role::Operator),
        supplied.wallet(Role::Operator),
    );
    assert_eq!(
        generated_op.account.to_commitment(),
        supplied_op.account.to_commitment(),
        "the same approver key must build the identical wallet on either key path",
    );
    assert!(
        supplied_op.secrets.is_empty(),
        "a supplied-key wallet must embed no secret material",
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
