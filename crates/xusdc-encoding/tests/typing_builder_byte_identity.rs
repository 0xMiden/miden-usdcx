//! Builder byte-identity suite — the HARD GATE for the enforce-by-construction builder changes
//! (drop the one-valued `xreserve_component` parameter, enforce max-supply mutability at
//! construction, and the crate-root faucet `Account` constructor).
//!
//! Every change here is wire-neutral: the composed account must be byte-for-byte what the
//! pre-change composition produced. This suite freezes the baseline composition's anchors — the
//! account's `initial_commitment`, its code commitment, a digest over its storage slots, and the
//! seed-derived id — captured at a FIXED seed from the baseline path, and asserts:
//!
//! 1. the crate-root `build_faucet_account` constructor reproduces them EXACTLY (the faucet it
//!    builds is `is_max_supply_mutable(true)`, so `set_max_supply` stays operable),
//! 2. the component path (`build_components` + the auth component, now with the builder assembling
//!    its own xreserve component) still reproduces them, and
//! 3. the two paths agree with each other.
//!
//! A single felt or byte of drift — a reordered component, a changed slot value, a different
//! assembled MAST root — flips one of these string-exact assertions RED.

mod support;

use miden_protocol::account::{Account, AccountType, AssetCallbackFlag, StorageSlotName};
use miden_protocol::asset::{AssetAmount, AssetCallbacks};
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Hasher, Word};
use support::*;
use xusdc_encoding::account::xreserve::{build_faucet_account, XReserveStablecoinBuilder};
use xusdc_encoding::xreserve::encoding::EthBytes32;

/// The fixed account seed the anchors were captured at (production uses a random seed; a fixed one
/// makes the seed-derived id and the whole account commitment deterministic).
const SEED: [u8; 32] = [7u8; 32];
const MAX_SUPPLY: u64 = 1_000_000;
const TOKEN_SUPPLY: u64 = 0;

// The baseline composition anchors, as their stable `Debug`/`Display` renderings (captured from the
// pre-change composition at SEED). Comparing the rendered strings sidesteps any felt-repr ambiguity.
//
// Re-materialized at the v0.16.0-rc.3 protocol bump. Three of the four anchors moved with it — the
// code commitment because six of the account's procedure roots moved (the fungible mint/burn
// dispatch rewrite moved `mint_and_send`/`receive_and_burn`; the network-account
// `auth_network_transaction` moved with the added sponsorship-policy/fee-asset enforcement; the
// upstream sweep moved `get_min_burn_amount` and the transfer-policy check; and `check_policy`
// moved because this migration edits `attestation_verify`, which it invokes); the storage digest
// because TWO things changed under it — the active mint-policy root moved (it is stored as
// `check_policy`'s MAST root) AND the rc.3 bump ADDED the `sponsor_at_most_collected_fees` slot
// (54 -> 55); and the initial commitment because it covers both. The account id did NOT move —
// which says only that the SEED-DERIVED IDENTITY is untouched; it does NOT say the slot layout is
// unchanged (the layout demonstrably gained that one slot). `check_policy` is measured here against
// the migration's fail-closed signature-verify stand-in; the later ECDSA-rebuild slice rewrites
// `attestation_verify`, so these three anchors MOVE AGAIN and must be re-materialized a second time
// then.
const GOLDEN_INITIAL_COMMITMENT: &str =
    "Word([223451725513909618, 9972382910206474275, 6729040912275203006, 2954999722093273053])";
const GOLDEN_CODE_COMMITMENT: &str =
    "Word([6071254445460505704, 12653310514341131241, 4080738568322131054, 12639662269255750522])";
const GOLDEN_STORAGE_DIGEST: &str =
    "Word([15954610800434419326, 6451156305011702001, 3091154321168034928, 9029760994496162649])";
const GOLDEN_ACCOUNT_ID: &str = "0x070707060707073107070707070707";

/// A deterministic digest over the account's storage slots (name + serialized slot), so a
/// storage-only drift is caught independently of the code commitment.
fn storage_digest(account: &Account) -> Word {
    let mut bytes = Vec::new();
    for slot in account.storage().slots() {
        bytes.extend_from_slice(&slot.to_bytes());
    }
    Hasher::hash(&bytes)
}

/// Asserts an account matches every frozen anchor.
fn assert_matches_golden(account: &Account, path: &str) {
    assert_eq!(
        format!("{}", account.id()),
        GOLDEN_ACCOUNT_ID,
        "{path}: seed-derived account id drifted",
    );
    assert_eq!(
        format!("{:?}", account.initial_commitment()),
        GOLDEN_INITIAL_COMMITMENT,
        "{path}: account initial commitment drifted (code, storage, id or type changed)",
    );
    assert_eq!(
        format!("{:?}", account.code().commitment()),
        GOLDEN_CODE_COMMITMENT,
        "{path}: account code commitment drifted (a procedure root moved)",
    );
    assert_eq!(
        format!("{:?}", storage_digest(account)),
        GOLDEN_STORAGE_DIGEST,
        "{path}: account storage drifted (a slot value or layout changed)",
    );
}

/// Composes the account the baseline way: `build_components` + the production auth component, at the
/// fixed seed, with the asset-callback flag derived from the composition (as the deploy path does).
fn account_via_component_path() -> Account {
    let components = production_component_set(MAX_SUPPLY, TOKEN_SUPPLY)
        .expect("the production composition must build");
    let has_callbacks = components.iter().any(|c| {
        c.storage_slots().iter().any(|s| {
            s.name() == AssetCallbacks::on_before_asset_added_to_note_slot()
                || s.name() == AssetCallbacks::on_before_asset_added_to_account_slot()
        })
    });
    let flag = if has_callbacks {
        AssetCallbackFlag::Enabled
    } else {
        AssetCallbackFlag::Disabled
    };
    let mut builder = Account::builder(SEED)
        .account_type(AccountType::Public)
        .with_asset_callbacks(flag);
    for component in components {
        builder = builder.with_component(component);
    }
    builder = builder.with_components(
        XReserveStablecoinBuilder::auth_component().expect("the auth component must build"),
    );
    builder
        .build_existing()
        .expect("the baseline-style composition must build the account")
}

/// Composes the account through the crate-root `build_faucet_account` constructor, at the
/// same fixed seed and the same domain-config / role inputs the component path uses.
fn account_via_crate_root_constructor() -> Account {
    build_faucet_account(
        SEED,
        AssetAmount::new(MAX_SUPPLY).expect("max supply is a valid asset amount"),
        AssetAmount::new(TOKEN_SUPPLY).expect("token supply is a valid asset amount"),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        EthBytes32::new(test_xreserve_contract()),
    )
    .expect("the crate-root faucet-account constructor must build the account")
}

/// The crate-root faucet-account constructor reproduces the baseline composition
/// byte-for-byte.
#[test]
fn crate_root_constructor_is_byte_identical_to_baseline() {
    assert_matches_golden(
        &account_via_crate_root_constructor(),
        "build_faucet_account",
    );
}

/// The component path (`build_components` + auth, with the builder now assembling its own xreserve
/// component) still reproduces the baseline composition byte-for-byte.
#[test]
fn component_path_is_byte_identical_to_baseline() {
    assert_matches_golden(&account_via_component_path(), "component-path");
}

/// The two construction paths agree with each other — the crate-root constructor is a faithful
/// wrapper over the component composition + auth, not a second, subtly-different assembly.
#[test]
fn the_two_construction_paths_agree() {
    let via_ctor = account_via_crate_root_constructor();
    let via_components = account_via_component_path();
    assert_eq!(
        format!("{:?}", via_ctor.initial_commitment()),
        format!("{:?}", via_components.initial_commitment()),
        "the crate-root constructor and the component path must compose the identical account",
    );
    assert_eq!(
        format!("{:?}", storage_digest(&via_ctor)),
        format!("{:?}", storage_digest(&via_components)),
        "the two paths must produce identical storage",
    );
}

/// xUSDC is a policed asset: the composition installs the transfer-policy callback slots, so the
/// crate-root constructor must build the account with the Enabled asset-callback flag (a Disabled
/// flag would silently never fire the blocklist callbacks). Locks the constructor's flag derivation.
#[test]
fn crate_root_account_carries_the_policed_asset_callback_flag() {
    let account = account_via_crate_root_constructor();
    assert_eq!(
        account.id().asset_callback_flag(),
        AssetCallbackFlag::Enabled,
        "the crate-root constructor must build a policed-asset faucet (Enabled callback flag)",
    );
}

/// Enforce-by-construction (16b): the crate-root constructor builds the faucet with a MUTABLE
/// `max_supply`, so the deployed `set_max_supply` admin function stays operable. This is the POSITIVE
/// lock that replaces the removed `ImmutableMaxSupply` runtime reject — a constructor that built the
/// faucet immutable would flip the flag felt and fail here. The `mutability_config` word layout is
/// `[is_desc, is_logo, is_extlink, is_max_supply]`, so the max-supply flag is element 3.
#[test]
fn crate_root_faucet_max_supply_is_mutable_by_construction() {
    const MUTABILITY_CONFIG_SLOT: &str = "miden::standards::faucets::mutability_config";
    const MAX_SUPPLY_MUTABLE_INDEX: usize = 3;
    let account = account_via_crate_root_constructor();
    let name = StorageSlotName::new(MUTABILITY_CONFIG_SLOT)
        .expect("the mutability_config slot name is valid");
    let slot = account
        .storage()
        .slots()
        .iter()
        .find(|slot| slot.name() == &name)
        .expect("the composed faucet installs its mutability_config slot");
    assert_eq!(
        slot.value()[MAX_SUPPLY_MUTABLE_INDEX],
        Felt::from(1u32),
        "the crate-root faucet must be built is_max_supply_mutable(true) (16b enforce-by-construction)",
    );
}
