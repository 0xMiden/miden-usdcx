//! R-MINT-16 `XReserveStablecoinBuilder` API suite (P5-01): the production builder must compose a
//! deny-active PUBLIC faucet and reject the two packaging mistakes that would re-open the stock
//! mint surface — a non-`Public` account type and an active mint policy that is not the deny guard
//! (INV-MINT-SECURITY, §5.2). The build-validation tests assert the two rejections (pure builder
//! logic); the behavior test asserts a production-deny faucet actually traps stock `mint_and_send`
//! with the exact ERR_XRESERVE_MINT_DENIED, end to end.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent, AccountType, StorageMap, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::MintPolicyConfig;
use miden_testing::assert_transaction_executor_error;
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};

// Dummy faucet config words (the builder does not read them; they only bind the xreserve component's
// value slots so it assembles, exactly as the composition harness does).
const DUMMY_DOMAIN: u32 = 7;

/// Builds a fresh `(FungibleFaucet, AccountComponent)` pair from the assembled `xreserve` library —
/// the two inputs `XReserveStablecoinBuilder::new` consumes. The component carries the standard
/// 4-slot composition layout (so it binds) AND exports the deny-guard `check_policy` (so
/// `mint_deny_guard_root` resolves). A fresh pair per call because `new` takes them by value.
fn faucet_and_component() -> Result<(FungibleFaucet, AccountComponent)> {
    let library = assemble_xreserve_lib()?;
    let domain = Word::from([DUMMY_DOMAIN, 0, 0, 0]);
    let identifier = Word::from([11u32, 12, 13, 14]);
    let xreserve_component = AccountComponent::new(
        library,
        vec![
            StorageSlot::with_value(
                StorageSlotName::new(DOMAIN_CONFIG_SLOT_LABEL).context("domain slot label")?,
                domain,
            ),
            StorageSlot::with_value(
                StorageSlotName::new(IDENTIFIER_CONFIG_SLOT_LABEL)
                    .context("identifier slot label")?,
                identifier,
            ),
            StorageSlot::with_map(
                StorageSlotName::new(USED_NONCES_SLOT_LABEL).context("used_nonces slot label")?,
                StorageMap::new(),
            ),
            StorageSlot::with_map(
                StorageSlotName::new(XRESERVE_ATTESTERS_SLOT_LABEL)
                    .context("xReserveAttesters slot label")?,
                StorageMap::new(),
            ),
        ],
        AccountComponentMetadata::new("xusdc-builder-api-xreserve"),
    )
    .context("binding the xreserve library + composition slots as a component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("XUSDC")?)
        .symbol(TokenSymbol::new("XUSDC")?)
        .decimals(6)
        .max_supply(AssetAmount::new(1_000_000).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("invalid token_supply")?)
        .build()
        .context("failed to build FungibleFaucet")?;
    Ok((faucet, xreserve_component))
}

/// Dummy config for the behavior fixture (the production-deny faucet drives stock mint_and_send,
/// which does not read these).
fn dummy_config() -> (Word, Word) {
    (
        Word::from([DUMMY_DOMAIN, 0, 0, 0]),
        Word::from([11u32, 12, 13, 14]),
    )
}

// BUILD + BEHAVIOR — production deny faucet
// ================================================================================================

/// The production `build_components` composes a deny-active PUBLIC faucet without error (the
/// build-validation half). The BEHAVIOR half installs that exact production composition
/// (`GuardSelection::ProductionDeny`) and asserts the stock `mint_and_send` traps with the exact
/// ERR_XRESERVE_MINT_DENIED — i.e. the production deny composition genuinely denies, end to end.
#[tokio::test]
async fn build_produces_deny_active_public_faucet() -> Result<()> {
    // build-validation half: the default builder (Public + deny active) composes cleanly.
    let (faucet, xreserve_component) = faucet_and_component()?;
    let components = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2)).build_components();
    assert!(
        components.is_ok(),
        "the default production builder must compose a deny-active Public faucet: {:?}",
        components.err()
    );

    // behavior half: the production-deny faucet must deny stock mint_and_send.
    let (driver, probe) = {
        let driver = mint_composition_driver_src(&[Felt::from(0u32)], 60, 6);
        let probe = composition_supply_probe_src(0);
        (driver, probe)
    };
    let (domain, identifier) = dummy_config();
    let gm = setup_guarded_mint_account(
        GuardSelection::ProductionDeny,
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
    let result = run_mint_and_send(&gm.harness, Word::from([0u32, 1, 2, 3]), 0, 4, 100, 0).await;
    assert_transaction_executor_error!(result, shell_error_by_name("ERR_XRESERVE_MINT_DENIED"));
    Ok(())
}

// BUILD VALIDATION REJECTS (GREEN)
// ================================================================================================

/// A non-`Public` account type is rejected at build time (packaging cannot produce an unobservable
/// faucet). The non-public check runs before the guard resolution, so this fails fast. GREEN.
#[test]
fn build_rejects_non_public_account_type() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component()?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2))
        .account_type(AccountType::Private)
        .build_components()
        .expect_err("a non-Public account type must be rejected");
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::NonPublicAccountType(AccountType::Private)
        ),
        "expected NonPublicAccountType(Private), got {err:?}"
    );
    Ok(())
}

/// An active mint policy that is not the deny guard is rejected — packaging cannot silently drop the
/// deny guard (the only mint policy production allows). GREEN.
#[test]
fn build_rejects_missing_mint_deny_guard() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component()?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2))
        .with_active_mint_policy(MintPolicyConfig::AllowAll)
        .build_components()
        .expect_err("a non-deny active mint policy must be rejected");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MissingMintDenyGuard),
        "expected MissingMintDenyGuard, got {err:?}"
    );
    Ok(())
}

/// An immutable-`max_supply` faucet is rejected at build time: the stock `set_max_supply` admin
/// function would otherwise ship permanently dead (every call traps the runtime mutability gate). The
/// faucet here is otherwise valid (Public + deny active) and differs ONLY in mutability, so the guard
/// is the sole reason for rejection — and deleting the guard makes this build succeed (removal-based
/// non-vacuity). `faucet_and_component()` builds an IMMUTABLE faucet (no `.is_max_supply_mutable`),
/// exactly the misconfiguration the guard exists to reject.
#[test]
fn build_rejects_immutable_max_supply() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component()?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2))
        .build_components()
        .expect_err("an immutable-max-supply faucet must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::ImmutableMaxSupply),
        "expected ImmutableMaxSupply, got {err:?}"
    );
    Ok(())
}
