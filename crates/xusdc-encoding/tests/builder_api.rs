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
use miden_standards::account::access::{PausableManager, PausableStorage};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicyConfig, MintPolicyConfig};
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
/// `is_max_supply_mutable` selects the faucet's stock mutability flag: production builds pass `true`
/// (the builder now rejects immutable `max_supply`); the rejection tests whose own check fires first
/// (non-public / missing-deny) and the immutable-rejection test pass `false`.
fn faucet_and_component(is_max_supply_mutable: bool) -> Result<(FungibleFaucet, AccountComponent)> {
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
        .is_max_supply_mutable(is_max_supply_mutable)
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
    // build-validation half: the default builder (Public + deny active, mutable max_supply) composes
    // cleanly.
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2), test_account_id(3)).build_components();
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
        true,
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
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2), test_account_id(3))
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
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2), test_account_id(3))
        .with_active_mint_policy(MintPolicyConfig::AllowAll)
        .build_components()
        .expect_err("a non-deny active mint policy must be rejected");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MissingMintDenyGuard),
        "expected MissingMintDenyGuard, got {err:?}"
    );
    Ok(())
}

/// An active burn policy that is not the installed `burn_policy::check_policy` is rejected (the
/// burn-slot twin of [`build_rejects_missing_mint_deny_guard`]): packaging cannot drop the burn
/// security predicate (CMP-A10, R-BURN-1/2). The faucet is otherwise valid (Public + deny mint active +
/// mutable max_supply) so the burn guard is the SOLE reason for rejection — removing the guard makes
/// this build succeed (removal-based non-vacuity).
#[test]
fn denies_non_policy_burn() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let result = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .with_active_burn_policy(BurnPolicyConfig::AllowAll)
    .build_components();
    assert!(
        matches!(result, Err(XReserveStablecoinBuilderError::MissingBurnPolicyGuard)),
        "production build_components must reject an AllowAll active burn policy with \
         MissingBurnPolicyGuard (the burn-slot twin of MissingMintDenyGuard); got Ok/other: {:?}",
        result.as_ref().map(|c| c.len())
    );
    Ok(())
}

/// An immutable-`max_supply` faucet is rejected at build time: the stock `set_max_supply` admin
/// function would otherwise ship permanently dead (every call traps the runtime mutability gate). The
/// faucet here is otherwise valid (Public + deny active) and differs ONLY in mutability, so the guard
/// is the sole reason for rejection — and deleting the guard makes this build succeed (removal-based
/// non-vacuity). `faucet_and_component(false)` builds an IMMUTABLE faucet, exactly the misconfiguration
/// the guard exists to reject.
#[test]
fn build_rejects_immutable_max_supply() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = XReserveStablecoinBuilder::new(faucet, xreserve_component, test_account_id(1), test_account_id(2), test_account_id(3))
        .build_components()
        .expect_err("an immutable-max-supply faucet must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::ImmutableMaxSupply),
        "expected ImmutableMaxSupply, got {err:?}"
    );
    Ok(())
}

// PRODUCTION minBurnSize SEEDING (P5-01 CMP-A10, plan §3.2/§5)
// ================================================================================================

/// Production `build_components` SEEDS the minBurnSize config slot
/// (`xusdc::xreserve::attester_admin::min_burn_size` = `[min_burn_size, 0, 0, 0]`) so the burn policy's
/// R-BURN-2 read resolves on a real production faucet — the builder owns a `min_burn_size`
/// default/override and binds the slot onto the xreserve component (the future CMP-F2 `set_min_burn_size`
/// co-owns the SAME slot). The expected value uses the canonical full-u64 `AssetAmount -> Felt`, so an
/// `as u32` truncation in the seed would fail this test (see the MIN_BURN choice below).
#[test]
fn production_seeds_min_burn_size() -> Result<()> {
    // Anti-truncation: minBurnSize is a FULL `u64` `AssetAmount` (plan §3.2; `AssetAmount::MAX` =
    // 2^63 - 2^31), encoded as `[min_burn_size, 0, 0, 0]`. MIN_BURN is chosen > `u32::MAX` so any
    // `... as u32` truncation — in the seed (green) OR in this expectation — yields a DIFFERENT `Felt`
    // and fails the test, rather than two sides silently agreeing on a truncated low-32-bit value.
    const MIN_BURN: u64 = 5_000_000_000; // > u32::MAX (4_294_967_295), well within AssetAmount::MAX
    const _: () = assert!(
        MIN_BURN > u32::MAX as u64,
        "MIN_BURN must exceed u32::MAX so the encoding test catches u32 truncation",
    );
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .min_burn_size(MIN_BURN)
    .build_components()
    .context("production build_components must compose")?;

    let slot_name =
        StorageSlotName::new(MIN_BURN_SIZE_SLOT_LABEL).context("min_burn_size slot label")?;
    let slot = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == &slot_name)
        .with_context(|| {
            format!(
                "production build_components must seed the minBurnSize slot \
                 '{MIN_BURN_SIZE_SLOT_LABEL}' (GREEN); none of the {} composed components carries it",
                components.len()
            )
        })?;
    // Canonical FULL-u64 encoding via the protocol's own `AssetAmount -> Felt` (asset_amount.rs:129
    // `Felt::try_from(u64)`), NOT `MIN_BURN as u32` — so a green seed that truncated the high bits
    // would mismatch and fail here.
    let expected_min_burn =
        Felt::from(AssetAmount::new(MIN_BURN).context("MIN_BURN must be within AssetAmount::MAX")?);
    assert_eq!(
        slot.value(),
        Word::from([expected_min_burn, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "the seeded minBurnSize slot must carry the FULL-u64 [min_burn_size, 0, 0, 0] (no u32 truncation)"
    );
    Ok(())
}

/// A `min_burn_size` exceeding `AssetAmount::MAX` (`2^63 - 2^31`) cannot be a valid burn amount / field
/// element, so `build_components` REJECTS it with `MinBurnSizeExceedsMax` rather than panicking or
/// silently truncating it into the `MIN_BURN_SIZE_SLOT`. The faucet is otherwise valid (Public + deny
/// mint active + mutable max_supply), so the oversized minBurnSize is the SOLE reason for rejection.
#[test]
fn build_rejects_min_burn_size_exceeding_max() -> Result<()> {
    let over_max = AssetAmount::MAX.as_u64() + 1;
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .min_burn_size(over_max)
    .build_components()
    .expect_err("a min_burn_size exceeding AssetAmount::MAX must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(v) if v == over_max),
        "expected MinBurnSizeExceedsMax({over_max}), got {err:?}"
    );
    Ok(())
}

// OPTION-1 PAUSE COMPOSITION (IMPL-DEV-1 remediation) — Domain-Pauser-ONLY pause surface
// ================================================================================================

/// OPTION 1 (Circle Domain-Pauser-only, CIRCLE-SPECIFICATION.md:121): the production composition
/// exposes NO stock `PausableManager` procedure — neither the `pause` nor the `unpause` root appears
/// in any composed component, so the ONLY pause surface is the DOM_PAUSER-gated
/// `xreserve::pause_admin::{pause,unpause}`. The structural twin of the executing
/// `owner_has_no_pause_path` / `owner_has_no_unpause_path` (pause_admin.rs). RED at the Option-2
/// baseline (the builder pushes `PausableManager`).
#[test]
fn builder_installs_no_stock_pause_manager() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .context("production build_components must compose")?;

    let banned = [PausableManager::pause_root(), PausableManager::unpause_root()];
    for component in &components {
        for (root, _is_auth) in component.procedures() {
            assert!(
                !banned.contains(&root),
                "the production composition must not expose the stock PausableManager \
                 pause/unpause (Option 1, Domain-Pauser-only); found a banned root in component \
                 '{}'",
                component.metadata().name(),
            );
        }
    }
    Ok(())
}

/// The `is_paused` slot SURVIVES Option 1: the production composition carries the value slot
/// `miden::standards::access::pausable::is_paused`, installed by `FungibleFaucet` ITSELF at the
/// pinned v0.15.3 (`fungible/mod.rs:397`) — NOT by the removed `PausableManager`, which installs
/// zero storage (`manager.rs:78`). Without this slot the mint/burn `assert_not_paused` halt-gates
/// break, reopening the CIR-ADMIN-4 halt-gap. This is also the structural TRIPWIRE for the upstream
/// v0.16 change (#2944) that moves the slot OUT of `FungibleFaucet`: at any future pin bump this
/// test fails loudly and the composition must add the base `Pausable` component instead.
#[test]
fn production_components_carry_is_paused_slot() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .context("production build_components must compose")?;

    let is_paused = PausableStorage::is_paused_slot();
    assert!(
        components
            .iter()
            .flat_map(|c| c.storage_slots().iter())
            .any(|slot| slot.name() == is_paused),
        "the production composition must carry the FungibleFaucet-installed is_paused slot \
         (its absence breaks the mint/burn pause halt-gates — CIR-ADMIN-4)"
    );
    Ok(())
}
