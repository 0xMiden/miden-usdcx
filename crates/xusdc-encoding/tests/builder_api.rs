//! R-MINT-16 `XReserveStablecoinBuilder` API suite: the production builder must compose a
//! deny-active PUBLIC faucet and reject the two packaging mistakes that would re-open the stock
//! mint surface — a non-`Public` account type and an active mint policy that is not the deny guard
//! (INV-MINT-SECURITY: `xreserve_mint` is the only supply-increasing surface). The build-validation
//! tests assert the two rejections (pure builder logic); the behavior test asserts a production-deny
//! faucet actually traps stock `mint_and_send` with the exact ERR_XRESERVE_MINT_DENIED, end to end.

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent, AccountProcedureRoot, AccountType, StorageMap, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{PausableManager, PausableStorage};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
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
    Ok((
        production_faucet(is_max_supply_mutable, 6, "USDCX")?,
        xreserve_component_with_slots(&ALL_XRESERVE_SLOT_LABELS)?,
    ))
}

/// The SEVEN required xreserve slot labels (the builder's slot-presence guard; the 4-field domain
/// config set + the two maps; `min_burn_size` is builder-seeded, not caller-declared).
const ALL_XRESERVE_SLOT_LABELS: [&str; 7] = [
    DOMAIN_CONFIG_SLOT_LABEL,
    IDENTIFIER_CONFIG_SLOT_LABEL,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL,
    XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
    USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL,
];

/// Assembles the xreserve component carrying exactly `labels` (value slots get a dummy word for
/// the domain/identifier pair and empty words for the new domain-config slots; the two well-known map labels
/// get empty maps) — the omission fixture for the slot-presence guard tests.
fn xreserve_component_with_slots(labels: &[&str]) -> Result<AccountComponent> {
    let library = assemble_xreserve_lib()?;
    let mut slots = Vec::new();
    for label in labels {
        let name = StorageSlotName::new(*label).with_context(|| format!("slot label {label}"))?;
        let slot = match *label {
            USED_NONCES_SLOT_LABEL | XRESERVE_ATTESTERS_SLOT_LABEL => {
                StorageSlot::with_map(name, StorageMap::new())
            }
            l if l == DOMAIN_CONFIG_SLOT_LABEL => {
                StorageSlot::with_value(name, Word::from([DUMMY_DOMAIN, 0, 0, 0]))
            }
            l if l == IDENTIFIER_CONFIG_SLOT_LABEL => {
                StorageSlot::with_value(name, Word::from([11u32, 12, 13, 14]))
            }
            _ => StorageSlot::with_value(name, Word::from([0u32, 0, 0, 0])),
        };
        slots.push(slot);
    }
    AccountComponent::new(
        library,
        slots,
        AccountComponentMetadata::new("xusdc-builder-api-xreserve"),
    )
    .context("binding the xreserve library + composition slots as a component")
}

/// Builds a `FungibleFaucet` with configurable decimals/symbol — the fixture for the builder's
/// token-config guard tests (`decimals=6`, the shipped `USDCX` symbol guard constant).
fn production_faucet(
    is_max_supply_mutable: bool,
    decimals: u8,
    symbol: &str,
) -> Result<FungibleFaucet> {
    FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new(symbol)?)
        .decimals(decimals)
        .max_supply(AssetAmount::new(1_000_000).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(0).context("invalid token_supply")?)
        .is_max_supply_mutable(is_max_supply_mutable)
        .build()
        .context("failed to build FungibleFaucet")
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
    let components = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components();
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
    let result = run_mint_and_send(&gm.harness, Word::from([0u32, 1, 2, 3]), 0, 4, 100).await;
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
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
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
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .with_active_mint_policy(MintPolicy::allow_all())
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
    .with_active_burn_policy(BurnPolicy::allow_all())
    .build_components();
    assert!(
        matches!(
            result,
            Err(XReserveStablecoinBuilderError::MissingBurnPolicyGuard)
        ),
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
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .expect_err("an immutable-max-supply faucet must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::ImmutableMaxSupply),
        "expected ImmutableMaxSupply, got {err:?}"
    );
    Ok(())
}

// PRODUCTION minBurnSize SEEDING (CMP-A10)
// ================================================================================================

/// Production `build_components` SEEDS the minBurnSize config slot
/// (`xusdc::xreserve::attester_admin::min_burn_size` = `[min_burn_size, 0, 0, 0]`) so the burn policy's
/// R-BURN-2 read resolves on a real production faucet — the builder owns a `min_burn_size`
/// default/override and binds the slot onto the xreserve component (the future CMP-F2 `set_min_burn_size`
/// co-owns the SAME slot). The expected value uses the canonical full-u64 `AssetAmount -> Felt`, so an
/// `as u32` truncation in the seed would fail this test (see the MIN_BURN choice below).
#[test]
fn production_seeds_min_burn_size() -> Result<()> {
    // Anti-truncation: minBurnSize is a FULL `u64` `AssetAmount` (`AssetAmount::MAX` =
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

// PAUSE COMPOSITION (IMPL-DEV-1) — Domain-Pauser-ONLY pause surface
// ================================================================================================

/// Domain-Pauser-only pause (IMPL-DEV-1; Circle requires that only the Domain Pauser role may
/// pause): the production composition exposes NO stock `PausableManager` procedure — neither the
/// `pause` nor the `unpause` root appears in any composed component, so the ONLY pause surface is the
/// DOM_PAUSER-gated `xreserve::pause_admin::{pause,unpause}`. The structural twin of the executing
/// `owner_has_no_pause_path` / `owner_has_no_unpause_path` (pause_admin.rs).
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

    let banned = [
        PausableManager::pause_root(),
        PausableManager::unpause_root(),
    ];
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

/// The `is_paused` slot SURVIVES the Domain-Pauser-only pause model: the production composition
/// carries the value slot `miden::standards::access::pausable::is_paused`, installed at v0.16 by
/// the base `Pausable` component the builder adds (`Pausable::unpaused()`) — NOT by
/// `FungibleFaucet` (protocol #2944 moved the slot OUT of the faucet; the v15 provenance this doc
/// used to cite is superseded — MIGRATION-V16-ALPHA2.md S1) and NOT by the deliberately-absent
/// `PausableManager`, which installs zero storage. Without this slot the mint/burn
/// `assert_not_paused` halt-gates break, reopening the pause halt-gap (Circle requires a paused
/// faucet halt mint and burn) — and at v0.16 that failure is SILENT rather than loud: #3047 made
/// `pausable::assert_not_paused` a no-op on accounts lacking the slot instead of trapping. This
/// test is therefore the load-bearing structural tripwire for the composition: it goes RED the
/// moment `Pausable` leaves the component list.
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
        "the production composition must carry the Pausable-installed is_paused slot (v0.16 #2944 \
         moved it out of FungibleFaucet); its absence SILENTLY disables the mint/burn pause \
         halt-gates at v0.16 (#3047 no-ops assert_not_paused when the slot is missing) — \
         CIR-ADMIN-4"
    );
    Ok(())
}

/// PIN-BUMP TRIPWIRE for the `mutability_config` slot: the
/// builder's fail-closed `unwrap_or(false)` in `faucet_max_supply_is_mutable` (builder.rs) only
/// arms when the slot is MISSING — unreachable at the pinned `=0.16.0-alpha.2`, where
/// `FungibleFaucet` still installs it (unlike `is_paused`, which #2944 moved out). This test pins the slot's presence AND its word layout on the production
/// build, so a pin bump that drops, renames, or reshuffles it fails loudly here instead of
/// silently arming the missing-slot default. The name string is DELIBERATELY duplicated from the
/// builder's private `FAUCET_MUTABILITY_CONFIG_SLOT` (builder.rs) rather than taken from a stock
/// accessor: a stock rename must fail THIS test, not be silently tracked.
#[test]
fn production_components_carry_mutability_config_slot() -> Result<()> {
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

    let mutability = StorageSlotName::new("miden::standards::faucets::mutability_config")
        .context("the pinned mutability_config slot name")?;
    let slot_value = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == &mutability)
        .map(|slot| slot.value())
        .expect(
            "the production composition must carry the FungibleFaucet-installed \
             mutability_config slot (PIN-BUMP TRIPWIRE: its absence arms the builder's \
             missing-slot default)",
        );
    // Layout tripwire: `[is_desc, is_logo, is_extlink, is_max_supply]` — the production build
    // passes is_max_supply_mutable(true), so element 3 (MAX_SUPPLY_MUTABLE_WORD_INDEX) must be 1.
    // A pin bump reshuffling the word would silently flip the builder's flag read.
    assert_eq!(
        slot_value[3],
        Felt::from(1u32),
        "mutability_config element 3 must be the is_max_supply_mutable flag (= 1 for the \
         production mutable-max-supply build)"
    );
    Ok(())
}

// COMPLETENESS GUARDS — the builder rejects an incompletely- or wrongly-composed faucet at build time.
// ================================================================================================

/// Validate-what-you-ship slot presence: a component missing ANY of the seven required xreserve
/// slots is rejected with the EXACT `MissingXReserveSlot(label)` naming the absent slot — a missing
/// slot would ship a faucet whose reads/writes of it trap `ERR_ACCOUNT_UNKNOWN_STORAGE_SLOT_NAME`
/// at runtime (LOUD, but deploy-time rejection is the "invalid composition → build error" bar). One
/// case per omitted slot.
#[rstest::rstest]
#[case::domain(0)]
#[case::identifier(1)]
#[case::source_domain(2)]
#[case::xreserve_contract_hi(3)]
#[case::xreserve_contract_lo(4)]
#[case::used_nonces(5)]
#[case::xreserve_attesters(6)]
fn build_rejects_missing_xreserve_slot(#[case] omitted: usize) -> Result<()> {
    let labels: Vec<&str> = ALL_XRESERVE_SLOT_LABELS
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != omitted)
        .map(|(_, l)| *l)
        .collect();
    let component = xreserve_component_with_slots(&labels)?;
    let faucet = production_faucet(true, 6, "USDCX")?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .expect_err("a component missing a required xreserve slot must be rejected at build time");
    let missing = ALL_XRESERVE_SLOT_LABELS[omitted];
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MissingXReserveSlot(l) if l == missing),
        "expected MissingXReserveSlot({missing}), got {err:?}"
    );
    Ok(())
}

/// Token-config exactness: a faucet whose `decimals != 6` is rejected with the EXACT
/// `WrongDecimals(d)` — Circle mandates six decimal places and the D5b reducer scales to 6dp, so
/// a mismatched faucet silently mis-scales every minted amount. The faucet is otherwise valid
/// (Public + deny active + mutable max_supply + full slot set), so the decimals are the SOLE reason
/// for rejection.
#[test]
fn build_rejects_wrong_decimals() -> Result<()> {
    let component = xreserve_component_with_slots(&ALL_XRESERVE_SLOT_LABELS)?;
    let faucet = production_faucet(true, 7, "USDCX")?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .expect_err("a faucet with decimals != 6 must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::WrongDecimals(7)),
        "expected WrongDecimals(7), got {err:?}"
    );
    Ok(())
}

/// Token-config exactness: a faucet whose `TokenSymbol` is not the shipped `USDCX` guard
/// constant is rejected with the EXACT `WrongTokenSymbol`. The token's identity is USDCx (DISTINCT
/// from the superseded "xUSDC"); the pinned `TokenSymbol` is
/// uppercase A–Z only (`token_symbol.rs:17`), so `USDCX` is the VM-forced uppercase on-chain form.
/// The WRONG fixture is deliberately the superseded `"XUSDC"` — this test now also guards against
/// regressing to the old symbol.
#[test]
fn build_rejects_wrong_token_symbol() -> Result<()> {
    let component = xreserve_component_with_slots(&ALL_XRESERVE_SLOT_LABELS)?;
    let faucet = production_faucet(true, 6, "XUSDC")?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .expect_err("a faucet whose symbol is not the shipped USDCX must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::WrongTokenSymbol),
        "expected WrongTokenSymbol, got {err:?}"
    );
    Ok(())
}

// S18 — THE POLICY-COMPANION SEAM (MIGRATION-V16-ALPHA2.md S18)
// ================================================================================================
// At v0.16 the policy descriptors CARRY their `custom()` companion components, and the manager's
// iterator emits one companion copy per DISTINCT policy root (deny + burn = two copies of the same
// xreserve component) after the manager component itself. The builder installs the xreserve
// component EXACTLY ONCE and drops those two recognized copies at the seam — anything else is a
// loud `PolicyCompanionMismatch`, never a silent drop. These two tests pin both directions.

/// POSITIVE shape: the production composition carries EXACTLY ONE component whose code is the
/// installed xreserve library and EXACTLY ONE policy-manager component (no duplicate install, no
/// dropped manager). A duplicate xreserve copy would hard-reject the account build with
/// `DuplicateStorageSlotName`, so this is the build-time tripwire for that failure.
#[test]
fn production_composition_installs_one_xreserve_and_one_manager() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let xreserve_code = xreserve_component.component_code().clone();
    let components = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    )
    .build_components()
    .context("the production composition must build")?;

    let xreserve_copies = components
        .iter()
        .filter(|c| c.component_code().as_library() == xreserve_code.as_library())
        .count();
    assert_eq!(
        xreserve_copies, 1,
        "the xreserve component must be installed EXACTLY once (the policy companions are dropped \
         at the seam); a second copy hard-rejects the account build with DuplicateStorageSlotName"
    );

    let manager_components = components
        .iter()
        .filter(|c| c.metadata().name() == TokenPolicyManager::NAME)
        .count();
    assert_eq!(
        manager_components, 1,
        "the composition must carry EXACTLY one policy-manager component"
    );
    Ok(())
}

/// NEGATIVE (the anti-smuggling proof): a policy override whose root IS the deny guard — so it
/// passes the `MissingMintDenyGuard` root check — but whose companion vector smuggles a FOREIGN
/// component is rejected at the seam with the exact `PolicyCompanionMismatch`, and the diagnostic
/// exposes the extra: the remainder holds 3 companions of which only 2 are the installed xreserve
/// component. Without this seam the foreign component would ride into the account silently.
#[test]
fn seam_rejects_a_smuggled_foreign_policy_companion() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let builder = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component.clone(),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
    );
    let deny_root = builder
        .mint_deny_guard_root()
        .context("the deny-guard root resolves from the installed component")?;

    // A stock component the production composition never installs through a POLICY — the smuggled
    // payload. The override's ROOT is still the deny guard, so the INV-MINT-SECURITY check passes
    // and the seam is the only thing standing between this component and the account.
    let foreign: AccountComponent = PausableManager.into();
    let smuggling_policy = MintPolicy::custom(
        AccountProcedureRoot::from_raw(deny_root),
        [xreserve_component, foreign],
    )
    .context("the smuggling policy still resolves to the deny-guard root")?;

    let err = builder
        .with_active_mint_policy(smuggling_policy)
        .build_components()
        .expect_err("a policy companion that is not the installed xreserve component must reject");
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::PolicyCompanionMismatch {
                expected: 2,
                found: 3,
                recognized: 2,
            }
        ),
        "expected PolicyCompanionMismatch{{expected:2, found:3, recognized:2}} (the foreign \
         companion must be visible as found > recognized), got {err:?}"
    );
    Ok(())
}
