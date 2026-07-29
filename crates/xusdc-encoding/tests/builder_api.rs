//! R-MINT-16 `XReserveStablecoinBuilder` API suite (Wave-1 S1 recomposition): the production
//! builder must compose an ATTESTATION-gated PUBLIC faucet and reject the packaging mistakes that
//! would weaken the mint/burn posture — a non-`Public` account type, an active mint policy that is
//! not the attestation policy (INV-MINT-SECURITY restated: every supply increase passes
//! `xreserve::mint_policy::check_policy`), an active burn policy that is not the stock
//! `MinBurnAmount`, a sub-floor `min_burn_size`, and a missing build-seeded domain config (DEC-4).
//! The build-validation tests assert the exact rejection variants (pure builder logic); the
//! composed-set tests pin the posture the builder ships (active-policy slot, component seam,
//! domain-config seeding).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent, AccountProcedureRoot, AccountType, StorageMap, StorageSlot, StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, TokenSymbol};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{PausableManager, PausableStorage};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BasicBlocklist, BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager,
};
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH,
};
use xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts;

// Dummy faucet config words (the builder does not read them; they only bind the xreserve component's
// value slots so it assembles, exactly as the composition harness does).
const DUMMY_DOMAIN: u32 = 7;

// R2-F2: the identifier value slot is the DEC-4 account-id fixpoint — it ships EMPTY at
// composition and the builder REJECTS a non-empty seed (the faucet-bound `identifier_init` note
// is its only writer). The fixtures below therefore declare an empty identifier; the
// `build_rejects_nonempty_identifier_seed` test drives a non-empty one via
// `xreserve_component_with_identifier`.

/// Builds a fresh `(FungibleFaucet, AccountComponent)` pair from the assembled `xreserve` library —
/// the two inputs `XReserveStablecoinBuilder::new` consumes. The component carries the standard
/// 7-slot composition layout (so it binds) AND exports the attestation mint policy `check_policy`
/// (so `attestation_mint_policy_root` resolves). A fresh pair per call because `new` takes them by
/// value. `is_max_supply_mutable` selects the faucet's stock mutability flag: production builds pass
/// `true` (the builder rejects immutable `max_supply`); the rejection tests whose own check fires
/// first (non-public / missing-attestation-policy) and the immutable-rejection test pass `false`.
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
                // R2-F2: the identifier fixpoint ships EMPTY (the builder requires it).
                StorageSlot::with_value(name, Word::empty())
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

/// The full 7-slot `xreserve` component but with the identifier value slot seeded to `identifier`
/// (the fixture for the R2-F2 non-empty-identifier rejection test — every other slot matches the
/// default fixture, so the ONLY difference exercised is the identifier value).
fn xreserve_component_with_identifier(identifier: Word) -> Result<AccountComponent> {
    let library = assemble_xreserve_lib()?;
    let mut slots = Vec::new();
    for label in ALL_XRESERVE_SLOT_LABELS {
        let name = StorageSlotName::new(label).with_context(|| format!("slot label {label}"))?;
        let slot = match label {
            USED_NONCES_SLOT_LABEL | XRESERVE_ATTESTERS_SLOT_LABEL => {
                StorageSlot::with_map(name, StorageMap::new())
            }
            l if l == DOMAIN_CONFIG_SLOT_LABEL => {
                StorageSlot::with_value(name, Word::from([DUMMY_DOMAIN, 0, 0, 0]))
            }
            l if l == IDENTIFIER_CONFIG_SLOT_LABEL => StorageSlot::with_value(name, identifier),
            _ => StorageSlot::with_value(name, Word::from([0u32, 0, 0, 0])),
        };
        slots.push(slot);
    }
    AccountComponent::new(
        library,
        slots,
        AccountComponentMetadata::new("xusdc-builder-api-xreserve-identifier"),
    )
    .context("binding the xreserve library + composition slots (seeded identifier) as a component")
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

/// The standard production builder over `(faucet, component)`: the seeded principal ids
/// (owner = id(1), DOM_PAUSER = id(2), DOM_MANAGER = id(3), BLK_MANAGER = id(4)) plus the REQUIRED
/// build-seeded domain config (DEC-4) — every construction in this suite goes through here unless
/// the test's very point is omitting the domain config.
fn production_builder(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
) -> XReserveStablecoinBuilder {
    XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )
    .with_domain_config(TEST_DOMAIN, TEST_SOURCE_DOMAIN, test_xreserve_contract())
}

/// Resolves a library-path procedure root across the composed component set (the
/// `wave1_recomposition.rs` resolve-helper pattern).
fn resolve_proc_root(components: &[AccountComponent], path: &str) -> Option<Word> {
    components
        .iter()
        .find_map(|c| c.get_procedure_root_by_path(path))
        .map(Word::from)
}

/// Finds a named VALUE slot's word across the composed component set.
fn find_value_slot(components: &[AccountComponent], name: &StorageSlotName) -> Option<Word> {
    components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == name)
        .map(|slot| slot.value())
}

// BUILD + POSTURE — the production attestation-gated faucet
// ================================================================================================

/// The production `build_components` composes an attestation-gated PUBLIC faucet without error (the
/// build-validation half), and the composed set's ACTIVE mint-policy slot holds the attestation
/// policy root resolved from the installed `xreserve` component — the builder-API half of the
/// restated INV-MINT-SECURITY (the E2E halves live in `wave1_recomposition.rs` /
/// `mint_policy_e2e.rs`).
#[test]
fn build_produces_attestation_gated_public_faucet() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = production_builder(faucet, xreserve_component)
        .build_components()
        .context(
            "the default production builder must compose an attestation-gated Public faucet",
        )?;

    let attestation_root = resolve_proc_root(&components, ATTESTATION_MINT_POLICY_PROC_PATH)
        .context("the composed set must carry the attestation mint policy proc")?;
    let active = find_value_slot(&components, TokenPolicyManager::active_mint_policy_slot())
        .context("the composed set must carry the active-mint-policy slot")?;
    assert_eq!(
        active, attestation_root,
        "the ACTIVE mint policy slot must hold the attestation policy root (INV-MINT-SECURITY)"
    );
    Ok(())
}

// BUILD VALIDATION REJECTS (GREEN)
// ================================================================================================

/// A non-`Public` account type is rejected at build time (packaging cannot produce an unobservable
/// faucet). The non-public check runs before the policy resolution, so this fails fast. GREEN.
#[test]
fn build_rejects_non_public_account_type() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = production_builder(faucet, xreserve_component)
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

/// An active mint policy that is not the attestation policy is rejected — packaging cannot silently
/// swap out the attestation gate (INV-MINT-SECURITY restated: the attestation policy is the only
/// mint policy production allows). GREEN.
#[test]
fn build_rejects_missing_attestation_mint_policy() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = production_builder(faucet, xreserve_component)
        .with_active_mint_policy(MintPolicy::allow_all())
        .build_components()
        .expect_err("a non-attestation active mint policy must be rejected");
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::MissingAttestationMintPolicy
        ),
        "expected MissingAttestationMintPolicy, got {err:?}"
    );
    Ok(())
}

/// An active burn policy that is not the stock `MinBurnAmount` is rejected (the burn-slot twin of
/// [`build_rejects_missing_attestation_mint_policy`]): packaging cannot drop the minimum-burn floor
/// predicate (R-BURN-1/2 preserved through the stock policy since the Wave-1 S1 swap). The faucet is
/// otherwise valid (Public + attestation mint active + mutable max_supply) so the burn policy is the
/// SOLE reason for rejection — removing the guard makes this build succeed (removal-based
/// non-vacuity).
#[test]
fn build_rejects_non_min_burn_amount_burn_policy() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let result = production_builder(faucet, xreserve_component)
        .with_active_burn_policy(BurnPolicy::allow_all())
        .build_components();
    assert!(
        matches!(
            result,
            Err(XReserveStablecoinBuilderError::MissingMinBurnAmountPolicy)
        ),
        "production build_components must reject an AllowAll active burn policy with \
         MissingMinBurnAmountPolicy (the burn-slot twin of MissingAttestationMintPolicy); got \
         Ok/other: {:?}",
        result.as_ref().map(|c| c.len())
    );
    Ok(())
}

/// R2-F1 (the same-root zero-floor bypass): an explicit `with_active_burn_policy` override that
/// carries the STOCK `MinBurnAmount` root — so it slips past the root check — but a ZERO-valued
/// companion must be rejected with the EXACT `BurnPolicyFloorMismatch`. Without this guard the
/// override installs its own zero-floor `MinBurnAmount` companion, and the stock predicate is
/// `min <= amount`, so it restores zero-amount burns despite the builder's `min_burn_size`
/// validation. This is the adversarial companion the burn-side lacked (only AllowAll and
/// `min_burn_size(0)` were covered).
#[test]
fn build_rejects_same_root_zero_seeded_min_burn_override() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    // a SAME-ROOT override (MinBurnAmount::root()) carrying a ZERO floor companion; the default
    // validated min_burn_size is 1.
    let zero_override = BurnPolicy::min_burn_amount(AssetAmount::new(0)?);
    let err = production_builder(faucet, xreserve_component)
        .with_active_burn_policy(zero_override)
        .build_components()
        .expect_err("a same-root zero-seeded MinBurnAmount override must be rejected");
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::BurnPolicyFloorMismatch {
                requested: 0,
                expected: 1
            }
        ),
        "expected BurnPolicyFloorMismatch {{ requested: 0, expected: 1 }}, got {err:?}"
    );
    Ok(())
}

/// R2-F1 (positive control): a same-root override whose companion floor MATCHES the validated
/// `min_burn_size` is accepted, and the shipped faucet's floor slot is exactly that value — the
/// override cannot lower the floor, only restate it.
#[test]
fn build_accepts_matching_min_burn_override() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let matching = BurnPolicy::min_burn_amount(AssetAmount::new(7)?);
    let components = production_builder(faucet, xreserve_component)
        .min_burn_size(7)
        .with_active_burn_policy(matching)
        .build_components()
        .context("a matching-floor override must be accepted")?;
    let floor = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|s| s.name() == MinBurnAmount::slot_name())
        .map(|s| s.value())
        .context("the shipped set must carry the MinBurnAmount floor slot")?;
    assert_eq!(
        floor,
        Word::from([7u32, 0, 0, 0]),
        "the shipped floor must be the validated min_burn_size (7)"
    );
    Ok(())
}

/// R2-F2 (the identifier fixpoint): a build whose supplied `xreserve` component declares a
/// NON-EMPTY identifier value slot must be rejected with the EXACT `IdentifierNotEmpty`. The
/// identifier is the DEC-4 account-id fixpoint (the account id derives from the initial storage
/// commitment), so it can never be build-seeded — a non-empty identifier would ship an
/// already-initialized, potentially misbound faucet and make `identifier_init` trap as a reinit.
#[test]
fn build_rejects_nonempty_identifier_seed() -> Result<()> {
    let faucet = production_faucet(true, 6, "USDCX")?;
    // the component ships a NON-EMPTY identifier — exactly what the fixpoint forbids.
    let xreserve_component = xreserve_component_with_identifier(Word::from([11u32, 12, 13, 14]))?;
    let err = production_builder(faucet, xreserve_component)
        .build_components()
        .expect_err("a non-empty declared identifier must be rejected (DEC-4 fixpoint)");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::IdentifierNotEmpty),
        "expected IdentifierNotEmpty, got {err:?}"
    );
    Ok(())
}

/// An immutable-`max_supply` faucet is rejected at build time: the stock `set_max_supply` admin
/// function would otherwise ship permanently dead (every call traps the runtime mutability gate). The
/// faucet here is otherwise valid (Public + attestation active) and differs ONLY in mutability, so the
/// guard is the sole reason for rejection — and deleting the guard makes this build succeed
/// (removal-based non-vacuity). `faucet_and_component(false)` builds an IMMUTABLE faucet, exactly the
/// misconfiguration the guard exists to reject.
#[test]
fn build_rejects_immutable_max_supply() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(false)?;
    let err = production_builder(faucet, xreserve_component)
        .build_components()
        .expect_err("an immutable-max-supply faucet must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::ImmutableMaxSupply),
        "expected ImmutableMaxSupply, got {err:?}"
    );
    Ok(())
}

// PRODUCTION minBurnSize SEEDING (the stock MinBurnAmount floor slot since Wave-1 S1)
// ================================================================================================

/// Production `build_components` SEEDS the STOCK `MinBurnAmount` floor slot
/// (`MinBurnAmount::slot_name()` = `[min_burn_size, 0, 0, 0]`, carried by the policy companion
/// component the manager emits) so the stock burn policy's floor read resolves on a real production
/// faucet — the builder owns a `min_burn_size` default/override, and the reworked
/// `set_min_burn_size` admin note mutates the SAME slot at runtime. The expected value uses the
/// canonical full-u64 `AssetAmount -> Felt`, so an `as u32` truncation in the seed would fail this
/// test (see the MIN_BURN choice below).
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
    let components = production_builder(faucet, xreserve_component)
        .min_burn_size(MIN_BURN)
        .build_components()
        .context("production build_components must compose")?;

    let floor = find_value_slot(&components, MinBurnAmount::slot_name()).with_context(|| {
        format!(
            "production build_components must install the stock MinBurnAmount floor slot \
             '{}' (the policy companion); none of the {} composed components carries it",
            MinBurnAmount::slot_name(),
            components.len()
        )
    })?;
    // Canonical FULL-u64 encoding via the protocol's own `AssetAmount -> Felt`, NOT `MIN_BURN as
    // u32` — so a seed that truncated the high bits would mismatch and fail here.
    let expected_min_burn =
        Felt::from(AssetAmount::new(MIN_BURN).context("MIN_BURN must be within AssetAmount::MAX")?);
    assert_eq!(
        floor,
        Word::from([expected_min_burn, Felt::ZERO, Felt::ZERO, Felt::ZERO]),
        "the seeded MinBurnAmount floor slot must carry the FULL-u64 [min_burn_size, 0, 0, 0] (no \
         u32 truncation)"
    );
    Ok(())
}

/// A `min_burn_size` below the floor (= 1) is rejected with the EXACT `MinBurnSizeBelowFloor(0)`:
/// the stock `MinBurnAmount` asserts only `min <= amount` (its stock setter even accepts 0), so a
/// zero seed would silently drop the R-BURN-1 zero-burn invariant — the builder half of the
/// zero-floor guard (the runtime half is the reworked `set_min_burn_size` note's assert). The faucet
/// is otherwise valid, so the sub-floor seed is the SOLE reason for rejection.
#[test]
fn build_rejects_zero_min_burn_size() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let err = production_builder(faucet, xreserve_component)
        .min_burn_size(0)
        .build_components()
        .expect_err("a min_burn_size of 0 must be rejected at build time (zero-floor invariant)");
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(0)
        ),
        "expected MinBurnSizeBelowFloor(0), got {err:?}"
    );
    Ok(())
}

/// A `min_burn_size` exceeding `AssetAmount::MAX` (`2^63 - 2^31`) cannot be a valid burn amount / field
/// element, so `build_components` REJECTS it with `MinBurnSizeExceedsMax` rather than panicking or
/// silently truncating it into the stock `MinBurnAmount` floor slot. The faucet is otherwise valid
/// (Public + attestation mint active + mutable max_supply), so the oversized minBurnSize is the SOLE
/// reason for rejection.
#[test]
fn build_rejects_min_burn_size_exceeding_max() -> Result<()> {
    let over_max = AssetAmount::MAX.as_u64() + 1;
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let err = production_builder(faucet, xreserve_component)
        .min_burn_size(over_max)
        .build_components()
        .expect_err("a min_burn_size exceeding AssetAmount::MAX must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(v) if v == over_max),
        "expected MinBurnSizeExceedsMax({over_max}), got {err:?}"
    );
    Ok(())
}

// DEC-4 DOMAIN-CONFIG SEEDING — required input + build-time slot writes
// ================================================================================================

/// Omitting `with_domain_config` is rejected with the EXACT `MissingDomainConfig`: DEC-4 moved the
/// three non-identifier domain-config fields to build time, so a build without them would ship a
/// faucet whose D5a domain compare reads an empty slot. The builder is otherwise fully valid, so the
/// missing domain config is the SOLE reason for rejection.
#[test]
fn build_rejects_missing_domain_config() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let err = XReserveStablecoinBuilder::new(
        faucet,
        xreserve_component,
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )
    .build_components()
    .expect_err("a build without with_domain_config must be rejected (DEC-4)");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MissingDomainConfig),
        "expected MissingDomainConfig, got {err:?}"
    );
    Ok(())
}

/// The build SEEDS the three DEC-4 domain-config fields into the declared xreserve slots —
/// `[domain, 0, 0, 0]`, `[source_domain, 0, 0, 0]`, and the packed `xreserve_contract` hi/lo words
/// (hi = packed felts 0..4 / wire bytes 0..16, lo = felts 4..8) — while the `identifier` slot stays
/// EMPTY through the build (the account-id fixpoint: the builder never seeds it, and the
/// faucet-bound `identifier_init` note is its only writer).
#[test]
fn build_seeds_the_domain_config_slots() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let components = production_builder(faucet, xreserve_component)
        .build_components()
        .context("production build_components must compose")?;

    let slot = |label: &str| -> Result<Word> {
        find_value_slot(
            &components,
            &StorageSlotName::new(label).with_context(|| format!("slot label {label}"))?,
        )
        .with_context(|| format!("the composed set must carry the '{label}' slot"))
    };
    assert_eq!(
        slot(DOMAIN_CONFIG_SLOT_LABEL)?,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        "the domain slot must hold the build-seeded [domain, 0, 0, 0]"
    );
    assert_eq!(
        slot(SOURCE_DOMAIN_CONFIG_SLOT_LABEL)?,
        Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
        "the source_domain slot must hold the build-seeded [source_domain, 0, 0, 0]"
    );
    let xrc = bytes32_to_packed_felts(&test_xreserve_contract());
    assert_eq!(
        slot(XRESERVE_CONTRACT_HI_SLOT_LABEL)?,
        Word::from([xrc[0], xrc[1], xrc[2], xrc[3]]),
        "the xreserve_contract_hi slot must hold the packed wire bytes 0..16"
    );
    assert_eq!(
        slot(XRESERVE_CONTRACT_LO_SLOT_LABEL)?,
        Word::from([xrc[4], xrc[5], xrc[6], xrc[7]]),
        "the xreserve_contract_lo slot must hold the packed wire bytes 16..32"
    );
    assert_eq!(
        slot(IDENTIFIER_CONFIG_SLOT_LABEL)?,
        Word::empty(),
        "the identifier slot must stay EMPTY through the build (DEC-4 fixpoint: the builder never \
         seeds it — the faucet-bound identifier_init note is its only writer)"
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
    let components = production_builder(faucet, xreserve_component)
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
    let components = production_builder(faucet, xreserve_component)
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
    let components = production_builder(faucet, xreserve_component)
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
    let err = production_builder(faucet, component)
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
    let err = production_builder(faucet, component)
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
    let err = production_builder(faucet, component)
        .build_components()
        .expect_err(
            "a faucet whose symbol is not the shipped USDCX must be rejected at build time",
        );
    assert!(
        matches!(err, XReserveStablecoinBuilderError::WrongTokenSymbol),
        "expected WrongTokenSymbol, got {err:?}"
    );
    Ok(())
}

// S18 — THE POLICY-COMPANION SEAM (MIGRATION-V16-ALPHA2.md S18; Wave-1 S1 rework)
// ================================================================================================
// At v0.16 the policy descriptors CARRY their companion components, and the manager's iterator
// emits the companions per DISTINCT policy root after the manager component itself. With the
// recomposed policy set the remainder is EXACTLY THREE: one xreserve copy (the custom attestation
// mint policy), one stock `MinBurnAmount` companion (the burn floor), and one `BasicBlocklist`
// companion (the shared send/receive transfer policy). The builder installs the xreserve component
// EXACTLY ONCE (dropping the recognized copy) and INSTALLS the two stock companions — anything
// else is a loud `PolicyCompanionMismatch`, never a silent drop. These two tests pin both
// directions.

/// POSITIVE shape: the production composition carries EXACTLY ONE component whose code is the
/// installed xreserve library, EXACTLY ONE policy-manager component, and EXACTLY ONE each of the
/// stock `MinBurnAmount` + `BasicBlocklist` companions — in the pinned install order
/// [faucet, Pausable, xreserve, MinBurnAmount, BasicBlocklist, manager, Ownable2Step, RBAC,
/// Authority]. A duplicate xreserve copy would hard-reject the account build with
/// `DuplicateStorageSlotName`, so this is the build-time tripwire for that failure.
#[test]
fn production_composition_installs_one_xreserve_and_one_manager() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let xreserve_code = xreserve_component.component_code().clone();
    let components = production_builder(faucet, xreserve_component)
        .build_components()
        .context("the production composition must build")?;

    assert_eq!(
        components.len(),
        9,
        "the recomposed production set is exactly the nine pinned components"
    );
    let count_by_code = |code: &AccountComponentCode| {
        components
            .iter()
            .filter(|c| c.component_code().as_package() == code.as_package())
            .count()
    };
    assert_eq!(
        count_by_code(&xreserve_code),
        1,
        "the xreserve component must be installed EXACTLY once (the policy companion copy is \
         dropped at the seam); a second copy hard-rejects the account build with \
         DuplicateStorageSlotName"
    );
    assert_eq!(
        count_by_code(MinBurnAmount::code()),
        1,
        "the composition must carry EXACTLY one stock MinBurnAmount companion (the burn floor)"
    );
    assert_eq!(
        count_by_code(BasicBlocklist::code()),
        1,
        "the composition must carry EXACTLY one BasicBlocklist companion (send + receive share it)"
    );
    let manager_components = components
        .iter()
        .filter(|c| c.metadata().name() == TokenPolicyManager::NAME)
        .count();
    assert_eq!(
        manager_components, 1,
        "the composition must carry EXACTLY one policy-manager component"
    );

    // the pinned install ORDER of the identifiable middle run: xreserve at index 2, then the
    // MinBurnAmount + BasicBlocklist companions, then the manager (Wave-1 S1 component order).
    assert!(
        components[2].component_code().as_package() == xreserve_code.as_package(),
        "component 2 must be the xreserve component"
    );
    assert!(
        components[3].component_code().as_package() == MinBurnAmount::code().as_package(),
        "component 3 must be the stock MinBurnAmount companion"
    );
    assert!(
        components[4].component_code().as_package() == BasicBlocklist::code().as_package(),
        "component 4 must be the BasicBlocklist companion"
    );
    assert_eq!(
        components[5].metadata().name(),
        TokenPolicyManager::NAME,
        "component 5 must be the policy-manager component"
    );
    Ok(())
}

/// NEGATIVE (the anti-smuggling proof): a policy override whose root IS the attestation policy — so
/// it passes the `MissingAttestationMintPolicy` root check — but whose companion vector smuggles a
/// FOREIGN component is rejected at the seam with the exact `PolicyCompanionMismatch`, and the
/// diagnostic exposes the extra: the remainder holds 4 companions of which only 3 are recognized
/// (1 xreserve + 1 MinBurnAmount + 1 BasicBlocklist). Without this seam the foreign component would
/// ride into the account silently.
#[test]
fn seam_rejects_a_smuggled_foreign_policy_companion() -> Result<()> {
    let (faucet, xreserve_component) = faucet_and_component(true)?;
    let builder = production_builder(faucet, xreserve_component.clone());
    let attestation_root = builder
        .attestation_mint_policy_root()
        .context("the attestation-policy root resolves from the installed component")?;

    // A stock component the production composition never installs through a POLICY — the smuggled
    // payload. The override's ROOT is still the attestation policy, so the INV-MINT-SECURITY check
    // passes and the seam is the only thing standing between this component and the account.
    let foreign: AccountComponent = PausableManager.into();
    let smuggling_policy = MintPolicy::custom(
        AccountProcedureRoot::from_raw(attestation_root),
        [xreserve_component, foreign],
    )
    .context("the smuggling policy still resolves to the attestation-policy root")?;

    let err = builder
        .with_active_mint_policy(smuggling_policy)
        .build_components()
        .expect_err("a policy companion that is not a recognized companion must reject");
    // The manager's companion remainder for the smuggled build: the mint policy emits its TWO
    // companions (the xreserve copy + the foreign PausableManager), the stock burn policy its ONE
    // MinBurnAmount companion, and the transfer policies their ONE shared BasicBlocklist — so
    // `found` is 4 with only 3 recognized: the foreign is visible as
    // `found > xreserve_recognized + min_burn_recognized + blocklist_recognized`.
    assert!(
        matches!(
            err,
            XReserveStablecoinBuilderError::PolicyCompanionMismatch {
                expected_xreserve: 1,
                expected_min_burn: 1,
                expected_blocklist: 1,
                found: 4,
                xreserve_recognized: 1,
                min_burn_recognized: 1,
                blocklist_recognized: 1,
            }
        ),
        "expected PolicyCompanionMismatch{{expected_xreserve:1, expected_min_burn:1, \
         expected_blocklist:1, found:4, xreserve_recognized:1, min_burn_recognized:1, \
         blocklist_recognized:1}} (the foreign companion must be visible as found > the recognized \
         sum), got {err:?}"
    );
    Ok(())
}
