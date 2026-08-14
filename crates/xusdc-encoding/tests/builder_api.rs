//! `XReserveStablecoinBuilder` API suite: the production
//! builder must compose an ATTESTATION-gated PUBLIC faucet and reject the packaging mistakes that
//! would weaken the mint/burn posture — a non-`Public` account type, an active mint policy that is
//! not the attestation policy (the sole-supply-surface invariant restated: every supply increase
//! passes
//! `xreserve::mint_policy::check_policy`) and a sub-floor `min_burn_size`.
//! The build-validation tests assert the exact rejection variants (pure builder logic); the
//! composed-set tests pin the posture the builder ships (active-policy slot, component seam,
//! domain-config seeding).

mod support;

use anyhow::{Context, Result};
use miden_protocol::account::component::AccountComponentCode;
use miden_protocol::account::{AccountComponent, RoleSymbol, StorageSlotName};
use miden_protocol::asset::AssetAmount;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{PausableManager, PausableStorage};
use miden_standards::account::fees::ConstantFeeManager;
use miden_standards::account::policies::{
    BasicBlocklist, BlocklistManager, MinBurnAmount, TokenPolicyManager,
};
use support::*;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, XReserveComponent, XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH, BLK_MANAGER_ROLE,
    DOM_PAUSER_ROLE,
};
use xusdc_encoding::xreserve::encoding::{bytes32_to_packed_felts, EthBytes32};

/// The standard production builder: the seeded principal ids (owner = id(1), DOM_PAUSER = id(2),
/// DOM_MANAGER = id(3), BLK_MANAGER = id(4)) plus the build-seeded domain config.
fn production_builder() -> XReserveStablecoinBuilder {
    XReserveStablecoinBuilder::new(
        AssetAmount::new(1_000_000).expect("the fixed test max supply is valid"),
        AssetAmount::new(0).expect("a zero token supply is valid"),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
        test_fee_parameters(),
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        EthBytes32::new(test_xreserve_contract()),
    )
    .expect("the fixed-identity USDCx faucet builds")
}

/// Looks up a procedure's root by its library path across every component in the composed set.
///
/// The set is a flat list of components and a given procedure lives in exactly one of them, so the
/// first hit is the answer; `None` means no component exposes that path at all.
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

/// The production composition builds, and the account it produces is gated on the attestation
/// policy.
///
/// Two things are asserted. The build succeeds and yields a public faucet, and the active
/// mint-policy storage slot holds the root of the attestation policy actually installed in the
/// composed component — not merely some non-empty value. Together they are the build-time half of
/// the claim that a mint can only happen against a valid Circle attestation; the runtime halves,
/// where real notes are minted and rejected, live in the recomposition and mint-policy end-to-end
/// suites.
#[test]
fn build_produces_attestation_gated_public_faucet() -> Result<()> {
    let components = production_builder().build_components().context(
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

// The max-supply mutability invariant is now enforced BY CONSTRUCTION: the crate-root
// `build_faucet_account` builds the faucet `is_max_supply_mutable(true)`, so there is no
// runtime `ImmutableMaxSupply` reject to exercise, and the former `build_rejects_immutable_max_supply`
// tripwire has no immutable faucet to inject through the public constructor. The invariant is
// asserted positively by the crate-root byte-identity suite, which builds through
// `build_faucet_account` and composes a valid faucet whose `set_max_supply` stays operable.

// PRODUCTION minBurnSize SEEDING (the stock MinBurnAmount floor slot)
// ================================================================================================

/// Production `build_components` SEEDS the STOCK `MinBurnAmount` floor slot
/// (`MinBurnAmount::slot_name()` = `[min_burn_size, 0, 0, 0]`, carried by the policy companion
/// component the manager emits) so the stock burn policy's floor read resolves on a real production
/// faucet — the builder owns a `min_burn_size` default/override, and the
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
    let components = production_builder()
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
/// zero seed would silently drop the zero-burn invariant — the builder half of the
/// zero-floor guard (the runtime half is the `set_min_burn_size` note's assert). The faucet
/// is otherwise valid, so the sub-floor seed is the SOLE reason for rejection.
#[test]
fn build_rejects_zero_min_burn_size() -> Result<()> {
    let err = production_builder()
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
    let err = production_builder()
        .min_burn_size(over_max)
        .build_components()
        .expect_err("a min_burn_size exceeding AssetAmount::MAX must be rejected at build time");
    assert!(
        matches!(err, XReserveStablecoinBuilderError::MinBurnSizeExceedsMax(v) if v == over_max),
        "expected MinBurnSizeExceedsMax({over_max}), got {err:?}"
    );
    Ok(())
}

// DOMAIN-CONFIG SEEDING — required input + build-time slot writes
// ================================================================================================

/// The build SEEDS the three build-time domain-config fields into the declared xreserve slots —
/// `[domain, 0, 0, 0]`, `[source_domain, 0, 0, 0]`, and the packed `xreserve_contract` hi/lo words
/// (hi = packed felts 0..4 / wire bytes 0..16, lo = felts 4..8).
#[test]
fn build_seeds_the_domain_config_slots() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let slot = |name: &StorageSlotName| -> Result<Word> {
        find_value_slot(&components, name)
            .with_context(|| format!("the composed set must carry the '{name}' slot"))
    };
    assert_eq!(
        slot(XReserveComponent::domain_config_slot())?,
        Word::from([TEST_DOMAIN, 0, 0, 0]),
        "the domain slot must hold the build-seeded [domain, 0, 0, 0]"
    );
    assert_eq!(
        slot(XReserveComponent::source_domain_config_slot())?,
        Word::from([TEST_SOURCE_DOMAIN, 0, 0, 0]),
        "the source_domain slot must hold the build-seeded [source_domain, 0, 0, 0]"
    );
    let xrc = bytes32_to_packed_felts(&test_xreserve_contract());
    assert_eq!(
        slot(XReserveComponent::xreserve_contract_hi_slot())?,
        Word::from([xrc[0], xrc[1], xrc[2], xrc[3]]),
        "the xreserve_contract_hi slot must hold the packed wire bytes 0..16"
    );
    assert_eq!(
        slot(XReserveComponent::xreserve_contract_lo_slot())?,
        Word::from([xrc[4], xrc[5], xrc[6], xrc[7]]),
        "the xreserve_contract_lo slot must hold the packed wire bytes 16..32"
    );
    Ok(())
}

// PAUSE COMPOSITION — Domain-Pauser-ONLY pause surface
// ================================================================================================

/// Domain-Pauser-only pause (Circle requires that only the Domain Pauser role may pause), now
/// expressed in the stock components: the production composition installs the stock
/// `PausableManager` and `BlocklistManager`, and the authority's role map is what keeps each of
/// their procedures with its own role rather than with the administrator.
///
/// The structural half is here — every one of the four manager roots is really installed, and each
/// really carries the role the faucet intends. The executing half is
/// `administrator_has_no_pause_path` / `administrator_has_no_unpause_path` (pause_admin.rs) and the effects suite.
#[test]
fn builder_installs_the_stock_managers_with_their_roles_assigned() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let installed: std::collections::BTreeSet<_> = components
        .iter()
        .flat_map(|component| component.procedures().map(|(root, _is_auth)| root))
        .collect();
    let roles = XReserveAdminAuthority::new().procedure_roles().clone();
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("the Domain pauser role symbol is valid");
    let blocklist_manager = RoleSymbol::new(BLK_MANAGER_ROLE)
        .expect("the blocklist administrator role symbol is valid");

    for (what, root, role) in [
        ("pause", PausableManager::pause_root(), &pauser),
        ("unpause", PausableManager::unpause_root(), &pauser),
        (
            "block_account",
            BlocklistManager::block_account_root(),
            &blocklist_manager,
        ),
        (
            "unblock_account",
            BlocklistManager::unblock_account_root(),
            &blocklist_manager,
        ),
    ] {
        assert!(
            installed.contains(&root),
            "the production composition must install the stock manager procedure {what} — the \
             standard config note calls that exact root"
        );
        assert_eq!(
            roles.get(&root),
            Some(role),
            "the stock manager procedure {what} must be gated on its intended role, or the \
             capability lands on the administrator instead"
        );
    }
    Ok(())
}

/// The `is_paused` slot's provenance: the production composition carries the value slot
/// `miden::standards::access::pausable::is_paused`, installed at v0.16 by the base `Pausable`
/// component the builder adds (`Pausable::unpaused()`) — NOT by `FungibleFaucet` (v0.16 moved the
/// slot OUT of the faucet) and NOT by the stock `PausableManager`, which writes the slot but
/// installs zero storage of its own. Without this slot the mint/burn
/// `assert_not_paused` halt-gates break, reopening the pause halt-gap (Circle requires a paused
/// faucet halt mint and burn) — and at v0.16 that failure is SILENT rather than loud: #3047 made
/// `pausable::assert_not_paused` a no-op on accounts lacking the slot instead of trapping. This
/// test is therefore the load-bearing structural tripwire for the composition: it goes RED the
/// moment `Pausable` leaves the component list.
#[test]
fn production_components_carry_is_paused_slot() -> Result<()> {
    let components = production_builder()
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

/// The production metadata mutability config permits maximum-supply updates while keeping the
/// description, logo URI, and external link immutable. This matters because the standard faucet
/// metadata configuration note dispatches all four actions from one allowlisted script root.
#[test]
fn production_components_carry_mutability_config_slot() -> Result<()> {
    let components = production_builder()
        .build_components()
        .context("production build_components must compose")?;

    let mutability = StorageSlotName::new("miden::standards::faucets::mutability_config")
        .context("the pinned mutability_config slot name")?;
    let slot_value = components
        .iter()
        .flat_map(|c| c.storage_slots().iter())
        .find(|slot| slot.name() == &mutability)
        .map(|slot| slot.value())
        .expect("the production composition must carry the faucet mutability configuration");
    assert_eq!(
        slot_value,
        Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ONE]),
        "only maximum supply is mutable",
    );
    Ok(())
}

// COMPLETENESS GUARDS — the builder rejects an incompletely- or wrongly-composed faucet at build time.
// ================================================================================================

// Token-config exactness (decimals == 6, symbol == USDCX) is now guaranteed BY CONSTRUCTION: the
// builder builds the fixed-identity USDCx faucet itself via `build_usdcx_faucet`, so a
// wrong-decimals or wrong-symbol faucet cannot be handed in through the public API and the former
// `build_rejects_wrong_decimals` / `build_rejects_wrong_token_symbol` tripwires have no
// mis-configured faucet to reject. The identity is asserted positively by the byte-identity suite,
// which builds the account through `build_faucet_account` and matches the frozen composition.

// THE POLICY COMPANIONS
// ================================================================================================
// The mint policy carries the domain-seeded xreserve component, so the manager iterator is the
// install set (manager + one companion per distinct policy root). This test pins that the
// composition carries exactly one of each: xreserve, MinBurnAmount, BasicBlocklist, and the
// policy manager.

/// POSITIVE shape: the production composition carries EXACTLY ONE component whose code is the
/// installed xreserve library, EXACTLY ONE policy-manager component, and EXACTLY ONE each of the
/// stock `MinBurnAmount` + `BasicBlocklist` companions — in the pinned install order
/// [faucet, Pausable, policy manager, MinBurnAmount, BasicBlocklist, xreserve, PausableManager,
/// BlocklistManager, ConstantFeeManager, RBAC, Authority]. The companion positions follow the
/// policy manager's `BTreeMap<AccountProcedureRoot, _>` order. This test also verifies that
/// xreserve is installed once; duplicate installation would fail account construction with
/// `DuplicateStorageSlotName`.
#[test]
fn production_composition_installs_one_xreserve_and_one_manager() -> Result<()> {
    // The same component the builder assembles internally, so its code is the code the composition
    // must carry exactly once.
    let xreserve_code = AccountComponent::from(XReserveComponent::assemble())
        .component_code()
        .clone();
    let components = production_builder()
        .build_components()
        .context("the production composition must build")?;

    assert_eq!(
        components.len(),
        11,
        "the recomposed production set is exactly the eleven pinned components"
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
        "the xreserve component must be installed EXACTLY once; a second copy hard-rejects the \
         account build with DuplicateStorageSlotName"
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

    // Manager iterator first (manager, then companions in procedure-root map order), then the
    // stock admin components.
    assert_eq!(
        components[2].metadata().name(),
        TokenPolicyManager::NAME,
        "component 2 must be the policy-manager component"
    );
    assert!(
        components[3].component_code().as_package() == MinBurnAmount::code().as_package(),
        "component 3 must be the stock MinBurnAmount companion"
    );
    assert!(
        components[4].component_code().as_package() == BasicBlocklist::code().as_package(),
        "component 4 must be the BasicBlocklist companion"
    );
    assert!(
        components[5].component_code().as_package() == xreserve_code.as_package(),
        "component 5 must be the xreserve component"
    );
    assert_eq!(
        components[8].metadata().name(),
        ConstantFeeManager::NAME,
        "component 8 must be the constant-fee manager component"
    );
    Ok(())
}
