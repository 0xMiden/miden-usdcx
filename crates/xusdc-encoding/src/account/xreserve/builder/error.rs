//! The error type the faucet-account builder returns
//! ([`XReserveStablecoinBuilderError`]).
//!
//! The variants describe wiring the builder refuses to compose.

use core::fmt;

use miden_protocol::account::AccountType;
use miden_standards::account::policies::{BurnPolicyError, MintPolicyError};

use super::{ATTESTATION_MINT_POLICY_PROC_PATH, MIN_BURN_SIZE_FLOOR};

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The xUSDC faucet must be public (network-observable). A non-`Public` account type is rejected
    /// at build time so packaging cannot produce an unobservable faucet.
    NonPublicAccountType(AccountType),
    /// The active mint policy does not resolve to the attestation mint policy, so packaging cannot
    /// bypass the attestation gate every supply increase has to pass.
    MissingAttestationMintPolicy,
    /// The supplied faucet was not built with a mutable `max_supply`, so the stock `set_max_supply`
    /// admin function would be permanently dead on the deployed faucet (every call traps the runtime
    /// mutability gate). Rejected at build time so packaging cannot silently ship a faucet whose
    /// `set_max_supply` is inoperable — build the faucet with `.is_max_supply_mutable(true)`.
    ImmutableMaxSupply,
    /// The supplied `xreserve` component does not export the attestation mint policy procedure
    /// (assembly/path drift). Carries the expected path for diagnosis.
    AttestationPolicyProcNotFound,
    /// The active burn policy does not resolve to the stock
    /// `MinBurnAmount` — packaging cannot
    /// ship a faucet whose burns bypass the floor predicate (the burn-side twin of
    /// [`Self::MissingAttestationMintPolicy`]).
    MissingMinBurnAmountPolicy,
    /// The requested `min_burn_size` is below [`MIN_BURN_SIZE_FLOOR`]
    /// (= 1). The stock `MinBurnAmount` policy asserts only `min <= amount` and its stock setter
    /// accepts `0`, so a sub-floor seed would silently allow zero-amount burns;
    /// rejected at build time (the runtime twin is the `set_min_burn_size` note's floor assert).
    /// Carries the offending value.
    MinBurnSizeBelowFloor(u64),
    /// The requested `min_burn_size` exceeds [`AssetAmount::MAX`](miden_protocol::asset::AssetAmount::MAX)
    /// (`2^63 - 2^31`), so it is not a valid burn amount and cannot be seeded into
    /// the stock `MinBurnAmount` floor slot. Carries the offending value.
    MinBurnSizeExceedsMax(u64),
    /// An explicit `with_active_burn_policy` override carries the stock `MinBurnAmount` root but a
    /// companion floor that disagrees with the builder-validated `min_burn_size`, which would let a
    /// same-root override smuggle a sub-floor value past that validation. `requested` is the
    /// override's companion floor; `expected` the validated `min_burn_size`.
    BurnPolicyFloorMismatch { requested: u64, expected: u64 },
    /// The three build-seeded domain-config fields (`domain`, `source_domain`,
    /// `xreserve_contract`) were not supplied — see
    /// [`XReserveStablecoinBuilder::with_domain_config`](super::XReserveStablecoinBuilder::with_domain_config).
    /// A build without them would ship a faucet whose domain compare reads an empty slot.
    MissingDomainConfig,
    /// The supplied `xreserve` component does not declare a required storage slot
    /// ([`REQUIRED_XRESERVE_SLOT_LABELS`](super::REQUIRED_XRESERVE_SLOT_LABELS)); reads and writes
    /// of a missing slot trap at runtime. Carries the missing slot's label.
    MissingXReserveSlot(&'static str),
    /// The supplied faucet's `decimals` is not [`USDCX_DECIMALS`](super::USDCX_DECIMALS) (= 6, a
    /// Circle requirement). The amount reducer scales to 6dp, so a mismatched faucet silently
    /// mis-scales every amount. Carries the offending value.
    WrongDecimals(u8),
    /// The supplied faucet's `TokenSymbol` is not the shipped
    /// [`USDCX_TOKEN_SYMBOL`](super::USDCX_TOKEN_SYMBOL) guard constant. The token's identity is
    /// USDCx, distinct from the "xUSDC" working label; the on-chain symbol is its uppercase form
    /// `USDCX`.
    WrongTokenSymbol,
    /// The `blocklist_manager_holder` (the seeded `BLK_MANAGER` member) collides with a privileged
    /// identity — the administrator, the `DOM_PAUSER` holder, or the `DOM_MANAGER` holder. The blocklist
    /// decision requires the transfer-blocklist administrator be an EXTERNAL entity with NO other faucet-admin
    /// capability (two-way capability isolation): a caller who set the administrator as `BLK_MANAGER`
    /// would give `ADMIN` a direct block/unblock path, and a caller who set a DOM_PAUSER/DOM_MANAGER
    /// holder as `BLK_MANAGER` would fuse those roles. Rejected at build time so packaging cannot ship
    /// a faucet whose blocklist admin is not capability-isolated. `collides_with` names the offending
    /// role (`"ADMIN"` / `"DOM_PAUSER"` / `"DOM_MANAGER"`).
    BlocklistManagerNotIsolated { collides_with: &'static str },
    /// The mint-policy descriptor rejected its construction (`MintPolicy::custom` validates
    /// the root against the supplied companion components).
    MintPolicy(MintPolicyError),
    /// The burn-policy descriptor rejected its construction — the burn-slot twin of
    /// [`Self::MintPolicy`].
    BurnPolicy(BurnPolicyError),
    /// The policy manager's companion components did not have the pinned shape at the composition
    /// seam: the manager component first, then EXACTLY one xreserve-component copy (the custom
    /// attestation mint policy), EXACTLY one stock `MinBurnAmount` companion (the burn floor), and
    /// EXACTLY one `BasicBlocklist` companion (the transfer-blocklist policy shared by the send and
    /// receive kinds). `found` is the FULL companion remainder the manager emitted; the
    /// `*_recognized` counters say how many of those were each expected component, so a smuggled
    /// foreign companion shows up as `found` exceeding their sum rather than hiding behind a
    /// matching total, and a missing stock companion shows up in its own counter.
    PolicyCompanionMismatch {
        expected_xreserve: usize,
        expected_min_burn: usize,
        expected_blocklist: usize,
        found: usize,
        xreserve_recognized: usize,
        min_burn_recognized: usize,
        blocklist_recognized: usize,
    },
}

impl fmt::Display for XReserveStablecoinBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPublicAccountType(account_type) => {
                write!(
                    f,
                    "xusdc faucet must be AccountType::Public, got {account_type:?}"
                )
            }
            Self::MissingAttestationMintPolicy => write!(
                f,
                "active mint policy is not the attestation mint policy; packaging cannot bypass \
                 the attestation gate (INV-MINT-SECURITY)"
            ),
            Self::ImmutableMaxSupply => write!(
                f,
                "xusdc faucet must be built with a mutable max supply \
                 (is_max_supply_mutable=true) so the deployed faucet's set_max_supply stays operable"
            ),
            Self::AttestationPolicyProcNotFound => write!(
                f,
                "the xreserve component does not export the attestation mint policy procedure \
                 '{ATTESTATION_MINT_POLICY_PROC_PATH}'"
            ),
            Self::MissingMinBurnAmountPolicy => write!(
                f,
                "active burn policy is not the stock MinBurnAmount; packaging cannot bypass the \
                 minimum-burn floor predicate"
            ),
            Self::MinBurnSizeBelowFloor(value) => write!(
                f,
                "min_burn_size {value} is below the floor {MIN_BURN_SIZE_FLOOR}; the stock \
                 MinBurnAmount accepts zero, so the zero-burn invariant (R-BURN-1) requires the \
                 seeded floor be at least {MIN_BURN_SIZE_FLOOR}"
            ),
            Self::MinBurnSizeExceedsMax(value) => write!(
                f,
                "min_burn_size {value} exceeds the maximum representable asset amount \
                 (AssetAmount::MAX = 2^63 - 2^31)"
            ),
            Self::BurnPolicyFloorMismatch { requested, expected } => write!(
                f,
                "the active burn policy override carries a MinBurnAmount floor of {requested}, but \
                 the validated min_burn_size is {expected}; an override may not diverge (nor lower) \
                 the shipped burn floor"
            ),
            Self::MissingDomainConfig => write!(
                f,
                "the build-seeded domain config (domain, source_domain, xreserve_contract) was \
                 not supplied; call with_domain_config before build_components (DEC-4)"
            ),
            Self::MissingXReserveSlot(label) => write!(
                f,
                "the xreserve component does not declare the required storage slot '{label}'"
            ),
            Self::WrongDecimals(decimals) => write!(
                f,
                "xusdc faucet decimals must be 6 (CIR-FEE-3; the reducer scales to 6dp), got \
                 {decimals}"
            ),
            Self::WrongTokenSymbol => write!(
                f,
                "xusdc faucet token symbol must be the shipped USDCX guard constant"
            ),
            Self::BlocklistManagerNotIsolated { collides_with } => write!(
                f,
                "the BLK_MANAGER holder (transfer-blocklist administrator) must be an external entity \
                 with no other faucet-admin capability, but it collides with the {collides_with} — \
                 F4-reversal two-way capability isolation is violated"
            ),
            Self::MintPolicy(_) => write!(f, "mint policy descriptor construction failed"),
            Self::BurnPolicy(_) => write!(f, "burn policy descriptor construction failed"),
            Self::PolicyCompanionMismatch {
                expected_xreserve,
                expected_min_burn,
                expected_blocklist,
                found,
                xreserve_recognized,
                min_burn_recognized,
                blocklist_recognized,
            } => write!(
                f,
                "token policy manager emitted an unexpected companion-component shape: expected \
                 exactly {expected_xreserve} xreserve-component copy + {expected_min_burn} \
                 MinBurnAmount companion + {expected_blocklist} BasicBlocklist companion after the \
                 manager component; the remainder held {found} companions, {xreserve_recognized} \
                 of them the installed xreserve component, {min_burn_recognized} the MinBurnAmount \
                 companion, and {blocklist_recognized} the BasicBlocklist companion ({} foreign)",
                found.saturating_sub(
                    xreserve_recognized + min_burn_recognized + blocklist_recognized
                )
            ),
        }
    }
}

impl core::error::Error for XReserveStablecoinBuilderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MintPolicy(source) => Some(source),
            Self::BurnPolicy(source) => Some(source),
            _ => None,
        }
    }
}

impl From<MintPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: MintPolicyError) -> Self {
        Self::MintPolicy(source)
    }
}

impl From<BurnPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: BurnPolicyError) -> Self {
        Self::BurnPolicy(source)
    }
}
