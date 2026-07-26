//! The error type returned while composing the xUSDC faucet account
//! (`XReserveStablecoinBuilderError`), moved verbatim from the builder module
//! to satisfy the file-size gate.

use core::fmt;

use miden_protocol::account::AccountType;
use miden_standards::account::policies::{BurnPolicyError, MintPolicyError};

use super::{BURN_POLICY_PROC_PATH, MINT_DENY_GUARD_PROC_PATH};

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The xUSDC faucet must be public (network-observable). A non-`Public` account type is rejected
    /// at build time so packaging cannot produce an unobservable faucet.
    NonPublicAccountType(AccountType),
    /// The active mint policy does not resolve to the deny guard — packaging cannot bypass the
    /// sole-supply-surface gate (INV-MINT-SECURITY).
    MissingMintDenyGuard,
    /// The supplied faucet was not built with a mutable `max_supply`, so the stock `set_max_supply`
    /// admin function would be permanently dead on the deployed faucet (every call traps the runtime
    /// mutability gate). Rejected at build time so packaging cannot silently ship a faucet whose
    /// `set_max_supply` is inoperable — build the faucet with `.is_max_supply_mutable(true)`.
    ImmutableMaxSupply,
    /// The supplied `xreserve` component does not export the deny-guard procedure (assembly/path
    /// drift). Carries the expected path for diagnosis.
    DenyGuardProcNotFound,
    /// The active burn policy does not resolve to the installed `burn_policy::check_policy` — packaging
    /// cannot ship a faucet whose burns bypass the R-BURN-1/2 security predicate (CMP-A10). The burn-slot
    /// twin of [`Self::MissingMintDenyGuard`].
    MissingBurnPolicyGuard,
    /// The supplied `xreserve` component does not export the burn-policy procedure (assembly/path
    /// drift). The burn-slot twin of [`Self::DenyGuardProcNotFound`].
    BurnPolicyProcNotFound,
    /// The requested `min_burn_size` exceeds [`AssetAmount::MAX`](miden_protocol::asset::AssetAmount::MAX)
    /// (`2^63 - 2^31`), so it is not a
    /// valid burn amount / field element and cannot be seeded into the `MIN_BURN_SIZE_SLOT`. Carries
    /// the offending value.
    MinBurnSizeExceedsMax(u64),
    /// The supplied `xreserve` component does not declare a required storage slot (the
    /// validate-what-you-ship check, [`REQUIRED_XRESERVE_SLOT_LABELS`](super::REQUIRED_XRESERVE_SLOT_LABELS):
    /// a missing slot would ship a
    /// faucet whose reads/writes of that slot trap at runtime). Carries the missing slot's label.
    MissingXReserveSlot(&'static str),
    /// The supplied faucet's `decimals` is not the spec-mandated [`USDCX_DECIMALS`](super::USDCX_DECIMALS)
    /// (= 6;
    /// `token_config` decimals = 6, a Circle requirement of six decimal places — the D5b reducer
    /// scales to 6dp, so a mismatched faucet silently mis-scales every amount). Carries the
    /// offending value.
    WrongDecimals(u8),
    /// The supplied faucet's `TokenSymbol` is not the shipped [`USDCX_TOKEN_SYMBOL`](super::USDCX_TOKEN_SYMBOL)
    /// guard
    /// constant. The token's identity is USDCx (human decision 2026-07-06, distinct from the
    /// superseded "xUSDC"); the pinned `TokenSymbol` is uppercase-A–Z only (`token_symbol.rs`),
    /// so the on-chain symbol is the VM-forced uppercase `USDCX`; this guard pins the shipped
    /// constant so the deployed symbol is load-bearing and a drift fails the build.
    WrongTokenSymbol,
    /// The `blocklist_manager_holder` (the seeded `BLK_MANAGER` member) collides with a privileged
    /// identity — the owner, the `DOM_PAUSER` holder, or the `DOM_MANAGER` holder. The F4-reversal
    /// requires the transfer-blocklist administrator be an EXTERNAL entity with NO other faucet-admin
    /// capability (two-way capability isolation): a caller who set the owner as `BLK_MANAGER` would
    /// give the owner/ADMIN a direct block/unblock path, and a caller who set a DOM_PAUSER/DOM_MANAGER
    /// holder as `BLK_MANAGER` would fuse those roles. Rejected at build time so packaging cannot ship
    /// a faucet whose blocklist admin is not capability-isolated. `collides_with` names the offending
    /// role (`"owner"` / `"DOM_PAUSER"` / `"DOM_MANAGER"`).
    BlocklistManagerNotIsolated { collides_with: &'static str },
    /// The mint-policy descriptor rejected its construction (v16 `MintPolicy::custom` validates
    /// the root against the supplied companion components).
    MintPolicy(MintPolicyError),
    /// The burn-policy descriptor rejected its construction — the burn-slot twin of
    /// [`Self::MintPolicy`].
    BurnPolicy(BurnPolicyError),
    /// The policy manager's companion components did not have the pinned shape at the
    /// composition seam (the manager component first, then EXACTLY two xreserve-component copies —
    /// one per custom mint/burn policy — plus EXACTLY one `BasicBlocklist` companion, the
    /// transfer-blocklist policy shared by the send and receive kinds — F4-reversal, MIGRATION-V16-
    /// ALPHA2.md S18). Never dropped silently. `found` is the FULL companion remainder the manager
    /// emitted; `xreserve_recognized`/`blocklist_recognized` count how many of those were the
    /// already-installed xreserve component and the `BasicBlocklist` companion respectively, so a
    /// smuggled foreign companion shows up as `found > xreserve_recognized + blocklist_recognized`
    /// instead of hiding behind a matching count, and a missing blocklist companion (which would
    /// ship a faucet whose `blocked_accounts` reads/writes trap) shows up as
    /// `blocklist_recognized != expected_blocklist`.
    PolicyCompanionMismatch {
        expected_xreserve: usize,
        expected_blocklist: usize,
        found: usize,
        xreserve_recognized: usize,
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
            Self::MissingMintDenyGuard => write!(
                f,
                "active mint policy is not the mint-deny guard; packaging cannot bypass the \
                 sole-supply-surface gate"
            ),
            Self::ImmutableMaxSupply => write!(
                f,
                "xusdc faucet must be built with a mutable max supply \
                 (is_max_supply_mutable=true) so the deployed faucet's set_max_supply stays operable"
            ),
            Self::DenyGuardProcNotFound => write!(
                f,
                "the xreserve component does not export the mint-deny guard procedure \
                 '{MINT_DENY_GUARD_PROC_PATH}'"
            ),
            Self::MissingBurnPolicyGuard => write!(
                f,
                "active burn policy is not the xreserve burn policy; packaging cannot bypass the \
                 burn security predicate (R-BURN-1/2)"
            ),
            Self::BurnPolicyProcNotFound => write!(
                f,
                "the xreserve component does not export the burn policy procedure \
                 '{BURN_POLICY_PROC_PATH}'"
            ),
            Self::MinBurnSizeExceedsMax(value) => write!(
                f,
                "min_burn_size {value} exceeds the maximum representable asset amount \
                 (AssetAmount::MAX = 2^63 - 2^31)"
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
                expected_blocklist,
                found,
                xreserve_recognized,
                blocklist_recognized,
            } => write!(
                f,
                "token policy manager emitted an unexpected companion-component shape: expected \
                 exactly {expected_xreserve} xreserve-component copies + {expected_blocklist} \
                 BasicBlocklist companion after the manager component; the remainder held {found} \
                 companions, {xreserve_recognized} of them the installed xreserve component and \
                 {blocklist_recognized} the BasicBlocklist companion ({} foreign)",
                found.saturating_sub(xreserve_recognized + blocklist_recognized)
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
