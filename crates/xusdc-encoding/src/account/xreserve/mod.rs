//! `xreserve` faucet account composition (CMP-A15) — the [`XReserveStablecoinBuilder`].

pub mod builder;

pub use builder::{
    BURN_POLICY_PROC_PATH, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE, MIN_BURN_SIZE_SLOT_LABEL,
    MINT_DENY_GUARD_PROC_PATH, XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};
