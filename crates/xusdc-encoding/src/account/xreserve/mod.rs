//! `xreserve` faucet account composition (CMP-A15) — the [`XReserveStablecoinBuilder`].

pub mod builder;

pub use builder::{
    ATTEST_ADMIN_ROLE, BURN_POLICY_PROC_PATH, MIN_BURN_SIZE_SLOT_LABEL, MINT_DENY_GUARD_PROC_PATH,
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError,
};
