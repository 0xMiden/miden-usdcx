//! `xreserve` faucet account composition (CMP-A15) — the [`XReserveStablecoinBuilder`].

pub mod builder;

pub use builder::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, MINT_DENY_GUARD_PROC_PATH,
};
