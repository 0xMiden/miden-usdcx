//! `xreserve` faucet account composition — the [`XReserveStablecoinBuilder`].

pub mod admin_authority;
pub mod builder;

pub use admin_authority::XReserveAdminAuthority;
pub use builder::{
    build_faucet_account, XReserveFaucetExtension, XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH, BLK_MANAGER_ROLE,
    DOM_MANAGER_ROLE, DOM_PAUSER_ROLE, MIN_BURN_SIZE_FLOOR, USDCX_DECIMALS, USDCX_TOKEN_SYMBOL,
};
