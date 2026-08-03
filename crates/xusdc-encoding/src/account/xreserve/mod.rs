//! `xreserve` faucet account composition — the [`XReserveStablecoinBuilder`].

pub mod admin_authority;
pub mod builder;

pub use admin_authority::XReserveAdminAuthority;
pub use builder::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, ATTESTATION_MINT_POLICY_PROC_PATH,
    BLK_MANAGER_ROLE, DOMAIN_CONFIG_SLOT_LABEL, DOM_MANAGER_ROLE, DOM_PAUSER_ROLE,
    IDENTIFIER_CONFIG_SLOT_LABEL, MIN_BURN_SIZE_FLOOR, REQUIRED_XRESERVE_SLOT_LABELS,
    SOURCE_DOMAIN_CONFIG_SLOT_LABEL, USDCX_DECIMALS, USDCX_TOKEN_SYMBOL, USED_NONCES_SLOT_LABEL,
    XRESERVE_ATTESTERS_SLOT_LABEL, XRESERVE_CONTRACT_HI_SLOT_LABEL,
    XRESERVE_CONTRACT_LO_SLOT_LABEL,
};
