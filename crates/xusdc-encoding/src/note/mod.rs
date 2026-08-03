//! Faucet-owned note constructors: the public burn-event note `XReserveBurnNote`
//! — the Circle-facing withdrawal evidence note — and the production mint-note
//! factory `XUsdcMintNote` — the STOCK standards `MintNote` carrying the
//! signed-DepositIntent transport as attachments, consumed by the faucet under its attestation
//! mint policy.
//!
//! Both are producers only — nothing here consumes a note. Payloads are written with the shared
//! codecs in `crate::xreserve::encoding`, so the bytes a note carries are defined in exactly one
//! place.

pub mod xreserve_admin;
pub mod xreserve_burn;
pub mod xreserve_mint;
