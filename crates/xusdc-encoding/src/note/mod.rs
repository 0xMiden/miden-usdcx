//! Faucet-owned note constructors (Component 1). Currently the public burn-event note
//! `XReserveBurnNote` (CMP-B2, DC-7) — the Circle-facing withdrawal evidence note.
//!
//! These are FAUCET-owned producers; the `NoteStorage.items` payload is encoded via the
//! 04-owned codec (`crate::xreserve::encoding`), consumed by reference.

pub mod xreserve_burn;
