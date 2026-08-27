//! A minimal deposit relayer: poll Circle's attestation feed, mint each attested deposit at the
//! xUSDC faucet, advance the cursor.
//!
//! Delivery is **at-least-once**. Every authoritative check — the DepositIntent parse, the amount
//! reduction, the `usedNonces` replay guard, the attester-allowlist check, the ECDSA verify — is
//! on-chain in the faucet's mint policy, so a duplicate submit is refused rather than double-minted
//! and a bug here can withhold a mint but never authorize one. That is what lets the relayer keep
//! no per-deposit state at all: its only persistence is the feed cursor, advanced once a page's
//! mint transaction is on chain.

pub mod config;
