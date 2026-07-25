//! Mint-effects grounding canary (P5-01 D5e) — exposes the component MASM and its module path so
//! the MockChain test can assemble, bind, and exercise it on a `FungibleFaucet` account. Scratch:
//! this crate is an isolated workspace, depends only on the pinned `protocol-pin-v0.15.3`, and
//! decides nothing about the faucet's real mint proc. It proves the write-side kernel primitives
//! (`create_fungible_asset` + `faucet::mint` + `output_note::*` + the `token_config` value-slot
//! read/modify/write + `set_map_item`) EXECUTE AND COMMIT on a faucet account carrying a custom
//! component. See `MINT-EFFECTS-GROUNDING-REPORT.md` (written in Phase 3).

/// Fully-qualified component module path. Passed to `CodeBuilder::compile_component_code` and
/// imported by the tx script via `use xusdc::canary::mint_effects->canary`. Must match the
/// namespace header in `asm/canary_mint.masm`.
pub const CANARY_PATH: &str = "xusdc::canary::mint_effects";

/// The map storage-slot label the MASM `word("...")` const hashes into the slot id. The harness
/// binds the same string via `StorageSlotName::new(USED_SLOT_LABEL)` (cross-language linkage).
/// Stands in for D5e's `usedNonces` registry — the canary just proves the SET commits.
pub const USED_SLOT_LABEL: &str = "xusdc::canary::mint_effects::used";

/// The faucet token-config value slot installed by the standard `FungibleFaucet` component, read
/// and written by the canary proc exactly as `mint_and_send` does (`fungible.masm:26,264,324`).
pub const TOKEN_CONFIG_SLOT_LABEL: &str = "miden::standards::faucets::fungible::token_config";

/// The hand-written, house-style component MASM source.
pub const CANARY_MASM: &str = include_str!("../asm/canary_mint.masm");
