//! Storage-map grounding canary (P5-01) — exposes the component MASM and its module path so the
//! MockChain test can assemble, bind, and exercise it. Scratch: this crate is an isolated
//! workspace, depends only on the pinned `protocol-pin-v0.15.3`, and decides nothing about the
//! faucet's real storage layout. See `STORAGE-MAP-GROUNDING-REPORT.md` (written in Phase 3).

/// Fully-qualified component module path. Passed to `CodeBuilder::compile_component_code` and
/// imported by the tx script via `use xusdc::canary::storage_map->canary`. Must match the
/// namespace header in `asm/canary_map.masm`.
pub const CANARY_PATH: &str = "xusdc::canary::storage_map";

/// The storage-slot label that the MASM `word("...")` const hashes into the slot id. The harness
/// binds the same string via `StorageSlotName::new(USED_SLOT_LABEL)` (cross-language linkage).
pub const USED_SLOT_LABEL: &str = "xusdc::canary::storage_map::used";

/// The hand-written, house-style component MASM source.
pub const CANARY_MASM: &str = include_str!("../asm/canary_map.masm");
