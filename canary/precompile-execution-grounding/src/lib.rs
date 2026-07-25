//! Precompile-execution grounding canary (P5-01) — exposes the component MASM and its module path
//! so the MockChain test can assemble, bind, and EXECUTE the Keccak256 + secp256k1-ECDSA precompiles.
//! Scratch: this crate is an isolated workspace, depends only on the pinned `protocol-pin-v0.15.3`,
//! and decides nothing about the faucet's real attestation/allowlist logic. It grounds a primitive —
//! that the precompiles run (not merely assemble/link) under the stock `miden-testing` MockChain host.
//! See `PRECOMPILE-EXECUTION-GROUNDING-REPORT.md` (written in Phase 3).

/// Fully-qualified component module path. Passed to `CodeBuilder::compile_component_code` and
/// imported by the tx script via `use xusdc::canary::precompile_execution->canary`. Must match the
/// namespace header in `asm/canary_precompile.masm`.
pub const CANARY_PATH: &str = "xusdc::canary::precompile_execution";

/// The hand-written, house-style component MASM source. Three `pub proc` drivers `exec` the core-lib
/// precompiles over `@locals` scratch; their inputs arrive via the advice provider (modelling D5d's
/// advice-delivered attester pubkey/signature), so the harness seeds advice and the host handlers
/// supply the precompile outputs.
pub const CANARY_MASM: &str = include_str!("../asm/canary_precompile.masm");
