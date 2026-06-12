//! xUSDC-on-Miden 04 shared encoding: Rust mirror of the hand-written MASM encoding
//! module plus the test harness (canonical golden-vector loader, vector generator).
//!
//! BUILD STATE: all four slice routines are implemented and green (R1 bytes32, R2
//! uint256 reducer, R3 AccountId Rust-primary, R4 DepositIntent layout + parser); the
//! test suite is the executable spec. Loop history: `TEST-LEDGER.md`.

pub mod vectors;
pub mod xreserve;

/// Embedded MASM sources (the on-disk files are the single source of truth; embedded
/// copies serve the constant-parity test).
pub const ENCODING_MOD_MASM: &str =
    include_str!("../../../asm/standards/xreserve/encoding/mod.masm");
pub const LAYOUT_MASM: &str = include_str!("../../../asm/standards/xreserve/encoding/layout.masm");

/// Absolute path of the `xreserve` MASM root, assembled from dir at test runtime
/// (namespace `xreserve`; mirrors `miden-standards/build.rs`).
pub fn xreserve_asm_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../asm/standards/xreserve")
}

/// Path of the one canonical golden-vector artifact (04-owned; loaded by reference from
/// both the Rust unit tests and the MASM execution tests).
pub fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/xreserve-encoding-vectors.json")
}
