//! xUSDC-on-Miden Rust mirror + test harness. Originally the shared-encoding unit (a Rust mirror of
//! the hand-written MASM encoding module plus the canonical golden-vector loader / generator); now
//! also hosts the faucet account composition (the
//! [`account::xreserve::XReserveStablecoinBuilder`], which wires the stock-mint-deny guard so the
//! custom path is the sole supply-increasing surface, R-MINT-16).
//!
//! The four encoding routines (bytes32 hashing, the uint256 → AssetAmount reducer, the Rust-primary
//! AccountId codec, and the DepositIntent layout + parser) are implemented; the faucet composition
//! adds the sole-supply-surface guard. The test suite is the executable spec.

pub mod account;
pub mod note;
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

/// Path of the one canonical golden-vector artifact, loaded by reference from both the Rust
/// unit tests and the MASM execution tests.
pub fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/xreserve-encoding-vectors.json")
}
