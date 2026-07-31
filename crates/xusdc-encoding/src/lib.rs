//! The xUSDC-on-Miden Rust mirror and test harness: the Rust mirror of the hand-written MASM encoding
//! module, the canonical golden-vector loader / generator, and the faucet account composition
//! (the [`account::xreserve::XReserveStablecoinBuilder`], which validates at build time that
//! the attestation mint policy is the active mint policy, so the attestation-gated path is the
//! sole supply-increasing surface).
//!
//! The four encoding routines are bytes32 hashing, the uint256 → AssetAmount reducer, the
//! Rust-primary AccountId codec, and the DepositIntent layout + parser.

pub mod account;
pub mod note;
pub mod vectors;
pub mod xreserve;

/// Embedded MASM sources. The on-disk files are the single source of truth; these copies exist so
/// callers can read the MASM without a filesystem.
pub const ENCODING_MOD_MASM: &str =
    include_str!("../../../asm/standards/xreserve/encoding/mod.masm");
pub const LAYOUT_MASM: &str = include_str!("../../../asm/standards/xreserve/encoding/layout.masm");

/// Absolute path of the `xreserve` MASM root, assembled from the directory at runtime under the
/// `xreserve` namespace.
pub fn xreserve_asm_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../asm/standards/xreserve")
}

/// Path of the one canonical golden-vector artifact, loaded by reference from both the Rust
/// unit tests and the MASM execution tests.
pub fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/xreserve-encoding-vectors.json")
}
