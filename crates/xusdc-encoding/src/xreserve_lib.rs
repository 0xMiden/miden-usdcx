//! The shipped xUSDC MASM, as it enters the binary.
//!
//! `build.rs` assembles `asm/` into packages under `$OUT_DIR/assets/` and this module embeds their
//! bytes, so the faucet's MASM is fixed at build time and no part of the running program reads the
//! source tree. The three helpers here are what every consumer goes through: the library itself, the
//! account-component code, and the note scripts.

use std::sync::Arc;

use miden_protocol::account::component::AccountComponentCode;
use miden_protocol::assembly::mast::MastForest;
use miden_protocol::assembly::Package;
use miden_protocol::note::NoteScript;
use miden_protocol::utils::sync::LazyLock;

// SHIPPED PACKAGES
// ================================================================================================

static XRESERVE_PACKAGE: LazyLock<Arc<Package>> = LazyLock::new(|| {
    // These bytes are produced by this crate's build script and embedded in the binary.
    Arc::new(
        Package::read_from_bytes_trusted(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/assets/xreserve.masp"
        )))
        .expect("the shipped xreserve package deserializes"),
    )
});

/// Deserializes a build-time-assembled account-component package into its component code.
pub(crate) fn component_code(bytes: &'static [u8]) -> AccountComponentCode {
    let package = Package::read_from_bytes_trusted(bytes)
        .expect("the shipped account-component package deserializes");
    AccountComponentCode::from(package)
}

/// Builds a note script from a build-time-assembled note package.
///
/// The note projects link the xreserve library statically, so the returned script carries its own
/// MAST and runs on any executor without the xreserve package having been loaded into it. That is a
/// property of the linkage declared in `asm/notes/miden-project.toml`, not of this function — if it
/// is ever flipped to dynamic, this stays correct and the script simply references code the executor
/// must then supply.
pub(crate) fn note_script(bytes: &'static [u8]) -> NoteScript {
    let package =
        Package::read_from_bytes_trusted(bytes).expect("the shipped note package deserializes");
    NoteScript::from_package(&package).expect("the note package exports exactly one note script")
}

// XRESERVE LIBRARY
// ================================================================================================

/// The shipped `xreserve` MASM library.
///
/// This is the whole library, which is more than the account exposes: the account's callable surface
/// is the separate `xreserve-faucet` component package. Consumers that need the library as such —
/// harnesses linking it into a script, or an executor that has to resolve its procedures — go
/// through here.
#[derive(Clone)]
pub struct XReserveLibrary(Arc<Package>);

impl XReserveLibrary {
    /// Returns the underlying [`Arc<Package>`].
    pub fn package(&self) -> Arc<Package> {
        self.0.clone()
    }

    /// Returns a reference to the [`MastForest`] of the inner [`Package`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.0.mast_forest()
    }
}

impl AsRef<Package> for XReserveLibrary {
    fn as_ref(&self) -> &Package {
        self.0.as_ref()
    }
}

impl From<XReserveLibrary> for Package {
    fn from(value: XReserveLibrary) -> Self {
        Arc::unwrap_or_clone(value.0)
    }
}

impl Default for XReserveLibrary {
    fn default() -> Self {
        Self(XRESERVE_PACKAGE.clone())
    }
}
