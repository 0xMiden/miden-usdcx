//! Output rendering: the faucet's `.mac` account file — the tool's only file output — and the
//! stdout id listing.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountFile};
use miden_protocol::address::NetworkId;

use crate::config::{GenesisToolConfig, Role};

/// The faucet's `.mac` file name. The network operator's genesis config references it as
/// `native_faucet` (see the crate README for the recipe).
const FAUCET_MAC_FILE: &str = "usdcx-faucet.mac";

/// Writes the tool's one file output into `out_dir` (created if absent): the faucet as a
/// protocol `AccountFile`.
pub fn write_outputs(faucet: &Account, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating the output directory {}", out_dir.display()))?;
    AccountFile::new(faucet.clone(), Vec::new())
        .write(out_dir.join(FAUCET_MAC_FILE))
        .context("writing the faucet account file")
}

/// Renders the stdout listing: the faucet id in hex and its bech32 form on each network, then
/// the configured role ids echoed back.
pub fn render_listing(faucet: &Account, config: &GenesisToolConfig) -> String {
    let id = faucet.id();
    let mut out = String::new();
    let _ = writeln!(out, "usdcx-faucet ({FAUCET_MAC_FILE})");
    let _ = writeln!(out, "  hex:     {}", id.to_hex());
    let _ = writeln!(out, "  mainnet: {}", id.to_bech32(NetworkId::Mainnet));
    let _ = writeln!(out, "  testnet: {}", id.to_bech32(NetworkId::Testnet));
    let _ = writeln!(out, "  devnet:  {}", id.to_bech32(NetworkId::Devnet));
    let _ = writeln!(out, "role accounts:");
    for role in Role::ALL {
        let _ = writeln!(
            out,
            "  {}: {}",
            role.as_str(),
            config.account_id(role).to_hex()
        );
    }
    out
}
