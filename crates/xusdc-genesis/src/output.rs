//! Output rendering: the faucet's `.mac` account file, the plain-text `genesis.toml` fragment,
//! the `accounts.json` summary, and the stdout listing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountFile};
use miden_protocol::address::NetworkId;
use serde::Serialize;

use crate::config::{GenesisToolConfig, Role};

/// The faucet's `.mac` file name, referenced by the `genesis.toml` fragment's `native_faucet`.
const FAUCET_MAC_FILE: &str = "usdcx-faucet.mac";
/// The emitted node-genesis fragment.
const GENESIS_TOML_FILE: &str = "genesis.toml";
/// The emitted machine-readable summary.
const ACCOUNTS_JSON_FILE: &str = "accounts.json";

/// The faucet's identity in every printable form.
#[derive(Serialize)]
struct FaucetSummary {
    mac_file: String,
    id_hex: String,
    bech32_mainnet: String,
    bech32_testnet: String,
    bech32_devnet: String,
}

/// One referenced role account: its extracted id and the `.mac` path the config resolved.
#[derive(Serialize)]
struct RoleSummary {
    name: String,
    id_hex: String,
    mac_file: PathBuf,
}

#[derive(Serialize)]
struct Summary {
    faucet: FaucetSummary,
    roles: Vec<RoleSummary>,
}

fn build_summary(faucet: &Account, config: &GenesisToolConfig) -> Summary {
    let id = faucet.id();
    Summary {
        faucet: FaucetSummary {
            mac_file: FAUCET_MAC_FILE.to_string(),
            id_hex: id.to_hex(),
            bech32_mainnet: id.to_bech32(NetworkId::Mainnet),
            bech32_testnet: id.to_bech32(NetworkId::Testnet),
            bech32_devnet: id.to_bech32(NetworkId::Devnet),
        },
        roles: Role::ALL
            .iter()
            .map(|role| {
                let account = config.role_account(*role);
                RoleSummary {
                    name: role.as_str().to_string(),
                    id_hex: account.id.to_hex(),
                    mac_file: account.path.clone(),
                }
            })
            .collect(),
    }
}

/// Writes every output into `out_dir` (created if absent): the faucet's `.mac` file, the
/// `genesis.toml` fragment, and the `accounts.json` summary. The role `.mac` files are
/// referenced by the fragment, never copied.
pub fn write_outputs(faucet: &Account, config: &GenesisToolConfig, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating the output directory {}", out_dir.display()))?;

    AccountFile::new(faucet.clone(), Vec::new())
        .write(out_dir.join(FAUCET_MAC_FILE))
        .context("writing the faucet account file")?;

    std::fs::write(
        out_dir.join(GENESIS_TOML_FILE),
        render_genesis_toml(config, out_dir)?,
    )
    .context("writing the genesis.toml fragment")?;

    let summary = serde_json::to_string_pretty(&build_summary(faucet, config))
        .context("serializing the summary")?;
    std::fs::write(out_dir.join(ACCOUNTS_JSON_FILE), summary + "\n")
        .context("writing the accounts.json summary")?;

    Ok(())
}

/// Renders the node-genesis fragment as plain text: the faucet as `native_faucet` plus one
/// `[[account]]` entry per role, each pointing back at the config-referenced `.mac` file with
/// the path rewritten to resolve from the fragment's own location in `out_dir`. Emitted
/// textually on purpose — this tool has no node-crate dependency, the node's own
/// `GenesisConfig` parses the fragment.
fn render_genesis_toml(config: &GenesisToolConfig, out_dir: &Path) -> Result<String> {
    let out_dir = out_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing the output directory {}", out_dir.display()))?;
    let mut out = String::new();
    let _ = writeln!(out, "native_faucet = \"{FAUCET_MAC_FILE}\"");
    for role in Role::ALL {
        let source = &config.role_account(role).path;
        let canonical = source.canonicalize().with_context(|| {
            format!(
                "canonicalizing the {} account file {}",
                role.as_str(),
                source.display()
            )
        })?;
        let rewritten = relative_from(&canonical, &out_dir);
        let _ = writeln!(out);
        let _ = writeln!(out, "[[account]]");
        let _ = writeln!(out, "path = \"{}\"", rewritten.display());
    }
    Ok(out)
}

/// Computes how `target` is reached from inside `base` (both canonical absolute paths): the
/// common prefix is dropped, the remaining `base` components become `..` hops, and `target`'s
/// remainder is appended. Falls back to the absolute `target` when the two share no root.
fn relative_from(target: &Path, base: &Path) -> PathBuf {
    let base_parts: Vec<_> = base.components().collect();
    let target_parts: Vec<_> = target.components().collect();
    let common = base_parts
        .iter()
        .zip(&target_parts)
        .take_while(|(a, b)| a == b)
        .count();
    if common == 0 {
        return target.to_path_buf();
    }
    let mut out = PathBuf::new();
    for _ in common..base_parts.len() {
        out.push("..");
    }
    for part in &target_parts[common..] {
        out.push(part);
    }
    out
}

/// Renders the stdout listing: the faucet id in hex and its bech32 form on each network, then
/// the referenced role accounts' extracted ids.
pub fn render_listing(faucet: &Account, config: &GenesisToolConfig) -> String {
    let summary = build_summary(faucet, config);
    let mut out = String::new();
    let _ = writeln!(out, "usdcx-faucet ({})", summary.faucet.mac_file);
    let _ = writeln!(out, "  hex:     {}", summary.faucet.id_hex);
    let _ = writeln!(out, "  mainnet: {}", summary.faucet.bech32_mainnet);
    let _ = writeln!(out, "  testnet: {}", summary.faucet.bech32_testnet);
    let _ = writeln!(out, "  devnet:  {}", summary.faucet.bech32_devnet);
    let _ = writeln!(out, "referenced role accounts:");
    for role in &summary.roles {
        let _ = writeln!(out, "  {}: {}", role.name, role.id_hex);
    }
    out
}
