//! Output rendering: the seven `.mac` account files, the plain-text `genesis.toml` fragment, the
//! `accounts.json` summary, and the stdout id listing.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use miden_protocol::account::{Account, AccountFile};
use miden_protocol::address::NetworkId;
use serde::Serialize;

use crate::accounts::GenesisAccounts;

/// The faucet's `.mac` file name, referenced by the `genesis.toml` fragment's `native_faucet`.
const FAUCET_MAC_FILE: &str = "usdcx-faucet.mac";
/// The emitted node-genesis fragment.
const GENESIS_TOML_FILE: &str = "genesis.toml";
/// The emitted machine-readable summary.
const ACCOUNTS_JSON_FILE: &str = "accounts.json";

/// One account's identity in every printable form.
#[derive(Serialize)]
struct AccountSummary {
    name: String,
    mac_file: String,
    id_hex: String,
    bech32_mainnet: String,
    bech32_testnet: String,
    bech32_devnet: String,
    /// True when the emitted `.mac` file embeds secret keys (passed through from the provided
    /// account file — this tool generates none).
    secrets_embedded: bool,
}

#[derive(Serialize)]
struct Summary {
    faucet: AccountSummary,
    accounts: Vec<AccountSummary>,
}

fn summarize(
    name: &str,
    mac_file: &str,
    account: &Account,
    secrets_embedded: bool,
) -> AccountSummary {
    let id = account.id();
    AccountSummary {
        name: name.to_string(),
        mac_file: mac_file.to_string(),
        id_hex: id.to_hex(),
        bech32_mainnet: id.to_bech32(NetworkId::Mainnet),
        bech32_testnet: id.to_bech32(NetworkId::Testnet),
        bech32_devnet: id.to_bech32(NetworkId::Devnet),
        secrets_embedded,
    }
}

fn build_summary(accounts: &GenesisAccounts) -> Summary {
    Summary {
        faucet: summarize("usdcx-faucet", FAUCET_MAC_FILE, &accounts.faucet, false),
        accounts: accounts
            .wallets
            .iter()
            .map(|wallet| {
                summarize(
                    wallet.role.as_str(),
                    &wallet.role.mac_file_name(),
                    &wallet.account,
                    !wallet.secrets.is_empty(),
                )
            })
            .collect(),
    }
}

/// Writes every output into `out_dir` (created if absent): the seven `.mac` files, the
/// `genesis.toml` fragment, and the `accounts.json` summary.
pub fn write_outputs(accounts: &GenesisAccounts, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating the output directory {}", out_dir.display()))?;

    AccountFile::new(accounts.faucet.clone(), Vec::new())
        .write(out_dir.join(FAUCET_MAC_FILE))
        .context("writing the faucet account file")?;
    for wallet in &accounts.wallets {
        AccountFile::new(wallet.account.clone(), wallet.secrets.clone())
            .write(out_dir.join(wallet.role.mac_file_name()))
            .with_context(|| format!("writing the {} account file", wallet.role.as_str()))?;
    }

    std::fs::write(
        out_dir.join(GENESIS_TOML_FILE),
        render_genesis_toml(accounts),
    )
    .context("writing the genesis.toml fragment")?;

    let summary = serde_json::to_string_pretty(&build_summary(accounts))
        .context("serializing the summary")?;
    std::fs::write(out_dir.join(ACCOUNTS_JSON_FILE), summary + "\n")
        .context("writing the accounts.json summary")?;

    Ok(())
}

/// Renders the node-genesis fragment as plain text: the faucet as `native_faucet` plus one
/// `[[account]]` entry per wallet. Emitted textually on purpose — this tool has no node-crate
/// dependency, the node's own `GenesisConfig` parses the fragment.
fn render_genesis_toml(accounts: &GenesisAccounts) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "native_faucet = \"{FAUCET_MAC_FILE}\"");
    for wallet in &accounts.wallets {
        let _ = writeln!(out);
        let _ = writeln!(out, "[[account]]");
        let _ = writeln!(out, "path = \"{}\"", wallet.role.mac_file_name());
    }
    out
}

/// Renders the stdout listing: per account the id in hex and its bech32 form on each network.
pub fn render_listing(accounts: &GenesisAccounts) -> String {
    let summary = build_summary(accounts);
    let mut out = String::new();
    for entry in std::iter::once(&summary.faucet).chain(summary.accounts.iter()) {
        let _ = writeln!(out, "{} ({})", entry.name, entry.mac_file);
        let _ = writeln!(out, "  hex:     {}", entry.id_hex);
        let _ = writeln!(out, "  mainnet: {}", entry.bech32_mainnet);
        let _ = writeln!(out, "  testnet: {}", entry.bech32_testnet);
        let _ = writeln!(out, "  devnet:  {}", entry.bech32_devnet);
        if entry.secrets_embedded {
            let _ = writeln!(
                out,
                "  key:     secret embedded in the .mac file (passed through from the provided \
                 account file)"
            );
        }
    }
    out
}
