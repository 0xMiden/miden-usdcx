//! The account pipeline: the externally-provided role wallets, the genesis faucet, and the
//! nonce-one promotion.

use anyhow::{Context, Result};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::Account;
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::block::FeeParameters;
use miden_protocol::Felt;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

use crate::config::{GenesisToolConfig, Role};

/// One genesis wallet: its role, the nonce-one account, and the secret keys its provided account
/// file embedded (passed through unchanged into the emitted `.mac` file).
#[derive(Debug, Clone)]
pub struct BuiltAccount {
    pub role: Role,
    pub account: Account,
    pub secrets: Vec<AuthSecretKey>,
}

/// The full genesis account set: the six role wallets (in [`Role::ALL`] order) and the keyless
/// faucet, all at nonce one.
#[derive(Debug, Clone)]
pub struct GenesisAccounts {
    pub wallets: Vec<BuiltAccount>,
    pub faucet: Account,
}

impl GenesisAccounts {
    /// Returns the built wallet for `role`.
    pub fn wallet(&self, role: Role) -> &BuiltAccount {
        self.wallets
            .iter()
            .find(|wallet| wallet.role == role)
            .expect("build_all builds every role")
    }
}

/// Builds the genesis account set from the validated config.
///
/// The role wallets are provided externally (their ids are fixed by whoever built them); this
/// tool only builds the faucet and normalizes everything to genesis form. The faucet is built as
/// the native fee faucet — its fee parameters carry the OPERATOR's id during the seed grind,
/// rebound to the faucet's own asset by `build_genesis_account` — and every provided wallet is
/// then promoted to nonce one. When `token_supply` is non-zero the operator's promotion adds
/// exactly that amount of the faucet's asset to its vault (vault contents do not enter the id),
/// matching the faucet's issued-supply tracker.
pub fn build_all(config: &GenesisToolConfig) -> Result<GenesisAccounts> {
    // The faucet: the operator's id is the placeholder fee faucet during the seed grind; the
    // genesis build rebinds the fee asset to the faucet's own asset.
    let faucet_config = &config.faucet;
    let operator_id = config.provided(Role::Operator).account().id();
    let fee_parameters = FeeParameters::new(operator_id, faucet_config.verification_base_fee);
    let min_burn_amount = faucet_config
        .min_burn_amount
        .map(AssetAmount::new)
        .transpose()
        .context("min_burn_amount is not a valid asset amount")?;
    let faucet = XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(faucet_config.max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(faucet_config.token_supply).context("invalid token_supply")?)
        .owner(config.provided(Role::Owner).account().id())
        .attest_admin_holder(config.provided(Role::AttestAdmin).account().id())
        .pauser_holder(config.provided(Role::Pauser).account().id())
        .unpauser_holder(config.provided(Role::Unpauser).account().id())
        .blocklist_manager_holder(config.provided(Role::BlocklistManager).account().id())
        .fee_parameters(fee_parameters)
        .domain(faucet_config.domain)
        .maybe_min_burn_amount(min_burn_amount)
        .build()
        .context("composing the xUSDC faucet builder")?
        .build_genesis_account(faucet_config.seed.as_bytes())
        .context("building the genesis faucet account")?;

    // Promote the provided wallets to nonce one. The operator additionally receives the genesis
    // circulating supply: exactly the faucet's initial token_supply.
    let mut wallets = Vec::new();
    for role in Role::ALL {
        let provided = config.provided(role);
        let supply = if role == Role::Operator && faucet_config.token_supply > 0 {
            Some(
                FungibleAsset::new(faucet.id(), faucet_config.token_supply)
                    .context("the genesis supply is not a valid fungible asset")?,
            )
        } else {
            None
        };
        let account = promote_to_genesis(provided.account().clone(), supply)
            .with_context(|| format!("promoting the {} wallet to nonce one", role.as_str()))?;
        wallets.push(BuiltAccount {
            role,
            account,
            secrets: provided.file.auth_secret_keys.clone(),
        });
    }

    Ok(GenesisAccounts { wallets, faucet })
}

/// Rebuilds a provided account at nonce one with no seed — a genesis account exists, it is not
/// deployed — optionally adding `extra_asset` to its vault (vault contents do not enter the id).
fn promote_to_genesis(account: Account, extra_asset: Option<FungibleAsset>) -> Result<Account> {
    let (id, mut vault, storage, code, _nonce, _seed) = account.into_parts();
    if let Some(asset) = extra_asset {
        vault
            .add_asset(asset.into())
            .context("adding the genesis supply to the operator's vault")?;
    }
    Account::new(id, vault, storage, code, Felt::ONE, None)
        .context("rebuilding the account at nonce one")
}
