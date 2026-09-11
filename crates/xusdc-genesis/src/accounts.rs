//! The account pipeline: six basic wallets, the genesis faucet, and the nonce-one promotion.

use anyhow::{Context, Result};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountType};
use miden_protocol::asset::{AssetAmount, AssetVault, FungibleAsset};
use miden_protocol::block::FeeParameters;
use miden_protocol::Felt;
use miden_standards::account::auth::Approver;
use miden_standards::account::wallets::create_basic_wallet;
use xusdc_encoding::account::xreserve::XReserveStablecoinBuilder;

use crate::config::{GenesisToolConfig, Role};
use crate::keys::RoleAuth;

/// One built genesis wallet: its role, the nonce-one account, and the secrets to embed in its
/// `.mac` file (empty when the key was supplied externally).
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

/// Builds every genesis account from the validated config.
///
/// The wallets are first built at nonce zero (the seed grind fixes their ids), the faucet is then
/// built as the native fee faucet — its fee parameters carry the OPERATOR's id during the grind,
/// rebound to the faucet's own asset by `build_genesis_account` — and finally every wallet is
/// promoted to nonce one. When `token_supply` is non-zero the operator's promotion swaps in a
/// vault holding exactly that amount of the faucet's asset (vault contents do not enter the id),
/// matching the faucet's issued-supply tracker.
pub fn build_all(config: &GenesisToolConfig) -> Result<GenesisAccounts> {
    // Resolve auth and build the nonce-zero wallets; the ids are final from here on.
    let mut ground_wallets = Vec::new();
    for role in Role::ALL {
        let entry = config.entry(role);
        let auth = RoleAuth::resolve(entry);
        let account = create_basic_wallet(
            entry.seed.as_bytes(),
            Approver::from(&auth.public_key()),
            AccountType::Public,
        )
        .with_context(|| format!("building the {} wallet", role.as_str()))?;
        ground_wallets.push((role, account, auth.secret_keys()));
    }

    let operator_id = ground_wallets
        .iter()
        .find(|(role, ..)| *role == Role::Operator)
        .expect("the operator wallet was just built")
        .1
        .id();

    // The faucet: the operator's id is the placeholder fee faucet during the seed grind; the
    // genesis build rebinds the fee asset to the faucet's own asset.
    let faucet_config = &config.faucet;
    let fee_parameters = FeeParameters::new(operator_id, faucet_config.verification_base_fee);
    let min_burn_amount = faucet_config
        .min_burn_amount
        .map(AssetAmount::new)
        .transpose()
        .context("min_burn_amount is not a valid asset amount")?;
    let faucet = XReserveStablecoinBuilder::builder()
        .max_supply(AssetAmount::new(faucet_config.max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(faucet_config.token_supply).context("invalid token_supply")?)
        .owner(wallet_id(&ground_wallets, Role::Owner))
        .attest_admin_holder(wallet_id(&ground_wallets, Role::AttestAdmin))
        .pauser_holder(wallet_id(&ground_wallets, Role::Pauser))
        .unpauser_holder(wallet_id(&ground_wallets, Role::Unpauser))
        .blocklist_manager_holder(wallet_id(&ground_wallets, Role::BlocklistManager))
        .fee_parameters(fee_parameters)
        .domain(faucet_config.domain)
        .maybe_min_burn_amount(min_burn_amount)
        .build()
        .context("composing the xUSDC faucet builder")?
        .build_genesis_account(faucet_config.seed.as_bytes())
        .context("building the genesis faucet account")?;

    // Promote the wallets to nonce one. The operator additionally receives the genesis
    // circulating supply: exactly the faucet's initial token_supply.
    let mut wallets = Vec::new();
    for (role, account, secrets) in ground_wallets {
        let vault_override = if role == Role::Operator && faucet_config.token_supply > 0 {
            let supply = FungibleAsset::new(faucet.id(), faucet_config.token_supply)
                .context("the genesis supply is not a valid fungible asset")?;
            Some(
                AssetVault::new(&[supply.into()])
                    .context("building the operator's funded vault")?,
            )
        } else {
            None
        };
        let account = promote_to_genesis(account, vault_override)
            .with_context(|| format!("promoting the {} wallet to nonce one", role.as_str()))?;
        wallets.push(BuiltAccount {
            role,
            account,
            secrets,
        });
    }

    Ok(GenesisAccounts { wallets, faucet })
}

/// Returns the ground (nonce-zero) wallet id for `role`.
fn wallet_id(
    wallets: &[(Role, Account, Vec<AuthSecretKey>)],
    role: Role,
) -> miden_protocol::account::AccountId {
    wallets
        .iter()
        .find(|(candidate, ..)| *candidate == role)
        .expect("build_all builds every role before asking for its id")
        .1
        .id()
}

/// Rebuilds a nonce-zero account at nonce one with no seed — a genesis account exists, it is not
/// deployed — optionally swapping in a pre-funded vault (vault contents do not enter the id).
fn promote_to_genesis(account: Account, vault_override: Option<AssetVault>) -> Result<Account> {
    let (id, vault, storage, code, _nonce, _seed) = account.into_parts();
    let vault = vault_override.unwrap_or(vault);
    Account::new(id, vault, storage, code, Felt::ONE, None)
        .context("rebuilding the account at nonce one")
}
