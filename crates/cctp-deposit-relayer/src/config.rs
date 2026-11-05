use alloy_primitives::{keccak256, Address, B256};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use url::Url;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub journal: PathBuf,
    pub arc_rpc: Url,
    pub circle_url: Url,
    pub chain_id: u64,
    pub arc_domain: u32,
    pub helper: Address,
    pub helper_code_hash: B256,
    pub messenger: Address,
    pub signer: Address,
    pub kms: Kms,
    pub max_gas: u64,
    pub max_fee_per_gas: u128,
    pub priority_fee_per_gas: u128,
    pub pending_timeout_secs: u64,
    pub queue_capacity: usize,
    pub sources: Vec<Source>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Kms {
    pub region: String,
    pub key_arn: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Source {
    pub domain: u32,
    pub rpc: Url,
    #[serde(flatten)]
    pub network: Network,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "runtime", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Network {
    Evm {
        chain_id: u64,
        messenger: Address,
        transmitter: Address,
        usdc: Address,
        start_block: u64,
        start_hash: B256,
    },
    Solana {
        genesis_hash: String,
        messenger: String,
        usdc: String,
        start_signature: String,
        start_slot: u64,
    },
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.chain_id > 0 && self.arc_domain == 26,
            "invalid Arc identity"
        );
        ensure!(
            !self.helper.is_zero()
                && !self.messenger.is_zero()
                && !self.signer.is_zero()
                && self.helper_code_hash != B256::ZERO,
            "missing destination identity"
        );
        ensure!(
            self.max_gas > 0
                && self.max_gas <= 10_000_000
                && self.max_fee_per_gas > 0
                && self.priority_fee_per_gas <= self.max_fee_per_gas,
            "invalid gas limits"
        );
        ensure!(
            (1..=100_000).contains(&self.queue_capacity)
                && (60..=604800).contains(&self.pending_timeout_secs),
            "invalid service bounds"
        );
        ensure!(
            !self.kms.region.is_empty() && !self.kms.key_arn.is_empty(),
            "missing signer settings"
        );
        endpoint(&self.arc_rpc)?;
        endpoint(&self.circle_url)?;
        ensure!(
            !self.sources.is_empty() && self.sources.len() <= 32,
            "invalid source count"
        );
        let mut domains = BTreeSet::new();
        for source in &self.sources {
            endpoint(&source.rpc)?;
            ensure!(
                source.domain != self.arc_domain && domains.insert(source.domain),
                "duplicate source domain"
            );
            match &source.network {
                Network::Evm {
                    chain_id,
                    messenger,
                    transmitter,
                    usdc,
                    start_block,
                    start_hash,
                } => {
                    ensure!(
                        *chain_id > 0
                            && !messenger.is_zero()
                            && !transmitter.is_zero()
                            && !usdc.is_zero()
                            && *start_block <= i64::MAX as u64
                            && *start_hash != B256::ZERO,
                        "invalid EVM source"
                    );
                }
                Network::Solana {
                    genesis_hash,
                    messenger,
                    usdc,
                    start_signature,
                    start_slot,
                } => {
                    base58::<32>(genesis_hash)?;
                    base58::<32>(messenger)?;
                    base58::<32>(usdc)?;
                    base58::<64>(start_signature)?;
                    ensure!(*start_slot <= i64::MAX as u64, "invalid source slot");
                }
            }
        }
        Ok(())
    }
    pub fn identity(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .context("invalid config")?
            .remove("journal");
        Ok(keccak256(serde_json::to_vec(&value)?).to_string())
    }
    pub fn source(&self, domain: u32) -> Result<&Source> {
        self.sources
            .iter()
            .find(|s| s.domain == domain)
            .context("unknown source")
    }
}
impl Source {
    pub fn transaction(&self, s: &str) -> Result<String> {
        match self.network {
            Network::Evm { .. } => Ok(s.parse::<B256>()?.to_string()),
            Network::Solana { .. } => {
                base58::<64>(s)?;
                Ok(s.to_owned())
            }
        }
    }
    pub fn route(&self) -> Result<(B256, B256)> {
        match &self.network {
            Network::Evm {
                messenger, usdc, ..
            } => Ok((
                crate::message::padded(*messenger),
                crate::message::padded(*usdc),
            )),
            Network::Solana {
                messenger, usdc, ..
            } => Ok((base58::<32>(messenger)?.into(), base58::<32>(usdc)?.into())),
        }
    }
}
fn endpoint(url: &Url) -> Result<()> {
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
        "endpoint must use HTTPS or loopback"
    );
    ensure!(url.fragment().is_none(), "endpoint fragment forbidden");
    Ok(())
}
pub(crate) fn base58<const N: usize>(s: &str) -> Result<[u8; N]> {
    ensure!(s.len() <= N * 2, "base58 input too long");
    bs58::decode(s)
        .into_vec()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid base58 width"))
}
