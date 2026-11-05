use crate::{
    abi::{Helper, Transmitter},
    config::Config,
    discovery::evm::block,
    message::{select, unhex, Message},
    rpc::{height, hex_u128, hex_u64, Rpc},
    store::{Pending, Store},
};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, Transaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{keccak256, Address, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use anyhow::{ensure, Context, Result};
use serde_json::json;
use usdcx_kms_signer::Signer;

pub(crate) struct ArcSender {
    pub rpc: Rpc,
    transmitter: Address,
}
impl ArcSender {
    pub fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            rpc: Rpc::new(config.arc_rpc.clone())?,
            transmitter: Address::ZERO,
        })
    }
    pub async fn verify(&mut self, config: &Config) -> Result<()> {
        ensure!(
            hex_u64(&self.rpc.call("eth_chainId", json!([])).await?)? == config.chain_id,
            "Arc chain identity mismatch"
        );
        let value = self
            .rpc
            .call("eth_getCode", json!([config.helper, "finalized"]))
            .await?;
        let bytes = unhex(value.as_str().context("helper runtime unavailable")?, 65536)?;
        ensure!(
            !bytes.is_empty() && keccak256(bytes) == config.helper_code_hash,
            "helper runtime identity mismatch"
        );
        self.transmitter = Address::from_word(
            self.view(
                config.helper,
                Helper::messageTransmitterCall {}.abi_encode(),
            )
            .await?,
        );
        let messenger = Address::from_word(
            self.view(config.helper, Helper::tokenMessengerCall {}.abi_encode())
                .await?,
        );
        ensure!(
            !self.transmitter.is_zero() && messenger == config.messenger,
            "helper binding mismatch"
        );
        Ok(())
    }
    async fn view(&self, target: Address, data: Vec<u8>) -> Result<B256> {
        let value = self
            .rpc
            .call(
                "eth_call",
                json!([{"to":target,"data":format!("0x{}",hex::encode(data))},"finalized"]),
            )
            .await?;
        let bytes = unhex(value.as_str().context("missing view result")?, 32)?;
        ensure!(bytes.len() == 32, "invalid view width");
        Ok(B256::from_slice(&bytes))
    }
    pub async fn nonces(&self, config: &Config) -> Result<(u64, u64)> {
        let finalized = self
            .rpc
            .call(
                "eth_getTransactionCount",
                json!([config.signer, "finalized"]),
            )
            .await?;
        let pending = self
            .rpc
            .call("eth_getTransactionCount", json!([config.signer, "pending"]))
            .await?;
        Ok((hex_u64(&finalized)?, hex_u64(&pending)?))
    }
    pub async fn used(&self, nonce: B256) -> Result<bool> {
        ensure!(
            nonce != B256::ZERO && !self.transmitter.is_zero(),
            "invalid transmitter nonce query"
        );
        Ok(self
            .view(
                self.transmitter,
                Transmitter::usedNoncesCall { nonce }.abi_encode(),
            )
            .await?
            != B256::ZERO)
    }
    pub async fn prepare(
        &self,
        config: &Config,
        message: &Message,
        nonce: u64,
        signer: &dyn Signer,
        now: i64,
    ) -> Result<Pending> {
        ensure!(
            select(&message.bytes, config, config.source(message.domain)?, true)?
                == Some(message.nonce),
            "queued message mismatch"
        );
        let calldata = calldata(message);
        let call = json!({"from":config.signer,"to":config.helper,"value":"0x0","data":format!("0x{}",hex::encode(&calldata)),"gas":height(config.max_gas)});
        self.rpc
            .call("eth_call", json!([call, "latest"]))
            .await
            .context("exact helper simulation failed")?;
        let estimate = hex_u64(
            &self
                .rpc
                .call("eth_estimateGas", json!([call]))
                .await
                .context("helper gas estimation failed")?,
        )?;
        ensure!(
            estimate > 0 && estimate <= config.max_gas,
            "helper gas estimate exceeds cap"
        );
        let gas_price = hex_u128(
            &self
                .rpc
                .call("eth_gasPrice", json!([]))
                .await
                .context("gas price lookup failed")?,
        )?;
        let fee = gas_price
            .checked_mul(2)
            .and_then(|n| n.checked_add(config.priority_fee_per_gas))
            .context("fee overflow")?;
        ensure!(
            fee <= config.max_fee_per_gas && fee >= config.priority_fee_per_gas,
            "fee exceeds cap"
        );
        let balance = hex_u128(
            &self
                .rpc
                .call("eth_getBalance", json!([config.signer, "latest"]))
                .await
                .context("balance lookup failed")?,
        )?;
        ensure!(
            u128::from(config.max_gas)
                .checked_mul(fee)
                .is_some_and(|cost| cost <= balance),
            "insufficient gas balance"
        );
        let tx = TxEip1559 {
            chain_id: config.chain_id,
            nonce,
            gas_limit: config.max_gas,
            max_fee_per_gas: fee,
            max_priority_fee_per_gas: config.priority_fee_per_gas,
            to: TxKind::Call(config.helper),
            value: U256::ZERO,
            input: calldata.into(),
            access_list: Default::default(),
        };
        let digest = tx.signature_hash();
        let signature = signer
            .sign_digest(digest)
            .await
            .context("KMS digest signing failed")?;
        ensure!(
            signature.normalize_s().is_none()
                && Address::from_public_key(
                    &signature
                        .recover_from_prehash(&digest)
                        .context("digest signer mismatch")?
                ) == config.signer,
            "digest signer mismatch"
        );
        let raw = tx.into_signed(signature).encoded_2718();
        let p = Pending {
            message: message.clone(),
            eoa_nonce: nonce,
            hash: keccak256(&raw),
            raw,
            created: now,
        };
        validate_saved(config, &p, nonce)?;
        Ok(p)
    }
    pub async fn submit(&self, config: &Config, store: &mut Store, p: &Pending) -> Result<()> {
        validate_saved(config, p, store.next_nonce()?)?;
        store.save_pending(p)?;
        let saved = store.pending()?.context("committed pending row missing")?;
        // Broadcast only the row reread after the successful durable commit.
        self.broadcast(config, &saved).await
    }
    pub async fn broadcast(&self, config: &Config, p: &Pending) -> Result<()> {
        validate_saved(config, p, p.eoa_nonce)?;
        let hash = self
            .rpc
            .call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(&p.raw))]),
            )
            .await?;
        ensure!(
            hash.as_str()
                .context("send hash missing")?
                .parse::<B256>()?
                == p.hash,
            "send hash mismatch"
        );
        Ok(())
    }
    pub async fn reconcile(
        &self,
        config: &Config,
        store: &mut Store,
        p: &Pending,
        now: i64,
    ) -> Result<()> {
        validate_saved(config, p, store.next_nonce()?)?;
        let finalized = hex_u64(&block(&self.rpc, "finalized").await?["number"])?;
        let receipt = self
            .rpc
            .call("eth_getTransactionReceipt", json!([p.hash]))
            .await?;
        if !receipt.is_null() {
            let checked = async {
                ensure!(
                    receipt["transactionHash"]
                        .as_str()
                        .context("receipt hash missing")?
                        .parse::<B256>()?
                        == p.hash,
                    "receipt hash mismatch"
                );
                ensure!(
                    receipt["from"]
                        .as_str()
                        .context("receipt sender missing")?
                        .parse::<Address>()?
                        == config.signer
                        && receipt["to"]
                            .as_str()
                            .context("receipt target missing")?
                            .parse::<Address>()?
                            == config.helper,
                    "receipt identity mismatch"
                );
                let number = hex_u64(&receipt["blockNumber"])?;
                if number > finalized {
                    return Ok(None);
                }
                let canonical = block(&self.rpc, &height(number)).await?;
                ensure!(
                    canonical["hash"] == receipt["blockHash"],
                    "receipt canonical block mismatch"
                );
                let status = hex_u64(&receipt["status"])?;
                ensure!(status <= 1, "invalid receipt status");
                Ok(Some(status == 1))
            }
            .await;
            match checked {
                Ok(Some(success)) => {
                    store.settle(p, success)?;
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => {
                    store.halt("receipt contradiction; manual recovery required")?;
                    return Ok(());
                }
            }
        } else {
            let (finalized, pending) = self.nonces(config).await?;
            if finalized != p.eoa_nonce || pending > p.eoa_nonce.saturating_add(1) {
                store.halt("unknown sender nonce consumption; manual recovery required")?;
                return Ok(());
            }
        }
        if now.saturating_sub(p.created) > config.pending_timeout_secs as i64 {
            store.halt("stale pending transaction; manual recovery required")?;
        }
        if receipt.is_null() && !store.halted()? {
            self.broadcast(config, p).await?;
        }
        Ok(())
    }
}
fn calldata(message: &Message) -> Vec<u8> {
    Helper::receiveAndDepositCall {
        message: message.bytes.clone().into(),
        attestation: message.attestation.clone().into(),
    }
    .abi_encode()
}
pub(crate) fn validate_saved(config: &Config, p: &Pending, next: u64) -> Result<()> {
    ensure!(
        p.raw.len() <= 70000
            && p.message.attestation.len() <= 65536
            && !p.message.attestation.is_empty()
            && p.message.attestation.len().is_multiple_of(65),
        "saved transaction exceeds bounds"
    );
    ensure!(
        select(
            &p.message.bytes,
            config,
            config.source(p.message.domain)?,
            true
        )? == Some(p.message.nonce),
        "saved message mismatch"
    );
    ensure!(keccak256(&p.raw) == p.hash, "saved raw hash mismatch");
    let mut bytes = p.raw.as_slice();
    let envelope = TxEnvelope::decode_2718(&mut bytes)?;
    ensure!(
        bytes.is_empty()
            && matches!(envelope, TxEnvelope::Eip1559(_))
            && envelope.recover_signer()? == config.signer
            && p.eoa_nonce == next
            && envelope.chain_id() == Some(config.chain_id)
            && envelope.nonce() == next
            && envelope.to() == Some(config.helper)
            && envelope.value() == U256::ZERO
            && envelope.input().as_ref() == calldata(&p.message)
            && envelope.gas_limit() > 0
            && envelope.gas_limit() <= config.max_gas
            && envelope.max_fee_per_gas() <= config.max_fee_per_gas
            && envelope
                .max_priority_fee_per_gas()
                .is_some_and(|tip| tip <= envelope.max_fee_per_gas())
            && envelope.access_list().is_some_and(|list| list.is_empty()),
        "saved signed bytes differ from fixed helper request"
    );
    Ok(())
}
