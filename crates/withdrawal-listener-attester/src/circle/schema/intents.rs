//! `POST /v1/prepare-withdrawal` — the RESPONSE Circle returns (`DC-10`).
//!
//! The burn intents, the `TransferSpec`s they embed, the `encoded` binary blob, and the digest the
//! attesters sign.

use serde::{Deserialize, Serialize};

use crate::circle::wire::{Calldata, DecimalUint, Hex20, Hex32};

/// `POST /v1/prepare-withdrawal` response — the top-level `batches[]` **wrapper**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareWithdrawalResponse {
    batches: Vec<PreparedBatch>,
}

impl PrepareWithdrawalResponse {
    pub fn batches(&self) -> &[PreparedBatch] {
        &self.batches
    }
}

/// One returned batch: Circle's burn intents, the binary form it encoded, and the digest to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedBatch {
    burn_intents: Vec<BurnIntent>,

    /// The binary burn intent Circle encoded — **opaque to the partner**, and typed `string` with NO
    /// pattern in the OpenAPI, so none is imposed. The JSON→binary transform is `REQUIRES CIRCLE
    /// CONFIRMATION` and is off the partner's critical path precisely because Circle returns this
    /// (`CIRCLE-DATA-SCHEMAS.md` §3.4). Never reconstructed here.
    encoded: String,

    /// The EIP-712 final digest the attesters sign (domain name `"GatewayWallet"`, version `"1"`,
    /// omitting `chainId`/`verifyingContract`). Also typed `string` with no documented pattern. That
    /// it equals the Gateway pipeline's step-3 digest is `Q-CRY-2` — OPEN — so the partner treats it
    /// as **opaque-and-sign** and does NO on-chain typed-data hashing on Miden
    /// (`INV-OFFCHAIN-BURN-SIGNING`).
    message_hash_to_sign: String,
}

impl PreparedBatch {
    pub fn burn_intents(&self) -> &[BurnIntent] {
        &self.burn_intents
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub fn message_hash_to_sign(&self) -> &str {
        &self.message_hash_to_sign
    }
}

/// The API (JSON) `BurnIntent`. Distinct from the binary Gateway `BurnIntent` (72-byte header +
/// encoded `TransferSpec`) — do not conflate the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BurnIntent {
    /// A decimal STRING: a `uint256` block height does not survive a JSON number.
    max_block_height: DecimalUint,

    /// The operator fee cap, in the smallest token unit. A decimal string, same reason.
    max_fee: DecimalUint,

    spec: TransferSpec,
}

impl BurnIntent {
    pub fn max_block_height(&self) -> &str {
        self.max_block_height.as_str()
    }

    pub fn max_fee(&self) -> &str {
        self.max_fee.as_str()
    }

    pub fn spec(&self) -> &TransferSpec {
        &self.spec
    }
}

/// The API (JSON) `TransferSpec` — 14 required fields.
///
/// Its `hookData` is a **structured object** ([`StructuredHookData`]), NOT the hex bytes string the
/// binary `WithdrawHookData` is. `CIRCLE-DATA-SCHEMAS.md` §3.4 spells out the difference field by
/// field and labels it "DO NOT CONFLATE"; the JSON form omits the binary `magic`, `version` and
/// length prefixes, and types the forwarding contract as 20 bytes where the binary form uses 32.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSpec {
    version: u32,
    source_domain: u32,
    destination_domain: u32,
    source_contract: Hex32,
    destination_contract: Hex32,
    source_token: Hex32,
    destination_token: Hex32,

    /// The address debited on the source side — **Circle assigns this** (`Q-DOM-3`). It appears here,
    /// on the RESPONSE, and never on [`PrepareBurnIntentInput`](super::PrepareBurnIntentInput).
    source_depositor: Hex32,

    destination_recipient: Hex32,
    source_signer: Hex32,

    /// May be all-zero (any caller).
    destination_caller: Hex32,

    /// The transfer amount in the SMALLEST TOKEN UNIT — not the request's decimal form.
    value: DecimalUint,

    salt: Hex32,
    hook_data: StructuredHookData,
}

impl TransferSpec {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn source_domain(&self) -> u32 {
        self.source_domain
    }

    /// Compared against the burn note's `destDomain` at the B5 gate.
    pub fn destination_domain(&self) -> u32 {
        self.destination_domain
    }

    pub fn source_contract(&self) -> &str {
        self.source_contract.as_str()
    }

    pub fn destination_contract(&self) -> &str {
        self.destination_contract.as_str()
    }

    pub fn source_token(&self) -> &str {
        self.source_token.as_str()
    }

    pub fn destination_token(&self) -> &str {
        self.destination_token.as_str()
    }

    /// Circle-assigned (`Q-DOM-3`) — never partner-supplied.
    pub fn source_depositor(&self) -> &str {
        self.source_depositor.as_str()
    }

    /// Compared against the burn note's `destRecipient` at the B5 gate.
    pub fn destination_recipient(&self) -> &str {
        self.destination_recipient.as_str()
    }

    pub fn source_signer(&self) -> &str {
        self.source_signer.as_str()
    }

    pub fn destination_caller(&self) -> &str {
        self.destination_caller.as_str()
    }

    /// Compared against the burn note's `amount` at the B5 gate.
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    pub fn salt(&self) -> &str {
        self.salt.as_str()
    }

    pub fn hook_data(&self) -> &StructuredHookData {
        &self.hook_data
    }
}

/// The JSON form of `TransferSpec.hookData`. **Not** the binary `WithdrawHookData` (§3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredHookData {
    remote_domain: u32,
    remote_depositor: Hex32,
    remote_token: Hex32,

    /// **20 bytes** here, where the binary `WithdrawHookData.forwardingContract` is 32. Circle
    /// left-pads during its server-side encoding.
    forwarding_contract_address: Hex20,

    /// `0x` + a 4-byte selector + optional data, or bare `0x` when not forwarding.
    forwarding_calldata: Calldata,
}

impl StructuredHookData {
    pub fn remote_domain(&self) -> u32 {
        self.remote_domain
    }

    pub fn remote_depositor(&self) -> &str {
        self.remote_depositor.as_str()
    }

    pub fn remote_token(&self) -> &str {
        self.remote_token.as_str()
    }

    pub fn forwarding_contract_address(&self) -> &str {
        self.forwarding_contract_address.as_str()
    }

    pub fn forwarding_calldata(&self) -> &str {
        self.forwarding_calldata.as_str()
    }
}
