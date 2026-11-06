use crate::config::{Config, Source};
use alloy_primitives::{Address, B256, U256};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Position {
    pub ordinal: u64,
    pub digest: B256,
}
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub transaction: String,
    pub positions: Vec<Position>,
    pub manual: bool,
}
#[derive(Clone, Debug)]
pub(crate) struct Message {
    pub nonce: B256,
    pub domain: u32,
    pub transaction: String,
    pub bytes: Vec<u8>,
    pub attestation: Vec<u8>,
}
// Absolute offsets in Circle's CCTP v2 MessageV2/BurnMessageV2 layout.
const VERSION_OFFSET: usize = 0;
const SOURCE_DOMAIN_OFFSET: usize = 4;
const DESTINATION_DOMAIN_OFFSET: usize = 8;
const CCTP_NONCE_OFFSET: usize = 12;
const SENDER_OFFSET: usize = 44;
const RECIPIENT_OFFSET: usize = 76;
const DESTINATION_CALLER_OFFSET: usize = 108;
const MIN_FINALITY_OFFSET: usize = 140;
const EXECUTED_FINALITY_OFFSET: usize = 144;
const BURN_BODY_OFFSET: usize = 148;
const BURN_TOKEN_OFFSET: usize = BURN_BODY_OFFSET + 4;
const MINT_RECIPIENT_OFFSET: usize = BURN_BODY_OFFSET + 36;
const EXPIRATION_BLOCK_OFFSET: usize = BURN_BODY_OFFSET + 196;
const APPLICATION_HOOK_OFFSET: usize = BURN_BODY_OFFSET + 228;
const ROUTING_PREFIX_LENGTH: usize = MINT_RECIPIENT_OFFSET + 32;
pub(crate) const APPLICATION_HOOK_LENGTH: usize = 64;
pub(crate) const APPLICATION_HOOK_VERSION: u32 = 1;
pub(crate) const STANDARD_FINALITY: u32 = 2000;
const HELPER_MESSAGE_LENGTH: usize = APPLICATION_HOOK_OFFSET + APPLICATION_HOOK_LENGTH;

// None means only that the routing prefix targets another destination. Its full
// layout is not validated; relevant routes must satisfy every supported-layout check.
pub(crate) fn select(
    bytes: &[u8],
    config: &Config,
    source: &Source,
    attested: bool,
) -> Result<Option<B256>> {
    ensure!(
        bytes.len() >= ROUTING_PREFIX_LENGTH,
        "truncated source message"
    );
    if number(bytes, DESTINATION_DOMAIN_OFFSET)? != config.arc_domain
        || word(bytes, DESTINATION_CALLER_OFFSET)? != padded(config.helper)
        || word(bytes, MINT_RECIPIENT_OFFSET)? != padded(config.helper)
    {
        return Ok(None);
    }
    let (messenger, token) = source.route()?;
    ensure!(
        bytes.len() == HELPER_MESSAGE_LENGTH
            && number(bytes, VERSION_OFFSET)? == 1
            && number(bytes, BURN_BODY_OFFSET)? == 1,
        "unsupported helper message"
    );
    ensure!(
        number(bytes, SOURCE_DOMAIN_OFFSET)? == source.domain
            && word(bytes, SENDER_OFFSET)? == messenger
            && word(bytes, RECIPIENT_OFFSET)? == padded(config.messenger)
            && word(bytes, BURN_TOKEN_OFFSET)? == token,
        "helper source route mismatch"
    );
    ensure!(
        number(bytes, MIN_FINALITY_OFFSET)? == STANDARD_FINALITY
            && word(bytes, APPLICATION_HOOK_OFFSET)?
                == B256::from(U256::from(APPLICATION_HOOK_VERSION).to_be_bytes::<32>()),
        "unsupported helper Standard request"
    );
    let nonce = word(bytes, CCTP_NONCE_OFFSET)?;
    // Source burns have no assigned Circle nonce yet. Attested messages require a
    // nonzero nonce, executed Standard finality and no expiration.
    if attested {
        ensure!(
            nonce != B256::ZERO
                && number(bytes, EXECUTED_FINALITY_OFFSET)? >= STANDARD_FINALITY
                && word(bytes, EXPIRATION_BLOCK_OFFSET)? == B256::ZERO,
            "unsupported helper attestation"
        );
    }
    Ok(Some(nonce))
}
pub(crate) fn word(bytes: &[u8], offset: usize) -> Result<B256> {
    Ok(B256::from_slice(
        bytes
            .get(offset..offset + 32)
            .context("message word missing")?,
    ))
}
pub(crate) fn number(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .context("message number missing")?
            .try_into()?,
    ))
}
pub(crate) fn padded(address: Address) -> B256 {
    let mut out = [0; 32];
    out[12..].copy_from_slice(address.as_slice());
    out.into()
}
pub(crate) fn unhex(s: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        s.starts_with("0x") && s.len().is_multiple_of(2) && s.len() <= max * 2 + 2,
        "invalid bounded hex"
    );
    Ok(hex::decode(&s[2..])?)
}
