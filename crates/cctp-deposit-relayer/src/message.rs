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
// None means a complete unrelated route; relevant unsupported layouts remain visible errors.
pub(crate) fn select(
    bytes: &[u8],
    config: &Config,
    source: &Source,
    attested: bool,
) -> Result<Option<B256>> {
    ensure!(bytes.len() >= 216, "truncated source message");
    if number(bytes, 8)? != config.arc_domain
        || word(bytes, 108)? != padded(config.helper)
        || word(bytes, 184)? != padded(config.helper)
    {
        return Ok(None);
    }
    let (messenger, token) = source.route()?;
    ensure!(
        bytes.len() == 440 && number(bytes, 0)? == 1 && number(bytes, 148)? == 1,
        "unsupported helper message"
    );
    ensure!(
        number(bytes, 4)? == source.domain
            && word(bytes, 44)? == messenger
            && word(bytes, 76)? == padded(config.messenger)
            && word(bytes, 152)? == token,
        "helper source route mismatch"
    );
    ensure!(
        number(bytes, 140)? == 2000
            && word(bytes, 376)? == B256::from(U256::from(1).to_be_bytes::<32>()),
        "unsupported helper Standard request"
    );
    let nonce = word(bytes, 12)?;
    if attested {
        ensure!(
            nonce != B256::ZERO && number(bytes, 144)? >= 2000 && word(bytes, 344)? == B256::ZERO,
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
