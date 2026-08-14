//! The OPTIONAL domain/token fast-fail (the optional domain/token fast-fail) — `remoteDomain == the
//! configured Miden domain` and `remoteToken == the configured xUSDC identifier`, corroborated
//! against Circle's own `GET /v1/info` discovery.
//!
//! # It is an optimization, and it must stay one
//!
//! Both comparisons happen ON-CHAIN in the faucet's deposit-intent parse, against the faucet's own
//! configuration, and only that verdict authorizes a mint. Everything here is LIVENESS: it saves a
//! block and a transaction fee by refusing a deposit the faucet would refuse anyway. A bug in this
//! file can withhold a mint; it cannot cause one. That asymmetry is why the check may be optional
//! at all — and why, when its expected values are placeholders, OFF is the safe default rather than
//! a gap.
//!
//! # Every expected value is Circle's to decide, and none is decided
//!
//! * The remote-domain id — `REQUIRES CIRCLE CONFIRMATION`. Circle has assigned Miden none.
//! * The xUSDC identifier — `REQUIRES CIRCLE CONFIRMATION` · `NO EVIDENCE OF CIRCLE APPROVAL`.
//!   Neither the identifier nor its AccountId↔bytes32 encoding is settled.
//!
//! So the configured values are placeholders the operator sets, this module compares against them,
//! and neither decision is marked resolved by anything here.

use crate::circle::schema::InfoResponse;
use crate::config::RelayerConfig;
use crate::error::RelayerError;
use xusdc_encoding::xreserve::encoding::{DepositIntent, EthEmbeddedAccountId};

/// Runs the fast-fail: does this attestation describe a deposit destined for the xUSDC faucet this
/// relayer serves?
///
/// Three questions, in the order an operator would want them answered:
///
/// 1. Is the intent's `remoteDomain` the configured one? A wrong domain means the deposit is not
///    Miden's at all.
/// 2. Is its `remoteToken` the configured xUSDC identifier? A wrong token means it is Miden's but
///    not this faucet's.
/// 3. Does Circle ADVERTISE the configured domain? A `no` here is not the attestation's fault — it
///    is the relayer's configuration disagreeing with Circle, which would refuse every honest
///    deposit. It is asked LAST precisely so a genuinely mismatching attestation still reports the
///    field that mismatched, rather than being blamed for a misconfiguration.
///
/// # Errors
/// [`RelayerError::DomainMismatch`] (1), [`RelayerError::TokenMismatch`] (2),
/// [`RelayerError::InfoDomainNotAdvertised`] (3). None is retryable: no amount of waiting turns one
/// domain into another.
pub fn check_domain_token_against_info(
    intent: &DepositIntent,
    info: &InfoResponse,
    config: &RelayerConfig,
) -> Result<(), RelayerError> {
    let header = intent.header();

    let expected_domain = config.remote_domain();
    if header.remote_domain() != expected_domain {
        return Err(RelayerError::DomainMismatch {
            expected: expected_domain,
            actual: header.remote_domain(),
        });
    }

    // the comparison runs in the wire form rather than as account ids: the configured identifier is
    // an operator-set placeholder that need not be a well-formed one at all (`REQUIRES CIRCLE
    // CONFIRMATION`), and a mismatch must report what was configured, not fail to parse it
    let expected_token = config.xusdc_identifier();
    let actual_token = EthEmbeddedAccountId::from_account_id(header.remote_token()).to_bytes32();
    if &actual_token != expected_token {
        return Err(RelayerError::TokenMismatch {
            expected: *expected_token,
            actual: actual_token,
        });
    }

    // Circle's own discovery is the corroboration: the expected domain above is an OPERATOR's claim
    // about a domain id that is still OPEN (Circle's to assign), and this is the one place the relayer can hear Circle's
    // answer to it. Read through the schema's own lookup (`InfoResponse::remote_domain`) rather than
    // by scanning the list here, so the shape stays owned in one place.
    if info.remote_domain(expected_domain).is_none() {
        return Err(RelayerError::InfoDomainNotAdvertised {
            domain: expected_domain,
        });
    }

    Ok(())
}
