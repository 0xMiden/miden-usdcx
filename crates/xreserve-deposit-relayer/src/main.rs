//! Binary entry point (scaffold). The poll→validate→build→submit loop (Circle attestation fetch
//! CMP-D3/D4, the idempotency seam, and the Miden submit leg CMP-E8) is OUT of scope for this
//! slice; `main` only constructs the parsed config so the async runtime + config wiring compile end
//! to end. This scaffold slice ships only the DepositIntent structural decoder.

use xreserve_deposit_relayer::config::RelayerConfig;

#[tokio::main]
async fn main() {
    let _config = RelayerConfig::default();
    // Later slices: fetch attestations, validate the (DepositIntent, signature, pubkey) triple,
    // build the public XReserveMintNote, and submit it via `miden-client`.
}
