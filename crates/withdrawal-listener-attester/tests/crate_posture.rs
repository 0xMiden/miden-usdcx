//! The crate's own posture: the config surface, and the types this slice consumes BY REFERENCE
//! rather than forking.

use miden_protocol::account::AccountId;
use withdrawal_listener_attester::evidence::assemble_evidence;
use withdrawal_listener_attester::types::ProofStrength;

// The unit adapter — the only way to obtain an `EvidencePackage` now
// that its constructor
// is sealed. Shared rather than re-declared, so this file and `evidence_trust_labeling.rs` cannot
// drift onto two different ideas of what an honest set of reads looks like (shared fixtures).
#[path = "evidence_support/mod.rs"]
mod evidence_support;

use evidence_support::{burn_note_id, burn_nullifier, faucet_id, UnitPort, CREATE_BLOCK};
use miden_standards::interop::eth::EthEmbeddedAccountId;

/// A real, parseable xUSDC faucet id, not a fabricated one.
const FAUCET_ID_HEX: &str = "0xbb405fd9fe431bd1135a292de098cb";

// THE TYPES THIS SLICE CONSUMES BY REFERENCE
// ================================================================================================

#[test]
fn the_evidence_package_labels_each_element_with_its_documented_proof_strength() {
    // Circle's documentation — the labels are reproduced from the evidence table, and they are not
    // decoration:
    // `burnTxId` is NODE-TRUSTED (there is no GetTransactionById), while the note id and block
    // number are CRYPTOGRAPHIC via the inclusion proof. Telling Circle otherwise would overstate what
    // Miden proves.
    //
    // The package is ASSEMBLED rather than constructed from literals, because it can no longer be
    // constructed from literals: `EvidencePackage::new` is `pub(crate)`, so the only package that
    // exists outside the crate is one whose consumption evidence was actually read and checked.
    // Minting one from four made-up values is precisely the bypass that narrowing closed, and the
    // labels are worth more asserted on a package that came through the real gate.
    let evidence = assemble_evidence(&UnitPort::honest(), burn_note_id(), faucet_id())
        .expect("the honest port assembles");

    assert_eq!(evidence.note_id_strength(), ProofStrength::Cryptographic);
    assert_eq!(evidence.block_num_strength(), ProofStrength::Cryptographic);
    assert_eq!(evidence.burn_tx_id_strength(), ProofStrength::NodeTrusted);
    assert_eq!(evidence.nullifier_strength(), ProofStrength::NodeTrusted);

    // the Circle wire wants 0x-hex, and the package renders it rather than making each caller do it
    assert_eq!(
        evidence.note_id_hex(),
        format!("0x{}", hex::encode(burn_note_id().as_word().as_bytes()))
    );
    assert_eq!(
        evidence.nullifier_hex(),
        format!("0x{}", hex::encode(burn_nullifier().as_word().as_bytes()))
    );
    assert_eq!(evidence.block_num(), CREATE_BLOCK);
}

#[test]
fn the_remote_depositor_encoding_is_unit_04s_account_id_codec_consumed_by_reference() {
    // `metadata.sender → remoteDepositor` goes through the shared AccountId↔bytes32 helper.
    // This crate does not redefine that encoding — it calls it, and this test pins that the wire
    // string the request carries is exactly what that codec produces.
    let faucet = AccountId::from_hex(FAUCET_ID_HEX).unwrap();
    let bytes = EthEmbeddedAccountId::from_account_id(faucet).to_bytes32();

    let wire = format!("0x{}", hex::encode(bytes));
    assert_eq!(wire.len(), 66, "0x + 64 hex digits");
    assert!(
        wire.starts_with(&"0x".to_string()) && wire[2..34] == "0".repeat(32),
        "the R-B layout leaves the first 16 bytes zero: {wire}"
    );
}
