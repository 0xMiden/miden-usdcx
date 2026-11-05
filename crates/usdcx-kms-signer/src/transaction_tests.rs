//! Deterministic local signing seam; this test never constructs an AWS client.
use alloy_consensus::{transaction::SignerRecoverable, SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use k256::ecdsa::SigningKey;

#[test]
fn digest_signature_encodes_and_recovers_an_eip1559_transaction() {
    // Public deterministic fixture, not an operator credential.
    let key = SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
    let tx = TxEip1559 {
        chain_id: 5042002,
        nonce: 7,
        gas_limit: 500_000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(Address::repeat_byte(0x22)),
        value: U256::ZERO,
        input: Bytes::from_static(&[0x12, 0x34, 0x56, 0x78]),
        access_list: Default::default(),
    };
    let (signature, recovery) = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap();
    assert!(!recovery.is_x_reduced());
    let signed = tx.into_signed(Signature::from_signature_and_parity(
        signature,
        recovery.is_y_odd(),
    ));
    let raw = signed.encoded_2718();
    let decoded = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
    assert_eq!(raw.len(), 114);
    assert_eq!(*decoded.tx_hash(), *signed.hash());
    assert_eq!(
        decoded.recover_signer().unwrap(),
        Address::from_private_key(&key)
    );
    assert_eq!(
        format!("{}", signed.hash()),
        "0xe5dd2b15914252fbdf373b46794846a07191e0947f3b42370db327a7f6f53d38"
    );
}
