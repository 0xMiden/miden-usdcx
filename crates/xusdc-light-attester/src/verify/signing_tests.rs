//! Checks signing order and ownership without a real signing backend.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Signature, B256, U256};

use crate::signer::{Signer, SignerError, SigningPublicKey};
use crate::tests::verified_withdrawal;

struct RecordingSigner {
    id: u8,
    calls: Arc<Mutex<Vec<(u8, B256)>>>,
    fail_at: Option<usize>,
}

impl Signer for RecordingSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        // Signer 1 holds the key with the lower Ethereum address, so ids follow address order.
        let key = match self.id {
            1 => alloy_primitives::hex!(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            ),
            _ => alloy_primitives::hex!(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
        };
        Box::pin(async move { Ok(SigningPublicKey(key)) })
    }

    fn sign_digest(
        &self,
        digest: B256,
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignerError>> + Send + '_>> {
        Box::pin(async move {
            let mut calls = self.calls.lock().unwrap();
            calls.push((self.id, digest));
            if self.fail_at == Some(calls.len()) {
                return Err(SignerError);
            }
            // Distinct markers per signer and call, not cryptographic signatures.
            Ok(Signature::new(
                U256::from(self.id),
                U256::from(calls.len()),
                false,
            ))
        })
    }
}

/// Both signers receive the checked hash, and both results stay with the original burn.
#[tokio::test]
async fn verified_withdrawal_gets_two_signatures() {
    let verified = verified_withdrawal();
    let expected = verified_withdrawal();
    let digest = expected.batch.digest;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let signers = [1, 2].map(|id| RecordingSigner {
        id,
        calls: calls.clone(),
        fail_at: None,
    });

    let signed = verified.sign([&signers[0], &signers[1]]).await.unwrap();
    assert_eq!(*calls.lock().unwrap(), [(1, digest), (2, digest)]);
    assert_eq!(signed.batch.batch.note_id, expected.batch.note_id);
    assert_eq!(signed.batch.batch.burn_tx_id, expected.batch.burn_tx_id);
    assert_eq!(signed.batch.batch.digest, digest);
    let (intent, _) = super::parse_intent(&signed.batch.batch.intent).unwrap();
    assert_eq!(intent.signing_hash(), digest);
    assert_eq!(
        signed.batch.signatures,
        [
            Signature::new(U256::from(1), U256::from(1), false),
            Signature::new(U256::from(2), U256::from(2), false),
        ]
    );
}

/// A failure from either signer stops the call sequence and returns no partial withdrawal.
#[tokio::test]
async fn signing_failure_returns_no_result() {
    for fail_at in 1..=2 {
        let verified = verified_withdrawal();
        let digest = verified.batch.digest;
        let expected = [(1, digest), (2, digest)];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signers = [1, 2].map(|id| RecordingSigner {
            id,
            calls: calls.clone(),
            fail_at: Some(fail_at),
        });

        assert!(matches!(
            verified.sign([&signers[0], &signers[1]]).await,
            Err(SignerError)
        ));
        assert_eq!(calls.lock().unwrap().as_slice(), &expected[..fail_at]);
    }
}

/// Signatures come out in ascending signer-address order however the pair is configured, and two
/// signers behind one address are rejected before anything is signed.
#[tokio::test]
async fn signatures_follow_signer_address_order() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let signers = [1, 2].map(|id| RecordingSigner {
        id,
        calls: calls.clone(),
        fail_at: None,
    });

    let signed = verified_withdrawal()
        .sign([&signers[1], &signers[0]])
        .await
        .unwrap();
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        signed.batch.signatures[0],
        Signature::new(U256::from(1), U256::from(1), false)
    );

    let same = [1, 1].map(|id| RecordingSigner {
        id,
        calls: calls.clone(),
        fail_at: None,
    });
    assert!(matches!(
        verified_withdrawal().sign([&same[0], &same[1]]).await,
        Err(SignerError)
    ));
    assert_eq!(
        calls.lock().unwrap().len(),
        2,
        "nothing is signed for an invalid pair"
    );
}
