//! Checks development signatures, signing order, and ownership.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Signature, B256, U256};

use crate::signer::{DevelopmentSigner, Signer, SignerError, SigningPublicKey};
use crate::tests::verified_withdrawal;

#[tokio::test]
async fn development_signers_sign_the_exact_digest() {
    let digest = alloy_primitives::keccak256(b"xUSDC attester development signing");
    for (scalar, expected_public_key) in [
        (
            1,
            alloy_primitives::hex!(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            ),
        ),
        (
            2,
            alloy_primitives::hex!(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
            ),
        ),
    ] {
        let mut secret = [0; 32];
        secret[31] = scalar;
        let signer = DevelopmentSigner::from_bytes(secret).unwrap();
        let public_key = signer.public_key().await.unwrap();
        assert!(public_key == SigningPublicKey::from_compressed(expected_public_key).unwrap());

        let signature = signer.sign_digest(digest).await.unwrap();
        assert!(signature.normalize_s().is_none());
        assert_eq!(
            signature
                .recover_from_prehash(&digest)
                .unwrap()
                .to_encoded_point(true)
                .as_bytes(),
            expected_public_key,
        );
    }
}

struct RecordingSigner {
    id: u8,
    calls: Arc<Mutex<Vec<(u8, B256)>>>,
    fail_at: Option<usize>,
}

impl Signer for RecordingSigner {
    fn public_key(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<SigningPublicKey, SignerError>> + Send + '_>> {
        Box::pin(async { panic!("this signing step does not load public keys") })
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
    assert_eq!(
        signed.batch.batch.amount, 1_000,
        "reserve gross, not payout after fees"
    );
    assert_eq!(signed.batch.batch.digest, digest);
    let (intent, _) = super::parse_intent(&signed.batch.batch.intent).unwrap();
    assert_eq!(super::signing_hash(intent, true), digest);
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
