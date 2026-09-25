use std::sync::Mutex;

use aws_sdk_kms::types::KeyMetadata;

use super::*;

// Public outputs of the authorized KMS diagnostic on 2026-09-17, not withdrawal signatures.
const DIGEST: B256 = B256::new(alloy_primitives::hex!(
    "a983a1bad821aba65c846f2d66f6d09250c731a6866bde1e0df4ff8b3f50a7f5"
));
const FIXTURES: [(&str, &str, &str, &str); 2] = [
    (
        "arn:aws:kms:eu-north-1:584968076953:key/1f82bbff-391f-4aec-8995-fe5782e1d559",
        "02cd6031d5cb4d64291980e1041f691ae56e64419775be42f06a5a8d6433363103",
        "3056301006072a8648ce3d020106052b8104000a03420004cd6031d5cb4d64291980e1041f691ae56e64419775be42f06a5a8d6433363103812a9a572e47457b0b1a0f15b732280b5da8e68115e6e3aa667c53dc51821aa0",
        "304502207e30ab787fc82f36f47c9721a672f1f9aedfb3783567e71747b74f367c7a1da1022100f68fb841a54fd3da80420e274236bffc0fe50d4245859ac9cc049380718cedf4",
    ),
    (
        "arn:aws:kms:eu-north-1:584968076953:key/5f5e3e2f-8818-48c0-a6e0-54aada5747b5",
        "03a9f3bbcdaee1502e8d651bfcb4f0cdb1ca5f438fce54f2f7714f3d8508343059",
        "3056301006072a8648ce3d020106052b8104000a03420004a9f3bbcdaee1502e8d651bfcb4f0cdb1ca5f438fce54f2f7714f3d85083430592c379baee0babf408f2552b9ef562d11125bc07b3e91a6eea179574c456250b9",
        "304402205481d2e8868ee4282ec83a5e52fd141fb3f3361fb4d304f40846a05925f3718f022041fd8b8193e951826cbf9696515cd894815472589e5c405e7d52b98425ba7c32",
    ),
];

struct Backend {
    arn: &'static str,
    metadata: Option<KeyMetadata>,
    public: GetPublicKeyOutput,
    signature: SignOutput,
    fail: Option<&'static str>,
    calls: Mutex<Vec<&'static str>>,
}

impl Backend {
    fn new(index: usize) -> Self {
        let (arn, _, spki, signature) = FIXTURES[index];
        Self {
            arn,
            metadata: Some(
                KeyMetadata::builder()
                    .key_id(arn)
                    .arn(arn)
                    .enabled(true)
                    .key_state(KeyState::Enabled)
                    .key_spec(KeySpec::EccSecgP256K1)
                    .key_usage(KeyUsageType::SignVerify)
                    .build()
                    .unwrap(),
            ),
            public: GetPublicKeyOutput::builder()
                .key_id(arn)
                .key_spec(KeySpec::EccSecgP256K1)
                .key_usage(KeyUsageType::SignVerify)
                .signing_algorithms(SigningAlgorithmSpec::EcdsaSha256)
                .public_key(Blob::new(hex::decode(spki).unwrap()))
                .build(),
            signature: SignOutput::builder()
                .key_id(arn)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .signature(Blob::new(hex::decode(signature).unwrap()))
                .build(),
            fail: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, call: &'static str, arn: Option<&str>) -> Result<(), SignerError> {
        assert_eq!(arn, Some(self.arn));
        self.calls.lock().unwrap().push(call);
        if self.fail == Some(call) {
            Err(SignerError)
        } else {
            Ok(())
        }
    }
}

impl KmsBackend for Backend {
    fn describe_key(&self, input: DescribeKeyInputBuilder) -> KmsFuture<'_, DescribeKeyOutput> {
        Box::pin(async move {
            self.record("describe", input.build().unwrap().key_id())?;
            Ok(DescribeKeyOutput::builder()
                .set_key_metadata(self.metadata.clone())
                .build())
        })
    }

    fn get_public_key(&self, input: GetPublicKeyInputBuilder) -> KmsFuture<'_, GetPublicKeyOutput> {
        Box::pin(async move {
            self.record("public", input.build().unwrap().key_id())?;
            Ok(self.public.clone())
        })
    }

    fn sign(&self, input: SignInputBuilder) -> KmsFuture<'_, SignOutput> {
        Box::pin(async move {
            let input = input.build().unwrap();
            self.record("sign", input.key_id())?;
            assert_eq!(input.message().unwrap().as_ref(), DIGEST.as_slice());
            assert_eq!(input.message_type(), Some(&MessageType::Digest));
            assert_eq!(
                input.signing_algorithm(),
                Some(&SigningAlgorithmSpec::EcdsaSha256)
            );
            Ok(self.signature.clone())
        })
    }
}

#[tokio::test]
async fn both_keys_sign_exact_prehashes_and_cache_their_pinned_identity() {
    for (index, (arn, pin, _, _)) in FIXTURES.iter().enumerate() {
        let backend = Arc::new(Backend::new(index));
        let signer = KmsSigner::connect_with(backend.clone(), arn, pin)
            .await
            .unwrap();
        for _ in 0..2 {
            assert_eq!(hex::encode(signer.public_key().await.unwrap().0), *pin);
        }
        let signature = signer.sign_digest(DIGEST).await.unwrap();
        assert!(signature.normalize_s().is_none());
        assert_eq!(
            signature.recover_from_prehash(&DIGEST).unwrap(),
            signer.public_key
        );
        assert_eq!(
            *backend.calls.lock().unwrap(),
            ["describe", "public", "sign"]
        );

        // Swapping just the expected pin is not a valid reordering of the pair.
        assert!(
            KmsSigner::connect_with(Arc::new(Backend::new(index)), arn, FIXTURES[1 - index].1)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn bad_key_metadata_and_backend_failures_abort_startup() {
    let cases: &[fn(&mut Backend)] = &[
        |b| b.fail = Some("describe"),
        |b| b.fail = Some("public"),
        |b| b.metadata = None,
        |b| b.metadata.as_mut().unwrap().arn = Some(FIXTURES[1].0.into()),
        |b| b.metadata.as_mut().unwrap().enabled = false,
        |b| b.metadata.as_mut().unwrap().key_state = Some(KeyState::Disabled),
        |b| b.metadata.as_mut().unwrap().key_spec = Some(KeySpec::EccNistP256),
        |b| b.metadata.as_mut().unwrap().key_usage = Some(KeyUsageType::EncryptDecrypt),
        |b| b.public.key_id = Some(FIXTURES[1].0.into()),
        |b| b.public.key_spec = Some(KeySpec::EccNistP256),
        |b| b.public.key_usage = Some(KeyUsageType::EncryptDecrypt),
        |b| b.public.signing_algorithms = None,
        |b| b.public.public_key = None,
        |b| b.public.public_key = Some(Blob::new([0])),
    ];
    for (index, mutate) in cases.iter().enumerate() {
        let mut backend = Backend::new(0);
        mutate(&mut backend);
        let backend = Arc::new(backend);
        assert!(
            KmsSigner::connect_with(backend.clone(), FIXTURES[0].0, FIXTURES[0].1)
                .await
                .is_err(),
            "case {index}"
        );
        assert!(!backend.calls.lock().unwrap().contains(&"sign"));
    }
}

#[tokio::test]
async fn bad_sign_responses_and_backend_errors_fail_closed() {
    let cases: &[fn(&mut Backend)] = &[
        |b| b.fail = Some("sign"),
        |b| b.signature.key_id = Some(FIXTURES[1].0.into()),
        |b| b.signature.signing_algorithm = Some(SigningAlgorithmSpec::EcdsaSha384),
        |b| b.signature.signature = None,
        |b| b.signature.signature = Some(Blob::new([0])),
        |b| b.signature.signature = Some(Blob::new(hex::decode(FIXTURES[1].3).unwrap())),
    ];
    for (index, mutate) in cases.iter().enumerate() {
        let mut backend = Backend::new(0);
        mutate(&mut backend);
        let signer = KmsSigner::connect_with(Arc::new(backend), FIXTURES[0].0, FIXTURES[0].1)
            .await
            .unwrap();
        assert!(signer.sign_digest(DIGEST).await.is_err(), "case {index}");
    }
}

#[test]
fn der_conversion_normalizes_s_and_rejects_other_digests_keys_or_trailing_bytes() {
    for (_, pin, _, der) in FIXTURES {
        let key = VerifyingKey::from_sec1_bytes(&hex::decode(pin).unwrap()).unwrap();
        let der = hex::decode(der).unwrap();
        let signature = k256::ecdsa::Signature::from_der(&der).unwrap();
        let low = signature.normalize_s().unwrap_or(signature);
        let high = k256::ecdsa::Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes())
            .unwrap();
        assert!(high.normalize_s().is_some());
        let canonical = signature_from_der(DIGEST, &der, &key).unwrap();
        assert_eq!(
            canonical,
            signature_from_der(DIGEST, high.to_der().as_bytes(), &key).unwrap()
        );
        assert!(signature_from_der(B256::ZERO, &der, &key).is_err());
        let wrong = k256::ecdsa::SigningKey::from_bytes(&[1; 32].into()).unwrap();
        assert!(signature_from_der(DIGEST, &der, wrong.verifying_key()).is_err());
        assert!(signature_from_der(DIGEST, &der[..der.len() - 1], &key).is_err());
        let mut trailing = der;
        trailing.push(0);
        assert!(signature_from_der(DIGEST, &trailing, &key).is_err());
    }
}
