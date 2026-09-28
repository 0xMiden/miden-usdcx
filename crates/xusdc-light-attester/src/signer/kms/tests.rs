use super::*;

// A public key and a signature over `DIGEST` from each of the two KMS keys, captured in a one-off
// test of the keys on 2026-09-17. Neither signature is for a withdrawal.
const DIGEST: B256 = B256::new(alloy_primitives::hex!(
    "a983a1bad821aba65c846f2d66f6d09250c731a6866bde1e0df4ff8b3f50a7f5"
));
/// Each key's ARN, compressed public key, public key as KMS returns it, and signature.
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

fn metadata(arn: &str) -> KeyMetadata {
    KeyMetadata::builder()
        .key_id(arn)
        .arn(arn)
        .enabled(true)
        .key_state(KeyState::Enabled)
        .key_spec(KeySpec::EccSecgP256K1)
        .key_usage(KeyUsageType::SignVerify)
        .build()
        .unwrap()
}

fn public_key_output(index: usize) -> GetPublicKeyOutput {
    let (arn, _, spki, _) = FIXTURES[index];
    GetPublicKeyOutput::builder()
        .key_id(arn)
        .key_spec(KeySpec::EccSecgP256K1)
        .key_usage(KeyUsageType::SignVerify)
        .signing_algorithms(SigningAlgorithmSpec::EcdsaSha256)
        .public_key(Blob::new(hex::decode(spki).unwrap()))
        .build()
}

fn sign_output(index: usize) -> SignOutput {
    let (arn, _, _, signature) = FIXTURES[index];
    SignOutput::builder()
        .key_id(arn)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .signature(Blob::new(hex::decode(signature).unwrap()))
        .build()
}

fn pin(index: usize) -> SigningPublicKey {
    SigningPublicKey::from_hex(FIXTURES[index].1).unwrap()
}

fn key(index: usize) -> VerifyingKey {
    VerifyingKey::from_sec1_bytes(&hex::decode(FIXTURES[index].1).unwrap()).unwrap()
}

/// `result` failed with exactly `message`.
fn refused<T: std::fmt::Debug>(result: Result<T, SignerError>, message: &str) {
    assert_eq!(result.unwrap_err().to_string(), message);
}

#[test]
fn sign_requests_ask_kms_to_sign_the_digest_as_given() {
    let request = sign_request(FIXTURES[0].0, DIGEST).build().unwrap();
    assert_eq!(request.key_id(), Some(FIXTURES[0].0));
    assert_eq!(request.message().unwrap().as_ref(), DIGEST.as_slice());
    assert_eq!(request.message_type(), Some(&MessageType::Digest));
    assert_eq!(
        request.signing_algorithm(),
        Some(&SigningAlgorithmSpec::EcdsaSha256)
    );
}

#[test]
fn only_the_enabled_signing_key_with_this_arn_is_accepted() {
    let arn = FIXTURES[0].0;
    check_key_metadata(Some(&metadata(arn)), arn).unwrap();
    refused(
        check_key_metadata(None, arn),
        "AWS KMS described the key without its metadata",
    );
    let cases: [fn(&mut KeyMetadata); 5] = [
        |m| m.arn = Some(FIXTURES[1].0.into()),
        |m| m.enabled = false,
        |m| m.key_state = Some(KeyState::Disabled),
        |m| m.key_spec = Some(KeySpec::EccNistP256),
        |m| m.key_usage = Some(KeyUsageType::EncryptDecrypt),
    ];
    for edit in cases {
        let mut changed = metadata(arn);
        edit(&mut changed);
        refused(
            check_key_metadata(Some(&changed), arn),
            "AWS KMS key is not the enabled secp256k1 signing key with this ARN",
        );
    }
}

#[test]
fn the_public_key_is_pinned_to_the_configured_key() {
    for (index, (arn, ..)) in FIXTURES.into_iter().enumerate() {
        assert_eq!(
            pinned_public_key(&public_key_output(index), arn, pin(index)).unwrap(),
            key(index)
        );
        // Swapping just the expected key is not a valid reordering of the pair.
        refused(
            pinned_public_key(&public_key_output(index), arn, pin(1 - index)),
            "AWS KMS public key is not the expected signing public key",
        );
    }
    let not_the_key = "AWS KMS public key is not the secp256k1 signing key with this ARN";
    let cases: [(fn(&mut GetPublicKeyOutput), &str); 6] = [
        (|p| p.key_id = Some(FIXTURES[1].0.into()), not_the_key),
        (|p| p.key_spec = Some(KeySpec::EccNistP256), not_the_key),
        (
            |p| p.key_usage = Some(KeyUsageType::EncryptDecrypt),
            not_the_key,
        ),
        (|p| p.signing_algorithms = None, not_the_key),
        (|p| p.public_key = None, "AWS KMS returned no public key"),
        (
            |p| p.public_key = Some(Blob::new([0])),
            "AWS KMS public key is not a secp256k1 key",
        ),
    ];
    for (edit, message) in cases {
        let mut changed = public_key_output(0);
        edit(&mut changed);
        refused(pinned_public_key(&changed, FIXTURES[0].0, pin(0)), message);
    }
}

#[test]
fn kms_signatures_become_low_s_signatures_that_recover_the_pinned_key() {
    for (index, (arn, ..)) in FIXTURES.into_iter().enumerate() {
        let signature =
            signature_from_response(&sign_output(index), arn, DIGEST, &key(index)).unwrap();
        assert!(signature.normalize_s().is_none());
        assert_eq!(signature.recover_from_prehash(&DIGEST).unwrap(), key(index));
    }
}

#[test]
fn other_keys_algorithms_and_malformed_signatures_are_refused() {
    let other = "AWS KMS signed with another key or algorithm";
    let cases: [(fn(&mut SignOutput), &str); 5] = [
        (|s| s.key_id = Some(FIXTURES[1].0.into()), other),
        (
            |s| s.signing_algorithm = Some(SigningAlgorithmSpec::EcdsaSha384),
            other,
        ),
        (|s| s.signature = None, "AWS KMS returned no signature"),
        (
            |s| s.signature = Some(Blob::new([0])),
            "AWS KMS signature is not DER",
        ),
        (
            |s| s.signature = Some(Blob::new(hex::decode(FIXTURES[1].3).unwrap())),
            "AWS KMS signature does not verify with its key",
        ),
    ];
    for (edit, message) in cases {
        let mut changed = sign_output(0);
        edit(&mut changed);
        refused(
            signature_from_response(&changed, FIXTURES[0].0, DIGEST, &key(0)),
            message,
        );
    }
}

#[test]
fn der_conversion_normalizes_s_and_rejects_other_digests_keys_or_trailing_bytes() {
    let no_verify = "AWS KMS signature does not verify with its key";
    let not_der = "AWS KMS signature is not DER";
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
        refused(signature_from_der(B256::ZERO, &der, &key), no_verify);
        let wrong = k256::ecdsa::SigningKey::from_bytes(&[1; 32].into()).unwrap();
        refused(
            signature_from_der(DIGEST, &der, wrong.verifying_key()),
            no_verify,
        );
        refused(
            signature_from_der(DIGEST, &der[..der.len() - 1], &key),
            not_der,
        );
        let mut trailing = der;
        trailing.push(0);
        refused(signature_from_der(DIGEST, &trailing, &key), not_der);
    }
}

/// A public key or signature from KMS that does not decode is refused with the decoder's error as
/// its cause.
#[test]
fn malformed_kms_output_keeps_its_cause() {
    let mut response = public_key_output(0);
    response.public_key = Some(Blob::new([0]));
    let error = pinned_public_key(&response, FIXTURES[0].0, pin(0)).unwrap_err();
    assert!(std::error::Error::source(&error).is_some(), "{error}");

    let mut response = sign_output(0);
    response.signature = Some(Blob::new([0]));
    let error = signature_from_response(&response, FIXTURES[0].0, DIGEST, &key(0)).unwrap_err();
    assert!(std::error::Error::source(&error).is_some(), "{error}");
}
