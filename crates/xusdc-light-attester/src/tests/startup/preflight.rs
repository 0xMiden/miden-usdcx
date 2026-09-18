use reqwest::{Method, StatusCode};

use crate::attester::Attester;
use crate::chain::ChainError;
use crate::circle::CircleError;
use crate::config::Config;
use crate::signer::{DevelopmentSigner, Signer};

use super::{
    create_store_parent, development_signers, load_config, ready_circle, start, CircleState,
    FakeCircle, ObservedRequest, TestArgs, TestChain, REQUEST_TIMEOUT, SIGNING_KEY_ONE,
    SIGNING_KEY_TWO,
};

async fn start_with_signing_keys(
    expected: &[&str],
    signers: [Box<dyn Signer>; 2],
) -> anyhow::Result<()> {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let mut args = TestArgs::new(&tempdir, 1);
    args.remove("--expected-signing-public-key");
    for key in expected {
        args.append("--expected-signing-public-key", key);
    }
    let result = Attester::start(
        args.load(),
        Box::new(TestChain::anchor_only()),
        ready_circle(),
        signers,
    )
    .await
    .map(|_| ());
    assert_eq!(store_path.exists(), result.is_ok());
    result
}

#[tokio::test]
async fn invalid_configured_signing_keys_are_rejected() {
    let invalid_hex = format!("0x{}", "gg".repeat(33));
    let invalid_point = format!("0x02{}", "ff".repeat(32));
    for expected in [
        &[SIGNING_KEY_ONE, &invalid_hex][..],
        &[SIGNING_KEY_ONE, "0x00"][..],
        &[SIGNING_KEY_ONE, &invalid_point][..],
        &[SIGNING_KEY_ONE, SIGNING_KEY_ONE][..],
    ] {
        assert!(start_with_signing_keys(expected, development_signers())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn invalid_provider_signing_keys_are_rejected() {
    for duplicate in [true, false] {
        let [first, _] = development_signers();
        let [same, _] = development_signers();
        let other = if duplicate {
            same
        } else {
            Box::new(DevelopmentSigner::from_bytes([3; 32]).unwrap())
        };
        assert!(
            start_with_signing_keys(&[SIGNING_KEY_ONE, SIGNING_KEY_TWO], [first, other])
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn matching_signing_keys_can_be_loaded_in_either_order() {
    let mut signers = development_signers();
    signers.swap(0, 1);
    start_with_signing_keys(&[SIGNING_KEY_ONE, SIGNING_KEY_TWO], signers)
        .await
        .unwrap();
}

#[tokio::test]
async fn unreachable_miden_node_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().unreachable(),
        ready_circle(),
    )
    .await;

    assert!(result.err().unwrap().downcast_ref::<ChainError>().is_some());
    assert!(!store_path.exists());
}

#[tokio::test]
async fn missing_faucet_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let store_path = create_store_parent(&tempdir);
    let (circle, requests) = FakeCircle::new(CircleState::Response(StatusCode::OK));
    let result = start(
        load_config(&tempdir, 1),
        TestChain::anchor_only().faucet_missing(),
        Box::new(circle),
    )
    .await;

    assert!(result.is_err());
    assert!(!store_path.exists());
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_circle_api_is_rejected() {
    for state in [
        CircleState::TransportError,
        CircleState::Response(StatusCode::NO_CONTENT),
    ] {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = create_store_parent(&tempdir);
        let (circle, requests) = FakeCircle::new(state);
        let result = start(
            load_config(&tempdir, 1),
            TestChain::anchor_only(),
            Box::new(circle),
        )
        .await;

        assert!(result
            .err()
            .unwrap()
            .downcast_ref::<CircleError>()
            .is_some());
        assert!(!store_path.exists());
        assert_eq!(
            *requests.lock().unwrap(),
            vec![ObservedRequest {
                method: Method::GET,
                url: "https://circle.example.invalid/v1/info".to_string(),
                timeout: Some(REQUEST_TIMEOUT),
                headers: Default::default(),
                body: Vec::new(),
            }]
        );
    }
}
