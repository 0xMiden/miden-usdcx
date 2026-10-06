use std::time::Duration;

use tempfile::TempDir;

use super::*;

#[test]
fn the_relayer_shares_the_attester_endpoints_and_faucet() {
    let directory = TempDir::new().unwrap();
    let mut args: Vec<String> = "usdcx-bridge
        --miden-rpc-url https://miden.invalid
        --circle-url https://circle.invalid
        --faucet-account-id 0x222222222222221122222222222222
        --relayer-page-size 100 --relayer-request-timeout 30s
        --relayer-miden-data-dir /unused/relayer
        --relayer-account-id 0x111111101111111111111111111111
        --relayer-attester-public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        --relayer-state-file /unused/relayer-progress
        --signer-provider aws-kms --aws-kms-region eu-west-1
        --aws-kms-key-arn arn:aws:kms:eu-west-1:123456789012:key/first
                         arn:aws:kms:eu-west-1:123456789012:key/second
        --aws-kms-operation-timeout 10s
        --expected-signing-public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        --expected-signing-public-key 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
        --attester-request-timeout 2s --attester-poll-interval 1s
        --faucet-deployment-block 1 --trusted-anchor-block 0
        --trusted-anchor-commitment 0x0100000000000000020000000000000003000000000000000400000000000000
        --minimum-finality-depth-blocks 1
        --max-withdrawal-fee 1000000 --max-withdrawal-fee-bps 3
        --cctp-forwarding-max-fee 500000
        --cctp-forwarder-address 0x008888878f94c0d87defdf0b07f46b93c1934442
        --cctp-token-messenger-address 0x8fe6b999dc680ccfdd5bf7eb0974218be2542daa
        --attester-store-path"
        .split_whitespace()
        .map(String::from)
        .collect();
    args.push(
        directory
            .path()
            .join("attester.sqlite3")
            .to_str()
            .unwrap()
            .to_owned(),
    );

    let config = Config::try_from(Cli::try_parse_from(args).unwrap()).unwrap();

    assert_eq!(
        config.relayer.miden_node_url.as_str(),
        "https://miden.invalid/"
    );
    assert_eq!(
        config.relayer.circle_url.as_str(),
        "https://circle.invalid/"
    );
    assert_eq!(
        config.relayer.faucet_account_id.to_hex(),
        "0x222222222222221122222222222222"
    );
    assert_eq!(config.relayer.remote_domain, CircleDomain::MIDEN);
    // The two services keep their own timings.
    assert_eq!(config.relayer.request_timeout, Duration::from_secs(30));
    assert_eq!(config.relayer.poll_interval, Duration::from_secs(5));
}
