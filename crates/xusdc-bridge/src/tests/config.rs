use clap::error::ErrorKind;
use rstest::rstest;
use tempfile::TempDir;
use xusdc_attester::config::SignerConfig;

use super::*;

fn arguments(directory: &TempDir) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "xusdc-bridge",
        "--miden-rpc-url",
        "https://miden.invalid",
        "--circle-url",
        "https://circle.invalid",
        "--faucet-account-id",
        "0x222222222222221122222222222222",
        "--shutdown-grace",
        "5m",
        "--relayer",
        "--page-size",
        "100",
        "--request-timeout",
        "30s",
        "--miden-data-dir",
        "/unused/relayer",
        "--relayer-account-id",
        "0x111111101111111111111111111111",
        "--attester-public-key",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "--state-file",
        "/unused/relayer-progress",
        "--attester",
        "--signer-provider",
        "aws-kms",
        "--aws-kms-region",
        "eu-west-1",
        "--aws-kms-key-arn",
        "arn:aws:kms:eu-west-1:123456789012:key/first",
        "arn:aws:kms:eu-west-1:123456789012:key/second",
        "--aws-kms-operation-timeout",
        "10s",
        "--expected-signing-public-key",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "--expected-signing-public-key",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        "--request-timeout",
        "2s",
        "--poll-interval",
        "1s",
        "--faucet-deployment-block",
        "1",
        "--trusted-anchor-block",
        "0",
        "--trusted-anchor-commitment",
        "0x0100000000000000020000000000000003000000000000000400000000000000",
        "--minimum-finality-depth-blocks",
        "1",
        "--max-withdrawal-fee",
        "1000000",
        "--max-withdrawal-fee-bps",
        "3",
        "--cctp-forwarding-max-fee",
        "500000",
        "--cctp-forwarder-address",
        "0x008888878f94c0d87defdf0b07f46b93c1934442",
        "--cctp-token-messenger-address",
        "0x8fe6b999dc680ccfdd5bf7eb0974218be2542daa",
        "--store-path",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(directory.path().join("attester.sqlite3").into_os_string());
    args
}

#[test]
fn forwards_common_values_and_keeps_service_defaults() {
    let directory = TempDir::new().unwrap();
    let config = Config::parse_from(arguments(&directory)).unwrap();
    assert_eq!(config.shutdown_grace, Duration::from_secs(300));
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
    assert_eq!(
        config.relayer.remote_domain.to_string(),
        AttesterConfig::source_domain().to_string()
    );
    assert_eq!(config.relayer.poll_interval, Duration::from_secs(5));
    assert_eq!(config.relayer.request_timeout, Duration::from_secs(30));
    let SignerConfig::AwsKms {
        key_arns,
        operation_timeout,
        ..
    } = config.attester.signer();
    assert!(key_arns[0].ends_with("/first"));
    assert!(key_arns[1].ends_with("/second"));
    assert_eq!(*operation_timeout, Duration::from_secs(10));
}

#[rstest]
#[case::missing_relayer("--relayer", "missing --relayer argument group")]
#[case::missing_attester("--attester", "missing --attester argument group")]
fn missing_groups_fail(#[case] removed: &str, #[case] message: &str) {
    let directory = TempDir::new().unwrap();
    let mut args = arguments(&directory);
    args.retain(|arg| arg != removed);
    assert_eq!(Config::parse_from(args).err().unwrap().to_string(), message);
}

#[rstest]
#[case::relayer("--relayer")]
#[case::attester("--attester")]
fn repeated_groups_fail(#[case] marker: &str) {
    let directory = TempDir::new().unwrap();
    let mut args = arguments(&directory);
    args.push(marker.into());
    assert_eq!(
        Config::parse_from(args).err().unwrap().to_string(),
        format!("{marker} argument group must occur exactly once")
    );
}

#[rstest]
#[case::relayer("--relayer")]
#[case::attester("--attester")]
fn common_overrides_fail_in_both_forms(#[case] group: &str) {
    let directory = TempDir::new().unwrap();
    for flag in [
        "--circle-url",
        "--miden-rpc-url",
        "--miden-node-url",
        "--faucet-account-id",
        "--remote-domain",
        "--shutdown-grace",
    ] {
        for values in [
            vec![flag.to_owned(), "other".to_owned()],
            vec![format!("{flag}=other")],
        ] {
            let mut args = arguments(&directory);
            let at = args.iter().position(|arg| arg == group).unwrap() + 1;
            args.splice(at..at, values.iter().map(OsString::from));
            let error = Config::parse_from(args).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!(
                    "common option {} cannot be overridden inside a service group",
                    values[0]
                )
            );
        }
    }
}

#[rstest]
#[case::unknown("--unknown", ErrorKind::UnknownArgument)]
#[case::duplicate("--poll-interval", ErrorKind::ArgumentConflict)]
#[case::maintenance("release-holds", ErrorKind::UnknownArgument)]
fn existing_parser_rejects_bad_service_arguments(#[case] flag: &str, #[case] kind: ErrorKind) {
    let directory = TempDir::new().unwrap();
    let mut args = arguments(&directory);
    args.extend([flag.into(), "1s".into()]);
    let error = Config::parse_from(args).err().unwrap();
    assert_eq!(error.downcast_ref::<clap::Error>().unwrap().kind(), kind);
}

#[test]
fn group_order_and_zero_grace_fail() {
    let directory = TempDir::new().unwrap();
    let mut args = arguments(&directory);
    let relayer = args.iter().position(|arg| arg == "--relayer").unwrap();
    let attester = args.iter().position(|arg| arg == "--attester").unwrap();
    args.swap(relayer, attester);
    assert_eq!(
        Config::parse_from(args).err().unwrap().to_string(),
        "--relayer must come before --attester"
    );
    let mut args = arguments(&directory);
    let grace = args
        .iter()
        .position(|arg| arg == "--shutdown-grace")
        .unwrap();
    args[grace + 1] = "0s".into();
    assert_eq!(
        Config::parse_from(args).err().unwrap().to_string(),
        "shutdown grace must be greater than zero"
    );
}
