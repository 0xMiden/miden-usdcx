use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::Parser;
use miden_client::rpc::Endpoint;
use miden_protocol::asset::AssetAmount;
use miden_protocol::block::BlockNumber;

use crate::config::{Cli, SignerConfig};

use super::{create_store_parent, startup_anchor, TestArgs, SIGNING_KEY_ONE, SIGNING_KEY_TWO};

fn assert_config_error(args: &TestArgs, expected_error: &str) {
    let error = args
        .config()
        .expect_err("invalid configuration must be rejected");
    assert_eq!(error.to_string(), expected_error);
}

fn assert_cli_error(args: &TestArgs, expected_kind: ErrorKind) {
    assert_eq!(
        args.parse()
            .expect_err("invalid arguments must be rejected")
            .kind(),
        expected_kind
    );
}

#[test]
fn cli_surface_is_explicit() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let valid = TestArgs::new(&tempdir, 1);

    assert_eq!(valid.load().miden_rpc_url(), &Endpoint::devnet());
    let mut local = valid.clone();
    local.replace("--miden-rpc-url", "http://localhost:57291");
    assert_eq!(local.load().miden_rpc_url(), &Endpoint::localhost());

    for required in [
        "--signer-provider",
        "--miden-rpc-url",
        "--circle-url",
        "--request-timeout",
        "--faucet-account-id",
        "--max-withdrawal-fee",
        "--max-withdrawal-fee-bps",
        "--cctp-forwarding-max-fee",
        "--cctp-forwarder-address",
        "--withdrawal-limit",
        "--poll-interval",
        "--faucet-deployment-block",
        "--trusted-anchor-block",
        "--trusted-anchor-commitment",
        "--expected-signing-public-key",
        "--minimum-finality-depth-blocks",
        "--store-path",
    ] {
        let mut args = valid.clone();
        args.remove(required);
        assert_cli_error(&args, ErrorKind::MissingRequiredArgument);
    }

    let mut bad_port = valid.clone();
    bad_port.replace("--miden-rpc-url", "https://rpc.devnet.miden.io:99999");
    assert_config_error(&bad_port, "Miden RPC URL is invalid");
    let mut no_scheme = valid.clone();
    no_scheme.replace("--miden-rpc-url", "rpc.devnet.miden.io");
    assert_config_error(
        &no_scheme,
        "Miden RPC URL must start with https:// or http://",
    );

    let mut unknown = valid.clone();
    unknown.append("--unknown-setting", "true");
    assert_cli_error(&unknown, ErrorKind::UnknownArgument);

    for (flag, duplicate_value) in [
        ("--signer-provider", "development"),
        ("--miden-rpc-url", "https://rpc.devnet.miden.io"),
        ("--circle-url", "https://circle.example.invalid"),
        ("--request-timeout", "1s"),
        ("--faucet-account-id", super::FAUCET_ACCOUNT_ID),
        ("--max-withdrawal-fee", "0"),
        ("--max-withdrawal-fee-bps", "0"),
        ("--withdrawal-limit", "0"),
        ("--withdrawal-window-hours", "24"),
        ("--withdrawal-cap-error-message", "exact message"),
        ("--poll-interval", "2s"),
        ("--faucet-deployment-block", "1"),
        ("--trusted-anchor-block", "0"),
        (
            "--trusted-anchor-commitment",
            "0x0100000000000000020000000000000003000000000000000400000000000000",
        ),
        ("--minimum-finality-depth-blocks", "1"),
        ("--store-path", "duplicate.sqlite3"),
    ] {
        let mut duplicate_scalar = valid.clone();
        if flag == "--withdrawal-cap-error-message" {
            duplicate_scalar.append(flag, duplicate_value);
        }
        duplicate_scalar.append(flag, duplicate_value);
        assert_cli_error(&duplicate_scalar, ErrorKind::ArgumentConflict);
    }

    let mut one_signer = valid.clone();
    one_signer.remove("--expected-signing-public-key");
    one_signer.append("--expected-signing-public-key", SIGNING_KEY_ONE);
    assert_config_error(
        &one_signer,
        "exactly two expected signing public keys are required",
    );

    let mut three_signers = valid.clone();
    three_signers.append("--expected-signing-public-key", "unchecked");
    assert_config_error(
        &three_signers,
        "exactly two expected signing public keys are required",
    );

    assert_eq!(
        Cli::try_parse_from(["xusdc-attester", "--help"])
            .expect_err("help exits without constructing configuration")
            .kind(),
        ErrorKind::DisplayHelp
    );
}

#[test]
fn invalid_config_is_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let valid = TestArgs::new(&tempdir, 1);
    let cases = [
        (
            "--request-timeout",
            "0s",
            "circle request timeout must be greater than zero",
        ),
        (
            "--faucet-account-id",
            "invalid",
            "faucet account id is invalid",
        ),
        (
            "--faucet-account-id",
            "0xBB405FD9FE431BD1135A292DE098CB",
            "faucet account id must use canonical 0x-prefixed lowercase hex",
        ),
        (
            "--circle-url",
            "not a URL",
            "Circle API base URL is invalid",
        ),
        (
            "--circle-url",
            "http://circle.example.invalid",
            "Circle API base URL must be an absolute HTTPS URL",
        ),
        (
            "--poll-interval",
            "0s",
            "poll interval must be greater than zero",
        ),
        (
            "--trusted-anchor-commitment",
            "0X0100000000000000020000000000000003000000000000000400000000000000",
            "trusted anchor commitment is invalid",
        ),
        (
            "--trusted-anchor-commitment",
            "0x01",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "--trusted-anchor-commitment",
            "0x01000000000000000200000000000000030000000000000004000000000000AA",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "--trusted-anchor-commitment",
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "trusted anchor commitment is invalid",
        ),
        (
            "--minimum-finality-depth-blocks",
            "0",
            "minimum finality depth must be greater than zero",
        ),
        ("--store-path", "", "store path must not be empty"),
    ];

    for (flag, value, expected_error) in cases {
        let mut args = valid.clone();
        args.replace(flag, value);
        assert_config_error(&args, expected_error);
    }

    for window in ["0", "2562047788016"] {
        let mut args = valid.clone();
        args.replace("--withdrawal-window-hours", window);
        assert_config_error(
            &args,
            "withdrawal window must be positive and fit in milliseconds",
        );
    }

    const FORWARDER: &str = "0x008888878f94c0d87defdf0b07f46b93c1934442";
    let mut forwarding = valid.clone();
    forwarding.replace("--max-withdrawal-fee", "1000");
    forwarding.replace("--cctp-forwarding-max-fee", "1000");
    assert_config_error(
        &forwarding,
        "cctp forwarding max fee must be below the maximum withdrawal fee",
    );
    forwarding.replace("--cctp-forwarding-max-fee", "999");
    forwarding.replace("--cctp-forwarder-address", "0x1234");
    assert_config_error(&forwarding, "cctp forwarder address is invalid");
    forwarding.replace("--cctp-forwarder-address", FORWARDER);
    assert_eq!(
        forwarding.load().cctp_forwarding(),
        (999, FORWARDER.parse().unwrap())
    );

    let mut blank_cap_message = valid.clone();
    blank_cap_message.append("--withdrawal-cap-error-message", "   ");
    assert_config_error(
        &blank_cap_message,
        "withdrawal cap error message must not be empty",
    );

    for (flag, value, kind) in [
        ("--request-timeout", "invalid", ErrorKind::ValueValidation),
        (
            "--faucet-deployment-block",
            "4294967296",
            ErrorKind::ValueValidation,
        ),
        (
            "--trusted-anchor-block",
            "4294967296",
            ErrorKind::ValueValidation,
        ),
    ] {
        let mut args = valid.clone();
        args.replace(flag, value);
        assert_cli_error(&args, kind);
    }

    let mut missing_parent = valid.clone();
    missing_parent.replace("--store-path", tempdir.path().join("missing/store.sqlite3"));
    assert_config_error(&missing_parent, "store path parent is not accessible");

    let parent_file = tempdir.path().join("not-a-directory");
    std::fs::write(&parent_file, b"file").unwrap();
    let mut parent_not_directory = valid.clone();
    parent_not_directory.replace("--store-path", parent_file.join("store.sqlite3"));
    assert_config_error(
        &parent_not_directory,
        "store path parent must be a directory",
    );

    let absolute_store = tempdir.path().join("absolute.sqlite3");
    let mut explicit = TestArgs::new(&tempdir, 0);
    explicit.replace("--store-path", &absolute_store);
    let config = explicit.load();
    assert_eq!(config.store_path(), absolute_store);
    assert_eq!(config.faucet_deployment_block(), BlockNumber::from(0u32));
    assert_eq!(config.trusted_anchor_block(), BlockNumber::from(0u32));
    assert_eq!(
        config.trusted_anchor_commitment(),
        startup_anchor().header().commitment()
    );
    assert_eq!(config.minimum_finality_depth_blocks(), 1);
    assert_eq!(
        config.expected_signing_public_keys_hex(),
        [SIGNING_KEY_ONE, SIGNING_KEY_TWO]
    );
    assert_eq!(config.max_withdrawal_fee().as_u64(), 1_000_000);
    assert_eq!(config.withdrawal_limit(), 10_000_000_000_000);
    assert_eq!(config.withdrawal_window_ms(), 86_400_000);
    assert_eq!(config.withdrawal_cap_error_message(), None);

    let mut relative = valid.clone();
    relative.replace("--store-path", "relative.sqlite3");
    assert_eq!(
        relative.load().store_path(),
        PathBuf::from("relative.sqlite3")
    );

    let mut paused = valid.clone();
    paused.replace("--withdrawal-limit", "0");
    paused.replace("--max-withdrawal-fee", "3500");
    paused.replace("--withdrawal-window-hours", "2");
    paused.append("--withdrawal-cap-error-message", " exact message ");
    let config = paused.load();
    assert_eq!(config.max_withdrawal_fee().as_u64(), 3500);
    assert_eq!(config.withdrawal_limit(), 0);
    assert_eq!(config.withdrawal_window_ms(), 7_200_000);
    assert_eq!(
        config.withdrawal_cap_error_message(),
        Some(" exact message ")
    );

    let mut excessive_fee = valid.clone();
    excessive_fee.replace(
        "--max-withdrawal-fee",
        (AssetAmount::MAX.as_u64() + 1).to_string(),
    );
    assert_config_error(&excessive_fee, "maximum withdrawal fee is invalid");

    let mut defaults = valid;
    defaults.remove("--withdrawal-window-hours");
    let config = defaults.load();
    assert_eq!(config.withdrawal_window_ms(), 86_400_000);
}

#[test]
fn signer_mode_validates_only_its_own_settings() {
    const FIRST: &str =
        "arn:aws:kms:eu-north-1:584968076953:key/1f82bbff-391f-4aec-8995-fe5782e1d559";
    const SECOND: &str =
        "arn:aws:kms:eu-north-1:584968076953:key/5f5e3e2f-8818-48c0-a6e0-54aada5747b5";
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let development = TestArgs::new(&directory, 1);
    assert!(matches!(
        development.load().signer(),
        SignerConfig::Development
    ));
    let mut unknown = development.clone();
    unknown.replace("--signer-provider", "fallback");
    assert_cli_error(&unknown, ErrorKind::InvalidValue);

    let options = [
        ("--aws-kms-region", "eu-north-1"),
        ("--aws-kms-key-arn", FIRST),
        ("--aws-kms-operation-timeout", "10s"),
    ];
    for (flag, value) in options {
        let mut invalid = development.clone();
        invalid.append(flag, value);
        assert!(
            invalid.config().is_err(),
            "{flag} cannot select KMS implicitly"
        );
    }
    let mut kms = development;
    kms.replace("--signer-provider", "aws-kms");
    for (flag, value) in options {
        kms.append(flag, value);
    }
    kms.append("--aws-kms-key-arn", SECOND);
    let config = kms.load();
    assert!(
        matches!(config.signer(), SignerConfig::AwsKms { region, key_arns, operation_timeout }
        if region == "eu-north-1" && key_arns == &[FIRST, SECOND]
            && *operation_timeout == std::time::Duration::from_secs(10))
    );
    for (flag, _) in options {
        let mut missing = kms.clone();
        missing.remove(flag);
        assert!(missing.config().is_err(), "{flag}");
    }
    for invalid_arn in [
        SECOND,
        "alias/testnet-usdcx-attester-1",
        "arn:aws:kms:eu-north-1:584968076953:alias/testnet-usdcx-attester-1",
        "arn:aws:kms:eu-west-1:584968076953:key/1234",
        "arn:aws:kms:eu-north-1:111111111111:key/1234",
        "arn:aws:kms:eu-north-1:584968076953:key/",
    ] {
        let mut invalid = kms.clone();
        invalid.replace("--aws-kms-key-arn", invalid_arn);
        assert!(invalid.config().is_err(), "{invalid_arn}");
    }
    let mut extra = kms.clone();
    extra.append("--aws-kms-key-arn", FIRST);
    assert!(extra.config().is_err());
    let mut zero = kms;
    zero.replace("--aws-kms-operation-timeout", "0s");
    assert!(zero.config().is_err());
}
