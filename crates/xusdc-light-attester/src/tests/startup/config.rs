use miden_protocol::block::BlockNumber;

use crate::config::Config;

use super::{config_toml, create_store_parent, replace_setting, startup_anchor, CONFIG_FILE};

fn remove_setting(config: &str, key: &str) -> String {
    replace_setting(config, key, "")
}

fn assert_config_error(config: &str, expected_error: &str) {
    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config).unwrap();
    let error = Config::load(&path).expect_err("invalid config must be rejected");
    assert_eq!(error.to_string(), expected_error);
}

#[test]
fn invalid_config_is_rejected() {
    let valid = config_toml(1);
    let cases = [
        (
            "circle_request_timeout_ms",
            "circle_request_timeout_ms = 0",
            "circle request timeout must be greater than zero",
        ),
        (
            "faucet_account_id_hex",
            "faucet_account_id_hex = \"invalid\"",
            "faucet account id is invalid",
        ),
        (
            "faucet_account_id_hex",
            "faucet_account_id_hex = \"0xBB405FD9FE431BD1135A292DE098CB\"",
            "faucet account id must use canonical 0x-prefixed lowercase hex",
        ),
        (
            "circle_api_base_url",
            "circle_api_base_url = \"not a URL\"",
            "Circle API base URL is invalid",
        ),
        (
            "circle_api_base_url",
            "circle_api_base_url = \"http://circle.example.invalid\"",
            "Circle API base URL must be an absolute HTTPS URL",
        ),
        (
            "poll_interval_ms",
            "poll_interval_ms = 0",
            "poll interval must be greater than zero",
        ),
        (
            "faucet_deployment_block",
            "faucet_deployment_block = 4294967296",
            "failed to parse config",
        ),
        (
            "trusted_anchor_block",
            "trusted_anchor_block = 4294967296",
            "failed to parse config",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0X0100000000000000020000000000000003000000000000000400000000000000\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0x01\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0x01000000000000000200000000000000030000000000000004000000000000AA\"",
            "trusted anchor commitment must use canonical 0x-prefixed lowercase 32-byte hex",
        ),
        (
            "trusted_anchor_commitment_hex",
            "trusted_anchor_commitment_hex = \"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"",
            "trusted anchor commitment is invalid",
        ),
        (
            "minimum_finality_depth_blocks",
            "minimum_finality_depth_blocks = 0",
            "minimum finality depth must be greater than zero",
        ),
        (
            "store_path",
            "store_path = \"\"",
            "store path must not be empty",
        ),
        (
            "store_path",
            "store_path = \"missing/store.sqlite3\"",
            "store path parent does not exist",
        ),
    ];

    for (key, replacement, expected_error) in cases {
        assert_config_error(&replace_setting(&valid, key, replacement), expected_error);
    }

    for missing_key in [
        "circle_request_timeout_ms",
        "faucet_account_id_hex",
        "circle_api_base_url",
        "poll_interval_ms",
        "faucet_deployment_block",
        "trusted_anchor_block",
        "trusted_anchor_commitment_hex",
        "minimum_finality_depth_blocks",
        "expected_signing_public_keys_hex",
        "store_path",
    ] {
        assert_config_error(
            &remove_setting(&valid, missing_key),
            "failed to parse config",
        );
    }

    for invalid_toml in [
        "circle_request_timeout_ms =".to_string(),
        replace_setting(
            &valid,
            "circle_request_timeout_ms",
            "circle_request_timeout_ms = \"1000\"",
        ),
        format!("{valid}unknown_setting = true\n"),
    ] {
        assert_config_error(&invalid_toml, "failed to parse config");
    }

    let tempdir = tempfile::tempdir().unwrap();
    let missing_path = tempdir.path().join("missing.toml");
    let error = Config::load(&missing_path).expect_err("missing config must be rejected");
    assert_eq!(error.to_string(), "failed to read config");

    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    std::fs::write(tempdir.path().join("not-a-directory"), b"file").unwrap();
    let invalid = replace_setting(
        &valid,
        "store_path",
        "store_path = \"not-a-directory/store.sqlite3\"",
    );
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, invalid).unwrap();
    let error = match Config::load(&path) {
        Err(error) => error,
        Ok(_) => panic!("a store parent file must be rejected"),
    };
    assert_eq!(error.to_string(), "store path parent must be a directory");

    let tempdir = tempfile::tempdir().unwrap();
    create_store_parent(&tempdir);
    let absolute_store = tempdir.path().join("absolute.sqlite3");
    let config = replace_setting(
        &config_toml(0),
        "store_path",
        &format!("store_path = {:?}", absolute_store),
    );
    let config = replace_setting(
        &config,
        "expected_signing_public_keys_hex",
        "expected_signing_public_keys_hex = [\"unchecked\"]",
    );
    let path = tempdir.path().join(CONFIG_FILE);
    std::fs::write(&path, config).unwrap();
    let config = Config::load(&path).expect("unchecked signing keys remain accepted in S1");
    assert_eq!(config.store_path(), absolute_store);
    assert_eq!(config.faucet_deployment_block(), BlockNumber::from(0u32));
    assert_eq!(config.trusted_anchor_block(), BlockNumber::from(0u32));
    assert_eq!(
        config.trusted_anchor_commitment(),
        startup_anchor().header().commitment()
    );
    assert_eq!(config.minimum_finality_depth_blocks(), 1);
    assert_eq!(config.expected_signing_public_keys_hex(), ["unchecked"]);
}
