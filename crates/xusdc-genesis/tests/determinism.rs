//! Determinism and golden-id freeze over the committed dev fixture.
//!
//! The whole point of the tool is that the genesis identities are derivable offline, before any
//! network exists — so the same config must always produce byte-identical outputs, and the dev
//! fixture's ids are FROZEN below as the drift alarm.

use std::path::PathBuf;

use miden_protocol::account::AccountFile;
use miden_protocol::utils::serde::Serializable;
use rstest::rstest;
use xusdc_genesis::accounts::{build_all, GenesisAccounts};
use xusdc_genesis::config::{GenesisToolConfig, Role};
use xusdc_genesis::output::write_outputs;

fn fixture_config() -> GenesisToolConfig {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dev-config.json");
    GenesisToolConfig::load(&path).expect("the committed dev fixture must parse")
}

fn build_fixture() -> GenesisAccounts {
    build_all(&fixture_config()).expect("the dev fixture must build")
}

/// Building the same config twice yields identical account commitments and byte-identical `.mac`
/// serializations — including the deterministically generated secret keys.
#[test]
fn the_same_config_builds_byte_identical_outputs() {
    let first = build_fixture();
    let second = build_fixture();

    assert_eq!(
        first.faucet.to_commitment(),
        second.faucet.to_commitment(),
        "the faucet commitment must be deterministic",
    );
    assert_eq!(
        AccountFile::new(first.faucet.clone(), Vec::new()).to_bytes(),
        AccountFile::new(second.faucet.clone(), Vec::new()).to_bytes(),
        "the faucet .mac bytes must be deterministic",
    );
    for role in Role::ALL {
        let (a, b) = (first.wallet(role), second.wallet(role));
        assert_eq!(
            a.account.to_commitment(),
            b.account.to_commitment(),
            "the {} wallet commitment must be deterministic",
            role.as_str(),
        );
        assert_eq!(
            AccountFile::new(a.account.clone(), a.secrets.clone()).to_bytes(),
            AccountFile::new(b.account.clone(), b.secrets.clone()).to_bytes(),
            "the {} .mac bytes (account + generated secret) must be deterministic",
            role.as_str(),
        );
    }
}

/// `write_outputs` emits the complete file set — the seven `.mac` files, the `genesis.toml`
/// fragment referencing all of them, and the `accounts.json` summary — and a second run over the
/// same build is byte-identical.
#[test]
fn write_outputs_emits_the_complete_deterministic_file_set() {
    let accounts = build_fixture();
    let dir = tempfile::tempdir().expect("a temp dir is available");
    write_outputs(&accounts, dir.path()).expect("the outputs must write");

    let expected_files = [
        "usdcx-faucet.mac",
        "operator.mac",
        "owner.mac",
        "attest_admin.mac",
        "pauser.mac",
        "unpauser.mac",
        "blocklist_manager.mac",
        "genesis.toml",
        "accounts.json",
    ];
    for name in expected_files {
        assert!(dir.path().join(name).is_file(), "{name} must be emitted");
    }
    assert_eq!(
        std::fs::read_dir(dir.path())
            .expect("the out dir is readable")
            .count(),
        expected_files.len(),
        "no unexpected files are emitted",
    );

    let genesis_toml = std::fs::read_to_string(dir.path().join("genesis.toml"))
        .expect("the genesis.toml fragment is readable");
    assert!(
        genesis_toml.contains("native_faucet = \"usdcx-faucet.mac\""),
        "the fragment must declare the faucet as native_faucet",
    );
    for role in Role::ALL {
        assert!(
            genesis_toml.contains(&format!("path = \"{}\"", role.mac_file_name())),
            "the fragment must reference the {} account file",
            role.as_str(),
        );
    }

    let second_dir = tempfile::tempdir().expect("a second temp dir is available");
    write_outputs(&accounts, second_dir.path()).expect("the second write must succeed");
    for name in expected_files {
        assert_eq!(
            std::fs::read(dir.path().join(name)).expect("first output readable"),
            std::fs::read(second_dir.path().join(name)).expect("second output readable"),
            "{name} must be byte-identical across writes",
        );
    }
}

// The dev-config account ids, FROZEN. These move on every protocol bump BY DESIGN — the account
// id hashes the code and storage commitments, so any protocol change that touches a component's
// MAST root moves every id. A failure here is the alarm that the genesis identity changed;
// refreeze deliberately, never mechanically.
const GOLDEN_FAUCET_ID: &str = "0x6c2fc53dff48d2f1077c0f2ee881f3";

/// The faucet's dev-config id is frozen.
#[test]
fn the_faucet_id_is_frozen() {
    assert_eq!(
        build_fixture().faucet.id().to_hex(),
        GOLDEN_FAUCET_ID,
        "the dev-config faucet id drifted — expected on a protocol bump, refreeze deliberately",
    );
}

/// Each wallet's dev-config id is frozen (same refreeze discipline as the faucet id above).
#[rstest]
#[case::operator(Role::Operator, "0x6aeeb7cba03918516870e95568b77b")]
#[case::owner(Role::Owner, "0x3cd7940c4946bad179675b1d7d8059")]
#[case::attest_admin(Role::AttestAdmin, "0x2bb51b585b2a98916aebb827cc5804")]
#[case::pauser(Role::Pauser, "0x88dc763b163d53513c4ea2c4f5f1f7")]
#[case::unpauser(Role::Unpauser, "0x83b89e07263e3b51799cb3af134d6d")]
#[case::blocklist_manager(Role::BlocklistManager, "0x5cf939821efad05159595966886192")]
fn the_wallet_ids_are_frozen(#[case] role: Role, #[case] expected: &str) {
    assert_eq!(
        build_fixture().wallet(role).account.id().to_hex(),
        expected,
        "the dev-config {} id drifted — expected on a protocol bump, refreeze deliberately",
        role.as_str(),
    );
}
