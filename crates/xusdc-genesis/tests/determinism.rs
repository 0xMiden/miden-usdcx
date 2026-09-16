//! Determinism and the golden-id freeze over the dev fixture.
//!
//! The whole point of the tool is that the genesis faucet identity is derivable offline, before
//! any network exists — so the same config must always produce byte-identical outputs, and the
//! dev fixture's faucet id is FROZEN below as the drift alarm.

mod common;

use miden_protocol::account::AccountFile;
use miden_protocol::utils::serde::Serializable;
use xusdc_genesis::accounts::build_all;
use xusdc_genesis::config::Role;
use xusdc_genesis::output::write_outputs;

use crate::common::Fixture;

/// Building the same config twice yields identical account commitments and byte-identical `.mac`
/// serializations — including the passed-through secret keys.
#[test]
fn the_same_config_builds_byte_identical_outputs() {
    let fixture = Fixture::new();
    let first = build_all(&fixture.config()).expect("the dev fixture must build");
    let second = build_all(&fixture.config()).expect("the dev fixture must build again");

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
            "the {} .mac bytes (account + passed-through secrets) must be deterministic",
            role.as_str(),
        );
    }
}

/// `write_outputs` emits the complete file set — the seven `.mac` files, the `genesis.toml`
/// fragment referencing all of them, and the `accounts.json` summary — and a second run over the
/// same build is byte-identical.
#[test]
fn write_outputs_emits_the_complete_deterministic_file_set() {
    let fixture = Fixture::new();
    let accounts = build_all(&fixture.config()).expect("the dev fixture must build");
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

// The dev-fixture faucet id, FROZEN. It moves on every protocol bump BY DESIGN — the account id
// hashes the code and storage commitments (the storage seeds the fixture's role account ids),
// so any protocol change that touches a component's MAST root moves it. A failure here is the
// alarm that the genesis identity changed; refreeze deliberately, never mechanically.
const GOLDEN_FAUCET_ID: &str = "0x6c2fc53dff48d2f1077c0f2ee881f3";

/// The faucet's dev-fixture id is frozen.
#[test]
fn the_faucet_id_is_frozen() {
    let fixture = Fixture::new();
    let accounts = build_all(&fixture.config()).expect("the dev fixture must build");
    assert_eq!(
        accounts.faucet.id().to_hex(),
        GOLDEN_FAUCET_ID,
        "the dev-fixture faucet id drifted — expected on a protocol bump, refreeze deliberately",
    );
}
