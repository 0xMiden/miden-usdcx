//! Determinism and the golden-id freeze over the dev fixture.
//!
//! The whole point of the tool is that the genesis faucet identity is derivable offline, before
//! any network exists — so the same config must always produce byte-identical outputs, and the
//! dev fixture's faucet id is FROZEN below as the drift alarm.

mod common;

use miden_protocol::account::AccountFile;
use miden_protocol::utils::serde::Serializable;
use xusdc_genesis::accounts::build_faucet;
use xusdc_genesis::output::write_outputs;

use crate::common::fixture_config;

/// Building the same config twice yields an identical faucet commitment and byte-identical
/// `.mac` serialization.
#[test]
fn the_same_config_builds_byte_identical_outputs() {
    let config = fixture_config();
    let first = build_faucet(&config).expect("the dev fixture must build");
    let second = build_faucet(&config).expect("the dev fixture must build again");

    assert_eq!(
        first.to_commitment(),
        second.to_commitment(),
        "the faucet commitment must be deterministic",
    );
    assert_eq!(
        AccountFile::new(first, Vec::new()).to_bytes(),
        AccountFile::new(second, Vec::new()).to_bytes(),
        "the faucet .mac bytes must be deterministic",
    );
}

/// `write_outputs` emits the complete file set — the faucet's `.mac` file, the `genesis.toml`
/// fragment carrying only the `native_faucet` line, and the `accounts.json` summary — and a
/// second run over the same build is byte-identical.
#[test]
fn write_outputs_emits_the_complete_deterministic_file_set() {
    let config = fixture_config();
    let faucet = build_faucet(&config).expect("the dev fixture must build");
    let dir = tempfile::tempdir().expect("a temp dir is available");
    write_outputs(&faucet, &config, dir.path()).expect("the outputs must write");

    let expected_files = ["usdcx-faucet.mac", "genesis.toml", "accounts.json"];
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
    assert_eq!(
        genesis_toml, "native_faucet = \"usdcx-faucet.mac\"\n",
        "the fragment must carry exactly the native_faucet line — the role accounts are not \
         this tool's genesis entries",
    );

    let second_dir = tempfile::tempdir().expect("a second temp dir is available");
    write_outputs(&faucet, &config, second_dir.path()).expect("the second write must succeed");
    for name in expected_files {
        assert_eq!(
            std::fs::read(dir.path().join(name)).expect("first output readable"),
            std::fs::read(second_dir.path().join(name)).expect("second output readable"),
            "{name} must be byte-identical across writes",
        );
    }
}

// The dev-fixture faucet id, FROZEN. The value is fixture-derived: it hashes the faucet seed
// plus the code and storage commitments, and the storage seeds the fixture's dummy role ids —
// so it moves on every protocol bump (the code commitment) and on any fixture change BY DESIGN.
// A failure here is the alarm that the genesis identity changed; refreeze deliberately, never
// mechanically.
const GOLDEN_FAUCET_ID: &str = "0x3f5867b34798c4314a78297038fe58";

/// The faucet's dev-fixture id is frozen.
#[test]
fn the_faucet_id_is_frozen() {
    let faucet = build_faucet(&fixture_config()).expect("the dev fixture must build");
    assert_eq!(
        faucet.id().to_hex(),
        GOLDEN_FAUCET_ID,
        "the dev-fixture faucet id drifted — expected on a protocol bump, refreeze deliberately",
    );
}
