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

use crate::common::Fixture;

/// Building the same config twice yields an identical faucet commitment and byte-identical
/// `.mac` serialization.
#[test]
fn the_same_config_builds_byte_identical_outputs() {
    let fixture = Fixture::new();
    let config = fixture.config();
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

/// `write_outputs` emits exactly one file — the faucet's `.mac` — and a second run over the
/// same build is byte-identical.
#[test]
fn write_outputs_emits_only_the_deterministic_faucet_file() {
    let fixture = Fixture::new();
    let faucet = build_faucet(&fixture.config()).expect("the dev fixture must build");
    let dir = tempfile::tempdir().expect("a temp dir is available");
    write_outputs(&faucet, dir.path()).expect("the outputs must write");

    assert!(
        dir.path().join("usdcx-faucet.mac").is_file(),
        "usdcx-faucet.mac must be emitted",
    );
    assert_eq!(
        std::fs::read_dir(dir.path())
            .expect("the out dir is readable")
            .count(),
        1,
        "the faucet .mac is the tool's only file output",
    );

    let second_dir = tempfile::tempdir().expect("a second temp dir is available");
    write_outputs(&faucet, second_dir.path()).expect("the second write must succeed");
    assert_eq!(
        std::fs::read(dir.path().join("usdcx-faucet.mac")).expect("first output readable"),
        std::fs::read(second_dir.path().join("usdcx-faucet.mac")).expect("second output readable"),
        "usdcx-faucet.mac must be byte-identical across writes",
    );
}

// The dev-fixture faucet id, FROZEN. The value is fixture-derived: it hashes the faucet seed
// plus the code and storage commitments, and the storage seeds the ids extracted from the
// fixture's generated role `.mac` files — so it moves on every protocol bump (the code
// commitment) and on any fixture change BY DESIGN. A failure here is the alarm that the
// genesis identity changed; refreeze deliberately, never mechanically.
const GOLDEN_FAUCET_ID: &str = "0x6c2fc53dff48d2f1077c0f2ee881f3";

/// The faucet's dev-fixture id is frozen.
#[test]
fn the_faucet_id_is_frozen() {
    let fixture = Fixture::new();
    let faucet = build_faucet(&fixture.config()).expect("the dev fixture must build");
    assert_eq!(
        faucet.id().to_hex(),
        GOLDEN_FAUCET_ID,
        "the dev-fixture faucet id drifted — expected on a protocol bump, refreeze deliberately",
    );
}
