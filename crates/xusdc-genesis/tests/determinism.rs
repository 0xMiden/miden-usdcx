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

/// `write_outputs` emits the complete file set — the faucet's `.mac` file, the `genesis.toml`
/// fragment, and the `accounts.json` summary — the fragment's `[[account]]` paths resolve from
/// the fragment's own location, and a second run over the same build is reproducible.
#[test]
fn write_outputs_emits_the_complete_resolvable_file_set() {
    let fixture = Fixture::new();
    let config = fixture.config();
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
        "no unexpected files are emitted — the role .mac files are referenced, never copied",
    );

    assert_fragment_resolves(dir.path());

    // A second run over the same build: the faucet `.mac` and the summary are byte-identical
    // (the fragment's `[[account]]` paths are rewritten per output location, so it is compared
    // by resolvability above, not by bytes across different directories).
    let second_dir = tempfile::tempdir().expect("a second temp dir is available");
    write_outputs(&faucet, &config, second_dir.path()).expect("the second write must succeed");
    assert_fragment_resolves(second_dir.path());
    for name in ["usdcx-faucet.mac", "accounts.json"] {
        assert_eq!(
            std::fs::read(dir.path().join(name)).expect("first output readable"),
            std::fs::read(second_dir.path().join(name)).expect("second output readable"),
            "{name} must be byte-identical across writes",
        );
    }
}

/// Asserts the fragment in `out_dir` declares the faucet plus six `[[account]]` entries, and
/// that every referenced path exists when resolved from the fragment's own directory.
fn assert_fragment_resolves(out_dir: &std::path::Path) {
    let genesis_toml = std::fs::read_to_string(out_dir.join("genesis.toml"))
        .expect("the genesis.toml fragment is readable");
    assert!(
        genesis_toml.contains("native_faucet = \"usdcx-faucet.mac\""),
        "the fragment must declare the faucet as native_faucet",
    );
    assert_eq!(
        genesis_toml.matches("[[account]]").count(),
        6,
        "the fragment must carry one [[account]] entry per role",
    );
    let referenced: Vec<&str> = genesis_toml
        .lines()
        .filter_map(|line| line.strip_prefix("path = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .collect();
    assert_eq!(
        referenced.len(),
        6,
        "every [[account]] entry carries a path"
    );
    for path in referenced {
        assert!(
            out_dir.join(path).is_file(),
            "the fragment path {path} must resolve from the fragment's own directory",
        );
    }
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
