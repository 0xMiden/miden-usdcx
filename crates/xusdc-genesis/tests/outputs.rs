//! The tool's file output over the dev fixture.

mod common;

use xusdc_genesis::accounts::build_faucet;
use xusdc_genesis::output::write_outputs;

use crate::common::Fixture;

/// `write_outputs` emits exactly one file — the faucet's `.mac`.
#[test]
fn write_outputs_emits_only_the_faucet_file() {
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
}
