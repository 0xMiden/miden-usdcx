//! The `.mac` file boundary — nothing is ever overwritten, a key-bearing file is private — and
//! the id listing.

mod common;

use miden_protocol::account::AccountFile;
use miden_protocol::utils::serde::Serializable;
use xusdc_encoding::xreserve::encoding::{EthEmbeddedAccountId, EthEmbeddedAccountIdExt};
use xusdc_genesis::output::{
    read_account_file, render_ids, write_account_file, DISTRIBUTOR_MAC_FILE, FAUCET_MAC_FILE,
};

use crate::common::{fresh_distributor, genesis_faucet};

/// The listing's `bytes32` line is the id in the xReserve wire form: decoding it as a deposit's
/// recipient field yields the id back.
#[test]
fn render_ids_prints_the_bytes32_wire_form_of_the_id() {
    let id = fresh_distributor().account.id();
    let listing = render_ids("distributor", id);

    let line = listing
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("bytes32: 0x"))
        .expect("the listing carries a bytes32 line");
    let bytes: [u8; 32] = hex::decode(line)
        .expect("the bytes32 line is hex")
        .try_into()
        .expect("the bytes32 line is 32 bytes");
    assert_eq!(
        EthEmbeddedAccountId::try_from_bytes32(bytes)
            .expect("the printed form decodes as an embedded account id")
            .into_account_id(),
        id,
        "the bytes32 line must decode back to the id",
    );
}

/// A keyless faucet file round-trips through the file boundary.
#[test]
fn the_faucet_file_round_trips_without_keys() {
    let faucet = genesis_faucet();
    let dir = tempfile::tempdir().expect("a temp dir is available");
    let path = dir.path().join(FAUCET_MAC_FILE);
    write_account_file(&AccountFile::new(faucet.clone(), Vec::new()), &path)
        .expect("the faucet must write");

    let file = read_account_file(&path).expect("the faucet file must load");
    assert_eq!(file.account, faucet);
    assert!(
        file.auth_secret_keys.is_empty(),
        "the faucet file carries no keys"
    );
}

/// The distributor file keeps its key and is readable by its owner only.
#[test]
fn the_distributor_file_keeps_the_key_and_is_private() {
    let distributor = fresh_distributor();
    let dir = tempfile::tempdir().expect("a temp dir is available");
    let path = dir.path().join(DISTRIBUTOR_MAC_FILE);
    write_account_file(&distributor, &path).expect("the distributor must write");

    let file = read_account_file(&path).expect("the distributor file must load");
    assert_eq!(file.account, distributor.account);
    assert_eq!(
        file.auth_secret_keys.to_bytes(),
        distributor.auth_secret_keys.to_bytes(),
        "the key must round-trip through the file",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("the file has metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a key-bearing file is owner-only");
    }
}

/// A second write to the same path is refused and leaves the first file intact.
#[test]
fn write_account_file_refuses_to_overwrite() {
    let dir = tempfile::tempdir().expect("a temp dir is available");
    let path = dir.path().join("account.mac");
    let first = AccountFile::new(genesis_faucet(), Vec::new());
    write_account_file(&first, &path).expect("the first write must succeed");
    let before = std::fs::read(&path).expect("the file is readable");

    let err = write_account_file(&fresh_distributor(), &path)
        .expect_err("writing over an existing file must be refused");
    assert!(
        err.to_string().contains("never overwritten"),
        "the refusal must say why, got: {err:#}",
    );
    assert_eq!(
        std::fs::read(&path).expect("the file is still readable"),
        before,
        "the refused write must not touch the existing file",
    );
}

/// A file that is not an account file is rejected with the path named.
#[test]
fn read_account_file_names_the_path_on_garbage() {
    let dir = tempfile::tempdir().expect("a temp dir is available");
    let path = dir.path().join("garbage.mac");
    std::fs::write(&path, b"not an account file").expect("the garbage is writable");

    let err = read_account_file(&path).expect_err("garbage must be rejected");
    assert!(
        err.to_string().contains("garbage.mac"),
        "the error must name the file, got: {err:#}",
    );
}
