//! The cursor store: real files, because "survives a restart" is only provable against a file a
//! second, independent handle can reopen.

use xreserve_deposit_relayer_lite::store::CursorStore;

/// What was written survives the handle being dropped and the file reopened.
#[test]
fn the_cursor_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cursor");

    CursorStore::new(path.clone()).set_cursor("page-2").unwrap();

    let reopened = CursorStore::new(path);
    assert_eq!(reopened.cursor().unwrap().as_deref(), Some("page-2"));
}

/// A first run reads `None`, not an error.
#[test]
fn a_first_run_has_no_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let store = CursorStore::new(dir.path().join("cursor"));
    assert_eq!(store.cursor().unwrap(), None);
}

/// The newest write wins — the file holds one value, not a history.
#[test]
fn the_cursor_is_replaced_not_appended() {
    let dir = tempfile::tempdir().unwrap();
    let store = CursorStore::new(dir.path().join("cursor"));

    store.set_cursor("first").unwrap();
    store.set_cursor("second").unwrap();

    assert_eq!(store.cursor().unwrap().as_deref(), Some("second"));
}
