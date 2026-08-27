//! The config: the shipped example must work, and bad files must be refused loudly.

use std::path::Path;

use xreserve_deposit_relayer_lite::config::Config;

fn example_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("relayer.toml")
}

/// The shipped example config parses and validates — otherwise `just run-relayer-lite` would be a
/// broken demo.
#[test]
fn the_shipped_example_config_is_valid() {
    let config = Config::load(&example_path()).expect("the shipped relayer.toml parses");
    assert_eq!(config.remote_domain, 10001);
}

/// A missing file is a clear error naming the path, never a default-configured relayer.
#[test]
fn a_missing_config_file_is_refused() {
    let error = format!(
        "{:#}",
        Config::load(Path::new("/nonexistent/relayer.toml")).unwrap_err()
    );
    assert!(error.contains("relayer.toml"), "unexpected error: {error}");
}

/// An unknown key is refused and NAMED: a mistyped key that silently kept its default is how an
/// operator ends up debugging a value they thought they set.
#[test]
fn an_unknown_config_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relayer.toml");
    let mut text = std::fs::read_to_string(example_path()).unwrap();
    text.push_str("\npol_interval_ms = 1234\n");
    std::fs::write(&path, text).unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(
        error.contains("pol_interval_ms"),
        "the refusal must name the unknown key, got: {error}"
    );
}

/// An invalid Circle URL is refused at load, not at the first request.
#[test]
fn an_invalid_circle_url_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relayer.toml");
    let text = std::fs::read_to_string(example_path())
        .unwrap()
        .replace("https://xreserve-api-testnet.circle.com", "not a url");
    std::fs::write(&path, text).unwrap();

    let error = format!("{:#}", Config::load(&path).unwrap_err());
    assert!(
        error.contains("circle_base_url"),
        "unexpected error: {error}"
    );
}
