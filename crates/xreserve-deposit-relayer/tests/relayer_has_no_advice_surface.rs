//! The NEGATIVE gate on the Miden-facing half: the relayer builds **no** witness data for anybody
//! else's transaction, and it takes **no** raw-bytes side door around its own validated boundary.
//!
//! # Why this is a test and not a review note
//!
//! An earlier mint-note-builder attempt shipped a module that assembled witness entries for the
//! CONSUMING transaction and pushed them into a `miden-client` transaction-request builder. It was
//! rejected, and not on style grounds — it cannot work: the mint note is consumed by a NETWORK
//! transaction that the network's ntx-builder assembles (the faucet is a keyless network account),
//! and that transaction's witness provider is rebuilt from the note's ATTACHMENTS. The relayer
//! never touches it, at any protocol version. The in-repo proof is the driver that committed real
//! mints against a live node (`crates/xusdc-validation/src/mintburn.rs`): it calls
//! `XUsdcMintNote::create` and nothing else.
//!
//! Prose cannot keep that out of the crate; a gate can. This one fails the build the moment any of
//! the rejected surface (or the `miden-client` dependency it needed) comes back — including through
//! a well-meaning "let me just help the consumer along" helper.
//!
//! The needles are assembled from FRAGMENTS at runtime, on purpose: spelled out literally they
//! would be hits on this very file, and the gate has to be able to scan the whole crate — its own
//! test sources included — without exempting anything. The faucet's advice-key implementation is out of the
//! `*.rs` scan by construction: the finding is preserved, the code surface is not.)

use std::path::{Path, PathBuf};

/// The forbidden surface, in fragments (see the module note).
fn forbidden_tokens() -> Vec<String> {
    vec![
        ["Advice", "Inputs"].concat(),
        ["extend", "_advice"].concat(),
        ["advice", "_map"].concat(),
        ["push_", "mapval"].concat(),
        ["populate", "_advice"].concat(),
    ]
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under the crate (src + tests), recursively.
fn rust_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("the crate's directories are readable") {
            let path = entry.expect("a readable dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    walk(&crate_root().join("src"), &mut out);
    walk(&crate_root().join("tests"), &mut out);
    out
}

/// THE GATE: zero occurrences of the rejected witness-staging surface anywhere in the crate's Rust
/// sources — library, binary and tests alike.
#[test]
fn t_the_crate_has_no_witness_staging_surface() {
    let sources = rust_sources();

    // non-vacuity: the scan must actually be looking at this crate, including the module the gate
    // exists for. A gate that scans nothing passes trivially.
    assert!(
        sources.len() >= 20,
        "the scan must cover the crate ({} files found)",
        sources.len()
    );
    assert!(
        sources
            .iter()
            .any(|p| p.ends_with("src/miden/mint_note.rs")),
        "the mint-note builder must be among the scanned files — if it moved, this gate moved with \
         it or it stopped protecting anything"
    );

    let tokens = forbidden_tokens();
    let mut hits: Vec<String> = Vec::new();

    for path in &sources {
        let text = std::fs::read_to_string(path).expect("a readable rust source");
        for (lineno, line) in text.lines().enumerate() {
            for token in &tokens {
                if line.contains(token.as_str()) {
                    hits.push(format!(
                        "{}:{}: {}",
                        path.strip_prefix(crate_root()).unwrap_or(path).display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        hits.is_empty(),
        "the relayer must build no witness data for the consuming transaction — it cannot reach \
         that transaction's provider at all (the ntx-builder rebuilds it from the note's \
         attachments). Offending lines:\n{}",
        hits.join("\n")
    );
}

/// `miden-client` must not be a dependency of this crate. It was the rejected implementation's
/// transaction-request sink, and the submit leg that would legitimately need a client is parked
/// (no v0.16 client exists). A dependency creeping back in is how the rejected design creeps back
/// in.
#[test]
fn t_the_crate_does_not_depend_on_miden_client() {
    let manifest =
        std::fs::read_to_string(crate_root().join("Cargo.toml")).expect("the crate's manifest");

    let declarations: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.starts_with("miden-client"))
        .collect();

    assert!(
        declarations.is_empty(),
        "miden-client must not be a dependency of the relayer: {declarations:?}"
    );
}

/// The builder's inputs come through the relayer's VALIDATED boundary — there is no public entry
/// point that takes the DepositIntent payload or the 65-byte signature as raw bytes.
///
/// The check is structural (it reads the module's own public signatures) because the property is
/// structural: a `pub fn build_mint_note(payload: &[u8], signature: [u8; 65], …)` sitting next to
/// the validated one would satisfy every behavioural test in the suite while re-opening exactly the
/// door the validated types exist to close — a caller could hand it bytes that never had their
/// `messageHash == keccak256(payload)` binding checked.
///
/// (The 33-byte attester pubkey is a different thing and is deliberately NOT covered: it is
/// operator CONFIGURATION, not a Circle wire field — it does not come through the envelope at all,
/// because Circle's attestation object does not carry it.)
#[test]
fn t_no_public_raw_bytes_side_door_into_the_builder() {
    let source = std::fs::read_to_string(crate_root().join("src/miden/mint_note.rs"))
        .expect("the mint-note builder module");

    let signatures = public_signatures(&source);
    assert!(
        !signatures.is_empty(),
        "the module must expose the builder publicly"
    );

    let builder = signatures
        .iter()
        .find(|sig| sig.contains("fn build_mint_note"))
        .expect("build_mint_note is public");

    assert!(
        builder.contains("&ValidatedAttestation"),
        "the builder consumes the VALIDATED attestation (payload + 65-byte signature), never raw \
         bytes: {builder}"
    );

    for sig in &signatures {
        assert!(
            !sig.contains("[u8; 65]"),
            "no public entry point takes a raw 65-byte signature: {sig}"
        );
        assert!(
            !sig.contains("&[u8]"),
            "no public entry point takes a raw byte payload: {sig}"
        );
    }
}

/// Collects every `pub fn` signature (from `pub fn` to the opening brace) out of a Rust source.
fn public_signatures(source: &str) -> Vec<String> {
    let mut signatures = Vec::new();
    let mut current: Option<String> = None;

    for line in source.lines() {
        let trimmed = line.trim();
        if current.is_none() && trimmed.starts_with("pub fn ") {
            current = Some(String::new());
        }
        if let Some(sig) = current.as_mut() {
            sig.push(' ');
            sig.push_str(trimmed);
            if trimmed.ends_with('{') || trimmed.ends_with(';') {
                signatures.push(sig.trim().to_string());
                current = None;
            }
        }
    }

    signatures
}
