//! The crate's own posture: the config surface, the dependency stack, and the types this slice
//! consumes BY REFERENCE rather than forking.
//!
//! Two of these are guard tests over the manifest. That is deliberate: "`k256` is a library
//! dependency, not a dev-only one" and "`miden-client` is absent" are decisions with real
//! consequences (the attester signs in production; `miden-client` has no v0.16 release, so a
//! dependency on it would not build at all), and a decision that lives only in a comment is a
//! decision that quietly reverts.

use assert_matches::assert_matches;
use miden_protocol::account::AccountId;
use rstest::rstest;
use withdrawal_listener_attester::config::{AttesterKeyHandle, ListenerConfig};
use withdrawal_listener_attester::error::ListenerError;
use withdrawal_listener_attester::evidence::assemble_evidence;
use withdrawal_listener_attester::types::{BurnPayload, ProofStrength};

use xusdc_encoding::xreserve::encoding::{account_id_to_bytes32, XReserveBurnItems};

// The unit adapter — the only way to obtain an `EvidencePackage` now
// that its constructor
// is sealed. Shared rather than re-declared, so this file and `evidence_trust_labeling.rs` cannot
// drift onto two different ideas of what an honest set of reads looks like (shared fixtures).
#[path = "evidence_support/mod.rs"]
mod evidence_support;

use evidence_support::{burn_note_id, burn_nullifier, faucet_id, UnitPort, CREATE_BLOCK};

/// This repo's own LNV4 local-node-validated xUSDC faucet
/// (`crates/xusdc-validation/VALIDATION-RECORD-LNV4.md`) — a real, parseable id, not a fabricated
/// one.
const FAUCET_ID_HEX: &str = "0xbb405fd9fe431bd1135a292de098cb";

fn manifest() -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .unwrap()
}

/// The manifest with its `#` comments stripped — the DECLARATIONS, not the prose about them. The
/// comments explain at length why `miden-client` is absent, and a sweep that read those as a
/// dependency would be asserting the opposite of what it means to.
fn manifest_declarations() -> String {
    manifest()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The `[dependencies]` section, ending where the next `[…]` section begins.
fn dependencies_section() -> String {
    let text = manifest_declarations();
    let start = text
        .find("\n[dependencies]")
        .expect("a [dependencies] section");
    let rest = &text[start + 1..];
    let end = rest[1..].find("\n[").map(|i| i + 1).unwrap_or(rest.len());
    rest[..end].to_string()
}

// THE DEPENDENCY POSTURE
// ================================================================================================

#[test]
fn k256_is_a_library_dependency_because_the_attester_signs_in_production() {
    // The relayer's k256 is DEV-only on purpose — it never verifies a signature off-chain. This
    // service is the opposite: the burn attester's off-chain ECDSA signature over `messageHashToSign`
    // is the product (burn signing happens off-chain), so k256 belongs in the library, and copying the
    // relayer's posture here would be a real mistake. The posture is fixed now, so the signing
    // call site cannot quietly arrive with k256 declared as a dev dependency.
    assert!(
        dependencies_section().contains("k256"),
        "k256 must be declared under [dependencies], not [dev-dependencies]"
    );
}

#[test]
fn miden_client_is_absent_from_the_graph() {
    // `miden-client` has no v0.16 release. Every real Miden read/submit is parked to a later slice;
    // a dependency on it would not resolve against the pinned v0.16 protocol family at all.
    assert!(
        !manifest_declarations().contains("miden-client"),
        "miden-client has no v0.16 release — the Miden legs are parked, and the dep with them"
    );
}

#[test]
fn the_shared_dependencies_are_consumed_from_the_workspace_table() {
    // workspace-shared-dependencies: a version pinned in two places drifts. Every dep this crate
    // shares with the relayer comes from the root table.
    let deps = dependencies_section();
    for shared in [
        "serde",
        "serde_json",
        "tokio",
        "reqwest",
        "hex",
        "k256",
        "bon",
        // the idempotency ledger's engine. It is the sharpest case for this rule in the workspace:
        // the relayer's submitted-nonce store and this crate's submitted-burn ledger are the same
        // pattern against the same recorded persistence choice, and two SQLite versions in one graph
        // is exactly the drift the workspace table exists to prevent.
        "rusqlite",
    ] {
        let line = deps
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{shared} ")))
            .unwrap_or_else(|| panic!("`{shared}` must be declared"));
        assert!(
            line.contains("workspace = true"),
            "`{shared}` must take its version from the root [workspace.dependencies]: {line}"
        );
    }
}

// THE CONFIG SURFACE
// ================================================================================================

#[test]
fn the_config_carries_the_five_static_parameters_the_spec_names() {
    // Circle's documentation config.rs: "PURE — static config: faucet_id, fixed burn tag (u32),
    // Miden domain, Circle
    // base URL, attester key handles".
    let config = ListenerConfig::builder()
        .faucet_id(AccountId::from_hex(FAUCET_ID_HEX).unwrap())
        .burn_tag(0xdead_beef)
        .miden_domain(10_001)
        .circle_base_url("https://xreserve-api.circle.com")
        .attester_key_handles(vec![
            AttesterKeyHandle::new("kms://attester-a"),
            AttesterKeyHandle::new("kms://attester-b"),
        ])
        .build()
        .unwrap();

    assert_eq!(config.faucet_id().to_hex(), FAUCET_ID_HEX);
    assert_eq!(config.burn_tag(), 0xdead_beef);
    assert_eq!(config.miden_domain(), 10_001);
    assert_eq!(config.circle_base_url(), "https://xreserve-api.circle.com");
    assert_eq!(config.attester_key_handles().len(), 2);
}

#[test]
fn an_attester_key_handle_is_an_identifier_and_never_key_material() {
    // The custody boundary: this crate holds a HANDLE (a KMS/HSM identifier). Private key material
    // never enters the config — that is P4-OPS's problem, and it stays that way.
    let handle = AttesterKeyHandle::new("kms://attester-a");
    assert_eq!(handle.as_str(), "kms://attester-a");

    // …and the type is a plain identifier, so no `expose`-style secret exit exists on it. What WOULD
    // be a leak is a handle that rendered a secret; it renders itself, which is the point.
    assert_eq!(
        format!("{handle:?}"),
        r#"AttesterKeyHandle("kms://attester-a")"#
    );
}

#[rstest]
#[case::empty("")]
#[case::not_a_url("xreserve-api.circle.com")]
#[case::unsupported_scheme("ftp://xreserve-api.circle.com")]
fn a_base_url_that_is_not_http_or_https_is_refused_at_construction(#[case] url: &str) {
    // validate-in-constructor: a config that exists is a config that can be used. A base URL that
    // cannot be joined against is caught here, not on the first Circle call.
    let attempt = ListenerConfig::builder().circle_base_url(url).build();
    assert_matches!(attempt, Err(ListenerError::BadBaseUrl { .. }));
}

#[test]
fn the_config_round_trips_through_serde_with_the_faucet_id_as_hex() {
    // AccountId has no serde impl of its own, so the config renders it the way an operator writes it:
    // the canonical hex. A config file that names a MALFORMED id must fail to load, not default.
    let config = ListenerConfig::builder()
        .faucet_id(AccountId::from_hex(FAUCET_ID_HEX).unwrap())
        .burn_tag(7)
        .build()
        .unwrap();

    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(json["faucet_id"], serde_json::json!(FAUCET_ID_HEX));

    let decoded: ListenerConfig = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.faucet_id(), config.faucet_id());
    assert_eq!(decoded.burn_tag(), 7);

    let mut bad = serde_json::to_value(&config).unwrap();
    bad["faucet_id"] = serde_json::json!("0xnot-an-account-id");
    assert!(
        serde_json::from_value::<ListenerConfig>(bad).is_err(),
        "a malformed faucet id must fail the load rather than silently default"
    );
}

#[test]
fn the_burn_tag_is_a_full_32_bit_value_carried_verbatim() {
    // Circle's documentation: SyncNotes matches tags by EXACT full-32-bit equality, never by
    // prefix. The config must therefore be able to hold any u32 — including one whose high bits
    // would be lost to a 16-bit-prefix design (the documented trap).
    for tag in [0u32, 1, 0x0000_ffff, 0xffff_0000, u32::MAX] {
        let config = ListenerConfig::builder().burn_tag(tag).build().unwrap();
        assert_eq!(config.burn_tag(), tag, "the full 32 bits survive");
    }
}

// THE TYPES THIS SLICE CONSUMES BY REFERENCE
// ================================================================================================

#[test]
fn the_burn_payload_is_unit_04s_type_not_a_second_copy_of_it() {
    // Circle's documented BurnPayload is field-for-field the shared encoding crate's
    // `XReserveBurnItems` — the type the burn-note
    // codec already owns (single-owner rule). Re-declaring it here would create two structs
    // that must be kept in sync by hand, which is exactly how a wire format drifts. The alias makes
    // that impossible: they are the same type.
    let items = XReserveBurnItems {
        amount: miden_protocol::asset::AssetAmount::new(10_000_000).unwrap(),
        dest_domain: 0,
        dest_recipient: [0xab; 32],
        salt: [0xcd; 32],
    };
    let payload: BurnPayload = items.clone();

    assert_eq!(payload, items);
    assert_eq!(payload.amount.as_u64(), 10_000_000);
    assert_eq!(payload.dest_domain, 0);
}

#[test]
fn the_evidence_package_labels_each_element_with_its_documented_proof_strength() {
    // Circle's documentation — the labels are reproduced from the evidence table, and they are not
    // decoration:
    // `burnTxId` is NODE-TRUSTED (there is no GetTransactionById), while the note id and block
    // number are CRYPTOGRAPHIC via the inclusion proof. Telling Circle otherwise would overstate what
    // Miden proves.
    //
    // The package is ASSEMBLED rather than constructed from literals, because it can no longer be
    // constructed from literals: `EvidencePackage::new` is `pub(crate)`, so the only package that
    // exists outside the crate is one whose consumption evidence was actually read and checked.
    // Minting one from four made-up values is precisely the bypass that narrowing closed, and the
    // labels are worth more asserted on a package that came through the real gate.
    let evidence = assemble_evidence(&UnitPort::honest(), burn_note_id(), faucet_id())
        .expect("the honest port assembles");

    assert_eq!(evidence.note_id_strength(), ProofStrength::Cryptographic);
    assert_eq!(evidence.block_num_strength(), ProofStrength::Cryptographic);
    assert_eq!(evidence.burn_tx_id_strength(), ProofStrength::NodeTrusted);
    assert_eq!(evidence.nullifier_strength(), ProofStrength::NodeTrusted);

    // the Circle wire wants 0x-hex, and the package renders it rather than making each caller do it
    assert_eq!(
        evidence.note_id_hex(),
        format!("0x{}", hex::encode(burn_note_id().as_word().as_bytes()))
    );
    assert_eq!(
        evidence.nullifier_hex(),
        format!("0x{}", hex::encode(burn_nullifier().as_word().as_bytes()))
    );
    assert_eq!(evidence.block_num(), CREATE_BLOCK);
}

#[test]
fn the_remote_depositor_encoding_is_unit_04s_account_id_codec_consumed_by_reference() {
    // `metadata.sender → remoteDepositor` goes through the shared AccountId↔bytes32 helper.
    // This crate does not redefine that encoding — it calls it, and this test pins that the wire
    // string the request carries is exactly what that codec produces.
    let faucet = AccountId::from_hex(FAUCET_ID_HEX).unwrap();
    let bytes = account_id_to_bytes32(faucet);

    let wire = format!("0x{}", hex::encode(bytes));
    assert_eq!(wire.len(), 66, "0x + 64 hex digits");
    assert!(
        wire.starts_with(&"0x".to_string()) && wire[2..34] == "0".repeat(32),
        "the R-B layout leaves the first 16 bytes zero: {wire}"
    );
}

// THE GOVERNING FILE-SIZE AND STRUCTURE RULE
// ================================================================================================

/// The rule: tests live in their **own file**, not inline with the implementation.
///
/// The gate is structural, and the pressure against it is real: when a `pub(crate)` narrowing puts
/// a function out of reach of `tests/` (another crate), the tempting fix is a `#[cfg(test)] mod
/// tests` at the bottom of the implementation file. The rule says no — and it does not have to be
/// inline, because a test module in its OWN file (`store_tests.rs`, declared `#[cfg(test)] mod
/// store_tests;`) is still inside the crate and still reaches `pub(crate)`, while keeping tests out
/// of the implementation.
///
/// So: an implementation file may DECLARE a test module (`#[cfg(test)] mod store_tests;` — a
/// one-line pointer at the file that holds them), but must not CONTAIN one (`#[cfg(test)] mod tests
/// { … }`). The distinction is the whole gate, and it is what the scan below looks for: the item
/// following a `#[cfg(test)]` must be a declaration ending in `;`, not a block opening a `{`.
#[test]
fn no_implementation_file_carries_an_inline_test_module() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut inline = Vec::new();

    for file in rust_files(&root.join("src")) {
        // a `*_tests.rs` file IS the test module — it is the compliant destination, not a violation
        let is_test_module = file
            .file_stem()
            .is_some_and(|s| s.to_string_lossy().ends_with("_tests"));
        if is_test_module {
            continue;
        }

        let text = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() != "#[cfg(test)]" {
                continue;
            }
            // the declared item, skipping any attributes between the gate and it (`#[path = …]`)
            let item = lines[i + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.starts_with("#[") && !l.starts_with("//") && !l.is_empty())
                .unwrap_or("");
            if !item.ends_with(';') {
                inline.push(format!("{}:{}: {item}", file.display(), i + 1));
            }
        }
    }

    assert!(
        inline.is_empty(),
        "G3: tests live in their own module/file, not inline with implementation. Move these into a \
         sibling `<name>_tests.rs` declared `#[cfg(test)] mod <name>_tests;` — it keeps pub(crate) \
         access without putting tests in the implementation:\n{}",
        inline.join("\n")
    );
}

#[test]
fn no_source_file_exceeds_the_governing_rust_line_ceiling() {
    // The rule: a Rust file is capped at roughly 500-700 lines; past that ceiling, stop and split
    // before continuing. The Circle schema crossed it once the wire constraints landed, and
    // was split into `circle::schema::{prepare, intents, withdraw}`. This keeps the gate mechanical
    // rather than something a reviewer has to remember to eyeball.
    //
    // `tests/` is swept too, and that is not pedantry: the ceiling is about Rust files, not only shipping ones. The idempotency
    // suite reached 1,232 lines in ONE file before this sweep covered the directory that held it — the
    // gate could not catch what it did not look at. It is now split into `conflict_recovery` /
    // `submit_idempotency` / `retry_policy` over a shared `submit_support` fixture module.
    const CEILING: usize = 700;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut oversized = Vec::new();

    for dir in ["src", "tests"] {
        for file in rust_files(&root.join(dir)) {
            let lines = std::fs::read_to_string(&file).unwrap().lines().count();
            if lines > CEILING {
                oversized.push(format!("{}: {lines} lines", file.display()));
            }
        }
    }

    assert!(
        oversized.is_empty(),
        "G3 caps a Rust file at ~{CEILING} lines; split these:\n{}",
        oversized.join("\n")
    );
}

fn rust_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
