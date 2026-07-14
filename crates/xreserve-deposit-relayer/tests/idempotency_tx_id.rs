//! `tests/idempotency_tx_id.rs` — the Miden transaction id the submitted-nonce log carries.
//!
//! It is the one field of a record an operator types back in by hand (out of a log line, out of an
//! explorer), so it parses the shapes they actually paste — and refuses everything else through the
//! crate's ONE hex taxonomy, rather than inventing a second, parallel family of "bad hex" errors.

use assert_matches::assert_matches;
use rstest::rstest;
use xreserve_deposit_relayer::{
    error::{HexField, RelayerError},
    idempotency::TxId,
};

/// The transaction id round-trips through its hex rendering, with or without the `0x` prefix and in
/// either case. `Display` always renders the canonical form: `0x` + 64 lowercase hex characters.
#[rstest]
#[case::prefixed_lowercase(true, false)]
#[case::bare_lowercase(false, false)]
#[case::prefixed_uppercase(true, true)]
#[case::bare_uppercase(false, true)]
fn a_transaction_id_round_trips_through_hex(#[case] prefixed: bool, #[case] upper: bool) {
    let id = TxId::new([0xAB; 32]);

    let mut rendered = hex::encode(id.as_bytes());
    if upper {
        rendered = rendered.to_uppercase();
    }
    if prefixed {
        rendered = format!("0x{rendered}");
    }

    assert_eq!(TxId::from_hex(&rendered).expect("parses"), id);
    assert_eq!(id.to_string(), format!("0x{}", hex::encode(id.as_bytes())));
}

/// A transaction id of the wrong length is refused: a truncated id in the log is a mint nobody can
/// look up again.
#[rstest]
#[case::too_short("0xdeadbeef")]
#[case::one_byte_short("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddee")]
#[case::one_byte_long("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")]
#[case::empty("")]
fn a_transaction_id_of_the_wrong_length_is_refused(#[case] rendered: &str) {
    assert_matches!(
        TxId::from_hex(rendered),
        Err(RelayerError::BadTxIdLength { .. })
    );
}

/// Non-hex input is refused through the existing malformed-hex taxonomy, naming the field that
/// failed — and the underlying `hex::FromHexError` is preserved, so the operator sees WHICH
/// character broke it.
#[test]
fn a_non_hex_transaction_id_is_refused_with_its_cause_preserved() {
    let err = TxId::from_hex(&"zz".repeat(32)).expect_err("not hex");

    assert_matches!(
        err,
        RelayerError::MalformedHex {
            field: HexField::TxId,
            ..
        }
    );
    assert!(
        err.hex_source().is_some(),
        "the originating hex error must survive in the source chain"
    );
}

/// An odd number of hex characters is not a byte string at all — it is refused as malformed hex, not
/// silently padded to a length that would then pass the 32-byte check.
#[test]
fn an_odd_length_transaction_id_is_refused_as_malformed_hex() {
    let odd = format!("0x{}", "a".repeat(63));

    assert_matches!(
        TxId::from_hex(&odd),
        Err(RelayerError::MalformedHex {
            field: HexField::TxId,
            ..
        })
    );
}
