//! Check Circle's returned terms locally, before anything can be signed.

use miden_protocol::{Felt, Word};
use serde_json::json;

use crate::circle::{UnverifiedPrepareBatch, UnverifiedPrepareResponse};
use crate::config::Config;
use crate::verify::{rebuild_for_test, verify_prepared_response, VerifyError};

use super::startup::{config_toml, create_store_parent};
use super::validation::validated_burn;

const FIRST_SALT: &str = "0x0807060504030201181716151413121128272625242322213837363534333231";
const SECOND_SALT: &str = "0x0807060504030201181716151413121128272625242322213937363534333231";
const ZERO_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

fn serial(last: u64) -> Word {
    Word::new([
        Felt::new(0x0102_0304_0506_0708).unwrap(),
        Felt::new(0x1112_1314_1516_1718).unwrap(),
        Felt::new(0x2122_2324_2526_2728).unwrap(),
        Felt::new(last).unwrap(),
    ])
}

fn config(fee_ceiling: Option<u64>) -> Config {
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let path = directory.path().join("attester.toml");
    let mut text = config_toml(1);
    if let Some(ceiling) = fee_ceiling {
        text.push_str(&format!("max_withdrawal_fee = {ceiling}\n"));
    }
    std::fs::write(&path, text).unwrap();
    Config::load(&path).unwrap()
}

fn batch(salt: &str, amount: u64, destination_domain: u32) -> UnverifiedPrepareBatch {
    // The burn-bound bytes are written independently of the prepare/verify helpers.
    let mut batch = serde_json::from_value(json!({
        "burnIntents": [{
            "maxBlockHeight": "184467440737095516170000",
            "maxFee": "0",
            "spec": {
                "version": 1,
                "sourceDomain": 6,
                "destinationDomain": destination_domain,
                "sourceContract": format!("0x{}", "11".repeat(32)),
                "destinationContract": format!("0x{}", "22".repeat(32)),
                "sourceToken": format!("0x{}", "33".repeat(32)),
                "destinationToken": format!("0x{}", "44".repeat(32)),
                "sourceDepositor": format!("0x{}", "55".repeat(32)),
                "destinationRecipient": "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "sourceSigner": format!("0x{}", "55".repeat(32)),
                "destinationCaller": ZERO_WORD,
                "value": amount.to_string(),
                "salt": salt,
                "hookData": {
                    "remoteDomain": 10007,
                    "remoteDepositor": "0x00000000000000000000000000000000ba0000000000ca110000dd000000ef00",
                    "remoteToken": "0x00000000000000000000000000000000bb405fd9fe431bd1135a292de098cb00",
                    "forwardingContractAddress": "0x0000000000000000000000000000000000000000",
                    "forwardingCalldata": "0x"
                }
            }
        }],
        "encoded": "0x",
        "messageHashToSign": "0x"
    }))
    .unwrap();
    // This gives semantic cases a consistent header/hash, not an independent crypto reference.
    rebuild_for_test(&mut batch, false).unwrap();
    batch
}

/// Each returned intent must belong to exactly one burn and preserve that burn's fields.
#[test]
fn circle_response_matches_burns() {
    use VerifyError::*;
    let first_serial = serial(0x3132_3334_3536_3738);
    let second_serial = serial(0x3132_3334_3536_3739);
    let mut burns = [
        validated_burn(1_000, first_serial, 9),
        validated_burn(2_000, second_serial, 7),
    ];
    // A faucet transaction can consume several notes; each remains a separate burn row.
    burns[1].burn.burn_tx_id = burns[0].burn.burn_tx_id;
    let config = config(None);
    type Case = (&'static str, fn(&mut UnverifiedPrepareBatch), VerifyError);
    let field_cases: [Case; 7] = [
        (
            "unknown salt",
            |b| b.burn_intents[0].spec.salt = ZERO_WORD.into(),
            UnknownSalt,
        ),
        (
            "destination chain",
            |b| b.burn_intents[0].spec.destination_domain = 7,
            WrongBurnField("destinationDomain"),
        ),
        (
            "destination recipient",
            |b| b.burn_intents[0].spec.destination_recipient = ZERO_WORD.into(),
            WrongBurnField("destinationRecipient"),
        ),
        (
            "remote chain",
            |b| b.burn_intents[0].spec.hook_data.remote_domain = 10001,
            WrongBurnField("remoteDomain"),
        ),
        (
            "remote depositor",
            |b| b.burn_intents[0].spec.hook_data.remote_depositor = ZERO_WORD.into(),
            WrongBurnField("remoteDepositor"),
        ),
        (
            "remote token",
            |b| b.burn_intents[0].spec.hook_data.remote_token = ZERO_WORD.into(),
            WrongBurnField("remoteToken"),
        ),
        (
            "signer differs from depositor",
            |b| b.burn_intents[0].spec.source_signer = ZERO_WORD.into(),
            WrongSigner,
        ),
    ];
    let refuse = |name: &str, batches, expected| {
        let response = UnverifiedPrepareResponse { batches };
        assert_eq!(
            verify_prepared_response(&burns[..1], response, &config).err(),
            Some(expected),
            "{name}"
        );
    };
    for (name, edit, expected) in field_cases {
        let mut changed = batch(FIRST_SALT, 1_000, 9);
        edit(&mut changed);
        rebuild_for_test(&mut changed, false).unwrap();
        refuse(name, vec![changed], expected);
    }
    refuse("missing batch", vec![], WrongCount);
    refuse(
        "extra batch",
        vec![batch(FIRST_SALT, 1_000, 9), batch(SECOND_SALT, 2_000, 7)],
        WrongCount,
    );
    let mut empty = batch(FIRST_SALT, 1_000, 9);
    empty.burn_intents.clear();
    refuse("empty batch", vec![empty], WrongCount);
    let mut split = batch(FIRST_SALT, 1_000, 9);
    split
        .burn_intents
        .push(batch(SECOND_SALT, 2_000, 7).burn_intents.remove(0));
    refuse("two intents in one batch", vec![split], WrongCount);

    for as_set in [false, true] {
        let mut accepted = batch(FIRST_SALT, 1_000, 9);
        rebuild_for_test(&mut accepted, as_set).unwrap();
        // Only the header selects the hash form; the unused body need not match.
        accepted.encoded.replace_range(10.., "00");
        let response = UnverifiedPrepareResponse {
            batches: vec![accepted],
        };
        assert_eq!(
            verify_prepared_response(&burns[..1], response, &config).err(),
            None
        );

        let mut changed = batch(FIRST_SALT, 1_000, 9);
        rebuild_for_test(&mut changed, as_set).unwrap();
        changed.message_hash_to_sign = ZERO_WORD.into();
        refuse("different digest", vec![changed], DigestMismatch);
    }
    let mut unknown_header = batch(FIRST_SALT, 1_000, 9);
    unknown_header.encoded.replace_range(..10, "0x00000000");
    refuse(
        "unknown header",
        vec![unknown_header],
        MalformedField("encoded"),
    );
    let reordered = UnverifiedPrepareResponse {
        batches: vec![batch(SECOND_SALT, 2_000, 7), batch(FIRST_SALT, 1_000, 9)],
    };
    let verified = verify_prepared_response(&burns, reordered, &config).unwrap();
    assert_eq!(
        verified.note_ids().collect::<Vec<_>>(),
        vec![burns[1].burn.note_id(), burns[0].burn.note_id()],
        "returned batches keep the matched note IDs, not their array positions or shared tx ID"
    );
    let duplicated = UnverifiedPrepareResponse {
        batches: vec![batch(FIRST_SALT, 1_000, 9), batch(FIRST_SALT, 1_000, 9)],
    };
    assert_eq!(
        verify_prepared_response(&burns, duplicated, &config).err(),
        Some(DuplicateSalt)
    );
    let ambiguous_burns = [
        validated_burn(1_000, first_serial, 9),
        validated_burn(2_000, first_serial, 7),
    ];
    let ambiguous = UnverifiedPrepareResponse {
        batches: vec![batch(FIRST_SALT, 1_000, 9), batch(SECOND_SALT, 2_000, 7)],
    };
    assert_eq!(
        verify_prepared_response(&ambiguous_burns, ambiguous, &config).err(),
        Some(AmbiguousSalt)
    );
}

/// The payout and fee must total the burn, respect the fee cap, and request no forwarding.
#[test]
fn circle_response_checks_amount_fee_and_forwarding() {
    use VerifyError::*;
    let burns = [validated_burn(1_000, serial(0x3132_3334_3536_3738), 9)];
    let check = |name: &str, batch, ceiling, expected| {
        let response = UnverifiedPrepareResponse {
            batches: vec![batch],
        };
        assert_eq!(
            verify_prepared_response(&burns, response, &config(ceiling)).err(),
            expected,
            "{name}"
        );
    };
    let amount_cases = [
        ("default refuses a fee", "999", "1", None, Some(FeeTooHigh)),
        (
            "configured ceiling is inclusive",
            "990",
            "10",
            Some(10),
            None,
        ),
        (
            "fee exceeds ceiling",
            "989",
            "11",
            Some(10),
            Some(FeeTooHigh),
        ),
        (
            "zero payout with correct total",
            "0",
            "1000",
            Some(1000),
            Some(BadAmount),
        ),
        ("total below burn", "999", "0", None, Some(BadAmount)),
        ("total above burn", "1001", "0", None, Some(BadAmount)),
    ];
    for (name, value, fee, ceiling, expected) in amount_cases {
        let mut changed = batch(FIRST_SALT, 1_000, 9);
        changed.burn_intents[0].spec.value = value.into();
        changed.burn_intents[0].max_fee = fee.into();
        rebuild_for_test(&mut changed, false).unwrap();
        check(name, changed, ceiling, expected);
    }
    type Case = (&'static str, fn(&mut UnverifiedPrepareBatch), VerifyError);
    let forwarding_cases: [Case; 3] = [
        (
            "restricted caller",
            |b| b.burn_intents[0].spec.destination_caller = format!("0x{}", "11".repeat(32)),
            CallerRestricted,
        ),
        (
            "forwarding contract",
            |b| {
                b.burn_intents[0].spec.hook_data.forwarding_contract_address =
                    format!("0x{}", "11".repeat(20))
            },
            Forwarding,
        ),
        (
            "forwarding calldata",
            |b| b.burn_intents[0].spec.hook_data.forwarding_calldata = "0x1234".into(),
            Forwarding,
        ),
    ];
    for (name, edit, expected) in forwarding_cases {
        let mut changed = batch(FIRST_SALT, 1_000, 9);
        edit(&mut changed);
        rebuild_for_test(&mut changed, false).unwrap();
        check(name, changed, None, Some(expected));
    }
}

/// Reconstruct the EIP-712 digest and compare it with Circle's captured messageHashToSign.
#[test]
#[ignore = "awaiting Philipp's captured prepare response with encoded and messageHashToSign"]
fn circle_hash_matches_reference() {
    todo!("use the captured response as the independent digest reference")
}
