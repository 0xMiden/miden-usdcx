//! Check Circle's returned terms locally, before anything can be signed.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use miden_protocol::{Felt, Word};
use serde_json::json;

use crate::circle::{UnverifiedPrepareBatch, UnverifiedPrepareResponse};
use crate::config::Config;
use crate::verify::{
    canonical_values_for_test, cctp, rebuild_for_test, VerifiedWithdrawal, VerifyError,
};

use super::startup::{create_store_parent, TestArgs};
use super::validation::{validated_burn, validated_burn_to};

const FIRST_SALT: &str = "0x0807060504030201181716151413121128272625242322213837363534333231";
const ZERO_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const FORWARDER: &str = "0x008888878f94c0d87defdf0b07f46b93c1934442";
// Circle's sandbox replies of 2026-09-21 for a 1 USDC burn to Linea (through xReserve on Arc plus
// CCTP) and to Base (direct), both prepared with forwarding on and a 0.5 USDC CCTP fee.
pub(super) const FORWARDED_FIXTURE: &str =
    include_str!("fixtures/circle-sandbox-2026-09-21-forwarded-linea.response.json");
// The same forwarded request to Solana, whose recipient fills all 32 bytes of the mint recipient.
const FORWARDED_SOLANA_FIXTURE: &str =
    include_str!("fixtures/circle-sandbox-2026-09-23-forwarded-solana.response.json");
const DIRECT_WITH_OPTIONS_FIXTURE: &str =
    include_str!("fixtures/circle-sandbox-2026-09-21-direct-base-with-options.response.json");

pub(super) fn serial(last: u64) -> Word {
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
    let mut args = TestArgs::new(&directory, 1);
    if let Some(ceiling) = fee_ceiling {
        args.replace("--max-withdrawal-fee", ceiling.to_string());
    }
    args.load()
}

fn forwarding_config(fee_ceiling: u64, cctp_fee: u64) -> Config {
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory, 1);
    args.replace("--max-withdrawal-fee", fee_ceiling.to_string());
    args.replace("--cctp-forwarding-max-fee", cctp_fee.to_string());
    args.replace("--cctp-forwarder-address", FORWARDER);
    args.load()
}

/// A captured reply, rebound to the test faucet: the probes ran against Circle's registered remote
/// domain and token, so those two hook fields are replaced and the digest rebuilt, keeping every
/// other field exactly as Circle laid it out.
pub(super) fn captured(fixture: &str) -> UnverifiedPrepareBatch {
    let mut response: UnverifiedPrepareResponse = serde_json::from_str(fixture).unwrap();
    let mut batch = response.batches.remove(0);
    let hook = &mut batch.burn_intents[0].spec.hook_data;
    hook.remote_domain = 10007;
    hook.remote_token = "0x00000000000000000000000000000000bb405fd9fe431bd1135a292de098cb00".into();
    rebuild_for_test(&mut batch).unwrap();
    batch
}

pub(super) fn decode_call(batch: &UnverifiedPrepareBatch) -> cctp::depositForBurnWithHookCall {
    let calldata = &batch.burn_intents[0].spec.hook_data.forwarding_calldata;
    cctp::depositForBurnWithHookCall::abi_decode(&hex::decode(&calldata[2..]).unwrap()).unwrap()
}

pub(super) fn with_calldata(
    mut batch: UnverifiedPrepareBatch,
    calldata: Vec<u8>,
) -> UnverifiedPrepareBatch {
    batch.burn_intents[0].spec.hook_data.forwarding_calldata =
        format!("0x{}", hex::encode(calldata));
    rebuild_for_test(&mut batch).unwrap();
    batch
}

pub(super) fn batch(salt: &str, amount: u64, destination_domain: u32) -> UnverifiedPrepareBatch {
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
    rebuild_for_test(&mut batch).unwrap();
    batch
}

pub(crate) fn verified_withdrawal() -> VerifiedWithdrawal {
    let burn = validated_burn(1_000, serial(0x3132_3334_3536_3738), 9);
    let mut prepared = batch(FIRST_SALT, 1_000, 9);
    prepared.burn_intents[0].spec.value = "990".into();
    prepared.burn_intents[0].max_fee = "10".into();
    rebuild_for_test(&mut prepared).unwrap();
    UnverifiedPrepareResponse {
        batches: vec![prepared],
    }
    .verify(&burn, &config(Some(10)))
    .unwrap()
}

/// The returned intent must belong to the burn and preserve all of its fields.
#[test]
fn circle_response_matches_burns() {
    use VerifyError::*;
    let burn = validated_burn(1_000, serial(0x3132_3334_3536_3738), 9);
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
            response.verify(&burn, &config).err(),
            Some(expected),
            "{name}"
        );
    };
    for (name, edit, expected) in field_cases {
        let mut changed = batch(FIRST_SALT, 1_000, 9);
        edit(&mut changed);
        rebuild_for_test(&mut changed).unwrap();
        refuse(name, vec![changed], expected);
    }
    refuse("missing batch", vec![], WrongCount);
    refuse(
        "extra batch",
        vec![batch(FIRST_SALT, 1_000, 9), batch(FIRST_SALT, 1_000, 9)],
        WrongCount,
    );
    let mut empty = batch(FIRST_SALT, 1_000, 9);
    empty.burn_intents.clear();
    refuse("empty batch", vec![empty], WrongCount);
    let mut split = batch(FIRST_SALT, 1_000, 9);
    split
        .burn_intents
        .push(batch(FIRST_SALT, 1_000, 9).burn_intents.remove(0));
    refuse("two intents in one batch", vec![split], WrongCount);

    let response = UnverifiedPrepareResponse {
        batches: vec![batch(FIRST_SALT, 1_000, 9)],
    };
    assert_eq!(response.verify(&burn, &config).err(), None);

    let mut changed = batch(FIRST_SALT, 1_000, 9);
    changed.message_hash_to_sign = ZERO_WORD.into();
    refuse("different digest", vec![changed], DigestMismatch);
    let mut set_header = batch(FIRST_SALT, 1_000, 9);
    set_header.encoded.replace_range(..10, "0xe999239b");
    refuse("burn-intent-set header", vec![set_header], EncodedMismatch);
    let mut mismatched = batch(FIRST_SALT, 1_000, 9);
    let original = mismatched.encoded.clone();
    let mut altered = hex::decode(&original[2..]).unwrap();
    altered[100] ^= 1;
    for encoded in [
        format!("{}00", original),
        original[..original.len() - 2].to_owned(),
        format!("0x{}", hex::encode(altered)),
    ] {
        mismatched.encoded = encoded;
        refuse(
            "complete encoded bytes must match",
            vec![mismatched],
            EncodedMismatch,
        );
        mismatched = batch(FIRST_SALT, 1_000, 9);
    }

    let verified = UnverifiedPrepareResponse {
        batches: vec![batch(FIRST_SALT, 1_000, 9)],
    }
    .verify(&burn, &config)
    .unwrap();
    assert_eq!(
        verified.note_id(),
        burn.burn.note_id(),
        "the verified authorization retains the durable burn row identity"
    );
}

/// The payout and fee must total the burn, respect the fee cap, and a direct reply must not
/// restrict the caller.
#[test]
fn circle_response_checks_amount_fee_and_forwarding() {
    use VerifyError::*;
    let burns = [validated_burn(1_000, serial(0x3132_3334_3536_3738), 9)];
    let check = |name: &str, batch, ceiling, expected| {
        let response = UnverifiedPrepareResponse {
            batches: vec![batch],
        };
        assert_eq!(
            response.verify(&burns[0], &config(ceiling)).err(),
            expected,
            "{name}"
        );
    };
    let amount_cases = [
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
        rebuild_for_test(&mut changed).unwrap();
        check(name, changed, ceiling, expected);
    }
    // Circle charged 11099 on a 1 USDC burn to Base: more than a fixed 11000, but within the
    // ceiling once one basis point of the burn (100) is added.
    let mut base_fee = batch(FIRST_SALT, 1_000_000, 9);
    base_fee.burn_intents[0].spec.value = "988901".into();
    base_fee.burn_intents[0].max_fee = "11099".into();
    rebuild_for_test(&mut base_fee).unwrap();
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory, 1);
    args.replace("--max-withdrawal-fee", "11000");
    args.replace("--max-withdrawal-fee-bps", "1");
    let usdc = validated_burn(1_000_000, serial(0x3132_3334_3536_3738), 9);
    let response = UnverifiedPrepareResponse {
        batches: vec![base_fee],
    };
    assert_eq!(response.verify(&usdc, &args.load()).err(), None);
    type Case = (&'static str, fn(&mut UnverifiedPrepareBatch), VerifyError);
    let forwarding_cases: [Case; 1] = [(
        "restricted caller",
        |b| b.burn_intents[0].spec.destination_caller = format!("0x{}", "11".repeat(32)),
        CallerRestricted,
    )];
    for (name, edit, expected) in forwarding_cases {
        let mut changed = batch(FIRST_SALT, 1_000, 9);
        edit(&mut changed);
        rebuild_for_test(&mut changed).unwrap();
        check(name, changed, None, Some(expected));
    }
}

/// Reconstruct the packed bytes and EIP-712 digest from Circle's untouched sandbox captures.
#[test]
fn circle_hash_matches_reference() {
    for fixture in [
        include_str!("fixtures/circle-sandbox-2026-09-10-live-control-single.response.json"),
        FORWARDED_FIXTURE,
        DIRECT_WITH_OPTIONS_FIXTURE,
        FORWARDED_SOLANA_FIXTURE,
    ] {
        let response: UnverifiedPrepareResponse = serde_json::from_str(fixture).unwrap();
        let [batch] = response.batches.as_slice() else {
            panic!("the captured response must contain one batch");
        };
        let (encoded, digest) = canonical_values_for_test(batch).unwrap();
        assert_eq!(format!("0x{}", hex::encode(encoded)), batch.encoded);
        assert_eq!(format!("{digest:#x}"), batch.message_hash_to_sign);
    }
}

/// On the forwarded route the burn's destination sits in the CCTP calldata: every field of that
/// call and the forwarder this leg pays are checked, the fee ceiling covers both legs, and a
/// direct reply prepared with forwarding on still takes the direct checks.
#[test]
fn forwarded_route_is_bound_to_the_burn() {
    use VerifyError::*;
    let recipient: [u8; 32] = core::array::from_fn(|i| if i < 12 { 0 } else { 0x11 });
    let burn = validated_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 11, recipient);
    let forwarding = forwarding_config(600_000, 500_000);
    let verify = |burn: &_, batch, config: &Config| {
        let response = UnverifiedPrepareResponse {
            batches: vec![batch],
        };
        response.verify(burn, config).err()
    };
    let solana = validated_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 5, [0x11; 32]);
    for (burn, fixture) in [
        (&burn, FORWARDED_FIXTURE),
        (&solana, FORWARDED_SOLANA_FIXTURE),
    ] {
        assert_eq!(verify(burn, captured(fixture), &forwarding), None);
    }

    type Edit = fn(&mut UnverifiedPrepareBatch, &mut cctp::depositForBurnWithHookCall);
    let cases: [(&str, Edit, VerifyError); 13] = [
        (
            "zero forwarding contract",
            |b, _| {
                b.burn_intents[0].spec.hook_data.forwarding_contract_address =
                    format!("0x{}", "00".repeat(20))
            },
            ForwardedField("forwardingContractAddress"),
        ),
        (
            "recipient is not the forwarder",
            |b, _| b.burn_intents[0].spec.destination_recipient = ZERO_WORD.into(),
            ForwardedField("destinationRecipient"),
        ),
        (
            "caller is not the forwarder",
            |b, _| b.burn_intents[0].spec.destination_caller = ZERO_WORD.into(),
            ForwardedField("destinationCaller"),
        ),
        (
            "leg leaves the reserve chain",
            |b, _| b.burn_intents[0].spec.destination_domain = 6,
            ForwardedField("destinationDomain"),
        ),
        (
            "amount",
            |_, c| c.amount += U256::from(1),
            ForwardedField("calldata amount"),
        ),
        (
            "destination",
            |_, c| c.destinationDomain = 6,
            ForwardedField("calldata destinationDomain"),
        ),
        (
            "recipient",
            |_, c| c.mintRecipient = B256::ZERO,
            ForwardedField("calldata mintRecipient"),
        ),
        (
            "token",
            |_, c| c.burnToken = Address::ZERO,
            ForwardedField("calldata burnToken"),
        ),
        (
            "restricted caller",
            |_, c| c.destinationCaller = B256::repeat_byte(1),
            ForwardedField("calldata destinationCaller"),
        ),
        (
            "fee differs from the configured one",
            |_, c| c.maxFee += U256::from(1),
            ForwardedField("calldata maxFee"),
        ),
        (
            "finality",
            |_, c| c.minFinalityThreshold = 2000,
            ForwardedField("calldata minFinalityThreshold"),
        ),
        (
            "hook marker",
            |_, c| c.hookData = Bytes::new(),
            ForwardedField("calldata hookData"),
        ),
        (
            "payout does not match the burn",
            |b, c| {
                b.burn_intents[0].spec.value = "400000".into();
                c.amount = U256::from(400_000);
            },
            BadAmount,
        ),
    ];
    for (name, edit, expected) in cases {
        let mut batch = captured(FORWARDED_FIXTURE);
        let mut call = decode_call(&batch);
        edit(&mut batch, &mut call);
        let batch = with_calldata(batch, call.abi_encode());
        assert_eq!(verify(&burn, batch, &forwarding), Some(expected), "{name}");
    }

    // A fee at or above the amount reverts the CCTP leg on chain, even when it is the configured one.
    let batch = captured(FORWARDED_FIXTURE);
    let mut call = decode_call(&batch);
    call.maxFee = call.amount;
    let batch = with_calldata(batch, call.abi_encode());
    assert_eq!(
        verify(&burn, batch, &forwarding_config(2_000_000, 981_751)),
        Some(TooSmallToForward),
        "fee at the amount"
    );
    let batch = captured(FORWARDED_FIXTURE);
    let padded = [decode_call(&batch).abi_encode(), vec![0]].concat();
    assert_eq!(
        verify(&burn, with_calldata(batch, padded), &forwarding),
        Some(ForwardedField("forwardingCalldata")),
        "calldata with a trailing byte"
    );
    assert_eq!(
        verify(
            &burn,
            with_calldata(captured(FORWARDED_FIXTURE), vec![]),
            &forwarding
        ),
        Some(ForwardedField("forwardingCalldata")),
        "forwarding contract without calldata"
    );
    assert_eq!(
        verify(
            &burn,
            captured(FORWARDED_FIXTURE),
            &forwarding_config(518_248, 500_000)
        ),
        Some(FeeTooHigh),
        "the ceiling covers Circle's fee plus the CCTP fee"
    );

    let base_burn = validated_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 6, recipient);
    assert_eq!(
        verify(
            &base_burn,
            captured(DIRECT_WITH_OPTIONS_FIXTURE),
            &forwarding
        ),
        None,
        "a direct reply prepared with forwarding on"
    );
    let mut restricted = captured(DIRECT_WITH_OPTIONS_FIXTURE);
    restricted.burn_intents[0].spec.destination_caller = format!("0x{}", "11".repeat(32));
    rebuild_for_test(&mut restricted).unwrap();
    assert_eq!(
        verify(&base_burn, restricted, &forwarding),
        Some(CallerRestricted),
        "a direct reply keeps the caller check"
    );
}
