//! Check Circle's returned terms locally, before anything can be signed.

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use miden_protocol::{Felt, Word};
use serde_json::json;
use usdcx_telemetry::{Classified as _, FailureClass};

use crate::burn::DiscoveredBurn;
use crate::circle::{UnverifiedPrepareBatch, UnverifiedPrepareResponse};
use crate::config::Config;
use crate::verify::{
    canonical_values_for_test, cctp, rebuild_for_test, VerifiedWithdrawal, VerifyError,
};

use super::startup::{create_store_parent, TestArgs};
use super::validation::{discovered_burn, discovered_burn_to};

/// The note serial of the test burns, which prepare sent as the salt before it sent the note ID.
const SERIAL_SALT: &str = "0x0807060504030201181716151413121128272625242322213837363534333231";
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
    let mut args = TestArgs::new(&directory);
    if let Some(ceiling) = fee_ceiling {
        args.replace("--max-withdrawal-fee", ceiling.to_string());
        args.replace("--cctp-forwarding-max-fee", "1");
    }
    args.load()
}

fn forwarding_config(fee_ceiling: u64, cctp_fee: u64) -> Config {
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory);
    args.replace("--max-withdrawal-fee", fee_ceiling.to_string());
    args.replace("--cctp-forwarding-max-fee", cctp_fee.to_string());
    args.replace("--cctp-forwarder-address", FORWARDER);
    args.load()
}

/// A captured Circle reply, adjusted to fit this burn and the test faucet: it changes the salt and
/// the two hook fields that name Circle's registered remote domain and token, then rebuilds the
/// encoded intent and digest. Every other field stays exactly as Circle laid it out.
pub(super) fn captured(fixture: &str, burn: &DiscoveredBurn) -> UnverifiedPrepareBatch {
    let mut response: UnverifiedPrepareResponse = serde_json::from_str(fixture).unwrap();
    let mut batch = response.batches.remove(0);
    // The capture was prepared with the note serial as the salt; bind it to this burn instead.
    batch.burn_intents[0].spec.salt = burn.note_id().to_hex();
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
                "sourceDomain": 26,
                "destinationDomain": destination_domain,
                "sourceContract": format!("0x{}", "11".repeat(32)),
                "destinationContract": format!("0x{}", "22".repeat(32)),
                "sourceToken": "0x0000000000000000000000003600000000000000000000000000000000000000",
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
    let burn = discovered_burn(1_000, serial(0x3132_3334_3536_3738), 9);
    let mut prepared = batch(&burn.note_id().to_hex(), 1_000, 9);
    rebuild_for_test(&mut prepared).unwrap();
    UnverifiedPrepareResponse {
        batches: vec![prepared],
    }
    .verify(&burn, &config(None))
    .unwrap()
}

/// The returned intent must belong to the burn and preserve all of its fields.
#[test]
fn circle_response_matches_burns() {
    use VerifyError::*;
    let burn = discovered_burn(1_000, serial(0x3132_3334_3536_3738), 9);
    let salt = burn.note_id().to_hex();
    let config = config(None);
    type Case = (&'static str, fn(&mut UnverifiedPrepareBatch), VerifyError);
    let field_cases: [Case; 10] = [
        (
            "unknown salt",
            |b| b.burn_intents[0].spec.salt = ZERO_WORD.into(),
            UnknownSalt,
        ),
        (
            "the note serial",
            |b| b.burn_intents[0].spec.salt = SERIAL_SALT.into(),
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
        (
            "source token is not USDC on Arc",
            |b| b.burn_intents[0].spec.source_token = ZERO_WORD.into(),
            WrongSourceToken,
        ),
        (
            "source domain is not Arc",
            |b| b.burn_intents[0].spec.source_domain = 6,
            WrongSourceDomain,
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
        let mut changed = batch(&salt, 1_000, 9);
        edit(&mut changed);
        rebuild_for_test(&mut changed).unwrap();
        refuse(name, vec![changed], expected);
    }
    let decimal_cases: [Case; 4] = [
        (
            "empty maximum fee",
            |b| b.burn_intents[0].max_fee.clear(),
            MalformedField("maxFee"),
        ),
        (
            "underscored value",
            |b| b.burn_intents[0].spec.value = "1_000".into(),
            MalformedField("value"),
        ),
        (
            "signed value",
            |b| b.burn_intents[0].spec.value = "+1000".into(),
            MalformedField("value"),
        ),
        (
            "space before maximum block height",
            |b| b.burn_intents[0].max_block_height = " 1".into(),
            MalformedField("maxBlockHeight"),
        ),
    ];
    for (name, edit, expected) in decimal_cases {
        let mut changed = batch(&salt, 1_000, 9);
        edit(&mut changed);
        refuse(name, vec![changed], expected);
    }
    refuse("missing batch", vec![], WrongCount);
    refuse(
        "extra batch",
        vec![batch(&salt, 1_000, 9), batch(&salt, 1_000, 9)],
        WrongCount,
    );
    let mut empty = batch(&salt, 1_000, 9);
    empty.burn_intents.clear();
    refuse("empty batch", vec![empty], WrongCount);
    let mut split = batch(&salt, 1_000, 9);
    split
        .burn_intents
        .push(batch(&salt, 1_000, 9).burn_intents.remove(0));
    refuse("two intents in one batch", vec![split], WrongCount);

    let response = UnverifiedPrepareResponse {
        batches: vec![batch(&salt, 1_000, 9)],
    };
    assert_eq!(response.verify(&burn, &config).err(), None);

    let mut changed = batch(&salt, 1_000, 9);
    changed.message_hash_to_sign = ZERO_WORD.into();
    refuse("different digest", vec![changed], DigestMismatch);
    let mut set_header = batch(&salt, 1_000, 9);
    set_header.encoded.replace_range(..10, "0xe999239b");
    refuse("burn-intent-set header", vec![set_header], EncodedMismatch);
    let mut mismatched = batch(&salt, 1_000, 9);
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
        mismatched = batch(&salt, 1_000, 9);
    }

    let verified = UnverifiedPrepareResponse {
        batches: vec![batch(&salt, 1_000, 9)],
    }
    .verify(&burn, &config)
    .unwrap();
    assert_eq!(
        verified.note_id(),
        burn.note_id(),
        "the verified authorization retains the durable burn row identity"
    );
}

/// The payout and fee must total the burn and respect the fee cap.
#[test]
fn circle_response_checks_amount_and_fee() {
    use VerifyError::*;
    let burns = [discovered_burn(1_000, serial(0x3132_3334_3536_3738), 9)];
    let salt = burns[0].note_id().to_hex();
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
        let mut changed = batch(&salt, 1_000, 9);
        changed.burn_intents[0].spec.value = value.into();
        changed.burn_intents[0].max_fee = fee.into();
        rebuild_for_test(&mut changed).unwrap();
        check(name, changed, ceiling, expected);
    }
    // Circle charged 11099 on a 1 USDC burn to Base: more than a fixed 11000, but within the
    // ceiling once one basis point of the burn (100) is added.
    let usdc = discovered_burn(1_000_000, serial(0x3132_3334_3536_3738), 9);
    let mut base_fee = batch(&usdc.note_id().to_hex(), 1_000_000, 9);
    base_fee.burn_intents[0].spec.value = "988901".into();
    base_fee.burn_intents[0].max_fee = "11099".into();
    rebuild_for_test(&mut base_fee).unwrap();
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory);
    args.replace("--max-withdrawal-fee", "11000");
    args.replace("--max-withdrawal-fee-bps", "1");
    args.replace("--cctp-forwarding-max-fee", "1");
    let response = UnverifiedPrepareResponse {
        batches: vec![base_fee],
    };
    assert_eq!(response.verify(&usdc, &args.load()).err(), None);
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
    let burn = discovered_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 11, recipient);
    let forwarding = forwarding_config(600_000, 500_000);
    let verify = |burn: &_, batch, config: &Config| {
        let response = UnverifiedPrepareResponse {
            batches: vec![batch],
        };
        response.verify(burn, config).err()
    };
    let solana = discovered_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 5, [0x11; 32]);
    for (burn, fixture) in [
        (&burn, FORWARDED_FIXTURE),
        (&solana, FORWARDED_SOLANA_FIXTURE),
    ] {
        assert_eq!(verify(burn, captured(fixture, burn), &forwarding), None);
    }

    type Edit = fn(&mut UnverifiedPrepareBatch, &mut cctp::depositForBurnWithHookCall);
    let cases: [(&str, Edit, VerifyError); 20] = [
        (
            "source token is not USDC on Arc",
            |b, _| b.burn_intents[0].spec.source_token = ZERO_WORD.into(),
            WrongSourceToken,
        ),
        (
            "zero forwarding contract",
            |b, _| {
                b.burn_intents[0].spec.hook_data.forwarding_contract_address =
                    format!("0x{}", "00".repeat(20))
            },
            ForwardedField("forwardingContractAddress"),
        ),
        (
            "forwarding contract is not TokenMessengerV2",
            |b, _| {
                b.burn_intents[0].spec.hook_data.forwarding_contract_address =
                    format!("0x{}", "ee".repeat(20))
            },
            ForwardedField("forwardingContractAddress"),
        ),
        (
            "forwarding contract is xReserve itself",
            |b, _| b.burn_intents[0].spec.hook_data.forwarding_contract_address = FORWARDER.into(),
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
            "leg starts outside Arc",
            |b, _| b.burn_intents[0].spec.source_domain = 6,
            WrongSourceDomain,
        ),
        (
            "leg stays on a chain other than Arc",
            |b, _| {
                b.burn_intents[0].spec.source_domain = 6;
                b.burn_intents[0].spec.destination_domain = 6;
            },
            ForwardedField("destinationDomain"),
        ),
        (
            "token has nonzero upper bytes",
            |b, _| {
                b.burn_intents[0].spec.destination_token =
                    "0x0100000000000000000000003600000000000000000000000000000000000000".into()
            },
            ForwardedField("destinationToken"),
        ),
        (
            "both tokens change together",
            |b, c| {
                b.burn_intents[0].spec.destination_token = format!("0x{}", "ee".repeat(32));
                c.burnToken = Address::repeat_byte(0xee);
            },
            ForwardedField("destinationToken"),
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
        let mut batch = captured(FORWARDED_FIXTURE, &burn);
        let mut call = decode_call(&batch);
        edit(&mut batch, &mut call);
        let batch = with_calldata(batch, call.abi_encode());
        assert_eq!(verify(&burn, batch, &forwarding), Some(expected), "{name}");
    }

    // A fee at or above the amount reverts the CCTP leg on chain, even when it is the configured one.
    let batch = captured(FORWARDED_FIXTURE, &burn);
    let mut call = decode_call(&batch);
    call.maxFee = call.amount;
    let batch = with_calldata(batch, call.abi_encode());
    assert_eq!(
        verify(&burn, batch, &forwarding_config(2_000_000, 981_751)),
        Some(PayoutTooSmallToForward),
        "fee at the amount"
    );
    let mut batch = captured(FORWARDED_FIXTURE, &burn);
    batch.burn_intents[0].spec.value = "981752".into();
    batch.burn_intents[0].max_fee = "18248".into();
    let mut call = decode_call(&batch);
    call.amount = U256::from(981_752);
    call.maxFee = U256::from(981_751);
    assert_eq!(
        verify(
            &burn,
            with_calldata(batch, call.abi_encode()),
            &forwarding_config(2_000_000, 981_751)
        ),
        None,
        "a payout one unit above the CCTP fee"
    );
    let batch = captured(FORWARDED_FIXTURE, &burn);
    let mut call = decode_call(&batch);
    call.maxFee = U256::from(1_000_000);
    assert_eq!(
        verify(
            &burn,
            with_calldata(batch, call.abi_encode()),
            &forwarding_config(3_000_000, 1_000_000)
        ),
        Some(TooSmallToForward),
        "a CCTP fee equal to the burn"
    );
    let batch = captured(FORWARDED_FIXTURE, &burn);
    let padded = [decode_call(&batch).abi_encode(), vec![0]].concat();
    assert_eq!(
        verify(&burn, with_calldata(batch, padded), &forwarding),
        Some(ForwardedField("forwardingCalldata")),
        "calldata with a trailing byte"
    );
    assert_eq!(
        verify(
            &burn,
            with_calldata(captured(FORWARDED_FIXTURE, &burn), vec![]),
            &forwarding
        ),
        Some(ForwardedField("forwardingCalldata")),
        "forwarding contract without calldata"
    );
    assert_eq!(
        verify(
            &burn,
            captured(FORWARDED_FIXTURE, &burn),
            &forwarding_config(518_248, 500_000)
        ),
        Some(FeeTooHigh),
        "the ceiling covers Circle's fee plus the CCTP fee"
    );

    let base_burn = discovered_burn_to(1_000_000, serial(0x3132_3334_3536_3738), 6, recipient);
    assert_eq!(
        verify(
            &base_burn,
            captured(DIRECT_WITH_OPTIONS_FIXTURE, &base_burn),
            &forwarding
        ),
        None,
        "a direct reply prepared with forwarding on"
    );
    let mut restricted = captured(DIRECT_WITH_OPTIONS_FIXTURE, &base_burn);
    restricted.burn_intents[0].spec.destination_caller = format!("0x{}", "11".repeat(32));
    rebuild_for_test(&mut restricted).unwrap();
    assert_eq!(
        verify(&base_burn, restricted, &forwarding),
        Some(CallerRestricted),
        "a direct reply keeps the caller check"
    );
}

/// A destination, fee or payout that does not fit the configuration needs an operator; every other
/// failed check means Circle asked for a signature over something other than the burn.
#[test]
fn verification_failures_are_classed_for_alerting() {
    use VerifyError::*;
    for error in [
        UnsupportedDestination,
        FeeTooHigh,
        PayoutTooSmallToForward,
        TooSmallToForward,
    ] {
        assert!(
            matches!(error.failure(), FailureClass::Actionable(_)),
            "{error:?}"
        );
    }
    for error in [
        WrongCount,
        UnknownSalt,
        BadAmount,
        WrongSigner,
        WrongSourceToken,
        WrongSourceDomain,
        CallerRestricted,
        ForwardedField("recipient"),
        MalformedField("salt"),
        WrongBurnField("value"),
        DigestMismatch,
        EncodedMismatch,
    ] {
        assert!(
            matches!(error.failure(), FailureClass::Integrity(_)),
            "{error:?}"
        );
    }
}

fn copy_batch(batch: &UnverifiedPrepareBatch) -> UnverifiedPrepareBatch {
    serde_json::from_value(json!({
        "burnIntents": batch.burn_intents,
        "encoded": batch.encoded,
        "messageHashToSign": batch.message_hash_to_sign,
    }))
    .unwrap()
}

// Synthetic redeposit terms use Circle's documented tuple and an independently written ABI head.
// The common outer encoding/hash helper keeps semantic mutations internally consistent.
pub(super) fn redeposit_batch(
    burn: &DiscoveredBurn,
    outer_fee: u64,
    cap: u64,
    mainnet: bool,
) -> UnverifiedPrepareBatch {
    let intermediate = if burn.items().dest_domain.as_u32() == 10003 {
        0
    } else {
        26
    };
    redeposit_batch_via(burn, outer_fee, cap, mainnet, intermediate)
}

fn redeposit_batch_via(
    burn: &DiscoveredBurn,
    outer_fee: u64,
    cap: u64,
    mainnet: bool,
    intermediate: u32,
) -> UnverifiedPrepareBatch {
    let mut prepared = batch(&burn.note_id().to_hex(), burn.amount() - outer_fee, 0);
    let (reserve, ethereum_token, wallet, minter) = if mainnet {
        (
            "8888888199b2df864bf678259607d6d5ebb4e3ce",
            "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "77777777dcc4d5a8b6e418fd04d8997ef11000ee",
            "2222222d7164433c4c09b0b0d809a9b52c04c205",
        )
    } else {
        (
            "008888878f94c0d87defdf0b07f46b93c1934442",
            "1c7d4b196cb0c7b01d743fbc6116a902379c7238",
            "0077777d7eba4688bdef3e311b846f25870a19b9",
            "0022222abe238cc2c7bb1f21003f0a260052475b",
        )
    };
    let token = if intermediate == 26 {
        "3600000000000000000000000000000000000000"
    } else {
        ethereum_token
    };
    let word = |address| format!("0x000000000000000000000000{address}");
    prepared.burn_intents[0].max_fee = outer_fee.to_string();
    let spec = &mut prepared.burn_intents[0].spec;
    spec.destination_domain = intermediate;
    spec.source_contract = word(wallet);
    spec.destination_contract = word(minter);
    spec.destination_token = word(token);
    spec.destination_recipient = word(reserve);
    spec.destination_caller = word(reserve);
    spec.hook_data.forwarding_contract_address = format!("0x{reserve}");
    let mut call = hex::decode("faadb53b").unwrap();
    call.extend(U256::from(burn.amount() - outer_fee).to_be_bytes::<32>());
    call.extend(U256::from(burn.items().dest_domain.as_u32()).to_be_bytes::<32>());
    call.extend(burn.items().dest_recipient.as_bytes());
    call.extend(hex::decode(&word(token)[2..]).unwrap());
    call.extend(U256::from(cap).to_be_bytes::<32>());
    call.extend(U256::from(192).to_be_bytes::<32>());
    call.extend([0; 32]);
    with_calldata(prepared, call)
}

pub(super) fn redeposit_config(ceiling: u64, cap: Option<u64>, mainnet: bool) -> Config {
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory);
    args.replace("--max-withdrawal-fee", ceiling.to_string());
    if let Some(cap) = cap {
        args.append("--xreserve-deposit-max-fee", cap.to_string());
    }
    if mainnet {
        args.replace(
            "--cctp-forwarder-address",
            "0x8888888199b2df864bf678259607d6d5ebb4e3ce",
        );
    }
    args.load()
}

#[test]
fn admitted_redeposits_accept_both_documented_intermediate_deployments() {
    for domain in [10003, 10004, 10005] {
        let burn = discovered_burn(10_000_000, serial(90), domain);
        for mainnet in [false, true] {
            let config = redeposit_config(600, Some(500), mainnet);
            for intermediate in [0, 26] {
                let prepared = redeposit_batch_via(&burn, 100, 500, mainnet, intermediate);
                assert!(
                    UnverifiedPrepareResponse {
                        batches: vec![prepared]
                    }
                    .verify(&burn, &config)
                    .is_ok(),
                    "domain {domain}, mainnet {mainnet}, intermediate {intermediate}"
                );
            }
        }
    }
}

#[test]
fn redeposit_binds_the_known_route_and_every_argument() {
    use VerifyError::ForwardedField;
    let burn = discovered_burn(10_000_000, serial(91), 10003);
    for (mainnet, intermediate) in [(false, 0), (false, 26), (true, 0), (true, 26)] {
        let config = redeposit_config(600, Some(500), mainnet);
        let prepared = redeposit_batch_via(&burn, 100, 500, mainnet, intermediate);
        assert!(UnverifiedPrepareResponse {
            batches: vec![copy_batch(&prepared)]
        }
        .verify(&burn, &config)
        .is_ok());
        type Edit = fn(&mut crate::circle::BurnIntent);
        let cases: [(Edit, &str); 7] = [
            (
                |b| b.spec.hook_data.forwarding_contract_address = Address::ZERO.to_string(),
                "forwardingContractAddress",
            ),
            (
                |b| b.spec.destination_recipient = ZERO_WORD.into(),
                "destinationRecipient",
            ),
            (
                |b| b.spec.destination_caller = ZERO_WORD.into(),
                "destinationCaller",
            ),
            (|b| b.spec.destination_domain = 99, "destinationDomain"),
            (
                |b| b.spec.destination_token = ZERO_WORD.into(),
                "destinationToken",
            ),
            (
                |b| b.spec.source_contract = ZERO_WORD.into(),
                "sourceContract",
            ),
            (
                |b| b.spec.destination_contract = ZERO_WORD.into(),
                "destinationContract",
            ),
        ];
        for (edit, field) in cases {
            let mut changed = copy_batch(&prepared);
            edit(&mut changed.burn_intents[0]);
            rebuild_for_test(&mut changed).unwrap();
            assert_eq!(
                UnverifiedPrepareResponse {
                    batches: vec![changed]
                }
                .verify(&burn, &config)
                .unwrap_err(),
                ForwardedField(field)
            );
        }
        // Reusing the same contract addresses on another chain must not admit its wrong token.
        let mut mismatched = copy_batch(&prepared);
        mismatched.burn_intents[0].spec.destination_domain =
            if intermediate == 26 { 0 } else { 26 };
        rebuild_for_test(&mut mismatched).unwrap();
        assert_eq!(
            UnverifiedPrepareResponse {
                batches: vec![mismatched]
            }
            .verify(&burn, &config)
            .unwrap_err(),
            ForwardedField("destinationToken")
        );
        let original =
            hex::decode(&prepared.burn_intents[0].spec.hook_data.forwarding_calldata[2..]).unwrap();
        // Mutate each inner argument, including the high recipient byte (not just an EVM suffix).
        for (offset, field) in [
            (35, "calldata value"),
            (67, "calldata remoteDomain"),
            (68, "calldata remoteRecipient"),
            (131, "calldata localToken"),
            (163, "calldata maxFee"),
        ] {
            let mut call = original.clone();
            call[offset] ^= 1;
            let changed = with_calldata(copy_batch(&prepared), call);
            assert_eq!(
                UnverifiedPrepareResponse {
                    batches: vec![changed]
                }
                .verify(&burn, &config)
                .unwrap_err(),
                ForwardedField(field)
            );
        }
        let mut nonempty =
            crate::verify::redeposit::depositToRemoteCall::abi_decode(&original).unwrap();
        nonempty.hookData = vec![1].into();
        assert_eq!(
            UnverifiedPrepareResponse {
                batches: vec![with_calldata(copy_batch(&prepared), nonempty.abi_encode())]
            }
            .verify(&burn, &config)
            .unwrap_err(),
            ForwardedField("calldata hookData")
        );
        let mut malformed = Vec::new();
        let mut selector = original.clone();
        selector[0] ^= 1;
        malformed.push(selector);
        malformed.push(original[..original.len() - 1].to_vec());
        let mut trailing = original.clone();
        trailing.push(0);
        malformed.push(trailing);
        let mut offset = original.clone();
        offset[195] = 0xa0;
        malformed.push(offset);
        let mut width = original.clone();
        width[36] = 1;
        malformed.push(width);
        let mut padding = original.clone();
        padding[100] = 1;
        malformed.push(padding);
        for call in malformed {
            assert_eq!(
                UnverifiedPrepareResponse {
                    batches: vec![with_calldata(copy_batch(&prepared), call)]
                }
                .verify(&burn, &config)
                .unwrap_err(),
                ForwardedField("forwardingCalldata")
            );
        }
    }
}

#[test]
fn redeposit_cap_is_opt_in_and_other_remote_routes_cannot_bypass_it() {
    use VerifyError::*;
    for domain in [10000, 10001, 10002, 10003, 10004, 10005, 10007, 10008] {
        let admitted = matches!(domain, 10003..=10005);
        let burn = discovered_burn(10_000_000, serial(92), domain);
        let prepared = redeposit_batch(&burn, 100, 0, false);
        assert_eq!(
            UnverifiedPrepareResponse {
                batches: vec![copy_batch(&prepared)]
            }
            .verify(&burn, &redeposit_config(100, None, false))
            .unwrap_err(),
            UnsupportedDestination
        );
        if admitted {
            assert!(UnverifiedPrepareResponse {
                batches: vec![prepared]
            }
            .verify(&burn, &redeposit_config(100, Some(0), false))
            .is_ok());
        } else {
            assert_eq!(
                UnverifiedPrepareResponse {
                    batches: vec![prepared]
                }
                .verify(&burn, &redeposit_config(1000, Some(500), false))
                .unwrap_err(),
                UnsupportedDestination
            );
        }
        let expected = if admitted {
            ForwardedField("destinationDomain")
        } else {
            UnsupportedDestination
        };
        let direct = batch(&burn.note_id().to_hex(), burn.amount(), domain);
        assert_eq!(
            UnverifiedPrepareResponse {
                batches: vec![direct]
            }
            .verify(&burn, &redeposit_config(1_000_000, Some(500), false))
            .unwrap_err(),
            expected
        );
        let mut cctp = captured(FORWARDED_FIXTURE, &burn);
        cctp.burn_intents[0].max_fee = "0".into();
        cctp.burn_intents[0].spec.value = burn.amount().to_string();
        let mut call = decode_call(&cctp);
        call.amount = U256::from(burn.amount());
        call.destinationDomain = domain;
        call.mintRecipient = B256::from_slice(burn.items().dest_recipient.as_bytes());
        cctp = with_calldata(cctp, call.abi_encode());
        let expected = if admitted {
            ForwardedField("forwardingContractAddress")
        } else {
            UnsupportedDestination
        };
        assert_eq!(
            UnverifiedPrepareResponse {
                batches: vec![cctp]
            }
            .verify(&burn, &redeposit_config(1_000_000, Some(500), false))
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn redeposit_combined_fees_and_payout_keep_existing_integrity_order() {
    use VerifyError::*;
    let burn = discovered_burn(1000, serial(93), 10003);
    for (ceiling, cap, fee, expected) in [
        (600, 500, 100, None),
        (599, 500, 100, Some(FeeTooHigh)),
        (1000, 1000, 0, Some(TooSmallToForward)),
        (1000, 900, 100, Some(PayoutTooSmallToForward)),
    ] {
        let prepared = redeposit_batch(&burn, fee, cap, false);
        let result = UnverifiedPrepareResponse {
            batches: vec![prepared],
        }
        .verify(&burn, &redeposit_config(ceiling, Some(cap), false));
        assert_eq!(result.err(), expected);
    }
    let mut bad = redeposit_batch(&burn, 0, 1000, false);
    bad.message_hash_to_sign = ZERO_WORD.into();
    assert_eq!(
        UnverifiedPrepareResponse { batches: vec![bad] }
            .verify(&burn, &redeposit_config(1000, Some(1000), false))
            .unwrap_err(),
        DigestMismatch
    );
}

#[test]
fn captured_mainnet_stacks_route_reaches_the_original_fee_refusal() {
    use miden_protocol::{
        account::AccountId, block::BlockNumber, note::Note, transaction::PublicOutputNote,
        utils::serde::Deserializable,
    };
    // Untouched public note and Circle response from the incident investigation. Consumption was
    // authenticated in the separate incident evidence; this unit test does not contact a node.
    let note = Note::read_from_bytes(include_bytes!(
        "fixtures/miden-mainnet-2026-10-16-stacks.note"
    ))
    .unwrap();
    let faucet = AccountId::from_hex("0xe69e6ca6e39df1b10c1e5399399feb").unwrap();
    let burn = crate::burn::BurnCandidate::new(
        PublicOutputNote::new(note).unwrap(),
        BlockNumber::from(57696),
        faucet,
    )
    .unwrap()
    .into_discovered(BlockNumber::from(57697));
    assert_eq!(
        burn.note_id().to_hex(),
        "0x159e52ecdbb8771140535f4f999fed891aec2a20da18de1ebd28ae6a05e98644"
    );
    let directory = tempfile::tempdir().unwrap();
    create_store_parent(&directory);
    let mut args = TestArgs::new(&directory);
    args.replace("--faucet-account-id", faucet.to_hex());
    args.replace("--max-withdrawal-fee", "1204200");
    args.replace("--max-withdrawal-fee-bps", "2");
    args.replace(
        "--cctp-forwarder-address",
        "0x8888888199b2df864bf678259607d6d5ebb4e3ce",
    );
    args.append("--xreserve-deposit-max-fee", "428026");
    let response: UnverifiedPrepareResponse = serde_json::from_str(include_str!(
        "fixtures/circle-mainnet-2026-10-20-stacks.response.json"
    ))
    .unwrap();
    let raw = &response.batches[0];
    let (encoded, digest) = canonical_values_for_test(raw).unwrap();
    assert_eq!(encoded, hex::decode(&raw.encoded[2..]).unwrap());
    assert_eq!(digest.to_string(), raw.message_hash_to_sign);
    assert_eq!(
        response.verify(&burn, &args.load()).unwrap_err(),
        VerifyError::FeeTooHigh
    );
}
