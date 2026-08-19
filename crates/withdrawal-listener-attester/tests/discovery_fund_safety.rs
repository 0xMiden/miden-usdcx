//! The two discovery checks that decide whether a note is a **burn of this faucet's xUSDC** at
//! all — the script-root pin and the carried-asset-versus-payload agreement.
//!
//! Both were structurally absent before this suite existed, and both are fund-safety checks in the
//! literal sense: what they refuse would otherwise reach Circle as a withdrawal request and unlock
//! native USDC against a burn that did not happen for the amount claimed.
//!
//! # Why the tag alone is not enough
//!
//! A note tag is a routing hint that anyone may write. `metadata.tag` costs nothing to copy, so a
//! note carrying the xUSDC burn tag and an arbitrary consume script is trivially constructible by
//! anybody; the faucet never runs, no supply is reduced, and the attester — matching on the tag and
//! nothing else — would happily read the attached payload and ask Circle to release. The script
//! root is what says the note will be consumed by the faucet's burn path, so it is pinned to
//! [`XReserveBurnNote::script_root()`] — read from the shared encoding crate, never written down
//! here as a digest literal, because issue #146's custom burn policy will MOVE that root and a
//! literal would rot into a check that rejects every real burn.
//!
//! # Why the payload alone is not enough
//!
//! The chain reduces supply by the amount in the note's VAULT and never reads the withdrawal
//! payload; the attester reads the PAYLOAD and — before this suite — never read the vault. The two
//! numbers are written by the same note author and nothing forced them to agree, so a note claiming
//! `1_000_000_000` in its attachment while carrying `1` of xUSDC would burn one unit on Miden and
//! ask Circle to release a thousand dollars. The agreement check closes that, and the faucet
//! identity check closes the same hole one step out: an asset issued by SOME OTHER faucet is not
//! xUSDC, however much of it the note carries.
//!
//! # These refusals happen BEFORE Circle is touched
//!
//! `validate_discovery` is B3, and B4/B5 (the request build and the prepare call) are downstream of
//! it, so a refusal here means zero Circle calls for that note. The last case in this file proves
//! that against the orchestration's own call log rather than by reading the source order.
//!
//! PURE + NON-GATING: no node runs here. What is under test is the checklist's REASONING over a
//! discovery report, which is exactly the shape the node-backed adapter fills in.

use assert_matches::assert_matches;
use rstest::rstest;

use miden_protocol::account::AccountId;
use miden_protocol::asset::{
    Asset, AssetAmount, FungibleAsset, NonFungibleAsset, NonFungibleAssetDetails,
};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::{Felt, Word};

use withdrawal_listener_attester::config::ListenerConfig;
use withdrawal_listener_attester::error::{DecodeError, DiscoveryReject};
use withdrawal_listener_attester::types::BurnPayload;
use withdrawal_listener_attester::validate::{
    validate_discovery, DiscoveredDetails, DiscoveryRecord,
};
use xusdc_encoding::note::xreserve_burn::{XReserveBurnNote, FIXED_XUSDC_BURN_TAG};
use xusdc_encoding::xreserve::encoding::ForeignChainAddress;

#[path = "listener_support/mod.rs"]
mod listener_support;

use listener_support::evidence_support::UnitPort;
use listener_support::{
    client_for, config as orchestration_config, discovered_forging, happy_script, ledger_in, mock,
    prepare_posts, production_signer, status_gets, withdraw_posts, CapturingEvents,
};

use withdrawal_listener_attester::listener::{run_once, RunContext, RunError};

// FIXTURES
// ================================================================================================

/// The amount the honest burn note carries, in both its vault and its withdrawal payload.
const HONEST_AMOUNT: u64 = 10_000_000;

/// The listener config under test: the canonical xUSDC burn tag, and the package-default faucet id
/// as the configured xUSDC faucet.
fn cfg() -> ListenerConfig {
    ListenerConfig::builder()
        .burn_tag(FIXED_XUSDC_BURN_TAG)
        .build()
        .expect("a valid config")
}

/// The configured xUSDC faucet — the only issuer whose asset is xUSDC.
fn xusdc_faucet() -> AccountId {
    cfg().faucet_id()
}

/// A real, parseable account id that is NOT the configured faucet. It is the holder account the
/// burner would use, which is the realistic negative: the asset most likely to turn up in a
/// wrongly-built burn note is one issued by an account that genuinely exists.
fn other_faucet() -> AccountId {
    AccountId::from_hex("0x0a8770f581c324b114fb42884cddc9").expect("a real, parseable account id")
}

/// The withdrawal payload claiming `amount`. The destination fields are not what this file is
/// about; they are well-formed so nothing else in the checklist fires first.
fn payload(amount: u64) -> BurnPayload {
    BurnPayload {
        amount: AssetAmount::new(amount).expect("an in-range amount"),
        dest_domain: 0,
        dest_recipient: ForeignChainAddress::new([0x74; 32]),
        salt: [0x5a; 32],
    }
}

/// `amount` units of xUSDC — issued by the CONFIGURED faucet.
fn xusdc(amount: u64) -> Asset {
    Asset::Fungible(FungibleAsset::new(xusdc_faucet(), amount).expect("an in-range amount"))
}

/// `amount` units of a fungible asset issued by some other faucet — not xUSDC, whatever the note's
/// payload says.
fn foreign_token(amount: u64) -> Asset {
    Asset::Fungible(FungibleAsset::new(other_faucet(), amount).expect("an in-range amount"))
}

/// A non-fungible asset issued by the configured faucet: the right issuer, the wrong KIND. A
/// withdrawal is denominated in an amount, and a non-fungible asset has none.
fn non_fungible() -> Asset {
    Asset::NonFungible(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        xusdc_faucet(),
        vec![0xAB; 32],
    )))
}

/// The pinned burn-note script root, taken from the shared encoding crate — the same symbol the
/// check itself reads, so this suite cannot pass against a stale digest.
fn canonical_root() -> NoteScriptRoot {
    XReserveBurnNote::script_root()
}

/// A script root that is NOT the burn note's — a note tagged for the listener whose consume script
/// is something else entirely.
fn foreign_root() -> NoteScriptRoot {
    let felt = |v: u64| Felt::new(v).expect("a value inside the field");
    NoteScriptRoot::from_raw(Word::from([felt(1), felt(2), felt(3), felt(4)]))
}

/// A discovery report for a PUBLIC note: the configured tag, a genuine sender, and whatever script
/// root and vault the case is about.
fn record(
    script_root: NoteScriptRoot,
    assets: Vec<Asset>,
    payload: &BurnPayload,
) -> DiscoveryRecord {
    record_with_items(script_root, assets, payload.encode())
}

/// The same, with the payload felts supplied raw — for the cases about ordering, where the payload
/// must be UNDECODABLE so a decode-first implementation is visibly distinguishable.
fn record_with_items(
    script_root: NoteScriptRoot,
    assets: Vec<Asset>,
    items: Vec<Felt>,
) -> DiscoveryRecord {
    let sender = other_faucet();
    DiscoveryRecord::new(
        FIXED_XUSDC_BURN_TAG,
        Some(DiscoveredDetails::from_raw_sender(
            items,
            sender.prefix().as_felt(),
            sender.suffix(),
            script_root,
            assets,
        )),
    )
}

/// The honest burn note: the pinned script root, one xUSDC asset, and a payload claiming exactly
/// that amount.
fn honest_record() -> DiscoveryRecord {
    record(
        canonical_root(),
        vec![xusdc(HONEST_AMOUNT)],
        &payload(HONEST_AMOUNT),
    )
}

// THE SCRIPT-ROOT PIN
// ================================================================================================

/// A note carrying the right TAG and the wrong SCRIPT is refused — the tag is a routing hint anyone
/// can write, and the script is what makes the note a burn.
#[test]
fn a_foreign_script_root_is_refused() {
    let assets = vec![xusdc(HONEST_AMOUNT)];
    let record = record(foreign_root(), assets, &payload(HONEST_AMOUNT));

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::ScriptRootMismatch { expected, actual })
            if expected == canonical_root() && actual == foreign_root(),
        "a correctly-tagged note whose consume script is not the burn note's is not a burn"
    );
}

/// …and the root the refusal names as EXPECTED is the shared encoding crate's, not a digest
/// written down here. Issue #146's custom burn policy will move that root; a literal pin would
/// silently become a check that rejects every real burn, so the pin is asserted to track its owner.
#[test]
fn the_pinned_root_is_the_encoding_crates_and_not_a_literal() {
    let record = record(
        foreign_root(),
        vec![xusdc(HONEST_AMOUNT)],
        &payload(HONEST_AMOUNT),
    );

    let Err(DiscoveryReject::ScriptRootMismatch { expected, .. }) =
        validate_discovery(&record, &cfg())
    else {
        panic!("a foreign script root is refused");
    };
    assert_eq!(
        expected,
        XReserveBurnNote::script_root(),
        "the pin must be sourced from XReserveBurnNote::script_root(), never from a digest literal"
    );
}

/// The non-vacuity control for the pin: the canonical root PASSES, and the burn it yields carries
/// the payload that was discovered.
#[test]
fn the_canonical_script_root_passes() {
    let payload = payload(HONEST_AMOUNT);
    let record = record(canonical_root(), vec![xusdc(HONEST_AMOUNT)], &payload);

    let discovered = validate_discovery(&record, &cfg()).expect("the pinned burn note validates");
    assert_eq!(discovered.payload(), &payload);
}

/// The pin fires BEFORE the payload decode. A note with a foreign script AND an undecodable
/// payload is refused for the SCRIPT — proof the check is not reachable only after a well-formed
/// payload has been parsed, which is exactly the note an attacker would send.
#[test]
fn the_script_root_is_checked_before_the_payload_is_decoded() {
    // 17 felts, not the required 18 — the payload cannot decode.
    let record = record_with_items(
        foreign_root(),
        vec![xusdc(HONEST_AMOUNT)],
        vec![Felt::from(0u32); 17],
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::ScriptRootMismatch { .. })
    );
}

/// …and the TAG still fires before the script root: a note that is not this listener's note at all
/// is refused as a tag mismatch, the existing first rung of the checklist, unchanged.
#[test]
fn the_tag_is_still_checked_before_the_script_root() {
    let cfg = ListenerConfig::builder()
        .burn_tag(0xAABB_CCDD)
        .build()
        .expect("a valid config");

    assert_matches!(
        validate_discovery(&honest_record(), &cfg),
        Err(DiscoveryReject::TagMismatch { .. })
    );
}

// THE CARRIED ASSET VERSUS THE PAYLOAD
// ================================================================================================

/// The vault says one number and the attachment says another. Miden burns the VAULT; Circle is
/// asked to release the ATTACHMENT. Both directions are refused, and the over-claim (carried <
/// payload) is the one that costs the reserve.
#[rstest]
#[case::carried_below_payload(HONEST_AMOUNT - 1, HONEST_AMOUNT)]
#[case::carried_above_payload(HONEST_AMOUNT + 1, HONEST_AMOUNT)]
#[case::carried_dust_payload_fortune(1, 1_000_000_000)]
#[case::carried_fortune_payload_dust(1_000_000_000, 1)]
fn a_carried_amount_that_disagrees_with_the_payload_is_refused(
    #[case] carried: u64,
    #[case] claimed: u64,
) {
    let record = record(canonical_root(), vec![xusdc(carried)], &payload(claimed));

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::AssetAmountMismatch { carried: c, payload: p })
            if c == carried && p == claimed,
        "the burned amount and the claimed amount must be the same number"
    );
}

/// An asset issued by ANOTHER faucet is not xUSDC, however exactly its amount matches the payload.
/// Matching amounts is precisely what makes this the case a pure amount check would wave through.
#[test]
fn an_asset_from_another_faucet_is_refused() {
    let record = record(
        canonical_root(),
        vec![foreign_token(HONEST_AMOUNT)],
        &payload(HONEST_AMOUNT),
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::AssetFaucetMismatch { expected, actual })
            if expected == xusdc_faucet() && actual == other_faucet(),
        "only the configured xUSDC faucet's asset is xUSDC"
    );
}

/// A zero burn must never reach Circle. The vault and the payload AGREE here — both say zero — so
/// the agreement check passes and this is the rung that has to catch it: releasing zero USDC
/// against a note that burned nothing is a withdrawal with no burn behind it.
#[test]
fn a_zero_amount_burn_is_refused() {
    let record = record(canonical_root(), vec![xusdc(0)], &payload(0));

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::ZeroAmount)
    );
}

/// A note carrying NO asset burns nothing at all. There is no amount to compare, so the refusal is
/// about the vault's shape rather than about a number.
#[test]
fn an_empty_vault_is_refused() {
    let record = record(canonical_root(), Vec::new(), &payload(HONEST_AMOUNT));

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::AssetCount { count: 0 })
    );
}

/// A note carrying TWO assets is refused rather than searched for the one that agrees. Picking the
/// matching asset out of a vault is how a note carrying xUSDC dust alongside a worthless token
/// gets read as a full-value burn.
#[test]
fn a_multi_asset_vault_is_refused() {
    let record = record(
        canonical_root(),
        vec![xusdc(HONEST_AMOUNT), foreign_token(1)],
        &payload(HONEST_AMOUNT),
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::AssetCount { count: 2 })
    );
}

/// A NON-fungible asset from the right faucet is refused: a withdrawal is denominated in an amount
/// and a non-fungible asset has none, so there is nothing for the payload to agree with.
#[test]
fn a_non_fungible_asset_is_refused() {
    let record = record(
        canonical_root(),
        vec![non_fungible()],
        &payload(HONEST_AMOUNT),
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::AssetNotFungible)
    );
}

/// The boundary: the largest amount the protocol can represent passes when both halves agree, so
/// the agreement check is an equality and not a range the top of the domain falls out of.
#[test]
fn the_maximum_representable_amount_passes_when_both_halves_agree() {
    let max = AssetAmount::MAX.as_u64();
    let payload = payload(max);
    let record = record(canonical_root(), vec![xusdc(max)], &payload);

    let discovered = validate_discovery(&record, &cfg()).expect("a max-amount burn validates");
    assert_eq!(discovered.payload().amount.as_u64(), max);
}

// THE EXISTING RUNGS ARE UNCHANGED
// ================================================================================================

/// A PRIVATE/erased note (`details = None`) still yields the SAME refusal it did before the two new
/// checks existed. An unobservable note has no script root and no vault to inspect, and the new
/// rungs must not turn "we cannot see it" into "it passed".
#[test]
fn a_private_note_is_still_unobservable() {
    let record = DiscoveryRecord::new(FIXED_XUSDC_BURN_TAG, None);

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::PrivateNoteUnobservable)
    );
}

/// A malformed payload is still the codec's verdict, carried through unflattened — the new asset
/// rung sits AFTER the decode and cannot pre-empt it.
#[test]
fn a_malformed_payload_is_still_a_decode_refusal() {
    let record = record_with_items(
        canonical_root(),
        vec![xusdc(HONEST_AMOUNT)],
        vec![Felt::from(0u32); 17],
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::Decode(
            DecodeError::BurnItemsMalformed { .. }
        ))
    );
}

/// A zero sender is still refused, and it is refused BEFORE the asset rung: the depositor is the
/// value Circle is told initiated the burn, and a note that names nobody is not made acceptable by
/// carrying the right asset.
#[test]
fn a_zero_sender_is_still_refused() {
    let record = DiscoveryRecord::new(
        FIXED_XUSDC_BURN_TAG,
        Some(DiscoveredDetails::from_raw_sender(
            payload(HONEST_AMOUNT).encode(),
            Felt::from(0u32),
            Felt::from(0u32),
            canonical_root(),
            vec![xusdc(HONEST_AMOUNT)],
        )),
    );

    assert_matches!(
        validate_discovery(&record, &cfg()),
        Err(DiscoveryReject::Decode(DecodeError::SenderZero))
    );
}

// THE REFUSAL LANDS BEFORE CIRCLE IS TOUCHED
// ================================================================================================

/// **The oracle for "before any Circle call".** Reading `run_once` top to bottom is not evidence;
/// the mock's call log is. A note whose script root is not the burn note's produces ZERO
/// `POST /v1/prepare-withdrawal`, ZERO `POST /v1/withdraw` and ZERO status polls — the refusal
/// happens at B3, so no request is ever built.
#[tokio::test]
async fn a_script_root_refusal_makes_no_circle_call() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().expect("a temp dir");
    let ledger = ledger_in(&dir);
    let signer = production_signer();
    let events = CapturingEvents::new();
    let cfg = orchestration_config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    let outcome = run_once(&ctx, &discovered_forging(foreign_root(), None)).await;

    assert_matches!(
        outcome,
        Err(RunError::Discovery(
            DiscoveryReject::ScriptRootMismatch { .. }
        ))
    );
    assert_eq!(
        prepare_posts(&mock),
        0,
        "no prepare call for a refused note"
    );
    assert_eq!(withdraw_posts(&mock), 0, "and no withdrawal");
    assert_eq!(status_gets(&mock), 0, "and nothing to poll");
}

/// The same for the asset disagreement: a note claiming a thousand times what it carries never
/// reaches Circle either.
#[tokio::test]
async fn an_asset_disagreement_makes_no_circle_call() {
    let mock = mock(happy_script());
    let circle = client_for(&mock);
    let dir = tempfile::tempdir().expect("a temp dir");
    let ledger = ledger_in(&dir);
    let signer = production_signer();
    let events = CapturingEvents::new();
    let cfg = orchestration_config();
    let port = UnitPort::honest();
    let ctx = RunContext::new(&cfg, &circle, &ledger, &signer, &port, &events);

    let dust = Asset::Fungible(FungibleAsset::new(cfg.faucet_id(), 1).expect("an in-range amount"));
    let outcome = run_once(
        &ctx,
        &discovered_forging(canonical_root(), Some(vec![dust])),
    )
    .await;

    assert_matches!(
        outcome,
        Err(RunError::Discovery(DiscoveryReject::AssetAmountMismatch {
            carried: 1,
            ..
        }))
    );
    assert_eq!(
        prepare_posts(&mock),
        0,
        "no prepare call for a refused note"
    );
    assert_eq!(withdraw_posts(&mock), 0, "and no withdrawal");
    assert_eq!(status_gets(&mock), 0, "and nothing to poll");
}
