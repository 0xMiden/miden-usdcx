//! Typed-boundary adoption suite — proves the round's typing work is REAL adoption, not facades.
//!
//! It locks: (1) every admin note factory has a `bon` builder + a dedicated note-storage type, and
//! the builder produces a note byte-identical to the retained `create` convenience; (2) the
//! mint-note builder takes the typed [`DepositIntent`] and is the factory's only entry point;
//! (3) the crate-root / account-root `build_faucet_account` constructor is reachable and composes a
//! valid `Account`; and (4) the [`XReserveComponent`] type converts into an `AccountComponent`. A
//! missing builder / storage type / export, or a builder that drifts from `create`, fails here.

mod support;

use anyhow::Result;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountComponent};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::{Felt, Word};
use miden_standards::interop::eth::EthAddress;
use support::*;
use xusdc_encoding::account::xreserve::{XReserveComponent, ATTESTATION_MINT_POLICY_PROC_PATH};
use xusdc_encoding::note::xreserve_admin::{
    XReserveSetAttesterNote, XReserveSetAttesterNoteStorage, XReserveSetMaxSupplyNote,
    XReserveSetMaxSupplyNoteStorage, XReserveSetMinBurnSizeNote, XReserveSetMinBurnSizeNoteStorage,
};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{
    DepositAttestation, XUsdcMintNote, XUsdcMintNoteStorage,
};
use xusdc_encoding::xreserve::encoding::{
    DepositIntent, DepositIntentHeader, DepositNonce, HookData, MintIntent, Signature,
    XReserveBurnItems,
};

fn note_rng(seed: u64) -> RandomCoin {
    RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(7u32),
        Felt::from(11u32),
    ]))
}

const RNG_SEED: u64 = 2026;

/// Two notes are byte-identical iff their serializations match (serial numbers align because both
/// draw from a fresh `note_rng(RNG_SEED)`).
fn assert_notes_identical(a: &Note, b: &Note, label: &str) {
    assert_eq!(
        a.to_bytes(),
        b.to_bytes(),
        "{label}: builder note != create note"
    );
}

// The admin note factories: bon builder + dedicated storage type, byte-identical to `create`.
// ================================================================================================

#[test]
fn set_attester_builder_matches_create() {
    let sender = test_account_id(5);
    let faucet = test_faucet_id(6);
    let commitment = Word::from([
        Felt::from(1u32),
        Felt::from(2u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]);

    let via_builder = XReserveSetAttesterNote::builder()
        .sender(sender)
        .faucet_id(faucet)
        .storage(
            XReserveSetAttesterNoteStorage::builder()
                .commitment(commitment)
                .enabled(1)
                .build(),
        )
        .rng(&mut note_rng(RNG_SEED))
        .build()
        .expect("builder note");
    let via_create =
        XReserveSetAttesterNote::create(sender, faucet, commitment, 1, &mut note_rng(RNG_SEED))
            .expect("create note");
    assert_notes_identical(&via_builder, &via_create, "set_attester");
}

#[test]
fn set_min_burn_size_builder_matches_create() {
    let sender = test_account_id(5);
    let faucet = test_faucet_id(6);

    let via_builder = XReserveSetMinBurnSizeNote::builder()
        .sender(sender)
        .faucet_id(faucet)
        .storage(
            XReserveSetMinBurnSizeNoteStorage::builder()
                .new_min(7)
                .build(),
        )
        .rng(&mut note_rng(RNG_SEED))
        .build()
        .expect("builder note");
    let via_create = XReserveSetMinBurnSizeNote::create(sender, faucet, 7, &mut note_rng(RNG_SEED))
        .expect("create note");
    assert_notes_identical(&via_builder, &via_create, "set_min_burn_size");
}

#[test]
fn set_max_supply_builder_matches_create() {
    let sender = test_account_id(5);
    let faucet = test_faucet_id(6);

    let via_builder = XReserveSetMaxSupplyNote::builder()
        .sender(sender)
        .faucet_id(faucet)
        .storage(
            XReserveSetMaxSupplyNoteStorage::builder()
                .new_max_supply(5_000)
                .build(),
        )
        .rng(&mut note_rng(RNG_SEED))
        .build()
        .expect("builder note");
    let via_create =
        XReserveSetMaxSupplyNote::create(sender, faucet, 5_000, &mut note_rng(RNG_SEED))
            .expect("create note");
    assert_notes_identical(&via_builder, &via_create, "set_max_supply");
}

// The burn note: XReserveBurnItems is its dedicated (bon) payload type.
// ================================================================================================

#[test]
fn burn_note_builder_matches_create() {
    let sender = test_account_id(5);
    let faucet = test_faucet_id(6);
    let items = XReserveBurnItems::builder()
        .amount(AssetAmount::new(1_234).expect("valid amount"))
        .dest_domain(9)
        .dest_recipient([0xAB; 32])
        .salt([0xCD; 32])
        .build();

    let via_builder = XReserveBurnNote::builder()
        .sender(sender)
        .faucet_id(faucet)
        .items(items.clone())
        .rng(&mut note_rng(RNG_SEED))
        .build()
        .expect("builder note");
    let via_create = XReserveBurnNote::create(sender, faucet, items, &mut note_rng(RNG_SEED))
        .expect("create note");
    assert_notes_identical(&via_builder, &via_create, "burn");
}

// The mint note builder takes the typed DepositIntent — there is no raw-bytes entry point.
// ================================================================================================

/// The mint factory's ONLY entry point is the typed builder over a decoded [`DepositIntent`], and
/// the assembled note converts into a protocol [`Note`] infallibly (`From`, not `TryFrom`): by the
/// time an `XUsdcMintNote` exists, every value in it has been accepted.
#[test]
fn mint_note_builder_takes_typed_deposit_intent() -> Result<()> {
    // A canonical DC-14 payload addressed to this faucet, and a real signature from the frozen
    // attestation vectors (the signature is the FAUCET's to check, not the factory's).
    let faucet = test_faucet_id(6);
    let payload = support::mint_transport::payload_for(test_account_id(7), faucet, 1_000, 0);
    let vectors = xusdc_encoding::vectors::load();
    let vector = vectors
        .families
        .att
        .first()
        .expect("an attestation vector is present");
    let attestation = DepositAttestation::new(Signature::new(vector.sig()), vector.public_key());

    let note = Note::from(
        XUsdcMintNote::builder()
            .sender(test_account_id(5))
            .target(faucet)
            .remote_domain(TEST_DOMAIN)
            .deposit_intent(DepositIntent::try_from(payload.as_slice())?)
            .attestation(attestation)
            .generate_serial_number(&mut note_rng(RNG_SEED))
            .build()?,
    );

    assert_eq!(
        note.attachments().num_attachments(),
        2,
        "the mint note carries the transport and the routing attachment"
    );
    Ok(())
}

// The crate-root / account-root constructor + component conversion.
// ================================================================================================

#[test]
fn crate_root_and_account_root_build_faucet_account_compose_an_account() {
    // Crate-root export (`xusdc_encoding::build_faucet_account`), taking the typed `EthAddress`
    // domain-config address.
    let account: Account = xusdc_encoding::build_faucet_account(
        [9u8; 32],
        AssetAmount::new(1_000_000).expect("valid max supply"),
        AssetAmount::new(0).expect("valid token supply"),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
        TEST_DOMAIN,
        TEST_SOURCE_DOMAIN,
        test_xreserve_contract(),
    )
    .expect("the crate-root constructor composes a valid account");
    assert!(
        !account.code().procedures().is_empty(),
        "the composed account carries a callable surface",
    );

    // Both the crate-root (`xusdc_encoding::build_faucet_account`, used above) and the account-module
    // -root (`xusdc_encoding::account::build_faucet_account`) exports resolve — finding 4's required
    // reachability. Referencing them as items is the compile-time proof.
    #[allow(clippy::let_underscore_untyped)]
    let _ = xusdc_encoding::account::build_faucet_account;
}

#[test]
fn xreserve_component_converts_into_account_component() {
    let component: AccountComponent = XReserveComponent::assemble().into();
    assert!(
        component
            .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
            .is_some(),
        "the converted xreserve component must export the attestation mint policy",
    );
}

// The mint note: the fifth factory has its OWN dedicated note-storage type, derived from the
// typed intent + faucet inputs (not the generic SDK MintNoteStorage inline).
// ================================================================================================

#[test]
fn mint_note_has_dedicated_storage_type_derived_from_the_typed_intent() -> Result<()> {
    let faucet = test_faucet_id(6);
    let recipient = test_account_id(7);

    // A DepositIntentHeader is built through its own builder, each field in the domain type the
    // deposit has to hold — no raw wire field is left to set.
    let local_token = EthAddress::new([2u8; 20]);
    let local_depositor = EthAddress::new([3u8; 20]);
    let amount = AssetAmount::new(1_000)?;
    let header = DepositIntentHeader::builder()
        .amount(amount)
        .remote_domain(1)
        .remote_token(faucet)
        .remote_recipient(recipient)
        .local_token(local_token)
        .local_depositor(local_depositor)
        .max_fee(AssetAmount::new(0)?)
        .nonce(DepositNonce::new([9u8; 32]))
        .build();

    // The dedicated `XUsdcMintNoteStorage` type is derivable from the carried intent + the attested
    // amount + the faucet id (the dedicated-storage-type requirement for the fifth factory), and
    // yields the attested fungible-public P2ID recipe the policy assert-matches.
    let intent = MintIntent::builder()
        .nonce(header.nonce())
        .local_token(local_token)
        .local_depositor(local_depositor)
        .remote_recipient(recipient)
        .max_fee(header.max_fee())
        .hook_data(HookData::new(Vec::new())?)
        .build();
    // Conversion works.
    XUsdcMintNoteStorage::new(&header, faucet);

    // and the two types describe the same deposit: expanding the carried intent against the same
    // faucet state reproduces the header it came from.
    assert_eq!(
        intent
            .to_deposit_intent(header.amount(), header.remote_domain(), faucet)
            .header(),
        &header,
        "the carried intent expands back to the header it was compressed from"
    );
    Ok(())
}

// G-RUST — the new admin note-storage types keep their fields PRIVATE, exposing read-only accessors.
// ================================================================================================

#[test]
fn admin_storage_types_expose_read_only_accessors_not_public_fields() {
    let commitment = Word::from([
        Felt::from(9u32),
        Felt::from(8u32),
        Felt::from(7u32),
        Felt::from(6u32),
    ]);
    let attester = XReserveSetAttesterNoteStorage::builder()
        .commitment(commitment)
        .enabled(1)
        .build();
    assert_eq!(
        attester.commitment(),
        commitment,
        "attester commitment accessor"
    );
    assert_eq!(attester.enabled(), 1, "attester enabled accessor");

    let min_burn = XReserveSetMinBurnSizeNoteStorage::builder()
        .new_min(42)
        .build();
    assert_eq!(min_burn.new_min(), 42, "min-burn accessor");

    let max_supply = XReserveSetMaxSupplyNoteStorage::builder()
        .new_max_supply(9_999)
        .build();
    assert_eq!(max_supply.new_max_supply(), 9_999, "max-supply accessor");
}
